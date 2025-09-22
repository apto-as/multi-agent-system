#!/usr/bin/env python3
"""
TMWS MCP Server - Optimized Database-Level Sharing Implementation

Each Claude Code instance runs this MCP server independently,
but all instances share state through PostgreSQL database.
"""

import asyncio
import json
import logging
import os
import socket
from datetime import datetime
from uuid import uuid4

import asyncpg
from fastmcp import FastMCP

from src.core.config import get_settings
from src.utils.embeddings import get_embedding

logger = logging.getLogger(__name__)
settings = get_settings()

class OptimizedMCPServer:
    """
    MCP Server with database-level sharing optimizations
    Each instance shares state through PostgreSQL with caching and pooling.
    """

    def __init__(self):
        # Instance identification
        self.agent_id = os.getenv("TMWS_AGENT_ID", f"agent-{uuid4().hex[:8]}")
        self.instance_id = f"{self.agent_id}-{os.getpid()}"
        self.hostname = socket.gethostname()

        # Database connection pool
        self.db_pool: asyncpg.Pool | None = None
        self.db_url = os.getenv("TMWS_DATABASE_URL", settings.database_url)

        # Advanced multi-tier cache system (temporarily using dicts to bypass ImportError)
        # Primary cache: High-importance items with longer TTL
        self.primary_cache = {}  # ttl_cache.TTLCache(maxsize=500, ttl=300)
        # Secondary cache: Normal items with standard TTL
        self.secondary_cache = {}  # ttl_cache.TTLCache(maxsize=1000, ttl=60)
        # Hot cache: Frequently accessed items
        self.hot_cache = {}  # ttl_cache.TTLCache(maxsize=100, ttl=600)
        self.access_counter = {}  # Track access patterns

        # Legacy cache reference for compatibility
        self.cache = self.secondary_cache

        # MCP server setup
        self.mcp = FastMCP(
            name="tmws",
            version="2.2.0"
        )

        # Notification listeners
        self.listeners = []

        # Performance metrics
        self.metrics = {
            "requests": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "db_queries": 0,
            "errors": 0,
            "primary_cache_hits": 0,
            "secondary_cache_hits": 0,
            "hot_cache_hits": 0
        }

        # Register MCP tools
        self._register_tools()

    def _register_tools(self):
        """Register all MCP tools"""

        @self.mcp.tool(
            name="store_memory",
            description="Store information in semantic memory"
        )
        async def store_memory(
            content: str,
            importance: float = 0.5,
            tags: list[str] = None,
            metadata: dict = None
        ) -> dict:
            """Store a new memory with vector embedding"""
            return await self.store_memory_shared(content, importance, tags, metadata)

        @self.mcp.tool(
            name="search_memories",
            description="Search semantic memories"
        )
        async def search_memories(
            query: str,
            limit: int = 10,
            global_search: bool = False
        ) -> dict:
            """Search memories using vector similarity"""
            return await self.search_global_memories(query, limit, global_search)

        @self.mcp.tool(
            name="create_task",
            description="Create a new task"
        )
        async def create_task(
            title: str,
            description: str = None,
            priority: str = "MEDIUM",
            assigned_persona: str = None
        ) -> dict:
            """Create and coordinate task"""
            return await self.create_coordinated_task(title, description, priority, assigned_persona)

        @self.mcp.tool(
            name="get_agent_status",
            description="Get status of all connected agents"
        )
        async def get_agent_status() -> dict:
            """Get status of all agent instances"""
            return await self.get_connected_agents()

        @self.mcp.tool(
            name="invalidate_cache",
            description="Invalidate local cache"
        )
        async def invalidate_cache(key: str = None) -> dict:
            """Invalidate cache entries"""
            if key:
                self.primary_cache.pop(key, None)
                self.secondary_cache.pop(key, None)
                self.hot_cache.pop(key, None)
                self.cache.pop(key, None) # Also clear the legacy cache reference
            else:
                self.primary_cache.clear()
                self.secondary_cache.clear()
                self.hot_cache.clear()
                self.cache.clear() # Also clear the legacy cache reference
            return {"status": "cache_invalidated", "key": key}

    async def initialize(self):
        """Initialize database pool and listeners"""
        try:
            # Optimized connection pool settings based on environment
            env = os.getenv("TMWS_ENVIRONMENT", "development")

            if env == "production":
                # Production: Higher concurrency
                min_size = 5
                max_size = 20
                max_queries = 100000
                max_inactive_lifetime = 600
            elif env == "staging":
                # Staging: Moderate settings
                min_size = 3
                max_size = 15
                max_queries = 50000
                max_inactive_lifetime = 300
            else:
                # Development: Conservative settings
                min_size = 1
                max_size = 5
                max_queries = 10000
                max_inactive_lifetime = 60

            # Create connection pool with optimized settings
            self.db_pool = await asyncpg.create_pool(
                dsn=self.db_url,
                min_size=min_size,
                max_size=max_size,
                max_queries=max_queries,
                max_inactive_connection_lifetime=max_inactive_lifetime,
                command_timeout=10,
                # Connection recycling for long-running instances
                max_cached_statement_lifetime=3600,
                max_cached_statement_use_count=5000
            )

            # Register this instance
            await self.register_instance()

            # Start listening for changes
            await self.setup_listeners()

            # Start heartbeat task
            asyncio.create_task(self.heartbeat_loop())

            logger.info(f"MCP Server initialized: {self.instance_id} (env: {env}, pool: {min_size}-{max_size})")

        except Exception as e:
            logger.error(f"Failed to initialize MCP server: {e}")
            raise

    async def register_instance(self):
        """Register this MCP server instance in the database"""
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO agent_instances (
                    id, agent_id, instance_id, pid, hostname, status
                )
                VALUES ($1, $2, $3, $4, $5, 'active')
                ON CONFLICT (instance_id) DO UPDATE
                SET last_heartbeat = NOW(),
                    status = 'active'
            """, uuid4(), self.agent_id, self.instance_id, os.getpid(), self.hostname)

    async def heartbeat_loop(self):
        """Send periodic heartbeats to maintain instance registration"""
        while True:
            try:
                await asyncio.sleep(30)  # Heartbeat every 30 seconds
                async with self.db_pool.acquire() as conn:
                    await conn.execute("""
                        UPDATE agent_instances
                        SET last_heartbeat = NOW()
                        WHERE instance_id = $1
                    """, self.instance_id)

                    # Record connection pool stats
                    pool_stats = self.db_pool.get_stats()
                    await conn.execute("""
                        INSERT INTO connection_stats (
                            instance_id, pool_size, active_connections,
                            idle_connections, waiting_requests,
                            total_requests, total_errors
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                    """, self.instance_id, pool_stats.size,
                        pool_stats.active, pool_stats.idle,
                        pool_stats.waiting, self.metrics["requests"],
                        self.metrics["errors"])

            except Exception as e:
                logger.error(f"Heartbeat error: {e}")

    async def setup_listeners(self):
        """Setup PostgreSQL LISTEN/NOTIFY for real-time sync"""
        conn = await self.db_pool.acquire()

        async def listen_for_memory_changes():
            """Listen for memory changes from other instances"""
            await conn.execute("LISTEN memory_changes")
            while True:
                try:
                    msg = await conn.wait_for_notification()
                    data = json.loads(msg.payload)

                    # Invalidate cache for changed memories
                    if data.get("visibility") == "shared":
                        self.cache.clear()  # Simple invalidation strategy

                        # Log sync event
                        await self.log_sync_event("memory_change", data)

                except Exception as e:
                    logger.error(f"Listener error: {e}")

        async def listen_for_task_changes():
            """Listen for task changes from other instances"""
            await conn.execute("LISTEN task_changes")
            while True:
                try:
                    msg = await conn.wait_for_notification()
                    data = json.loads(msg.payload)

                    # Handle task coordination
                    if data.get("assigned_agent") == self.agent_id:
                        logger.info(f"Task assigned to this agent: {data['task_id']}")

                except Exception as e:
                    logger.error(f"Task listener error: {e}")

        # Start listeners
        asyncio.create_task(listen_for_memory_changes())
        asyncio.create_task(listen_for_task_changes())

    async def store_memory_shared(
        self,
        content: str,
        importance: float,
        tags: list[str],
        metadata: dict
    ) -> dict:
        """Store memory with shared visibility"""
        self.metrics["requests"] += 1

        try:
            # Generate embedding
            embedding = get_embedding(content)

            async with self.db_pool.acquire() as conn:
                # Store memory
                memory_id = uuid4()
                await conn.execute("""
                    INSERT INTO shared_memories (
                        id, content, embedding_vector, importance,
                        agent_id, instance_id, visibility, tags, metadata
                    )
                    VALUES ($1, $2, $3::vector, $4, $5, $6, 'shared', $7, $8)
                """, memory_id, content, embedding, importance,
                    self.agent_id, self.instance_id, tags, json.dumps(metadata or {}))

                # Trigger will notify other instances automatically

                self.metrics["db_queries"] += 1

                return {
                    "memory_id": str(memory_id),
                    "status": "stored",
                    "importance": importance,
                    "shared": True
                }

        except Exception as e:
            self.metrics["errors"] += 1
            logger.error(f"Memory storage error: {e}")
            return {"error": str(e)}

    async def search_global_memories(
        self,
        query: str,
        limit: int,
        global_search: bool
    ) -> dict:
        """Search memories with multi-tier caching and vector similarity"""
        self.metrics["requests"] += 1

        # Check caches in order: hot -> primary -> secondary
        cache_key = f"search:{query}:{limit}:{global_search}"

        # Track access for hot cache promotion
        self.access_counter[cache_key] = self.access_counter.get(cache_key, 0) + 1

        # Check hot cache first (frequently accessed)
        if cache_key in self.hot_cache:
            self.metrics["cache_hits"] += 1
            self.metrics["hot_cache_hits"] += 1
            return self.hot_cache[cache_key]

        # Check primary cache (important queries)
        if cache_key in self.primary_cache:
            self.metrics["cache_hits"] += 1
            self.metrics["primary_cache_hits"] += 1
            result = self.primary_cache[cache_key]

            # Promote to hot cache if accessed frequently
            if self.access_counter[cache_key] >= 3:
                self.hot_cache[cache_key] = result

            return result

        # Check secondary cache (normal queries)
        if cache_key in self.secondary_cache:
            self.metrics["cache_hits"] += 1
            self.metrics["secondary_cache_hits"] += 1
            return self.secondary_cache[cache_key]

        self.metrics["cache_misses"] += 1

        try:
            # Generate query embedding
            query_embedding = get_embedding(query)

            async with self.db_pool.acquire() as conn:
                # Use vector similarity search
                if global_search:
                    results = await conn.fetch("""
                        SELECT id, content, importance, agent_id,
                               embedding_vector <=> $1::vector as distance
                        FROM shared_memories
                        WHERE visibility = 'shared'
                        ORDER BY embedding_vector <=> $1::vector
                        LIMIT $2
                    """, query_embedding, limit)
                else:
                    results = await conn.fetch("""
                        SELECT id, content, importance, agent_id,
                               embedding_vector <=> $1::vector as distance
                        FROM shared_memories
                        WHERE agent_id = $2
                        ORDER BY embedding_vector <=> $1::vector
                        LIMIT $3
                    """, query_embedding, self.agent_id, limit)

                self.metrics["db_queries"] += 1

                # Format results
                memories = [
                    {
                        "id": str(r["id"]),
                        "content": r["content"],
                        "importance": r["importance"],
                        "agent_id": r["agent_id"],
                        "similarity": 1.0 - r["distance"]  # Convert distance to similarity
                    }
                    for r in results
                ]

                result = {"memories": memories, "count": len(memories)}

                # Determine cache tier based on result importance
                if memories and any(m["importance"] >= 0.8 for m in memories):
                    # High importance results go to primary cache
                    self.primary_cache[cache_key] = result
                else:
                    # Normal results go to secondary cache
                    self.secondary_cache[cache_key] = result

                # Also update legacy cache reference
                self.cache[cache_key] = result

                return result

        except Exception as e:
            self.metrics["errors"] += 1
            logger.error(f"Memory search error: {e}")
            return {"error": str(e)}

    async def create_coordinated_task(
        self,
        title: str,
        description: str,
        priority: str,
        assigned_persona: str
    ) -> dict:
        """Create task with coordination support"""
        self.metrics["requests"] += 1

        try:
            async with self.db_pool.acquire() as conn:
                # Create task
                task_id = uuid4()
                await conn.execute("""
                    INSERT INTO tasks (
                        id, title, description, priority,
                        assigned_persona, status
                    )
                    VALUES ($1, $2, $3, $4, $5, 'pending')
                """, task_id, title, description, priority, assigned_persona)

                # Create coordination entry
                await conn.execute("""
                    INSERT INTO task_coordination (
                        id, task_id, assigned_agent, priority
                    )
                    VALUES ($1, $2, $3, $4)
                """, uuid4(), task_id, assigned_persona or self.agent_id,
                    {"LOW": 1, "MEDIUM": 5, "HIGH": 8, "URGENT": 10}.get(priority, 5))

                self.metrics["db_queries"] += 2

                return {
                    "task_id": str(task_id),
                    "status": "created",
                    "assigned_to": assigned_persona or self.agent_id
                }

        except Exception as e:
            self.metrics["errors"] += 1
            logger.error(f"Task creation error: {e}")
            return {"error": str(e)}

    async def get_connected_agents(self) -> dict:
        """Get status of all connected agent instances"""
        self.metrics["requests"] += 1

        try:
            async with self.db_pool.acquire() as conn:
                agents = await conn.fetch("""
                    SELECT agent_id, instance_id, hostname, status,
                           last_heartbeat, connected_at
                    FROM agent_instances
                    WHERE status = 'active'
                    ORDER BY agent_id, connected_at
                """)

                self.metrics["db_queries"] += 1

                return {
                    "agents": [
                        {
                            "agent_id": a["agent_id"],
                            "instance_id": a["instance_id"],
                            "hostname": a["hostname"],
                            "status": a["status"],
                            "uptime": str(datetime.now() - a["connected_at"])
                        }
                        for a in agents
                    ],
                    "total": len(agents),
                    "current_instance": self.instance_id
                }

        except Exception as e:
            self.metrics["errors"] += 1
            logger.error(f"Agent status error: {e}")
            return {"error": str(e)}

    async def log_sync_event(self, event_type: str, data: dict):
        """Log synchronization event for debugging"""
        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO sync_events (
                        event_type, entity_type, entity_id,
                        agent_id, instance_id, payload
                    )
                    VALUES ($1, $2, $3, $4, $5, $6)
                """, event_type, data.get("entity_type", "unknown"),
                    uuid4(), self.agent_id, self.instance_id,
                    json.dumps(data))

        except Exception as e:
            logger.error(f"Sync event logging error: {e}")

    async def cleanup(self):
        """Cleanup on shutdown"""
        try:
            # Mark instance as disconnected
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    UPDATE agent_instances
                    SET status = 'disconnected',
                        disconnected_at = NOW()
                    WHERE instance_id = $1
                """, self.instance_id)

            # Close database pool
            await self.db_pool.close()

            # Log final metrics
            logger.info(f"Final metrics: {self.metrics}")

        except Exception as e:
            logger.error(f"Cleanup error: {e}")


async def main():
    """Main entry point for MCP server"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    server = OptimizedMCPServer()

    try:
        # Initialize server
        await server.initialize()

        # Run MCP server
        await server.mcp.run()

    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        await server.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
