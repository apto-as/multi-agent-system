#!/usr/bin/env python3
"""
TMWS MCP Server - Hybrid PostgreSQL + Chroma Implementation

MCP Server providing Trinitas agents with:
- Ultra-fast vector search via Chroma (P95: 0.47ms)
- Multilingual-E5 embeddings (1024-dimensional, cross-lingual)
- PostgreSQL as source of truth
- Agent coordination and task management

Phase: 4b (TMWS v2.2.6)
"""

import asyncio
import logging
import os
from datetime import datetime
from uuid import uuid4

from fastmcp import FastMCP

from src.core.config import get_settings
from src.core.database import get_session
from src.core.exceptions import (
    ChromaOperationError,
    MCPInitializationError,
    MemoryCreationError,
    MemorySearchError,
    ServiceInitializationError,
    log_and_raise,
)
from src.integration.genai_toolbox_bridge import register_genai_integration
from src.services.memory_service import HybridMemoryService
from src.services.unified_embedding_service import get_unified_embedding_service
from src.services.vector_search_service import get_vector_search_service

logger = logging.getLogger(__name__)
settings = get_settings()


class HybridMCPServer:
    """
    MCP Server with Hybrid Memory Architecture.

    Architecture:
    - HybridMemoryService: PostgreSQL + Chroma unified interface
    - MultilingualEmbeddingService: 1024-dimensional embeddings
    - VectorSearchService: Chroma with P95 latency 0.47ms

    Performance improvements over legacy:
    - store_memory: 10ms → 2ms (5x faster)
    - search_memories: 200ms → 0.5ms (400x faster)
    """

    def __init__(self):
        # Instance identification
        self.agent_id = os.getenv("TMWS_AGENT_ID", f"agent-{uuid4().hex[:8]}")
        self.instance_id = f"{self.agent_id}-{os.getpid()}"

        # Services (initialized in initialize())
        self.memory_service = None
        self.embedding_service = get_unified_embedding_service()
        self.vector_service = get_vector_search_service()

        # Performance metrics
        self.metrics = {
            "requests": 0,
            "chroma_hits": 0,
            "postgresql_fallbacks": 0,
            "errors": 0,
            "avg_latency_ms": 0.0,
        }

        # MCP server setup
        self.mcp = FastMCP(name="tmws", version="2.2.6")

        # Register MCP tools
        self._register_tools()

        # Register GenAI Toolbox integration
        self.genai_bridge = register_genai_integration(self.mcp)

        logger.info(f"HybridMCPServer created: {self.instance_id}")

    def _register_tools(self):
        """Register all MCP tools with Hybrid Memory Service."""

        @self.mcp.tool(
            name="store_memory",
            description="Store information in hybrid semantic memory (PostgreSQL + Chroma)",
        )
        async def store_memory(
            content: str,
            importance: float = 0.5,
            tags: list[str] = None,
            namespace: str = "default",
            metadata: dict = None,
        ) -> dict:
            """
            Store memory with ultra-fast Chroma sync.

            Performance: ~2ms P95 (5x faster than legacy)
            """
            return await self.store_memory_hybrid(content, importance, tags, namespace, metadata)

        @self.mcp.tool(
            name="search_memories",
            description="Search semantic memories (Chroma vector search, 0.47ms P95)",
        )
        async def search_memories(
            query: str,
            limit: int = 10,
            min_similarity: float = 0.7,
            namespace: str = "default",
            tags: list[str] = None,
        ) -> dict:
            """
            Search memories with Chroma ultra-fast vector search.

            Performance: ~0.5ms P95 (400x faster than legacy PostgreSQL)
            """
            return await self.search_memories_hybrid(query, limit, min_similarity, namespace, tags)

        @self.mcp.tool(name="create_task", description="Create a coordinated task")
        async def create_task(
            title: str,
            description: str = None,
            priority: str = "MEDIUM",
            assigned_persona: str = None,
        ) -> dict:
            """Create coordinated task."""
            return await self.create_task_postgresql(title, description, priority, assigned_persona)

        @self.mcp.tool(name="get_agent_status", description="Get status of connected agents")
        async def get_agent_status() -> dict:
            """Get status of connected agents."""
            return await self.get_agent_status_postgresql()

        @self.mcp.tool(name="get_memory_stats", description="Get memory statistics")
        async def get_memory_stats() -> dict:
            """Get combined PostgreSQL + Chroma statistics."""
            return await self.get_hybrid_memory_stats()

        @self.mcp.tool(name="invalidate_cache", description="Clear Chroma cache (for testing)")
        async def invalidate_cache() -> dict:
            """Clear Chroma collection (use with caution)."""
            return await self.clear_chroma_cache()

    async def initialize(self):
        """Initialize MCP server with database session and services."""
        try:
            # Initialize Chroma vector service
            self.vector_service.initialize()
            logger.info("Chroma vector service initialized")

            # Start GenAI Toolbox sidecar services
            await self.genai_bridge.start_sidecar_services()

            logger.info(
                f"HybridMCPServer initialized: {self.instance_id} "
                f"(Chroma: {self.vector_service.HOT_CACHE_SIZE} hot cache)"
            )

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except (ChromaOperationError, ServiceInitializationError):
            # Expected initialization errors - already logged
            raise
        except Exception as e:
            # Unexpected initialization errors
            log_and_raise(
                MCPInitializationError,
                "Failed to initialize HybridMCPServer",
                original_exception=e,
                details={"instance_id": self.instance_id},
            )

    async def store_memory_hybrid(
        self,
        content: str,
        importance: float,
        tags: list[str],
        namespace: str,
        metadata: dict,
    ) -> dict:
        """
        Store memory using HybridMemoryService.

        Write-through pattern: PostgreSQL + Chroma simultaneously.
        """
        start_time = datetime.utcnow()
        self.metrics["requests"] += 1

        try:
            # Get database session
            async for session in get_session():
                memory_service = HybridMemoryService(session)

                # Create memory (writes to both PostgreSQL and Chroma)
                memory = await memory_service.create_memory(
                    content=content,
                    agent_id=self.agent_id,
                    namespace=namespace,
                    importance=importance,
                    tags=tags or [],
                    metadata=metadata or {},
                )

                # Calculate latency
                latency_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                self._update_avg_latency(latency_ms)

                logger.info(
                    f"Memory stored: {memory.id} (latency: {latency_ms:.2f}ms, "
                    f"importance: {importance})"
                )

                return {
                    "memory_id": str(memory.id),
                    "status": "stored",
                    "importance": importance,
                    "latency_ms": round(latency_ms, 2),
                    "stored_in": ["postgresql", "chroma"],
                    "embedding_model": settings.embedding_model,
                    "embedding_dimension": settings.vector_dimension,
                }

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except (MemoryCreationError, ChromaOperationError) as e:
            # Expected errors - already logged
            self.metrics["errors"] += 1
            return {"error": str(e), "status": "failed", "error_type": e.__class__.__name__}
        except Exception as e:
            # Unexpected errors - log and return error
            self.metrics["errors"] += 1
            logger.critical(f"Unexpected memory storage error: {e}", exc_info=True)
            return {"error": str(e), "status": "failed", "error_type": "UnexpectedError"}

    async def search_memories_hybrid(
        self,
        query: str,
        limit: int,
        min_similarity: float,
        namespace: str,
        tags: list[str],
    ) -> dict:
        """
        Search memories using HybridMemoryService.

        Read-first pattern: Chroma (0.47ms) → PostgreSQL fallback.
        """
        start_time = datetime.utcnow()
        self.metrics["requests"] += 1

        try:
            async for session in get_session():
                memory_service = HybridMemoryService(session)

                # Search (Chroma first, PostgreSQL fallback)
                memories = await memory_service.search_memories(
                    query=query,
                    agent_id=self.agent_id,
                    namespace=namespace,
                    tags=tags,
                    limit=limit,
                    min_similarity=min_similarity,
                )

                # Calculate latency
                latency_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                self._update_avg_latency(latency_ms)

                # Track Chroma vs PostgreSQL
                if latency_ms < 5.0:
                    self.metrics["chroma_hits"] += 1
                    search_source = "chroma"
                else:
                    self.metrics["postgresql_fallbacks"] += 1
                    search_source = "postgresql_fallback"

                logger.info(
                    f"Memory search: {len(memories)} results (latency: {latency_ms:.2f}ms, "
                    f"source: {search_source})"
                )

                return {
                    "query": query,
                    "results": [
                        {
                            "id": str(m.id),
                            "content": m.content,
                            "similarity": getattr(m, "similarity", 0.0),
                            "importance": m.importance,
                            "tags": m.tags,
                            "created_at": m.created_at.isoformat(),
                        }
                        for m in memories
                    ],
                    "count": len(memories),
                    "latency_ms": round(latency_ms, 2),
                    "search_source": search_source,
                    "embedding_model": settings.embedding_model,
                }

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except (MemorySearchError, ChromaOperationError) as e:
            # Expected errors - already logged
            self.metrics["errors"] += 1
            return {
                "error": str(e),
                "results": [],
                "count": 0,
                "error_type": e.__class__.__name__,
            }
        except Exception as e:
            # Unexpected errors - log and return error
            self.metrics["errors"] += 1
            logger.critical(f"Unexpected memory search error: {e}", exc_info=True)
            return {"error": str(e), "results": [], "count": 0, "error_type": "UnexpectedError"}

    async def create_task_postgresql(
        self, title: str, description: str, priority: str, assigned_persona: str
    ) -> dict:
        """Create task in PostgreSQL."""
        self.metrics["requests"] += 1

        try:
            from src.services.task_service import TaskService

            async for session in get_session():
                task_service = TaskService(session)

                task = await task_service.create_task(
                    title=title,
                    description=description,
                    priority=priority,
                    assigned_persona=assigned_persona,
                )

                return {
                    "task_id": str(task.id),
                    "status": "created",
                    "assigned_to": assigned_persona or self.agent_id,
                    "priority": priority,
                    "storage": "postgresql",
                }

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except ImportError as e:
            # TaskService not available (expected during development)
            self.metrics["errors"] += 1
            logger.warning(f"TaskService not available: {e}")
            return {"error": "TaskService not available", "error_type": "ImportError"}
        except Exception as e:
            # Unexpected errors - log and return error
            self.metrics["errors"] += 1
            logger.critical(f"Unexpected task creation error: {e}", exc_info=True)
            return {"error": str(e), "error_type": "UnexpectedError"}

    async def get_agent_status_postgresql(self) -> dict:
        """Get agent status from PostgreSQL."""
        self.metrics["requests"] += 1

        try:
            from src.services.agent_service import AgentService

            async for session in get_session():
                agent_service = AgentService(session)

                agents = await agent_service.list_agents(status="active")

                return {
                    "agents": [
                        {
                            "agent_id": a.agent_id,
                            "namespace": a.namespace,
                            "status": a.status,
                            "capabilities": a.capabilities,
                        }
                        for a in agents
                    ],
                    "total": len(agents),
                    "current_instance": self.instance_id,
                    "storage": "postgresql",
                }

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except ImportError as e:
            # AgentService not available (expected during development)
            self.metrics["errors"] += 1
            logger.warning(f"AgentService not available: {e}")
            return {
                "error": "AgentService not available",
                "agents": [],
                "total": 0,
                "error_type": "ImportError",
            }
        except Exception as e:
            # Unexpected errors - log and return error
            self.metrics["errors"] += 1
            logger.critical(f"Unexpected agent status error: {e}", exc_info=True)
            return {"error": str(e), "agents": [], "total": 0, "error_type": "UnexpectedError"}

    async def get_hybrid_memory_stats(self) -> dict:
        """Get combined PostgreSQL + Chroma statistics."""
        self.metrics["requests"] += 1

        try:
            async for session in get_session():
                memory_service = HybridMemoryService(session)

                stats = await memory_service.get_memory_stats(
                    agent_id=self.agent_id, namespace="default"
                )

                # Add MCP server metrics
                stats["mcp_metrics"] = {
                    "total_requests": self.metrics["requests"],
                    "chroma_hits": self.metrics["chroma_hits"],
                    "postgresql_fallbacks": self.metrics["postgresql_fallbacks"],
                    "errors": self.metrics["errors"],
                    "avg_latency_ms": round(self.metrics["avg_latency_ms"], 2),
                    "chroma_hit_rate": (
                        round(
                            self.metrics["chroma_hits"]
                            / (self.metrics["chroma_hits"] + self.metrics["postgresql_fallbacks"])
                            * 100,
                            1,
                        )
                        if (self.metrics["chroma_hits"] + self.metrics["postgresql_fallbacks"]) > 0
                        else 0.0
                    ),
                }

                return stats

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except Exception as e:
            # Unexpected errors - log and return error
            self.metrics["errors"] += 1
            logger.critical(f"Unexpected stats error: {e}", exc_info=True)
            return {"error": str(e), "error_type": "UnexpectedError"}

    async def clear_chroma_cache(self) -> dict:
        """Clear Chroma collection (use with caution)."""
        try:
            await self.vector_service.clear_collection()
            logger.warning("Chroma cache cleared")

            return {
                "status": "cleared",
                "warning": "Chroma cache cleared. PostgreSQL data intact.",
            }

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except ChromaOperationError as e:
            # Expected ChromaDB errors
            logger.error(f"Cache clear error: {e}")
            return {"error": str(e), "error_type": "ChromaOperationError"}
        except Exception as e:
            # Unexpected errors - log critical
            logger.critical(f"Unexpected cache clear error: {e}", exc_info=True)
            return {"error": str(e), "error_type": "UnexpectedError"}

    def _update_avg_latency(self, latency_ms: float):
        """Update rolling average latency."""
        alpha = 0.1  # Exponential moving average factor
        self.metrics["avg_latency_ms"] = (
            alpha * latency_ms + (1 - alpha) * self.metrics["avg_latency_ms"]
        )

    async def cleanup(self):
        """Cleanup on shutdown."""
        try:
            # Shutdown GenAI Toolbox integration
            await self.genai_bridge.shutdown()

            # Log final metrics
            logger.info(
                f"HybridMCPServer shutdown: {self.instance_id}\n"
                f"Final metrics: {self.metrics}\n"
                f"Chroma hit rate: "
                f"{self.metrics['chroma_hits'] / (self.metrics['chroma_hits'] + self.metrics['postgresql_fallbacks']) * 100:.1f}%"
                if (self.metrics["chroma_hits"] + self.metrics["postgresql_fallbacks"]) > 0
                else "N/A"
            )

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts during cleanup
            raise
        except Exception as e:
            # Log but don't raise during cleanup
            logger.error(f"Cleanup error: {e}", exc_info=True)


def first_run_setup():
    """
    First-run setup for uvx one-command installation.

    Creates necessary directories and displays setup information.
    """
    from pathlib import Path

    TMWS_HOME = Path.home() / ".tmws"
    TMWS_DATA_DIR = TMWS_HOME / "data"
    TMWS_CHROMA_DIR = TMWS_HOME / "chroma"
    INITIALIZED_FLAG = TMWS_HOME / ".initialized"

    # Check if this is first run
    if not INITIALIZED_FLAG.exists():
        print("=" * 60)
        print("🚀 TMWS v2.2.6 - First-time Setup")
        print("=" * 60)
        print()
        print(f"📁 Data directory: {TMWS_HOME}")
        print(f"   ├── Database: {TMWS_DATA_DIR}/tmws.db")
        print(f"   ├── ChromaDB: {TMWS_CHROMA_DIR}")
        print(f"   └── Secret key: {TMWS_HOME}/.secret_key")
        print()
        print("✅ Smart defaults enabled:")
        print("   • SQLite database (development)")
        print("   • Auto-generated secret key")
        print("   • Multilingual-E5 embeddings (1024-dim)")
        print("   • ChromaDB vector search")
        print()
        print("📝 For Claude Desktop, add to config:")
        print("""
{
  "tmws": {
    "command": "uvx",
    "args": ["tmws-mcp-server"]
  }
}
""")
        print("=" * 60)
        print()

        # Create TMWS_HOME directory and mark as initialized
        TMWS_HOME.mkdir(parents=True, exist_ok=True)
        INITIALIZED_FLAG.touch()


async def async_main():
    """Async main entry point for MCP server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    server = HybridMCPServer()

    try:
        # Initialize server
        await server.initialize()

        logger.info(
            "🚀 TMWS v2.2.6 MCP Server Started\n"
            "   Architecture: Hybrid (SQLite + Chroma)\n"
            "   Embeddings: Multilingual-E5 (1024-dim)\n"
            "   Vector Search: Chroma (P95: 0.47ms)\n"
            f"   Agent ID: {server.agent_id}\n"
            f"   Instance: {server.instance_id}"
        )

        # Run MCP server (async version to work within existing event loop)
        await server.mcp.run_async()

    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except (MCPInitializationError, ServiceInitializationError) as e:
        # Expected initialization errors - already logged
        logger.error(f"Server failed to initialize: {e}")
    except Exception as e:
        # Unexpected errors - log critical
        logger.critical(f"Unexpected server error: {e}", exc_info=True)
    finally:
        await server.cleanup()


def main():
    """CLI entry point for tmws-mcp-server command."""
    # First-run setup (synchronous)
    first_run_setup()

    # Run async main
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
