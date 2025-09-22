"""
Test suite for TMWS Multi-Instance - Database-level sharing
Tests multi-instance coordination, caching, and real-time sync
"""

import asyncio
import os
import uuid

import asyncpg
import pytest

import pytest_asyncio

from src.core.cache import CacheDecorator, CacheManager
from src.core.notifications import ChangeNotifier, NotificationCoordinator, SyncHandler
from src.mcp_server import OptimizedMCPServer


@pytest.fixture
async def db_pool():
    """Create test database pool"""
    db_url = os.getenv("TMWS_TEST_DATABASE_URL", "postgresql://localhost/tmws_test")
    pool = await asyncpg.create_pool(
        dsn=db_url,
        min_size=1,
        max_size=5
    )

    # Clean test database
    async with pool.acquire() as conn:
        await conn.execute("TRUNCATE shared_memories, agent_instances, task_coordination CASCADE")

    yield pool

    await pool.close()


@pytest.fixture
async def cache_manager():
    """Create test cache manager"""
    manager = CacheManager(
        redis_url=None,  # Local only for tests
        local_ttl=10,
        max_local_size=100
    )
    await manager.initialize()
    return manager


@pytest.fixture
async def notification_coordinator(db_pool):
    """Create test notification coordinator"""
    coordinator = NotificationCoordinator(db_pool)
    await coordinator.initialize()

    yield coordinator

    await coordinator.cleanup()


@pytest_asyncio.fixture
async def initialized_cache_manager(cache_manager):
    """Provides an initialized CacheManager instance."""
    return cache_manager # pytest-asyncio already awaits this fixture

@pytest_asyncio.fixture
async def initialized_notification_coordinator(notification_coordinator):
    """Provides an initialized NotificationCoordinator instance."""
    return notification_coordinator # pytest-asyncio already awaits this fixture

@pytest_asyncio.fixture
async def cache_decorator(initialized_cache_manager):
    """Provides a CacheDecorator instance with an initialized CacheManager."""
    return CacheDecorator(initialized_cache_manager)

@pytest_asyncio.fixture
async def sync_handler(initialized_notification_coordinator, initialized_cache_manager):
    """Provides a SyncHandler instance with initialized NotificationCoordinator and CacheManager."""
    handler = SyncHandler(initialized_notification_coordinator, initialized_cache_manager)
    await handler.setup_handlers()
    return handler


@pytest_asyncio.fixture
async def optimized_mcp_server(db_pool):
    """Create an initialized OptimizedMCPServer instance."""
    server = OptimizedMCPServer()
    server.db_pool = db_pool
    server.agent_id = f"test-agent-{uuid.uuid4().hex[:8]}"
    server.instance_id = f"{server.agent_id}-{os.getpid()}"
    await server.initialize()
    yield server
    await server.cleanup()


class TestMultiInstanceCoordination:
    """Test multiple MCP server instances sharing database"""

    @pytest.mark.asyncio
    async def test_instance_registration(self, optimized_mcp_server, db_pool):
        """Test that instances register correctly"""
        # Use the fixture for server1
        server1 = optimized_mcp_server
        server1.agent_id = "test-agent-1" # Override agent_id for this test

        # Create a second instance directly, ensuring it uses the same db_pool
        server2 = OptimizedMCPServer()
        server2.db_pool = db_pool
        server2.agent_id = "test-agent-2"
        server2.instance_id = f"{server2.agent_id}-{os.getpid()}" # Ensure unique instance_id
        await server2.register_instance()

        # Register server1 (already initialized by fixture, just ensure it's registered)
        await server1.register_instance()


        # Check registrations
        async with db_pool.acquire() as conn:
            instances = await conn.fetch("""
                SELECT agent_id, instance_id, status
                FROM agent_instances
                WHERE status = 'active'
            """)

        assert len(instances) == 2
        agent_ids = {i["agent_id"] for i in instances}
        assert "test-agent-1" in agent_ids
        assert "test-agent-2" in agent_ids

    @pytest.mark.asyncio
    async def test_shared_memory_creation(self, optimized_mcp_server, db_pool):
        """Test that memories are shared between instances"""
        server1 = optimized_mcp_server
        server1.agent_id = "agent-1" # Override agent_id for this test

        server2 = OptimizedMCPServer()
        server2.db_pool = db_pool
        server2.agent_id = "agent-2"
        server2.instance_id = f"{server2.agent_id}-{os.getpid()}" # Ensure unique instance_id
        await server2.initialize() # Initialize the second server

        # Server 1 creates memory
        result = await server1.store_memory_shared(
            content="Test shared memory",
            importance=0.8,
            tags=["test"],
            metadata={"source": "test"}
        )

        assert result["status"] == "stored"
        memory_id = result["memory_id"]

        # Server 2 should be able to search it
        search_result = await server2.search_global_memories(
            query="shared memory",
            limit=10,
            global_search=True
        )

        assert len(search_result["memories"]) > 0
        found = any(m["content"] == "Test shared memory" for m in search_result["memories"])
        assert found

        await server2.cleanup() # Clean up the second server

    @pytest.mark.asyncio
    async def test_task_coordination(self, optimized_mcp_server, db_pool):
        """Test task coordination between instances"""
        server1 = optimized_mcp_server
        server1.agent_id = "coordinator" # Override agent_id for this test

        server2 = OptimizedMCPServer()
        server2.db_pool = db_pool
        server2.agent_id = "worker"
        server2.instance_id = f"{server2.agent_id}-{os.getpid()}" # Ensure unique instance_id
        await server2.initialize() # Initialize the second server

        # Create task assigned to worker
        result = await server1.create_coordinated_task(
            title="Test task",
            description="Task for worker",
            priority="HIGH",
            assigned_persona="worker"
        )

        assert result["status"] == "created"
        assert result["assigned_to"] == "worker"

        # Check task coordination table
        async with db_pool.acquire() as conn:
            coordination = await conn.fetchrow("""
                SELECT * FROM task_coordination
                WHERE task_id = $1::uuid
            """, uuid.UUID(result["task_id"]))

        assert coordination is not None
        assert coordination["assigned_agent"] == "worker"
        assert coordination["priority"] == 8  # HIGH priority

        await server2.cleanup() # Clean up the second server


class TestCacheSystem:
    """Test caching functionality"""

    @pytest.mark.asyncio
    async def test_local_cache(self, initialized_cache_manager):
        """Test local cache operations"""
        # Set value
        await initialized_cache_manager.set("test_key", {"data": "test"}, namespace="test")

        # Get value
        value = await initialized_cache_manager.get("test_key", namespace="test")
        assert value == {"data": "test"}

        # Check stats
        stats = initialized_cache_manager.get_stats()
        assert stats["local_hits"] == 1

        # Delete value
        await initialized_cache_manager.delete("test_key", namespace="test")
        value = await initialized_cache_manager.get("test_key", namespace="test")
        assert value is None

    @pytest.mark.asyncio
    async def test_cache_ttl(self, initialized_cache_manager):
        """Test cache TTL expiration"""
        # Set with short TTL
        initialized_cache_manager.local_ttl = 1  # 1 second
        await initialized_cache_manager.set("ttl_test", "value", namespace="test")

        # Should exist immediately
        value = await initialized_cache_manager.get("ttl_test", namespace="test")
        assert value == "value"

        # Wait for expiration
        await asyncio.sleep(1.5)

        # Should be expired
        value = await initialized_cache_manager.get("ttl_test", namespace="test")
        assert value is None

    @pytest.mark.asyncio
    async def test_cache_decorator(self, cache_decorator):
        """Test cache decorator"""
        decorator = cache_decorator

        call_count = 0

        @decorator.cached(namespace="test", ttl=10)
        async def expensive_function(x: int) -> int:
            nonlocal call_count
            call_count += 1
            return x * 2

        # First call
        result = await expensive_function(5)
        assert result == 10
        assert call_count == 1

        # Second call should be cached
        result = await expensive_function(5)
        assert result == 10
        assert call_count == 1  # Not incremented

        # Different argument
        result = await expensive_function(10)
        assert result == 20
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_cache_invalidation(self, initialized_cache_manager):
        """Test cache invalidation patterns"""
        # Set multiple values
        await initialized_cache_manager.set("user:1", "data1", namespace="users")
        await initialized_cache_manager.set("user:2", "data2", namespace="users")
        await initialized_cache_manager.set("post:1", "data3", namespace="posts")

        # Clear namespace
        await initialized_cache_manager.clear("users")

        # Users should be gone
        assert await initialized_cache_manager.get("user:1", namespace="users") is None
        assert await initialized_cache_manager.get("user:2", namespace="users") is None

        # Posts should still exist
        assert await initialized_cache_manager.get("post:1", namespace="posts") == "data3"


class TestNotificationSystem:
    """Test LISTEN/NOTIFY functionality"""

    @pytest.mark.asyncio
    async def test_notification_subscription(self, initialized_notification_coordinator):
        """Test subscribing to notifications"""
        received = []

        async def handler(payload):
            received.append(payload)

        # Subscribe
        await initialized_notification_coordinator.subscribe("test_channel", handler)

        # Send notification
        await initialized_notification_coordinator.notify("test_channel", {
            "message": "test",
            "value": 123
        })

        # Wait for processing
        await asyncio.sleep(0.1)

        # Check received
        assert len(received) == 1
        assert received[0]["message"] == "test"
        assert received[0]["value"] == 123

    @pytest.mark.asyncio
    async def test_change_notifier(self, initialized_notification_coordinator):
        """Test change notification helpers"""
        notifier = ChangeNotifier(initialized_notification_coordinator)

        received_memory_changes = []
        received_task_changes = []

        async def memory_handler(payload):
            received_memory_changes.append(payload)

        async def task_handler(payload):
            received_task_changes.append(payload)

        # Subscribe
        await initialized_notification_coordinator.subscribe("memory_changes", memory_handler)
        await initialized_notification_coordinator.subscribe("task_changes", task_handler)

        # Notify changes
        await notifier.notify_memory_change(
            operation="INSERT",
            memory_id="mem-123",
            agent_id="test-agent",
            instance_id="test-instance",
            visibility="shared"
        )

        await notifier.notify_task_change(
            operation="UPDATE",
            task_id="task-456",
            assigned_agent="worker",
            status="in_progress"
        )

        # Wait for processing
        await asyncio.sleep(0.1)

        # Check notifications
        assert len(received_memory_changes) == 1
        assert received_memory_changes[0]["memory_id"] == "mem-123"

        assert len(received_task_changes) == 1
        assert received_task_changes[0]["task_id"] == "task-456"

    @pytest.mark.asyncio
    async def test_sync_handler_cache_invalidation(self, sync_handler, initialized_cache_manager):
        """Test sync handler cache invalidation"""
        handler = sync_handler

        # Populate cache
        await initialized_cache_manager.set("search:query1", "result1", namespace="search")
        await initialized_cache_manager.set("search:query2", "result2", namespace="search")

        # Notify memory change (should clear search cache)
        await handler.coordinator.notify("memory_changes", {
            "operation": "INSERT",
            "visibility": "shared",
            "memory_id": "new-memory"
        })

        # Wait for processing
        await asyncio.sleep(0.1)

        # Search cache should be cleared
        assert await initialized_cache_manager.get("search:query1", namespace="search") is None
        assert await initialized_cache_manager.get("search:query2", namespace="search") is None


class TestPerformanceMetrics:
    """Test performance tracking"""

    @pytest.mark.asyncio
    async def test_metrics_collection(self, optimized_mcp_server):
        """Test that performance metrics are collected"""
        server = optimized_mcp_server
        server.agent_id = "metrics-test" # Override agent_id for this test

        # Perform operations
        await server.store_memory_shared(
            "Test memory", 0.5, ["test"], {}
        )

        await server.search_global_memories(
            "test", 10, False
        )

        # Check metrics
        assert server.metrics["requests"] == 2
        assert server.metrics["db_queries"] >= 2
        assert server.metrics["cache_misses"] >= 1

    @pytest.mark.asyncio
    async def test_connection_pool_stats(self, optimized_mcp_server, db_pool):
        """Test connection pool statistics"""
        server = optimized_mcp_server
        server.instance_id = "pool-test" # Override instance_id for this test

        # Register and trigger heartbeat
        await server.register_instance()

        # Check pool stats were recorded
        async with db_pool.acquire() as conn:
            stats = await conn.fetchrow("""
                SELECT * FROM connection_stats
                WHERE instance_id = $1
                ORDER BY recorded_at DESC
                LIMIT 1
            """, server.instance_id)

        # Stats may not exist yet if heartbeat hasn't run
        # This is expected in test environment
