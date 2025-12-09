"""Unit tests for LazyConnectionPool.

Tests:
1. Lazy connection creation
2. LRU eviction when pool full
3. TTL expiration
4. Thread safety (concurrent access)
5. Error handling

Author: Metis (Testing)
Created: 2025-12-09 (Phase 4.1: Issue #29)
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.infrastructure.exceptions import MCPConnectionError
from src.infrastructure.mcp.connection_pool import (
    ConnectionState,
    LazyConnectionPool,
)
from src.models.registry import ServerRegistryEntry, ToolCategory


@pytest.fixture
def mock_registry():
    """Create mock SparseRegistryManager."""
    registry = MagicMock()

    # Mock server entry
    server_entry = ServerRegistryEntry(
        server_id="test-server",
        name="Test Server",
        command="python",
        args=["-m", "test.server"],
        category=ToolCategory.MEMORY,
    )

    registry.get_server_config = MagicMock(return_value=server_entry)
    return registry


@pytest.fixture
def mock_transport():
    """Create mock STDIOTransport."""
    transport = AsyncMock()
    transport.connect = AsyncMock()
    transport.disconnect = AsyncMock()
    transport.is_connected = True
    return transport


@pytest.fixture
async def connection_pool(mock_registry):
    """Create LazyConnectionPool for testing."""
    pool = LazyConnectionPool(
        registry=mock_registry,
        max_connections=3,  # Small pool for testing
        default_ttl=2,  # Short TTL for testing
        cleanup_interval=1,  # Short cleanup interval
    )
    yield pool
    # Cleanup
    await pool.shutdown()


class TestLazyConnectionCreation:
    """Test lazy connection creation."""

    @pytest.mark.asyncio
    async def test_connection_created_on_first_access(
        self, connection_pool, mock_registry, mock_transport
    ):
        """Test that connection is created only when first accessed."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport",
            return_value=mock_transport,
        ):
            # Initially no connections
            assert len(connection_pool._pool) == 0

            # First access creates connection
            conn = await connection_pool.get_connection("test-server")
            assert conn is not None
            assert len(connection_pool._pool) == 1

            # Verify connection was created
            assert connection_pool._stats["connections_created"] == 1
            assert connection_pool._stats["cache_misses"] == 1

    @pytest.mark.asyncio
    async def test_existing_connection_reused(
        self, connection_pool, mock_registry, mock_transport
    ):
        """Test that existing connection is reused instead of creating new one."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport",
            return_value=mock_transport,
        ):
            # First access
            conn1 = await connection_pool.get_connection("test-server")

            # Second access should reuse
            conn2 = await connection_pool.get_connection("test-server")

            assert conn1 is conn2
            assert len(connection_pool._pool) == 1
            assert connection_pool._stats["connections_created"] == 1
            assert connection_pool._stats["cache_hits"] == 1

    @pytest.mark.asyncio
    async def test_server_not_found_raises_error(self, connection_pool):
        """Test that accessing unknown server raises MCPConnectionError."""
        # Mock registry returns None for unknown server
        connection_pool.registry.get_server_config = MagicMock(return_value=None)

        with pytest.raises(MCPConnectionError, match="Server not found"):
            await connection_pool.get_connection("unknown-server")

    @pytest.mark.asyncio
    async def test_connection_creation_failure_raises_error(
        self, connection_pool, mock_registry
    ):
        """Test that connection creation failure raises MCPConnectionError."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport"
        ) as mock_transport_class:
            # Simulate connection failure
            mock_transport_class.return_value.connect = AsyncMock(
                side_effect=Exception("Connection failed")
            )

            with pytest.raises(MCPConnectionError, match="Failed to create connection"):
                await connection_pool.get_connection("test-server")


class TestLRUEviction:
    """Test LRU eviction when pool is full."""

    @pytest.mark.asyncio
    async def test_lru_eviction_when_pool_full(
        self, connection_pool, mock_registry, mock_transport
    ):
        """Test that least recently used connection is evicted when pool is full."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport",
            return_value=mock_transport,
        ):
            # Create 3 servers in registry (pool max is 3)
            servers = {
                f"server-{i}": ServerRegistryEntry(
                    server_id=f"server-{i}",
                    name=f"Server {i}",
                    command="python",
                    args=["-m", "test.server"],
                    category=ToolCategory.MEMORY,
                )
                for i in range(4)
            }
            mock_registry.get_server_config = lambda sid: servers.get(sid)

            # Fill pool to capacity
            await connection_pool.get_connection("server-0")
            await connection_pool.get_connection("server-1")
            await connection_pool.get_connection("server-2")

            assert len(connection_pool._pool) == 3

            # Release server-0 to make it idle (LRU candidate)
            await connection_pool.release_connection("server-0")

            # Add 4th connection - should evict server-0 (LRU idle)
            await connection_pool.get_connection("server-3")

            assert len(connection_pool._pool) == 3
            assert "server-0" not in connection_pool._pool
            assert "server-3" in connection_pool._pool

            # Verify eviction stat
            assert connection_pool._stats["evictions"] == 1

    @pytest.mark.asyncio
    async def test_idle_connections_evicted_before_active(
        self, connection_pool, mock_registry, mock_transport
    ):
        """Test that idle connections are evicted before active ones."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport",
            return_value=mock_transport,
        ):
            servers = {
                f"server-{i}": ServerRegistryEntry(
                    server_id=f"server-{i}",
                    name=f"Server {i}",
                    command="python",
                    args=["-m", "test.server"],
                    category=ToolCategory.MEMORY,
                )
                for i in range(4)
            }
            mock_registry.get_server_config = lambda sid: servers.get(sid)

            # Fill pool
            await connection_pool.get_connection("server-0")
            await connection_pool.get_connection("server-1")
            await connection_pool.get_connection("server-2")

            # Release server-1 (make it idle)
            await connection_pool.release_connection("server-1")

            # Add 4th connection - should evict idle server-1
            await connection_pool.get_connection("server-3")

            assert "server-1" not in connection_pool._pool
            assert "server-0" in connection_pool._pool  # Active
            assert "server-2" in connection_pool._pool  # Active


class TestTTLExpiration:
    """Test TTL expiration of idle connections."""

    @pytest.mark.asyncio
    async def test_expired_connections_removed_by_cleanup(
        self, connection_pool, mock_registry, mock_transport
    ):
        """Test that expired idle connections are removed by cleanup task."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport",
            return_value=mock_transport,
        ):
            # Create connection
            await connection_pool.get_connection("test-server")
            await connection_pool.release_connection("test-server")

            # Start cleanup task
            await connection_pool.start_cleanup_task()

            # Connection should exist initially
            assert "test-server" in connection_pool._pool

            # Wait for TTL to expire (TTL=2s, cleanup_interval=1s)
            await asyncio.sleep(3)

            # Connection should be removed
            assert "test-server" not in connection_pool._pool
            assert connection_pool._stats["ttl_expirations"] >= 1

    @pytest.mark.asyncio
    async def test_active_connections_not_expired(
        self, connection_pool, mock_registry, mock_transport
    ):
        """Test that active connections are not expired even if old."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport",
            return_value=mock_transport,
        ):
            # Create connection (active)
            await connection_pool.get_connection("test-server")

            # Start cleanup task
            await connection_pool.start_cleanup_task()

            # Wait longer than TTL
            await asyncio.sleep(3)

            # Active connection should still exist
            assert "test-server" in connection_pool._pool
            assert connection_pool._stats["ttl_expirations"] == 0

    @pytest.mark.asyncio
    async def test_manual_cleanup_removes_expired(
        self, connection_pool, mock_registry, mock_transport
    ):
        """Test manual cleanup of expired connections."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport",
            return_value=mock_transport,
        ):
            # Create and release connection
            await connection_pool.get_connection("test-server")
            await connection_pool.release_connection("test-server")

            # Manually set last_used to past
            pooled_conn = connection_pool._pool["test-server"]
            pooled_conn.last_used = time.time() - 10  # 10 seconds ago

            # Run cleanup manually
            await connection_pool._cleanup_expired_connections()

            # Connection should be removed
            assert "test-server" not in connection_pool._pool


class TestThreadSafety:
    """Test thread safety with concurrent access."""

    @pytest.mark.asyncio
    async def test_concurrent_get_connection(
        self, connection_pool, mock_registry, mock_transport
    ):
        """Test concurrent get_connection calls are thread-safe."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport",
            return_value=mock_transport,
        ):
            # Simulate concurrent access to same server
            tasks = [
                connection_pool.get_connection("test-server") for _ in range(10)
            ]

            results = await asyncio.gather(*tasks)

            # All should return same connection
            assert all(r is results[0] for r in results)

            # Only one connection created
            assert len(connection_pool._pool) == 1
            assert connection_pool._stats["connections_created"] == 1

    @pytest.mark.asyncio
    async def test_concurrent_different_servers(
        self, connection_pool, mock_registry, mock_transport
    ):
        """Test concurrent access to different servers."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport",
            return_value=mock_transport,
        ):
            servers = {
                f"server-{i}": ServerRegistryEntry(
                    server_id=f"server-{i}",
                    name=f"Server {i}",
                    command="python",
                    args=["-m", "test.server"],
                    category=ToolCategory.MEMORY,
                )
                for i in range(3)
            }
            mock_registry.get_server_config = lambda sid: servers.get(sid)

            # Concurrent access to different servers
            tasks = [
                connection_pool.get_connection(f"server-{i}") for i in range(3)
            ]

            await asyncio.gather(*tasks)

            # All 3 connections created
            assert len(connection_pool._pool) == 3


class TestConnectionLifecycle:
    """Test connection lifecycle management."""

    @pytest.mark.asyncio
    async def test_release_connection(
        self, connection_pool, mock_registry, mock_transport
    ):
        """Test releasing connection back to pool."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport",
            return_value=mock_transport,
        ):
            # Create connection (active)
            await connection_pool.get_connection("test-server")
            pooled_conn = connection_pool._pool["test-server"]
            assert pooled_conn.state == ConnectionState.ACTIVE

            # Release connection
            await connection_pool.release_connection("test-server")
            assert pooled_conn.state == ConnectionState.IDLE

    @pytest.mark.asyncio
    async def test_close_connection(
        self, connection_pool, mock_registry, mock_transport
    ):
        """Test explicitly closing connection."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport",
            return_value=mock_transport,
        ):
            # Create connection
            await connection_pool.get_connection("test-server")
            assert len(connection_pool._pool) == 1

            # Close connection
            await connection_pool.close_connection("test-server")
            assert len(connection_pool._pool) == 0
            assert connection_pool._stats["connections_closed"] == 1

    @pytest.mark.asyncio
    async def test_shutdown_closes_all_connections(
        self, mock_registry, mock_transport
    ):
        """Test that shutdown closes all connections."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport",
            return_value=mock_transport,
        ):
            pool = LazyConnectionPool(
                registry=mock_registry,
                max_connections=3,
            )

            servers = {
                f"server-{i}": ServerRegistryEntry(
                    server_id=f"server-{i}",
                    name=f"Server {i}",
                    command="python",
                    args=["-m", "test.server"],
                    category=ToolCategory.MEMORY,
                )
                for i in range(3)
            }
            mock_registry.get_server_config = lambda sid: servers.get(sid)

            # Create multiple connections
            for i in range(3):
                await pool.get_connection(f"server-{i}")

            assert len(pool._pool) == 3

            # Shutdown
            await pool.shutdown()

            # All connections closed
            assert len(pool._pool) == 0


class TestStatistics:
    """Test pool statistics."""

    @pytest.mark.asyncio
    async def test_get_stats(self, connection_pool, mock_registry, mock_transport):
        """Test get_stats returns correct statistics."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport",
            return_value=mock_transport,
        ):
            # Create connection
            await connection_pool.get_connection("test-server")

            # Get another (cache hit)
            await connection_pool.get_connection("test-server")

            stats = connection_pool.get_stats()

            assert stats["connections_created"] == 1
            assert stats["cache_hits"] == 1
            assert stats["cache_misses"] == 1
            assert stats["active_connections"] == 1
            assert stats["max_connections"] == 3
            assert stats["hit_rate"] == 0.5  # 1 hit / 2 requests

    @pytest.mark.asyncio
    async def test_stats_after_eviction(
        self, connection_pool, mock_registry, mock_transport
    ):
        """Test statistics after LRU eviction."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport",
            return_value=mock_transport,
        ):
            servers = {
                f"server-{i}": ServerRegistryEntry(
                    server_id=f"server-{i}",
                    name=f"Server {i}",
                    command="python",
                    args=["-m", "test.server"],
                    category=ToolCategory.MEMORY,
                )
                for i in range(4)
            }
            mock_registry.get_server_config = lambda sid: servers.get(sid)

            # Fill pool and trigger eviction
            for i in range(3):
                await connection_pool.get_connection(f"server-{i}")
                await connection_pool.release_connection(f"server-{i}")

            await connection_pool.get_connection("server-3")

            stats = connection_pool.get_stats()
            assert stats["evictions"] == 1


class TestErrorHandling:
    """Test error handling scenarios."""

    @pytest.mark.asyncio
    async def test_release_unknown_connection_warning(
        self, connection_pool, caplog
    ):
        """Test warning when releasing unknown connection."""
        await connection_pool.release_connection("unknown-server")
        assert "Cannot release unknown connection" in caplog.text

    @pytest.mark.asyncio
    async def test_close_unknown_connection_warning(
        self, connection_pool, caplog
    ):
        """Test warning when closing unknown connection."""
        await connection_pool.close_connection("unknown-server")
        assert "Cannot close unknown connection" in caplog.text

    @pytest.mark.asyncio
    async def test_disconnect_error_handled_gracefully(
        self, connection_pool, mock_registry
    ):
        """Test that errors during disconnect are handled gracefully."""
        with patch(
            "src.infrastructure.mcp.stdio_transport.STDIOTransport"
        ) as mock_transport_class:
            # Create mock that fails on disconnect
            failing_transport = AsyncMock()
            failing_transport.connect = AsyncMock()
            failing_transport.disconnect = AsyncMock(
                side_effect=Exception("Disconnect failed")
            )
            mock_transport_class.return_value = failing_transport

            # Create connection
            await connection_pool.get_connection("test-server")

            # Close should handle error gracefully
            await connection_pool.close_connection("test-server")

            # Connection removed despite error
            assert "test-server" not in connection_pool._pool
