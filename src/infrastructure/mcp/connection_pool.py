"""Lazy Connection Pool with LRU eviction and TTL expiration.

Provides connection pooling for MCP servers with:
- Lazy loading: connections created on first use
- LRU eviction: least recently used connection evicted when pool full
- TTL expiration: idle connections closed after timeout
- Thread-safe: asyncio.Lock for concurrent access

Security Notes:
- Server IDs validated against SparseRegistryManager
- Connection timeout prevents indefinite blocking (30s default)
- Command validation delegated to SparseRegistryManager (ALLOWED_COMMANDS)
- Proper cleanup on errors (no resource leaks)
- Thread-safe operations with asyncio.Lock

Security Trust Model:
- SparseRegistryManager is the security boundary for server configs
- Server commands/args/env are validated by registry's from_dict()
- Connection pool trusts validated registry entries

Author: Metis (Implementation)
Created: 2025-12-09 (Phase 4.1: Issue #29)
Security Review: Hestia (2025-12-09) - CONDITIONAL APPROVAL
Security Fixes: Connection timeout, state validation, documentation
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

from src.infrastructure.exceptions import MCPConnectionError
from src.infrastructure.mcp.sparse_registry_manager import SparseRegistryManager

logger = logging.getLogger(__name__)


class ConnectionState(Enum):
    """Connection lifecycle states."""

    IDLE = "idle"  # Connection exists but not in use
    CONNECTING = "connecting"  # Connection being established
    ACTIVE = "active"  # Connection in use
    CLOSED = "closed"  # Connection closed


@dataclass
class PooledConnection:
    """Wrapper for managed connection with metadata.

    Attributes:
        server_id: Server identifier
        connection: MCPConnection instance (STDIOTransport or MCPClientAdapter)
        state: Current connection state
        created_at: Unix timestamp when connection created
        last_used: Unix timestamp when last accessed
        lock: Asyncio lock for thread-safe access
    """

    server_id: str
    connection: Any  # MCPConnection when active, None when closed
    state: ConnectionState
    created_at: float
    last_used: float
    lock: asyncio.Lock


class LazyConnectionPool:
    """Lazy connection pool with LRU eviction and TTL expiration.

    Features:
    - Lazy loading: connections created on first use
    - LRU eviction: least recently used connection evicted when pool full
    - TTL expiration: idle connections closed after timeout
    - Thread-safe: asyncio.Lock for concurrent access

    Example:
        >>> pool = LazyConnectionPool(registry, max_connections=10, default_ttl=300)
        >>> conn = await pool.get_connection("tmws")
        >>> # Use connection...
        >>> await pool.release_connection("tmws")
        >>> await pool.shutdown()
    """

    # Security: Connection timeout to prevent indefinite blocking
    DEFAULT_CONNECTION_TIMEOUT: int = 30

    def __init__(
        self,
        registry: SparseRegistryManager,
        max_connections: int = 10,
        default_ttl: int = 300,
        cleanup_interval: int = 60,
        connection_timeout: int = 30,
    ):
        """Initialize lazy connection pool.

        Args:
            registry: SparseRegistryManager for server validation and connection creation
            max_connections: Maximum number of connections in pool (default: 10)
            default_ttl: Default TTL for idle connections in seconds (default: 300)
            cleanup_interval: Interval for TTL cleanup task in seconds (default: 60)
            connection_timeout: Timeout for connection creation in seconds (default: 30)
        """
        self.registry = registry
        self.max_connections = max_connections
        self.default_ttl = default_ttl
        self.cleanup_interval = cleanup_interval
        self.connection_timeout = connection_timeout

        # Connection storage
        self._pool: dict[str, PooledConnection] = {}  # server_id -> PooledConnection
        self._access_times: dict[str, float] = {}  # server_id -> last_used timestamp

        # Pool-level lock for thread-safe operations
        self._pool_lock = asyncio.Lock()

        # Statistics
        self._stats = {
            "connections_created": 0,
            "connections_closed": 0,
            "evictions": 0,
            "ttl_expirations": 0,
            "cache_hits": 0,
            "cache_misses": 0,
        }

        # Cleanup task
        self._cleanup_task: asyncio.Task | None = None
        self._shutdown_event = asyncio.Event()

    async def start_cleanup_task(self) -> None:
        """Start background TTL cleanup task."""
        if self._cleanup_task is not None:
            logger.warning("Cleanup task already running")
            return

        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info(f"Started TTL cleanup task (interval: {self.cleanup_interval}s)")

    async def get_connection(self, server_id: str) -> Any:
        """Get or create connection (lazy loading).

        Args:
            server_id: Server identifier

        Returns:
            MCPConnection instance (STDIOTransport or MCPClientAdapter)

        Raises:
            MCPConnectionError: If server not found or connection fails
        """
        async with self._pool_lock:
            # Security: Validate server_id against registry
            server_entry = self.registry.get_server_config(server_id)
            if server_entry is None:
                raise MCPConnectionError(
                    f"Server not found in registry: {server_id}",
                    details={"server_id": server_id},
                )

            # Check if connection exists
            if server_id in self._pool:
                pooled_conn = self._pool[server_id]

                # Check if connection is still valid
                if pooled_conn.state in (ConnectionState.IDLE, ConnectionState.ACTIVE):
                    # Update access time (LRU tracking)
                    pooled_conn.last_used = time.time()
                    self._access_times[server_id] = pooled_conn.last_used

                    # Update state
                    pooled_conn.state = ConnectionState.ACTIVE

                    self._stats["cache_hits"] += 1
                    logger.debug(f"Reusing existing connection for {server_id}")
                    return pooled_conn.connection

                # Connection is closed, remove it
                del self._pool[server_id]
                self._access_times.pop(server_id, None)

            # Cache miss - create new connection
            self._stats["cache_misses"] += 1

            # Check pool size and evict if necessary
            if len(self._pool) >= self.max_connections:
                await self._evict_lru()

            # Create new connection
            try:
                connection = await self._create_connection(server_entry)

                # Create pooled connection wrapper
                now = time.time()
                pooled_conn = PooledConnection(
                    server_id=server_id,
                    connection=connection,
                    state=ConnectionState.ACTIVE,
                    created_at=now,
                    last_used=now,
                    lock=asyncio.Lock(),
                )

                self._pool[server_id] = pooled_conn
                self._access_times[server_id] = now

                self._stats["connections_created"] += 1
                logger.info(f"Created new connection for {server_id}")

                return connection

            except Exception as e:
                logger.error(f"Failed to create connection for {server_id}: {e}")
                raise MCPConnectionError(
                    f"Failed to create connection for {server_id}: {e}",
                    details={"server_id": server_id, "error": str(e)},
                ) from e

    async def release_connection(self, server_id: str) -> None:
        """Release connection back to pool (mark as idle).

        Args:
            server_id: Server identifier

        Raises:
            MCPConnectionError: If trying to release a closed connection
        """
        async with self._pool_lock:
            if server_id not in self._pool:
                logger.warning(f"Cannot release unknown connection: {server_id}")
                return

            pooled_conn = self._pool[server_id]

            # Security: Validate connection state before release
            if pooled_conn.state == ConnectionState.IDLE:
                logger.debug(f"Connection {server_id} already idle, skipping release")
                return
            elif pooled_conn.state == ConnectionState.CLOSED:
                raise MCPConnectionError(
                    f"Cannot release closed connection: {server_id}",
                    details={"server_id": server_id, "state": pooled_conn.state.value},
                )

            # Update state to idle
            pooled_conn.state = ConnectionState.IDLE
            pooled_conn.last_used = time.time()
            self._access_times[server_id] = pooled_conn.last_used

            logger.debug(f"Released connection for {server_id}")

    async def close_connection(self, server_id: str) -> None:
        """Explicitly close and remove connection.

        Args:
            server_id: Server identifier
        """
        async with self._pool_lock:
            if server_id not in self._pool:
                logger.warning(f"Cannot close unknown connection: {server_id}")
                return

            pooled_conn = self._pool[server_id]

            # Close connection
            await self._close_pooled_connection(pooled_conn)

            # Remove from pool
            del self._pool[server_id]
            self._access_times.pop(server_id, None)

            self._stats["connections_closed"] += 1
            logger.info(f"Closed connection for {server_id}")

    async def shutdown(self) -> None:
        """Gracefully close all connections and stop cleanup task."""
        logger.info("Shutting down connection pool...")

        # Signal shutdown
        self._shutdown_event.set()

        # Stop cleanup task
        if self._cleanup_task is not None:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

        # Close all connections
        async with self._pool_lock:
            for server_id in list(self._pool.keys()):
                pooled_conn = self._pool[server_id]
                await self._close_pooled_connection(pooled_conn)

            self._pool.clear()
            self._access_times.clear()

        logger.info("Connection pool shutdown complete")

    def get_stats(self) -> dict[str, Any]:
        """Return pool statistics.

        Returns:
            Dict with connection counts, cache hit rate, etc.
        """
        total_requests = self._stats["cache_hits"] + self._stats["cache_misses"]
        hit_rate = (
            self._stats["cache_hits"] / total_requests if total_requests > 0 else 0.0
        )

        return {
            **self._stats,
            "active_connections": len(self._pool),
            "max_connections": self.max_connections,
            "hit_rate": hit_rate,
        }

    # Private methods

    async def _create_connection(self, server_entry: Any) -> Any:
        """Create new MCP connection from server entry.

        Args:
            server_entry: ServerRegistryEntry from registry

        Returns:
            MCPConnection instance (STDIOTransport or MCPClientAdapter)

        Raises:
            MCPConnectionError: If connection creation fails or times out
        """
        from src.infrastructure.mcp.preset_config import MCPServerPreset, MCPTransportType
        from src.infrastructure.mcp.stdio_transport import STDIOTransport

        # Create preset from registry entry
        # Note: For now, we assume STDIO transport. In future, support HTTP as well.
        # Security: Command/args/env are validated by SparseRegistryManager.from_dict()
        preset = MCPServerPreset(
            name=server_entry.name,
            transport_type=MCPTransportType.STDIO,
            command=server_entry.command,
            args=server_entry.args,
            env=server_entry.env,
        )

        # Create transport and connect with timeout
        # Security: Timeout prevents indefinite blocking from malicious/broken servers
        transport = STDIOTransport(preset=preset)
        try:
            async with asyncio.timeout(self.connection_timeout):
                await transport.connect()
        except asyncio.TimeoutError:
            # Clean up partially created transport
            try:
                await transport.disconnect()
            except Exception:
                pass
            raise MCPConnectionError(
                f"Connection timeout ({self.connection_timeout}s) for {server_entry.server_id}",
                details={"server_id": server_entry.server_id, "timeout": self.connection_timeout},
            )

        return transport

    async def _close_pooled_connection(self, pooled_conn: PooledConnection) -> None:
        """Close a pooled connection.

        Args:
            pooled_conn: PooledConnection to close
        """
        try:
            if pooled_conn.connection is not None:
                # Attempt to disconnect
                if hasattr(pooled_conn.connection, "disconnect"):
                    await pooled_conn.connection.disconnect()

                pooled_conn.connection = None

            pooled_conn.state = ConnectionState.CLOSED

        except Exception as e:
            logger.warning(
                f"Error closing connection for {pooled_conn.server_id}: {e}"
            )

    async def _evict_lru(self) -> None:
        """Evict least recently used connection from pool.

        Should be called when pool is full and new connection is needed.
        """
        if not self._pool:
            return

        # Find LRU connection (idle connections preferred)
        lru_server_id = None
        lru_time = float("inf")

        for server_id, pooled_conn in self._pool.items():
            # Prefer idle connections over active ones
            if pooled_conn.state == ConnectionState.IDLE:
                access_time = self._access_times.get(server_id, 0)
                if access_time < lru_time:
                    lru_time = access_time
                    lru_server_id = server_id

        # If no idle connections, evict least recently used active connection
        if lru_server_id is None:
            lru_server_id = min(
                self._access_times.keys(),
                key=lambda k: self._access_times[k],
            )

        # Close and remove LRU connection
        pooled_conn = self._pool[lru_server_id]
        await self._close_pooled_connection(pooled_conn)

        del self._pool[lru_server_id]
        self._access_times.pop(lru_server_id, None)

        self._stats["evictions"] += 1
        logger.info(f"Evicted LRU connection: {lru_server_id}")

    async def _cleanup_expired_connections(self) -> None:
        """Remove connections that have exceeded TTL.

        This method is called periodically by the cleanup task.
        """
        async with self._pool_lock:
            now = time.time()
            expired_server_ids = []

            for server_id, pooled_conn in self._pool.items():
                # Only check idle connections
                if pooled_conn.state != ConnectionState.IDLE:
                    continue

                # Check if connection has exceeded TTL
                idle_time = now - pooled_conn.last_used
                if idle_time > self.default_ttl:
                    expired_server_ids.append(server_id)

            # Close expired connections
            for server_id in expired_server_ids:
                pooled_conn = self._pool[server_id]
                await self._close_pooled_connection(pooled_conn)

                del self._pool[server_id]
                self._access_times.pop(server_id, None)

                self._stats["ttl_expirations"] += 1
                logger.info(f"Closed expired connection: {server_id}")

            if expired_server_ids:
                logger.info(f"TTL cleanup: removed {len(expired_server_ids)} connections")

    async def _cleanup_loop(self) -> None:
        """Background task for periodic TTL cleanup."""
        logger.info("TTL cleanup loop started")

        try:
            while not self._shutdown_event.is_set():
                # Wait for cleanup interval or shutdown
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(),
                        timeout=self.cleanup_interval,
                    )
                    # Shutdown event was set
                    break
                except asyncio.TimeoutError:
                    # Timeout reached, perform cleanup
                    pass

                # Perform TTL cleanup
                try:
                    await self._cleanup_expired_connections()
                except Exception as e:
                    logger.error(f"Error during TTL cleanup: {e}", exc_info=True)

        except asyncio.CancelledError:
            logger.info("TTL cleanup loop cancelled")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in cleanup loop: {e}", exc_info=True)
        finally:
            logger.info("TTL cleanup loop stopped")
