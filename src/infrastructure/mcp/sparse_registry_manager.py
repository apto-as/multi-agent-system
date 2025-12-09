"""Sparse Registry Manager for lazy MCP server loading.

Provides O(1) lookup for server/tool metadata without loading full schemas.
Registry stored at ~/.tmws/registry/index.json (~50 bytes per tool).

Key Features:
- O(1) server config lookup
- O(n) tool search by name/keywords
- Atomic file writes for consistency
- Thread-safe with asyncio.Lock
- Graceful fallback if registry missing/corrupt
"""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from src.models.registry import (
    RegistryMetadata,
    RegistrySecurityError,
    ServerRegistryEntry,
    SparseRegistry,
    ToolCategory,
    ToolRegistryEntry,
)

logger = logging.getLogger(__name__)

# Security: Allowed base directories for registry path
ALLOWED_REGISTRY_BASES = [
    Path("~/.tmws").expanduser().resolve(),
    Path("/tmp"),  # For testing
    Path("/private/tmp"),  # macOS symlink target
    Path("/private/var/folders"),  # macOS pytest tmp_path location
]


class SparseRegistryManager:
    """Manages sparse registry for lazy MCP server loading.

    Provides O(1) lookup for server/tool metadata without loading full schemas.
    Registry is persisted to disk and loaded on initialization.

    Example:
        >>> registry = SparseRegistryManager()
        >>> await registry.initialize()
        >>> server = registry.get_server_config("tmws")
        >>> tools = registry.search_tools("memory", category=ToolCategory.MEMORY)
        >>> await registry.update_popularity("tmws", delta=0.1)
    """

    REGISTRY_PATH = Path("~/.tmws/registry/index.json").expanduser()
    REGISTRY_VERSION = "1.0.0"

    def __init__(self, registry_path: Path | None = None):
        """Initialize sparse registry manager.

        Args:
            registry_path: Custom registry path (defaults to ~/.tmws/registry/index.json)

        Raises:
            RegistrySecurityError: If registry_path is outside allowed directories
        """
        if registry_path is not None:
            # Security: Validate path is within allowed directories
            resolved_path = registry_path.expanduser().resolve()
            is_allowed = any(
                self._is_path_under(resolved_path, base)
                for base in ALLOWED_REGISTRY_BASES
            )
            if not is_allowed:
                raise RegistrySecurityError(
                    f"Registry path must be within allowed directories: "
                    f"{[str(b) for b in ALLOWED_REGISTRY_BASES]}"
                )
            self.registry_path = resolved_path
        else:
            self.registry_path = self.REGISTRY_PATH

        self._servers: dict[str, ServerRegistryEntry] = {}
        self._tools: dict[str, ToolRegistryEntry] = {}
        self._tool_by_server: dict[str, list[str]] = {}  # server_id -> [tool_ids]
        self._metadata: RegistryMetadata | None = None
        self._initialized = False
        self._lock = asyncio.Lock()

    @staticmethod
    def _is_path_under(path: Path, base: Path) -> bool:
        """Check if path is under base directory (prevents path traversal).

        Args:
            path: Path to check (must be resolved)
            base: Base directory (must be resolved)

        Returns:
            True if path is under base directory
        """
        try:
            path.relative_to(base)
            return True
        except ValueError:
            return False

    async def initialize(self) -> None:
        """Load registry from disk or create empty registry.

        Raises:
            IOError: If registry file is corrupt and cannot be loaded
        """
        async with self._lock:
            if self._initialized:
                logger.warning("Registry already initialized, skipping")
                return

            self.registry_path.parent.mkdir(parents=True, exist_ok=True)

            if self.registry_path.exists():
                try:
                    self._load_registry()
                    logger.info(
                        f"Loaded registry: {len(self._servers)} servers, {len(self._tools)} tools"
                    )
                except Exception as e:
                    logger.error(f"Failed to load registry: {e}")
                    logger.warning("Creating empty registry")
                    self._create_empty_registry()
                    await self._save_registry()  # Persist empty registry
            else:
                logger.info("No registry found, creating empty registry")
                self._create_empty_registry()
                await self._save_registry()  # Persist empty registry

            self._initialized = True

    def get_server_config(self, server_id: str) -> ServerRegistryEntry | None:
        """Get server configuration by ID (O(1) lookup).

        Args:
            server_id: Server identifier (e.g., "tmws", "serena")

        Returns:
            Server registry entry if found, None otherwise
        """
        self._ensure_initialized()
        return self._servers.get(server_id)

    def search_tools(
        self,
        query: str,
        category: ToolCategory | None = None,
        limit: int = 10,
    ) -> list[ToolRegistryEntry]:
        """Search tools by name/description/keywords (O(n) search).

        Args:
            query: Search query (case-insensitive)
            category: Optional category filter
            limit: Maximum number of results

        Returns:
            List of matching tool entries, sorted by relevance
        """
        self._ensure_initialized()

        matching_tools = []
        for tool in self._tools.values():
            # Filter by category first
            if category is not None and tool.category != category:
                continue

            # Check if query matches
            if tool.matches_query(query):
                matching_tools.append(tool)

        # Sort by relevance (exact name match first)
        matching_tools.sort(
            key=lambda t: (
                not t.name.lower().startswith(query.lower()),  # Prefix match first
                query.lower() not in t.name.lower(),  # Substring match second
                t.name,  # Alphabetical
            )
        )

        return matching_tools[:limit]

    def get_tools_for_server(self, server_id: str) -> list[ToolRegistryEntry]:
        """Get all tools registered for a server (O(1) lookup + O(k) retrieval).

        Args:
            server_id: Server identifier

        Returns:
            List of tool entries for the server
        """
        self._ensure_initialized()

        tool_ids = self._tool_by_server.get(server_id, [])
        return [self._tools[tid] for tid in tool_ids if tid in self._tools]

    async def update_popularity(self, server_id: str, delta: float = 0.1) -> None:
        """Update server popularity score (call after tool execution).

        Args:
            server_id: Server identifier
            delta: Score adjustment (-1.0 to 1.0)
        """
        async with self._lock:
            server = self._servers.get(server_id)
            if server is None:
                logger.warning(f"Cannot update popularity for unknown server: {server_id}")
                return

            # Update score (clamped to 0.0 - 1.0)
            server.popularity_score = max(0.0, min(1.0, server.popularity_score + delta))
            server.last_connected = datetime.now()

            # Persist changes
            await self._save_registry()

    async def register_server(
        self, server: ServerRegistryEntry, tools: list[ToolRegistryEntry]
    ) -> None:
        """Register a new server and its tools.

        Args:
            server: Server registry entry
            tools: List of tool entries for this server
        """
        async with self._lock:
            # Add server
            self._servers[server.server_id] = server

            # Add tools
            tool_ids = []
            for tool in tools:
                self._tools[tool.tool_id] = tool
                tool_ids.append(tool.tool_id)

            # Update tool-by-server mapping
            self._tool_by_server[server.server_id] = tool_ids

            # Update metadata
            if self._metadata:
                self._metadata.server_count = len(self._servers)
                self._metadata.tool_count = len(self._tools)

            # Persist changes
            await self._save_registry()

            logger.info(
                f"Registered server '{server.server_id}' with {len(tools)} tools"
            )

    async def unregister_server(self, server_id: str) -> None:
        """Unregister a server and its tools.

        Args:
            server_id: Server identifier
        """
        async with self._lock:
            if server_id not in self._servers:
                logger.warning(f"Cannot unregister unknown server: {server_id}")
                return

            # Remove server
            del self._servers[server_id]

            # Remove tools
            tool_ids = self._tool_by_server.pop(server_id, [])
            for tool_id in tool_ids:
                self._tools.pop(tool_id, None)

            # Update metadata
            if self._metadata:
                self._metadata.server_count = len(self._servers)
                self._metadata.tool_count = len(self._tools)

            # Persist changes
            await self._save_registry()

            logger.info(f"Unregistered server '{server_id}' and {len(tool_ids)} tools")

    def get_stats(self) -> dict[str, Any]:
        """Return registry statistics.

        Returns:
            Dict with server_count, tool_count, categories, etc.
        """
        self._ensure_initialized()

        # Count servers by category
        category_counts = {}
        for server in self._servers.values():
            cat = server.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Calculate total estimated memory
        total_memory_mb = sum(s.estimated_memory_mb for s in self._servers.values())

        return {
            "server_count": len(self._servers),
            "tool_count": len(self._tools),
            "categories": category_counts,
            "total_estimated_memory_mb": total_memory_mb,
            "registry_size_bytes": (
                self._metadata.total_size_bytes if self._metadata else 0
            ),
            "version": self.REGISTRY_VERSION,
        }

    async def rebuild_from_presets(self, presets_path: Path) -> None:
        """Rebuild registry by introspecting all preset servers.

        This is a heavy operation - should be run offline or on-demand.

        Args:
            presets_path: Path to MCP presets configuration file
        """
        from src.infrastructure.mcp.registry_builder import build_sparse_registry

        logger.info(f"Rebuilding registry from presets: {presets_path}")

        # Build new registry
        new_metadata = await build_sparse_registry(presets_path, self.registry_path)

        # Reload
        async with self._lock:
            self._load_registry()

        logger.info(
            f"Registry rebuilt: {new_metadata.server_count} servers, {new_metadata.tool_count} tools"
        )

    async def _save_registry(self) -> None:
        """Persist registry to disk atomically.

        Uses atomic write (write to temp file, then rename) for consistency.
        """
        if not self._metadata:
            logger.warning("Cannot save registry without metadata")
            return

        # Update metadata
        self._metadata.server_count = len(self._servers)
        self._metadata.tool_count = len(self._tools)

        # Create registry object
        registry = SparseRegistry(
            metadata=self._metadata,
            servers=self._servers,
            tools=self._tools,
            tool_by_server=self._tool_by_server,
        )

        # Serialize to JSON
        json_str = registry.to_json(indent=2)
        self._metadata.total_size_bytes = len(json_str.encode("utf-8"))

        # Atomic write: write to temp file, then rename
        temp_path = self.registry_path.with_suffix(".tmp")
        try:
            temp_path.write_text(json_str)
            temp_path.rename(self.registry_path)
            logger.debug(f"Saved registry to {self.registry_path}")
        except Exception as e:
            logger.error(f"Failed to save registry: {e}")
            if temp_path.exists():
                temp_path.unlink()
            raise

    def _load_registry(self) -> None:
        """Load registry from disk.

        Raises:
            IOError: If registry file is corrupt
        """
        try:
            json_str = self.registry_path.read_text()
            registry = SparseRegistry.from_json(json_str)

            self._metadata = registry.metadata
            self._servers = registry.servers
            self._tools = registry.tools
            self._tool_by_server = registry.tool_by_server

            logger.debug(f"Loaded registry from {self.registry_path}")
        except Exception as e:
            logger.error(f"Failed to load registry: {e}")
            raise OSError(f"Corrupt registry file: {self.registry_path}") from e

    def _create_empty_registry(self) -> None:
        """Create an empty registry."""
        self._metadata = RegistryMetadata(
            version=self.REGISTRY_VERSION,
            created_at=datetime.now(),
            server_count=0,
            tool_count=0,
            total_size_bytes=0,
        )
        self._servers = {}
        self._tools = {}
        self._tool_by_server = {}

    def _ensure_initialized(self) -> None:
        """Ensure registry is initialized.

        Raises:
            RuntimeError: If registry not initialized
        """
        if not self._initialized:
            raise RuntimeError("Registry not initialized. Call initialize() first.")
