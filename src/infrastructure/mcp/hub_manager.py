"""MCP Hub Manager for unified tool management.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 1.4 - MCP Hub Manager
Phase: 2.1-2.2 - Security Foundation

Extends the existing MCPManager with:
- Integration with ToolSearchService
- Lazy initialization for memory efficiency
- Connection pooling (max 10 servers)
- Tool metadata aggregation

Security (Phase 2):
- S-P0-3: JSON Schema validation for tool inputs
- S-P0-6: Response size limits (10MB)
- S-P0-7: Timeout enforcement (30s)

Author: Artemis (Implementation) + Hestia (Security Review)
Created: 2025-12-04
Updated: 2025-12-05 (Phase 2 Security)
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ...models.tool_search import (
    MCPServerMetadata,
    ToolMetadata,
)
from ...models.tool_search import (
    MCPTransportType as ToolSearchTransportType,
)
from ...services.tool_search_service import (
    ToolSearchService,
    get_tool_search_service,
)
from ..exceptions import MCPConnectionError
from ..security import (
    InputValidationError,
    ResponseLimitError,
    check_response_size,
    validate_tool_input,
)
from .manager import MCPConnection, MCPManager, get_mcp_manager
from .preset_config import (
    MCPServerPreset,
    MCPTransportType,
    load_mcp_presets,
)

logger = logging.getLogger(__name__)


@dataclass
class HubConnectionStats:
    """Statistics for hub connection status."""
    total_servers: int = 0
    connected_servers: int = 0
    total_tools: int = 0
    last_refresh: datetime | None = None


class MCPHubManager:
    """Unified MCP Hub Manager with Tool Search integration.

    Features:
    - Connection pool management (max 10 concurrent connections)
    - Lazy initialization for memory efficiency
    - Automatic tool metadata extraction and indexing
    - Integration with ToolSearchService

    Security:
    - Preset-only connections (no arbitrary command execution)
    - Maximum connection limit enforced
    - Connection timeout enforcement

    Usage:
        >>> hub = MCPHubManager()
        >>> await hub.initialize()
        >>> await hub.connect_server("context7")
        >>> results = await hub.search_tools("search code")
    """

    MAX_CONNECTIONS = 10
    DEFAULT_TIMEOUT = 30  # seconds

    def __init__(
        self,
        mcp_manager: MCPManager | None = None,
        tool_search_service: ToolSearchService | None = None,
    ):
        """Initialize MCP Hub Manager.

        Args:
            mcp_manager: Existing MCP manager (uses singleton if None)
            tool_search_service: Tool search service (uses singleton if None)
        """
        self._mcp_manager = mcp_manager
        self._tool_search_service = tool_search_service
        self._initialized = False
        self._lock = asyncio.Lock()

        # Track registered servers
        self._registered_servers: dict[str, MCPServerMetadata] = {}

        logger.info("MCPHubManager created (lazy initialization)")

    async def initialize(self) -> None:
        """Initialize hub manager and services.

        Performs lazy initialization of:
        - MCP Manager
        - Tool Search Service
        - ChromaDB collection
        """
        async with self._lock:
            if self._initialized:
                return

            # Get or create MCP manager
            if self._mcp_manager is None:
                self._mcp_manager = get_mcp_manager()

            # Get or create Tool Search service
            if self._tool_search_service is None:
                self._tool_search_service = get_tool_search_service()
                if not self._tool_search_service._collection:
                    await self._tool_search_service.initialize()

            self._initialized = True
            logger.info("MCPHubManager initialized")

    async def connect_server(self, server_id: str) -> dict[str, Any]:
        """Connect to an MCP server by ID.

        Args:
            server_id: Server identifier from presets

        Returns:
            Connection status dictionary

        Raises:
            MCPConnectionError: If connection fails or limit reached
        """
        await self._ensure_initialized()

        # Check connection limit
        current_connections = len(self._mcp_manager.connections)
        if current_connections >= self.MAX_CONNECTIONS:
            raise MCPConnectionError(
                f"Maximum connections ({self.MAX_CONNECTIONS}) reached",
                details={"current": current_connections},
            )

        # Load preset
        presets = load_mcp_presets()
        preset = presets.get_server(server_id)

        if not preset:
            raise MCPConnectionError(
                f"Server not found in presets: {server_id}",
                details={"available": list(presets.servers.keys())},
            )

        # Connect via MCP manager
        try:
            connection = await self._mcp_manager.connect(preset)

            # Extract and index tools
            await self._index_server_tools(preset, connection)

            return {
                "server_id": server_id,
                "status": "connected",
                "tool_count": len(connection.tools),
                "transport": preset.transport_type.value,
            }
        except Exception as e:
            logger.error(f"Failed to connect to {server_id}: {e}")
            raise MCPConnectionError(
                f"Connection failed: {server_id}",
                details={"error": str(e)},
            )

    async def disconnect_server(self, server_id: str) -> dict[str, Any]:
        """Disconnect from an MCP server.

        Args:
            server_id: Server identifier

        Returns:
            Disconnection status
        """
        await self._ensure_initialized()

        try:
            await self._mcp_manager.disconnect(server_id)

            # Remove from registered servers
            self._registered_servers.pop(server_id, None)

            return {
                "server_id": server_id,
                "status": "disconnected",
            }
        except Exception as e:
            logger.error(f"Failed to disconnect from {server_id}: {e}")
            return {
                "server_id": server_id,
                "status": "error",
                "error": str(e),
            }

    async def list_servers(self) -> list[dict[str, Any]]:
        """List all available and connected MCP servers.

        Returns:
            List of server status dictionaries
        """
        await self._ensure_initialized()

        # Get presets
        presets = load_mcp_presets()

        servers = []
        for name, preset in presets.servers.items():
            connection = self._mcp_manager.get_connection(name)
            servers.append({
                "server_id": name,
                "name": preset.name,
                "transport": preset.transport_type.value,
                "auto_connect": preset.auto_connect,
                "is_connected": connection.is_connected if connection else False,
                "tool_count": len(connection.tools) if connection else 0,
            })

        return servers

    async def get_status(self) -> dict[str, Any]:
        """Get MCP Hub status.

        Returns:
            Hub status dictionary
        """
        await self._ensure_initialized()

        connections = self._mcp_manager.list_connections()
        connected = [c for c in connections if c["is_connected"]]

        stats = await self._tool_search_service.get_stats()

        return {
            "initialized": self._initialized,
            "max_connections": self.MAX_CONNECTIONS,
            "active_connections": len(connected),
            "total_tools_indexed": stats["total_indexed"],
            "mcp_server_tools": stats["mcp_server_tools"],
            "servers": connections,
        }

    async def search_tools(
        self,
        query: str,
        source: str = "all",
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Search for tools across all sources.

        Args:
            query: Search query
            source: Source filter
            limit: Maximum results

        Returns:
            List of matching tools
        """
        await self._ensure_initialized()
        return await self._tool_search_service.search_tools(
            query=query,
            source=source,
            limit=limit,
        )

    async def call_tool(
        self,
        server_id: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute a tool on a specific MCP server.

        Security (Phase 2):
        - S-P0-3: Validates arguments against tool schema
        - S-P0-6: Enforces 10MB response size limit
        - S-P0-7: Enforces 30s timeout

        Args:
            server_id: Server identifier
            tool_name: Tool name
            arguments: Tool arguments

        Returns:
            Tool execution result

        Raises:
            MCPConnectionError: If tool execution fails
            InputValidationError: If arguments fail validation (S-P0-3)
            ResponseLimitError: If response exceeds limit (S-P0-6)
            asyncio.TimeoutError: If execution exceeds timeout (S-P0-7)
        """
        await self._ensure_initialized()

        # Handle internal vs external servers
        if server_id == "tmws" or server_id == "tmws:skills":
            # Internal tool - not proxied
            raise MCPConnectionError(
                "Internal tools cannot be called through hub",
                details={"server_id": server_id, "tool_name": tool_name},
            )

        # Extract actual server ID from mcp__ prefix
        if server_id.startswith("mcp__"):
            actual_server_id = server_id.replace("mcp__", "")
        else:
            actual_server_id = server_id

        # S-P0-3: Validate arguments against schema
        tool_schema = self._get_tool_schema(actual_server_id, tool_name)
        if tool_schema:
            try:
                validate_tool_input(arguments, tool_schema, tool_name)
            except InputValidationError as e:
                logger.warning(
                    f"Input validation failed for {server_id}:{tool_name}: {e}"
                )
                raise MCPConnectionError(
                    f"Input validation failed: {e}",
                    details={
                        "server_id": server_id,
                        "tool_name": tool_name,
                        "validation_error": str(e),
                    },
                )

        # S-P0-7: Execute with timeout enforcement
        try:
            result = await asyncio.wait_for(
                self._mcp_manager.call_tool(
                    server_name=actual_server_id,
                    tool_name=tool_name,
                    arguments=arguments,
                ),
                timeout=self.DEFAULT_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.error(
                f"Tool execution timeout ({self.DEFAULT_TIMEOUT}s) for "
                f"{server_id}:{tool_name}"
            )
            raise MCPConnectionError(
                f"Tool execution timeout ({self.DEFAULT_TIMEOUT}s)",
                details={
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "timeout": self.DEFAULT_TIMEOUT,
                },
            )

        # S-P0-6: Check response size limit
        try:
            check_response_size(result, server_id, tool_name)
        except ResponseLimitError as e:
            logger.error(f"Response size limit exceeded for {server_id}:{tool_name}")
            raise MCPConnectionError(
                f"Response size limit exceeded: {e}",
                details={
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "size_bytes": e.size_bytes,
                    "limit_bytes": e.limit_bytes,
                },
            )

        return result

    def _get_tool_schema(
        self,
        server_id: str,
        tool_name: str,
    ) -> dict[str, Any] | None:
        """Get JSON schema for a tool.

        Args:
            server_id: Server identifier
            tool_name: Tool name

        Returns:
            Tool input schema or None if not found
        """
        # Check registered servers first
        server_metadata = self._registered_servers.get(server_id)
        if server_metadata:
            for tool in server_metadata.tools:
                if tool.name == tool_name:
                    return tool.input_schema

        # Try to get from connection
        connection = self._mcp_manager.get_connection(server_id)
        if connection and connection.tools:
            for tool in connection.tools:
                if tool.name == tool_name:
                    return tool.input_schema if hasattr(tool, "input_schema") else None

        return None

    async def refresh_server_tools(self, server_id: str) -> int:
        """Refresh tools from a connected server.

        Args:
            server_id: Server identifier

        Returns:
            Number of tools found
        """
        await self._ensure_initialized()

        connection = self._mcp_manager.get_connection(server_id)
        if not connection:
            raise MCPConnectionError(
                f"Server not connected: {server_id}",
                details={"server_id": server_id},
            )

        # Refresh tools
        tools = await self._mcp_manager.refresh_tools(server_id)

        # Re-index
        presets = load_mcp_presets()
        preset = presets.get_server(server_id)
        if preset:
            await self._index_server_tools(preset, connection)

        return len(tools)

    async def auto_connect(self) -> list[str]:
        """Auto-connect to all servers with autoConnect=true.

        Returns:
            List of successfully connected server IDs
        """
        await self._ensure_initialized()

        connected = await self._mcp_manager.auto_connect_from_config()

        # Index tools from all connected servers
        for server_id in connected:
            connection = self._mcp_manager.get_connection(server_id)
            presets = load_mcp_presets()
            preset = presets.get_server(server_id)
            if connection and preset:
                await self._index_server_tools(preset, connection)

        return connected

    # Private methods

    async def _ensure_initialized(self) -> None:
        """Ensure hub is initialized."""
        if not self._initialized:
            await self.initialize()

    async def _index_server_tools(
        self,
        preset: MCPServerPreset,
        connection: MCPConnection,
    ) -> None:
        """Index tools from a connected server.

        Args:
            preset: Server preset
            connection: Active connection
        """
        if not connection.tools:
            return

        # Convert to ToolMetadata
        tool_metadata = []
        for tool in connection.tools:
            tool_metadata.append(ToolMetadata(
                name=tool.name,
                description=tool.description or "",
                input_schema=tool.input_schema if hasattr(tool, "input_schema") else {},
                tags=[],
            ))

        # Create server metadata
        transport = ToolSearchTransportType.STDIO
        if preset.transport_type == MCPTransportType.HTTP:
            transport = ToolSearchTransportType.HTTP

        server_metadata = MCPServerMetadata(
            server_id=preset.name,
            name=preset.name,
            description=f"MCP server: {preset.name}",
            transport=transport,
            command=preset.command_list if hasattr(preset, "command_list") else None,
            url=preset.url,
            tools=tool_metadata,
            auto_connect=preset.auto_connect,
            last_connected=datetime.now(),
        )

        # Register with tool search service
        await self._tool_search_service.register_mcp_server(server_metadata)

        # Track registration
        self._registered_servers[preset.name] = server_metadata

        logger.info(
            f"Indexed {len(tool_metadata)} tools from {preset.name}"
        )


# Singleton instance
_hub_manager: MCPHubManager | None = None


def get_hub_manager() -> MCPHubManager:
    """Get singleton MCPHubManager instance.

    Returns:
        MCPHubManager instance
    """
    global _hub_manager
    if _hub_manager is None:
        _hub_manager = MCPHubManager()
    return _hub_manager


async def initialize_hub_manager() -> MCPHubManager:
    """Initialize and return the hub manager.

    Returns:
        Initialized MCPHubManager
    """
    hub = get_hub_manager()
    await hub.initialize()
    return hub
