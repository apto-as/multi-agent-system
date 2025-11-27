"""Unified MCP Manager.

This module provides a unified interface for managing MCP server connections
across different transport types (STDIO and HTTP).

Features:
- Auto-connect to preset servers on startup
- Unified tool listing and execution
- Transport-agnostic interface
- Connection lifecycle management

Author: Artemis (Implementation) + Athena (Coordination)
Created: 2025-11-27 (Phase: MCP Preset Integration)
"""

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.domain.entities.tool import Tool
from src.domain.value_objects.connection_config import ConnectionConfig
from src.infrastructure.adapters.mcp_client_adapter import MCPClientAdapter
from src.infrastructure.exceptions import MCPConnectionError

from .preset_config import (
    MCPPresetConfig,
    MCPServerPreset,
    MCPTransportType,
    load_mcp_presets,
)
from .stdio_transport import STDIOTransport

logger = logging.getLogger(__name__)


@dataclass
class MCPConnection:
    """Represents an active MCP connection.

    Attributes:
        preset: Original preset configuration
        transport: Either STDIOTransport or MCPClientAdapter
        tools: Cached list of available tools
    """

    preset: MCPServerPreset
    transport: STDIOTransport | MCPClientAdapter | None = None
    tools: list[Tool] = field(default_factory=list)

    @property
    def is_connected(self) -> bool:
        """Check if connection is active."""
        if isinstance(self.transport, STDIOTransport):
            return self.transport.is_connected
        elif isinstance(self.transport, MCPClientAdapter):
            return self.transport._connected
        return False

    @property
    def server_name(self) -> str:
        """Get server name."""
        return self.preset.name


class MCPManager:
    """Unified manager for all MCP connections.

    Provides a single interface for managing MCP server connections
    regardless of transport type (STDIO or HTTP).

    Example:
        >>> manager = MCPManager()
        >>>
        >>> # Auto-connect to all servers with autoConnect=true
        >>> await manager.auto_connect_from_config()
        >>>
        >>> # Or connect specific preset
        >>> preset = MCPServerPreset(name="custom", command="node", args=["server.js"])
        >>> await manager.connect(preset)
        >>>
        >>> # List all tools across all servers
        >>> tools = await manager.list_all_tools()
        >>>
        >>> # Execute a tool
        >>> result = await manager.call_tool("context7", "search", {"query": "fastapi"})
        >>>
        >>> # Disconnect all
        >>> await manager.disconnect_all()
    """

    def __init__(self):
        """Initialize MCP manager."""
        self.connections: dict[str, MCPConnection] = {}
        self._lock = asyncio.Lock()

    async def connect(self, preset: MCPServerPreset) -> MCPConnection:
        """Connect to an MCP server using preset configuration.

        Args:
            preset: Server preset configuration

        Returns:
            MCPConnection instance

        Raises:
            MCPConnectionError: If connection fails
        """
        async with self._lock:
            # Check for existing connection
            if preset.name in self.connections:
                existing = self.connections[preset.name]
                if existing.is_connected:
                    logger.debug(f"Reusing existing connection to {preset.name}")
                    return existing
                # Clean up disconnected connection
                await self._disconnect_connection(existing)

            # Create appropriate transport
            if preset.transport_type == MCPTransportType.STDIO:
                transport = await self._create_stdio_transport(preset)
            else:
                transport = await self._create_http_transport(preset)

            # Create connection object
            connection = MCPConnection(preset=preset, transport=transport)

            # Discover tools
            try:
                connection.tools = await self._list_tools(connection)
                logger.info(
                    f"Connected to {preset.name}: {len(connection.tools)} tools available"
                )
            except Exception as e:
                logger.warning(f"Failed to discover tools from {preset.name}: {e}")

            self.connections[preset.name] = connection
            return connection

    async def disconnect(self, server_name: str) -> None:
        """Disconnect from a specific server.

        Args:
            server_name: Name of server to disconnect
        """
        async with self._lock:
            connection = self.connections.pop(server_name, None)
            if connection:
                await self._disconnect_connection(connection)

    async def disconnect_all(self) -> None:
        """Disconnect from all servers."""
        async with self._lock:
            for name in list(self.connections.keys()):
                connection = self.connections.pop(name)
                await self._disconnect_connection(connection)

    async def auto_connect_from_config(
        self,
        project_dir: Path | None = None,
        parallel: bool = True
    ) -> list[str]:
        """Auto-connect to all servers with autoConnect=true.

        Args:
            project_dir: Optional project directory for .mcp.json
            parallel: If True, connect to all servers in parallel

        Returns:
            List of successfully connected server names
        """
        presets = load_mcp_presets(project_dir)
        return await self.auto_connect(presets, parallel=parallel)

    async def auto_connect(
        self,
        config: MCPPresetConfig,
        parallel: bool = True
    ) -> list[str]:
        """Connect to all servers with autoConnect=true in config.

        Args:
            config: Preset configuration
            parallel: If True, connect to all servers in parallel

        Returns:
            List of successfully connected server names
        """
        auto_connect_servers = config.get_auto_connect_servers()

        if not auto_connect_servers:
            logger.info("No MCP servers configured for auto-connect")
            return []

        logger.info(f"Auto-connecting to {len(auto_connect_servers)} MCP servers")

        connected = []

        if parallel:
            # Connect in parallel
            tasks = [self.connect(preset) for preset in auto_connect_servers]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for preset, result in zip(auto_connect_servers, results, strict=False):
                if isinstance(result, Exception):
                    logger.error(f"Failed to connect to {preset.name}: {result}")
                else:
                    connected.append(preset.name)
        else:
            # Connect sequentially
            for preset in auto_connect_servers:
                try:
                    await self.connect(preset)
                    connected.append(preset.name)
                except Exception as e:
                    logger.error(f"Failed to connect to {preset.name}: {e}")

        return connected

    async def list_all_tools(self) -> dict[str, list[Tool]]:
        """List tools from all connected servers.

        Returns:
            Dictionary of server_name -> list of Tools
        """
        result = {}
        for name, connection in self.connections.items():
            if connection.is_connected:
                result[name] = connection.tools
        return result

    async def refresh_tools(self, server_name: str) -> list[Tool]:
        """Refresh tool list from a specific server.

        Args:
            server_name: Name of server

        Returns:
            Updated list of Tools

        Raises:
            MCPConnectionError: If server not found or not connected
        """
        connection = self.connections.get(server_name)
        if not connection:
            raise MCPConnectionError(
                f"Server not found: {server_name}",
                details={"available_servers": list(self.connections.keys())}
            )

        if not connection.is_connected:
            raise MCPConnectionError(
                f"Server not connected: {server_name}",
                details={"server_name": server_name}
            )

        connection.tools = await self._list_tools(connection)
        return connection.tools

    async def call_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute a tool on a specific server.

        Args:
            server_name: Name of server
            tool_name: Name of tool to execute
            arguments: Tool arguments

        Returns:
            Tool execution result

        Raises:
            MCPConnectionError: If server not found or not connected
        """
        connection = self.connections.get(server_name)
        if not connection:
            raise MCPConnectionError(
                f"Server not found: {server_name}",
                details={"available_servers": list(self.connections.keys())}
            )

        if not connection.is_connected:
            raise MCPConnectionError(
                f"Server not connected: {server_name}",
                details={"server_name": server_name}
            )

        return await self._call_tool(connection, tool_name, arguments)

    def get_connection(self, server_name: str) -> MCPConnection | None:
        """Get connection by server name.

        Args:
            server_name: Name of server

        Returns:
            MCPConnection or None if not found
        """
        return self.connections.get(server_name)

    def list_connections(self) -> list[dict[str, Any]]:
        """List all connections with their status.

        Returns:
            List of connection info dictionaries
        """
        return [
            {
                "name": name,
                "transport_type": conn.preset.transport_type.value,
                "is_connected": conn.is_connected,
                "tool_count": len(conn.tools),
                "auto_connect": conn.preset.auto_connect,
            }
            for name, conn in self.connections.items()
        ]

    # Private methods

    async def _create_stdio_transport(self, preset: MCPServerPreset) -> STDIOTransport:
        """Create and connect STDIO transport.

        Args:
            preset: Server preset

        Returns:
            Connected STDIOTransport
        """
        transport = STDIOTransport(preset=preset)
        await transport.connect()
        return transport

    async def _create_http_transport(self, preset: MCPServerPreset) -> MCPClientAdapter:
        """Create and connect HTTP transport.

        Args:
            preset: Server preset

        Returns:
            Connected MCPClientAdapter
        """
        if not preset.url:
            raise MCPConnectionError(
                f"HTTP preset {preset.name} missing URL",
                details={"server_name": preset.name}
            )

        # Get API key if auth required
        api_key = preset.get_api_key() if preset.auth_required else None

        config = ConnectionConfig(
            server_name=preset.name,
            url=preset.url,
            timeout=preset.timeout,
            retry_attempts=preset.retry_attempts,
            auth_required=preset.auth_required,
            api_key=api_key,
        )

        adapter = MCPClientAdapter(config)
        await adapter.connect()
        return adapter

    async def _disconnect_connection(self, connection: MCPConnection) -> None:
        """Disconnect a connection.

        Args:
            connection: Connection to disconnect
        """
        try:
            if isinstance(connection.transport, (STDIOTransport, MCPClientAdapter)):
                await connection.transport.disconnect()
        except Exception as e:
            logger.warning(f"Error disconnecting {connection.server_name}: {e}")

        logger.info(f"Disconnected from {connection.server_name}")

    async def _list_tools(self, connection: MCPConnection) -> list[Tool]:
        """List tools from a connection.

        Args:
            connection: Active connection

        Returns:
            List of Tools
        """
        if isinstance(connection.transport, STDIOTransport):
            return await connection.transport.list_tools()
        elif isinstance(connection.transport, MCPClientAdapter):
            return await connection.transport.discover_tools()
        return []

    async def _call_tool(
        self,
        connection: MCPConnection,
        tool_name: str,
        arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute a tool on a connection.

        Args:
            connection: Active connection
            tool_name: Tool name
            arguments: Tool arguments

        Returns:
            Tool execution result
        """
        if isinstance(connection.transport, STDIOTransport):
            return await connection.transport.call_tool(tool_name, arguments)
        elif isinstance(connection.transport, MCPClientAdapter):
            return await connection.transport.execute_tool(tool_name, arguments)
        raise MCPConnectionError("Unknown transport type")


# Singleton manager instance
_mcp_manager: MCPManager | None = None


def get_mcp_manager() -> MCPManager:
    """Get singleton MCP manager instance.

    Returns:
        MCPManager instance
    """
    global _mcp_manager
    if _mcp_manager is None:
        _mcp_manager = MCPManager()
    return _mcp_manager


async def auto_connect_mcp_servers(project_dir: Path | None = None) -> list[str]:
    """Convenience function to auto-connect MCP servers.

    Args:
        project_dir: Optional project directory

    Returns:
        List of connected server names
    """
    manager = get_mcp_manager()
    return await manager.auto_connect_from_config(project_dir)
