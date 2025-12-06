"""MCP Hub Management Tools for TMWS.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 3.2 - Core Integration

Provides MCP tools for:
- list_mcp_servers: List available and connected MCP servers
- connect_mcp_server: Connect to an MCP server by ID
- disconnect_mcp_server: Disconnect from an MCP server
- get_mcp_hub_status: Get overall MCP Hub status
- call_mcp_tool: Execute a tool on a connected MCP server

Security:
- S-P0-3: JSON Schema validation for tool inputs
- S-P0-6: Response size limits (10MB)
- S-P0-7: Timeout enforcement (30s)

Author: Metis (Implementation) + Hestia (Security Review)
Created: 2025-12-05
"""

import logging
from typing import Any

from fastmcp import FastMCP

from ..infrastructure.mcp.hub_manager import (
    get_hub_manager,
    initialize_hub_manager,
)

logger = logging.getLogger(__name__)


async def register_tools(mcp: FastMCP, **kwargs: Any) -> None:
    """Register MCP Hub management tools.

    Args:
        mcp: FastMCP instance to register tools on
        **kwargs: Additional configuration options
            - hub_manager: Optional pre-configured MCPHubManager
    """
    # Get or initialize hub manager
    hub_manager = kwargs.get("hub_manager")

    if hub_manager is None:
        try:
            hub_manager = get_hub_manager()
        except Exception:
            hub_manager = await initialize_hub_manager()

    @mcp.tool(
        name="list_mcp_servers",
        description=(
            "List all available MCP servers and their connection status. "
            "Shows server ID, name, transport type, auto-connect setting, "
            "connection status, and tool count."
        ),
    )
    async def list_mcp_servers() -> dict[str, Any]:
        """List all available and connected MCP servers.

        Returns:
            Dictionary with:
            - servers: List of server info dictionaries
            - total: Total number of available servers
            - connected: Number of currently connected servers

        Example:
            >>> list_mcp_servers()
            {
                "servers": [
                    {"server_id": "context7", "is_connected": true, "tool_count": 2},
                    {"server_id": "serena", "is_connected": false, "tool_count": 0}
                ],
                "total": 2,
                "connected": 1
            }
        """
        try:
            servers = await hub_manager.list_servers()
            connected_count = sum(1 for s in servers if s.get("is_connected", False))

            return {
                "servers": servers,
                "total": len(servers),
                "connected": connected_count,
            }
        except Exception as e:
            logger.error(f"Failed to list MCP servers: {e}")
            return {
                "error": str(e),
                "servers": [],
                "total": 0,
                "connected": 0,
            }

    @mcp.tool(
        name="connect_mcp_server",
        description=(
            "Connect to an MCP server by its preset ID. "
            "Maximum 10 concurrent connections allowed. "
            "Automatically indexes the server's tools for search."
        ),
    )
    async def connect_mcp_server(server_id: str) -> dict[str, Any]:
        """Connect to an MCP server by ID.

        Args:
            server_id: Server identifier from presets (e.g., "context7", "serena")

        Returns:
            Dictionary with:
            - server_id: Server identifier
            - status: "connected" or "error"
            - tool_count: Number of tools available
            - transport: Transport type (stdio, sse)

        Raises:
            Error if server not found in presets or connection limit reached.

        Example:
            >>> connect_mcp_server("context7")
            {"server_id": "context7", "status": "connected", "tool_count": 2}
        """
        try:
            result = await hub_manager.connect_server(server_id)
            return result
        except Exception as e:
            logger.error(f"Failed to connect to MCP server {server_id}: {e}")
            return {
                "server_id": server_id,
                "status": "error",
                "error": str(e),
            }

    @mcp.tool(
        name="disconnect_mcp_server",
        description=(
            "Disconnect from a connected MCP server. "
            "The server's tools will no longer be available until reconnected."
        ),
    )
    async def disconnect_mcp_server(server_id: str) -> dict[str, Any]:
        """Disconnect from an MCP server.

        Args:
            server_id: Server identifier to disconnect

        Returns:
            Dictionary with:
            - server_id: Server identifier
            - status: "disconnected" or "error"

        Example:
            >>> disconnect_mcp_server("context7")
            {"server_id": "context7", "status": "disconnected"}
        """
        try:
            result = await hub_manager.disconnect_server(server_id)
            return result
        except Exception as e:
            logger.error(f"Failed to disconnect from MCP server {server_id}: {e}")
            return {
                "server_id": server_id,
                "status": "error",
                "error": str(e),
            }

    @mcp.tool(
        name="get_mcp_hub_status",
        description=(
            "Get the overall status of the MCP Hub, including connection limits, "
            "active connections, and indexed tools count."
        ),
    )
    async def get_mcp_hub_status() -> dict[str, Any]:
        """Get MCP Hub status.

        Returns:
            Dictionary with:
            - initialized: Whether hub is initialized
            - max_connections: Maximum allowed connections
            - active_connections: Current connection count
            - total_tools_indexed: Total tools in search index
            - mcp_server_tools: Tools from MCP servers
            - servers: List of server connection states

        Example:
            >>> get_mcp_hub_status()
            {
                "initialized": true,
                "max_connections": 10,
                "active_connections": 2,
                "total_tools_indexed": 50
            }
        """
        try:
            result = await hub_manager.get_status()
            return result
        except Exception as e:
            logger.error(f"Failed to get MCP Hub status: {e}")
            return {
                "error": str(e),
                "initialized": False,
            }

    @mcp.tool(
        name="call_mcp_tool",
        description=(
            "Execute a tool on a connected MCP server. "
            "Validates inputs, enforces 30s timeout, and limits response to 10MB. "
            "Use search_tools to find available tools first."
        ),
    )
    async def call_mcp_tool(
        server_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a tool on an MCP server.

        Security:
        - S-P0-3: Validates arguments against tool's JSON schema
        - S-P0-6: Response size limited to 10MB
        - S-P0-7: Execution timeout of 30 seconds

        Args:
            server_id: Server identifier (e.g., "context7")
            tool_name: Tool name to execute (e.g., "resolve-library-id")
            arguments: Tool arguments as a dictionary (optional)

        Returns:
            The tool's execution result, or error information.

        Example:
            >>> call_mcp_tool(
            ...     "context7",
            ...     "resolve-library-id",
            ...     {"libraryName": "react"}
            ... )
            {"libraryId": "/facebook/react", "description": "A JavaScript library..."}
        """
        if arguments is None:
            arguments = {}

        try:
            result = await hub_manager.call_tool(
                server_id=server_id,
                tool_name=tool_name,
                arguments=arguments,
            )
            return {
                "success": True,
                "server_id": server_id,
                "tool_name": tool_name,
                "result": result,
            }
        except Exception as e:
            logger.error(f"Failed to call MCP tool {server_id}:{tool_name}: {e}")
            return {
                "success": False,
                "server_id": server_id,
                "tool_name": tool_name,
                "error": str(e),
            }

    logger.info("MCP Hub management tools registered (5 tools)")
