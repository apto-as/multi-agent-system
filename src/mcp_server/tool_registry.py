"""Tool registration for MCP server.

This module contains the tool registration logic extracted from HybridMCPServer.
"""

import logging

logger = logging.getLogger(__name__)


def register_core_tools(mcp, server):
    """Register core MCP tools with FastMCP instance.

    Args:
        mcp: FastMCP instance
        server: HybridMCPServer instance

    This function registers the core tools:
    - store_memory: Store information in hybrid semantic memory
    - search_memories: Search semantic memories with Chroma vector search
    - create_task: Create a coordinated task
    - get_agent_status: Get status of connected agents
    - get_memory_stats: Get memory statistics
    - invalidate_cache: Clear Chroma cache (for testing)
    - list_mcp_servers: List available MCP servers from presets
    - connect_mcp_server: Connect to a preset MCP server
    - disconnect_mcp_server: Disconnect from an MCP server
    - get_mcp_status: Get current status of all MCP server connections
    """

    @mcp.tool(
        name="store_memory",
        description="Store information in hybrid semantic memory (SQLite + Chroma)",
    )
    async def store_memory(
        content: str,
        importance_score: float = 0.5,
        tags: list[str] = None,
        namespace: str = None,
        context: dict = None,
    ) -> dict:
        """Store memory with ultra-fast Chroma sync.

        Performance: ~2ms P95 (5x faster than legacy)

        Security: Namespace is auto-detected from project context if not provided.
        Explicit 'default' namespace is rejected to prevent cross-project leakage.
        """
        # Use cached namespace if not provided (detected once at server startup)
        if namespace is None:
            namespace = server.default_namespace

        # Validate namespace (rejects 'default')
        from src.utils.namespace import validate_namespace

        validate_namespace(namespace)

        return await server.store_memory_hybrid(
            content, importance_score, tags, namespace, context
        )

    @mcp.tool(
        name="search_memories",
        description="Search semantic memories (Chroma vector search, 0.47ms P95)",
    )
    async def search_memories(
        query: str,
        limit: int = 10,
        min_similarity: float = 0.7,
        namespace: str = None,
        tags: list[str] = None,
    ) -> dict:
        """Search memories with Chroma ultra-fast vector search.

        Performance: ~0.5ms P95 (ChromaDB vector search + SQLite metadata)

        Security: Namespace is auto-detected from project context if not provided.
        Explicit 'default' namespace is rejected to prevent cross-project leakage.
        """
        # Use cached namespace if not provided (detected once at server startup)
        if namespace is None:
            namespace = server.default_namespace

        # Validate namespace (rejects 'default')
        from src.utils.namespace import validate_namespace

        validate_namespace(namespace)

        return await server.search_memories_hybrid(query, limit, min_similarity, namespace, tags)

    @mcp.tool(name="create_task", description="Create a coordinated task")
    async def create_task(
        title: str,
        description: str = None,
        priority: str = "medium",
        assigned_agent_id: str = None,
        estimated_duration: int = None,
        due_date: str = None,
    ) -> dict:
        """Create coordinated task."""
        return await server._create_task(
            title, description, priority, assigned_agent_id, estimated_duration, due_date
        )

    @mcp.tool(name="get_agent_status", description="Get status of connected agents")
    async def get_agent_status() -> dict:
        """Get status of connected agents."""
        return await server._get_agent_status()

    @mcp.tool(name="get_memory_stats", description="Get memory statistics")
    async def get_memory_stats() -> dict:
        """Get combined SQLite + ChromaDB statistics."""
        return await server.get_hybrid_memory_stats()

    @mcp.tool(name="invalidate_cache", description="Clear Chroma cache (for testing)")
    async def invalidate_cache() -> dict:
        """Clear Chroma collection (use with caution)."""
        return await server.clear_chroma_cache()

    # ========================================================================
    # External MCP Server Management Tools (v2.4.3+)
    # Allows agents to dynamically connect/disconnect to preset MCP servers
    # ========================================================================

    @mcp.tool(
        name="list_mcp_servers",
        description="List available MCP servers from presets and their connection status",
    )
    async def list_mcp_servers() -> dict:
        """List all MCP servers defined in presets with their current status.

        Returns available servers from ~/.tmws/mcp.json and .mcp.json,
        including whether they are currently connected.

        Returns:
            dict with 'servers' list containing server info
        """
        from src.infrastructure.mcp import load_mcp_presets

        try:
            presets = load_mcp_presets()
            servers = []

            for name, preset in presets.servers.items():
                # Check if currently connected
                is_connected = False
                tool_count = 0
                if server.external_mcp_manager:
                    conn = server.external_mcp_manager.get_connection(name)
                    if conn:
                        is_connected = conn.is_connected
                        tool_count = len(conn.tools)

                servers.append(
                    {
                        "name": name,
                        "transport_type": preset.transport_type.value,
                        "auto_connect": preset.auto_connect,
                        "is_connected": is_connected,
                        "tool_count": tool_count,
                        "command": preset.command if preset.command else None,
                        "url": preset.url if preset.url else None,
                    }
                )

            return {
                "status": "success",
                "server_count": len(servers),
                "servers": servers,
            }
        except Exception as e:
            logger.error(f"Failed to list MCP servers: {e}")
            return {
                "status": "error",
                "error": str(e),
                "servers": [],
            }

    @mcp.tool(
        name="connect_mcp_server", description="Connect to a preset MCP server by name"
    )
    async def connect_mcp_server(server_name: str) -> dict:
        """Connect to an MCP server defined in presets.

        Only servers defined in ~/.tmws/mcp.json or .mcp.json can be connected.
        This is a security measure to prevent arbitrary command execution.

        Args:
            server_name: Name of the server as defined in presets

        Returns:
            dict with connection status and available tools
        """
        from src.infrastructure.mcp import load_mcp_presets

        try:
            # Ensure manager is initialized
            if not server.external_mcp_manager:
                from src.infrastructure.mcp import MCPManager

                server.external_mcp_manager = MCPManager()

            # Check if already connected
            existing = server.external_mcp_manager.get_connection(server_name)
            if existing and existing.is_connected:
                return {
                    "status": "already_connected",
                    "server": server_name,
                    "tool_count": len(existing.tools),
                    "tools": [t.name for t in existing.tools],
                }

            # Load presets and find the server
            presets = load_mcp_presets()
            preset = presets.get_server(server_name)

            if not preset:
                available = list(presets.servers.keys())
                return {
                    "status": "error",
                    "error": f"Server '{server_name}' not found in presets",
                    "available_servers": available,
                }

            # Security check: Enforce maximum connections (prevent resource exhaustion)
            MAX_CONNECTIONS = 10
            current_connections = len(
                [c for c in server.external_mcp_manager.connections.values() if c.is_connected]
            )
            if current_connections >= MAX_CONNECTIONS:
                return {
                    "status": "error",
                    "error": f"Max connections ({MAX_CONNECTIONS}) reached. "
                    f"Disconnect a server first.",
                    "current_connections": current_connections,
                }

            # Connect to the server
            logger.info(f"Connecting to MCP server: {server_name}")
            connection = await server.external_mcp_manager.connect(preset)

            return {
                "status": "connected",
                "server": server_name,
                "transport_type": preset.transport_type.value,
                "tool_count": len(connection.tools),
                "tools": [t.name for t in connection.tools],
            }

        except Exception as e:
            logger.error(f"Failed to connect to MCP server '{server_name}': {e}")
            return {
                "status": "error",
                "server": server_name,
                "error": str(e),
            }

    @mcp.tool(name="disconnect_mcp_server", description="Disconnect from an MCP server")
    async def disconnect_mcp_server(server_name: str) -> dict:
        """Disconnect from an MCP server.

        Args:
            server_name: Name of the server to disconnect

        Returns:
            dict with disconnection status
        """
        try:
            if not server.external_mcp_manager:
                return {
                    "status": "error",
                    "error": "No MCP manager initialized",
                }

            connection = server.external_mcp_manager.get_connection(server_name)
            if not connection:
                return {
                    "status": "error",
                    "error": f"Server '{server_name}' is not connected",
                }

            await server.external_mcp_manager.disconnect(server_name)
            logger.info(f"Disconnected from MCP server: {server_name}")

            return {
                "status": "disconnected",
                "server": server_name,
            }

        except Exception as e:
            logger.error(f"Failed to disconnect from MCP server '{server_name}': {e}")
            return {
                "status": "error",
                "server": server_name,
                "error": str(e),
            }

    @mcp.tool(
        name="get_mcp_status", description="Get current status of all MCP server connections"
    )
    async def get_mcp_status() -> dict:
        """Get status of all connected MCP servers.

        Returns:
            dict with connection status and tool counts
        """
        try:
            if not server.external_mcp_manager:
                return {
                    "status": "success",
                    "manager_initialized": False,
                    "connections": [],
                    "total_tools": 0,
                }

            connections = server.external_mcp_manager.list_connections()
            total_tools = sum(c.get("tool_count", 0) for c in connections)

            return {
                "status": "success",
                "manager_initialized": True,
                "connection_count": len(connections),
                "connections": connections,
                "total_tools": total_tools,
            }

        except Exception as e:
            logger.error(f"Failed to get MCP status: {e}")
            return {
                "status": "error",
                "error": str(e),
            }

    # Note: Expiration tools will be registered during initialize()
    # after scheduler is created, since it needs scheduler instance
    logger.info("Core MCP tools registered (10 tools)")
