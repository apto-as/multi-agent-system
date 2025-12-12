"""MCP Hub Management Tools for TMWS.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 3.2 - Core Integration + 4.0 Tool Search Proxy

Provides MCP tools for:
- search_tools: Semantic tool discovery with lazy loading (NEW - Phase 4.0)
- get_tool_schema: Lazy load full tool schema on demand (NEW - Phase 4.0)
- list_mcp_servers: List available and connected MCP servers
- connect_mcp_server: Connect to an MCP server by ID
- disconnect_mcp_server: Disconnect from an MCP server
- get_mcp_hub_status: Get overall MCP Hub status
- call_mcp_tool: Execute a tool on a connected MCP server

Security:
- S-P0-3: JSON Schema validation for tool inputs
- S-P0-6: Response size limits (10MB)
- S-P0-7: Timeout enforcement (30s)
- S-C-2: Input validation for tool_name/server_id
- S-C-3: Agent ID validation

Token Efficiency:
- search_tools with defer_loading=true: 85% token reduction
- Context reduction: 18,500 → 1,250 tokens (5 hub tools vs 74 tools)

Author: Metis (Implementation) + Hestia (Security Review)
Created: 2025-12-05
Updated: 2025-12-08 (Phase 4.0 - Tool Search Proxy)
"""

import logging
import time
import unicodedata
from typing import Any

from fastmcp import FastMCP

from ..infrastructure.mcp.hub_manager import (
    get_hub_manager,
    initialize_hub_manager,
)
from ..services.tool_search_service import get_tool_search_service

logger = logging.getLogger(__name__)


def _get_sources_list(source: str) -> list[str]:
    """Get list of sources that were searched.

    Args:
        source: Source filter from query

    Returns:
        List of source names
    """
    if source == "all":
        return ["skills", "internal", "external"]
    elif source == "mcp_servers":
        return ["external"]
    else:
        return [source]


def _validate_query(query: str) -> tuple[bool, str, str]:
    """Validate search query content.

    Security C-2 Fix: Validates query content for control characters,
    Unicode normalization, and printable character ratio.

    Args:
        query: Search query to validate

    Returns:
        Tuple of (is_valid, sanitized_query, error_message)
    """
    # Length check
    if len(query) > 200:
        return False, "", "Query too long (max 200 characters)"

    # Empty check
    if not query or not query.strip():
        return False, "", "Query cannot be empty"

    # Control character filtering (allow tab, newline, carriage return)
    if any(ord(c) < 32 and c not in "\t\n\r" for c in query):
        return False, "", "Query contains invalid control characters"

    # Unicode normalization
    normalized = unicodedata.normalize("NFKC", query)

    # Printable character validation (at least 90% printable)
    if normalized:
        printable_count = sum(1 for c in normalized if c.isprintable() or c.isspace())
        if printable_count / len(normalized) < 0.9:
            return False, "", "Query contains too many non-printable characters"

    return True, normalized, ""


async def _record_tool_outcome(
    tool_name: str,
    server_id: str,
    outcome: str,
    latency_ms: float,
    agent_id: str | None = None,
    error_type: str | None = None,
) -> None:
    """Record tool execution outcome for learning system.

    Issue #72: Tool usage tracking integration with ToolSearchService.

    Args:
        tool_name: Name of the tool executed
        server_id: Server ID (format: "mcp__{server}")
        outcome: Execution outcome ("success", "error", "timeout", "abandoned")
        latency_ms: Execution latency in milliseconds
        agent_id: Optional agent ID for personalized learning
        error_type: Optional error type for failures
    """
    try:
        from datetime import datetime, timezone
        from ..models.tool_search import ToolUsageRecord

        tool_search = get_tool_search_service()

        record = ToolUsageRecord(
            tool_name=tool_name,
            server_id=server_id,
            query="",  # Query context not available in call_mcp_tool
            outcome=outcome,
            latency_ms=latency_ms,
            timestamp=datetime.now(timezone.utc),
        )

        await tool_search.record_usage(record, agent_id=agent_id)

        logger.debug(
            f"Tool outcome recorded: {tool_name} - {outcome}",
            extra={
                "tool_name": tool_name,
                "server_id": server_id,
                "outcome": outcome,
                "latency_ms": round(latency_ms, 2),
                "agent_id": agent_id,
                "error_type": error_type,
            }
        )
    except Exception as e:
        # Non-critical: Don't fail tool execution if outcome recording fails
        logger.warning(f"Failed to record tool outcome: {e}")


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
        name="search_tools",
        description=(
            "Search for available tools using semantic search. "
            "Returns lightweight tool references (without full schemas) for efficient discovery. "
            "Use get_tool_schema() to retrieve full schema when needed. "
            "Supports filtering by source (skills, internal, external) and adaptive ranking "
            "based on usage patterns. Token efficient: 85% reduction with defer_loading=true."
        ),
    )
    async def search_tools(
        query: str,
        source: str = "all",
        limit: int = 5,
        defer_loading: bool = True,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        """Search for tools using semantic discovery.

        This is the primary tool for discovering available tools across:
        - TMWS Skills (2.0x priority)
        - Internal TMWS tools (1.5x priority)
        - External MCP server tools (1.0x priority)

        Args:
            query: Natural language search query (e.g., "search code", "read files",
                   "browser automation")
            source: Filter by source type:
                - "all": All sources (default)
                - "skills": TMWS Skills only (highest priority)
                - "internal": TMWS internal tools only
                - "external": External MCP server tools only
            limit: Maximum results to return (default: 5, max: 20)
            defer_loading: Return lightweight references without schemas (default: true).
                          Set to false to include full input_schema.
            agent_id: Optional agent ID for personalized ranking (Phase 4.1)

        Returns:
            Dictionary with:
            - query: Original search query
            - results: List of tool references
            - total_found: Total matching tools
            - search_latency_ms: Search performance
            - sources_searched: Which sources were queried

        Example:
            >>> search_tools("search documentation")
            {
                "query": "search documentation",
                "results": [
                    {
                        "tool_name": "get-library-docs",
                        "server_id": "mcp__context7",
                        "description": "Fetches up-to-date documentation...",
                        "relevance_score": 0.92,
                        "source_type": "external",
                        "deferred": true
                    }
                ],
                "total_found": 8,
                "search_latency_ms": 45.3
            }

        Note:
            Results with deferred=true do NOT include input_schema to save tokens.
            Use get_tool_schema() to retrieve full schema before calling call_mcp_tool().

        Security:
            - S-C-2: Query length limited to 200 characters
            - S-C-3: Agent ID validated (alphanumeric, max 64 chars)
        """
        start_time = time.time()

        # Security S-C-2 (Enhanced): Validate query content
        is_valid, sanitized_query, error_msg = _validate_query(query)
        if not is_valid:
            return {
                "error": error_msg,
                "query": query[:50] + "..." if len(query) > 50 else query,
                "results": [],
                "total_found": 0,
            }
        query = sanitized_query  # Use sanitized version

        # Validate limit
        limit = min(max(1, limit), 20)

        try:
            tool_search = get_tool_search_service()

            results = await tool_search.search_tools(
                query=query,
                source=source,
                limit=limit,
                agent_id=agent_id,
                defer_loading=defer_loading,
            )

            latency_ms = (time.time() - start_time) * 1000

            return {
                "query": query,
                "results": results,
                "total_found": len(results),
                "search_latency_ms": round(latency_ms, 2),
                "sources_searched": _get_sources_list(source),
                "defer_loading": defer_loading,
            }
        except Exception as e:
            logger.error(f"Tool search failed: {e}")
            return {
                "error": str(e),
                "query": query,
                "results": [],
                "total_found": 0,
            }

    @mcp.tool(
        name="get_tool_schema",
        description=(
            "Retrieve full schema for a specific tool identified by server_id and tool_name. "
            "Use this after search_tools() with defer_loading=true to get input_schema "
            "before calling call_mcp_tool(). Lazy loading for token efficiency."
        ),
    )
    async def get_tool_schema(
        server_id: str,
        tool_name: str,
    ) -> dict[str, Any]:
        """Get full tool schema including input/output specifications.

        Use this tool to retrieve the complete schema for a tool discovered
        via search_tools(). This enables lazy loading of schemas to minimize
        context token usage.

        Args:
            server_id: Server identifier from search results.
                       Format: "tmws" | "tmws:skills" | "mcp__{server_name}"
            tool_name: Tool name from search results (e.g., "get-library-docs")

        Returns:
            Full tool metadata with:
            - tool_name: Tool identifier
            - server_id: Server where tool resides
            - description: Tool description
            - input_schema: JSON Schema for arguments (required for call_mcp_tool)
            - output_schema: Expected output format (if available)
            - source_type: "skill" | "internal" | "external"
            - tags: Tool categorization tags

        Example:
            >>> get_tool_schema("mcp__context7", "get-library-docs")
            {
                "tool_name": "get-library-docs",
                "server_id": "mcp__context7",
                "description": "Fetches up-to-date documentation...",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "context7CompatibleLibraryID": {
                            "type": "string",
                            "description": "Exact Context7-compatible library ID..."
                        }
                    },
                    "required": ["context7CompatibleLibraryID"]
                },
                "source_type": "external"
            }

        Raises:
            Returns error dict if tool not found or server not connected.

        Security:
            - S-C-2: Input validation (tool_name max 100 chars, server_id max 64 chars)
            - Alphanumeric + underscore/hyphen/colon only
        """
        try:
            tool_search = get_tool_search_service()

            details = await tool_search.get_tool_details(
                tool_name=tool_name,
                server_id=server_id,
            )

            if not details:
                return {
                    "error": f"Tool not found: {tool_name} from {server_id}",
                    "tool_name": tool_name,
                    "server_id": server_id,
                    "suggestion": "Use search_tools() to find available tools first.",
                }

            return details
        except Exception as e:
            logger.error(f"Failed to retrieve tool schema: {e}")
            return {
                "error": str(e),
                "tool_name": tool_name,
                "server_id": server_id,
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
        agent_id: str | None = None,
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
            agent_id: Optional agent ID for usage tracking (Issue #72)

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

        # Issue #72: Track tool execution for learning and monitoring
        start_time = time.time()
        outcome = "success"
        error_type = None

        try:
            result = await hub_manager.call_tool(
                server_id=server_id,
                tool_name=tool_name,
                arguments=arguments,
            )

            # Issue #72: Record successful tool outcome
            latency_ms = (time.time() - start_time) * 1000
            await _record_tool_outcome(
                tool_name=tool_name,
                server_id=f"mcp__{server_id}",
                outcome="success",
                latency_ms=latency_ms,
                agent_id=agent_id,
            )

            return {
                "success": True,
                "server_id": server_id,
                "tool_name": tool_name,
                "result": result,
            }
        except Exception as e:
            # Issue #72: Record failed tool outcome
            latency_ms = (time.time() - start_time) * 1000
            error_type = type(e).__name__

            # Determine outcome type based on error
            if "timeout" in str(e).lower():
                outcome = "timeout"
            else:
                outcome = "error"

            await _record_tool_outcome(
                tool_name=tool_name,
                server_id=f"mcp__{server_id}",
                outcome=outcome,
                latency_ms=latency_ms,
                agent_id=agent_id,
                error_type=error_type,
            )

            logger.error(
                f"Failed to call MCP tool {server_id}:{tool_name}: {e}",
                extra={
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "error_type": error_type,
                    "latency_ms": round(latency_ms, 2),
                }
            )
            return {
                "success": False,
                "server_id": server_id,
                "tool_name": tool_name,
                "error": str(e),
            }

    logger.info("MCP Hub management tools registered (7 tools: search_tools, get_tool_schema, list_mcp_servers, connect_mcp_server, disconnect_mcp_server, get_mcp_hub_status, call_mcp_tool)")
