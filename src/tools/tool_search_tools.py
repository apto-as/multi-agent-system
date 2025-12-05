"""Tool Search MCP Tools for TMWS.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 1.2 - MCP Tool Registration

Provides MCP tools for:
- search_tools: Semantic tool discovery
- get_tool_stats: Tool search statistics

Performance target: < 100ms P95 latency

Author: Artemis (Implementation)
Created: 2025-12-04
"""

import logging
from typing import Any

from fastmcp import FastMCP

from ..services.tool_search_service import (
    get_tool_search_service,
    initialize_tool_search_service,
)

logger = logging.getLogger(__name__)


async def register_tools(mcp: FastMCP, **kwargs: Any) -> None:
    """Register Tool Search MCP tools.

    Args:
        mcp: FastMCP instance to register tools on
        **kwargs: Additional configuration options
    """
    # Get or initialize service
    embedding_service = kwargs.get("embedding_service")

    try:
        service = get_tool_search_service()
        if not service._collection:
            await service.initialize()
    except Exception:
        service = await initialize_tool_search_service(
            embedding_service=embedding_service,
            persist_directory=kwargs.get("persist_directory", "./data/chromadb"),
        )

    @mcp.tool(
        name="search_tools",
        description="Search for available tools using semantic search. Skills are prioritized (2.0x weight), followed by internal tools (1.5x), then external MCP tools (1.0x). Returns ranked results with relevance scores.",
    )
    async def search_tools(
        query: str,
        source: str = "all",
        limit: int = 10,
    ) -> dict[str, Any]:
        """Search for tools using semantic search.

        Integrates with TMWS 4 core features:
        - Skills: Prioritized in search results (2.0x weight)
        - Memory: Tool usage history considered
        - Learning: Adaptive ranking based on usage patterns

        Args:
            query: Natural language search query (e.g., "search code", "file operations")
            source: Filter by source type:
                   - "all": Search all sources (default)
                   - "skills": Only search TMWS Skills
                   - "internal": Only search built-in TMWS tools
                   - "external": Only search external MCP server tools
                   - "mcp_servers": Alias for "external"
            limit: Maximum number of results (default: 10, max: 50)

        Returns:
            Dictionary with:
            - results: List of matching tools with scores
            - query: Original query
            - total_found: Total matches found
            - search_latency_ms: Search time in milliseconds
            - sources_searched: Which sources were queried

        Examples:
            >>> search_tools("search code repository")
            {"results": [{"tool_name": "grep", "weighted_score": 0.95, ...}], ...}

            >>> search_tools("database operations", source="skills")
            {"results": [{"tool_name": "sql_query_skill", ...}], ...}
        """
        # Validate limit
        limit = max(1, min(limit, 50))

        try:
            results = await service.search_tools(
                query=query,
                source=source,
                limit=limit,
            )

            stats = await service.get_stats()

            return {
                "results": results,
                "query": query,
                "total_found": len(results),
                "search_latency_ms": 0,  # Will be added from response
                "sources_searched": _get_sources(source),
                "stats": {
                    "total_indexed": stats["total_indexed"],
                    "skills_count": 0,  # Will be populated when skills are registered
                    "internal_count": stats["internal_tools"],
                    "external_count": stats["mcp_server_tools"],
                },
            }
        except Exception as e:
            logger.error(f"Tool search failed: {e}")
            return {
                "error": str(e),
                "results": [],
                "query": query,
                "total_found": 0,
            }

    @mcp.tool(
        name="get_tool_search_stats",
        description="Get statistics about the tool search index, including counts of skills, internal tools, and external MCP tools.",
    )
    async def get_tool_search_stats() -> dict[str, Any]:
        """Get tool search statistics.

        Returns:
            Dictionary with:
            - collection_name: ChromaDB collection name
            - total_indexed: Total tools in index
            - internal_tools: Count of internal TMWS tools
            - mcp_servers: Count of connected MCP servers
            - mcp_server_tools: Total tools from MCP servers
            - cache_entries: Number of cached search results
        """
        try:
            return await service.get_stats()
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {"error": str(e)}

    logger.info("Tool Search MCP tools registered (2 tools)")


def _get_sources(source: str) -> list[str]:
    """Get list of sources for a filter.

    Args:
        source: Source filter

    Returns:
        List of source names
    """
    if source == "all":
        return ["skills", "internal", "external"]
    elif source == "mcp_servers":
        return ["external"]
    else:
        return [source]
