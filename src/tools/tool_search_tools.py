"""Tool Search MCP Tools for TMWS.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 1.2 - MCP Tool Registration
Phase: 4.1 - Adaptive Ranking Integration
Phase: 4.2 - Tool Promotion

Provides MCP tools for:
- search_tools: Semantic tool discovery with personalized ranking
- get_tool_stats: Tool search statistics
- record_tool_outcome: Record tool usage for learning
- get_promotion_candidates: Find tools eligible for promotion
- promote_tool: Promote a tool to a Skill

Performance target: < 100ms P95 latency

Author: Artemis (Implementation)
Created: 2025-12-04
Updated: 2025-12-05 (Phase 4.1, 4.2)
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
        description="Search for available tools using semantic search. Skills are prioritized (2.0x weight), followed by internal tools (1.5x), then external MCP tools (1.0x). Provides personalized ranking when agent_id is provided.",
    )
    async def search_tools(
        query: str,
        source: str = "all",
        limit: int = 10,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        """Search for tools using semantic search.

        Integrates with TMWS 4 core features:
        - Skills: Prioritized in search results (2.0x weight)
        - Memory: Tool usage history considered
        - Learning: Adaptive ranking based on usage patterns (Phase 4.1)

        Args:
            query: Natural language search query (e.g., "search code", "file operations")
            source: Filter by source type:
                   - "all": Search all sources (default)
                   - "skills": Only search TMWS Skills
                   - "internal": Only search built-in TMWS tools
                   - "external": Only search external MCP server tools
                   - "mcp_servers": Alias for "external"
            limit: Maximum number of results (default: 10, max: 50)
            agent_id: Optional agent identifier for personalized ranking.
                     When provided, results are ranked based on agent's usage history.

        Returns:
            Dictionary with:
            - results: List of matching tools with scores and personalization_boost
            - query: Original query
            - total_found: Total matches found
            - search_latency_ms: Search time in milliseconds
            - sources_searched: Which sources were queried
            - personalized: Whether personalization was applied

        Examples:
            >>> search_tools("search code repository")
            {"results": [{"tool_name": "grep", "weighted_score": 0.95, ...}], ...}

            >>> search_tools("database operations", source="skills", agent_id="artemis")
            {"results": [{"tool_name": "sql_query_skill", "personalization_boost": 0.15, ...}], ...}
        """
        # Validate limit
        limit = max(1, min(limit, 50))

        try:
            results = await service.search_tools(
                query=query,
                source=source,
                limit=limit,
                agent_id=agent_id,
            )

            stats = await service.get_stats()

            return {
                "results": results,
                "query": query,
                "total_found": len(results),
                "search_latency_ms": 0,  # Will be added from response
                "sources_searched": _get_sources(source),
                "personalized": agent_id is not None,
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

    @mcp.tool(
        name="record_tool_outcome",
        description="Record the outcome of a tool execution for learning. This enables personalized ranking in future searches. Call after executing any tool.",
    )
    async def record_tool_outcome(
        tool_name: str,
        server_id: str,
        query: str,
        outcome: str,
        agent_id: str,
        latency_ms: float = 0.0,
    ) -> dict[str, Any]:
        """Record tool execution outcome for adaptive learning.

        Phase 4.1: Integrates with TMWS Learning system for personalized ranking.
        Recording outcomes helps improve future search results for this agent.

        Args:
            tool_name: Name of the tool that was executed
            server_id: Server ID where the tool resides (e.g., "tmws", "mcp__context7")
            query: Original search query that led to this tool
            outcome: Execution outcome - one of:
                    - "success": Tool executed successfully
                    - "error": Tool execution failed
                    - "timeout": Tool execution timed out
                    - "abandoned": User abandoned before completion
            agent_id: ID of the agent that used the tool
            latency_ms: Execution time in milliseconds (optional)

        Returns:
            Dictionary with:
            - recorded: True if outcome was recorded
            - tool_name: Name of the tool
            - outcome: The recorded outcome

        Examples:
            >>> record_tool_outcome("grep", "tmws", "search code", "success", "artemis", 45.2)
            {"recorded": True, "tool_name": "grep", "outcome": "success"}
        """
        from datetime import datetime

        from ..models.tool_search import ToolUsageRecord

        try:
            record = ToolUsageRecord(
                tool_name=tool_name,
                server_id=server_id,
                query=query,
                outcome=outcome,
                latency_ms=latency_ms,
                timestamp=datetime.now(),
            )

            await service.record_usage(record, agent_id=agent_id)

            return {
                "recorded": True,
                "tool_name": tool_name,
                "outcome": outcome,
                "agent_id": agent_id,
            }
        except Exception as e:
            logger.error(f"Failed to record tool outcome: {e}")
            return {
                "recorded": False,
                "error": str(e),
                "tool_name": tool_name,
            }

    # Phase 4.2: Tool Promotion tools
    # Initialize promotion service (lazy)
    promotion_service = None

    def _get_promotion_service():
        nonlocal promotion_service
        if promotion_service is None:
            from ..services.tool_promotion_service import ToolPromotionService

            promotion_service = ToolPromotionService()
            # Try to connect to adaptive ranker if available
            if hasattr(service, "_adaptive_ranker") and service._adaptive_ranker:
                promotion_service.set_adaptive_ranker(service._adaptive_ranker)
        return promotion_service

    @mcp.tool(
        name="get_promotion_candidates",
        description="Get tools that are candidates for promotion to Skills. Shows tools with high usage and success rates that could become Skills.",
    )
    async def get_promotion_candidates(
        agent_id: str | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:
        """Get tools eligible for promotion to Skills.

        Phase 4.2: Tool → Skill Promotion

        Tools can be promoted to Skills when they meet criteria:
        - Minimum 50 uses
        - Minimum 85% success rate
        - Used across at least 5 different query contexts

        Args:
            agent_id: Optional agent ID to filter candidates
            limit: Maximum candidates to return (default: 10)

        Returns:
            Dictionary with:
            - candidates: List of promotion candidates
            - criteria: Current promotion criteria
            - total_candidates: Total eligible candidates

        Examples:
            >>> get_promotion_candidates(agent_id="artemis")
            {"candidates": [{"tool_name": "grep", "promotion_score": 0.92, ...}], ...}
        """
        try:
            promo = _get_promotion_service()
            candidates = await promo.get_promotion_candidates(
                agent_id=agent_id,
                limit=limit,
            )
            stats = await promo.get_promotion_stats()

            return {
                "candidates": [c.to_dict() for c in candidates],
                "criteria": stats["criteria"],
                "total_candidates": len(candidates),
            }
        except Exception as e:
            logger.error(f"Failed to get promotion candidates: {e}")
            return {"error": str(e), "candidates": []}

    @mcp.tool(
        name="promote_tool",
        description="Promote a frequently-used tool to a Skill. This creates a new Skill based on the tool's usage patterns.",
    )
    async def promote_tool(
        tool_name: str,
        server_id: str,
        agent_id: str,
        skill_name: str | None = None,
        description: str | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        """Promote a tool to a Skill.

        Phase 4.2: Integrates with TMWS Skills (3rd core feature).

        Args:
            tool_name: Name of the tool to promote
            server_id: Server ID where the tool resides
            agent_id: Agent requesting the promotion
            skill_name: Optional custom name for the skill
            description: Optional description for the skill
            force: Skip criteria check if True (admin only)

        Returns:
            Dictionary with:
            - success: True if promotion succeeded
            - skill_id: ID of the created skill (if successful)
            - skill_name: Name of the created skill
            - error: Error message (if failed)

        Examples:
            >>> promote_tool("grep", "tmws", "artemis")
            {"success": True, "skill_id": "skill_123", "skill_name": "Promoted: grep"}
        """
        try:
            promo = _get_promotion_service()
            result = await promo.promote_tool(
                tool_name=tool_name,
                server_id=server_id,
                agent_id=agent_id,
                skill_name=skill_name,
                description=description,
                force=force,
            )
            return result.to_dict()
        except Exception as e:
            logger.error(f"Failed to promote tool: {e}")
            return {
                "success": False,
                "tool_name": tool_name,
                "error": str(e),
            }

    logger.info("Tool Search MCP tools registered (5 tools)")


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
