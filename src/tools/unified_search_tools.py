"""Unified Search MCP Tools for TMWS v2.4.18

Specification: CHROMADB_UNIFIED_SEARCH_DESIGN.md
Phase: 3.0 - Unified Search MCP Tools

Provides cross-collection semantic search across:
- Memories (1.5x weight)
- Skills (2.0x weight)
- Tools (1.0x weight)

Performance target: P95 < 200ms

Author: Artemis (Implementation)
Created: 2025-12-13
"""

import logging
from typing import Any

from fastmcp import FastMCP

logger = logging.getLogger(__name__)


async def register_tools(mcp: FastMCP, **kwargs: Any) -> None:
    """Register Unified Search MCP tools.

    Args:
        mcp: FastMCP instance to register tools on
        **kwargs: Additional configuration options including:
            - unified_search_service: UnifiedSearchService instance
            - memory_service: HybridMemoryService instance
            - skill_chroma_store: SkillChromaStore instance
            - tool_search_service: ToolSearchService instance
            - vector_search_service: VectorSearchService instance
            - embedding_service: Embedding service
    """
    # Get services from kwargs
    unified_search_service = kwargs.get("unified_search_service")

    # If not provided, initialize from dependencies
    if unified_search_service is None:
        from ..services.unified_search_service import UnifiedSearchService
        from ..storage.skill_chroma_store import get_skill_chroma_store

        memory_service = kwargs.get("memory_service")
        skill_chroma_store = kwargs.get("skill_chroma_store") or get_skill_chroma_store()
        tool_search_service = kwargs.get("tool_search_service")
        vector_search_service = kwargs.get("vector_search_service")
        embedding_service = kwargs.get("embedding_service")

        unified_search_service = UnifiedSearchService(
            memory_service=memory_service,
            skill_chroma_store=skill_chroma_store,
            tool_search_service=tool_search_service,
            vector_search_service=vector_search_service,
            embedding_service=embedding_service,
        )

    @mcp.tool(
        name="search_unified",
        description=(
            "Unified semantic search across Memories, Skills, and Tools. "
            "Skills are prioritized (2.0x), followed by Memories (1.5x), "
            "then Tools (1.0x). Returns aggregated ranked results."
        ),
    )
    async def search_unified(
        query: str,
        search_types: list[str] | None = None,
        limit: int = 10,
        namespace: str | None = None,
        agent_id: str | None = None,
        min_similarity: float = 0.7,
        detail_level: int = 2,
    ) -> dict[str, Any]:
        """Execute unified search across Memories, Skills, and Tools.

        Integrates with TMWS 4 core features:
        - Memory: Semantic memory search
        - Skills: Semantic skill search (prioritized 2.0x)
        - Tools: Tool discovery search
        - Learning: (Future) Adaptive ranking

        Args:
            query: Natural language search query
            search_types: Types to search ["skills", "memories", "tools"]
                         (defaults to all)
            limit: Maximum results to return (default: 10)
            namespace: Namespace filter (for memories and skills)
            agent_id: Agent ID filter (for memories)
            min_similarity: Minimum similarity threshold (0.0-1.0, default: 0.7)
            detail_level: Progressive Disclosure level (1=metadata, 2=core, 3=full)
                         Default: 2 (core info)

        Returns:
            Dictionary with:
            - results: List of ranked results across all types
            - by_type: Results grouped by type (memories, skills, tools)
            - query: Original query
            - total_found: Total matches found
            - search_latency_ms: Search time in milliseconds
            - sources_searched: Which sources were queried

        Examples:
            >>> search_unified("OAuth2 security authentication")
            {
                "results": [
                    {"type": "skill", "title": "oauth-security", "weighted_score": 0.95, ...},
                    {"type": "memory", "title": "Memory abc123", "weighted_score": 0.82, ...},
                    {"type": "tool", "title": "oauth-validator", "weighted_score": 0.75, ...}
                ],
                "by_type": {
                    "skill": [...],
                    "memory": [...],
                    "tool": [...]
                },
                "total_found": 15,
                "search_latency_ms": 125.4
            }

            >>> search_unified("database performance", search_types=["skills", "tools"])
            {
                "results": [...],
                "sources_searched": ["skills", "tools"]
            }
        """
        # M-4 Security Fix: Validate all inputs
        # Validate query length
        if not query or not query.strip():
            return {
                "error": "Query cannot be empty",
                "results": [],
                "query": query,
                "total_found": 0,
            }
        if len(query) > 1000:
            return {
                "error": "Query exceeds maximum length of 1000 characters",
                "results": [],
                "query": query[:50] + "...",
                "total_found": 0,
            }
        query = query.strip()

        # Validate search_types if provided
        if search_types is not None:
            valid_types = {"skills", "memories", "tools"}
            invalid_types = [t for t in search_types if t not in valid_types]
            if invalid_types:
                return {
                    "error": f"Invalid search types: {invalid_types}",
                    "results": [],
                    "query": query,
                    "total_found": 0,
                }

        # Validate limit
        limit = max(1, min(limit, 50))

        # Validate min_similarity
        min_similarity = max(0.0, min(min_similarity, 1.0))

        # Validate detail_level
        if detail_level not in [1, 2, 3]:
            return {
                "error": "Invalid detail_level: must be 1, 2, or 3",
                "results": [],
                "query": query,
                "total_found": 0,
            }

        # Validate namespace if provided
        if namespace:
            import re
            if len(namespace) > 64 or not re.match(r'^[a-zA-Z0-9_-]+$', namespace):
                return {
                    "error": "Invalid namespace format",
                    "results": [],
                    "query": query,
                    "total_found": 0,
                }

        # Validate agent_id if provided
        if agent_id:
            import re
            if len(agent_id) > 64 or not re.match(r'^[a-zA-Z0-9_-]+$', agent_id):
                return {
                    "error": "Invalid agent_id format",
                    "results": [],
                    "query": query,
                    "total_found": 0,
                }

        try:
            # Execute unified search
            result = await unified_search_service.unified_search(
                query=query,
                search_types=search_types,
                limit=limit,
                namespace=namespace,
                agent_id=agent_id,
                min_similarity=min_similarity,
                detail_level=detail_level,
            )

            # Convert to dict format
            return {
                "results": [
                    {
                        "type": item.type.value,
                        "id": item.id,
                        "title": item.title,
                        "description": item.description,
                        "relevance_score": item.relevance_score,
                        "weighted_score": item.weighted_score,
                        "metadata": item.metadata,
                        "content": item.content if detail_level >= 2 else None,
                    }
                    for item in result.results
                ],
                "by_type": {
                    type_key.value: [
                        {
                            "type": item.type.value,
                            "id": item.id,
                            "title": item.title,
                            "description": item.description,
                            "relevance_score": item.relevance_score,
                            "weighted_score": item.weighted_score,
                            "metadata": item.metadata,
                        }
                        for item in items
                    ]
                    for type_key, items in result.by_type.items()
                },
                "query": result.query,
                "total_found": result.total_found,
                "search_latency_ms": result.search_latency_ms,
                "sources_searched": result.sources_searched,
                "detail_level": detail_level,
            }

        except Exception as e:
            logger.error(f"Unified search failed: {e}")
            return {
                "error": str(e),
                "results": [],
                "query": query,
                "total_found": 0,
            }

    logger.info("Unified Search MCP tool registered (1 tool)")
