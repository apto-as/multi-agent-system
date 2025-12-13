"""Unified Search Service for TMWS v2.4.18
Cross-collection semantic search across Memories, Skills, and Tools.

Specification: CHROMADB_UNIFIED_SEARCH_DESIGN.md
Phase: 2.0 - Unified Search Service

Performance target: P95 < 200ms

Author: Artemis (Implementation)
Created: 2025-12-13
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..storage.skill_chroma_store import SkillChromaStore, get_skill_chroma_store
from ..services.memory_service.core import HybridMemoryService
from ..services.tool_search_service import ToolSearchService
from ..services.vector_search_service import VectorSearchService

logger = logging.getLogger(__name__)


class SearchResultType(str, Enum):
    """Type of search result."""

    MEMORY = "memory"
    SKILL = "skill"
    TOOL = "tool"


@dataclass
class UnifiedSearchItem:
    """Single search result item."""

    type: SearchResultType
    id: str
    title: str  # Normalized title field
    description: str  # Normalized description
    relevance_score: float  # 0.0-1.0 (raw similarity)
    weighted_score: float  # After source weighting
    metadata: dict[str, Any]
    content: str | None = None  # Progressive Disclosure Level 2+


@dataclass
class UnifiedSearchResult:
    """Aggregated search results."""

    query: str
    results: list[UnifiedSearchItem]
    total_found: int
    search_latency_ms: float
    sources_searched: list[str]  # ["memories", "skills", "tools"]

    # Results grouped by type (for UI)
    by_type: dict[SearchResultType, list[UnifiedSearchItem]]


class UnifiedSearchService:
    """Unified semantic search across Memories, Skills, and Tools.

    Architecture:
    - Parallel search across 3 ChromaDB collections
    - Result aggregation with source-weighted ranking
    - Progressive Disclosure support
    - P95 < 200ms performance target

    Source Weighting:
    - Skills: 2.0x (prioritized, third core feature)
    - Memories: 1.5x (contextual importance)
    - Tools: 1.0x (baseline)

    Usage:
        service = UnifiedSearchService(
            memory_service=memory_service,
            skill_chroma_store=skill_store,
            tool_search_service=tool_service,
        )

        result = await service.unified_search(
            query="OAuth2 security best practices",
            search_types=["skills", "memories", "tools"],
            limit=10,
            namespace="security",
            min_similarity=0.7
        )
    """

    # Source weighting configuration
    SKILL_WEIGHT = 2.0
    MEMORY_WEIGHT = 1.5
    TOOL_WEIGHT = 1.0

    def __init__(
        self,
        memory_service: HybridMemoryService | None = None,
        skill_chroma_store: SkillChromaStore | None = None,
        tool_search_service: ToolSearchService | None = None,
        vector_search_service: VectorSearchService | None = None,
        embedding_service: Any = None,
    ):
        """Initialize Unified Search Service.

        Args:
            memory_service: HybridMemoryService for memory search
            skill_chroma_store: SkillChromaStore for skill vector search
            tool_search_service: ToolSearchService for tool search
            vector_search_service: VectorSearchService for direct memory vector search
            embedding_service: Service for generating query embeddings
        """
        self.memory_service = memory_service
        self.skill_chroma_store = skill_chroma_store or get_skill_chroma_store()
        self.tool_search_service = tool_search_service
        self.vector_search_service = vector_search_service
        self.embedding_service = embedding_service

        logger.info("🔍 UnifiedSearchService initialized")

    async def unified_search(
        self,
        query: str,
        search_types: list[str] = None,
        limit: int = 10,
        namespace: str | None = None,
        agent_id: str | None = None,
        min_similarity: float = 0.7,
        detail_level: int = 2,
    ) -> UnifiedSearchResult:
        """Execute parallel search across selected types.

        Performance:
        - Generate embedding: ~50ms (Ollama)
        - Parallel ChromaDB searches: ~20ms (3 collections)
        - Result aggregation: ~10ms
        - Total: ~80ms P50, ~200ms P95

        Args:
            query: Search query string
            search_types: Types to search ["skills", "memories", "tools"]
                         (defaults to all)
            limit: Maximum results per type
            namespace: Namespace filter (for memories and skills)
            agent_id: Agent ID filter (for memories)
            min_similarity: Minimum similarity threshold (0.0-1.0)
            detail_level: Progressive Disclosure level (1=metadata, 2=core, 3=full)

        Returns:
            UnifiedSearchResult with ranked results by type
        """
        start_time = time.time()

        # Default to searching all types
        if search_types is None:
            search_types = ["skills", "memories", "tools"]

        # Validate search_types
        valid_types = {"skills", "memories", "tools"}
        search_types = [t for t in search_types if t in valid_types]

        if not search_types:
            logger.warning("No valid search types provided")
            return UnifiedSearchResult(
                query=query,
                results=[],
                total_found=0,
                search_latency_ms=0,
                sources_searched=[],
                by_type={},
            )

        # Generate query embedding (shared across all searches)
        query_embedding = None
        if self.embedding_service:
            try:
                embedding_result = await self.embedding_service.encode_query(query)
                query_embedding = embedding_result.tolist()
            except Exception as e:
                logger.error(f"Failed to generate query embedding: {e}")
                # Continue with text-based search fallback

        # Parallel search across collections
        tasks = []
        task_types = []

        if "skills" in search_types:
            tasks.append(self._search_skills(query_embedding, limit, namespace, min_similarity))
            task_types.append("skills")

        if "memories" in search_types:
            tasks.append(
                self._search_memories(
                    query_embedding, limit, namespace, agent_id, min_similarity
                )
            )
            task_types.append("memories")

        if "tools" in search_types:
            tasks.append(self._search_tools(query, limit, min_similarity))
            task_types.append("tools")

        # Execute all searches in parallel
        search_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate results
        all_items = []
        by_type = {}

        for idx, result in enumerate(search_results):
            result_type = task_types[idx]

            if isinstance(result, Exception):
                logger.error(f"Search failed for {result_type}: {result}")
                by_type[SearchResultType(result_type)] = []
                continue

            # Convert to UnifiedSearchItem
            items = self._convert_results(result, result_type)
            all_items.extend(items)
            by_type[SearchResultType(result_type)] = items

        # Apply source-weighted ranking
        ranked_results = self._apply_source_ranking(all_items)

        # Limit total results
        final_results = ranked_results[:limit]

        latency_ms = (time.time() - start_time) * 1000

        logger.info(
            f"🔍 Unified search completed in {latency_ms:.2f}ms: "
            f"{len(final_results)} results from {len(search_types)} sources"
        )

        return UnifiedSearchResult(
            query=query,
            results=final_results,
            total_found=len(ranked_results),
            search_latency_ms=latency_ms,
            sources_searched=search_types,
            by_type=by_type,
        )

    async def _search_skills(
        self,
        query_embedding: list[float] | None,
        limit: int,
        namespace: str | None,
        min_similarity: float,
    ) -> list[dict[str, Any]]:
        """Search Skills collection.

        Args:
            query_embedding: Query embedding vector
            limit: Maximum results
            namespace: Namespace filter
            min_similarity: Minimum similarity threshold

        Returns:
            List of skill search results
        """
        if query_embedding is None:
            logger.warning("No query embedding for skill search")
            return []

        # Build filters
        filters = {}
        if namespace:
            filters["namespace"] = namespace

        # Search skill ChromaDB collection
        results = await self.skill_chroma_store.search(
            query_embedding=query_embedding,
            top_k=limit,
            filters=filters if filters else None,
            min_similarity=min_similarity,
        )

        return results

    async def _search_memories(
        self,
        query_embedding: list[float] | None,
        limit: int,
        namespace: str | None,
        agent_id: str | None,
        min_similarity: float,
    ) -> list[dict[str, Any]]:
        """Search Memories collection.

        Args:
            query_embedding: Query embedding vector
            limit: Maximum results
            namespace: Namespace filter
            agent_id: Agent ID filter
            min_similarity: Minimum similarity threshold

        Returns:
            List of memory search results
        """
        if query_embedding is None:
            logger.warning("No query embedding for memory search")
            return []

        # Use VectorSearchService directly for better control
        if self.vector_search_service:
            filters = {}
            if namespace:
                filters["namespace"] = namespace
            if agent_id:
                filters["agent_id"] = agent_id

            results = await self.vector_search_service.search(
                query_embedding=query_embedding,
                top_k=limit,
                filters=filters if filters else None,
                min_similarity=min_similarity,
            )
            return results
        else:
            logger.warning("VectorSearchService not available")
            return []

    async def _search_tools(
        self,
        query: str,
        limit: int,
        min_similarity: float,
    ) -> list[dict[str, Any]]:
        """Search Tools collection.

        Args:
            query: Query string
            limit: Maximum results
            min_similarity: Minimum similarity threshold

        Returns:
            List of tool search results
        """
        if self.tool_search_service is None:
            logger.warning("ToolSearchService not available")
            return []

        # Use tool search service
        results = await self.tool_search_service.search_tools(
            query=query,
            source="all",
            limit=limit,
            detail_level=2,  # Core info
        )

        return results

    def _convert_results(
        self,
        results: list[dict[str, Any]],
        result_type: str,
    ) -> list[UnifiedSearchItem]:
        """Convert search results to UnifiedSearchItem.

        Args:
            results: Raw search results
            result_type: Type of results ("skills", "memories", "tools")

        Returns:
            List of UnifiedSearchItem
        """
        items = []

        for result in results:
            if result_type == "skills":
                # Skill result format from ChromaDB
                items.append(
                    UnifiedSearchItem(
                        type=SearchResultType.SKILL,
                        id=result.get("id", ""),
                        title=result.get("metadata", {}).get("skill_name", "Unnamed Skill"),
                        description=result.get("metadata", {}).get("description", "")[:200],
                        relevance_score=result.get("similarity", 0.0),
                        weighted_score=result.get("similarity", 0.0)
                        * self.SKILL_WEIGHT,  # 2.0x
                        metadata=result.get("metadata", {}),
                        content=result.get("content"),
                    )
                )

            elif result_type == "memories":
                # Memory result format from VectorSearchService
                items.append(
                    UnifiedSearchItem(
                        type=SearchResultType.MEMORY,
                        id=result.get("id", ""),
                        title=f"Memory {result.get('id', '')[:8]}",
                        description=result.get("content", "")[:200] if result.get("content") else "",
                        relevance_score=result.get("similarity", 0.0),
                        weighted_score=result.get("similarity", 0.0)
                        * self.MEMORY_WEIGHT,  # 1.5x
                        metadata=result.get("metadata", {}),
                        content=result.get("content"),
                    )
                )

            elif result_type == "tools":
                # Tool result format from ToolSearchService
                items.append(
                    UnifiedSearchItem(
                        type=SearchResultType.TOOL,
                        id=f"{result.get('server_id', '')}:{result.get('tool_name', '')}",
                        title=result.get("tool_name", "Unnamed Tool"),
                        description=result.get("description", "")[:200],
                        relevance_score=result.get("relevance_score", 0.0),
                        weighted_score=result.get("weighted_score", 0.0)
                        * self.TOOL_WEIGHT,  # 1.0x
                        metadata={
                            "server_id": result.get("server_id", ""),
                            "source_type": result.get("source_type", ""),
                            "tags": result.get("tags", []),
                        },
                        content=None,  # Tools don't have content field
                    )
                )

        return items

    def _apply_source_ranking(
        self,
        items: list[UnifiedSearchItem],
    ) -> list[UnifiedSearchItem]:
        """Apply source-weighted ranking.

        Weights are already applied in _convert_results().
        This method just sorts by weighted_score.

        Args:
            items: List of search items

        Returns:
            Sorted list by weighted_score descending
        """
        return sorted(items, key=lambda item: item.weighted_score, reverse=True)


# Singleton instance
_unified_search_service_instance = None


def get_unified_search_service(
    memory_service: HybridMemoryService | None = None,
    skill_chroma_store: SkillChromaStore | None = None,
    tool_search_service: ToolSearchService | None = None,
    vector_search_service: VectorSearchService | None = None,
    embedding_service: Any = None,
) -> UnifiedSearchService:
    """Get singleton instance of UnifiedSearchService.

    Args:
        memory_service: Optional HybridMemoryService (for first init)
        skill_chroma_store: Optional SkillChromaStore (for first init)
        tool_search_service: Optional ToolSearchService (for first init)
        vector_search_service: Optional VectorSearchService (for first init)
        embedding_service: Optional embedding service (for first init)

    Returns:
        Singleton instance

    Example:
        >>> from src.services.unified_search_service import get_unified_search_service
        >>> service = get_unified_search_service(
        ...     memory_service=memory_service,
        ...     skill_chroma_store=skill_store,
        ...     tool_search_service=tool_service,
        ...     vector_search_service=vector_service,
        ...     embedding_service=embedding_service,
        ... )
        >>> result = await service.unified_search("OAuth2 security")
    """
    global _unified_search_service_instance

    if _unified_search_service_instance is None:
        _unified_search_service_instance = UnifiedSearchService(
            memory_service=memory_service,
            skill_chroma_store=skill_chroma_store,
            tool_search_service=tool_search_service,
            vector_search_service=vector_search_service,
            embedding_service=embedding_service,
        )

    return _unified_search_service_instance
