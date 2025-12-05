"""Tool Search Service for TMWS Tool Discovery Engine.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 1.2 - Tool Search Service

Provides semantic search across:
1. TMWS Skills (2.0x weight) - Third core feature
2. Internal TMWS tools (1.5x weight)
3. External MCP server tools (1.0x weight)

Performance target: < 100ms P95 latency

Author: Artemis (Implementation)
Created: 2025-12-04
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

import chromadb
from chromadb.config import Settings

from ..models.tool_search import (
    MCPServerMetadata,
    ToolMetadata,
    ToolSearchQuery,
    ToolSearchResponse,
    ToolSearchResult,
    ToolSourceType,
    ToolUsageRecord,
)

# Phase 4.1: Adaptive Ranking imports (lazy to avoid circular)
# AdaptiveRanker and ToolOutcome imported at runtime

logger = logging.getLogger(__name__)


@dataclass
class ToolSearchConfig:
    """Configuration for Tool Search Service."""

    collection_name: str = "tmws_tools"
    skills_weight: float = 2.0
    internal_weight: float = 1.5
    external_weight: float = 1.0
    cache_ttl_seconds: int = 3600
    max_results: int = 50
    min_similarity: float = 0.3

    # Phase 4.1: Adaptive Ranking settings
    enable_adaptive_ranking: bool = True
    adaptive_success_rate_boost: float = 0.2
    adaptive_frequency_boost: float = 0.1
    adaptive_recency_boost: float = 0.1


class ToolSearchService:
    """Service for semantic tool discovery.

    Uses ChromaDB for vector search with:
    - Separate collection from memories (tmws_tools vs tmws_memories)
    - BM25 + vector hybrid search
    - Source-weighted ranking

    Integration with 4 Core Features:
    - Memory: Tool usage stored in Memory
    - Narrative: Search context for Narrative
    - Skills: Skills prioritized in ranking
    - Learning: Usage patterns for adaptive ranking
    """

    def __init__(
        self,
        config: ToolSearchConfig | None = None,
        persist_directory: str = "./data/chromadb",
        embedding_service: Any = None,
        learning_service: Any = None,
    ):
        """Initialize Tool Search Service.

        Args:
            config: Service configuration
            persist_directory: ChromaDB persistence directory
            embedding_service: Service for generating embeddings
            learning_service: LearningService for adaptive ranking (Phase 4.1)
        """
        self.config = config or ToolSearchConfig()
        self.persist_directory = persist_directory
        self.embedding_service = embedding_service

        # Initialize ChromaDB client
        self._client = chromadb.PersistentClient(
            path=persist_directory,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True,
            ),
        )

        self._collection = None
        self._internal_tools: dict[str, ToolMetadata] = {}
        self._mcp_servers: dict[str, MCPServerMetadata] = {}

        # Cache for search results
        self._cache: dict[str, tuple[float, list[ToolSearchResult]]] = {}

        # Phase 4.1: Adaptive Ranking
        self._adaptive_ranker = None
        if self.config.enable_adaptive_ranking:
            from .adaptive_ranker import AdaptiveRanker, AdaptiveRankingConfig

            ranker_config = AdaptiveRankingConfig(
                success_rate_boost=self.config.adaptive_success_rate_boost,
                frequency_boost=self.config.adaptive_frequency_boost,
                recency_boost=self.config.adaptive_recency_boost,
            )
            self._adaptive_ranker = AdaptiveRanker(
                config=ranker_config, learning_service=learning_service
            )

        logger.info(
            f"ToolSearchService initialized (collection: {self.config.collection_name}, "
            f"adaptive_ranking: {self.config.enable_adaptive_ranking})"
        )

    async def initialize(self) -> None:
        """Initialize ChromaDB collection for tools.

        Creates or gets the tmws_tools collection with HNSW index.
        """
        try:
            self._collection = await asyncio.to_thread(
                self._client.get_or_create_collection,
                name=self.config.collection_name,
                metadata={
                    "hnsw:space": "cosine",
                    "hnsw:M": 16,
                    "hnsw:ef_construction": 200,
                    "description": "TMWS Tool Discovery Engine",
                },
            )
            count = self._collection.count()
            logger.info(f"Collection '{self.config.collection_name}' ready ({count} tools)")
        except Exception as e:
            logger.error(f"Failed to initialize collection: {e}")
            raise

    async def register_internal_tools(self, tools: list[ToolMetadata]) -> int:
        """Register internal TMWS tools.

        Args:
            tools: List of tool metadata to register

        Returns:
            Number of tools registered
        """
        for tool in tools:
            self._internal_tools[tool.name] = tool

        # Add to vector store
        await self._index_tools(tools, source_type=ToolSourceType.INTERNAL, server_id="tmws")

        logger.info(f"Registered {len(tools)} internal tools")
        return len(tools)

    async def register_skills(self, skills: list[ToolMetadata]) -> int:
        """Register TMWS Skills with highest priority.

        Skills are the third core feature and get 2.0x ranking weight.

        Args:
            skills: List of skill metadata to register

        Returns:
            Number of skills registered
        """
        await self._index_tools(skills, source_type=ToolSourceType.SKILL, server_id="tmws:skills")

        logger.info(f"Registered {len(skills)} skills")
        return len(skills)

    async def register_mcp_server(self, server: MCPServerMetadata) -> int:
        """Register an MCP server and its tools.

        Args:
            server: MCP server metadata with tools

        Returns:
            Number of tools registered
        """
        self._mcp_servers[server.server_id] = server

        if server.tools:
            await self._index_tools(
                server.tools,
                source_type=ToolSourceType.EXTERNAL,
                server_id=f"mcp__{server.server_id}",
            )

        logger.info(f"Registered MCP server '{server.server_id}' with {len(server.tools)} tools")
        return len(server.tools)

    async def search(
        self,
        query: ToolSearchQuery,
        agent_id: str | None = None,
    ) -> ToolSearchResponse:
        """Search for tools using semantic search.

        Args:
            query: Search query parameters
            agent_id: Optional agent ID for personalized ranking (Phase 4.1)

        Returns:
            ToolSearchResponse with ranked results
        """
        start_time = time.time()

        # Check cache (include agent_id for personalized caching)
        cache_key = f"{query.query}:{query.source}:{query.limit}:{agent_id or 'none'}"
        if cache_key in self._cache:
            cache_time, cached_results = self._cache[cache_key]
            if time.time() - cache_time < self.config.cache_ttl_seconds:
                return ToolSearchResponse(
                    results=cached_results[: query.limit],
                    query=query.query,
                    total_found=len(cached_results),
                    search_latency_ms=(time.time() - start_time) * 1000,
                    sources_searched=["cache"],
                )

        # Generate embedding for query
        query_embedding = await self._get_embedding(query.query)

        # Search ChromaDB
        results = await self._vector_search(
            query_embedding=query_embedding,
            limit=min(query.limit * 2, self.config.max_results),  # Over-fetch for re-ranking
            source_filter=query.source,
            min_score=query.min_score,
        )

        # Apply source-weighted ranking
        ranked_results = self._apply_ranking(results)

        # Phase 4.1: Apply adaptive ranking if enabled and agent_id provided
        if self._adaptive_ranker and agent_id:
            ranked_results = await self._adaptive_ranker.rank_for_agent(
                results=ranked_results,
                agent_id=agent_id,
                query_context={"query": query.query, "source": query.source},
            )

        # Filter and limit
        final_results = ranked_results[: query.limit]

        # Update cache
        self._cache[cache_key] = (time.time(), ranked_results)

        latency_ms = (time.time() - start_time) * 1000
        logger.debug(
            f"Tool search completed in {latency_ms:.2f}ms: {len(final_results)} results "
            f"(adaptive: {bool(self._adaptive_ranker and agent_id)})"
        )

        return ToolSearchResponse(
            results=final_results,
            query=query.query,
            total_found=len(ranked_results),
            search_latency_ms=latency_ms,
            sources_searched=self._get_searched_sources(query.source),
        )

    async def search_tools(
        self,
        query: str,
        source: str = "all",
        limit: int = 10,
        agent_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Simplified search interface for MCP tool.

        Args:
            query: Search query string
            source: Source filter ("all", "skills", "internal", "external")
            limit: Maximum results to return
            agent_id: Optional agent ID for personalized ranking (Phase 4.1)

        Returns:
            List of tool dictionaries
        """
        search_query = ToolSearchQuery(query=query, source=source, limit=limit)
        response = await self.search(search_query, agent_id=agent_id)

        return [
            {
                "tool_name": r.tool_name,
                "server_id": r.server_id,
                "description": r.description,
                "relevance_score": r.relevance_score,
                "weighted_score": r.weighted_score,
                "source_type": r.source_type.value,
                "tags": r.tags,
                "input_schema": r.input_schema,
                "personalization_boost": r._personalization_boost,  # Phase 4.1
            }
            for r in response.results
        ]

    async def record_usage(
        self,
        record: ToolUsageRecord,
        agent_id: str | None = None,
    ) -> None:
        """Record tool usage for learning system.

        Integrates with the fourth core feature (Learning).
        Phase 4.1: Now stores usage in AdaptiveRanker for personalized ranking.

        Args:
            record: Tool usage record
            agent_id: Agent ID that used the tool
        """
        # Phase 4.1: Integrate with AdaptiveRanker
        if self._adaptive_ranker and agent_id:
            from .adaptive_ranker import ToolOutcome

            # Map outcome string to ToolOutcome enum
            outcome_map = {
                "success": ToolOutcome.SUCCESS,
                "error": ToolOutcome.ERROR,
                "timeout": ToolOutcome.TIMEOUT,
                "abandoned": ToolOutcome.ABANDONED,
            }
            outcome = outcome_map.get(record.outcome, ToolOutcome.SUCCESS)

            await self._adaptive_ranker.record_outcome(
                agent_id=agent_id,
                tool_name=record.tool_name,
                server_id=record.server_id,
                query=record.query,
                outcome=outcome,
                latency_ms=record.latency_ms,
                context={"timestamp": record.timestamp.isoformat() if record.timestamp else None},
            )

        logger.debug(
            f"Tool usage recorded: {record.tool_name} - {record.outcome} "
            f"(agent: {agent_id or 'unknown'})"
        )

    async def get_stats(self) -> dict[str, Any]:
        """Get tool search statistics.

        Returns:
            Dictionary with service statistics
        """
        collection_count = 0
        if self._collection:
            collection_count = await asyncio.to_thread(self._collection.count)

        return {
            "collection_name": self.config.collection_name,
            "total_indexed": collection_count,
            "internal_tools": len(self._internal_tools),
            "mcp_servers": len(self._mcp_servers),
            "mcp_server_tools": sum(s.tool_count for s in self._mcp_servers.values()),
            "cache_entries": len(self._cache),
        }

    # Private methods

    async def _get_embedding(self, text: str) -> list[float]:
        """Generate embedding for text.

        Args:
            text: Text to embed

        Returns:
            Embedding vector
        """
        if self.embedding_service:
            return await self.embedding_service.get_embedding(text)

        # Fallback: Use ChromaDB's default embedding
        # In production, this should use OllamaEmbeddingService
        return []

    async def _index_tools(
        self,
        tools: list[ToolMetadata],
        source_type: ToolSourceType,
        server_id: str,
    ) -> None:
        """Index tools in ChromaDB.

        Args:
            tools: Tools to index
            source_type: Source type for ranking
            server_id: Server identifier
        """
        if not self._collection or not tools:
            return

        ids = []
        documents = []
        metadatas = []

        for tool in tools:
            tool_id = f"{server_id}:{tool.name}"
            ids.append(tool_id)
            documents.append(tool.to_embedding_text())
            metadatas.append(
                {
                    "tool_name": tool.name,
                    "server_id": server_id,
                    "description": tool.description[:1000],  # Truncate for metadata
                    "source_type": source_type.value,
                    "tags": ",".join(tool.tags) if tool.tags else "",
                }
            )

        await asyncio.to_thread(
            self._collection.upsert,
            ids=ids,
            documents=documents,
            metadatas=metadatas,
        )

    async def _vector_search(
        self,
        query_embedding: list[float],
        limit: int,
        source_filter: str,
        min_score: float,
    ) -> list[ToolSearchResult]:
        """Perform vector search in ChromaDB.

        Args:
            query_embedding: Query embedding
            limit: Maximum results
            source_filter: Source type filter
            min_score: Minimum similarity score

        Returns:
            List of search results
        """
        if not self._collection:
            return []

        # Build where clause for filtering
        where_clause = None
        if source_filter and source_filter != "all":
            source_map = {
                "skills": ToolSourceType.SKILL.value,
                "internal": ToolSourceType.INTERNAL.value,
                "external": ToolSourceType.EXTERNAL.value,
                "mcp_servers": ToolSourceType.EXTERNAL.value,
            }
            if source_filter in source_map:
                where_clause = {"source_type": source_map[source_filter]}

        # Query ChromaDB
        try:
            if query_embedding:
                results = await asyncio.to_thread(
                    self._collection.query,
                    query_embeddings=[query_embedding],
                    n_results=limit,
                    where=where_clause,
                    include=["documents", "metadatas", "distances"],
                )
            else:
                # Fallback to text query if no embedding
                results = await asyncio.to_thread(
                    self._collection.query,
                    query_texts=[self._last_query_text]
                    if hasattr(self, "_last_query_text")
                    else [""],
                    n_results=limit,
                    where=where_clause,
                    include=["documents", "metadatas", "distances"],
                )
        except Exception as e:
            logger.error(f"Vector search failed: {e}")
            return []

        # Convert to ToolSearchResult
        search_results = []
        if results and results.get("metadatas"):
            for i, metadata in enumerate(results["metadatas"][0]):
                distance = results["distances"][0][i] if results.get("distances") else 0
                # Convert distance to similarity score (cosine distance to similarity)
                similarity = max(0, 1 - distance)

                if similarity < min_score:
                    continue

                search_results.append(
                    ToolSearchResult(
                        tool_name=metadata.get("tool_name", ""),
                        server_id=metadata.get("server_id", ""),
                        description=metadata.get("description", ""),
                        relevance_score=similarity,
                        source_type=ToolSourceType(metadata.get("source_type", "external")),
                        tags=metadata.get("tags", "").split(",") if metadata.get("tags") else [],
                    )
                )

        return search_results

    def _apply_ranking(self, results: list[ToolSearchResult]) -> list[ToolSearchResult]:
        """Apply source-weighted ranking.

        Skills get 2.0x weight (third core feature priority).
        Internal tools get 1.5x weight.
        External tools get 1.0x weight.

        Args:
            results: Search results to rank

        Returns:
            Sorted results by weighted score
        """
        # Sort by weighted score descending
        return sorted(results, key=lambda r: r.weighted_score, reverse=True)

    def _get_searched_sources(self, source_filter: str) -> list[str]:
        """Get list of sources that were searched.

        Args:
            source_filter: Source filter from query

        Returns:
            List of source names
        """
        if source_filter == "all":
            return ["skills", "internal", "external"]
        elif source_filter == "mcp_servers":
            return ["external"]
        else:
            return [source_filter]


# Singleton instance
_tool_search_service: ToolSearchService | None = None


def get_tool_search_service() -> ToolSearchService:
    """Get singleton ToolSearchService instance.

    Returns:
        ToolSearchService instance
    """
    global _tool_search_service
    if _tool_search_service is None:
        _tool_search_service = ToolSearchService()
    return _tool_search_service


async def initialize_tool_search_service(
    embedding_service: Any = None,
    persist_directory: str = "./data/chromadb",
) -> ToolSearchService:
    """Initialize and return the tool search service.

    Args:
        embedding_service: Optional embedding service
        persist_directory: ChromaDB persistence directory

    Returns:
        Initialized ToolSearchService
    """
    global _tool_search_service
    _tool_search_service = ToolSearchService(
        persist_directory=persist_directory,
        embedding_service=embedding_service,
    )
    await _tool_search_service.initialize()
    return _tool_search_service
