"""Memory Search Operations - Semantic vector search with ChromaDB.

This module handles semantic search operations:
- search_memories: Main search interface
- _search_chroma: ChromaDB vector search
- Helper functions for UUID restoration

Performance:
- ChromaDB search: 0.47ms P95
- Embedding generation: ~50ms
"""

import logging
from typing import TYPE_CHECKING, Any

from src.core.exceptions import (
    ChromaOperationError,
    EmbeddingGenerationError,
    MemorySearchError,
    log_and_raise,
)
from src.models.memory import Memory

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from src.services.embedding_service import EmbeddingService
    from src.services.vector_search_service import VectorSearchService

logger = logging.getLogger(__name__)


class MemorySearchOperations:
    """Search operations for memories using ChromaDB."""

    def __init__(
        self,
        session: "AsyncSession",
        embedding_service: "EmbeddingService",
        vector_service: "VectorSearchService | None",
        ensure_initialized: Any,  # Callable for lazy init
        fetch_memories_by_ids: Any,  # Callable for fetching by IDs
    ):
        """Initialize search operations.

        Args:
            session: Async database session
            embedding_service: Service for generating embeddings
            vector_service: ChromaDB vector search service
            ensure_initialized: Async callable for ChromaDB lazy init
            fetch_memories_by_ids: Async callable for fetching memories by IDs
        """
        self.session = session
        self.embedding_service = embedding_service
        self.vector_service = vector_service
        self._ensure_initialized = ensure_initialized
        self._fetch_memories_by_ids = fetch_memories_by_ids

    async def search_memories(
        self,
        query: str,
        agent_id: str | None = None,
        namespace: str | None = None,
        tags: list[str] | None = None,
        min_importance: float = 0.0,
        limit: int = 10,
        min_similarity: float = 0.7,
    ) -> list[dict[str, Any]]:
        """Semantic search with ChromaDB (ultra-fast) + SQLite (authoritative metadata).

        Read-first pattern:
        1. Generate query embedding (Multilingual-E5 Large, 1024-dim via Ollama)
        2. Search ChromaDB for top-k candidates (0.47ms P95)
        3. Fetch full Memory objects from SQLite by IDs
        4. Apply additional filters (access control, importance)

        Args:
            query: Search query text
            agent_id: Filter by agent ID (optional)
            namespace: Filter by namespace (required for security)
            tags: Filter by tags (optional)
            min_importance: Minimum importance score (default: 0.0)
            limit: Maximum results to return (default: 10)
            min_similarity: Minimum similarity threshold (default: 0.7)

        Returns:
            List of memory dictionaries with similarity scores

        Raises:
            MemorySearchError: If search fails
        """
        try:
            # Generate query embedding
            query_embedding = await self.embedding_service.encode_query(query)

            # Search ChromaDB (REQUIRED - no fallback)
            chroma_results = await self._search_chroma(
                query_embedding.tolist(),
                agent_id=agent_id,
                namespace=namespace,
                tags=tags,
                min_similarity=min_similarity,
                limit=limit * 2,  # Over-fetch for filtering
            )

            if not chroma_results:
                return []

            # Debug logging
            if chroma_results:
                logger.debug(f"ChromaDB returned {len(chroma_results)} results")
                logger.debug(f"Sample ID from ChromaDB: {chroma_results[0]['id']}")

            # Fetch full Memory objects from SQLite
            # ChromaDB stores UUIDs without hyphens, need to restore them
            memory_ids = [self._restore_uuid_hyphens(r["id"]) for r in chroma_results]
            logger.debug(f"Querying {len(memory_ids)} memory IDs from SQLite")

            memories = await self._fetch_memories_by_ids(
                memory_ids,
                agent_id=agent_id,
                min_importance=min_importance,
            )

            # Preserve similarity scores from ChromaDB and convert to dicts
            similarity_map = {r["id"]: r["similarity"] for r in chroma_results}

            # Convert Memory objects to dicts with similarity scores
            results = []
            for memory in memories[:limit]:
                memory_dict = {
                    "id": str(memory.id),
                    "content": memory.content,
                    "agent_id": memory.agent_id,
                    "namespace": memory.namespace,
                    "importance_score": memory.importance_score,
                    "tags": memory.tags,
                    "access_level": memory.access_level.value,
                    "shared_with_agents": memory.shared_with_agents,
                    "context": memory.context,
                    "created_at": memory.created_at.isoformat()
                    if hasattr(memory.created_at, "isoformat")
                    else str(memory.created_at),
                    "updated_at": memory.updated_at.isoformat()
                    if hasattr(memory.updated_at, "isoformat")
                    else str(memory.updated_at),
                    "similarity": similarity_map.get(str(memory.id), 0.0),
                }
                results.append(memory_dict)

            return results

        except (KeyboardInterrupt, SystemExit):
            raise
        except (ChromaOperationError, EmbeddingGenerationError):
            raise
        except Exception as e:
            log_and_raise(
                MemorySearchError,
                "Memory search failed with unexpected error",
                original_exception=e,
                details={
                    "query_length": len(query),
                    "agent_id": agent_id,
                    "namespace": namespace,
                },
            )

    async def _search_chroma(
        self,
        query_embedding: list[float],
        agent_id: str | None,
        namespace: str,
        tags: list[str] | None,
        min_similarity: float,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Search ChromaDB with metadata filtering.

        Args:
            query_embedding: Query embedding vector
            agent_id: Filter by agent ID
            namespace: Filter by namespace
            tags: Filter by tags
            min_similarity: Minimum similarity threshold
            limit: Maximum results

        Returns:
            List of search results with IDs and similarity scores
        """
        await self._ensure_initialized()

        if not self.vector_service:
            return []

        filters = {
            "namespace": namespace,
        }
        if agent_id:
            filters["agent_id"] = agent_id
        if tags:
            filters["tags"] = {"$in": tags}

        return await self.vector_service.search(
            query_embedding=query_embedding,
            top_k=limit,
            filters=filters,
            min_similarity=min_similarity,
        )

    @staticmethod
    def _restore_uuid_hyphens(uuid_str: str) -> str:
        """Restore hyphens to UUID (ChromaDB removes them).

        Format: 8-4-4-4-12

        Args:
            uuid_str: UUID string (possibly without hyphens)

        Returns:
            UUID string with hyphens
        """
        if len(uuid_str) == 32 and "-" not in uuid_str:
            restored = (
                f"{uuid_str[:8]}-{uuid_str[8:12]}-{uuid_str[12:16]}-"
                f"{uuid_str[16:20]}-{uuid_str[20:]}"
            )
            logger.debug(f"Restored UUID: {uuid_str} -> {restored}")
            return restored
        return uuid_str
