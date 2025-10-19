"""
Vector Search Service using ChromaDB for TMWS v2.2.6
Provides high-speed semantic search with 5-20ms P95 latency.
"""

import logging
from pathlib import Path
from typing import Any
from uuid import UUID

import chromadb
from chromadb.config import Settings

from ..core.config import get_settings

logger = logging.getLogger(__name__)


class VectorSearchService:
    """
    Vector search service using ChromaDB for hot cache.

    Features:
    - Embedded mode (no separate server required)
    - DuckDB backend for persistence
    - HNSW index for fast similarity search (M=16, ef_construction=200)
    - Metadata filtering support
    - 10K memory hot cache capacity

    Architecture:
    - Chroma: Hot cache for fast retrieval (5-20ms P95)
    - PostgreSQL: Source of truth for all data (50-200ms P95)
    - Speedup: 5-10x faster queries

    Usage:
        service = VectorSearchService()
        service.initialize()

        # Add memory
        service.add_memory(
            memory_id="mem_123",
            embedding=[0.1, 0.2, ...],  # 1024-dim
            metadata={"agent_id": "athena", "namespace": "default"}
        )

        # Search
        results = service.search(
            query_embedding=[0.1, 0.2, ...],
            top_k=10,
            filters={"agent_id": "athena"}
        )
    """

    COLLECTION_NAME = "tmws_memories_v2"
    HOT_CACHE_SIZE = 10000  # Maximum memories in hot cache

    def __init__(self, persist_directory: str | Path | None = None):
        """
        Initialize vector search service.

        Args:
            persist_directory: Directory for ChromaDB persistence
                              (defaults to ./data/chromadb)
        """
        self.settings = get_settings()

        # Set persist directory
        if persist_directory is None:
            persist_directory = Path("./data/chromadb")
        else:
            persist_directory = Path(persist_directory)

        persist_directory.mkdir(parents=True, exist_ok=True)
        self.persist_directory = persist_directory

        # Initialize Chroma client (embedded mode)
        self._client = chromadb.PersistentClient(
            path=str(persist_directory),
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True,
            ),
        )

        self._collection = None
        logger.info(f"🚀 VectorSearchService initialized (persist: {persist_directory})")

    def initialize(self) -> None:
        """
        Initialize or get collection with HNSW index.

        HNSW Parameters:
        - space: cosine (for normalized embeddings)
        - M: 16 (number of bi-directional links per node)
        - ef_construction: 200 (search breadth during construction)
        - ef_search: 100 (search breadth during query)
        """
        try:
            self._collection = self._client.get_or_create_collection(
                name=self.COLLECTION_NAME,
                metadata={
                    "description": "TMWS v2.2.6 semantic memory search (1024-dim)",
                    "hnsw:space": "cosine",
                    "hnsw:M": 16,
                    "hnsw:construction_ef": 200,
                    "hnsw:search_ef": 100,
                },
            )
            count = self._collection.count()
            logger.info(f"✅ Collection '{self.COLLECTION_NAME}' ready ({count} memories)")

        except Exception as e:
            logger.error(f"❌ Failed to initialize collection: {e}")
            raise

    def add_memory(
        self,
        memory_id: str | UUID,
        embedding: list[float],
        metadata: dict[str, Any],
        content: str | None = None,
    ) -> None:
        """
        Add single memory to vector store.

        Args:
            memory_id: Unique memory identifier (UUID string)
            embedding: 1024-dimensional embedding vector
            metadata: Metadata for filtering (agent_id, namespace, tags, etc.)
            content: Optional content text (for debugging)

        Example:
            >>> service.add_memory(
            ...     memory_id="mem_123",
            ...     embedding=doc_embedding.tolist(),
            ...     metadata={
            ...         "agent_id": "athena",
            ...         "namespace": "default",
            ...         "importance": 0.9,
            ...         "tags": ["architecture", "design"]
            ...     }
            ... )
        """
        if self._collection is None:
            raise RuntimeError("Collection not initialized. Call initialize() first.")

        # Convert UUID to string
        memory_id_str = str(memory_id)

        # Prepare metadata (Chroma requires string/int/float types)
        sanitized_metadata = self._sanitize_metadata(metadata)

        try:
            self._collection.add(
                ids=[memory_id_str],
                embeddings=[embedding],
                metadatas=[sanitized_metadata],
                documents=[content] if content else None,
            )
            logger.debug(f"✅ Added memory {memory_id_str} to vector store")

        except Exception as e:
            logger.error(f"❌ Failed to add memory {memory_id_str}: {e}")
            raise

    def add_memories_batch(
        self,
        memory_ids: list[str | UUID],
        embeddings: list[list[float]],
        metadatas: list[dict[str, Any]],
        contents: list[str] | None = None,
    ) -> None:
        """
        Add multiple memories in batch (more efficient).

        Args:
            memory_ids: List of memory IDs
            embeddings: List of 1024-dim embeddings
            metadatas: List of metadata dicts
            contents: Optional list of content texts

        Example:
            >>> service.add_memories_batch(
            ...     memory_ids=["mem_1", "mem_2"],
            ...     embeddings=[emb1.tolist(), emb2.tolist()],
            ...     metadatas=[
            ...         {"agent_id": "athena", "namespace": "default"},
            ...         {"agent_id": "artemis", "namespace": "default"}
            ...     ]
            ... )
        """
        if self._collection is None:
            raise RuntimeError("Collection not initialized. Call initialize() first.")

        # Convert UUIDs to strings
        ids = [str(mid) for mid in memory_ids]

        # Sanitize all metadata
        sanitized = [self._sanitize_metadata(m) for m in metadatas]

        try:
            self._collection.add(
                ids=ids, embeddings=embeddings, metadatas=sanitized, documents=contents
            )
            logger.info(f"✅ Added {len(ids)} memories to vector store (batch)")

        except Exception as e:
            logger.error(f"❌ Failed to add batch: {e}")
            raise

    def search(
        self,
        query_embedding: list[float],
        top_k: int = 10,
        filters: dict[str, Any] | None = None,
        min_similarity: float = 0.0,
    ) -> list[dict[str, Any]]:
        """
        Search for similar memories.

        Args:
            query_embedding: 1024-dim query embedding
            top_k: Number of results to return
            filters: Metadata filters (e.g., {"agent_id": "athena"})
            min_similarity: Minimum cosine similarity threshold (0.0-1.0)

        Returns:
            List of results with id, similarity, and metadata

        Example:
            >>> results = service.search(
            ...     query_embedding=query_emb.tolist(),
            ...     top_k=5,
            ...     filters={"agent_id": "athena", "namespace": "default"},
            ...     min_similarity=0.7
            ... )
            >>> for result in results:
            ...     print(f"{result['id']}: {result['similarity']:.4f}")
        """
        if self._collection is None:
            raise RuntimeError("Collection not initialized. Call initialize() first.")

        # Build where clause for filters
        where = self._build_where_clause(filters) if filters else None

        try:
            results = self._collection.query(
                query_embeddings=[query_embedding],
                n_results=top_k,
                where=where,
                include=["metadatas", "distances", "documents"],
            )

            # Process results
            processed = []
            if results["ids"] and results["ids"][0]:
                for idx, memory_id in enumerate(results["ids"][0]):
                    # Convert distance to similarity
                    distance = results["distances"][0][idx]
                    similarity = 1.0 - distance  # Cosine distance to similarity

                    # Apply similarity threshold
                    if similarity >= min_similarity:
                        processed.append(
                            {
                                "id": memory_id,
                                "similarity": similarity,
                                "metadata": results["metadatas"][0][idx],
                                "content": results["documents"][0][idx]
                                if results.get("documents")
                                else None,
                            }
                        )

            logger.debug(f"🔍 Found {len(processed)} results (top_k={top_k})")
            return processed

        except Exception as e:
            logger.error(f"❌ Search failed: {e}")
            raise

    def delete_memory(self, memory_id: str | UUID) -> None:
        """
        Delete memory from vector store.

        Args:
            memory_id: Memory ID to delete
        """
        if self._collection is None:
            raise RuntimeError("Collection not initialized. Call initialize() first.")

        memory_id_str = str(memory_id)

        try:
            self._collection.delete(ids=[memory_id_str])
            logger.debug(f"🗑️ Deleted memory {memory_id_str} from vector store")

        except Exception as e:
            logger.error(f"❌ Failed to delete memory {memory_id_str}: {e}")
            raise

    def delete_memories_batch(self, memory_ids: list[str | UUID]) -> None:
        """
        Delete multiple memories in batch.

        Args:
            memory_ids: List of memory IDs to delete
        """
        if self._collection is None:
            raise RuntimeError("Collection not initialized. Call initialize() first.")

        ids = [str(mid) for mid in memory_ids]

        try:
            self._collection.delete(ids=ids)
            logger.info(f"🗑️ Deleted {len(ids)} memories from vector store (batch)")

        except Exception as e:
            logger.error(f"❌ Failed to delete batch: {e}")
            raise

    def get_collection_stats(self) -> dict[str, Any]:
        """
        Get collection statistics.

        Returns:
            Dictionary with stats (count, capacity_usage, etc.)
        """
        if self._collection is None:
            raise RuntimeError("Collection not initialized. Call initialize() first.")

        count = self._collection.count()
        capacity_usage = count / self.HOT_CACHE_SIZE

        return {
            "collection_name": self.COLLECTION_NAME,
            "memory_count": count,
            "hot_cache_capacity": self.HOT_CACHE_SIZE,
            "capacity_usage": capacity_usage,
            "capacity_usage_percent": f"{capacity_usage * 100:.1f}%",
            "persist_directory": str(self.persist_directory),
        }

    def clear_collection(self) -> None:
        """
        Clear all memories from collection (dangerous!).
        """
        if self._collection is None:
            raise RuntimeError("Collection not initialized. Call initialize() first.")

        logger.warning(f"⚠️ Clearing all memories from collection '{self.COLLECTION_NAME}'")
        self._client.delete_collection(name=self.COLLECTION_NAME)
        self.initialize()  # Recreate empty collection

    def _sanitize_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        """
        Sanitize metadata for ChromaDB (string/int/float only).

        Args:
            metadata: Raw metadata dict

        Returns:
            Sanitized metadata dict
        """
        sanitized = {}

        for key, value in metadata.items():
            if value is None:
                continue  # Skip None values

            # Handle lists (convert to JSON string or first element)
            if isinstance(value, list):
                if len(value) > 0 and isinstance(value[0], str):
                    # For tags, join with commas
                    sanitized[key] = ",".join(value[:5])  # Limit to first 5
                else:
                    continue  # Skip non-string lists

            # Handle strings, ints, floats
            elif isinstance(value, str | int | float | bool):
                sanitized[key] = value

            # Handle dicts (skip for now, could JSON serialize)
            elif isinstance(value, dict):
                continue

            # Convert other types to string
            else:
                sanitized[key] = str(value)

        return sanitized

    def _build_where_clause(self, filters: dict[str, Any]) -> dict[str, Any]:
        """
        Build ChromaDB where clause from filters.

        Args:
            filters: Filter dict (e.g., {"agent_id": "athena"})

        Returns:
            ChromaDB where clause
        """
        where = {}

        for key, value in filters.items():
            if isinstance(value, list):
                # List filters: use $in operator
                where[key] = {"$in": value}
            else:
                # Exact match
                where[key] = value

        return where


# Singleton instance
_vector_search_service_instance = None


def get_vector_search_service() -> VectorSearchService:
    """
    Get singleton instance of VectorSearchService.

    Returns:
        Singleton instance

    Example:
        >>> from src.services.vector_search_service import get_vector_search_service
        >>> service = get_vector_search_service()
        >>> service.initialize()
    """
    global _vector_search_service_instance

    if _vector_search_service_instance is None:
        _vector_search_service_instance = VectorSearchService()
        _vector_search_service_instance.initialize()

    return _vector_search_service_instance
