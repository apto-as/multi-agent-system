"""
Vector Search Service using ChromaDB for TMWS v2.2.6
Provides high-speed semantic search with 5-20ms P95 latency.

IMPORTANT: All methods are async to prevent blocking the event loop.
ChromaDB operations are wrapped in asyncio.to_thread() for non-blocking execution.
"""

import asyncio
import logging
from pathlib import Path
from typing import Any
from uuid import UUID

import chromadb
from chromadb.config import Settings

from ..core.config import get_settings
from ..core.exceptions import ChromaInitializationError, ChromaOperationError, log_and_raise

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
    - ChromaDB: Vector search with DuckDB persistence (5-20ms P95)
    - SQLite: Relational data storage (10-50ms P95)
    - Dual-storage architecture for optimal performance

    Usage:
        service = VectorSearchService()
        await service.initialize()

        # Add memory
        await service.add_memory(
            memory_id="mem_123",
            embedding=[0.1, 0.2, ...],  # 1024-dim
            metadata={"agent_id": "athena", "namespace": "default"}
        )

        # Search
        results = await service.search(
            query_embedding=[0.1, 0.2, ...],
            top_k=10,
            filters={"agent_id": "athena"}
        )
    """

    COLLECTION_NAME = "tmws_memories"
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

    async def initialize(self) -> None:
        """
        Initialize or get collection with HNSW index (async).

        HNSW Parameters:
        - space: cosine (for normalized embeddings)
        - M: 16 (number of bi-directional links per node)
        - ef_construction: 200 (search breadth during construction)
        - ef_search: 100 (search breadth during query)

        Note: ChromaDB operations run in thread pool to avoid blocking event loop.
        """
        try:
            # Run sync ChromaDB operation in thread pool
            self._collection = await asyncio.to_thread(
                self._client.get_or_create_collection,
                name=self.COLLECTION_NAME,
                metadata={
                    "description": "TMWS v2.2.6 semantic memory search (1024-dim)",
                    "hnsw:space": "cosine",
                    "hnsw:M": 16,
                    "hnsw:construction_ef": 200,
                    "hnsw:search_ef": 100,
                },
            )
            count = await asyncio.to_thread(self._collection.count)
            logger.info(f"✅ Collection '{self.COLLECTION_NAME}' ready ({count} memories)")

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except Exception as e:
            # ChromaDB initialization errors
            log_and_raise(
                ChromaInitializationError,
                f"Failed to initialize ChromaDB collection '{self.COLLECTION_NAME}'",
                original_exception=e,
                details={
                    "collection_name": self.COLLECTION_NAME,
                    "persist_directory": str(self.persist_directory),
                },
            )

    async def add_memory(
        self,
        memory_id: str | UUID,
        embedding: list[float],
        metadata: dict[str, Any],
        content: str | None = None,
    ) -> None:
        """
        Add single memory to vector store (async).

        Args:
            memory_id: Unique memory identifier (UUID string)
            embedding: 1024-dimensional embedding vector
            metadata: Metadata for filtering (agent_id, namespace, tags, etc.)
            content: Optional content text (for debugging)

        Example:
            >>> await service.add_memory(
            ...     memory_id="mem_123",
            ...     embedding=doc_embedding.tolist(),
            ...     metadata={
            ...         "agent_id": "athena",
            ...         "namespace": "default",
            ...         "importance": 0.9,
            ...         "tags": ["architecture", "design"]
            ...     }
            ... )

        Note: ChromaDB operation runs in thread pool to avoid blocking event loop.
        """
        if self._collection is None:
            raise RuntimeError("Collection not initialized. Call initialize() first.")

        # Convert UUID to string
        memory_id_str = str(memory_id)

        # Prepare metadata (Chroma requires string/int/float types)
        sanitized_metadata = self._sanitize_metadata(metadata)

        try:
            # Run sync ChromaDB operation in thread pool
            await asyncio.to_thread(
                self._collection.add,
                ids=[memory_id_str],
                embeddings=[embedding],
                metadatas=[sanitized_metadata],
                documents=[content] if content else None,
            )
            logger.debug(f"✅ Added memory {memory_id_str} to vector store")

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except Exception as e:
            # ChromaDB add operation errors
            log_and_raise(
                ChromaOperationError,
                "Failed to add memory to ChromaDB",
                original_exception=e,
                details={"memory_id": memory_id_str, "operation": "add"},
            )

    async def add_memories_batch(
        self,
        memory_ids: list[str | UUID],
        embeddings: list[list[float]],
        metadatas: list[dict[str, Any]],
        contents: list[str] | None = None,
    ) -> None:
        """
        Add multiple memories in batch (async, more efficient).

        Args:
            memory_ids: List of memory IDs
            embeddings: List of 1024-dim embeddings
            metadatas: List of metadata dicts
            contents: Optional list of content texts

        Example:
            >>> await service.add_memories_batch(
            ...     memory_ids=["mem_1", "mem_2"],
            ...     embeddings=[emb1.tolist(), emb2.tolist()],
            ...     metadatas=[
            ...         {"agent_id": "athena", "namespace": "default"},
            ...         {"agent_id": "artemis", "namespace": "default"}
            ...     ]
            ... )

        Note: ChromaDB operation runs in thread pool to avoid blocking event loop.
        """
        if self._collection is None:
            raise RuntimeError("Collection not initialized. Call initialize() first.")

        # Convert UUIDs to strings
        ids = [str(mid) for mid in memory_ids]

        # Sanitize all metadata
        sanitized = [self._sanitize_metadata(m) for m in metadatas]

        try:
            # Run sync ChromaDB operation in thread pool
            await asyncio.to_thread(
                self._collection.add,
                ids=ids,
                embeddings=embeddings,
                metadatas=sanitized,
                documents=contents,
            )
            logger.info(f"✅ Added {len(ids)} memories to vector store (batch)")

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except Exception as e:
            # ChromaDB batch add operation errors
            log_and_raise(
                ChromaOperationError,
                "Failed to batch add memories to ChromaDB",
                original_exception=e,
                details={"memory_count": len(ids), "operation": "add_batch"},
            )

    async def search(
        self,
        query_embedding: list[float],
        top_k: int = 10,
        filters: dict[str, Any] | None = None,
        min_similarity: float = 0.0,
    ) -> list[dict[str, Any]]:
        """
        Search for similar memories (async).

        Args:
            query_embedding: 1024-dim query embedding
            top_k: Number of results to return
            filters: Metadata filters (e.g., {"agent_id": "athena"})
            min_similarity: Minimum cosine similarity threshold (0.0-1.0)

        Returns:
            List of results with id, similarity, and metadata

        Example:
            >>> results = await service.search(
            ...     query_embedding=query_emb.tolist(),
            ...     top_k=5,
            ...     filters={"agent_id": "athena", "namespace": "default"},
            ...     min_similarity=0.7
            ... )
            >>> for result in results:
            ...     print(f"{result['id']}: {result['similarity']:.4f}")

        Note: ChromaDB operation runs in thread pool to avoid blocking event loop.
        """
        if self._collection is None:
            raise RuntimeError("Collection not initialized. Call initialize() first.")

        # Build where clause for filters
        where = self._build_where_clause(filters) if filters else None

        try:
            # Run sync ChromaDB operation in thread pool
            results = await asyncio.to_thread(
                self._collection.query,
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

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except Exception as e:
            # ChromaDB search operation errors
            log_and_raise(
                ChromaOperationError,
                "Failed to search in ChromaDB",
                original_exception=e,
                details={
                    "top_k": top_k,
                    "min_similarity": min_similarity,
                    "has_filters": filters is not None,
                    "operation": "search",
                },
            )

    async def delete_memory(self, memory_id: str | UUID) -> None:
        """
        Delete memory from vector store (async).

        Args:
            memory_id: Memory ID to delete

        Note: ChromaDB operation runs in thread pool to avoid blocking event loop.
        """
        if self._collection is None:
            raise RuntimeError("Collection not initialized. Call initialize() first.")

        memory_id_str = str(memory_id)

        try:
            # Run sync ChromaDB operation in thread pool
            await asyncio.to_thread(self._collection.delete, ids=[memory_id_str])
            logger.debug(f"🗑️ Deleted memory {memory_id_str} from vector store")

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except Exception as e:
            # ChromaDB delete operation errors
            log_and_raise(
                ChromaOperationError,
                "Failed to delete memory from ChromaDB",
                original_exception=e,
                details={"memory_id": memory_id_str, "operation": "delete"},
            )

    async def delete_memories_batch(self, memory_ids: list[str | UUID]) -> None:
        """
        Delete multiple memories in batch (async).

        Args:
            memory_ids: List of memory IDs to delete

        Note: ChromaDB operation runs in thread pool to avoid blocking event loop.
        """
        if self._collection is None:
            raise RuntimeError("Collection not initialized. Call initialize() first.")

        ids = [str(mid) for mid in memory_ids]

        try:
            # Run sync ChromaDB operation in thread pool
            await asyncio.to_thread(self._collection.delete, ids=ids)
            logger.info(f"🗑️ Deleted {len(ids)} memories from vector store (batch)")

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except Exception as e:
            # ChromaDB batch delete operation errors
            log_and_raise(
                ChromaOperationError,
                "Failed to batch delete memories from ChromaDB",
                original_exception=e,
                details={"memory_count": len(ids), "operation": "delete_batch"},
            )

    async def get_collection_stats(self) -> dict[str, Any]:
        """
        Get collection statistics (async).

        Returns:
            Dictionary with stats (count, capacity_usage, etc.)

        Note: ChromaDB operation runs in thread pool to avoid blocking event loop.
        """
        if self._collection is None:
            raise RuntimeError("Collection not initialized. Call initialize() first.")

        # Run sync ChromaDB operation in thread pool
        count = await asyncio.to_thread(self._collection.count)
        capacity_usage = count / self.HOT_CACHE_SIZE

        return {
            "collection_name": self.COLLECTION_NAME,
            "memory_count": count,
            "hot_cache_capacity": self.HOT_CACHE_SIZE,
            "capacity_usage": capacity_usage,
            "capacity_usage_percent": f"{capacity_usage * 100:.1f}%",
            "persist_directory": str(self.persist_directory),
        }

    async def clear_collection(self) -> None:
        """
        Clear all memories from collection (async, dangerous!).

        Note: ChromaDB operations run in thread pool to avoid blocking event loop.
        """
        if self._collection is None:
            raise RuntimeError("Collection not initialized. Call initialize() first.")

        logger.warning(f"⚠️ Clearing all memories from collection '{self.COLLECTION_NAME}'")
        # Run sync ChromaDB operation in thread pool
        await asyncio.to_thread(self._client.delete_collection, name=self.COLLECTION_NAME)
        await self.initialize()  # Recreate empty collection

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

    def _build_where_clause(self, filters: dict[str, Any]) -> dict[str, Any] | None:
        """
        Build ChromaDB where clause from filters.

        Args:
            filters: Filter dict (e.g., {"agent_id": "athena", "namespace": "default"})

        Returns:
            ChromaDB where clause (None if no filters)

        Note:
            ChromaDB requires multiple conditions to be wrapped in $and operator.
            Example: {"$and": [{"namespace": "default"}, {"agent_id": "athena"}]}
        """
        if not filters:
            return None

        conditions = []
        for key, value in filters.items():
            if isinstance(value, list):
                # List filters: use $in operator
                conditions.append({key: {"$in": value}})
            elif isinstance(value, dict):
                # Already an operator dict (e.g., {"tags": {"$in": ["tag1"]}})
                conditions.append({key: value})
            else:
                # Exact match
                conditions.append({key: value})

        # Single condition: return as-is
        if len(conditions) == 1:
            return conditions[0]

        # Multiple conditions: wrap in $and
        return {"$and": conditions}


# Singleton instance
_vector_search_service_instance = None


def get_vector_search_service() -> VectorSearchService:
    """
    Get singleton instance of VectorSearchService (sync factory).

    Returns:
        Singleton instance (not yet initialized)

    Example:
        >>> from src.services.vector_search_service import get_vector_search_service
        >>> service = get_vector_search_service()
        >>> await service.initialize()  # Must initialize after getting instance

    Note: You MUST call await service.initialize() after getting the instance.
    """
    global _vector_search_service_instance

    if _vector_search_service_instance is None:
        _vector_search_service_instance = VectorSearchService()

    return _vector_search_service_instance
