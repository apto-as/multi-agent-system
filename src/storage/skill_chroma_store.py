"""Skill ChromaDB Store for TMWS v2.4.18
Provides semantic search for Skills using ChromaDB.

Pattern: Same architecture as VectorSearchService
Collection: tmws_skills (separate from tmws_memories and tmws_tools)

Performance target: < 100ms P95 latency

Author: Artemis (Implementation)
Created: 2025-12-13
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


class SkillChromaStore:
    """ChromaDB store for Skills semantic search.

    Features:
    - Separate collection (tmws_skills) from memories/tools
    - 1024-dim embeddings (Multilingual-E5 Large)
    - Metadata filtering (namespace, persona, tags)
    - Lazy initialization pattern

    Architecture:
    - ChromaDB: Vector search with DuckDB persistence
    - SQLite: Source of truth (Skill model)
    - Dual-storage for optimal query performance

    Usage:
        store = SkillChromaStore()
        await store.initialize()

        # Index skill
        await store.add_skill(
            skill_id="skill_123",
            embedding=[0.1, 0.2, ...],  # 1024-dim
            metadata={"namespace": "default", "persona": "hestia-auditor"}
        )

        # Search
        results = await store.search(
            query_embedding=[0.1, 0.2, ...],
            top_k=10,
            filters={"namespace": "default"}
        )
    """

    COLLECTION_NAME = "tmws_skills"

    def __init__(self, persist_directory: str | Path | None = None):
        """Initialize skill ChromaDB store (lazy mode).

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

        self.persist_directory = persist_directory

        # Lazy initialization state
        self._client: chromadb.PersistentClient | None = None
        self._collection: chromadb.Collection | None = None
        self._init_lock = asyncio.Lock()
        self._initialized = False

        logger.info(f"🚀 SkillChromaStore initialized (lazy mode, persist: {persist_directory})")

    INIT_TIMEOUT_SECONDS = 30.0  # Maximum time for lazy initialization

    async def _ensure_initialized(self, timeout: float | None = None) -> None:
        """Ensure ChromaDB client and collection are initialized (lazy).

        Thread-safe lazy initialization using double-check locking pattern.

        Security hardening (Hestia P0):
        - Timeout protection (30s max)
        - Partial state cleanup on failure

        Args:
            timeout: Maximum seconds to wait for initialization.
                    Defaults to INIT_TIMEOUT_SECONDS (30s).

        Raises:
            ChromaInitializationError: If initialization fails or times out.
        """
        if self._initialized:
            return

        timeout = timeout or self.INIT_TIMEOUT_SECONDS

        try:
            async with asyncio.timeout(timeout):
                async with self._init_lock:
                    # Double-check pattern
                    if self._initialized:
                        return

                    # Temp variables for atomic state transition (Hestia C-1)
                    temp_client = None
                    temp_collection = None

                    try:
                        # Create persist directory if needed
                        self.persist_directory.mkdir(parents=True, exist_ok=True)

                        # Initialize ChromaDB client (embedded mode)
                        temp_client = await asyncio.to_thread(
                            chromadb.PersistentClient,
                            path=str(self.persist_directory),
                            settings=Settings(
                                anonymized_telemetry=False,
                                allow_reset=True,
                            ),
                        )

                        logger.info(
                            f"📦 ChromaDB client initialized (persist: {self.persist_directory})"
                        )

                        # Get or create tmws_skills collection
                        temp_collection = await asyncio.to_thread(
                            temp_client.get_or_create_collection,
                            name=self.COLLECTION_NAME,
                            metadata={
                                "description": "TMWS v2.4.18 skill semantic search (1024-dim)",
                            },
                        )
                        count = await asyncio.to_thread(temp_collection.count)
                        logger.info(
                            f"✅ Collection '{self.COLLECTION_NAME}' ready ({count} skills)"
                        )

                        # Atomic state transition
                        self._client = temp_client
                        self._collection = temp_collection
                        self._initialized = True

                    except (KeyboardInterrupt, SystemExit):
                        raise
                    except Exception as e:
                        # Clean up partial state (Hestia C-1 fix)
                        if temp_client is not None:
                            try:
                                del temp_client
                                logger.debug(
                                    "Cleaned up partial ChromaDB client after init failure"
                                )
                            except Exception:
                                pass  # Best effort cleanup

                        log_and_raise(
                            ChromaInitializationError,
                            f"Failed to initialize ChromaDB collection '{self.COLLECTION_NAME}'",
                            original_exception=e,
                            details={
                                "collection_name": self.COLLECTION_NAME,
                                "persist_directory": str(self.persist_directory),
                            },
                        )

        except TimeoutError:
            # Hestia C-3 fix: Timeout protection
            log_and_raise(
                ChromaInitializationError,
                f"ChromaDB initialization timed out after {timeout}s",
                details={
                    "timeout_seconds": timeout,
                    "collection_name": self.COLLECTION_NAME,
                    "persist_directory": str(self.persist_directory),
                },
            )

    async def initialize(self) -> None:
        """Initialize collection (DEPRECATED - use lazy init).

        Kept for backward compatibility.
        """
        logger.info("⚠️ Explicit initialize() called - lazy init is now automatic")
        await self._ensure_initialized()

    async def add_skill(
        self,
        skill_id: str | UUID,
        embedding: list[float],
        metadata: dict[str, Any],
        content: str | None = None,
    ) -> None:
        """Add single skill to vector store (async).

        Args:
            skill_id: Unique skill identifier (UUID string)
            embedding: 1024-dimensional embedding vector
            metadata: Metadata for filtering (namespace, persona, tags, etc.)
            content: Optional content text (core_instructions, for debugging)

        Example:
            >>> await store.add_skill(
            ...     skill_id="skill_123",
            ...     embedding=doc_embedding.tolist(),
            ...     metadata={
            ...         "skill_name": "oauth-security",
            ...         "namespace": "security",
            ...         "persona": "hestia-auditor",
            ...         "tags": "security,audit",
            ...         "access_level": "PRIVATE",
            ...         "version": 1,
            ...         "created_by": "hestia-001"
            ...     }
            ... )
        """
        await self._ensure_initialized()

        skill_id_str = str(skill_id)

        # HIGH-3: Sanitize content to remove potential secrets
        if content:
            content = self._sanitize_skill_content(content)

        # Sanitize metadata (ChromaDB requires string/int/float types)
        sanitized_metadata = self._sanitize_metadata(metadata)

        try:
            # Run sync ChromaDB operation in thread pool
            await asyncio.to_thread(
                self._collection.add,
                ids=[skill_id_str],
                embeddings=[embedding],
                metadatas=[sanitized_metadata],
                documents=[content] if content else None,
            )
            logger.debug(f"✅ Added skill {skill_id_str} to vector store")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            log_and_raise(
                ChromaOperationError,
                "Failed to add skill to ChromaDB",
                original_exception=e,
                details={"skill_id": skill_id_str, "operation": "add"},
            )

    async def add_skills_batch(
        self,
        skill_ids: list[str | UUID],
        embeddings: list[list[float]],
        metadatas: list[dict[str, Any]],
        contents: list[str] | None = None,
    ) -> None:
        """Add multiple skills in batch (async, more efficient).

        Args:
            skill_ids: List of skill IDs
            embeddings: List of 1024-dim embeddings
            metadatas: List of metadata dicts
            contents: Optional list of content texts
        """
        await self._ensure_initialized()

        ids = [str(sid) for sid in skill_ids]
        sanitized = [self._sanitize_metadata(m) for m in metadatas]

        try:
            await asyncio.to_thread(
                self._collection.add,
                ids=ids,
                embeddings=embeddings,
                metadatas=sanitized,
                documents=contents,
            )
            logger.info(f"✅ Added {len(ids)} skills to vector store (batch)")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            log_and_raise(
                ChromaOperationError,
                "Failed to batch add skills to ChromaDB",
                original_exception=e,
                details={"skill_count": len(ids), "operation": "add_batch"},
            )

    async def update_skill(
        self,
        skill_id: str | UUID,
        embedding: list[float],
        metadata: dict[str, Any],
        content: str | None = None,
    ) -> None:
        """Update existing skill (async).

        Uses ChromaDB upsert to update or insert.

        Args:
            skill_id: Skill ID to update
            embedding: New embedding vector
            metadata: Updated metadata
            content: Updated content
        """
        await self._ensure_initialized()

        skill_id_str = str(skill_id)

        # HIGH-3: Sanitize content to remove potential secrets
        if content:
            content = self._sanitize_skill_content(content)

        sanitized_metadata = self._sanitize_metadata(metadata)

        try:
            await asyncio.to_thread(
                self._collection.upsert,
                ids=[skill_id_str],
                embeddings=[embedding],
                metadatas=[sanitized_metadata],
                documents=[content] if content else None,
            )
            logger.debug(f"✅ Updated skill {skill_id_str} in vector store")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            log_and_raise(
                ChromaOperationError,
                "Failed to update skill in ChromaDB",
                original_exception=e,
                details={"skill_id": skill_id_str, "operation": "update"},
            )

    async def search(
        self,
        query_embedding: list[float],
        top_k: int = 10,
        filters: dict[str, Any] | None = None,
        min_similarity: float = 0.0,
    ) -> list[dict[str, Any]]:
        """Search for similar skills (async).

        Args:
            query_embedding: 1024-dim query embedding
            top_k: Number of results to return
            filters: Metadata filters (e.g., {"namespace": "security"})
            min_similarity: Minimum cosine similarity threshold (0.0-1.0)

        Returns:
            List of results with id, similarity, and metadata

        Example:
            >>> results = await store.search(
            ...     query_embedding=query_emb.tolist(),
            ...     top_k=5,
            ...     filters={"namespace": "security", "persona": "hestia-auditor"},
            ...     min_similarity=0.7
            ... )
            >>> for result in results:
            ...     print(f"{result['id']}: {result['similarity']:.4f}")
        """
        await self._ensure_initialized()

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
                for idx, skill_id in enumerate(results["ids"][0]):
                    # Convert distance to similarity
                    distance = results["distances"][0][idx]
                    similarity = 1.0 - distance  # Cosine distance to similarity

                    # Apply similarity threshold
                    if similarity >= min_similarity:
                        processed.append(
                            {
                                "id": skill_id,
                                "similarity": similarity,
                                "metadata": results["metadatas"][0][idx],
                                "content": results["documents"][0][idx]
                                if results.get("documents")
                                else None,
                            }
                        )

            logger.debug(f"🔍 Found {len(processed)} skill results (top_k={top_k})")
            return processed

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            log_and_raise(
                ChromaOperationError,
                "Failed to search skills in ChromaDB",
                original_exception=e,
                details={
                    "top_k": top_k,
                    "min_similarity": min_similarity,
                    "has_filters": filters is not None,
                    "operation": "search",
                },
            )

    async def delete_skill(self, skill_id: str | UUID) -> None:
        """Delete skill from vector store (async).

        Args:
            skill_id: Skill ID to delete
        """
        await self._ensure_initialized()

        skill_id_str = str(skill_id)

        try:
            await asyncio.to_thread(self._collection.delete, ids=[skill_id_str])
            logger.debug(f"🗑️ Deleted skill {skill_id_str} from vector store")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            log_and_raise(
                ChromaOperationError,
                "Failed to delete skill from ChromaDB",
                original_exception=e,
                details={"skill_id": skill_id_str, "operation": "delete"},
            )

    async def delete_skills_batch(self, skill_ids: list[str | UUID]) -> None:
        """Delete multiple skills in batch (async).

        Args:
            skill_ids: List of skill IDs to delete
        """
        await self._ensure_initialized()

        ids = [str(sid) for sid in skill_ids]

        try:
            await asyncio.to_thread(self._collection.delete, ids=ids)
            logger.info(f"🗑️ Deleted {len(ids)} skills from vector store (batch)")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            log_and_raise(
                ChromaOperationError,
                "Failed to batch delete skills from ChromaDB",
                original_exception=e,
                details={"skill_count": len(ids), "operation": "delete_batch"},
            )

    async def get_collection_stats(self, force_init: bool = False) -> dict[str, Any]:
        """Get collection statistics (async).

        Args:
            force_init: If True, force initialization before getting stats.
                       If False, returns metadata only without initializing ChromaDB.

        Returns:
            Dictionary with stats (count, persist_directory, etc.)
        """
        if force_init or self._initialized:
            await self._ensure_initialized()

            count = await asyncio.to_thread(self._collection.count)

            return {
                "collection_name": self.COLLECTION_NAME,
                "skill_count": count,
                "persist_directory": str(self.persist_directory),
                "initialized": True,
            }
        else:
            # Return metadata only without forcing initialization
            return {
                "collection_name": self.COLLECTION_NAME,
                "skill_count": 0,
                "persist_directory": str(self.persist_directory),
                "initialized": False,
            }

    async def clear_collection(self, *, confirm: bool = False) -> dict[str, Any]:
        """Clear all skills from collection (async, dangerous!).

        ⚠️ WARNING: This operation is irreversible.

        Args:
            confirm: Must be explicitly set to True to proceed.

        Returns:
            Dict with operation result including deleted_count.

        Raises:
            ValueError: If confirm is not True.
        """
        if not confirm:
            raise ValueError(
                "clear_collection() requires explicit confirm=True parameter. "
                "This operation will delete ALL skills and cannot be undone."
            )

        await self._ensure_initialized()

        # Get count before deletion for logging
        try:
            count = await asyncio.to_thread(self._collection.count)
        except Exception:
            count = "unknown"

        logger.warning(
            f"⚠️ DESTRUCTIVE: Clearing {count} skills from collection '{self.COLLECTION_NAME}'"
        )

        await asyncio.to_thread(self._client.delete_collection, name=self.COLLECTION_NAME)

        # Reset state and reinitialize
        self._initialized = False
        self._collection = None
        await self._ensure_initialized()  # Recreate empty collection

        return {"success": True, "deleted_count": count, "collection": self.COLLECTION_NAME}

    def _sanitize_skill_content(self, content: str) -> str:
        """Sanitize skill content to remove potential sensitive data.

        HIGH-3 (Partial): Content sanitization hook.
        Removes API keys, secrets, AWS credentials, JWT tokens.

        Note: Order matters! More specific patterns first to avoid false positives.

        Args:
            content: Raw skill content

        Returns:
            Sanitized content with secrets redacted
        """
        import re

        # JWT tokens (eyJ... format) - MUST be first before generic token pattern
        content = re.sub(
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "[JWT_REDACTED]",
            content,
        )

        # AWS keys (AKIA format)
        content = re.sub(r"AKIA[0-9A-Z]{16}", "[AWS_KEY_REDACTED]", content)

        # API keys and secrets (generic pattern, less specific)
        # Use negative lookahead to skip already-redacted values
        content = re.sub(
            r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*(?!\[.*?REDACTED\])\S+",
            r"\1: [REDACTED]",
            content,
        )

        return content

    def _sanitize_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        """Sanitize metadata for ChromaDB (string/int/float only).

        Args:
            metadata: Raw metadata dict

        Returns:
            Sanitized metadata dict
        """
        sanitized = {}

        for key, value in metadata.items():
            if value is None:
                continue  # Skip None values

            # Handle lists (convert to CSV string for tags)
            if isinstance(value, list):
                if len(value) > 0 and isinstance(value[0], str):
                    sanitized[key] = ",".join(value[:10])  # Limit to first 10
                else:
                    continue  # Skip non-string lists

            # Handle strings, ints, floats, bools
            elif isinstance(value, str | int | float | bool):
                sanitized[key] = value

            # Skip dicts
            elif isinstance(value, dict):
                continue

            # Convert other types to string
            else:
                sanitized[key] = str(value)

        return sanitized

    def _build_where_clause(self, filters: dict[str, Any]) -> dict[str, Any] | None:
        """Build ChromaDB where clause from filters.

        Args:
            filters: Filter dict (e.g., {"namespace": "security", "persona": "hestia-auditor"})

        Returns:
            ChromaDB where clause (None if no filters)
        """
        if not filters:
            return None

        conditions = []
        for key, value in filters.items():
            if isinstance(value, list):
                # List filters: use $in operator
                conditions.append({key: {"$in": value}})
            elif isinstance(value, dict):
                # Already an operator dict
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
_skill_chroma_store_instance = None


def get_skill_chroma_store() -> SkillChromaStore:
    """Get singleton instance of SkillChromaStore (sync factory).

    Returns:
        Singleton instance (not yet initialized)

    Example:
        >>> from src.storage.skill_chroma_store import get_skill_chroma_store
        >>> store = get_skill_chroma_store()
        >>> await store.initialize()  # Must initialize after getting instance
    """
    global _skill_chroma_store_instance

    if _skill_chroma_store_instance is None:
        _skill_chroma_store_instance = SkillChromaStore()

    return _skill_chroma_store_instance
