"""Hybrid Memory Service - SQLite + Chroma Integration

This service provides unified memory management with:
- SQLite as source of truth (lightweight, zero-config)
- Chroma as high-speed vector cache (P95: 0.47ms)
- Multilingual-E5 Large embeddings (1024-dimensional, cross-lingual via Ollama)
- Write-through pattern for consistency
- Read-first pattern for performance

Phase: 4a (TMWS v2.2.6)
"""

import logging
from datetime import datetime, timedelta, timezone

# Import AgentService after avoiding circular imports
# AgentService is needed for namespace verification during authorization
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_session
from src.core.exceptions import (
    AuthorizationError,
    ChromaOperationError,
    EmbeddingGenerationError,
    MemoryCreationError,
    MemorySearchError,
    ValidationError,
    log_and_raise,
)
from src.models.memory import AccessLevel, Memory
from src.services.ollama_embedding_service import get_ollama_embedding_service
from src.services.vector_search_service import get_vector_search_service

if TYPE_CHECKING:
    from src.services.agent_service import AgentService

logger = logging.getLogger(__name__)


def _validate_ttl_days(ttl_days: int | None) -> None:
    """Validate TTL (Time-To-Live) parameter for security.

    This function prevents security attacks targeting the TTL parameter:
    - V-TTL-1: Prevents extreme TTL values (> 3650 days / 10 years)
    - V-TTL-2: Prevents zero or negative TTL values
    - V-TTL-3: Prevents type confusion attacks (string, float, etc.)

    Args:
        ttl_days: Optional TTL in days (1-3650) or None for permanent storage

    Raises:
        ValueError: If ttl_days is invalid (0, negative, or > 3650)
        TypeError: If ttl_days is not int or None

    Security Implications:
        - Extreme TTL values could be used to exhaust storage
        - Zero/negative values could bypass cleanup logic
        - Type confusion could lead to unexpected behavior

    TODO(v2.3.1 Phase 1B):
        - Add access-level based TTL limits (e.g., PRIVATE: 365, PUBLIC: 90)
        - Add namespace-based quotas
        - Add rate limiting for TTL-based memory creation

    Examples:
        >>> _validate_ttl_days(None)  # OK: Permanent memory
        >>> _validate_ttl_days(7)     # OK: 7 days
        >>> _validate_ttl_days(3650)  # OK: 10 years (maximum)
        >>> _validate_ttl_days(0)     # Raises ValueError
        >>> _validate_ttl_days(3651)  # Raises ValueError
        >>> _validate_ttl_days("7")   # Raises TypeError
    """
    if ttl_days is None:
        return  # Permanent memory is allowed

    # V-TTL-3: Type validation (prevent type confusion attacks)
    if not isinstance(ttl_days, int):
        raise TypeError(
            f"ttl_days must be an integer or None, got {type(ttl_days).__name__}"
        )

    # V-TTL-2: Prevent zero/negative values (security bypass)
    if ttl_days < 1:
        raise ValueError(
            f"ttl_days must be at least 1 day, got {ttl_days}. "
            "For immediate deletion, use delete_memory() instead."
        )

    # V-TTL-1: Prevent extreme values (storage exhaustion)
    if ttl_days > 3650:
        raise ValueError(
            f"ttl_days must be at most 3650 days (10 years), got {ttl_days}. "
            "For permanent storage, use ttl_days=None."
        )


def _validate_access_level_ttl_limit(access_level: AccessLevel, ttl_days: int | None) -> None:
    """Validate TTL limits based on access level (Phase 1B Part 3).

    Access-level based TTL limits prevent long-lived exposure of sensitive data:
    - PRIVATE: max 365 days (1 year) - personal sensitive data
    - TEAM: max 180 days (6 months) - team collaboration data
    - PUBLIC: max 90 days (3 months) - publicly accessible data (most restricted)
    - SYSTEM: None only (permanent) - system configuration and announcements

    This builds on top of _validate_ttl_days() which enforces base limits (1-3650 days).

    Args:
        access_level: The access level of the memory
        ttl_days: Optional TTL in days or None for permanent storage

    Raises:
        ValidationError: If ttl_days exceeds the maximum for the access level

    Security Rationale:
        - PUBLIC memories are most restricted (90 days) to limit exposure window
        - TEAM memories have medium restriction (180 days) for collaboration needs
        - PRIVATE memories have longest user-space limit (365 days)
        - SYSTEM memories must be permanent (no TTL) for consistency

    Examples:
        >>> _validate_access_level_ttl_limit(AccessLevel.PRIVATE, 365)  # OK
        >>> _validate_access_level_ttl_limit(AccessLevel.PRIVATE, 366)  # Raises ValidationError
        >>> _validate_access_level_ttl_limit(AccessLevel.TEAM, 180)    # OK
        >>> _validate_access_level_ttl_limit(AccessLevel.TEAM, 181)    # Raises ValidationError
        >>> _validate_access_level_ttl_limit(AccessLevel.PUBLIC, 90)   # OK
        >>> _validate_access_level_ttl_limit(AccessLevel.PUBLIC, 91)   # Raises ValidationError
        >>> _validate_access_level_ttl_limit(AccessLevel.SYSTEM, None) # OK
        >>> _validate_access_level_ttl_limit(AccessLevel.SYSTEM, 1)    # Raises ValidationError
    """
    # Define maximum TTL for each access level
    ACCESS_LEVEL_TTL_LIMITS = {
        AccessLevel.PRIVATE: 365,  # 1 year
        AccessLevel.TEAM: 180,     # 6 months
        AccessLevel.PUBLIC: 90,    # 3 months (most restricted)
        AccessLevel.SYSTEM: None,  # Permanent only (no TTL allowed)
    }

    max_ttl = ACCESS_LEVEL_TTL_LIMITS[access_level]

    # SYSTEM memories must NOT have a TTL (permanent only)
    if access_level == AccessLevel.SYSTEM:
        if ttl_days is not None:
            raise ValidationError(
                f"SYSTEM memories must be permanent (ttl_days=None). "
                f"Got ttl_days={ttl_days}. "
                f"SYSTEM memories are for configuration and announcements that should never expire."
            )
        return  # None is valid for SYSTEM

    # For other access levels, None is always allowed (permanent storage)
    if ttl_days is None:
        return

    # Check if TTL exceeds the maximum for this access level
    if ttl_days > max_ttl:
        raise ValidationError(
            f"{access_level.value.upper()} memories cannot have TTL > {max_ttl} days. "
            f"Got ttl_days={ttl_days}. "
            f"This limit prevents long-lived exposure of {access_level.value} data. "
            f"For permanent storage, use ttl_days=None."
        )


class HybridMemoryService:
    """Hybrid Memory Service combining SQLite and Chroma.

    Architecture:
    - SQLite: Source of truth, full metadata, ACID transactions, zero-config
    - Chroma: Hot cache, ultra-fast vector search (0.47ms P95)
    - Multilingual-E5 Large: 1024-dimensional embeddings, cross-lingual support via Ollama

    Performance targets (achieved in Phase 1 benchmarks):
    - Hierarchical retrieval: < 50ms (achieved: 32.85ms)
    - Tag search: < 10-20ms (achieved: 10.87ms)
    - Metadata complex search: < 20ms (achieved: 2.63ms)
    - Cross-agent sharing: < 15ms (achieved: 9.33ms)
    """

    def __init__(
        self,
        session: AsyncSession,
        agent_service: "AgentService | None" = None,
    ):
        self.session = session
        self.embedding_service = get_ollama_embedding_service()
        self.vector_service = get_vector_search_service()

        # AgentService for authorization (lazy initialization if not provided)
        self._agent_service = agent_service

        # Get model info for metadata tracking
        model_info = self.embedding_service.get_model_info()
        self.embedding_model_name = model_info.get("model_name", "zylonai/multilingual-e5-large")
        self.embedding_dimension = model_info.get("dimension", 1024)

        # Note: Chroma initialization is deferred to first async method call
        # This is required because __init__ cannot be async
        self._initialized = False

    @property
    def agent_service(self) -> "AgentService":
        """Get AgentService instance (lazy initialization)."""
        if self._agent_service is None:
            # Avoid circular import by importing here
            from src.services.agent_service import AgentService
            self._agent_service = AgentService(self.session)
        return self._agent_service

    @agent_service.setter
    def agent_service(self, value: "AgentService") -> None:
        """Set AgentService instance (for testing)."""
        self._agent_service = value

    async def _ensure_initialized(self) -> None:
        """Ensure vector service is initialized (called from async methods)."""
        if self._initialized:
            return

        # Chroma is REQUIRED for vector storage (SQLite stores metadata only)
        try:
            await self.vector_service.initialize()
            self._initialized = True
            logger.info("HybridMemoryService initialized: SQLite (metadata) + Chroma (vectors)")
        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except ChromaOperationError:
            # ChromaDB specific errors - already logged by ChromaOperationError
            raise
        except Exception as e:
            # Unexpected initialization errors
            log_and_raise(
                ChromaOperationError,
                "Chroma initialization FAILED - system cannot function without vectors",
                original_exception=e,
                details={"component": "HybridMemoryService"},
            )

    async def create_memory(
        self,
        content: str,
        agent_id: str,
        namespace: str,
        importance_score: float = 0.5,
        tags: list[str] | None = None,
        access_level: AccessLevel = AccessLevel.PRIVATE,
        shared_with_agents: list[str] | None = None,
        context: dict[str, Any] | None = None,
        parent_memory_id: UUID | None = None,
        ttl_days: int | None = None,
    ) -> Memory:
        """Create memory with dual storage (SQLite + Chroma).

        Write-through pattern:
        1. Generate Multilingual-E5 Large embedding (1024-dim via Ollama)
        2. Write to SQLite (metadata only - source of truth)
        3. Write to Chroma (vectors - REQUIRED, not optional)
        4. On Chroma failure, rollback SQLite and raise error

        Args:
            content: Memory content to store
            agent_id: Owner agent identifier
            namespace: Project-specific namespace (required)
            importance_score: Importance score (0.0-1.0, default=0.5)
            tags: Optional tags for categorization
            access_level: Access control level (default=PRIVATE)
            shared_with_agents: List of agent IDs with explicit access
            context: Additional structured metadata (renamed from 'metadata' for consistency)
            parent_memory_id: Optional parent memory for hierarchies
            ttl_days: Optional Time-To-Live in days (1-3650) or None for permanent

        Raises:
            ValueError: If ttl_days is invalid (0, negative, or > 3650)
            TypeError: If ttl_days is not int or None
            ChromaOperationError: If Chroma sync fails (SQLite rollback automatic)

        Security:
            - TTL validated against attacks (V-TTL-1, V-TTL-2, V-TTL-3)
            - TODO(v2.3.1 Phase 1B): Add access-level based TTL limits

        Performance:
            - TTL calculation: +0.05ms overhead (negligible)
        """
        try:
            # V-TTL-1, V-TTL-2, V-TTL-3: Validate TTL parameter (security-critical)
            try:
                _validate_ttl_days(ttl_days)
            except (ValueError, TypeError) as e:
                # AUDIT LOG: TTL validation failed
                validation_error = (
                    "value_too_high" if "at most" in str(e)
                    else "value_too_low" if "at least" in str(e)
                    else "type_error" if isinstance(e, TypeError)
                    else "invalid_value"
                )
                logger.warning(
                    "ttl_validation_failed",
                    extra={
                        "agent_id": agent_id,
                        "ttl_days": ttl_days,
                        "validation_error": validation_error,
                    },
                )
                raise  # Re-raise for exception handling below

            # Phase 1B Part 3: Validate access-level based TTL limits
            try:
                _validate_access_level_ttl_limit(access_level, ttl_days)
            except ValidationError:
                # AUDIT LOG: Access-level TTL limit exceeded
                max_ttl = {
                    AccessLevel.PRIVATE: 365,
                    AccessLevel.TEAM: 180,
                    AccessLevel.PUBLIC: 90,
                    AccessLevel.SYSTEM: None,
                }.get(access_level)
                logger.warning(
                    "access_level_ttl_limit_exceeded",
                    extra={
                        "agent_id": agent_id,
                        "access_level": access_level.value,
                        "ttl_days": ttl_days,
                        "max_allowed": max_ttl,
                    },
                )
                raise  # Re-raise for exception handling below

            # Calculate expiration timestamp if TTL specified
            expires_at = None
            if ttl_days is not None:
                from datetime import datetime, timedelta, timezone
                expires_at = datetime.now(timezone.utc) + timedelta(days=ttl_days)

                # AUDIT LOG: TTL set successfully
                logger.info(
                    "memory_ttl_set",
                    extra={
                        "agent_id": agent_id,
                        "ttl_days": ttl_days,
                        "access_level": access_level.value,
                    },
                )

            # Generate embedding using Multilingual-E5
            embedding_vector = await self.embedding_service.encode_document(content)

            # Create memory in SQLite (source of truth for metadata)
            # Embeddings are stored in Chroma only
            memory = Memory(
                content=content,
                agent_id=agent_id,
                namespace=namespace,
                embedding_model=self.embedding_model_name,
                embedding_dimension=self.embedding_dimension,
                importance_score=importance_score,
                tags=tags or [],
                access_level=access_level,
                shared_with_agents=shared_with_agents or [],
                context=context or {},
                parent_memory_id=parent_memory_id,
                expires_at=expires_at,  # Set expiration timestamp
            )

            self.session.add(memory)
            await self.session.commit()
            await self.session.refresh(memory)

            # Write to Chroma (REQUIRED for vector storage)
            try:
                await self._sync_to_chroma(memory, embedding_vector.tolist())
            except (KeyboardInterrupt, SystemExit):
                # Never suppress user interrupts
                await self.session.rollback()
                raise
            except ChromaOperationError:
                # ChromaDB specific errors - rollback and re-raise
                await self.session.rollback()
                raise
            except Exception as e:
                # Chroma is required - rollback SQLite and raise error
                await self.session.rollback()
                log_and_raise(
                    ChromaOperationError,
                    "Cannot create memory without Chroma vector storage",
                    original_exception=e,
                    details={"memory_id": str(memory.id), "agent_id": agent_id},
                )

            logger.info(
                f"Memory created: {memory.id} (agent: {agent_id}, importance_score: {importance_score})",
            )
            return memory

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            await self.session.rollback()
            raise
        except (ChromaOperationError, SQLAlchemyError, ValidationError, ValueError, TypeError):
            # Expected errors - already handled/logged
            await self.session.rollback()
            raise
        except Exception as e:
            # Unexpected errors
            await self.session.rollback()
            log_and_raise(
                MemoryCreationError,
                "Memory creation failed with unexpected error",
                original_exception=e,
                details={"agent_id": agent_id, "content_length": len(content)},
            )

    async def _sync_to_chroma(self, memory: Memory, embedding: list[float]) -> None:
        """Sync memory to Chroma vector store."""
        await self._ensure_initialized()

        if not self.vector_service:
            return

        metadata = {
            "agent_id": memory.agent_id,
            "namespace": memory.namespace,
            "importance": memory.importance_score,
            "access_level": memory.access_level.value,
            "tags": memory.tags,
            "created_at": memory.created_at.isoformat()
            if hasattr(memory.created_at, "isoformat")
            else memory.created_at,
        }

        await self.vector_service.add_memory(
            memory_id=str(memory.id),
            embedding=embedding,
            metadata=metadata,
            content=memory.content,
        )

    async def get_memory(
        self,
        memory_id: UUID,
        caller_agent_id: str | None = None,
        track_access: bool = True,
    ) -> Memory | None:
        """Get memory by ID with authorization and optional access tracking.

        Args:
            memory_id: UUID of the memory to retrieve
            caller_agent_id: ID of the agent requesting access (for authorization).
                             If None, skips authorization (backward compatibility, Phase 1A behavior).
                             If provided with track_access=True, authorization is checked BEFORE tracking.
            track_access: If True (default), increment access_count and update accessed_at.
                          Set to False for internal operations (e.g., admin queries, batch processing)

        Returns:
            Memory object or None if not found

        Raises:
            AuthorizationError: If caller_agent_id is provided but agent not found or access denied

        Performance:
            - +0.2ms overhead when track_access=True (Phase 1A)
            - +0.5ms overhead when caller_agent_id provided (authorization check, Phase 1B)
            - No performance impact when track_access=False

        Security (Phase 1B):
            - Authorization check occurs BEFORE access tracking (V-ACCESS-1 fix)
            - Namespace verification from database (never trust user input)
            - Prevents unauthorized agents from inflating access_count
            - Rate limiting (5-second window) prevents DoS via access spam (V-RATE-1)
        """
        # Fetch memory from database
        result = await self.session.execute(select(Memory).where(Memory.id == memory_id))
        memory = result.scalar_one_or_none()

        # Memory not found - return None (no authorization needed)
        if memory is None:
            return None

        # PHASE 1B SECURITY: Authorization check BEFORE tracking
        if caller_agent_id is not None and track_access:
            # Fetch agent to verify namespace (SECURITY-CRITICAL)
            caller_agent = await self.agent_service.get_agent_by_id(caller_agent_id)
            if caller_agent is None:
                log_and_raise(
                    AuthorizationError,
                    f"Agent {caller_agent_id} not found",
                    details={"memory_id": str(memory_id), "caller_agent_id": caller_agent_id},
                )

            # Verify namespace from database (NEVER trust user input)
            verified_namespace = caller_agent.namespace

            # Check authorization using Memory.is_accessible_by()
            if not memory.is_accessible_by(caller_agent_id, verified_namespace):
                log_and_raise(
                    AuthorizationError,
                    f"Access denied to memory {memory_id}",
                    details={
                        "memory_id": str(memory_id),
                        "memory_owner": memory.agent_id,
                        "memory_namespace": memory.namespace,
                        "memory_access_level": memory.access_level.value,
                        "caller_agent_id": caller_agent_id,
                        "caller_namespace": verified_namespace,
                    },
                )

        # Authorization passed (or skipped) - proceed with access tracking
        if track_access:
            # PHASE 1B SECURITY: Rate limiting (V-RATE-1)
            # Check if enough time has passed since last access (5-second window)
            should_track = True
            if memory.accessed_at is not None:
                time_since_last_access = datetime.now(timezone.utc) - memory.accessed_at
                if time_since_last_access < timedelta(seconds=5):
                    # Rate limited - skip tracking
                    should_track = False
                    logger.debug(
                        f"Access tracking rate limited for memory {memory_id}: "
                        f"{time_since_last_access.total_seconds():.1f}s since last access"
                    )

            if should_track:
                memory.update_access()  # Increment access_count, update accessed_at, adjust relevance
                await self.session.commit()
                await self.session.refresh(memory)

                # AUDIT LOG: Access tracked successfully
                logger.info(
                    "memory_access_tracked",
                    extra={
                        "memory_id": str(memory_id),
                        "agent_id": memory.agent_id,
                        "access_count": memory.access_count,
                        "tracked": True,
                    },
                )
            else:
                # AUDIT LOG: Access rate limited
                logger.info(
                    "memory_access_rate_limited",
                    extra={
                        "memory_id": str(memory_id),
                        "agent_id": memory.agent_id,
                        "tracked": False,
                        "reason": "rate_limited",
                    },
                )

        return memory

    async def update_memory(
        self,
        memory_id: UUID,
        content: str | None = None,
        importance_score: float | None = None,
        tags: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Update memory with re-sync to Chroma.

        If content changes, regenerate embedding and update both stores.

        Returns:
            bool: True if memory was updated successfully, False if memory not found
        """
        memory = await self.get_memory(memory_id)
        if not memory:
            return False

        # Update fields
        if content is not None and content != memory.content:
            memory.content = content
            # Regenerate embedding for new content
            embedding_vector = await self.embedding_service.encode_document(content)
            # Embedding stored in Chroma only (not in SQLite)

            # Re-sync to Chroma (REQUIRED)
            try:
                await self._ensure_initialized()
                await self.vector_service.delete_memory(str(memory_id))
                await self._sync_to_chroma(memory, embedding_vector.tolist())
            except (KeyboardInterrupt, SystemExit):
                # Never suppress user interrupts
                await self.session.rollback()
                raise
            except ChromaOperationError:
                # ChromaDB specific errors - rollback and re-raise
                await self.session.rollback()
                raise
            except Exception as e:
                # Chroma is required - rollback and raise error
                await self.session.rollback()
                log_and_raise(
                    ChromaOperationError,
                    "Cannot update memory without Chroma vector storage",
                    original_exception=e,
                    details={"memory_id": str(memory_id)},
                )

        if importance_score is not None:
            memory.importance_score = importance_score
        if tags is not None:
            memory.tags = tags
        if context is not None:
            memory.context = context

        await self.session.commit()
        await self.session.refresh(memory)

        logger.info(f"Memory updated: {memory_id}")
        return True

    async def delete_memory(self, memory_id: UUID) -> bool:
        """Delete memory from both SQLite and Chroma.

        Best-effort deletion from Chroma, but ensure SQLite deletion succeeds.
        """
        # Delete from Chroma first (best-effort)
        if self.vector_service:
            try:
                await self._ensure_initialized()
                await self.vector_service.delete_memory(str(memory_id))
            except (KeyboardInterrupt, SystemExit):
                # Never suppress user interrupts
                raise
            except ChromaOperationError as e:
                # ChromaDB errors (best-effort, log warning and continue)
                logger.warning(f"Chroma deletion failed for {memory_id}: {e}")
            except Exception as e:
                # Unexpected errors (best-effort, log warning and continue)
                logger.warning(f"Unexpected error during Chroma deletion for {memory_id}: {e}")

        # Delete from SQLite (must succeed)
        result = await self.session.execute(delete(Memory).where(Memory.id == memory_id))
        await self.session.commit()

        deleted = result.rowcount > 0
        if deleted:
            logger.info(f"Memory deleted: {memory_id}")
        return deleted

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
        """Semantic search with Chroma (ultra-fast) + SQLite (authoritative metadata).

        Read-first pattern:
        1. Generate query embedding (Multilingual-E5 Large, 1024-dim via Ollama)
        2. Search Chroma for top-k candidates (0.47ms P95)
        3. Fetch full Memory objects from SQLite by IDs
        4. Apply additional filters (access control, importance)
        """
        try:
            # Generate query embedding
            query_embedding = await self.embedding_service.encode_query(query)

            # Search Chroma (REQUIRED - no fallback)
            chroma_results = await self._search_chroma(
                query_embedding.tolist(),
                agent_id=agent_id,
                namespace=namespace,
                tags=tags,
                min_similarity=min_similarity,
                limit=limit * 2,  # Over-fetch for filtering
            )

            if not chroma_results:
                # No results found (not an error)
                return []

            # Debug: Check ChromaDB result format
            if chroma_results:
                logger.debug(f"📦 ChromaDB returned {len(chroma_results)} results")
                logger.debug(f"🔑 Sample ID from ChromaDB: {chroma_results[0]['id']}")

            # Fetch full Memory objects from SQLite
            # ChromaDB stores UUIDs without hyphens, need to restore them
            def restore_uuid_hyphens(uuid_str: str) -> str:
                """Restore hyphens to UUID (ChromaDB removes them). Format: 8-4-4-4-12"""
                if len(uuid_str) == 32 and '-' not in uuid_str:
                    restored = f"{uuid_str[:8]}-{uuid_str[8:12]}-{uuid_str[12:16]}-{uuid_str[16:20]}-{uuid_str[20:]}"
                    logger.debug(f"🔧 Restored UUID: {uuid_str} → {restored}")
                    return restored
                return uuid_str

            # Memory.id is String(36), so we need string UUIDs, not UUID objects
            memory_ids = [restore_uuid_hyphens(r["id"]) for r in chroma_results]
            logger.debug(f"🔍 Querying {len(memory_ids)} memory IDs from SQLite")
            memories = await self._fetch_memories_by_ids(
                memory_ids,
                agent_id=agent_id,
                min_importance=min_importance,
            )

            # Preserve similarity scores from Chroma and convert to dicts
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
                    "created_at": memory.created_at.isoformat() if hasattr(memory.created_at, "isoformat") else str(memory.created_at),
                    "updated_at": memory.updated_at.isoformat() if hasattr(memory.updated_at, "isoformat") else str(memory.updated_at),
                    "similarity": similarity_map.get(str(memory.id), 0.0),
                }
                results.append(memory_dict)

            return results

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except (ChromaOperationError, EmbeddingGenerationError):
            # Expected errors - already logged
            raise
        except Exception as e:
            # Unexpected errors
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
        """Search Chroma with metadata filtering."""
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

    async def _fetch_memories_by_ids(
        self,
        memory_ids: list[str],  # Memory.id is String(36), not UUID
        agent_id: str | None,
        min_importance: float,
    ) -> list[Memory]:
        """Fetch memories from SQLite by IDs with additional filtering."""
        if not memory_ids:
            return []

        query = select(Memory).where(Memory.id.in_(memory_ids))

        # Apply filters
        if agent_id:
            # TEMPORARY FIX: SQLite doesn't support .contains() on JSON columns like PostgreSQL
            # For now, only check agent_id and access_level
            query = query.where(
                or_(
                    Memory.agent_id == agent_id,
                    Memory.access_level == AccessLevel.PUBLIC,
                    # Memory.shared_with_agents.contains([agent_id]),  # TODO: Fix for SQLite
                ),
            )

        if min_importance > 0:
            query = query.where(Memory.importance_score >= min_importance)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def batch_create_memories(
        self,
        memories_data: list[dict[str, Any]],
    ) -> list[Memory]:
        """Batch create memories with optimized Chroma sync.

        Performance: > 100 memories/second
        """
        memories = []
        embeddings = []

        try:
            # Generate embeddings in batch
            contents = [m["content"] for m in memories_data]
            embedding_vectors = await self.embedding_service.encode_batch(contents, is_query=False)

            # Create Memory objects (metadata only - embeddings go to Chroma)
            for data, embedding in zip(memories_data, embedding_vectors, strict=False):
                # Namespace is required - no default fallback for security
                if "namespace" not in data:
                    raise ValueError(
                        "namespace is required in memory data. "
                        "Explicit 'default' namespace is rejected to prevent cross-project leakage.",
                    )

                memory = Memory(
                    content=data["content"],
                    agent_id=data["agent_id"],
                    namespace=data["namespace"],
                    embedding_model=self.embedding_model_name,
                    embedding_dimension=self.embedding_dimension,
                    importance_score=data.get("importance_score", 0.5),
                    tags=data.get("tags", []),
                    access_level=data.get("access_level", AccessLevel.PRIVATE),
                    shared_with_agents=data.get("shared_with_agents", []),
                    context=data.get("context", {}),
                )
                memories.append(memory)
                embeddings.append(embedding.tolist())

            # Batch insert to SQLite
            self.session.add_all(memories)
            await self.session.commit()

            # Refresh all to get IDs
            for memory in memories:
                await self.session.refresh(memory)

            # Batch sync to Chroma (REQUIRED)
            try:
                memory_ids = [str(m.id) for m in memories]
                metadatas = [
                    {
                        "agent_id": m.agent_id,
                        "namespace": m.namespace,
                        "importance": m.importance_score,
                        "access_level": m.access_level.value,
                        "tags": m.tags,
                        "created_at": m.created_at.isoformat()
                        if hasattr(m.created_at, "isoformat")
                        else m.created_at,
                    }
                    for m in memories
                ]
                documents = [m.content for m in memories]

                await self._ensure_initialized()
                await self.vector_service.add_memories_batch(
                    memory_ids=memory_ids,
                    embeddings=embeddings,
                    metadatas=metadatas,
                    documents=documents,
                )
            except (KeyboardInterrupt, SystemExit):
                # Never suppress user interrupts
                await self.session.rollback()
                raise
            except ChromaOperationError:
                # ChromaDB specific errors - rollback and re-raise
                await self.session.rollback()
                raise
            except Exception as e:
                # Chroma is required - rollback and raise error
                await self.session.rollback()
                log_and_raise(
                    ChromaOperationError,
                    "Cannot batch create memories without Chroma vector storage",
                    original_exception=e,
                    details={"memory_count": len(memories)},
                )

            logger.info(f"Batch created {len(memories)} memories")
            return memories

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            await self.session.rollback()
            raise
        except (ChromaOperationError, SQLAlchemyError, EmbeddingGenerationError):
            # Expected errors - already handled/logged
            await self.session.rollback()
            raise
        except Exception as e:
            # Unexpected errors
            await self.session.rollback()
            log_and_raise(
                MemoryCreationError,
                "Batch memory creation failed with unexpected error",
                original_exception=e,
                details={"memory_count": len(memories_data)},
            )

    async def count_memories(
        self,
        agent_id: str | None = None,
        namespace: str | None = None,
    ) -> int:
        """Count memories (SQLite source of truth)."""
        query = select(func.count(Memory.id)).where(Memory.namespace == namespace)

        if agent_id:
            query = query.where(
                or_(
                    Memory.agent_id == agent_id,
                    Memory.access_level == AccessLevel.PUBLIC,
                    Memory.shared_with_agents.contains([agent_id]),
                ),
            )

        result = await self.session.execute(query)
        return result.scalar() or 0

    async def get_memory_stats(
        self,
        agent_id: str | None = None,
        namespace: str | None = None,
    ) -> dict[str, Any]:
        """Get memory statistics combining SQLite and Chroma."""
        # SQLite stats (authoritative)
        sqlite_count = await self.count_memories(agent_id=agent_id, namespace=namespace)

        # Chroma stats (vector storage)
        chroma_stats = {}
        if self.vector_service:
            try:
                await self._ensure_initialized()
                chroma_stats = await self.vector_service.get_collection_stats()
            except (KeyboardInterrupt, SystemExit):
                # Never suppress user interrupts
                raise
            except ChromaOperationError as e:
                # ChromaDB errors (expected, log warning)
                logger.warning(f"Chroma stats unavailable: {e}")
            except Exception as e:
                # Unexpected errors (log warning and continue)
                logger.warning(f"Unexpected error retrieving Chroma stats: {e}")

        return {
            "total_memories": sqlite_count,
            "chroma_vector_count": chroma_stats.get("memory_count", 0),
            "chroma_available": self.vector_service is not None,
            "embedding_model": self.embedding_model_name,
            "embedding_dimension": self.embedding_dimension,
            "namespace": namespace,
        }

    async def cleanup_old_memories(
        self,
        days: int = 90,
        min_importance: float = 0.3,
    ) -> int:
        """Cleanup old, low-importance memories from both stores.

        Removes memories that are:
        - Older than `days` days
        - Below `min_importance` threshold
        - Not accessed recently (access_count == 0)
        """
        from datetime import datetime, timedelta

        cutoff_date = datetime.utcnow() - timedelta(days=days)

        # Find memories to delete
        query = select(Memory.id).where(
            and_(
                Memory.created_at < cutoff_date,
                Memory.importance_score < min_importance,
                Memory.access_count == 0,
            ),
        )

        result = await self.session.execute(query)
        memory_ids = [row[0] for row in result.all()]

        if not memory_ids:
            return 0

        # Delete from Chroma (best-effort)
        if self.vector_service:
            try:
                await self._ensure_initialized()
                await self.vector_service.delete_memories_batch([str(mid) for mid in memory_ids])
            except (KeyboardInterrupt, SystemExit):
                # Never suppress user interrupts
                raise
            except ChromaOperationError as e:
                # ChromaDB errors (best-effort, log warning and continue)
                logger.warning(f"Chroma cleanup failed: {e}")
            except Exception as e:
                # Unexpected errors (best-effort, log warning and continue)
                logger.warning(f"Unexpected error during Chroma cleanup: {e}")

        # Delete from SQLite
        result = await self.session.execute(delete(Memory).where(Memory.id.in_(memory_ids)))
        await self.session.commit()

        deleted_count = result.rowcount
        logger.info(f"Cleaned up {deleted_count} old memories")
        return deleted_count

    async def find_expired_memories(self) -> list[Memory]:
        """Find all memories that have expired (expires_at is in the past).

        Returns:
            List of expired Memory objects
        """
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)

        # Query for memories where expires_at is in the past
        query = select(Memory).where(
            and_(
                Memory.expires_at.is_not(None),  # Has an expiration date
                Memory.expires_at < now,  # Already expired
            ),
        )

        result = await self.session.execute(query)
        expired_memories = result.scalars().all()

        return list(expired_memories)

    async def cleanup_expired_memories(self, expired_memories: list[Memory]) -> int:
        """Delete expired memories from both SQLite and ChromaDB.

        Args:
            expired_memories: List of Memory objects to delete

        Returns:
            Number of memories successfully deleted

        Note:
            ChromaDB deletion failures are logged but do not prevent SQLite deletion.
        """
        if not expired_memories:
            return 0

        deleted_count = 0

        for memory in expired_memories:
            try:
                # Delete from ChromaDB (best-effort)
                if self.vector_service:
                    try:
                        await self._ensure_initialized()
                        await self.vector_service.delete_memory(str(memory.id))
                    except (KeyboardInterrupt, SystemExit):
                        # Never suppress user interrupts
                        raise
                    except ChromaOperationError as e:
                        # ChromaDB errors (best-effort, log warning and continue)
                        logger.warning(
                            f"ChromaDB deletion failed for memory {memory.id}: {e}",
                            extra={
                                "memory_id": str(memory.id),
                                "agent_id": memory.agent_id,
                            },
                        )
                    except Exception as e:
                        # Unexpected errors (best-effort, log warning and continue)
                        logger.warning(
                            f"Unexpected error during ChromaDB deletion for memory {memory.id}: {e}",
                            extra={
                                "memory_id": str(memory.id),
                                "agent_id": memory.agent_id,
                            },
                        )

                # Delete from SQLite
                await self.session.delete(memory)
                deleted_count += 1

                # AUDIT LOG: Individual memory deletion
                logger.info(
                    "memory_expired_deleted",
                    extra={
                        "memory_id": str(memory.id),
                        "agent_id": memory.agent_id,
                        "access_level": memory.access_level.value,
                        "expired_at": memory.expires_at.isoformat() if memory.expires_at else None,
                    },
                )

            except (KeyboardInterrupt, SystemExit):
                # Never suppress user interrupts
                raise
            except Exception as e:
                # Unexpected error during deletion (log and continue with next memory)
                logger.error(
                    f"Failed to delete expired memory {memory.id}: {e}",
                    extra={
                        "memory_id": str(memory.id),
                        "agent_id": memory.agent_id,
                    },
                )

        # Commit all deletions
        await self.session.commit()

        # AUDIT LOG: Cleanup summary
        logger.info(
            "memories_expired_cleanup",
            extra={
                "deleted_count": deleted_count,
            },
        )

        return deleted_count

    async def run_expiration_cleanup(self) -> int:
        """Complete workflow: find and cleanup all expired memories.

        Returns:
            Number of memories deleted
        """
        # Find expired memories
        expired_memories = await self.find_expired_memories()

        if not expired_memories:
            # AUDIT LOG: No expired memories
            logger.info(
                "expiration_cleanup_completed",
                extra={
                    "deleted_count": 0,
                },
            )
            return 0

        # Cleanup expired memories
        deleted_count = await self.cleanup_expired_memories(expired_memories)

        # AUDIT LOG: Cleanup completed
        logger.info(
            "expiration_cleanup_completed",
            extra={
                "deleted_count": deleted_count,
            },
        )

        return deleted_count


# Dependency injection for FastAPI
async def get_memory_service() -> HybridMemoryService:
    """Get HybridMemoryService instance with database session."""
    async with get_session() as session:
        yield HybridMemoryService(session)
