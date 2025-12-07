"""Memory CRUD Operations - Create, Read, Update, Delete operations.

This module handles all CRUD operations for memories:
- create_memory: Create new memory with embedding
- get_memory: Retrieve memory with access control
- update_memory: Update memory with embedding re-sync
- delete_memory: Delete from SQLite and ChromaDB
- batch_create_memories: Batch creation for performance

Security Patterns:
- P0-1: Ownership verification
- V-NS-1: Namespace verification from database
- V-RATE-1: Access tracking rate limiting
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import delete, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import (
    AuthorizationError,
    ChromaOperationError,
    EmbeddingGenerationError,
    MemoryCreationError,
    NotFoundError,
    log_and_raise,
)
from src.models.agent import AccessLevel
from src.models.memory import Memory

from .validation import validate_access_level_ttl_limit, validate_ttl_days

if TYPE_CHECKING:
    from src.services.embedding_service import EmbeddingService
    from src.services.vector_search_service import VectorSearchService

logger = logging.getLogger(__name__)


class MemoryCRUDOperations:
    """CRUD operations for memories."""

    def __init__(
        self,
        session: AsyncSession,
        embedding_service: "EmbeddingService",
        vector_service: "VectorSearchService | None",
        embedding_model_name: str,
        embedding_dimension: int,
        ensure_initialized: Any,  # Callable for lazy init
        sync_to_chroma: Any,  # Callable for ChromaDB sync
        get_agent_service: Any,  # Callable to get AgentService
    ):
        """Initialize CRUD operations.

        Args:
            session: Async database session
            embedding_service: Service for generating embeddings
            vector_service: ChromaDB vector search service
            embedding_model_name: Name of embedding model
            embedding_dimension: Dimension of embeddings
            ensure_initialized: Async callable for ChromaDB lazy init
            sync_to_chroma: Async callable for syncing to ChromaDB
            get_agent_service: Callable to get AgentService (lazy)
        """
        self.session = session
        self.embedding_service = embedding_service
        self.vector_service = vector_service
        self.embedding_model_name = embedding_model_name
        self.embedding_dimension = embedding_dimension
        self._ensure_initialized = ensure_initialized
        self._sync_to_chroma = sync_to_chroma
        self._get_agent_service = get_agent_service

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
        ttl_days: int | None = None,
    ) -> Memory:
        """Create a new memory with embedding generation.

        Phase 1B Security:
        - V-TTL-1: TTL validation (1-3650 days)
        - V-TTL-2: Access-level based TTL limits
        - V-TTL-3: Input type validation

        Workflow:
        1. Validate TTL parameters
        2. Generate embedding
        3. Create Memory in SQLite
        4. Sync to ChromaDB (REQUIRED)
        5. Return created Memory

        Args:
            content: Memory content text
            agent_id: Owner agent ID
            namespace: Namespace for isolation
            importance_score: Importance score (0.0-1.0)
            tags: Optional tags list
            access_level: Access level (default: PRIVATE)
            shared_with_agents: List of agent IDs for SHARED access
            context: Optional context dictionary
            ttl_days: TTL in days (1-3650) or None for permanent

        Returns:
            Created Memory object

        Raises:
            ValidationError: Invalid TTL or parameters
            MemoryCreationError: Failed to create memory
        """
        try:
            # Phase 1B Security: Validate TTL parameters
            validate_ttl_days(ttl_days)
            validate_access_level_ttl_limit(access_level, ttl_days)

            # Calculate expires_at from ttl_days
            expires_at = None
            if ttl_days is not None:
                expires_at = datetime.now(timezone.utc) + timedelta(days=ttl_days)

            # Generate embedding
            embedding_vector = await self.embedding_service.encode_document(content)

            # Create Memory object (metadata only - embedding goes to Chroma)
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
                expires_at=expires_at,
            )

            # Save to SQLite first
            self.session.add(memory)
            await self.session.commit()
            await self.session.refresh(memory)

            # Sync to Chroma (REQUIRED - no fallback)
            try:
                await self._ensure_initialized()
                await self._sync_to_chroma(memory, embedding_vector.tolist())
            except (KeyboardInterrupt, SystemExit):
                await self.session.rollback()
                raise
            except ChromaOperationError:
                await self.session.rollback()
                raise
            except Exception as e:
                await self.session.rollback()
                log_and_raise(
                    ChromaOperationError,
                    "Cannot create memory without Chroma vector storage",
                    original_exception=e,
                    details={"memory_id": str(memory.id)},
                )

            logger.info(
                f"Memory created: {memory.id}",
                extra={
                    "memory_id": str(memory.id),
                    "agent_id": agent_id,
                    "namespace": namespace,
                    "ttl_days": ttl_days,
                    "expires_at": expires_at.isoformat() if expires_at else None,
                },
            )
            return memory

        except (KeyboardInterrupt, SystemExit):
            raise
        except (ChromaOperationError, EmbeddingGenerationError):
            raise
        except SQLAlchemyError as e:
            await self.session.rollback()
            log_and_raise(
                MemoryCreationError,
                "Database error during memory creation",
                original_exception=e,
                details={"agent_id": agent_id, "namespace": namespace},
            )
        except Exception as e:
            await self.session.rollback()
            log_and_raise(
                MemoryCreationError,
                "Unexpected error during memory creation",
                original_exception=e,
                details={"agent_id": agent_id, "namespace": namespace},
            )

    async def get_memory(
        self,
        memory_id: UUID,
        caller_agent_id: str | None = None,
        track_access: bool = True,
    ) -> Memory | None:
        """Get a single memory by ID with access tracking and authorization.

        Phase 1B Security Features:
        - Authorization check using Memory.is_accessible_by()
        - Rate-limited access tracking (5-second window)
        - Namespace verification from database (V-NS-1)
        - Audit logging for access events

        Args:
            memory_id: Memory UUID to retrieve
            caller_agent_id: Agent requesting access (for authorization)
            track_access: Whether to track access (update count and timestamp)

        Returns:
            Memory object if found and authorized, None if not found

        Raises:
            AuthorizationError: If agent not authorized to access memory
        """
        result = await self.session.execute(
            select(Memory).where(Memory.id == str(memory_id))
        )
        memory = result.scalar_one_or_none()

        if not memory:
            return None

        # Authorization check when caller is specified
        if caller_agent_id is not None and track_access:
            agent_service = self._get_agent_service()
            caller_agent = await agent_service.get_agent_by_id(caller_agent_id)
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

        # Access tracking (rate limited)
        if track_access:
            should_track = True
            if memory.accessed_at is not None:
                time_since_last_access = datetime.now(timezone.utc) - memory.accessed_at
                if time_since_last_access < timedelta(seconds=5):
                    should_track = False
                    logger.debug(
                        f"Access tracking rate limited for memory {memory_id}: "
                        f"{time_since_last_access.total_seconds():.1f}s since last access"
                    )

            if should_track:
                memory.update_access()
                await self.session.commit()
                await self.session.refresh(memory)

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
        """Update memory with re-sync to ChromaDB.

        If content changes, regenerate embedding and update both stores.

        Args:
            memory_id: Memory UUID to update
            content: New content (triggers embedding regeneration)
            importance_score: New importance score
            tags: New tags list
            context: New context dictionary

        Returns:
            True if updated successfully, False if memory not found
        """
        memory = await self.get_memory(memory_id, track_access=False)
        if not memory:
            return False

        # Update fields
        if content is not None and content != memory.content:
            memory.content = content
            # Regenerate embedding for new content
            embedding_vector = await self.embedding_service.encode_document(content)

            # Re-sync to Chroma (REQUIRED)
            try:
                await self._ensure_initialized()
                await self.vector_service.delete_memory(str(memory_id))
                await self._sync_to_chroma(memory, embedding_vector.tolist())
            except (KeyboardInterrupt, SystemExit):
                await self.session.rollback()
                raise
            except ChromaOperationError:
                await self.session.rollback()
                raise
            except Exception as e:
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
        """Delete memory from both SQLite and ChromaDB.

        Best-effort deletion from ChromaDB, but ensure SQLite deletion succeeds.

        Args:
            memory_id: Memory UUID to delete

        Returns:
            True if deleted, False if memory not found
        """
        # Delete from Chroma first (best-effort)
        if self.vector_service:
            try:
                await self._ensure_initialized()
                await self.vector_service.delete_memory(str(memory_id))
            except (KeyboardInterrupt, SystemExit):
                raise
            except ChromaOperationError as e:
                logger.warning(f"Chroma deletion failed for {memory_id}: {e}")
            except Exception as e:
                logger.warning(f"Unexpected error during Chroma deletion for {memory_id}: {e}")

        # Delete from SQLite (must succeed)
        result = await self.session.execute(delete(Memory).where(Memory.id == memory_id))
        await self.session.commit()

        deleted = result.rowcount > 0
        if deleted:
            logger.info(f"Memory deleted: {memory_id}")
        return deleted

    async def batch_create_memories(
        self,
        memories_data: list[dict[str, Any]],
    ) -> list[Memory]:
        """Batch create memories with optimized ChromaDB sync.

        Performance: > 100 memories/second

        Args:
            memories_data: List of memory data dictionaries

        Returns:
            List of created Memory objects

        Raises:
            ValueError: If namespace is missing
            MemoryCreationError: If batch creation fails
        """
        memories = []
        embeddings = []

        try:
            # Generate embeddings in batch
            contents = [m["content"] for m in memories_data]
            embedding_vectors = await self.embedding_service.encode_batch(contents, is_query=False)

            # Create Memory objects
            for data, embedding in zip(memories_data, embedding_vectors, strict=False):
                if "namespace" not in data:
                    raise ValueError(
                        "namespace is required in memory data. "
                        "Explicit 'default' namespace is rejected to prevent "
                        "cross-project leakage."
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
                await self.session.rollback()
                raise
            except ChromaOperationError:
                await self.session.rollback()
                raise
            except Exception as e:
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
            await self.session.rollback()
            raise
        except (ChromaOperationError, SQLAlchemyError, EmbeddingGenerationError):
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            log_and_raise(
                MemoryCreationError,
                "Batch memory creation failed with unexpected error",
                original_exception=e,
                details={"memory_count": len(memories_data)},
            )

    async def fetch_memories_by_ids(
        self,
        memory_ids: list[str],
        agent_id: str | None,
        min_importance: float,
    ) -> list[Memory]:
        """Fetch memories from SQLite by IDs with additional filtering.

        Args:
            memory_ids: List of memory ID strings
            agent_id: Filter by agent ID
            min_importance: Minimum importance score filter

        Returns:
            List of Memory objects matching criteria
        """
        if not memory_ids:
            return []

        query = select(Memory).where(Memory.id.in_(memory_ids))

        # Apply filters
        if agent_id:
            # Note: SQLite doesn't support .contains() on JSON columns like PostgreSQL
            query = query.where(
                or_(
                    Memory.agent_id == agent_id,
                    Memory.access_level == AccessLevel.PUBLIC,
                ),
            )

        if min_importance > 0:
            query = query.where(Memory.importance_score >= min_importance)

        result = await self.session.execute(query)
        return list(result.scalars().all())
