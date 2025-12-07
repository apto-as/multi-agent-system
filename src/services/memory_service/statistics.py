"""Memory Statistics - Stats, count, and TTL management.

This module handles memory statistics and TTL management:
- count_memories: Count memories with filters
- get_memory_stats: Get combined SQLite and ChromaDB stats
- set_memory_ttl: Update TTL for existing memory

Security Patterns:
- P0-1: Ownership verification for TTL updates
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import (
    AuthorizationError,
    ChromaOperationError,
    ValidationError,
    log_and_raise,
)
from src.models.agent import AccessLevel
from src.models.memory import Memory

if TYPE_CHECKING:
    from src.services.vector_search_service import VectorSearchService

logger = logging.getLogger(__name__)


class MemoryStatisticsService:
    """Statistics and TTL management for memories."""

    def __init__(
        self,
        session: AsyncSession,
        vector_service: "VectorSearchService | None",
        embedding_model_name: str,
        embedding_dimension: int,
        ensure_initialized: Any,  # Callable for lazy init
        ensure_audit_initialized: Any,  # Callable for audit init
        audit_logger: Any,  # AuditLogger instance
    ):
        """Initialize statistics service.

        Args:
            session: Async database session
            vector_service: ChromaDB vector search service
            embedding_model_name: Name of embedding model
            embedding_dimension: Dimension of embeddings
            ensure_initialized: Async callable for ChromaDB lazy init
            ensure_audit_initialized: Async callable for audit logger init
            audit_logger: Audit logger instance
        """
        self.session = session
        self.vector_service = vector_service
        self.embedding_model_name = embedding_model_name
        self.embedding_dimension = embedding_dimension
        self._ensure_initialized = ensure_initialized
        self._ensure_audit_initialized = ensure_audit_initialized
        self.audit_logger = audit_logger

    async def count_memories(
        self,
        agent_id: str | None = None,
        namespace: str | None = None,
    ) -> int:
        """Count memories (SQLite source of truth).

        Args:
            agent_id: Filter by agent ID (optional)
            namespace: Filter by namespace (optional)

        Returns:
            Number of memories matching criteria
        """
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
        """Get memory statistics combining SQLite and ChromaDB.

        Args:
            agent_id: Filter by agent ID (optional)
            namespace: Filter by namespace (optional)

        Returns:
            Dictionary with memory statistics
        """
        # SQLite stats (authoritative)
        sqlite_count = await self.count_memories(agent_id=agent_id, namespace=namespace)

        # ChromaDB stats (vector storage)
        chroma_stats = {}
        if self.vector_service:
            try:
                await self._ensure_initialized()
                chroma_stats = await self.vector_service.get_collection_stats()
            except (KeyboardInterrupt, SystemExit):
                raise
            except ChromaOperationError as e:
                logger.warning(f"Chroma stats unavailable: {e}")
            except Exception as e:
                logger.warning(f"Unexpected error retrieving Chroma stats: {e}")

        return {
            "total_memories": sqlite_count,
            "chroma_vector_count": chroma_stats.get("memory_count", 0),
            "chroma_available": self.vector_service is not None,
            "embedding_model": self.embedding_model_name,
            "embedding_dimension": self.embedding_dimension,
            "namespace": namespace,
        }

    async def set_memory_ttl(
        self,
        memory_id: UUID,
        agent_id: str,
        ttl_days: int | None,
    ) -> dict[str, Any]:
        """Update TTL for an existing memory (P0-1 security pattern).

        This method implements ownership verification to prevent unauthorized
        TTL modifications.

        Security Measures:
        - Ownership verification (memory.agent_id == requesting agent_id)
        - TTL validation (1-3650 days or None for permanent)
        - Audit logging (TTL changes logged)
        - Rate limiting: 30 updates/minute (enforced at API layer)

        Args:
            memory_id: Memory UUID to update
            agent_id: Requesting agent's ID (REQUIRED for ownership check)
            ttl_days: New TTL in days (1-3650) or None for permanent

        Returns:
            Dictionary with update result

        Raises:
            AuthorizationError: If not memory owner
            ValidationError: If TTL invalid or memory not found
        """
        # STEP 1: Validate TTL parameter
        if ttl_days is not None:
            if not isinstance(ttl_days, int):
                log_and_raise(
                    ValidationError,
                    f"ttl_days must be an integer or None, got {type(ttl_days).__name__}",
                    details={"ttl_days": ttl_days, "type": type(ttl_days).__name__},
                )

            if ttl_days < 1:
                log_and_raise(
                    ValidationError,
                    f"ttl_days must be at least 1, got {ttl_days}",
                    details={"ttl_days": ttl_days},
                )

            if ttl_days > 3650:
                log_and_raise(
                    ValidationError,
                    f"ttl_days must be at most 3650 (10 years), got {ttl_days}",
                    details={"ttl_days": ttl_days},
                )

        # STEP 2: Fetch memory and verify ownership
        stmt = select(Memory).where(Memory.id == str(memory_id))
        result = await self.session.execute(stmt)
        memory = result.scalar_one_or_none()

        if not memory:
            log_and_raise(
                ValidationError,
                f"Memory {memory_id} not found",
                details={"memory_id": str(memory_id)},
            )

        # STEP 3: Verify ownership (P0-1 pattern)
        if memory.agent_id != agent_id:
            # CRITICAL SECURITY EVENT: Log unauthorized attempt
            logger.critical(
                "unauthorized_memory_ttl_update_attempt",
                extra={
                    "memory_id": str(memory_id),
                    "memory_agent_id": memory.agent_id,
                    "requesting_agent_id": agent_id,
                    "ttl_days": ttl_days,
                    "severity": "CRITICAL",
                },
            )
            log_and_raise(
                AuthorizationError,
                f"Agent {agent_id} not authorized to update memory {memory_id} "
                f"(owner: {memory.agent_id})",
                details={
                    "memory_id": str(memory_id),
                    "memory_agent_id": memory.agent_id,
                    "requesting_agent_id": agent_id,
                },
            )

        # AUDIT LOG: Memory TTL update initiated (BEFORE operation)
        await self._ensure_audit_initialized()
        if self.audit_logger:
            await self.audit_logger.log_event(
                event_type="memory_ttl_update_initiated",
                event_data={
                    "severity": "MEDIUM",
                    "message": f"Updating TTL for memory {memory_id}",
                    "details": {
                        "memory_id": str(memory_id),
                        "new_ttl_days": ttl_days,
                        "agent_id": agent_id,
                    },
                },
                agent_id=agent_id,
            )

        # STEP 4: Calculate previous TTL (for audit logging)
        previous_ttl_days = None
        if memory.expires_at:
            delta = memory.expires_at - memory.created_at
            previous_ttl_days = int(delta.total_seconds() / 86400)

        # STEP 5: Update TTL
        if ttl_days is None:
            memory.expires_at = None
            new_expires_at = None
        else:
            memory.expires_at = datetime.now(timezone.utc) + timedelta(days=ttl_days)
            new_expires_at = memory.expires_at.isoformat()

        memory.updated_at = datetime.now(timezone.utc)

        await self.session.commit()
        await self.session.refresh(memory)

        # AUDIT LOG: TTL updated
        logger.warning(
            "memory_ttl_updated",
            extra={
                "memory_id": str(memory_id),
                "agent_id": agent_id,
                "previous_ttl_days": previous_ttl_days,
                "new_ttl_days": ttl_days,
                "new_expires_at": new_expires_at,
            },
        )

        # AUDIT LOG: Memory TTL update complete (AFTER operation)
        if self.audit_logger:
            await self.audit_logger.log_event(
                event_type="memory_ttl_update_complete",
                event_data={
                    "severity": "LOW",
                    "message": f"TTL updated to {ttl_days} days",
                    "details": {
                        "memory_id": str(memory_id),
                        "previous_ttl_days": previous_ttl_days,
                        "new_ttl_days": ttl_days,
                        "new_expires_at": new_expires_at,
                    },
                },
                agent_id=agent_id,
            )

        return {
            "success": True,
            "memory_id": str(memory_id),
            "expires_at": new_expires_at,
            "ttl_days": ttl_days,
            "previous_ttl_days": previous_ttl_days,
        }
