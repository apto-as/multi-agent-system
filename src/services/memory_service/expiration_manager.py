"""Memory Expiration Manager - TTL cleanup and expiration handling.

This module handles memory expiration operations:
- cleanup_old_memories: Clean old, low-importance memories
- find_expired_memories: Find memories past their TTL
- cleanup_expired_memories: Delete expired memories
- run_expiration_cleanup: Complete cleanup workflow
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import and_, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import ChromaOperationError
from src.models.memory import Memory

if TYPE_CHECKING:
    from src.services.vector_search_service import VectorSearchService

logger = logging.getLogger(__name__)


class MemoryExpirationManager:
    """Manager for memory expiration and cleanup operations."""

    def __init__(
        self,
        session: AsyncSession,
        vector_service: "VectorSearchService | None",
        ensure_initialized: Any,  # Callable for lazy init
    ):
        """Initialize expiration manager.

        Args:
            session: Async database session
            vector_service: ChromaDB vector search service
            ensure_initialized: Async callable for ChromaDB lazy init
        """
        self.session = session
        self.vector_service = vector_service
        self._ensure_initialized = ensure_initialized

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

        Args:
            days: Age threshold in days (default: 90)
            min_importance: Importance threshold (default: 0.3)

        Returns:
            Number of memories deleted
        """
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

        # Delete from ChromaDB (best-effort)
        if self.vector_service:
            try:
                await self._ensure_initialized()
                await self.vector_service.delete_memories_batch([str(mid) for mid in memory_ids])
            except (KeyboardInterrupt, SystemExit):
                raise
            except ChromaOperationError as e:
                logger.warning(f"Chroma cleanup failed: {e}")
            except Exception as e:
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
                        raise
                    except ChromaOperationError as e:
                        logger.warning(
                            f"ChromaDB deletion failed for memory {memory.id}: {e}",
                            extra={
                                "memory_id": str(memory.id),
                                "agent_id": memory.agent_id,
                            },
                        )
                    except Exception as e:
                        logger.warning(
                            f"Unexpected error during ChromaDB deletion for memory "
                            f"{memory.id}: {e}",
                            extra={
                                "memory_id": str(memory.id),
                                "agent_id": memory.agent_id,
                            },
                        )

                # Delete from SQLite
                await self.session.delete(memory)
                deleted_count += 1

                # Audit log: Individual memory deletion
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
                raise
            except Exception as e:
                logger.error(
                    f"Failed to delete expired memory {memory.id}: {e}",
                    extra={
                        "memory_id": str(memory.id),
                        "agent_id": memory.agent_id,
                    },
                )

        # Commit all deletions
        await self.session.commit()

        # Audit log: Cleanup summary
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
            logger.info(
                "expiration_cleanup_completed",
                extra={
                    "deleted_count": 0,
                },
            )
            return 0

        # Cleanup expired memories
        deleted_count = await self.cleanup_expired_memories(expired_memories)

        # Audit log: Cleanup completed
        logger.info(
            "expiration_cleanup_completed",
            extra={
                "deleted_count": deleted_count,
            },
        )

        return deleted_count
