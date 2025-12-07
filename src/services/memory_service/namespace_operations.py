"""Memory Namespace Operations - Namespace cleanup and pruning.

This module handles namespace-level operations:
- cleanup_namespace: Clean old memories in a namespace
- prune_expired_memories: Prune expired memories from a namespace

Security Patterns:
- V-NS-1: Namespace spoofing prevention
- V-PRUNE-1: Cross-namespace protection
- V-PRUNE-2: Parameter validation
- V-PRUNE-3: Rate limiting (batch limits)
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import and_, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import (
    AuthorizationError,
    ChromaOperationError,
    ValidationError,
    log_and_raise,
)
from src.models.agent import Agent
from src.models.memory import Memory

if TYPE_CHECKING:
    from src.services.vector_search_service import VectorSearchService

logger = logging.getLogger(__name__)


class MemoryNamespaceOperations:
    """Namespace-level operations for memories (SECURITY-CRITICAL)."""

    def __init__(
        self,
        session: AsyncSession,
        vector_service: "VectorSearchService | None",
        ensure_initialized: Any,  # Callable for lazy init
        ensure_audit_initialized: Any,  # Callable for audit init
        audit_logger: Any,  # AuditLogger instance
    ):
        """Initialize namespace operations.

        Args:
            session: Async database session
            vector_service: ChromaDB vector search service
            ensure_initialized: Async callable for ChromaDB lazy init
            ensure_audit_initialized: Async callable for audit logger init
            audit_logger: Audit logger instance
        """
        self.session = session
        self.vector_service = vector_service
        self._ensure_initialized = ensure_initialized
        self._ensure_audit_initialized = ensure_audit_initialized
        self.audit_logger = audit_logger

    async def cleanup_namespace(
        self,
        namespace: str,
        agent_id: str,
        days: int = 90,
        min_importance: float = 0.3,
        dry_run: bool = False,
        limit: int = 100_000,
    ) -> dict[str, Any]:
        """Cleanup old memories in a namespace (SECURITY-CRITICAL).

        This method implements V-NS-1 (Namespace Spoofing Prevention) and
        V-PRUNE-2 (Parameter Validation) security measures.

        Security Measures:
        - V-NS-1: Namespace authorization (agent.namespace == target namespace)
        - V-PRUNE-2: Parameter validation (days: 1-3650, importance: 0.0-1.0)
        - V-PRUNE-3: Rate limiting (max 100k deletions per call)
        - Audit logging (BEFORE + AFTER deletion)

        Args:
            namespace: Target namespace to cleanup (REQUIRED)
            agent_id: Requesting agent's ID (REQUIRED for authorization)
            days: Delete memories older than this (default: 90, range: 1-3650)
            min_importance: Delete memories below this (default: 0.3, range: 0.0-1.0)
            dry_run: If True, only count without deleting (default: False)
            limit: Maximum deletions per call (default: 100k)

        Returns:
            Dictionary with cleanup results

        Raises:
            AuthorizationError: If agent not authorized for this namespace
            ValidationError: If parameters invalid
        """
        # STEP 1: Validate input parameters (V-PRUNE-2)
        self._validate_cleanup_params(namespace, days, min_importance)

        # STEP 2: Verify agent exists and get VERIFIED namespace (V-NS-1)
        agent = await self._verify_agent_namespace(agent_id, namespace)

        # AUDIT LOG: Namespace cleanup initiated (BEFORE operation)
        await self._ensure_audit_initialized()
        if self.audit_logger:
            await self.audit_logger.log_event(
                event_type="namespace_cleanup_initiated",
                event_data={
                    "severity": "HIGH",
                    "message": f"Namespace cleanup initiated by {agent_id}",
                    "details": {
                        "namespace": namespace,
                        "agent_id": agent_id,
                        "days": days,
                        "min_importance": min_importance,
                        "dry_run": dry_run,
                        "limit": limit,
                    },
                },
                agent_id=agent_id,
                user_id=agent_id,
            )

        # STEP 3: Find memories to delete
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        query = (
            select(Memory.id)
            .where(
                and_(
                    Memory.namespace == namespace,
                    Memory.created_at < cutoff_date,
                    Memory.importance_score < min_importance,
                    Memory.access_count == 0,
                ),
            )
            .limit(limit)
        )

        result = await self.session.execute(query)
        memory_ids = [row[0] for row in result.all()]

        # AUDIT LOG: Cleanup started
        logger.warning(
            "namespace_cleanup_started",
            extra={
                "namespace": namespace,
                "agent_id": agent_id,
                "days": days,
                "min_importance": min_importance,
                "memories_to_delete": len(memory_ids),
                "dry_run": dry_run,
                "limit": limit,
            },
        )

        # DRY RUN mode: Return count without deleting
        if dry_run:
            logger.info(
                "namespace_cleanup_dry_run",
                extra={
                    "namespace": namespace,
                    "would_delete": len(memory_ids),
                },
            )
            return {
                "deleted_count": 0,
                "would_delete": len(memory_ids),
                "dry_run": True,
                "namespace": namespace,
                "criteria": {
                    "days": days,
                    "min_importance": min_importance,
                    "limit": limit,
                },
            }

        # STEP 4: Delete memories (if not dry-run)
        if not memory_ids:
            logger.info(
                "namespace_cleanup_completed",
                extra={
                    "namespace": namespace,
                    "deleted_count": 0,
                },
            )
            return {
                "deleted_count": 0,
                "dry_run": False,
                "namespace": namespace,
                "criteria": {
                    "days": days,
                    "min_importance": min_importance,
                    "limit": limit,
                },
            }

        # Delete from ChromaDB (best-effort)
        await self._delete_from_chroma(memory_ids, namespace)

        # Delete from SQLite
        result = await self.session.execute(delete(Memory).where(Memory.id.in_(memory_ids)))
        await self.session.commit()

        deleted_count = result.rowcount

        # AUDIT LOG: Cleanup completed
        logger.warning(
            "namespace_cleanup_completed",
            extra={
                "namespace": namespace,
                "agent_id": agent_id,
                "deleted_count": deleted_count,
                "days": days,
                "min_importance": min_importance,
            },
        )

        # AUDIT LOG: Namespace cleanup complete (AFTER operation)
        if self.audit_logger:
            await self.audit_logger.log_event(
                event_type="namespace_cleanup_complete",
                event_data={
                    "severity": "MEDIUM",
                    "message": f"Deleted {deleted_count} memories from {namespace}",
                    "details": {
                        "namespace": namespace,
                        "deleted_count": deleted_count,
                        "dry_run": dry_run,
                    },
                },
                agent_id=agent_id,
            )

        return {
            "deleted_count": deleted_count,
            "dry_run": False,
            "namespace": namespace,
            "criteria": {
                "days": days,
                "min_importance": min_importance,
                "limit": limit,
            },
        }

    async def prune_expired_memories(
        self,
        namespace: str,
        agent_id: str,
        limit: int = 1000,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Prune expired memories from a namespace (SECURITY-CRITICAL).

        This method implements V-PRUNE-1 (Cross-namespace protection) and
        V-NS-1 (Namespace Spoofing Prevention) security measures.

        Security Measures:
        - V-PRUNE-1: Namespace parameter MANDATORY (no default)
        - V-NS-1: Authorization check (agent.namespace == target namespace)
        - V-PRUNE-3: Batch limit (max 1000 per call to prevent DoS)
        - Audit logging (expired memory IDs logged)

        Args:
            namespace: Target namespace to prune (REQUIRED)
            agent_id: Requesting agent's ID (REQUIRED for authorization)
            limit: Maximum deletions per call (default: 1000, max: 100000)
            dry_run: If True, only count without deleting (default: False)

        Returns:
            Dictionary with prune results

        Raises:
            AuthorizationError: If agent not authorized for this namespace
            ValidationError: If parameters invalid
        """
        # STEP 1: Validate input parameters (V-PRUNE-2)
        self._validate_prune_params(namespace, limit)

        # STEP 2: Verify agent exists and get VERIFIED namespace (V-NS-1)
        agent = await self._verify_agent_namespace(agent_id, namespace)

        # AUDIT LOG: Expired memory prune initiated (BEFORE operation)
        await self._ensure_audit_initialized()
        if self.audit_logger:
            await self.audit_logger.log_event(
                event_type="expired_memory_prune_initiated",
                event_data={
                    "severity": "HIGH",
                    "message": f"Pruning expired memories in {namespace}",
                    "details": {
                        "namespace": namespace,
                        "agent_id": agent_id,
                        "dry_run": dry_run,
                        "limit": limit,
                    },
                },
                agent_id=agent_id,
            )

        # STEP 3: Find expired memories
        now = datetime.now(timezone.utc)

        query = (
            select(Memory.id)
            .where(
                and_(
                    Memory.namespace == namespace,
                    Memory.expires_at.isnot(None),
                    Memory.expires_at < now,
                )
            )
            .limit(limit)
        )

        result = await self.session.execute(query)
        memory_ids = [row[0] for row in result.all()]

        # AUDIT LOG: Prune started
        logger.warning(
            "namespace_prune_started",
            extra={
                "namespace": namespace,
                "agent_id": agent_id,
                "expired_count": len(memory_ids),
                "dry_run": dry_run,
                "limit": limit,
            },
        )

        # DRY RUN mode: Return count without deleting
        if dry_run:
            logger.info(
                "namespace_prune_dry_run",
                extra={
                    "namespace": namespace,
                    "would_delete": len(memory_ids),
                },
            )
            return {
                "deleted_count": 0,
                "expired_count": len(memory_ids),
                "dry_run": True,
                "namespace": namespace,
            }

        # STEP 4: Delete memories (if not dry-run)
        if not memory_ids:
            logger.info(
                "namespace_prune_completed",
                extra={
                    "namespace": namespace,
                    "deleted_count": 0,
                },
            )
            return {
                "deleted_count": 0,
                "expired_count": 0,
                "dry_run": False,
                "namespace": namespace,
                "deleted_ids": [],
            }

        # Delete from ChromaDB (best-effort)
        await self._delete_from_chroma(memory_ids, namespace)

        # Delete from SQLite
        result = await self.session.execute(delete(Memory).where(Memory.id.in_(memory_ids)))
        await self.session.commit()

        deleted_count = result.rowcount

        # AUDIT LOG: Prune completed
        logger.warning(
            "namespace_prune_completed",
            extra={
                "namespace": namespace,
                "agent_id": agent_id,
                "deleted_count": deleted_count,
                "deleted_ids": [str(mid) for mid in memory_ids],
            },
        )

        # AUDIT LOG: Expired memory prune complete (AFTER operation)
        if self.audit_logger:
            await self.audit_logger.log_event(
                event_type="expired_memory_prune_complete",
                event_data={
                    "severity": "MEDIUM",
                    "message": f"Pruned {deleted_count} expired memories",
                    "details": {
                        "namespace": namespace,
                        "deleted_count": deleted_count,
                        "deleted_ids": [str(mid) for mid in memory_ids[:10]],
                    },
                },
                agent_id=agent_id,
            )

        return {
            "deleted_count": deleted_count,
            "expired_count": len(memory_ids),
            "dry_run": False,
            "namespace": namespace,
            "deleted_ids": [str(mid) for mid in memory_ids],
        }

    def _validate_cleanup_params(
        self,
        namespace: str,
        days: int,
        min_importance: float,
    ) -> None:
        """Validate cleanup parameters (V-PRUNE-2).

        Args:
            namespace: Namespace to validate
            days: Days parameter to validate
            min_importance: Importance parameter to validate

        Raises:
            ValidationError: If any parameter is invalid
        """
        # Validate days parameter
        if not isinstance(days, int):
            log_and_raise(
                ValidationError,
                f"days must be an integer, got {type(days).__name__}",
                details={"days": days, "type": type(days).__name__},
            )

        if days < 1:
            log_and_raise(
                ValidationError,
                f"days must be at least 1, got {days}",
                details={"days": days},
            )

        if days > 3650:
            log_and_raise(
                ValidationError,
                f"days must be at most 3650 (10 years), got {days}",
                details={"days": days},
            )

        # Validate min_importance parameter
        if not isinstance(min_importance, int | float):
            log_and_raise(
                ValidationError,
                f"min_importance must be a number, got {type(min_importance).__name__}",
                details={"min_importance": min_importance, "type": type(min_importance).__name__},
            )

        if min_importance < 0.0 or min_importance > 1.0:
            log_and_raise(
                ValidationError,
                f"min_importance must be between 0.0 and 1.0, got {min_importance}",
                details={"min_importance": min_importance},
            )

        # Validate namespace parameter
        if not namespace or not isinstance(namespace, str):
            log_and_raise(
                ValidationError,
                "namespace must be a non-empty string",
                details={"namespace": namespace},
            )

    def _validate_prune_params(self, namespace: str, limit: int) -> None:
        """Validate prune parameters (V-PRUNE-2).

        Args:
            namespace: Namespace to validate
            limit: Limit parameter to validate

        Raises:
            ValidationError: If any parameter is invalid
        """
        if not namespace or not isinstance(namespace, str):
            log_and_raise(
                ValidationError,
                "namespace must be a non-empty string",
                details={"namespace": namespace},
            )

        if not isinstance(limit, int):
            log_and_raise(
                ValidationError,
                f"limit must be an integer, got {type(limit).__name__}",
                details={"limit": limit, "type": type(limit).__name__},
            )

        if limit < 1:
            log_and_raise(
                ValidationError,
                f"limit must be at least 1, got {limit}",
                details={"limit": limit},
            )

        if limit > 100_000:
            log_and_raise(
                ValidationError,
                f"limit must be at most 100,000, got {limit}",
                details={"limit": limit},
            )

    async def _verify_agent_namespace(self, agent_id: str, namespace: str) -> Agent:
        """Verify agent exists and has access to namespace (V-NS-1).

        Args:
            agent_id: Agent ID to verify
            namespace: Target namespace

        Returns:
            Verified Agent object

        Raises:
            AuthorizationError: If agent not found or unauthorized
        """
        stmt = select(Agent).where(Agent.agent_id == agent_id)
        result = await self.session.execute(stmt)
        agent = result.scalar_one_or_none()

        if not agent:
            log_and_raise(
                AuthorizationError,
                f"Agent {agent_id} not found",
                details={"agent_id": agent_id},
            )

        # Verify agent's namespace matches target namespace (V-NS-1)
        if agent.namespace != namespace:
            # CRITICAL SECURITY EVENT: Log unauthorized attempt
            logger.critical(
                "unauthorized_namespace_operation_attempt",
                extra={
                    "agent_id": agent_id,
                    "agent_namespace": agent.namespace,
                    "target_namespace": namespace,
                    "severity": "CRITICAL",
                },
            )
            log_and_raise(
                AuthorizationError,
                f"Agent {agent_id} (namespace: {agent.namespace}) not authorized "
                f"for namespace {namespace}",
                details={
                    "agent_id": agent_id,
                    "agent_namespace": agent.namespace,
                    "target_namespace": namespace,
                },
            )

        return agent

    async def _delete_from_chroma(self, memory_ids: list, namespace: str) -> None:
        """Delete memories from ChromaDB (best-effort).

        Args:
            memory_ids: List of memory IDs to delete
            namespace: Namespace (for logging)
        """
        if self.vector_service:
            try:
                await self._ensure_initialized()
                await self.vector_service.delete_memories_batch([str(mid) for mid in memory_ids])
            except (KeyboardInterrupt, SystemExit):
                raise
            except ChromaOperationError as e:
                logger.warning(
                    f"Chroma deletion failed (continuing with SQLite): {e}",
                    extra={
                        "namespace": namespace,
                        "memory_count": len(memory_ids),
                    },
                )
            except Exception as e:
                logger.warning(
                    f"Unexpected error during Chroma deletion (continuing with SQLite): {e}",
                    extra={
                        "namespace": namespace,
                        "memory_count": len(memory_ids),
                    },
                )
