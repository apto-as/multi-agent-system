"""Authorization helper functions for security-critical operations.

This module provides authorization verification for privileged operations
that require SYSTEM-level or admin-level permissions.

Security Design:
- SYSTEM privilege = user.role == "system" or user.is_admin == True
- Never trust client-provided metadata (always verify from DB)
- All privileged operations must call these helpers first
"""

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import AuthorizationError, log_and_raise
from src.models.agent import Agent

logger = logging.getLogger(__name__)


class User:
    """User representation for authorization checks.

    In production, this would come from JWT token after validation.
    For now, this is a simple data class.
    """

    def __init__(
        self,
        user_id: str,
        agent_id: str | None = None,
        role: str = "user",
        is_admin: bool = False,
        permissions: list[str] | None = None,
    ):
        self.user_id = user_id
        self.agent_id = agent_id
        self.role = role
        self.is_admin = is_admin
        self.permissions = permissions or []

    @property
    def is_system_user(self) -> bool:
        """Check if user has SYSTEM privileges."""
        return self.role == "system" or self.is_admin

    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission."""
        return permission in self.permissions or self.is_system_user


async def verify_system_privilege(
    user: User,
    operation: str,
    details: dict[str, Any] | None = None,
) -> None:
    """Verify that user has SYSTEM privilege for operation.

    Args:
        user: User requesting the operation
        operation: Name of the privileged operation
        details: Additional context for audit log

    Raises:
        AuthorizationError: If user lacks SYSTEM privilege

    Security:
        - SYSTEM = role=="system" OR is_admin==True
        - Failed checks are logged for audit trail

    Example:
        >>> await verify_system_privilege(user, "update_trust_score", {"agent_id": "123"})
    """
    if not user.is_system_user:
        log_and_raise(
            AuthorizationError,
            f"SYSTEM privilege required for operation: {operation}",
            details={
                "user_id": user.user_id,
                "user_role": user.role,
                "is_admin": user.is_admin,
                "operation": operation,
                "operation_details": details or {},
            },
        )

    # AUDIT LOG: Privileged operation authorized
    logger.info(
        "system_operation_authorized",
        extra={
            "user_id": user.user_id,
            "operation": operation,
            "details": details or {},
        },
    )


async def verify_namespace_access(
    session: AsyncSession,
    user: User,
    agent_id: str,
    operation: str = "access_agent_data",
) -> str:
    """Verify user has access to agent's namespace and return verified namespace.

    SECURITY-CRITICAL: Always fetch namespace from database, never trust user input.

    Args:
        session: Database session
        user: User requesting access
        agent_id: Target agent ID
        operation: Operation being performed (for audit log)

    Returns:
        Verified namespace from database

    Raises:
        AuthorizationError: If agent not found or access denied

    Security:
        - Namespace MUST come from database (V-TRUST-4 fix)
        - System users can access any namespace
        - Regular users can only access their own namespace

    Example:
        >>> namespace = await verify_namespace_access(session, user, "agent-123")
    """
    # Fetch agent from database (SECURITY: Verify namespace)
    result = await session.execute(select(Agent).where(Agent.agent_id == agent_id))
    agent = result.scalar_one_or_none()

    if agent is None:
        log_and_raise(
            AuthorizationError,
            f"Agent not found: {agent_id}",
            details={
                "user_id": user.user_id,
                "agent_id": agent_id,
                "operation": operation,
            },
        )

    # System users can access any namespace
    if user.is_system_user:
        return agent.namespace

    # Regular users must be in the same namespace
    if user.agent_id:
        user_result = await session.execute(select(Agent).where(Agent.agent_id == user.agent_id))
        user_agent = user_result.scalar_one_or_none()

        if user_agent and user_agent.namespace == agent.namespace:
            return agent.namespace

    # Access denied - different namespace
    log_and_raise(
        AuthorizationError,
        f"Cross-namespace access denied: {agent_id}",
        details={
            "user_id": user.user_id,
            "user_agent_id": user.agent_id,
            "target_agent_id": agent_id,
            "target_namespace": agent.namespace,
            "operation": operation,
        },
    )


async def verify_memory_immutable_delete(
    user: User,
    memory_id: str,
    is_immutable: bool,
) -> None:
    """Verify permission to delete immutable memory.

    Only SYSTEM users can delete immutable memories (V-TRUST-3 fix).

    Args:
        user: User requesting deletion
        memory_id: Memory ID to delete
        is_immutable: Whether memory is marked immutable

    Raises:
        AuthorizationError: If attempting to delete immutable memory without SYSTEM privilege

    Example:
        >>> await verify_memory_immutable_delete(user, "mem-123", True)
    """
    if is_immutable and not user.is_system_user:
        log_and_raise(
            AuthorizationError,
            f"Cannot delete immutable memory: {memory_id}",
            details={
                "user_id": user.user_id,
                "memory_id": memory_id,
                "is_immutable": is_immutable,
                "user_role": user.role,
            },
        )
