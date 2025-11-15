"""RBAC (Role-Based Access Control) Implementation.

Implements permission checking for license management MCP tools.
Based on design: docs/security/RBAC_PERMISSION_MATRIX.md

Security Compliance:
- V-RBAC-1: Namespace isolation (fetch agent from DB)
- V-RBAC-2: Audit logging (all permission checks)
- Fail-secure defaults (unknown → DENY)

Author: Artemis (Technical Perfectionist)
Created: 2025-11-15
Version: 1.0.0
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from functools import wraps
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import PermissionError, log_and_raise
from src.models.agent import Agent
from src.models.audit_log import SecurityAuditLog

logger = logging.getLogger(__name__)


class Role(str, Enum):
    """RBAC roles (hierarchy: viewer < editor < admin)."""

    VIEWER = "viewer"
    EDITOR = "editor"
    ADMIN = "admin"


# Permission matrix (from Hestia's design)
ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.VIEWER: {
        "license:validate",
        "license:read",  # own licenses only
        "license:usage:read",  # own licenses only
    },
    Role.EDITOR: {
        "license:validate",
        "license:read",
        "license:usage:read",
        "license:generate",  # NEW permission
    },
    Role.ADMIN: {
        "license:validate",
        "license:read",
        "license:usage:read",
        "license:generate",
        "license:revoke",  # NEW permission
        "license:admin",  # NEW permission
        "agent:update:tier",  # NEW permission
        "system:audit",  # NEW permission
    },
}

# Operations requiring ownership check
OWNERSHIP_REQUIRED_OPERATIONS = {
    "license:read",
    "license:usage:read",
}


async def check_permission(
    db_session: AsyncSession,
    agent_id: UUID,
    operation: str,
    resource_owner_id: UUID | None = None,
) -> bool:
    """Check if agent has permission for operation.

    Security Implementation (V-RBAC-1, V-RBAC-2):
    1. Fetch agent from DB (verified namespace)
    2. Get role (default: viewer)
    3. Check role permissions
    4. Ownership check (if applicable)
    5. Audit log (ALLOW/DENY)

    Args:
        db_session: Database session
        agent_id: Agent UUID
        operation: Operation ID (e.g., "license:generate")
        resource_owner_id: Owner of resource (for ownership checks)

    Returns:
        True if allowed, False if denied

    Security:
        - Fetches agent from DB (V-RBAC-1: verified namespace)
        - Logs all checks (V-RBAC-2: audit trail)
        - Fail-secure: Unknown operation → DENY
    """
    # Step 1: Fetch agent with verified namespace (V-RBAC-1)
    stmt = select(Agent).where(Agent.id == str(agent_id))
    result = await db_session.execute(stmt)
    agent = result.scalar_one_or_none()

    if not agent:
        await _audit_log(
            db_session, agent_id, operation, "DENY", "Agent not found"
        )
        return False

    # Step 2: Get agent's role (default: viewer, fail-secure)
    role_str = getattr(agent, "role", "viewer")
    try:
        role = Role(role_str)
    except ValueError:
        # Unknown role → default to viewer (fail-secure)
        role = Role.VIEWER
        await _audit_log(
            db_session,
            agent_id,
            operation,
            "DENY",
            f"Unknown role '{role_str}', defaulted to viewer",
        )

    # Step 3: Check role hierarchy
    permissions = ROLE_PERMISSIONS.get(role, set())

    if operation not in permissions:
        await _audit_log(
            db_session,
            agent_id,
            operation,
            "DENY",
            f"Role {role.value} lacks permission",
        )
        return False

    # Step 4: Ownership check (if applicable)
    if operation in OWNERSHIP_REQUIRED_OPERATIONS and role != Role.ADMIN and resource_owner_id != agent_id:
        await _audit_log(
            db_session,
            agent_id,
            operation,
            "DENY",
            "Ownership check failed",
        )
        return False

    # Step 5: Audit log success (V-RBAC-2)
    await _audit_log(
        db_session, agent_id, operation, "ALLOW", f"Role {role.value}"
    )
    return True


async def _audit_log(
    db_session: AsyncSession,
    agent_id: UUID,
    operation: str,
    result: str,  # "ALLOW" or "DENY"
    details: str,
) -> None:
    """Log permission check to security_audit_logs table (V-RBAC-2)."""
    audit_entry = SecurityAuditLog(
        event_type="permission_check",
        severity="medium" if result == "DENY" else "low",
        timestamp=datetime.now(timezone.utc),
        client_ip="internal",  # RBAC checks are internal
        user_id=str(agent_id),
        message=f"Permission check: {operation} → {result}",
        details={
            "operation": operation,
            "result": result,
            "details": details,
        },
        risk_score=50 if result == "DENY" else 0,
        blocked=result == "DENY",
    )
    db_session.add(audit_entry)
    # Note: No commit here - caller handles transaction


def require_permission(operation: str):
    """Decorator to enforce permission checks on MCP tools.

    Usage:
        @require_permission("license:generate")
        async def generate_license_key(...):
            ...

    Args:
        operation: Operation ID (e.g., "license:admin")

    Raises:
        PermissionError: If agent lacks permission
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract db_session and agent_id from kwargs
            db_session = kwargs.get("db_session")
            agent_id = kwargs.get("agent_id")
            resource_owner_id = kwargs.get("resource_owner_id")

            if not db_session or not agent_id:
                log_and_raise(
                    PermissionError,
                    "RBAC decorator requires db_session and agent_id kwargs",
                )

            # Check permission
            allowed = await check_permission(
                db_session, agent_id, operation, resource_owner_id
            )

            if not allowed:
                log_and_raise(
                    PermissionError,
                    f"Permission denied: Operation '{operation}' requires appropriate role",
                    details={
                        "agent_id": str(agent_id),
                        "operation": operation,
                    },
                )

            # Execute function
            return await func(*args, **kwargs)

        return wrapper

    return decorator
