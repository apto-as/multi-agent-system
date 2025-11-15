"""MCP Tools for License Key System.

This module provides Model Context Protocol (MCP) tools for managing license keys,
including generation, validation, revocation, and usage tracking.

Wave 1 Status: ✅ Scaffolding complete
Wave 2 Status: ✅ RBAC integration + LicenseService implementation
Wave 3 TODO: Add comprehensive test suite

Design Principles:
1. Admin-only operations: generate_license_key, revoke_license_key
2. Owner/Admin operations: get_license_usage_history, get_license_info
3. All authenticated: validate_license_key
4. RBAC integration: ✅ Complete
5. Complete error handling with custom exceptions: ✅ Complete
"""

import hashlib
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import (
    NotFoundError,
    ValidationError,
    log_and_raise,
)
from src.models.license_key import LicenseKey
from src.security.rbac import require_permission
from src.services.license_service import LicenseService, TierEnum

logger = logging.getLogger(__name__)


# ============================================================================
# RBAC Integration (Wave 2: ✅ Complete)
# ============================================================================
# The require_permission decorator is imported from src.security.rbac
# All MCP tools below use this decorator for permission enforcement


# ============================================================================
# MCP Tool 1: Generate License Key (ADMIN only)
# ============================================================================


@require_permission("license:generate")
async def generate_license_key(
    db_session: AsyncSession,
    agent_id: UUID,
    tier: str,
    expires_days: int | None = None,
) -> dict[str, Any]:
    """Generate a new license key for an agent.

    Creates a new license key with the specified tier and expiration.
    Only users with ADMIN/EDITOR role can call this function.

    Args:
        db_session: Database session (required for RBAC)
        agent_id: Agent UUID (must be valid UUID)
        tier: License tier, one of: "FREE", "PRO", "ENTERPRISE"
        expires_days: Expiration in days (None = perpetual license)

    Returns:
        Dictionary containing:
            - license_key (str): The generated license key string
                Format: TMWS-{tier}-{uuid}-{checksum}
            - license_id (str): License UUID for future reference
            - tier (str): License tier (FREE/PRO/ENTERPRISE)
            - issued_at (str): ISO 8601 datetime when license was issued
            - expires_at (str | None): ISO 8601 datetime when license expires
                (None if perpetual)

    Raises:
        PermissionError: If caller lacks ADMIN/EDITOR role
        ValidationError: If tier is not one of: FREE, PRO, ENTERPRISE
        ValidationError: If expires_days is negative

    Example:
        >>> result = await generate_license_key(
        ...     db_session=session,
        ...     agent_id=UUID("550e8400-e29b-41d4-a716-446655440000"),
        ...     tier="PRO",
        ...     expires_days=365
        ... )
        >>> print(result["license_key"])
        TMWS-PRO-a1b2c3d4-e5f6-7890-abcd-ef1234567890-A3F9
    """
    # 1. Validate tier
    try:
        tier_enum = TierEnum[tier.upper()]
    except KeyError:
        log_and_raise(
            ValidationError,
            f"Invalid tier: {tier}. Must be one of: FREE, PRO, ENTERPRISE",
            details={"tier": tier, "valid_tiers": ["FREE", "PRO", "ENTERPRISE"]},
        )

    # 2. Validate expires_days (if provided)
    if expires_days is not None and expires_days <= 0:
        log_and_raise(
            ValidationError,
            f"expires_days must be positive (got: {expires_days})",
            details={"expires_days": expires_days},
        )

    # 3. Call LicenseService.generate_license_key()
    service = LicenseService(db_session=db_session)
    license_key = await service.generate_license_key(
        agent_id=agent_id,
        tier=tier_enum,
        expires_days=expires_days,
    )

    # 4. Get license info (fetch from DB)
    license_key_hash = hashlib.sha256(license_key.encode()).hexdigest()
    stmt = select(LicenseKey).where(LicenseKey.license_key_hash == license_key_hash)
    result = await db_session.execute(stmt)
    db_license = result.scalar_one()

    # 5. Return formatted response
    return {
        "license_key": license_key,
        "license_id": str(db_license.id),
        "tier": tier,
        "issued_at": db_license.issued_at.isoformat(),
        "expires_at": db_license.expires_at.isoformat() if db_license.expires_at else None,
    }


# ============================================================================
# MCP Tool 2: Validate License Key (All authenticated agents)
# ============================================================================


@require_permission("license:validate")
async def validate_license_key(
    db_session: AsyncSession,
    agent_id: UUID,  # noqa: ARG001 - Required for RBAC decorator
    key: str,
    feature_accessed: str | None = None,
) -> dict[str, Any]:
    """Validate a license key and optionally record usage.

    Checks if a license key is valid, active, and not expired. Optionally
    records which feature is being accessed for usage tracking.

    Args:
        db_session: Database session (required for RBAC)
        agent_id: Agent UUID (required for RBAC)
        key: License key string in format: TMWS-{tier}-{uuid}-{checksum}
        feature_accessed: Optional feature name for usage tracking
            Examples: "semantic_search", "workflow_execution", "memory_export"

    Returns:
        Dictionary containing:
            - valid (bool): True if key is valid and active
            - tier (str | None): License tier (FREE/PRO/ENTERPRISE) if valid
            - expires_at (str | None): ISO 8601 expiration datetime if applicable
            - is_perpetual (bool): True if license never expires
            - agent_id (str | None): Agent UUID if license is valid
            - error (str | None): Error message if validation failed

    Raises:
        ValidationError: If key format is invalid (not TMWS-{tier}-{uuid}-{checksum})

    Example:
        >>> result = await validate_license_key(
        ...     db_session=session,
        ...     agent_id=UUID("..."),
        ...     key="TMWS-PRO-a1b2c3d4-e5f6-7890-abcd-ef1234567890-A3F9",
        ...     feature_accessed="semantic_search"
        ... )
        >>> if result["valid"]:
        ...     print(f"License tier: {result['tier']}")
    """
    # Call LicenseService.validate_license_key()
    service = LicenseService(db_session=db_session)
    validation_result = await service.validate_license_key(
        key=key, feature_accessed=feature_accessed
    )

    # Format response
    return {
        "valid": validation_result.valid,
        "tier": validation_result.tier.value if validation_result.tier else None,
        "expires_at": (
            validation_result.expires_at.isoformat()
            if validation_result.expires_at
            else None
        ),
        "is_perpetual": validation_result.expires_at is None,
        "agent_id": (
            str(validation_result.license_id) if validation_result.license_id else None
        ),
        "error": validation_result.error_message,
    }


# ============================================================================
# MCP Tool 3: Revoke License Key (ADMIN only)
# ============================================================================


@require_permission("license:revoke")
async def revoke_license_key(
    db_session: AsyncSession,
    agent_id: UUID,  # noqa: ARG001 - Required for RBAC decorator
    license_id: UUID,
    reason: str | None = None,
) -> dict[str, Any]:
    """Revoke a license key, making it unusable.

    Immediately deactivates a license key, preventing any further use.
    This operation is irreversible.

    Args:
        db_session: Database session (required for RBAC)
        agent_id: Agent UUID (required for RBAC)
        license_id: License UUID to revoke
        reason: Optional revocation reason for audit trail
            Examples: "expired_subscription", "policy_violation", "user_request"

    Returns:
        Dictionary containing:
            - success (bool): True if revocation succeeded
            - license_id (str): License UUID that was revoked
            - revoked_at (str): ISO 8601 datetime when license was revoked
            - reason (str | None): Revocation reason if provided

    Raises:
        PermissionError: If caller lacks ADMIN role
        NotFoundError: If license_id does not exist

    Example:
        >>> result = await revoke_license_key(
        ...     db_session=session,
        ...     agent_id=UUID("..."),
        ...     license_id=UUID("550e8400-e29b-41d4-a716-446655440000"),
        ...     reason="expired_subscription"
        ... )
        >>> print(f"Revoked at: {result['revoked_at']}")
    """
    # Call LicenseService.revoke_license_key()
    service = LicenseService(db_session=db_session)
    await service.revoke_license_key(license_id=license_id, reason=reason)

    # Fetch updated license to get revoked_at timestamp
    stmt = select(LicenseKey).where(LicenseKey.id == license_id)
    result = await db_session.execute(stmt)
    db_license = result.scalar_one_or_none()

    if not db_license:
        log_and_raise(
            NotFoundError,
            resource_type="LicenseKey",
            resource_id=str(license_id),
        )

    return {
        "success": True,
        "license_id": str(license_id),
        "revoked_at": db_license.revoked_at.isoformat() if db_license.revoked_at else None,
        "reason": reason,
    }


# ============================================================================
# MCP Tool 4: Get License Usage History (ADMIN or owner)
# ============================================================================


@require_permission("license:usage:read")
async def get_license_usage_history(
    db_session: AsyncSession,
    agent_id: UUID,  # noqa: ARG001 - Required for RBAC decorator
    license_id: UUID,
    limit: int = 100,
    resource_owner_id: UUID | None = None,  # noqa: ARG001 - Required for RBAC ownership check
) -> list[dict[str, Any]]:
    """Get usage history for a license key.

    Retrieves the most recent usage records for a license, including
    which features were accessed and when.

    Args:
        db_session: Database session (required for RBAC)
        agent_id: Agent UUID (required for RBAC)
        license_id: License UUID
        limit: Maximum records to return (default 100, max 1000)
        resource_owner_id: Owner of license (for ownership check)

    Returns:
        List of usage records, each containing:
            - id (str): Usage record UUID
            - used_at (str): ISO 8601 datetime when feature was accessed
            - feature_accessed (str | None): Feature name if recorded
            - usage_metadata (dict | None): Additional usage context

        Ordered by used_at descending (most recent first)

    Raises:
        PermissionError: If caller lacks ADMIN role or is not license owner
        NotFoundError: If license_id does not exist
        ValidationError: If limit is < 1 or > 1000

    Example:
        >>> history = await get_license_usage_history(
        ...     db_session=session,
        ...     agent_id=UUID("..."),
        ...     license_id=UUID("550e8400-e29b-41d4-a716-446655440000"),
        ...     limit=10
        ... )
        >>> for record in history:
        ...     print(f"{record['used_at']}: {record['feature_accessed']}")
    """
    # 1. Validate limit
    if limit < 1 or limit > 1000:
        log_and_raise(
            ValidationError,
            f"limit must be between 1 and 1000 (got: {limit})",
            details={"limit": limit, "min": 1, "max": 1000},
        )

    # 2. Call LicenseService.get_license_usage_history()
    service = LicenseService(db_session=db_session)
    usage_records = await service.get_license_usage_history(
        license_id=license_id, limit=limit
    )

    # 3. Format response
    return [
        {
            "id": str(record.id),
            "used_at": record.used_at.isoformat(),
            "feature_accessed": record.feature_accessed,
            "usage_metadata": record.usage_metadata if hasattr(record, "usage_metadata") else None,
        }
        for record in usage_records
    ]


# ============================================================================
# MCP Tool 5: Get License Info (ADMIN or owner)
# ============================================================================


@require_permission("license:read")
async def get_license_info(
    db_session: AsyncSession,
    agent_id: UUID,  # noqa: ARG001 - Required for RBAC decorator
    license_id: UUID,
    resource_owner_id: UUID | None = None,  # noqa: ARG001 - Required for RBAC ownership check
) -> dict[str, Any]:
    """Get detailed information about a license key.

    Retrieves all metadata about a license, including tier, expiration,
    and revocation status.

    Args:
        db_session: Database session (required for RBAC)
        agent_id: Agent UUID (required for RBAC)
        license_id: License UUID
        resource_owner_id: Owner of license (for ownership check)

    Returns:
        Dictionary containing:
            - id (str): License UUID
            - agent_id (str): Agent UUID that owns this license
            - tier (str): License tier (FREE/PRO/ENTERPRISE)
            - issued_at (str): ISO 8601 datetime when license was issued
            - expires_at (str | None): ISO 8601 expiration datetime
                (None if perpetual)
            - is_active (bool): True if license is currently active
            - revoked_at (str | None): ISO 8601 datetime if license was revoked
            - revoked_reason (str | None): Revocation reason if applicable

    Raises:
        PermissionError: If caller lacks ADMIN role or is not license owner
        NotFoundError: If license_id does not exist

    Example:
        >>> info = await get_license_info(
        ...     db_session=session,
        ...     agent_id=UUID("..."),
        ...     license_id=UUID("550e8400-e29b-41d4-a716-446655440000")
        ... )
        >>> print(f"Tier: {info['tier']}, Active: {info['is_active']}")
    """
    # Fetch license from database
    stmt = select(LicenseKey).where(LicenseKey.id == license_id)
    result = await db_session.execute(stmt)
    db_license = result.scalar_one_or_none()

    if not db_license:
        log_and_raise(
            NotFoundError,
            resource_type="LicenseKey",
            resource_id=str(license_id),
        )

    # Format response
    return {
        "id": str(db_license.id),
        "agent_id": str(db_license.agent_id),
        "tier": db_license.tier.value,
        "issued_at": db_license.issued_at.isoformat(),
        "expires_at": db_license.expires_at.isoformat() if db_license.expires_at else None,
        "is_active": db_license.is_active,
        "revoked_at": db_license.revoked_at.isoformat() if db_license.revoked_at else None,
        "revoked_reason": db_license.revoked_reason if hasattr(db_license, "revoked_reason") else None,
    }
