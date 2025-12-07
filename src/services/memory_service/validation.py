"""Memory Validation - TTL and access level validation functions.

This module contains pure validation functions for memory TTL and access levels.
All functions are stateless and have no external dependencies.

Security Patterns Implemented:
- V-TTL-1: TTL range validation (1-3650 days)
- V-TTL-2: Access-level based TTL limits
- V-TTL-3: Input type validation
"""

import logging

from src.core.exceptions import ValidationError, log_and_raise
from src.models.agent import AccessLevel

logger = logging.getLogger(__name__)

# Access level TTL constraints (Phase 1B security policy)
ACCESS_LEVEL_TTL_LIMITS = {
    AccessLevel.PRIVATE: {"min_days": 1, "max_days": 3650},  # Full range
    AccessLevel.TEAM: {"min_days": 1, "max_days": 365},  # Max 1 year for team
    AccessLevel.SHARED: {"min_days": 1, "max_days": 90},  # Max 90 days for shared
    AccessLevel.PUBLIC: {"min_days": 1, "max_days": 30},  # Max 30 days for public
    AccessLevel.SYSTEM: {"min_days": 1, "max_days": 3650},  # Full range for system
}


def validate_ttl_days(ttl_days: int | None) -> None:
    """Validate TTL days parameter (V-TTL-1, V-TTL-3).

    Security Checks:
    - V-TTL-3: Type validation (must be int or None)
    - V-TTL-1: Range validation (1-3650 days)

    Args:
        ttl_days: TTL in days (1-3650) or None for permanent

    Raises:
        ValidationError: If ttl_days is invalid type or out of range
    """
    # V-TTL-3: Type validation
    if ttl_days is not None and not isinstance(ttl_days, int):
        log_and_raise(
            ValidationError,
            f"ttl_days must be an integer or None, got {type(ttl_days).__name__}",
            details={
                "ttl_days": ttl_days,
                "type": type(ttl_days).__name__,
                "security_check": "V-TTL-3",
            },
        )

    # V-TTL-1: Range validation
    if ttl_days is not None:
        if ttl_days < 1:
            log_and_raise(
                ValidationError,
                f"ttl_days must be at least 1, got {ttl_days}",
                details={
                    "ttl_days": ttl_days,
                    "min_allowed": 1,
                    "security_check": "V-TTL-1",
                },
            )

        if ttl_days > 3650:  # 10 years max
            log_and_raise(
                ValidationError,
                f"ttl_days must be at most 3650 (10 years), got {ttl_days}",
                details={
                    "ttl_days": ttl_days,
                    "max_allowed": 3650,
                    "security_check": "V-TTL-1",
                },
            )


def validate_access_level_ttl_limit(
    access_level: AccessLevel,
    ttl_days: int | None,
) -> None:
    """Validate TTL against access level constraints (V-TTL-2).

    Phase 1B Security Policy:
    - PRIVATE: Full range (1-3650 days)
    - TEAM: Max 1 year (365 days)
    - SHARED: Max 90 days
    - PUBLIC: Max 30 days
    - SYSTEM: Full range (1-3650 days)

    Args:
        access_level: Memory access level
        ttl_days: TTL in days or None for permanent

    Raises:
        ValidationError: If TTL exceeds access level limit
    """
    # None (permanent) is allowed for all access levels
    if ttl_days is None:
        return

    # Get TTL limits for this access level
    limits = ACCESS_LEVEL_TTL_LIMITS.get(access_level)
    if limits is None:
        # Unknown access level - use most restrictive limit
        logger.warning(
            f"Unknown access level {access_level}, using most restrictive TTL limit"
        )
        limits = {"min_days": 1, "max_days": 30}

    max_days = limits["max_days"]

    # V-TTL-2: Access level TTL limit enforcement
    if ttl_days > max_days:
        log_and_raise(
            ValidationError,
            f"TTL {ttl_days} days exceeds limit for {access_level.value} access level "
            f"(max: {max_days} days)",
            details={
                "ttl_days": ttl_days,
                "access_level": access_level.value,
                "max_allowed": max_days,
                "security_check": "V-TTL-2",
                "suggestion": f"Use ttl_days <= {max_days} for {access_level.value} memories",
            },
        )

    logger.debug(
        f"TTL validation passed: {ttl_days} days for {access_level.value} "
        f"(max: {max_days})"
    )
