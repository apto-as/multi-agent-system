"""
License Service - TMWS License Key Management and Validation

This service provides license key generation, validation, and tier-based
feature enforcement for the TMWS system.

Security:
- HMAC-SHA256 signature validation
- Constant-time comparison for timing attack resistance
- Offline-first validation (no network dependency)
- Graceful degradation with helpful error messages

License Key Format:
    TMWS-{TIER}-{UUID}-{CHECKSUM}

    Example:
        TMWS-PRO-550e8400-e29b-41d4-a716-446655440000-a1b2c3d4e5f67890

Tiers:
- FREE: Basic features (6 MCP tools, 60 req/min)
- PRO: Professional features (11 MCP tools, 300 req/min)
- ENTERPRISE: Full features (21 MCP tools, 1000 req/min)

Author: Artemis (Technical Perfectionist)
Created: 2025-11-14
Version: 1.0.0
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.exceptions import (
    ValidationError,
    log_and_raise,
)
from src.models.agent import Agent
from src.models.license_key import LicenseKey, LicenseKeyUsage


class TierEnum(str, Enum):
    """License tier enumeration."""

    FREE = "FREE"
    PRO = "PRO"
    ENTERPRISE = "ENTERPRISE"


class LicenseFeature(str, Enum):
    """Feature flags for tier-based access control."""

    # Core features (FREE+)
    MEMORY_STORE = "memory_store"
    MEMORY_SEARCH = "memory_search"
    TASK_CREATE = "task_create"
    AGENT_STATUS = "agent_status"
    MEMORY_STATS = "memory_stats"
    CACHE_INVALIDATE = "cache_invalidate"

    # Professional features (PRO+)
    EXPIRATION_PRUNE = "expiration_prune"
    EXPIRATION_STATS = "expiration_stats"
    MEMORY_TTL = "memory_ttl"
    NAMESPACE_CLEANUP = "namespace_cleanup"
    NAMESPACE_STATS = "namespace_stats"

    # Enterprise features (ENTERPRISE only)
    SCHEDULER_STATUS = "scheduler_status"
    SCHEDULER_CONFIGURE = "scheduler_configure"
    SCHEDULER_START = "scheduler_start"
    SCHEDULER_STOP = "scheduler_stop"
    SCHEDULER_TRIGGER = "scheduler_trigger"
    VERIFY_AND_RECORD = "verify_and_record"
    TRUST_SCORE = "trust_score"
    VERIFICATION_HISTORY = "verification_history"
    VERIFICATION_STATISTICS = "verification_statistics"
    TRUST_HISTORY = "trust_history"


class TierLimits(BaseModel):
    """Feature limits for a given tier."""

    tier: TierEnum
    max_agents: int = Field(description="Maximum number of agents")
    max_memories_per_agent: int = Field(description="Maximum memories per agent")
    rate_limit_per_minute: int = Field(description="API rate limit per minute")
    features: list[LicenseFeature] = Field(description="Enabled features")
    max_namespace_count: int = Field(description="Maximum number of namespaces")
    support_level: str = Field(description="Support tier (Community/Email/Priority)")


class LicenseValidationResult(BaseModel):
    """Result of license key validation."""

    valid: bool
    tier: Optional[TierEnum] = None
    license_id: Optional[UUID] = None
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    is_expired: bool = False
    is_revoked: bool = False
    error_message: Optional[str] = None
    limits: Optional[TierLimits] = None


class LicenseService:
    """
    License key validation and tier management service.

    Responsibilities:
    - License key format validation (TMWS-{TIER}-{UUID}-{CHECKSUM})
    - Tier detection (FREE, PRO, ENTERPRISE)
    - Expiration checking
    - Usage limit enforcement
    - HMAC-SHA256 signature generation and validation
    """

    def __init__(self, db_session: Optional[AsyncSession] = None):
        """
        Initialize LicenseService.

        Args:
            db_session: Optional database session for license key storage
        """
        self.db_session = db_session
        self.secret_key = settings.secret_key

        # Tier limits configuration
        self._tier_limits = {
            TierEnum.FREE: TierLimits(
                tier=TierEnum.FREE,
                max_agents=10,
                max_memories_per_agent=1000,
                rate_limit_per_minute=60,
                features=[
                    LicenseFeature.MEMORY_STORE,
                    LicenseFeature.MEMORY_SEARCH,
                    LicenseFeature.TASK_CREATE,
                    LicenseFeature.AGENT_STATUS,
                    LicenseFeature.MEMORY_STATS,
                    LicenseFeature.CACHE_INVALIDATE,
                ],
                max_namespace_count=3,
                support_level="Community",
            ),
            TierEnum.PRO: TierLimits(
                tier=TierEnum.PRO,
                max_agents=50,
                max_memories_per_agent=10000,
                rate_limit_per_minute=300,
                features=[
                    # FREE features
                    LicenseFeature.MEMORY_STORE,
                    LicenseFeature.MEMORY_SEARCH,
                    LicenseFeature.TASK_CREATE,
                    LicenseFeature.AGENT_STATUS,
                    LicenseFeature.MEMORY_STATS,
                    LicenseFeature.CACHE_INVALIDATE,
                    # PRO features
                    LicenseFeature.EXPIRATION_PRUNE,
                    LicenseFeature.EXPIRATION_STATS,
                    LicenseFeature.MEMORY_TTL,
                    LicenseFeature.NAMESPACE_CLEANUP,
                    LicenseFeature.NAMESPACE_STATS,
                ],
                max_namespace_count=10,
                support_level="Email",
            ),
            TierEnum.ENTERPRISE: TierLimits(
                tier=TierEnum.ENTERPRISE,
                max_agents=1000,
                max_memories_per_agent=100000,
                rate_limit_per_minute=1000,
                features=[
                    # All features (FREE + PRO + ENTERPRISE)
                    LicenseFeature.MEMORY_STORE,
                    LicenseFeature.MEMORY_SEARCH,
                    LicenseFeature.TASK_CREATE,
                    LicenseFeature.AGENT_STATUS,
                    LicenseFeature.MEMORY_STATS,
                    LicenseFeature.CACHE_INVALIDATE,
                    LicenseFeature.EXPIRATION_PRUNE,
                    LicenseFeature.EXPIRATION_STATS,
                    LicenseFeature.MEMORY_TTL,
                    LicenseFeature.NAMESPACE_CLEANUP,
                    LicenseFeature.NAMESPACE_STATS,
                    LicenseFeature.SCHEDULER_STATUS,
                    LicenseFeature.SCHEDULER_CONFIGURE,
                    LicenseFeature.SCHEDULER_START,
                    LicenseFeature.SCHEDULER_STOP,
                    LicenseFeature.SCHEDULER_TRIGGER,
                    LicenseFeature.VERIFY_AND_RECORD,
                    LicenseFeature.TRUST_SCORE,
                    LicenseFeature.VERIFICATION_HISTORY,
                    LicenseFeature.VERIFICATION_STATISTICS,
                    LicenseFeature.TRUST_HISTORY,
                ],
                max_namespace_count=100,
                support_level="Priority",
            ),
        }

    async def generate_license_key(
        self,
        agent_id: UUID,
        tier: TierEnum,
        expires_days: Optional[int] = None,
        license_id: Optional[UUID] = None,
    ) -> str:
        """
        Generate a new license key with HMAC-SHA256 signature and save to database.

        Args:
            agent_id: Agent UUID to associate license with
            tier: License tier (FREE, PRO, ENTERPRISE)
            expires_days: Days until expiration (None = perpetual)
            license_id: Optional UUID (auto-generated if not provided)

        Returns:
            License key in format: TMWS-{TIER}-{UUID}-{CHECKSUM}

        Raises:
            ValidationError: If database session is not available or agent not found

        Example:
            >>> service = LicenseService(db_session)
            >>> key = await service.generate_license_key(
            ...     agent_id=UUID("..."),
            ...     tier=TierEnum.PRO,
            ...     expires_days=365
            ... )
            >>> print(key)
            TMWS-PRO-550e8400-e29b-41d4-a716-446655440000-a1b2c3d4e5f67890
        """
        # Require database session for license generation
        if not self.db_session:
            log_and_raise(
                ValidationError,
                "Database session required for license key generation",
                details={"agent_id": str(agent_id), "tier": tier.value},
            )

        # Verify agent exists
        # Note: Agent.id is stored as string, so convert UUID to string for query
        stmt = select(Agent).where(Agent.id == str(agent_id))
        result = await self.db_session.execute(stmt)
        agent = result.scalar_one_or_none()

        if agent is None:
            log_and_raise(
                ValidationError,
                f"Agent not found: {agent_id}",
                details={"agent_id": str(agent_id)},
            )

        # Generate or use provided UUID
        if license_id is None:
            license_id = uuid4()

        # Calculate expiration date (None for perpetual)
        now = datetime.now(timezone.utc)
        if expires_days is None:
            expiry_date = None
            expiry_timestamp = "PERPETUAL"
        else:
            expiry_date = now + timedelta(days=expires_days)
            expiry_timestamp = str(int(expiry_date.timestamp()))

        # Create signature data: {tier}:{uuid}:{expiry}
        signature_data = f"{tier.value}:{license_id}:{expiry_timestamp}"

        # Generate HMAC-SHA256 signature
        signature = hmac.new(
            self.secret_key.encode(), signature_data.encode(), hashlib.sha256
        ).hexdigest()

        # Take first 16 characters of signature for checksum
        checksum = signature[:16]

        # Assemble license key
        license_key = f"TMWS-{tier.value}-{license_id}-{checksum}"

        # Store license key in database
        try:
            db_license = LicenseKey(
                id=license_id,
                agent_id=agent_id,
                tier=tier,
                license_key_hash=hashlib.sha256(license_key.encode()).hexdigest(),
                issued_at=now,
                expires_at=expiry_date,
                is_active=True,
            )
            self.db_session.add(db_license)
            agent.tier = tier.value
            await self.db_session.commit()
            await self.db_session.refresh(db_license)

        except Exception as e:
            await self.db_session.rollback()
            log_and_raise(
                ValidationError,
                f"Failed to create license key in database: {e!s}",
                original_exception=e,
                details={
                    "agent_id": str(agent_id),
                    "tier": tier.value,
                    "license_id": str(license_id),
                },
            )

        return license_key

    async def validate_license_key(
        self, key: str, feature_accessed: Optional[str] = None
    ) -> LicenseValidationResult:
        """
        Validate a license key format and checksum, and record usage.

        Security:
        - Constant-time comparison for checksum (timing attack resistance)
        - HMAC-SHA256 signature validation
        - Expiration checking with timezone awareness
        - Usage tracking in database

        Args:
            key: License key to validate
            feature_accessed: Optional feature name being accessed (for usage tracking)

        Returns:
            LicenseValidationResult with validation details

        Example:
            >>> result = await service.validate_license_key(
            ...     license_key,
            ...     feature_accessed="memory_store"
            ... )
            >>> if result.valid:
            >>>     print(f"Valid {result.tier} license")
            >>> else:
            >>>     print(f"Invalid: {result.error_message}")
        """
        # Parse license key format
        # Format: TMWS-{TIER}-{UUID}-{CHECKSUM}
        # UUID contains 4 hyphens, so we need to use rsplit to get checksum from right
        if not key.startswith("TMWS-"):
            return LicenseValidationResult(
                valid=False, error_message="Invalid license key format"
            )

        # Split from right: [TMWS-TIER-UUID, CHECKSUM]
        parts = key.rsplit("-", 1)
        if len(parts) != 2:
            return LicenseValidationResult(
                valid=False, error_message="Invalid license key format"
            )

        prefix, checksum = parts[0], parts[1]

        # Now split prefix: [TMWS, TIER, UUID_PART1, UUID_PART2, UUID_PART3, UUID_PART4, UUID_PART5]
        # UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (5 parts)
        # So total parts should be: TMWS + TIER + 5 UUID parts = 7 parts
        prefix_parts = prefix.split("-")
        if len(prefix_parts) != 7:  # TMWS + TIER + UUID (5 parts)
            return LicenseValidationResult(
                valid=False, error_message="Invalid license key format"
            )

        # Extract tier and UUID
        tier_str = prefix_parts[1]
        uuid_str = "-".join(prefix_parts[2:7])  # Reconstruct UUID

        # Validate tier
        try:
            tier = TierEnum(tier_str)
        except ValueError:
            return LicenseValidationResult(
                valid=False, error_message=f"Invalid tier: {tier_str}"
            )

        # Validate UUID
        try:
            license_id = UUID(uuid_str)
        except ValueError:
            return LicenseValidationResult(
                valid=False, error_message=f"Invalid UUID: {uuid_str}"
            )

        # Fetch license from database (if available)
        if self.db_session:
            try:
                from src.models.license_key import LicenseKey  # Avoid circular import

                stmt = select(LicenseKey).where(LicenseKey.id == license_id)
                result = await self.db_session.execute(stmt)
                db_license = result.scalar_one_or_none()

                if db_license is None:
                    return LicenseValidationResult(
                        valid=False, error_message="License key not found in database"
                    )

                # Check if revoked
                if db_license.revoked:
                    return LicenseValidationResult(
                        valid=False,
                        is_revoked=True,
                        error_message="License key has been revoked",
                    )

                # Get expiration from DB
                expires_at = db_license.expires_at
                issued_at = db_license.issued_at

            except Exception:
                # Database check failed, continue with checksum validation
                expires_at = None
                issued_at = None
        else:
            # No database session, use checksum-only validation
            expires_at = None
            issued_at = None

        # Reconstruct signature data
        # Note: We need to determine if this is a perpetual license
        # For checksum validation, we'll try both possibilities

        # Try PERPETUAL first
        signature_data_perpetual = f"{tier.value}:{license_id}:PERPETUAL"
        expected_signature_perpetual = hmac.new(
            self.secret_key.encode(),
            signature_data_perpetual.encode(),
            hashlib.sha256,
        ).hexdigest()[:16]

        # Constant-time comparison for timing attack resistance
        is_valid_perpetual = hmac.compare_digest(checksum, expected_signature_perpetual)

        if is_valid_perpetual:
            # Record usage in database (if session available)
            if self.db_session:
                try:
                    usage = LicenseKeyUsage(
                        license_key_id=license_id,
                        used_at=datetime.now(timezone.utc),
                        feature_accessed=feature_accessed,
                    )
                    self.db_session.add(usage)
                    await self.db_session.commit()
                except Exception:
                    # Log usage recording failure but don't fail validation
                    await self.db_session.rollback()
                    # Continue with validation result

            # Valid perpetual license
            return LicenseValidationResult(
                valid=True,
                tier=tier,
                license_id=license_id,
                issued_at=issued_at,
                expires_at=None,
                is_expired=False,
                is_revoked=False,
                limits=self._tier_limits[tier],
            )

        # If not perpetual, try to validate with expiration timestamp
        # Without DB, we can't know the expiration, so we reject non-perpetual keys
        # when DB is unavailable
        if expires_at:
            expiry_timestamp = str(int(expires_at.timestamp()))
            signature_data_expiry = f"{tier.value}:{license_id}:{expiry_timestamp}"
            expected_signature_expiry = hmac.new(
                self.secret_key.encode(),
                signature_data_expiry.encode(),
                hashlib.sha256,
            ).hexdigest()[:16]

            is_valid_expiry = hmac.compare_digest(checksum, expected_signature_expiry)

            if is_valid_expiry:
                # Valid time-limited license
                now = datetime.now(timezone.utc)
                is_expired = expires_at < now

                # Record usage in database (only if not expired and session available)
                if not is_expired and self.db_session:
                    try:
                        usage = LicenseKeyUsage(
                            license_key_id=license_id,
                            used_at=now,
                            feature_accessed=feature_accessed,
                        )
                        self.db_session.add(usage)
                        await self.db_session.commit()
                    except Exception:
                        # Log usage recording failure but don't fail validation
                        await self.db_session.rollback()
                        # Continue with validation result

                return LicenseValidationResult(
                    valid=not is_expired,
                    tier=tier,
                    license_id=license_id,
                    issued_at=issued_at,
                    expires_at=expires_at,
                    is_expired=is_expired,
                    is_revoked=False,
                    error_message="License has expired" if is_expired else None,
                    limits=self._tier_limits[tier],
                )

        # Invalid checksum
        return LicenseValidationResult(
            valid=False, error_message="Invalid checksum (signature mismatch)"
        )

    def get_tier_limits(self, tier: TierEnum) -> TierLimits:
        """
        Get feature limits for a given tier.

        Args:
            tier: License tier

        Returns:
            TierLimits configuration

        Example:
            >>> limits = service.get_tier_limits(TierEnum.PRO)
            >>> print(f"Rate limit: {limits.rate_limit_per_minute} req/min")
            >>> print(f"Features: {len(limits.features)}")
        """
        return self._tier_limits[tier]

    def is_feature_enabled(self, tier: TierEnum, feature: LicenseFeature) -> bool:
        """
        Check if a feature is enabled for a given tier.

        Args:
            tier: License tier
            feature: Feature to check

        Returns:
            True if feature is enabled for this tier

        Example:
            >>> if service.is_feature_enabled(TierEnum.FREE, LicenseFeature.SCHEDULER_START):
            >>>     print("Scheduler available")
            >>> else:
            >>>     print("Upgrade to ENTERPRISE for scheduler features")
        """
        limits = self._tier_limits[tier]
        return feature in limits.features

    async def get_agent_tier(self, agent_id: UUID) -> TierEnum:
        """
        Get the license tier for a specific agent.

        Args:
            agent_id: Agent UUID

        Returns:
            TierEnum (defaults to FREE if no license found)

        Raises:
            ValidationError: If database session is not available
        """
        if not self.db_session:
            log_and_raise(
                ValidationError,
                "Database session required for agent tier lookup",
                details={"agent_id": str(agent_id)},
            )

        # Fetch agent from database
        # Note: Agent.id is stored as string, so convert UUID to string for query
        stmt = select(Agent).where(Agent.id == str(agent_id))
        result = await self.db_session.execute(stmt)
        agent = result.scalar_one_or_none()

        if agent is None:
            log_and_raise(
                ValidationError,
                f"Agent not found: {agent_id}",
                details={"agent_id": str(agent_id)},
            )

        # Return agent's tier (default to FREE if not set)
        return TierEnum(agent.tier) if hasattr(agent, "tier") else TierEnum.FREE

    async def check_feature_access(
        self, agent_id: UUID, feature: LicenseFeature
    ) -> bool:
        """
        Check if an agent has access to a specific feature.

        Args:
            agent_id: Agent UUID
            feature: Feature to check

        Returns:
            True if agent's tier allows this feature

        Example:
            >>> has_access = await service.check_feature_access(
            >>>     agent_id,
            >>>     LicenseFeature.SCHEDULER_START
            >>> )
            >>> if not has_access:
            >>>     raise HTTPException(403, "Feature requires ENTERPRISE tier")
        """
        tier = await self.get_agent_tier(agent_id)
        return self.is_feature_enabled(tier, feature)

    async def generate_trial_key(
        self, agent_id: UUID, tier: TierEnum = TierEnum.PRO
    ) -> str:
        """
        Generate a 30-day trial license key and save to database.

        Args:
            agent_id: Agent UUID to associate license with
            tier: Trial tier (default: PRO)

        Returns:
            30-day trial license key

        Raises:
            ValidationError: If database session is not available or agent not found

        Example:
            >>> trial_key = await service.generate_trial_key(UUID("..."), TierEnum.PRO)
            >>> print(f"Your 30-day trial: {trial_key}")
        """
        return await self.generate_license_key(agent_id, tier, expires_days=30)

    async def generate_perpetual_key(self, agent_id: UUID, tier: TierEnum) -> str:
        """
        Generate a perpetual (never expires) license key and save to database.

        Args:
            agent_id: Agent UUID to associate license with
            tier: License tier

        Returns:
            Perpetual license key

        Raises:
            ValidationError: If database session is not available or agent not found

        Example:
            >>> perpetual_key = await service.generate_perpetual_key(
            ...     UUID("..."),
            ...     TierEnum.ENTERPRISE
            ... )
            >>> print(f"Perpetual license: {perpetual_key}")
        """
        return await self.generate_license_key(agent_id, tier, expires_days=None)

    async def revoke_license_key(
        self, license_id: UUID, reason: Optional[str] = None
    ) -> bool:
        """
        Revoke a license key, making it unusable.

        Args:
            license_id: License key UUID to revoke
            reason: Optional reason for revocation

        Returns:
            True if license was successfully revoked

        Raises:
            ValidationError: If database session is not available or license not found

        Example:
            >>> await service.revoke_license_key(
            ...     UUID("..."),
            ...     reason="License key compromised"
            ... )
        """
        if not self.db_session:
            log_and_raise(
                ValidationError,
                "Database session required for license key revocation",
                details={"license_id": str(license_id)},
            )

        # Fetch license from database
        stmt = select(LicenseKey).where(LicenseKey.id == license_id)
        result = await self.db_session.execute(stmt)
        db_license = result.scalar_one_or_none()

        if db_license is None:
            log_and_raise(
                ValidationError,
                f"License key not found: {license_id}",
                details={"license_id": str(license_id)},
            )

        # Revoke license
        try:
            db_license.revoke(reason)
            await self.db_session.commit()
            return True
        except Exception as e:
            await self.db_session.rollback()
            log_and_raise(
                ValidationError,
                f"Failed to revoke license key: {e!s}",
                original_exception=e,
                details={"license_id": str(license_id)},
            )

    async def get_license_usage_history(
        self, license_id: UUID, limit: int = 100
    ) -> list[LicenseKeyUsage]:
        """
        Get usage history for a license key.

        Args:
            license_id: License key UUID
            limit: Maximum number of records to return (default: 100)

        Returns:
            List of LicenseKeyUsage records, ordered by used_at DESC

        Raises:
            ValidationError: If database session is not available

        Example:
            >>> usage_history = await service.get_license_usage_history(UUID("..."))
            >>> for usage in usage_history:
            ...     print(f"{usage.used_at}: {usage.feature_accessed}")
        """
        if not self.db_session:
            log_and_raise(
                ValidationError,
                "Database session required for license usage history",
                details={"license_id": str(license_id)},
            )

        # Fetch usage records from database
        stmt = (
            select(LicenseKeyUsage)
            .where(LicenseKeyUsage.license_key_id == license_id)
            .order_by(LicenseKeyUsage.used_at.desc())
            .limit(limit)
        )
        result = await self.db_session.execute(stmt)
        return list(result.scalars().all())
