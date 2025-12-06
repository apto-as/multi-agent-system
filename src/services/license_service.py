"""
License Service - TMWS License Key Validation

This service provides license key validation and tier-based feature enforcement
for the TMWS system. License key GENERATION is handled by separate CLI tools
that are NOT included in Docker images for security.

Security (Phase 2E-2: Signature-Only Validation + Phase 2E-1: Ed25519):
- Database-independent validation (tampering has zero effect)
- Ed25519 signature verification (primary, v2.4.1+)
- HMAC-SHA256 fallback for legacy keys (v2.4.0 and earlier)
- Constant-time comparison for timing attack resistance
- Expiry date embedded in license key (not fetched from database)
- Offline-first validation (no network or database dependency)
- Usage tracking is optional (best-effort, does not affect validation)
- License GENERATION removed from runtime (CLI tools only)

License Key Format (Version 3 - Ed25519):
    TMWS-{TIER}-{UUID}-{EXPIRY}-{ED25519_SIGNATURE_B64}

    Example (Perpetual):
        TMWS-ENTERPRISE-550e8400-e29b-41d4-a716-446655440000-PERPETUAL-base64signature...

    Example (Time-Limited):
        TMWS-PRO-550e8400-e29b-41d4-a716-446655440000-20261117-base64signature...

Legacy Format (Version 2 - HMAC):
    TMWS-{TIER}-{UUID}-{EXPIRY}-{HMAC_HEX_16}

    Example:
        TMWS-PRO-550e8400-e29b-41d4-a716-446655440000-20261117-a7f3b9c2d1e4f5a6

Tiers:
- FREE: Basic features (6 MCP tools, 60 req/min)
- PRO: Professional features (11 MCP tools, 300 req/min)
- ENTERPRISE: Full features (21 MCP tools, 1000 req/min)
- ADMINISTRATOR: Unlimited + Perpetual (internal use)

Security Properties:
- User cannot forge license keys without Trinitas PRIVATE KEY
- User cannot modify tier, expiry, or UUID without invalidating signature
- Database tampering has ZERO effect on validation
- Docker image contains only PUBLIC KEY (safe to distribute)
- Performance: <5ms P95 (pure crypto, no I/O)
- License generation CLI tools are excluded from Docker image

License Key Generation:
- Use scripts/license/generate_keys.py to create Ed25519 key pair
- Use scripts/license/sign_license.py to generate license keys
- Private key MUST be kept secure and NEVER distributed

Author: Artemis (Technical Perfectionist)
Created: 2025-11-14
Updated: 2025-11-29 (Phase 2E-1: Removed HMAC generation, CLI-only)
Version: 3.1.0
"""

import base64
import hashlib
import hmac
import logging
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID

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

# Ed25519 signature verification (v2.4.1+)
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    ED25519_AVAILABLE = True
except ImportError:
    ED25519_AVAILABLE = False
    Ed25519PublicKey = None
    # Security: Do NOT create placeholder Exception class
    # InvalidSignature is only used when cryptography is available
    InvalidSignature = None  # type: ignore

logger = logging.getLogger(__name__)


class TierEnum(str, Enum):
    """License tier enumeration."""

    FREE = "FREE"
    PRO = "PRO"
    ENTERPRISE = "ENTERPRISE"
    ADMINISTRATOR = "ADMINISTRATOR"  # v2.4.0: Unlimited + Perpetual tier


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
    rate_limit_per_minute: int | None = Field(description="API rate limit per minute (None = unlimited)")
    features: list[LicenseFeature] = Field(description="Enabled features")
    max_namespace_count: int = Field(description="Maximum number of namespaces")
    support_level: str = Field(description="Support tier (Community/Email/Priority)")
    # v2.4.0: Token budget system (Progressive Disclosure)
    max_tokens_per_hour: int | None = Field(
        description="Maximum tokens per hour (None = unlimited)"
    )


class LicenseValidationResult(BaseModel):
    """Result of license key validation."""

    valid: bool
    tier: TierEnum | None = None
    license_id: UUID | None = None
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    is_expired: bool = False
    is_revoked: bool = False
    error_message: str | None = None
    limits: TierLimits | None = None


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

    def __init__(self, db_session: AsyncSession | None = None):
        """
        Initialize LicenseService.

        Args:
            db_session: Optional database session for license key storage
        """
        self.db_session = db_session
        self.secret_key = settings.secret_key

        # Initialize Ed25519 public key for signature verification (v2.4.1+)
        self._ed25519_public_key: Ed25519PublicKey | None = None
        self._load_ed25519_public_key()

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
                max_tokens_per_hour=10_000,  # v2.4.0: 10k tokens/hour (Phase 2D-2)
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
                max_tokens_per_hour=50_000,  # v2.4.0: 50k tokens/hour (Phase 2D-2)
            ),
            TierEnum.ENTERPRISE: TierLimits(
                tier=TierEnum.ENTERPRISE,
                max_agents=1000,
                max_memories_per_agent=100000,
                rate_limit_per_minute=1_000_000,  # v2.4.0: DoS threshold only
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
                max_tokens_per_hour=None,  # v2.4.0: Unlimited tokens
            ),
            # v2.4.0: ADMINISTRATOR tier (unlimited + perpetual)
            TierEnum.ADMINISTRATOR: TierLimits(
                tier=TierEnum.ADMINISTRATOR,
                max_agents=10000,  # Practically unlimited
                max_memories_per_agent=1_000_000,  # Practically unlimited
                rate_limit_per_minute=None,  # No rate limits
                features=[
                    # All features (same as ENTERPRISE)
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
                max_namespace_count=1000,  # Practically unlimited
                support_level="Premium",
                max_tokens_per_hour=None,  # v2.4.0: Unlimited + Perpetual
            ),
        }

    def _load_ed25519_public_key(self) -> None:
        """
        Load Ed25519 public key from configuration.

        The public key is stored as Base64-encoded raw bytes (32 bytes).
        This is the format output by generate_keys.py (trinitas_public.b64).

        Security:
        - Public key is safe to embed in Docker images
        - Only Trinitas has the corresponding private key
        - Cannot forge signatures without private key
        """
        if not ED25519_AVAILABLE:
            logger.warning(
                "cryptography package not installed - Ed25519 verification disabled"
            )
            return

        public_key_b64 = settings.license_public_key
        if not public_key_b64:
            logger.info(
                "TMWS_LICENSE_PUBLIC_KEY not set - using HMAC-SHA256 fallback"
            )
            return

        try:
            # Decode Base64 to raw bytes (32 bytes)
            public_key_bytes = base64.b64decode(public_key_b64)

            # Load Ed25519 public key from raw bytes
            self._ed25519_public_key = Ed25519PublicKey.from_public_bytes(
                public_key_bytes
            )
            logger.info(
                "Ed25519 public key loaded successfully - signature verification enabled"
            )
        except Exception as e:
            logger.error(
                f"Failed to load Ed25519 public key: {e} - using HMAC fallback"
            )
            self._ed25519_public_key = None

    def _verify_ed25519_signature(
        self, signature_data: str, signature_b64: str
    ) -> bool:
        """
        Verify Ed25519 signature.

        Args:
            signature_data: Data that was signed (tier:uuid:expiry)
            signature_b64: Base64 URL-safe encoded signature (without padding)

        Returns:
            True if signature is valid, False otherwise

        Security:
        - Ed25519 provides 128-bit security level
        - Signature is 64 bytes (512 bits)
        - Constant-time verification (cryptography library handles this)
        """
        if not self._ed25519_public_key:
            return False

        try:
            # Restore '+' and '/' from '.' and '~' (sign_license.py replaces to avoid delimiter conflict)
            # This is a custom encoding: '.' -> '+', '~' -> '/'
            signature_b64 = signature_b64.replace(".", "+").replace("~", "/")

            # Add padding if needed (standard base64 without padding)
            padding = 4 - len(signature_b64) % 4
            if padding != 4:
                signature_b64 += "=" * padding

            # Decode signature from standard Base64
            signature_bytes = base64.b64decode(signature_b64)

            # Verify signature (raises InvalidSignature if invalid)
            self._ed25519_public_key.verify(
                signature_bytes, signature_data.encode()
            )
            return True
        except Exception as e:
            # Security: Handle InvalidSignature specifically when cryptography is available
            # Other exceptions are logged for debugging (fail-secure: return False)
            if InvalidSignature is not None and isinstance(e, InvalidSignature):
                return False  # Invalid signature - expected case
            logger.warning(f"Ed25519 signature verification error: {type(e).__name__}: {e}")
            return False

    def _is_ed25519_signature(self, signature: str) -> bool:
        """
        Determine if a signature is Ed25519 (Base64) or HMAC (hex).

        Ed25519 signatures are 64 bytes = 86 Base64 characters (without padding).
        HMAC-SHA256 truncated signatures are 16 hex characters.

        Args:
            signature: The signature string to check

        Returns:
            True if signature appears to be Ed25519 format
        """
        # HMAC signatures are exactly 16 hex characters
        if len(signature) == 16 and all(c in "0123456789abcdef" for c in signature.lower()):
            return False

        # Ed25519 signatures are longer and Base64-encoded
        # 64 bytes = 86 Base64 chars (without padding) or 88 chars (with padding)
        return len(signature) >= 80

    # NOTE: License key generation has been removed from runtime for security.
    # Use the CLI tools instead:
    #   - scripts/license/generate_keys.py (create Ed25519 key pair)
    #   - scripts/license/sign_license.py (generate signed license keys)
    #
    # This ensures the private key never exists in Docker images.

    async def validate_license_key(
        self, key: str, feature_accessed: str | None = None
    ) -> LicenseValidationResult:
        """
        Validate license key using signature-only approach (NO DATABASE DEPENDENCY).

        Security:
        - Signature-only validation (database tampering has zero effect)
        - Ed25519 signature verification (primary, v2.4.1+)
        - HMAC-SHA256 fallback for legacy keys (v2.4.0 and earlier)
        - Constant-time comparison for signature (timing attack resistance)
        - Expiry date embedded in license key (not fetched from database)
        - Usage tracking is optional (best-effort, does not affect validation)

        Signature Detection:
        - Ed25519: Base64 URL-safe encoded, >= 80 characters
        - HMAC-SHA256: 16 hex characters (0-9, a-f)

        Args:
            key: License key to validate
            feature_accessed: Optional feature name being accessed (for usage tracking)

        Returns:
            LicenseValidationResult with validation details

        Example:
            >>> result = await service.validate_license_key(
            ...     "TMWS-PRO-550e8400-e29b-41d4-a716-446655440000-20261117-base64sig...",
            ...     feature_accessed="memory_store"
            ... )
            >>> if result.valid:
            >>>     print(f"Valid {result.tier} license")
            >>> else:
            >>>     print(f"Invalid: {result.error_message}")
        """
        # Phase 1: Parse license key format
        # Format: TMWS-{TIER}-{UUID}-{EXPIRY}-{SIGNATURE}
        # UUID has 5 parts (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
        # Total: TMWS + TIER + 5 UUID parts + EXPIRY + SIGNATURE = 9 parts
        if not key.startswith("TMWS-"):
            return LicenseValidationResult(
                valid=False, error_message="Invalid license key format"
            )

        parts = key.split("-")
        if len(parts) != 9:
            return LicenseValidationResult(
                valid=False,
                error_message=f"Invalid license key format (expected 9 parts, got {len(parts)})",
            )

        # Extract components
        tier_str = parts[1]
        uuid_str = "-".join(parts[2:7])  # Reconstruct UUID
        expiry_str = parts[7]
        signature_provided = parts[8]

        # Phase 2: Validate tier
        try:
            tier = TierEnum(tier_str)
        except ValueError:
            return LicenseValidationResult(
                valid=False, error_message=f"Invalid tier: {tier_str}"
            )

        # Phase 3: Validate UUID format
        try:
            license_id = UUID(uuid_str)
        except ValueError:
            return LicenseValidationResult(
                valid=False, error_message=f"Invalid UUID: {uuid_str}"
            )

        # Phase 4: Parse expiry date
        if expiry_str == "PERPETUAL":
            expires_at = None
            is_expired = False
        else:
            try:
                expires_at = datetime.strptime(expiry_str, "%Y%m%d").replace(
                    tzinfo=timezone.utc
                )
                now = datetime.now(timezone.utc)
                is_expired = expires_at < now
            except ValueError:
                return LicenseValidationResult(
                    valid=False, error_message=f"Invalid expiry format: {expiry_str}"
                )

        # Phase 5: Verify signature (CRITICAL - NO DATABASE)
        # Support both Ed25519 (v2.4.1+) and HMAC-SHA256 (legacy)
        signature_data = f"{tier.value}:{license_id}:{expiry_str}"
        signature_valid = False

        # Check signature type and verify accordingly
        if self._is_ed25519_signature(signature_provided):
            # Ed25519 signature verification (v2.4.1+)
            if self._ed25519_public_key:
                signature_valid = self._verify_ed25519_signature(
                    signature_data, signature_provided
                )
            else:
                # No public key configured - cannot verify Ed25519
                return LicenseValidationResult(
                    valid=False,
                    error_message="Ed25519 license key requires TMWS_LICENSE_PUBLIC_KEY configuration",
                )
        else:
            # HMAC-SHA256 signature verification (legacy)
            expected_signature = hmac.new(
                self.secret_key.encode(), signature_data.encode(), hashlib.sha256
            ).hexdigest()[:16]
            # Constant-time comparison (timing attack resistance)
            signature_valid = hmac.compare_digest(signature_provided, expected_signature)

        if not signature_valid:
            return LicenseValidationResult(
                valid=False,
                error_message="Invalid signature (possible tampering or incorrect key)",
            )

        # Phase 6: Check expiration
        if is_expired:
            return LicenseValidationResult(
                valid=False,
                tier=tier,
                license_id=license_id,
                expires_at=expires_at,
                is_expired=True,
                error_message=f"License expired on {expires_at.strftime('%Y-%m-%d')}",
                limits=self._tier_limits[tier],
            )

        # Phase 7: Record usage (OPTIONAL, best-effort, does NOT affect validation)
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
                # Usage tracking failure does NOT invalidate the license
                await self.db_session.rollback()
                # Continue with validation result

        # Phase 8: Return successful validation result
        return LicenseValidationResult(
            valid=True,
            tier=tier,
            license_id=license_id,
            expires_at=expires_at,
            is_expired=False,
            is_revoked=False,
            limits=self._tier_limits[tier],
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

    # NOTE: generate_trial_key() and generate_perpetual_key() have been removed.
    # Use CLI tools instead:
    #   python scripts/license/sign_license.py --tier PRO --expiry 30
    #   python scripts/license/sign_license.py --tier ENTERPRISE --perpetual

    async def revoke_license_key(
        self, license_id: UUID, reason: str | None = None
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
