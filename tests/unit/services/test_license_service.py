"""
Unit Tests for License Service

Coverage:
- License key validation (valid, invalid, expired, revoked)
- Tier limits and feature access control
- Database integration (license persistence, usage tracking)
- Edge cases and error handling

NOTE: License key generation tests were removed in Phase 2E-1 (2025-11-15)
      for security hardening. License generation is now CLI-only via
      scripts/license/sign_license.py

Target:
- >90% code coverage for validation operations
- <5ms validation performance

Author: Artemis (Technical Perfectionist)
Created: 2025-11-14
Updated: 2025-11-15 (DB integration)
Updated: 2025-12-10 (Removed obsolete generation tests - Phase 2E-1)
"""

import time
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import ValidationError
from src.models.agent import Agent
from src.services.license_service import (
    LicenseFeature,
    LicenseService,
    TierEnum,
)


@pytest.fixture
async def test_agent(db_session: AsyncSession) -> Agent:
    """Create a test agent in the database."""
    agent = Agent(
        agent_id="test-agent",
        display_name="Test Agent",
        capabilities={"features": ["memory_store", "task_create"]},
        namespace="test-namespace",
        tier="FREE",  # Default tier
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest.fixture
def license_service(db_session: AsyncSession) -> LicenseService:
    """Create LicenseService with database session."""
    return LicenseService(db_session=db_session)


# NOTE: TestLicenseKeyGeneration class was removed in Phase 2E-1 (2025-11-15)
# License key generation (generate_license_key, generate_trial_key, generate_perpetual_key)
# was removed from LicenseService for security hardening.
# License generation is now CLI-only: scripts/license/sign_license.py


class TestLicenseKeyValidation:
    """Test suite for license key validation.

    NOTE: Tests requiring dynamic license generation were removed in Phase 2E-1.
    License generation is now CLI-only (scripts/license/sign_license.py).
    These tests use static invalid keys to verify validation logic.
    """

    # NOTE: test_validate_perpetual_key_success was removed - depends on generate_perpetual_key

    @pytest.mark.asyncio
    async def test_validate_invalid_format(self, license_service: LicenseService):
        """Test validation of invalid format license key."""
        invalid_key = "INVALID-KEY-FORMAT"

        result = await license_service.validate_license_key(invalid_key)

        assert result.valid is False
        assert "Invalid license key format" in result.error_message

    @pytest.mark.asyncio
    async def test_validate_invalid_tier(self, license_service: LicenseService):
        """Test validation of license key with invalid tier (9-part format)."""
        # Format: TMWS-{TIER}-{UUID 5parts}-{EXPIRY}-{SIGNATURE}
        invalid_key = "TMWS-INVALID-550e8400-e29b-41d4-a716-446655440000-20261117-abcd1234"

        result = await license_service.validate_license_key(invalid_key)

        assert result.valid is False
        assert "Invalid tier" in result.error_message

    @pytest.mark.asyncio
    async def test_validate_invalid_uuid(self, license_service: LicenseService):
        """Test validation of license key with invalid UUID (9-part format)."""
        # Create a key with malformed UUID (valid format but invalid UUID)
        invalid_key = "TMWS-PRO-invalid-xxxx-xxxx-xxxx-xxxxxxxxxxxx-20261117-abcd1234567890ab"

        result = await license_service.validate_license_key(invalid_key)

        assert result.valid is False
        assert "Invalid UUID" in result.error_message

    @pytest.mark.asyncio
    async def test_validate_invalid_checksum(self, license_service: LicenseService):
        """Test validation of license key with invalid checksum (9-part format)."""
        # Create a key with valid format but invalid signature
        invalid_key = "TMWS-PRO-550e8400-e29b-41d4-a716-446655440000-20261117-0000000000000000"

        result = await license_service.validate_license_key(invalid_key)

        assert result.valid is False
        # Signature validation fails
        assert result.error_message is not None

    @pytest.mark.asyncio
    async def test_validate_performance(self, license_service: LicenseService):
        """Test that validation completes in <5ms (even for invalid keys)."""
        # Use an invalid key for performance testing (doesn't need generation)
        invalid_key = "TMWS-PRO-550e8400-e29b-41d4-a716-446655440000-20261117-abcd123456789012"

        # Warm-up run
        await license_service.validate_license_key(invalid_key)

        # Measure performance
        start = time.perf_counter()
        for _ in range(100):
            await license_service.validate_license_key(invalid_key)
        end = time.perf_counter()

        avg_time_ms = ((end - start) / 100) * 1000
        assert avg_time_ms < 5.0, f"Validation took {avg_time_ms:.2f}ms (target: <5ms)"

    # NOTE: test_validate_records_usage was removed - depends on generate_perpetual_key


class TestLicenseRevocation:
    """Test suite for license key revocation.

    NOTE: test_revoke_license_key was removed - depends on generate_perpetual_key
    """

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_license_fails(self, license_service: LicenseService):
        """Test that revoking nonexistent license fails."""
        nonexistent_license_id = uuid4()

        with pytest.raises(ValidationError, match="License key not found"):
            await license_service.revoke_license_key(nonexistent_license_id)

    @pytest.mark.asyncio
    async def test_revoke_without_db_session_fails(self):
        """Test that revocation without DB session fails."""
        service = LicenseService(db_session=None)

        with pytest.raises(ValidationError, match="Database session required"):
            await service.revoke_license_key(uuid4())


class TestLicenseUsageHistory:
    """Test suite for license usage history.

    NOTE: test_get_license_usage_history and test_get_usage_history_limit
    were removed - depend on generate_perpetual_key
    """

    @pytest.mark.asyncio
    async def test_get_usage_history_without_db_session_fails(self):
        """Test that usage history without DB session fails."""
        service = LicenseService(db_session=None)

        with pytest.raises(ValidationError, match="Database session required"):
            await service.get_license_usage_history(uuid4())


class TestTierLimits:
    """Test suite for tier limits and feature access."""

    def test_get_free_tier_limits(self, license_service: LicenseService):
        """Test FREE tier limits retrieval."""
        limits = license_service.get_tier_limits(TierEnum.FREE)

        assert limits.tier == TierEnum.FREE
        assert limits.max_agents == 10
        assert limits.max_memories_per_agent == 1000
        assert limits.rate_limit_per_minute == 60
        assert len(limits.features) == 6  # 6 FREE features
        assert limits.max_namespace_count == 3
        assert limits.support_level == "Community"

    def test_get_pro_tier_limits(self, license_service: LicenseService):
        """Test PRO tier limits retrieval."""
        limits = license_service.get_tier_limits(TierEnum.PRO)

        assert limits.tier == TierEnum.PRO
        assert limits.max_agents == 50
        assert limits.max_memories_per_agent == 10000
        assert limits.rate_limit_per_minute == 300
        assert len(limits.features) == 11  # 6 FREE + 5 PRO features
        assert limits.max_namespace_count == 10
        assert limits.support_level == "Email"

    def test_get_enterprise_tier_limits(self, license_service: LicenseService):
        """Test ENTERPRISE tier limits retrieval."""
        limits = license_service.get_tier_limits(TierEnum.ENTERPRISE)

        assert limits.tier == TierEnum.ENTERPRISE
        assert limits.max_agents == 1000
        assert limits.max_memories_per_agent == 100000
        assert limits.rate_limit_per_minute == 1_000_000  # Updated: 1M req/min for ENTERPRISE
        assert len(limits.features) == 21  # All features
        assert limits.max_namespace_count == 100
        assert limits.support_level == "Priority"

    def test_feature_enabled_free_tier(self, license_service: LicenseService):
        """Test feature access for FREE tier."""
        # FREE tier should have basic features
        assert license_service.is_feature_enabled(TierEnum.FREE, LicenseFeature.MEMORY_STORE)
        assert license_service.is_feature_enabled(TierEnum.FREE, LicenseFeature.MEMORY_SEARCH)
        assert license_service.is_feature_enabled(TierEnum.FREE, LicenseFeature.TASK_CREATE)

        # FREE tier should NOT have PRO features
        assert not license_service.is_feature_enabled(
            TierEnum.FREE, LicenseFeature.EXPIRATION_PRUNE
        )

        # FREE tier should NOT have ENTERPRISE features
        assert not license_service.is_feature_enabled(TierEnum.FREE, LicenseFeature.SCHEDULER_START)

    def test_feature_enabled_pro_tier(self, license_service: LicenseService):
        """Test feature access for PRO tier."""
        # PRO tier should have FREE features
        assert license_service.is_feature_enabled(TierEnum.PRO, LicenseFeature.MEMORY_STORE)

        # PRO tier should have PRO features
        assert license_service.is_feature_enabled(TierEnum.PRO, LicenseFeature.EXPIRATION_PRUNE)
        assert license_service.is_feature_enabled(TierEnum.PRO, LicenseFeature.MEMORY_TTL)

        # PRO tier should NOT have ENTERPRISE features
        assert not license_service.is_feature_enabled(TierEnum.PRO, LicenseFeature.SCHEDULER_START)

    def test_feature_enabled_enterprise_tier(self, license_service: LicenseService):
        """Test feature access for ENTERPRISE tier."""
        # ENTERPRISE tier should have all features
        assert license_service.is_feature_enabled(TierEnum.ENTERPRISE, LicenseFeature.MEMORY_STORE)
        assert license_service.is_feature_enabled(
            TierEnum.ENTERPRISE, LicenseFeature.EXPIRATION_PRUNE
        )
        assert license_service.is_feature_enabled(
            TierEnum.ENTERPRISE, LicenseFeature.SCHEDULER_START
        )
        assert license_service.is_feature_enabled(TierEnum.ENTERPRISE, LicenseFeature.TRUST_SCORE)


# NOTE: TestSecurityProperties tests were removed in Phase 2E-1 (2025-11-15)
# These tests used generate_perpetual_key and generate_license_key which are now CLI-only.
# Timing attack resistance is tested in CLI integration tests: tests/integration/test_license_cli.py


class TestEdgeCases:
    """Test suite for edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_validate_empty_key(self, license_service: LicenseService):
        """Test validation of empty license key."""
        result = await license_service.validate_license_key("")

        assert result.valid is False
        assert "Invalid license key format" in result.error_message

    @pytest.mark.asyncio
    async def test_validate_none_key(self, license_service: LicenseService):
        """Test validation of None license key (should raise)."""
        with pytest.raises(AttributeError):
            await license_service.validate_license_key(None)

    @pytest.mark.asyncio
    @pytest.mark.skip(
        reason="Time-limited license validation requires DB lookup for expires_at - TODO Phase 2C"
    )
    async def test_generate_one_day_expiration(
        self, license_service: LicenseService, test_agent: Agent
    ):
        """Test license generation with 1 day expiration."""
        # 1 day expiration should create a valid key
        key = await license_service.generate_license_key(
            agent_id=UUID(test_agent.id), tier=TierEnum.PRO, expires_days=1
        )

        assert key.startswith("TMWS-PRO-")

        # Validate the key (requires DB lookup for expires_at)
        result = await license_service.validate_license_key(key)
        assert result.valid is True
        assert result.expires_at is not None
        # Should expire in ~24 hours
        now = datetime.now(timezone.utc)
        time_until_expiry = (result.expires_at - now).total_seconds()
        assert 86000 < time_until_expiry < 86500  # ~24 hours (with some margin)

    def test_tier_limits_immutability(self, license_service: LicenseService):
        """Test that tier limits are not accidentally modified."""
        limits1 = license_service.get_tier_limits(TierEnum.PRO)
        limits2 = license_service.get_tier_limits(TierEnum.PRO)

        # Should return consistent results
        assert limits1.max_agents == limits2.max_agents
        assert limits1.rate_limit_per_minute == limits2.rate_limit_per_minute
