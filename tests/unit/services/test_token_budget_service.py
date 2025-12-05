"""
Token Budget Service Unit Tests

Tests for token consumption tracking and budget validation (v2.4.0 V-2 Progressive Disclosure).

Test Coverage:
- Budget validation for all tiers (FREE/PRO/ENTERPRISE/ADMINISTRATOR)
- Token consumption tracking (atomic operations)
- Budget status queries
- Window expiration and cleanup
- Error handling (fail-secure design)

Author: Artemis (Technical Perfectionist)
Created: 2025-11-24
Updated: 2025-11-24 (Phase 2D-2: SQLite migration)
Phase: 2D-2 - V-2 Progressive Disclosure Testing (SQLite-Only)
"""

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from src.core.exceptions import AuthorizationError
from src.models.token_consumption import TokenConsumption
from src.services.license_service import LicenseService, TierEnum, TierLimits
from src.services.token_budget_service import TokenBudgetService


@pytest.fixture
def mock_license_service():
    """Mock LicenseService for testing."""
    service = AsyncMock(spec=LicenseService)

    # Mock tier limits (Phase 2D-2: Updated token limits 10k/50k)
    def mock_get_tier_limits(tier: TierEnum) -> TierLimits:
        limits_map = {
            TierEnum.FREE: TierLimits(
                tier=TierEnum.FREE,
                max_agents=10,
                max_memories_per_agent=1000,
                rate_limit_per_minute=60,
                features=[],
                max_namespace_count=3,
                support_level="Community",
                max_tokens_per_hour=10_000,  # Phase 2D-2: 10k tokens/hour
            ),
            TierEnum.PRO: TierLimits(
                tier=TierEnum.PRO,
                max_agents=50,
                max_memories_per_agent=10000,
                rate_limit_per_minute=300,
                features=[],
                max_namespace_count=10,
                support_level="Email",
                max_tokens_per_hour=50_000,  # Phase 2D-2: 50k tokens/hour
            ),
            TierEnum.ENTERPRISE: TierLimits(
                tier=TierEnum.ENTERPRISE,
                max_agents=1000,
                max_memories_per_agent=100000,
                rate_limit_per_minute=1_000_000,
                features=[],
                max_namespace_count=100,
                support_level="Priority",
                max_tokens_per_hour=None,  # Unlimited
            ),
            TierEnum.ADMINISTRATOR: TierLimits(
                tier=TierEnum.ADMINISTRATOR,
                max_agents=10000,
                max_memories_per_agent=1_000_000,
                rate_limit_per_minute=None,
                features=[],
                max_namespace_count=1000,
                support_level="Premium",
                max_tokens_per_hour=None,  # Unlimited
            ),
        }
        return limits_map[tier]

    service.get_tier_limits = mock_get_tier_limits
    return service


@pytest.fixture
async def mock_db_session():
    """Mock SQLAlchemy async session for testing."""
    session = AsyncMock()

    # Mock execute() to return a result with scalar_one_or_none()
    def create_mock_result(consumption_count=None):
        mock_result = AsyncMock()
        if consumption_count is not None:
            mock_consumption = MagicMock(spec=TokenConsumption)
            mock_consumption.consumption_count = consumption_count
            mock_result.scalar_one_or_none = MagicMock(return_value=mock_consumption)
        else:
            mock_result.scalar_one_or_none = MagicMock(return_value=None)
        return mock_result

    session.execute = AsyncMock(return_value=create_mock_result())
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.delete = AsyncMock()

    return session


@pytest.fixture
async def budget_service(mock_license_service, mock_db_session):
    """Create TokenBudgetService instance with mocked dependencies."""
    service = TokenBudgetService(mock_license_service, mock_db_session)
    return service


class TestBudgetValidation:
    """Test budget validation for different tiers."""

    @pytest.mark.asyncio
    async def test_free_tier_within_budget(
        self, budget_service, mock_license_service, mock_db_session
    ):
        """FREE tier: Operation within budget should succeed."""
        agent_id = uuid4()
        mock_license_service.get_agent_tier = AsyncMock(return_value=TierEnum.FREE)

        # Mock database to return 1,000 tokens consumed
        mock_result = AsyncMock()
        mock_consumption = MagicMock(spec=TokenConsumption)
        mock_consumption.consumption_count = 1000
        mock_result.scalar_one_or_none = MagicMock(return_value=mock_consumption)
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        # Should not raise - within 10k limit
        await budget_service.validate_budget(
            agent_id=agent_id, estimated_tokens=5000, operation_name="test_operation"
        )

    @pytest.mark.asyncio
    async def test_free_tier_exceeds_budget(
        self, budget_service, mock_license_service, mock_db_session
    ):
        """FREE tier: Operation exceeding budget should fail."""
        agent_id = uuid4()
        mock_license_service.get_agent_tier = AsyncMock(return_value=TierEnum.FREE)

        # Mock database to return 9,000 tokens consumed
        mock_result = AsyncMock()
        mock_consumption = MagicMock(spec=TokenConsumption)
        mock_consumption.consumption_count = 9000
        mock_result.scalar_one_or_none = MagicMock(return_value=mock_consumption)
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        # Should raise - would exceed 10k limit
        with pytest.raises(AuthorizationError) as exc_info:
            await budget_service.validate_budget(
                agent_id=agent_id, estimated_tokens=2000, operation_name="test_operation"
            )

        assert "Token budget exceeded" in str(exc_info.value)
        assert "remaining_tokens" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_pro_tier_within_budget(
        self, budget_service, mock_license_service, mock_db_session
    ):
        """PRO tier: Operation within 50k budget should succeed."""
        agent_id = uuid4()
        mock_license_service.get_agent_tier = AsyncMock(return_value=TierEnum.PRO)

        # Mock database to return 20,000 tokens consumed
        mock_result = AsyncMock()
        mock_consumption = MagicMock(spec=TokenConsumption)
        mock_consumption.consumption_count = 20000
        mock_result.scalar_one_or_none = MagicMock(return_value=mock_consumption)
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        # Should not raise - within 50k limit
        await budget_service.validate_budget(
            agent_id=agent_id, estimated_tokens=10000, operation_name="test_operation"
        )

    @pytest.mark.asyncio
    async def test_pro_tier_exceeds_budget(
        self, budget_service, mock_license_service, mock_db_session
    ):
        """PRO tier: Operation exceeding 50k budget should fail."""
        agent_id = uuid4()
        mock_license_service.get_agent_tier = AsyncMock(return_value=TierEnum.PRO)

        # Mock database to return 48,000 tokens consumed
        mock_result = AsyncMock()
        mock_consumption = MagicMock(spec=TokenConsumption)
        mock_consumption.consumption_count = 48000
        mock_result.scalar_one_or_none = MagicMock(return_value=mock_consumption)
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        # Should raise - would exceed 50k limit
        with pytest.raises(AuthorizationError):
            await budget_service.validate_budget(
                agent_id=agent_id, estimated_tokens=5000, operation_name="test_operation"
            )

    @pytest.mark.asyncio
    async def test_enterprise_tier_unlimited(
        self, budget_service, mock_license_service, mock_db_session
    ):
        """ENTERPRISE tier: Unlimited tokens, should never fail."""
        agent_id = uuid4()
        mock_license_service.get_agent_tier = AsyncMock(return_value=TierEnum.ENTERPRISE)

        # Mock database to return very high consumption
        mock_result = AsyncMock()
        mock_consumption = MagicMock(spec=TokenConsumption)
        mock_consumption.consumption_count = 999999999
        mock_result.scalar_one_or_none = MagicMock(return_value=mock_consumption)
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        # Should not raise - unlimited tier
        await budget_service.validate_budget(
            agent_id=agent_id, estimated_tokens=999999999, operation_name="test_operation"
        )

    @pytest.mark.asyncio
    async def test_administrator_tier_unlimited(
        self, budget_service, mock_license_service, mock_db_session
    ):
        """ADMINISTRATOR tier: Unlimited tokens, should never fail."""
        agent_id = uuid4()
        mock_license_service.get_agent_tier = AsyncMock(return_value=TierEnum.ADMINISTRATOR)

        # Mock database to return very high consumption
        mock_result = AsyncMock()
        mock_consumption = MagicMock(spec=TokenConsumption)
        mock_consumption.consumption_count = 999999999
        mock_result.scalar_one_or_none = MagicMock(return_value=mock_consumption)
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        # Should not raise - unlimited tier
        await budget_service.validate_budget(
            agent_id=agent_id, estimated_tokens=999999999, operation_name="test_operation"
        )


class TestTokenConsumption:
    """Test token consumption tracking."""

    @pytest.mark.asyncio
    async def test_track_consumption_atomic(self, budget_service, mock_db_session):
        """Token consumption tracking should be atomic (upsert)."""
        agent_id = uuid4()

        await budget_service.track_consumption(agent_id=agent_id, actual_tokens=1500)

        # Verify execute was called (for INSERT ... ON CONFLICT DO UPDATE)
        assert mock_db_session.execute.called
        assert mock_db_session.commit.called

    @pytest.mark.asyncio
    async def test_track_consumption_database_failure(self, budget_service, mock_db_session):
        """Token consumption tracking should not fail operation on database error."""
        agent_id = uuid4()
        mock_db_session.execute = AsyncMock(side_effect=Exception("Database connection failed"))

        # Should not raise - tracking failure is logged but doesn't fail operation
        await budget_service.track_consumption(agent_id=agent_id, actual_tokens=1500)

        # Verify rollback was called
        assert mock_db_session.rollback.called


class TestBudgetStatus:
    """Test budget status queries."""

    @pytest.mark.asyncio
    async def test_get_budget_status_free_tier(
        self, budget_service, mock_license_service, mock_db_session
    ):
        """Get budget status for FREE tier."""
        agent_id = uuid4()
        mock_license_service.get_agent_tier = AsyncMock(return_value=TierEnum.FREE)

        # Mock database to return 2,500 tokens consumed
        mock_result = AsyncMock()
        mock_consumption = MagicMock(spec=TokenConsumption)
        mock_consumption.consumption_count = 2500
        mock_result.scalar_one_or_none = MagicMock(return_value=mock_consumption)
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        status = await budget_service.get_budget_status(agent_id)

        assert status.agent_id == agent_id
        assert status.tier == TierEnum.FREE
        assert status.current_consumption == 2500
        assert status.budget_limit == 10_000
        assert status.remaining_tokens == 7500
        assert not status.is_unlimited

    @pytest.mark.asyncio
    async def test_get_budget_status_pro_tier(
        self, budget_service, mock_license_service, mock_db_session
    ):
        """Get budget status for PRO tier."""
        agent_id = uuid4()
        mock_license_service.get_agent_tier = AsyncMock(return_value=TierEnum.PRO)

        # Mock database to return 30,000 tokens consumed
        mock_result = AsyncMock()
        mock_consumption = MagicMock(spec=TokenConsumption)
        mock_consumption.consumption_count = 30000
        mock_result.scalar_one_or_none = MagicMock(return_value=mock_consumption)
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        status = await budget_service.get_budget_status(agent_id)

        assert status.tier == TierEnum.PRO
        assert status.current_consumption == 30000
        assert status.budget_limit == 50_000
        assert status.remaining_tokens == 20_000

    @pytest.mark.asyncio
    async def test_get_budget_status_unlimited_tier(
        self, budget_service, mock_license_service, mock_db_session
    ):
        """Get budget status for unlimited tier (ENTERPRISE)."""
        agent_id = uuid4()
        mock_license_service.get_agent_tier = AsyncMock(return_value=TierEnum.ENTERPRISE)

        status = await budget_service.get_budget_status(agent_id)

        assert status.tier == TierEnum.ENTERPRISE
        assert status.current_consumption == 0
        assert status.budget_limit is None
        assert status.remaining_tokens is None
        assert status.is_unlimited

    @pytest.mark.asyncio
    async def test_get_budget_status_zero_consumption(
        self, budget_service, mock_license_service, mock_db_session
    ):
        """Get budget status with zero consumption."""
        agent_id = uuid4()
        mock_license_service.get_agent_tier = AsyncMock(return_value=TierEnum.FREE)

        # Mock database to return None (no consumption yet)
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=None)
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        status = await budget_service.get_budget_status(agent_id)

        assert status.current_consumption == 0
        assert status.remaining_tokens == 10_000


class TestWindowManagement:
    """Test hourly window management."""

    @pytest.mark.asyncio
    async def test_window_key_format(self, budget_service):
        """Window hour key should follow correct format."""
        agent_id = uuid4()

        window_hour, window_start, window_end = budget_service._get_window_key(agent_id)

        # Verify key format: YYYYMMDDHH
        assert len(window_hour) == 10
        assert window_hour.isdigit()

        # Verify window is 1 hour
        assert (window_end - window_start).total_seconds() == 3600

    @pytest.mark.asyncio
    async def test_reset_budget(self, budget_service, mock_db_session):
        """Budget reset should delete current window record."""
        agent_id = uuid4()

        # Mock database to return a consumption record
        mock_result = AsyncMock()
        mock_consumption = MagicMock(spec=TokenConsumption)
        mock_result.scalar_one_or_none = MagicMock(return_value=mock_consumption)
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        await budget_service.reset_budget(agent_id)

        # Verify delete and commit were called
        assert mock_db_session.delete.called
        assert mock_db_session.commit.called


class TestFailSecure:
    """Test fail-secure behavior on errors."""

    @pytest.mark.asyncio
    async def test_validate_budget_database_failure(
        self, budget_service, mock_license_service, mock_db_session
    ):
        """Budget validation should fail-secure on database errors."""
        agent_id = uuid4()
        mock_license_service.get_agent_tier = AsyncMock(return_value=TierEnum.FREE)
        mock_db_session.execute = AsyncMock(side_effect=Exception("Database connection failed"))

        # Should raise AuthorizationError (fail-secure)
        with pytest.raises(AuthorizationError) as exc_info:
            await budget_service.validate_budget(
                agent_id=agent_id, estimated_tokens=1000, operation_name="test_operation"
            )

        assert "Token budget validation failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_budget_status_database_failure(
        self, budget_service, mock_license_service, mock_db_session
    ):
        """Budget status query should fail on database errors."""
        agent_id = uuid4()
        mock_license_service.get_agent_tier = AsyncMock(return_value=TierEnum.FREE)
        mock_db_session.execute = AsyncMock(side_effect=Exception("Database connection failed"))

        # Should raise AuthorizationError
        with pytest.raises(AuthorizationError):
            await budget_service.get_budget_status(agent_id)


class TestPerformance:
    """Test performance targets."""

    @pytest.mark.asyncio
    async def test_validation_performance(
        self, budget_service, mock_license_service, mock_db_session
    ):
        """Budget validation should complete in <20ms (target)."""
        import time

        agent_id = uuid4()
        mock_license_service.get_agent_tier = AsyncMock(return_value=TierEnum.FREE)

        # Mock database to return 1,000 tokens
        mock_result = AsyncMock()
        mock_consumption = MagicMock(spec=TokenConsumption)
        mock_consumption.consumption_count = 1000
        mock_result.scalar_one_or_none = MagicMock(return_value=mock_consumption)
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        start = time.perf_counter()
        await budget_service.validate_budget(
            agent_id=agent_id, estimated_tokens=1000, operation_name="test_operation"
        )
        duration = (time.perf_counter() - start) * 1000  # Convert to ms

        # With mocks, should be <20ms
        assert duration < 20, f"Validation took {duration:.2f}ms (target: <20ms)"

    @pytest.mark.asyncio
    async def test_consumption_tracking_performance(self, budget_service, mock_db_session):
        """Token consumption tracking should complete in <10ms (target)."""
        import time

        agent_id = uuid4()

        start = time.perf_counter()
        await budget_service.track_consumption(agent_id=agent_id, actual_tokens=1500)
        duration = (time.perf_counter() - start) * 1000

        # With mocks, should be <10ms
        assert duration < 10, f"Tracking took {duration:.2f}ms (target: <10ms)"


class TestIntegration:
    """Integration tests (validate + track workflow)."""

    @pytest.mark.asyncio
    async def test_validate_then_track_workflow(
        self, budget_service, mock_license_service, mock_db_session
    ):
        """Complete workflow: validate → execute → track."""
        agent_id = uuid4()
        mock_license_service.get_agent_tier = AsyncMock(return_value=TierEnum.FREE)

        # Mock database to return 1,000 tokens (initial consumption)
        mock_result = AsyncMock()
        mock_consumption = MagicMock(spec=TokenConsumption)
        mock_consumption.consumption_count = 1000
        mock_result.scalar_one_or_none = MagicMock(return_value=mock_consumption)
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        # Step 1: Validate budget (estimate)
        await budget_service.validate_budget(
            agent_id=agent_id, estimated_tokens=5000, operation_name="create_memory"
        )

        # Step 2: Execute operation (simulated)
        actual_tokens = 4500  # Actual consumption (measured)

        # Step 3: Track actual consumption
        await budget_service.track_consumption(agent_id=agent_id, actual_tokens=actual_tokens)

        # Verify tracking was called
        assert mock_db_session.execute.called
        assert mock_db_session.commit.called
