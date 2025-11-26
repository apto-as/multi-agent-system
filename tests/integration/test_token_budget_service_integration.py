"""
Integration tests for TokenBudgetService with real SQLite database.

Tests token budget validation and tracking with actual database operations
to verify Phase 2D-2 SQLite implementation.

Author: Artemis (Technical Perfectionist)
Created: 2025-11-24
Phase: v2.4.0 Phase 3B - Performance Validation
"""

import pytest
from uuid import uuid4
from datetime import datetime, timezone

from src.services.token_budget_service import TokenBudgetService, TokenBudgetStatus
from src.services.license_service import LicenseService, TierEnum
from src.models.token_consumption import TokenConsumption
from src.core.exceptions import AuthorizationError


@pytest.mark.asyncio
class TestTokenBudgetServiceIntegration:
    """Integration tests for TokenBudgetService with real database."""

    async def test_free_tier_budget_validation_with_real_db(
        self, test_session, test_agent
    ):
        """Test FREE tier budget validation with real database operations."""
        # Setup services with real DB session
        license_service = LicenseService(db_session=test_session)
        budget_service = TokenBudgetService(license_service, test_session)

        agent_id = test_agent.id

        # Test 1: First operation within budget (5,000 tokens)
        await budget_service.validate_budget(
            agent_id=agent_id,
            estimated_tokens=5000,
            operation_name="test_memory_create",
        )

        # Track consumption
        await budget_service.track_consumption(agent_id=agent_id, actual_tokens=5000)

        # Test 2: Second operation within budget (4,000 more tokens = 9,000 total)
        await budget_service.validate_budget(
            agent_id=agent_id,
            estimated_tokens=4000,
            operation_name="test_search",
        )

        await budget_service.track_consumption(agent_id=agent_id, actual_tokens=4000)

        # Test 3: Third operation exceeds budget (2,000 more would = 11,000 > 10k limit)
        with pytest.raises(AuthorizationError) as exc_info:
            await budget_service.validate_budget(
                agent_id=agent_id,
                estimated_tokens=2000,
                operation_name="test_exceeds_budget",
            )

        assert "Token budget exceeded" in str(exc_info.value)
        assert "10,000" in str(exc_info.value)  # Budget limit
        assert "9,000" in str(exc_info.value)  # Current consumption

    async def test_get_budget_status_with_real_db(
        self, test_session, test_agent
    ):
        """Test budget status retrieval with real database."""
        license_service = LicenseService(db_session=test_session)
        budget_service = TokenBudgetService(license_service, test_session)

        agent_id = test_agent.id

        # Track some consumption
        await budget_service.track_consumption(agent_id=agent_id, actual_tokens=7500)

        # Get budget status
        status = await budget_service.get_budget_status(agent_id=agent_id)

        # Verify status
        assert isinstance(status, TokenBudgetStatus)
        assert str(status.agent_id) == str(agent_id)  # Compare string representations
        assert status.tier == TierEnum.FREE
        assert status.current_consumption == 7500
        assert status.budget_limit == 10_000
        assert status.remaining_tokens == 2_500
        assert status.is_unlimited is False
        assert isinstance(status.window_start, datetime)
        assert isinstance(status.window_end, datetime)

    async def test_token_consumption_persistence(
        self, test_session, test_agent
    ):
        """Test that token consumption persists across service instances."""
        license_service = LicenseService()
        agent_id = test_agent.id

        # Service instance 1: Track consumption
        budget_service_1 = TokenBudgetService(license_service, test_session)
        await budget_service_1.track_consumption(agent_id=agent_id, actual_tokens=3000)

        # Verify persistence by querying database directly
        from sqlalchemy import select
        stmt = select(TokenConsumption).where(TokenConsumption.agent_id == str(agent_id))
        result = await test_session.execute(stmt)
        consumption_record = result.scalar_one_or_none()

        assert consumption_record is not None
        assert consumption_record.consumption_count == 3000

        # Service instance 2: Add more consumption
        budget_service_2 = TokenBudgetService(license_service, test_session)
        await budget_service_2.track_consumption(agent_id=agent_id, actual_tokens=2000)

        # Verify atomic update (3000 + 2000 = 5000)
        await test_session.refresh(consumption_record)
        assert consumption_record.consumption_count == 5000

    async def test_reset_budget_with_real_db(
        self, test_session, test_agent
    ):
        """Test budget reset with real database."""
        license_service = LicenseService(db_session=test_session)
        budget_service = TokenBudgetService(license_service, test_session)

        agent_id = test_agent.id

        # Track consumption
        await budget_service.track_consumption(agent_id=agent_id, actual_tokens=8000)

        # Verify consumption
        status = await budget_service.get_budget_status(agent_id=agent_id)
        assert status.current_consumption == 8000

        # Reset budget
        await budget_service.reset_budget(agent_id=agent_id)

        # Verify reset (should be 0)
        status_after = await budget_service.get_budget_status(agent_id=agent_id)
        assert status_after.current_consumption == 0
        assert status_after.remaining_tokens == 10_000

    async def test_pro_tier_budget_validation(
        self, test_session, test_agent_pro
    ):
        """Test PRO tier budget validation with real database."""
        license_service = LicenseService(db_session=test_session)
        budget_service = TokenBudgetService(license_service, test_session)

        agent_id = test_agent_pro.id

        # PRO tier has 50,000 tokens/hour
        # Test large consumption within budget
        await budget_service.validate_budget(
            agent_id=agent_id,
            estimated_tokens=45000,
            operation_name="test_large_operation",
        )

        await budget_service.track_consumption(agent_id=agent_id, actual_tokens=45000)

        # Verify can still use remaining budget
        status = await budget_service.get_budget_status(agent_id=agent_id)
        assert status.current_consumption == 45000
        assert status.budget_limit == 50_000
        assert status.remaining_tokens == 5_000

        # Exceeding budget should fail
        with pytest.raises(AuthorizationError):
            await budget_service.validate_budget(
                agent_id=agent_id,
                estimated_tokens=6000,  # Would exceed 50k
                operation_name="test_exceeds_pro_budget",
            )

    async def test_window_hour_format(
        self, test_session, test_agent
    ):
        """Test that window_hour is in correct format (YYYYMMDDHH)."""
        license_service = LicenseService(db_session=test_session)
        budget_service = TokenBudgetService(license_service, test_session)

        agent_id = test_agent.id

        # Track consumption
        await budget_service.track_consumption(agent_id=agent_id, actual_tokens=1000)

        # Query database to verify window_hour format
        from sqlalchemy import select
        stmt = select(TokenConsumption).where(TokenConsumption.agent_id == str(agent_id))
        result = await test_session.execute(stmt)
        consumption_record = result.scalar_one()

        # Verify format: YYYYMMDDHH (10 characters, all digits)
        assert len(consumption_record.window_hour) == 10
        assert consumption_record.window_hour.isdigit()

        # Verify matches current hour
        now = datetime.now(timezone.utc)
        expected_window = now.replace(minute=0, second=0, microsecond=0).strftime("%Y%m%d%H")
        assert consumption_record.window_hour == expected_window


# Fixtures

@pytest.fixture
async def test_agent(test_session):
    """Create a test agent with FREE tier for testing."""
    from src.models.agent import Agent, AccessLevel, AgentStatus

    agent = Agent(
        agent_id=f"test-agent-{uuid4()}",
        display_name="Test Agent (FREE)",
        namespace="test",
        tier="FREE",
        default_access_level=AccessLevel.PRIVATE,
        status=AgentStatus.ACTIVE,
    )

    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)

    yield agent

    # Cleanup
    await test_session.delete(agent)
    await test_session.commit()


@pytest.fixture
async def test_agent_pro(test_session):
    """Create a test agent with PRO tier for testing."""
    from src.models.agent import Agent, AccessLevel, AgentStatus

    agent = Agent(
        agent_id=f"test-agent-pro-{uuid4()}",
        display_name="Test Agent (PRO)",
        namespace="test",
        tier="PRO",
        default_access_level=AccessLevel.PRIVATE,
        status=AgentStatus.ACTIVE,
    )

    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)

    yield agent

    # Cleanup
    await test_session.delete(agent)
    await test_session.commit()
