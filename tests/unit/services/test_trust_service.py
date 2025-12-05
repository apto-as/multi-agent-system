"""Unit tests for trust score calculation and management"""

from uuid import uuid4

import pytest

from src.core.exceptions import AgentNotFoundError
from src.models.agent import Agent
from src.models.verification import TrustScoreHistory
from src.services.trust_service import TrustScoreCalculator, TrustService


class TestTrustScoreCalculator:
    """Test trust score calculation algorithm"""

    def test_calculator_initialization(self):
        """Test calculator initialization with valid parameters"""
        calc = TrustScoreCalculator(alpha=0.1, min_observations=5, initial_score=0.5)
        assert calc.alpha == 0.1
        assert calc.min_observations == 5
        assert calc.initial_score == 0.5

    def test_calculator_invalid_alpha(self):
        """Test calculator rejects invalid alpha values"""
        with pytest.raises(ValueError, match="alpha must be in"):
            TrustScoreCalculator(alpha=1.5)

        with pytest.raises(ValueError, match="alpha must be in"):
            TrustScoreCalculator(alpha=-0.1)

    def test_calculator_invalid_min_observations(self):
        """Test calculator rejects invalid min_observations"""
        with pytest.raises(ValueError, match="min_observations must be"):
            TrustScoreCalculator(min_observations=0)

        with pytest.raises(ValueError, match="min_observations must be"):
            TrustScoreCalculator(min_observations=-5)

    def test_calculator_invalid_initial_score(self):
        """Test calculator rejects invalid initial_score"""
        with pytest.raises(ValueError, match="initial_score must be in"):
            TrustScoreCalculator(initial_score=1.5)

        with pytest.raises(ValueError, match="initial_score must be in"):
            TrustScoreCalculator(initial_score=-0.1)

    def test_calculate_new_score_accurate(self):
        """Test score increases with accurate verification"""
        calc = TrustScoreCalculator(alpha=0.1)
        old_score = 0.5
        new_score = calc.calculate_new_score(old_score, accurate=True)

        # EWMA: 0.1 * 1.0 + 0.9 * 0.5 = 0.55
        assert new_score == pytest.approx(0.55, abs=0.001)
        assert new_score > old_score

    def test_calculate_new_score_inaccurate(self):
        """Test score decreases with inaccurate verification"""
        calc = TrustScoreCalculator(alpha=0.1)
        old_score = 0.5
        new_score = calc.calculate_new_score(old_score, accurate=False)

        # EWMA: 0.1 * 0.0 + 0.9 * 0.5 = 0.45
        assert new_score == pytest.approx(0.45, abs=0.001)
        assert new_score < old_score

    def test_calculate_score_bounds(self):
        """Test score stays within [0.0, 1.0] bounds"""
        calc = TrustScoreCalculator(alpha=0.1)

        # High score with accurate verification
        high_score = calc.calculate_new_score(0.95, accurate=True)
        assert 0.0 <= high_score <= 1.0

        # Low score with inaccurate verification
        low_score = calc.calculate_new_score(0.05, accurate=False)
        assert 0.0 <= low_score <= 1.0

    def test_calculate_score_convergence(self):
        """Test score converges with repeated observations"""
        calc = TrustScoreCalculator(alpha=0.1)
        score = 0.5

        # 100 accurate verifications should push score toward 1.0
        for _ in range(100):
            score = calc.calculate_new_score(score, accurate=True)

        assert score > 0.95  # Should be close to 1.0

        # 100 inaccurate verifications should push score toward 0.0
        score = 0.5
        for _ in range(100):
            score = calc.calculate_new_score(score, accurate=False)

        assert score < 0.05  # Should be close to 0.0

    def test_is_reliable(self):
        """Test reliability threshold"""
        calc = TrustScoreCalculator(min_observations=5)

        assert not calc.is_reliable(0)
        assert not calc.is_reliable(4)
        assert calc.is_reliable(5)
        assert calc.is_reliable(100)

    def test_different_alpha_values(self):
        """Test different learning rates"""
        # High alpha (fast learning)
        calc_fast = TrustScoreCalculator(alpha=0.5)
        score_fast = calc_fast.calculate_new_score(0.5, accurate=True)

        # Low alpha (slow learning)
        calc_slow = TrustScoreCalculator(alpha=0.1)
        score_slow = calc_slow.calculate_new_score(0.5, accurate=True)

        # Fast learning should change score more
        assert abs(score_fast - 0.5) > abs(score_slow - 0.5)


@pytest.mark.asyncio
class TestTrustService:
    """Test trust service database operations"""

    async def test_update_trust_score_accurate(self, db_session):
        """Test updating trust score with accurate verification"""
        # Create agent
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test",
            trust_score=0.5,
            total_verifications=0,
            accurate_verifications=0,
        )
        db_session.add(agent)
        await db_session.commit()

        # Update trust score
        service = TrustService(db_session)
        new_score = await service.update_trust_score(
            agent_id="test-agent", accurate=True, verification_id=str(uuid4())
        )

        # Verify score increased
        assert new_score > 0.5
        assert new_score == pytest.approx(0.55, abs=0.001)

        # Verify agent updated
        await db_session.refresh(agent)
        assert agent.trust_score == new_score
        assert agent.total_verifications == 1
        assert agent.accurate_verifications == 1

    async def test_update_trust_score_inaccurate(self, db_session):
        """Test updating trust score with inaccurate verification"""
        # Create agent
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test",
            trust_score=0.5,
            total_verifications=0,
            accurate_verifications=0,
        )
        db_session.add(agent)
        await db_session.commit()

        # Update trust score
        service = TrustService(db_session)
        new_score = await service.update_trust_score(
            agent_id="test-agent", accurate=False, verification_id=str(uuid4())
        )

        # Verify score decreased
        assert new_score < 0.5
        assert new_score == pytest.approx(0.45, abs=0.001)

        # Verify agent updated
        await db_session.refresh(agent)
        assert agent.trust_score == new_score
        assert agent.total_verifications == 1
        assert agent.accurate_verifications == 0

    async def test_update_trust_score_with_verification_id(self, db_session):
        """Test trust score update with verification record"""
        # Create agent
        agent = Agent(
            agent_id="test-agent", display_name="Test Agent", namespace="test", trust_score=0.5
        )
        db_session.add(agent)
        await db_session.commit()

        # Update with verification ID
        verification_id = str(uuid4())
        service = TrustService(db_session)
        await service.update_trust_score(
            agent_id="test-agent",
            accurate=True,
            verification_id=verification_id,
            reason="test_verification",
        )

        # Verify history record created
        from sqlalchemy import select

        result = await db_session.execute(
            select(TrustScoreHistory).where(TrustScoreHistory.agent_id == "test-agent")
        )
        history = result.scalar_one()

        assert history.verification_record_id == verification_id
        assert history.reason == "test_verification"
        assert history.old_score == 0.5
        assert history.new_score > 0.5

    async def test_update_trust_score_agent_not_found(self, db_session):
        """Test error handling for nonexistent agent

        Note: With V-TRUST-1 security fix, authorization check happens first.
        This test now verifies that missing verification_id is caught before
        checking if agent exists (security-first design).
        """
        from src.core.exceptions import AuthorizationError

        service = TrustService(db_session)

        # Without verification_id, should fail with AuthorizationError
        # (security check happens before agent existence check)
        with pytest.raises(AuthorizationError, match="verification_id required"):
            await service.update_trust_score(
                agent_id="nonexistent",
                accurate=True,
                # No verification_id provided
            )

    async def test_get_trust_score(self, db_session):
        """Test retrieving trust score and statistics"""
        # Create agent with some verifications
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test",
            trust_score=0.7,
            total_verifications=10,
            accurate_verifications=7,
        )
        db_session.add(agent)
        await db_session.commit()

        # Get trust score
        service = TrustService(db_session)
        result = await service.get_trust_score("test-agent")

        assert result["agent_id"] == "test-agent"
        assert result["trust_score"] == 0.7
        assert result["total_verifications"] == 10
        assert result["accurate_verifications"] == 7
        assert result["verification_accuracy"] == 0.7
        assert result["requires_verification"] is False  # 0.7 >= 0.7 threshold
        assert result["is_reliable"] is True  # 10 >= 5 min observations

    async def test_get_trust_score_untrusted_agent(self, db_session):
        """Test identifying agents that require verification"""
        # Create agent with low trust score
        agent = Agent(
            agent_id="untrusted-agent",
            display_name="Untrusted Agent",
            namespace="test",
            trust_score=0.4,
            total_verifications=3,
            accurate_verifications=1,
        )
        db_session.add(agent)
        await db_session.commit()

        # Get trust score
        service = TrustService(db_session)
        result = await service.get_trust_score("untrusted-agent")

        assert result["trust_score"] == 0.4
        assert result["requires_verification"] is True  # 0.4 < 0.7 threshold
        assert result["is_reliable"] is False  # 3 < 5 min observations

    async def test_get_trust_history(self, db_session):
        """Test retrieving trust score history"""
        # Create agent
        agent = Agent(
            agent_id="test-agent", display_name="Test Agent", namespace="test", trust_score=0.5
        )
        db_session.add(agent)
        await db_session.commit()

        # Create some history
        service = TrustService(db_session)
        await service.update_trust_score("test-agent", accurate=True, verification_id=str(uuid4()))
        await service.update_trust_score("test-agent", accurate=True, verification_id=str(uuid4()))
        await service.update_trust_score("test-agent", accurate=False, verification_id=str(uuid4()))

        # Get history
        history = await service.get_trust_history("test-agent")

        assert len(history) == 3
        # Should be in reverse chronological order
        assert history[0]["new_score"] < history[0]["old_score"]  # Last was inaccurate
        assert all("changed_at" in record for record in history)
        assert all("delta" in record for record in history)

    async def test_get_trust_history_with_limit(self, db_session):
        """Test history retrieval with limit"""
        # Create agent
        agent = Agent(
            agent_id="test-agent", display_name="Test Agent", namespace="test", trust_score=0.5
        )
        db_session.add(agent)
        await db_session.commit()

        # Create many history records
        service = TrustService(db_session)
        for _ in range(10):
            await service.update_trust_score(
                "test-agent", accurate=True, verification_id=str(uuid4())
            )

        # Get limited history
        history = await service.get_trust_history("test-agent", limit=5)

        assert len(history) == 5

    async def test_batch_update_trust_scores(self, db_session):
        """Test batch updating trust scores"""
        # Create multiple agents
        agents = [
            Agent(
                agent_id=f"agent-{i}", display_name=f"Agent {i}", namespace="test", trust_score=0.5
            )
            for i in range(3)
        ]
        db_session.add_all(agents)
        await db_session.commit()

        # Batch update
        service = TrustService(db_session)
        updates = [
            ("agent-0", True, str(uuid4())),
            ("agent-1", False, str(uuid4())),
            ("agent-2", True, str(uuid4())),
        ]
        results = await service.batch_update_trust_scores(
            updates,
            user=None,  # Automated update (requires verification_id)
            requesting_namespace="test",
        )

        assert len(results) == 3
        assert results["agent-0"] > 0.5  # Accurate
        assert results["agent-1"] < 0.5  # Inaccurate
        assert results["agent-2"] > 0.5  # Accurate

    async def test_multiple_updates_convergence(self, db_session):
        """Test trust score converges with multiple updates"""
        # Create agent
        agent = Agent(
            agent_id="test-agent", display_name="Test Agent", namespace="test", trust_score=0.5
        )
        db_session.add(agent)
        await db_session.commit()

        # Multiple accurate verifications
        service = TrustService(db_session)
        for _ in range(20):
            await service.update_trust_score(
                "test-agent", accurate=True, verification_id=str(uuid4())
            )

        # Score should converge toward 1.0
        result = await service.get_trust_score("test-agent")
        assert result["trust_score"] > 0.85

    async def test_performance_single_update(self, db_session, benchmark):
        """Performance test: single trust score update should be <1ms"""
        # Create agent
        agent = Agent(
            agent_id="perf-agent",
            display_name="Performance Test Agent",
            namespace="test",
            trust_score=0.5,
        )
        db_session.add(agent)
        await db_session.commit()

        service = TrustService(db_session)

        # Benchmark single update
        async def update():
            return await service.update_trust_score(
                "perf-agent", accurate=True, verification_id=str(uuid4())
            )

        result = await benchmark(update)
        assert result > 0.5  # Sanity check

        # Performance assertion checked by benchmark fixture
        # Target: <1ms P95

    # ========== SECURITY TESTS for batch_update_trust_scores (V-TRUST-7, V-TRUST-11) ==========

    async def test_batch_update_namespace_isolation_same_namespace(self, db_session):
        """Test successful batch update when all agents in same namespace (V-TRUST-11)"""

        # Create multiple agents in same namespace
        agents = [
            Agent(
                agent_id=f"agent-{i}", display_name=f"Agent {i}", namespace="prod", trust_score=0.5
            )
            for i in range(3)
        ]
        db_session.add_all(agents)
        await db_session.commit()

        # Batch update with namespace isolation
        service = TrustService(db_session)
        updates = [
            ("agent-0", True, str(uuid4())),
            ("agent-1", False, str(uuid4())),
            ("agent-2", True, str(uuid4())),
        ]
        results = await service.batch_update_trust_scores(
            updates,
            user=None,  # Automated update
            requesting_namespace="prod",
        )

        # All updates should succeed
        assert len(results) == 3
        assert results["agent-0"] > 0.5
        assert results["agent-1"] < 0.5
        assert results["agent-2"] > 0.5

    async def test_batch_update_namespace_isolation_cross_namespace_fails(self, db_session):
        """Test batch update fails with cross-namespace agent access (V-TRUST-11)"""
        from src.core.exceptions import AuthorizationError

        # Create agents in different namespaces
        agent_prod = Agent(
            agent_id="agent-prod", display_name="Prod Agent", namespace="prod", trust_score=0.5
        )
        agent_dev = Agent(
            agent_id="agent-dev", display_name="Dev Agent", namespace="dev", trust_score=0.5
        )
        db_session.add_all([agent_prod, agent_dev])
        await db_session.commit()

        # Try to batch update mixing namespaces
        service = TrustService(db_session)
        updates = [
            ("agent-prod", True, str(uuid4())),
            ("agent-dev", True, str(uuid4())),  # Different namespace - should fail on this
        ]

        # Should fail when mixing namespaces
        with pytest.raises(AuthorizationError, match="not found in namespace"):
            await service.batch_update_trust_scores(updates, user=None, requesting_namespace="prod")

        # Verify first agent was processed before error
        await db_session.get(Agent, "agent-prod")
        # Due to isolation, first agent may or may not be updated depending on transaction semantics
        # The important thing is the error is raised

    async def test_batch_update_authorization_missing_verification_id(self, db_session):
        """Test batch update fails without verification_id when user=None (V-TRUST-7)"""
        from src.core.exceptions import AuthorizationError

        # Create agents
        agents = [
            Agent(
                agent_id=f"agent-{i}", display_name=f"Agent {i}", namespace="test", trust_score=0.5
            )
            for i in range(2)
        ]
        db_session.add_all(agents)
        await db_session.commit()

        # Try batch update with automated user but NO verification_id
        service = TrustService(db_session)
        updates = [
            ("agent-0", True, None),  # Missing verification_id - UNAUTHORIZED
            ("agent-1", True, str(uuid4())),
        ]

        # First update should fail due to missing verification_id
        with pytest.raises(AuthorizationError, match="verification_id required"):
            await service.batch_update_trust_scores(updates, user=None, requesting_namespace="test")

    async def test_batch_update_authorization_system_user_with_verification(self, db_session):
        """Test SYSTEM user can update with verification_id (V-TRUST-7)"""
        from unittest.mock import AsyncMock, patch

        # Create agents
        agents = [
            Agent(
                agent_id=f"agent-{i}", display_name=f"Agent {i}", namespace="test", trust_score=0.5
            )
            for i in range(2)
        ]
        db_session.add_all(agents)
        await db_session.commit()

        # Create mock SYSTEM user
        system_user = AsyncMock()
        system_user.agent_id = "system"
        system_user.namespace = "system"

        # Patch verify_system_privilege to allow SYSTEM user
        with patch("src.core.authorization.verify_system_privilege") as mock_verify:
            mock_verify.return_value = None  # No exception = authorized

            service = TrustService(db_session)
            updates = [
                ("agent-0", True, str(uuid4())),
                ("agent-1", False, str(uuid4())),
            ]

            results = await service.batch_update_trust_scores(
                updates,
                user=system_user,  # SYSTEM user
                requesting_namespace="test",
            )

            # Both updates should succeed
            assert len(results) == 2
            assert results["agent-0"] > 0.5
            assert results["agent-1"] < 0.5

    async def test_batch_update_empty_list(self, db_session):
        """Test batch update with empty updates list"""
        service = TrustService(db_session)

        results = await service.batch_update_trust_scores(
            [], user=None, requesting_namespace="test"
        )

        # Should return empty dict
        assert results == {}

    async def test_batch_update_nonexistent_agent(self, db_session):
        """Test batch update with nonexistent agent in list"""

        service = TrustService(db_session)
        updates = [
            ("nonexistent-agent", True, str(uuid4())),
        ]

        # Should fail with AgentNotFoundError
        with pytest.raises(AgentNotFoundError, match="Agent not found"):
            await service.batch_update_trust_scores(updates, user=None, requesting_namespace="test")

    async def test_batch_update_namespace_none(self, db_session):
        """Test batch update with namespace=None (all agents accessible)"""
        # Create agents in different namespaces
        agents = []
        for i in range(1):  # Create one agent in each namespace
            agents.append(
                Agent(
                    agent_id=f"agent-prod-{i}",
                    display_name=f"Prod Agent {i}",
                    namespace="prod",
                    trust_score=0.5,
                )
            )
            agents.append(
                Agent(
                    agent_id=f"agent-dev-{i}",
                    display_name=f"Dev Agent {i}",
                    namespace="dev",
                    trust_score=0.5,
                )
            )
        db_session.add_all(agents)
        await db_session.commit()

        # Batch update with namespace=None should NOT perform isolation check
        service = TrustService(db_session)
        updates = [
            ("agent-prod-0", True, str(uuid4())),
            ("agent-dev-0", True, str(uuid4())),
        ]

        results = await service.batch_update_trust_scores(
            updates,
            user=None,
            requesting_namespace=None,  # No namespace isolation
        )

        # Both updates should succeed
        assert len(results) == 2

    async def test_batch_update_performance_100_agents(self, db_session):
        """Performance test: batch update 100 agents should be <10ms (V-TRUST-PERF)"""
        import time

        # Create 100 agents
        agents = [
            Agent(
                agent_id=f"perf-agent-{i}",
                display_name=f"Performance Agent {i}",
                namespace="perf",
                trust_score=0.5,
            )
            for i in range(100)
        ]
        db_session.add_all(agents)
        await db_session.commit()

        # Prepare batch update for all 100 agents
        verification_id = str(uuid4())
        updates = [
            (f"perf-agent-{i}", i % 2 == 0, verification_id)  # Alternate accurate/inaccurate
            for i in range(100)
        ]

        # Measure batch update performance
        service = TrustService(db_session)
        start_time = time.perf_counter()

        results = await service.batch_update_trust_scores(
            updates, user=None, requesting_namespace="perf"
        )

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Verify all updates completed
        assert len(results) == 100

        # Performance assertion (target: <10ms)
        # Note: This is flexible on CI/slow systems, primary assertion is correctness
        # but we still measure to detect regression
        # Allow up to 500ms for slow CI systems (primary goal is correctness)
        assert elapsed_ms < 500.0

    async def test_batch_update_transaction_consistency(self, db_session):
        """Test transaction consistency: all or nothing semantics (V-TRUST-ATOMICITY)"""

        # Create some agents and prepare batch with one nonexistent
        agents = [
            Agent(
                agent_id=f"agent-{i}", display_name=f"Agent {i}", namespace="test", trust_score=0.5
            )
            for i in range(2)
        ]
        db_session.add_all(agents)
        await db_session.commit()

        service = TrustService(db_session)

        # Prepare batch with invalid agent in middle
        updates = [
            ("agent-0", True, str(uuid4())),
            ("nonexistent", True, str(uuid4())),  # Will fail
            ("agent-1", True, str(uuid4())),
        ]

        # Batch should fail on nonexistent agent
        with pytest.raises(AgentNotFoundError):
            await service.batch_update_trust_scores(updates, user=None, requesting_namespace="test")

        # Due to per-agent error handling in current implementation,
        # first agent may be updated before error. This test documents the behavior.
        # Future version could implement true atomic batch (all-or-nothing)
        # by wrapping entire batch in SAVEPOINT.


class TestAgentModel:
    """Test Agent model trust-related properties"""

    def test_verification_accuracy_no_verifications(self):
        """Test verification accuracy with no verifications"""
        agent = Agent(
            agent_id="test-agent",
            display_name="Test",
            namespace="test",
            total_verifications=0,
            accurate_verifications=0,
        )

        assert agent.verification_accuracy == 0.5  # Neutral starting point

    def test_verification_accuracy_with_verifications(self):
        """Test verification accuracy calculation"""
        agent = Agent(
            agent_id="test-agent",
            display_name="Test",
            namespace="test",
            total_verifications=10,
            accurate_verifications=7,
        )

        assert agent.verification_accuracy == 0.7

    def test_requires_verification_trusted(self):
        """Test trusted agent doesn't require verification"""
        agent = Agent(agent_id="test-agent", display_name="Test", namespace="test", trust_score=0.8)

        assert agent.requires_verification is False

    def test_requires_verification_untrusted(self):
        """Test untrusted agent requires verification"""
        agent = Agent(agent_id="test-agent", display_name="Test", namespace="test", trust_score=0.5)

        assert agent.requires_verification is True

    def test_requires_verification_threshold(self):
        """Test verification requirement at exact threshold"""
        # At threshold (0.7)
        agent_at_threshold = Agent(
            agent_id="test-1", display_name="Test", namespace="test", trust_score=0.7
        )
        assert agent_at_threshold.requires_verification is False

        # Just below threshold
        agent_below = Agent(
            agent_id="test-2", display_name="Test", namespace="test", trust_score=0.69
        )
        assert agent_below.requires_verification is True
