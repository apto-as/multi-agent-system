"""Integration tests for agent trust and verification workflow

Tests the complete workflow:
1. Agent makes a claim
2. Claim is verified
3. Evidence is recorded
4. Trust score is updated
5. Future reports require verification if trust is low
"""

import pytest

from src.models.agent import Agent
from src.services.memory_service import HybridMemoryService
from src.services.trust_service import TrustService
from src.services.verification_service import ClaimType, VerificationService


@pytest.mark.asyncio
class TestAgentTrustWorkflow:
    """Test complete agent trust workflow"""

    async def test_complete_verification_workflow(self, db_session):
        """Test end-to-end verification workflow"""
        # Setup: Create agent with neutral trust score
        agent = Agent(
            agent_id="artemis-optimizer",
            display_name="Artemis - Technical Perfectionist",
            namespace="trinitas",
            trust_score=0.5,
            total_verifications=0,
            accurate_verifications=0,
        )
        db_session.add(agent)
        await db_session.commit()

        # Services
        memory_service = HybridMemoryService(db_session)
        trust_service = TrustService(db_session)
        verification_service = VerificationService(
            db_session, memory_service=memory_service, trust_service=trust_service
        )

        # Step 1: Artemis claims all tests passed
        claim = {
            "return_code": 0,
            "output_contains": ["PASSED", "100%"],
            "metrics": {"coverage": 90.0},
        }

        # Step 2: Verify the claim
        result = await verification_service.verify_claim(
            agent_id="artemis-optimizer",
            claim_type=ClaimType.TEST_RESULT,
            claim_content=claim,
            verification_command="pytest tests/unit/ -v --cov=src",
        )

        # Step 3: Check verification result
        assert result.accurate is True  # Assuming tests actually pass
        assert result.new_trust_score > 0.5  # Trust increased
        assert result.evidence_id is not None  # Evidence recorded

        # Step 4: Verify agent state updated
        await db_session.refresh(agent)
        assert agent.total_verifications == 1
        assert agent.accurate_verifications == 1
        assert agent.trust_score == result.new_trust_score

        # Step 5: Verify evidence memory exists
        from sqlalchemy import select

        from src.models.memory import Memory

        evidence_result = await db_session.execute(
            select(Memory).where(Memory.id == result.evidence_id)
        )
        evidence = evidence_result.scalar_one()

        assert evidence.content is not None
        assert "✅" in evidence.content  # Accurate marker
        assert evidence.metadata["accurate"] is True

    async def test_trust_degradation_on_false_claims(self, db_session):
        """Test trust score decreases with false claims"""
        # Setup: Create agent with high trust
        agent = Agent(
            agent_id="unreliable-agent",
            display_name="Unreliable Agent",
            namespace="test",
            trust_score=0.8,
            total_verifications=10,
            accurate_verifications=8,
        )
        db_session.add(agent)
        await db_session.commit()

        memory_service = HybridMemoryService(db_session)
        verification_service = VerificationService(db_session, memory_service=memory_service)

        # Make false claims multiple times
        for _ in range(5):
            result = await verification_service.verify_claim(
                agent_id="unreliable-agent",
                claim_type=ClaimType.TEST_RESULT,
                claim_content={"return_code": 0},  # Claims success
                verification_command="exit 1",  # Actually fails
            )

            assert result.accurate is False
            assert result.new_trust_score < agent.trust_score

            await db_session.refresh(agent)
            # Trust score should be decreasing

        # After 5 false claims, trust should be low
        await db_session.refresh(agent)
        assert agent.trust_score < 0.7  # Below verification threshold
        assert agent.requires_verification is True

    async def test_trust_recovery(self, db_session):
        """Test trust score recovers with accurate verifications"""
        # Setup: Create agent with low trust
        agent = Agent(
            agent_id="recovering-agent",
            display_name="Recovering Agent",
            namespace="test",
            trust_score=0.4,  # Below threshold
            total_verifications=10,
            accurate_verifications=4,
        )
        db_session.add(agent)
        await db_session.commit()

        assert agent.requires_verification is True  # Initially requires verification

        memory_service = HybridMemoryService(db_session)
        verification_service = VerificationService(db_session, memory_service=memory_service)

        # Make 10 accurate claims
        for _ in range(10):
            result = await verification_service.verify_claim(
                agent_id="recovering-agent",
                claim_type=ClaimType.TEST_RESULT,
                claim_content={"return_code": 0},
                verification_command="exit 0",  # Success
            )

            assert result.accurate is True

        # Trust should recover
        await db_session.refresh(agent)
        assert agent.trust_score > 0.4  # Improved
        # May or may not be above 0.7 depending on EWMA alpha

    async def test_verification_history_tracking(self, db_session):
        """Test verification history is properly tracked"""
        # Setup
        agent = Agent(
            agent_id="tracked-agent",
            display_name="Tracked Agent",
            namespace="test",
            trust_score=0.5,
        )
        db_session.add(agent)
        await db_session.commit()

        memory_service = HybridMemoryService(db_session)
        verification_service = VerificationService(db_session, memory_service=memory_service)

        # Perform multiple verifications of different types
        claims = [
            (ClaimType.TEST_RESULT, {"return_code": 0}, "exit 0"),
            (ClaimType.PERFORMANCE_METRIC, {"metrics": {"latency": 10}}, "exit 0"),
            (ClaimType.SECURITY_FINDING, {"return_code": 0}, "exit 1"),  # False claim
        ]

        for claim_type, claim_content, command in claims:
            await verification_service.verify_claim(
                agent_id="tracked-agent",
                claim_type=claim_type,
                claim_content=claim_content,
                verification_command=command,
            )

        # Check history
        history = await verification_service.get_verification_history("tracked-agent")

        assert len(history) == 3
        assert history[0]["claim_type"] == ClaimType.SECURITY_FINDING.value  # Most recent
        assert history[0]["accurate"] is False
        assert history[1]["accurate"] is True
        assert history[2]["accurate"] is True

    async def test_verification_statistics(self, db_session):
        """Test verification statistics calculation"""
        # Setup
        agent = Agent(
            agent_id="stats-agent",
            display_name="Stats Agent",
            namespace="test",
            trust_score=0.6,
            total_verifications=20,
            accurate_verifications=15,
        )
        db_session.add(agent)
        await db_session.commit()

        memory_service = HybridMemoryService(db_session)
        verification_service = VerificationService(db_session, memory_service=memory_service)

        # Add some verifications
        for i in range(5):
            await verification_service.verify_claim(
                agent_id="stats-agent",
                claim_type=ClaimType.TEST_RESULT,
                claim_content={"return_code": 0},
                verification_command="exit 0" if i < 4 else "exit 1",  # 4 accurate, 1 false
            )

        # Get statistics
        stats = await verification_service.get_verification_statistics("stats-agent")

        assert stats["agent_id"] == "stats-agent"
        assert stats["total_verifications"] == 25  # 20 + 5
        assert stats["accurate_verifications"] == 19  # 15 + 4
        assert stats["accuracy_rate"] == pytest.approx(19 / 25, abs=0.01)

        # Check claim type breakdown
        assert ClaimType.TEST_RESULT.value in stats["by_claim_type"]
        test_stats = stats["by_claim_type"][ClaimType.TEST_RESULT.value]
        assert test_stats["total"] == 5
        assert test_stats["accurate"] == 4

    async def test_trust_score_history(self, db_session):
        """Test trust score history tracking"""
        # Setup
        agent = Agent(
            agent_id="history-agent",
            display_name="History Agent",
            namespace="test",
            trust_score=0.5,
        )
        db_session.add(agent)
        await db_session.commit()

        trust_service = TrustService(db_session)

        # Make several trust score updates
        for i, accurate in enumerate([True, True, False, True, False]):
            await trust_service.update_trust_score(
                agent_id="history-agent", accurate=accurate, reason=f"test_update_{i}"
            )

        # Get history
        history = await trust_service.get_trust_history("history-agent")

        assert len(history) == 5
        # History should be in reverse chronological order
        assert history[0]["reason"] == "test_update_4"
        assert history[-1]["reason"] == "test_update_0"

        # Check delta calculation
        for record in history:
            assert "delta" in record
            assert record["new_score"] == record["old_score"] + record["delta"]

    async def test_multiple_agents_isolation(self, db_session):
        """Test that trust scores are isolated per agent"""
        # Setup: Create two agents
        agent1 = Agent(
            agent_id="agent-1", display_name="Agent 1", namespace="test", trust_score=0.5
        )
        agent2 = Agent(
            agent_id="agent-2", display_name="Agent 2", namespace="test", trust_score=0.5
        )
        db_session.add_all([agent1, agent2])
        await db_session.commit()

        memory_service = HybridMemoryService(db_session)
        verification_service = VerificationService(db_session, memory_service=memory_service)

        # Agent 1 makes accurate claim
        await verification_service.verify_claim(
            agent_id="agent-1",
            claim_type=ClaimType.TEST_RESULT,
            claim_content={"return_code": 0},
            verification_command="exit 0",
        )

        # Agent 2 makes false claim
        await verification_service.verify_claim(
            agent_id="agent-2",
            claim_type=ClaimType.TEST_RESULT,
            claim_content={"return_code": 0},
            verification_command="exit 1",
        )

        # Verify isolation
        await db_session.refresh(agent1)
        await db_session.refresh(agent2)

        assert agent1.trust_score > 0.5  # Increased
        assert agent2.trust_score < 0.5  # Decreased
        assert agent1.total_verifications == 1
        assert agent2.total_verifications == 1
        assert agent1.accurate_verifications == 1
        assert agent2.accurate_verifications == 0

    async def test_performance_batch_verification(self, db_session, benchmark):
        """Performance test: batch verification should scale linearly"""
        # Setup: Create 10 agents
        agents = [
            Agent(
                agent_id=f"perf-agent-{i}",
                display_name=f"Performance Agent {i}",
                namespace="test",
                trust_score=0.5,
            )
            for i in range(10)
        ]
        db_session.add_all(agents)
        await db_session.commit()

        memory_service = HybridMemoryService(db_session)
        verification_service = VerificationService(db_session, memory_service=memory_service)

        # Benchmark batch verification
        async def batch_verify():
            results = []
            for i in range(10):
                result = await verification_service.verify_claim(
                    agent_id=f"perf-agent-{i}",
                    claim_type=ClaimType.TEST_RESULT,
                    claim_content={"return_code": 0},
                    verification_command="exit 0",
                )
                results.append(result)
            return results

        results = await benchmark(batch_verify)
        assert len(results) == 10
        assert all(r.accurate for r in results)

        # Performance target: <5000ms for 10 verifications (<500ms each)
