"""Unit tests for verification service"""
import json
import pytest
from datetime import datetime
from uuid import uuid4

from src.core.exceptions import AgentNotFoundError, VerificationError
from src.models.agent import Agent
from src.models.memory import Memory
from src.models.verification import VerificationRecord
from src.services.verification_service import (
    ClaimType,
    VerificationResult,
    VerificationService
)


@pytest.mark.asyncio
class TestVerificationService:
    """Test verification service operations"""

    async def test_verify_claim_accurate(self, db_session, mock_memory_service):
        """Test verifying an accurate claim"""
        # Create agent
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test",
            trust_score=0.5
        )
        db_session.add(agent)
        await db_session.commit()

        # Create service with mock memory service
        service = VerificationService(
            db_session,
            memory_service=mock_memory_service
        )

        # Verify claim
        result = await service.verify_claim(
            agent_id="test-agent",
            claim_type=ClaimType.TEST_RESULT,
            claim_content={"return_code": 0, "output_contains": "PASSED"},
            verification_command="echo 'ALL TESTS PASSED' && exit 0"
        )

        assert isinstance(result, VerificationResult)
        assert result.accurate is True
        assert result.new_trust_score > 0.5  # Score should increase
        assert result.evidence_id is not None
        assert result.verification_id is not None

        # Verify agent updated
        await db_session.refresh(agent)
        assert agent.trust_score > 0.5
        assert agent.total_verifications == 1
        assert agent.accurate_verifications == 1

    async def test_verify_claim_inaccurate(self, db_session, mock_memory_service):
        """Test verifying an inaccurate claim"""
        # Create agent
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test",
            trust_score=0.5
        )
        db_session.add(agent)
        await db_session.commit()

        # Create service
        service = VerificationService(
            db_session,
            memory_service=mock_memory_service
        )

        # Verify inaccurate claim
        result = await service.verify_claim(
            agent_id="test-agent",
            claim_type=ClaimType.TEST_RESULT,
            claim_content={"return_code": 0, "output_contains": "ALL PASSED"},
            verification_command="echo 'SOME TESTS FAILED' && exit 1"
        )

        assert result.accurate is False
        assert result.new_trust_score < 0.5  # Score should decrease

        # Verify agent updated
        await db_session.refresh(agent)
        assert agent.trust_score < 0.5
        assert agent.total_verifications == 1
        assert agent.accurate_verifications == 0

    async def test_verify_claim_agent_not_found(self, db_session, mock_memory_service):
        """Test error handling for nonexistent agent"""
        service = VerificationService(
            db_session,
            memory_service=mock_memory_service
        )

        with pytest.raises(AgentNotFoundError):
            await service.verify_claim(
                agent_id="nonexistent",
                claim_type=ClaimType.TEST_RESULT,
                claim_content={"return_code": 0},
                verification_command="exit 0"
            )

    async def test_execute_verification_success(self, db_session):
        """Test successful command execution"""
        service = VerificationService(db_session)

        result = await service._execute_verification(
            command="echo 'test output' && exit 0"
        )

        assert result["return_code"] == 0
        assert "test output" in result["stdout"]
        assert result["stderr"] == ""

    async def test_execute_verification_failure(self, db_session):
        """Test failed command execution"""
        service = VerificationService(db_session)

        result = await service._execute_verification(
            command="echo 'error' >&2 && exit 1"
        )

        assert result["return_code"] == 1
        assert "error" in result["stderr"]

    async def test_execute_verification_timeout(self, db_session):
        """Test command timeout handling"""
        service = VerificationService(db_session)

        with pytest.raises(VerificationError, match="timed out"):
            await service._execute_verification(
                command="sleep 10",
                timeout_seconds=0.1
            )

    async def test_compare_results_return_code(self, db_session):
        """Test result comparison by return code"""
        service = VerificationService(db_session)

        # Matching return code
        assert service._compare_results(
            claim={"return_code": 0},
            actual={"return_code": 0}
        ) is True

        # Non-matching return code
        assert service._compare_results(
            claim={"return_code": 0},
            actual={"return_code": 1}
        ) is False

    async def test_compare_results_output_contains(self, db_session):
        """Test result comparison by output pattern"""
        service = VerificationService(db_session)

        # Single pattern match
        assert service._compare_results(
            claim={"output_contains": "SUCCESS"},
            actual={"stdout": "Test completed: SUCCESS", "return_code": 0}
        ) is True

        # Multiple patterns
        assert service._compare_results(
            claim={"output_contains": ["SUCCESS", "100%"]},
            actual={"stdout": "SUCCESS: 100% coverage", "return_code": 0}
        ) is True

        # Pattern not found
        assert service._compare_results(
            claim={"output_contains": "FAILED"},
            actual={"stdout": "SUCCESS", "return_code": 0}
        ) is False

    async def test_compare_results_metrics(self, db_session):
        """Test result comparison with numeric metrics"""
        service = VerificationService(db_session)

        # Within tolerance (default 5%)
        assert service._compare_results(
            claim={"metrics": {"coverage": 90.0}},
            actual={"metrics": {"coverage": 91.0}}
        ) is True

        # Outside tolerance
        assert service._compare_results(
            claim={"metrics": {"coverage": 90.0}},
            actual={"metrics": {"coverage": 85.0}}
        ) is False

        # Custom tolerance (10%)
        assert service._compare_results(
            claim={"metrics": {"coverage": 90.0}, "tolerance": 0.1},
            actual={"metrics": {"coverage": 85.0}}
        ) is True

    async def test_compare_results_exact_match(self, db_session):
        """Test exact result matching"""
        service = VerificationService(db_session)

        assert service._compare_results(
            claim={"exact_match": {"status": "success", "count": 42}},
            actual={"status": "success", "count": 42}
        ) is True

        assert service._compare_results(
            claim={"exact_match": {"status": "success"}},
            actual={"status": "failure"}
        ) is False

    async def test_create_evidence_memory(self, db_session, mock_memory_service):
        """Test evidence memory creation"""
        # Create agent
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test"
        )
        db_session.add(agent)
        await db_session.commit()

        # Create verification record
        verification_record = VerificationRecord(
            id=uuid4(),
            agent_id="test-agent",
            claim_type=ClaimType.TEST_RESULT.value,
            claim_content={"return_code": 0},
            verification_command="pytest tests/",
            verification_result={"return_code": 0, "stdout": "100% PASSED"},
            accurate=True,
            verified_at=datetime.utcnow()
        )

        service = VerificationService(
            db_session,
            memory_service=mock_memory_service
        )

        # Create evidence
        memory = await service._create_evidence_memory(
            agent_id="test-agent",
            verification_record=verification_record,
            verification_duration_ms=150.5
        )

        assert memory.content is not None
        assert "✅" in memory.content  # Accurate indicator
        assert "pytest tests/" in memory.content
        assert memory.metadata["verification_id"] == str(verification_record.id)
        assert memory.metadata["accurate"] is True

    async def test_format_evidence_accurate(self, db_session):
        """Test evidence formatting for accurate verification"""
        service = VerificationService(db_session)

        verification_record = VerificationRecord(
            id=uuid4(),
            agent_id="test-agent",
            claim_type=ClaimType.TEST_RESULT.value,
            claim_content={"return_code": 0, "output_contains": "PASSED"},
            verification_command="pytest tests/",
            verification_result={
                "return_code": 0,
                "stdout": "Tests: 100 PASSED",
                "stderr": ""
            },
            accurate=True,
            verified_at=datetime.utcnow()
        )

        evidence = service._format_evidence(verification_record, 123.45)

        assert "✅ Verification Result" in evidence
        assert "pytest tests/" in evidence
        assert "Return Code: 0" in evidence
        assert "Duration: 123.45ms" in evidence
        assert "ACCURATE - Claim verified" in evidence

    async def test_format_evidence_inaccurate(self, db_session):
        """Test evidence formatting for inaccurate verification"""
        service = VerificationService(db_session)

        verification_record = VerificationRecord(
            id=uuid4(),
            agent_id="test-agent",
            claim_type=ClaimType.TEST_RESULT.value,
            claim_content={"return_code": 0},
            verification_command="pytest tests/",
            verification_result={
                "return_code": 1,
                "stdout": "Tests: 50 FAILED",
                "stderr": "Errors detected"
            },
            accurate=False,
            verified_at=datetime.utcnow()
        )

        evidence = service._format_evidence(verification_record, 200.0)

        assert "❌ Verification Result" in evidence
        assert "Return Code: 1" in evidence
        assert "INACCURATE - Claim rejected" in evidence
        assert "Errors detected" in evidence

    async def test_get_verification_history(self, db_session, mock_memory_service):
        """Test retrieving verification history"""
        # Create agent
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test"
        )
        db_session.add(agent)

        # Create verification records
        records = [
            VerificationRecord(
                agent_id="test-agent",
                claim_type=ClaimType.TEST_RESULT.value,
                claim_content={"test": i},
                verification_command=f"test-{i}",
                verification_result={"return_code": 0},
                accurate=i % 2 == 0,
                verified_at=datetime.utcnow()
            )
            for i in range(5)
        ]
        db_session.add_all(records)
        await db_session.commit()

        service = VerificationService(
            db_session,
            memory_service=mock_memory_service
        )

        # Get all history
        history = await service.get_verification_history("test-agent")

        assert len(history) == 5
        assert all("claim_type" in record for record in history)
        assert all("accurate" in record for record in history)

    async def test_get_verification_history_filtered(self, db_session, mock_memory_service):
        """Test filtered verification history"""
        # Create agent
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test"
        )
        db_session.add(agent)

        # Create mixed verification records
        records = [
            VerificationRecord(
                agent_id="test-agent",
                claim_type=ClaimType.TEST_RESULT.value,
                claim_content={},
                verification_command="test",
                verification_result={"return_code": 0},
                accurate=True,
                verified_at=datetime.utcnow()
            ),
            VerificationRecord(
                agent_id="test-agent",
                claim_type=ClaimType.SECURITY_FINDING.value,
                claim_content={},
                verification_command="security",
                verification_result={"return_code": 0},
                accurate=True,
                verified_at=datetime.utcnow()
            ),
        ]
        db_session.add_all(records)
        await db_session.commit()

        service = VerificationService(
            db_session,
            memory_service=mock_memory_service
        )

        # Filter by claim type
        history = await service.get_verification_history(
            "test-agent",
            claim_type=ClaimType.TEST_RESULT
        )

        assert len(history) == 1
        assert history[0]["claim_type"] == ClaimType.TEST_RESULT.value

    async def test_get_verification_statistics(self, db_session, mock_memory_service):
        """Test verification statistics calculation"""
        # Create agent
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test",
            trust_score=0.7,
            total_verifications=10,
            accurate_verifications=7
        )
        db_session.add(agent)

        # Create verification records
        records = [
            VerificationRecord(
                agent_id="test-agent",
                claim_type=ClaimType.TEST_RESULT.value,
                claim_content={},
                verification_command="test",
                verification_result={"return_code": 0},
                accurate=True,
                verified_at=datetime.utcnow()
            ),
            VerificationRecord(
                agent_id="test-agent",
                claim_type=ClaimType.TEST_RESULT.value,
                claim_content={},
                verification_command="test",
                verification_result={"return_code": 1},
                accurate=False,
                verified_at=datetime.utcnow()
            ),
            VerificationRecord(
                agent_id="test-agent",
                claim_type=ClaimType.SECURITY_FINDING.value,
                claim_content={},
                verification_command="security",
                verification_result={"return_code": 0},
                accurate=True,
                verified_at=datetime.utcnow()
            ),
        ]
        db_session.add_all(records)
        await db_session.commit()

        service = VerificationService(
            db_session,
            memory_service=mock_memory_service
        )

        # Get statistics
        stats = await service.get_verification_statistics("test-agent")

        assert stats["agent_id"] == "test-agent"
        assert stats["trust_score"] == 0.7
        assert stats["total_verifications"] == 10
        assert stats["accurate_verifications"] == 7
        assert stats["accuracy_rate"] == 0.7
        assert stats["requires_verification"] is False

        # Check by claim type
        assert ClaimType.TEST_RESULT.value in stats["by_claim_type"]
        test_stats = stats["by_claim_type"][ClaimType.TEST_RESULT.value]
        assert test_stats["total"] == 2
        assert test_stats["accurate"] == 1
        assert test_stats["accuracy"] == 0.5

    async def test_performance_verification(self, db_session, mock_memory_service, benchmark):
        """Performance test: verification should be <500ms"""
        # Create agent
        agent = Agent(
            agent_id="perf-agent",
            display_name="Performance Test",
            namespace="test",
            trust_score=0.5
        )
        db_session.add(agent)
        await db_session.commit()

        service = VerificationService(
            db_session,
            memory_service=mock_memory_service
        )

        # Benchmark verification
        async def verify():
            return await service.verify_claim(
                agent_id="perf-agent",
                claim_type=ClaimType.TEST_RESULT,
                claim_content={"return_code": 0},
                verification_command="exit 0"
            )

        result = await benchmark(verify)
        assert result.accurate is True

        # Target: <500ms P95 (checked by benchmark fixture)


class TestClaimType:
    """Test ClaimType enum"""

    def test_claim_types(self):
        """Test all claim types are defined"""
        assert ClaimType.TEST_RESULT == "test_result"
        assert ClaimType.PERFORMANCE_METRIC == "performance_metric"
        assert ClaimType.CODE_QUALITY == "code_quality"
        assert ClaimType.SECURITY_FINDING == "security_finding"
        assert ClaimType.DEPLOYMENT_STATUS == "deployment_status"
        assert ClaimType.CUSTOM == "custom"


class TestVerificationResult:
    """Test VerificationResult data class"""

    def test_verification_result_to_dict(self):
        """Test VerificationResult dictionary conversion"""
        claim = {"return_code": 0}
        actual = {"return_code": 0, "stdout": "success"}
        evidence_id = uuid4()
        verification_id = uuid4()

        result = VerificationResult(
            claim=claim,
            actual=actual,
            accurate=True,
            evidence_id=evidence_id,
            verification_id=verification_id,
            new_trust_score=0.55
        )

        result_dict = result.to_dict()

        assert result_dict["claim"] == claim
        assert result_dict["actual"] == actual
        assert result_dict["accurate"] is True
        assert result_dict["evidence_id"] == str(evidence_id)
        assert result_dict["verification_id"] == str(verification_id)
        assert result_dict["new_trust_score"] == 0.55


# Fixtures for testing

@pytest.fixture
def mock_memory_service():
    """Mock memory service for testing"""
    class MockMemoryService:
        async def create_memory(self, **kwargs):
            """Mock memory creation"""
            # Match HybridMemoryService signature
            return Memory(
                id=uuid4(),
                content=kwargs.get("content", ""),
                agent_id=kwargs.get("agent_id", ""),
                namespace=kwargs.get("namespace", "test"),
                importance=kwargs.get("importance_score", 0.5),
                metadata_json=json.dumps(kwargs.get("context", {}))
            )

    return MockMemoryService()
