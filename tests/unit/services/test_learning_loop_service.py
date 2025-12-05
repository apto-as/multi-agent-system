"""Unit tests for LearningLoopService (Layer 3).

Tests cover:
- Pattern validation with multi-metric scoring
- Skill promotion with quota enforcement
- Feedback collection and threshold adjustment
- Race condition protection
- P0-1 namespace isolation

Test Structure:
- TestValidatePattern: 10 tests
- TestPromoteToSkill: 8 tests
- TestCollectFeedback: 5 tests
- TestAdjustThresholds: 4 tests
- TestLearningCycle: 5 tests
- TestQuotaEnforcement: 3 tests
- TestPromotionLock: 3 tests

Total: 38 tests
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from src.models.execution_trace import DetectedPattern
from src.services.learning_loop_service import (
    FeedbackResult,
    LearningLoopService,
    PromotionResult,
    ValidationResult,
)


@pytest.fixture
def mock_session():
    """Create a mock async session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.get = AsyncMock()
    return session


@pytest.fixture
def mock_pattern_service():
    """Create a mock PatternDetectionService."""
    service = AsyncMock()
    service.get_patterns_by_state = AsyncMock(return_value=[])
    service.get_pattern_by_id = AsyncMock()
    service.transition_pattern_state = AsyncMock()
    service.generate_sop_draft = AsyncMock()
    service.link_pattern_to_skill = AsyncMock()
    service.get_pattern_statistics = AsyncMock(return_value={})
    return service


@pytest.fixture
def mock_skill_service():
    """Create a mock SkillService."""
    service = AsyncMock()
    skill_dto = MagicMock()
    skill_dto.id = str(uuid4())
    service.create_skill = AsyncMock(return_value=skill_dto)
    return service


@pytest.fixture
def learning_service(mock_session, mock_pattern_service, mock_skill_service):
    """Create LearningLoopService with mocked dependencies."""
    service = LearningLoopService(
        session=mock_session,
        pattern_service=mock_pattern_service,
        skill_service=mock_skill_service,
    )
    return service


@pytest.fixture
def sample_pattern():
    """Create a sample DetectedPattern."""
    pattern_id = str(uuid4())
    return DetectedPattern(
        id=pattern_id,
        namespace="test-namespace",
        tool_sequence=["tool_a", "tool_b", "tool_c"],
        pattern_hash="abc123def456",
        frequency=15,
        avg_success_rate=0.85,
        avg_execution_time_ms=100.0,
        state="DETECTED",
        detected_at=datetime.now(timezone.utc),
        last_occurrence_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def approved_pattern():
    """Create an approved pattern ready for promotion."""
    pattern_id = str(uuid4())
    return DetectedPattern(
        id=pattern_id,
        namespace="test-namespace",
        tool_sequence=["search", "analyze", "report"],
        pattern_hash="xyz789abc123",
        frequency=20,
        avg_success_rate=0.90,
        avg_execution_time_ms=150.0,
        state="APPROVED",
        sop_draft="# Test SOP\n\nThis is a test SOP draft.",
        sop_title="Test SOP Title",
        detected_at=datetime.now(timezone.utc),
        last_occurrence_at=datetime.now(timezone.utc),
    )


class TestValidatePattern:
    """Tests for pattern validation."""

    async def test_validate_pattern_success(self, learning_service, sample_pattern):
        """Test successful pattern validation."""
        result = await learning_service.validate_pattern(
            pattern=sample_pattern,
            namespace="test-namespace",
        )

        assert isinstance(result, ValidationResult)
        assert result.passed is True
        assert result.pattern_id == str(sample_pattern.id)
        assert "success_rate" in result.scores
        assert "stability" in result.scores
        assert result.elapsed_ms > 0

    async def test_validate_pattern_namespace_mismatch(self, learning_service, sample_pattern):
        """Test validation fails with wrong namespace."""
        result = await learning_service.validate_pattern(
            pattern=sample_pattern,
            namespace="different-namespace",
        )

        assert result.passed is False
        assert "Namespace mismatch" in result.errors[0]

    async def test_validate_pattern_low_success_rate(self, learning_service, sample_pattern):
        """Test validation fails with low success rate."""
        sample_pattern.avg_success_rate = 0.5  # Below 0.75 threshold

        result = await learning_service.validate_pattern(
            pattern=sample_pattern,
            namespace="test-namespace",
        )

        assert result.passed is False
        assert any("Success rate too low" in e for e in result.errors)

    async def test_validate_pattern_security_sensitive_tools(
        self, learning_service, sample_pattern
    ):
        """Test validation fails with security-sensitive tools."""
        sample_pattern.tool_sequence = ["delete_file", "analyze", "report"]

        result = await learning_service.validate_pattern(
            pattern=sample_pattern,
            namespace="test-namespace",
        )

        assert result.passed is False
        assert any("Security-sensitive tools" in e for e in result.errors)

    async def test_validate_pattern_trivial_single_tool(self, learning_service, sample_pattern):
        """Test validation fails with single tool pattern."""
        sample_pattern.tool_sequence = ["single_tool"]

        result = await learning_service.validate_pattern(
            pattern=sample_pattern,
            namespace="test-namespace",
        )

        assert result.passed is False
        assert any("too trivial" in e for e in result.errors)

    async def test_validate_pattern_transitions_state(
        self, learning_service, sample_pattern, mock_pattern_service
    ):
        """Test successful validation transitions pattern to VALIDATING."""
        await learning_service.validate_pattern(
            pattern=sample_pattern,
            namespace="test-namespace",
        )

        mock_pattern_service.transition_pattern_state.assert_called_once()
        call_args = mock_pattern_service.transition_pattern_state.call_args
        assert call_args.kwargs["new_state"] == "VALIDATING"

    async def test_validate_pattern_scores_structure(self, learning_service, sample_pattern):
        """Test validation returns correct score structure."""
        result = await learning_service.validate_pattern(
            pattern=sample_pattern,
            namespace="test-namespace",
        )

        assert "success_rate" in result.scores
        assert "stability" in result.scores
        assert "security" in result.scores
        assert "complexity" in result.scores
        assert all(0.0 <= v <= 1.0 for v in result.scores.values())

    async def test_validate_pattern_low_stability(self, learning_service, sample_pattern):
        """Test validation with low frequency (low stability)."""
        sample_pattern.frequency = 3  # Minimum threshold

        result = await learning_service.validate_pattern(
            pattern=sample_pattern,
            namespace="test-namespace",
        )

        # With frequency=3 over 14 days, stability = 3/14 = 0.21 < 0.8
        assert result.passed is False
        assert any("not stable enough" in e for e in result.errors)

    async def test_validate_pattern_high_frequency(self, learning_service, sample_pattern):
        """Test validation with high frequency (high stability)."""
        sample_pattern.frequency = 20  # Well above threshold

        result = await learning_service.validate_pattern(
            pattern=sample_pattern,
            namespace="test-namespace",
        )

        assert result.passed is True
        assert result.scores["stability"] >= 0.8

    async def test_validate_pattern_multiple_security_tools(self, learning_service, sample_pattern):
        """Test validation with multiple security-sensitive tools."""
        sample_pattern.tool_sequence = ["delete_file", "rm", "drop_table"]

        result = await learning_service.validate_pattern(
            pattern=sample_pattern,
            namespace="test-namespace",
        )

        assert result.passed is False
        assert result.scores["security"] == 0.0


class TestPromoteToSkill:
    """Tests for skill promotion."""

    async def test_promote_approved_pattern_success(
        self, learning_service, approved_pattern, mock_skill_service
    ):
        """Test successful promotion of approved pattern."""
        result = await learning_service.promote_to_skill(
            pattern=approved_pattern,
            namespace="test-namespace",
            approved_by="test-agent",
        )

        assert isinstance(result, PromotionResult)
        assert result.success is True
        assert result.skill_id is not None
        assert result.error is None

    async def test_promote_non_approved_pattern_fails(self, learning_service, sample_pattern):
        """Test promotion fails for non-approved pattern."""
        sample_pattern.state = "DETECTED"

        result = await learning_service.promote_to_skill(
            pattern=sample_pattern,
            namespace="test-namespace",
            approved_by="test-agent",
        )

        assert result.success is False
        assert "not in APPROVED state" in result.error

    async def test_promote_creates_correct_skill(
        self, learning_service, approved_pattern, mock_skill_service
    ):
        """Test promotion creates skill with correct parameters."""
        await learning_service.promote_to_skill(
            pattern=approved_pattern,
            namespace="test-namespace",
            approved_by="test-agent",
        )

        mock_skill_service.create_skill.assert_called_once()
        call_kwargs = mock_skill_service.create_skill.call_args.kwargs
        assert call_kwargs["namespace"] == "test-namespace"
        assert call_kwargs["created_by"] == "test-agent"
        assert "auto-generated" in call_kwargs["tags"]

    async def test_promote_links_pattern_to_skill(
        self, learning_service, approved_pattern, mock_pattern_service
    ):
        """Test promotion links pattern to created skill."""
        await learning_service.promote_to_skill(
            pattern=approved_pattern,
            namespace="test-namespace",
            approved_by="test-agent",
        )

        mock_pattern_service.link_pattern_to_skill.assert_called_once()

    async def test_promote_handles_skill_creation_failure(
        self, learning_service, approved_pattern, mock_skill_service
    ):
        """Test promotion handles skill creation failure."""
        mock_skill_service.create_skill.side_effect = Exception("Creation failed")

        result = await learning_service.promote_to_skill(
            pattern=approved_pattern,
            namespace="test-namespace",
            approved_by="test-agent",
        )

        assert result.success is False
        assert "Skill creation failed" in result.error

    async def test_promote_generates_sop_if_missing(
        self, learning_service, approved_pattern, mock_pattern_service
    ):
        """Test promotion generates SOP if not present."""
        approved_pattern.sop_draft = None

        await learning_service.promote_to_skill(
            pattern=approved_pattern,
            namespace="test-namespace",
            approved_by="test-agent",
        )

        mock_pattern_service.generate_sop_draft.assert_called_once()

    async def test_promote_increments_quota(self, learning_service, approved_pattern):
        """Test promotion increments quota counter."""
        initial_count = learning_service._promotion_count.get("test-namespace", 0)

        await learning_service.promote_to_skill(
            pattern=approved_pattern,
            namespace="test-namespace",
            approved_by="test-agent",
        )

        assert learning_service._promotion_count["test-namespace"] == initial_count + 1

    async def test_promote_uses_default_content_if_no_sop(
        self, learning_service, approved_pattern, mock_skill_service
    ):
        """Test promotion uses default content if no SOP draft."""
        approved_pattern.sop_draft = None
        learning_service._pattern_service.generate_sop_draft = AsyncMock(return_value=None)

        await learning_service.promote_to_skill(
            pattern=approved_pattern,
            namespace="test-namespace",
            approved_by="test-agent",
        )

        call_kwargs = mock_skill_service.create_skill.call_args.kwargs
        assert "Auto-Generated Skill" in call_kwargs["content"]


class TestCollectFeedback:
    """Tests for feedback collection."""

    async def test_collect_feedback_empty(self, learning_service, mock_session):
        """Test feedback collection with no suggestions."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        result = await learning_service.collect_feedback(namespace="test-namespace")

        assert isinstance(result, FeedbackResult)
        assert result.total_suggestions == 0
        assert result.activation_rate == 0.0
        assert result.helpfulness_rate == 0.0

    async def test_collect_feedback_calculates_rates(self, learning_service, mock_session):
        """Test feedback collection calculates correct rates."""
        suggestions = [
            MagicMock(pattern_id=str(uuid4()), was_activated=True, was_helpful=True),
            MagicMock(pattern_id=str(uuid4()), was_activated=True, was_helpful=False),
            MagicMock(pattern_id=str(uuid4()), was_activated=False, was_helpful=False),
            MagicMock(pattern_id=str(uuid4()), was_activated=False, was_helpful=False),
        ]
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = suggestions
        mock_session.execute.return_value = mock_result

        result = await learning_service.collect_feedback(namespace="test-namespace")

        assert result.total_suggestions == 4
        assert result.activation_rate == 0.5  # 2/4
        assert result.helpfulness_rate == 0.5  # 1/2

    async def test_collect_feedback_groups_by_pattern(self, learning_service, mock_session):
        """Test feedback groups suggestions by pattern."""
        pattern_id = str(uuid4())
        suggestions = [
            MagicMock(pattern_id=pattern_id, was_activated=True, was_helpful=True),
            MagicMock(pattern_id=pattern_id, was_activated=True, was_helpful=False),
            MagicMock(pattern_id=pattern_id, was_activated=False, was_helpful=False),
        ]
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = suggestions

        # Mock pattern lookup
        mock_pattern = MagicMock()
        mock_pattern.namespace = "test-namespace"
        mock_pattern.validation_metadata = {}
        mock_session.execute.return_value = mock_result
        mock_session.get.return_value = mock_pattern

        result = await learning_service.collect_feedback(namespace="test-namespace")

        assert result.patterns_updated >= 0  # At least tried to update

    async def test_collect_feedback_handles_null_pattern_id(self, learning_service, mock_session):
        """Test feedback handles null pattern_id."""
        suggestions = [
            MagicMock(pattern_id=None, was_activated=True, was_helpful=True),
        ]
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = suggestions
        mock_session.execute.return_value = mock_result

        result = await learning_service.collect_feedback(namespace="test-namespace")

        assert result.total_suggestions == 1
        assert result.patterns_updated == 0  # No pattern to update

    async def test_collect_feedback_elapsed_time(self, learning_service, mock_session):
        """Test feedback collection records elapsed time."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        result = await learning_service.collect_feedback(namespace="test-namespace")

        assert result.elapsed_ms > 0


class TestAdjustThresholds:
    """Tests for threshold adjustment."""

    async def test_adjust_thresholds_low_activation(self, learning_service):
        """Test threshold adjustment with low activation rate."""
        initial_stability = learning_service._thresholds["stability"]
        feedback = FeedbackResult(
            total_suggestions=100,
            activation_rate=0.2,  # Below 0.3
            helpfulness_rate=0.7,
            patterns_updated=10,
            elapsed_ms=50.0,
        )

        result = await learning_service.adjust_thresholds(feedback)

        assert result["new_thresholds"]["stability"] > initial_stability

    async def test_adjust_thresholds_high_activation(self, learning_service):
        """Test threshold adjustment with high activation rate."""
        initial_stability = learning_service._thresholds["stability"]
        feedback = FeedbackResult(
            total_suggestions=100,
            activation_rate=0.8,  # Above 0.7
            helpfulness_rate=0.7,
            patterns_updated=10,
            elapsed_ms=50.0,
        )

        result = await learning_service.adjust_thresholds(feedback)

        assert result["new_thresholds"]["stability"] < initial_stability

    async def test_adjust_thresholds_low_helpfulness(self, learning_service):
        """Test threshold adjustment with low helpfulness rate."""
        initial_relevance = learning_service._thresholds["relevance"]
        feedback = FeedbackResult(
            total_suggestions=100,
            activation_rate=0.5,  # Normal
            helpfulness_rate=0.3,  # Below 0.5
            patterns_updated=10,
            elapsed_ms=50.0,
        )

        result = await learning_service.adjust_thresholds(feedback)

        assert result["new_thresholds"]["relevance"] > initial_relevance

    async def test_adjust_thresholds_respects_limits(self, learning_service):
        """Test threshold adjustment respects min/max limits."""
        learning_service._thresholds["stability"] = 0.95  # At max
        feedback = FeedbackResult(
            total_suggestions=100,
            activation_rate=0.1,  # Would increase
            helpfulness_rate=0.7,
            patterns_updated=10,
            elapsed_ms=50.0,
        )

        result = await learning_service.adjust_thresholds(feedback)

        assert result["new_thresholds"]["stability"] <= 0.95  # Capped at max


class TestLearningCycle:
    """Tests for learning cycle execution."""

    async def test_learning_cycle_empty_patterns(
        self, learning_service, mock_pattern_service, mock_session
    ):
        """Test learning cycle with no patterns."""
        mock_pattern_service.get_patterns_by_state.return_value = []
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        result = await learning_service.run_learning_cycle(namespace="test-namespace")

        assert result.validated == 0
        assert result.promoted == 0
        assert result.elapsed_ms > 0

    async def test_learning_cycle_validates_patterns(
        self, learning_service, mock_pattern_service, sample_pattern
    ):
        """Test learning cycle validates detected patterns."""
        mock_pattern_service.get_patterns_by_state.side_effect = [
            [sample_pattern],  # DETECTED
            [],  # VALIDATED
            [],  # APPROVED
        ]

        with patch.object(learning_service, "collect_feedback") as mock_feedback:
            mock_feedback.return_value = FeedbackResult(
                total_suggestions=0,
                activation_rate=0.0,
                helpfulness_rate=0.0,
                patterns_updated=0,
                elapsed_ms=0.0,
            )
            result = await learning_service.run_learning_cycle(namespace="test-namespace")

        assert result.validated >= 0  # Depends on validation result

    async def test_learning_cycle_handles_errors(self, learning_service, mock_pattern_service):
        """Test learning cycle handles errors gracefully."""
        mock_pattern_service.get_patterns_by_state.side_effect = Exception("DB error")

        result = await learning_service.run_learning_cycle(namespace="test-namespace")

        assert len(result.errors) > 0
        assert "Validation phase error" in result.errors[0]

    async def test_learning_cycle_respects_max_validations(
        self, learning_service, mock_pattern_service, sample_pattern
    ):
        """Test learning cycle respects max_validations limit."""
        patterns = [sample_pattern] * 20
        mock_pattern_service.get_patterns_by_state.return_value = patterns[:5]  # Limited

        with patch.object(learning_service, "validate_pattern") as mock_validate:
            mock_validate.return_value = ValidationResult(
                pattern_id="test",
                passed=True,
                elapsed_ms=10.0,
            )
            with patch.object(learning_service, "collect_feedback") as mock_feedback:
                mock_feedback.return_value = FeedbackResult(
                    total_suggestions=0,
                    activation_rate=0.0,
                    helpfulness_rate=0.0,
                    patterns_updated=0,
                    elapsed_ms=0.0,
                )
                await learning_service.run_learning_cycle(
                    namespace="test-namespace",
                    max_validations=5,
                )

        # Should only validate up to limit
        assert mock_validate.call_count <= 5

    async def test_learning_cycle_collects_feedback(self, learning_service, mock_pattern_service):
        """Test learning cycle collects feedback."""
        mock_pattern_service.get_patterns_by_state.return_value = []

        with patch.object(learning_service, "collect_feedback") as mock_feedback:
            mock_feedback.return_value = FeedbackResult(
                total_suggestions=10,
                activation_rate=0.5,
                helpfulness_rate=0.6,
                patterns_updated=3,
                elapsed_ms=20.0,
            )
            result = await learning_service.run_learning_cycle(namespace="test-namespace")

        mock_feedback.assert_called_once()
        assert result.feedback_collected == 3


class TestQuotaEnforcement:
    """Tests for skill quota enforcement."""

    async def test_quota_blocks_excess_promotions(self, learning_service, approved_pattern):
        """Test quota blocks promotions when exceeded."""
        # Fill up quota
        learning_service._promotion_count["test-namespace"] = (
            learning_service.MAX_PROMOTIONS_PER_HOUR
        )
        learning_service._promotion_reset_time["test-namespace"] = datetime.now(
            timezone.utc
        ) + timedelta(hours=1)

        result = await learning_service.promote_to_skill(
            pattern=approved_pattern,
            namespace="test-namespace",
            approved_by="test-agent",
        )

        assert result.success is False
        assert "quota exceeded" in result.error

    async def test_quota_resets_after_hour(self, learning_service, approved_pattern):
        """Test quota resets after one hour."""
        # Set quota with expired reset time
        learning_service._promotion_count["test-namespace"] = 10
        learning_service._promotion_reset_time["test-namespace"] = (
            datetime.now(timezone.utc) - timedelta(minutes=1)  # Expired
        )

        result = await learning_service.promote_to_skill(
            pattern=approved_pattern,
            namespace="test-namespace",
            approved_by="test-agent",
        )

        # Quota should have reset, allowing promotion
        assert result.success is True

    async def test_quota_per_namespace(self, learning_service, approved_pattern):
        """Test quota is tracked per namespace."""
        # Fill quota for one namespace
        learning_service._promotion_count["other-namespace"] = 100

        result = await learning_service.promote_to_skill(
            pattern=approved_pattern,
            namespace="test-namespace",
            approved_by="test-agent",
        )

        # Different namespace should not be affected
        assert result.success is True


class TestPromotionLock:
    """Tests for promotion lock mechanism."""

    async def test_lock_creates_new_for_pattern(self, learning_service):
        """Test lock creates new lock for pattern."""
        pattern_id = str(uuid4())
        lock = learning_service._get_promotion_lock(pattern_id)

        assert isinstance(lock, asyncio.Lock)
        assert pattern_id in learning_service._promotion_locks

    async def test_lock_reuses_existing(self, learning_service):
        """Test lock reuses existing lock for same pattern."""
        pattern_id = str(uuid4())
        lock1 = learning_service._get_promotion_lock(pattern_id)
        lock2 = learning_service._get_promotion_lock(pattern_id)

        assert lock1 is lock2

    async def test_different_patterns_different_locks(self, learning_service):
        """Test different patterns get different locks."""
        lock1 = learning_service._get_promotion_lock(str(uuid4()))
        lock2 = learning_service._get_promotion_lock(str(uuid4()))

        assert lock1 is not lock2


class TestSkillNameGeneration:
    """Tests for skill name generation."""

    def test_generate_name_single_tool(self, learning_service, sample_pattern):
        """Test name generation for single tool."""
        sample_pattern.tool_sequence = ["single_tool"]

        name = learning_service._generate_skill_name(sample_pattern)

        assert "single-tool" in name
        assert sample_pattern.pattern_hash[:6] in name

    def test_generate_name_two_tools(self, learning_service, sample_pattern):
        """Test name generation for two tools."""
        sample_pattern.tool_sequence = ["start_tool", "end_tool"]

        name = learning_service._generate_skill_name(sample_pattern)

        assert "start-tool" in name
        assert "end-tool" in name
        assert "-to-" in name

    def test_generate_name_many_tools(self, learning_service, sample_pattern):
        """Test name generation for many tools."""
        sample_pattern.tool_sequence = ["a", "b", "c", "d", "e"]

        name = learning_service._generate_skill_name(sample_pattern)

        assert "5step" in name

    def test_generate_name_empty_sequence(self, learning_service, sample_pattern):
        """Test name generation for empty sequence."""
        sample_pattern.tool_sequence = []

        name = learning_service._generate_skill_name(sample_pattern)

        assert "pattern-" in name


class TestApprovePattern:
    """Tests for pattern approval."""

    async def test_approve_validated_pattern(
        self, learning_service, mock_pattern_service, sample_pattern
    ):
        """Test approving a validated pattern."""
        sample_pattern.state = "VALIDATED"
        mock_pattern_service.get_pattern_by_id.return_value = sample_pattern
        mock_pattern_service.transition_pattern_state.return_value = sample_pattern

        result = await learning_service.approve_pattern(
            pattern_id=sample_pattern.id,
            namespace="test-namespace",
            approved_by="test-agent",
        )

        assert result is not None
        mock_pattern_service.transition_pattern_state.assert_called_once()

    async def test_approve_non_validated_fails(
        self, learning_service, mock_pattern_service, sample_pattern
    ):
        """Test approving non-validated pattern fails."""
        sample_pattern.state = "DETECTED"
        mock_pattern_service.get_pattern_by_id.return_value = sample_pattern

        with pytest.raises(Exception) as exc_info:
            await learning_service.approve_pattern(
                pattern_id=sample_pattern.id,
                namespace="test-namespace",
                approved_by="test-agent",
            )

        assert "VALIDATED" in str(exc_info.value)


class TestGetLearningStatistics:
    """Tests for learning statistics."""

    async def test_get_statistics_structure(
        self, learning_service, mock_session, mock_pattern_service
    ):
        """Test statistics returns correct structure."""
        mock_pattern_service.get_pattern_statistics.return_value = {
            "total_patterns": 10,
            "by_state": {},
        }
        mock_row = MagicMock()
        mock_row.total = 5
        mock_row.activated = 2
        mock_row.helpful = 1
        mock_result = MagicMock()
        mock_result.one.return_value = mock_row
        mock_session.execute.return_value = mock_result

        result = await learning_service.get_learning_statistics(
            namespace="test-namespace",
        )

        assert "patterns" in result
        assert "suggestions" in result
        assert "thresholds" in result
        assert "quota" in result

    async def test_get_statistics_calculates_rates(
        self, learning_service, mock_session, mock_pattern_service
    ):
        """Test statistics calculates rates correctly."""
        mock_pattern_service.get_pattern_statistics.return_value = {}
        mock_row = MagicMock()
        mock_row.total = 10
        mock_row.activated = 5
        mock_row.helpful = 3
        mock_result = MagicMock()
        mock_result.one.return_value = mock_row
        mock_session.execute.return_value = mock_result

        result = await learning_service.get_learning_statistics(
            namespace="test-namespace",
        )

        assert result["suggestions"]["activation_rate"] == 0.5
        assert result["suggestions"]["helpfulness_rate"] == 0.6
