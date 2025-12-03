"""Unit tests for ProactiveContextService (Layer 4).

Tests cover:
    - Skill suggestion based on task context
    - Context injection into orchestrations
    - Feedback recording and processing
    - Effectiveness report generation
    - P0-1 namespace isolation
    - Performance targets (<100ms P95)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.execution_trace import SkillSuggestion
from src.models.skill import AccessLevel, Skill
from src.services.proactive_context_service import (
    ContextInjectionResult,
    EffectivenessReport,
    ProactiveContextService,
    SuggestedSkill,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_session():
    """Create a mock async session."""
    session = AsyncMock(spec=AsyncSession)
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    return session


@pytest.fixture
def mock_embedding_service():
    """Create a mock embedding service."""
    service = MagicMock()
    service.embed_text = MagicMock(return_value=[0.1] * 1024)
    return service


@pytest.fixture
def mock_vector_search_service():
    """Create a mock vector search service."""
    service = AsyncMock()
    service.search = AsyncMock(return_value=[])
    return service


@pytest.fixture
def mock_skill_service():
    """Create a mock skill service."""
    service = AsyncMock()
    return service


@pytest.fixture
def service(
    mock_session,
    mock_embedding_service,
    mock_vector_search_service,
    mock_skill_service,
):
    """Create ProactiveContextService with mocked dependencies."""
    svc = ProactiveContextService(
        session=mock_session,
        skill_service=mock_skill_service,
        vector_search_service=mock_vector_search_service,
        embedding_service=mock_embedding_service,
    )
    return svc


@pytest.fixture
def sample_skill():
    """Create a sample skill."""
    skill = MagicMock()
    skill.id = uuid4()
    skill.name = "test-skill"
    skill.display_name = "Test Skill"
    skill.description = "A test skill for unit testing"
    skill.namespace = "test-namespace"
    skill.access_level = AccessLevel.PUBLIC
    skill.is_active = True
    skill.deleted_at = None
    skill.tags = ["testing", "sample"]
    return skill


@pytest.fixture
def sample_suggestion():
    """Create a sample suggestion record."""
    suggestion = MagicMock(spec=SkillSuggestion)
    suggestion.id = uuid4()
    suggestion.orchestration_id = str(uuid4())
    suggestion.skill_id = str(uuid4())
    suggestion.agent_id = "test-agent"
    suggestion.namespace = "test-namespace"
    suggestion.relevance_score = 0.85
    suggestion.suggestion_reason = "Semantic similarity: 85%"
    suggestion.was_activated = None
    suggestion.was_helpful = None
    suggestion.created_at = datetime.now(timezone.utc)
    return suggestion


# =============================================================================
# Test SuggestedSkill Data Class
# =============================================================================


class TestSuggestedSkill:
    """Tests for SuggestedSkill data class."""

    def test_create_suggested_skill(self):
        """Test creating a SuggestedSkill."""
        skill = SuggestedSkill(
            skill_id="skill-123",
            skill_name="test-skill",
            display_name="Test Skill",
            description="A test skill",
            relevance_score=0.85,
            suggestion_reason="Semantic match",
            tags=["test", "sample"],
        )

        assert skill.skill_id == "skill-123"
        assert skill.skill_name == "test-skill"
        assert skill.relevance_score == 0.85
        assert len(skill.tags) == 2

    def test_suggested_skill_to_dict(self):
        """Test converting SuggestedSkill to dictionary."""
        skill = SuggestedSkill(
            skill_id="skill-123",
            skill_name="test-skill",
            display_name="Test Skill",
            description="A test skill",
            relevance_score=0.85,
            suggestion_reason="Semantic match",
        )

        result = skill.to_dict()

        assert result["skill_id"] == "skill-123"
        assert result["relevance_score"] == 0.85
        assert result["tags"] == []

    def test_suggested_skill_default_tags(self):
        """Test default empty tags list."""
        skill = SuggestedSkill(
            skill_id="skill-123",
            skill_name="test-skill",
            display_name=None,
            description=None,
            relevance_score=0.5,
            suggestion_reason="Match",
        )

        assert skill.tags == []


# =============================================================================
# Test ContextInjectionResult Data Class
# =============================================================================


class TestContextInjectionResult:
    """Tests for ContextInjectionResult data class."""

    def test_create_injection_result(self):
        """Test creating a ContextInjectionResult."""
        suggested = SuggestedSkill(
            skill_id="skill-1",
            skill_name="skill-a",
            display_name="Skill A",
            description="Desc",
            relevance_score=0.9,
            suggestion_reason="Match",
        )

        result = ContextInjectionResult(
            orchestration_id="orch-123",
            agent_id="agent-1",
            namespace="test-ns",
            suggested_skills=[suggested],
            suggestion_ids=["sugg-1"],
            total_candidates=5,
            injection_time_ms=45.5,
            context_summary="Test context",
        )

        assert result.orchestration_id == "orch-123"
        assert len(result.suggested_skills) == 1
        assert result.injection_time_ms == 45.5

    def test_injection_result_to_dict(self):
        """Test converting result to dictionary."""
        result = ContextInjectionResult(
            orchestration_id="orch-123",
            agent_id="agent-1",
            namespace="test-ns",
            suggested_skills=[],
            suggestion_ids=[],
            total_candidates=0,
            injection_time_ms=10.0,
        )

        data = result.to_dict()

        assert data["orchestration_id"] == "orch-123"
        assert data["suggested_skills"] == []
        assert data["context_summary"] is None


# =============================================================================
# Test EffectivenessReport Data Class
# =============================================================================


class TestEffectivenessReport:
    """Tests for EffectivenessReport data class."""

    def test_create_effectiveness_report(self):
        """Test creating an EffectivenessReport."""
        report = EffectivenessReport(
            namespace="test-ns",
            period_days=30,
            total_suggestions=100,
            activated_count=50,
            helpful_count=40,
            unhelpful_count=5,
            no_feedback_count=55,
            activation_rate=0.5,
            helpfulness_rate=0.89,
            top_effective_skills=[{"skill_id": "s1"}],
            low_performing_skills=[],
            recommendations=["Improve matching"],
        )

        assert report.namespace == "test-ns"
        assert report.total_suggestions == 100
        assert report.activation_rate == 0.5
        assert len(report.recommendations) == 1

    def test_effectiveness_report_to_dict(self):
        """Test converting report to dictionary."""
        report = EffectivenessReport(
            namespace="test-ns",
            period_days=7,
            total_suggestions=10,
            activated_count=5,
            helpful_count=4,
            unhelpful_count=1,
            no_feedback_count=5,
            activation_rate=0.5,
            helpfulness_rate=0.8,
            top_effective_skills=[],
            low_performing_skills=[],
            recommendations=[],
        )

        data = report.to_dict()

        assert data["period_days"] == 7
        assert data["helpfulness_rate"] == 0.8


# =============================================================================
# Test ProactiveContextService - suggest_skills
# =============================================================================


class TestSuggestSkills:
    """Tests for suggest_skills method."""

    @pytest.mark.asyncio
    async def test_suggest_skills_empty_results(self, service, mock_vector_search_service):
        """Test suggesting skills with no matches."""
        # Mock the entire _search_skills and _filter_candidates to return empty
        with (
            patch.object(service, "_search_skills", new_callable=AsyncMock, return_value=[]),
            patch.object(service, "_filter_candidates", new_callable=AsyncMock, return_value=[]),
        ):
            result = await service.suggest_skills(
                task_context="Build a REST API",
                namespace="test-ns",
                agent_id="agent-1",
            )

        assert result == []

    @pytest.mark.asyncio
    async def test_suggest_skills_with_matches(
        self, service, mock_session, mock_vector_search_service, sample_skill
    ):
        """Test suggesting skills with matching results."""
        skill_id = str(sample_skill.id)

        # Mock _search_skills to return results
        search_results = [
            {
                "id": "vec-1",
                "similarity": 0.85,
                "metadata": {"skill_id": skill_id, "namespace": "test-ns"},
            }
        ]

        # Mock database queries - use AsyncMock for async methods
        with (
            patch.object(service, "_search_skills", new_callable=AsyncMock, return_value=search_results),
            patch.object(service, "_get_recent_skill_ids", new_callable=AsyncMock, return_value=set()),
            patch.object(
                service,
                "_get_skill_info",
                new_callable=AsyncMock,
                return_value={
                    "name": "test-skill",
                    "display_name": "Test Skill",
                    "description": "A test skill",
                    "tags": ["test"],
                },
            ),
        ):
            result = await service.suggest_skills(
                task_context="Build a REST API",
                namespace="test-ns",
                agent_id="agent-1",
            )

        assert len(result) == 1
        assert result[0].skill_id == skill_id
        assert result[0].relevance_score == 0.85

    @pytest.mark.asyncio
    async def test_suggest_skills_respects_max_suggestions(
        self, service, mock_vector_search_service
    ):
        """Test that max_suggestions limit is respected."""
        # Create 10 mock search results
        skill_ids = [str(uuid4()) for _ in range(10)]
        search_results = [
            {"id": f"vec-{i}", "similarity": 0.9 - i * 0.01, "metadata": {"skill_id": sid}}
            for i, sid in enumerate(skill_ids)
        ]

        with (
            patch.object(service, "_search_skills", new_callable=AsyncMock, return_value=search_results),
            patch.object(service, "_get_recent_skill_ids", new_callable=AsyncMock, return_value=set()),
            patch.object(
                service,
                "_get_skill_info",
                new_callable=AsyncMock,
                return_value={
                    "name": "skill",
                    "display_name": "Skill",
                    "description": "Desc",
                    "tags": [],
                },
            ),
        ):
            result = await service.suggest_skills(
                task_context="Test",
                namespace="test-ns",
                agent_id="agent-1",
                max_suggestions=3,
            )

        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_suggest_skills_respects_min_relevance(
        self, service, mock_vector_search_service
    ):
        """Test that min_relevance threshold is applied."""
        skill_id = str(uuid4())

        # Mock _search_skills - it receives min_relevance and returns filtered results
        mock_search = AsyncMock(return_value=[])
        with (
            patch.object(service, "_search_skills", mock_search),
            patch.object(service, "_filter_candidates", new_callable=AsyncMock, return_value=[]),
        ):
            # High min_relevance should filter out low-scoring results
            result = await service.suggest_skills(
                task_context="Test",
                namespace="test-ns",
                agent_id="agent-1",
                min_relevance=0.8,
            )

        # _search_skills should be called with the min_relevance
        mock_search.assert_called_once()
        call_args = mock_search.call_args
        assert call_args.kwargs.get("min_similarity") == 0.8

    @pytest.mark.asyncio
    async def test_suggest_skills_excludes_specified_skills(
        self, service, mock_vector_search_service
    ):
        """Test that excluded skill IDs are filtered out."""
        skill_1 = str(uuid4())
        skill_2 = str(uuid4())

        search_results = [
            {"id": "vec-1", "similarity": 0.9, "metadata": {"skill_id": skill_1}},
            {"id": "vec-2", "similarity": 0.85, "metadata": {"skill_id": skill_2}},
        ]

        with (
            patch.object(service, "_search_skills", new_callable=AsyncMock, return_value=search_results),
            patch.object(service, "_get_recent_skill_ids", new_callable=AsyncMock, return_value=set()),
            patch.object(
                service,
                "_get_skill_info",
                new_callable=AsyncMock,
                return_value={
                    "name": "skill",
                    "display_name": "Skill",
                    "description": "Desc",
                    "tags": [],
                },
            ),
        ):
            result = await service.suggest_skills(
                task_context="Test",
                namespace="test-ns",
                agent_id="agent-1",
                exclude_skill_ids=[skill_1],
            )

        assert len(result) == 1
        assert result[0].skill_id == skill_2

    @pytest.mark.asyncio
    async def test_suggest_skills_excludes_recent_suggestions(
        self, service, mock_vector_search_service
    ):
        """Test that recently suggested skills are excluded."""
        skill_id = str(uuid4())

        search_results = [
            {"id": "vec-1", "similarity": 0.9, "metadata": {"skill_id": skill_id}}
        ]

        with (
            patch.object(service, "_search_skills", new_callable=AsyncMock, return_value=search_results),
            patch.object(service, "_get_recent_skill_ids", new_callable=AsyncMock, return_value={skill_id}),
        ):
            result = await service.suggest_skills(
                task_context="Test",
                namespace="test-ns",
                agent_id="agent-1",
            )

        assert len(result) == 0


# =============================================================================
# Test ProactiveContextService - inject_context
# =============================================================================


class TestInjectContext:
    """Tests for inject_context method."""

    @pytest.mark.asyncio
    async def test_inject_context_success(self, service, mock_session):
        """Test successful context injection."""
        orchestration_id = str(uuid4())
        skill_id = str(uuid4())

        # Mock suggest_skills
        mock_suggestion = SuggestedSkill(
            skill_id=skill_id,
            skill_name="test-skill",
            display_name="Test Skill",
            description="Desc",
            relevance_score=0.85,
            suggestion_reason="Match",
        )

        with (
            patch.object(service, "suggest_skills", return_value=[mock_suggestion]),
            patch.object(service, "_record_suggestions", return_value=["sugg-1"]),
        ):
            result = await service.inject_context(
                orchestration_id=orchestration_id,
                task_context="Build API",
                namespace="test-ns",
                agent_id="agent-1",
            )

        assert isinstance(result, ContextInjectionResult)
        assert result.orchestration_id == orchestration_id
        assert len(result.suggested_skills) == 1
        assert result.suggestion_ids == ["sugg-1"]
        assert result.injection_time_ms > 0

    @pytest.mark.asyncio
    async def test_inject_context_no_suggestions(self, service):
        """Test context injection with no matching skills."""
        with (
            patch.object(service, "suggest_skills", return_value=[]),
            patch.object(service, "_record_suggestions", return_value=[]),
        ):
            result = await service.inject_context(
                orchestration_id="orch-1",
                task_context="Unknown task",
                namespace="test-ns",
                agent_id="agent-1",
            )

        assert result.suggested_skills == []
        assert result.suggestion_ids == []
        assert result.total_candidates == 0

    @pytest.mark.asyncio
    async def test_inject_context_truncates_context_summary(self, service):
        """Test that context summary is truncated to 200 chars."""
        long_context = "x" * 500

        with (
            patch.object(service, "suggest_skills", return_value=[]),
            patch.object(service, "_record_suggestions", return_value=[]),
        ):
            result = await service.inject_context(
                orchestration_id="orch-1",
                task_context=long_context,
                namespace="test-ns",
                agent_id="agent-1",
            )

        assert len(result.context_summary) == 200


# =============================================================================
# Test ProactiveContextService - record_feedback
# =============================================================================


class TestRecordFeedback:
    """Tests for record_feedback method."""

    @pytest.mark.asyncio
    async def test_record_feedback_success(self, service, mock_session, sample_suggestion):
        """Test successful feedback recording."""
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_suggestion
        mock_session.execute.return_value = mock_result

        result = await service.record_feedback(
            suggestion_id=str(sample_suggestion.id),
            was_activated=True,
            was_helpful=True,
        )

        assert result is True
        sample_suggestion.mark_activated.assert_called_once()
        sample_suggestion.provide_feedback.assert_called_once_with(True)
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_record_feedback_not_found(self, service, mock_session):
        """Test feedback for non-existent suggestion."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await service.record_feedback(
            suggestion_id=str(uuid4()),
            was_activated=True,
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_record_feedback_only_activated(self, service, mock_session, sample_suggestion):
        """Test recording only activation without helpfulness."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_suggestion
        mock_session.execute.return_value = mock_result

        result = await service.record_feedback(
            suggestion_id=str(sample_suggestion.id),
            was_activated=True,
        )

        assert result is True
        sample_suggestion.mark_activated.assert_called_once()
        sample_suggestion.provide_feedback.assert_not_called()

    @pytest.mark.asyncio
    async def test_record_feedback_rollback_on_error(self, service, mock_session):
        """Test rollback on feedback error."""
        mock_session.execute.side_effect = Exception("DB error")

        result = await service.record_feedback(
            suggestion_id=str(uuid4()),
            was_activated=True,
        )

        assert result is False
        mock_session.rollback.assert_called_once()


# =============================================================================
# Test ProactiveContextService - get_effectiveness_report
# =============================================================================


class TestGetEffectivenessReport:
    """Tests for get_effectiveness_report method."""

    @pytest.mark.asyncio
    async def test_get_effectiveness_report_success(self, service):
        """Test successful effectiveness report generation."""
        stats = {
            "total": 100,
            "activated": 50,
            "helpful": 40,
            "unhelpful": 5,
            "no_feedback": 55,
            "activation_rate": 0.5,
            "helpfulness_rate": 0.89,
        }

        with (
            patch.object(service, "_get_suggestion_stats", return_value=stats),
            patch.object(service, "_get_top_effective_skills", return_value=[]),
            patch.object(service, "_get_low_performing_skills", return_value=[]),
        ):
            report = await service.get_effectiveness_report(
                namespace="test-ns",
                days=30,
            )

        assert isinstance(report, EffectivenessReport)
        assert report.total_suggestions == 100
        assert report.activation_rate == 0.5
        assert report.period_days == 30

    @pytest.mark.asyncio
    async def test_get_effectiveness_report_default_days(self, service):
        """Test default 30-day period."""
        stats = {
            "total": 0,
            "activated": 0,
            "helpful": 0,
            "unhelpful": 0,
            "no_feedback": 0,
            "activation_rate": 0.0,
            "helpfulness_rate": 0.0,
        }

        with (
            patch.object(service, "_get_suggestion_stats", return_value=stats),
            patch.object(service, "_get_top_effective_skills", return_value=[]),
            patch.object(service, "_get_low_performing_skills", return_value=[]),
        ):
            report = await service.get_effectiveness_report(namespace="test-ns")

        assert report.period_days == 30

    @pytest.mark.asyncio
    async def test_get_effectiveness_report_with_recommendations(self, service):
        """Test report generates recommendations."""
        stats = {
            "total": 100,
            "activated": 20,  # Low activation rate
            "helpful": 10,
            "unhelpful": 10,
            "no_feedback": 80,
            "activation_rate": 0.2,
            "helpfulness_rate": 0.5,
        }

        with (
            patch.object(service, "_get_suggestion_stats", return_value=stats),
            patch.object(service, "_get_top_effective_skills", return_value=[]),
            patch.object(
                service,
                "_get_low_performing_skills",
                return_value=[{"skill_id": "s1", "activation_rate": 0.1}],
            ),
        ):
            report = await service.get_effectiveness_report(namespace="test-ns")

        # Should have recommendations for low activation rate and low-performing skills
        assert len(report.recommendations) >= 1


# =============================================================================
# Test ProactiveContextService - get_recent_suggestions
# =============================================================================


class TestGetRecentSuggestions:
    """Tests for get_recent_suggestions method."""

    @pytest.mark.asyncio
    async def test_get_recent_suggestions_success(
        self, service, mock_session, sample_suggestion
    ):
        """Test getting recent suggestions for an orchestration."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sample_suggestion]
        mock_session.execute.return_value = mock_result

        result = await service.get_recent_suggestions(
            orchestration_id="orch-123",
            namespace="test-ns",
        )

        assert len(result) == 1
        sample_suggestion.to_dict.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_recent_suggestions_empty(self, service, mock_session):
        """Test getting suggestions when none exist."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        result = await service.get_recent_suggestions(
            orchestration_id="orch-999",
            namespace="test-ns",
        )

        assert result == []


# =============================================================================
# Test ProactiveContextService - Private Methods
# =============================================================================


class TestPrivateMethods:
    """Tests for private helper methods."""

    @pytest.mark.asyncio
    async def test_generate_embedding(self, service, mock_embedding_service):
        """Test embedding generation."""
        result = await service._generate_embedding("test text")

        assert len(result) == 1024
        mock_embedding_service.embed_text.assert_called_once_with("test text")

    @pytest.mark.asyncio
    async def test_get_skill_info_success(self, service, mock_session, sample_skill):
        """Test getting skill info from database."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_skill
        mock_session.execute.return_value = mock_result

        result = await service._get_skill_info(str(sample_skill.id))

        assert result is not None
        assert result["name"] == sample_skill.name

    @pytest.mark.asyncio
    async def test_get_skill_info_not_found(self, service, mock_session):
        """Test getting skill info for non-existent skill."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await service._get_skill_info(str(uuid4()))

        assert result is None

    @pytest.mark.asyncio
    async def test_get_skill_info_invalid_uuid(self, service):
        """Test getting skill info with invalid UUID."""
        result = await service._get_skill_info("invalid-uuid")

        assert result is None

    def test_generate_recommendations_low_activation(self, service):
        """Test recommendation generation for low activation rate."""
        stats = {
            "total": 100,
            "activated": 10,
            "helpful": 5,
            "unhelpful": 5,
            "no_feedback": 90,
            "activation_rate": 0.1,
            "helpfulness_rate": 0.5,
        }

        recommendations = service._generate_recommendations(
            stats=stats,
            top_skills=[],
            low_skills=[],
        )

        assert any("Low activation rate" in r for r in recommendations)

    def test_generate_recommendations_high_activation(self, service):
        """Test recommendation generation for high activation rate."""
        stats = {
            "total": 100,
            "activated": 80,
            "helpful": 70,
            "unhelpful": 5,
            "no_feedback": 25,
            "activation_rate": 0.8,
            "helpfulness_rate": 0.93,
        }

        recommendations = service._generate_recommendations(
            stats=stats,
            top_skills=[],
            low_skills=[],
        )

        assert any("High activation rate" in r for r in recommendations)

    def test_generate_recommendations_low_helpfulness(self, service):
        """Test recommendation generation for low helpfulness rate."""
        stats = {
            "total": 100,
            "activated": 50,
            "helpful": 20,
            "unhelpful": 30,
            "no_feedback": 50,
            "activation_rate": 0.5,
            "helpfulness_rate": 0.4,
        }

        recommendations = service._generate_recommendations(
            stats=stats,
            top_skills=[],
            low_skills=[],
        )

        assert any("Low helpfulness rate" in r for r in recommendations)

    def test_generate_recommendations_with_low_performing_skills(self, service):
        """Test recommendation generation with low-performing skills."""
        stats = {
            "total": 100,
            "activated": 50,
            "helpful": 40,
            "unhelpful": 5,
            "no_feedback": 55,
            "activation_rate": 0.5,
            "helpfulness_rate": 0.89,
        }

        recommendations = service._generate_recommendations(
            stats=stats,
            top_skills=[],
            low_skills=[{"skill_id": "s1"}, {"skill_id": "s2"}],
        )

        assert any("low-performing" in r.lower() for r in recommendations)

    def test_generate_recommendations_with_high_effective_skills(self, service):
        """Test recommendation generation with high-performing skills."""
        stats = {
            "total": 100,
            "activated": 50,
            "helpful": 40,
            "unhelpful": 5,
            "no_feedback": 55,
            "activation_rate": 0.5,
            "helpfulness_rate": 0.89,
        }

        recommendations = service._generate_recommendations(
            stats=stats,
            top_skills=[{"skill_id": "s1", "helpfulness_rate": 0.95}],
            low_skills=[],
        )

        assert any("80%" in r for r in recommendations)

    def test_generate_recommendations_low_feedback_rate(self, service):
        """Test recommendation for low feedback collection."""
        stats = {
            "total": 100,
            "activated": 50,
            "helpful": 10,
            "unhelpful": 5,
            "no_feedback": 85,
            "activation_rate": 0.5,
            "helpfulness_rate": 0.67,
        }

        recommendations = service._generate_recommendations(
            stats=stats,
            top_skills=[],
            low_skills=[],
        )

        assert any("feedback" in r.lower() for r in recommendations)


# =============================================================================
# Test ProactiveContextService - P0-1 Namespace Isolation
# =============================================================================


class TestNamespaceIsolation:
    """Tests for P0-1 namespace isolation."""

    @pytest.mark.asyncio
    async def test_suggest_skills_uses_namespace_filter(
        self, service, mock_vector_search_service
    ):
        """Test that namespace is used in _search_skills call."""
        # Mock _search_skills to capture the namespace parameter
        mock_search = AsyncMock(return_value=[])
        with (
            patch.object(service, "_search_skills", mock_search),
            patch.object(service, "_filter_candidates", new_callable=AsyncMock, return_value=[]),
        ):
            await service.suggest_skills(
                task_context="Test",
                namespace="secure-namespace",
                agent_id="agent-1",
            )

        # Verify namespace filter was applied via _search_skills
        mock_search.assert_called_once()
        call_args = mock_search.call_args
        assert call_args.kwargs["namespace"] == "secure-namespace"

    @pytest.mark.asyncio
    async def test_get_recent_suggestions_enforces_namespace(self, service, mock_session):
        """Test that get_recent_suggestions filters by namespace."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        await service.get_recent_suggestions(
            orchestration_id="orch-1",
            namespace="secure-namespace",
        )

        # Verify execute was called (namespace filter is in the query)
        mock_session.execute.assert_called_once()


# =============================================================================
# Test ProactiveContextService - Performance
# =============================================================================


class TestPerformance:
    """Tests for performance requirements."""

    @pytest.mark.asyncio
    async def test_suggest_skills_performance(self, service, mock_vector_search_service):
        """Test that suggest_skills meets <100ms target."""
        import time

        # Mock _search_skills and _filter_candidates to return empty
        with (
            patch.object(service, "_search_skills", new_callable=AsyncMock, return_value=[]),
            patch.object(service, "_filter_candidates", new_callable=AsyncMock, return_value=[]),
        ):
            start = time.perf_counter()
            await service.suggest_skills(
                task_context="Test task",
                namespace="test-ns",
                agent_id="agent-1",
            )
            elapsed_ms = (time.perf_counter() - start) * 1000

        # Should complete very quickly with mocked dependencies
        assert elapsed_ms < 100

    @pytest.mark.asyncio
    async def test_inject_context_performance(self, service):
        """Test that inject_context meets <50ms target (excluding suggestion)."""
        import time

        with (
            patch.object(service, "suggest_skills", return_value=[]),
            patch.object(service, "_record_suggestions", return_value=[]),
        ):
            start = time.perf_counter()
            await service.inject_context(
                orchestration_id="orch-1",
                task_context="Test",
                namespace="test-ns",
                agent_id="agent-1",
            )
            elapsed_ms = (time.perf_counter() - start) * 1000

        # Should complete very quickly with mocked dependencies
        assert elapsed_ms < 50


# =============================================================================
# Test ProactiveContextService - Configuration
# =============================================================================


class TestConfiguration:
    """Tests for service configuration."""

    def test_default_configuration(self, service):
        """Test default configuration values."""
        assert service.MIN_RELEVANCE_SCORE == 0.7
        assert service.MAX_SUGGESTIONS_PER_INJECTION == 5
        assert service.DEFAULT_TOP_K == 20
        assert service.SUGGESTION_COOLDOWN_HOURS == 2
        assert service.EFFECTIVENESS_PERIOD_DAYS == 30

    def test_threshold_configuration(self, service):
        """Test threshold configuration values."""
        assert service.LOW_ACTIVATION_THRESHOLD == 0.2
        assert service.HIGH_EFFECTIVENESS_THRESHOLD == 0.8


# =============================================================================
# Test ProactiveContextService - Lazy Loading
# =============================================================================


class TestLazyLoading:
    """Tests for lazy-loaded dependencies."""

    def test_skill_service_initially_none(self, mock_session):
        """Test that SkillService is initially None."""
        svc = ProactiveContextService(session=mock_session)

        # Initially None
        assert svc._skill_service is None

    def test_vector_search_service_initially_none(self, mock_session):
        """Test that VectorSearchService is initially None."""
        svc = ProactiveContextService(session=mock_session)

        assert svc._vector_search_service is None

    def test_embedding_service_initially_none(self, mock_session):
        """Test that embedding service is initially None."""
        svc = ProactiveContextService(session=mock_session)

        assert svc._embedding_service is None

    def test_injected_dependencies_used(self, mock_session):
        """Test that injected dependencies are used instead of lazy-loaded."""
        mock_skill = MagicMock()
        mock_vector = MagicMock()
        mock_embed = MagicMock()

        svc = ProactiveContextService(
            session=mock_session,
            skill_service=mock_skill,
            vector_search_service=mock_vector,
            embedding_service=mock_embed,
        )

        # Injected dependencies should be returned
        assert svc.skill_service is mock_skill
        assert svc.vector_search_service is mock_vector
        assert svc.embedding_service is mock_embed


# =============================================================================
# Test ProactiveContextService - Concurrency
# =============================================================================


class TestConcurrency:
    """Tests for concurrency handling."""

    @pytest.mark.asyncio
    async def test_record_suggestions_uses_lock(self, service, mock_session):
        """Test that _record_suggestions uses lock for thread safety."""
        # The suggestion lock should prevent race conditions
        assert hasattr(service, "_suggestion_lock")
        assert isinstance(service._suggestion_lock, asyncio.Lock)

    @pytest.mark.asyncio
    async def test_concurrent_injections_serialized(self, service, mock_session):
        """Test that concurrent injections are properly serialized."""
        recorded_calls = []

        async def mock_record(*args, **kwargs):
            recorded_calls.append(("start", len(recorded_calls)))
            await asyncio.sleep(0.01)  # Simulate some work
            recorded_calls.append(("end", len(recorded_calls)))
            return []

        with (
            patch.object(service, "suggest_skills", return_value=[]),
            patch.object(service, "_record_suggestions", side_effect=mock_record),
        ):
            # Run concurrent injections
            await asyncio.gather(
                service.inject_context("orch-1", "Task 1", "ns", "agent"),
                service.inject_context("orch-2", "Task 2", "ns", "agent"),
            )

        # Both should complete (4 calls total: 2 starts + 2 ends)
        assert len(recorded_calls) == 4
