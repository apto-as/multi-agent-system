"""Integration tests for ProactiveContextService.

This module tests the full integration of ProactiveContextService with:
- Database (SQLite)
- SkillSuggestion model
- Mocked VectorSearchService and EmbeddingService

Test Coverage:
- Suggestion recording and retrieval
- Feedback recording and effectiveness reporting
- P0-1 Namespace isolation
- Performance validation
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.execution_trace import SkillSuggestion
from src.services.proactive_context_service import (
    ContextInjectionResult,
    EffectivenessReport,
    ProactiveContextService,
    SuggestedSkill,
)

if TYPE_CHECKING:
    pass


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_embedding_service() -> MagicMock:
    """Create mock embedding service."""
    mock = MagicMock()
    mock.embed_text = MagicMock(return_value=[0.1] * 1024)
    return mock


@pytest.fixture
def mock_vector_search_service() -> AsyncMock:
    """Create mock vector search service."""
    mock = AsyncMock()
    mock.search = AsyncMock(return_value=[])
    return mock


@pytest.fixture
def service(
    test_session: AsyncSession,
    mock_embedding_service: MagicMock,
    mock_vector_search_service: AsyncMock,
) -> ProactiveContextService:
    """Create ProactiveContextService with mocked dependencies."""
    return ProactiveContextService(
        session=test_session,
        embedding_service=mock_embedding_service,
        vector_search_service=mock_vector_search_service,
    )


# =============================================================================
# Context Injection Tests (with mocked vector search)
# =============================================================================


class TestContextInjection:
    """Test context injection functionality."""

    @pytest.mark.asyncio
    async def test_inject_context_empty_results(
        self,
        service: ProactiveContextService,
        mock_vector_search_service: AsyncMock,
    ) -> None:
        """Test injection when no matching skills found."""
        mock_vector_search_service.search.return_value = []

        result = await service.inject_context(
            orchestration_id=str(uuid4()),
            task_context="Very unique task with no matching skills",
            namespace="test-namespace",
            agent_id="test-agent",
        )

        assert isinstance(result, ContextInjectionResult)
        assert len(result.suggested_skills) == 0
        assert len(result.suggestion_ids) == 0
        assert result.total_candidates == 0


class TestNamespaceIsolation:
    """Test P0-1 namespace isolation requirements."""

    @pytest.mark.asyncio
    async def test_get_recent_suggestions_namespace_isolation(
        self,
        test_session: AsyncSession,
        service: ProactiveContextService,
    ) -> None:
        """Verify get_recent_suggestions respects namespace."""
        orchestration_id = str(uuid4())

        # Create suggestions in different namespaces
        suggestion1 = SkillSuggestion(
            orchestration_id=orchestration_id,
            skill_id=str(uuid4()),
            agent_id="agent-1",
            namespace="namespace-a",
            relevance_score=0.8,
        )
        suggestion2 = SkillSuggestion(
            orchestration_id=orchestration_id,
            skill_id=str(uuid4()),
            agent_id="agent-2",
            namespace="namespace-b",
            relevance_score=0.9,
        )
        test_session.add_all([suggestion1, suggestion2])
        await test_session.commit()

        # Query for namespace-a only
        results = await service.get_recent_suggestions(
            orchestration_id=orchestration_id,
            namespace="namespace-a",
        )

        assert len(results) == 1
        assert results[0]["namespace"] == "namespace-a"


class TestEffectivenessReporting:
    """Test effectiveness report generation."""

    @pytest.mark.asyncio
    async def test_effectiveness_report_generation(
        self,
        test_session: AsyncSession,
        service: ProactiveContextService,
    ) -> None:
        """Test generation of effectiveness report."""
        namespace = "test-namespace"
        skill_id = str(uuid4())

        # Create varied suggestions
        suggestions = [
            SkillSuggestion(
                orchestration_id=str(uuid4()),
                skill_id=skill_id,
                agent_id="agent-1",
                namespace=namespace,
                relevance_score=0.8,
                was_activated=True,
                was_helpful=True,
            ),
            SkillSuggestion(
                orchestration_id=str(uuid4()),
                skill_id=skill_id,
                agent_id="agent-1",
                namespace=namespace,
                relevance_score=0.7,
                was_activated=True,
                was_helpful=False,
            ),
            SkillSuggestion(
                orchestration_id=str(uuid4()),
                skill_id=skill_id,
                agent_id="agent-1",
                namespace=namespace,
                relevance_score=0.9,
                was_activated=False,
                was_helpful=None,
            ),
        ]
        test_session.add_all(suggestions)
        await test_session.commit()

        report = await service.get_effectiveness_report(
            namespace=namespace,
            days=30,
        )

        assert isinstance(report, EffectivenessReport)
        assert report.namespace == namespace
        assert report.total_suggestions == 3
        assert report.activated_count == 2
        assert report.helpful_count == 1
        assert report.unhelpful_count == 1
        assert report.activation_rate == pytest.approx(2 / 3, rel=0.01)
        assert report.helpfulness_rate == pytest.approx(0.5, rel=0.01)

    @pytest.mark.asyncio
    async def test_effectiveness_report_empty_namespace(
        self,
        service: ProactiveContextService,
    ) -> None:
        """Test effectiveness report for empty namespace."""
        report = await service.get_effectiveness_report(
            namespace="empty-namespace",
            days=30,
        )

        assert report.total_suggestions == 0
        assert report.activation_rate == 0.0
        assert report.helpfulness_rate == 0.0


class TestCooldownBehavior:
    """Test suggestion cooldown functionality."""

    @pytest.mark.asyncio
    async def test_recent_skill_ids_query(
        self,
        test_session: AsyncSession,
        service: ProactiveContextService,
    ) -> None:
        """Test that _get_recent_skill_ids returns correct skill IDs."""
        namespace = "test-namespace"
        agent_id = "test-agent"
        skill_id = str(uuid4())

        # Create a recent suggestion (within cooldown)
        recent_suggestion = SkillSuggestion(
            orchestration_id=str(uuid4()),
            skill_id=skill_id,
            agent_id=agent_id,
            namespace=namespace,
            relevance_score=0.8,
            created_at=datetime.now(timezone.utc),  # Just now
        )
        test_session.add(recent_suggestion)
        await test_session.commit()

        # Get recent skill IDs
        recent_ids = await service._get_recent_skill_ids(namespace, agent_id)

        assert skill_id in recent_ids

    @pytest.mark.asyncio
    async def test_old_skill_not_in_recent(
        self,
        test_session: AsyncSession,
        service: ProactiveContextService,
    ) -> None:
        """Test that old suggestions are not included in recent."""
        namespace = "test-namespace"
        agent_id = "test-agent"
        skill_id = str(uuid4())

        # Create an old suggestion (past cooldown)
        old_suggestion = SkillSuggestion(
            orchestration_id=str(uuid4()),
            skill_id=skill_id,
            agent_id=agent_id,
            namespace=namespace,
            relevance_score=0.8,
            created_at=datetime.now(timezone.utc) - timedelta(hours=3),  # 3 hours ago
        )
        test_session.add(old_suggestion)
        await test_session.commit()

        # Get recent skill IDs
        recent_ids = await service._get_recent_skill_ids(namespace, agent_id)

        assert skill_id not in recent_ids


class TestPerformance:
    """Test performance requirements."""

    @pytest.mark.asyncio
    async def test_suggestion_performance(
        self,
        service: ProactiveContextService,
        mock_vector_search_service: AsyncMock,
    ) -> None:
        """Verify suggestion performance meets target (<100ms)."""
        mock_vector_search_service.search.return_value = []

        import time

        start = time.perf_counter()

        await service.suggest_skills(
            task_context="Performance test context",
            namespace="test-namespace",
            agent_id="test-agent",
        )

        elapsed_ms = (time.perf_counter() - start) * 1000

        # Should complete in <100ms (with mocked dependencies)
        assert elapsed_ms < 100, f"Suggestion took {elapsed_ms:.2f}ms, expected <100ms"

    @pytest.mark.asyncio
    async def test_injection_performance(
        self,
        service: ProactiveContextService,
        mock_vector_search_service: AsyncMock,
    ) -> None:
        """Verify injection performance meets target."""
        mock_vector_search_service.search.return_value = []

        import time

        start = time.perf_counter()

        await service.inject_context(
            orchestration_id=str(uuid4()),
            task_context="Performance test context",
            namespace="test-namespace",
            agent_id="test-agent",
        )

        elapsed_ms = (time.perf_counter() - start) * 1000

        # Should complete quickly with mocked dependencies
        assert elapsed_ms < 200, f"Injection took {elapsed_ms:.2f}ms, expected <200ms"


class TestFeedbackRecording:
    """Test feedback recording functionality."""

    @pytest.mark.asyncio
    async def test_record_feedback_nonexistent_suggestion(
        self,
        service: ProactiveContextService,
    ) -> None:
        """Test feedback for non-existent suggestion returns False."""
        result = await service.record_feedback(
            suggestion_id=str(uuid4()),
            was_activated=True,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_record_feedback_invalid_uuid(
        self,
        service: ProactiveContextService,
    ) -> None:
        """Test feedback with invalid UUID returns False."""
        result = await service.record_feedback(
            suggestion_id="invalid-uuid",
            was_activated=True,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_record_partial_feedback(
        self,
        test_session: AsyncSession,
        service: ProactiveContextService,
    ) -> None:
        """Test recording partial feedback (activation only)."""
        suggestion = SkillSuggestion(
            orchestration_id=str(uuid4()),
            skill_id=str(uuid4()),
            agent_id="test-agent",
            namespace="test-namespace",
            relevance_score=0.8,
        )
        test_session.add(suggestion)
        await test_session.commit()

        # Record activation only
        result = await service.record_feedback(
            suggestion_id=str(suggestion.id),
            was_activated=True,
        )
        assert result is True

        await test_session.refresh(suggestion)
        assert suggestion.was_activated is True
        assert suggestion.was_helpful is None  # Not set


class TestDataclassSerialization:
    """Test dataclass serialization."""

    def test_suggested_skill_to_dict(self) -> None:
        """Test SuggestedSkill serialization."""
        skill = SuggestedSkill(
            skill_id="123",
            skill_name="test",
            display_name="Test",
            description="Description",
            relevance_score=0.85,
            suggestion_reason="High similarity",
            tags=["a", "b"],
        )

        data = skill.to_dict()

        assert data["skill_id"] == "123"
        assert data["relevance_score"] == 0.85
        assert data["tags"] == ["a", "b"]

    def test_context_injection_result_to_dict(self) -> None:
        """Test ContextInjectionResult serialization."""
        result = ContextInjectionResult(
            orchestration_id="orch-1",
            agent_id="agent-1",
            namespace="ns-1",
            suggested_skills=[],
            suggestion_ids=[],
            total_candidates=0,
            injection_time_ms=50.0,
        )

        data = result.to_dict()

        assert data["orchestration_id"] == "orch-1"
        assert data["injection_time_ms"] == 50.0

    def test_effectiveness_report_to_dict(self) -> None:
        """Test EffectivenessReport serialization."""
        report = EffectivenessReport(
            namespace="ns-1",
            period_days=30,
            total_suggestions=100,
            activated_count=50,
            helpful_count=40,
            unhelpful_count=10,
            no_feedback_count=50,
            activation_rate=0.5,
            helpfulness_rate=0.8,
            top_effective_skills=[],
            low_performing_skills=[],
            recommendations=["Improve targeting"],
        )

        data = report.to_dict()

        assert data["namespace"] == "ns-1"
        assert data["activation_rate"] == 0.5
        assert "Improve targeting" in data["recommendations"]
