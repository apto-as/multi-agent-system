"""Unit tests for Trust Score Weighted Routing (P1 Learning Gap Fix).

Tests for hybrid routing algorithm combining pattern matching with trust scores.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.services.task_routing_service import TaskRoutingService, RoutingResult


@pytest.fixture
def mock_session():
    """Create a mock database session."""
    return AsyncMock()


@pytest.fixture
def routing_service(mock_session):
    """Create a TaskRoutingService instance."""
    return TaskRoutingService(mock_session)


class TestTrustScoreWeighting:
    """Test trust score weighted routing algorithm."""

    @pytest.mark.asyncio
    async def test_pattern_only_routing(self, routing_service):
        """Test routing without trust scores (pattern-only mode)."""
        task_content = "Optimize database query performance"

        # Pattern-only routing (no DB)
        result = routing_service.route_task(task_content)

        assert result.primary_agent == "artemis-optimizer"
        assert result.confidence > 0.0
        assert "artemis-optimizer" in result.detected_patterns

    @pytest.mark.asyncio
    async def test_trust_score_disabled(self, routing_service, mock_session):
        """Test routing with trust scoring disabled."""
        task_content = "Optimize performance"

        # Mock agent service
        mock_agent_service = AsyncMock()
        mock_agent_service.get_recommended_agents = AsyncMock(return_value=[])
        routing_service.agent_service = mock_agent_service

        result = await routing_service.route_task_with_db(
            task_content,
            namespace=None,
            include_trust_scoring=False,
        )

        # Should use pattern-only routing
        assert result.primary_agent == "artemis-optimizer"
        assert "trust-weighted" not in result.reasoning

    @pytest.mark.asyncio
    async def test_trust_score_weighted_routing(self, routing_service, mock_session):
        """Test routing with trust score weighting enabled."""
        task_content = "Optimize and audit security"

        # Mock agent service to return agents with trust scores
        mock_agent = MagicMock()
        mock_agent.agent_id = "artemis-optimizer"
        mock_agent.trust_score = 0.9  # High trust

        mock_agent_service = AsyncMock()
        mock_agent_service.get_recommended_agents = AsyncMock(return_value=[mock_agent])
        mock_agent_service.get_agent_by_id = AsyncMock(return_value=mock_agent)

        routing_service.agent_service = mock_agent_service

        result = await routing_service.route_task_with_db(
            task_content,
            namespace=None,
            include_trust_scoring=True,
        )

        # Should include trust score in reasoning
        assert "trust-weighted" in result.reasoning
        # High trust score should boost confidence
        assert result.confidence > 0.5

    @pytest.mark.asyncio
    async def test_default_trust_score_for_new_agents(self, routing_service, mock_session):
        """Test that new/unknown agents get default 0.5 trust score."""
        task_content = "Test task"

        # Mock agent service to return None (agent not found)
        mock_agent_service = AsyncMock()
        mock_agent_service.get_recommended_agents = AsyncMock(return_value=[])
        mock_agent_service.get_agent_by_id = AsyncMock(return_value=None)

        routing_service.agent_service = mock_agent_service

        result = await routing_service.route_task_with_db(
            task_content,
            namespace=None,
            include_trust_scoring=True,
        )

        # Should still work with default trust score
        assert result.primary_agent is not None

    @pytest.mark.asyncio
    async def test_hybrid_formula_60_40_split(self, routing_service):
        """Test hybrid formula: 60% pattern + 40% trust."""
        # Create a scenario where pattern and trust differ

        # Pattern score: artemis (0.8)
        # Trust score: artemis (0.5), hestia (0.9)
        # Weighted: artemis = 0.8*0.6 + 0.5*0.4 = 0.68
        #          hestia = 0.4*0.6 + 0.9*0.4 = 0.60
        # artemis should still win

        task_content = "Optimize code performance"

        mock_artemis = MagicMock()
        mock_artemis.agent_id = "artemis-optimizer"
        mock_artemis.trust_score = 0.5

        mock_hestia = MagicMock()
        mock_hestia.agent_id = "hestia-auditor"
        mock_hestia.trust_score = 0.9

        mock_agent_service = AsyncMock()
        mock_agent_service.get_recommended_agents = AsyncMock(
            return_value=[mock_artemis, mock_hestia]
        )

        async def mock_get_agent(agent_id):
            if agent_id == "artemis-optimizer":
                return mock_artemis
            elif agent_id == "hestia-auditor":
                return mock_hestia
            return None

        mock_agent_service.get_agent_by_id = AsyncMock(side_effect=mock_get_agent)
        routing_service.agent_service = mock_agent_service

        result = await routing_service.route_task_with_db(
            task_content,
            namespace=None,
            include_trust_scoring=True,
        )

        # Artemis should win despite lower trust (stronger pattern match)
        assert result.primary_agent == "artemis-optimizer"


class TestPatternScoreCalculation:
    """Test _calculate_pattern_score helper method."""

    def test_calculate_pattern_score_detected(self, routing_service):
        """Test pattern score calculation for detected agent."""
        task_content = "Optimize database performance"

        # Get pattern matches
        persona_matches = routing_service.detect_personas(task_content)

        # Calculate pattern score for artemis-optimizer
        mock_result = RoutingResult(
            primary_agent="artemis-optimizer",
            support_agents=[],
            confidence=0.8,
            reasoning="",
            detected_patterns=persona_matches,
            suggested_phase="",
        )

        score = routing_service._calculate_pattern_score(
            "artemis-optimizer", task_content, mock_result
        )

        assert score > 0.0  # Should have non-zero pattern match

    def test_calculate_pattern_score_not_detected(self, routing_service):
        """Test pattern score for non-detected agent."""
        task_content = "Optimize performance"

        persona_matches = routing_service.detect_personas(task_content)

        mock_result = RoutingResult(
            primary_agent="artemis-optimizer",
            support_agents=[],
            confidence=0.8,
            reasoning="",
            detected_patterns=persona_matches,
            suggested_phase="",
        )

        # aphrodite-designer should not match "optimize"
        score = routing_service._calculate_pattern_score(
            "aphrodite-designer", task_content, mock_result
        )

        assert score == 0.0  # No pattern match


class TestErrorHandling:
    """Test error handling in trust score routing."""

    @pytest.mark.asyncio
    async def test_trust_score_fetch_failure_fallback(self, routing_service, mock_session):
        """Test graceful fallback when trust score fetch fails."""
        task_content = "Optimize code"

        # Mock agent service to raise exception
        mock_agent_service = AsyncMock()
        mock_agent_service.get_recommended_agents = AsyncMock(return_value=[])
        mock_agent_service.get_agent_by_id = AsyncMock(side_effect=Exception("DB error"))

        routing_service.agent_service = mock_agent_service

        # Should not raise, should fallback to pattern-only
        result = await routing_service.route_task_with_db(
            task_content,
            namespace=None,
            include_trust_scoring=True,
        )

        assert result.primary_agent is not None

    @pytest.mark.asyncio
    async def test_no_agent_service_fallback(self, routing_service):
        """Test routing works without agent service (pattern-only)."""
        task_content = "Optimize performance"

        routing_service.agent_service = None

        result = await routing_service.route_task_with_db(
            task_content,
            namespace=None,
            include_trust_scoring=True,
        )

        # Should fallback to pattern-only routing
        assert result.primary_agent == "artemis-optimizer"


class TestRoutingConfidence:
    """Test confidence calculation with trust scores."""

    @pytest.mark.asyncio
    async def test_high_trust_boosts_confidence(self, routing_service, mock_session):
        """Test that high trust scores boost routing confidence."""
        task_content = "Optimize code"

        mock_agent = MagicMock()
        mock_agent.agent_id = "artemis-optimizer"
        mock_agent.trust_score = 0.95  # Very high trust

        mock_agent_service = AsyncMock()
        mock_agent_service.get_recommended_agents = AsyncMock(return_value=[mock_agent])
        mock_agent_service.get_agent_by_id = AsyncMock(return_value=mock_agent)

        routing_service.agent_service = mock_agent_service

        result = await routing_service.route_task_with_db(
            task_content,
            namespace=None,
            include_trust_scoring=True,
        )

        # High trust + pattern match should yield good confidence
        # With 60% pattern (0.3) + 40% trust (0.95) + 0.1 DB bonus = ~0.66
        assert result.confidence > 0.6

    @pytest.mark.asyncio
    async def test_low_trust_lowers_confidence(self, routing_service, mock_session):
        """Test that low trust scores lower routing confidence."""
        task_content = "Optimize code"

        mock_agent = MagicMock()
        mock_agent.agent_id = "artemis-optimizer"
        mock_agent.trust_score = 0.2  # Low trust

        mock_agent_service = AsyncMock()
        mock_agent_service.get_recommended_agents = AsyncMock(return_value=[mock_agent])
        mock_agent_service.get_agent_by_id = AsyncMock(return_value=mock_agent)

        routing_service.agent_service = mock_agent_service

        result = await routing_service.route_task_with_db(
            task_content,
            namespace=None,
            include_trust_scoring=True,
        )

        # Low trust should reduce overall confidence
        assert result.confidence < 0.8


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
