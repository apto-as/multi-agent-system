"""Phase 4.2: Tool Promotion Service Unit Tests.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 4.2 - Tool → Skill Promotion Logic

Tests cover:
- PromotionCriteria defaults
- PromotionCandidate evaluation
- Tool promotion workflow
- Auto-promotion logic
- Integration with AdaptiveRanker

Author: Artemis (Implementation)
Created: 2025-12-05
"""

import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from src.services.adaptive_ranker import AdaptiveRanker, ToolUsagePattern
from src.services.tool_promotion_service import (
    PromotionCandidate,
    PromotionCriteria,
    PromotionResult,
    ToolPromotionService,
)

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def criteria():
    """Default promotion criteria."""
    return PromotionCriteria(
        min_usage_count=50,
        min_success_rate=0.85,
        min_success_count=40,
        max_average_latency_ms=5000.0,
        min_days_active=7,
        min_query_contexts=5,
    )


@pytest.fixture
def mock_skill_service():
    """Mock SkillService for testing."""
    service = AsyncMock()
    service.create_skill = AsyncMock(
        return_value={"skill_id": "skill_123", "name": "Promoted: grep"}
    )
    return service


@pytest.fixture
def mock_ranker():
    """Mock AdaptiveRanker with patterns."""
    ranker = AdaptiveRanker()
    ranker._agent_patterns = {}
    ranker._cache_timestamps = {}
    return ranker


@pytest.fixture
def promotion_service(criteria, mock_ranker, mock_skill_service):
    """ToolPromotionService with mocked dependencies."""
    service = ToolPromotionService(
        adaptive_ranker=mock_ranker,
        skill_service=mock_skill_service,
        criteria=criteria,
    )
    return service


@pytest.fixture
def eligible_pattern():
    """Pattern that meets all promotion criteria."""
    return ToolUsagePattern(
        tool_name="grep",
        server_id="tmws",
        agent_id="artemis",
        usage_count=100,
        success_count=90,  # 90% success rate
        error_count=10,
        total_latency_ms=200000.0,  # 2000ms average
        last_used=datetime.now() - timedelta(days=10),
        query_contexts=[f"query{i}" for i in range(10)],  # 10 unique contexts
    )


@pytest.fixture
def ineligible_pattern():
    """Pattern that does not meet criteria."""
    return ToolUsagePattern(
        tool_name="read_file",
        server_id="tmws",
        agent_id="artemis",
        usage_count=10,  # Below min_usage_count
        success_count=8,
        error_count=2,
        total_latency_ms=1000.0,
        last_used=datetime.now(),
        query_contexts=["query1", "query2"],  # Below min_query_contexts
    )


# ============================================================================
# PromotionCriteria Tests
# ============================================================================


class TestPromotionCriteria:
    """Tests for PromotionCriteria dataclass."""

    def test_default_values(self):
        """Should have sensible defaults."""
        criteria = PromotionCriteria()
        assert criteria.min_usage_count == 50
        assert criteria.min_success_rate == 0.85
        assert criteria.min_success_count == 40
        assert criteria.max_average_latency_ms == 5000.0
        assert criteria.min_days_active == 7
        assert criteria.min_query_contexts == 5

    def test_custom_values(self):
        """Should accept custom values."""
        criteria = PromotionCriteria(
            min_usage_count=100,
            min_success_rate=0.90,
        )
        assert criteria.min_usage_count == 100
        assert criteria.min_success_rate == 0.90


# ============================================================================
# PromotionCandidate Tests
# ============================================================================


class TestPromotionCandidate:
    """Tests for PromotionCandidate dataclass."""

    def test_to_dict(self):
        """Should convert to dictionary."""
        candidate = PromotionCandidate(
            tool_name="grep",
            server_id="tmws",
            agent_id="artemis",
            usage_count=100,
            success_rate=0.9,
            average_latency_ms=2000.0,
            days_active=10,
            query_contexts=10,
            promotion_score=0.85,
            meets_criteria=True,
            missing_criteria=[],
        )
        d = candidate.to_dict()
        assert d["tool_name"] == "grep"
        assert d["meets_criteria"] is True
        assert d["promotion_score"] == 0.85


class TestPromotionResult:
    """Tests for PromotionResult dataclass."""

    def test_success_result(self):
        """Should create success result."""
        result = PromotionResult(
            success=True,
            tool_name="grep",
            server_id="tmws",
            skill_id="skill_123",
            skill_name="Promoted: grep",
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["skill_id"] == "skill_123"

    def test_failure_result(self):
        """Should create failure result."""
        result = PromotionResult(
            success=False,
            tool_name="grep",
            server_id="tmws",
            error="Does not meet criteria",
        )
        d = result.to_dict()
        assert d["success"] is False
        assert d["error"] == "Does not meet criteria"


# ============================================================================
# ToolPromotionService Initialization Tests
# ============================================================================


class TestToolPromotionServiceInit:
    """Tests for ToolPromotionService initialization."""

    def test_default_initialization(self):
        """Should initialize with defaults."""
        service = ToolPromotionService()
        assert service._adaptive_ranker is None
        assert service._skill_service is None
        assert service.criteria is not None

    def test_with_dependencies(self, mock_ranker, mock_skill_service, criteria):
        """Should accept dependencies."""
        service = ToolPromotionService(
            adaptive_ranker=mock_ranker,
            skill_service=mock_skill_service,
            criteria=criteria,
        )
        assert service._adaptive_ranker == mock_ranker
        assert service._skill_service == mock_skill_service
        assert service.criteria == criteria


# ============================================================================
# get_promotion_candidates Tests
# ============================================================================


class TestGetPromotionCandidates:
    """Tests for get_promotion_candidates method."""

    @pytest.mark.asyncio
    async def test_no_candidates_without_ranker(self, mock_skill_service, criteria):
        """Should return empty list without ranker."""
        service = ToolPromotionService(
            skill_service=mock_skill_service,
            criteria=criteria,
        )
        candidates = await service.get_promotion_candidates()
        assert candidates == []

    @pytest.mark.asyncio
    async def test_no_candidates_without_patterns(self, promotion_service):
        """Should return empty list without patterns."""
        candidates = await promotion_service.get_promotion_candidates(agent_id="artemis")
        assert candidates == []

    @pytest.mark.asyncio
    async def test_finds_eligible_candidate(self, promotion_service, mock_ranker, eligible_pattern):
        """Should find eligible candidates."""
        # Add pattern
        mock_ranker._agent_patterns["artemis"] = {
            "tmws:grep": eligible_pattern,
        }
        mock_ranker._cache_timestamps["artemis"] = time.time()

        candidates = await promotion_service.get_promotion_candidates(agent_id="artemis")

        assert len(candidates) == 1
        assert candidates[0].tool_name == "grep"
        assert candidates[0].meets_criteria is True

    @pytest.mark.asyncio
    async def test_finds_ineligible_candidate(
        self, promotion_service, mock_ranker, ineligible_pattern
    ):
        """Should mark ineligible candidates."""
        mock_ranker._agent_patterns["artemis"] = {
            "tmws:read_file": ineligible_pattern,
        }
        mock_ranker._cache_timestamps["artemis"] = time.time()

        candidates = await promotion_service.get_promotion_candidates(agent_id="artemis")

        assert len(candidates) == 1
        assert candidates[0].tool_name == "read_file"
        assert candidates[0].meets_criteria is False
        assert len(candidates[0].missing_criteria) > 0

    @pytest.mark.asyncio
    async def test_sorts_by_promotion_score(
        self, promotion_service, mock_ranker, eligible_pattern, ineligible_pattern
    ):
        """Should sort candidates by promotion score."""
        mock_ranker._agent_patterns["artemis"] = {
            "tmws:grep": eligible_pattern,
            "tmws:read_file": ineligible_pattern,
        }
        mock_ranker._cache_timestamps["artemis"] = time.time()

        candidates = await promotion_service.get_promotion_candidates(agent_id="artemis")

        assert len(candidates) == 2
        # Eligible should be first (higher score)
        assert candidates[0].tool_name == "grep"

    @pytest.mark.asyncio
    async def test_respects_limit(self, promotion_service, mock_ranker):
        """Should respect limit parameter."""
        # Add many patterns
        mock_ranker._agent_patterns["artemis"] = {
            f"tmws:tool{i}": ToolUsagePattern(
                tool_name=f"tool{i}",
                server_id="tmws",
                agent_id="artemis",
                usage_count=50 + i,
                success_count=45 + i,
            )
            for i in range(20)
        }
        mock_ranker._cache_timestamps["artemis"] = time.time()

        candidates = await promotion_service.get_promotion_candidates(
            agent_id="artemis",
            limit=5,
        )

        assert len(candidates) == 5


# ============================================================================
# promote_tool Tests
# ============================================================================


class TestPromoteTool:
    """Tests for promote_tool method."""

    @pytest.mark.asyncio
    async def test_promotes_eligible_tool(
        self, promotion_service, mock_ranker, mock_skill_service, eligible_pattern
    ):
        """Should promote eligible tool."""
        mock_ranker._agent_patterns["artemis"] = {
            "tmws:grep": eligible_pattern,
        }
        mock_ranker._cache_timestamps["artemis"] = time.time()

        result = await promotion_service.promote_tool(
            tool_name="grep",
            server_id="tmws",
            agent_id="artemis",
        )

        assert result.success is True
        assert result.skill_id == "skill_123"
        mock_skill_service.create_skill.assert_called_once()

    @pytest.mark.asyncio
    async def test_rejects_ineligible_tool(
        self, promotion_service, mock_ranker, ineligible_pattern
    ):
        """Should reject ineligible tool."""
        mock_ranker._agent_patterns["artemis"] = {
            "tmws:read_file": ineligible_pattern,
        }
        mock_ranker._cache_timestamps["artemis"] = time.time()

        result = await promotion_service.promote_tool(
            tool_name="read_file",
            server_id="tmws",
            agent_id="artemis",
        )

        assert result.success is False
        assert "Does not meet criteria" in result.error

    @pytest.mark.asyncio
    async def test_force_promotion_requires_admin(
        self, promotion_service, mock_ranker, mock_skill_service, ineligible_pattern
    ):
        """Should reject force=True from non-admin agent (H-2 security fix)."""
        mock_ranker._agent_patterns["artemis"] = {
            "tmws:read_file": ineligible_pattern,
        }
        mock_ranker._cache_timestamps["artemis"] = time.time()

        # Non-admin agents cannot use force=True
        with pytest.raises(PermissionError, match="Force promotion requires admin"):
            await promotion_service.promote_tool(
                tool_name="read_file",
                server_id="tmws",
                agent_id="artemis",
                force=True,
            )

    @pytest.mark.asyncio
    async def test_force_promotion_with_admin(
        self, promotion_service, mock_ranker, mock_skill_service, ineligible_pattern
    ):
        """Should allow force=True from admin agent (H-2 security fix)."""
        # Update pattern for admin agent
        ineligible_pattern.agent_id = "athena-conductor"
        mock_ranker._agent_patterns["athena-conductor"] = {
            "tmws:read_file": ineligible_pattern,
        }
        mock_ranker._cache_timestamps["athena-conductor"] = time.time()

        # Admin agents can use force=True
        result = await promotion_service.promote_tool(
            tool_name="read_file",
            server_id="tmws",
            agent_id="athena-conductor",  # Admin agent
            force=True,
        )

        assert result.success is True
        mock_skill_service.create_skill.assert_called_once()

    @pytest.mark.asyncio
    async def test_custom_skill_name(
        self, promotion_service, mock_ranker, mock_skill_service, eligible_pattern
    ):
        """Should use custom skill name."""
        mock_ranker._agent_patterns["artemis"] = {
            "tmws:grep": eligible_pattern,
        }
        mock_ranker._cache_timestamps["artemis"] = time.time()

        await promotion_service.promote_tool(
            tool_name="grep",
            server_id="tmws",
            agent_id="artemis",
            skill_name="My Custom Grep Skill",
        )

        call_kwargs = mock_skill_service.create_skill.call_args[1]
        assert call_kwargs["name"] == "My Custom Grep Skill"

    @pytest.mark.asyncio
    async def test_prevents_duplicate_promotion(
        self, promotion_service, mock_ranker, mock_skill_service, eligible_pattern
    ):
        """Should prevent promoting same tool twice."""
        mock_ranker._agent_patterns["artemis"] = {
            "tmws:grep": eligible_pattern,
        }
        mock_ranker._cache_timestamps["artemis"] = time.time()

        # First promotion
        result1 = await promotion_service.promote_tool(
            tool_name="grep",
            server_id="tmws",
            agent_id="artemis",
        )
        assert result1.success is True

        # Second promotion (should fail)
        result2 = await promotion_service.promote_tool(
            tool_name="grep",
            server_id="tmws",
            agent_id="artemis",
        )
        assert result2.success is False
        assert "already promoted" in result2.error

    @pytest.mark.asyncio
    async def test_handles_missing_pattern(self, promotion_service, mock_ranker):
        """Should handle missing usage pattern."""
        mock_ranker._agent_patterns["artemis"] = {}
        mock_ranker._cache_timestamps["artemis"] = time.time()

        result = await promotion_service.promote_tool(
            tool_name="nonexistent",
            server_id="tmws",
            agent_id="artemis",
        )

        assert result.success is False
        assert "No usage pattern found" in result.error

    @pytest.mark.asyncio
    async def test_handles_skill_service_error(
        self, promotion_service, mock_ranker, mock_skill_service, eligible_pattern
    ):
        """Should handle SkillService errors."""
        mock_ranker._agent_patterns["artemis"] = {
            "tmws:grep": eligible_pattern,
        }
        mock_ranker._cache_timestamps["artemis"] = time.time()
        mock_skill_service.create_skill.side_effect = Exception("Database error")

        result = await promotion_service.promote_tool(
            tool_name="grep",
            server_id="tmws",
            agent_id="artemis",
        )

        assert result.success is False
        assert "Database error" in result.error


# ============================================================================
# auto_promote Tests
# ============================================================================


class TestAutoPromote:
    """Tests for auto_promote method."""

    @pytest.mark.asyncio
    async def test_auto_promotes_eligible_tools(
        self, promotion_service, mock_ranker, mock_skill_service
    ):
        """Should auto-promote eligible tools."""
        # Add multiple eligible patterns
        for i in range(3):
            mock_ranker._agent_patterns.setdefault("artemis", {})[f"tmws:tool{i}"] = (
                ToolUsagePattern(
                    tool_name=f"tool{i}",
                    server_id="tmws",
                    agent_id="artemis",
                    usage_count=100,
                    success_count=90,
                    last_used=datetime.now() - timedelta(days=10),
                    query_contexts=[f"q{j}" for j in range(10)],
                )
            )
        mock_ranker._cache_timestamps["artemis"] = time.time()

        results = await promotion_service.auto_promote(agent_id="artemis", max_promotions=2)

        assert len(results) == 2
        assert all(r.success for r in results)

    @pytest.mark.asyncio
    async def test_skips_ineligible_tools(
        self, promotion_service, mock_ranker, mock_skill_service, ineligible_pattern
    ):
        """Should skip ineligible tools."""
        mock_ranker._agent_patterns["artemis"] = {
            "tmws:read_file": ineligible_pattern,
        }
        mock_ranker._cache_timestamps["artemis"] = time.time()

        results = await promotion_service.auto_promote(agent_id="artemis")

        assert len(results) == 0


# ============================================================================
# get_promotion_stats Tests
# ============================================================================


class TestGetPromotionStats:
    """Tests for get_promotion_stats method."""

    @pytest.mark.asyncio
    async def test_returns_stats(self, promotion_service):
        """Should return promotion statistics."""
        stats = await promotion_service.get_promotion_stats()

        assert "total_promoted" in stats
        assert "promoted_tools" in stats
        assert "criteria" in stats
        assert stats["total_promoted"] == 0

    @pytest.mark.asyncio
    async def test_tracks_promoted_count(
        self, promotion_service, mock_ranker, mock_skill_service, eligible_pattern
    ):
        """Should track number of promoted tools."""
        mock_ranker._agent_patterns["artemis"] = {
            "tmws:grep": eligible_pattern,
        }
        mock_ranker._cache_timestamps["artemis"] = time.time()

        await promotion_service.promote_tool(
            tool_name="grep",
            server_id="tmws",
            agent_id="artemis",
        )

        stats = await promotion_service.get_promotion_stats()
        assert stats["total_promoted"] == 1
        assert "tmws:grep" in stats["promoted_tools"]


# ============================================================================
# Edge Cases
# ============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    @pytest.mark.asyncio
    async def test_no_skill_service(self, mock_ranker, criteria, eligible_pattern):
        """Should handle missing skill service."""
        service = ToolPromotionService(
            adaptive_ranker=mock_ranker,
            criteria=criteria,
        )
        mock_ranker._agent_patterns["artemis"] = {
            "tmws:grep": eligible_pattern,
        }
        mock_ranker._cache_timestamps["artemis"] = time.time()

        result = await service.promote_tool(
            tool_name="grep",
            server_id="tmws",
            agent_id="artemis",
        )

        assert result.success is False
        assert "SkillService not configured" in result.error

    @pytest.mark.asyncio
    async def test_set_services_after_init(self, mock_ranker, mock_skill_service, eligible_pattern):
        """Should allow setting services after init."""
        service = ToolPromotionService()
        service.set_adaptive_ranker(mock_ranker)
        service.set_skill_service(mock_skill_service)

        mock_ranker._agent_patterns["artemis"] = {
            "tmws:grep": eligible_pattern,
        }
        mock_ranker._cache_timestamps["artemis"] = time.time()

        result = await service.promote_tool(
            tool_name="grep",
            server_id="tmws",
            agent_id="artemis",
        )

        assert result.success is True
