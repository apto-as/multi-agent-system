"""Four Features Regression Test Suite.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md

CRITICAL TEST: This test MUST pass on every commit.
It verifies that TMWS's 4 core features remain intact after Tool Search integration.

The 4 core features are:
1. 記憶 (Memory) - Semantic memory storage and retrieval
2. ナラティブ (Narrative) - Agent context and storytelling
3. スキル (Skills) - Reusable capabilities with priority ranking
4. 学習 (Learning) - Usage pattern tracking and adaptation

Author: Artemis (Implementation) + Hestia (Verification)
Created: 2025-12-04
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from src.models.tool_search import (
    ToolSearchResult,
    ToolSourceType,
    ToolUsageRecord,
)


class TestMemoryFeaturePreserved:
    """第1特徴: 記憶 (Memory) が正常に動作することを検証."""

    def test_tool_usage_can_be_stored_as_memory(self):
        """ツール使用履歴がMemory形式で保存可能."""
        record = ToolUsageRecord(
            tool_name="search_tools",
            server_id="tmws",
            query="find code search tool",
            outcome="success",
            latency_ms=45.2,
        )

        content = record.to_memory_content()

        # Memory storage requirements
        assert isinstance(content, dict)
        assert "tool_name" in content
        assert "query" in content
        assert "outcome" in content
        assert "timestamp" in content
        assert content["tool_name"] == "search_tools"
        assert content["outcome"] == "success"

    def test_memory_content_includes_timestamp(self):
        """Memory内容にタイムスタンプが含まれる."""
        record = ToolUsageRecord(
            tool_name="test",
            server_id="tmws",
            query="test",
            outcome="success",
        )

        content = record.to_memory_content()
        timestamp = content["timestamp"]

        # Should be ISO format string
        assert isinstance(timestamp, str)
        # Should be parseable
        datetime.fromisoformat(timestamp)

    def test_chromadb_collection_separation(self):
        """ChromaDBコレクションが分離されている (tmws_memories vs tmws_tools)."""
        from src.services.tool_search_service import ToolSearchConfig

        # Tool search uses separate collection
        config = ToolSearchConfig()
        assert config.collection_name == "tmws_tools"
        assert config.collection_name != "tmws_memories"


class TestNarrativeFeaturePreserved:
    """第2特徴: ナラティブ (Narrative) が正常に動作することを検証."""

    def test_search_response_includes_context(self):
        """検索レスポンスにナラティブ用コンテキストが含まれる."""
        from src.models.tool_search import ToolSearchResponse

        response = ToolSearchResponse(
            results=[
                ToolSearchResult(
                    tool_name="grep",
                    server_id="tmws",
                    description="Search for patterns",
                    relevance_score=0.9,
                    source_type=ToolSourceType.INTERNAL,
                )
            ],
            query="search code",
            total_found=1,
            search_latency_ms=15.5,
            sources_searched=["skills", "internal", "external"],
        )

        # Narrative can use these fields
        assert response.query == "search code"
        assert response.total_found == 1
        assert len(response.sources_searched) == 3
        assert response.top_result is not None
        assert response.top_result.tool_name == "grep"

    def test_tool_metadata_supports_narrative(self):
        """ツールメタデータがナラティブをサポート."""
        from src.models.tool_search import ToolMetadata

        tool = ToolMetadata(
            name="advanced_search",
            description="Perform semantic search across codebase with AI-powered ranking",
            tags=["search", "semantic", "ai"],
        )

        # Narrative can use description for context
        assert len(tool.description) > 20
        assert "semantic" in tool.description.lower()


class TestSkillsFeatureEnhanced:
    """第3特徴: スキル (Skills) が強化されていることを検証."""

    def test_skills_get_2x_weight_in_ranking(self):
        """スキルが検索結果で2.0倍の重みを持つ."""
        skill = ToolSearchResult(
            tool_name="code_analysis_skill",
            server_id="tmws:skills",
            description="Analyze code quality",
            relevance_score=0.5,
            source_type=ToolSourceType.SKILL,
        )

        # Skills MUST get 2.0x weight
        assert skill.weighted_score == 1.0  # 0.5 * 2.0

    def test_skills_rank_higher_than_same_score_internal(self):
        """同じスコアの場合、スキルは内部ツールより上位."""
        skill = ToolSearchResult(
            tool_name="skill",
            server_id="tmws:skills",
            description="",
            relevance_score=0.5,
            source_type=ToolSourceType.SKILL,
        )
        internal = ToolSearchResult(
            tool_name="internal",
            server_id="tmws",
            description="",
            relevance_score=0.5,
            source_type=ToolSourceType.INTERNAL,
        )

        # skill: 0.5 * 2.0 = 1.0
        # internal: 0.5 * 1.5 = 0.75
        assert skill.weighted_score > internal.weighted_score

    def test_skills_rank_higher_than_same_score_external(self):
        """同じスコアの場合、スキルは外部ツールより上位."""
        skill = ToolSearchResult(
            tool_name="skill",
            server_id="tmws:skills",
            description="",
            relevance_score=0.5,
            source_type=ToolSourceType.SKILL,
        )
        external = ToolSearchResult(
            tool_name="external",
            server_id="mcp__context7",
            description="",
            relevance_score=0.5,
            source_type=ToolSourceType.EXTERNAL,
        )

        # skill: 0.5 * 2.0 = 1.0
        # external: 0.5 * 1.0 = 0.5
        assert skill.weighted_score > external.weighted_score

    def test_skill_source_type_is_distinct(self):
        """スキルソースタイプが他と区別される."""
        assert ToolSourceType.SKILL != ToolSourceType.INTERNAL
        assert ToolSourceType.SKILL != ToolSourceType.EXTERNAL
        assert ToolSourceType.SKILL.value == "skill"


class TestLearningFeatureEnhanced:
    """第4特徴: 学習 (Learning) が強化されていることを検証."""

    def test_tool_usage_record_captures_outcome(self):
        """ツール使用記録が結果を記録."""
        success_record = ToolUsageRecord(
            tool_name="search_tools",
            server_id="tmws",
            query="find database tool",
            outcome="success",
            latency_ms=23.5,
        )

        error_record = ToolUsageRecord(
            tool_name="search_tools",
            server_id="tmws",
            query="invalid query",
            outcome="error",
            error_message="Invalid query format",
        )

        assert success_record.outcome == "success"
        assert error_record.outcome == "error"
        assert error_record.error_message is not None

    def test_tool_usage_record_captures_latency(self):
        """ツール使用記録がレイテンシを記録."""
        record = ToolUsageRecord(
            tool_name="search_tools",
            server_id="tmws",
            query="test",
            outcome="success",
            latency_ms=45.2,
        )

        assert record.latency_ms == 45.2

    def test_usage_record_supports_pattern_learning(self):
        """使用記録がパターン学習をサポート."""
        record = ToolUsageRecord(
            tool_name="grep",
            server_id="tmws",
            query="search for error handling code",
            outcome="success",
        )

        content = record.to_memory_content()

        # Learning system needs query and tool pairing
        assert "query" in content
        assert "tool_name" in content
        assert content["query"] == "search for error handling code"
        assert content["tool_name"] == "grep"


class TestNoRegressionInExistingFeatures:
    """既存機能に回帰がないことを検証."""

    def test_source_weights_are_correct(self):
        """ソース重みが仕様通り."""
        from src.services.tool_search_service import ToolSearchConfig

        config = ToolSearchConfig()

        # Must match specification
        assert config.skills_weight == 2.0
        assert config.internal_weight == 1.5
        assert config.external_weight == 1.0

    def test_weighted_score_calculation(self):
        """重み付けスコア計算が正確."""
        test_cases = [
            (ToolSourceType.SKILL, 0.5, 1.0),      # 0.5 * 2.0
            (ToolSourceType.INTERNAL, 0.5, 0.75),  # 0.5 * 1.5
            (ToolSourceType.EXTERNAL, 0.5, 0.5),   # 0.5 * 1.0
            (ToolSourceType.SKILL, 1.0, 2.0),      # 1.0 * 2.0
            (ToolSourceType.INTERNAL, 1.0, 1.5),   # 1.0 * 1.5
            (ToolSourceType.EXTERNAL, 1.0, 1.0),   # 1.0 * 1.0
        ]

        for source_type, relevance, expected in test_cases:
            result = ToolSearchResult(
                tool_name="test",
                server_id="test",
                description="",
                relevance_score=relevance,
                source_type=source_type,
            )
            assert result.weighted_score == expected, f"Failed for {source_type}"


# Pytest configuration
def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers",
        "four_features: Tests for TMWS 4 core features regression",
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
