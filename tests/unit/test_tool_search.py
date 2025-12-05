"""Unit tests for Tool Search Service.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 1.5 - Unit Tests

Tests:
- Data model creation and validation
- Search ranking with source weights
- Tool indexing and retrieval
- Cache behavior

Author: Artemis (Implementation)
Created: 2025-12-04
"""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from src.models.tool_search import (
    MCPServerMetadata,
    MCPTransportType,
    ToolMetadata,
    ToolSearchQuery,
    ToolSearchResponse,
    ToolSearchResult,
    ToolSourceType,
    ToolUsageRecord,
)
from src.services.tool_search_service import (
    ToolSearchConfig,
    ToolSearchService,
)


class TestToolSearchModels:
    """Tests for Tool Search data models."""

    def test_tool_source_type_values(self):
        """Test ToolSourceType enum values."""
        assert ToolSourceType.SKILL.value == "skill"
        assert ToolSourceType.INTERNAL.value == "internal"
        assert ToolSourceType.EXTERNAL.value == "external"

    def test_tool_search_result_weighted_score_skill(self):
        """Test Skills get 2.0x weight (third core feature priority)."""
        result = ToolSearchResult(
            tool_name="test_skill",
            server_id="tmws:skills",
            description="Test skill",
            relevance_score=0.5,
            source_type=ToolSourceType.SKILL,
        )
        assert result.weighted_score == 1.0  # 0.5 * 2.0

    def test_tool_search_result_weighted_score_internal(self):
        """Test internal tools get 1.5x weight."""
        result = ToolSearchResult(
            tool_name="test_internal",
            server_id="tmws",
            description="Test internal tool",
            relevance_score=0.5,
            source_type=ToolSourceType.INTERNAL,
        )
        assert result.weighted_score == 0.75  # 0.5 * 1.5

    def test_tool_search_result_weighted_score_external(self):
        """Test external tools get 1.0x weight (no boost)."""
        result = ToolSearchResult(
            tool_name="test_external",
            server_id="mcp__context7",
            description="Test external tool",
            relevance_score=0.5,
            source_type=ToolSourceType.EXTERNAL,
        )
        assert result.weighted_score == 0.5  # 0.5 * 1.0

    def test_tool_metadata_to_embedding_text(self):
        """Test embedding text generation."""
        tool = ToolMetadata(
            name="grep",
            description="Search for patterns in files",
            tags=["search", "text", "regex"],
        )
        text = tool.to_embedding_text()
        assert "grep" in text
        assert "Search for patterns" in text
        assert "search" in text  # from tags

    def test_mcp_server_metadata_tool_count(self):
        """Test tool count property."""
        server = MCPServerMetadata(
            server_id="test",
            name="Test Server",
            description="Test",
            transport=MCPTransportType.STDIO,
            tools=[
                ToolMetadata(name="tool1", description=""),
                ToolMetadata(name="tool2", description=""),
            ],
        )
        assert server.tool_count == 2

    def test_mcp_server_metadata_is_connected(self):
        """Test is_connected property."""
        # Not connected (no last_connected)
        server1 = MCPServerMetadata(
            server_id="test",
            name="Test",
            description="",
            transport=MCPTransportType.STDIO,
        )
        assert not server1.is_connected

        # Connected (recent)
        server2 = MCPServerMetadata(
            server_id="test",
            name="Test",
            description="",
            transport=MCPTransportType.STDIO,
            last_connected=datetime.now(),
        )
        assert server2.is_connected

    def test_tool_usage_record_to_memory_content(self):
        """Test conversion to Memory format (first core feature integration)."""
        record = ToolUsageRecord(
            tool_name="grep",
            server_id="tmws",
            query="search code",
            outcome="success",
            latency_ms=45.2,
        )
        content = record.to_memory_content()
        assert content["tool_name"] == "grep"
        assert content["outcome"] == "success"
        assert "timestamp" in content

    def test_tool_search_query_defaults(self):
        """Test query defaults."""
        query = ToolSearchQuery(query="test")
        assert query.source == "all"
        assert query.limit == 10
        assert query.min_score == 0.3

    def test_tool_search_response_has_skills(self):
        """Test has_skills property."""
        # With skills
        response1 = ToolSearchResponse(
            results=[
                ToolSearchResult(
                    tool_name="skill1",
                    server_id="tmws:skills",
                    description="",
                    relevance_score=0.9,
                    source_type=ToolSourceType.SKILL,
                )
            ],
            query="test",
            total_found=1,
            search_latency_ms=10.0,
            sources_searched=["skills"],
        )
        assert response1.has_skills

        # Without skills
        response2 = ToolSearchResponse(
            results=[
                ToolSearchResult(
                    tool_name="internal1",
                    server_id="tmws",
                    description="",
                    relevance_score=0.9,
                    source_type=ToolSourceType.INTERNAL,
                )
            ],
            query="test",
            total_found=1,
            search_latency_ms=10.0,
            sources_searched=["internal"],
        )
        assert not response2.has_skills


class TestToolSearchService:
    """Tests for Tool Search Service."""

    @pytest.fixture
    def config(self):
        """Create test config."""
        return ToolSearchConfig(
            collection_name="test_tools",
            skills_weight=2.0,
            internal_weight=1.5,
            external_weight=1.0,
        )

    @pytest.fixture
    def mock_chromadb(self):
        """Create mock ChromaDB client."""
        with patch("src.services.tool_search_service.chromadb") as mock:
            mock_client = MagicMock()
            mock_collection = MagicMock()
            mock_collection.count.return_value = 0
            mock_collection.query.return_value = {
                "metadatas": [[]],
                "distances": [[]],
            }
            mock_client.get_or_create_collection.return_value = mock_collection
            mock.PersistentClient.return_value = mock_client
            yield mock, mock_client, mock_collection

    def test_ranking_applies_weights(self, config):
        """Test that ranking applies source weights correctly."""
        service = ToolSearchService.__new__(ToolSearchService)
        service.config = config

        results = [
            ToolSearchResult(
                tool_name="external",
                server_id="mcp__test",
                description="",
                relevance_score=0.9,
                source_type=ToolSourceType.EXTERNAL,
            ),
            ToolSearchResult(
                tool_name="skill",
                server_id="tmws:skills",
                description="",
                relevance_score=0.5,
                source_type=ToolSourceType.SKILL,
            ),
            ToolSearchResult(
                tool_name="internal",
                server_id="tmws",
                description="",
                relevance_score=0.6,
                source_type=ToolSourceType.INTERNAL,
            ),
        ]

        ranked = service._apply_ranking(results)

        # Skills should be first despite lower base score
        # skill: 0.5 * 2.0 = 1.0
        # internal: 0.6 * 1.5 = 0.9
        # external: 0.9 * 1.0 = 0.9
        assert ranked[0].tool_name == "skill"
        assert ranked[0].weighted_score == 1.0

    def test_get_searched_sources_all(self, config):
        """Test sources for 'all' filter."""
        service = ToolSearchService.__new__(ToolSearchService)
        sources = service._get_searched_sources("all")
        assert "skills" in sources
        assert "internal" in sources
        assert "external" in sources

    def test_get_searched_sources_specific(self, config):
        """Test sources for specific filter."""
        service = ToolSearchService.__new__(ToolSearchService)
        assert service._get_searched_sources("skills") == ["skills"]
        assert service._get_searched_sources("mcp_servers") == ["external"]


class TestToolSearchRanking:
    """Tests for search result ranking logic."""

    def test_skills_always_rank_first(self):
        """Test that Skills always appear before other sources with same base score."""
        skill_result = ToolSearchResult(
            tool_name="skill",
            server_id="tmws:skills",
            description="",
            relevance_score=0.5,
            source_type=ToolSourceType.SKILL,
        )
        internal_result = ToolSearchResult(
            tool_name="internal",
            server_id="tmws",
            description="",
            relevance_score=0.5,
            source_type=ToolSourceType.INTERNAL,
        )
        external_result = ToolSearchResult(
            tool_name="external",
            server_id="mcp__test",
            description="",
            relevance_score=0.5,
            source_type=ToolSourceType.EXTERNAL,
        )

        # Even with same base score, weighted scores differ
        assert skill_result.weighted_score > internal_result.weighted_score
        assert internal_result.weighted_score > external_result.weighted_score

    def test_high_external_can_beat_low_skill(self):
        """Test that very high external score can beat low skill score."""
        skill_result = ToolSearchResult(
            tool_name="skill",
            server_id="tmws:skills",
            description="",
            relevance_score=0.3,  # Low score
            source_type=ToolSourceType.SKILL,
        )
        external_result = ToolSearchResult(
            tool_name="external",
            server_id="mcp__test",
            description="",
            relevance_score=0.95,  # Very high score
            source_type=ToolSourceType.EXTERNAL,
        )

        # skill: 0.3 * 2.0 = 0.6
        # external: 0.95 * 1.0 = 0.95
        assert external_result.weighted_score > skill_result.weighted_score


class TestFourFeaturesIntegration:
    """Tests verifying 4 core features are preserved."""

    def test_memory_integration_tool_usage_record(self):
        """Test tool usage can be stored in Memory (first core feature)."""
        record = ToolUsageRecord(
            tool_name="grep",
            server_id="tmws",
            query="search code",
            outcome="success",
        )
        content = record.to_memory_content()

        # Should be valid for store_memory
        assert isinstance(content, dict)
        assert "tool_name" in content
        assert "timestamp" in content

    def test_skills_priority_in_ranking(self):
        """Test Skills get priority ranking (third core feature)."""
        skill = ToolSearchResult(
            tool_name="skill",
            server_id="tmws:skills",
            description="",
            relevance_score=0.5,
            source_type=ToolSourceType.SKILL,
        )
        # Skills must get 2.0x weight
        assert skill.weighted_score == 1.0

    def test_search_response_includes_sources(self):
        """Test search response tracks sources (supports Narrative)."""
        response = ToolSearchResponse(
            results=[],
            query="test",
            total_found=0,
            search_latency_ms=10.0,
            sources_searched=["skills", "internal", "external"],
        )
        # Should have all sources for Narrative context
        assert len(response.sources_searched) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
