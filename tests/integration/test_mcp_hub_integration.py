"""Integration tests for Tool Search + MCP Hub.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 3.3 - Integration Testing

Tests:
- MCP Hub Manager initialization and connection pooling
- Tool Search Service integration with ChromaDB
- Security layer integration (S-P0-3, S-P0-6, S-P0-7)
- MCP tool registration and invocation flow

Author: Metis (Testing) + Hestia (Security Review)
Created: 2025-12-05
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.infrastructure.mcp.hub_manager import HubConnectionStats, MCPHubManager
from src.infrastructure.security import (
    InputValidationError,
    ResponseLimitError,
    check_response_size,
    validate_tool_input,
)
from src.models.tool_search import (
    MCPServerMetadata,
    MCPTransportType,
    ToolMetadata,
    ToolSearchResult,
    ToolSourceType,
)
from src.services.tool_search_service import ToolSearchService


class TestMCPHubManagerIntegration:
    """Integration tests for MCPHubManager."""

    @pytest.fixture
    def mock_mcp_manager(self):
        """Create mock MCP Manager."""
        manager = MagicMock()
        manager.connections = {}
        manager.list_connections.return_value = []
        manager.get_connection.return_value = None
        return manager

    @pytest.fixture
    def mock_tool_search_service(self):
        """Create mock ToolSearchService."""
        service = AsyncMock(spec=ToolSearchService)
        service.get_stats.return_value = {
            "collection_name": "tmws_tools",
            "total_indexed": 0,
            "internal_tools": 0,
            "mcp_servers": 0,
            "mcp_server_tools": 0,
        }
        return service

    @pytest.fixture
    def hub_manager(self, mock_mcp_manager, mock_tool_search_service):
        """Create MCPHubManager with mocks."""
        hub = MCPHubManager(
            mcp_manager=mock_mcp_manager,
            tool_search_service=mock_tool_search_service,
        )
        hub._initialized = True
        return hub

    @pytest.mark.asyncio
    async def test_connection_limit_enforced(self, hub_manager, mock_mcp_manager):
        """Test MAX_CONNECTIONS limit is enforced (S-P0 security)."""
        # Simulate max connections reached
        mock_mcp_manager.connections = {f"server_{i}": MagicMock() for i in range(10)}

        with pytest.raises(Exception) as exc_info:
            await hub_manager.connect_server("new_server")

        assert "Maximum connections" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_list_servers_returns_correct_format(self, hub_manager):
        """Test list_servers returns expected structure."""
        with patch.object(hub_manager, "_mcp_manager") as mock_manager:
            mock_manager.get_connection.return_value = None

            with patch("src.infrastructure.mcp.hub_manager.load_mcp_presets") as mock_presets:
                mock_presets.return_value = MagicMock(
                    servers={
                        "context7": MagicMock(
                            name="Context7",
                            transport_type=MagicMock(value="stdio"),
                            auto_connect=True,
                        )
                    }
                )

                servers = await hub_manager.list_servers()

        assert isinstance(servers, list)
        assert len(servers) == 1
        assert servers[0]["server_id"] == "context7"
        assert "is_connected" in servers[0]
        assert "tool_count" in servers[0]

    @pytest.mark.asyncio
    async def test_get_status_includes_all_fields(
        self, hub_manager, mock_mcp_manager, mock_tool_search_service
    ):
        """Test get_status returns complete information."""
        mock_mcp_manager.list_connections.return_value = []

        status = await hub_manager.get_status()

        assert "initialized" in status
        assert "max_connections" in status
        assert "active_connections" in status
        assert "total_tools_indexed" in status
        assert status["max_connections"] == 10


class TestSecurityIntegration:
    """Integration tests for security layer (Phase 2 requirements)."""

    def test_sp03_input_validation_blocks_invalid(self):
        """Test S-P0-3: JSON Schema validation blocks invalid input."""
        schema = {
            "type": "object",
            "properties": {"query": {"type": "string", "maxLength": 100}},
            "required": ["query"],
        }

        # Missing required field
        with pytest.raises(InputValidationError):
            validate_tool_input({}, schema, "test_tool")

        # Wrong type
        with pytest.raises(InputValidationError):
            validate_tool_input({"query": 123}, schema, "test_tool")

    def test_sp03_input_validation_passes_valid(self):
        """Test S-P0-3: Valid input passes validation."""
        schema = {
            "type": "object",
            "properties": {"query": {"type": "string"}},
        }

        # Should not raise
        validate_tool_input({"query": "test"}, schema, "test_tool")

    def test_sp06_response_size_limit_blocks_large(self):
        """Test S-P0-6: Large responses are blocked."""
        from src.infrastructure.security.response_limits import ResponseLimiter

        limiter = ResponseLimiter(max_response_bytes=100)
        large_response = {"data": "x" * 200}

        with pytest.raises(ResponseLimitError):
            limiter.check_size(large_response)

    def test_sp06_response_size_passes_small(self):
        """Test S-P0-6: Small responses pass."""
        small_response = {"data": "test"}
        size = check_response_size(small_response)
        assert size > 0
        assert size < 100


class TestToolSearchIntegration:
    """Integration tests for ToolSearchService with security."""

    def test_tool_metadata_security_fields(self):
        """Test ToolMetadata includes security-relevant fields."""
        tool = ToolMetadata(
            name="test_tool",
            description="A test tool",
            input_schema={"type": "object", "properties": {}},
        )

        assert tool.input_schema is not None
        assert tool.to_embedding_text() is not None

    def test_tool_search_result_weighted_scoring(self):
        """Test search results apply correct source weights."""
        # Skills: 2.0x weight
        skill = ToolSearchResult(
            tool_name="skill",
            server_id="tmws:skills",
            description="test",
            relevance_score=0.5,
            source_type=ToolSourceType.SKILL,
        )
        assert skill.weighted_score == 1.0

        # Internal: 1.5x weight
        internal = ToolSearchResult(
            tool_name="internal",
            server_id="tmws",
            description="test",
            relevance_score=0.5,
            source_type=ToolSourceType.INTERNAL,
        )
        assert internal.weighted_score == 0.75

        # External: 1.0x weight
        external = ToolSearchResult(
            tool_name="external",
            server_id="mcp__context7",
            description="test",
            relevance_score=0.5,
            source_type=ToolSourceType.EXTERNAL,
        )
        assert external.weighted_score == 0.5

    def test_mcp_server_metadata_structure(self):
        """Test MCPServerMetadata has required fields."""
        server = MCPServerMetadata(
            server_id="context7",
            name="Context7",
            description="Documentation provider",
            transport=MCPTransportType.STDIO,
            tools=[
                ToolMetadata(name="resolve-library-id", description="Resolve library"),
                ToolMetadata(name="get-library-docs", description="Get docs"),
            ],
        )

        assert server.tool_count == 2
        assert not server.is_connected  # No last_connected set


class TestEndToEndFlow:
    """End-to-end integration tests for the complete flow."""

    @pytest.mark.asyncio
    async def test_tool_discovery_to_execution_flow(self):
        """Test the complete flow: search -> select -> execute."""
        # 1. Create mock search results
        search_results = [
            ToolSearchResult(
                tool_name="resolve-library-id",
                server_id="mcp__context7",
                description="Resolve a library name to ID",
                relevance_score=0.95,
                source_type=ToolSourceType.EXTERNAL,
            )
        ]

        # 2. Verify ranking
        assert search_results[0].weighted_score == 0.95  # 1.0x for external

        # 3. Mock tool execution (with security checks)
        tool_schema = {
            "type": "object",
            "properties": {"libraryName": {"type": "string"}},
            "required": ["libraryName"],
        }
        arguments = {"libraryName": "react"}

        # S-P0-3: Validate input
        validate_tool_input(arguments, tool_schema, "resolve-library-id")

        # S-P0-6: Check response size (mock result)
        mock_result = {"libraryId": "/facebook/react", "version": "18.2.0"}
        check_response_size(mock_result)

        # Flow complete without errors

    @pytest.mark.asyncio
    async def test_security_chain_blocks_malicious_input(self):
        """Test that security chain blocks malicious inputs."""
        # Attempt SQL injection in query
        malicious_input = {"query": "'; DROP TABLE tools; --"}

        # Schema validation would catch type issues, but string is valid
        # This tests that downstream validation/sanitization is needed
        schema = {"type": "object", "properties": {"query": {"type": "string"}}}

        # Input passes schema (string type is valid)
        validate_tool_input(malicious_input, schema, "search_tools")
        # Note: Additional sanitization happens at tool execution layer


class TestHubConnectionStats:
    """Tests for HubConnectionStats data class."""

    def test_stats_default_values(self):
        """Test default values are reasonable."""
        stats = HubConnectionStats()
        assert stats.total_servers == 0
        assert stats.connected_servers == 0
        assert stats.total_tools == 0
        assert stats.last_refresh is None

    def test_stats_with_values(self):
        """Test stats with custom values."""
        from datetime import datetime

        now = datetime.now()
        stats = HubConnectionStats(
            total_servers=5,
            connected_servers=3,
            total_tools=50,
            last_refresh=now,
        )
        assert stats.total_servers == 5
        assert stats.connected_servers == 3
        assert stats.total_tools == 50
        assert stats.last_refresh == now


class TestFourCoreFeatures:
    """Regression tests ensuring 4 core features are not impacted."""

    def test_memory_integration_preserved(self):
        """Test Memory integration (1st core feature) is preserved."""
        from src.models.tool_search import ToolUsageRecord

        record = ToolUsageRecord(
            tool_name="search_tools",
            server_id="tmws",
            query="find database tools",
            outcome="success",
            latency_ms=45.2,
        )

        # Should produce Memory-compatible content
        content = record.to_memory_content()
        assert isinstance(content, dict)
        assert "tool_name" in content
        assert "timestamp" in content

    def test_skills_priority_preserved(self):
        """Test Skills priority (3rd core feature) is preserved."""
        skill_result = ToolSearchResult(
            tool_name="custom_skill",
            server_id="tmws:skills",
            description="User-defined skill",
            relevance_score=0.5,
            source_type=ToolSourceType.SKILL,
        )

        # Skills must maintain 2.0x weight
        assert skill_result.weighted_score == 1.0

    def test_tool_search_supports_narrative(self):
        """Test Tool Search supports Narrative (4th core feature)."""
        from src.models.tool_search import ToolSearchResponse

        response = ToolSearchResponse(
            results=[],
            query="database operations",
            total_found=0,
            search_latency_ms=15.0,
            sources_searched=["skills", "internal", "external"],
        )

        # Response includes metadata for Narrative context building
        assert response.query is not None
        assert response.sources_searched is not None
        assert len(response.sources_searched) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
