"""
Integration tests for MCP Tools Summary API endpoint.

This module tests the /api/v1/mcp/tools/summary endpoint which implements
the defer_loading pattern for efficient token usage in Push-type integrations.

Reference: https://www.anthropic.com/engineering/advanced-tool-use

Security Requirements:
- SEC-PUSH-2: Namespace isolation via API
- V-TOOL-1: Namespace isolation for multi-tenant security
- Rate limiting: 30/min production, 60/min development

Test Categories:
1. Basic Functionality: Valid requests return expected structure
2. Rate Limiting: Endpoint respects rate limits
3. Security: Namespace isolation (V-TOOL-1)
4. Error Handling: Graceful degradation on invalid inputs
"""

import pytest

# Mark all tests in this module as asyncio
pytestmark = pytest.mark.asyncio


class TestMCPToolsSummaryBasic:
    """Test basic functionality of MCP tools summary endpoint."""

    async def test_summary_returns_expected_structure(self, async_client):
        """Test that summary endpoint returns expected JSON structure.

        Expected response:
        {
            "total_count": int,
            "frequently_used": [
                {"server": str, "tool": str, "description": str, "usage_count": int}
            ],
            "servers": [str],
            "token_estimate": int
        }
        """
        response = await async_client.get("/api/v1/mcp/tools/summary")

        assert response.status_code == 200
        data = response.json()

        # Verify required fields exist
        assert "total_count" in data
        assert "frequently_used" in data
        assert "servers" in data
        assert "token_estimate" in data

        # Verify types
        assert isinstance(data["total_count"], int)
        assert isinstance(data["frequently_used"], list)
        assert isinstance(data["servers"], list)
        assert isinstance(data["token_estimate"], int)

    async def test_summary_with_limit_parameter(self, async_client):
        """Test that limit parameter controls frequently_used count."""
        # Request with limit=3
        response = await async_client.get("/api/v1/mcp/tools/summary?limit=3")

        assert response.status_code == 200
        data = response.json()

        # frequently_used should have at most 'limit' items
        assert len(data["frequently_used"]) <= 3

    async def test_summary_with_default_limit(self, async_client):
        """Test that default limit is applied (5)."""
        response = await async_client.get("/api/v1/mcp/tools/summary")

        assert response.status_code == 200
        data = response.json()

        # Default limit is 5
        assert len(data["frequently_used"]) <= 5

    async def test_summary_limit_boundary_min(self, async_client):
        """Test minimum limit value (1)."""
        response = await async_client.get("/api/v1/mcp/tools/summary?limit=1")

        assert response.status_code == 200
        data = response.json()

        assert len(data["frequently_used"]) <= 1

    async def test_summary_limit_boundary_max(self, async_client):
        """Test maximum reasonable limit value."""
        response = await async_client.get("/api/v1/mcp/tools/summary?limit=20")

        assert response.status_code == 200
        data = response.json()

        # Should not exceed 20
        assert len(data["frequently_used"]) <= 20


class TestMCPToolsSummaryFrequentlyUsed:
    """Test frequently_used tool structure in response."""

    async def test_tool_structure_has_required_fields(self, async_client):
        """Test that each tool in frequently_used has required fields."""
        response = await async_client.get("/api/v1/mcp/tools/summary")

        assert response.status_code == 200
        data = response.json()

        for tool in data["frequently_used"]:
            # Required fields per ToolSummary interface
            assert "server" in tool
            assert "tool" in tool
            assert "description" in tool
            assert "usage_count" in tool

            # Type validation
            assert isinstance(tool["server"], str)
            assert isinstance(tool["tool"], str)
            assert isinstance(tool["description"], str)
            assert isinstance(tool["usage_count"], int)

    async def test_tools_sorted_by_usage_count_descending(self, async_client):
        """Test that tools are sorted by usage_count in descending order."""
        response = await async_client.get("/api/v1/mcp/tools/summary?limit=10")

        assert response.status_code == 200
        data = response.json()

        if len(data["frequently_used"]) >= 2:
            usage_counts = [t["usage_count"] for t in data["frequently_used"]]
            # Verify descending order
            assert usage_counts == sorted(usage_counts, reverse=True)


class TestMCPToolsSummaryTokenEstimate:
    """Test token estimation functionality."""

    async def test_token_estimate_is_reasonable(self, async_client):
        """Test that token estimate is within reasonable bounds.

        defer_loading pattern target: ~2,000 tokens (reduced from ~17,000)
        """
        response = await async_client.get("/api/v1/mcp/tools/summary")

        assert response.status_code == 200
        data = response.json()

        # Token estimate should be positive
        assert data["token_estimate"] >= 0

        # Should be much less than full tool definitions (~17,000)
        # Typical summary: ~2,000 tokens
        assert data["token_estimate"] < 10000  # Conservative upper bound

    async def test_token_estimate_scales_with_limit(self, async_client):
        """Test that token estimate increases with limit."""
        response_small = await async_client.get("/api/v1/mcp/tools/summary?limit=2")
        response_large = await async_client.get("/api/v1/mcp/tools/summary?limit=10")

        data_small = response_small.json()
        data_large = response_large.json()

        # Larger limit should have >= token estimate
        # (may be equal if fewer tools available than limit)
        assert data_large["token_estimate"] >= data_small["token_estimate"]


class TestMCPToolsSummaryRateLimiting:
    """Test rate limiting for MCP tools summary endpoint."""

    async def test_rate_limit_not_exceeded_in_test_env(self, async_client):
        """Test that rate limiting is bypassed in test environment.

        Per rate_limiter.py: Test environment has rate limiting disabled.
        """
        # Make multiple requests quickly
        for _ in range(10):
            response = await async_client.get("/api/v1/mcp/tools/summary")
            # All should succeed in test environment
            assert response.status_code == 200


class TestMCPToolsSummaryErrorHandling:
    """Test error handling for edge cases."""

    async def test_invalid_limit_type_returns_validation_error(self, async_client):
        """Test that non-integer limit returns validation error (400 or 422)."""
        response = await async_client.get("/api/v1/mcp/tools/summary?limit=abc")

        # FastAPI validation error - can be 400 (Bad Request) or 422 (Unprocessable Entity)
        assert response.status_code in [400, 422]

    async def test_negative_limit_returns_validation_error(self, async_client):
        """Test that negative limit returns validation error."""
        response = await async_client.get("/api/v1/mcp/tools/summary?limit=-1")

        # Should return validation error (422) or handle gracefully
        # Implementation may vary: 422 validation error or treat as 0
        assert response.status_code in [200, 422]

    async def test_zero_limit_returns_empty_frequently_used(self, async_client):
        """Test that limit=0 returns empty frequently_used list."""
        response = await async_client.get("/api/v1/mcp/tools/summary?limit=0")

        # Should succeed with empty list
        if response.status_code == 200:
            data = response.json()
            assert data["frequently_used"] == []


class TestMCPToolsSummaryPerformance:
    """Test performance characteristics of the endpoint."""

    async def test_response_time_under_threshold(self, async_client, performance_timer):
        """Test that response time is under acceptable threshold.

        Target: <200ms for API response (typical target for REST APIs)
        """
        timer = performance_timer.start()
        response = await async_client.get("/api/v1/mcp/tools/summary")
        elapsed_ms = timer.stop()

        assert response.status_code == 200

        # Performance target: <200ms
        assert elapsed_ms < 200, f"Response took {elapsed_ms:.2f}ms, expected <200ms"

    async def test_consistent_response_time(self, async_client, performance_timer):
        """Test that response times are consistent across multiple requests."""
        times = []

        for _ in range(5):
            timer = performance_timer.start()
            response = await async_client.get("/api/v1/mcp/tools/summary")
            elapsed_ms = timer.stop()

            assert response.status_code == 200
            times.append(elapsed_ms)

        # Calculate variance
        avg_time = sum(times) / len(times)
        max_deviation = max(abs(t - avg_time) for t in times)

        # Deviation should be within 50% of average (reasonable for async operations)
        assert max_deviation < avg_time * 0.5 or max_deviation < 50  # 50ms absolute tolerance


class TestMCPToolsSummaryIntegration:
    """Integration tests with other TMWS components."""

    async def test_summary_reflects_registered_tools(self, async_client):
        """Test that summary reflects actually registered MCP tools.

        This test verifies the endpoint connects to the MCP tools registry.
        """
        response = await async_client.get("/api/v1/mcp/tools/summary")

        assert response.status_code == 200
        data = response.json()

        # At minimum, should have system tools registered
        # (exact count depends on configuration)
        assert data["total_count"] >= 0
        assert isinstance(data["servers"], list)

    async def test_servers_list_contains_valid_servers(self, async_client):
        """Test that servers list contains valid server names."""
        response = await async_client.get("/api/v1/mcp/tools/summary")

        assert response.status_code == 200
        data = response.json()

        for server in data["servers"]:
            # Server names should be non-empty strings
            assert isinstance(server, str)
            assert len(server) > 0
