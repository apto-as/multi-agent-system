"""Unit tests for DynamicToolRegistry (P0.2 Skills Gap Fix).

Tests for dynamic MCP tool registration when skills are activated.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.services.skill_service.skill_activation import DynamicToolRegistry
from src.core.exceptions import ValidationError


@pytest.fixture
def mock_mcp_server():
    """Create a mock FastMCP server."""
    server = MagicMock()
    server.tool = MagicMock(return_value=lambda f: f)  # Decorator pattern
    return server


@pytest.fixture
def registry(mock_mcp_server):
    """Create a DynamicToolRegistry instance with mock server."""
    return DynamicToolRegistry(mcp_server=mock_mcp_server)


class TestDynamicToolRegistryInit:
    """Test DynamicToolRegistry initialization."""

    def test_init_with_server(self, mock_mcp_server):
        """Test initialization with MCP server."""
        registry = DynamicToolRegistry(mcp_server=mock_mcp_server)
        assert registry.mcp_server is mock_mcp_server
        assert registry._registered_tools == {}

    def test_init_without_server(self):
        """Test initialization without MCP server."""
        registry = DynamicToolRegistry()
        assert registry.mcp_server is None
        assert registry._registered_tools == {}

    def test_set_server(self, mock_mcp_server):
        """Test setting server after initialization."""
        registry = DynamicToolRegistry()
        assert registry.mcp_server is None

        registry.set_server(mock_mcp_server)
        assert registry.mcp_server is mock_mcp_server


class TestToolRegistration:
    """Test tool registration functionality."""

    def test_register_tool_success(self, registry, mock_mcp_server):
        """Test successful tool registration."""
        skill_id = "skill-123"
        skill_name = "test-skill"
        skill_content = "# Test Skill\nThis is a test skill."

        tool_name = registry.register_tool(skill_id, skill_name, skill_content)

        assert tool_name == "skill_test_skill"
        assert tool_name in registry._registered_tools
        assert registry._registered_tools[tool_name] == skill_id
        mock_mcp_server.tool.assert_called_once()

    def test_register_tool_no_server(self):
        """Test registration fails without MCP server."""
        registry = DynamicToolRegistry()

        with pytest.raises(RuntimeError, match="MCP server not initialized"):
            registry.register_tool("skill-123", "test-skill", "content")

    def test_register_tool_empty_content(self, registry):
        """Test registration fails with empty content."""
        with pytest.raises(ValidationError, match="Skill content cannot be empty"):
            registry.register_tool("skill-123", "test-skill", "")

    def test_register_tool_whitespace_content(self, registry):
        """Test registration fails with whitespace-only content."""
        with pytest.raises(ValidationError, match="Skill content cannot be empty"):
            registry.register_tool("skill-123", "test-skill", "   \n\t  ")

    def test_register_tool_content_too_large(self, registry):
        """Test registration fails with content exceeding 50KB."""
        large_content = "x" * 50001  # 50KB + 1 byte

        with pytest.raises(ValidationError, match="Skill content too large"):
            registry.register_tool("skill-123", "test-skill", large_content)

    def test_register_tool_name_normalization(self, registry):
        """Test tool name normalization (hyphens to underscores)."""
        skill_id = "skill-456"
        skill_name = "my-awesome-skill"
        skill_content = "# Test"

        tool_name = registry.register_tool(skill_id, skill_name, skill_content)

        assert tool_name == "skill_my_awesome_skill"
        assert "-" not in tool_name


class TestToolUnregistration:
    """Test tool unregistration functionality."""

    def test_unregister_tool_success(self, registry):
        """Test successful tool unregistration."""
        skill_id = "skill-123"
        tool_name = "skill_test_skill"

        # Register first
        registry._registered_tools[tool_name] = skill_id

        # Unregister
        registry.unregister_tool(skill_id, tool_name)

        assert tool_name not in registry._registered_tools

    def test_unregister_nonexistent_tool(self, registry):
        """Test unregistering a non-existent tool (no-op)."""
        # Should not raise
        registry.unregister_tool("skill-999", "nonexistent_tool")


class TestToolQueries:
    """Test tool query methods."""

    def test_is_registered_true(self, registry):
        """Test is_registered returns True for registered tool."""
        registry._registered_tools["skill_test"] = "skill-123"

        assert registry.is_registered("skill_test") is True

    def test_is_registered_false(self, registry):
        """Test is_registered returns False for unregistered tool."""
        assert registry.is_registered("nonexistent_tool") is False

    def test_get_registered_tools(self, registry):
        """Test get_registered_tools returns copy of registry."""
        registry._registered_tools = {
            "skill_test1": "skill-123",
            "skill_test2": "skill-456",
        }

        tools = registry.get_registered_tools()

        assert tools == {"skill_test1": "skill-123", "skill_test2": "skill-456"}
        # Verify it's a copy, not a reference
        assert tools is not registry._registered_tools


class TestToolHandler:
    """Test generated tool handler functionality."""

    @pytest.mark.asyncio
    async def test_tool_handler_execution(self, registry):
        """Test that generated handler executes correctly."""
        skill_content = "# Test Skill\nDo something"

        handler = registry._generate_tool_handler(skill_content)

        result = await handler(arg1="value1", arg2="value2")

        assert result["success"] is True
        assert result["message"] == "Skill invoked successfully"
        assert result["instructions"] == skill_content
        assert result["arguments"] == {"arg1": "value1", "arg2": "value2"}

    @pytest.mark.asyncio
    async def test_tool_handler_no_args(self, registry):
        """Test handler works with no arguments."""
        skill_content = "# Test"

        handler = registry._generate_tool_handler(skill_content)

        result = await handler()

        assert result["success"] is True
        assert result["arguments"] == {}


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_multiple_registrations_same_skill(self, registry, mock_mcp_server):
        """Test registering same skill multiple times."""
        skill_id = "skill-123"
        skill_name = "test-skill"
        skill_content = "# Test"

        # First registration
        tool_name1 = registry.register_tool(skill_id, skill_name, skill_content)

        # Second registration (should overwrite in registry)
        tool_name2 = registry.register_tool(skill_id, skill_name, skill_content)

        assert tool_name1 == tool_name2
        # Registry should only have one entry
        assert len([k for k in registry._registered_tools if registry._registered_tools[k] == skill_id]) == 1

    def test_content_at_boundary(self, registry):
        """Test registration with content at 50KB boundary."""
        content_at_limit = "x" * 50000  # Exactly 50KB

        # Should succeed
        tool_name = registry.register_tool("skill-123", "test", content_at_limit)
        assert tool_name == "skill_test"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
