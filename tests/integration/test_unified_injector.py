"""
Integration tests for Unified Context Injector (Claude Code Hooks).

This module tests the unified_injector.py which implements
the defer_loading pattern for Claude Code sessions.

Reference: https://www.anthropic.com/engineering/advanced-tool-use

Security Requirements:
- SEC-PUSH-1: Markdown content sanitization
- Prevents XSS/injection via context templates

Test Categories:
1. Context Loading: Template files load correctly
2. Sanitization: HTML/script tags are removed
3. MCP Integration: API client functions work
4. Event Handlers: Session events trigger correct injections
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Add hooks directory to path for imports
HOOKS_DIR = Path(__file__).parent.parent.parent / "hooks" / "core"
sys.path.insert(0, str(HOOKS_DIR))

# Mark all tests in this module as asyncio
pytestmark = pytest.mark.asyncio


class TestContextTemplateLoading:
    """Test context template loading functionality."""

    def test_level1_template_exists(self):
        """Test that level-1.md template file exists."""
        template_path = Path(__file__).parent.parent.parent / "hooks" / "context" / "level-1.md"
        assert template_path.exists(), f"Level 1 template not found at {template_path}"

    def test_level2_template_exists(self):
        """Test that level-2.md template file exists."""
        template_path = Path(__file__).parent.parent.parent / "hooks" / "context" / "level-2.md"
        assert template_path.exists(), f"Level 2 template not found at {template_path}"

    def test_level3_template_exists(self):
        """Test that level-3.md template file exists."""
        template_path = Path(__file__).parent.parent.parent / "hooks" / "context" / "level-3.md"
        assert template_path.exists(), f"Level 3 template not found at {template_path}"

    def test_level1_template_contains_core_identity(self):
        """Test that level-1 template contains core identity information."""
        template_path = Path(__file__).parent.parent.parent / "hooks" / "context" / "level-1.md"
        content = template_path.read_text()

        # Should contain Trinitas system information
        assert "Trinitas" in content or "TRINITAS" in content
        # Should contain agent information
        assert "agent" in content.lower() or "persona" in content.lower()

    def test_level3_template_is_compressed(self):
        """Test that level-3 template is compressed (< 2000 chars target ~500 tokens)."""
        template_path = Path(__file__).parent.parent.parent / "hooks" / "context" / "level-3.md"
        content = template_path.read_text()

        # Level 3 should be compressed (~500 tokens = ~2000 chars)
        # Allow some margin for longer templates
        assert len(content) < 4000, f"Level 3 template too large: {len(content)} chars"


class TestSanitization:
    """Test SEC-PUSH-1: Markdown content sanitization."""

    def test_sanitize_removes_script_tags(self):
        """Test that script tags are removed from content."""
        from unified_injector import sanitize_md_content

        malicious = "<script>alert('xss')</script>Safe content"
        result = sanitize_md_content(malicious)

        assert "<script>" not in result
        assert "</script>" not in result
        assert "Safe content" in result

    def test_sanitize_removes_html_tags(self):
        """Test that HTML tags are removed from content."""
        from unified_injector import sanitize_md_content

        content = "<div>Content</div><p>Paragraph</p>"
        result = sanitize_md_content(content)

        assert "<div>" not in result
        assert "</div>" not in result
        assert "<p>" not in result
        assert "</p>" not in result

    def test_sanitize_removes_javascript_protocol(self):
        """Test that javascript: protocol is removed."""
        from unified_injector import sanitize_md_content

        content = "Click [here](javascript:alert('xss')) for more"
        result = sanitize_md_content(content)

        assert "javascript:" not in result.lower()

    def test_sanitize_removes_event_handlers(self):
        """Test that on* event handlers are removed."""
        from unified_injector import sanitize_md_content

        content = "Image: <img src='x' onerror='alert(1)'>"
        result = sanitize_md_content(content)

        assert "onerror" not in result.lower()
        assert "onclick" not in sanitize_md_content("onclick=test").lower()
        assert "onload" not in sanitize_md_content("onload=test").lower()

    def test_sanitize_preserves_markdown(self):
        """Test that valid Markdown is preserved."""
        from unified_injector import sanitize_md_content

        markdown = """# Heading

- Item 1
- Item 2

**Bold** and *italic*

```python
print("code")
```
"""
        result = sanitize_md_content(markdown)

        # Markdown syntax should be preserved
        assert "# Heading" in result
        assert "- Item 1" in result
        assert "**Bold**" in result
        assert "```python" in result

    def test_sanitize_handles_nested_tags(self):
        """Test that nested malicious tags are handled."""
        from unified_injector import sanitize_md_content

        content = "<div><script>evil()</script></div>"
        result = sanitize_md_content(content)

        assert "<script>" not in result
        assert "<div>" not in result


class TestMCPToolsSummaryFormatting:
    """Test MCP tools summary formatting for context injection."""

    def test_format_tools_summary_with_data(self):
        """Test formatting of tools summary with actual data."""
        from unified_injector import format_mcp_tools_summary

        summary = {
            "total_count": 10,
            "frequently_used": [
                {
                    "server": "tmws",
                    "tool": "create_memory",
                    "description": "Create memory",
                    "usage_count": 50,
                },
                {
                    "server": "tmws",
                    "tool": "search_memory",
                    "description": "Search memory",
                    "usage_count": 30,
                },
            ],
            "servers": ["tmws", "context7"],
            "token_estimate": 500,
        }

        result = format_mcp_tools_summary(summary)

        # Should contain tool information
        assert "create_memory" in result
        assert "search_memory" in result
        assert "tmws" in result
        assert "10" in result  # total_count
        assert "500" in result  # token_estimate

    def test_format_tools_summary_empty(self):
        """Test formatting when no tools available."""
        from unified_injector import format_mcp_tools_summary

        summary = {
            "total_count": 0,
            "frequently_used": [],
            "servers": [],
            "token_estimate": 0,
        }

        result = format_mcp_tools_summary(summary)

        # Should handle empty gracefully
        assert "No tools available" in result or "0" in result

    def test_format_tools_summary_with_error(self):
        """Test formatting when API returned error."""
        from unified_injector import format_mcp_tools_summary

        summary = {
            "total_count": 0,
            "frequently_used": [],
            "servers": [],
            "token_estimate": 0,
            "error": "Connection timeout",
        }

        result = format_mcp_tools_summary(summary)

        # Should indicate error
        assert "unavailable" in result.lower() or "error" in result.lower()


class TestContextInjection:
    """Test full context injection flow."""

    async def test_inject_session_start_returns_context(self):
        """Test that inject_session_start returns context string."""
        from unified_injector import inject_session_start

        # Mock the API call
        with patch("unified_injector.fetch_mcp_tools_summary") as mock_fetch:
            mock_fetch.return_value = {
                "total_count": 5,
                "frequently_used": [],
                "servers": ["tmws"],
                "token_estimate": 100,
            }

            result = await inject_session_start()

            # Should return non-empty string
            assert isinstance(result, str)
            assert len(result) > 0

            # Should contain Level 1 content (Core Identity)
            assert "Trinitas" in result or "System" in result

    async def test_inject_pre_compact_returns_compressed(self):
        """Test that inject_pre_compact returns compressed context."""
        from unified_injector import inject_pre_compact

        result = await inject_pre_compact()

        # Should return non-empty string
        assert isinstance(result, str)
        assert len(result) > 0

        # Should be smaller than session start (compressed)
        # Level 3 is ~500 tokens vs Level 1+2 at ~2000 tokens
        assert len(result) < 5000  # Reasonable upper bound


class TestSyncWrappers:
    """Test synchronous wrapper functions for Claude Code Hooks."""

    def test_sync_session_start_returns_string(self):
        """Test that sync wrapper returns string synchronously."""
        from unified_injector import sync_session_start

        # Mock async function
        with patch("unified_injector.inject_session_start") as mock_inject:
            mock_inject.return_value = "Test context"

            with patch("asyncio.run") as mock_run:
                mock_run.return_value = "Test context"
                result = sync_session_start()

                assert isinstance(result, str)

    def test_sync_pre_compact_returns_string(self):
        """Test that sync pre_compact wrapper returns string."""
        from unified_injector import sync_pre_compact

        # Mock async function
        with patch("unified_injector.inject_pre_compact") as mock_inject:
            mock_inject.return_value = "Compressed context"

            with patch("asyncio.run") as mock_run:
                mock_run.return_value = "Compressed context"
                result = sync_pre_compact()

                assert isinstance(result, str)


class TestAPIClientIntegration:
    """Test TMWS API client integration."""

    async def test_fetch_mcp_tools_summary_returns_dict(self):
        """Test that fetch_mcp_tools_summary returns a dict with expected structure."""
        from unified_injector import fetch_mcp_tools_summary

        # Call the actual function (will return fallback if server not available)
        result = await fetch_mcp_tools_summary()

        # Should always return a dict with expected structure
        assert isinstance(result, dict)
        assert "total_count" in result
        assert "frequently_used" in result
        assert "servers" in result
        assert "token_estimate" in result

    async def test_fetch_returns_expected_types(self):
        """Test that fetch response has correct types."""
        from unified_injector import fetch_mcp_tools_summary

        result = await fetch_mcp_tools_summary()

        # Verify types
        assert isinstance(result["total_count"], int)
        assert isinstance(result["frequently_used"], list)
        assert isinstance(result["servers"], list)
        assert isinstance(result["token_estimate"], int)


class TestConfigurationLoading:
    """Test configuration and settings loading."""

    def test_settings_file_exists(self):
        """Test that settings_unified.json exists."""
        settings_path = Path(__file__).parent.parent.parent / "hooks" / "settings_unified.json"
        assert settings_path.exists(), f"Settings file not found at {settings_path}"

    def test_settings_file_valid_json(self):
        """Test that settings file is valid JSON."""
        import json

        settings_path = Path(__file__).parent.parent.parent / "hooks" / "settings_unified.json"
        content = settings_path.read_text()

        # Should not raise
        data = json.loads(content)

        # Should have hooks section
        assert "hooks" in data

    def test_settings_has_session_start_hook(self):
        """Test that settings has SessionStart hook configured."""
        import json

        settings_path = Path(__file__).parent.parent.parent / "hooks" / "settings_unified.json"
        data = json.loads(settings_path.read_text())

        assert "SessionStart" in data["hooks"]
        assert len(data["hooks"]["SessionStart"]) > 0

    def test_settings_has_pre_compact_hook(self):
        """Test that settings has PreCompact hook configured."""
        import json

        settings_path = Path(__file__).parent.parent.parent / "hooks" / "settings_unified.json"
        data = json.loads(settings_path.read_text())

        assert "PreCompact" in data["hooks"]
        assert len(data["hooks"]["PreCompact"]) > 0
