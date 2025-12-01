#!/usr/bin/env python3
"""Unified Context Injector for Claude Code Hooks.

Integrates with TMWS REST API to fetch MCP tool summaries and inject them
into AI context (defer_loading pattern). Implements Anthropic's recommended
pattern for efficient token usage (~88% reduction).

Events handled:
- SessionStart: Level 1-2 context + MCP tools summary
- PreCompact: Level 3 compressed summary

Security:
- SEC-PUSH-1: MD content sanitization
- SEC-PUSH-2: Namespace isolation via API
- P0-1: Namespace verified from database

Reference:
    https://www.anthropic.com/engineering/advanced-tool-use

Created: 2025-12-01 (Unified Push Architecture)
Authors: Trinitas Full Mode (Athena, Artemis, Hestia, Muses)
"""

import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any

# Configure logging
logger = logging.getLogger(__name__)
if os.getenv("TRINITAS_VERBOSE", "0") == "1":
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[UnifiedInjector] %(levelname)s: %(message)s"))
    logger.addHandler(handler)
else:
    logger.setLevel(logging.WARNING)


# =============================================================================
# Configuration
# =============================================================================

# Environment variables
TMWS_API_URL = os.environ.get("TMWS_API_URL", "http://localhost:8000")
TMWS_JWT_TOKEN = os.environ.get("TMWS_JWT_TOKEN", "")
TMWS_NAMESPACE = os.environ.get("TMWS_NAMESPACE", "default")
TMWS_AGENT_ID = os.environ.get("TMWS_AGENT_ID", "athena-conductor")

# Context file directory
CONTEXT_DIR = Path(__file__).parent.parent / "context"

# HTTP timeout
HTTP_TIMEOUT = 5.0


# =============================================================================
# Security: Content Sanitization (SEC-PUSH-1)
# =============================================================================

def sanitize_md_content(content: str) -> str:
    """Sanitize Markdown content to prevent injection attacks.

    SEC-PUSH-1: Remove potentially dangerous content:
    - Script tags
    - HTML tags
    - JavaScript protocols
    - Event handlers

    Args:
        content: Raw Markdown content

    Returns:
        Sanitized Markdown content
    """
    # Remove script tags
    content = re.sub(
        r'<script[^>]*>.*?</script>',
        '',
        content,
        flags=re.DOTALL | re.IGNORECASE
    )

    # Remove HTML tags (preserve content)
    content = re.sub(r'<[^>]+>', '', content)

    # Remove javascript: protocol
    content = re.sub(r'javascript:', '', content, flags=re.IGNORECASE)

    # Remove event handlers
    content = re.sub(r'on\w+\s*=', '', content, flags=re.IGNORECASE)

    return content


# =============================================================================
# API Client
# =============================================================================

async def fetch_mcp_tools_summary() -> dict[str, Any]:
    """Fetch MCP tools summary from TMWS REST API.

    Implements defer_loading pattern for token-efficient context injection.

    Returns:
        Dictionary with tools summary:
        - total_count: Total number of available tools
        - frequently_used: List of frequently used tools
        - servers: List of connected server names
        - token_estimate: Estimated token count
        - error: Error message if request failed
    """
    try:
        # Use httpx for async HTTP (preferred)
        import httpx

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            response = await client.get(
                f"{TMWS_API_URL}/api/v1/mcp/tools/summary",
                params={"limit": 5},  # defer_loading: Top 5 tools
                headers={
                    "Authorization": f"Bearer {TMWS_JWT_TOKEN}",
                    "Content-Type": "application/json",
                }
            )
            response.raise_for_status()
            return response.json()

    except ImportError:
        # Fallback to urllib if httpx not available
        logger.warning("httpx not available, using urllib")
        return _fetch_sync()

    except Exception as e:
        # Fail-safe: API failure should not break basic functionality
        logger.error(f"Failed to fetch MCP tools summary: {e}")
        return {
            "total_count": 0,
            "frequently_used": [],
            "servers": [],
            "token_estimate": 0,
            "error": str(e)
        }


def _fetch_sync() -> dict[str, Any]:
    """Synchronous fallback for environments without httpx."""
    import urllib.request
    import urllib.error
    from urllib.parse import urlencode

    try:
        url = f"{TMWS_API_URL}/api/v1/mcp/tools/summary?{urlencode({'limit': 5})}"

        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {TMWS_JWT_TOKEN}",
                "Content-Type": "application/json",
            }
        )

        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            return json.loads(response.read().decode('utf-8'))

    except Exception as e:
        logger.error(f"Sync fetch failed: {e}")
        return {
            "total_count": 0,
            "frequently_used": [],
            "servers": [],
            "token_estimate": 0,
            "error": str(e)
        }


# =============================================================================
# Context Templates
# =============================================================================

def load_context_template(level: int) -> str:
    """Load context template from file.

    Args:
        level: Context level (1, 2, or 3)

    Returns:
        Template content or fallback message
    """
    template_path = CONTEXT_DIR / f"level-{level}.md"

    if template_path.exists():
        try:
            content = template_path.read_text(encoding="utf-8")
            return sanitize_md_content(content)
        except Exception as e:
            logger.error(f"Failed to load template level-{level}: {e}")

    # Fallback content
    return f"# Level {level} Context\n\n[Template not found at {template_path}]"


def format_mcp_tools_summary(summary: dict[str, Any]) -> str:
    """Format MCP tools summary as Markdown.

    Args:
        summary: Tools summary from API

    Returns:
        Formatted Markdown string
    """
    if summary.get("error"):
        return f"\n### MCP Tools (unavailable)\n*Error: {summary['error']}*\n"

    if summary.get("total_count", 0) == 0:
        return "\n### MCP Tools\n*No tools available*\n"

    lines = [
        f"\n### Available MCP Tools ({summary['total_count']} total)",
        "",
        f"**Servers**: {', '.join(summary.get('servers', ['none']))}",
        "",
        "**Frequently Used**:",
    ]

    for tool in summary.get("frequently_used", []):
        server = tool.get("server", "unknown")
        tool_name = tool.get("tool", "unknown")
        description = tool.get("description", "No description")
        lines.append(f"- `{server}.{tool_name}`: {description}")

    lines.extend([
        "",
        f"*Token estimate: ~{summary.get('token_estimate', 0)} tokens*",
        "*Use `list_mcp_tools` for full list (defer_loading pattern)*",
    ])

    return "\n".join(lines)


# =============================================================================
# Event Handlers
# =============================================================================

async def inject_session_start() -> str:
    """Inject context for SessionStart event.

    Combines:
    - Level 1: Core Identity (~2,000 tokens)
    - Level 2: Session Context (dynamic)
    - MCP Tools Summary (defer_loading pattern)

    Returns:
        Formatted context string for injection
    """
    logger.debug("Injecting SessionStart context")

    # Level 1: Core Identity (always present)
    level1 = load_context_template(1)

    # Level 2: Session Context (dynamic)
    level2 = load_context_template(2)

    # MCP Tools Summary (defer_loading)
    mcp_summary = await fetch_mcp_tools_summary()
    mcp_section = format_mcp_tools_summary(mcp_summary)

    # Combine contexts
    result = f"{level1}\n\n{level2}\n{mcp_section}"

    logger.debug(f"SessionStart context: {len(result)} chars")
    return result


async def inject_pre_compact() -> str:
    """Inject context for PreCompact event.

    Uses Level 3 compressed summary for context limits.

    Returns:
        Compressed context string
    """
    logger.debug("Injecting PreCompact context")

    # Level 3: Compressed Summary (~500 tokens)
    level3 = load_context_template(3)

    logger.debug(f"PreCompact context: {len(level3)} chars")
    return level3


# =============================================================================
# Hook Entry Points (Claude Code)
# =============================================================================

async def on_session_start(event: dict[str, Any] | None = None) -> str:
    """SessionStart event handler for Claude Code Hooks.

    Args:
        event: Event data from Claude Code (optional)

    Returns:
        Context to inject into session
    """
    return await inject_session_start()


async def on_pre_compact(event: dict[str, Any] | None = None) -> str:
    """PreCompact event handler for Claude Code Hooks.

    Args:
        event: Event data from Claude Code (optional)

    Returns:
        Compressed context for injection
    """
    return await inject_pre_compact()


# =============================================================================
# Synchronous Wrappers (for non-async environments)
# =============================================================================

def sync_session_start(event: dict[str, Any] | None = None) -> str:
    """Synchronous wrapper for SessionStart."""
    import asyncio

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    return loop.run_until_complete(on_session_start(event))


def sync_pre_compact(event: dict[str, Any] | None = None) -> str:
    """Synchronous wrapper for PreCompact."""
    import asyncio

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    return loop.run_until_complete(on_pre_compact(event))


# =============================================================================
# Main (for testing)
# =============================================================================

if __name__ == "__main__":
    import asyncio

    async def test():
        print("=== Testing Unified Injector ===\n")

        print("--- SessionStart ---")
        result = await inject_session_start()
        print(result[:1000] + "..." if len(result) > 1000 else result)
        print(f"\nTotal: {len(result)} chars\n")

        print("--- PreCompact ---")
        result = await inject_pre_compact()
        print(result)
        print(f"\nTotal: {len(result)} chars\n")

    asyncio.run(test())
