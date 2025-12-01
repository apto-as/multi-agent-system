"""DTOs for MCP Tools Summary endpoint (defer_loading pattern)

This module provides Data Transfer Objects for the tools/summary endpoint,
which implements Anthropic's defer_loading pattern for efficient token usage.

Reference: https://www.anthropic.com/engineering/advanced-tool-use

Author: Artemis (Implementation)
Created: 2025-12-01 (Phase: Unified Push Architecture)
"""

from dataclasses import dataclass, field


@dataclass
class ToolSummaryItem:
    """Single tool summary for defer_loading.

    Contains minimal information for context injection.
    Full tool definition available via list_mcp_tools.
    """

    server: str
    tool: str
    description: str
    usage_count: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "server": self.server,
            "tool": self.tool,
            "description": self.description,
            "usage_count": self.usage_count,
        }


@dataclass
class GetToolsSummaryRequest:
    """Request DTO for MCP tools summary.

    Security:
    - namespace: MUST be verified from database (P0-1 compliance)
    - agent_id: Extracted from JWT token
    """

    namespace: str
    agent_id: str
    limit: int = 5  # defer_loading: Number of frequently used tools to include


@dataclass
class GetToolsSummaryResponse:
    """Response DTO for MCP tools summary (defer_loading pattern).

    Token optimization:
    - Before: ~17,000 tokens (all tool definitions)
    - After: ~2,000 tokens (summary + top 5 tools)
    - Reduction: 88%

    Attributes:
        total_count: Total number of available tools
        frequently_used: Top N frequently used tools with details
        servers: List of connected server names
        token_estimate: Estimated token count for this summary
        error: Optional error message (for fail-safe mode)
    """

    total_count: int
    frequently_used: list[ToolSummaryItem] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)
    token_estimate: int = 0
    error: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_count": self.total_count,
            "frequently_used": [t.to_dict() for t in self.frequently_used],
            "servers": self.servers,
            "token_estimate": self.token_estimate,
            "error": self.error,
        }
