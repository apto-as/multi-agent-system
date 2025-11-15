"""ToolCategory value object for MCP Integration.

ToolCategory represents the functional classification of tools discovered
from MCP servers. This categorization helps with:
- Tool organization and discovery
- Access control and security policies
- Performance optimization (caching strategies)
- User experience (grouping related tools)

Author: Athena (TDD) + Hera (DDD)
Created: 2025-11-12 (Phase 1-1: Day 1)
"""

from enum import Enum


class ToolCategory(str, Enum):
    """Functional category of an MCP tool.

    Tools are automatically categorized based on their name and description.
    This categorization is used for organizing tools and applying category-specific
    policies (e.g., security restrictions, caching strategies).
    """

    GENERAL = "general"
    """General-purpose tools that don't fit other categories."""

    MEMORY = "memory"
    """Tools for memory management, storage, and retrieval."""

    WORKFLOW = "workflow"
    """Tools for workflow orchestration and task management."""

    SEARCH = "search"
    """Tools for searching, querying, and information retrieval."""

    CODE_ANALYSIS = "code_analysis"
    """Tools for code analysis, linting, and static analysis."""

    DOCUMENTATION = "documentation"
    """Tools for documentation generation and management."""

    SECURITY = "security"
    """Tools for security auditing, scanning, and compliance."""

    PERFORMANCE = "performance"
    """Tools for performance profiling, benchmarking, and optimization."""

    DATA = "data"
    """Tools for data processing, transformation, and analytics."""

    INTEGRATION = "integration"
    """Tools for integrating with external services and APIs."""

    @classmethod
    def infer_from_name(cls, tool_name: str, tool_description: str = "") -> "ToolCategory":
        """Infer tool category from name and description.

        This is a heuristic-based categorization that can be overridden
        by explicit configuration.

        Args:
            tool_name: Name of the tool
            tool_description: Description of the tool

        Returns:
            Inferred ToolCategory

        Example:
            >>> ToolCategory.infer_from_name("store_memory")
            ToolCategory.MEMORY
            >>> ToolCategory.infer_from_name("analyze_code", "Performs static analysis")
            ToolCategory.CODE_ANALYSIS
        """
        text = (tool_name + " " + tool_description).lower()

        # Category keywords (ordered by specificity)
        category_keywords = {
            cls.MEMORY: ["memory", "store", "recall", "remember", "cache"],
            cls.WORKFLOW: ["workflow", "task", "orchestrate", "coordinate", "schedule"],
            cls.SEARCH: ["search", "find", "query", "lookup", "retrieve"],
            cls.CODE_ANALYSIS: ["analyze", "lint", "check", "validate", "review", "code"],
            cls.DOCUMENTATION: ["document", "doc", "generate", "markdown", "readme"],
            cls.SECURITY: ["security", "audit", "scan", "vulnerability", "threat"],
            cls.PERFORMANCE: ["performance", "benchmark", "profile", "optimize", "speed"],
            cls.DATA: ["data", "transform", "process", "analytics", "export"],
            cls.INTEGRATION: ["integrate", "api", "webhook", "external", "connect"],
        }

        # Check for category keywords
        for category, keywords in category_keywords.items():
            if any(keyword in text for keyword in keywords):
                return category

        # Default to GENERAL if no match
        return cls.GENERAL
