"""ToolCategory value object for MCP Integration.

ToolCategory represents the functional classification of tools discovered
from MCP servers. This categorization helps with:
- Tool organization and discovery
- Access control and security policies
- Performance optimization (caching strategies)
- User experience (grouping related tools)

⚠️ AUTHORITY SOURCE: Go Orchestrator Implementation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This enum MUST match the authoritative Go implementation:

File: src/orchestrator/internal/orchestrator/discovery.go
Lines: 15-21
Map: validCategories

Go defines exactly 5 categories (snake_case):
  1. "data_processing"
  2. "api_integration"
  3. "file_management"
  4. "security"
  5. "monitoring"

⚠️ DO NOT ADD CATEGORIES without updating Go first!
⚠️ Python is a consumer, Go is the producer.

Author: Artemis (R-2 Alignment) + Muses (R-3 Implementation)
Created: 2025-11-12 (Phase 1-1: Day 1)
Updated: 2025-11-22 (Phase 2-4: Go Alignment, V-DISC-4 Fix)
"""

from enum import Enum


class ToolCategory(str, Enum):
    """Tool categories - MUST match Go orchestrator/discovery.go validCategories.

    These 5 categories are defined by the Go orchestrator and validated during
    tool discovery. Python code MUST NOT add categories without first updating
    the Go implementation.

    Categories:
    - DATA_PROCESSING: Data operations, ETL, workflow automation, task orchestration
    - API_INTEGRATION: External APIs, MCP servers, communication integrations
    - FILE_MANAGEMENT: File system operations and document handling
    - SECURITY: Authentication, authorization, encryption tools
    - MONITORING: Logging, metrics, health check tools

    Migration Notes (v2.3.0):
    - Removed: MCP_SERVER → API_INTEGRATION (MCP is an API integration pattern)
    - Removed: WORKFLOW_AUTOMATION → DATA_PROCESSING (workflows process data)
    - Removed: COMMUNICATION → API_INTEGRATION (communication uses APIs)
    - Removed: DEVELOPMENT → (no clear mapping, fail-fast instead)
    - Removed: UNCATEGORIZED → (fail-fast, force explicit categorization)
    """

    DATA_PROCESSING = "data_processing"
    """Data transformation, ETL, workflow automation, task orchestration."""

    API_INTEGRATION = "api_integration"
    """External APIs, REST, GraphQL, MCP servers, communication services."""

    FILE_MANAGEMENT = "file_management"
    """File system operations, document handling, storage."""

    SECURITY = "security"
    """Authentication, authorization, encryption, secrets management."""

    MONITORING = "monitoring"
    """Logging, metrics, health checks, observability."""

    @classmethod
    def infer_from_name(cls, tool_name: str, tool_description: str = "") -> "ToolCategory":
        """Infer tool category from tool name and description.

        Uses pattern matching with deterministic priority order matching Go's
        validCategories map iteration. Patterns from removed categories have been
        merged into the 5 Go-defined categories.

        Inference Rules (Priority Order):
        1. DATA_PROCESSING: data, process, transform, analys, etl, workflow, task, automation, orchestrat
        2. API_INTEGRATION: api, rest, graphql, client, sdk, mcp, server, connection, message, email, notify, chat, slack, webhook
        3. FILE_MANAGEMENT: file, document, storage, upload, download
        4. SECURITY: auth, security, encrypt, vault, secret
        5. MONITORING: monitor, log, metric, health, observ

        Migration from v2.2.x:
        - MCP_SERVER patterns → API_INTEGRATION (MCP is an API integration)
        - WORKFLOW_AUTOMATION patterns → DATA_PROCESSING (workflows process data)
        - COMMUNICATION patterns → API_INTEGRATION (communication uses APIs)
        - DEVELOPMENT patterns → Removed (fail-fast, no clear category)
        - UNCATEGORIZED → Removed (fail-fast, force explicit categorization)

        Args:
            tool_name: Name of the tool
            tool_description: Description of the tool (optional)

        Returns:
            ToolCategory: Inferred category

        Raises:
            ValueError: If no category matches (fail-fast, no UNCATEGORIZED fallback)

        Example:
            >>> ToolCategory.infer_from_name("mcp-server")
            ToolCategory.API_INTEGRATION
            >>> ToolCategory.infer_from_name("workflow-automation-tool")
            ToolCategory.DATA_PROCESSING
            >>> ToolCategory.infer_from_name("data-processor")
            ToolCategory.DATA_PROCESSING
        """
        combined = f"{tool_name.lower()} {tool_description.lower()}"

        # Priority order matching Go's deterministic validation
        INFERENCE_RULES = [
            (
                cls.DATA_PROCESSING,
                [
                    # Data operations (original)
                    "data", "process", "transform", "analys", "etl",
                    # Workflow operations (from removed WORKFLOW_AUTOMATION)
                    "workflow", "task", "automation", "orchestrat"
                ]
            ),
            (
                cls.API_INTEGRATION,
                [
                    # API operations (original)
                    "api", "rest", "graphql", "client", "sdk",
                    # MCP operations (from removed MCP_SERVER)
                    "mcp", "server", "connection",
                    # Communication APIs (from removed COMMUNICATION)
                    "message", "email", "notify", "chat", "slack", "webhook"
                ]
            ),
            (
                cls.FILE_MANAGEMENT,
                ["file", "document", "storage", "upload", "download"]
            ),
            (
                cls.SECURITY,
                ["auth", "security", "encrypt", "vault", "secret"]
            ),
            (
                cls.MONITORING,
                ["monitor", "log", "metric", "health", "observ"]
            ),
        ]

        for category, patterns in INFERENCE_RULES:
            if any(pattern in combined for pattern in patterns):
                return category

        # Fail-fast: No UNCATEGORIZED fallback
        raise ValueError(
            f"Tool '{tool_name}' does not match any valid category. "
            f"Valid categories: {[c.value for c in cls]}"
        )
