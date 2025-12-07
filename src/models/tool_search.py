"""Tool Search data models for TMWS Tool Discovery Engine.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 1.1 - Data Models

These models support semantic tool discovery with:
- Skills priority ranking (2.0x weight)
- Internal tools ranking (1.5x weight)
- External MCP tools (1.0x weight)

Author: Artemis (Implementation)
Created: 2025-12-04
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ToolSourceType(str, Enum):
    """Source type for discovered tools.

    Priority order for search ranking:
    1. SKILL (2.0x weight) - TMWS Skills (third core feature)
    2. INTERNAL (1.5x weight) - Built-in TMWS tools
    3. EXTERNAL (1.0x weight) - External MCP server tools
    """

    SKILL = "skill"
    INTERNAL = "internal"
    EXTERNAL = "external"


class SearchMode(str, Enum):
    """Search mode for tool discovery."""

    SEMANTIC = "semantic"  # Default: vector-based semantic search
    REGEX = "regex"  # Pattern matching on tool names/descriptions
    HYBRID = "hybrid"  # Combine both approaches


class MCPTransportType(str, Enum):
    """Transport type for MCP connections."""

    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"


@dataclass
class ToolSearchResult:
    """Result from tool search operation.

    Includes all metadata needed for tool selection and execution.
    """

    tool_name: str
    server_id: str  # "tmws" for internal, "mcp__{server}" for external
    description: str
    relevance_score: float  # 0.0-1.0 base score
    source_type: ToolSourceType
    input_schema: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    trust_score: float = 1.0  # From Learning system
    usage_count: int = 0  # From Memory system
    _personalization_boost: float = 0.0  # From AdaptiveRanker (Phase 4.1)

    @property
    def weighted_score(self) -> float:
        """Calculate weighted score based on source type.

        Skills get 2.0x boost (third core feature priority).
        Internal tools get 1.5x boost.
        External tools get 1.0x (no boost).
        """
        weights = {
            ToolSourceType.SKILL: 2.0,
            ToolSourceType.INTERNAL: 1.5,
            ToolSourceType.EXTERNAL: 1.0,
        }
        return self.relevance_score * weights.get(self.source_type, 1.0)


@dataclass
class ToolReference:
    """Lightweight tool reference for deferred loading.

    Used when defer_loading=True to minimize context tokens.
    Contains only metadata needed for tool selection.
    Full definition retrieved via get_tool_details().
    """
    tool_name: str
    server_id: str
    description: str
    relevance_score: float
    weighted_score: float
    source_type: ToolSourceType
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "tool_name": self.tool_name,
            "server_id": self.server_id,
            "description": self.description,
            "relevance_score": self.relevance_score,
            "weighted_score": self.weighted_score,
            "source_type": self.source_type.value,
            "tags": self.tags,
            "deferred": True,
        }


@dataclass
class ToolMetadata:
    """Metadata for a single tool.

    Used for both internal and external tools.
    """

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] | None = None
    tags: list[str] = field(default_factory=list)
    examples: list[dict[str, Any]] = field(default_factory=list)

    def to_embedding_text(self) -> str:
        """Generate text for embedding generation.

        Combines name, description, and tags for semantic search.
        """
        parts = [self.name, self.description]
        if self.tags:
            parts.append(" ".join(self.tags))
        return " | ".join(parts)


@dataclass
class MCPServerMetadata:
    """Metadata for an MCP server connection.

    Supports both STDIO and HTTP/SSE transports.
    """

    server_id: str  # Unique identifier (e.g., "context7", "serena")
    name: str  # Display name
    description: str
    transport: MCPTransportType
    command: list[str] | None = None  # For STDIO transport
    url: str | None = None  # For HTTP/SSE transport
    tools: list[ToolMetadata] = field(default_factory=list)
    trust_score: float = 0.5  # Default medium trust
    auto_connect: bool = False
    last_connected: datetime | None = None
    env: dict[str, str] = field(default_factory=dict)

    @property
    def tool_count(self) -> int:
        """Number of tools available from this server."""
        return len(self.tools)

    @property
    def is_connected(self) -> bool:
        """Check if server was recently connected."""
        if self.last_connected is None:
            return False
        # Consider connected if within last 5 minutes
        delta = datetime.now() - self.last_connected
        return delta.total_seconds() < 300


@dataclass
class ToolUsageRecord:
    """Record of tool usage for learning system integration.

    Supports the fourth core feature (Learning) by tracking:
    - Which tools are used for which queries
    - Success/failure outcomes
    - Usage patterns over time
    """

    tool_name: str
    server_id: str
    query: str
    outcome: str  # "success" | "error" | "abandoned"
    timestamp: datetime = field(default_factory=datetime.now)
    latency_ms: float | None = None
    error_message: str | None = None

    def to_memory_content(self) -> dict[str, Any]:
        """Convert to format suitable for Memory storage.

        Supports the first core feature (Memory).
        """
        return {
            "tool_name": self.tool_name,
            "server_id": self.server_id,
            "query": self.query,
            "outcome": self.outcome,
            "timestamp": self.timestamp.isoformat(),
            "latency_ms": self.latency_ms,
            "error_message": self.error_message,
        }


@dataclass
class ToolSearchQuery:
    """Query parameters for tool search.

    Supports filtering by source, tags, and other criteria.
    """

    query: str
    source: str = "all"  # "all" | "skills" | "mcp_servers" | "registry"
    limit: int = 5
    min_score: float = 0.3
    tags: list[str] = field(default_factory=list)
    namespace: str | None = None
    include_disconnected: bool = False
    search_mode: SearchMode = SearchMode.SEMANTIC
    defer_loading: bool = False


@dataclass
class ToolSearchResponse:
    """Response from tool search operation.

    Includes metadata about the search for debugging and analytics.
    """

    results: list[ToolSearchResult]
    query: str
    total_found: int
    search_latency_ms: float
    sources_searched: list[str]  # Which sources were queried

    @property
    def has_skills(self) -> bool:
        """Check if any skills were found."""
        return any(r.source_type == ToolSourceType.SKILL for r in self.results)

    @property
    def top_result(self) -> ToolSearchResult | None:
        """Get the top-ranked result."""
        return self.results[0] if self.results else None
