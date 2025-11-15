"""Domain events for MCP Integration.

Domain events represent something that happened in the domain.
They are named in the past tense (e.g., MCPConnectedEvent, not MCPConnectEvent).

Events are collected by aggregates and dispatched after successful commit.
This ensures that events are only published after the state change has been persisted.

Author: Athena (TDD) + Hera (DDD)
Created: 2025-11-12 (Phase 1-1: Day 1)
"""

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4


@dataclass(frozen=True)
class DomainEvent:
    """Base class for all domain events.

    Domain events are immutable (frozen=True) to prevent accidental modification.
    They include an event ID and timestamp for auditing and correlation.
    """

    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=datetime.utcnow)
    aggregate_id: UUID | None = None


@dataclass(frozen=True)
class MCPConnectedEvent(DomainEvent):
    """Event raised when an MCP connection is established.

    This event indicates that:
    - Connection to MCP server was successful
    - Tools are ready to be discovered
    - Connection is in ACTIVE state
    """

    connection_id: UUID | None = None
    server_name: str | None = None
    namespace: str | None = None
    tools: list[dict] = field(default_factory=list)

    # Compatibility fields
    url: str | None = None
    agent_id: str | None = None
    tool_count: int = 0

    def __post_init__(self):
        # Set aggregate_id from connection_id if provided
        if self.connection_id and not self.aggregate_id:
            object.__setattr__(self, "aggregate_id", self.connection_id)


@dataclass(frozen=True)
class MCPDisconnectedEvent(DomainEvent):
    """Event raised when an MCP connection is closed.

    This event indicates that:
    - Connection to MCP server was closed (gracefully or due to error)
    - Tools are no longer available
    - Connection is in DISCONNECTED state
    """

    connection_id: UUID | None = None
    server_name: str | None = None
    namespace: str | None = None
    reason: str | None = None
    was_graceful: bool = True

    def __post_init__(self):
        # Set aggregate_id from connection_id if provided
        if self.connection_id and not self.aggregate_id:
            object.__setattr__(self, "aggregate_id", self.connection_id)


@dataclass(frozen=True)
class ToolDiscoveredEvent(DomainEvent):
    """Event raised when a new tool is discovered from an MCP server.

    This event indicates that:
    - A new tool was added to the connection
    - Tool metadata is available
    - Tool is ready for use
    """

    tool_name: str | None = None
    tool_description: str | None = None
    tool_category: str | None = None
    server_name: str | None = None
    input_schema: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ToolsDiscoveredEvent(DomainEvent):
    """Event raised when tools are discovered or refreshed from MCP connection.

    This event indicates that:
    - Tool discovery completed successfully
    - Multiple tools may have been added or updated
    - Connection tools list is now up to date
    """

    connection_id: UUID | None = None
    tools: list[dict] = field(default_factory=list)
    server_name: str | None = None

    def __post_init__(self):
        # Set aggregate_id from connection_id if provided
        if self.connection_id and not self.aggregate_id:
            object.__setattr__(self, "aggregate_id", self.connection_id)
