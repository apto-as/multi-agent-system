"""MCPConnection aggregate root for MCP Integration.

MCPConnection is the central aggregate root for managing connections
to MCP (Model Context Protocol) servers.

As an aggregate root:
- It maintains consistency boundaries
- It enforces business rules and invariants
- It raises domain events on state changes
- It controls access to child entities (Tools)

Business Rules:
1. State transitions must be valid (enforced by ConnectionStatus)
2. ACTIVE connection must have at least one tool (invariant)
3. Domain events are raised on state changes
4. Namespace isolation is enforced (security)

Author: Athena (TDD) + Hera (DDD)
Created: 2025-11-12 (Phase 1-1: Day 1)
"""

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4

from src.domain.entities.tool import Tool
from src.domain.events import (
    DomainEvent,
    MCPConnectedEvent,
    MCPDisconnectedEvent,
    ToolDiscoveredEvent,
)
from src.domain.exceptions import (
    DomainInvariantViolation,
    InvalidStateTransitionError,
)
from src.domain.value_objects.connection_config import ConnectionConfig
from src.domain.value_objects.connection_status import ConnectionStatus


@dataclass
class MCPConnection:
    """Aggregate root for MCP server connections.

    This aggregate manages the lifecycle of a connection to an MCP server,
    including connection establishment, tool discovery, and disconnection.

    Attributes:
        id: Unique identifier for this connection (UUID)
        server_name: Name of the MCP server
        config: Connection configuration (immutable value object)
        status: Current connection status
        tools: List of discovered tools
        created_at: When this connection was created
        connected_at: When connection became ACTIVE (None if never connected)
        disconnected_at: When connection was closed (None if still connected)
        error_message: Error message if status is ERROR
        error_at: When error occurred
        namespace: Namespace for isolation (security)
        agent_id: Agent that owns this connection (security)
        domain_events: List of domain events (cleared after dispatch)

    Example:
        >>> config = ConnectionConfig(
        ...     server_name="test_server",
        ...     url="http://localhost:8080/mcp"
        ... )
        >>> conn = MCPConnection(
        ...     id=uuid4(),
        ...     server_name="test_server",
        ...     config=config
        ... )
        >>> conn.status
        ConnectionStatus.DISCONNECTED
        >>> tools = [Tool(name="test_tool", description="Test")]
        >>> conn.mark_as_active(tools)
        >>> conn.status
        ConnectionStatus.ACTIVE
    """

    id: UUID
    server_name: str
    config: ConnectionConfig
    status: ConnectionStatus = ConnectionStatus.DISCONNECTED
    tools: list[Tool] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    connected_at: datetime | None = None
    disconnected_at: datetime | None = None
    error_message: str | None = None
    error_at: datetime | None = None
    namespace: str | None = None
    agent_id: str | None = None
    domain_events: list[DomainEvent] = field(default_factory=list)

    def mark_as_active(self, tools: list[Tool]) -> None:
        """Mark connection as ACTIVE with discovered tools.

        Business Rules:
        - Can only transition to ACTIVE from CONNECTING or DISCONNECTED
        - Must provide at least one tool (invariant)
        - Raises MCPConnectedEvent

        Args:
            tools: List of tools discovered from the MCP server

        Raises:
            InvalidStateTransitionError: If transition is not allowed
            DomainInvariantViolation: If no tools provided

        Example:
            >>> conn = MCPConnection(id=uuid4(), server_name="test", config=config)
            >>> tools = [Tool(name="tool1", description="Tool 1")]
            >>> conn.mark_as_active(tools)
            >>> conn.status
            ConnectionStatus.ACTIVE
            >>> len(conn.domain_events)
            1
        """
        # Validate state transition
        if not self.status.can_transition_to(ConnectionStatus.ACTIVE):
            allowed = ConnectionStatus.get_allowed_transitions(self.status)
            raise InvalidStateTransitionError(
                current_state=self.status.value,
                attempted_state=ConnectionStatus.ACTIVE.value,
                allowed_transitions=[s.value for s in allowed],
            )

        # Validate invariant: ACTIVE connection must have tools
        if not tools:
            raise DomainInvariantViolation(
                invariant="ACTIVE connection must have at least one tool",
                current_state={"status": self.status.value, "tools_count": len(tools)},
            )

        # Update state
        self.status = ConnectionStatus.ACTIVE
        self.tools = tools
        self.connected_at = datetime.utcnow()

        # Raise domain event
        event = MCPConnectedEvent(
            event_id=uuid4(),
            occurred_at=datetime.utcnow(),
            aggregate_id=self.id,
            server_name=self.server_name,
            url=self.config.url,
            namespace=self.namespace,
            agent_id=self.agent_id,
            tool_count=len(tools),
        )
        self.domain_events.append(event)

    def disconnect(self, reason: str | None = None) -> None:
        """Disconnect from MCP server.

        Business Rules:
        - Can disconnect from any state except DISCONNECTED
        - Raises MCPDisconnectedEvent
        - Graceful disconnection (not error-based)

        Args:
            reason: Optional reason for disconnection

        Raises:
            InvalidStateTransitionError: If already disconnected

        Example:
            >>> conn.disconnect("User requested")
            >>> conn.status
            ConnectionStatus.DISCONNECTED
            >>> conn.disconnected_at is not None
            True
        """
        # Validate state transition
        if self.status == ConnectionStatus.DISCONNECTED:
            raise InvalidStateTransitionError(
                current_state=self.status.value,
                attempted_state=ConnectionStatus.DISCONNECTED.value,
                allowed_transitions=[],
            )

        # Update state
        self.status = ConnectionStatus.DISCONNECTED
        self.disconnected_at = datetime.utcnow()

        # Raise domain event
        event = MCPDisconnectedEvent(
            event_id=uuid4(),
            occurred_at=datetime.utcnow(),
            aggregate_id=self.id,
            server_name=self.server_name,
            reason=reason,
            was_graceful=True,
        )
        self.domain_events.append(event)

    def mark_as_error(self, error_message: str) -> None:
        """Mark connection as ERROR.

        Business Rules:
        - Can transition to ERROR from any state
        - Does NOT raise MCPDisconnectedEvent (error, not graceful)

        Args:
            error_message: Description of the error

        Example:
            >>> conn.mark_as_error("Connection timeout")
            >>> conn.status
            ConnectionStatus.ERROR
            >>> conn.error_message
            'Connection timeout'
        """
        self.status = ConnectionStatus.ERROR
        self.error_message = error_message
        self.error_at = datetime.utcnow()

        # Note: We don't raise MCPDisconnectedEvent for errors
        # because this was not a graceful disconnection

    def add_tools(self, new_tools: list[Tool]) -> None:
        """Add newly discovered tools to the connection.

        Business Rules:
        - Can only add tools when connection is ACTIVE
        - Raises ToolDiscoveredEvent for each new tool

        Args:
            new_tools: List of newly discovered tools

        Raises:
            DomainInvariantViolation: If connection is not ACTIVE

        Example:
            >>> new_tools = [Tool(name="new_tool", description="New")]
            >>> conn.add_tools(new_tools)
            >>> len(conn.domain_events)
            2  # One per tool
        """
        if self.status != ConnectionStatus.ACTIVE:
            raise DomainInvariantViolation(
                invariant="Can only add tools to ACTIVE connection",
                current_state={"status": self.status.value},
            )

        # Add tools
        self.tools.extend(new_tools)

        # Raise domain events
        for tool in new_tools:
            event = ToolDiscoveredEvent(
                event_id=uuid4(),
                occurred_at=datetime.utcnow(),
                aggregate_id=self.id,
                tool_name=tool.name,
                tool_description=tool.description,
                tool_category=tool.category.value,
                server_name=self.server_name,
                input_schema=tool.input_schema,
            )
            self.domain_events.append(event)

    def get_tool_by_name(self, tool_name: str) -> Tool | None:
        """Find a tool by its name.

        This is a query method that doesn't modify state.

        Args:
            tool_name: Name of the tool to find

        Returns:
            Tool if found, None otherwise

        Example:
            >>> tool = conn.get_tool_by_name("test_tool")
            >>> tool.name if tool else None
            'test_tool'
        """
        return next((tool for tool in self.tools if tool.name == tool_name), None)

    def clear_events(self) -> None:
        """Clear domain events after they have been dispatched.

        This should be called after events have been published to
        the event bus or message queue.

        Example:
            >>> len(conn.domain_events)
            3
            >>> conn.clear_events()
            >>> len(conn.domain_events)
            0
        """
        self.domain_events.clear()

    def __eq__(self, other: object) -> bool:
        """Entity equality based on identity (ID).

        Two connections are equal if they have the same ID.

        Args:
            other: Object to compare with

        Returns:
            True if both have the same ID

        Example:
            >>> conn1 = MCPConnection(id=id1, server_name="test", config=config)
            >>> conn2 = MCPConnection(id=id1, server_name="test", config=config)
            >>> conn1 == conn2
            True
        """
        if not isinstance(other, MCPConnection):
            return False
        return self.id == other.id

    def __hash__(self) -> int:
        """Hash based on identity (ID).

        Returns:
            Hash of the connection ID

        Example:
            >>> conn_set = {conn}
            >>> conn in conn_set
            True
        """
        return hash(self.id)

    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return (
            f"MCPConnection("
            f"id={self.id}, "
            f"server_name='{self.server_name}', "
            f"status={self.status.value}, "
            f"tools_count={len(self.tools)}"
            f")"
        )

    def __str__(self) -> str:
        """User-friendly representation."""
        return f"MCP Connection to {self.server_name} ({self.status.value})"
