"""Domain layer for MCP Integration.

This package contains the core business logic and domain model
for MCP (Model Context Protocol) integration.

Domain-Driven Design (DDD) Structure:
- aggregates/: Aggregate roots (MCPConnection)
- entities/: Entities (Tool)
- value_objects/: Value objects (ConnectionConfig, ConnectionStatus, ToolCategory)
- events.py: Domain events
- exceptions.py: Domain-specific exceptions

Author: Athena (TDD) + Hera (DDD)
Created: 2025-11-12 (Phase 1-1: Day 1)
"""

# Aggregate Roots
from src.domain.aggregates.mcp_connection import MCPConnection

# Entities
from src.domain.entities.tool import Tool

# Value Objects
from src.domain.value_objects.connection_config import ConnectionConfig
from src.domain.value_objects.connection_status import ConnectionStatus
from src.domain.value_objects.tool_category import ToolCategory

# Events
from src.domain.events import (
    DomainEvent,
    MCPConnectedEvent,
    MCPDisconnectedEvent,
    ToolDiscoveredEvent,
)

# Exceptions
from src.domain.exceptions import (
    DomainException,
    DomainInvariantViolation,
    InvalidConnectionError,
    InvalidStateTransitionError,
)

__all__ = [
    # Aggregate Roots
    "MCPConnection",
    # Entities
    "Tool",
    # Value Objects
    "ConnectionConfig",
    "ConnectionStatus",
    "ToolCategory",
    # Events
    "DomainEvent",
    "MCPConnectedEvent",
    "MCPDisconnectedEvent",
    "ToolDiscoveredEvent",
    # Exceptions
    "DomainException",
    "DomainInvariantViolation",
    "InvalidConnectionError",
    "InvalidStateTransitionError",
]
