"""Domain-specific exceptions for MCP Integration.

These exceptions represent violations of business rules and domain invariants.
They should be raised by domain objects (aggregates, entities, value objects)
when business rules are violated.

Author: Athena (TDD) + Hera (DDD)
Created: 2025-11-12 (Phase 1-1: Day 1)
"""


class DomainException(Exception):
    """Base exception for all domain-level errors."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class InvalidStateTransitionError(DomainException):
    """Raised when an invalid state transition is attempted.

    Example:
        Cannot transition from ACTIVE to ACTIVE
        Cannot transition from DISCONNECTED to DISCONNECTING
    """

    def __init__(
        self, current_state: str, attempted_state: str, allowed_transitions: list[str]
    ):
        message = (
            f"Cannot transition from {current_state} to {attempted_state}. "
            f"Allowed transitions: {', '.join(allowed_transitions)}"
        )
        details = {
            "current_state": current_state,
            "attempted_state": attempted_state,
            "allowed_transitions": allowed_transitions,
        }
        super().__init__(message, details)


class InvalidConnectionError(DomainException):
    """Raised when a connection configuration is invalid.

    Example:
        Invalid URL format
        Negative timeout value
        Missing required fields
    """

    def __init__(self, field: str, value: str | None, reason: str):
        message = f"Invalid connection configuration: {field}={value}. {reason}"
        details = {"field": field, "value": value, "reason": reason}
        super().__init__(message, details)


class DomainInvariantViolation(DomainException):
    """Raised when a domain invariant is violated.

    Domain invariants are business rules that must always be true.

    Example:
        An ACTIVE connection must have at least one tool
        A connection cannot have a negative retry count
    """

    def __init__(self, invariant: str, current_state: dict | None = None):
        message = f"Domain invariant violated: {invariant}"
        details = {"invariant": invariant, "current_state": current_state or {}}
        super().__init__(message, details)


class AggregateNotFoundError(DomainException):
    """Raised when a requested aggregate is not found.

    Example:
        Agent not found by ID
        MCPConnection not found by ID
    """

    def __init__(self, aggregate_type: str, identifier: str):
        message = f"{aggregate_type} not found: {identifier}"
        details = {"aggregate_type": aggregate_type, "identifier": identifier}
        super().__init__(message, details)


class MCPConnectionNotFoundError(AggregateNotFoundError):
    """Raised when a requested MCP connection is not found."""

    def __init__(self, connection_id: str):
        super().__init__("MCPConnection", connection_id)
