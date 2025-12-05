"""ConnectionStatus value object for MCP Integration.

ConnectionStatus represents the lifecycle state of an MCP connection.
It is implemented as a str-based Enum for easy serialization and database storage.

Valid state transitions:
    DISCONNECTED → CONNECTING → ACTIVE
    ACTIVE → DISCONNECTING → DISCONNECTED
    Any state → ERROR

Author: Athena (TDD) + Hera (DDD)
Created: 2025-11-12 (Phase 1-1: Day 1)
"""

from enum import Enum


class ConnectionStatus(str, Enum):
    """Status of an MCP connection.

    This enum represents the possible states of an MCP connection.
    Transitions between states are governed by business rules enforced
    by the MCPConnection aggregate.
    """

    DISCONNECTED = "disconnected"
    """Connection is not established. Initial state."""

    CONNECTING = "connecting"
    """Connection attempt is in progress."""

    ACTIVE = "active"
    """Connection is established and ready for tool discovery/execution."""

    DISCONNECTING = "disconnecting"
    """Connection is being closed gracefully."""

    ERROR = "error"
    """Connection encountered an error and is in an invalid state."""

    @classmethod
    def get_allowed_transitions(
        cls, current_status: "ConnectionStatus"
    ) -> list["ConnectionStatus"]:
        """Get allowed state transitions from the current status.

        Args:
            current_status: Current connection status

        Returns:
            List of allowed next states

        Example:
            >>> ConnectionStatus.get_allowed_transitions(ConnectionStatus.DISCONNECTED)
            [ConnectionStatus.CONNECTING, ConnectionStatus.ACTIVE, ConnectionStatus.ERROR]
        """
        transitions = {
            cls.DISCONNECTED: [
                cls.CONNECTING,
                cls.ACTIVE,
                cls.ERROR,
            ],  # Allow direct ACTIVE transition
            cls.CONNECTING: [cls.ACTIVE, cls.ERROR, cls.DISCONNECTED],
            cls.ACTIVE: [cls.DISCONNECTING, cls.ERROR],
            cls.DISCONNECTING: [cls.DISCONNECTED, cls.ERROR],
            cls.ERROR: [cls.DISCONNECTED],  # Can only recover by disconnecting
        }
        return transitions.get(current_status, [])

    def can_transition_to(self, target_status: "ConnectionStatus") -> bool:
        """Check if transition to target status is allowed.

        Args:
            target_status: Desired target status

        Returns:
            True if transition is allowed, False otherwise

        Example:
            >>> status = ConnectionStatus.DISCONNECTED
            >>> status.can_transition_to(ConnectionStatus.CONNECTING)
            True
            >>> status.can_transition_to(ConnectionStatus.ACTIVE)
            False
        """
        allowed = self.get_allowed_transitions(self)
        return target_status in allowed
