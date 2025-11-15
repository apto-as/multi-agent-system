"""Infrastructure-specific exceptions for MCP Integration.

These exceptions represent failures in infrastructure components:
- Protocol translation errors (ACL)
- Network/communication errors (Adapters)
- Persistence errors (Repositories)

Infrastructure exceptions should be caught and translated to domain exceptions
or appropriate error responses at application service boundaries.

Author: Artemis (Implementation)
Created: 2025-11-12 (Phase 1-1-B: Infrastructure Layer)
"""


class InfrastructureError(Exception):
    """Base exception for all infrastructure-level errors.

    Infrastructure errors represent technical failures that are not
    part of the domain model (e.g., network errors, database failures).
    """

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class RepositoryError(InfrastructureError):
    """Raised when repository operations fail.

    Example:
        Database connection error
        Transaction rollback failure
        Query execution error
    """

    pass


class AggregateNotFoundError(RepositoryError):
    """Raised when an aggregate cannot be found in the repository.

    Example:
        MCPConnection not found by ID
        Agent not found in namespace
    """

    def __init__(self, aggregate_type: str, identifier: str):
        message = f"{aggregate_type} not found: {identifier}"
        details = {"aggregate_type": aggregate_type, "identifier": identifier}
        super().__init__(message, details)


class MCPProtocolError(InfrastructureError):
    """Raised when MCP protocol communication fails.

    Example:
        Invalid MCP response format
        Missing required protocol fields
        Protocol version mismatch
    """

    pass


class MCPConnectionError(InfrastructureError):
    """Raised when MCP server connection fails.

    Example:
        Network timeout
        Connection refused
        Authentication failure
    """

    pass


class MCPToolNotFoundError(MCPProtocolError):
    """Raised when a requested MCP tool is not available.

    Example:
        Tool not registered on MCP server
        Tool removed after connection established
    """

    def __init__(self, tool_name: str, available_tools: list[str] | None = None):
        message = f"MCP tool not found: {tool_name}"
        details = {"tool_name": tool_name, "available_tools": available_tools or []}
        super().__init__(message, details)


class ToolExecutionError(InfrastructureError):
    """Raised when MCP tool execution fails.

    Example:
        Tool execution timeout
        Invalid tool arguments
        Tool returned error response
    """

    def __init__(self, tool_name: str, error_message: str, details: dict | None = None):
        message = f"Tool execution failed: {tool_name}. {error_message}"
        super().__init__(message, details or {})
        self.tool_name = tool_name
        self.error_message = error_message


# Alias for backwards compatibility
MCPToolExecutionError = ToolExecutionError
