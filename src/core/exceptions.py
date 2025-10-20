"""
Custom exceptions for TMWS.

Design Principles:
1. All exceptions must be logged (auto-logging in TMWSException)
2. Never catch Exception without re-raising or logging
3. Use specific exception types for better error handling
4. Include original exception as context (__cause__)
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class TMWSException(Exception):
    """
    Base exception for TMWS.

    All custom exceptions inherit from this class.
    Automatically logs the error when raised.
    """

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        log_level: int = logging.ERROR,
    ):
        super().__init__(message)
        self.message = message
        self.details = details or {}

        # Auto-log all exceptions with context
        logger.log(
            log_level,
            f"{self.__class__.__name__}: {message}",
            extra={"details": self.details},
            exc_info=True,
        )


class DatabaseException(TMWSException):
    """Database-related errors."""

    pass


class DatabaseError(DatabaseException):
    """Alias for DatabaseException for backward compatibility."""

    pass


class MemoryException(TMWSException):
    """Memory operation errors."""

    pass


class WorkflowException(TMWSException):
    """Workflow operation errors."""

    pass


class ValidationException(TMWSException):
    """Input validation errors."""

    pass


class ValidationError(ValidationException):
    """Alias for ValidationException for backward compatibility."""

    pass


class AuthenticationException(TMWSException):
    """Authentication errors."""

    pass


class AuthorizationException(TMWSException):
    """Authorization errors."""

    pass


class RateLimitException(TMWSException):
    """Rate limit exceeded errors."""

    pass


class VectorizationException(TMWSException):
    """Vector embedding errors."""

    pass


class ConfigurationError(TMWSException):
    """Configuration-related errors."""

    pass


class PermissionError(TMWSException):
    """Permission-related errors."""

    pass


class SecurityError(TMWSException):
    """Security-related errors."""

    pass


class ServiceError(TMWSException):
    """General service errors."""

    pass


class NotFoundError(TMWSException):
    """Resource not found errors."""

    def __init__(self, resource_type: str, resource_id: str):
        message = f"{resource_type} with id '{resource_id}' not found"
        super().__init__(
            message, {"resource_type": resource_type, "resource_id": resource_id}
        )


# Detailed Database Errors
class DatabaseConnectionError(DatabaseException):
    """Raised when database connection fails."""

    pass


class DatabaseOperationError(DatabaseException):
    """Raised when database operation fails (query, commit, etc)."""

    pass


class DatabaseInitializationError(DatabaseException):
    """Raised when database initialization fails (tables, migrations)."""

    pass


# Service Initialization and Execution Errors
class ServiceInitializationError(ServiceError):
    """Raised when service initialization fails."""

    pass


class ServiceExecutionError(ServiceError):
    """Raised when service operation fails during execution."""

    pass


# Memory Service Specific Errors
class MemoryCreationError(MemoryException):
    """Raised when memory creation fails."""

    pass


class MemorySearchError(MemoryException):
    """Raised when memory search fails."""

    pass


class MemoryUpdateError(MemoryException):
    """Raised when memory update fails."""

    pass


class MemoryDeletionError(MemoryException):
    """Raised when memory deletion fails."""

    pass


class MemoryNotFoundError(MemoryException):
    """Raised when requested memory does not exist."""

    def __init__(self, memory_id: str):
        super().__init__(
            f"Memory not found: {memory_id}", details={"memory_id": memory_id}
        )


# Vector Search Specific Errors
class VectorSearchError(ServiceError):
    """Base class for vector search errors."""

    pass


class ChromaInitializationError(VectorSearchError):
    """Raised when ChromaDB initialization fails."""

    pass


class ChromaOperationError(VectorSearchError):
    """Raised when ChromaDB operation fails."""

    pass


class EmbeddingGenerationError(VectorSearchError):
    """Raised when embedding generation fails."""

    pass


# Agent Service Errors
class AgentError(ServiceError):
    """Base class for agent service errors."""

    pass


class AgentRegistrationError(AgentError):
    """Raised when agent registration fails."""

    pass


class AgentNotFoundError(AgentError):
    """Raised when requested agent does not exist."""

    def __init__(self, agent_id: str):
        super().__init__(
            f"Agent not found: {agent_id}", details={"agent_id": agent_id}
        )


# Integration Errors
class IntegrationError(TMWSException):
    """Base class for external integration errors."""

    pass


class GenAIToolboxError(IntegrationError):
    """Raised when GenAI Toolbox integration fails."""

    pass


class OllamaError(IntegrationError):
    """Raised when Ollama service fails."""

    pass


# MCP Server Errors
class MCPServerError(TMWSException):
    """Base class for MCP server errors."""

    pass


class MCPInitializationError(MCPServerError):
    """Raised when MCP server initialization fails."""

    pass


class MCPToolExecutionError(MCPServerError):
    """Raised when MCP tool execution fails."""

    pass


# Environment Variable Errors
class EnvironmentVariableError(ConfigurationError):
    """Raised when required environment variable is missing or invalid."""

    pass


# Utility function for logging and re-raising
def log_and_raise(
    exception_class: type[TMWSException],
    message: str,
    original_exception: Exception | None = None,
    details: dict[str, Any] | None = None,
    log_level: int = logging.ERROR,
) -> None:
    """
    Helper function to log and raise custom exceptions.

    Args:
        exception_class: The exception class to raise
        message: Error message
        original_exception: Original exception (if any) to chain
        details: Additional context details
        log_level: Logging level (default: ERROR)

    Raises:
        exception_class: The specified exception type

    Example:
        try:
            await db.commit()
        except SQLAlchemyError as e:
            log_and_raise(
                DatabaseOperationError,
                "Failed to commit transaction",
                original_exception=e,
                details={"operation": "commit"}
            )
    """
    exc = exception_class(message, details=details, log_level=log_level)
    if original_exception:
        raise exc from original_exception
    else:
        raise exc
