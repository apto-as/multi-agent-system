"""Custom exceptions for TMWS.

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
    """Base exception for TMWS.

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


# Alias for consistency with Error suffix naming
AuthorizationError = AuthorizationException


class RateLimitException(TMWSException):
    """Rate limit exceeded errors."""

    pass


# Alias for consistency with Error suffix naming
RateLimitError = RateLimitException


class VectorizationException(TMWSException):
    """Vector embedding errors."""

    pass


class ConfigurationError(TMWSException):
    """Configuration-related errors."""

    pass


class PermissionError(TMWSException):
    """Permission-related errors."""

    pass


class ServiceError(TMWSException):
    """General service errors."""

    pass


class NotFoundError(TMWSException):
    """Resource not found errors."""

    def __init__(self, resource_type: str, resource_id: str):
        message = f"{resource_type} with id '{resource_id}' not found"
        super().__init__(
            message,
            {"resource_type": resource_type, "resource_id": resource_id},
        )


# Detailed Database Errors


class DatabaseOperationError(DatabaseException):
    """Raised when database operation fails (query, commit, etc)."""

    pass


# Service Initialization and Execution Errors
class ServiceInitializationError(ServiceError):
    """Raised when service initialization fails."""

    pass


# Memory Service Specific Errors
class MemoryCreationError(MemoryException):
    """Raised when memory creation fails."""

    pass


class MemorySearchError(MemoryException):
    """Raised when memory search fails."""

    pass


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


# Integration Errors
class IntegrationError(TMWSException):
    """Base class for external integration errors."""

    pass


# MCP Server Errors
class MCPServerError(TMWSException):
    """Base class for MCP server errors."""

    pass


class MCPInitializationError(MCPServerError):
    """Raised when MCP server initialization fails."""

    pass


# Agent Management Errors
class AgentNotFoundError(TMWSException):
    """Raised when agent is not found."""

    pass


class VerificationError(ServiceError):
    """Raised when claim verification fails."""

    pass


class ImmutableRecordError(TMWSException):
    """Raised when attempting to modify or delete an immutable record.

    Used to protect verification evidence and audit trails from tampering.
    This is a security-critical exception for maintaining evidence integrity.
    """

    pass


# Utility function for logging and re-raising
def log_and_raise(
    exception_class: type[Exception],
    message: str,
    original_exception: Exception | None = None,
    details: dict[str, Any] | None = None,
    log_level: int = logging.ERROR,
) -> None:
    """Helper function to log and raise exceptions with automatic logging.

    Supports both TMWSException subclasses (with auto-logging) and standard
    Python exceptions (ValueError, RuntimeError, etc.) with explicit logging.

    Args:
        exception_class: The exception class to raise (TMWSException or standard)
        message: Error message
        original_exception: Original exception (if any) to chain
        details: Additional context details
        log_level: Logging level (default: ERROR)

    Raises:
        exception_class: The specified exception type

    Example:
        # With TMWSException (auto-logged via __init__)
        log_and_raise(
            DatabaseOperationError,
            "Failed to commit transaction",
            original_exception=e,
            details={"operation": "commit"}
        )

        # With standard exception (explicitly logged)
        log_and_raise(
            ValueError,
            "Invalid parameter value",
            details={"param": "age", "value": -1}
        )

    """
    # Check if it's a TMWSException subclass (has auto-logging in __init__)
    if issubclass(exception_class, TMWSException):
        exc = exception_class(message, details=details, log_level=log_level)
    else:
        # Standard exception - log explicitly before raising
        logger.log(
            log_level,
            f"{exception_class.__name__}: {message}",
            extra={"details": details or {}},
            exc_info=original_exception is not None,
        )
        exc = exception_class(message)

    if original_exception:
        raise exc from original_exception
    raise exc
