"""
Custom exceptions for TMWS.
"""

from typing import Any


class TMWSException(Exception):
    """Base exception for TMWS."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


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
        super().__init__(message, {"resource_type": resource_type, "resource_id": resource_id})
