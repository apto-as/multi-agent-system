"""Application Layer Exceptions

All exceptions should be sanitized before exposing to external clients.
"""


class ApplicationError(Exception):
    """Base exception for application layer"""

    def __init__(
        self,
        message: str,
        error_code: str = "APPLICATION_ERROR",
        details: dict | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}


class ValidationError(ApplicationError):
    """Raised when input validation fails"""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(
            message, error_code="VALIDATION_ERROR", details=details
        )


class AuthorizationError(ApplicationError):
    """Raised when authorization fails"""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(
            message, error_code="AUTHORIZATION_ERROR", details=details
        )


class ExternalServiceError(ApplicationError):
    """Raised when external service (MCP) fails"""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(
            message, error_code="EXTERNAL_SERVICE_ERROR", details=details
        )
