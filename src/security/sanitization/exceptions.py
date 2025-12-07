"""Custom exceptions for sanitization module.

Security:
- All exceptions should be safe to expose to users
- No sensitive information in error messages
- Consistent error codes for API responses

Author: Artemis (Implementation)
Created: 2025-12-07 (Issue #22: Unified Sanitization)
"""


class SanitizationError(Exception):
    """Base exception for all sanitization errors."""

    def __init__(self, message: str, error_code: str = "SANITIZATION_ERROR"):
        self.message = message
        self.error_code = error_code
        super().__init__(message)


class ValidationError(SanitizationError):
    """Raised when input validation fails."""

    def __init__(self, message: str, field_name: str | None = None):
        self.field_name = field_name
        error_code = f"VALIDATION_ERROR:{field_name}" if field_name else "VALIDATION_ERROR"
        super().__init__(message, error_code)


class SQLInjectionError(SanitizationError):
    """Raised when SQL injection pattern is detected."""

    def __init__(self, message: str = "Potential SQL injection detected"):
        super().__init__(message, "SQL_INJECTION_DETECTED")


class CommandInjectionError(SanitizationError):
    """Raised when command injection pattern is detected."""

    def __init__(self, message: str = "Potential command injection detected"):
        super().__init__(message, "COMMAND_INJECTION_DETECTED")


class PathTraversalError(SanitizationError):
    """Raised when path traversal pattern is detected."""

    def __init__(self, message: str = "Potential path traversal detected"):
        super().__init__(message, "PATH_TRAVERSAL_DETECTED")


class XSSError(SanitizationError):
    """Raised when XSS pattern is detected."""

    def __init__(self, message: str = "Potential XSS attack detected"):
        super().__init__(message, "XSS_DETECTED")


class RegexValidationError(SanitizationError):
    """Raised when regex pattern validation fails."""

    def __init__(self, message: str = "Invalid or dangerous regex pattern"):
        super().__init__(message, "REGEX_VALIDATION_ERROR")


class ValidatorNotFoundError(SanitizationError):
    """Raised when requested validator is not registered."""

    def __init__(self, validator_name: str):
        super().__init__(
            f"Validator '{validator_name}' not registered",
            "VALIDATOR_NOT_FOUND",
        )
