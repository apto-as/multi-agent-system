"""Base classes for unified sanitization module.

This module defines the abstract base classes and result types that all
validators must implement. Following the Strategy pattern for extensibility.

Security:
- Immutable ValidationResult prevents tampering
- Generic typing for type safety
- Severity levels for security monitoring

Author: Artemis (Implementation)
Created: 2025-12-07 (Issue #22: Unified Sanitization)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class Severity(str, Enum):
    """Severity levels for validation results."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ValidationResult(Generic[T]):
    """Immutable validation result.

    Attributes:
        is_valid: Whether the input passed validation
        sanitized_value: The sanitized value (may differ from input)
        error_message: Human-readable error message (None if valid)
        severity: Severity level of the validation result
        details: Additional details for debugging/auditing
    """

    is_valid: bool
    sanitized_value: T | None
    error_message: str | None
    severity: Severity
    details: dict[str, Any] | None = None

    @classmethod
    def success(cls, value: T, details: dict[str, Any] | None = None) -> "ValidationResult[T]":
        """Create a successful validation result."""
        return cls(
            is_valid=True,
            sanitized_value=value,
            error_message=None,
            severity=Severity.INFO,
            details=details,
        )

    @classmethod
    def failure(
        cls,
        message: str,
        severity: Severity = Severity.CRITICAL,
        sanitized_value: T | None = None,
        details: dict[str, Any] | None = None,
    ) -> "ValidationResult[T]":
        """Create a failed validation result."""
        return cls(
            is_valid=False,
            sanitized_value=sanitized_value,
            error_message=message,
            severity=severity,
            details=details,
        )


class BaseValidator(ABC, Generic[T]):
    """Abstract base validator - all validators extend this.

    Subclasses must implement:
    - validate(): Main validation logic
    - get_validation_rules(): Return human-readable rules for documentation/audit

    Example:
        >>> class StringValidator(BaseValidator[str]):
        ...     def validate(self, value: Any, **kwargs) -> ValidationResult[str]:
        ...         if not isinstance(value, str):
        ...             return ValidationResult.failure("Value must be string")
        ...         return ValidationResult.success(value)
        ...
        ...     def get_validation_rules(self) -> dict[str, Any]:
        ...         return {"type": "string"}
    """

    @abstractmethod
    def validate(self, value: Any, **kwargs: Any) -> ValidationResult[T]:
        """Validate and optionally sanitize input.

        Args:
            value: The input value to validate
            **kwargs: Additional validation options

        Returns:
            ValidationResult containing validation status and sanitized value
        """
        pass

    @abstractmethod
    def get_validation_rules(self) -> dict[str, Any]:
        """Return human-readable validation rules.

        Useful for:
        - Documentation generation
        - Security audits
        - API schema generation

        Returns:
            Dictionary describing the validation rules
        """
        pass

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"
