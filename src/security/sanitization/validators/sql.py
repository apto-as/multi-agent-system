"""SQL injection prevention validator.

Provides comprehensive SQL injection detection and prevention:
- Pattern-based detection of SQL keywords
- Comment injection detection
- UNION-based injection detection
- Stored procedure injection detection

Security:
- V-SQL-1: SQL injection prevention
- Multiple detection patterns for defense-in-depth
- Conservative detection (false positives preferred over false negatives)

Author: Artemis (Implementation)
Created: 2025-12-07 (Issue #22: Unified Sanitization)
"""

import re
from typing import Any

from ..base import BaseValidator, Severity, ValidationResult
from ..core.patterns import get_pattern_registry
from ..exceptions import SQLInjectionError


class SQLValidator(BaseValidator[str]):
    """Validator for SQL injection prevention.

    Detects and prevents SQL injection attacks by:
    - Checking for SQL keywords in suspicious contexts
    - Detecting comment-based injection
    - Detecting UNION-based injection
    - Checking for stored procedure calls

    Example:
        >>> validator = SQLValidator()
        >>> result = validator.validate("'; DROP TABLE users;--")
        >>> result.is_valid
        False
        >>> result.severity
        <Severity.CRITICAL: 'critical'>
    """

    def __init__(
        self,
        max_length: int = 1000,
        allow_wildcards: bool = False,
        strict_mode: bool = True,
    ):
        """Initialize SQL validator.

        Args:
            max_length: Maximum allowed input length (default 1000)
            allow_wildcards: Allow % and _ wildcards (default False)
            strict_mode: Use strict detection (default True)
        """
        self.max_length = max_length
        self.allow_wildcards = allow_wildcards
        self.strict_mode = strict_mode
        self._patterns = get_pattern_registry()

    def validate(self, value: Any, **kwargs: Any) -> ValidationResult[str]:
        """Validate input for SQL injection patterns.

        Args:
            value: The input value to validate
            **kwargs: Override options

        Returns:
            ValidationResult indicating if input is safe
        """
        # Type check
        if not isinstance(value, str):
            return ValidationResult.failure(
                f"SQL value must be string, got {type(value).__name__}",
                severity=Severity.CRITICAL,
            )

        # Length check
        max_length = kwargs.get("max_length", self.max_length)
        if len(value) > max_length:
            return ValidationResult.failure(
                f"SQL value exceeds maximum length of {max_length}",
                severity=Severity.WARNING,
                sanitized_value=value[:max_length],
                details={"original_length": len(value)},
            )

        # SQL injection pattern check
        if self._patterns.test("sql_injection", value):
            sanitized = self._sanitize_sql(value)
            return ValidationResult.failure(
                "Potential SQL injection pattern detected",
                severity=Severity.CRITICAL,
                sanitized_value=sanitized,
                details={
                    "security_event": "sql_injection_attempt",
                    "pattern_matched": "sql_injection",
                },
            )

        # Additional checks in strict mode
        if self.strict_mode:
            # Check for suspicious characters
            suspicious_chars = ["'", '"', ";", "\\", "`"]
            for char in suspicious_chars:
                if char in value:
                    sanitized = self._sanitize_sql(value)
                    return ValidationResult.failure(
                        f"Suspicious character '{char}' in SQL input",
                        severity=Severity.WARNING,
                        sanitized_value=sanitized,
                        details={"character": char},
                    )

        # Wildcard check
        if not self.allow_wildcards and ("%" in value or "_" in value):
            return ValidationResult.failure(
                "SQL wildcards not allowed",
                severity=Severity.WARNING,
                sanitized_value=value.replace("%", "").replace("_", ""),
            )

        return ValidationResult.success(value)

    def _sanitize_sql(self, value: str) -> str:
        """Aggressively sanitize SQL input.

        Args:
            value: Input string to sanitize

        Returns:
            Sanitized string with dangerous characters removed
        """
        # Remove common SQL injection characters
        sanitized = re.sub(r"[';\"\\`]", "", value)
        # Remove SQL comments
        sanitized = re.sub(r"--.*$", "", sanitized, flags=re.MULTILINE)
        sanitized = re.sub(r"/\*.*?\*/", "", sanitized, flags=re.DOTALL)
        # Truncate to max length
        return sanitized[: self.max_length]

    def get_validation_rules(self) -> dict[str, Any]:
        """Return validation rules for documentation/audit.

        Returns:
            Dictionary describing the validation rules
        """
        return {
            "type": "sql",
            "max_length": self.max_length,
            "allow_wildcards": self.allow_wildcards,
            "strict_mode": self.strict_mode,
            "blocked_patterns": [
                "SQL keywords (SELECT, INSERT, UPDATE, DELETE, DROP, etc.)",
                "SQL comments (-- and /* */)",
                "UNION injection",
                "Stored procedure calls (xp_, sp_)",
            ],
        }


def validate_sql_safe(value: str, raise_on_injection: bool = True) -> str:
    """Convenience function for quick SQL validation.

    Args:
        value: String to validate
        raise_on_injection: Raise exception on injection (default True)

    Returns:
        The original value if safe, sanitized value if not

    Raises:
        SQLInjectionError: If injection detected and raise_on_injection is True
    """
    validator = SQLValidator()
    result = validator.validate(value)

    if not result.is_valid:
        if raise_on_injection and result.severity == Severity.CRITICAL:
            raise SQLInjectionError(result.error_message or "SQL injection detected")
        return result.sanitized_value or ""

    return result.sanitized_value or value
