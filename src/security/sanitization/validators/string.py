"""String validator for sanitization module.

Provides comprehensive string validation including:
- Length validation
- Control character removal
- NULL byte detection
- Unicode normalization
- Whitespace handling

Security:
- Prevents NULL byte injection
- Removes dangerous control characters
- Enforces length limits to prevent DoS

Author: Artemis (Implementation)
Created: 2025-12-07 (Issue #22: Unified Sanitization)
"""

import unicodedata
from typing import Any

from ..base import BaseValidator, Severity, ValidationResult
from ..core.patterns import get_pattern_registry


class StringValidator(BaseValidator[str]):
    """Validator for string inputs.

    Validates strings for:
    - Type correctness
    - Length constraints
    - Control characters
    - NULL bytes
    - Unicode normalization

    Example:
        >>> validator = StringValidator(max_length=100)
        >>> result = validator.validate("Hello World")
        >>> result.is_valid
        True
        >>> result.sanitized_value
        'Hello World'
    """

    def __init__(
        self,
        min_length: int = 0,
        max_length: int = 10000,
        strip_whitespace: bool = True,
        normalize_unicode: bool = True,
        remove_control_chars: bool = True,
        allow_empty: bool = True,
    ):
        """Initialize string validator.

        Args:
            min_length: Minimum allowed length (default 0)
            max_length: Maximum allowed length (default 10000)
            strip_whitespace: Strip leading/trailing whitespace (default True)
            normalize_unicode: Normalize to NFC form (default True)
            remove_control_chars: Remove control characters (default True)
            allow_empty: Allow empty strings (default True)
        """
        self.min_length = min_length
        self.max_length = max_length
        self.strip_whitespace = strip_whitespace
        self.normalize_unicode = normalize_unicode
        self.remove_control_chars = remove_control_chars
        self.allow_empty = allow_empty
        self._patterns = get_pattern_registry()

    def validate(self, value: Any, **kwargs: Any) -> ValidationResult[str]:
        """Validate and sanitize a string input.

        Args:
            value: The input value to validate
            **kwargs: Override options (min_length, max_length, etc.)

        Returns:
            ValidationResult with sanitized string or error
        """
        # Apply any runtime overrides
        max_length = kwargs.get("max_length", self.max_length)
        min_length = kwargs.get("min_length", self.min_length)
        allow_empty = kwargs.get("allow_empty", self.allow_empty)

        # Type check
        if not isinstance(value, str):
            return ValidationResult.failure(
                f"Expected string, got {type(value).__name__}",
                severity=Severity.CRITICAL,
            )

        sanitized = value

        # NULL byte check (security critical)
        if self._patterns.test("null_bytes", sanitized):
            return ValidationResult.failure(
                "NULL byte detected in input",
                severity=Severity.CRITICAL,
                details={"security_event": "null_byte_injection"},
            )

        # Strip whitespace
        if self.strip_whitespace:
            sanitized = sanitized.strip()

        # Empty check
        if not sanitized and not allow_empty:
            return ValidationResult.failure(
                "Empty string not allowed",
                severity=Severity.WARNING,
            )

        # Control character removal
        if self.remove_control_chars:
            # Remove control chars except \n, \r, \t
            sanitized = "".join(
                char for char in sanitized if char in "\n\r\t" or not unicodedata.category(char).startswith("C")
            )

        # Unicode normalization
        if self.normalize_unicode:
            sanitized = unicodedata.normalize("NFC", sanitized)

        # Length validation
        if len(sanitized) > max_length:
            return ValidationResult.failure(
                f"String exceeds maximum length of {max_length}",
                severity=Severity.WARNING,
                sanitized_value=sanitized[:max_length],
                details={"original_length": len(sanitized), "max_length": max_length},
            )

        if len(sanitized) < min_length:
            return ValidationResult.failure(
                f"String is shorter than minimum length of {min_length}",
                severity=Severity.WARNING,
                sanitized_value=sanitized,
                details={"length": len(sanitized), "min_length": min_length},
            )

        return ValidationResult.success(sanitized)

    def get_validation_rules(self) -> dict[str, Any]:
        """Return validation rules for documentation/audit.

        Returns:
            Dictionary describing the validation rules
        """
        return {
            "type": "string",
            "min_length": self.min_length,
            "max_length": self.max_length,
            "strip_whitespace": self.strip_whitespace,
            "normalize_unicode": self.normalize_unicode,
            "remove_control_chars": self.remove_control_chars,
            "allow_empty": self.allow_empty,
        }


class IdentifierValidator(BaseValidator[str]):
    """Validator for identifiers (agent_id, namespace, etc.).

    Validates that strings match identifier pattern:
    - Starts with letter or underscore
    - Contains only alphanumeric, underscore, hyphen
    - Length 1-64 characters

    Example:
        >>> validator = IdentifierValidator()
        >>> result = validator.validate("my-agent-123")
        >>> result.is_valid
        True
    """

    def __init__(
        self,
        max_length: int = 64,
        allow_hyphen: bool = True,
    ):
        """Initialize identifier validator.

        Args:
            max_length: Maximum identifier length (default 64)
            allow_hyphen: Allow hyphens in identifier (default True)
        """
        self.max_length = max_length
        self.allow_hyphen = allow_hyphen
        self._patterns = get_pattern_registry()

    def validate(self, value: Any, **kwargs: Any) -> ValidationResult[str]:  # noqa: ARG002
        """Validate an identifier string.

        Args:
            value: The identifier to validate
            **kwargs: Override options (reserved for future use)

        Returns:
            ValidationResult with identifier or error
        """
        # Type check
        if not isinstance(value, str):
            return ValidationResult.failure(
                f"Identifier must be string, got {type(value).__name__}",
                severity=Severity.CRITICAL,
            )

        sanitized = value.strip()

        # Empty check
        if not sanitized:
            return ValidationResult.failure(
                "Identifier cannot be empty",
                severity=Severity.CRITICAL,
            )

        # Length check
        if len(sanitized) > self.max_length:
            return ValidationResult.failure(
                f"Identifier exceeds maximum length of {self.max_length}",
                severity=Severity.WARNING,
                sanitized_value=sanitized[: self.max_length],
            )

        # Pattern check
        if not self._patterns.test("valid_identifier", sanitized):
            return ValidationResult.failure(
                "Invalid identifier format. Must start with letter/underscore, "
                "contain only alphanumeric, underscore, or hyphen",
                severity=Severity.CRITICAL,
                details={"value": sanitized[:50]},  # Truncate for safety
            )

        return ValidationResult.success(sanitized)

    def get_validation_rules(self) -> dict[str, Any]:
        """Return validation rules.

        Returns:
            Dictionary describing the validation rules
        """
        return {
            "type": "identifier",
            "max_length": self.max_length,
            "pattern": "^[a-zA-Z_][a-zA-Z0-9_-]*$",
            "allow_hyphen": self.allow_hyphen,
        }
