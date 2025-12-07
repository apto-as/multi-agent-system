"""Unified Sanitizer facade for all sanitization operations.

Provides a single entry point for all sanitization needs with:
- Unified API for all validators
- Automatic validator selection
- Backward-compatible convenience methods
- Extensibility via registry

Security:
- Centralizes all sanitization logic
- Consistent validation behavior
- Audit-friendly design

Author: Artemis (Implementation)
Created: 2025-12-07 (Issue #22: Unified Sanitization)
"""

import logging
from typing import Any

from .base import BaseValidator, Severity, ValidationResult
from .exceptions import SanitizationError, ValidatorNotFoundError
from .registry import ValidatorRegistry, get_registry
from .validators import (
    CommandValidator,
    HTMLValidator,
    IdentifierValidator,
    JSONValidator,
    PathValidator,
    SQLValidator,
    StringValidator,
)

logger = logging.getLogger(__name__)


class Sanitizer:
    """Unified facade for all sanitization operations.

    Provides a single entry point for:
    - String sanitization
    - SQL injection prevention
    - Command injection prevention
    - Path traversal prevention
    - HTML/XSS sanitization
    - JSON validation

    Example:
        >>> sanitizer = Sanitizer()
        >>> result = sanitizer.validate("test", "string")
        >>> result.is_valid
        True

        >>> # Convenience method
        >>> sanitized = sanitizer.sanitize_string("  hello  ")
        >>> sanitized
        'hello'
    """

    def __init__(self, registry: ValidatorRegistry | None = None):
        """Initialize sanitizer with optional custom registry.

        Args:
            registry: Custom validator registry (default: global registry)
        """
        self._registry = registry or get_registry()
        self._register_default_validators()

    def _register_default_validators(self) -> None:
        """Register all built-in validators."""
        defaults = {
            "string": StringValidator,
            "identifier": IdentifierValidator,
            "sql": SQLValidator,
            "command": CommandValidator,
            "path": PathValidator,
            "html": HTMLValidator,
            "json": JSONValidator,
        }

        for name, validator_class in defaults.items():
            if not self._registry.has(name):
                self._registry.register(name, validator_class)

    def validate(
        self,
        value: Any,
        validator_type: str,
        **kwargs: Any,
    ) -> ValidationResult[Any]:
        """Validate using specified validator.

        Args:
            value: The value to validate
            validator_type: Name of the validator to use
            **kwargs: Options passed to validator constructor and validate()

        Returns:
            ValidationResult from the validator

        Raises:
            ValidatorNotFoundError: If validator type is not registered
        """
        try:
            validator_class = self._registry.get(validator_type)
        except ValidatorNotFoundError:
            logger.error(f"Validator not found: {validator_type}")
            raise

        # Extract constructor kwargs vs validate kwargs
        # Constructor kwargs have specific prefixes
        constructor_kwargs = {}
        validate_kwargs = {}

        for key, val in kwargs.items():
            # Known constructor parameters
            if key in (
                "max_length",
                "min_length",
                "max_depth",
                "max_size",
                "max_keys",
                "preset",
                "strict_mode",
                "allowed_commands",
                "allowed_tags",
                "base_path",
                "allow_absolute",
                "allow_symlinks",
                "allow_empty",
                "allow_wildcards",
                "escape_output",
            ):
                constructor_kwargs[key] = val
            else:
                validate_kwargs[key] = val

        # Instantiate validator with constructor kwargs
        validator: BaseValidator[Any] = validator_class(**constructor_kwargs)

        # Validate with remaining kwargs
        return validator.validate(value, **validate_kwargs)

    # =========================================================================
    # Convenience Methods (backward compatibility + ease of use)
    # =========================================================================

    def sanitize_string(
        self,
        value: str,
        max_length: int = 10000,
        allow_empty: bool = True,
        **kwargs: Any,
    ) -> str:
        """Sanitize a string value.

        Args:
            value: String to sanitize
            max_length: Maximum allowed length
            allow_empty: Allow empty strings
            **kwargs: Additional options

        Returns:
            Sanitized string

        Raises:
            SanitizationError: If validation fails critically
        """
        result = self.validate(
            value,
            "string",
            max_length=max_length,
            allow_empty=allow_empty,
            **kwargs,
        )

        if not result.is_valid and result.severity == Severity.CRITICAL:
            raise SanitizationError(
                result.error_message or "String validation failed"
            )

        return result.sanitized_value or ""

    def sanitize_identifier(
        self,
        value: str,
        max_length: int = 64,
        **kwargs: Any,
    ) -> str:
        """Sanitize an identifier (agent_id, namespace, etc.).

        Args:
            value: Identifier to sanitize
            max_length: Maximum length
            **kwargs: Additional options

        Returns:
            Sanitized identifier

        Raises:
            SanitizationError: If validation fails
        """
        result = self.validate(
            value,
            "identifier",
            max_length=max_length,
            **kwargs,
        )

        if not result.is_valid:
            raise SanitizationError(
                result.error_message or "Identifier validation failed"
            )

        return result.sanitized_value or ""

    def sanitize_sql(
        self,
        value: str,
        max_length: int = 1000,
        strict_mode: bool = True,
        **kwargs: Any,
    ) -> str:
        """Sanitize SQL input.

        Args:
            value: SQL value to sanitize
            max_length: Maximum length
            strict_mode: Use strict detection
            **kwargs: Additional options

        Returns:
            Sanitized SQL value

        Raises:
            SanitizationError: If SQL injection detected
        """
        result = self.validate(
            value,
            "sql",
            max_length=max_length,
            strict_mode=strict_mode,
            **kwargs,
        )

        if not result.is_valid and result.severity == Severity.CRITICAL:
            raise SanitizationError(
                result.error_message or "SQL injection detected"
            )

        return result.sanitized_value or ""

    def validate_command(
        self,
        command: str,
        allowed_commands: set[str] | None = None,
        **kwargs: Any,
    ) -> str:
        """Validate a command for execution.

        Args:
            command: Command to validate
            allowed_commands: Set of allowed command names
            **kwargs: Additional options

        Returns:
            Original command if valid

        Raises:
            SanitizationError: If command injection detected
        """
        result = self.validate(
            command,
            "command",
            allowed_commands=allowed_commands,
            **kwargs,
        )

        if not result.is_valid:
            raise SanitizationError(
                result.error_message or "Command validation failed"
            )

        return command

    def sanitize_path(
        self,
        path: str,
        base_path: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Sanitize a file path.

        Args:
            path: Path to sanitize
            base_path: Base directory for validation
            **kwargs: Additional options

        Returns:
            Sanitized path

        Raises:
            SanitizationError: If path traversal detected
        """
        result = self.validate(
            path,
            "path",
            base_path=base_path,
            **kwargs,
        )

        if not result.is_valid and result.severity == Severity.CRITICAL:
            raise SanitizationError(
                result.error_message or "Path traversal detected"
            )

        return result.sanitized_value or ""

    def sanitize_html(
        self,
        content: str,
        preset: str = "strict",
        **kwargs: Any,
    ) -> str:
        """Sanitize HTML content.

        Args:
            content: HTML content to sanitize
            preset: Sanitization preset (strict, basic, markdown, rich)
            **kwargs: Additional options

        Returns:
            Sanitized HTML content

        Raises:
            SanitizationError: If XSS detected and critical
        """
        result = self.validate(
            content,
            "html",
            preset=preset,
            **kwargs,
        )

        if not result.is_valid and result.severity == Severity.CRITICAL:
            raise SanitizationError(
                result.error_message or "XSS detected"
            )

        return result.sanitized_value or ""

    def validate_json(
        self,
        value: str | dict[str, Any] | list[Any],
        max_depth: int = 20,
        max_size: int = 1_000_000,
        **kwargs: Any,
    ) -> dict[str, Any] | list[Any]:
        """Validate JSON input.

        Args:
            value: JSON string or dict/list
            max_depth: Maximum nesting depth
            max_size: Maximum size in bytes
            **kwargs: Additional options

        Returns:
            Parsed JSON

        Raises:
            SanitizationError: If JSON validation fails
        """
        result = self.validate(
            value,
            "json",
            max_depth=max_depth,
            max_size=max_size,
            **kwargs,
        )

        if not result.is_valid:
            raise SanitizationError(
                result.error_message or "JSON validation failed"
            )

        return result.sanitized_value  # type: ignore

    # =========================================================================
    # Extensibility
    # =========================================================================

    def register_validator(
        self,
        name: str,
        validator_class: type[BaseValidator[Any]],
        override: bool = False,
    ) -> None:
        """Register a custom validator.

        Args:
            name: Unique name for the validator
            validator_class: The validator class to register
            override: Allow overriding existing registration
        """
        self._registry.register(name, validator_class, override=override)
        logger.info(f"Custom validator registered: {name}")

    def list_validators(self) -> list[str]:
        """List all registered validator names.

        Returns:
            Sorted list of validator names
        """
        return self._registry.list_validators()

    def get_validator_info(self) -> dict[str, dict[str, Any]]:
        """Get information about all validators.

        Returns:
            Dictionary with validator details and rules
        """
        return self._registry.get_validator_info()


# Module-level singleton
_sanitizer: Sanitizer | None = None


def get_sanitizer() -> Sanitizer:
    """Get the global Sanitizer instance.

    Returns:
        The singleton Sanitizer instance
    """
    global _sanitizer
    if _sanitizer is None:
        _sanitizer = Sanitizer()
    return _sanitizer
