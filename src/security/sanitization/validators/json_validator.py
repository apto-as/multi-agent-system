"""JSON validator for sanitization module.

Provides JSON validation including:
- Structure validation
- Depth limiting (DoS prevention)
- Size limiting
- Schema validation (optional)

Security:
- Prevents deeply nested JSON DoS
- Enforces size limits
- Validates structure before processing

Author: Artemis (Implementation)
Created: 2025-12-07 (Issue #22: Unified Sanitization)
"""

import json
from typing import Any

from ..base import BaseValidator, Severity, ValidationResult


class JSONValidator(BaseValidator[dict[str, Any] | list[Any]]):
    """Validator for JSON inputs.

    Validates JSON for:
    - Valid JSON syntax
    - Maximum depth (DoS prevention)
    - Maximum size
    - Required keys (optional)

    Example:
        >>> validator = JSONValidator(max_depth=10)
        >>> result = validator.validate('{"key": "value"}')
        >>> result.is_valid
        True
        >>> result.sanitized_value
        {'key': 'value'}
    """

    def __init__(
        self,
        max_depth: int = 20,
        max_size: int = 1_000_000,  # 1MB
        max_keys: int = 1000,
        required_keys: set[str] | None = None,
        allow_array_root: bool = True,
    ):
        """Initialize JSON validator.

        Args:
            max_depth: Maximum nesting depth (default 20)
            max_size: Maximum JSON string size in bytes (default 1MB)
            max_keys: Maximum total keys (default 1000)
            required_keys: Required top-level keys (optional)
            allow_array_root: Allow array as root element (default True)
        """
        self.max_depth = max_depth
        self.max_size = max_size
        self.max_keys = max_keys
        self.required_keys = required_keys or set()
        self.allow_array_root = allow_array_root

    def validate(
        self, value: Any, **kwargs: Any
    ) -> ValidationResult[dict[str, Any] | list[Any]]:
        """Validate JSON input.

        Args:
            value: JSON string or dict/list to validate
            **kwargs: Override options

        Returns:
            ValidationResult with parsed JSON
        """
        # Handle string input
        if isinstance(value, str):
            # Size check for string
            max_size = kwargs.get("max_size", self.max_size)
            if len(value.encode("utf-8")) > max_size:
                return ValidationResult.failure(
                    f"JSON exceeds maximum size of {max_size} bytes",
                    severity=Severity.WARNING,
                    details={"size": len(value.encode("utf-8"))},
                )

            # Parse JSON
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError as e:
                return ValidationResult.failure(
                    f"Invalid JSON: {e.msg}",
                    severity=Severity.CRITICAL,
                    details={"line": e.lineno, "column": e.colno},
                )
        elif isinstance(value, dict | list):
            parsed = value
        else:
            return ValidationResult.failure(
                f"Expected JSON string or dict/list, got {type(value).__name__}",
                severity=Severity.CRITICAL,
            )

        # Type check for root element
        if isinstance(parsed, list):
            if not self.allow_array_root:
                return ValidationResult.failure(
                    "Array as root element not allowed",
                    severity=Severity.WARNING,
                )
        elif not isinstance(parsed, dict):
            return ValidationResult.failure(
                f"Expected object or array, got {type(parsed).__name__}",
                severity=Severity.CRITICAL,
            )

        # Depth check
        max_depth = kwargs.get("max_depth", self.max_depth)
        depth = self._calculate_depth(parsed)
        if depth > max_depth:
            return ValidationResult.failure(
                f"JSON depth {depth} exceeds maximum of {max_depth}",
                severity=Severity.WARNING,
                details={"depth": depth, "max_depth": max_depth},
            )

        # Key count check
        max_keys = kwargs.get("max_keys", self.max_keys)
        key_count = self._count_keys(parsed)
        if key_count > max_keys:
            return ValidationResult.failure(
                f"JSON has {key_count} keys, exceeds maximum of {max_keys}",
                severity=Severity.WARNING,
                details={"key_count": key_count, "max_keys": max_keys},
            )

        # Required keys check (only for dict)
        if isinstance(parsed, dict):
            required_keys = kwargs.get("required_keys", self.required_keys)
            missing_keys = required_keys - set(parsed.keys())
            if missing_keys:
                return ValidationResult.failure(
                    f"Missing required keys: {', '.join(sorted(missing_keys))}",
                    severity=Severity.WARNING,
                    details={"missing_keys": sorted(missing_keys)},
                )

        return ValidationResult.success(parsed)

    def _calculate_depth(self, obj: Any, current_depth: int = 0) -> int:
        """Calculate the maximum depth of a JSON structure.

        Args:
            obj: JSON object/array to measure
            current_depth: Current recursion depth

        Returns:
            Maximum depth found
        """
        if isinstance(obj, dict):
            if not obj:
                return current_depth
            return max(
                self._calculate_depth(v, current_depth + 1) for v in obj.values()
            )
        elif isinstance(obj, list):
            if not obj:
                return current_depth
            return max(
                self._calculate_depth(item, current_depth + 1) for item in obj
            )
        else:
            return current_depth

    def _count_keys(self, obj: Any) -> int:
        """Count total keys in a JSON structure.

        Args:
            obj: JSON object/array to count

        Returns:
            Total key count
        """
        if isinstance(obj, dict):
            count = len(obj)
            for v in obj.values():
                count += self._count_keys(v)
            return count
        elif isinstance(obj, list):
            return sum(self._count_keys(item) for item in obj)
        else:
            return 0

    def get_validation_rules(self) -> dict[str, Any]:
        """Return validation rules for documentation/audit.

        Returns:
            Dictionary describing the validation rules
        """
        return {
            "type": "json",
            "max_depth": self.max_depth,
            "max_size": self.max_size,
            "max_keys": self.max_keys,
            "required_keys": sorted(self.required_keys) if self.required_keys else [],
            "allow_array_root": self.allow_array_root,
        }


def validate_json(
    value: str | dict[str, Any] | list[Any],
    max_depth: int = 20,
    max_size: int = 1_000_000,
) -> dict[str, Any] | list[Any]:
    """Convenience function for JSON validation.

    Args:
        value: JSON string or dict/list to validate
        max_depth: Maximum nesting depth
        max_size: Maximum size in bytes

    Returns:
        Parsed JSON if valid

    Raises:
        ValueError: If validation fails
    """
    validator = JSONValidator(max_depth=max_depth, max_size=max_size)
    result = validator.validate(value)

    if not result.is_valid:
        raise ValueError(result.error_message or "Invalid JSON")

    return result.sanitized_value  # type: ignore
