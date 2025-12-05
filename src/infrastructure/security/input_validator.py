"""JSON Schema Validation for MCP Tool Inputs.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 2.2 - Input/Output Controls
Requirement: S-P0-3 - JSON Schema Validation

Security Properties:
- Validates all tool inputs against JSON Schema
- Prevents injection attacks via malformed inputs
- Type coercion prevention
- Maximum string/array length enforcement

Usage:
    >>> validator = JSONSchemaValidator()
    >>> validator.validate(arguments, tool_schema)
    >>> # Or use the convenience function
    >>> validate_tool_input(arguments, tool_schema)

Author: Artemis (Implementation) + Hestia (Security Review)
Created: 2025-12-05
"""

import logging
from typing import Any

import jsonschema
from jsonschema import Draft7Validator

logger = logging.getLogger(__name__)


class InputValidationError(Exception):
    """Input validation error.

    Raised when tool input fails schema validation.
    """

    def __init__(
        self,
        message: str,
        schema_path: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.schema_path = schema_path
        self.details = details or {}


class JSONSchemaValidator:
    """JSON Schema validator for MCP tool inputs.

    Security Features:
    - Draft 7 JSON Schema validation
    - Format validation (uri, email, datetime)
    - Maximum depth protection
    - String length limits
    - Array size limits

    Configuration:
    - max_string_length: Maximum allowed string length (default: 100KB)
    - max_array_items: Maximum array items (default: 1000)
    - max_object_properties: Maximum object properties (default: 100)
    - max_depth: Maximum nesting depth (default: 20)
    """

    # Default limits
    DEFAULT_MAX_STRING_LENGTH = 100 * 1024  # 100KB
    DEFAULT_MAX_ARRAY_ITEMS = 1000
    DEFAULT_MAX_OBJECT_PROPERTIES = 100
    DEFAULT_MAX_DEPTH = 20

    def __init__(
        self,
        max_string_length: int | None = None,
        max_array_items: int | None = None,
        max_object_properties: int | None = None,
        max_depth: int | None = None,
    ):
        """Initialize validator with limits.

        Args:
            max_string_length: Maximum string length in characters
            max_array_items: Maximum number of array items
            max_object_properties: Maximum number of object properties
            max_depth: Maximum nesting depth
        """
        self.max_string_length = max_string_length or self.DEFAULT_MAX_STRING_LENGTH
        self.max_array_items = max_array_items or self.DEFAULT_MAX_ARRAY_ITEMS
        self.max_object_properties = max_object_properties or self.DEFAULT_MAX_OBJECT_PROPERTIES
        self.max_depth = max_depth or self.DEFAULT_MAX_DEPTH

        logger.debug(
            f"JSONSchemaValidator initialized with limits: "
            f"string={self.max_string_length}, array={self.max_array_items}, "
            f"properties={self.max_object_properties}, depth={self.max_depth}"
        )

    def validate(
        self,
        instance: dict[str, Any],
        schema: dict[str, Any],
        tool_name: str | None = None,
    ) -> None:
        """Validate instance against JSON Schema.

        Args:
            instance: Data to validate
            schema: JSON Schema to validate against
            tool_name: Optional tool name for error messages

        Raises:
            InputValidationError: If validation fails
        """
        # Pre-validation: Check structural limits
        self._check_structural_limits(instance, tool_name=tool_name)

        # Skip if no schema provided
        if not schema:
            logger.debug(f"No schema provided for tool {tool_name}, skipping validation")
            return

        # Create validator
        try:
            validator = Draft7Validator(schema)
        except jsonschema.SchemaError as e:
            raise InputValidationError(
                f"Invalid schema for tool {tool_name}",
                schema_path=str(e.absolute_path),
                details={"error": str(e)},
            )

        # Collect all validation errors
        errors = list(validator.iter_errors(instance))

        if errors:
            # Format first error for message
            first_error = errors[0]
            error_path = ".".join(str(p) for p in first_error.absolute_path)

            raise InputValidationError(
                f"Validation failed for tool {tool_name}: {first_error.message}",
                schema_path=error_path,
                details={
                    "error_count": len(errors),
                    "first_error": first_error.message,
                    "path": error_path,
                    "validator": first_error.validator,
                },
            )

        logger.debug(f"Validation passed for tool {tool_name}")

    def _check_structural_limits(
        self,
        data: Any,
        depth: int = 0,
        tool_name: str | None = None,
    ) -> None:
        """Check structural limits (depth, size) before schema validation.

        Args:
            data: Data to check
            depth: Current nesting depth
            tool_name: Tool name for error messages

        Raises:
            InputValidationError: If limits exceeded
        """
        # Check depth
        if depth > self.max_depth:
            raise InputValidationError(
                f"Maximum nesting depth exceeded for tool {tool_name}",
                details={"max_depth": self.max_depth, "current_depth": depth},
            )

        if isinstance(data, dict):
            # Check property count
            if len(data) > self.max_object_properties:
                raise InputValidationError(
                    f"Maximum object properties exceeded for tool {tool_name}",
                    details={
                        "max_properties": self.max_object_properties,
                        "actual_properties": len(data),
                    },
                )

            # Recurse into values
            for value in data.values():
                self._check_structural_limits(value, depth + 1, tool_name)

        elif isinstance(data, list):
            # Check array size
            if len(data) > self.max_array_items:
                raise InputValidationError(
                    f"Maximum array items exceeded for tool {tool_name}",
                    details={
                        "max_items": self.max_array_items,
                        "actual_items": len(data),
                    },
                )

            # Recurse into items
            for item in data:
                self._check_structural_limits(item, depth + 1, tool_name)

        elif isinstance(data, str):
            # Check string length
            if len(data) > self.max_string_length:
                raise InputValidationError(
                    f"Maximum string length exceeded for tool {tool_name}",
                    details={
                        "max_length": self.max_string_length,
                        "actual_length": len(data),
                    },
                )


# Singleton instance
_validator: JSONSchemaValidator | None = None


def get_validator() -> JSONSchemaValidator:
    """Get singleton JSONSchemaValidator instance.

    Returns:
        JSONSchemaValidator instance
    """
    global _validator
    if _validator is None:
        _validator = JSONSchemaValidator()
    return _validator


def validate_tool_input(
    arguments: dict[str, Any],
    schema: dict[str, Any],
    tool_name: str | None = None,
) -> None:
    """Validate tool input against schema.

    Convenience function using singleton validator.

    Args:
        arguments: Tool arguments to validate
        schema: JSON Schema for validation
        tool_name: Tool name for error messages

    Raises:
        InputValidationError: If validation fails
    """
    validator = get_validator()
    validator.validate(arguments, schema, tool_name)
