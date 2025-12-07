"""Unified Sanitization Module for TMWS.

This module provides a centralized, extensible sanitization system with:
- Type-safe validation with detailed results
- Multiple validator types (string, SQL, command, path, HTML, JSON)
- Extensible registry for custom validators
- Backward-compatible convenience functions

Security:
- Centralized validation reduces attack surface
- Consistent error handling and logging
- Audit-friendly design with validation rules

Usage:
    >>> from src.security.sanitization import Sanitizer, get_sanitizer
    >>>
    >>> # Using singleton
    >>> sanitizer = get_sanitizer()
    >>> result = sanitizer.validate("test", "string")
    >>> print(result.is_valid)
    True
    >>>
    >>> # Convenience methods
    >>> safe_string = sanitizer.sanitize_string("  hello  ")
    >>> safe_sql = sanitizer.sanitize_sql("user_input")
    >>> safe_html = sanitizer.sanitize_html("<p>content</p>")

Author: Artemis (Implementation)
Created: 2025-12-07 (Issue #22: Unified Sanitization)
"""

# Base classes
from .base import BaseValidator, Severity, ValidationResult

# Core patterns
from .core import PatternRegistry, get_pattern_registry

# Exceptions
from .exceptions import (
    CommandInjectionError,
    PathTraversalError,
    RegexValidationError,
    SanitizationError,
    SQLInjectionError,
    ValidationError,
    ValidatorNotFoundError,
    XSSError,
)

# Facade
from .facade import Sanitizer, get_sanitizer

# Registry
from .registry import ValidatorRegistry, get_registry

# Validators
from .validators import (
    CommandValidator,
    HTMLValidator,
    IdentifierValidator,
    JSONValidator,
    PathValidator,
    SQLValidator,
    StringValidator,
    sanitize_html,
    validate_command_safe,
    validate_json,
    validate_path_safe,
    validate_sql_safe,
)

__all__ = [
    # Base
    "BaseValidator",
    "ValidationResult",
    "Severity",
    # Core
    "PatternRegistry",
    "get_pattern_registry",
    # Facade
    "Sanitizer",
    "get_sanitizer",
    # Registry
    "ValidatorRegistry",
    "get_registry",
    # Validators
    "StringValidator",
    "IdentifierValidator",
    "SQLValidator",
    "CommandValidator",
    "PathValidator",
    "HTMLValidator",
    "JSONValidator",
    # Convenience functions
    "validate_sql_safe",
    "validate_command_safe",
    "validate_path_safe",
    "sanitize_html",
    "validate_json",
    # Exceptions
    "SanitizationError",
    "ValidationError",
    "SQLInjectionError",
    "CommandInjectionError",
    "PathTraversalError",
    "XSSError",
    "RegexValidationError",
    "ValidatorNotFoundError",
]

__version__ = "1.0.0"
