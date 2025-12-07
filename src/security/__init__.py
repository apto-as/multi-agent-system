"""TMWS Security Module
Hestia's Paranoid Security Implementation

"……最悪のケースを想定して、完璧な防御を構築します……"
"""

from .html_sanitizer import HTMLSanitizer
from .rate_limiter import DDoSProtection, RateLimiter

# Issue #22: Unified Sanitization Module (new recommended API)
from .sanitization import (
    CommandInjectionError,
    CommandValidator,
    HTMLValidator,
    IdentifierValidator,
    JSONValidator,
    PathTraversalError,
    PathValidator,
    # Exceptions
    SanitizationError,
    Sanitizer,
    Severity,
    SQLInjectionError,
    SQLValidator,
    # Validators
    StringValidator,
    ValidationError,
    ValidationResult,
    XSSError,
    get_sanitizer,
    sanitize_html,
    validate_command_safe,
    validate_json,
    validate_path_safe,
    # Convenience functions
    validate_sql_safe,
)

# Phase 4.2: Facade Pattern - AsyncSecurityAuditLogger replaced by SecurityAuditFacade
from .security_audit_facade import SecurityAuditFacade as AsyncSecurityAuditLogger

# P2-4: SecurityEvent kept for backward compatibility
from .security_event import SecurityEvent
from .validators import InputValidator, SQLInjectionValidator, VectorValidator

__all__ = [
    # Legacy exports (backward compatibility)
    "InputValidator",
    "SQLInjectionValidator",
    "VectorValidator",
    "RateLimiter",
    "DDoSProtection",
    "SecurityEvent",
    "AsyncSecurityAuditLogger",
    "HTMLSanitizer",
    # Issue #22: Unified Sanitization (recommended)
    "Sanitizer",
    "get_sanitizer",
    "Severity",
    "ValidationResult",
    "StringValidator",
    "IdentifierValidator",
    "SQLValidator",
    "CommandValidator",
    "PathValidator",
    "HTMLValidator",
    "JSONValidator",
    "validate_sql_safe",
    "validate_command_safe",
    "validate_path_safe",
    "sanitize_html",
    "validate_json",
    "SanitizationError",
    "ValidationError",
    "SQLInjectionError",
    "CommandInjectionError",
    "PathTraversalError",
    "XSSError",
]
