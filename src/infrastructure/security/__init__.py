"""Security infrastructure for TMWS MCP Hub.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 2.1-2.3 - Security Foundation & Runtime Protection

P0 Security Requirements (All Implemented):
- S-P0-1: HMAC Socket Authentication
- S-P0-2: Container Capability Drop (Docker config)
- S-P0-3: JSON Schema Validation
- S-P0-4: Subprocess Sandboxing (AST-based code validation)
- S-P0-5: Allowlist-Only Servers (preset_config.py)
- S-P0-6: Response Size Limits
- S-P0-7: Timeout Enforcement (hub_manager.py)
- S-P0-8: Audit Logging

Author: Artemis (Implementation) + Hestia (Security Review) + Metis (S-P0-4, S-P0-8)
Created: 2025-12-05
"""

from .audit_logger import (
    AuditEntry,
    AuditEventType,
    AuditLevel,
    SecurityAuditLogger,
    configure_audit_logger,
    get_audit_logger,
)
from .code_validator import (
    CodeValidationError,
    CodeValidator,
    CodeValidatorConfig,
    ValidationResult,
    validate_code,
    validate_code_or_raise,
)
from .hmac_auth import (
    HMACAuthenticator,
    HMACAuthError,
    create_hmac_authenticator,
)
from .input_validator import (
    InputValidationError,
    JSONSchemaValidator,
    validate_tool_input,
)
from .response_limits import (
    ResponseLimiter,
    ResponseLimitError,
    check_response_size,
)

__all__ = [
    # HMAC Authentication (S-P0-1)
    "HMACAuthenticator",
    "HMACAuthError",
    "create_hmac_authenticator",
    # Input Validation (S-P0-3)
    "JSONSchemaValidator",
    "InputValidationError",
    "validate_tool_input",
    # Code Validation / Subprocess Sandboxing (S-P0-4)
    "CodeValidator",
    "CodeValidatorConfig",
    "CodeValidationError",
    "ValidationResult",
    "validate_code",
    "validate_code_or_raise",
    # Response Limits (S-P0-6)
    "ResponseLimiter",
    "ResponseLimitError",
    "check_response_size",
    # Audit Logging (S-P0-8)
    "SecurityAuditLogger",
    "AuditEntry",
    "AuditEventType",
    "AuditLevel",
    "get_audit_logger",
    "configure_audit_logger",
]
