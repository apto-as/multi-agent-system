"""Security infrastructure for TMWS MCP Hub.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 2.1 - Security Foundation

P0 Security Requirements:
- S-P0-1: HMAC Socket Authentication
- S-P0-2: Container Capability Drop (Docker config)
- S-P0-3: JSON Schema Validation
- S-P0-4: Subprocess Sandboxing
- S-P0-5: Allowlist-Only Servers
- S-P0-6: Response Size Limits
- S-P0-7: Timeout Enforcement
- S-P0-8: Audit Logging

Author: Artemis (Implementation) + Hestia (Security Review)
Created: 2025-12-05
"""

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
    # Response Limits (S-P0-6)
    "ResponseLimiter",
    "ResponseLimitError",
    "check_response_size",
]
