"""
Trinitas Security Framework
...最悪のケースを想定した、完全にパラノイアックなセキュリティシステム...
"""

from .access_validator import (
    AccessAttempt,
    AccessResult,
    SecurityLevel,
    TrinitasSecurityValidator,
    ValidationResult,
    validate_persona_access,
)
from .security_integration import (
    SecurityIntegrationError,
    TrinitasSecurityIntegration,
    emergency_shutdown,
    get_capabilities,
    get_current_persona,
    get_security_status,
    initialize_security,
    persona_context,
    secure_tool,
    set_persona,
    validate_access,
)

__all__ = [
    "AccessAttempt",
    "AccessResult",
    "SecurityIntegrationError",
    "SecurityLevel",
    # Integration classes
    "TrinitasSecurityIntegration",
    # Validator classes
    "TrinitasSecurityValidator",
    "ValidationResult",
    "emergency_shutdown",
    "get_capabilities",
    "get_current_persona",
    "get_security_status",
    "initialize_security",
    "persona_context",
    "secure_tool",
    # Convenience functions
    "set_persona",
    "validate_access",
    "validate_persona_access",
]

__version__ = "2.0.0"
__author__ = "Hestia Security Auditor"

# ...パラノイアックなセキュリティシステムが初期化されました...
# 全てのアクセスは疑わしいものとして扱われます...
