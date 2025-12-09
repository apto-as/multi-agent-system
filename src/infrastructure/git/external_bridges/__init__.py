"""External Git Hosting Bridges for TMWS.

Phase 4.2: Issue #33 - External Git Integration
- Abstract bridge interface for GitHub/GitLab
- Rate limiting and circuit breaker patterns
- Security-hardened token validation
- Async session sync and issue search

Supported Platforms:
- GitHub (Issues, Discussions, Projects)
- GitLab (Issues, Merge Requests, Wiki)

Security Notes:
- Tokens are validated for format but NEVER logged
- All URLs are validated to prevent SSRF attacks
- Request timeouts prevent hanging connections
- Rate limiting prevents API abuse
- Circuit breaker protects against cascading failures

Author: Metis (Development Assistant)
Created: 2025-12-09
Security Review: Hestia (2025-12-09) - Security patterns applied
"""

from .base import (
    BridgeConfig,
    BridgeError,
    SecurityError,
    CircuitBreaker,
    CircuitBreakerState,
    ExternalBridge,
    IssueResult,
    RateLimiter,
    SessionSnapshot,
)
from .github_bridge import GitHubBridge
from .gitlab_bridge import GitLabBridge

__all__ = [
    # Base classes and types
    "BridgeConfig",
    "ExternalBridge",
    "IssueResult",
    "SessionSnapshot",
    # Exceptions
    "BridgeError",
    "SecurityError",
    # Utilities
    "CircuitBreaker",
    "CircuitBreakerState",
    "RateLimiter",
    # Concrete implementations
    "GitHubBridge",
    "GitLabBridge",
]
