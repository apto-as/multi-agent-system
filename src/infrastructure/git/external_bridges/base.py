"""Abstract Base Interface for External Git Hosting Bridges.

Phase 4.2: Issue #33 - External Git Integration
This module provides the foundation for integrating with external git hosting
platforms (GitHub, GitLab) to sync TMWS sessions and search across issues.

Key Components:
- ExternalBridge: Abstract interface for platform integrations
- RateLimiter: Token bucket rate limiting for API calls
- CircuitBreaker: Failure protection with automatic recovery
- Data Models: Type-safe configuration and results

Security Features:
- Token validation (format check, no logging)
- URL validation (HTTPS only, SSRF prevention)
- Input sanitization (all external inputs)
- Timeout protection (30s default)
- Forbidden localhost/internal IP ranges

Author: Metis (Development Assistant)
Created: 2025-12-09
Security Review: Hestia (2025-12-09) - CRITICAL security patterns applied
"""

import asyncio
import ipaddress
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Final
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

# Security: Valid token prefixes for different platforms
GITHUB_TOKEN_PREFIXES: Final[frozenset[str]] = frozenset({
    "ghp_",  # GitHub Personal Access Token
    "gho_",  # GitHub OAuth Token
    "ghs_",  # GitHub Server-to-Server Token
    "github_pat_",  # GitHub Fine-grained PAT
})

GITLAB_TOKEN_PREFIXES: Final[frozenset[str]] = frozenset({
    "glpat-",  # GitLab Personal Access Token
    "gloas-",  # GitLab OAuth Application Secret
})

# Security: Forbidden URL patterns to prevent SSRF
FORBIDDEN_URL_SCHEMES: Final[frozenset[str]] = frozenset({
    "file", "ftp", "gopher", "data", "javascript",
})

# Security: Internal IP ranges to prevent SSRF
FORBIDDEN_IP_RANGES: Final[list[ipaddress.IPv4Network]] = [
    ipaddress.IPv4Network("127.0.0.0/8"),    # Loopback
    ipaddress.IPv4Network("10.0.0.0/8"),     # Private
    ipaddress.IPv4Network("172.16.0.0/12"),  # Private
    ipaddress.IPv4Network("192.168.0.0/16"), # Private
    ipaddress.IPv4Network("169.254.0.0/16"), # Link-local
    ipaddress.IPv4Network("0.0.0.0/8"),      # Current network
]

# Security: Pattern for safe query strings (alphanumeric, spaces, basic punctuation, hash)
# Allows: letters, numbers, spaces, hyphen, underscore, dot, comma, colon, semicolon
#         exclamation, question mark, parentheses, quotes, hash, equals, slash
SAFE_QUERY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-zA-Z0-9\s\-_.,:;!?()\"'#=/]+$"
)

# Default timeouts
DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0
DEFAULT_CONNECT_TIMEOUT_SECONDS: Final[float] = 10.0


class SecurityError(Exception):
    """Raised when a security validation fails."""
    pass


class BridgeError(Exception):
    """Base exception for all bridge-related errors."""
    pass


class CircuitBreakerState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "CLOSED"        # Normal operation
    OPEN = "OPEN"            # Failing, reject calls
    HALF_OPEN = "HALF_OPEN"  # Testing recovery


def _validate_token_format(token: str, bridge_type: str) -> str:
    """Validate token format without logging the actual token.

    Security:
    - Checks token prefix to prevent invalid credentials
    - NEVER logs the actual token value
    - Uses redacted logging for security

    Args:
        token: API token to validate
        bridge_type: "github" or "gitlab"

    Returns:
        Validated token

    Raises:
        SecurityError: If token format is invalid
    """
    if not token:
        raise SecurityError("Token cannot be empty")

    # Minimum length check (tokens should be reasonably long)
    if len(token) < 20:
        raise SecurityError("Token too short (minimum 20 characters)")

    # Platform-specific prefix validation
    if bridge_type == "github":
        if not any(token.startswith(prefix) for prefix in GITHUB_TOKEN_PREFIXES):
            raise SecurityError(
                f"Invalid GitHub token format. Must start with one of: "
                f"{', '.join(GITHUB_TOKEN_PREFIXES)}"
            )
    elif bridge_type == "gitlab":
        if not any(token.startswith(prefix) for prefix in GITLAB_TOKEN_PREFIXES):
            raise SecurityError(
                f"Invalid GitLab token format. Must start with one of: "
                f"{', '.join(GITLAB_TOKEN_PREFIXES)}"
            )
    else:
        raise SecurityError(f"Unknown bridge_type: {bridge_type}")

    # SECURITY: Never log the actual token
    # Use redacted format for logging
    return token


def _validate_url(
    url: str,
    allow_custom_domains: bool = False,
    allow_insecure_http: bool = False,
) -> str:
    """Validate URL to prevent SSRF attacks.

    Security:
    - Enforces HTTPS by default (HTTP allowed with explicit opt-in)
    - Blocks localhost and internal IP ranges (unless explicitly allowed)
    - Blocks forbidden URL schemes (file://, ftp://, etc.)
    - Validates hostname format

    Args:
        url: URL to validate
        allow_custom_domains: Whether to allow non-standard GitHub/GitLab domains
        allow_insecure_http: Allow HTTP for self-hosted/local instances.
                            WARNING: Only enable for trusted internal networks.

    Returns:
        Validated URL

    Raises:
        SecurityError: If URL is invalid or unsafe
    """
    if not url:
        raise SecurityError("URL cannot be empty")

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise SecurityError(f"Invalid URL format: {e}")

    # Security: Enforce HTTPS by default, allow HTTP with explicit opt-in
    if parsed.scheme == "http":
        if allow_insecure_http:
            logger.warning(
                f"⚠️ SECURITY WARNING: Using insecure HTTP connection to {parsed.hostname}. "
                "This should only be used for trusted internal/local GitLab instances."
            )
        else:
            raise SecurityError(
                f"URL must use HTTPS scheme, got: {parsed.scheme}. "
                "Set allow_insecure_http=True for local/self-hosted instances."
            )
    elif parsed.scheme != "https":
        raise SecurityError(f"URL must use HTTPS (or HTTP with allow_insecure_http), got: {parsed.scheme}")

    # Security: Block forbidden schemes
    if parsed.scheme in FORBIDDEN_URL_SCHEMES:
        raise SecurityError(f"Forbidden URL scheme: {parsed.scheme}")

    # Security: Validate hostname exists
    if not parsed.hostname:
        raise SecurityError("URL must have a valid hostname")

    hostname = parsed.hostname

    # Security: Block localhost and internal IPs (unless HTTP is allowed for local instances)
    if hostname in ("localhost", "127.0.0.1", "::1"):
        if allow_insecure_http:
            logger.warning(
                f"⚠️ SECURITY WARNING: Connecting to localhost ({hostname}). "
                "This should only be used for local development instances."
            )
        else:
            raise SecurityError(
                "URLs pointing to localhost are forbidden. "
                "Set allow_insecure_http=True for local development instances."
            )

    # Security: Check for internal IP ranges
    try:
        ip = ipaddress.ip_address(hostname)
        for forbidden_range in FORBIDDEN_IP_RANGES:
            if ip in forbidden_range:
                if allow_insecure_http:
                    logger.warning(
                        f"⚠️ SECURITY WARNING: Connecting to internal IP ({hostname}). "
                        "This should only be used for trusted internal networks."
                    )
                    break  # Allow but warn
                else:
                    raise SecurityError(
                        f"URL points to forbidden IP range: {hostname}. "
                        "Set allow_insecure_http=True for internal network instances."
                    )
    except ValueError:
        # Not an IP address, continue with hostname validation
        pass

    # Validate against standard domains if not allowing custom
    if not allow_custom_domains:
        allowed_domains = {
            "api.github.com",
            "github.com",
            "gitlab.com",
            "api.gitlab.com",
        }
        if hostname not in allowed_domains:
            raise SecurityError(
                f"URL domain not allowed: {hostname}. "
                f"Set allow_custom_domains=True for custom domains."
            )

    return url


def _sanitize_query(query: str) -> str:
    """Sanitize search query to prevent injection attacks.

    Security:
    - Limits to safe characters only
    - Prevents newlines and control characters
    - Enforces maximum length

    Args:
        query: Search query to sanitize

    Returns:
        Sanitized query

    Raises:
        SecurityError: If query contains unsafe characters
    """
    if not query:
        raise SecurityError("Query cannot be empty")

    # Maximum query length
    if len(query) > 500:
        raise SecurityError("Query too long (maximum 500 characters)")

    # Security: Explicitly check for newlines and control characters
    if "\n" in query or "\r" in query:
        raise SecurityError("Query contains newline or carriage return characters")

    # Security: Check for null bytes
    if "\x00" in query:
        raise SecurityError("Query contains null byte")

    # Check for safe pattern
    if not SAFE_QUERY_PATTERN.match(query):
        raise SecurityError(
            "Query contains unsafe characters. "
            "Allowed: alphanumeric, spaces, and basic punctuation"
        )

    return query.strip()


@dataclass
class BridgeConfig:
    """Configuration for external git hosting bridge.

    Security:
    - token is validated but never logged
    - base_url is validated to prevent SSRF
    - timeout enforces maximum request duration

    Self-Hosted/Local Instances:
    - Set allow_custom_domain=True for non-standard domains
    - Set allow_insecure_http=True for HTTP (local GitLab, dev environments)
    - WARNING: allow_insecure_http should only be used for trusted networks
    """

    bridge_type: str  # "github" or "gitlab"
    token: str  # API token (validated, never logged)
    base_url: str  # Base API URL (HTTPS by default, HTTP with opt-in)
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_retries: int = 3
    allow_custom_domain: bool = False
    allow_insecure_http: bool = False  # Allow HTTP for local/self-hosted instances

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        # Validate bridge type
        if self.bridge_type not in ("github", "gitlab"):
            raise ValueError(f"Invalid bridge_type: {self.bridge_type}")

        # Security: Validate token format
        _validate_token_format(self.token, self.bridge_type)

        # Security: Validate URL (with optional HTTP for self-hosted)
        _validate_url(
            self.base_url,
            allow_custom_domains=self.allow_custom_domain,
            allow_insecure_http=self.allow_insecure_http,
        )

        # Validate timeout
        if self.timeout_seconds <= 0 or self.timeout_seconds > 300:
            raise ValueError("timeout_seconds must be between 0 and 300")

        # Validate retries
        if self.max_retries < 0 or self.max_retries > 10:
            raise ValueError("max_retries must be between 0 and 10")

    def __repr__(self) -> str:
        """Redacted string representation.

        Security: Never expose token in string representation.
        """
        return (
            f"BridgeConfig(bridge_type={self.bridge_type!r}, "
            f"token=[REDACTED], "
            f"base_url={self.base_url!r}, "
            f"timeout_seconds={self.timeout_seconds}, "
            f"max_retries={self.max_retries}, "
            f"allow_insecure_http={self.allow_insecure_http})"
        )


@dataclass
class SessionSnapshot:
    """Snapshot of a TMWS session for external sync."""

    session_id: str
    timestamp: datetime
    summary: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class IssueResult:
    """Result from external issue search."""

    issue_id: str  # Platform-specific ID (e.g., "123" for GitHub, "456" for GitLab)
    title: str
    body: str
    state: str  # "open", "closed", "merged"
    url: str
    labels: list[str] = field(default_factory=list)
    created_at: datetime | None = None
    updated_at: datetime | None = None


class RateLimiter:
    """Token bucket rate limiter for API calls.

    Implements the token bucket algorithm to prevent API abuse:
    - Tokens are added at a fixed rate (max_requests per window)
    - Each request consumes one token
    - If no tokens available, request waits or fails

    Example:
        >>> limiter = RateLimiter(max_requests=10, window_seconds=60.0)
        >>> await limiter.wait_if_needed()  # Waits if rate limit exceeded
        >>> if await limiter.acquire():     # Non-blocking check
        ...     await make_api_call()
    """

    def __init__(self, max_requests: int, window_seconds: float):
        """Initialize rate limiter.

        Args:
            max_requests: Maximum requests allowed in window
            window_seconds: Time window in seconds
        """
        if max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.tokens = float(max_requests)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        """Try to acquire a token (non-blocking).

        Returns:
            True if token acquired, False if rate limit exceeded
        """
        async with self._lock:
            self._refill()
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

    async def wait_if_needed(self) -> None:
        """Wait until a token is available (blocking)."""
        while not await self.acquire():
            # Calculate wait time based on token refill rate
            wait_time = self.window_seconds / self.max_requests
            await asyncio.sleep(wait_time)

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_update

        # Calculate tokens to add based on elapsed time
        tokens_to_add = (elapsed / self.window_seconds) * self.max_requests
        self.tokens = min(self.max_requests, self.tokens + tokens_to_add)
        self.last_update = now


class CircuitBreaker:
    """Circuit breaker for external API calls.

    Prevents cascading failures by temporarily blocking requests after failures:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Too many failures, requests immediately fail
    - HALF_OPEN: Testing recovery, limited requests allowed

    State transitions:
    - CLOSED -> OPEN: After failure_threshold consecutive failures
    - OPEN -> HALF_OPEN: After recovery_timeout seconds
    - HALF_OPEN -> CLOSED: After success_threshold consecutive successes
    - HALF_OPEN -> OPEN: After any failure

    Example:
        >>> breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=60.0)
        >>> result = await breaker.call(api_function, arg1, arg2)
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        success_threshold: int = 2,
    ):
        """Initialize circuit breaker.

        Args:
            failure_threshold: Failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
            success_threshold: Successes needed to close circuit from half-open
        """
        if failure_threshold <= 0:
            raise ValueError("failure_threshold must be positive")
        if recovery_timeout <= 0:
            raise ValueError("recovery_timeout must be positive")
        if success_threshold <= 0:
            raise ValueError("success_threshold must be positive")

        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold

        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: float | None = None
        self._lock = asyncio.Lock()

    async def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute function with circuit breaker protection.

        Args:
            func: Async function to call
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Result from function

        Raises:
            RuntimeError: If circuit is OPEN
            Exception: Any exception from the called function
        """
        async with self._lock:
            # Check if we should attempt recovery
            if self.state == CircuitBreakerState.OPEN:
                if self._should_attempt_recovery():
                    self.state = CircuitBreakerState.HALF_OPEN
                    self.success_count = 0
                else:
                    raise RuntimeError(
                        f"Circuit breaker is OPEN. "
                        f"Recovery attempt in {self._time_until_recovery():.1f}s"
                    )

        # Execute the function
        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except Exception:
            await self._on_failure()
            raise

    async def _on_success(self) -> None:
        """Handle successful call."""
        async with self._lock:
            if self.state == CircuitBreakerState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= self.success_threshold:
                    # Recovery successful
                    self.state = CircuitBreakerState.CLOSED
                    self.failure_count = 0
                    self.success_count = 0
            elif self.state == CircuitBreakerState.CLOSED:
                # Reset failure count on success
                self.failure_count = 0

    async def _on_failure(self) -> None:
        """Handle failed call."""
        async with self._lock:
            self.last_failure_time = time.monotonic()

            if self.state == CircuitBreakerState.HALF_OPEN:
                # Failed during recovery, reopen circuit
                self.state = CircuitBreakerState.OPEN
                self.failure_count = 0
                self.success_count = 0
            else:
                self.failure_count += 1
                if self.failure_count >= self.failure_threshold:
                    # Too many failures, open circuit
                    self.state = CircuitBreakerState.OPEN

    def _should_attempt_recovery(self) -> bool:
        """Check if enough time has passed to attempt recovery."""
        if self.last_failure_time is None:
            return True
        elapsed = time.monotonic() - self.last_failure_time
        return elapsed >= self.recovery_timeout

    def _time_until_recovery(self) -> float:
        """Calculate time until recovery attempt."""
        if self.last_failure_time is None:
            return 0.0
        elapsed = time.monotonic() - self.last_failure_time
        return max(0.0, self.recovery_timeout - elapsed)

    async def get_state(self) -> CircuitBreakerState:
        """Get current circuit breaker state."""
        async with self._lock:
            return self.state


class ExternalBridge(ABC):
    """Abstract base class for external git hosting bridges.

    Concrete implementations must provide:
    - connect: Authenticate and establish connection
    - disconnect: Clean up resources
    - sync_sessions: Push TMWS sessions to external platform
    - search_issues: Search for issues/discussions
    - push_memory_snapshot: Create issue/wiki page from sessions

    All implementations should:
    - Use rate limiting to respect API limits
    - Use circuit breaker to handle failures gracefully
    - Validate all inputs for security
    - Never log tokens or sensitive data
    - Enforce timeouts on all network requests
    """

    def __init__(self, config: BridgeConfig):
        """Initialize bridge with configuration.

        Args:
            config: Bridge configuration (validated)
        """
        self.config = config
        self.rate_limiter = RateLimiter(
            max_requests=60,  # Default: 60 requests per minute
            window_seconds=60.0,
        )
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60.0,
            success_threshold=2,
        )
        self._connected = False

    @abstractmethod
    async def connect(self, credentials: dict[str, str]) -> bool:
        """Establish connection to external platform.

        Security:
        - Validate credentials format
        - Never log credential values
        - Enforce timeout on authentication requests

        Args:
            credentials: Platform-specific credentials

        Returns:
            True if connected successfully

        Raises:
            SecurityError: If credentials are invalid
            RuntimeError: If connection fails
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect and clean up resources.

        Should be called when bridge is no longer needed.
        Idempotent - safe to call multiple times.
        """
        pass

    @abstractmethod
    async def sync_sessions(
        self, since: datetime
    ) -> list[SessionSnapshot]:
        """Sync TMWS sessions from external platform.

        Args:
            since: Only sync sessions after this timestamp

        Returns:
            List of session snapshots

        Raises:
            RuntimeError: If not connected or sync fails
        """
        pass

    @abstractmethod
    async def search_issues(
        self, query: str, limit: int = 10
    ) -> list[IssueResult]:
        """Search for issues/discussions on external platform.

        Security:
        - Query is sanitized to prevent injection
        - Limit is enforced to prevent resource exhaustion

        Args:
            query: Search query (will be sanitized)
            limit: Maximum results (1-100)

        Returns:
            List of matching issues

        Raises:
            SecurityError: If query is invalid
            RuntimeError: If not connected or search fails
        """
        pass

    @abstractmethod
    async def push_memory_snapshot(
        self, sessions: list[SessionSnapshot]
    ) -> str:
        """Push memory snapshot to external platform.

        Creates an issue or wiki page containing session summaries.

        Args:
            sessions: Sessions to include in snapshot

        Returns:
            URL of created resource

        Raises:
            RuntimeError: If not connected or push fails
        """
        pass

    def is_connected(self) -> bool:
        """Check if bridge is connected."""
        return self._connected
