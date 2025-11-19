"""
Security Utilities - WK-3, WK-5 Fixes

This module provides security utilities for:
- WK-3: Rate limiting for alert suppression
- WK-5: Constant-time comparison for sensitive operations
- CWE-208: Observable Timing Discrepancy mitigation

Security References:
- WK-3: Alert Suppression Abuse (LOW)
- WK-5: Timing Attack Mitigation (LOW)
- CWE-208: Observable Timing Discrepancy
- CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
"""

import hashlib
import hmac
import time
from collections import deque
from datetime import datetime, timedelta


class AlertRateLimiter:
    """
    Rate limiter for alert suppression to prevent abuse (WK-3).

    Prevents excessive suppression of security alerts by limiting
    how many times alerts can be suppressed per hour.

    Example:
        >>> limiter = AlertRateLimiter(max_suppressions=10, window_seconds=3600)
        >>> if limiter.can_suppress("auth_failure"):
        ...     # Suppress alert
        ...     limiter.record_suppression("auth_failure")
        ... else:
        ...     # Too many suppressions, force alert
        ...     logger.warning("Rate limit exceeded for alert suppression")
    """

    def __init__(
        self,
        max_suppressions: int = 10,
        window_seconds: int = 3600,
    ):
        """
        Initialize rate limiter.

        Args:
            max_suppressions: Maximum suppressions allowed per window (default: 10/hour)
            window_seconds: Time window in seconds (default: 3600 = 1 hour)
        """
        self.max_suppressions = max_suppressions
        self.window_seconds = window_seconds

        # Track suppressions per alert type
        self._suppressions: dict[str, deque[datetime]] = {}

    def can_suppress(self, alert_type: str) -> bool:
        """
        Check if alert can be suppressed without exceeding rate limit.

        Args:
            alert_type: Type of alert to check

        Returns:
            True if suppression is allowed, False if rate limit exceeded
        """
        now = datetime.now()

        # Initialize if first suppression
        if alert_type not in self._suppressions:
            return True

        # Remove old suppressions outside window
        self._clean_old_suppressions(alert_type, now)

        # Check if we're within limit
        return len(self._suppressions[alert_type]) < self.max_suppressions

    def record_suppression(self, alert_type: str) -> None:
        """
        Record an alert suppression.

        Args:
            alert_type: Type of alert being suppressed
        """
        now = datetime.now()

        if alert_type not in self._suppressions:
            self._suppressions[alert_type] = deque()

        self._suppressions[alert_type].append(now)

    def _clean_old_suppressions(self, alert_type: str, now: datetime) -> None:
        """
        Remove suppressions outside the time window.

        Args:
            alert_type: Type of alert to clean
            now: Current timestamp
        """
        if alert_type not in self._suppressions:
            return

        cutoff = now - timedelta(seconds=self.window_seconds)

        # Remove old entries
        while (
            self._suppressions[alert_type]
            and self._suppressions[alert_type][0] < cutoff
        ):
            self._suppressions[alert_type].popleft()

    def get_suppression_count(self, alert_type: str) -> int:
        """
        Get current suppression count for alert type.

        Args:
            alert_type: Type of alert

        Returns:
            Number of suppressions in current window
        """
        if alert_type not in self._suppressions:
            return 0

        now = datetime.now()
        self._clean_old_suppressions(alert_type, now)
        return len(self._suppressions[alert_type])

    def reset(self, alert_type: str | None = None) -> None:
        """
        Reset suppression tracking.

        Args:
            alert_type: Specific alert type to reset, or None for all
        """
        if alert_type:
            if alert_type in self._suppressions:
                self._suppressions[alert_type].clear()
        else:
            self._suppressions.clear()


def constant_time_compare(a: str, b: str) -> bool:
    """
    Constant-time string comparison to prevent timing attacks (WK-5).

    This function compares two strings in constant time to prevent
    timing attacks that could leak information about sensitive data
    (e.g., authentication tokens, API keys).

    Uses HMAC comparison which is implemented in constant time
    by the hmac module.

    Args:
        a: First string to compare
        b: Second string to compare

    Returns:
        True if strings are equal, False otherwise

    Security:
        - Prevents timing attacks (CWE-208)
        - Safe for comparing passwords, tokens, API keys
        - Uses cryptographically secure comparison

    Example:
        >>> token_from_user = "secret_token_123"
        >>> token_from_db = "secret_token_123"
        >>> if constant_time_compare(token_from_user, token_from_db):
        ...     # Tokens match
        ...     pass
    """
    # Convert to bytes for hmac.compare_digest
    a_bytes = a.encode('utf-8') if isinstance(a, str) else a
    b_bytes = b.encode('utf-8') if isinstance(b, str) else b

    # Use hmac.compare_digest for constant-time comparison
    return hmac.compare_digest(a_bytes, b_bytes)


def constant_time_hash_compare(a: str, b_hash: str, algorithm: str = 'sha256') -> bool:
    """
    Constant-time hash comparison (WK-5).

    Computes hash of 'a' and compares with 'b_hash' in constant time.
    Useful when you have a stored hash and want to verify input.

    Args:
        a: Input string to hash and compare
        b_hash: Expected hash (hexadecimal string)
        algorithm: Hash algorithm to use (default: sha256)

    Returns:
        True if hashes match, False otherwise

    Example:
        >>> user_input = "password123"
        >>> stored_hash = "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
        >>> if constant_time_hash_compare(user_input, stored_hash):
        ...     # Password correct
        ...     pass
    """
    # Compute hash of input
    hash_func = getattr(hashlib, algorithm)
    a_hash = hash_func(a.encode('utf-8')).hexdigest()

    # Constant-time compare the hashes
    return constant_time_compare(a_hash, b_hash)


class TimingAttackProtector:
    """
    Protects against timing attacks by adding random delays (WK-5).

    For operations where constant-time comparison isn't possible,
    this class adds random delays to mask timing differences.

    Example:
        >>> protector = TimingAttackProtector(min_delay_ms=50, max_delay_ms=150)
        >>> @protector.protect
        ... def verify_user(username, password):
        ...     # Verification logic
        ...     return is_valid
    """

    def __init__(self, min_delay_ms: int = 50, max_delay_ms: int = 150):
        """
        Initialize timing attack protector.

        Args:
            min_delay_ms: Minimum delay in milliseconds
            max_delay_ms: Maximum delay in milliseconds
        """
        self.min_delay_seconds = min_delay_ms / 1000.0
        self.max_delay_seconds = max_delay_ms / 1000.0

    def protect(self, func):
        """
        Decorator to add random delay to function execution.

        Args:
            func: Function to protect

        Returns:
            Wrapped function with random delay
        """
        import random

        def wrapper(*args, **kwargs):
            # Execute function
            result = func(*args, **kwargs)

            # Add random delay
            delay = random.uniform(self.min_delay_seconds, self.max_delay_seconds)
            time.sleep(delay)

            return result

        return wrapper


# Pre-configured instances for common use cases
alert_rate_limiter = AlertRateLimiter(max_suppressions=10, window_seconds=3600)
timing_protector = TimingAttackProtector(min_delay_ms=50, max_delay_ms=150)
