#!/usr/bin/env python3
"""
rate_limiter.py - Thread-safe Rate Limiter for DoS Protection
==============================================================

Implements sliding window rate limiting with O(1) amortized complexity.

Target: 100 calls/60 seconds
Algorithm: Sliding window with deque
Memory: O(max_calls) = ~800 bytes
"""

from collections import deque
from datetime import datetime, timedelta
from threading import Lock
from typing import Optional


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded"""

    def __init__(
        self,
        max_calls: int,
        window_seconds: int,
        retry_after: int,
        operation_id: Optional[str] = None
    ):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self.retry_after = retry_after
        self.operation_id = operation_id

        message = (
            f"Rate limit exceeded: {max_calls} calls/{window_seconds}s. "
            f"Retry after {retry_after}s"
        )
        if operation_id:
            message += f" (operation: {operation_id})"

        super().__init__(message)


class ThreadSafeRateLimiter:
    """
    Thread-safe rate limiter for DoS protection

    Algorithm: Sliding window with deque
    Complexity: O(1) amortized for check()
    Memory: O(max_calls) = O(100) = 800 bytes

    Example:
        limiter = ThreadSafeRateLimiter(max_calls=100, window_seconds=60)

        try:
            limiter.check(operation_id="user_prompt_submit")
            # Proceed with operation
        except RateLimitExceeded as e:
            # Handle rate limit
            print(f"Rate limited. Retry after {e.retry_after}s")
    """

    def __init__(
        self,
        max_calls: int = 100,
        window_seconds: int = 60,
        burst_size: int = 10
    ):
        """
        Initialize rate limiter

        Args:
            max_calls: Maximum calls allowed in window
            window_seconds: Time window in seconds
            burst_size: Allow short bursts (not implemented yet)
        """
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self.burst_size = burst_size

        # Deque for O(1) popleft
        self.calls: deque[datetime] = deque(maxlen=max_calls)

        # Lock for thread safety
        self._lock = Lock()

        # Metrics
        self.total_calls = 0
        self.rejected_calls = 0

    def check(self, operation_id: Optional[str] = None) -> bool:
        """
        Check if call is allowed under rate limit

        Args:
            operation_id: Optional operation identifier for logging

        Returns:
            True if allowed

        Raises:
            RateLimitExceeded: If limit exceeded
        """
        with self._lock:
            now = datetime.now()
            cutoff = now - timedelta(seconds=self.window_seconds)

            # Remove expired calls (O(k) where k = expired calls)
            while self.calls and self.calls[0] < cutoff:
                self.calls.popleft()

            # Check limit
            if len(self.calls) >= self.max_calls:
                self.rejected_calls += 1
                oldest = self.calls[0]
                retry_after = (oldest + timedelta(seconds=self.window_seconds) - now).total_seconds()

                raise RateLimitExceeded(
                    max_calls=self.max_calls,
                    window_seconds=self.window_seconds,
                    retry_after=int(retry_after) + 1,
                    operation_id=operation_id
                )

            # Allow call
            self.calls.append(now)
            self.total_calls += 1
            return True

    def get_stats(self) -> dict:
        """
        Get rate limiter statistics

        Returns:
            dict: Statistics with total_calls, rejected_calls, etc.
        """
        with self._lock:
            return {
                "total_calls": self.total_calls,
                "rejected_calls": self.rejected_calls,
                "current_window_calls": len(self.calls),
                "rejection_rate": self.rejected_calls / max(self.total_calls, 1) if self.total_calls > 0 else 0.0
            }

    def reset(self) -> None:
        """Reset rate limiter state (for testing)"""
        with self._lock:
            self.calls.clear()
            self.total_calls = 0
            self.rejected_calls = 0
