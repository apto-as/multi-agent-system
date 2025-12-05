"""Response Size Limits for MCP Hub.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 2.2 - Input/Output Controls
Requirements:
- S-P0-6: Response Size Limits (10MB)
- S-P0-7: Timeout Enforcement (30s)

Security Properties:
- Maximum response size enforcement (default: 10MB)
- Prevents memory exhaustion attacks
- Prevents DoS via large payloads

Usage:
    >>> limiter = ResponseLimiter()
    >>> limiter.check_size(response_data)
    >>> # Or use the convenience function
    >>> check_response_size(response_data)

Author: Artemis (Implementation) + Hestia (Security Review)
Created: 2025-12-05
"""

import json
import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


class ResponseLimitError(Exception):
    """Response limit exceeded error.

    Raised when response size exceeds configured limit.
    """

    def __init__(
        self,
        message: str,
        size_bytes: int | None = None,
        limit_bytes: int | None = None,
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.size_bytes = size_bytes
        self.limit_bytes = limit_bytes
        self.details = details or {}


@dataclass
class ResponseLimiter:
    """Response size limiter for MCP Hub.

    Security Features:
    - Maximum response size enforcement
    - JSON serialization size calculation
    - Configurable limits per tool/server

    Configuration:
    - max_response_bytes: Maximum response size in bytes (default: 10MB)
    - warn_threshold_percent: Threshold for warning logs (default: 80%)
    """

    # Default: 10MB maximum response
    DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024

    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    warn_threshold_percent: float = 0.8

    def check_size(
        self,
        response: dict[str, Any] | bytes | str,
        server_id: str | None = None,
        tool_name: str | None = None,
    ) -> int:
        """Check response size against limit.

        Args:
            response: Response data to check
            server_id: Optional server identifier for logging
            tool_name: Optional tool name for logging

        Returns:
            Size of response in bytes

        Raises:
            ResponseLimitError: If response exceeds limit
        """
        # Calculate size
        if isinstance(response, bytes):
            size_bytes = len(response)
        elif isinstance(response, str):
            size_bytes = len(response.encode("utf-8"))
        else:
            # Serialize to JSON to get accurate size
            try:
                serialized = json.dumps(response, default=str)
                size_bytes = len(serialized.encode("utf-8"))
            except (TypeError, ValueError) as e:
                logger.warning(f"Failed to serialize response for size check: {e}")
                # Estimate size using repr
                size_bytes = len(repr(response).encode("utf-8"))

        # Check against limit
        if size_bytes > self.max_response_bytes:
            context = f"{server_id}:{tool_name}" if server_id and tool_name else "unknown"
            raise ResponseLimitError(
                f"Response size ({self._format_bytes(size_bytes)}) exceeds "
                f"limit ({self._format_bytes(self.max_response_bytes)}) "
                f"for {context}",
                size_bytes=size_bytes,
                limit_bytes=self.max_response_bytes,
                details={
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "size_bytes": size_bytes,
                    "limit_bytes": self.max_response_bytes,
                },
            )

        # Log warning if approaching limit
        if size_bytes > self.max_response_bytes * self.warn_threshold_percent:
            context = f"{server_id}:{tool_name}" if server_id and tool_name else "unknown"
            logger.warning(
                f"Response size ({self._format_bytes(size_bytes)}) approaching "
                f"limit ({self._format_bytes(self.max_response_bytes)}) "
                f"for {context}"
            )

        return size_bytes

    def truncate_response(
        self,
        response: dict[str, Any],
        max_bytes: int | None = None,
    ) -> dict[str, Any]:
        """Truncate response to fit within limit.

        Note: This is a best-effort truncation. Complex nested structures
        may not truncate cleanly.

        Args:
            response: Response to truncate
            max_bytes: Maximum size (uses configured limit if None)

        Returns:
            Truncated response with metadata
        """
        if max_bytes is None:
            max_bytes = self.max_response_bytes

        try:
            serialized = json.dumps(response, default=str)
            size_bytes = len(serialized.encode("utf-8"))
        except (TypeError, ValueError):
            return {
                "error": "Response could not be serialized",
                "truncated": True,
            }

        if size_bytes <= max_bytes:
            return response

        # Calculate truncation percentage
        truncation_factor = max_bytes / size_bytes

        # Create truncated response
        return {
            "data": self._truncate_dict(response, truncation_factor),
            "truncated": True,
            "original_size_bytes": size_bytes,
            "truncated_size_bytes": max_bytes,
            "truncation_message": (
                f"Response truncated from {self._format_bytes(size_bytes)} "
                f"to {self._format_bytes(max_bytes)}"
            ),
        }

    def _truncate_dict(
        self,
        data: dict[str, Any],
        factor: float,
    ) -> dict[str, Any]:
        """Truncate dictionary values proportionally.

        Args:
            data: Dictionary to truncate
            factor: Truncation factor (0.0 to 1.0)

        Returns:
            Truncated dictionary
        """
        result = {}
        for key, value in data.items():
            if isinstance(value, str) and len(value) > 100:
                # Truncate long strings
                max_len = max(int(len(value) * factor), 100)
                result[key] = value[:max_len] + f"... (truncated, {len(value)} chars)"
            elif isinstance(value, list) and len(value) > 10:
                # Truncate long arrays
                max_items = max(int(len(value) * factor), 10)
                result[key] = value[:max_items]
                result[f"{key}_truncated_count"] = len(value) - max_items
            elif isinstance(value, dict):
                result[key] = self._truncate_dict(value, factor)
            else:
                result[key] = value
        return result

    @staticmethod
    def _format_bytes(size_bytes: int) -> str:
        """Format bytes as human-readable string.

        Args:
            size_bytes: Size in bytes

        Returns:
            Human-readable size string
        """
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes / (1024 * 1024):.1f} MB"


# Singleton instance
_limiter: ResponseLimiter | None = None


def get_response_limiter() -> ResponseLimiter:
    """Get singleton ResponseLimiter instance.

    Returns:
        ResponseLimiter instance
    """
    global _limiter
    if _limiter is None:
        _limiter = ResponseLimiter()
    return _limiter


def check_response_size(
    response: dict[str, Any] | bytes | str,
    server_id: str | None = None,
    tool_name: str | None = None,
) -> int:
    """Check response size against limit.

    Convenience function using singleton limiter.

    Args:
        response: Response data to check
        server_id: Optional server identifier
        tool_name: Optional tool name

    Returns:
        Size of response in bytes

    Raises:
        ResponseLimitError: If response exceeds limit
    """
    limiter = get_response_limiter()
    return limiter.check_size(response, server_id, tool_name)
