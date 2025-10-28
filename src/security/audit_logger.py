"""Synchronous Security Audit Logger - Thin Wrapper
This is a lightweight wrapper around AsyncSecurityAuditLogger for synchronous contexts.

For new code, prefer using audit_logger_async.AsyncSecurityAuditLogger directly.
This wrapper exists for backward compatibility with synchronous services.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any

from fastapi import Request

from ..models.audit_log import SecurityEventSeverity, SecurityEventType
from .audit_logger_async import AsyncSecurityAuditLogger
from .audit_logger_async import get_audit_logger as get_async_audit_logger
from .security_event import SecurityEvent

logger = logging.getLogger(__name__)


class SecurityAuditLogger:
    """Synchronous wrapper around AsyncSecurityAuditLogger.

    This class provides a synchronous interface to the async audit logger
    by running async methods in a new event loop. This is primarily for
    backward compatibility with existing synchronous code.

    Note: This wrapper has performance overhead due to event loop creation.
    For new code, use AsyncSecurityAuditLogger directly.
    """

    def __init__(self):
        """Initialize sync wrapper."""
        self._async_logger: AsyncSecurityAuditLogger | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def _get_or_create_loop(self) -> asyncio.AbstractEventLoop:
        """Get or create event loop for sync operations."""
        try:
            # Try to get existing loop
            return asyncio.get_event_loop()
        except RuntimeError:
            # Create new loop if none exists
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop

    def _get_async_logger(self) -> AsyncSecurityAuditLogger:
        """Get or create async logger instance."""
        if self._async_logger is None:
            loop = self._get_or_create_loop()
            self._async_logger = loop.run_until_complete(get_async_audit_logger())
        return self._async_logger

    async def log_event(
        self,
        event_type: SecurityEventType,
        severity: SecurityEventSeverity,
        client_ip: str,
        message: str = None,
        request: Request | None = None,
        user_id: str | None = None,
        session_id: str | None = None,
        details: dict[str, Any] | None = None,
        blocked: bool = False,
    ) -> SecurityEvent:
        """Log a security event (async wrapper for sync context).

        This method can be called with await in async contexts.
        For synchronous contexts, use the synchronous wrapper methods.
        """
        async_logger = self._get_async_logger()
        return await async_logger.log_event(
            event_type=event_type,
            severity=severity,
            client_ip=client_ip,
            message=message,
            request=request,
            user_id=user_id,
            session_id=session_id,
            details=details,
            blocked=blocked,
        )

    def log_event_sync(
        self,
        event_type: SecurityEventType,
        severity: SecurityEventSeverity,
        client_ip: str,
        message: str = None,
        request: Request | None = None,
        user_id: str | None = None,
        session_id: str | None = None,
        details: dict[str, Any] | None = None,
        blocked: bool = False,
    ) -> SecurityEvent:
        """Log a security event synchronously.

        Note: This creates a new event loop for each call, which has performance overhead.
        For better performance, use the async version directly.
        """
        loop = self._get_or_create_loop()
        return loop.run_until_complete(
            self.log_event(
                event_type=event_type,
                severity=severity,
                client_ip=client_ip,
                message=message,
                request=request,
                user_id=user_id,
                session_id=session_id,
                details=details,
                blocked=blocked,
            ),
        )

    async def get_events(
        self,
        limit: int = 100,
        event_type: SecurityEventType | None = None,
        severity: SecurityEventSeverity | None = None,
        client_ip: str | None = None,
        user_id: str | None = None,
        start_time: datetime | None = None,  # noqa: ARG002 - Reserved for future time-based filtering
        end_time: datetime | None = None,  # noqa: ARG002 - Reserved for future time-based filtering
    ) -> list[dict[str, Any]]:
        """Retrieve security events with filtering (async).

        Note: start_time and end_time are reserved for future implementation
        when AsyncSecurityAuditLogger supports time-based filtering.
        """
        async_logger = self._get_async_logger()

        # Map to async method (which supports similar filtering via get_recent_events)
        # For full filtering, we'd need to add a method to AsyncSecurityAuditLogger
        # For now, return recent events and filter client-side if needed
        all_events = await async_logger.get_recent_events(minutes=1440)  # 24 hours

        # Apply filters
        filtered = all_events
        if event_type:
            filtered = [e for e in filtered if e["event_type"] == event_type.value]
        if severity:
            filtered = [e for e in filtered if e["severity"] == severity.value]
        if client_ip:
            filtered = [e for e in filtered if e.get("client_ip") == client_ip]
        if user_id:
            filtered = [e for e in filtered if e.get("user_id") == user_id]

        return filtered[:limit]

    async def get_statistics(self) -> dict[str, Any]:
        """Get security event statistics (async).

        Note: This is a simplified version. The full statistics from the original
        implementation would require adding this method to AsyncSecurityAuditLogger.
        """
        async_logger = self._get_async_logger()

        # Get recent events for basic statistics
        recent_events = await async_logger.get_recent_events(minutes=1440)

        # Calculate basic stats
        total_events = len(recent_events)
        critical_count = sum(1 for e in recent_events if e["severity"] == "critical")

        # Count by severity
        severity_counts = {}
        for event in recent_events:
            severity = event["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Count by type
        type_counts = {}
        for event in recent_events:
            event_type = event["event_type"]
            type_counts[event_type] = type_counts.get(event_type, 0) + 1

        # Top IPs
        ip_counts = {}
        for event in recent_events:
            ip = event.get("client_ip", "unknown")
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        return {
            "total_events": total_events,
            "critical_events_24h": critical_count,
            "events_by_severity": severity_counts,
            "events_by_type": type_counts,
            "top_attacking_ips": dict(
                sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            ),
        }


# Global audit logger instance
_audit_logger: SecurityAuditLogger | None = None


def get_audit_logger() -> SecurityAuditLogger:
    """Get global audit logger instance (synchronous wrapper).

    For new code, prefer using get_async_audit_logger() from audit_logger_async.
    """
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = SecurityAuditLogger()
    return _audit_logger
