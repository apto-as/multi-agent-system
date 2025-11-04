"""
Security Monitoring System (TMWS v2.3.0 Phase 1C Part 4)

Monitors security events, triggers alerts, and provides security metrics.

Features:
- Real-time security event tracking
- Configurable alert thresholds
- Alert management (acknowledge, resolve)
- Security metrics and dashboard data
- Agent-specific security profiles
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

logger = logging.getLogger(__name__)


class AlertLevel(str, Enum):
    """Alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityEvent:
    """Represents a security-related event."""

    id: UUID = field(default_factory=uuid4)
    event_type: str = ""
    agent_id: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    severity: str = "low"
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityAlert:
    """Represents a security alert."""

    id: UUID = field(default_factory=uuid4)
    event_type: str = ""
    agent_id: str = ""
    level: AlertLevel = AlertLevel.LOW
    message: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False
    acknowledged_by: str | None = None
    acknowledged_at: datetime | None = None
    resolved: bool = False
    resolved_by: str | None = None
    resolved_at: datetime | None = None
    resolution_notes: str | None = None


@dataclass
class AlertThresholdConfig:
    """Configuration for alert thresholds."""

    event_type: str
    threshold: int
    window: timedelta
    enabled: bool = True


class SecurityMonitor:
    """Security monitoring and alerting system."""

    # Default thresholds
    DEFAULT_THRESHOLDS = {
        "failed_auth": {"threshold": 5, "window": timedelta(minutes=5)},
        "access_denied": {"threshold": 10, "window": timedelta(minutes=1)},
        "rate_limit_exceeded": {"threshold": 20, "window": timedelta(minutes=1)},
        "privilege_escalation_attempt": {"threshold": 1, "window": timedelta(seconds=1)},
    }

    # Severity to alert level mapping
    SEVERITY_TO_ALERT_LEVEL = {
        "low": AlertLevel.LOW,
        "medium": AlertLevel.MEDIUM,
        "high": AlertLevel.HIGH,
        "critical": AlertLevel.CRITICAL,
    }

    def __init__(self):
        """Initialize security monitor."""
        self._events: list[SecurityEvent] = []
        self._alerts: dict[UUID, SecurityAlert] = {}
        self._thresholds: dict[str, AlertThresholdConfig] = {}

        # Initialize default thresholds
        for event_type, config in self.DEFAULT_THRESHOLDS.items():
            self._thresholds[event_type] = AlertThresholdConfig(
                event_type=event_type,
                threshold=config["threshold"],
                window=config["window"],
            )

    async def record_event(
        self,
        event_type: str,
        agent_id: str,
        severity: str = "low",
        **context: Any,
    ) -> SecurityEvent:
        """Record a security event.

        Args:
            event_type: Type of security event
            agent_id: Agent ID associated with the event
            severity: Event severity (low, medium, high, critical)
            **context: Additional event context

        Returns:
            The recorded SecurityEvent
        """
        # Create event
        event = SecurityEvent(
            event_type=event_type,
            agent_id=agent_id,
            severity=severity,
            context=context,
        )

        # Store event
        self._events.append(event)

        # Check if alert should be triggered
        await self._check_alert_threshold(event)

        # Log event
        logger.info(
            f"security_event_recorded",
            extra={
                "event_id": str(event.id),
                "event_type": event_type,
                "agent_id": agent_id,
                "severity": severity,
            },
        )

        return event

    async def _check_alert_threshold(self, event: SecurityEvent) -> None:
        """Check if event should trigger an alert based on thresholds.

        Args:
            event: The security event to check
        """
        event_type = event.event_type

        # Get threshold configuration
        threshold_config = self._thresholds.get(event_type)
        if not threshold_config or not threshold_config.enabled:
            return

        # Count recent events of this type
        now = datetime.now(timezone.utc)
        cutoff_time = now - threshold_config.window
        recent_events = [
            e
            for e in self._events
            if e.event_type == event_type
            and e.agent_id == event.agent_id
            and e.timestamp >= cutoff_time
        ]

        # Trigger alert if threshold exceeded
        if len(recent_events) >= threshold_config.threshold:
            await self._create_alert(event, len(recent_events))

    async def _create_alert(self, event: SecurityEvent, event_count: int) -> SecurityAlert:
        """Create a security alert.

        Args:
            event: The triggering security event
            event_count: Number of similar events

        Returns:
            The created SecurityAlert
        """
        # Map severity to alert level, but escalate for threshold violations
        base_level = self.SEVERITY_TO_ALERT_LEVEL.get(event.severity, AlertLevel.LOW)

        # Escalate alert level based on threshold violation
        if base_level == AlertLevel.MEDIUM:
            alert_level = AlertLevel.HIGH  # Escalate to HIGH
        elif base_level == AlertLevel.LOW:
            alert_level = AlertLevel.MEDIUM  # Escalate to MEDIUM
        else:
            alert_level = base_level  # Keep HIGH/CRITICAL as is

        # Create alert message
        message = f"{event_count} {event.event_type} events detected for agent {event.agent_id}"

        # Create alert
        alert = SecurityAlert(
            event_type=event.event_type,
            agent_id=event.agent_id,
            level=alert_level,
            message=message,
            context=event.context.copy(),
        )

        # Store alert
        self._alerts[alert.id] = alert

        # Log alert creation
        logger.warning(
            f"security_alert_triggered",
            extra={
                "alert_id": str(alert.id),
                "alert_level": alert.level.value,
                "event_type": event.event_type,
                "agent_id": event.agent_id,
                "event_count": event_count,
            },
        )

        return alert

    def get_metrics(self, time_window: timedelta | None = None) -> dict[str, Any]:
        """Get security metrics.

        Args:
            time_window: Optional time window to filter events

        Returns:
            Dictionary of security metrics
        """
        # Filter events by time window
        if time_window:
            cutoff_time = datetime.now(timezone.utc) - time_window
            events = [e for e in self._events if e.timestamp >= cutoff_time]
        else:
            events = self._events

        # Calculate metrics
        metrics = {
            "total_events": len(events),
            "failed_auth_count": len([e for e in events if e.event_type == "failed_auth"]),
            "rate_limit_violations": len(
                [e for e in events if e.event_type == "rate_limit_exceeded"]
            ),
            "access_denials": len([e for e in events if e.event_type == "access_denied"]),
            "failed_auth_by_agent": defaultdict(int),
            "events_by_type": defaultdict(int),
            "events_by_severity": defaultdict(int),
        }

        # Count by agent and type
        for event in events:
            if event.event_type == "failed_auth":
                metrics["failed_auth_by_agent"][event.agent_id] += 1
            metrics["events_by_type"][event.event_type] += 1
            metrics["events_by_severity"][event.severity] += 1

        return metrics

    def get_active_alerts(self) -> list[SecurityAlert]:
        """Get all active (unresolved) alerts.

        Returns:
            List of active SecurityAlert objects
        """
        return [alert for alert in self._alerts.values() if not alert.resolved]

    def get_alert_by_id(self, alert_id: UUID) -> SecurityAlert | None:
        """Get alert by ID.

        Args:
            alert_id: Alert UUID

        Returns:
            SecurityAlert if found, None otherwise
        """
        return self._alerts.get(alert_id)

    async def acknowledge_alert(
        self,
        alert_id: UUID,
        acknowledged_by: str,
    ) -> SecurityAlert | None:
        """Acknowledge an alert.

        Args:
            alert_id: Alert UUID
            acknowledged_by: User/agent who acknowledged

        Returns:
            Updated SecurityAlert if found, None otherwise
        """
        alert = self._alerts.get(alert_id)
        if not alert:
            return None

        alert.acknowledged = True
        alert.acknowledged_by = acknowledged_by
        alert.acknowledged_at = datetime.now(timezone.utc)

        logger.info(
            "security_alert_acknowledged",
            extra={
                "alert_id": str(alert_id),
                "acknowledged_by": acknowledged_by,
            },
        )

        return alert

    async def resolve_alert(
        self,
        alert_id: UUID,
        resolved_by: str,
        resolution_notes: str | None = None,
    ) -> SecurityAlert | None:
        """Resolve an alert.

        Args:
            alert_id: Alert UUID
            resolved_by: User/agent who resolved
            resolution_notes: Optional resolution notes

        Returns:
            Updated SecurityAlert if found, None otherwise
        """
        alert = self._alerts.get(alert_id)
        if not alert:
            return None

        alert.resolved = True
        alert.resolved_by = resolved_by
        alert.resolved_at = datetime.now(timezone.utc)
        alert.resolution_notes = resolution_notes

        logger.info(
            "security_alert_resolved",
            extra={
                "alert_id": str(alert_id),
                "resolved_by": resolved_by,
            },
        )

        return alert

    def get_alert_history(self, limit: int = 100) -> list[SecurityAlert]:
        """Get alert history.

        Args:
            limit: Maximum number of alerts to return

        Returns:
            List of SecurityAlert objects, most recent first
        """
        alerts = sorted(self._alerts.values(), key=lambda a: a.created_at, reverse=True)
        return alerts[:limit]

    def get_security_summary(self) -> dict[str, Any]:
        """Get security summary for monitoring dashboard.

        Returns:
            Dictionary with security summary data
        """
        metrics = self.get_metrics()

        summary = {
            "total_events": metrics["total_events"],
            "events_by_type": dict(metrics["events_by_type"]),
            "events_by_severity": dict(metrics["events_by_severity"]),
            "active_alerts_count": len(self.get_active_alerts()),
            "total_alerts": len(self._alerts),
            "critical_alerts": len(
                [a for a in self._alerts.values() if a.level == AlertLevel.CRITICAL]
            ),
        }

        return summary

    def get_agent_security_profile(self, agent_id: str) -> dict[str, Any]:
        """Get security profile for specific agent.

        Args:
            agent_id: Agent ID

        Returns:
            Dictionary with agent security profile
        """
        # Filter events for this agent
        agent_events = [e for e in self._events if e.agent_id == agent_id]

        # Count events by type
        events_by_type = defaultdict(int)
        for event in agent_events:
            events_by_type[event.event_type] += 1

        # Calculate risk score (simple heuristic)
        risk_score = 0
        risk_score += events_by_type.get("failed_auth", 0) * 2
        risk_score += events_by_type.get("access_denied", 0) * 3
        risk_score += events_by_type.get("privilege_escalation_attempt", 0) * 10

        profile = {
            "agent_id": agent_id,
            "total_events": len(agent_events),
            "events_by_type": dict(events_by_type),
            "risk_score": risk_score,
            "recent_alerts": [
                a for a in self._alerts.values() if a.agent_id == agent_id and not a.resolved
            ],
        }

        return profile

    def set_alert_threshold(
        self,
        event_type: str,
        threshold: int,
        window: timedelta,
    ) -> None:
        """Set custom alert threshold for event type.

        Args:
            event_type: Type of security event
            threshold: Number of events to trigger alert
            window: Time window for counting events
        """
        self._thresholds[event_type] = AlertThresholdConfig(
            event_type=event_type,
            threshold=threshold,
            window=window,
        )

        logger.info(
            "alert_threshold_configured",
            extra={
                "event_type": event_type,
                "threshold": threshold,
                "window_seconds": window.total_seconds(),
            },
        )

    def disable_alert_threshold(self, event_type: str) -> None:
        """Disable alerts for specific event type.

        Args:
            event_type: Type of security event
        """
        if event_type in self._thresholds:
            self._thresholds[event_type].enabled = False

        logger.info(
            "alert_threshold_disabled",
            extra={"event_type": event_type},
        )

    def reset_threshold_to_default(self, event_type: str) -> None:
        """Reset alert threshold to default value.

        Args:
            event_type: Type of security event
        """
        if event_type in self.DEFAULT_THRESHOLDS:
            config = self.DEFAULT_THRESHOLDS[event_type]
            self._thresholds[event_type] = AlertThresholdConfig(
                event_type=event_type,
                threshold=config["threshold"],
                window=config["window"],
            )

            logger.info(
                "alert_threshold_reset_to_default",
                extra={"event_type": event_type},
            )

    def get_threshold_config(self, event_type: str) -> dict[str, Any] | None:
        """Get threshold configuration for event type.

        Args:
            event_type: Type of security event

        Returns:
            Dictionary with threshold configuration
        """
        config = self._thresholds.get(event_type)
        if not config:
            return None

        return {
            "event_type": config.event_type,
            "threshold": config.threshold,
            "window": config.window,
            "enabled": config.enabled,
        }

    def get_recent_events(self, limit: int = 100) -> list[SecurityEvent]:
        """Get recent security events.

        Args:
            limit: Maximum number of events to return

        Returns:
            List of SecurityEvent objects, most recent first
        """
        events = sorted(self._events, key=lambda e: e.timestamp, reverse=True)
        return events[:limit]
