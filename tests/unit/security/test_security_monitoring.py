"""
Security Monitoring Tests (TMWS v2.3.0 Phase 1C Part 4)

Tests security monitoring and alert system:
- Metrics collection for security events
- Alert triggering for critical security violations
- Threshold-based monitoring
- Alert history and tracking
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from src.security.monitoring.security_monitor import AlertLevel, SecurityMonitor


@pytest.fixture
def security_monitor():
    """Create SecurityMonitor instance for testing."""
    return SecurityMonitor()


class TestSecurityMetricsCollection:
    """Test collection of security-related metrics."""

    @pytest.mark.asyncio
    async def test_record_failed_auth_attempt(self, security_monitor):
        """Test recording failed authentication attempts."""
        # Arrange
        agent_id = "test-agent"
        ip_address = "192.168.1.100"

        # Act
        await security_monitor.record_event(
            event_type="failed_auth",
            agent_id=agent_id,
            ip_address=ip_address,
            severity="medium",
        )

        # Assert
        metrics = security_monitor.get_metrics()
        assert metrics["failed_auth_count"] >= 1
        assert "test-agent" in metrics["failed_auth_by_agent"]

    @pytest.mark.asyncio
    async def test_record_rate_limit_violation(self, security_monitor):
        """Test recording rate limit violations."""
        # Arrange
        agent_id = "test-agent"
        resource = "memory_access"

        # Act
        await security_monitor.record_event(
            event_type="rate_limit_exceeded",
            agent_id=agent_id,
            resource=resource,
            severity="low",
        )

        # Assert
        metrics = security_monitor.get_metrics()
        assert metrics["rate_limit_violations"] >= 1

    @pytest.mark.asyncio
    async def test_record_access_denial(self, security_monitor):
        """Test recording access denials."""
        # Arrange
        agent_id = "test-agent"
        resource_id = str(uuid4())
        reason = "insufficient_permissions"

        # Act
        await security_monitor.record_event(
            event_type="access_denied",
            agent_id=agent_id,
            resource_id=resource_id,
            reason=reason,
            severity="high",
        )

        # Assert
        metrics = security_monitor.get_metrics()
        assert metrics["access_denials"] >= 1

    @pytest.mark.asyncio
    async def test_metrics_time_window(self, security_monitor):
        """Test that metrics are tracked within time windows."""
        # Arrange
        agent_id = "test-agent"

        # Act - Record events
        await security_monitor.record_event(
            event_type="failed_auth",
            agent_id=agent_id,
            severity="medium",
        )

        # Get metrics for last hour
        metrics_1h = security_monitor.get_metrics(time_window=timedelta(hours=1))

        # Get metrics for last day
        metrics_24h = security_monitor.get_metrics(time_window=timedelta(hours=24))

        # Assert
        assert metrics_1h["failed_auth_count"] >= 1
        assert metrics_24h["failed_auth_count"] >= 1


class TestAlertTriggering:
    """Test alert triggering for critical security events."""

    @pytest.mark.asyncio
    async def test_alert_on_multiple_failed_auth(self, security_monitor):
        """Test that alert triggers after threshold failed auth attempts."""
        # Arrange
        agent_id = "test-agent"
        ip_address = "192.168.1.100"
        threshold = 5

        # Configure threshold
        security_monitor.set_alert_threshold("failed_auth", threshold, window=timedelta(minutes=5))

        # Act - Exceed threshold
        for _i in range(threshold + 1):
            await security_monitor.record_event(
                event_type="failed_auth",
                agent_id=agent_id,
                ip_address=ip_address,
                severity="medium",
            )

        # Assert
        alerts = security_monitor.get_active_alerts()
        assert len(alerts) >= 1
        assert any(a.event_type == "failed_auth" for a in alerts)
        assert any(a.level == AlertLevel.HIGH for a in alerts)

    @pytest.mark.asyncio
    async def test_alert_on_access_pattern_anomaly(self, security_monitor):
        """Test alert for unusual access patterns."""
        # Arrange
        agent_id = "test-agent"
        threshold = 10

        # Configure anomaly detection
        security_monitor.set_alert_threshold(
            "access_denied", threshold, window=timedelta(minutes=1)
        )

        # Act - Generate anomalous pattern
        for _i in range(threshold + 1):
            await security_monitor.record_event(
                event_type="access_denied",
                agent_id=agent_id,
                reason="namespace_violation",
                severity="high",
            )

        # Assert
        alerts = security_monitor.get_active_alerts()
        assert len(alerts) >= 1
        assert any(a.event_type == "access_denied" for a in alerts)

    @pytest.mark.asyncio
    async def test_critical_alert_on_privilege_escalation(self, security_monitor):
        """Test critical alert for privilege escalation attempts."""
        # Arrange
        agent_id = "test-agent"

        # Act
        await security_monitor.record_event(
            event_type="privilege_escalation_attempt",
            agent_id=agent_id,
            severity="critical",
        )

        # Assert
        alerts = security_monitor.get_active_alerts()
        assert len(alerts) >= 1
        critical_alerts = [a for a in alerts if a.level == AlertLevel.CRITICAL]
        assert len(critical_alerts) >= 1

    @pytest.mark.asyncio
    async def test_alert_includes_context(self, security_monitor):
        """Test that alerts include relevant context information."""
        # Arrange
        agent_id = "test-agent"
        ip_address = "192.168.1.100"

        # Act
        await security_monitor.record_event(
            event_type="privilege_escalation_attempt",
            agent_id=agent_id,
            ip_address=ip_address,
            target_privilege="admin",
            severity="critical",
        )

        # Assert
        alerts = security_monitor.get_active_alerts()
        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.agent_id == agent_id
        assert alert.context.get("ip_address") == ip_address
        assert alert.context.get("target_privilege") == "admin"


class TestAlertManagement:
    """Test alert history and management."""

    @pytest.mark.asyncio
    async def test_acknowledge_alert(self, security_monitor):
        """Test acknowledging an alert."""
        # Arrange
        await security_monitor.record_event(
            event_type="privilege_escalation_attempt",
            agent_id="test-agent",
            severity="critical",
        )

        alerts = security_monitor.get_active_alerts()
        alert_id = alerts[0].id

        # Act
        await security_monitor.acknowledge_alert(alert_id, acknowledged_by="admin")

        # Assert
        alert = security_monitor.get_alert_by_id(alert_id)
        assert alert.acknowledged is True
        assert alert.acknowledged_by == "admin"
        assert alert.acknowledged_at is not None

    @pytest.mark.asyncio
    async def test_resolve_alert(self, security_monitor):
        """Test resolving an alert."""
        # Arrange
        await security_monitor.record_event(
            event_type="privilege_escalation_attempt",
            agent_id="test-agent",
            severity="critical",
        )

        alerts = security_monitor.get_active_alerts()
        alert_id = alerts[0].id

        # Act
        await security_monitor.resolve_alert(
            alert_id,
            resolved_by="admin",
            resolution_notes="False positive - legitimate admin action",
        )

        # Assert
        alert = security_monitor.get_alert_by_id(alert_id)
        assert alert.resolved is True
        assert alert.resolved_by == "admin"
        assert alert.resolution_notes == "False positive - legitimate admin action"

        # Alert should no longer be active
        active_alerts = security_monitor.get_active_alerts()
        assert alert_id not in [a.id for a in active_alerts]

    @pytest.mark.asyncio
    async def test_alert_history(self, security_monitor):
        """Test retrieving alert history."""
        # Arrange - Create threshold violations for 5 different agents
        for i in range(5):
            agent_id = f"agent-{i}"
            # Trigger threshold for each agent (5 events per agent)
            for _j in range(6):  # 6 events exceeds threshold of 5
                await security_monitor.record_event(
                    event_type="failed_auth",
                    agent_id=agent_id,
                    severity="medium",
                )

        # Act
        history = security_monitor.get_alert_history(limit=10)

        # Assert - Should have at least 5 alerts (one per agent)
        assert len(history) >= 5


class TestMonitoringDashboard:
    """Test monitoring dashboard data retrieval."""

    @pytest.mark.asyncio
    async def test_get_security_summary(self, security_monitor):
        """Test retrieving security summary for dashboard."""
        # Arrange - Generate various events
        await security_monitor.record_event(
            event_type="failed_auth",
            agent_id="agent-1",
            severity="medium",
        )
        await security_monitor.record_event(
            event_type="access_denied",
            agent_id="agent-2",
            severity="high",
        )
        await security_monitor.record_event(
            event_type="rate_limit_exceeded",
            agent_id="agent-1",
            severity="low",
        )

        # Act
        summary = security_monitor.get_security_summary()

        # Assert
        assert "total_events" in summary
        assert "events_by_type" in summary
        assert "events_by_severity" in summary
        assert "active_alerts_count" in summary
        assert summary["total_events"] >= 3

    @pytest.mark.asyncio
    async def test_get_agent_security_profile(self, security_monitor):
        """Test retrieving security profile for specific agent."""
        # Arrange
        agent_id = "test-agent"

        # Generate events for agent
        for _i in range(3):
            await security_monitor.record_event(
                event_type="failed_auth",
                agent_id=agent_id,
                severity="medium",
            )

        # Act
        profile = security_monitor.get_agent_security_profile(agent_id)

        # Assert
        assert profile["agent_id"] == agent_id
        assert profile["total_events"] >= 3
        assert "failed_auth" in profile["events_by_type"]
        assert profile["risk_score"] > 0


class TestAlertThresholds:
    """Test configurable alert thresholds."""

    @pytest.mark.asyncio
    async def test_set_custom_threshold(self, security_monitor):
        """Test setting custom alert threshold."""
        # Act
        security_monitor.set_alert_threshold(
            event_type="failed_auth",
            threshold=10,
            window=timedelta(minutes=5),
        )

        # Assert
        config = security_monitor.get_threshold_config("failed_auth")
        assert config["threshold"] == 10
        assert config["window"] == timedelta(minutes=5)

    @pytest.mark.asyncio
    async def test_disable_alert_threshold(self, security_monitor):
        """Test disabling alert for specific event type."""
        # Act
        security_monitor.disable_alert_threshold("rate_limit_exceeded")

        # Generate events that would normally trigger alert
        for _i in range(20):
            await security_monitor.record_event(
                event_type="rate_limit_exceeded",
                agent_id="test-agent",
                severity="low",
            )

        # Assert - No alerts should be triggered
        alerts = security_monitor.get_active_alerts()
        rate_limit_alerts = [a for a in alerts if a.event_type == "rate_limit_exceeded"]
        assert len(rate_limit_alerts) == 0

    @pytest.mark.asyncio
    async def test_reset_threshold_to_default(self, security_monitor):
        """Test resetting threshold to default value."""
        # Arrange
        security_monitor.set_alert_threshold(
            "failed_auth", threshold=100, window=timedelta(hours=1)
        )

        # Act
        security_monitor.reset_threshold_to_default("failed_auth")

        # Assert
        config = security_monitor.get_threshold_config("failed_auth")
        assert config["threshold"] == 5  # Default value
        assert config["window"] == timedelta(minutes=5)  # Default window


class TestSecurityEventTracking:
    """Test detailed security event tracking."""

    @pytest.mark.asyncio
    async def test_event_includes_timestamp(self, security_monitor):
        """Test that recorded events include timestamp."""
        # Act
        before = datetime.now(timezone.utc)
        await security_monitor.record_event(
            event_type="failed_auth",
            agent_id="test-agent",
            severity="medium",
        )
        after = datetime.now(timezone.utc)

        # Assert
        events = security_monitor.get_recent_events(limit=1)
        assert len(events) >= 1
        event = events[0]
        assert before <= event.timestamp <= after

    @pytest.mark.asyncio
    async def test_event_includes_metadata(self, security_monitor):
        """Test that events can include arbitrary metadata."""
        # Arrange
        metadata = {
            "request_id": str(uuid4()),
            "user_agent": "TestClient/1.0",
            "endpoint": "/api/memories",
        }

        # Act
        await security_monitor.record_event(
            event_type="access_denied",
            agent_id="test-agent",
            severity="high",
            **metadata,
        )

        # Assert
        events = security_monitor.get_recent_events(limit=1)
        event = events[0]
        assert event.context["request_id"] == metadata["request_id"]
        assert event.context["user_agent"] == metadata["user_agent"]
        assert event.context["endpoint"] == metadata["endpoint"]
