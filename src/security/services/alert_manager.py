"""
Alert Manager Service for Security Audit System.

This service handles security alert notifications.
Extracted from AsyncSecurityAuditLogger as part of Phase 4.2 refactoring.
"""

import logging
from datetime import datetime
from typing import Any

from src.core.config import Settings

logger = logging.getLogger(__name__)


class AlertManager:
    """
    Service for security alert management.

    Responsibilities:
    - Check if events meet alert conditions
    - Send alerts via configured channels
    - Prevent alert spam
    """

    def __init__(self, settings: Settings):
        """
        Initialize alert manager.

        Args:
            settings: Application settings (for alert configuration)
        """
        self.settings = settings

        # Alert thresholds
        self.risk_score_threshold = 80
        self.brute_force_threshold = 5

        # Alert history (simple in-memory tracking)
        # TODO: Move to Redis/database for distributed systems
        self.recent_alerts: dict[str, datetime] = {}
        self.alert_cooldown = 60  # seconds

    async def check_and_notify(
        self,
        event_type: str,
        risk_score: int,
        event_data: dict[str, Any],
        brute_force_info: dict[str, Any] | None = None,
    ) -> bool:
        """
        Check if alert is needed and send if conditions are met.

        Alert conditions:
        1. CRITICAL severity events
        2. High risk score (>= 80)
        3. Brute force detection

        Args:
            event_type: Type of security event
            risk_score: Calculated risk score (0-100)
            event_data: Event details dict
            brute_force_info: Optional brute force detection results

        Returns:
            True if alert was sent, False otherwise
        """
        alert_reason = None

        # Condition 1: CRITICAL severity
        severity = event_data.get("severity", "LOW")
        if severity == "CRITICAL":
            alert_reason = "CRITICAL SECURITY EVENT"

        # Condition 2: High risk score
        elif risk_score >= self.risk_score_threshold:
            alert_reason = "HIGH RISK EVENT DETECTED"

        # Condition 3: Brute force detection
        elif brute_force_info and brute_force_info.get("is_brute_force"):
            alert_reason = "BRUTE FORCE ATTACK DETECTED"

        # Send alert if conditions met
        if alert_reason:
            await self._send_alert(
                alert_reason=alert_reason,
                event_type=event_type,
                event_data=event_data,
                risk_score=risk_score,
                brute_force_info=brute_force_info,
            )
            return True

        return False

    async def _send_alert(
        self,
        alert_reason: str,
        event_type: str,
        event_data: dict[str, Any],
        risk_score: int,
        brute_force_info: dict[str, Any] | None = None,
    ) -> None:
        """
        Send security alert.

        Currently logs to critical logger. Future enhancements:
        - Email notifications
        - Slack/Discord webhooks
        - PagerDuty integration
        - SMS alerts

        Args:
            alert_reason: Reason for alert (e.g., "CRITICAL SECURITY EVENT")
            event_type: Type of security event
            event_data: Event details dict
            risk_score: Risk score
            brute_force_info: Optional brute force detection results
        """
        # Check alert cooldown to prevent spam
        alert_key = f"{event_type}:{event_data.get('client_ip', 'unknown')}"
        if self._is_in_cooldown(alert_key):
            logger.debug(
                f"Alert suppressed (cooldown active): {alert_reason}",
                extra={"alert_key": alert_key}
            )
            return

        # Build alert message
        timestamp = event_data.get("timestamp", datetime.utcnow())
        client_ip = event_data.get("client_ip") or event_data.get("ip_address", "Unknown")
        user_id = event_data.get("user_id", "Unknown")
        agent_id = event_data.get("agent_id", "Unknown")
        endpoint = event_data.get("endpoint") or event_data.get("path", "Unknown")
        message = event_data.get("message", "No message")
        blocked = event_data.get("blocked", False)

        alert_message = f"""
╔══════════════════════════════════════════════════════════════
║ 🚨 {alert_reason}
╠══════════════════════════════════════════════════════════════
║ Time:       {timestamp}
║ Event Type: {event_type}
║ Risk Score: {risk_score}/100
║
║ Source:
║   IP:       {client_ip}
║   User:     {user_id}
║   Agent:    {agent_id}
║
║ Target:
║   Endpoint: {endpoint}
║   Blocked:  {'✅ YES' if blocked else '❌ NO'}
║
║ Message:    {message}
"""

        # Add brute force details if available
        if brute_force_info:
            attempt_count = brute_force_info.get("attempt_count", 0)
            time_window = brute_force_info.get("time_window", "unknown")
            alert_message += f"""║
║ Brute Force Detection:
║   Attempts:    {attempt_count}
║   Time Window: {time_window}s
║   Threshold:   {self.brute_force_threshold} attempts
"""

        alert_message += "╚══════════════════════════════════════════════════════════════\n"

        # Log CRITICAL alert
        logger.critical(
            f"SECURITY ALERT: {alert_reason}",
            extra={
                "alert_reason": alert_reason,
                "event_type": event_type,
                "risk_score": risk_score,
                "client_ip": client_ip,
                "user_id": user_id,
                "agent_id": agent_id,
                "endpoint": endpoint,
                "blocked": blocked,
                "brute_force_info": brute_force_info,
            }
        )
        print(alert_message)  # Also print to console for immediate visibility

        # Record alert to prevent spam
        self.recent_alerts[alert_key] = datetime.utcnow()

        # TODO: Send email alert
        # await self._send_email_alert(alert_message)

        # TODO: Send webhook alert
        # await self._send_webhook_alert(alert_data)

    def _is_in_cooldown(self, alert_key: str) -> bool:
        """
        Check if alert is in cooldown period.

        Args:
            alert_key: Unique key for alert (e.g., "event_type:ip")

        Returns:
            True if alert should be suppressed, False if can send
        """
        if alert_key not in self.recent_alerts:
            return False

        last_alert_time = self.recent_alerts[alert_key]
        time_since_alert = (datetime.utcnow() - last_alert_time).total_seconds()

        return time_since_alert < self.alert_cooldown

    def clear_cooldown(self, alert_key: str) -> None:
        """
        Clear cooldown for specific alert key.

        Useful for testing or manual override.

        Args:
            alert_key: Alert key to clear
        """
        if alert_key in self.recent_alerts:
            del self.recent_alerts[alert_key]
            logger.debug(f"Alert cooldown cleared: {alert_key}")

    def set_risk_threshold(self, threshold: int) -> None:
        """
        Update risk score threshold for alerts.

        Args:
            threshold: New risk score threshold (0-100)
        """
        if not 0 <= threshold <= 100:
            raise ValueError("Risk threshold must be between 0 and 100")

        old_threshold = self.risk_score_threshold
        self.risk_score_threshold = threshold
        logger.info(
            f"Risk score threshold updated: {old_threshold} → {threshold}",
            extra={"old_threshold": old_threshold, "new_threshold": threshold}
        )

    def set_cooldown(self, cooldown_seconds: int) -> None:
        """
        Update alert cooldown period.

        Args:
            cooldown_seconds: Cooldown period in seconds
        """
        if cooldown_seconds < 0:
            raise ValueError("Cooldown must be non-negative")

        old_cooldown = self.alert_cooldown
        self.alert_cooldown = cooldown_seconds
        logger.info(
            f"Alert cooldown updated: {old_cooldown}s → {cooldown_seconds}s",
            extra={"old_cooldown": old_cooldown, "new_cooldown": cooldown_seconds}
        )
