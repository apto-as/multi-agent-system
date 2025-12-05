"""
Webhook notification service for security alerts.

Provides async webhook sending functionality for Slack, Discord, PagerDuty, etc.
"""

import logging
from typing import Any

import httpx

from src.core.config import Settings

logger = logging.getLogger(__name__)


class WebhookNotifier:
    """
    Service for sending security alert webhooks.

    Features:
    - Async HTTP webhook sending
    - Support for multiple webhook formats (Slack, Discord, generic)
    - Configurable webhook URL
    - Error handling with fallback logging
    - Timeout and retry logic
    """

    def __init__(self, settings: Settings):
        """
        Initialize webhook notifier.

        Args:
            settings: Application settings (for webhook configuration)
        """
        self.settings = settings
        self.enabled = bool(settings.alert_webhook_url)
        self.timeout = 10.0  # seconds

    async def send_alert(
        self,
        subject: str,
        alert_message: str,
        alert_data: dict[str, Any],
    ) -> bool:
        """
        Send security alert via webhook.

        Args:
            subject: Alert subject
            alert_message: Alert message (plain text format)
            alert_data: Alert metadata dict

        Returns:
            True if webhook sent successfully, False otherwise
        """
        if not self.enabled:
            logger.debug("Webhook alerts disabled - skipping")
            return False

        webhook_url = self.settings.alert_webhook_url
        if not webhook_url:
            return False

        try:
            # Detect webhook type and build appropriate payload
            payload = self._build_webhook_payload(subject, alert_message, alert_data)

            # Send webhook
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()

            logger.info(
                f"✅ Security alert webhook sent: {subject}",
                extra={"subject": subject, "webhook_url": webhook_url[:50] + "..."},
            )
            return True

        except httpx.TimeoutException:
            logger.error(
                f"⏱️ Webhook timeout for alert: {subject}",
                extra={"subject": subject, "timeout": self.timeout},
            )
            return False

        except httpx.HTTPStatusError as e:
            logger.error(
                f"❌ Webhook HTTP error for alert: {subject} - Status {e.response.status_code}",
                extra={"subject": subject, "status_code": e.response.status_code},
            )
            return False

        except Exception as e:
            logger.error(
                f"❌ Failed to send security alert webhook: {e}",
                extra={"subject": subject, "error": str(e)},
                exc_info=True,
            )
            return False

    def _build_webhook_payload(
        self,
        subject: str,
        alert_message: str,
        alert_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Build webhook payload based on webhook URL format.

        Supports:
        - Slack incoming webhooks
        - Discord webhooks
        - Generic JSON webhooks

        Args:
            subject: Alert subject
            alert_message: Plain text alert message
            alert_data: Alert metadata

        Returns:
            Webhook payload dict
        """
        webhook_url = self.settings.alert_webhook_url or ""

        # Slack format
        if "slack.com" in webhook_url or "hooks.slack.com" in webhook_url:
            return self._build_slack_payload(subject, alert_message, alert_data)

        # Discord format
        elif "discord.com" in webhook_url or "discordapp.com" in webhook_url:
            return self._build_discord_payload(subject, alert_message, alert_data)

        # Generic format (default)
        else:
            return self._build_generic_payload(subject, alert_message, alert_data)

    def _build_slack_payload(
        self,
        subject: str,
        alert_message: str,
        alert_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Build Slack-specific webhook payload.

        Args:
            subject: Alert subject
            alert_message: Alert message
            alert_data: Alert metadata

        Returns:
            Slack webhook payload
        """
        # Extract key data
        event_type = alert_data.get("event_type", "Unknown")
        risk_score = alert_data.get("risk_score", 0)
        client_ip = alert_data.get("client_ip", "Unknown")
        endpoint = alert_data.get("endpoint", "Unknown")
        blocked = alert_data.get("blocked", False)

        # Determine color based on risk score
        if risk_score >= 80:
            color = "danger"  # Red
        elif risk_score >= 50:
            color = "warning"  # Orange
        else:
            color = "good"  # Green

        return {
            "text": f"🚨 *TMWS Security Alert: {subject}*",
            "attachments": [
                {
                    "color": color,
                    "fields": [
                        {
                            "title": "Event Type",
                            "value": event_type,
                            "short": True,
                        },
                        {
                            "title": "Risk Score",
                            "value": f"{risk_score}/100",
                            "short": True,
                        },
                        {
                            "title": "Source IP",
                            "value": client_ip,
                            "short": True,
                        },
                        {
                            "title": "Action Blocked",
                            "value": "✅ YES" if blocked else "❌ NO",
                            "short": True,
                        },
                        {
                            "title": "Endpoint",
                            "value": endpoint,
                            "short": False,
                        },
                    ],
                    "text": f"```\n{alert_message}\n```",
                    "footer": "TMWS Security Audit System",
                    "ts": alert_data.get("timestamp", ""),
                }
            ],
        }

    def _build_discord_payload(
        self,
        subject: str,
        alert_message: str,
        alert_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Build Discord-specific webhook payload.

        Args:
            subject: Alert subject
            alert_message: Alert message
            alert_data: Alert metadata

        Returns:
            Discord webhook payload
        """
        # Extract key data
        event_type = alert_data.get("event_type", "Unknown")
        risk_score = alert_data.get("risk_score", 0)
        client_ip = alert_data.get("client_ip", "Unknown")
        endpoint = alert_data.get("endpoint", "Unknown")
        blocked = alert_data.get("blocked", False)

        # Determine color based on risk score (decimal format for Discord)
        if risk_score >= 80:
            color = 0xDC3545  # Red
        elif risk_score >= 50:
            color = 0xFFC107  # Orange
        else:
            color = 0x28A745  # Green

        return {
            "content": f"🚨 **TMWS Security Alert: {subject}**",
            "embeds": [
                {
                    "title": "Security Event Details",
                    "color": color,
                    "fields": [
                        {"name": "Event Type", "value": event_type, "inline": True},
                        {"name": "Risk Score", "value": f"{risk_score}/100", "inline": True},
                        {"name": "Source IP", "value": client_ip, "inline": True},
                        {
                            "name": "Action Blocked",
                            "value": "✅ YES" if blocked else "❌ NO",
                            "inline": True,
                        },
                        {"name": "Endpoint", "value": endpoint, "inline": False},
                    ],
                    "description": f"```\n{alert_message}\n```",
                    "footer": {"text": "TMWS Security Audit System"},
                    "timestamp": alert_data.get("timestamp", ""),
                }
            ],
        }

    def _build_generic_payload(
        self,
        subject: str,
        alert_message: str,
        alert_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Build generic webhook payload.

        Args:
            subject: Alert subject
            alert_message: Alert message
            alert_data: Alert metadata

        Returns:
            Generic webhook payload
        """
        return {
            "alert_type": "security_alert",
            "subject": subject,
            "message": alert_message,
            "severity": alert_data.get("severity", "MEDIUM"),
            "risk_score": alert_data.get("risk_score", 0),
            "event_type": alert_data.get("event_type", "Unknown"),
            "source_ip": alert_data.get("client_ip", "Unknown"),
            "endpoint": alert_data.get("endpoint", "Unknown"),
            "blocked": alert_data.get("blocked", False),
            "timestamp": alert_data.get("timestamp", ""),
            "metadata": alert_data,
        }
