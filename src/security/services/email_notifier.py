"""
Email notification service for security alerts.

Provides async email sending functionality using SMTP.
"""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from src.core.config import Settings

logger = logging.getLogger(__name__)


class EmailNotifier:
    """
    Service for sending security alert emails.

    Features:
    - Async SMTP email sending
    - HTML and plain text support
    - Configurable SMTP settings
    - Error handling with fallback logging
    """

    def __init__(self, settings: Settings):
        """
        Initialize email notifier.

        Args:
            settings: Application settings (for SMTP configuration)
        """
        self.settings = settings
        self.enabled = self._check_configuration()

    def _check_configuration(self) -> bool:
        """
        Check if email alerts are properly configured.

        Returns:
            True if email alerts can be sent, False otherwise
        """
        required_settings = [
            self.settings.smtp_host,
            self.settings.smtp_port,
            self.settings.alert_email_from,
            self.settings.alert_email_to,
        ]

        if not all(required_settings):
            logger.warning(
                "Email alerts disabled - missing SMTP configuration. "
                "Set TMWS_SMTP_HOST, TMWS_SMTP_PORT, TMWS_ALERT_EMAIL_FROM, "
                "TMWS_ALERT_EMAIL_TO in environment."
            )
            return False

        return True

    async def send_alert(
        self,
        subject: str,
        alert_message: str,
        alert_data: dict[str, Any],
    ) -> bool:
        """
        Send security alert email.

        Args:
            subject: Email subject
            alert_message: Alert message (plain text format)
            alert_data: Alert metadata dict

        Returns:
            True if email sent successfully, False otherwise
        """
        if not self.enabled:
            logger.debug("Email alerts disabled - skipping")
            return False

        try:
            # Build email message
            msg = MIMEMultipart("alternative")
            msg["From"] = self.settings.alert_email_from
            msg["To"] = self.settings.alert_email_to
            msg["Subject"] = f"🚨 TMWS Security Alert: {subject}"

            # Plain text version
            text_part = MIMEText(alert_message, "plain")
            msg.attach(text_part)

            # HTML version (optional, can be enhanced)
            html_content = self._build_html_alert(subject, alert_message, alert_data)
            html_part = MIMEText(html_content, "html")
            msg.attach(html_part)

            # Send email
            with smtplib.SMTP(self.settings.smtp_host, self.settings.smtp_port) as server:
                if self.settings.smtp_use_tls:
                    server.starttls()

                if self.settings.smtp_username and self.settings.smtp_password:
                    server.login(
                        self.settings.smtp_username,
                        self.settings.smtp_password,
                    )

                server.send_message(msg)

            logger.info(
                f"✅ Security alert email sent: {subject}",
                extra={"subject": subject, "to": self.settings.alert_email_to},
            )
            return True

        except Exception as e:
            logger.error(
                f"❌ Failed to send security alert email: {e}",
                extra={"subject": subject, "error": str(e)},
                exc_info=True,
            )
            return False

    def _build_html_alert(
        self,
        subject: str,
        alert_message: str,
        alert_data: dict[str, Any],
    ) -> str:
        """
        Build HTML version of alert email.

        Args:
            subject: Alert subject
            alert_message: Plain text alert message
            alert_data: Alert metadata

        Returns:
            HTML content string
        """
        # Extract key data
        event_type = alert_data.get("event_type", "Unknown")
        risk_score = alert_data.get("risk_score", 0)
        client_ip = alert_data.get("client_ip", "Unknown")
        endpoint = alert_data.get("endpoint", "Unknown")
        blocked = alert_data.get("blocked", False)

        # Build HTML
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
        }}
        .alert-container {{
            max-width: 600px;
            margin: 0 auto;
            border: 2px solid #dc3545;
            border-radius: 8px;
            padding: 20px;
            background: #fff5f5;
        }}
        .alert-header {{
            background: #dc3545;
            color: white;
            padding: 15px;
            margin: -20px -20px 20px -20px;
            border-radius: 6px 6px 0 0;
        }}
        .alert-header h1 {{
            margin: 0;
            font-size: 24px;
        }}
        .metric {{
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-left: 4px solid #dc3545;
        }}
        .metric strong {{
            color: #dc3545;
        }}
        .risk-score {{
            font-size: 32px;
            font-weight: bold;
            color: #dc3545;
        }}
        .blocked-yes {{
            color: #28a745;
            font-weight: bold;
        }}
        .blocked-no {{
            color: #dc3545;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="alert-container">
        <div class="alert-header">
            <h1>🚨 Security Alert: {subject}</h1>
        </div>

        <div class="metric">
            <strong>Event Type:</strong> {event_type}
        </div>

        <div class="metric">
            <strong>Risk Score:</strong>
            <span class="risk-score">{risk_score}/100</span>
        </div>

        <div class="metric">
            <strong>Source IP:</strong> {client_ip}
        </div>

        <div class="metric">
            <strong>Target Endpoint:</strong> {endpoint}
        </div>

        <div class="metric">
            <strong>Action Blocked:</strong>
            <span class="{"blocked-yes" if blocked else "blocked-no"}">
                {"✅ YES" if blocked else "❌ NO"}
            </span>
        </div>

        <div class="metric">
            <strong>Timestamp:</strong> {alert_data.get("timestamp", "N/A")}
        </div>

        <hr>

        <h3>Details:</h3>
        <pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto;">
{alert_message}
        </pre>
    </div>
</body>
</html>
"""
        return html
