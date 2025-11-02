"""
Unit tests for EmailNotifier service.

Tests email alert functionality with mocked SMTP.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.core.config import Settings
from src.security.services.email_notifier import EmailNotifier


@pytest.fixture
def settings_with_smtp():
    """Settings with SMTP configuration."""
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-secret-key-at-least-32-chars-long-for-validation",
        environment="development",
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_username="alerts@example.com",
        smtp_password="test_password",
        alert_email_from="alerts@example.com",
        alert_email_to="security@example.com",
    )


@pytest.fixture
def settings_without_smtp():
    """Settings without SMTP configuration."""
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-secret-key-at-least-32-chars-long-for-validation",
        environment="development",
    )


@pytest.fixture
def email_notifier_enabled(settings_with_smtp):
    """EmailNotifier with SMTP enabled."""
    return EmailNotifier(settings_with_smtp)


@pytest.fixture
def email_notifier_disabled(settings_without_smtp):
    """EmailNotifier with SMTP disabled."""
    return EmailNotifier(settings_without_smtp)


class TestEmailNotifier:
    """Test suite for EmailNotifier service."""

    def test_initialization_with_config(self, email_notifier_enabled):
        """Test EmailNotifier initialization with SMTP config."""
        assert email_notifier_enabled.enabled is True
        assert email_notifier_enabled.settings.smtp_host == "smtp.example.com"
        assert email_notifier_enabled.settings.smtp_port == 587

    def test_initialization_without_config(self, email_notifier_disabled):
        """Test EmailNotifier initialization without SMTP config."""
        assert email_notifier_disabled.enabled is False

    @pytest.mark.asyncio
    async def test_send_alert_disabled(self, email_notifier_disabled):
        """Test send_alert when SMTP is disabled."""
        result = await email_notifier_disabled.send_alert(
            subject="Test Alert",
            alert_message="Test message",
            alert_data={},
        )

        assert result is False
        # SMTP is disabled, so email should not be sent

    @pytest.mark.asyncio
    @patch("src.security.services.email_notifier.smtplib.SMTP")
    async def test_send_alert_success(self, mock_smtp, email_notifier_enabled):
        """Test successful email alert sending."""
        # Mock SMTP server
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        result = await email_notifier_enabled.send_alert(
            subject="CRITICAL SECURITY EVENT",
            alert_message="Security alert message",
            alert_data={
                "event_type": "authentication_failed",
                "risk_score": 95,
                "client_ip": "192.168.1.100",
                "endpoint": "/api/auth/login",
                "blocked": True,
            },
        )

        assert result is True
        mock_smtp.assert_called_once_with("smtp.example.com", 587)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with(
            "alerts@example.com",
            "test_password",
        )
        mock_server.send_message.assert_called_once()

    @pytest.mark.asyncio
    @patch("src.security.services.email_notifier.smtplib.SMTP")
    async def test_send_alert_failure(self, mock_smtp, email_notifier_enabled, caplog):
        """Test email alert sending failure."""
        # Mock SMTP failure
        mock_smtp.side_effect = Exception("SMTP connection failed")

        result = await email_notifier_enabled.send_alert(
            subject="Test Alert",
            alert_message="Test message",
            alert_data={},
        )

        assert result is False
        assert "Failed to send security alert email" in caplog.text

    def test_build_html_alert(self, email_notifier_enabled):
        """Test HTML alert generation."""
        html = email_notifier_enabled._build_html_alert(
            subject="HIGH RISK EVENT DETECTED",
            alert_message="Alert message text",
            alert_data={
                "event_type": "authorization_denied",
                "risk_score": 85,
                "client_ip": "10.0.0.5",
                "endpoint": "/api/admin/delete_all",
                "blocked": True,
                "timestamp": "2025-10-29T12:00:00Z",
            },
        )

        # Verify HTML structure
        assert "<!DOCTYPE html>" in html
        assert "HIGH RISK EVENT DETECTED" in html
        assert "authorization_denied" in html
        assert "85/100" in html
        assert "10.0.0.5" in html
        assert "/api/admin/delete_all" in html
        assert "✅ YES" in html  # Blocked

    def test_html_alert_not_blocked(self, email_notifier_enabled):
        """Test HTML alert generation when action not blocked."""
        html = email_notifier_enabled._build_html_alert(
            subject="Test Alert",
            alert_message="Test",
            alert_data={
                "blocked": False,
            },
        )

        assert "❌ NO" in html  # Not blocked


class TestEmailNotifierIntegration:
    """Integration tests for EmailNotifier with AlertManager."""

    @pytest.mark.asyncio
    @patch("src.security.services.email_notifier.smtplib.SMTP")
    async def test_alert_manager_email_integration(self, mock_smtp, settings_with_smtp):
        """Test AlertManager integration with EmailNotifier."""
        from src.security.services.alert_manager import AlertManager

        # Mock SMTP
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        # Create AlertManager (which creates EmailNotifier)
        alert_manager = AlertManager(settings_with_smtp)

        # Simulate high-risk event triggering email
        result = await alert_manager.check_and_notify(
            event_type="authentication_failed",
            risk_score=95,  # Above threshold (80)
            event_data={
                "severity": "HIGH",
                "client_ip": "192.168.1.100",
                "message": "Multiple failed login attempts",
            },
        )

        assert result is True  # Alert was sent
        mock_server.send_message.assert_called_once()

    @pytest.mark.asyncio
    @patch("src.security.services.email_notifier.smtplib.SMTP")
    async def test_critical_event_triggers_email(self, mock_smtp, settings_with_smtp):
        """Test CRITICAL severity events trigger email."""
        from src.security.services.alert_manager import AlertManager

        # Mock SMTP
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        alert_manager = AlertManager(settings_with_smtp)

        result = await alert_manager.check_and_notify(
            event_type="unauthorized_access",
            risk_score=50,  # Below threshold, but CRITICAL severity
            event_data={
                "severity": "CRITICAL",
                "client_ip": "192.168.1.100",
                "message": "Attempted admin panel access",
            },
        )

        assert result is True  # Alert was sent due to CRITICAL severity
        mock_server.send_message.assert_called_once()
