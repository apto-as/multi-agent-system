"""
Security Services Package.

Subsystems for security audit functionality, extracted from AsyncSecurityAuditLogger
as part of Phase 4.2 Facade Pattern refactoring.

Each service handles a single responsibility:
- GeoIPService: IP address geolocation
- RiskAnalyzer: Risk scoring and threat detection
- AlertManager: Security alert notifications
- EmailNotifier: Email alert notifications
- WebhookNotifier: Webhook alert notifications (Slack, Discord, etc.)
- EventStore: Event persistence and querying
"""

from src.security.services.alert_manager import AlertManager
from src.security.services.email_notifier import EmailNotifier
from src.security.services.event_store import EventStore
from src.security.services.geo_ip_service import GeoIPService
from src.security.services.risk_analyzer import RiskAnalyzer
from src.security.services.webhook_notifier import WebhookNotifier

__all__ = [
    "GeoIPService",
    "RiskAnalyzer",
    "AlertManager",
    "EmailNotifier",
    "WebhookNotifier",
    "EventStore",
]
