import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import geoip2.database
import geoip2.errors
from fastapi import Request
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ..core.config import get_settings
from ..core.database import Base
from ..models.audit_log import SecurityAuditLog, SecurityEventSeverity, SecurityEventType
from .security_event import SecurityEvent

logger = logging.getLogger(__name__)


class SecurityAuditLogger:
    """
    Comprehensive security audit logging system.
    Hestia's Rule: Every security event must be tracked and analyzed.
    """

    def __init__(self):
        """Initialize audit logger."""
        self.settings = get_settings()
        self.engine = None
        self.session_maker = None
        self.geoip_reader = None

        # Initialize database
        self._init_database()

        # Initialize GeoIP (optional)
        self._init_geoip()

        # Risk scoring patterns
        self.risk_patterns = {
            "high_risk_ips": set(),  # Known bad IPs
            "suspicious_user_agents": ["sqlmap", "nikto", "burp", "nessus", "openvas"],
            "attack_endpoints": ["admin", "wp-admin", "phpmyadmin", ".env", "config"],
        }

    def _init_database(self) -> None:
        """Initialize database connection."""
        try:
            self.engine = create_engine(self.settings.database_url)
            self.session_maker = sessionmaker(bind=self.engine)

            # Create tables if they don't exist
            Base.metadata.create_all(self.engine)

            logger.info("Security audit database initialized")
        except Exception as e:
            logger.error(f"Failed to initialize audit database: {e}")

    def _init_geoip(self) -> None:
        """Initialize GeoIP database (optional)."""
        try:
            # Try to load GeoLite2 database
            geoip_path = Path("/usr/local/share/GeoIP/GeoLite2-City.mmdb")
            if geoip_path.exists():
                self.geoip_reader = geoip2.database.Reader(str(geoip_path))
                logger.info("GeoIP database loaded")
            else:
                logger.info("GeoIP database not found - location tracking disabled")
        except Exception as e:
            logger.warning(f"Failed to load GeoIP database: {e}")

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
        """
        Log a security event.

        Args:
            event_type: Type of security event
            severity: Event severity level
            client_ip: Client IP address
            message: Event message
            request: FastAPI request object (optional)
            user_id: User ID (optional)
            session_id: Session ID (optional)
            details: Additional event details
            blocked: Whether the action was blocked

        Returns:
            Created SecurityEvent object
        """
        now = datetime.utcnow()

        # Create security event
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            timestamp=now,
            client_ip=client_ip,
            user_id=user_id,
            session_id=session_id,
            message=message,
            details=details or {},
            blocked=blocked,
        )

        # Extract request information
        if request:
            event.endpoint = str(request.url.path)
            event.method = request.method
            event.user_agent = request.headers.get("User-Agent")
            event.referer = request.headers.get("Referer")

        # Add location information
        event.location = await self._get_location_info(client_ip)

        # Calculate risk score
        event.risk_score = self._calculate_risk_score(event)

        # Store in database
        await self._store_event(event)

        # Log to file/console
        self._log_to_file(event)

        # Check for alert conditions
        await self._check_alert_conditions(event)

        return event

    async def _store_event(self, event: SecurityEvent) -> None:
        """Store event in database."""
        if not self.session_maker:
            return

        try:
            # Generate event hash for deduplication
            event_hash = self._generate_event_hash(event)

            session = self.session_maker()
            try:
                # Check if similar event already exists recently
                existing = session.query(SecurityAuditLog).filter_by(event_hash=event_hash).first()

                if existing:
                    # Update existing event (increment counter in details)
                    details = existing.details or {}
                    details["count"] = details.get("count", 1) + 1
                    details["last_occurrence"] = event.timestamp.isoformat()
                    existing.details = details
                else:
                    # Create new event
                    audit_log = SecurityAuditLog(
                        event_type=event.event_type.value,
                        severity=event.severity.value,
                        timestamp=event.timestamp,
                        client_ip=event.client_ip,
                        user_id=event.user_id,
                        session_id=event.session_id,
                        endpoint=event.endpoint,
                        method=event.method,
                        user_agent=event.user_agent,
                        referer=event.referer,
                        message=event.message,
                        details=event.details,
                        location=event.location,
                        risk_score=event.risk_score,
                        blocked=event.blocked,
                        event_hash=event_hash,
                    )
                    session.add(audit_log)

                session.commit()

            finally:
                session.close()

        except Exception as e:
            logger.error(f"Failed to store security event: {e}")

    def _generate_event_hash(self, event: SecurityEvent) -> str:
        """Generate hash for event deduplication."""
        # Create hash based on key fields
        hash_data = f"{event.event_type.value}:{event.client_ip}:{event.endpoint}:{event.user_id}"
        return hashlib.sha256(hash_data.encode()).hexdigest()[:16]

    async def _get_location_info(self, ip_address: str) -> dict[str, str] | None:
        """Get location information for IP address."""
        if not self.geoip_reader:
            return None

        try:
            response = self.geoip_reader.city(ip_address)
            return {
                "country": response.country.name or "Unknown",
                "country_code": response.country.iso_code or "XX",
                "city": response.city.name or "Unknown",
                "region": response.subdivisions.most_specific.name or "Unknown",
                "latitude": str(response.location.latitude) if response.location.latitude else None,
                "longitude": str(response.location.longitude)
                if response.location.longitude
                else None,
            }
        except (geoip2.errors.AddressNotFoundError, geoip2.errors.GeoIP2Error):
            return {"country": "Unknown", "country_code": "XX"}
        except Exception as e:
            logger.warning(f"GeoIP lookup failed for {ip_address}: {e}")
            return None

    def _calculate_risk_score(self, event: SecurityEvent) -> int:
        """
        Calculate risk score for event (0-100).
        Hestia's scoring: Everything is suspicious until proven otherwise.
        """
        base_scores = {
            SecurityEventType.LOGIN_FAILED: 20,
            SecurityEventType.SQL_INJECTION_ATTEMPT: 90,
            SecurityEventType.XSS_ATTEMPT: 80,
            SecurityEventType.DDOS_DETECTED: 95,
            SecurityEventType.UNAUTHORIZED_ACCESS: 70,
            SecurityEventType.RATE_LIMIT_EXCEEDED: 40,
            SecurityEventType.BOT_DETECTED: 60,
            SecurityEventType.SYSTEM_COMPROMISE: 100,
        }

        score = base_scores.get(event.event_type, 30)  # Default paranoid score

        # Increase score based on patterns
        if event.client_ip in self.risk_patterns["high_risk_ips"]:
            score += 30

        if event.user_agent:
            for suspicious_ua in self.risk_patterns["suspicious_user_agents"]:
                if suspicious_ua.lower() in event.user_agent.lower():
                    score += 25
                    break

        if event.endpoint:
            for attack_endpoint in self.risk_patterns["attack_endpoints"]:
                if attack_endpoint.lower() in event.endpoint.lower():
                    score += 20
                    break

        # Increase score for repeat offenders
        if event.details and event.details.get("count", 1) > 1:
            score += min(event.details["count"] * 5, 30)

        # Location-based scoring
        if event.location:
            # Increase score for high-risk countries (placeholder logic)
            high_risk_countries = ["XX", "Unknown"]  # Unknown/blocked countries
            if event.location.get("country_code") in high_risk_countries:
                score += 15

        return min(score, 100)  # Cap at 100

    def _log_to_file(self, event: SecurityEvent) -> None:
        """Log event to file/console."""
        log_level = {
            SecurityEventSeverity.LOW: logging.INFO,
            SecurityEventSeverity.MEDIUM: logging.WARNING,
            SecurityEventSeverity.HIGH: logging.ERROR,
            SecurityEventSeverity.CRITICAL: logging.CRITICAL,
        }.get(event.severity, logging.INFO)

        message = (
            f"Security Event: {event.event_type.value} | "
            f"IP: {event.client_ip} | "
            f"Risk: {event.risk_score} | "
            f"{event.message}"
        )

        logger.log(log_level, message, extra={"security_event": event.to_dict()})

    async def _check_alert_conditions(self, event: SecurityEvent) -> None:
        """Check if event should trigger alerts."""
        # Critical events always trigger alerts
        if event.severity == SecurityEventSeverity.CRITICAL:
            await self._send_alert(event, "Critical security event detected")

        # High-risk events
        if event.risk_score >= 80:
            await self._send_alert(event, f"High-risk security event (score: {event.risk_score})")

        # Multiple failed attempts
        if (
            event.event_type == SecurityEventType.LOGIN_FAILED
            and event.details
            and event.details.get("count", 1) >= 5
        ):
            await self._send_alert(event, "Brute force attack detected")

        # DDoS detection
        if event.event_type == SecurityEventType.DDOS_DETECTED:
            await self._send_alert(event, "DDoS attack in progress")

    async def _send_alert(self, event: SecurityEvent, alert_message: str) -> None:
        """Send security alert (placeholder implementation)."""
        logger.critical(f"SECURITY ALERT: {alert_message}")

        # TODO: Implement actual alerting:
        # - Email notifications
        # - Slack/Discord webhooks
        # - SMS alerts for critical events
        # - PagerDuty integration
        # - SIEM integration

    async def get_events(
        self,
        limit: int = 100,
        event_type: SecurityEventType | None = None,
        severity: SecurityEventSeverity | None = None,
        client_ip: str | None = None,
        user_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve security events with filtering.

        Args:
            limit: Maximum number of events to return
            event_type: Filter by event type
            severity: Filter by severity
            client_ip: Filter by client IP
            user_id: Filter by user ID
            start_time: Filter events after this time
            end_time: Filter events before this time

        Returns:
            List of security events
        """
        if not self.session_maker:
            return []

        try:
            session = self.session_maker()
            try:
                query = session.query(SecurityAuditLog)

                # Apply filters
                if event_type:
                    query = query.filter(SecurityAuditLog.event_type == event_type.value)

                if severity:
                    query = query.filter(SecurityAuditLog.severity == severity.value)

                if client_ip:
                    query = query.filter(SecurityAuditLog.client_ip == client_ip)

                if user_id:
                    query = query.filter(SecurityAuditLog.user_id == user_id)

                if start_time:
                    query = query.filter(SecurityAuditLog.timestamp >= start_time)

                if end_time:
                    query = query.filter(SecurityAuditLog.timestamp <= end_time)

                # Order by timestamp (newest first) and limit
                events = query.order_by(SecurityAuditLog.timestamp.desc()).limit(limit).all()

                # Convert to dict
                return [
                    {
                        "id": event.id,
                        "event_type": event.event_type,
                        "severity": event.severity,
                        "timestamp": event.timestamp.isoformat(),
                        "client_ip": event.client_ip,
                        "user_id": event.user_id,
                        "endpoint": event.endpoint,
                        "message": event.message,
                        "details": event.details,
                        "location": event.location,
                        "risk_score": event.risk_score,
                        "blocked": event.blocked,
                    }
                    for event in events
                ]

            finally:
                session.close()

        except Exception as e:
            logger.error(f"Failed to retrieve security events: {e}")
            return []

    async def get_statistics(self) -> dict[str, Any]:
        """Get security event statistics."""
        if not self.session_maker:
            return {}

        try:
            session = self.session_maker()
            try:
                from sqlalchemy import func

                # Total events by severity
                severity_stats = (
                    session.query(SecurityAuditLog.severity, func.count(SecurityAuditLog.id))
                    .group_by(SecurityAuditLog.severity)
                    .all()
                )

                # Events by type (top 10)
                type_stats = (
                    session.query(SecurityAuditLog.event_type, func.count(SecurityAuditLog.id))
                    .group_by(SecurityAuditLog.event_type)
                    .order_by(func.count(SecurityAuditLog.id).desc())
                    .limit(10)
                    .all()
                )

                # Top attacking IPs
                ip_stats = (
                    session.query(SecurityAuditLog.client_ip, func.count(SecurityAuditLog.id))
                    .group_by(SecurityAuditLog.client_ip)
                    .order_by(func.count(SecurityAuditLog.id).desc())
                    .limit(10)
                    .all()
                )

                # Recent critical events count
                twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
                critical_count = (
                    session.query(SecurityAuditLog)
                    .filter(
                        SecurityAuditLog.severity == "critical",
                        SecurityAuditLog.timestamp >= twenty_four_hours_ago,
                    )
                    .count()
                )

                return {
                    "total_events": session.query(SecurityAuditLog).count(),
                    "critical_events_24h": critical_count,
                    "events_by_severity": dict(severity_stats),
                    "events_by_type": dict(type_stats),
                    "top_attacking_ips": dict(ip_stats),
                }

            finally:
                session.close()

        except Exception as e:
            logger.error(f"Failed to get security statistics: {e}")
            return {}


# Global audit logger instance
_audit_logger: SecurityAuditLogger | None = None


def get_audit_logger() -> SecurityAuditLogger:
    """Get global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = SecurityAuditLogger()
    return _audit_logger
