"""
Security Audit Facade.

Facade for coordinating security audit subsystems.
Replaces AsyncSecurityAuditLogger with modular architecture (Phase 4.2).

Architecture:
    SecurityAuditFacade
    ├── GeoIPService (IP geolocation)
    ├── RiskAnalyzer (risk scoring, brute force detection)
    ├── AlertManager (alert conditions and notifications)
    └── EventStore (event persistence with multi-tier fallback)
"""

import logging
from typing import Any

from src.core.config import get_settings
from src.models.audit_log import SecurityAuditLog
from src.security.services import AlertManager, EventStore, GeoIPService, RiskAnalyzer

logger = logging.getLogger(__name__)


class SecurityAuditFacade:
    """
    Facade for security audit system.

    Coordinates all subsystems to provide a simple, unified interface for
    security event logging.

    Features:
    - GeoIP location tracking
    - Risk score calculation
    - Brute force detection
    - Security alerts
    - Event persistence with fallback
    """

    def __init__(self):
        """
        Initialize security audit facade.

        Creates all subsystem instances.
        Call initialize() to set up async components.
        """
        self.settings = get_settings()

        # Initialize all services
        self.geo_ip = GeoIPService()
        self.event_store = EventStore(self.settings)
        self.risk_analyzer = RiskAnalyzer(None)  # Session maker set in initialize()
        self.alert_manager = AlertManager(self.settings)

        self._initialized = False

    async def initialize(self) -> None:
        """
        Initialize all async services.

        Must be called before using the facade.
        """
        if self._initialized:
            logger.debug("Security audit facade already initialized")
            return

        logger.info("🔐 Initializing security audit facade...")

        # Initialize subsystems
        await self.geo_ip.initialize()
        await self.event_store.initialize()

        # Update risk analyzer with database session maker
        self.risk_analyzer.session_maker = self.event_store.session_maker

        self._initialized = True
        logger.info("✅ Security audit facade initialized")

    async def log_event(
        self,
        event_type: str,
        event_data: dict[str, Any],
        agent_id: str | None = None,
        user_id: str | None = None,
        ip_address: str | None = None,
    ) -> SecurityAuditLog | None:
        """
        Log security event (main entry point).

        Workflow:
        1. Lookup location (GeoIPService)
        2. Calculate risk score (RiskAnalyzer)
        3. Check brute force (RiskAnalyzer, if applicable)
        4. Check alert conditions (AlertManager)
        5. Save event (EventStore)

        Args:
            event_type: Type of security event (e.g., "authentication_failed")
            event_data: Event details dict with keys:
                - severity: "LOW", "MEDIUM", "HIGH", "CRITICAL" (optional, default: "MEDIUM")
                - message: Human-readable message (optional)
                - endpoint: API endpoint or path (optional)
                - method: HTTP method (optional)
                - user_agent: Client user agent (optional)
                - session_id: Session ID (optional)
                - blocked: Whether action was blocked (optional, default: False)
                - details: Additional event-specific data (optional)
            agent_id: Agent ID (optional)
            user_id: User ID (optional)
            ip_address: Client IP address (optional)

        Returns:
            Saved SecurityAuditLog model, or None if database unavailable
        """
        if not self._initialized:
            logger.warning("Security audit facade not initialized - call initialize() first")
            await self.initialize()

        # Step 1: GeoIP lookup
        location_info = None
        if ip_address and self.geo_ip.is_available:
            location_info = await self.geo_ip.lookup(ip_address)

        # Step 2: Risk analysis
        risk_score = await self.risk_analyzer.calculate_risk_score(
            event_type, event_data, location_info
        )

        # Step 3: Brute force detection (for authentication events)
        brute_force_info = None
        if event_type in ["authentication_failed", "authorization_denied", "login_failed"] and (
            ip_address or agent_id
        ):
            brute_force_info = await self.risk_analyzer.check_brute_force(
                agent_id=agent_id or "unknown",
                event_type=event_type,
                client_ip=ip_address,
            )

        # Step 4: Alert if needed
        alert_sent = await self.alert_manager.check_and_notify(
            event_type, risk_score, event_data, brute_force_info
        )

        if alert_sent:
            logger.info(
                f"🚨 Security alert sent for {event_type}",
                extra={"event_type": event_type, "risk_score": risk_score},
            )

        # Step 5: Store event
        event_hash = RiskAnalyzer.generate_event_hash(
            {
                "event_type": event_type,
                "client_ip": ip_address,
                "endpoint": event_data.get("endpoint"),
                "user_id": user_id,
            }
        )

        saved_event = await self.event_store.save(
            event_type=event_type,
            event_data=event_data,
            agent_id=agent_id,
            user_id=user_id,
            ip_address=ip_address,
            location_info=location_info,
            risk_score=risk_score,
            event_hash=event_hash,
        )

        return saved_event

    async def log_pattern_execution(
        self,
        pattern_id: str,
        agent_id: str,
        status: str,
        execution_data: dict[str, Any],
    ) -> SecurityAuditLog | None:
        """
        Log pattern execution event.

        Simplified delegation to log_event() with pattern-specific event type.

        Args:
            pattern_id: Pattern identifier
            agent_id: Agent executing the pattern
            status: Execution status ("success", "failure", "error")
            execution_data: Execution details dict

        Returns:
            Saved SecurityAuditLog model, or None if database unavailable
        """
        return await self.log_event(
            event_type="pattern_execution",
            event_data={
                "pattern_id": pattern_id,
                "status": status,
                "severity": "HIGH" if status == "failure" else "LOW",
                **execution_data,
            },
            agent_id=agent_id,
        )

    async def get_recent_events(
        self,
        limit: int = 100,
        event_type: str | None = None,
        agent_id: str | None = None,
        min_risk_score: int | None = None,
        time_window_minutes: int = 60,
    ) -> list[SecurityAuditLog]:
        """
        Query recent security events.

        Direct delegation to EventStore.

        Args:
            limit: Maximum number of events to return (default: 100)
            event_type: Filter by event type (optional)
            agent_id: Filter by agent ID (optional)
            min_risk_score: Filter by minimum risk score (optional)
            time_window_minutes: Time window in minutes (default: 60)

        Returns:
            List of SecurityAuditLog models (most recent first)
        """
        return await self.event_store.get_recent(
            limit=limit,
            event_type=event_type,
            agent_id=agent_id,
            min_risk_score=min_risk_score,
            time_window_minutes=time_window_minutes,
        )

    async def cleanup(self) -> None:
        """
        Cleanup all services.

        Closes database connections and releases resources.
        """
        logger.info("🧹 Cleaning up security audit facade...")

        # Cleanup all services
        await self.geo_ip.cleanup()
        await self.event_store.cleanup()

        self._initialized = False
        logger.info("✅ Security audit facade cleanup complete")

    @property
    def is_initialized(self) -> bool:
        """Check if facade is initialized."""
        return self._initialized

    @property
    def database_available(self) -> bool:
        """Check if database backend is available."""
        return self.event_store.is_database_available


# Global singleton instance (for backward compatibility with old API)
_audit_facade: SecurityAuditFacade | None = None


async def get_audit_logger() -> SecurityAuditFacade:
    """
    Get global security audit facade instance.

    Creates and initializes facade on first call.

    Returns:
        Initialized SecurityAuditFacade instance
    """
    global _audit_facade

    if _audit_facade is None:
        _audit_facade = SecurityAuditFacade()
        await _audit_facade.initialize()

    return _audit_facade
