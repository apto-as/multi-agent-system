"""
Event Store Service for Security Audit System.

This service handles event persistence with multi-tier fallback.
Extracted from AsyncSecurityAuditLogger as part of Phase 4.2 refactoring.
"""

import json
import logging
import sys
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.config import Settings
from src.core.database import Base
from src.models.audit_log import SecurityAuditLog

logger = logging.getLogger(__name__)


class EventStore:
    """
    Service for security event persistence.

    Implements multi-tier fallback for critical audit logs:
    1. Database (primary)
    2. File (fallback)
    3. Stdout/stderr (last resort)

    CRITICAL: This service MUST never lose audit logs.
    """

    def __init__(self, settings: Settings):
        """
        Initialize event store.

        Args:
            settings: Application settings (for database URL)
        """
        self.settings = settings
        self.engine = None
        self.session_maker: async_sessionmaker[AsyncSession] | None = None
        self._initialized = False

    async def initialize(self) -> None:
        """
        Initialize database connection.

        Gracefully degrades to file-only mode if database unavailable.
        """
        if self._initialized:
            logger.debug("Event store already initialized")
            return

        try:
            # SQLite + async architecture
            db_url = self.settings.database_url

            self.engine = create_async_engine(db_url, echo=False)
            self.session_maker = async_sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )

            # Create tables if they don't exist
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            logger.info("✅ Security audit database initialized")
            self._initialized = True

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            # CRITICAL: Audit log database failure means NO security event tracking
            # This is a fail-secure scenario - we continue but with degraded logging
            logger.critical(
                f"❌ CRITICAL: Audit log database initialization failed. "
                f"Security events will ONLY be logged to file/stdout. "
                f"Error: {e}",
                exc_info=True,
                extra={
                    "database_url": db_url.split("@")[-1] if "@" in db_url else "unknown",
                    "fallback_mode": "file_only",
                },
            )
            # DO NOT raise - allow service to start with file-only logging
            self.engine = None
            self.session_maker = None
            self._initialized = True

    async def save(
        self,
        event_type: str,
        event_data: dict[str, Any],
        agent_id: str | None,
        user_id: str | None,
        ip_address: str | None,
        location_info: dict[str, Any] | None,
        risk_score: int,
        event_hash: str,
    ) -> SecurityAuditLog | None:
        """
        Save event with multi-tier fallback.

        Fallback hierarchy: DB → File → Stdout

        Args:
            event_type: Type of security event
            event_data: Event details dict
            agent_id: Agent ID (if applicable)
            user_id: User ID (if applicable)
            ip_address: Client IP address
            location_info: GeoIP location data
            risk_score: Calculated risk score (0-100)
            event_hash: Event hash for deduplication

        Returns:
            Saved SecurityAuditLog model, or None if database unavailable
        """
        if not self.session_maker:
            # DB not available - fallback to file immediately
            logger.warning("⚠️  Audit log DB unavailable, using file fallback")
            await self._log_to_file(event_type, event_data, risk_score)
            return None

        try:
            async with self.session_maker() as session:
                # Check if similar event already exists recently
                stmt = select(SecurityAuditLog).filter_by(event_hash=event_hash)
                result = await session.execute(stmt)
                existing = result.scalar_one_or_none()

                if existing:
                    # Update existing event (increment counter in details)
                    details = existing.details or {}
                    details["count"] = details.get("count", 1) + 1
                    details["last_occurrence"] = datetime.utcnow().isoformat()
                    existing.details = details
                    saved_event = existing
                else:
                    # Create new event
                    audit_log = SecurityAuditLog(
                        event_type=event_type,
                        severity=event_data.get("severity", "MEDIUM"),
                        timestamp=event_data.get("timestamp", datetime.utcnow()),
                        client_ip=ip_address,
                        user_id=user_id,
                        agent_id=agent_id,
                        session_id=event_data.get("session_id"),
                        endpoint=event_data.get("endpoint") or event_data.get("path"),
                        method=event_data.get("method"),
                        user_agent=event_data.get("user_agent"),
                        referer=event_data.get("referer"),
                        message=event_data.get("message"),
                        details=event_data.get("details", {}),
                        location=location_info,
                        risk_score=risk_score,
                        blocked=event_data.get("blocked", False),
                        event_hash=event_hash,
                    )
                    session.add(audit_log)
                    saved_event = audit_log

                await session.commit()
                await session.refresh(saved_event)

                logger.debug(
                    f"Security event saved: {event_type}",
                    extra={
                        "event_type": event_type,
                        "event_hash": event_hash,
                        "risk_score": risk_score,
                    }
                )

                return saved_event

        except (KeyboardInterrupt, SystemExit):
            # Flush pending logs before exit
            logger.critical("🚨 User interrupt during audit log write - flushing to file")
            await self._log_to_file(event_type, event_data, risk_score)
            raise
        except Exception as e:
            # CRITICAL: Database write failed - MUST fallback to file
            logger.critical(
                f"❌ CRITICAL: Audit log database write failed, falling back to file. "
                f"Event: {event_type}, IP: {ip_address}, Error: {e}",
                exc_info=True,
                extra={
                    "event_type": event_type,
                    "client_ip": ip_address,
                    "severity": event_data.get("severity", "UNKNOWN"),
                    "event_hash": event_hash,
                },
            )

            # Fallback to file logging (MUST succeed)
            try:
                await self._log_to_file(event_type, event_data, risk_score)
            except Exception as file_error:
                # LAST RESORT: Both DB and file failed - dump to stdout
                self._emergency_log(event_type, event_data, ip_address, e, file_error)

            return None

    async def _log_to_file(
        self,
        event_type: str,
        event_data: dict[str, Any],
        risk_score: int,
    ) -> None:
        """
        Log event to file asynchronously.

        CRITICAL: This is the fallback when database fails.
        MUST NOT fail silently.

        Args:
            event_type: Type of security event
            event_data: Event details dict
            risk_score: Risk score
        """
        try:
            log_entry = {
                "timestamp": event_data.get("timestamp", datetime.utcnow()).isoformat()
                if isinstance(event_data.get("timestamp"), datetime)
                else event_data.get("timestamp", datetime.utcnow().isoformat()),
                "event_type": event_type,
                "severity": event_data.get("severity", "MEDIUM"),
                "client_ip": event_data.get("client_ip") or event_data.get("ip_address"),
                "user_id": event_data.get("user_id"),
                "agent_id": event_data.get("agent_id"),
                "endpoint": event_data.get("endpoint") or event_data.get("path"),
                "message": event_data.get("message"),
                "risk_score": risk_score,
                "blocked": event_data.get("blocked", False),
            }

            # Use appropriate log level based on severity
            severity = event_data.get("severity", "MEDIUM")
            if severity == "CRITICAL":
                logger.critical(f"SECURITY: {json.dumps(log_entry)}")
            elif severity == "HIGH":
                logger.error(f"SECURITY: {json.dumps(log_entry)}")
            elif severity == "MEDIUM":
                logger.warning(f"SECURITY: {json.dumps(log_entry)}")
            else:
                logger.info(f"SECURITY: {json.dumps(log_entry)}")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            # CRITICAL: File logging failed (this is the fallback!)
            logger.critical(
                f"❌ CRITICAL: File audit logging failed! Event: {event_type}, "
                f"IP: {event_data.get('client_ip')}, Error: {e}",
                exc_info=True,
            )
            print(
                f"EMERGENCY_AUDIT: {event_type} from {event_data.get('client_ip')} - "
                f"File logging failed: {e}",
                file=sys.stderr,
            )
            # Re-raise so caller knows file logging failed
            raise

    def _emergency_log(
        self,
        event_type: str,
        event_data: dict[str, Any],
        ip_address: str | None,
        db_error: Exception,
        file_error: Exception,
    ) -> None:
        """
        Emergency logging when all backends fail.

        Dumps to stderr as last resort.

        Args:
            event_type: Type of security event
            event_data: Event details dict
            ip_address: Client IP
            db_error: Database error
            file_error: File logging error
        """
        emergency_log = {
            "EMERGENCY_AUDIT_LOG": True,
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "severity": event_data.get("severity", "UNKNOWN"),
            "client_ip": ip_address,
            "user_id": event_data.get("user_id"),
            "agent_id": event_data.get("agent_id"),
            "endpoint": event_data.get("endpoint"),
            "message": event_data.get("message"),
            "db_error": str(db_error),
            "file_error": str(file_error),
        }

        print(
            f"\n🚨 EMERGENCY AUDIT LOG (ALL BACKENDS FAILED):\n"
            f"{json.dumps(emergency_log, indent=2)}\n",
            file=sys.stderr,
        )

        logger.critical(
            f"🚨🚨🚨 CATASTROPHIC: All audit log backends failed! "
            f"Event dumped to stderr. DB error: {db_error}, File error: {file_error}",
            exc_info=True,
        )

    async def get_recent(
        self,
        limit: int = 100,
        event_type: str | None = None,
        agent_id: str | None = None,
        min_risk_score: int | None = None,
        time_window_minutes: int = 60,
    ) -> list[SecurityAuditLog]:
        """
        Query recent security events.

        Args:
            limit: Maximum number of events to return
            event_type: Filter by event type (optional)
            agent_id: Filter by agent ID (optional)
            min_risk_score: Filter by minimum risk score (optional)
            time_window_minutes: Time window in minutes (default: 60)

        Returns:
            List of SecurityAuditLog models (most recent first)
        """
        if not self.session_maker:
            logger.warning("Event store database unavailable - cannot query events")
            return []

        try:
            async with self.session_maker() as session:
                # Calculate time cutoff
                cutoff_time = datetime.utcnow() - timedelta(minutes=time_window_minutes)

                # Build query
                stmt = select(SecurityAuditLog).filter(
                    SecurityAuditLog.timestamp >= cutoff_time
                )

                # Apply filters
                if event_type:
                    stmt = stmt.filter(SecurityAuditLog.event_type == event_type)

                if agent_id:
                    stmt = stmt.filter(SecurityAuditLog.agent_id == agent_id)

                if min_risk_score is not None:
                    stmt = stmt.filter(SecurityAuditLog.risk_score >= min_risk_score)

                # Order by timestamp desc and limit
                stmt = stmt.order_by(SecurityAuditLog.timestamp.desc()).limit(limit)

                result = await session.execute(stmt)
                events = result.scalars().all()

                return list(events)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(
                f"❌ Failed to retrieve recent security events: {e}",
                exc_info=True,
                extra={
                    "limit": limit,
                    "event_type": event_type,
                    "agent_id": agent_id,
                    "min_risk_score": min_risk_score,
                    "time_window_minutes": time_window_minutes,
                },
            )
            return []  # Return empty list on failure (non-critical operation)

    async def cleanup(self) -> None:
        """
        Cleanup database resources.

        Closes engine and disposes connections.
        """
        if self.engine:
            try:
                await self.engine.dispose()
                logger.debug("Event store database engine disposed")
            except Exception as e:
                logger.warning(f"Error disposing database engine: {e}", exc_info=True)
            finally:
                self.engine = None
                self.session_maker = None
                self._initialized = False

    @property
    def is_database_available(self) -> bool:
        """
        Check if database is available.

        Returns:
            True if database is operational, False if in file-only mode
        """
        return self._initialized and self.session_maker is not None
