"""
Risk Analyzer Service for Security Audit System.

This service handles risk scoring, brute force detection, and event hashing.
Extracted from AsyncSecurityAuditLogger as part of Phase 4.2 refactoring.
"""

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.models.audit_log import SecurityAuditLog

logger = logging.getLogger(__name__)


class RiskAnalyzer:
    """
    Service for security risk analysis.

    Provides:
    - Risk score calculation (0-100)
    - Brute force attack detection
    - Event fingerprinting (hash generation)
    """

    def __init__(self, session_maker: async_sessionmaker[AsyncSession] | None = None):
        """
        Initialize risk analyzer.

        Args:
            session_maker: SQLAlchemy async session maker for database queries.
                          If None, brute force detection will be disabled.
        """
        self.session_maker = session_maker

        # Risk scoring patterns
        self.risk_patterns = {
            "high_risk_ips": set(),  # Known bad IPs (dynamically updated)
            "suspicious_user_agents": ["sqlmap", "nikto", "burp", "nessus", "openvas"],
            "attack_endpoints": ["admin", "wp-admin", "phpmyadmin", ".env", "config"],
        }

        # Event severity to score mapping
        self.severity_scores = {
            "LOW": 10,
            "MEDIUM": 30,
            "HIGH": 60,
            "CRITICAL": 100,
        }

        # High-risk event types (attacks)
        self.attack_event_types = {
            "SQL_INJECTION_ATTEMPT",
            "XSS_ATTEMPT",
            "PATH_TRAVERSAL_ATTEMPT",
            "COMMAND_INJECTION_ATTEMPT",
            "VECTOR_INJECTION_ATTEMPT",
        }

    async def calculate_risk_score(
        self,
        event_type: str,
        event_data: dict[str, Any],
        location_info: dict[str, Any] | None = None,  # noqa: ARG002 - Reserved for future geographic risk scoring
    ) -> int:
        """
        Calculate risk score for an event (0-100).

        Risk factors:
        - Event severity (from event_data.get("severity"))
        - IP reputation (high_risk_ips)
        - User agent patterns (suspicious_user_agents)
        - Endpoint patterns (attack_endpoints)
        - Attack type detection

        Args:
            event_type: Type of security event (e.g., "authentication_failed")
            event_data: Event details dict
            location_info: Optional location data from GeoIP

        Returns:
            Risk score from 0 (safe) to 100 (critical threat)
        """
        score = 0

        # Factor 1: Severity-based scoring
        severity = event_data.get("severity", "LOW")
        score += self.severity_scores.get(severity, 0)

        # Factor 2: High-risk IP check
        client_ip = event_data.get("client_ip") or event_data.get("ip_address")
        if client_ip and client_ip in self.risk_patterns["high_risk_ips"]:
            score += 50
            logger.warning(
                f"🚨 High-risk IP detected: {client_ip}",
                extra={"client_ip": client_ip, "event_type": event_type}
            )

        # Factor 3: Suspicious user agent
        user_agent = event_data.get("user_agent")
        if user_agent:
            ua_lower = user_agent.lower()
            for pattern in self.risk_patterns["suspicious_user_agents"]:
                if pattern in ua_lower:
                    score += 30
                    logger.warning(
                        f"⚠️  Suspicious user agent detected: {pattern}",
                        extra={"user_agent": user_agent, "pattern": pattern}
                    )
                    break

        # Factor 4: Attack endpoint patterns
        endpoint = event_data.get("endpoint") or event_data.get("path")
        if endpoint:
            endpoint_lower = endpoint.lower()
            for pattern in self.risk_patterns["attack_endpoints"]:
                if pattern in endpoint_lower:
                    score += 20
                    logger.warning(
                        f"⚠️  Attack endpoint accessed: {pattern}",
                        extra={"endpoint": endpoint, "pattern": pattern}
                    )
                    break

        # Factor 5: Known attack types
        if event_type.upper() in self.attack_event_types:
            score += 40
            logger.warning(
                f"🚨 Attack attempt detected: {event_type}",
                extra={"event_type": event_type}
            )

        # Cap score at 100
        return min(score, 100)

    async def check_brute_force(
        self,
        agent_id: str,
        event_type: str,
        client_ip: str | None = None,
        time_window: int = 300,  # 5 minutes default
    ) -> dict[str, Any]:
        """
        Check for brute force attack patterns.

        Analyzes recent failed authentication attempts from same IP or agent.

        Args:
            agent_id: Agent ID to check
            event_type: Event type (typically "authentication_failed")
            client_ip: Optional client IP for IP-based detection
            time_window: Time window in seconds (default: 300 = 5 minutes)

        Returns:
            {
                "is_brute_force": bool,
                "attempt_count": int,
                "first_attempt": datetime | None,
                "last_attempt": datetime | None,
                "threshold_exceeded": bool
            }
        """
        if not self.session_maker:
            logger.warning(
                "⚠️  Brute force check skipped (database unavailable)",
                extra={"agent_id": agent_id, "client_ip": client_ip}
            )
            return {
                "is_brute_force": False,
                "attempt_count": 0,
                "first_attempt": None,
                "last_attempt": None,
                "threshold_exceeded": False,
            }

        try:
            async with self.session_maker() as session:
                # Calculate time threshold
                time_threshold = datetime.utcnow() - timedelta(seconds=time_window)

                # Query recent failed attempts
                stmt = select(SecurityAuditLog).filter(
                    SecurityAuditLog.event_type == event_type,
                    SecurityAuditLog.timestamp >= time_threshold,
                )

                # Filter by IP or agent_id
                if client_ip:
                    stmt = stmt.filter(SecurityAuditLog.client_ip == client_ip)
                else:
                    stmt = stmt.filter(SecurityAuditLog.agent_id == agent_id)

                result = await session.execute(stmt)
                failed_attempts = result.scalars().all()

                attempt_count = len(failed_attempts)
                threshold = 5  # Alert if >= 5 attempts

                is_brute_force = attempt_count >= threshold

                # Update high-risk IPs if brute force detected
                if is_brute_force and client_ip:
                    self.risk_patterns["high_risk_ips"].add(client_ip)
                    logger.error(
                        f"🚨 BRUTE FORCE DETECTED: {attempt_count} attempts from {client_ip}",
                        extra={
                            "client_ip": client_ip,
                            "agent_id": agent_id,
                            "attempt_count": attempt_count,
                            "time_window": time_window,
                        }
                    )

                return {
                    "is_brute_force": is_brute_force,
                    "attempt_count": attempt_count,
                    "first_attempt": failed_attempts[0].timestamp if failed_attempts else None,
                    "last_attempt": failed_attempts[-1].timestamp if failed_attempts else None,
                    "threshold_exceeded": is_brute_force,
                }

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            # Brute force detection failure is CRITICAL - might miss active attack
            logger.error(
                f"❌ Failed to check brute force pattern (possible attack ongoing!): {e}",
                exc_info=True,
                extra={
                    "agent_id": agent_id,
                    "client_ip": client_ip,
                    "event_type": event_type,
                },
            )
            # Return safe default (assume no brute force to avoid false positives)
            return {
                "is_brute_force": False,
                "attempt_count": 0,
                "first_attempt": None,
                "last_attempt": None,
                "threshold_exceeded": False,
            }

    @staticmethod
    def generate_event_hash(event_data: dict[str, Any]) -> str:
        """
        Generate SHA-256 hash for event deduplication.

        Hash is based on key event fields:
        - event_type
        - client_ip
        - endpoint
        - user_id

        Args:
            event_data: Event details dict

        Returns:
            16-character hex hash (SHA-256 truncated)
        """
        event_type = event_data.get("event_type", "unknown")
        client_ip = event_data.get("client_ip") or event_data.get("ip_address", "")
        endpoint = event_data.get("endpoint") or event_data.get("path", "")
        user_id = event_data.get("user_id", "")

        # Create hash based on key fields
        hash_data = f"{event_type}:{client_ip}:{endpoint}:{user_id}"
        return hashlib.sha256(hash_data.encode()).hexdigest()[:16]

    def add_high_risk_ip(self, ip_address: str) -> None:
        """
        Manually add IP to high-risk list.

        Args:
            ip_address: IP to mark as high-risk
        """
        self.risk_patterns["high_risk_ips"].add(ip_address)
        logger.warning(
            f"🚨 IP added to high-risk list: {ip_address}",
            extra={"ip_address": ip_address}
        )

    def remove_high_risk_ip(self, ip_address: str) -> bool:
        """
        Remove IP from high-risk list.

        Args:
            ip_address: IP to remove

        Returns:
            True if IP was in list and removed, False otherwise
        """
        if ip_address in self.risk_patterns["high_risk_ips"]:
            self.risk_patterns["high_risk_ips"].discard(ip_address)
            logger.info(
                f"✅ IP removed from high-risk list: {ip_address}",
                extra={"ip_address": ip_address}
            )
            return True
        return False

    def get_high_risk_ips(self) -> set[str]:
        """
        Get current high-risk IP list.

        Returns:
            Set of high-risk IP addresses
        """
        return self.risk_patterns["high_risk_ips"].copy()
