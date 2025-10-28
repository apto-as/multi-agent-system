"""Rate Limiting and DDoS Protection Module
Hestia's Paranoid Traffic Control System

"……大量のリクエストは必ず攻撃です……全て制限します……"
"""

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import redis
from fastapi import HTTPException, Request, status

from ..core.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class RateLimit:
    """Rate limit configuration."""

    requests: int  # Number of requests allowed
    period: int  # Time period in seconds
    burst: int = 0  # Burst allowance (extra requests)
    block_duration: int = 300  # Block duration in seconds when exceeded


@dataclass
class ClientStats:
    """Client request statistics."""

    ip_address: str
    requests: deque = field(default_factory=deque)
    blocked_until: datetime | None = None
    total_requests: int = 0
    violations: int = 0
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    user_agent: str | None = None


class RateLimiter:
    """Advanced rate limiting system with multiple strategies.
    Hestia's Rule: 99.7% of attacks use excessive request patterns.
    """

    def __init__(self, redis_client: redis.Redis | None = None):
        """Initialize rate limiter."""
        self.settings = get_settings()
        self.redis_client = redis_client
        self.local_storage: dict[str, ClientStats] = {}
        self.global_stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "unique_clients": set(),
        }

        # Redis health tracking (H-2 fix: explicit degraded mode visibility)
        self.redis_health = {
            "is_available": redis_client is not None,
            "failure_count": 0,
            "last_failure_time": None,
            "degraded_mode_active": False,
            "consecutive_failures": 0,
        }

        # Default rate limits (production-grade strict limits)
        env = self.settings.environment
        if env == "production":
            # Stricter limits in production
            self.rate_limits = {
                "global": RateLimit(500, 60),  # 500 requests per minute globally
                "per_ip": RateLimit(30, 60, burst=5),  # 30 requests per minute per IP
                "per_user": RateLimit(60, 60, burst=10),  # 60 requests per minute per user
                "login": RateLimit(
                    3, 60, block_duration=1800,
                ),  # 3 login attempts per minute, 30min block
                "register": RateLimit(
                    1, 60, block_duration=600,
                ),  # 1 registration per minute, 10min block
                "search": RateLimit(20, 60),  # 20 searches per minute
                "embedding": RateLimit(5, 60),  # 5 embedding requests per minute
            }
        else:
            # More lenient limits for development
            self.rate_limits = {
                "global": RateLimit(1000, 60),  # 1000 requests per minute globally
                "per_ip": RateLimit(60, 60, burst=10),  # 60 requests per minute per IP
                "per_user": RateLimit(120, 60, burst=20),  # 120 requests per minute per user
                "login": RateLimit(5, 60, block_duration=900),  # 5 login attempts per minute
                "register": RateLimit(2, 60, block_duration=300),  # 2 registrations per minute
                "search": RateLimit(30, 60),  # 30 searches per minute
                "embedding": RateLimit(10, 60),  # 10 embedding requests per minute
            }

        # Suspicious patterns that indicate attacks
        self.suspicious_patterns = [
            "admin",
            "wp-admin",
            "phpmyadmin",
            "sql",
            ".env",
            "config",
            "backup",
            "test",
            "dev",
            "api/v1/../../",
            "../../../etc/passwd",
            ".git",
            ".svn",
            ".DS_Store",
            "web.config",
            ".htaccess",
            "eval(",
            "exec(",
            "system(",
            "shell_exec(",
            "<script",
            "javascript:",
            "onerror=",
            "onload=",
            "onclick=",
        ]

        # Permanent ban list (IPs that repeatedly violate)
        self.permanent_bans: set = set()
        self.ban_threshold = 10  # Violations before permanent ban

    def _record_redis_failure(self, operation: str, error: Exception) -> None:
        """Record Redis failure for operational visibility (H-2 fix).

        Args:
            operation: Operation that failed (e.g., "global_rate_limit", "user_rate_limit")
            error: The exception that occurred

        """
        self.redis_health["failure_count"] += 1
        self.redis_health["consecutive_failures"] += 1
        self.redis_health["last_failure_time"] = datetime.utcnow()

        # Enter degraded mode after multiple consecutive failures
        if (
            self.redis_health["consecutive_failures"] >= 3
            and not self.redis_health["degraded_mode_active"]
        ):
            self.redis_health["degraded_mode_active"] = True
            logger.critical(
                "⚠️  DEGRADED MODE ACTIVATED: Redis connection failing. "
                f"Using fail-secure fallback limits. Operation: {operation}",
            )

        # Log every failure for operational visibility
        logger.error(
            f"Redis operation failed: {operation} - {error}. "
            f"Total failures: {self.redis_health['failure_count']}, "
            f"Consecutive: {self.redis_health['consecutive_failures']}. "
            f"Degraded mode: {self.redis_health['degraded_mode_active']}",
        )

    def _record_redis_success(self) -> None:
        """Record successful Redis operation."""
        if self.redis_health["consecutive_failures"] > 0:
            self.redis_health["consecutive_failures"] = 0

            # Exit degraded mode
            if self.redis_health["degraded_mode_active"]:
                self.redis_health["degraded_mode_active"] = False
                logger.info("✅ DEGRADED MODE EXITED: Redis connection restored")

    async def check_rate_limit(
        self, request: Request, endpoint_type: str = "default", user_id: str | None = None,
    ) -> bool:
        """Check if request is within rate limits.
        Implements fail-secure principle: Any error = deny access.

        Args:
            request: FastAPI request object
            endpoint_type: Type of endpoint (login, search, etc.)
            user_id: User ID for authenticated requests

        Returns:
            True if allowed, False if rate limited

        Raises:
            HTTPException: If rate limit exceeded or any error occurs

        """
        try:
            return await self._check_rate_limit_internal(request, endpoint_type, user_id)
        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except HTTPException:
            # Re-raise HTTP exceptions (rate limit exceeded, etc.)
            raise
        except Exception as e:
            # FAIL-SECURE: Any unexpected error = deny access
            client_ip = self._get_client_ip(request)
            logger.error(
                f"❌ Rate limiter error (FAIL-SECURE activated): {e}",
                exc_info=True,
                extra={
                    "client_ip": client_ip,
                    "endpoint_type": endpoint_type,
                    "user_id": user_id,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable",
                headers={"Retry-After": "60"},
            )

    async def _check_rate_limit_internal(
        self, request: Request, endpoint_type: str = "default", user_id: str | None = None,
    ) -> bool:
        """Internal rate limit check implementation.
        """
        client_ip = self._get_client_ip(request)
        now = datetime.utcnow()

        # Update global stats
        self.global_stats["total_requests"] += 1
        self.global_stats["unique_clients"].add(client_ip)

        # Check permanent ban list first
        if client_ip in self.permanent_bans:
            logger.critical(f"Permanently banned IP attempted access: {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Access permanently denied",
            )

        # Get or create client stats
        client_stats = self._get_client_stats(client_ip, request)
        client_stats.last_seen = now
        client_stats.total_requests += 1

        # Check if client is currently blocked
        if client_stats.blocked_until and now < client_stats.blocked_until:
            remaining_time = (client_stats.blocked_until - now).seconds
            logger.warning(
                f"Blocked client {client_ip} attempted request. {remaining_time}s remaining",
            )

            # Security audit log
            await self._log_security_event(
                "rate_limit_violation_while_blocked",
                client_ip,
                request,
                {"remaining_block_time": remaining_time},
            )

            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Try again in {remaining_time} seconds.",
                headers={"Retry-After": str(remaining_time)},
            )

        # Check suspicious patterns in URL
        if await self._check_suspicious_patterns(request, client_ip):
            return False

        # Check global rate limit first
        if not await self._check_global_limit():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable due to high traffic",
                headers={"Retry-After": "60"},
            )

        # Check IP-based rate limit
        if not await self._check_ip_limit(client_stats, endpoint_type):
            return False

        # Check user-based rate limit if authenticated
        if user_id and not await self._check_user_limit(user_id, endpoint_type):
            return False

        # Check endpoint-specific limits
        if not await self._check_endpoint_limit(client_stats, endpoint_type, request):
            return False

        # Record successful request
        client_stats.requests.append(now)

        # Clean old requests
        self._clean_old_requests(client_stats)

        return True

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request."""
        # Check X-Forwarded-For header first (for reverse proxies)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Take the first IP (client IP)
            return forwarded.split(",")[0].strip()

        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fallback to request client IP
        return request.client.host if request.client else "unknown"

    def _get_client_stats(self, ip_address: str, request: Request) -> ClientStats:
        """Get or create client statistics."""
        if ip_address not in self.local_storage:
            self.local_storage[ip_address] = ClientStats(
                ip_address=ip_address, user_agent=request.headers.get("User-Agent", "Unknown"),
            )

        return self.local_storage[ip_address]

    async def _check_suspicious_patterns(self, request: Request, client_ip: str) -> bool:
        """Check for suspicious request patterns."""
        url_path = str(request.url.path).lower()
        query_string = str(request.url.query).lower()
        request.headers.get("User-Agent", "").lower()

        # Check URL for suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern in url_path or pattern in query_string:
                logger.critical(f"Suspicious pattern '{pattern}' detected from {client_ip}")

                # Immediately block suspicious clients
                client_stats = self.local_storage.get(client_ip)
                if client_stats:
                    client_stats.violations += 5  # Heavy penalty for suspicious patterns
                    if client_stats.violations >= self.ban_threshold:
                        # Permanent ban for repeat offenders
                        self.permanent_bans.add(client_ip)
                        logger.critical(f"PERMANENT BAN: {client_ip} - repeated violations")
                    else:
                        client_stats.blocked_until = datetime.utcnow() + timedelta(hours=24)

                await self._log_security_event(
                    "suspicious_pattern_detected",
                    client_ip,
                    request,
                    {"pattern": pattern, "url": url_path},
                )

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Access forbidden",
                )

        # Check for bot-like behavior
        return not await self._detect_bot_behavior(request, client_ip)

    async def _detect_bot_behavior(self, request: Request, client_ip: str) -> bool:
        """Detect potentially malicious bot behavior."""
        user_agent = request.headers.get("User-Agent", "").lower()

        # Common attack bot patterns
        bot_patterns = [
            "sqlmap",
            "nikto",
            "nessus",
            "openvas",
            "burp",
            "acunetix",
            "w3af",
            "skipfish",
            "gobuster",
            "dirb",
            "dirbuster",
            "wpscan",
            "masscan",
            "zmap",
            "curl/7.",
            "wget/",
            "python-requests",
        ]

        for pattern in bot_patterns:
            if pattern in user_agent:
                logger.warning(f"Potential attack bot detected: {user_agent} from {client_ip}")

                # Block attack bots immediately
                client_stats = self.local_storage.get(client_ip)
                if client_stats:
                    client_stats.blocked_until = datetime.utcnow() + timedelta(hours=24)
                    client_stats.violations += 10  # Heavy penalty

                await self._log_security_event(
                    "attack_bot_detected",
                    client_ip,
                    request,
                    {"user_agent": user_agent, "pattern": pattern},
                )

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Access forbidden",
                )

        return False

    async def _check_global_limit(self) -> bool:
        """Check global rate limit."""
        limit = self.rate_limits["global"]
        current_time = time.time()

        # Use Redis if available for distributed rate limiting
        if self.redis_client:
            try:
                key = f"global_rate_limit:{int(current_time // limit.period)}"
                current_count = await self.redis_client.incr(key)
                await self.redis_client.expire(key, limit.period)

                self._record_redis_success()  # H-2 fix: track success
                return current_count <= limit.requests
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                # H-2 fix: explicit degraded mode tracking
                self._record_redis_failure("global_rate_limit", e)
                # FAIL-SECURE: Redis failure = use 50% stricter fallback limits
                fallback_allowed = limit.requests // 2
                is_allowed = self.global_stats["total_requests"] < fallback_allowed
                logger.warning(
                    f"⚠️  Global rate limit using fallback (Redis unavailable). "
                    f"Allowed: {fallback_allowed}, Current: {self.global_stats['total_requests']}, "
                    f"Result: {'ALLOW' if is_allowed else 'DENY'}",
                    extra={"degraded_mode": True, "fallback_limit": fallback_allowed},
                )
                return is_allowed

    async def _check_ip_limit(self, client_stats: ClientStats, _endpoint_type: str) -> bool:
        """Check IP-based rate limit."""
        limit = self.rate_limits.get("per_ip", self.rate_limits["per_ip"])
        now = datetime.utcnow()

        # Count recent requests
        recent_requests = [
            req_time
            for req_time in client_stats.requests
            if (now - req_time).seconds < limit.period
        ]

        allowed_requests = limit.requests + limit.burst

        if len(recent_requests) >= allowed_requests:
            # Block the client
            client_stats.blocked_until = now + timedelta(seconds=limit.block_duration)
            client_stats.violations += 1

            logger.warning(
                f"IP rate limit exceeded for {client_stats.ip_address}: "
                f"{len(recent_requests)} requests in {limit.period}s",
            )

            await self._log_security_event(
                "ip_rate_limit_exceeded",
                client_stats.ip_address,
                None,
                {
                    "requests": len(recent_requests),
                    "limit": allowed_requests,
                    "period": limit.period,
                },
            )

            self.global_stats["blocked_requests"] += 1

            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Blocked for {limit.block_duration} seconds.",
                headers={"Retry-After": str(limit.block_duration)},
            )

        return True

    async def _check_user_limit(self, user_id: str, _endpoint_type: str) -> bool:
        """Check user-based rate limit."""
        if not self.redis_client:
            return True  # Skip if no Redis

        limit = self.rate_limits.get("per_user", self.rate_limits["per_user"])

        try:
            key = f"user_rate_limit:{user_id}:{int(time.time() // limit.period)}"
            current_count = await self.redis_client.incr(key)
            await self.redis_client.expire(key, limit.period)

            self._record_redis_success()  # H-2 fix: track success

            if current_count > limit.requests + limit.burst:
                logger.warning(f"User rate limit exceeded for {user_id}")

                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="User rate limit exceeded",
                    headers={"Retry-After": str(limit.period)},
                )

            return True

        except (KeyboardInterrupt, SystemExit):
            raise
        except HTTPException:
            # Re-raise HTTP exceptions (not Redis errors)
            raise
        except Exception as e:
            # H-2 fix: explicit degraded mode tracking
            self._record_redis_failure("user_rate_limit", e)
            # FAIL-SECURE: Redis failure = deny access for safety
            logger.error(
                f"❌ User rate limit check failed (FAIL-SECURE: denying access). User: {user_id}, Error: {e}",
                exc_info=True,
                extra={"user_id": user_id, "degraded_mode": True},
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable (degraded mode)",
                headers={"Retry-After": "30"},
            )

    async def _check_endpoint_limit(
        self, client_stats: ClientStats, endpoint_type: str, request: Request,
    ) -> bool:
        """Check endpoint-specific rate limits."""
        if endpoint_type == "default":
            return True

        limit = self.rate_limits.get(endpoint_type)
        if not limit:
            return True

        # Use Redis for endpoint-specific limits
        if self.redis_client:
            try:
                key = f"endpoint_limit:{endpoint_type}:{client_stats.ip_address}:{int(time.time() // limit.period)}"
                current_count = await self.redis_client.incr(key)
                await self.redis_client.expire(key, limit.period)

                self._record_redis_success()  # H-2 fix: track success

                if current_count > limit.requests:
                    logger.warning(
                        f"Endpoint rate limit exceeded: {endpoint_type} from {client_stats.ip_address}",
                    )

                    await self._log_security_event(
                        "endpoint_rate_limit_exceeded",
                        client_stats.ip_address,
                        request,
                        {
                            "endpoint_type": endpoint_type,
                            "requests": current_count,
                            "limit": limit.requests,
                        },
                    )

                    # For critical endpoints like login, block for longer
                    if endpoint_type in ["login", "register"]:
                        client_stats.blocked_until = datetime.utcnow() + timedelta(
                            seconds=limit.block_duration,
                        )
                        client_stats.violations += 5  # Heavy penalty for auth abuse

                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Rate limit exceeded for {endpoint_type}",
                        headers={"Retry-After": str(limit.period)},
                    )

                return True

            except (KeyboardInterrupt, SystemExit):
                raise
            except HTTPException:
                # Re-raise HTTP exceptions (not Redis errors)
                raise
            except Exception as e:
                # H-2 fix: explicit degraded mode tracking
                self._record_redis_failure("endpoint_rate_limit", e)
                # FAIL-SECURE: Redis failure = apply strict local block
                client_stats.blocked_until = datetime.utcnow() + timedelta(seconds=60)
                logger.error(
                    f"❌ Endpoint rate limit check failed (FAIL-SECURE: blocking client). "
                    f"Endpoint: {endpoint_type}, IP: {client_stats.ip_address}, Error: {e}",
                    exc_info=True,
                    extra={
                        "endpoint_type": endpoint_type,
                        "client_ip": client_stats.ip_address,
                        "degraded_mode": True,
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Service temporarily unavailable (degraded mode)",
                    headers={"Retry-After": "60"},
                )

        return True

    def _clean_old_requests(self, client_stats: ClientStats) -> None:
        """Clean old requests from client statistics."""
        now = datetime.utcnow()
        cutoff_time = now - timedelta(seconds=3600)  # Keep 1 hour of history

        # Remove old requests
        while client_stats.requests and client_stats.requests[0] < cutoff_time:
            client_stats.requests.popleft()

    async def _log_security_event(
        self,
        event_type: str,
        client_ip: str,
        request: Request | None,
        extra_data: dict[str, Any] = None,
    ) -> None:
        """Log security event for audit purposes."""
        event_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "client_ip": client_ip,
            "extra_data": extra_data or {},
        }

        if request:
            event_data.update(
                {
                    "method": request.method,
                    "url": str(request.url),
                    "user_agent": request.headers.get("User-Agent", ""),
                    "referer": request.headers.get("Referer", ""),
                },
            )

        # TODO: Integrate with SecurityAuditLogger
        logger.info(f"Security event: {event_type}", extra=event_data)

    def get_statistics(self) -> dict[str, Any]:
        """Get rate limiting statistics."""
        active_blocks = sum(
            1
            for stats in self.local_storage.values()
            if stats.blocked_until and datetime.utcnow() < stats.blocked_until
        )

        return {
            "total_requests": self.global_stats["total_requests"],
            "blocked_requests": self.global_stats["blocked_requests"],
            "unique_clients": len(self.global_stats["unique_clients"]),
            "active_blocks": active_blocks,
            "clients_tracked": len(self.local_storage),
            "top_violators": [
                {
                    "ip": stats.ip_address,
                    "violations": stats.violations,
                    "total_requests": stats.total_requests,
                }
                for stats in sorted(
                    self.local_storage.values(), key=lambda s: s.violations, reverse=True,
                )[:10]
            ],
            # H-2 fix: Redis health visibility for operations
            "redis_health": {
                "available": self.redis_health["is_available"],
                "degraded_mode": self.redis_health["degraded_mode_active"],
                "failure_count": self.redis_health["failure_count"],
                "consecutive_failures": self.redis_health["consecutive_failures"],
                "last_failure": (
                    self.redis_health["last_failure_time"].isoformat()
                    if self.redis_health["last_failure_time"]
                    else None
                ),
            },
        }


class DDoSProtection:
    """Advanced DDoS protection system.
    "……分散攻撃は最も危険です……必ず阻止します……"
    """

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.traffic_analyzer = TrafficAnalyzer()
        self.auto_block_enabled = True

        # DDoS detection thresholds
        self.thresholds = {
            "requests_per_second": 100,  # Requests per second
            "unique_ips_spike": 1000,  # Sudden increase in unique IPs
            "error_rate_threshold": 0.5,  # 50% error rate
            "bandwidth_threshold": 100,  # MB/s (if tracking bandwidth)
        }

    async def analyze_traffic(self, request: Request) -> bool:
        """Analyze traffic for DDoS patterns.

        Args:
            request: Incoming request

        Returns:
            True if traffic is normal, False if attack detected

        """
        datetime.utcnow()
        client_ip = self.rate_limiter._get_client_ip(request)

        # Update traffic analyzer
        await self.traffic_analyzer.record_request(client_ip, request)

        # Check for various DDoS patterns
        checks = [
            self._check_request_flood(),
            self._check_ip_diversity_attack(),
            self._check_error_rate_attack(),
            self._check_slowloris_attack(request),
        ]

        # If any check fails, it's likely a DDoS
        for check_name, is_attack in checks:
            if is_attack:
                await self._handle_ddos_detection(check_name, client_ip, request)
                return False

        return True

    async def _check_request_flood(self) -> tuple[str, bool]:
        """Check for request flood attacks."""
        stats = self.traffic_analyzer.get_current_stats()
        rps = stats.get("requests_per_second", 0)

        if rps > self.thresholds["requests_per_second"]:
            logger.critical(f"Request flood detected: {rps} requests/second")
            return "request_flood", True

        return "request_flood", False

    async def _check_ip_diversity_attack(self) -> tuple[str, bool]:
        """Check for distributed attacks with many IPs."""
        stats = self.traffic_analyzer.get_current_stats()
        unique_ips = stats.get("unique_ips_last_minute", 0)
        baseline = stats.get("baseline_unique_ips", 50)

        # Check for sudden spike in unique IPs (potential botnet)
        if unique_ips > baseline * 5 and unique_ips > 100:
            logger.critical(f"IP diversity attack detected: {unique_ips} unique IPs")
            return "ip_diversity_attack", True

        return "ip_diversity_attack", False

    async def _check_error_rate_attack(self) -> tuple[str, bool]:
        """Check for attacks causing high error rates."""
        stats = self.traffic_analyzer.get_current_stats()
        error_rate = stats.get("error_rate", 0)

        if error_rate > self.thresholds["error_rate_threshold"]:
            logger.warning(f"High error rate detected: {error_rate:.2%}")
            return "error_rate_attack", True

        return "error_rate_attack", False

    async def _check_slowloris_attack(self, request: Request) -> tuple[str, bool]:
        """Check for Slowloris-style attacks."""
        # Check for incomplete requests or very slow connections
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                # Suspiciously large content length
                if length > 10 * 1024 * 1024:  # 10MB
                    logger.warning(f"Suspicious large content-length: {length}")
                    return "slowloris_attack", True
            except ValueError:
                pass

        return "slowloris_attack", False

    async def _handle_ddos_detection(
        self, attack_type: str, client_ip: str, request: Request,
    ) -> None:
        """Handle detected DDoS attack."""
        logger.critical(f"DDoS attack detected: {attack_type} from {client_ip}")

        if self.auto_block_enabled:
            # Block the offending IP for extended period
            client_stats = self.rate_limiter.local_storage.get(client_ip)
            if client_stats:
                client_stats.blocked_until = datetime.utcnow() + timedelta(hours=24)
                client_stats.violations += 100  # Massive penalty

            # TODO: Integrate with firewall/iptables for network-level blocking
            await self._network_level_block(client_ip, attack_type)

        # Log security event
        await self.rate_limiter._log_security_event(
            f"ddos_{attack_type}", client_ip, request, {"auto_blocked": self.auto_block_enabled},
        )

    async def _network_level_block(self, ip_address: str, attack_type: str) -> None:
        """Implement network-level blocking (placeholder)."""
        # TODO: Implement integration with:
        # - iptables/firewall rules
        # - Cloud provider DDoS protection (AWS Shield, Cloudflare)
        # - Load balancer blocking rules
        logger.info(f"Network-level block requested for {ip_address} ({attack_type})")


class TrafficAnalyzer:
    """Analyze traffic patterns for DDoS detection."""

    def __init__(self):
        self.request_history = deque(maxlen=1000)  # Last 1000 requests
        self.ip_history = deque(maxlen=5000)  # Last 5000 unique IPs
        self.error_history = deque(maxlen=500)  # Last 500 errors

    async def record_request(self, client_ip: str, request: Request) -> None:
        """Record request for analysis."""
        now = datetime.utcnow()

        self.request_history.append(
            {
                "timestamp": now,
                "ip": client_ip,
                "method": request.method,
                "path": request.url.path,
                "user_agent": request.headers.get("User-Agent", ""),
            },
        )

        self.ip_history.append({"timestamp": now, "ip": client_ip})

    def get_current_stats(self) -> dict[str, Any]:
        """Get current traffic statistics."""
        now = datetime.utcnow()
        one_minute_ago = now - timedelta(minutes=1)

        # Recent requests
        recent_requests = [r for r in self.request_history if r["timestamp"] > one_minute_ago]

        # Recent unique IPs
        recent_ips = {r["ip"] for r in recent_requests}

        # Calculate requests per second
        rps = len(recent_requests) / 60 if recent_requests else 0

        return {
            "requests_per_second": rps,
            "unique_ips_last_minute": len(recent_ips),
            "total_requests_last_minute": len(recent_requests),
            "baseline_unique_ips": 50,  # TODO: Calculate dynamic baseline
            "error_rate": 0,  # TODO: Calculate from error_history
        }
