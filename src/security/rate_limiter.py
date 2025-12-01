"""Rate Limiting and DDoS Protection Module
Hestia's Paranoid Traffic Control System

"……大量のリクエストは必ず攻撃です……全て制限します……"

v2.4.3: Redis removed - using local in-memory rate limiting only
v2.4.4: Fixed time calculation bug (.seconds → .total_seconds()),
        added periodic cache cleanup, single-instance documentation

IMPORTANT: Single-Instance Deployment Only
==========================================
This rate limiter uses in-memory storage and is designed for single-instance
deployments only. In a distributed environment (multiple instances behind a
load balancer), each instance maintains separate rate limit counters, which:

1. Allows clients to exceed rate limits by distributing requests across instances
2. Creates inconsistent blocking behavior across instances
3. May cause memory duplication across instances

For distributed deployments, use a centralized rate limiting solution:
- Redis-based rate limiting (recommended)
- API Gateway rate limiting (AWS API Gateway, Kong, etc.)
- Cloud provider DDoS protection (AWS Shield, Cloudflare)

Configuration:
- TMWS_USE_SLIDING_WINDOW: Enable sliding window rate limiting (default: False)
- Sliding window provides more accurate rate limiting but has slightly higher CPU cost
"""

import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from fastapi import HTTPException, Request, status

from ..core.config import get_settings
from ..security.security_audit_facade import get_audit_logger

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
    """Advanced rate limiting system with local in-memory storage.

    v2.4.3: Simplified to local-only rate limiting (Redis removed).
    Hestia's Rule: 99.7% of attacks use excessive request patterns.
    """

    def __init__(self):
        """Initialize rate limiter with local storage only."""
        self.settings = get_settings()
        self.local_storage: dict[str, ClientStats] = {}
        self.global_stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "unique_clients": set(),
        }

        # v2.4.4: Periodic cache cleanup tracking
        self._last_cleanup: datetime = datetime.utcnow()
        self._cleanup_interval: int = getattr(self.settings, "rate_limit_cleanup_interval", 300)
        self._cache_ttl: int = getattr(self.settings, "rate_limit_cache_ttl", 3600)

        # v2.4.4: Thread-safety for cleanup (Hestia security requirement)
        self._cleanup_lock = threading.Lock()
        self._stats_lock = threading.RLock()

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
                # Phase 1 Memory Management (v2.4.0)
                "memory_cleanup": RateLimit(
                    5, 60, block_duration=300,
                ),  # 5 cleanup calls per minute, 5min block
                "memory_prune": RateLimit(
                    5, 60, block_duration=300,
                ),  # 5 prune calls per minute, 5min block
                "memory_ttl": RateLimit(
                    30, 60, block_duration=60,
                ),  # 30 TTL updates per minute, 1min block
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
                # Phase 1 Memory Management (v2.4.0)
                "memory_cleanup": RateLimit(
                    10, 60, block_duration=180,
                ),  # 10 cleanup calls per minute, 3min block
                "memory_prune": RateLimit(
                    10, 60, block_duration=180,
                ),  # 10 prune calls per minute, 3min block
                "memory_ttl": RateLimit(
                    60, 60, block_duration=30,
                ),  # 60 TTL updates per minute, 30s block
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

        # User rate limit tracking (in-memory)
        self.user_rate_limits: dict[str, deque] = {}

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
        """Internal rate limit check implementation."""
        client_ip = self._get_client_ip(request)
        now = datetime.utcnow()

        # v2.4.4: Periodic cleanup to prevent memory leaks
        self._cleanup_old_stats()

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
        """Check global rate limit using local counter."""
        limit = self.rate_limits["global"]

        # Simple global counter (resets periodically via cleanup)
        return self.global_stats["total_requests"] < limit.requests

    async def _check_ip_limit(self, client_stats: ClientStats, _endpoint_type: str) -> bool:
        """Check IP-based rate limit."""
        limit = self.rate_limits.get("per_ip", self.rate_limits["per_ip"])
        now = datetime.utcnow()

        # Count recent requests (v2.4.4: fixed .seconds → .total_seconds() bug)
        recent_requests = [
            req_time
            for req_time in client_stats.requests
            if (now - req_time).total_seconds() < limit.period
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
        """Check user-based rate limit using local storage."""
        limit = self.rate_limits.get("per_user", self.rate_limits["per_user"])
        now = datetime.utcnow()

        # Get or create user's request history
        if user_id not in self.user_rate_limits:
            self.user_rate_limits[user_id] = deque(maxlen=1000)

        user_requests = self.user_rate_limits[user_id]

        # Count recent requests (v2.4.4: fixed .seconds → .total_seconds() bug)
        recent_count = sum(
            1 for req_time in user_requests
            if (now - req_time).total_seconds() < limit.period
        )

        if recent_count >= limit.requests + limit.burst:
            logger.warning(f"User rate limit exceeded for {user_id}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="User rate limit exceeded",
                headers={"Retry-After": str(limit.period)},
            )

        # Record this request
        user_requests.append(now)
        return True

    async def _check_endpoint_limit(
        self, client_stats: ClientStats, endpoint_type: str, request: Request,
    ) -> bool:
        """Check endpoint-specific rate limits using local storage."""
        if endpoint_type == "default":
            return True

        limit = self.rate_limits.get(endpoint_type)
        if not limit:
            return True

        now = datetime.utcnow()

        # Use client's request history for endpoint-specific limits
        # v2.4.4: fixed .seconds → .total_seconds() bug
        recent_requests = [
            req_time
            for req_time in client_stats.requests
            if (now - req_time).total_seconds() < limit.period
        ]

        if len(recent_requests) >= limit.requests:
            logger.warning(
                f"Endpoint rate limit exceeded: {endpoint_type} from {client_stats.ip_address}",
            )

            await self._log_security_event(
                "endpoint_rate_limit_exceeded",
                client_stats.ip_address,
                request,
                {
                    "endpoint_type": endpoint_type,
                    "requests": len(recent_requests),
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

    def _clean_old_requests(self, client_stats: ClientStats) -> None:
        """Clean old requests from client statistics."""
        now = datetime.utcnow()
        cutoff_time = now - timedelta(seconds=self._cache_ttl)

        # Remove old requests
        while client_stats.requests and client_stats.requests[0] < cutoff_time:
            client_stats.requests.popleft()

    def _cleanup_old_stats(self) -> int:
        """v2.4.4: Periodic cleanup of old client statistics to prevent memory leaks.

        This method removes client stats that have been inactive for longer than
        the configured cache TTL. It runs at most once per cleanup interval.

        Thread-safety: Uses _cleanup_lock to prevent double cleanup, and
        _stats_lock to protect dictionary modifications (Hestia security requirement).

        Returns:
            int: Number of clients removed during cleanup
        """
        now = datetime.utcnow()

        # Quick check without lock (optimization)
        if (now - self._last_cleanup).total_seconds() < self._cleanup_interval:
            return 0

        # Try to acquire cleanup lock (non-blocking to avoid deadlock)
        if not self._cleanup_lock.acquire(blocking=False):
            # Another thread is cleaning up, skip
            return 0

        try:
            # Double-check inside lock (another thread may have cleaned up)
            if (now - self._last_cleanup).total_seconds() < self._cleanup_interval:
                return 0

            # Update last cleanup time
            self._last_cleanup = now
            cutoff_time = now - timedelta(seconds=self._cache_ttl)

            # Find stale clients (read under stats lock)
            with self._stats_lock:
                clients_to_remove = []
                for client_ip, stats in self.local_storage.items():
                    # Remove if no recent activity
                    if stats.last_seen < cutoff_time:
                        clients_to_remove.append(client_ip)
                    # Also check if blocked_until has expired (allow re-entry)
                    elif stats.blocked_until and stats.blocked_until < now:
                        # Don't remove, just clear the block
                        stats.blocked_until = None

                # Remove stale clients (still under lock)
                for client_ip in clients_to_remove:
                    del self.local_storage[client_ip]

                # Also cleanup user rate limits
                user_cutoff = now - timedelta(seconds=self._cache_ttl)
                users_to_remove = []
                for user_id, requests in self.user_rate_limits.items():
                    if requests and requests[-1] < user_cutoff:
                        users_to_remove.append(user_id)
                for user_id in users_to_remove:
                    del self.user_rate_limits[user_id]

            if clients_to_remove or users_to_remove:
                logger.info(
                    f"Rate limiter cleanup: removed {len(clients_to_remove)} clients, "
                    f"{len(users_to_remove)} users",
                )

            return len(clients_to_remove)
        finally:
            self._cleanup_lock.release()

    def _determine_severity(self, event_type: str) -> str:
        """Determine severity level based on event type."""
        critical_events = ["permanent_ban", "ddos_attack", "attack_bot_detected"]
        high_events = ["rate_limit_exceeded", "suspicious_pattern", "temporary_ban"]

        if event_type in critical_events:
            return "CRITICAL"
        elif event_type in high_events:
            return "HIGH"
        else:
            return "MEDIUM"

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

        # Log to standard logger
        logger.info(f"Security event: {event_type}", extra=event_data)

        # Integrate with SecurityAuditFacade
        try:
            audit_logger = await get_audit_logger()
            await audit_logger.log_event(
                event_type=event_type,
                event_data={
                    "severity": self._determine_severity(event_type),
                    "message": f"Rate limiter event: {event_type}",
                    "endpoint": str(request.url) if request else None,
                    "method": request.method if request else None,
                    "user_agent": request.headers.get("User-Agent") if request else None,
                    "blocked": True,  # Rate limit events are always blocked
                    "details": extra_data or {},
                },
                ip_address=client_ip,
            )
        except Exception as e:
            logger.error(f"Failed to log security event to audit logger: {e}", exc_info=True)

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
        """Analyze traffic for DDoS patterns."""
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
