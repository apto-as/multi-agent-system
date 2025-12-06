"""MCP Rate Limiting for TMWS v2.4.3.

Provides rate limiting for MCP tool invocations to prevent DoS attacks.
Implements Hestia's REQ-4 security requirement.

Security Architecture:
- REQ-4: Tool-specific rate limits (stricter for dangerous operations)
- Local in-memory rate limiting (v2.4.3: Redis removed)
- Security audit logging for all violations

Pattern:
    @require_mcp_rate_limit("prune_expired_memories")
    async def prune_expired_memories(...):
        # Tool implementation
"""

import functools
import logging
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from ..security.mcp_auth import MCPAuthContext, MCPAuthorizationError
from ..security.rate_limiter import RateLimit, RateLimiter

logger = logging.getLogger(__name__)


# REQ-4: MCP Tool Rate Limits
# Hestia's Paranoid Configuration: Strict limits for dangerous operations
MCP_RATE_LIMITS = {
    # Memory operations: Moderate limits
    "store_memory": RateLimit(
        requests=60,  # 60 creates per minute
        period=60,
        burst=10,
        block_duration=300,  # 5 minutes
    ),
    "search_memories": RateLimit(
        requests=30,  # 30 searches per minute
        period=60,
        burst=5,
        block_duration=60,  # 1 minute
    ),
    "get_memory": RateLimit(
        requests=100,  # 100 reads per minute
        period=60,
        burst=20,
        block_duration=60,
    ),
    # Expiration operations: Strict limits (REQ-4)
    "prune_expired_memories": RateLimit(
        requests=5,  # 5 deletion operations per hour
        period=3600,  # 1 hour
        burst=0,  # No burst allowed for deletions
        block_duration=3600,  # 1 hour block
    ),
    "get_expiration_stats": RateLimit(
        requests=30,  # 30 stats queries per minute
        period=60,
        burst=5,
        block_duration=60,
    ),
    "set_memory_ttl": RateLimit(
        requests=30,  # 30 TTL updates per minute
        period=60,
        burst=5,
        block_duration=300,
    ),
    # Namespace operations: Very strict (REQ-4)
    "cleanup_namespace": RateLimit(
        requests=2,  # 2 namespace cleanups per day
        period=86400,  # 24 hours
        burst=0,  # No burst for mass deletion
        block_duration=86400,  # 24 hour block
    ),
    "get_namespace_stats": RateLimit(
        requests=20,  # 20 stats queries per minute
        period=60,
        burst=5,
        block_duration=60,
    ),
    # Scheduler operations: Admin-only strict limits (REQ-4)
    "get_scheduler_status": RateLimit(
        requests=60,  # 60 status checks per minute
        period=60,
        burst=10,
        block_duration=60,
    ),
    "configure_scheduler": RateLimit(
        requests=3,  # 3 config changes per hour (admin only)
        period=3600,
        burst=0,  # No burst for config changes
        block_duration=1800,  # 30 minutes
    ),
    "start_scheduler": RateLimit(
        requests=5,  # 5 starts per hour (admin only)
        period=3600,
        burst=0,
        block_duration=1800,
    ),
    "stop_scheduler": RateLimit(
        requests=2,  # 2 stops per day (admin only)
        period=86400,  # 24 hours
        burst=0,  # No burst for service interruption
        block_duration=3600,  # 1 hour
    ),
    "trigger_scheduler": RateLimit(
        requests=10,  # 10 manual triggers per hour
        period=3600,
        burst=0,
        block_duration=1800,
    ),
    # Skill operations: MCP-first (v2.4.7)
    "skill_list": RateLimit(
        requests=60,  # 60 list operations per minute
        period=60,
        burst=10,
        block_duration=60,
    ),
    "skill_get": RateLimit(
        requests=120,  # 120 reads per minute
        period=60,
        burst=20,
        block_duration=60,
    ),
    "skill_create": RateLimit(
        requests=10,  # 10 creates per hour
        period=3600,
        burst=2,
        block_duration=1800,  # 30 minutes
    ),
    "skill_update": RateLimit(
        requests=30,  # 30 updates per hour
        period=3600,
        burst=5,
        block_duration=600,  # 10 minutes
    ),
    "skill_delete": RateLimit(
        requests=5,  # 5 deletes per hour
        period=3600,
        burst=0,  # No burst for deletions
        block_duration=1800,  # 30 minutes
    ),
    "skill_share": RateLimit(
        requests=20,  # 20 shares per hour
        period=3600,
        burst=3,
        block_duration=600,
    ),
    "skill_activate": RateLimit(
        requests=20,  # 20 activations per hour
        period=3600,
        burst=3,
        block_duration=600,
    ),
    "skill_deactivate": RateLimit(
        requests=20,  # 20 deactivations per hour
        period=3600,
        burst=3,
        block_duration=600,
    ),
    # Agent operations: MCP-first (v2.4.7)
    "agent_list": RateLimit(
        requests=60,  # 60 list operations per minute
        period=60,
        burst=10,
        block_duration=60,
    ),
    "agent_get": RateLimit(
        requests=120,  # 120 reads per minute
        period=60,
        burst=20,
        block_duration=60,
    ),
    "agent_search": RateLimit(
        requests=30,  # 30 searches per minute
        period=60,
        burst=5,
        block_duration=120,
    ),
    "agent_register": RateLimit(
        requests=5,  # 5 registrations per hour
        period=3600,
        burst=1,
        block_duration=1800,  # 30 minutes
    ),
    "agent_update": RateLimit(
        requests=30,  # 30 updates per hour
        period=3600,
        burst=5,
        block_duration=600,
    ),
    "agent_deactivate": RateLimit(
        requests=5,  # 5 deactivations per hour
        period=3600,
        burst=0,  # No burst for status changes
        block_duration=1800,
    ),
    "agent_activate": RateLimit(
        requests=10,  # 10 activations per hour
        period=3600,
        burst=2,
        block_duration=600,
    ),
    "agent_stats": RateLimit(
        requests=60,  # 60 stats queries per minute
        period=60,
        burst=10,
        block_duration=60,
    ),
    "agent_recommend": RateLimit(
        requests=30,  # 30 recommendations per minute
        period=60,
        burst=5,
        block_duration=120,
    ),
    # Pattern-to-Skill operations: v2.4.12 (REQ-4)
    "pattern_skill_find": RateLimit(
        requests=60,  # 60 find operations per minute
        period=60,
        burst=10,
        block_duration=60,
    ),
    "pattern_skill_promote": RateLimit(
        requests=10,  # 10 promotions per hour (creates skills)
        period=3600,
        burst=2,
        block_duration=1800,  # 30 minutes
    ),
    "pattern_skill_batch": RateLimit(
        requests=5,  # 5 batch promotions per hour
        period=3600,
        burst=0,  # No burst for batch operations
        block_duration=1800,  # 30 minutes
    ),
    "pattern_skill_status": RateLimit(
        requests=60,  # 60 status checks per minute
        period=60,
        burst=10,
        block_duration=60,
    ),
}


class MCPRateLimiter:
    """Rate limiter for MCP tool invocations.

    Security (REQ-4):
    - Per-agent, per-tool rate limiting
    - Local in-memory limits (v2.4.3: Redis removed)
    - Audit logging for violations

    Thread-safety: Service is stateless and thread-safe.
    """

    def __init__(self, rate_limiter: RateLimiter | None = None):
        """Initialize MCP rate limiter.

        Args:
            rate_limiter: Optional existing RateLimiter instance.
                         If None, creates a new instance.
        """
        self.rate_limiter = rate_limiter or RateLimiter()
        self.rate_limits = MCP_RATE_LIMITS.copy()

        # Local counters for rate limiting
        self.local_counters: dict[str, dict[str, Any]] = {}

    async def check_rate_limit(
        self,
        context: MCPAuthContext,
        tool_name: str,
    ) -> None:
        """Check rate limit for MCP tool invocation.

        Args:
            context: Authenticated MCP context
            tool_name: Name of MCP tool being invoked

        Raises:
            MCPAuthorizationError: If rate limit exceeded

        Security Pattern:
            FAIL-SECURE - Deny on any error
        """
        # Get rate limit for tool
        limit = self.rate_limits.get(tool_name)

        if not limit:
            # Tool not in rate limit config -> Allow (but log)
            logger.debug(
                f"No rate limit configured for MCP tool: {tool_name}",
                extra={"tool_name": tool_name, "agent_id": context.agent_id},
            )
            return

        # Check local rate limit
        await self._check_local_limit(
            context=context,
            tool_name=tool_name,
            limit=limit,
        )

    async def _check_local_limit(
        self,
        context: MCPAuthContext,
        tool_name: str,
        limit: RateLimit,
    ) -> None:
        """Check rate limit using local counters.

        Args:
            context: MCP auth context
            tool_name: Tool name
            limit: Rate limit config

        Raises:
            MCPAuthorizationError: If rate limit exceeded
        """
        # Create counter key
        counter_key = f"{tool_name}:{context.agent_id}"

        # Get or create counter
        if counter_key not in self.local_counters:
            self.local_counters[counter_key] = {
                "count": 0,
                "window_start": datetime.utcnow(),
            }

        counter = self.local_counters[counter_key]
        now = datetime.utcnow()

        # Check if window expired
        if now - counter["window_start"] > timedelta(seconds=limit.period):
            # Reset counter for new window
            counter["count"] = 0
            counter["window_start"] = now

        # Increment counter
        counter["count"] += 1
        current_count = counter["count"]

        # Calculate effective limit
        effective_limit = limit.requests + limit.burst

        logger.debug(
            (
                f"MCP rate limit check: {tool_name} for {context.agent_id}: "
                f"{current_count}/{effective_limit}"
            ),
            extra={
                "tool_name": tool_name,
                "agent_id": context.agent_id,
                "current_count": current_count,
                "limit": effective_limit,
            },
        )

        # Check if limit exceeded
        if current_count > effective_limit:
            await self._handle_rate_limit_exceeded(
                context=context,
                tool_name=tool_name,
                limit=limit,
                current_count=current_count,
            )

    async def _handle_rate_limit_exceeded(
        self,
        context: MCPAuthContext,
        tool_name: str,
        limit: RateLimit,
        current_count: int,
    ) -> None:
        """Handle rate limit exceeded event.

        Args:
            context: MCP auth context
            tool_name: Tool name
            limit: Rate limit config
            current_count: Current request count

        Raises:
            MCPAuthorizationError: Always (rate limit exceeded)

        Security:
            - Audit log violation
            - Provide clear error message with retry guidance
        """
        # Security audit log
        total_limit = limit.requests + limit.burst
        logger.warning(
            (
                f"MCP rate limit exceeded: tool={tool_name}, agent={context.agent_id}, "
                f"count={current_count}/{total_limit}"
            ),
            extra={
                "tool_name": tool_name,
                "agent_id": context.agent_id,
                "namespace": context.namespace,
                "current_count": current_count,
                "limit": total_limit,
                "period": limit.period,
                "block_duration": limit.block_duration,
                "event_type": "mcp_rate_limit_exceeded",
            },
        )

        # Calculate retry-after
        retry_after = limit.block_duration

        # Raise authorization error
        total_limit_val = limit.requests + limit.burst
        raise MCPAuthorizationError(
            (
                f"Rate limit exceeded for {tool_name}: {current_count}/{total_limit_val} "
                f"requests in {limit.period}s. Retry after {retry_after}s."
            ),
            details={
                "tool_name": tool_name,
                "agent_id": context.agent_id,
                "current_count": current_count,
                "limit": total_limit_val,
                "period": limit.period,
                "retry_after": retry_after,
            },
        )

    def get_remaining_requests(
        self,
        agent_id: str,
        tool_name: str,
    ) -> dict[str, Any]:
        """Get remaining requests for agent/tool.

        Args:
            agent_id: Agent ID
            tool_name: Tool name

        Returns:
            Dict with remaining requests, limit, and reset time
        """
        limit = self.rate_limits.get(tool_name)

        if not limit:
            return {
                "tool_name": tool_name,
                "agent_id": agent_id,
                "limit": None,
                "remaining": None,
                "reset_at": None,
            }

        # Check local counter
        counter_key = f"{tool_name}:{agent_id}"
        counter = self.local_counters.get(counter_key)

        if not counter:
            return {
                "tool_name": tool_name,
                "agent_id": agent_id,
                "limit": limit.requests + limit.burst,
                "remaining": limit.requests + limit.burst,
                "reset_at": None,
            }

        current_count = counter["count"]
        remaining = max(0, (limit.requests + limit.burst) - current_count)
        reset_at = counter["window_start"] + timedelta(seconds=limit.period)

        return {
            "tool_name": tool_name,
            "agent_id": agent_id,
            "limit": limit.requests + limit.burst,
            "remaining": remaining,
            "reset_at": reset_at.isoformat(),
        }


# Global MCP rate limiter instance
_mcp_rate_limiter: MCPRateLimiter | None = None


def get_mcp_rate_limiter() -> MCPRateLimiter:
    """Get global MCP rate limiter instance.

    Returns:
        Global MCPRateLimiter instance
    """
    global _mcp_rate_limiter
    if _mcp_rate_limiter is None:
        _mcp_rate_limiter = MCPRateLimiter()
    return _mcp_rate_limiter


def require_mcp_rate_limit(tool_name: str) -> Callable:
    """Decorator to enforce rate limiting on MCP tools.

    Usage:
        @require_mcp_rate_limit("prune_expired_memories")
        async def prune_expired_memories(context: MCPAuthContext, ...):
            # Tool implementation

    Args:
        tool_name: Name of the MCP tool (must match MCP_RATE_LIMITS key)

    Returns:
        Decorator function

    Raises:
        MCPAuthorizationError: If rate limit exceeded
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Extract context from arguments
            context = None
            for arg in args:
                if isinstance(arg, MCPAuthContext):
                    context = arg
                    break

            if context is None:
                # Check kwargs
                context = kwargs.get("context")

            if context is None:
                # FAIL-SECURE: No context = deny
                logger.error(
                    f"MCP rate limit decorator: No MCPAuthContext found for {tool_name}",
                    extra={"tool_name": tool_name, "func": func.__name__},
                )
                raise MCPAuthorizationError(
                    f"Authentication required for {tool_name}",
                    details={"tool_name": tool_name},
                )

            # Check rate limit
            limiter = get_mcp_rate_limiter()
            await limiter.check_rate_limit(context, tool_name)

            # Execute tool
            return await func(*args, **kwargs)

        return wrapper

    return decorator
