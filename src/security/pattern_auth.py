"""
Pattern Execution Authentication and Authorization
Addresses Hestia's CRITICAL finding: No authentication on pattern execution

Security Model:
- Agent-based authentication (JWT tokens)
- Pattern-level permissions
- Rate limiting per agent
- Audit logging of all pattern executions
"""

import logging
import time
from dataclasses import dataclass
from datetime import datetime

from ..core.exceptions import AuthenticationException, AuthorizationException
from ..security.jwt_service import jwt_service

logger = logging.getLogger(__name__)


@dataclass
class PatternPermission:
    """Permission required to execute a pattern"""

    pattern_name: str
    required_role: str  # 'admin', 'agent', 'readonly'
    allowed_agents: set[str]  # Empty = all agents allowed
    rate_limit_per_minute: int = 60

    def is_allowed(self, agent_id: str, agent_role: str) -> bool:
        """Check if agent is allowed to execute this pattern"""
        # Check role requirement
        role_hierarchy = {"admin": 3, "agent": 2, "readonly": 1}
        if role_hierarchy.get(agent_role, 0) < role_hierarchy.get(self.required_role, 0):
            return False

        # Check agent whitelist (empty means all allowed)
        if self.allowed_agents and agent_id not in self.allowed_agents:
            return False

        return True


class PatternAuthManager:
    """
    Manages authentication and authorization for pattern execution

    Security Features:
    - JWT token validation
    - Pattern-level permissions
    - Rate limiting per agent
    - Audit logging
    """

    def __init__(self):
        self.permissions: dict[str, PatternPermission] = {}
        self.rate_limit_cache: dict[str, list[float]] = {}
        self._load_default_permissions()

    def _load_default_permissions(self):
        """Load default pattern permissions (conservative defaults)"""
        # Infrastructure patterns - agent role required
        self.permissions["health_check"] = PatternPermission(
            pattern_name="health_check",
            required_role="readonly",
            allowed_agents=set(),  # All agents
            rate_limit_per_minute=120,
        )

        # Memory patterns - agent role required, more restrictive
        self.permissions["semantic_search"] = PatternPermission(
            pattern_name="semantic_search",
            required_role="agent",
            allowed_agents=set(),
            rate_limit_per_minute=60,
        )

        self.permissions["store_memory"] = PatternPermission(
            pattern_name="store_memory",
            required_role="agent",
            allowed_agents=set(),
            rate_limit_per_minute=30,
        )

        # Hybrid patterns - admin role for sensitive operations
        self.permissions["system_analysis"] = PatternPermission(
            pattern_name="system_analysis",
            required_role="admin",
            allowed_agents=set(),
            rate_limit_per_minute=10,
        )

    async def authenticate_request(self, token: str, pattern_name: str) -> dict[str, str]:
        """
        Authenticate and authorize pattern execution request

        Args:
            token: JWT token from request
            pattern_name: Pattern to execute

        Returns:
            Dict with agent_id and agent_role

        Raises:
            AuthenticationException: Invalid token
            AuthorizationException: Insufficient permissions
        """
        # 1. Validate JWT token
        try:
            payload = jwt_service.decode_token(token)
            agent_id = payload.get("sub")
            agent_role = payload.get("role", "readonly")

            if not agent_id:
                raise AuthenticationException("Invalid token: missing agent_id")

        except Exception as e:
            logger.error(f"JWT validation failed: {e}")
            raise AuthenticationException(f"Token validation failed: {e}")

        # 2. Check pattern permissions
        permission = self.permissions.get(pattern_name)
        if not permission:
            # Pattern not registered - deny by default (fail-secure)
            logger.warning(f"Pattern {pattern_name} has no permissions defined")
            raise AuthorizationException(f"Pattern {pattern_name} not registered for execution")

        if not permission.is_allowed(agent_id, agent_role):
            logger.warning(f"Agent {agent_id} (role: {agent_role}) denied access to {pattern_name}")
            raise AuthorizationException(f"Insufficient permissions for pattern {pattern_name}")

        # 3. Check rate limiting
        if not self._check_rate_limit(agent_id, pattern_name, permission):
            logger.warning(f"Rate limit exceeded for {agent_id} on {pattern_name}")
            raise AuthorizationException(f"Rate limit exceeded for pattern {pattern_name}")

        # 4. Audit log
        await self._log_pattern_access(agent_id, pattern_name, "ALLOWED")

        return {"agent_id": agent_id, "agent_role": agent_role}

    def _check_rate_limit(
        self, agent_id: str, pattern_name: str, permission: PatternPermission
    ) -> bool:
        """Check if agent is within rate limits"""
        key = f"{agent_id}:{pattern_name}"
        now = time.time()
        window_start = now - 60  # 1 minute window

        # Get or create request history
        if key not in self.rate_limit_cache:
            self.rate_limit_cache[key] = []

        # Remove old requests outside window
        self.rate_limit_cache[key] = [ts for ts in self.rate_limit_cache[key] if ts > window_start]

        # Check limit
        if len(self.rate_limit_cache[key]) >= permission.rate_limit_per_minute:
            return False

        # Record this request
        self.rate_limit_cache[key].append(now)
        return True

    async def _log_pattern_access(self, agent_id: str, pattern_name: str, result: str):
        """Log pattern access for audit trail"""
        logger.info(
            f"PATTERN_ACCESS: agent={agent_id} pattern={pattern_name} "
            f"result={result} timestamp={datetime.utcnow().isoformat()}"
        )

    def register_pattern_permission(self, permission: PatternPermission):
        """Register a new pattern permission"""
        self.permissions[permission.pattern_name] = permission
        logger.info(f"Registered permission for pattern: {permission.pattern_name}")

    def update_agent_permissions(self, pattern_name: str, allowed_agents: set[str]):
        """Update allowed agents for a pattern"""
        if pattern_name in self.permissions:
            self.permissions[pattern_name].allowed_agents = allowed_agents
            logger.info(
                f"Updated permissions for {pattern_name}: {len(allowed_agents)} agents allowed"
            )


# Singleton instance
pattern_auth_manager = PatternAuthManager()
