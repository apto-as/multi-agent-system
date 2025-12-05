"""MCP Authentication & Authorization for TMWS v2.3.0.

Provides secure authentication and authorization for MCP tool invocations.
Implements Hestia's REQ-1, REQ-2, REQ-5 security requirements.

Security Architecture:
- REQ-1: Database-verified agent authentication (API key or JWT)
- REQ-2: P0-1 pattern namespace isolation (never trust client input)
- REQ-5: Role-based access control for privileged operations

Pattern:
    1. Authenticate agent (verify existence + credentials)
    2. Authorize namespace access (verify ownership)
    3. Check operation permission (verify role)
    4. Audit log all operations
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.agent import Agent, AgentStatus
from ..security.jwt_service import JWTService

logger = logging.getLogger(__name__)


class MCPAuthenticationError(Exception):
    """Raised when MCP authentication fails.

    Security: FAIL-SECURE - Always deny on auth failure.
    """

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        """Initialize with message and optional security context."""
        super().__init__(message)
        self.details = details or {}
        self.timestamp = datetime.now(timezone.utc)


class MCPAuthorizationError(Exception):
    """Raised when MCP authorization check fails.

    Security: FAIL-SECURE - Always deny on authz failure.
    """

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        """Initialize with message and optional security context."""
        super().__init__(message)
        self.details = details or {}
        self.timestamp = datetime.now(timezone.utc)


class MCPOperation(str, Enum):
    """MCP operations requiring authorization."""

    # Memory operations
    MEMORY_READ = "memory:read"
    MEMORY_WRITE = "memory:write"
    MEMORY_DELETE = "memory:delete"
    MEMORY_SHARE = "memory:share"

    # Namespace operations
    NAMESPACE_READ = "namespace:read"
    NAMESPACE_WRITE = "namespace:write"
    NAMESPACE_ADMIN = "namespace:admin"

    # Scheduler operations (REQ-5: Privileged)
    SCHEDULER_READ = "scheduler:read"
    SCHEDULER_CONFIGURE = "scheduler:configure"  # Admin only
    SCHEDULER_CONTROL = "scheduler:control"  # Admin only

    # Cleanup operations (REQ-5: Privileged)
    CLEANUP_NAMESPACE = "cleanup:namespace"  # Admin only
    CLEANUP_GLOBAL = "cleanup:global"  # Super admin only

    # Skill operations (v2.4.7: MCP-first)
    SKILL_READ = "skill:read"
    SKILL_WRITE = "skill:write"
    SKILL_DELETE = "skill:delete"
    SKILL_SHARE = "skill:share"
    SKILL_ACTIVATE = "skill:activate"
    SKILL_DEACTIVATE = "skill:deactivate"

    # Agent operations (v2.4.7: MCP-first)
    AGENT_READ = "agent:read"
    AGENT_WRITE = "agent:write"
    AGENT_DELETE = "agent:delete"
    AGENT_ADMIN = "agent:admin"  # For status changes, team management


class MCPRole(str, Enum):
    """MCP roles for RBAC (REQ-5)."""

    AGENT = "agent"  # Regular agent (default)
    NAMESPACE_ADMIN = "namespace_admin"  # Can manage own namespace
    SYSTEM_ADMIN = "system_admin"  # Can manage system (scheduler, global cleanup)
    SUPER_ADMIN = "super_admin"  # Full system access


@dataclass
class MCPAuthContext:
    """Authenticated MCP request context.

    Security: Immutable context with verified agent data.
    """

    agent_id: str
    namespace: str  # VERIFIED from database (P0-1 pattern)
    agent: Agent  # VERIFIED database record
    role: MCPRole
    tool_name: str
    request_id: str
    timestamp: datetime
    auth_method: str  # "api_key" or "jwt"


class MCPAuthService:
    """MCP authentication and authorization service.

    Security Requirements:
    - REQ-1: Database-verified authentication
    - REQ-2: P0-1 namespace isolation
    - REQ-5: Role-based access control

    Thread-safety: Service is stateless and thread-safe.
    """

    def __init__(self):
        """Initialize MCP auth service with security dependencies."""
        self.jwt_service = JWTService()

        # REQ-5: Operation → Required Role mapping
        self.operation_roles = {
            # Memory: All agents
            MCPOperation.MEMORY_READ: [MCPRole.AGENT],
            MCPOperation.MEMORY_WRITE: [MCPRole.AGENT],
            MCPOperation.MEMORY_DELETE: [MCPRole.AGENT],
            MCPOperation.MEMORY_SHARE: [MCPRole.AGENT],
            # Namespace: Namespace admin or higher
            MCPOperation.NAMESPACE_READ: [MCPRole.AGENT],
            MCPOperation.NAMESPACE_WRITE: [MCPRole.NAMESPACE_ADMIN, MCPRole.SYSTEM_ADMIN],
            MCPOperation.NAMESPACE_ADMIN: [MCPRole.NAMESPACE_ADMIN, MCPRole.SYSTEM_ADMIN],
            # Scheduler: System admin only
            MCPOperation.SCHEDULER_READ: [MCPRole.AGENT],
            MCPOperation.SCHEDULER_CONFIGURE: [MCPRole.SYSTEM_ADMIN, MCPRole.SUPER_ADMIN],
            MCPOperation.SCHEDULER_CONTROL: [MCPRole.SYSTEM_ADMIN, MCPRole.SUPER_ADMIN],
            # Cleanup: Admins only
            MCPOperation.CLEANUP_NAMESPACE: [MCPRole.NAMESPACE_ADMIN, MCPRole.SYSTEM_ADMIN],
            MCPOperation.CLEANUP_GLOBAL: [MCPRole.SUPER_ADMIN],
        }

    async def authenticate_mcp_agent(
        self,
        session: AsyncSession,
        agent_id: str,
        api_key: str | None = None,
        jwt_token: str | None = None,
        tool_name: str = "unknown",
        request_id: str | None = None,
    ) -> MCPAuthContext:
        """Authenticate MCP agent and create verified context.

        Security (REQ-1):
        1. Verify agent exists in database
        2. Validate credentials (API key OR JWT)
        3. Check agent is not suspended/deprecated
        4. Return VERIFIED agent record

        Args:
            session: Database session
            agent_id: Agent identifier to authenticate
            api_key: Optional API key for authentication
            jwt_token: Optional JWT token for authentication
            tool_name: Name of MCP tool being invoked
            request_id: Optional request ID for audit logging

        Returns:
            MCPAuthContext with verified agent data

        Raises:
            MCPAuthenticationError: If authentication fails

        Security Pattern:
            FAIL-SECURE - Deny access on any error or invalid credential
        """
        # Input validation
        if not agent_id:
            raise MCPAuthenticationError(
                "Agent ID is required",
                details={"tool_name": tool_name, "request_id": request_id},
            )

        if not api_key and not jwt_token:
            raise MCPAuthenticationError(
                "Either API key or JWT token is required",
                details={"agent_id": agent_id, "tool_name": tool_name},
            )

        # Step 1: Verify agent exists in database (REQ-1)
        try:
            stmt = select(Agent).where(Agent.agent_id == agent_id)
            result = await session.execute(stmt)
            agent = result.scalar_one_or_none()
        except (KeyboardInterrupt, SystemExit):
            raise  # Never suppress user interrupts
        except Exception as e:
            logger.critical(
                f"❌ CRITICAL: Database error during agent lookup: {type(e).__name__}",
                exc_info=True,
                extra={"agent_id": agent_id, "tool_name": tool_name},
            )
            raise MCPAuthenticationError(
                "Authentication system error",
                details={"error_type": "database_error"},
            ) from e

        if not agent:
            logger.warning(
                f"🚨 Authentication failed: Agent not found: {agent_id}",
                extra={"agent_id": agent_id, "tool_name": tool_name},
            )
            raise MCPAuthenticationError(
                f"Agent not found: {agent_id}",
                details={"agent_id": agent_id},
            )

        # Step 2: Check agent status (REQ-1)
        if agent.status in (AgentStatus.SUSPENDED, AgentStatus.DEPRECATED):
            logger.warning(
                f"🚨 Authentication denied: Agent is {agent.status.value}: {agent_id}",
                extra={"agent_id": agent_id, "status": agent.status.value, "tool_name": tool_name},
            )
            raise MCPAuthenticationError(
                f"Agent is {agent.status.value}: {agent_id}",
                details={"agent_id": agent_id, "status": agent.status.value},
            )

        if agent.status != AgentStatus.ACTIVE:
            logger.warning(
                f"⚠️  Authentication denied: Agent is not active: {agent_id}",
                extra={"agent_id": agent_id, "status": agent.status.value, "tool_name": tool_name},
            )
            raise MCPAuthenticationError(
                f"Agent is not active: {agent_id}",
                details={"agent_id": agent_id, "status": agent.status.value},
            )

        # Step 3: Validate credentials (REQ-1)
        auth_method = None
        try:
            if jwt_token:
                # Verify JWT signature and claims
                payload = self.jwt_service.verify_token(jwt_token)
                if not payload:
                    raise MCPAuthenticationError(
                        "Invalid or expired JWT token",
                        details={"agent_id": agent_id},
                    )

                # Verify agent_id matches JWT sub claim
                jwt_agent_id = payload.get("sub")
                if jwt_agent_id != agent_id:
                    logger.error(
                        f"🚨 JWT agent_id mismatch: JWT={jwt_agent_id}, Requested={agent_id}",
                        extra={"jwt_agent_id": jwt_agent_id, "requested_agent_id": agent_id},
                    )
                    raise MCPAuthenticationError(
                        "JWT agent_id mismatch",
                        details={"jwt_agent_id": jwt_agent_id, "requested_agent_id": agent_id},
                    )

                auth_method = "jwt"

            elif api_key:
                # Verify API key against stored hash
                # P1b: Dual support for bcrypt (NEW) and SHA256 (DEPRECATED)
                from ..utils.security import (
                    detect_hash_format,
                    verify_password,
                    verify_password_with_salt,
                )

                if not agent.api_key_hash:
                    raise MCPAuthenticationError(
                        "Agent has no API key configured",
                        details={"agent_id": agent_id},
                    )

                # Detect hash format (bcrypt or SHA256)
                try:
                    hash_format = detect_hash_format(agent.api_key_hash)
                except ValueError as e:
                    logger.error(
                        f"Unknown api_key_hash format for agent {agent_id}: {e}",
                        extra={"agent_id": agent_id, "tool_name": tool_name},
                    )
                    raise MCPAuthenticationError(
                        "Authentication failed",
                        details={"agent_id": agent_id},
                    ) from e

                # Verify API key based on hash format
                if hash_format == "bcrypt":
                    # NEW: Secure bcrypt verification
                    is_valid = verify_password(api_key, agent.api_key_hash)

                elif hash_format == "sha256_salt":
                    # DEPRECATED: SHA256 with salt (backward compatibility)
                    logger.warning(
                        f"⚠️  Agent {agent_id} using DEPRECATED SHA256 API key. "
                        "Please regenerate API key for improved security (bcrypt).",
                        extra={
                            "agent_id": agent_id,
                            "hash_format": "sha256_salt",
                            "security_risk": "CVSS 7.5 HIGH - vulnerable to GPU brute force",
                            "recommendation": "Regenerate API key to use bcrypt",
                        },
                    )

                    try:
                        # Parse SHA256 format: "salt:hash"
                        salt, hashed = agent.api_key_hash.split(":", 1)
                    except ValueError:
                        logger.error(
                            f"Invalid SHA256 api_key_hash format for agent {agent_id}",
                            extra={"agent_id": agent_id, "tool_name": tool_name},
                        )
                        raise MCPAuthenticationError(
                            "Authentication failed",
                            details={"agent_id": agent_id},
                        )

                    # Verify with SHA256
                    is_valid = verify_password_with_salt(api_key, hashed, salt)

                else:
                    # Should never reach here due to detect_hash_format validation
                    logger.error(
                        f"Unsupported hash format '{hash_format}' for agent {agent_id}",
                        extra={"agent_id": agent_id, "hash_format": hash_format},
                    )
                    raise MCPAuthenticationError(
                        "Authentication failed",
                        details={"agent_id": agent_id},
                    )

                # Check verification result
                if not is_valid:
                    logger.warning(
                        f"🚨 Authentication failed: Invalid API key for agent: {agent_id}",
                        extra={
                            "agent_id": agent_id,
                            "tool_name": tool_name,
                            "hash_format": hash_format,
                        },
                    )
                    raise MCPAuthenticationError(
                        "Invalid API key",
                        details={"agent_id": agent_id},
                    )

                auth_method = "api_key"

        except (KeyboardInterrupt, SystemExit):
            raise
        except MCPAuthenticationError:
            raise  # Re-raise our own exceptions
        except Exception as e:
            logger.error(
                f"❌ Credential verification failed: {type(e).__name__}: {str(e)}",
                exc_info=True,
                extra={"agent_id": agent_id, "tool_name": tool_name},
            )
            raise MCPAuthenticationError(
                "Credential verification failed",
                details={"error_type": type(e).__name__},
            ) from e

        # Step 4: Determine agent role (REQ-5)
        role = self._determine_agent_role(agent)

        # Step 5: Create verified context
        context = MCPAuthContext(
            agent_id=agent.agent_id,
            namespace=agent.namespace,  # ✅ VERIFIED from database (P0-1)
            agent=agent,
            role=role,
            tool_name=tool_name,
            request_id=request_id or f"mcp_{datetime.now(timezone.utc).timestamp()}",
            timestamp=datetime.now(timezone.utc),
            auth_method=auth_method or "unknown",
        )

        # Audit log successful authentication
        logger.info(
            f"✅ MCP authentication successful: agent={agent_id}, tool={tool_name}, method={auth_method}",
            extra={
                "agent_id": agent_id,
                "namespace": agent.namespace,
                "tool_name": tool_name,
                "auth_method": auth_method,
                "role": role.value,
            },
        )

        return context

    def _determine_agent_role(self, agent: Agent) -> MCPRole:
        """Determine agent role based on capabilities and config.

        Security (REQ-5): Role-based access control.

        Note: Handles both dict and list formats for agent.capabilities
        to support legacy data and various agent configurations.
        """
        # Normalize capabilities to dict format
        capabilities = agent.capabilities or {}

        # Handle legacy list format: convert to dict
        if isinstance(capabilities, list):
            logger.debug(
                f"Agent {agent.agent_id} has list-format capabilities, treating as regular agent",
                extra={"agent_id": agent.agent_id, "capabilities": capabilities},
            )
            capabilities = {}  # No role extraction from list format

        # Super admin: Full system access
        if capabilities.get("role") == "super_admin":
            return MCPRole.SUPER_ADMIN

        # System admin: Can manage system resources
        if capabilities.get("role") == "system_admin":
            return MCPRole.SYSTEM_ADMIN

        # Namespace admin: Can manage own namespace
        if capabilities.get("role") == "namespace_admin":
            return MCPRole.NAMESPACE_ADMIN

        # Check config for role override
        config = agent.config or {}
        if config.get("mcp_role"):
            try:
                return MCPRole(config["mcp_role"])
            except (KeyboardInterrupt, SystemExit):
                raise
            except ValueError:
                logger.warning(
                    f"⚠️  Invalid mcp_role in agent config: {config['mcp_role']}",
                    extra={"agent_id": agent.agent_id, "invalid_role": config["mcp_role"]},
                )

        # Default: Regular agent
        return MCPRole.AGENT

    async def authorize_namespace_access(
        self,
        context: MCPAuthContext,
        target_namespace: str,
        operation: MCPOperation,
    ) -> None:
        """Verify agent has permission for target namespace.

        Security (REQ-2): P0-1 pattern namespace isolation.

        Rules:
        1. Agent can ALWAYS access their own namespace
        2. Agent can read PUBLIC namespace
        3. Admins can access multiple namespaces (per role)
        4. Cross-namespace access is DENIED by default

        Args:
            context: Authenticated MCP context (with VERIFIED namespace)
            target_namespace: Namespace being accessed
            operation: Operation being performed

        Raises:
            MCPAuthorizationError: If access is denied

        Security Pattern:
            FAIL-SECURE - Deny on any doubt
        """
        # Rule 1: Own namespace → Always allowed
        if context.namespace == target_namespace:
            logger.debug(
                "✅ Namespace access granted: Own namespace",
                extra={
                    "agent_id": context.agent_id,
                    "namespace": target_namespace,
                    "operation": operation.value,
                },
            )
            return

        # Rule 2: PUBLIC namespace → Read-only
        if target_namespace == "public":
            if operation in (MCPOperation.MEMORY_READ, MCPOperation.NAMESPACE_READ):
                logger.debug(
                    "✅ Namespace access granted: Public read",
                    extra={
                        "agent_id": context.agent_id,
                        "namespace": "public",
                        "operation": operation.value,
                    },
                )
                return
            else:
                logger.warning(
                    "🚨 Namespace access denied: Write/delete not allowed in public namespace",
                    extra={
                        "agent_id": context.agent_id,
                        "namespace": "public",
                        "operation": operation.value,
                    },
                )
                raise MCPAuthorizationError(
                    "Write/delete not allowed in public namespace",
                    details={
                        "agent_id": context.agent_id,
                        "target_namespace": "public",
                        "operation": operation.value,
                    },
                )

        # Rule 3: Admin roles can access multiple namespaces
        if context.role in (MCPRole.SYSTEM_ADMIN, MCPRole.SUPER_ADMIN):
            logger.info(
                "✅ Namespace access granted: Admin role",
                extra={
                    "agent_id": context.agent_id,
                    "role": context.role.value,
                    "target_namespace": target_namespace,
                    "operation": operation.value,
                },
            )
            return

        # Rule 4: Cross-namespace access → DENY
        logger.warning(
            "🚨 Namespace access denied: Cross-namespace access not allowed",
            extra={
                "agent_id": context.agent_id,
                "own_namespace": context.namespace,
                "target_namespace": target_namespace,
                "operation": operation.value,
            },
        )
        raise MCPAuthorizationError(
            f"Agent {context.agent_id} cannot access namespace {target_namespace}",
            details={
                "agent_id": context.agent_id,
                "own_namespace": context.namespace,
                "target_namespace": target_namespace,
                "operation": operation.value,
            },
        )

    async def authorize_operation(
        self,
        context: MCPAuthContext,
        operation: MCPOperation,
    ) -> None:
        """Verify agent role has permission for operation.

        Security (REQ-5): Role-based access control.

        Args:
            context: Authenticated MCP context
            operation: Operation being performed

        Raises:
            MCPAuthorizationError: If operation is not allowed for role

        Security Pattern:
            FAIL-SECURE - Deny if operation not explicitly allowed
        """
        # Get required roles for operation
        required_roles = self.operation_roles.get(operation)

        if not required_roles:
            # Operation not in whitelist → DENY
            logger.error(
                f"🚨 Authorization denied: Unknown operation: {operation.value}",
                extra={
                    "agent_id": context.agent_id,
                    "role": context.role.value,
                    "operation": operation.value,
                },
            )
            raise MCPAuthorizationError(
                f"Unknown operation: {operation.value}",
                details={
                    "agent_id": context.agent_id,
                    "operation": operation.value,
                },
            )

        # Check if agent role is in required roles
        if context.role not in required_roles:
            logger.warning(
                f"🚨 Authorization denied: Role {context.role.value} not allowed for {operation.value}",
                extra={
                    "agent_id": context.agent_id,
                    "role": context.role.value,
                    "operation": operation.value,
                    "required_roles": [r.value for r in required_roles],
                },
            )
            raise MCPAuthorizationError(
                f"Role {context.role.value} not allowed for operation {operation.value}",
                details={
                    "agent_id": context.agent_id,
                    "role": context.role.value,
                    "operation": operation.value,
                    "required_roles": [r.value for r in required_roles],
                },
            )

        # Authorization successful
        logger.debug(
            f"✅ Operation authorized: {operation.value} for role {context.role.value}",
            extra={
                "agent_id": context.agent_id,
                "role": context.role.value,
                "operation": operation.value,
            },
        )


# Global instance for convenience
mcp_auth_service = MCPAuthService()


async def authenticate_mcp_request(
    session: AsyncSession,
    agent_id: str,
    api_key: str | None = None,
    jwt_token: str | None = None,
    tool_name: str = "unknown",
    request_id: str | None = None,
) -> MCPAuthContext:
    """Convenience function for MCP authentication.

    Usage:
        context = await authenticate_mcp_request(
            session, agent_id="test-agent", api_key="..."
        )
    """
    return await mcp_auth_service.authenticate_mcp_agent(
        session=session,
        agent_id=agent_id,
        api_key=api_key,
        jwt_token=jwt_token,
        tool_name=tool_name,
        request_id=request_id,
    )


async def authorize_mcp_request(
    context: MCPAuthContext,
    target_namespace: str,
    operation: MCPOperation,
) -> None:
    """Convenience function for MCP authorization.

    Usage:
        await authorize_mcp_request(
            context, target_namespace="project-x", operation=MCPOperation.MEMORY_DELETE
        )
    """
    await mcp_auth_service.authorize_namespace_access(context, target_namespace, operation)
    await mcp_auth_service.authorize_operation(context, operation)
