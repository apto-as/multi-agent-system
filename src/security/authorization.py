"""Role-Based Authorization System for TMWS.
Implements fine-grained access control with high performance.
"""

from dataclasses import dataclass
from enum import Enum
from functools import wraps
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.agent import AccessLevel, Agent
from ..models.memory import Memory
from ..models.user import APIKeyScope, User, UserRole


class Resource(str, Enum):
    """System resources for authorization."""

    USERS = "users"
    API_KEYS = "api_keys"
    AGENTS = "agents"
    MEMORIES = "memories"
    TASKS = "tasks"
    WORKFLOWS = "workflows"
    AUDIT_LOGS = "audit_logs"
    SYSTEM_CONFIG = "system_config"
    NAMESPACES = "namespaces"


class Permission(str, Enum):
    """System permissions."""

    # CRUD operations
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"

    # Special operations
    EXECUTE = "execute"
    SHARE = "share"
    APPROVE = "approve"
    AUDIT = "audit"

    # Administrative
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


@dataclass
class AuthorizationContext:
    """Context for authorization decisions."""

    user: User
    resource: Resource
    permission: Permission
    resource_id: str | None = None
    namespace: str | None = None
    ip_address: str | None = None
    api_key_scopes: list[APIKeyScope] | None = None
    additional_context: dict[str, Any] | None = None


class RolePermissionMatrix:
    """Defines permissions for each role."""

    # Base permissions for each role
    ROLE_PERMISSIONS = {
        UserRole.SUPER_ADMIN: {
            # Super admin has all permissions
            Resource.USERS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.ADMIN,
            ],
            Resource.API_KEYS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.ADMIN,
            ],
            Resource.AGENTS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.ADMIN,
            ],
            Resource.MEMORIES: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.SHARE,
            ],
            Resource.TASKS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.EXECUTE,
            ],
            Resource.WORKFLOWS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.EXECUTE,
            ],
            Resource.AUDIT_LOGS: [Permission.READ, Permission.AUDIT],
            Resource.SYSTEM_CONFIG: [Permission.READ, Permission.UPDATE, Permission.ADMIN],
            Resource.NAMESPACES: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.ADMIN,
            ],
        },
        UserRole.ADMIN: {
            Resource.USERS: [Permission.CREATE, Permission.READ, Permission.UPDATE],
            Resource.API_KEYS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
            ],
            Resource.AGENTS: [Permission.READ, Permission.UPDATE],
            Resource.MEMORIES: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.SHARE,
            ],
            Resource.TASKS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.EXECUTE,
            ],
            Resource.WORKFLOWS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.EXECUTE,
            ],
            Resource.AUDIT_LOGS: [Permission.READ],
            Resource.SYSTEM_CONFIG: [Permission.READ],
            Resource.NAMESPACES: [Permission.READ, Permission.UPDATE],
        },
        UserRole.USER: {
            Resource.USERS: [Permission.READ],  # Own profile only
            Resource.API_KEYS: [
                Permission.CREATE,
                Permission.READ,
                Permission.DELETE,
            ],  # Own keys only
            Resource.AGENTS: [Permission.READ],
            Resource.MEMORIES: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.SHARE,
            ],
            Resource.TASKS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.EXECUTE,
            ],
            Resource.WORKFLOWS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.EXECUTE,
            ],
            Resource.AUDIT_LOGS: [],  # No access
            Resource.SYSTEM_CONFIG: [],  # No access
            Resource.NAMESPACES: [Permission.READ],  # Own namespace only
        },
        UserRole.READONLY: {
            Resource.USERS: [Permission.READ],  # Own profile only
            Resource.API_KEYS: [Permission.READ],  # Own keys only
            Resource.AGENTS: [Permission.READ],
            Resource.MEMORIES: [Permission.READ],
            Resource.TASKS: [Permission.READ],
            Resource.WORKFLOWS: [Permission.READ],
            Resource.AUDIT_LOGS: [],  # No access
            Resource.SYSTEM_CONFIG: [],  # No access
            Resource.NAMESPACES: [Permission.READ],  # Own namespace only
        },
        UserRole.SERVICE: {
            Resource.USERS: [],  # No user management
            Resource.API_KEYS: [],  # No key management
            Resource.AGENTS: [Permission.READ],
            Resource.MEMORIES: [Permission.CREATE, Permission.READ, Permission.UPDATE],
            Resource.TASKS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.EXECUTE,
            ],
            Resource.WORKFLOWS: [Permission.CREATE, Permission.READ, Permission.EXECUTE],
            Resource.AUDIT_LOGS: [],  # No access
            Resource.SYSTEM_CONFIG: [],  # No access
            Resource.NAMESPACES: [Permission.READ],
        },
    }

    @classmethod
    def get_role_permissions(cls, role: UserRole, resource: Resource) -> set[Permission]:
        """Get permissions for role on resource."""
        return set(cls.ROLE_PERMISSIONS.get(role, {}).get(resource, []))

    @classmethod
    def has_permission(
        cls,
        user_roles: list[UserRole],
        resource: Resource,
        permission: Permission,
    ) -> bool:
        """Check if any user role has permission on resource."""
        for role in user_roles:
            role_permissions = cls.get_role_permissions(role, resource)
            if permission in role_permissions:
                return True
        return False


class APIKeyScopeMapper:
    """Maps API key scopes to permissions."""

    SCOPE_PERMISSIONS = {
        APIKeyScope.FULL: {
            # Full access to most resources
            Resource.AGENTS: [Permission.READ],
            Resource.MEMORIES: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.SHARE,
            ],
            Resource.TASKS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.EXECUTE,
            ],
            Resource.WORKFLOWS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.EXECUTE,
            ],
            Resource.NAMESPACES: [Permission.READ],
        },
        APIKeyScope.READ: {
            Resource.AGENTS: [Permission.READ],
            Resource.MEMORIES: [Permission.READ],
            Resource.TASKS: [Permission.READ],
            Resource.WORKFLOWS: [Permission.READ],
            Resource.NAMESPACES: [Permission.READ],
        },
        APIKeyScope.WRITE: {
            Resource.AGENTS: [Permission.READ],
            Resource.MEMORIES: [Permission.CREATE, Permission.READ, Permission.UPDATE],
            Resource.TASKS: [Permission.CREATE, Permission.READ, Permission.UPDATE],
            Resource.WORKFLOWS: [Permission.CREATE, Permission.READ, Permission.UPDATE],
            Resource.NAMESPACES: [Permission.READ],
        },
        APIKeyScope.ADMIN: {
            Resource.API_KEYS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
            ],
            Resource.AGENTS: [Permission.READ, Permission.UPDATE],
            Resource.MEMORIES: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.SHARE,
            ],
            Resource.TASKS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.EXECUTE,
            ],
            Resource.WORKFLOWS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.EXECUTE,
            ],
            Resource.AUDIT_LOGS: [Permission.READ],
            Resource.NAMESPACES: [Permission.READ, Permission.UPDATE],
        },
        APIKeyScope.MEMORY: {
            Resource.MEMORIES: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.SHARE,
            ],
            Resource.NAMESPACES: [Permission.READ],
        },
        APIKeyScope.TASKS: {
            Resource.TASKS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.EXECUTE,
            ],
            Resource.AGENTS: [Permission.READ],
            Resource.NAMESPACES: [Permission.READ],
        },
        APIKeyScope.WORKFLOWS: {
            Resource.WORKFLOWS: [
                Permission.CREATE,
                Permission.READ,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.EXECUTE,
            ],
            Resource.TASKS: [
                Permission.READ,
                Permission.EXECUTE,
            ],  # Workflows may need to execute tasks
            Resource.AGENTS: [Permission.READ],
            Resource.NAMESPACES: [Permission.READ],
        },
    }

    @classmethod
    def has_scope_permission(
        cls,
        scopes: list[APIKeyScope],
        resource: Resource,
        permission: Permission,
    ) -> bool:
        """Check if API key scopes allow permission on resource."""
        for scope in scopes:
            scope_permissions = cls.SCOPE_PERMISSIONS.get(scope, {})
            resource_permissions = scope_permissions.get(resource, [])
            if permission in resource_permissions:
                return True
        return False


class AuthorizationService:
    """High-performance authorization service with database-verified security."""

    def __init__(self, session: AsyncSession):
        """Initialize authorization service.

        Args:
            session: Async database session for namespace verification

        """
        self.session = session
        self.role_matrix = RolePermissionMatrix()
        self.scope_mapper = APIKeyScopeMapper()

    async def check_permission(self, context: AuthorizationContext) -> bool:
        """Check if user has permission for resource.
        Performance target: <50ms (includes database verification for memories).

        Security: Database-verified namespace isolation for MEMORIES resource.
        """
        # Super admin bypass
        if UserRole.SUPER_ADMIN in context.user.roles:
            return True

        # Check role-based permissions
        if self.role_matrix.has_permission(
            context.user.roles,
            context.resource,
            context.permission,
        ):
            # Additional context checks (async for database verification)
            return await self._check_additional_constraints(context)

        # Check API key scope permissions if applicable
        if context.api_key_scopes:
            return self.scope_mapper.has_scope_permission(
                context.api_key_scopes,
                context.resource,
                context.permission,
            )

        return False

    async def check_resource_ownership(self, context: AuthorizationContext) -> bool:
        """Check if user owns the resource (async for database verification)."""
        if not context.resource_id:
            return False

        # Resource-specific ownership checks
        if context.resource == Resource.USERS:
            return str(context.user.id) == context.resource_id
        elif context.resource == Resource.API_KEYS:
            # Would need to query database for ownership
            return True  # Simplified for now
        elif context.resource == Resource.MEMORIES:
            # Check memory ownership through database-verified namespace
            return await self._check_memory_access(context)

        return False

    def check_namespace_access(self, user: User, namespace: str, access_level: AccessLevel) -> bool:
        """Check if user can access namespace with given access level."""
        # User's own namespace
        if user.agent_namespace == namespace:
            return True

        # Public access
        if access_level == AccessLevel.PUBLIC:
            return True

        # System access (for trinitas agents)
        if access_level == AccessLevel.SYSTEM:
            return namespace == "trinitas"

        # Team access (same organization/project)
        if access_level == AccessLevel.TEAM:
            # Would check organization membership
            return True  # Simplified

        # Shared access (explicitly shared)
        if access_level == AccessLevel.SHARED:
            # Would check explicit sharing permissions
            return False  # Deny by default

        # Private access (owner only)
        return False

    async def _check_additional_constraints(self, context: AuthorizationContext) -> bool:
        """Check additional authorization constraints (async for database verification)."""
        # Namespace isolation for non-admin users
        if (
            context.namespace
            and UserRole.ADMIN not in context.user.roles
            and context.namespace != context.user.agent_namespace
            and context.namespace != "public"
        ):
            return False

        # Resource ownership for certain operations
        if context.permission in [Permission.UPDATE, Permission.DELETE] and context.resource in [
            Resource.USERS,
            Resource.API_KEYS,
        ]:
            return await self.check_resource_ownership(context)

        return True

    async def _check_memory_access(self, context: AuthorizationContext) -> bool:
        """Check memory access permissions with database-verified namespace isolation.

        SECURITY-CRITICAL: P0-2 FIX - Database-verified namespace (CVSS 9.1)

        This method implements secure namespace verification by:
        1. Fetching the memory from database by resource_id
        2. Fetching the requesting agent's VERIFIED namespace from database
        3. Calling memory.is_accessible_by(agent_id, verified_namespace)

        The namespace is verified from the database, NOT from JWT claims,
        preventing authentication bypass attacks.

        Args:
            context: Authorization context with user and resource_id

        Returns:
            bool: True if access is allowed, False otherwise

        Raises:
            None - Returns False on any error for security

        """
        try:
            # Validate inputs
            if not context.resource_id or not context.user.agent_id:
                return False

            # Parse UUID (resource_id should be memory UUID)
            try:
                memory_id = (
                    UUID(context.resource_id)
                    if isinstance(context.resource_id, str)
                    else context.resource_id
                )
            except (ValueError, AttributeError):
                return False

            # STEP 1: Fetch memory from database
            stmt = select(Memory).where(Memory.id == str(memory_id))
            result = await self.session.execute(stmt)
            memory = result.scalar_one_or_none()

            if not memory:
                # Memory doesn't exist - deny access
                return False

            # STEP 2: Fetch requesting agent's VERIFIED namespace from database
            agent_id = context.user.agent_id
            stmt = select(Agent).where(Agent.agent_id == agent_id)
            result = await self.session.execute(stmt)
            agent = result.scalar_one_or_none()

            if not agent:
                # Agent doesn't exist - deny access
                return False

            # Get VERIFIED namespace from database (not from JWT!)
            verified_namespace = agent.namespace

            # STEP 3: Use Memory's built-in access control with verified namespace
            return memory.is_accessible_by(agent_id, verified_namespace)

        except Exception:
            # On any error, deny access for security
            # Do not expose error details to potential attackers
            return False

    def get_user_permissions(self, user: User, resource: Resource) -> list[Permission]:
        """Get all permissions user has on resource."""
        permissions = []

        for role in user.roles:
            role_permissions = self.role_matrix.get_role_permissions(role, resource)
            permissions.extend(role_permissions)

        return list(set(permissions))  # Remove duplicates

    def validate_api_key_scope(
        self,
        required_scope: APIKeyScope,
        available_scopes: list[APIKeyScope],
    ) -> bool:
        """Validate API key has required scope."""
        if APIKeyScope.FULL in available_scopes:
            return True

        return required_scope in available_scopes


# Global authorization service
authorization_service = AuthorizationService()


def require_permission(resource: Resource, permission: Permission, check_ownership: bool = False):
    """Decorator for route permission checking."""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract user from kwargs (injected by dependency)
            user = kwargs.get("user") or kwargs.get("current_user")
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )

            # Extract additional context
            resource_id = kwargs.get("id") or kwargs.get("resource_id")
            namespace = kwargs.get("namespace")
            api_key_scopes = kwargs.get("api_key_scopes", [])

            # Create authorization context
            auth_context = AuthorizationContext(
                user=user,
                resource=resource,
                permission=permission,
                resource_id=resource_id,
                namespace=namespace,
                api_key_scopes=api_key_scopes,
            )

            # Check permission
            if not authorization_service.check_permission(auth_context):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions",
                )

            # Check ownership if required
            if check_ownership and not authorization_service.check_resource_ownership(auth_context):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: not resource owner",
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_role(*required_roles: UserRole):
    """Decorator for role-based access control."""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user = kwargs.get("user") or kwargs.get("current_user")
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )

            if not any(role in user.roles for role in required_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required roles: {[r.value for r in required_roles]}",
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_permissions(resource: Resource, *permissions: Permission):
    """Decorator for checking permissions on a resource.
    Can be used on FastAPI route handlers.
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get user from kwargs (injected by dependency)
            user = kwargs.get("current_user")
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )

            # Check permissions
            for permission in permissions:
                if not authorization_service.check_permission(user, resource, permission):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Missing permission: {permission.value} on {resource.value}",
                    )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_api_scope(*required_scopes: APIKeyScope):
    """Decorator for API key scope checking."""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            api_key_scopes = kwargs.get("api_key_scopes", [])

            if not api_key_scopes:
                # No API key authentication - check user permissions instead
                return await func(*args, **kwargs)

            if not any(
                authorization_service.validate_api_key_scope(scope, api_key_scopes)
                for scope in required_scopes
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required API scopes: {[s.value for s in required_scopes]}",
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator
