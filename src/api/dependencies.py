"""
API Dependencies for TMWS
Provides dependency injection for FastAPI routes
"""

import logging
from typing import Any

from fastapi import Depends, Header, HTTPException, Request, status

from ..core.config import get_settings
from ..core.database import get_db_session
from ..models.user import APIKey, APIKeyScope, User
from ..services.auth_service import (
    AccountDisabledError,
    AuthService,
    InsufficientPermissionsError,
    InvalidCredentialsError,
    TokenExpiredError,
)
from ..services.memory_service import MemoryService
from ..services.persona_service import PersonaService
from ..services.task_service import TaskService
from ..services.workflow_service import WorkflowService
from .security import get_current_user  # Import unified authentication

logger = logging.getLogger(__name__)
settings = get_settings()


def get_task_service() -> TaskService:
    """Get task service instance"""
    return TaskService()


def get_workflow_service() -> WorkflowService:
    """Get workflow service instance"""
    return WorkflowService()


def get_memory_service() -> MemoryService:
    """Get memory service instance"""
    return MemoryService()


def get_persona_service() -> PersonaService:
    """Get persona service instance"""
    return PersonaService()


async def verify_api_key(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> tuple[User | None, APIKey | None]:
    """
    Verify API key using AuthService.

    Args:
        request: FastAPI request object
        x_api_key: API key from X-API-Key header

    Returns:
        tuple[User | None, APIKey | None]: Authenticated user and API key objects.
            Returns (None, None) in development mode when auth is disabled.

    Raises:
        HTTPException: 401 for invalid/expired keys, 403 for insufficient permissions

    Note:
        - IP restrictions: Disabled (as per requirements)
        - Default expiration: None (unlimited)
        - Default rate limit: None (unlimited)
    """
    if not settings.auth_enabled:
        # Development mode: no authentication required
        logger.debug("Authentication disabled in development mode")
        return None, None

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required in X-API-Key header",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Get database session and authenticate
    async with get_db_session():
        auth_service = AuthService()

        try:
            # AuthService.validate_api_key() performs all validations:
            # 1. Key format (key_id.raw_key)
            # 2. Database lookup
            # 3. Bcrypt hash verification
            # 4. Expiration check (if expires_at is set)
            # 5. User status check
            # 6. Automatic usage tracking (last_used_at, total_requests)
            user, api_key = await auth_service.validate_api_key(
                api_key=x_api_key,
                ip_address=None,  # IP restrictions disabled
            )

            logger.info(
                f"API key authenticated: {api_key.key_prefix}... "
                f"(user: {user.username}, requests: {api_key.total_requests})"
            )

            return user, api_key

        except InvalidCredentialsError as e:
            client_host = request.client.host if request.client else "unknown"
            logger.warning(f"Invalid API key attempt from {client_host}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        except TokenExpiredError as e:
            client_host = request.client.host if request.client else "unknown"
            logger.warning(f"Expired API key attempt from {client_host}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key expired",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        except InsufficientPermissionsError as e:
            client_host = request.client.host if request.client else "unknown"
            logger.warning(f"Insufficient permissions from {client_host}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(e),
            )

        except AccountDisabledError as e:
            client_host = request.client.host if request.client else "unknown"
            logger.warning(f"Disabled account attempt from {client_host}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account disabled",
            )

        except Exception as e:
            # Catch-all for unexpected errors
            client_host = request.client.host if request.client else "unknown"
            logger.error(
                f"Unexpected error during API key validation from {client_host}: {type(e).__name__}: {str(e)}",
                exc_info=True
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error during authentication",
            )


async def check_rate_limit(
    request: Request, user: dict[str, Any] = Depends(get_current_user)
) -> None:
    """
    Check rate limiting for the current user.
    Rate limiting is handled by middleware, this is for custom checks.
    """
    # Rate limiting is primarily handled by UnifiedSecurityMiddleware
    # This dependency provides an additional layer for critical endpoints

    # Check if rate limit has been exceeded (set by middleware)
    if hasattr(request.state, "rate_limit_exceeded") and request.state.rate_limit_exceeded:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for user {user.get('username', 'unknown')}",
        )

    # Per-user rate limit tracking could be added here
    # Example: Redis-based per-user counters
    return None


def require_scope(required_scope: APIKeyScope):
    """
    Dependency factory for scope-based authorization.

    Args:
        required_scope: Required API key scope (e.g., APIKeyScope.WRITE)

    Returns:
        Dependency function that validates the scope

    Usage:
        @app.post("/tasks", dependencies=[Depends(require_scope(APIKeyScope.WRITE))])
        async def create_task(...):
            ...

    Raises:
        HTTPException: 403 if API key lacks required scope
    """

    async def scope_checker(
        user_and_key: tuple[User | None, APIKey | None] = Depends(verify_api_key),
    ) -> tuple[User | None, APIKey | None]:
        user, api_key = user_and_key

        # Development mode: skip scope check
        if not settings.auth_enabled or api_key is None:
            return user, api_key

        # Verify scope
        if not api_key.has_scope(required_scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Scope '{required_scope.value}' required",
            )

        return user, api_key

    return scope_checker


async def require_admin(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    """
    Require admin role for access.
    """
    if "admin" not in user.get("roles", []):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


async def get_request_metadata(
    request: Request, user: dict[str, Any] = Depends(get_current_user)
) -> dict[str, Any]:
    """
    Extract metadata from request for auditing.
    """
    return {
        "user_id": user.get("id"),
        "username": user.get("username"),
        "ip_address": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", "unknown"),
        "method": request.method,
        "path": request.url.path,
        "timestamp": "now()",  # Will be set by database
    }


# Export public interface
__all__ = [
    "get_current_user",  # Re-exported from security module
    "get_task_service",
    "get_workflow_service",
    "get_memory_service",
    "get_persona_service",
    "verify_api_key",
    "require_scope",  # New: Scope-based authorization
    "check_rate_limit",
    "require_admin",
    "get_request_metadata",
]
