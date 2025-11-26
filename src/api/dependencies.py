"""FastAPI Dependency Injection

This module provides dependency injection for FastAPI routers.
All use cases and repositories are injected through these functions.

Security Note:
- Namespace MUST be verified from database, never trust JWT claims
- Authentication extracts agent_id from JWT, then fetches agent from DB
- Verified namespace is used for all authorization checks (P0-1 compliance)
"""

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from src.application.events.synchronous_dispatcher import SynchronousEventDispatcher
from src.application.use_cases.connect_mcp_server_use_case import (
    ConnectMCPServerUseCase,
)
from src.application.use_cases.disconnect_mcp_server_use_case import (
    DisconnectMCPServerUseCase,
)
from src.application.use_cases.discover_tools_use_case import DiscoverToolsUseCase
from src.application.use_cases.execute_tool_use_case import ExecuteToolUseCase
from src.core.config import settings
from src.core.database import get_db_session
from src.infrastructure.adapters.mcp_client_adapter import MCPClientAdapter
from src.infrastructure.repositories.agent_repository import AgentRepository
from src.infrastructure.repositories.mcp_connection_repository import (
    MCPConnectionRepository,
)
from src.infrastructure.unit_of_work import SQLAlchemyUnitOfWork
from src.security.rate_limiter import RateLimit, RateLimiter

# Security scheme
security = HTTPBearer()


class User:
    """Authenticated user with verified namespace

    Security Critical:
    - namespace is verified from database (P0-1 compliance)
    - agent_id extracted from JWT token
    - roles determine authorization level
    """

    def __init__(self, agent_id: str, namespace: str, roles: list[str]):
        self.agent_id = agent_id
        self.namespace = namespace
        self.roles = roles


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> User:
    """Extract and verify user from JWT token

    Security Flow (P0-1 Compliant):
    1. Decode JWT token to get agent_id
    2. Fetch agent from database (VERIFY existence)
    3. Extract namespace from database record (NOT from JWT)
    4. Return User with verified namespace

    Args:
        credentials: JWT bearer token from Authorization header
        session: Database session for agent verification

    Returns:
        User object with verified namespace

    Raises:
        HTTPException: 401 if token invalid or agent not found
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # SECURITY CRITICAL: Validate secret key is properly configured
    if not settings.secret_key or len(settings.secret_key) < 32:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: JWT secret key not properly configured",
        )

    try:
        # 1. Decode JWT token with secret from configuration
        payload = jwt.decode(
            credentials.credentials,
            settings.secret_key,  # ✅ Load from secure configuration
            algorithms=["HS256"],
        )
        agent_id_str: str | None = payload.get("sub")

        if agent_id_str is None:
            raise credentials_exception

        # 2. SECURITY CRITICAL: Verify agent exists in database
        agent_repo = AgentRepository(session)
        agent = await agent_repo.get_by_id(agent_id_str)

        if not agent:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Agent not found",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 3. Extract VERIFIED namespace from database (NOT from JWT)
        verified_namespace = agent.namespace

        # 4. Return User with verified namespace
        return User(
            agent_id=str(agent.agent_id),
            namespace=verified_namespace,
            roles=["user"],  # TODO: Load roles from agent.roles
        )

    except JWTError:
        raise credentials_exception


# ============================================================================
# Use Case Dependencies
# ============================================================================


async def get_connect_use_case(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> ConnectMCPServerUseCase:
    """Inject ConnectMCPServerUseCase with all dependencies

    This is a Factory Pattern for dependency injection.
    All repositories, adapters, and services are created here.

    Args:
        session: SQLAlchemy async session

    Returns:
        Configured ConnectMCPServerUseCase instance
    """
    # Repositories
    mcp_repo = MCPConnectionRepository(session)
    agent_repo = AgentRepository(session)

    # Adapters
    adapter = MCPClientAdapter()

    # Infrastructure
    uow = SQLAlchemyUnitOfWork(lambda: session)
    dispatcher = SynchronousEventDispatcher()

    # Use Case
    return ConnectMCPServerUseCase(
        repository=mcp_repo,
        adapter=adapter,
        agent_repository=agent_repo,
        uow=uow,
        event_dispatcher=dispatcher,
    )


async def get_disconnect_use_case(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> DisconnectMCPServerUseCase:
    """Inject DisconnectMCPServerUseCase with all dependencies

    Args:
        session: SQLAlchemy async session

    Returns:
        Configured DisconnectMCPServerUseCase instance
    """
    # Repositories
    mcp_repo = MCPConnectionRepository(session)
    agent_repo = AgentRepository(session)

    # Adapters
    adapter = MCPClientAdapter()

    # Infrastructure
    uow = SQLAlchemyUnitOfWork(lambda: session)
    dispatcher = SynchronousEventDispatcher()

    # Use Case
    return DisconnectMCPServerUseCase(
        repository=mcp_repo,
        adapter=adapter,
        agent_repository=agent_repo,
        uow=uow,
        event_dispatcher=dispatcher,
    )


async def get_discover_tools_use_case(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> DiscoverToolsUseCase:
    """Inject DiscoverToolsUseCase with all dependencies

    Args:
        session: SQLAlchemy async session

    Returns:
        Configured DiscoverToolsUseCase instance
    """
    # Repositories
    mcp_repo = MCPConnectionRepository(session)
    agent_repo = AgentRepository(session)

    # Adapters
    adapter = MCPClientAdapter()

    # Infrastructure
    uow = SQLAlchemyUnitOfWork(lambda: session)
    dispatcher = SynchronousEventDispatcher()

    # Use Case
    return DiscoverToolsUseCase(
        repository=mcp_repo,
        adapter=adapter,
        agent_repository=agent_repo,
        uow=uow,
        event_dispatcher=dispatcher,
    )


async def get_execute_tool_use_case(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> ExecuteToolUseCase:
    """Inject ExecuteToolUseCase with all dependencies

    Args:
        session: SQLAlchemy async session

    Returns:
        Configured ExecuteToolUseCase instance
    """
    # Repositories
    mcp_repo = MCPConnectionRepository(session)
    agent_repo = AgentRepository(session)

    # Adapters
    adapter = MCPClientAdapter()

    # Use Case (read-only, no UoW or EventDispatcher needed)
    return ExecuteToolUseCase(
        repository=mcp_repo,
        adapter=adapter,
        agent_repository=agent_repo,
    )


# ============================================================================
# Rate Limiting (V-MCP-2 Security Fix)
# ============================================================================

# Global rate limiter instance with MCP-specific limits
_rate_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    """Get or create global rate limiter instance.

    Returns:
        Configured RateLimiter with MCP API-specific limits

    Security Note:
        - Limits configured per endpoint type
        - Fail-secure: Errors result in 503 (deny access)
        - Redis optional (degrades to in-memory if unavailable)
    """
    global _rate_limiter

    if _rate_limiter is None:
        _rate_limiter = RateLimiter()

        # Override with MCP-specific rate limits
        env = settings.environment
        if env == "production":
            # Production: Strict limits
            _rate_limiter.rate_limits.update({
                "mcp_create_connection": RateLimit(10, 60, burst=2),    # 10/min
                "mcp_execute_tool": RateLimit(100, 60, burst=20),       # 100/min
                "mcp_discover_tools": RateLimit(50, 60, burst=10),      # 50/min
                "mcp_disconnect": RateLimit(20, 60, burst=5),           # 20/min
            })
        else:
            # Development: Lenient limits
            _rate_limiter.rate_limits.update({
                "mcp_create_connection": RateLimit(30, 60, burst=10),   # 30/min
                "mcp_execute_tool": RateLimit(200, 60, burst=50),       # 200/min
                "mcp_discover_tools": RateLimit(100, 60, burst=20),     # 100/min
                "mcp_disconnect": RateLimit(50, 60, burst=10),          # 50/min
            })

    return _rate_limiter


async def check_rate_limit_mcp_create(
    request: Request,
) -> None:
    """Check rate limit for MCP connection creation.

    Raises:
        HTTPException: 429 if rate limit exceeded

    Security:
        - 10 connections/min in production
        - 30 connections/min in development
        - Prevents connection pool exhaustion
        - Disabled in test environment
    """
    # Skip rate limiting in test environment
    if settings.environment == "test":
        return

    limiter = get_rate_limiter()
    await limiter.check_rate_limit(
        request=request,
        endpoint_type="mcp_create_connection",
    )


async def check_rate_limit_mcp_execute(
    request: Request,
) -> None:
    """Check rate limit for MCP tool execution.

    Raises:
        HTTPException: 429 if rate limit exceeded

    Security:
        - 100 executions/min in production
        - 200 executions/min in development
        - Prevents MCP server overload
        - Disabled in test environment
    """
    # Skip rate limiting in test environment
    if settings.environment == "test":
        return

    limiter = get_rate_limiter()
    await limiter.check_rate_limit(
        request=request,
        endpoint_type="mcp_execute_tool",
    )


async def check_rate_limit_mcp_discover(
    request: Request,
) -> None:
    """Check rate limit for MCP tool discovery.

    Raises:
        HTTPException: 429 if rate limit exceeded

    Security:
        - 50 discoveries/min in production
        - 100 discoveries/min in development
        - Disabled in test environment
    """
    # Skip rate limiting in test environment
    if settings.environment == "test":
        return

    limiter = get_rate_limiter()
    await limiter.check_rate_limit(
        request=request,
        endpoint_type="mcp_discover_tools",
    )


async def check_rate_limit_mcp_disconnect(
    request: Request,
) -> None:
    """Check rate limit for MCP disconnection.

    Raises:
        HTTPException: 429 if rate limit exceeded

    Security:
        - 20 disconnections/min in production
        - 50 disconnections/min in development
        - Disabled in test environment
    """
    # Skip rate limiting in test environment
    if settings.environment == "test":
        return

    limiter = get_rate_limiter()
    await limiter.check_rate_limit(
        request=request,
        endpoint_type="mcp_disconnect",
    )


# ============================================================================
# Memory Management Rate Limiting (Phase 1 - v2.4.0)
# ============================================================================


async def check_rate_limit_memory_cleanup(
    request: Request,
) -> None:
    """Check rate limit for namespace cleanup operation.

    Raises:
        HTTPException: 429 if rate limit exceeded

    Security:
        - 5 cleanups/min in production
        - 10 cleanups/min in development
        - Prevents abuse of administrative operation
        - Disabled in test environment
    """
    # Skip rate limiting in test environment
    if settings.environment == "test":
        return

    limiter = get_rate_limiter()
    await limiter.check_rate_limit(
        request=request,
        endpoint_type="memory_cleanup",
    )


async def check_rate_limit_memory_prune(
    request: Request,
) -> None:
    """Check rate limit for expired memory pruning operation.

    Raises:
        HTTPException: 429 if rate limit exceeded

    Security:
        - 5 prunes/min in production
        - 10 prunes/min in development
        - Prevents abuse of maintenance operation
        - Disabled in test environment
    """
    # Skip rate limiting in test environment
    if settings.environment == "test":
        return

    limiter = get_rate_limiter()
    await limiter.check_rate_limit(
        request=request,
        endpoint_type="memory_prune",
    )


async def check_rate_limit_memory_ttl(
    request: Request,
) -> None:
    """Check rate limit for memory TTL update operation.

    Raises:
        HTTPException: 429 if rate limit exceeded

    Security:
        - 30 TTL updates/min in production
        - 60 TTL updates/min in development
        - Prevents abuse while allowing reasonable user operations
        - Disabled in test environment
    """
    # Skip rate limiting in test environment
    if settings.environment == "test":
        return

    limiter = get_rate_limiter()
    await limiter.check_rate_limit(
        request=request,
        endpoint_type="memory_ttl",
    )
