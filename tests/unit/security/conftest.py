"""
Security-specific pytest fixtures for MCP authentication and authorization tests.

This module provides fixtures for testing REQ-1 (authentication), REQ-2 (namespace isolation),
and REQ-5 (RBAC) security requirements.
"""

import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio
from passlib.context import CryptContext

from src.models.agent import Agent
from src.models.user import APIKey, APIKeyScope, User, UserRole, UserStatus

# Note: Lazy import to avoid global initialization issues
# from src.security.mcp_auth import MCPAuthContext, MCPRole


@pytest.fixture
def pwd_context():
    """Password hashing context for API key generation."""
    return CryptContext(schemes=["bcrypt"], deprecated="auto")


@pytest_asyncio.fixture
async def test_agent(test_session):
    """Create a test agent in the database for MCP authentication tests.

    Returns:
        Agent: Test agent with namespace 'test-namespace'
    """
    agent = Agent(
        agent_id="test-agent-123",
        namespace="test-namespace",
        display_name="Test Agent",
        capabilities=["memory:read", "memory:write"],
        status="active",
        metadata={"test": True},
    )

    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)

    return agent


@pytest_asyncio.fixture
async def test_agent_different_namespace(test_session):
    """Create a test agent in a different namespace for isolation tests.

    Returns:
        Agent: Test agent with namespace 'other-namespace'
    """
    agent = Agent(
        agent_id="other-agent-456",
        namespace="other-namespace",
        display_name="Other Agent",
        capabilities=["memory:read"],
        status="active",
        metadata={"test": True},
    )

    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)

    return agent


@pytest_asyncio.fixture
async def test_agent_admin(test_session):
    """Create an admin agent for authorization tests.

    Returns:
        Agent: Admin agent with elevated permissions
    """
    agent = Agent(
        agent_id="admin-agent-789",
        namespace="admin-namespace",
        display_name="Admin Agent",
        capabilities=["memory:*", "scheduler:*", "admin:*"],
        status="active",
        metadata={"role": "admin", "test": True},
    )

    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)

    return agent


@pytest_asyncio.fixture
async def test_agent_suspended(test_session):
    """Create a suspended agent for negative testing.

    Returns:
        Agent: Suspended agent (should fail authentication)
    """
    agent = Agent(
        agent_id="suspended-agent-999",
        namespace="test-namespace",
        display_name="Suspended Agent",
        capabilities=[],
        status="suspended",
        metadata={"test": True},
    )

    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)

    return agent


@pytest_asyncio.fixture
async def test_api_key_for_agent(test_agent, test_session, pwd_context):
    """Create a test API key for the test agent.

    Args:
        test_agent: Agent fixture
        test_session: Database session
        pwd_context: Password hashing context

    Returns:
        tuple: (full_key, key_info) where:
            - full_key: Complete API key string in format "{key_id}.{raw_key}"
            - key_info: Dictionary with key metadata
    """
    # Generate secure key components
    key_id = secrets.token_urlsafe(16)
    raw_key = secrets.token_urlsafe(32)
    full_key = f"{key_id}.{raw_key}"

    # Create a minimal user for the agent (required by APIKey foreign key)
    user = User(
        username=f"agent-user-{test_agent.agent_id}",
        email=f"{test_agent.agent_id}@tmws.local",
        password_hash="dummy",
        password_salt="dummy",
        roles=[UserRole.AGENT],
        agent_namespace=test_agent.namespace,
        password_changed_at=datetime.now(timezone.utc),
        status=UserStatus.ACTIVE,
    )

    test_session.add(user)
    await test_session.flush()  # Get user.id without commit

    # Create API key record
    api_key = APIKey(
        key_id=key_id,
        key_prefix=raw_key[:8],
        key_hash=pwd_context.hash(raw_key),
        user_id=user.id,
        name=f"Test API Key for {test_agent.agent_id}",
        description="Test API key for MCP authentication",
        scopes=[APIKeyScope.READ, APIKeyScope.WRITE, APIKeyScope.ADMIN],
        expires_at=None,  # No expiration
        allowed_ips=None,  # No IP restrictions
        rate_limit_per_hour=None,  # No rate limiting
    )

    test_session.add(api_key)
    await test_session.commit()
    await test_session.refresh(api_key)

    return full_key, {
        "key_id": key_id,
        "key_prefix": raw_key[:8],
        "agent_id": test_agent.agent_id,
        "namespace": test_agent.namespace,
        "user_id": str(user.id),
    }


@pytest_asyncio.fixture
async def test_expired_api_key(test_agent, test_session, pwd_context):
    """Create an expired API key for negative testing.

    Returns:
        tuple: (full_key, key_info)
    """
    # Generate secure key components
    key_id = secrets.token_urlsafe(16)
    raw_key = secrets.token_urlsafe(32)
    full_key = f"{key_id}.{raw_key}"

    # Create user
    user = User(
        username=f"expired-user-{test_agent.agent_id}",
        email=f"expired-{test_agent.agent_id}@tmws.local",
        password_hash="dummy",
        password_salt="dummy",
        roles=[UserRole.AGENT],
        agent_namespace=test_agent.namespace,
        password_changed_at=datetime.now(timezone.utc),
        status=UserStatus.ACTIVE,
    )

    test_session.add(user)
    await test_session.flush()

    # Create expired API key (expired 1 day ago)
    api_key = APIKey(
        key_id=key_id,
        key_prefix=raw_key[:8],
        key_hash=pwd_context.hash(raw_key),
        user_id=user.id,
        name="Expired Test API Key",
        description="Expired API key for testing",
        scopes=[APIKeyScope.READ],
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),  # Expired
        allowed_ips=None,
        rate_limit_per_hour=None,
    )

    test_session.add(api_key)
    await test_session.commit()
    await test_session.refresh(api_key)

    return full_key, {
        "key_id": key_id,
        "agent_id": test_agent.agent_id,
    }


@pytest.fixture
def mock_jwt_service():
    """Mock JWT service for testing JWT authentication."""
    from unittest.mock import MagicMock

    mock_service = MagicMock()

    # Default: valid JWT
    mock_service.verify_access_token.return_value = {
        "sub": str(uuid4()),  # user_id
        "agent_id": "test-agent-123",
        "namespace": "test-namespace",
        "exp": (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp(),
    }

    return mock_service


@pytest.fixture
def sample_mcp_auth_context(test_agent):
    """Create a sample MCPAuthContext for testing authorization.

    Returns:
        MCPAuthContext: Authenticated context for test agent
    """
    # Lazy import
    from src.security.mcp_auth import MCPAuthContext, MCPRole

    return MCPAuthContext(
        agent_id=test_agent.agent_id,
        namespace=test_agent.namespace,  # VERIFIED from database
        agent=test_agent,
        role=MCPRole.AGENT,
        tool_name="test_tool",
        request_id=str(uuid4()),
        timestamp=datetime.now(timezone.utc),
        auth_method="api_key",
    )


@pytest.fixture
def sample_admin_context(test_agent_admin):
    """Create a sample admin MCPAuthContext for testing admin operations.

    Returns:
        MCPAuthContext: Authenticated admin context
    """
    # Lazy import
    from src.security.mcp_auth import MCPAuthContext, MCPRole

    return MCPAuthContext(
        agent_id=test_agent_admin.agent_id,
        namespace=test_agent_admin.namespace,
        agent=test_agent_admin,
        role=MCPRole.SYSTEM_ADMIN,
        tool_name="admin_tool",
        request_id=str(uuid4()),
        timestamp=datetime.now(timezone.utc),
        auth_method="api_key",
    )


@pytest.fixture
def mock_rate_limiter():
    """Mock rate limiter for testing rate limiting bypass in tests."""
    limiter = AsyncMock()
    limiter.check_rate_limit = AsyncMock(return_value=None)  # Always allow
    return limiter
