"""Pytest configuration for E2E tests.

E2E tests use the same infrastructure as integration tests:
- Real SQLite :memory: database (StaticPool)
- Real FastAPI TestClient
- Real Application Use Cases and Repositories
- Mocked MCPClientAdapter (external service)

The fixtures are duplicated here because pytest requires fixtures
to be defined in conftest.py files for discovery.

Author: Artemis (Technical Perfectionist)
Created: 2025-11-12 (Phase 1-3-E: E2E Tests)
"""

from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.api.dependencies import get_current_user, get_db_session
from src.api.main import app
from src.infrastructure.adapters.mcp_client_adapter import MCPClientAdapter
from src.models.agent import Agent, AgentStatus
from src.models.base import Base
from src.security.jwt_service import jwt_service


# ============================================================================
# Database Fixtures (Real SQLite :memory: with StaticPool)
# ============================================================================


@pytest_asyncio.fixture
async def test_engine():
    """Create test database engine with StaticPool for :memory: sharing.

    StaticPool ensures all connections share the same :memory: database.
    This is CRITICAL for SQLite :memory: databases in async tests.

    Yields:
        AsyncEngine: Configured test engine
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,  # CRITICAL: StaticPool for :memory: sharing
        connect_args={"check_same_thread": False},
        echo=False,  # Set to True for SQL debugging
    )

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    # Cleanup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture
async def test_session_factory(test_engine):
    """Create session factory for test database.

    Args:
        test_engine: Test database engine

    Returns:
        sessionmaker: Factory for creating async sessions
    """
    return sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )


@pytest_asyncio.fixture
async def test_session(
    test_session_factory,
) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session.

    This session is used for test data setup and verification.
    FastAPI endpoints use a separate session from the same factory.

    Args:
        test_session_factory: Session factory from test_session_factory fixture

    Yields:
        AsyncSession: Database session for test
    """
    async with test_session_factory() as session:
        yield session


# ============================================================================
# Test Data Fixtures (Real Database Models)
# ============================================================================


@pytest_asyncio.fixture
async def test_agent(test_session: AsyncSession) -> Agent:
    """Create test agent in database with verified namespace.

    This agent is used for authenticated API requests.

    Args:
        test_session: Database session

    Returns:
        Agent: Test agent with namespace 'test-namespace'
    """
    agent_uuid = uuid4()
    agent = Agent(
        agent_id=str(agent_uuid),
        namespace="test-namespace",
        display_name="Test Agent",
        capabilities=["mcp:connect", "mcp:execute"],
        status=AgentStatus.ACTIVE,
        metadata={"test": True},
    )

    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)

    return agent


@pytest_asyncio.fixture
async def test_agent_other_namespace(test_session: AsyncSession) -> Agent:
    """Create test agent in different namespace for security tests.

    Args:
        test_session: Database session

    Returns:
        Agent: Test agent with namespace 'other-namespace'
    """
    agent_uuid = uuid4()
    agent = Agent(
        agent_id=str(agent_uuid),
        namespace="other-namespace",
        display_name="Other Agent",
        capabilities=["mcp:connect"],
        status=AgentStatus.ACTIVE,
        metadata={"test": True},
    )

    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)

    return agent


# ============================================================================
# MCP Adapter Mocks (External Service)
# ============================================================================


@pytest.fixture
def mock_mcp_adapter() -> AsyncMock:
    """Create mock MCP client adapter for external service simulation.

    This is the ONLY mock in E2E tests - all other layers are real.

    Returns:
        AsyncMock: Mocked MCPClientAdapter with default behavior
    """
    from src.domain.entities.tool import Tool
    from src.domain.value_objects.tool_category import ToolCategory

    adapter = AsyncMock(spec=MCPClientAdapter)

    # Default behavior: successful connection
    adapter.connect = AsyncMock(return_value=None)

    # Default behavior: discover tools (return real Tool entities)
    adapter.discover_tools = AsyncMock(
        return_value=[
            Tool(
                name="test_tool",
                description="Test tool for integration testing",
                input_schema={"type": "object", "properties": {"param": {"type": "string"}}},
                category=ToolCategory.GENERAL,
            ),
        ],
    )

    # Default behavior: execute tool
    adapter.execute_tool = AsyncMock(return_value={"result": "success", "status": "completed"})

    # Default behavior: disconnect
    adapter.disconnect = AsyncMock(return_value=None)

    return adapter


# ============================================================================
# FastAPI TestClient (Real Router + Dependency Injection)
# ============================================================================


@pytest.fixture
def test_client(
    test_session_factory,
    mock_mcp_adapter: AsyncMock,
    test_agent: Agent,
) -> TestClient:
    """Create FastAPI test client with dependency overrides.

    This client uses:
    - Real database (via test_session_factory)
    - Real routers and use cases
    - Mocked MCP adapter (external service) via module-level patch
    - Mocked authentication (returns test_agent)

    Args:
        test_session_factory: Session factory for database
        mock_mcp_adapter: Mocked MCP adapter
        test_agent: Test agent for authentication

    Returns:
        TestClient: Configured FastAPI test client
    """
    from unittest.mock import patch

    # Override database session dependency
    async def override_get_session() -> AsyncGenerator[AsyncSession, None]:
        async with test_session_factory() as session:
            yield session

    # Override authentication dependency (mock current user)
    async def override_get_current_user() -> MagicMock:
        # Return mock user with test_agent data
        from src.api.dependencies import User

        return User(
            agent_id=test_agent.agent_id,
            namespace=test_agent.namespace,
            roles=["user"],
        )

    # Apply dependency overrides
    app.dependency_overrides[get_db_session] = override_get_session
    app.dependency_overrides[get_current_user] = override_get_current_user

    # Patch MCPClientAdapter at module level (dependency injection creates it)
    # This ensures all use cases get our mocked adapter
    adapter_patcher = patch(
        "src.api.dependencies.MCPClientAdapter",
        return_value=mock_mcp_adapter,
    )
    adapter_patcher.start()

    client = TestClient(app)

    yield client

    # Cleanup
    adapter_patcher.stop()
    app.dependency_overrides.clear()


# ============================================================================
# Authentication Fixtures (JWT Token Generation)
# ============================================================================


@pytest.fixture
def auth_headers(test_agent: Agent) -> dict[str, str]:
    """Generate JWT authentication headers for test agent.

    This creates a REAL JWT token using the actual jwt_service.
    The token is valid and contains the test_agent's data.

    Args:
        test_agent: Test agent for token generation

    Returns:
        dict: Authorization headers with Bearer token
    """
    # Create a mock User object for JWT generation
    from src.models.user import User, UserRole, UserStatus

    mock_user = User(
        id=uuid4(),
        username=test_agent.agent_id,
        email=f"{test_agent.agent_id}@test.local",
        password_hash="dummy",  # Not used for token generation
        password_salt="dummy",
        roles=[UserRole.SERVICE],  # Use SERVICE role for agent authentication
        agent_namespace=test_agent.namespace,
        preferred_agent_id=test_agent.agent_id,
        password_changed_at=datetime.now(timezone.utc),
        status=UserStatus.ACTIVE,
        session_timeout_minutes=480,
    )

    # Generate real JWT token
    token = jwt_service.create_access_token(
        user=mock_user,
        expires_delta=timedelta(hours=1),
    )

    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def auth_headers_other_namespace(test_agent_other_namespace: Agent) -> dict[str, str]:
    """Generate JWT authentication headers for agent in other namespace.

    Used for testing cross-namespace access control (P0-1 security).

    Args:
        test_agent_other_namespace: Test agent in other namespace

    Returns:
        dict: Authorization headers with Bearer token
    """
    from src.models.user import User, UserRole, UserStatus

    mock_user = User(
        id=uuid4(),
        username=test_agent_other_namespace.agent_id,
        email=f"{test_agent_other_namespace.agent_id}@test.local",
        password_hash="dummy",
        password_salt="dummy",
        roles=[UserRole.SERVICE],  # Use SERVICE role for agent authentication
        agent_namespace=test_agent_other_namespace.namespace,
        preferred_agent_id=test_agent_other_namespace.agent_id,
        password_changed_at=datetime.now(timezone.utc),
        status=UserStatus.ACTIVE,
        session_timeout_minutes=480,
    )

    token = jwt_service.create_access_token(
        user=mock_user,
        expires_delta=timedelta(hours=1),
    )

    return {"Authorization": f"Bearer {token}"}


# ============================================================================
# Helper Functions
# ============================================================================


def create_jwt_token(agent: Agent, expires_delta: timedelta | None = None) -> str:
    """Create JWT token for given agent.

    Helper function for creating tokens in test cases.

    Args:
        agent: Agent to create token for
        expires_delta: Token expiration (default: 1 hour)

    Returns:
        str: JWT token string
    """
    from src.models.user import User, UserRole, UserStatus

    mock_user = User(
        id=uuid4(),
        username=agent.agent_id,
        email=f"{agent.agent_id}@test.local",
        password_hash="dummy",
        password_salt="dummy",
        roles=[UserRole.SERVICE],  # Use SERVICE role for agent authentication
        agent_namespace=agent.namespace,
        preferred_agent_id=agent.agent_id,
        password_changed_at=datetime.now(timezone.utc),
        status=UserStatus.ACTIVE,
        session_timeout_minutes=480,
    )

    return jwt_service.create_access_token(
        user=mock_user,
        expires_delta=expires_delta or timedelta(hours=1),
    )
