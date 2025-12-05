"""
Shared pytest fixtures and configuration for TMWS test suite.
"""

import asyncio
import os
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

# Set test environment - MUST be set before importing src.core.config
os.environ["TMWS_ENVIRONMENT"] = "test"
os.environ["TMWS_AUTH_ENABLED"] = "false"
os.environ["TMWS_SECRET_KEY"] = "test_secret_key_for_testing_only_32_chars"

# Database URL configuration - SQLite + ChromaDB architecture (v2.2.6+)
os.environ["TMWS_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

# Import after environment setup - environment variables must be set first
# Import for dependency override (test authentication bypass)
from src.api.dependencies import User, get_current_user  # noqa: E402
from src.core.config import get_settings  # noqa: E402
from src.core.database import Base, get_db_session_dependency  # noqa: E402

# Import memory service dependency (for mocking)
try:
    from src.api.routers.memory import get_memory_service  # noqa: E402
except ImportError:
    get_memory_service = None  # Not available in all test scenarios

# Import all models to ensure Base.metadata discovers them
from src.models.agent import Agent  # noqa: E402
from src.models.user import User, UserRole  # noqa: E402

# Get test settings
settings = get_settings()

# TMWS v2.3.0+: FastAPI available in main.py
# Import FastAPI app only if available (for backward compatibility with existing tests)
try:
    from src.api.main import app
except ImportError:
    # v3.0: MCP-only, no FastAPI app
    app = None
    get_db_session_dependency = None  # Not needed in v3.0


@pytest.fixture(scope="function")
def event_loop():
    """Create an instance of the default event loop for each test function.

    Changed from scope="session" to scope="function" to prevent
    "RuntimeError: Event loop is closed" in full test suite runs.
    Each test gets a fresh event loop, ensuring isolation.

    Fix for: P0-1 Event Loop Fixture Issue (2025-10-27)
    Root Cause: Session-scoped loop closed after first test, subsequent tests failed
    Impact: Fixes 12+ event loop errors in full suite execution
    """
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def test_engine():
    """Create test database engine with StaticPool for :memory: database."""
    import src.core.database as db_module

    settings = get_settings()
    # CRITICAL: Use StaticPool for SQLite :memory: database
    # This ensures all connections see the same in-memory database
    engine = create_async_engine(
        settings.database_url_async,
        poolclass=StaticPool,  # Required for :memory: databases
        echo=False,
        connect_args={"check_same_thread": False},  # Required for SQLite async
    )

    # Monkeypatch the global _engine so get_engine() returns our test engine
    db_module._engine = engine
    db_module._session_maker = None  # Clear session maker cache

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)  # Drop all tables for a clean slate
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    # Cleanup: reset global state
    db_module._engine = None
    db_module._session_maker = None
    await engine.dispose()


@pytest_asyncio.fixture
async def test_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    async_session = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        yield session


@pytest_asyncio.fixture
async def db_session(test_session) -> AsyncGenerator[AsyncSession, None]:
    """Alias for test_session for backward compatibility."""
    yield test_session


@pytest.fixture
def mock_user():
    """Create mock user for bypassing authentication in tests.

    Returns:
        User object with test agent credentials
    """
    return User(
        agent_id="test-agent-id",
        namespace="test-namespace",
        roles=["user", "admin"],
    )


@pytest_asyncio.fixture
async def client(test_session, mock_user):
    """Create test client (v3.0: Skips if FastAPI not available)."""
    if app is None:
        pytest.skip("FastAPI not available in TMWS v3.0 (MCP-only)")

    # Override dependencies: database session + authentication bypass
    app.dependency_overrides[get_db_session_dependency] = lambda: test_session
    app.dependency_overrides[get_current_user] = lambda: mock_user

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def async_client(test_session, mock_user):
    """Create async test client for E2E tests (v3.0: Skips if FastAPI not available)."""
    if app is None:
        pytest.skip("FastAPI not available in TMWS v3.0 (MCP-only)")

    from httpx import ASGITransport, AsyncClient

    # Override dependencies: database session + authentication bypass
    app.dependency_overrides[get_db_session_dependency] = lambda: test_session
    app.dependency_overrides[get_current_user] = lambda: mock_user

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def authenticated_client(client, test_session):
    """Create authenticated test client."""
    # Create test user and get token
    from datetime import datetime, timezone

    from src.models.user import User, UserRole, UserStatus
    from src.services.jwt_service import JWTService
    from src.utils.security import hash_password_with_salt

    # Create test user directly in test session
    password_hash, password_salt = hash_password_with_salt("TestPassword123!")

    user = User(
        username="testuser",
        email="test@example.com",
        password_hash=password_hash,
        password_salt=password_salt,
        roles=[UserRole.USER],
        agent_namespace="default",
        password_changed_at=datetime.now(timezone.utc),
        status=UserStatus.ACTIVE,
    )

    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    # Generate JWT token
    jwt_service = JWTService()
    token = jwt_service.create_access_token(
        subject=str(user.id),
        additional_claims={"username": user.username, "roles": [role.value for role in user.roles]},
    )

    # Add auth header to client
    client.headers["Authorization"] = f"Bearer {token}"

    yield client


@pytest_asyncio.fixture
async def test_user(test_session, test_user_data):
    """Create a test user in the database."""
    from datetime import datetime, timezone

    from src.models.user import User, UserStatus
    from src.utils.security import hash_password_with_salt

    # Create test user directly in test session
    password_hash, password_salt = hash_password_with_salt(test_user_data["password"])

    user = User(
        username=test_user_data["username"],
        email=test_user_data["email"],
        password_hash=password_hash,
        password_salt=password_salt,
        roles=test_user_data["roles"],
        agent_namespace="default",
        password_changed_at=datetime.now(timezone.utc),
        status=UserStatus.ACTIVE,
    )

    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def test_api_key(test_user, test_session):
    """
    Create test API key with full permissions.

    Returns:
        tuple: (full_key, key_info) where:
            - full_key: Complete API key string in format "{key_id}.{raw_key}"
            - key_info: Dictionary with key metadata (key_id, key_prefix, scopes)

    Note:
        - No IP restrictions (as per requirements)
        - No expiration (unlimited lifetime)
        - No rate limiting (unlimited requests)
        - Scopes: READ, WRITE, ADMIN (full access)
    """
    import secrets

    from passlib.context import CryptContext

    from src.models.user import APIKey, APIKeyScope

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    # Generate secure key components
    key_id = secrets.token_urlsafe(16)
    raw_key = secrets.token_urlsafe(32)
    full_key = f"{key_id}.{raw_key}"

    # Create API key record
    api_key = APIKey(
        key_id=key_id,
        key_prefix=raw_key[:8],
        key_hash=pwd_context.hash(raw_key),
        user_id=test_user.id,
        name="Test API Key",
        description="Test API key for integration tests",
        scopes=[APIKeyScope.READ, APIKeyScope.WRITE, APIKeyScope.ADMIN],
        expires_at=None,  # No expiration (unlimited)
        allowed_ips=None,  # No IP restrictions
        rate_limit_per_hour=None,  # No rate limiting (unlimited)
    )

    test_session.add(api_key)
    await test_session.commit()
    await test_session.refresh(api_key)

    # Return both the full key and metadata
    # Note: scopes from DB might be strings or enum objects
    scopes_list = []
    for s in api_key.scopes:
        if isinstance(s, str):
            scopes_list.append(s)
        else:
            scopes_list.append(s.value)

    return full_key, {
        "key_id": key_id,
        "key_prefix": raw_key[:8],
        "scopes": scopes_list,
        "user_id": str(test_user.id),
    }


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)
    redis_mock.set = AsyncMock(return_value=True)
    redis_mock.setex = AsyncMock(return_value=True)
    redis_mock.delete = AsyncMock(return_value=1)
    redis_mock.exists = AsyncMock(return_value=0)
    redis_mock.expire = AsyncMock(return_value=True)
    redis_mock.incr = AsyncMock(return_value=1)
    redis_mock.eval = AsyncMock(return_value=[1, 99])
    return redis_mock


@pytest.fixture
def mock_memory_service():
    """Mock memory service."""
    memory_mock = AsyncMock()
    memory_mock.create_memory = AsyncMock(return_value={"id": "test-memory-id"})
    memory_mock.search_memories = AsyncMock(return_value=[])
    memory_mock.get_memory = AsyncMock(return_value=None)
    memory_mock.update_memory = AsyncMock(return_value=True)
    memory_mock.delete_memory = AsyncMock(return_value=True)
    return memory_mock


@pytest.fixture
def mock_task_service():
    """Mock task service."""
    task_mock = AsyncMock()
    task_mock.create_task = AsyncMock(return_value={"id": "test-task-id"})
    task_mock.get_task = AsyncMock(return_value=None)
    task_mock.update_task = AsyncMock(return_value=True)
    task_mock.delete_task = AsyncMock(return_value=True)
    task_mock.list_tasks = AsyncMock(return_value=[])
    return task_mock


@pytest.fixture
def mock_workflow_service():
    """Mock workflow service."""
    workflow_mock = AsyncMock()
    workflow_mock.create_workflow = AsyncMock(return_value={"id": "test-workflow-id"})
    workflow_mock.execute_workflow = AsyncMock(return_value={"status": "running"})
    workflow_mock.get_workflow = AsyncMock(return_value=None)
    workflow_mock.cancel_workflow = AsyncMock(return_value=True)
    return workflow_mock


# Test data fixtures
@pytest.fixture
def sample_task_data():
    """Sample task data for testing."""
    return {
        "title": "Test Task",
        "description": "Test task description",
        "priority": "medium",
        "status": "pending",
        "assigned_persona": "artemis-optimizer",
    }


@pytest.fixture
def sample_workflow_data():
    """Sample workflow data for testing."""
    return {
        "name": "Test Workflow",
        "workflow_type": "sequential",
        "priority": "high",
        "config": {
            "steps": [
                {"action": "analyze", "persona": "athena"},
                {"action": "optimize", "persona": "artemis"},
            ]
        },
    }


@pytest.fixture
def sample_memory_data():
    """Sample memory data for testing."""
    return {
        "content": "Test memory content",
        "importance": 0.8,
        "tags": ["test", "sample"],
        "metadata": {"source": "test"},
    }


@pytest.fixture
def test_user_data():
    """Sample user data for testing."""
    return {
        "username": "testuser",
        "email": "test@example.com",
        "password": "TestPassword123!",
        "roles": [UserRole.USER],
    }


@pytest.fixture
def performance_timer():
    """Performance timer fixture for measuring execution times."""
    import time

    class PerformanceTimer:
        def __init__(self):
            self.start_time = None
            self.end_time = None

        def start(self):
            """Start the timer."""
            self.start_time = time.perf_counter()
            return self

        def stop(self):
            """Stop the timer and return elapsed milliseconds."""
            if self.start_time is None:
                raise RuntimeError("Timer not started")
            self.end_time = time.perf_counter()
            elapsed_seconds = self.end_time - self.start_time
            return elapsed_seconds * 1000  # Convert to milliseconds

        def get_elapsed(self):
            """Get elapsed time without stopping."""
            if self.start_time is None:
                raise RuntimeError("Timer not started")
            current = time.perf_counter()
            return (current - self.start_time) * 1000

    return PerformanceTimer()


@pytest.fixture
def sample_vector_data():
    """Sample vector data for testing ChromaDB vector functionality."""
    import numpy as np

    return {
        "content": "Test memory content for vector search",
        "embedding": np.random.rand(1024).tolist(),  # 1024-dimensional vector (v2.2.6)
        "importance": 0.8,
        "tags": ["test", "vector", "memory"],
        "metadata": {"source": "test", "test_type": "vector"},
    }


@pytest.fixture
def database_marker():
    """Helper to identify current database type (SQLite + ChromaDB architecture)."""
    return "sqlite"


# ============================================================================
# RBAC Test Fixtures (Wave 2: Security Validation Framework)
# ============================================================================


@pytest_asyncio.fixture
async def viewer_agent(test_session):
    """Create agent with viewer role for RBAC permission tests."""
    from uuid import uuid4

    agent = Agent(
        id=str(uuid4()),
        agent_id="test-viewer",
        display_name="Test Viewer",
        namespace="test",
        status="active",
        health_score=1.0,
        role="viewer",
    )
    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def editor_agent(test_session):
    """Create agent with editor role for RBAC permission tests."""
    from uuid import uuid4

    agent = Agent(
        id=str(uuid4()),
        agent_id="test-editor",
        display_name="Test Editor",
        namespace="test",
        status="active",
        health_score=1.0,
        role="editor",
    )
    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def admin_agent(test_session):
    """Create agent with admin role for RBAC permission tests."""
    from uuid import uuid4

    agent = Agent(
        id=str(uuid4()),
        agent_id="test-admin",
        display_name="Test Admin",
        namespace="test",
        status="active",
        health_score=1.0,
        role="admin",
    )
    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)
    return agent
