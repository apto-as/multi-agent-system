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
from sqlalchemy.pool import NullPool

# Set test environment
os.environ["TMWS_ENVIRONMENT"] = "test"
os.environ["TMWS_AUTH_ENABLED"] = "false"
os.environ["TMWS_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["TMWS_SECRET_KEY"] = "test_secret_key_for_testing_only_32_chars"

from src.api.app import create_app
from src.core.config import get_settings
from src.core.database import Base, get_db_session_dependency

# Import all models to ensure Base.metadata discovers them
from src.models.user import User, UserRole, APIKey, RefreshToken
from src.models.agent import Agent, AgentTeam, AgentNamespace
from src.models.task import Task, TaskTemplate
from src.models.workflow import Workflow, WorkflowType, WorkflowStatus
from src.models.workflow_history import WorkflowExecution, WorkflowStepExecution, WorkflowExecutionLog, WorkflowSchedule
from src.models.learning_pattern import LearningPattern
from src.models.memory import Memory
from src.models.persona import Persona
from src.models.api_audit_log import APIAuditLog

# Get test settings
settings = get_settings()
app = create_app()

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest_asyncio.fixture
async def test_engine():
    """Create test database engine."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=NullPool,
        echo=False
    )

    # Import all models to ensure Base.metadata discovers them within the fixture scope
    from src.models.user import User, UserRole, APIKey, RefreshToken
    from src.models.agent import Agent, AgentTeam, AgentNamespace
    from src.models.task import Task, TaskTemplate
    from src.models.workflow import Workflow, WorkflowType, WorkflowStatus
    from src.models.workflow_history import WorkflowExecution, WorkflowStepExecution, WorkflowExecutionLog, WorkflowSchedule
    from src.models.learning_pattern import LearningPattern
    from src.models.memory import Memory
    from src.models.persona import Persona
    from src.models.api_audit_log import APIAuditLog

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all) # Drop all tables for a clean slate
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    await engine.dispose()

@pytest_asyncio.fixture
async def test_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    async_session = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )

    async with async_session() as session:
        yield session

@pytest_asyncio.fixture
async def client(test_session):
    """Create test client."""
    from src.api.app import create_app
    app = create_app()
    app.dependency_overrides[get_db_session_dependency] = lambda: test_session

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()

@pytest_asyncio.fixture
async def authenticated_client(client, test_session):
    """Create authenticated test client."""
    # Create test user and get token
    from src.models.user import UserRole
    from src.services.auth_service import AuthService

    auth_service = AuthService()

    # Create test user
    user = await auth_service.create_user(
        username="testuser",
        email="test@example.com",
        password="TestPassword123!",
        roles=[UserRole.USER]
    )

    # Generate token
    user, token, _ = await auth_service.authenticate_user(
        username="testuser",
        password="TestPassword123!"
    )


    # Add auth header to client
    client.headers["Authorization"] = f"Bearer {token}"

    yield client

@pytest_asyncio.fixture
async def test_user(test_session, test_user_data):
    """Create a test user in the database."""
    from src.services.auth_service import AuthService
    auth_service = AuthService()
    user = await auth_service.create_user(
        username=test_user_data["username"],
        email=test_user_data["email"],
        password=test_user_data["password"],
        roles=test_user_data["roles"]
    )
    return user

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
        "assigned_persona": "artemis-optimizer"
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
                {"action": "optimize", "persona": "artemis"}
            ]
        }
    }

@pytest.fixture
def sample_memory_data():
    """Sample memory data for testing."""
    return {
        "content": "Test memory content",
        "importance": 0.8,
        "tags": ["test", "sample"],
        "metadata": {"source": "test"}
    }

@pytest.fixture
def test_user_data():
    """Sample user data for testing."""
    return {
        "username": "testuser",
        "email": "test@example.com",
        "password": "TestPassword123!",
        "roles": [UserRole.USER]
    }