"""
Performance benchmark fixtures (TMWS v3.0 - SQLite + Chroma).
"""

import asyncio
import os
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Set test environment
os.environ["TMWS_ENVIRONMENT"] = "test"
os.environ["TMWS_AUTH_ENABLED"] = "false"
os.environ["TMWS_SECRET_KEY"] = "test_secret_key_for_performance_benchmarks_32_chars_min"

# Use SQLite for performance testing (sufficient performance demonstrated in Phase 1)
os.environ["TMWS_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

from src.core.config import get_settings
from src.core.database import Base

# Import all models to ensure Base.metadata discovers them (FIX: "no such table: agents")
from src.models.agent import Agent  # noqa: E402, F401
from src.models.learning_pattern import LearningPattern, PatternUsageHistory  # noqa: E402, F401
from src.models.memory import Memory  # noqa: E402, F401
from src.models.task import Task  # noqa: E402, F401
from src.models.user import User, UserRole  # noqa: E402, F401
from src.models.verification import TrustScoreHistory, VerificationRecord  # noqa: E402, F401
from src.models.workflow import Workflow  # noqa: E402, F401


@pytest.fixture(scope="function")
def event_loop():
    """Create an instance of the default event loop for each test function."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def test_engine():
    """Create test database engine for performance benchmarks (SQLite in-memory).

    FIX: Use StaticPool (not NullPool) for :memory: databases to ensure
    all connections see the same in-memory database.
    """
    import src.core.database as db_module

    settings = get_settings()
    # CRITICAL: Use StaticPool for SQLite :memory: database
    # This ensures all connections see the same in-memory database
    from sqlalchemy.pool import StaticPool
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
    """Create test database session for performance benchmarks."""
    async_session = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        yield session


@pytest_asyncio.fixture
async def db_session(test_session) -> AsyncGenerator[AsyncSession, None]:
    """
    Alias for test_session to match benchmark test expectations.

    Performance tests use db_session name for clarity.
    """
    yield test_session
