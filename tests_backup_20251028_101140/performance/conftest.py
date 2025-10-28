"""
Performance benchmark fixtures (TMWS v3.0 - SQLite + Chroma).
"""

import asyncio
import os
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

# Set test environment
os.environ["TMWS_ENVIRONMENT"] = "test"
os.environ["TMWS_AUTH_ENABLED"] = "false"
os.environ["TMWS_SECRET_KEY"] = "test_secret_key_for_performance_benchmarks_32_chars_min"

# Use SQLite for performance testing (sufficient performance demonstrated in Phase 1)
os.environ["TMWS_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

from src.core.config import get_settings
from src.core.database import Base


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def test_engine():
    """Create test database engine for performance benchmarks (SQLite in-memory)."""
    settings = get_settings()
    engine = create_async_engine(settings.database_url_async, poolclass=NullPool, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    await engine.dispose()


@pytest_asyncio.fixture
async def test_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session for performance benchmarks."""
    async_session = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        yield session


@pytest_asyncio.fixture
async def db_session(test_session: AsyncSession) -> AsyncSession:
    """
    Alias for test_session to match benchmark test expectations.

    Performance tests use db_session name for clarity.
    """
    return test_session
