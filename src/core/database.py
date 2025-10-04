"""
Database configuration and session management for TMWS.
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import sqlalchemy as sa
from sqlalchemy import event, pool, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import get_settings

logger = logging.getLogger(__name__)


# Base class for all database models
class Base(DeclarativeBase):
    pass


# Global variables for database engine and session maker
_engine: object | None = None
_session_maker: async_sessionmaker | None = None


def _setup_connection_events(engine) -> None:
    """Setup connection pool events for monitoring, security, and performance tracking."""

    @event.listens_for(engine.sync_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        """Optimize connection settings."""
        if "sqlite" in str(engine.url):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    @event.listens_for(engine.sync_engine, "checkout")
    def receive_checkout(dbapi_connection, connection_record, connection_proxy):
        """Monitor connection checkout and detect slow queries."""
        connection_record.info["checkout_time"] = sa.func.now()
        logger.debug(
            f"Connection checked out from pool (pool size: {engine.pool.size() if hasattr(engine.pool, 'size') else 'N/A'})"
        )

    @event.listens_for(engine.sync_engine, "checkin")
    def receive_checkin(dbapi_connection, connection_record):
        """Monitor connection checkin and track connection lifetime."""
        if "checkout_time" in connection_record.info:
            # Track connection usage time for performance monitoring
            logger.debug(
                f"Connection checked in to pool (pool size: {engine.pool.size() if hasattr(engine.pool, 'size') else 'N/A'})"
            )
            del connection_record.info["checkout_time"]


def get_engine():
    """Get database engine singleton with optimized pooling."""
    global _engine

    if _engine is None:
        settings = get_settings()

        # Environment-specific pool sizing for 50% throughput improvement
        if settings.environment == "production":
            pool_size = 20
            max_overflow = 50
        elif settings.environment == "staging":
            pool_size = 10
            max_overflow = 20
        else:  # development
            pool_size = 5
            max_overflow = 10

        engine_config = {}

        if settings.database_url_async.startswith("postgresql"):
            engine_config.update(
                {
                    "pool_size": pool_size,
                    "max_overflow": max_overflow,
                }
            )

        # Add connection arguments for PostgreSQL with performance tuning
        if settings.database_url_async.startswith("postgresql"):
            connect_args = {
                "server_settings": {
                    "application_name": "tmws",
                    "jit": "off",  # Disable JIT for better connection times
                },
                "command_timeout": 60,
            }

            # SSL enforcement in production
            if settings.environment == "production":
                connect_args["ssl"] = "require"

            engine_config.update(
                {
                    "connect_args": connect_args,
                    "poolclass": pool.AsyncAdaptedQueuePool,  # Better for async operations
                }
            )

        _engine = create_async_engine(settings.database_url_async, **engine_config)

        # Setup connection monitoring
        _setup_connection_events(_engine)

        logger.info(f"Database engine created for {settings.environment} environment")

    return _engine


def get_session_maker():
    """Get session maker singleton."""
    global _session_maker

    if _session_maker is None:
        engine = get_engine()
        _session_maker = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=True,
            autocommit=False,
        )
        logger.info("Database session maker created")

    return _session_maker


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Get database session with automatic cleanup.

    Usage:
        async with get_db_session() as session:
            # Use session here
            pass
    """
    session_maker = get_session_maker()
    async with session_maker() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            await session.close()


async def get_db_session_dependency() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for database session.

    Usage in FastAPI routes:
        @app.get("/items")
        async def get_items(db: AsyncSession = Depends(get_db_session_dependency)):
            # Use db here
    """
    async with get_db_session() as session:
        yield session


class DatabaseHealthCheck:
    """Database health check utilities."""

    @staticmethod
    async def check_connection() -> bool:
        """Check if database connection is healthy."""
        try:
            async with get_db_session() as session:
                result = await session.execute(sa.text("SELECT 1"))
                return result.scalar() == 1
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

    @staticmethod
    async def get_pool_status() -> dict:
        """Get detailed connection pool status for monitoring."""
        engine = get_engine()
        pool = engine.pool
        settings = get_settings()

        status = {
            "pool_size": pool.size() if hasattr(pool, "size") else 0,
            "checked_in": pool.checkedin() if hasattr(pool, "checkedin") else 0,
            "checked_out": pool.checkedout() if hasattr(pool, "checkedout") else 0,
            "overflow": pool.overflow() if hasattr(pool, "overflow") else 0,
            "total": pool.total() if hasattr(pool, "total") else 0,
            "environment": settings.environment,
        }

        # Calculate pool utilization
        if status["pool_size"] > 0 and status["checked_out"] > 0:
            status["utilization"] = (status["checked_out"] / status["pool_size"]) * 100
        else:
            status["utilization"] = 0

        # Add warnings if pool is stressed
        if status["utilization"] > 80:
            status["warning"] = "High pool utilization - consider increasing pool size"
        if status["overflow"] > 0:
            status["warning"] = f"Pool overflow active: {status['overflow']} connections"

        return status

    @staticmethod
    async def analyze_slow_queries() -> list:
        """Analyze and return slow queries for optimization."""
        try:
            async with get_db_session() as session:
                # PostgreSQL slow query detection
                if "postgresql" in str(get_engine().url):
                    query = text("""
                        SELECT
                            query,
                            calls,
                            mean_exec_time,
                            total_exec_time
                        FROM pg_stat_statements
                        WHERE mean_exec_time > 100  -- queries slower than 100ms
                        ORDER BY mean_exec_time DESC
                        LIMIT 10
                    """)
                    result = await session.execute(query)
                    slow_queries = [
                        {
                            "query": row.query[:100],  # Truncate for safety
                            "calls": row.calls,
                            "mean_time_ms": row.mean_exec_time,
                            "total_time_ms": row.total_exec_time,
                        }
                        for row in result
                    ]
                    return slow_queries
                return []
        except Exception as e:
            logger.error(f"Failed to analyze slow queries: {e}")
            return []


async def create_tables():
    """Create all tables in the database with optimized indexes."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # Create optimized indexes for common queries
        if "postgresql" in str(engine.url):
            indexes = [
                # Vector search optimization
                "CREATE INDEX IF NOT EXISTS idx_memory_embedding_ivfflat ON memory_embeddings USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)",
                # Timestamp indexes for time-based queries
                "CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_memories_created_at ON memories(created_at DESC)",
                # Composite indexes for common filters
                "CREATE INDEX IF NOT EXISTS idx_tasks_status_priority ON tasks(status, priority)",
                "CREATE INDEX IF NOT EXISTS idx_memories_persona_type ON memories(persona_id, memory_type)",
            ]

            for index_sql in indexes:
                try:
                    await conn.execute(text(index_sql))
                except Exception as e:
                    logger.warning(f"Could not create index: {e}")

    logger.info("Database tables and indexes created")


async def drop_tables():
    """Drop all tables in the database."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    logger.info("Database tables dropped")


async def get_session():
    """Alias for get_db_session_dependency for backward compatibility."""
    async with get_db_session() as session:
        yield session


async def close_db_connections():
    """Gracefully close all database connections."""
    global _engine, _session_maker

    if _engine:
        # Log final pool statistics before closing
        try:
            pool_status = await DatabaseHealthCheck.get_pool_status()
            logger.info(f"Final pool status before shutdown: {pool_status}")
        except Exception as e:
            logger.error(f"Could not get final pool status: {e}")

        await _engine.dispose()
        _engine = None
        logger.info("Database engine disposed")

    if _session_maker:
        _session_maker = None
        logger.info("Session maker cleared")


async def optimize_database():
    """Run database optimization tasks."""
    if "postgresql" not in str(get_engine().url):
        return

    try:
        async with get_db_session() as session:
            # Update statistics for query planner
            await session.execute(text("ANALYZE"))

            # Clean up dead tuples
            tables = ["tasks", "memories", "memory_embeddings", "personas"]
            for table in tables:
                try:
                    await session.execute(text(f"VACUUM ANALYZE {table}"))
                except Exception as e:
                    logger.warning(f"Could not vacuum {table}: {e}")

            await session.commit()
            logger.info("Database optimization completed")
    except Exception as e:
        logger.error(f"Database optimization failed: {e}")
