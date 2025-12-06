"""Database configuration and session management for TMWS.

Version: 2.4.12
Updated: 2025-12-03 - Added optional SQLCipher encryption support (AES-256-GCM)

When db_encryption_enabled=True:
- Requires pysqlcipher3 package: pip install pysqlcipher3
- Encryption key auto-generated on first run (stored in ~/.tmws/secrets/)
- Uses SQLCipher AES-256-GCM with PBKDF2 key derivation
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import sqlalchemy as sa
from sqlalchemy import event, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import get_settings
from .exceptions import DatabaseOperationError, log_and_raise

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
    def set_sqlite_pragma(dbapi_connection, _connection_record):
        """Optimize connection settings."""
        if "sqlite" in str(engine.url):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    @event.listens_for(engine.sync_engine, "checkout")
    def receive_checkout(_dbapi_connection, connection_record, _connection_proxy):
        """Monitor connection checkout and detect slow queries."""
        connection_record.info["checkout_time"] = sa.func.now()
        pool_size = (
            engine.pool.size() if hasattr(engine.pool, "size") else "N/A"
        )
        logger.debug(
            f"Connection checked out from pool (pool size: {pool_size})"
        )

    @event.listens_for(engine.sync_engine, "checkin")
    def receive_checkin(_dbapi_connection, connection_record):
        """Monitor connection checkin and track connection lifetime."""
        if "checkout_time" in connection_record.info:
            # Track connection usage time for performance monitoring
            pool_size = (
                engine.pool.size() if hasattr(engine.pool, "size") else "N/A"
            )
            logger.debug(
                f"Connection checked in to pool (pool size: {pool_size})"
            )
            del connection_record.info["checkout_time"]


def get_engine():
    """Get database engine singleton with optimized pooling.

    v2.4.12: Supports optional SQLCipher encryption when db_encryption_enabled=True.

    Encryption Mode:
    - Requires pysqlcipher3 package
    - Uses AES-256-GCM cipher with PBKDF2 (256,000 iterations)
    - Encryption key auto-generated and stored in ~/.tmws/secrets/

    Standard Mode (default):
    - Uses standard SQLite with NullPool
    - No encryption overhead
    """
    global _engine

    if _engine is None:
        settings = get_settings()

        # Check if encryption is enabled (v2.4.12)
        if settings.db_encryption_enabled:
            _engine = _create_encrypted_engine(settings)
        else:
            _engine = _create_standard_engine(settings)

        # Setup connection monitoring
        _setup_connection_events(_engine)

        logger.info(f"Database engine created for {settings.environment} environment")

    return _engine


def _create_standard_engine(settings):
    """Create standard SQLite engine (no encryption).

    SQLite uses NullPool - creates connections on-demand without pooling.
    This allows the database file to be created on first connection.
    """
    from sqlalchemy.pool import NullPool

    # MCP STDIO mode: echo_pool must be False to keep stdout clean for JSON-RPC
    # Pool debug logs would corrupt the MCP protocol communication
    engine_config = {
        "poolclass": NullPool,
        "echo_pool": False,  # Disabled for MCP STDIO compatibility (was: dev only)
    }

    engine = create_async_engine(settings.database_url_async, **engine_config)
    logger.info("Standard SQLite engine created (no encryption)")

    return engine


def _create_encrypted_engine(settings):
    """Create encrypted SQLite engine using SQLCipher.

    v2.4.12: AES-256-GCM encryption with PBKDF2 key derivation.

    Note: This function handles the async encryption service synchronously
    since get_engine() must remain sync for backward compatibility.
    The encryption service's create_encrypted_engine() is async, but we
    use a sync approach for the connection URL configuration.
    """
    from sqlalchemy.pool import NullPool

    # Import encryption service
    try:
        from src.security.db_encryption import get_encryption_service
    except ImportError as e:
        logger.error(
            "db_encryption_enabled=True but cannot import DatabaseEncryptionService. "
            "Ensure src/security/db_encryption.py exists."
        )
        raise ImportError("Database encryption enabled but encryption service unavailable") from e

    encryption_service = get_encryption_service()
    key_name = settings.db_encryption_key_name

    # Auto-generate key if not exists (first-run experience)
    if not encryption_service.key_exists(key_name):
        logger.warning(
            "⚠️ Database encryption enabled but no key found. "
            f"Generating new encryption key: ~/.tmws/secrets/{key_name}"
        )
        new_key = encryption_service.generate_encryption_key()
        encryption_service.save_encryption_key(new_key, key_name)
        logger.warning(
            "⚠️ CRITICAL: Backup ~/.tmws/secrets/ directory immediately! "
            "Lost encryption key = lost data."
        )

    # Load encryption key
    encryption_key = encryption_service.load_encryption_key(key_name)

    # Extract database path from URL
    # Format: sqlite+aiosqlite:///./data/tmws.db -> ./data/tmws.db
    db_url = settings.database_url_async
    if ":///" in db_url:
        db_path = db_url.split(":///")[1]
    else:
        db_path = db_url.replace("sqlite+aiosqlite://", "")

    # SQLCipher connection URL
    # pysqlcipher3 uses sqlite+pysqlcipher:// scheme
    encrypted_url = f"sqlite+pysqlcipher:///{db_path}"

    # Connection arguments for SQLCipher
    connect_args = {
        "check_same_thread": False,  # Required for async usage
        "key": encryption_key,  # Encryption key (raw hex string)
        "cipher": encryption_service.CIPHER,  # AES-256-GCM
        "kdf_iter": 256000,  # PBKDF2 iterations (SQLCipher 4 default)
    }

    # Create async engine with encryption
    engine = create_async_engine(
        encrypted_url,
        connect_args=connect_args,
        poolclass=NullPool,
        echo_pool=False,  # MCP STDIO compatibility
    )

    logger.info(
        f"Encrypted SQLite engine created (SQLCipher AES-256-GCM, key: ~/.tmws/secrets/{key_name})"
    )

    return engine


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
            # Enable compiled_cache for prepared statement reuse
            info={"compiled_cache_size": 500},
        )
        logger.info("Database session maker created")

    return _session_maker


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session with automatic cleanup and commit.

    Usage:
        async with get_db_session() as session:
            # Use session here
            pass  # Auto-commits on successful exit
    """
    session_maker = get_session_maker()
    async with session_maker() as session:
        try:
            yield session
            # Auto-commit on successful completion
            await session.commit()
        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            await session.rollback()
            raise
        except SQLAlchemyError as e:
            # Database errors - rollback and raise with context
            await session.rollback()
            log_and_raise(
                DatabaseOperationError,
                "Database session error during operation",
                original_exception=e,
                details={"session_id": id(session)},
            )
        except Exception as e:
            # Unexpected errors - rollback and log critical
            await session.rollback()
            logger.critical(f"Unexpected database session error: {e}", exc_info=True)
            raise
        finally:
            await session.close()


async def get_db_session_dependency() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for database session.

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
        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except SQLAlchemyError as e:
            # Database connection errors (expected during health checks)
            logger.warning(f"Database health check failed (connection error): {e}")
            return False
        except Exception as e:
            # Unexpected errors - log critical
            logger.critical(f"Database health check failed (unexpected error): {e}", exc_info=True)
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
        """Analyze and return slow queries for optimization.

        Note: SQLite doesn't have built-in slow query tracking like PostgreSQL.
        Consider using application-level query timing for slow query detection.
        """
        # SQLite doesn't have pg_stat_statements equivalent
        # Use application-level monitoring instead
        logger.info("Slow query analysis not available for SQLite - use application-level timing")
        return []


async def create_tables():
    """Create all tables in the database with optimized indexes.

    Note: Vector indexes are managed by ChromaDB separately.
    SQLite indexes are defined in model definitions via SQLAlchemy.
    """
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    logger.info("Database tables created (SQLite + Chroma architecture)")


async def drop_tables():
    """Drop all tables in the database."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    logger.info("Database tables dropped")


@asynccontextmanager
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
        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except Exception as e:
            # Expected errors during shutdown - log but continue
            logger.warning(f"Could not get final pool status during shutdown: {e}")

        try:
            await _engine.dispose()
            _engine = None
            logger.info("Database engine disposed")
        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except Exception as e:
            # Unexpected errors during disposal - log critical
            logger.critical(f"Error disposing database engine: {e}", exc_info=True)
            _engine = None  # Clear anyway to prevent reuse

    if _session_maker:
        _session_maker = None
        logger.info("Session maker cleared")


async def optimize_database():
    """Run database optimization tasks for SQLite."""
    try:
        async with get_db_session() as session:
            # SQLite optimization: ANALYZE for query planner
            await session.execute(text("ANALYZE"))

            # SQLite VACUUM (rebuild database file, reclaim space)
            # Note: VACUUM cannot run in a transaction
            await session.commit()

            logger.info("SQLite database optimization completed (ANALYZE)")
    except (KeyboardInterrupt, SystemExit):
        # Never suppress user interrupts
        raise
    except SQLAlchemyError as e:
        # Database optimization errors (expected)
        log_and_raise(
            DatabaseOperationError,
            "Database optimization failed",
            original_exception=e,
            details={"operation": "ANALYZE"},
        )
    except Exception as e:
        # Unexpected errors - log critical
        logger.critical(f"Unexpected error during database optimization: {e}", exc_info=True)
        raise
