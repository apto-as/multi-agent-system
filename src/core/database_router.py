"""
Multi-database router for hybrid cloud-local architecture.

Handles intelligent routing of database operations to either:
- Cloud PostgreSQL (global/shared knowledge)
- Local SQLite (project/private knowledge)
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Literal

from sqlalchemy import pool
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import get_settings
from .memory_scope import MemoryScope, StorageLocation, get_storage_location

logger = logging.getLogger(__name__)


class DatabaseRouter:
    """Route database operations to cloud or local storage."""

    def __init__(self):
        self._cloud_engine = None
        self._local_engine = None
        self._cloud_session_maker = None
        self._local_session_maker = None
        self.settings = get_settings()

    def get_cloud_engine(self):
        """Get or create cloud database engine (PostgreSQL)."""
        if self._cloud_engine is None:
            cloud_url = self.settings.cloud_database_url

            if not cloud_url:
                logger.warning("Cloud database URL not configured, using local fallback")
                return self.get_local_engine()

            # Production-grade pool configuration
            engine_config = {
                "pool_size": 20,
                "max_overflow": 50,
                "pool_recycle": 3600,
                "connect_args": {
                    "server_settings": {
                        "application_name": "tmws_cloud",
                        "jit": "off",
                    },
                    "command_timeout": 60,
                },
            }

            # SSL enforcement for cloud connections
            if self.settings.environment == "production":
                engine_config["connect_args"]["ssl"] = "require"
                engine_config["connect_args"]["sslmode"] = "verify-full"

                # Certificate paths (if provided)
                if self.settings.cloud_ssl_cert_path:
                    engine_config["connect_args"]["sslrootcert"] = (
                        self.settings.cloud_ssl_cert_path
                    )

            engine_config["poolclass"] = pool.AsyncAdaptedQueuePool

            self._cloud_engine = create_async_engine(cloud_url, **engine_config)
            logger.info("Cloud database engine created")

        return self._cloud_engine

    def get_local_engine(self):
        """Get or create local database engine (SQLite)."""
        if self._local_engine is None:
            local_url = self.settings.local_database_url or "sqlite+aiosqlite:///./tmws_local.db"

            engine_config = {
                "pool_size": 5,
                "max_overflow": 10,
            }

            # SQLite-specific optimizations
            if "sqlite" in local_url:
                engine_config["connect_args"] = {
                    "check_same_thread": False,
                }

            self._local_engine = create_async_engine(local_url, **engine_config)
            logger.info("Local database engine created")

        return self._local_engine

    def get_cloud_session_maker(self):
        """Get cloud database session maker."""
        if self._cloud_session_maker is None:
            engine = self.get_cloud_engine()
            self._cloud_session_maker = async_sessionmaker(
                engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autoflush=True,
                autocommit=False,
            )
        return self._cloud_session_maker

    def get_local_session_maker(self):
        """Get local database session maker."""
        if self._local_session_maker is None:
            engine = self.get_local_engine()
            self._local_session_maker = async_sessionmaker(
                engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autoflush=True,
                autocommit=False,
            )
        return self._local_session_maker

    @asynccontextmanager
    async def get_session(
        self, scope: MemoryScope | None = None, location: StorageLocation | None = None
    ) -> AsyncGenerator[AsyncSession, None]:
        """
        Get database session based on memory scope or explicit location.

        Args:
            scope: Memory scope (auto-determines location)
            location: Explicit storage location (overrides scope)

        Usage:
            # By scope
            async with router.get_session(scope=MemoryScope.GLOBAL) as session:
                # Uses cloud database
                pass

            # By explicit location
            async with router.get_session(location=StorageLocation.LOCAL) as session:
                # Uses local database
                pass
        """
        # Determine which database to use
        if location is None:
            if scope is None:
                # Default to local for safety
                location = StorageLocation.LOCAL
            else:
                location = get_storage_location(scope)

        # Get appropriate session maker
        if location == StorageLocation.CLOUD:
            session_maker = self.get_cloud_session_maker()
        else:  # LOCAL or BOTH (for now, BOTH uses local)
            session_maker = self.get_local_session_maker()

        async with session_maker() as session:
            try:
                yield session
            except Exception as e:
                logger.error(f"Database session error: {e}")
                await session.rollback()
                raise
            finally:
                await session.close()

    @asynccontextmanager
    async def get_multi_session(
        self,
    ) -> AsyncGenerator[tuple[AsyncSession, AsyncSession], None]:
        """
        Get both cloud and local sessions for sync operations.

        Returns:
            Tuple of (cloud_session, local_session)

        Usage:
            async with router.get_multi_session() as (cloud, local):
                # Sync operations between cloud and local
                pass
        """
        cloud_maker = self.get_cloud_session_maker()
        local_maker = self.get_local_session_maker()

        async with cloud_maker() as cloud_session, local_maker() as local_session:
            try:
                yield cloud_session, local_session
            except Exception as e:
                logger.error(f"Multi-session error: {e}")
                await cloud_session.rollback()
                await local_session.rollback()
                raise
            finally:
                await cloud_session.close()
                await local_session.close()

    async def close_all(self):
        """Close all database connections (cleanup)."""
        if self._cloud_engine:
            await self._cloud_engine.dispose()
            logger.info("Cloud database engine disposed")

        if self._local_engine:
            await self._local_engine.dispose()
            logger.info("Local database engine disposed")


# Global router instance
_router: DatabaseRouter | None = None


def get_database_router() -> DatabaseRouter:
    """Get global database router singleton."""
    global _router
    if _router is None:
        _router = DatabaseRouter()
    return _router
