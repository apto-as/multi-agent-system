#!/usr/bin/env python3
"""Graceful Shutdown Handler for TMWS
Ensures proper cleanup of resources during container shutdown
"""

import asyncio
import logging
import signal
from collections.abc import Callable
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


class GracefulShutdownHandler:
    """Handles graceful shutdown of the TMWS application.
    Ensures all resources are properly cleaned up.
    """

    def __init__(self):
        self.shutdown_event = asyncio.Event()
        self.cleanup_tasks: list[Callable] = []
        self.is_shutting_down = False

    def add_cleanup_task(self, task: Callable) -> None:
        """Add a cleanup task to be executed during shutdown."""
        self.cleanup_tasks.append(task)

    async def setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        loop = asyncio.get_running_loop()

        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self._signal_handler(s)))

    async def _signal_handler(self, signum: int) -> None:
        """Handle shutdown signals."""
        if self.is_shutting_down:
            logger.warning(f"Already shutting down, ignoring signal {signum}")
            return

        logger.info(f"Received shutdown signal {signum}, initiating graceful shutdown")
        self.is_shutting_down = True
        self.shutdown_event.set()

    async def wait_for_shutdown(self) -> None:
        """Wait for shutdown signal."""
        await self.shutdown_event.wait()

    async def cleanup(self) -> None:
        """Execute all cleanup tasks."""
        logger.info("Starting cleanup tasks...")

        cleanup_results = []
        for i, task in enumerate(self.cleanup_tasks):
            try:
                logger.info(f"Executing cleanup task {i + 1}/{len(self.cleanup_tasks)}")
                if asyncio.iscoroutinefunction(task):
                    await task()
                else:
                    task()
                cleanup_results.append(True)
            except Exception as e:
                logger.error(f"Cleanup task {i + 1} failed: {e}")
                cleanup_results.append(False)

        successful_cleanups = sum(cleanup_results)
        logger.info(
            f"Cleanup completed: {successful_cleanups}/{len(self.cleanup_tasks)} tasks successful",
        )


# Global shutdown handler instance
shutdown_handler = GracefulShutdownHandler()


@asynccontextmanager
async def lifespan_handler(_app):
    """FastAPI lifespan context manager for graceful startup and shutdown.
    """
    # Startup
    logger.info("TMWS starting up...")
    await shutdown_handler.setup_signal_handlers()

    # Add database cleanup
    from src.core.database import close_db_connections

    shutdown_handler.add_cleanup_task(close_db_connections)

    yield

    # Shutdown
    logger.info("TMWS shutting down...")
    await shutdown_handler.cleanup()
    logger.info("TMWS shutdown complete")


async def wait_for_shutdown() -> None:
    """Wait for shutdown signal - used in main.py."""
    return await shutdown_handler.wait_for_shutdown()


def add_cleanup_task(task: Callable) -> None:
    """Add cleanup task - convenience function."""
    return shutdown_handler.add_cleanup_task(task)
