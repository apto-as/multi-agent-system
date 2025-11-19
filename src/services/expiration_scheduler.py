"""
Expiration Scheduler for Automatic Memory Cleanup (TMWS v2.3.0 Phase 1C Part 2)

Background scheduler that periodically runs memory expiration cleanup.
Provides configurable interval, manual triggering, and metrics tracking.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from src.services.memory_service import HybridMemoryService

logger = logging.getLogger(__name__)


class ExpirationScheduler:
    """Background scheduler for automatic memory expiration cleanup.

    Features:
    - Periodic cleanup execution (configurable interval)
    - Manual trigger support
    - Error resilience (continues after failures)
    - Metrics tracking (run times, cleanup counts)
    - Graceful start/stop lifecycle
    """

    def __init__(
        self,
        memory_service: HybridMemoryService,
        interval_hours: float = 24.0,
    ):
        """Initialize the expiration scheduler.

        Args:
            memory_service: HybridMemoryService instance for cleanup operations
            interval_hours: Time between cleanup runs (default: 24 hours)

        Raises:
            ValueError: If interval_hours is less than 1 second (0.00028 hours)
        """
        if interval_hours < (1 / 3600):  # Less than 1 second (for testing)
            raise ValueError("Cleanup interval must be at least 1 second (0.00028 hours)")

        self.memory_service = memory_service
        self.interval_hours = interval_hours
        self._task: asyncio.Task | None = None
        self._running = False

        # Metrics
        self._last_run_time: datetime | None = None
        self._next_run_time: datetime | None = None
        self._total_cleanups = 0
        self._total_deleted = 0

    async def start(self) -> None:
        """Start the background scheduler.

        Raises:
            RuntimeError: If scheduler is already running
        """
        if self._running:
            raise RuntimeError("Scheduler is already running")

        self._running = True

        # Set next run time immediately
        interval_seconds = self.interval_hours * 3600
        self._next_run_time = datetime.now(timezone.utc) + timedelta(seconds=interval_seconds)

        self._task = asyncio.create_task(self._run_scheduler())
        logger.info(
            "Expiration scheduler started",
            extra={"interval_hours": self.interval_hours},
        )

    async def stop(self) -> None:
        """Stop the background scheduler gracefully."""
        if not self._running:
            return

        self._running = False

        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass  # Expected when stopping

        logger.info(
            "Expiration scheduler stopped",
            extra={
                "total_cleanups": self._total_cleanups,
                "total_deleted": self._total_deleted,
            },
        )

    def is_running(self) -> bool:
        """Check if scheduler is currently running."""
        return self._running

    async def trigger_cleanup(self) -> int:
        """Manually trigger a cleanup job immediately.

        Returns:
            Number of memories deleted

        Note:
            Can be called even when scheduler is not running.
        """
        return await self._execute_cleanup()

    def get_last_run_time(self) -> datetime | None:
        """Get the timestamp of the last cleanup run."""
        return self._last_run_time

    def get_next_run_time(self) -> datetime | None:
        """Get the estimated timestamp of the next cleanup run."""
        return self._next_run_time

    def get_total_cleanups_count(self) -> int:
        """Get the total number of cleanup runs executed."""
        return self._total_cleanups

    def get_total_deleted_count(self) -> int:
        """Get the total number of memories deleted across all runs."""
        return self._total_deleted

    async def _run_scheduler(self) -> None:
        """Main scheduler loop - runs cleanup periodically."""
        interval_seconds = self.interval_hours * 3600

        while self._running:
            try:
                # Calculate next run time
                self._next_run_time = datetime.now(timezone.utc) + timedelta(
                    seconds=interval_seconds
                )

                # Wait for interval
                await asyncio.sleep(interval_seconds)

                # Execute cleanup
                await self._execute_cleanup()

            except asyncio.CancelledError:
                # Expected when stopping
                break
            except Exception as e:
                # Log error but continue running
                logger.error(
                    f"Expiration cleanup failed: {e}",
                    extra={"error_type": type(e).__name__},
                    exc_info=True,
                )
                # Continue loop despite error

    async def _execute_cleanup(self) -> int:
        """Execute the cleanup job and update metrics.

        Returns:
            Number of memories deleted
        """
        try:
            # Execute cleanup
            deleted_count = await self.memory_service.run_expiration_cleanup()

            # Update metrics
            self._last_run_time = datetime.now(timezone.utc)
            self._total_cleanups += 1
            self._total_deleted += deleted_count

            logger.info(
                "Scheduled expiration cleanup completed",
                extra={
                    "deleted_count": deleted_count,
                    "total_cleanups": self._total_cleanups,
                    "total_deleted": self._total_deleted,
                },
            )

            return deleted_count

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except Exception as e:
            # Log error and re-raise
            logger.error(
                f"Expiration cleanup failed: {e}",
                extra={"error_type": type(e).__name__},
                exc_info=True,
            )
            raise
