"""Memory Decay Scheduler - Background task for periodic decay application.

Runs batch decay operations on a configurable schedule.
Follows ExpirationScheduler pattern for consistency.

Author: Metis (Implementation)
Created: 2025-12-09 (Phase 4.1: Issue #30)
"""

import asyncio
import logging
from contextlib import suppress
from datetime import datetime, timedelta, timezone

from src.services.memory_service.decay_manager import MemoryDecayManager

logger = logging.getLogger(__name__)


class MemoryDecayScheduler:
    """Background scheduler for periodic memory decay operations.

    Features:
    - Configurable decay interval (default: 24 hours)
    - Manual trigger support
    - Error resilience (continues after failures)
    - Metrics tracking
    - Graceful start/stop lifecycle
    """

    def __init__(
        self,
        decay_manager: MemoryDecayManager,
        interval_hours: float = 24.0,
    ):
        """Initialize decay scheduler.

        Args:
            decay_manager: MemoryDecayManager instance
            interval_hours: Time between decay runs (default: 24 hours)

        Raises:
            ValueError: If interval_hours is less than 1 second
        """
        if interval_hours < (1 / 3600):  # Less than 1 second
            raise ValueError("Decay interval must be at least 1 second (0.00028 hours)")

        self.decay_manager = decay_manager
        self.interval_hours = interval_hours
        self._task: asyncio.Task | None = None
        self._running = False

        # Metrics
        self._last_run_time: datetime | None = None
        self._next_run_time: datetime | None = None
        self._total_runs = 0
        self._total_decayed = 0

    async def start(self) -> None:
        """Start the background scheduler."""
        if self._running:
            raise RuntimeError("Decay scheduler is already running")

        self._running = True
        interval_seconds = self.interval_hours * 3600
        self._next_run_time = datetime.now(timezone.utc) + timedelta(seconds=interval_seconds)

        self._task = asyncio.create_task(self._run_scheduler())
        logger.info(
            "Memory decay scheduler started",
            extra={"interval_hours": self.interval_hours},
        )

    async def stop(self) -> None:
        """Stop the background scheduler gracefully."""
        if not self._running:
            return

        self._running = False

        if self._task:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task

        logger.info(
            "Memory decay scheduler stopped",
            extra={
                "total_runs": self._total_runs,
                "total_decayed": self._total_decayed,
            },
        )

    def is_running(self) -> bool:
        """Check if scheduler is running."""
        return self._running

    async def trigger_decay(
        self,
        namespace: str | None = None,
        agent_id: str | None = None,
    ) -> dict[str, int]:
        """Manually trigger decay operation.

        Args:
            namespace: Optional namespace filter
            agent_id: Optional agent filter

        Returns:
            Decay statistics
        """
        return await self._execute_decay(namespace, agent_id)

    def get_last_run_time(self) -> datetime | None:
        """Get timestamp of last decay run."""
        return self._last_run_time

    def get_next_run_time(self) -> datetime | None:
        """Get estimated next run timestamp."""
        return self._next_run_time

    def get_total_runs(self) -> int:
        """Get total number of decay runs."""
        return self._total_runs

    def get_total_decayed(self) -> int:
        """Get total memories decayed across all runs."""
        return self._total_decayed

    async def _run_scheduler(self) -> None:
        """Main scheduler loop."""
        interval_seconds = self.interval_hours * 3600

        while self._running:
            try:
                self._next_run_time = datetime.now(timezone.utc) + timedelta(
                    seconds=interval_seconds
                )

                await asyncio.sleep(interval_seconds)
                await self._execute_decay()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    f"Memory decay failed: {e}",
                    extra={"error_type": type(e).__name__},
                    exc_info=True,
                )

    async def _execute_decay(
        self,
        namespace: str | None = None,
        agent_id: str | None = None,
    ) -> dict[str, int]:
        """Execute decay operation."""
        try:
            stats = await self.decay_manager.run_batch_decay(
                namespace=namespace,
                agent_id=agent_id,
            )

            self._last_run_time = datetime.now(timezone.utc)
            self._total_runs += 1
            self._total_decayed += stats["decayed_count"]

            logger.info(
                "Scheduled memory decay completed",
                extra={
                    "decayed_count": stats["decayed_count"],
                    "total_runs": self._total_runs,
                },
            )

            return stats

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(
                f"Memory decay failed: {e}",
                extra={"error_type": type(e).__name__},
                exc_info=True,
            )
            raise
