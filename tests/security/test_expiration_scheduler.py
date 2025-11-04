"""
Security Tests for Expiration Scheduler (TMWS v2.3.0 Phase 1C Part 2)

Tests the background scheduler that periodically runs memory expiration cleanup:
- Scheduler starts and stops correctly
- Cleanup job runs on schedule
- Configurable cleanup interval
- Error handling and resilience
- Manual trigger support
"""

import asyncio
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from src.services.expiration_scheduler import ExpirationScheduler
from src.services.memory_service import HybridMemoryService


@pytest.fixture
def mock_memory_service():
    """Mock HybridMemoryService."""
    service = AsyncMock(spec=HybridMemoryService)
    service.run_expiration_cleanup = AsyncMock(return_value=0)
    return service


@pytest.fixture
def scheduler(mock_memory_service):
    """Create ExpirationScheduler with mocked memory service."""
    return ExpirationScheduler(
        memory_service=mock_memory_service, interval_hours=1  # 1 hour for testing
    )


class TestSchedulerLifecycle:
    """Test scheduler start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_scheduler_starts_successfully(self, scheduler):
        """Test that scheduler starts without errors."""
        # Act
        await scheduler.start()

        # Assert
        assert scheduler.is_running() is True

        # Cleanup
        await scheduler.stop()

    @pytest.mark.asyncio
    async def test_scheduler_stops_successfully(self, scheduler):
        """Test that scheduler stops correctly."""
        # Arrange
        await scheduler.start()
        assert scheduler.is_running() is True

        # Act
        await scheduler.stop()

        # Assert
        assert scheduler.is_running() is False

    @pytest.mark.asyncio
    async def test_scheduler_cannot_start_twice(self, scheduler):
        """Test that starting an already-running scheduler raises error."""
        # Arrange
        await scheduler.start()

        # Act & Assert
        with pytest.raises(RuntimeError, match="already running"):
            await scheduler.start()

        # Cleanup
        await scheduler.stop()

    @pytest.mark.asyncio
    async def test_scheduler_can_restart(self, scheduler):
        """Test that scheduler can be stopped and restarted."""
        # Arrange
        await scheduler.start()
        await scheduler.stop()

        # Act
        await scheduler.start()

        # Assert
        assert scheduler.is_running() is True

        # Cleanup
        await scheduler.stop()


class TestScheduledCleanup:
    """Test that cleanup jobs run on schedule."""

    @pytest.mark.asyncio
    async def test_cleanup_job_runs_on_schedule(self, scheduler, mock_memory_service):
        """Test that cleanup job executes periodically."""
        # Arrange
        scheduler_fast = ExpirationScheduler(
            memory_service=mock_memory_service,
            interval_hours=0.001,  # ~3.6 seconds for fast testing
        )

        # Act
        await scheduler_fast.start()
        await asyncio.sleep(4)  # Wait for at least one execution

        # Assert
        assert mock_memory_service.run_expiration_cleanup.call_count >= 1

        # Cleanup
        await scheduler_fast.stop()

    @pytest.mark.asyncio
    async def test_cleanup_job_respects_interval(self, scheduler, mock_memory_service):
        """Test that cleanup job respects configured interval."""
        # Arrange
        scheduler_fast = ExpirationScheduler(
            memory_service=mock_memory_service,
            interval_hours=0.0014,  # ~5 seconds
        )

        # Act
        await scheduler_fast.start()
        await asyncio.sleep(3)  # Wait less than interval

        # Assert - Should not have run yet
        assert mock_memory_service.run_expiration_cleanup.call_count == 0

        await asyncio.sleep(3)  # Wait for interval to complete

        # Assert - Should have run once
        assert mock_memory_service.run_expiration_cleanup.call_count >= 1

        # Cleanup
        await scheduler_fast.stop()

    @pytest.mark.asyncio
    async def test_cleanup_continues_after_error(self, scheduler, mock_memory_service, caplog):
        """Test that scheduler continues running even if cleanup fails."""
        import logging

        # Arrange
        mock_memory_service.run_expiration_cleanup.side_effect = [
            Exception("First cleanup failed"),
            5,  # Second cleanup succeeds
        ]

        scheduler_fast = ExpirationScheduler(
            memory_service=mock_memory_service,
            interval_hours=0.001,  # ~3.6 seconds
        )

        # Act
        with caplog.at_level(logging.ERROR):
            await scheduler_fast.start()
            await asyncio.sleep(8)  # Wait for both attempts

        # Assert
        assert mock_memory_service.run_expiration_cleanup.call_count >= 2
        assert scheduler_fast.is_running() is True

        # Verify error was logged
        error_logs = [r for r in caplog.records if "Expiration cleanup failed" in r.message]
        assert len(error_logs) >= 1

        # Cleanup
        await scheduler_fast.stop()


class TestManualTrigger:
    """Test manual triggering of cleanup job."""

    @pytest.mark.asyncio
    async def test_manual_trigger_runs_cleanup(self, scheduler, mock_memory_service):
        """Test that manual trigger executes cleanup immediately."""
        # Arrange
        await scheduler.start()
        mock_memory_service.run_expiration_cleanup.return_value = 10

        # Act
        deleted_count = await scheduler.trigger_cleanup()

        # Assert
        assert deleted_count == 10
        mock_memory_service.run_expiration_cleanup.assert_called_once()

        # Cleanup
        await scheduler.stop()

    @pytest.mark.asyncio
    async def test_manual_trigger_when_not_running(self, scheduler, mock_memory_service):
        """Test that manual trigger works even when scheduler is not running."""
        # Arrange
        mock_memory_service.run_expiration_cleanup.return_value = 5

        # Act
        deleted_count = await scheduler.trigger_cleanup()

        # Assert
        assert deleted_count == 5
        mock_memory_service.run_expiration_cleanup.assert_called_once()


class TestSchedulerConfiguration:
    """Test scheduler configuration options."""

    @pytest.mark.asyncio
    async def test_custom_interval_respected(self, mock_memory_service):
        """Test that custom cleanup interval is respected."""
        # Arrange
        scheduler_12h = ExpirationScheduler(
            memory_service=mock_memory_service, interval_hours=12
        )

        # Assert
        assert scheduler_12h.interval_hours == 12

    @pytest.mark.asyncio
    async def test_default_interval_24_hours(self, mock_memory_service):
        """Test that default interval is 24 hours."""
        # Arrange
        scheduler_default = ExpirationScheduler(memory_service=mock_memory_service)

        # Assert
        assert scheduler_default.interval_hours == 24

    @pytest.mark.asyncio
    async def test_minimum_interval_enforced(self, mock_memory_service):
        """Test that minimum interval (1 second) is enforced."""
        # Arrange & Act
        with pytest.raises(ValueError, match="at least 1 second"):
            ExpirationScheduler(
                memory_service=mock_memory_service,
                interval_hours=0.0001 / 3600,  # Less than 1 second
            )


class TestSchedulerMetrics:
    """Test scheduler metrics and statistics."""

    @pytest.mark.asyncio
    async def test_get_last_run_time(self, scheduler, mock_memory_service):
        """Test that last run time is tracked."""
        # Arrange
        await scheduler.start()
        mock_memory_service.run_expiration_cleanup.return_value = 3

        # Act
        time_before = datetime.now(timezone.utc)
        await scheduler.trigger_cleanup()
        time_after = datetime.now(timezone.utc)

        # Assert
        last_run = scheduler.get_last_run_time()
        assert last_run is not None
        assert time_before <= last_run <= time_after

        # Cleanup
        await scheduler.stop()

    @pytest.mark.asyncio
    async def test_get_next_run_time(self, scheduler):
        """Test that next run time is calculated correctly."""
        # Arrange
        await scheduler.start()

        # Act
        next_run = scheduler.get_next_run_time()

        # Assert
        assert next_run is not None
        now = datetime.now(timezone.utc)
        # Next run should be approximately interval_hours from now
        expected_next = now + timedelta(hours=scheduler.interval_hours)
        time_diff = abs((next_run - expected_next).total_seconds())
        assert time_diff < 60  # Within 1 minute tolerance

        # Cleanup
        await scheduler.stop()

    @pytest.mark.asyncio
    async def test_get_total_cleanups_count(self, scheduler, mock_memory_service):
        """Test that total cleanup count is tracked."""
        # Arrange
        await scheduler.start()
        mock_memory_service.run_expiration_cleanup.return_value = 5

        # Act
        await scheduler.trigger_cleanup()
        await scheduler.trigger_cleanup()

        # Assert
        assert scheduler.get_total_cleanups_count() == 2

        # Cleanup
        await scheduler.stop()

    @pytest.mark.asyncio
    async def test_get_total_deleted_count(self, scheduler, mock_memory_service):
        """Test that total deleted memories count is tracked."""
        # Arrange
        await scheduler.start()
        mock_memory_service.run_expiration_cleanup.side_effect = [10, 5, 3]

        # Act
        await scheduler.trigger_cleanup()
        await scheduler.trigger_cleanup()
        await scheduler.trigger_cleanup()

        # Assert
        assert scheduler.get_total_deleted_count() == 18  # 10 + 5 + 3

        # Cleanup
        await scheduler.stop()
