"""
Unit tests for GracefulShutdownHandler
Testing graceful shutdown functionality
"""

import asyncio
import os
import signal

# Import the class directly to avoid circular dependencies
import sys
from unittest.mock import AsyncMock, Mock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from core.graceful_shutdown import GracefulShutdownHandler, add_cleanup_task, wait_for_shutdown


class TestGracefulShutdownHandlerInitialization:
    """Test GracefulShutdownHandler initialization."""

    def test_initialization(self):
        """Test that GracefulShutdownHandler initializes correctly."""
        handler = GracefulShutdownHandler()

        assert isinstance(handler.shutdown_event, asyncio.Event)
        assert handler.cleanup_tasks == []
        assert handler.is_shutting_down is False

    def test_add_cleanup_task(self):
        """Test adding cleanup tasks."""
        handler = GracefulShutdownHandler()
        mock_task = Mock()

        handler.add_cleanup_task(mock_task)

        assert len(handler.cleanup_tasks) == 1
        assert handler.cleanup_tasks[0] == mock_task

    def test_add_multiple_cleanup_tasks(self):
        """Test adding multiple cleanup tasks."""
        handler = GracefulShutdownHandler()
        task1 = Mock()
        task2 = Mock()
        task3 = Mock()

        handler.add_cleanup_task(task1)
        handler.add_cleanup_task(task2)
        handler.add_cleanup_task(task3)

        assert len(handler.cleanup_tasks) == 3
        assert handler.cleanup_tasks == [task1, task2, task3]


class TestGracefulShutdownHandlerSignalHandling:
    """Test signal handling functionality."""

    @pytest.mark.asyncio
    async def test_signal_handler_first_call(self):
        """Test signal handler on first call."""
        handler = GracefulShutdownHandler()

        await handler._signal_handler(signal.SIGTERM)

        assert handler.is_shutting_down is True
        assert handler.shutdown_event.is_set() is True

    @pytest.mark.asyncio
    async def test_signal_handler_multiple_calls(self):
        """Test signal handler ignores subsequent calls."""
        handler = GracefulShutdownHandler()

        # First call
        await handler._signal_handler(signal.SIGTERM)
        assert handler.is_shutting_down is True

        # Reset event to test that it doesn't get set again
        handler.shutdown_event.clear()

        # Second call should be ignored
        await handler._signal_handler(signal.SIGINT)
        assert handler.shutdown_event.is_set() is False

    @pytest.mark.asyncio
    async def test_wait_for_shutdown(self):
        """Test waiting for shutdown signal."""
        handler = GracefulShutdownHandler()

        # Create a task that will set the event after a short delay
        async def trigger_shutdown():
            await asyncio.sleep(0.01)
            handler.shutdown_event.set()

        # Start both tasks
        wait_task = asyncio.create_task(handler.wait_for_shutdown())
        trigger_task = asyncio.create_task(trigger_shutdown())

        # Wait for both to complete
        await asyncio.gather(wait_task, trigger_task)

        # Verify the event was set
        assert handler.shutdown_event.is_set() is True


class TestGracefulShutdownHandlerCleanup:
    """Test cleanup functionality."""

    @pytest.mark.asyncio
    async def test_cleanup_sync_functions(self):
        """Test cleanup with synchronous functions."""
        handler = GracefulShutdownHandler()

        # Create mock tasks
        task1 = Mock()
        task2 = Mock()

        handler.add_cleanup_task(task1)
        handler.add_cleanup_task(task2)

        await handler.cleanup()

        # Verify both tasks were called
        task1.assert_called_once()
        task2.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_async_functions(self):
        """Test cleanup with async functions."""
        handler = GracefulShutdownHandler()

        # Create async mock tasks
        task1 = AsyncMock()
        task2 = AsyncMock()

        handler.add_cleanup_task(task1)
        handler.add_cleanup_task(task2)

        await handler.cleanup()

        # Verify both async tasks were awaited
        task1.assert_awaited_once()
        task2.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cleanup_mixed_functions(self):
        """Test cleanup with mix of sync and async functions."""
        handler = GracefulShutdownHandler()

        # Create mixed tasks
        sync_task = Mock()
        async_task = AsyncMock()

        handler.add_cleanup_task(sync_task)
        handler.add_cleanup_task(async_task)

        await handler.cleanup()

        # Verify both were called appropriately
        sync_task.assert_called_once()
        async_task.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cleanup_with_errors(self):
        """Test cleanup handles errors gracefully."""
        handler = GracefulShutdownHandler()

        # Create tasks where one fails
        good_task = Mock()
        bad_task = Mock(side_effect=Exception("Test error"))

        handler.add_cleanup_task(good_task)
        handler.add_cleanup_task(bad_task)

        # Cleanup should not raise exception
        await handler.cleanup()

        # Both tasks should have been attempted
        good_task.assert_called_once()
        bad_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_empty_tasks(self):
        """Test cleanup with no tasks."""
        handler = GracefulShutdownHandler()

        # Should not raise any exceptions
        await handler.cleanup()

        # No tasks to verify, just ensure it doesn't crash


class TestGracefulShutdownHandlerAsyncCoroutines:
    """Test async coroutine detection and handling."""

    @pytest.mark.asyncio
    async def test_coroutine_function_detection(self):
        """Test that async functions are properly detected and awaited."""
        handler = GracefulShutdownHandler()

        # Track if async function was called
        async_called = False

        async def async_cleanup():
            nonlocal async_called
            async_called = True

        handler.add_cleanup_task(async_cleanup)
        await handler.cleanup()

        assert async_called is True

    @pytest.mark.asyncio
    async def test_regular_function_detection(self):
        """Test that regular functions are called directly."""
        handler = GracefulShutdownHandler()

        # Track if sync function was called
        sync_called = False

        def sync_cleanup():
            nonlocal sync_called
            sync_called = True

        handler.add_cleanup_task(sync_cleanup)
        await handler.cleanup()

        assert sync_called is True


class TestConvenienceFunctions:
    """Test convenience functions."""

    @patch("core.graceful_shutdown.shutdown_handler")
    def test_add_cleanup_task_convenience(self, mock_handler):
        """Test the convenience add_cleanup_task function."""
        mock_task = Mock()

        add_cleanup_task(mock_task)

        mock_handler.add_cleanup_task.assert_called_once_with(mock_task)

    @pytest.mark.asyncio
    @patch("core.graceful_shutdown.shutdown_handler")
    async def test_wait_for_shutdown_convenience(self, mock_handler):
        """Test the convenience wait_for_shutdown function."""
        # Configure mock to return a completed future
        mock_handler.wait_for_shutdown.return_value = asyncio.Future()
        mock_handler.wait_for_shutdown.return_value.set_result(None)

        await wait_for_shutdown()

        mock_handler.wait_for_shutdown.assert_called_once()


class TestGracefulShutdownHandlerEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.asyncio
    async def test_cleanup_with_async_error(self):
        """Test cleanup handles async function errors."""
        handler = GracefulShutdownHandler()

        async def failing_async_task():
            raise ValueError("Async task failed")

        handler.add_cleanup_task(failing_async_task)

        # Should not raise exception
        await handler.cleanup()

    def test_add_cleanup_task_none(self):
        """Test adding None as cleanup task."""
        handler = GracefulShutdownHandler()

        # This should work without error
        handler.add_cleanup_task(None)

        assert len(handler.cleanup_tasks) == 1
        assert handler.cleanup_tasks[0] is None

    @pytest.mark.asyncio
    async def test_cleanup_with_none_task(self):
        """Test cleanup handles None tasks."""
        handler = GracefulShutdownHandler()

        handler.add_cleanup_task(None)

        # Should handle None gracefully
        await handler.cleanup()


class TestGracefulShutdownHandlerIntegration:
    """Integration tests combining multiple features."""

    @pytest.mark.asyncio
    async def test_full_shutdown_workflow(self):
        """Test complete shutdown workflow."""
        handler = GracefulShutdownHandler()

        # Track cleanup execution
        cleanup_executed = []

        def cleanup1():
            cleanup_executed.append("sync1")

        async def cleanup2():
            cleanup_executed.append("async1")

        def cleanup3():
            cleanup_executed.append("sync2")

        # Add cleanup tasks
        handler.add_cleanup_task(cleanup1)
        handler.add_cleanup_task(cleanup2)
        handler.add_cleanup_task(cleanup3)

        # Trigger shutdown signal
        await handler._signal_handler(signal.SIGTERM)

        # Verify shutdown state
        assert handler.is_shutting_down is True
        assert handler.shutdown_event.is_set() is True

        # Execute cleanup
        await handler.cleanup()

        # Verify all cleanups were executed in order
        assert cleanup_executed == ["sync1", "async1", "sync2"]

    @pytest.mark.asyncio
    async def test_multiple_handlers_independence(self):
        """Test that multiple handler instances are independent."""
        handler1 = GracefulShutdownHandler()
        handler2 = GracefulShutdownHandler()

        # Add different tasks to each
        task1 = Mock()
        task2 = Mock()

        handler1.add_cleanup_task(task1)
        handler2.add_cleanup_task(task2)

        # Trigger shutdown on first handler only
        await handler1._signal_handler(signal.SIGTERM)

        assert handler1.is_shutting_down is True
        assert handler2.is_shutting_down is False

        # Cleanup first handler
        await handler1.cleanup()

        # Verify only first task was called
        task1.assert_called_once()
        task2.assert_not_called()


class TestGracefulShutdownHandlerPerformance:
    """Test performance aspects."""

    @pytest.mark.asyncio
    async def test_cleanup_large_number_of_tasks(self):
        """Test cleanup with many tasks."""
        handler = GracefulShutdownHandler()

        # Add 100 tasks
        tasks = [Mock() for _ in range(100)]
        for task in tasks:
            handler.add_cleanup_task(task)

        await handler.cleanup()

        # Verify all tasks were called
        for task in tasks:
            task.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_timing(self):
        """Test that cleanup completes in reasonable time."""
        handler = GracefulShutdownHandler()

        # Add tasks with small delays
        async def slow_task():
            await asyncio.sleep(0.001)

        for _ in range(10):
            handler.add_cleanup_task(slow_task)

        import time

        start = time.time()
        await handler.cleanup()
        duration = time.time() - start

        # Should complete in under 1 second for 10 tasks with 1ms delay each
        assert duration < 1.0
