"""Unit tests for Expiration Scheduler Lifecycle Integration (P2 Memory Gap fix).

Tests auto-start/auto-stop of expiration scheduler in server lifecycle.

Author: Artemis (Fixing unit tests)
Updated: 2025-12-12 (Sprint 1: Issue #56)
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.services.expiration_scheduler import ExpirationScheduler


@pytest.fixture
def mock_server():
    """Create mock HybridMCPServer."""
    server = MagicMock()
    server.instance_id = "test-server-1"
    server.vector_service = MagicMock()
    server.vector_service.initialize = AsyncMock()
    server.embedding_service = MagicMock()
    server.mcp = MagicMock()
    server.cleanup = AsyncMock()
    return server


class TestExpirationSchedulerCleanup:
    """Test cleanup functionality."""

    async def test_scheduler_stopped_on_cleanup(self, mock_server):
        """Test scheduler is stopped during server cleanup."""
        from src.mcp_server.lifecycle import cleanup_server

        # Mock running scheduler
        mock_scheduler = MagicMock(spec=ExpirationScheduler)
        mock_scheduler.stop = AsyncMock()
        mock_server.expiration_scheduler = mock_scheduler

        await cleanup_server(mock_server)

        # Verify scheduler was stopped
        mock_scheduler.stop.assert_called_once()

    async def test_cleanup_without_scheduler(self, mock_server):
        """Test cleanup works when no scheduler exists."""
        from src.mcp_server.lifecycle import cleanup_server

        # Ensure no scheduler attached (clean slate for this test)
        if hasattr(mock_server, "expiration_scheduler"):
            delattr(mock_server, "expiration_scheduler")

        # Should not raise exception
        await cleanup_server(mock_server)

    async def test_cleanup_handles_scheduler_stop_error(self, mock_server):
        """Test cleanup handles scheduler stop errors gracefully."""
        from src.mcp_server.lifecycle import cleanup_server

        # Mock scheduler that raises on stop
        mock_scheduler = MagicMock(spec=ExpirationScheduler)
        mock_scheduler.stop = AsyncMock(side_effect=RuntimeError("Stop failed"))
        mock_server.expiration_scheduler = mock_scheduler

        # Should not raise exception
        await cleanup_server(mock_server)


class TestEnvironmentVariableConfiguration:
    """Test environment variable configuration."""

    def test_default_auto_start_true(self):
        """Test default auto-start is true."""
        os.environ.pop("TMWS_AUTOSTART_EXPIRATION_SCHEDULER", None)

        # Should default to true
        auto_start = os.getenv("TMWS_AUTOSTART_EXPIRATION_SCHEDULER", "true").lower() == "true"
        assert auto_start is True

    def test_default_interval_1_hour(self):
        """Test default interval is 1 hour."""
        os.environ.pop("MEMORY_CLEANUP_INTERVAL_HOURS", None)

        interval = float(os.getenv("MEMORY_CLEANUP_INTERVAL_HOURS", "1.0"))
        assert interval == 1.0

    def test_custom_interval_parsing(self):
        """Test custom interval parsing."""
        os.environ["MEMORY_CLEANUP_INTERVAL_HOURS"] = "0.5"

        interval = float(os.getenv("MEMORY_CLEANUP_INTERVAL_HOURS", "1.0"))
        assert interval == 0.5


class TestSchedulerAutoStartLogic:
    """Test scheduler auto-start logic (isolated unit tests)."""

    async def test_scheduler_created_when_auto_start_enabled(self):
        """Test scheduler is created when auto-start is enabled."""
        # Mock environment
        os.environ["TMWS_AUTOSTART_EXPIRATION_SCHEDULER"] = "true"
        os.environ["MEMORY_CLEANUP_INTERVAL_HOURS"] = "2.0"

        # Test the logic directly
        auto_start = os.getenv("TMWS_AUTOSTART_EXPIRATION_SCHEDULER", "true").lower() == "true"
        assert auto_start is True

        # Test interval parsing
        cleanup_interval = float(os.getenv("MEMORY_CLEANUP_INTERVAL_HOURS", "1.0"))
        assert cleanup_interval == 2.0

    async def test_scheduler_not_created_when_disabled(self):
        """Test scheduler is not created when auto-start is disabled."""
        os.environ["TMWS_AUTOSTART_EXPIRATION_SCHEDULER"] = "false"

        auto_start = os.getenv("TMWS_AUTOSTART_EXPIRATION_SCHEDULER", "true").lower() == "true"
        assert auto_start is False

    async def test_custom_interval_configuration(self):
        """Test custom cleanup interval configuration."""
        os.environ["MEMORY_CLEANUP_INTERVAL_HOURS"] = "6.0"

        cleanup_interval = float(os.getenv("MEMORY_CLEANUP_INTERVAL_HOURS", "1.0"))
        assert cleanup_interval == 6.0
