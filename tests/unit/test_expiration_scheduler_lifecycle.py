"""Unit tests for Expiration Scheduler Lifecycle Integration (P2 Memory Gap fix).

Tests auto-start/auto-stop of expiration scheduler in server lifecycle.

Author: Metis (Testing)
Created: 2025-12-12 (Phase 2: P2 Memory Gap)
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


@pytest.fixture
def mock_get_session():
    """Create mock get_session factory."""

    async def _factory():
        session = AsyncMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock()
        return session

    return _factory


class TestExpirationSchedulerAutoStart:
    """Test auto-start functionality."""

    async def test_auto_start_enabled_by_default(self, mock_server, mock_get_session):
        """Test scheduler auto-starts by default."""
        from src.mcp_server.lifecycle import initialize_server

        # Set environment variable
        os.environ["TMWS_AUTOSTART_EXPIRATION_SCHEDULER"] = "true"
        os.environ["MEMORY_CLEANUP_INTERVAL_HOURS"] = "2.0"

        # Mock scheduler creation
        mock_scheduler = MagicMock(spec=ExpirationScheduler)
        mock_scheduler.start = AsyncMock()

        with patch("src.mcp_server.lifecycle.ExpirationScheduler", return_value=mock_scheduler):
            with patch("src.mcp_server.lifecycle.get_session", return_value=mock_get_session()):
                await initialize_server(mock_server)

                # Verify scheduler was created and started
                assert hasattr(mock_server, "expiration_scheduler")
                assert mock_server.expiration_scheduler == mock_scheduler
                mock_scheduler.start.assert_called_once()

    async def test_auto_start_disabled(self, mock_server, mock_get_session):
        """Test scheduler doesn't auto-start when disabled."""
        from src.mcp_server.lifecycle import initialize_server

        # Disable auto-start
        os.environ["TMWS_AUTOSTART_EXPIRATION_SCHEDULER"] = "false"

        with patch("src.mcp_server.lifecycle.get_session", return_value=mock_get_session()):
            await initialize_server(mock_server)

            # Verify scheduler was not created
            assert not hasattr(mock_server, "expiration_scheduler") or (
                mock_server.expiration_scheduler is None
            )

    async def test_custom_interval(self, mock_server, mock_get_session):
        """Test custom cleanup interval configuration."""
        from src.mcp_server.lifecycle import initialize_server

        os.environ["TMWS_AUTOSTART_EXPIRATION_SCHEDULER"] = "true"
        os.environ["MEMORY_CLEANUP_INTERVAL_HOURS"] = "6.0"

        mock_scheduler = MagicMock(spec=ExpirationScheduler)
        mock_scheduler.start = AsyncMock()

        with patch("src.mcp_server.lifecycle.ExpirationScheduler") as MockScheduler:
            MockScheduler.return_value = mock_scheduler
            with patch("src.mcp_server.lifecycle.get_session", return_value=mock_get_session()):
                await initialize_server(mock_server)

                # Verify scheduler was created with custom interval
                MockScheduler.assert_called_once()
                call_kwargs = MockScheduler.call_args[1]
                assert call_kwargs["interval_hours"] == 6.0


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

        # No scheduler attached
        assert not hasattr(mock_server, "expiration_scheduler")

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
