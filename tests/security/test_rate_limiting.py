"""
Security Tests for Access Tracking Rate Limiting (TMWS v2.3.0 Phase 1B Part 2)

Tests the rate limiting for access tracking to prevent DoS attacks:
- V-RATE-1: Prevents rapid access count inflation spam
- 5-second rate limit window per memory
- Uses existing accessed_at field for tracking

This prevents attackers from rapidly accessing the same memory to inflate
access_count and artificially boost relevance_score.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from src.models.memory import AccessLevel, Memory
from src.services.memory_service import HybridMemoryService


@pytest.fixture
def mock_session():
    """Mock async database session."""
    session = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock()
    session.execute = AsyncMock()
    return session


@pytest.fixture
def mock_agent_service():
    """Mock agent service."""
    return AsyncMock()


@pytest.fixture
def memory_service(mock_session, mock_agent_service):
    """Create HybridMemoryService with mocked dependencies."""
    service = HybridMemoryService(mock_session)
    service.agent_service = mock_agent_service
    return service


def create_test_memory(
    memory_id: str | None = None,
    accessed_at: datetime | None = None,
    access_count: int = 0,
) -> Memory:
    """Create a test Memory object with configurable access tracking state."""
    return Memory(
        id=memory_id or str(uuid4()),
        content="Test memory content",
        agent_id="test-agent",
        namespace="test-namespace",
        importance_score=0.8,
        relevance_score=0.5,
        access_count=access_count,
        accessed_at=accessed_at,
        access_level=AccessLevel.PRIVATE,
        tags=["test"],
        context={},
        embedding_model="zylonai/multilingual-e5-large",
        embedding_dimension=1024,
    )


class TestRateLimitingInitialAccess:
    """Test rate limiting behavior for initial access (no previous access)."""

    @pytest.mark.asyncio
    async def test_first_access_always_tracked(self, memory_service, mock_session):
        """Test that first access (accessed_at=None) is always tracked."""
        # Arrange
        memory_id = str(uuid4())
        test_memory = create_test_memory(
            memory_id=memory_id,
            accessed_at=None,  # Never accessed before
            access_count=0,
        )

        # Mock database response
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result

        # Act
        result = await memory_service.get_memory(memory_id, track_access=True)

        # Assert
        assert result is not None
        assert result.access_count == 1  # Tracked
        mock_session.commit.assert_called_once()


class TestRateLimitingWithinWindow:
    """Test rate limiting when accessing within the 5-second window."""

    @pytest.mark.asyncio
    async def test_rapid_access_rate_limited(self, memory_service, mock_session):
        """Test that access within 5 seconds is rate limited (V-RATE-1)."""
        # Arrange
        memory_id = str(uuid4())
        now = datetime.now(timezone.utc)
        # Last accessed 2 seconds ago (within 5-second window)
        last_access = now - timedelta(seconds=2)

        test_memory = create_test_memory(
            memory_id=memory_id,
            accessed_at=last_access,
            access_count=5,  # Already accessed 5 times
        )

        # Mock database response
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result

        # Mock datetime.now() to return consistent time
        with patch("src.models.memory.datetime") as mock_datetime:
            mock_datetime.now.return_value = now
            mock_datetime.utcnow.return_value = now
            mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

            # Act
            result = await memory_service.get_memory(memory_id, track_access=True)

        # Assert - Access NOT tracked (rate limited)
        assert result is not None
        assert result.access_count == 5  # NOT incremented
        mock_session.commit.assert_not_called()  # No update

    @pytest.mark.asyncio
    async def test_access_at_boundary_rate_limited(self, memory_service, mock_session):
        """Test that access at exactly 4.9 seconds is still rate limited."""
        # Arrange
        memory_id = str(uuid4())
        now = datetime.now(timezone.utc)
        # Last accessed 4.9 seconds ago (just under 5-second limit)
        last_access = now - timedelta(seconds=4.9)

        test_memory = create_test_memory(
            memory_id=memory_id,
            accessed_at=last_access,
            access_count=10,
        )

        # Mock database response
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result

        with patch("src.models.memory.datetime") as mock_datetime:
            mock_datetime.now.return_value = now
            mock_datetime.utcnow.return_value = now
            mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

            # Act
            result = await memory_service.get_memory(memory_id, track_access=True)

        # Assert - Still rate limited
        assert result.access_count == 10  # NOT incremented
        mock_session.commit.assert_not_called()


class TestRateLimitingOutsideWindow:
    """Test rate limiting when accessing outside the 5-second window."""

    @pytest.mark.asyncio
    async def test_access_after_window_tracked(self, memory_service, mock_session):
        """Test that access after 5 seconds is tracked normally."""
        # Arrange
        memory_id = str(uuid4())
        now = datetime.now(timezone.utc)
        # Last accessed 6 seconds ago (outside 5-second window)
        last_access = now - timedelta(seconds=6)

        test_memory = create_test_memory(
            memory_id=memory_id,
            accessed_at=last_access,
            access_count=3,
        )

        # Mock database response
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result

        with patch("src.models.memory.datetime") as mock_datetime:
            mock_datetime.now.return_value = now
            mock_datetime.utcnow.return_value = now
            mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

            # Act
            result = await memory_service.get_memory(memory_id, track_access=True)

        # Assert - Access tracked
        assert result.access_count == 4  # Incremented
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_access_at_exact_boundary_tracked(self, memory_service, mock_session):
        """Test that access at exactly 5.0 seconds is tracked."""
        # Arrange
        memory_id = str(uuid4())
        now = datetime.now(timezone.utc)
        # Last accessed exactly 5.0 seconds ago (boundary)
        last_access = now - timedelta(seconds=5.0)

        test_memory = create_test_memory(
            memory_id=memory_id,
            accessed_at=last_access,
            access_count=7,
        )

        # Mock database response
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result

        with patch("src.models.memory.datetime") as mock_datetime:
            mock_datetime.now.return_value = now
            mock_datetime.utcnow.return_value = now
            mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

            # Act
            result = await memory_service.get_memory(memory_id, track_access=True)

        # Assert - Access tracked (>= 5 seconds)
        assert result.access_count == 8  # Incremented
        mock_session.commit.assert_called_once()


class TestRateLimitingWithTrackAccessFalse:
    """Test that track_access=False bypasses rate limiting."""

    @pytest.mark.asyncio
    async def test_track_false_bypasses_rate_limit(self, memory_service, mock_session):
        """Test that track_access=False skips both rate limiting and tracking."""
        # Arrange
        memory_id = str(uuid4())
        now = datetime.now(timezone.utc)
        # Last accessed 1 second ago (within rate limit)
        last_access = now - timedelta(seconds=1)

        test_memory = create_test_memory(
            memory_id=memory_id,
            accessed_at=last_access,
            access_count=5,
        )

        # Mock database response
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result

        # Act - Admin query (no tracking)
        result = await memory_service.get_memory(memory_id, track_access=False)

        # Assert - No tracking, no rate limiting check
        assert result.access_count == 5  # NOT incremented
        mock_session.commit.assert_not_called()


class TestRateLimitingSequentialAccesses:
    """Test rate limiting behavior over multiple sequential accesses."""

    @pytest.mark.asyncio
    async def test_sequential_accesses_respect_rate_limit(self, memory_service, mock_session):
        """Test that multiple rapid accesses are properly rate limited."""
        # Arrange
        memory_id = str(uuid4())
        base_time = datetime.now(timezone.utc)

        test_memory = create_test_memory(
            memory_id=memory_id,
            accessed_at=None,  # Initial state
            access_count=0,
        )

        # Mock database response
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result

        # Simulate 5 rapid accesses over 10 seconds
        access_times = [
            base_time,  # T+0s: Tracked (first access)
            base_time + timedelta(seconds=2),  # T+2s: Rate limited
            base_time + timedelta(seconds=4),  # T+4s: Rate limited
            base_time + timedelta(seconds=6),  # T+6s: Tracked (>5s from T+0s)
            base_time + timedelta(seconds=8),  # T+8s: Rate limited (only 2s from T+6s)
        ]

        tracked_count = 0
        for current_time in access_times:
            # Patch BOTH datetime in memory service AND memory model
            with (
                patch("src.services.memory_service.datetime") as mock_svc_dt,
                patch("src.models.memory.datetime") as mock_model_dt,
            ):
                # Mock datetime for rate limit check in service
                mock_svc_dt.now.return_value = current_time
                mock_svc_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)

                # Mock datetime for update_access() in model
                mock_model_dt.now.return_value = current_time
                mock_model_dt.utcnow.return_value = current_time
                mock_model_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)

                await memory_service.get_memory(memory_id, track_access=True)

                # Count actual commits (successful tracking)
                if mock_session.commit.called:
                    tracked_count += 1
                    # Update test_memory state for next iteration
                    test_memory.accessed_at = current_time
                    test_memory.access_count += 1
                    mock_session.commit.reset_mock()

        # Assert - Only 2 accesses tracked (T+0s and T+6s)
        assert tracked_count == 2


class TestRateLimitingEdgeCases:
    """Test edge cases for rate limiting."""

    @pytest.mark.asyncio
    async def test_timezone_aware_rate_limiting(self, memory_service, mock_session):
        """Test that rate limiting works correctly with timezone-aware datetimes."""
        # Arrange
        memory_id = str(uuid4())
        now_utc = datetime.now(timezone.utc)
        last_access_utc = now_utc - timedelta(seconds=3)

        test_memory = create_test_memory(
            memory_id=memory_id,
            accessed_at=last_access_utc,  # UTC timezone
            access_count=5,
        )

        # Mock database response
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result

        with patch("src.models.memory.datetime") as mock_datetime:
            mock_datetime.now.return_value = now_utc
            mock_datetime.utcnow.return_value = now_utc
            mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

            # Act
            result = await memory_service.get_memory(memory_id, track_access=True)

        # Assert - Rate limited (3 seconds < 5 seconds)
        assert result.access_count == 5
        mock_session.commit.assert_not_called()
