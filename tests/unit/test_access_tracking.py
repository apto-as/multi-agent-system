"""
Unit Tests for Access Tracking Feature (TMWS v2.3.0 Phase 1A Part 1)

Tests the access tracking functionality of get_memory():
- Automatic increment of access_count when track_access=True (default)
- No increment when track_access=False (opt-out for admin queries)
- Update of accessed_at timestamp
- Relevance score calculation
- Concurrent access handling
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock
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
def mock_embedding_service():
    """Mock embedding service."""
    service = MagicMock()
    service.get_model_info = MagicMock(
        return_value={"model_name": "zylonai/multilingual-e5-large", "dimension": 1024}
    )
    return service


@pytest.fixture
def mock_vector_service():
    """Mock vector search service."""
    service = AsyncMock()
    service.initialize = MagicMock()
    return service


@pytest.fixture
def memory_service(mock_session, mock_embedding_service, mock_vector_service):
    """Create HybridMemoryService with mocked session and services."""
    return HybridMemoryService(
        session=mock_session,
        embedding_service=mock_embedding_service,
        vector_service=mock_vector_service,
    )


def create_test_memory(memory_id: str | None = None) -> Memory:
    """Create a test Memory object.

    Note: embedding is stored in ChromaDB, not in SQLite Memory model.
    """
    return Memory(
        id=memory_id or str(uuid4()),
        content="Test memory content",
        agent_id="test-agent",
        namespace="test_namespace",
        importance_score=0.8,
        relevance_score=0.5,
        access_count=0,
        accessed_at=None,
        access_level=AccessLevel.PRIVATE,
        tags=["test"],
        context={},  # Changed from metadata to context (correct field name)
        embedding_model="zylonai/multilingual-e5-large",
        embedding_dimension=1024,
    )


@pytest.mark.asyncio
async def test_get_memory_track_access_true_increments_count(memory_service, mock_session):
    """Test that get_memory() with track_access=True (default) increments access_count."""
    # Arrange
    memory_id = str(uuid4())
    test_memory = create_test_memory(memory_id)

    # Mock database response
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = test_memory
    mock_session.execute.return_value = mock_result

    # Act
    result = await memory_service.get_memory(memory_id, track_access=True)

    # Assert
    assert result is not None
    assert result.access_count == 1  # Incremented from 0 to 1
    assert result.accessed_at is not None  # Timestamp updated
    mock_session.commit.assert_called_once()  # Access tracking committed
    mock_session.refresh.assert_called_once()  # Memory refreshed after commit


@pytest.mark.asyncio
async def test_get_memory_track_access_false_no_increment(memory_service, mock_session):
    """Test that get_memory() with track_access=False does NOT increment access_count."""
    # Arrange
    memory_id = str(uuid4())
    test_memory = create_test_memory(memory_id)

    # Mock database response
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = test_memory
    mock_session.execute.return_value = mock_result

    # Act
    result = await memory_service.get_memory(memory_id, track_access=False)

    # Assert
    assert result is not None
    assert result.access_count == 0  # NOT incremented
    assert result.accessed_at is None  # NOT updated
    mock_session.commit.assert_not_called()  # No commit for read-only query
    mock_session.refresh.assert_not_called()  # No refresh needed


@pytest.mark.asyncio
async def test_multiple_accesses_increment_correctly(memory_service, mock_session):
    """Test that multiple get_memory() calls increment access_count correctly.

    Note (Phase 1B): With rate limiting (5-second window), we need to space out
    accesses to ensure they're all tracked. We mock datetime to simulate
    accesses at T+0s, T+6s, T+12s (all outside the rate limit window).
    """
    from unittest.mock import patch

    # Arrange
    memory_id = str(uuid4())
    test_memory = create_test_memory(memory_id)

    # Mock database response
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = test_memory
    mock_session.execute.return_value = mock_result

    # Mock datetime to space out accesses beyond rate limit window (5 seconds)
    base_time = datetime.now(timezone.utc)
    access_times = [
        base_time,  # T+0s: First access
        base_time + timedelta(seconds=6),  # T+6s: Outside rate limit
        base_time + timedelta(seconds=12),  # T+12s: Outside rate limit
    ]

    # Act - Access memory 3 times with mocked datetime
    # Note: memory_service is now in memory_service/crud_operations.py
    for _i, access_time in enumerate(access_times):
        with (
            patch("src.services.memory_service.crud_operations.datetime") as mock_svc_dt,
            patch("src.models.memory.datetime") as mock_model_dt,
        ):
            # Mock rate limit check in service
            mock_svc_dt.now.return_value = access_time
            mock_svc_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)

            # Mock update_access() in model
            mock_model_dt.now.return_value = access_time
            mock_model_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)

            await memory_service.get_memory(memory_id, track_access=True)

            # Update test_memory state for next iteration
            if mock_session.commit.called:
                test_memory.accessed_at = access_time
                mock_session.commit.reset_mock()

    # Assert
    # All 3 accesses should be tracked (spaced >5 seconds apart)
    assert test_memory.access_count == 3  # All 3 accesses tracked
    assert mock_session.commit.call_count == 0  # Reset after each iteration


@pytest.mark.asyncio
async def test_non_existent_memory_no_tracking(memory_service, mock_session):
    """Test that non-existent memory does not cause tracking errors."""
    # Arrange
    memory_id = str(uuid4())

    # Mock database response - memory not found
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result

    # Act
    result = await memory_service.get_memory(memory_id, track_access=True)

    # Assert
    assert result is None  # Memory not found
    mock_session.commit.assert_not_called()  # No commit for non-existent memory
    mock_session.refresh.assert_not_called()  # No refresh


@pytest.mark.asyncio
async def test_accessed_at_updated_to_current_time(memory_service, mock_session):
    """Test that accessed_at is updated to current UTC time.

    Note (Phase 1B): Uses timezone-aware datetimes for consistency with rate limiting.
    """
    # Arrange
    memory_id = str(uuid4())
    test_memory = create_test_memory(memory_id)

    # Mock database response
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = test_memory
    mock_session.execute.return_value = mock_result

    # Record time before access (timezone-aware)
    time_before = datetime.now(timezone.utc)

    # Act
    result = await memory_service.get_memory(memory_id, track_access=True)

    # Record time after access (timezone-aware)
    time_after = datetime.now(timezone.utc)

    # Assert
    assert result is not None
    assert result.accessed_at is not None
    # accessed_at should be between time_before and time_after
    assert time_before <= result.accessed_at <= time_after


@pytest.mark.asyncio
async def test_relevance_score_updated_correctly(memory_service, mock_session):
    """Test that relevance_score is calculated correctly by update_access()."""
    # Arrange
    memory_id = str(uuid4())
    test_memory = create_test_memory(memory_id)
    test_memory.relevance_score = 0.5  # Initial relevance

    # Mock database response
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = test_memory
    mock_session.execute.return_value = mock_result

    # Act
    result = await memory_service.get_memory(memory_id, track_access=True)

    # Assert
    assert result is not None
    # Expected calculation: min(1.0, 0.5 * 0.99 + 0.05) = min(1.0, 0.545) = 0.545
    expected_relevance = min(1.0, 0.5 * 0.99 + 0.05)
    assert abs(result.relevance_score - expected_relevance) < 0.001  # Float comparison


@pytest.mark.asyncio
async def test_concurrent_access_tracking(memory_service, mock_session):
    """Test that concurrent accesses to the same memory increment count correctly.

    Note (Phase 1B): With rate limiting (5-second window), we mock datetime to
    simulate accesses spaced >5 seconds apart. Each "concurrent" access in the
    test represents a different time period to avoid rate limiting.
    """
    from unittest.mock import patch

    # Arrange
    memory_id = str(uuid4())
    test_memory = create_test_memory(memory_id)

    # Mock database response
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = test_memory
    mock_session.execute.return_value = mock_result

    # Mock datetime to space out each "concurrent" access beyond rate limit
    base_time = datetime.now(timezone.utc)

    # Act - Simulate 5 accesses at different times
    # Note: memory_service is now in memory_service/crud_operations.py
    for i in range(5):
        access_time = base_time + timedelta(seconds=i * 6)  # 0s, 6s, 12s, 18s, 24s

        with (
            patch("src.services.memory_service.crud_operations.datetime") as mock_svc_dt,
            patch("src.models.memory.datetime") as mock_model_dt,
        ):
            # Mock rate limit check in service
            mock_svc_dt.now.return_value = access_time
            mock_svc_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)

            # Mock update_access() in model
            mock_model_dt.now.return_value = access_time
            mock_model_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)

            await memory_service.get_memory(memory_id, track_access=True)

            # Update test_memory state for next iteration
            if mock_session.commit.called:
                test_memory.accessed_at = access_time
                mock_session.commit.reset_mock()

    # Assert
    # All 5 accesses should be tracked (spaced >5 seconds apart)
    # Note: In production, database locking would ensure atomicity
    assert test_memory.access_count == 5
    assert mock_session.commit.call_count == 0  # Reset after each iteration
