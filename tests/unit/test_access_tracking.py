"""
Unit Tests for Access Tracking Feature (TMWS v2.3.0 Phase 1A Part 1)

Tests the access tracking functionality of get_memory():
- Automatic increment of access_count when track_access=True (default)
- No increment when track_access=False (opt-out for admin queries)
- Update of accessed_at timestamp
- Relevance score calculation
- Concurrent access handling
"""

import asyncio
from datetime import datetime, timezone
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
def memory_service(mock_session):
    """Create HybridMemoryService with mocked session."""
    # Note: We'll mock the dependencies at the test level
    return HybridMemoryService(mock_session)


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
    """Test that multiple get_memory() calls increment access_count correctly."""
    # Arrange
    memory_id = str(uuid4())
    test_memory = create_test_memory(memory_id)

    # Mock database response
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = test_memory
    mock_session.execute.return_value = mock_result

    # Act - Access memory 3 times
    result1 = await memory_service.get_memory(memory_id, track_access=True)
    result2 = await memory_service.get_memory(memory_id, track_access=True)
    result3 = await memory_service.get_memory(memory_id, track_access=True)

    # Assert
    # Note: result1, result2, result3 all point to the same test_memory object instance
    # So they all show the final access_count after 3 updates
    assert result1 is test_memory  # Same object
    assert result2 is test_memory  # Same object
    assert result3 is test_memory  # Same object
    assert test_memory.access_count == 3  # All 3 accesses tracked
    assert mock_session.commit.call_count == 3  # 3 commits


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
    """Test that accessed_at is updated to current UTC time."""
    # Arrange
    memory_id = str(uuid4())
    test_memory = create_test_memory(memory_id)

    # Mock database response
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = test_memory
    mock_session.execute.return_value = mock_result

    # Record time before access
    time_before = datetime.utcnow()

    # Act
    result = await memory_service.get_memory(memory_id, track_access=True)

    # Record time after access
    time_after = datetime.utcnow()

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
    """Test that concurrent accesses to the same memory increment count correctly."""
    # Arrange
    memory_id = str(uuid4())
    test_memory = create_test_memory(memory_id)

    # Mock database response
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = test_memory
    mock_session.execute.return_value = mock_result

    # Act - Concurrent accesses
    tasks = [
        memory_service.get_memory(memory_id, track_access=True)
        for _ in range(5)
    ]
    results = await asyncio.gather(*tasks)

    # Assert
    assert len(results) == 5
    # Final access_count should be 5 (all accesses tracked)
    # Note: In production, database locking would ensure atomicity
    assert test_memory.access_count == 5
    assert mock_session.commit.call_count == 5
