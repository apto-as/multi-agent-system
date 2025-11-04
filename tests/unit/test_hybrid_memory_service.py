"""
Unit Tests for HybridMemoryService (TMWS v2.2.6)

Tests the hybrid SQLite + Chroma memory service:
- Memory creation with dual storage (SQLite metadata, Chroma vectors)
- Search with Chroma (REQUIRED, no fallback)
- Batch operations
- Cleanup and statistics
"""

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
    session.add_all = MagicMock()
    session.execute = AsyncMock()
    return session


@pytest.fixture
def mock_embedding_service():
    """Mock unified embedding service (1024-dimensional Multilingual-E5 Large)."""
    service = MagicMock()
    service.get_model_info = MagicMock(
        return_value={"model_name": "zylonai/multilingual-e5-large", "dimension": 1024}
    )
    service.encode_document = AsyncMock(return_value=MagicMock(tolist=lambda: [0.1] * 1024))
    service.encode_query = MagicMock(return_value=MagicMock(tolist=lambda: [0.2] * 1024))
    service.encode_batch = AsyncMock(
        return_value=[MagicMock(tolist=lambda: [0.1] * 1024) for _ in range(3)]
    )
    service.compute_similarity = MagicMock(return_value=0.85)
    return service


@pytest.fixture
def mock_vector_service():
    """Mock vector search service."""
    service = AsyncMock()
    service.initialize = MagicMock()
    service.add_memory = AsyncMock()
    service.add_memories_batch = AsyncMock()
    service.delete_memory = AsyncMock()
    service.delete_memories_batch = AsyncMock()
    service.search = AsyncMock(
        return_value=[
            {
                "id": str(uuid4()),
                "content": "Test memory",
                "similarity": 0.9,
                "metadata": {"agent_id": "test-agent", "importance": 0.8},
            }
        ]
    )
    service.get_collection_stats = AsyncMock(return_value={"count": 100})
    return service


@pytest.fixture
def hybrid_service(mock_session, mock_embedding_service, mock_vector_service):
    """Create HybridMemoryService with mocked dependencies."""
    with (
        patch(
            "src.services.memory_service.get_ollama_embedding_service",
            return_value=mock_embedding_service,
        ),
        patch(
            "src.services.memory_service.get_vector_search_service",
            return_value=mock_vector_service,
        ),
    ):
        service = HybridMemoryService(mock_session)
        return service


@pytest.mark.asyncio
async def test_create_memory_success(hybrid_service, mock_session, mock_vector_service):
    """Test successful memory creation with SQLite + Chroma."""
    # Arrange
    memory_id = str(uuid4())  # UUID as string in v2.2.6

    # Mock session.refresh to set the ID
    async def mock_refresh(mem):
        mem.id = memory_id
        mem.created_at = "2025-01-10T00:00:00"

    mock_session.refresh.side_effect = mock_refresh

    # Act
    result = await hybrid_service.create_memory(
        content="Test memory content",
        agent_id="test-agent",
        namespace="test_namespace",
        importance=0.8,
        tags=["test"],
    )

    # Assert
    mock_session.add.assert_called_once()
    mock_session.commit.assert_called_once()
    mock_vector_service.add_memory.assert_called_once()
    assert result.content == "Test memory content"
    assert result.agent_id == "test-agent"


@pytest.mark.asyncio
async def test_create_memory_chroma_failure_raises(
    hybrid_service, mock_session, mock_vector_service
):
    """Test that memory creation fails if Chroma sync fails (v2.2.6: Chroma is REQUIRED)."""
    # Arrange
    mock_vector_service.add_memory.side_effect = Exception("Chroma connection failed")

    # Act & Assert - Should raise RuntimeError
    with pytest.raises(RuntimeError, match="Cannot create memory without Chroma"):
        await hybrid_service.create_memory(
            content="Test memory",
            agent_id="test-agent",
            namespace="test_namespace",
        )

    # Assert - SQLite should be rolled back (may be called by both create_memory and exception handler)
    assert mock_session.rollback.call_count >= 1


@pytest.mark.asyncio
async def test_search_memories_chroma_first(hybrid_service, mock_vector_service, mock_session):
    """Test that search uses Chroma first for performance."""
    # Arrange
    memory_id = uuid4()
    mock_vector_service.search.return_value = [
        {
            "id": str(memory_id),
            "content": "Found memory",
            "similarity": 0.92,
            "metadata": {"agent_id": "test-agent"},
        }
    ]

    # Mock SQLite fetch
    mock_result = MagicMock()
    mock_memory = Memory(
        id=memory_id,
        content="Found memory",
        agent_id="test-agent",
        namespace="default",
        importance_score=0.8,
    )
    mock_result.scalars.return_value.all.return_value = [mock_memory]
    mock_session.execute.return_value = mock_result

    # Act
    results = await hybrid_service.search_memories(
        query="search query",
        agent_id="test-agent",
        namespace="test_namespace",
        min_similarity=0.7,
    )

    # Assert
    mock_vector_service.search.assert_called_once()
    assert len(results) > 0
    assert results[0].similarity == 0.92


@pytest.mark.asyncio
async def test_search_memories_chroma_failure_raises(hybrid_service, mock_vector_service):
    """Test that search fails when Chroma is unavailable (v2.2.6: Chroma is REQUIRED)."""
    # Arrange
    mock_vector_service.search.side_effect = Exception("Chroma unavailable")

    # Act & Assert - Should raise RuntimeError
    with pytest.raises(RuntimeError, match="Cannot search without Chroma"):
        await hybrid_service.search_memories(
            query="search query",
            agent_id="test-agent",
            namespace="test_namespace",
        )


@pytest.mark.asyncio
async def test_batch_create_memories(hybrid_service, mock_session, mock_vector_service):
    """Test batch memory creation with optimized Chroma sync."""
    # Arrange
    memories_data = [
        {"content": "Memory 1", "agent_id": "agent-1", "namespace": "test_namespace", "importance": 0.7},
        {"content": "Memory 2", "agent_id": "agent-2", "namespace": "test_namespace", "importance": 0.8},
        {"content": "Memory 3", "agent_id": "agent-3", "namespace": "test_namespace", "importance": 0.9},
    ]

    # Mock session.refresh to set IDs
    ids = [uuid4() for _ in range(3)]
    refresh_count = [0]

    async def mock_refresh(mem):
        mem.id = ids[refresh_count[0]]
        mem.created_at = "2025-01-10T00:00:00"
        refresh_count[0] += 1

    mock_session.refresh.side_effect = mock_refresh

    # Act
    results = await hybrid_service.batch_create_memories(memories_data)

    # Assert
    assert len(results) == 3
    mock_session.add_all.assert_called_once()
    mock_session.commit.assert_called_once()
    mock_vector_service.add_memories_batch.assert_called_once()


@pytest.mark.asyncio
async def test_update_memory_with_content_change(hybrid_service, mock_session, mock_vector_service):
    """Test that updating content regenerates embedding and re-syncs to Chroma."""
    # Arrange
    memory_id = uuid4()
    original_memory = Memory(
        id=memory_id,
        content="Original content",
        agent_id="test-agent",
        access_level=AccessLevel.PRIVATE,
    )

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = original_memory
    mock_session.execute.return_value = mock_result

    # Act
    updated = await hybrid_service.update_memory(
        memory_id=memory_id,
        content="Updated content",
    )

    # Assert
    assert updated.content == "Updated content"
    mock_vector_service.delete_memory.assert_called_once_with(str(memory_id))
    mock_vector_service.add_memory.assert_called_once()


@pytest.mark.asyncio
async def test_delete_memory_both_stores(hybrid_service, mock_session, mock_vector_service):
    """Test that delete removes from both SQLite and Chroma."""
    # Arrange
    memory_id = uuid4()
    mock_result = MagicMock()
    mock_result.rowcount = 1
    mock_session.execute.return_value = mock_result

    # Act
    deleted = await hybrid_service.delete_memory(memory_id)

    # Assert
    assert deleted is True
    mock_vector_service.delete_memory.assert_called_once_with(str(memory_id))
    mock_session.commit.assert_called_once()


@pytest.mark.asyncio
async def test_get_memory_stats(hybrid_service, mock_session, mock_vector_service):
    """Test combined statistics from SQLite and Chroma."""
    # Arrange
    mock_result = MagicMock()
    mock_result.scalar.return_value = 150
    mock_session.execute.return_value = mock_result

    # Act
    stats = await hybrid_service.get_memory_stats(
        agent_id="test-agent",
        namespace="default",
    )

    # Assert
    assert stats["total_memories"] == 150
    assert stats["chroma_vector_count"] == 100
    assert stats["chroma_available"] is True
    assert stats["embedding_model"] == "zylonai/multilingual-e5-large"
    assert stats["embedding_dimension"] == 1024


@pytest.mark.asyncio
async def test_cleanup_old_memories(hybrid_service, mock_session, mock_vector_service):
    """Test cleanup removes old memories from both stores."""
    # Arrange
    old_memory_ids = [uuid4() for _ in range(5)]

    # Mock select query
    select_result = MagicMock()
    select_result.all.return_value = [(mid,) for mid in old_memory_ids]

    # Mock delete query
    delete_result = MagicMock()
    delete_result.rowcount = 5

    mock_session.execute.side_effect = [select_result, delete_result]

    # Act
    deleted_count = await hybrid_service.cleanup_old_memories(days=90, min_importance=0.3)

    # Assert
    assert deleted_count == 5
    mock_vector_service.delete_memories_batch.assert_called_once()
    mock_session.commit.assert_called_once()


@pytest.mark.asyncio
async def test_chroma_unavailable_raises_error(mock_session, mock_embedding_service):
    """Test that service initialization fails when Chroma is unavailable (v2.2.6: Chroma is REQUIRED)."""
    # Arrange
    with (
        patch(
            "src.services.memory_service.get_ollama_embedding_service",
            return_value=mock_embedding_service,
        ),
        patch("src.services.memory_service.get_vector_search_service") as mock_get_vector,
    ):
        mock_vector = MagicMock()
        mock_vector.initialize = MagicMock(side_effect=Exception("Chroma unavailable"))
        mock_get_vector.return_value = mock_vector

        # Act & Assert - Should raise RuntimeError
        with pytest.raises(RuntimeError, match="Chroma is required"):
            HybridMemoryService(mock_session)
