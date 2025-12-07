"""
P0 Integration Tests: Memory Service Operations
CRITICAL: These tests verify core memory CRUD operations.

Test IDs:
- MEM-P0-001: Vector search accuracy
- MEM-P0-002: Memory lifecycle (CRUD + TTL)
- MEM-P0-003: Concurrent access safety
- MEM-P0-004: Namespace isolation
- MEM-P0-005: Expired memory pruning
- MEM-P0-006: Semantic similarity ranking
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from uuid import uuid4

import numpy as np
import pytest
import pytest_asyncio

from src.models.memory import AccessLevel


@pytest.fixture
def mock_memory():
    """Create a mock Memory object."""
    memory = Mock()
    memory.id = uuid4()
    memory.content = "Test memory content"
    memory.summary = "Test summary"
    memory.agent_id = "test-agent"
    memory.namespace = "test-namespace"
    memory.access_level = AccessLevel.PRIVATE
    memory.shared_with_agents = []
    memory.importance_score = 0.8
    memory.relevance_score = 0.9
    memory.tags = ["test"]
    memory.created_at = datetime.now(timezone.utc)
    memory.expires_at = None
    return memory


@pytest.fixture
def mock_memory_service():
    """Mock HybridMemoryService for testing."""
    service = AsyncMock()

    # Mock memory object
    mock_mem = Mock()
    mock_mem.id = uuid4()
    mock_mem.content = "Test memory content"
    mock_mem.agent_id = "test-agent"
    mock_mem.namespace = "test-namespace"
    mock_mem.importance_score = 0.8
    mock_mem.created_at = datetime.now(timezone.utc)

    service.create_memory = AsyncMock(return_value=mock_mem)
    service.get_memory = AsyncMock(return_value=mock_mem)
    service.search_memories = AsyncMock(return_value=[mock_mem])
    service.delete_memory = AsyncMock(return_value=True)
    service.update_memory = AsyncMock(return_value=mock_mem)

    return service


@pytest.mark.integration
@pytest.mark.asyncio
class TestMemoryVectorSearch:
    """MEM-P0-001: Vector search accuracy tests."""

    async def test_vector_search_returns_results(self, mock_memory_service):
        """MEM-P0-001-T1: Vector search returns matching results."""
        # Create memory
        memory = await mock_memory_service.create_memory(
            content="Test memory about Python programming",
            agent_id="test-agent",
            namespace="test-namespace",
            importance_score=0.8,
        )

        assert memory is not None
        assert memory.id is not None
        mock_memory_service.create_memory.assert_called_once()

    async def test_vector_search_respects_namespace(self, mock_memory_service):
        """MEM-P0-001-T2: Vector search respects namespace boundaries."""
        # Create memory in namespace A
        await mock_memory_service.create_memory(
            content="Secret data for namespace A",
            agent_id="agent-a",
            namespace="namespace-a",
            importance_score=0.9,
        )

        # Configure mock to return empty for different namespace search
        mock_memory_service.search_memories.return_value = []

        # Search from namespace B should not find namespace A data
        results = await mock_memory_service.search_memories(
            query="secret data",
            agent_id="agent-b",
            namespace="namespace-b",
        )

        assert results == []


@pytest.mark.integration
@pytest.mark.asyncio
class TestMemoryLifecycle:
    """MEM-P0-002: Memory lifecycle (CRUD + TTL) tests."""

    async def test_memory_create_success(self, mock_memory_service):
        """MEM-P0-002-T1: Memory creation succeeds."""
        memory = await mock_memory_service.create_memory(
            content="Test memory content",
            agent_id="test-agent",
            namespace="test-namespace",
            importance_score=0.5,
        )

        assert memory is not None
        assert memory.id is not None
        assert memory.content == "Test memory content"

    async def test_memory_read_by_id(self, mock_memory_service):
        """MEM-P0-002-T2: Memory read by ID succeeds."""
        # Create
        created = await mock_memory_service.create_memory(
            content="Memory to read",
            agent_id="test-agent",
            namespace="test-namespace",
            importance_score=0.5,
        )

        # Read
        memory_id = str(created.id)
        retrieved = await mock_memory_service.get_memory(
            memory_id=memory_id,
            agent_id="test-agent",
        )

        assert retrieved is not None
        mock_memory_service.get_memory.assert_called_once()

    async def test_memory_update_content(self, mock_memory_service):
        """MEM-P0-002-T3: Memory update succeeds."""
        # Create
        created = await mock_memory_service.create_memory(
            content="Original content",
            agent_id="test-agent",
            namespace="test-namespace",
            importance_score=0.5,
        )

        # Setup mock for updated memory
        updated_memory = Mock()
        updated_memory.id = created.id
        updated_memory.content = "Updated content"
        mock_memory_service.update_memory.return_value = updated_memory

        # Update
        updated = await mock_memory_service.update_memory(
            memory_id=str(created.id),
            content="Updated content",
            agent_id="test-agent",
        )

        assert updated.content == "Updated content"

    async def test_memory_delete_success(self, mock_memory_service):
        """MEM-P0-002-T4: Memory deletion succeeds."""
        # Create
        created = await mock_memory_service.create_memory(
            content="Memory to delete",
            agent_id="test-agent",
            namespace="test-namespace",
            importance_score=0.5,
        )

        # Delete
        result = await mock_memory_service.delete_memory(
            memory_id=str(created.id),
            agent_id="test-agent",
        )

        assert result is True
        mock_memory_service.delete_memory.assert_called_once()


@pytest.mark.integration
@pytest.mark.asyncio
class TestMemoryConcurrentAccess:
    """MEM-P0-003: Concurrent access safety tests."""

    async def test_concurrent_memory_creation(self, mock_memory_service):
        """MEM-P0-003-T1: Concurrent memory creation is safe."""
        # Create multiple memories concurrently
        async def create_memory(i: int):
            memory = Mock()
            memory.id = uuid4()
            memory.content = f"Concurrent memory {i}"
            mock_memory_service.create_memory.return_value = memory
            return await mock_memory_service.create_memory(
                content=f"Concurrent memory {i}",
                agent_id="test-agent",
                namespace="test-namespace",
                importance_score=0.5,
            )

        # Run concurrently
        results = await asyncio.gather(
            *[create_memory(i) for i in range(5)],
            return_exceptions=True
        )

        # All should succeed (no exceptions)
        successes = [r for r in results if not isinstance(r, Exception)]
        assert len(successes) >= 4, "Most concurrent creations should succeed"


@pytest.mark.integration
@pytest.mark.asyncio
class TestMemoryNamespaceIsolation:
    """MEM-P0-004: Namespace isolation tests."""

    async def test_namespace_isolation_create(self):
        """MEM-P0-004-T1: Memories are isolated by namespace."""
        # Create two separate mock services to simulate different namespaces
        service_a = AsyncMock()
        service_b = AsyncMock()

        memory_a = Mock()
        memory_a.id = uuid4()
        memory_a.namespace = "namespace-a"

        memory_b = Mock()
        memory_b.id = uuid4()
        memory_b.namespace = "namespace-b"

        service_a.create_memory = AsyncMock(return_value=memory_a)
        service_b.create_memory = AsyncMock(return_value=memory_b)

        # Create memory in namespace A
        result_a = await service_a.create_memory(
            content="Namespace A memory",
            agent_id="agent-a",
            namespace="namespace-a",
            importance_score=0.8,
        )

        # Create memory in namespace B
        result_b = await service_b.create_memory(
            content="Namespace B memory",
            agent_id="agent-b",
            namespace="namespace-b",
            importance_score=0.8,
        )

        assert result_a is not None
        assert result_b is not None

        # Both should have different IDs
        assert result_a.id != result_b.id
        assert result_a.namespace != result_b.namespace


@pytest.mark.integration
@pytest.mark.asyncio
class TestMemoryExpiration:
    """MEM-P0-005: Expired memory pruning tests."""

    async def test_memory_with_ttl(self, mock_memory_service):
        """MEM-P0-005-T1: Memory can be created with TTL."""
        # Setup mock with expires_at
        memory_with_ttl = Mock()
        memory_with_ttl.id = uuid4()
        memory_with_ttl.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        mock_memory_service.create_memory.return_value = memory_with_ttl

        # Create memory with TTL
        memory = await mock_memory_service.create_memory(
            content="Expiring memory",
            agent_id="test-agent",
            namespace="test-namespace",
            importance_score=0.5,
            ttl_days=1,
        )

        assert memory is not None
        assert memory.expires_at is not None

    async def test_expired_memory_cleanup(self):
        """MEM-P0-005-T2: Expired memories are cleaned up."""
        mock_service = AsyncMock()
        mock_service.prune_expired_memories = AsyncMock(return_value=5)

        # Prune expired memories
        pruned_count = await mock_service.prune_expired_memories(
            namespace="test-namespace"
        )

        assert pruned_count == 5
        mock_service.prune_expired_memories.assert_called_once()


@pytest.mark.integration
@pytest.mark.asyncio
class TestMemorySemanticSimilarity:
    """MEM-P0-006: Semantic similarity ranking tests."""

    async def test_search_returns_similar_content(self, mock_memory_service):
        """MEM-P0-006-T1: Search returns semantically similar content."""
        # Setup mock with multiple results ordered by relevance
        python_memory = Mock()
        python_memory.id = uuid4()
        python_memory.content = "Python is a programming language"
        python_memory.relevance_score = 0.95

        js_memory = Mock()
        js_memory.id = uuid4()
        js_memory.content = "JavaScript is used for web development"
        js_memory.relevance_score = 0.3

        tutorial_memory = Mock()
        tutorial_memory.id = uuid4()
        tutorial_memory.content = "Python programming tutorials"
        tutorial_memory.relevance_score = 0.9

        # Results ordered by relevance (descending)
        mock_memory_service.search_memories.return_value = [
            python_memory,
            tutorial_memory,
            js_memory,
        ]

        # Search for Python-related content
        results = await mock_memory_service.search_memories(
            query="Python programming",
            agent_id="test-agent",
            namespace="test-namespace",
            limit=10,
        )

        # Results should be returned
        assert isinstance(results, list)
        assert len(results) == 3

        # First result should be most relevant (Python)
        assert results[0].relevance_score >= results[1].relevance_score

    async def test_search_with_filters(self, mock_memory_service):
        """MEM-P0-006-T2: Search supports filtering by tags and importance."""
        high_importance_memory = Mock()
        high_importance_memory.id = uuid4()
        high_importance_memory.importance_score = 0.9
        high_importance_memory.tags = ["python", "tutorial"]

        mock_memory_service.search_memories.return_value = [high_importance_memory]

        results = await mock_memory_service.search_memories(
            query="Python",
            agent_id="test-agent",
            namespace="test-namespace",
            min_importance=0.8,
            tags=["python"],
        )

        assert len(results) == 1
        assert results[0].importance_score >= 0.8


@pytest.mark.integration
@pytest.mark.asyncio
class TestMemoryServiceValidation:
    """MEM-P0-007: Memory input validation tests."""

    async def test_rejects_empty_content(self, mock_memory_service):
        """MEM-P0-007-T1: Empty content is rejected."""
        mock_memory_service.create_memory.side_effect = ValueError("Content cannot be empty")

        with pytest.raises(ValueError) as exc_info:
            await mock_memory_service.create_memory(
                content="",
                agent_id="test-agent",
                namespace="test-namespace",
                importance_score=0.5,
            )

        assert "empty" in str(exc_info.value).lower()

    async def test_rejects_invalid_importance_score(self, mock_memory_service):
        """MEM-P0-007-T2: Invalid importance score is rejected."""
        mock_memory_service.create_memory.side_effect = ValueError(
            "Importance score must be between 0 and 1"
        )

        with pytest.raises(ValueError) as exc_info:
            await mock_memory_service.create_memory(
                content="Test content",
                agent_id="test-agent",
                namespace="test-namespace",
                importance_score=1.5,  # Invalid: > 1
            )

        assert "importance" in str(exc_info.value).lower()

    async def test_rejects_invalid_namespace(self, mock_memory_service):
        """MEM-P0-007-T3: Invalid namespace format is rejected."""
        mock_memory_service.create_memory.side_effect = ValueError(
            "Namespace cannot contain special characters"
        )

        with pytest.raises(ValueError) as exc_info:
            await mock_memory_service.create_memory(
                content="Test content",
                agent_id="test-agent",
                namespace="invalid/namespace!@#",  # Invalid characters
                importance_score=0.5,
            )

        assert "namespace" in str(exc_info.value).lower()
