"""
Integration tests for Memory service with SQLite backend.
Tests the complete memory service functionality including vector operations.
"""

from unittest.mock import AsyncMock, patch

import numpy as np
import pytest

from src.models.agent import AccessLevel
from src.models.memory import Memory
from src.services.memory_service import HybridMemoryService


@pytest.mark.database
@pytest.mark.integration
class TestMemoryServiceIntegration:
    """Test memory service with real SQLite backend."""

    @pytest.fixture
    async def memory_service(self, test_session):
        """Create memory service with SQLite session."""
        from unittest.mock import MagicMock

        # Mock embedding service for testing (v2.2.6: UnifiedEmbeddingService)
        mock_embedding_service = AsyncMock()
        mock_embedding_service.encode_document.return_value = np.random.rand(
            1024
        )  # v2.2.6: 1024-dim numpy array
        mock_embedding_service.encode_query.return_value = np.random.rand(1024)
        # get_model_info is synchronous method
        mock_embedding_service.get_model_info = MagicMock(
            return_value={
                "model_name": "zylonai/multilingual-e5-large",
                "dimension": 1024,
                "provider": "ollama",
            }
        )

        with patch(
            "src.services.ollama_embedding_service.get_ollama_embedding_service",
            return_value=mock_embedding_service,
        ):
            service = HybridMemoryService(test_session)  # v2.2.6: HybridMemoryService
            yield service

    async def test_create_memory_with_auto_embedding(self, memory_service, test_session):
        """Test creating memory with automatic embedding generation."""
        memory_data = {
            "content": "Test memory content for automatic embedding",
            "agent_id": "test-agent",
            "importance": 0.8,
            "tags": ["test", "auto_embedding"],
            "access_level": AccessLevel.PRIVATE,
        }

        created_memory = await memory_service.create_memory(**memory_data)

        assert created_memory["id"] is not None
        assert created_memory["content"] == memory_data["content"]
        assert created_memory["embedding"] is not None
        assert len(created_memory["embedding"]) == 1024  # v2.2.6: 1024-dim embedding

        # Verify in database
        db_memory = await test_session.get(Memory, created_memory["id"])
        assert db_memory is not None
        assert db_memory.embedding is not None

    async def test_semantic_search(self, memory_service, test_session):
        """Test semantic search functionality."""
        # Create multiple memories
        memories_data = [
            {
                "content": "Machine learning is a subset of artificial intelligence",
                "agent_id": "search-agent",
                "importance": 0.9,
                "tags": ["ai", "ml"],
                "access_level": AccessLevel.PUBLIC,
            },
            {
                "content": "Deep learning uses neural networks with multiple layers",
                "agent_id": "search-agent",
                "importance": 0.8,
                "tags": ["ai", "deep_learning"],
                "access_level": AccessLevel.PUBLIC,
            },
            {
                "content": "The weather is sunny today",
                "agent_id": "search-agent",
                "importance": 0.3,
                "tags": ["weather"],
                "access_level": AccessLevel.PUBLIC,
            },
        ]

        created_memories = []
        for memory_data in memories_data:
            memory = await memory_service.create_memory(**memory_data)
            created_memories.append(memory)

        # Search for AI-related content
        search_results = await memory_service.search_memories(
            query="artificial intelligence and neural networks",
            agent_id="search-agent",
            limit=5,
            min_similarity=0.0,
        )

        assert len(search_results) >= 2
        # AI-related memories should rank higher than weather content
        ai_contents = [r["content"] for r in search_results[:2]]
        assert any("artificial intelligence" in content for content in ai_contents)
        assert any("neural networks" in content for content in ai_contents)

    async def test_memory_access_control(self, memory_service, test_session):
        """Test memory access control in search results."""
        # Create memories with different access levels
        memories_data = [
            {
                "content": "Private technical specification",
                "agent_id": "agent-1",
                "importance": 0.9,
                "tags": ["private", "spec"],
                "access_level": AccessLevel.PRIVATE,
            },
            {
                "content": "Team collaboration document",
                "agent_id": "agent-1",
                "importance": 0.8,
                "tags": ["team", "collab"],
                "access_level": AccessLevel.TEAM,
                "shared_with_agents": ["agent-2"],
            },
            {
                "content": "Public knowledge base article",
                "agent_id": "agent-1",
                "importance": 0.7,
                "tags": ["public", "kb"],
                "access_level": AccessLevel.PUBLIC,
            },
        ]

        for memory_data in memories_data:
            await memory_service.create_memory(**memory_data)

        # Search as agent-2
        search_results = await memory_service.search_memories(
            query="document specification article", agent_id="agent-2", limit=10, min_similarity=0.0
        )

        # Should see team and public memories only
        contents = [r["content"] for r in search_results]
        assert "Team collaboration document" in contents
        assert "Public knowledge base article" in contents
        assert "Private technical specification" not in contents

    async def test_importance_weighted_search(self, memory_service):
        """Test search results weighted by importance score."""
        # Create memories with different importance scores
        memories_data = [
            {
                "content": "Critical system alert",
                "agent_id": "importance-agent",
                "importance": 1.0,
                "tags": ["critical", "alert"],
                "access_level": AccessLevel.PUBLIC,
            },
            {
                "content": "Routine system message",
                "agent_id": "importance-agent",
                "importance": 0.3,
                "tags": ["routine", "message"],
                "access_level": AccessLevel.PUBLIC,
            },
            {
                "content": "Important system notification",
                "agent_id": "importance-agent",
                "importance": 0.8,
                "tags": ["important", "notification"],
                "access_level": AccessLevel.PUBLIC,
            },
        ]

        for memory_data in memories_data:
            await memory_service.create_memory(**memory_data)

        # Search should weight by importance
        search_results = await memory_service.search_memories(
            query="system", agent_id="importance-agent", limit=3, min_similarity=0.0
        )

        # Critical and important should rank higher than routine
        assert len(search_results) >= 3
        top_result = search_results[0]
        # Top result should be either critical or important, not routine
        assert "Routine" not in top_result["content"]

    async def test_memory_consolidation(self, memory_service, test_session):
        """Test memory consolidation functionality."""
        # Create related memories
        related_memories = []
        for i in range(3):
            memory_data = {
                "content": f"Related project milestone {i + 1}",
                "agent_id": "consolidation-agent",
                "importance": 0.7,
                "tags": ["project", "milestone"],
                "access_level": AccessLevel.PRIVATE,
            }
            memory = await memory_service.create_memory(**memory_data)
            related_memories.append(memory)

        # Consolidate memories
        consolidation_data = {
            "consolidated_content": "Project milestone summary",
            "source_memory_ids": [m["id"] for m in related_memories],
            "agent_id": "consolidation-agent",
            "importance": 0.9,
            "consolidation_type": "manual",
        }

        consolidation = await memory_service.create_consolidation(**consolidation_data)

        assert consolidation["id"] is not None
        assert consolidation["consolidated_content"] == "Project milestone summary"
        assert len(consolidation["source_memory_ids"]) == 3
        assert consolidation["embedding"] is not None

        # Search should find consolidation
        search_results = await memory_service.search_memories(
            query="project milestone summary", agent_id="consolidation-agent", limit=5
        )

        consolidated_contents = [r["content"] for r in search_results]
        assert "Project milestone summary" in consolidated_contents

    async def test_memory_update_with_reembedding(self, memory_service):
        """Test updating memory content triggers re-embedding."""
        # Create initial memory
        memory_data = {
            "content": "Original content about databases",
            "agent_id": "update-agent",
            "importance": 0.5,
            "tags": ["original"],
            "access_level": AccessLevel.PRIVATE,
        }

        created_memory = await memory_service.create_memory(**memory_data)
        original_embedding = created_memory["embedding"]

        # Update memory content
        updated_memory = await memory_service.update_memory(
            memory_id=created_memory["id"],
            agent_id="update-agent",
            content="Updated content about machine learning",
            tags=["updated", "ml"],
        )

        # Embedding should change due to content change
        assert updated_memory["content"] == "Updated content about machine learning"
        assert updated_memory["embedding"] != original_embedding
        assert updated_memory["tags"] == ["updated", "ml"]

    async def test_batch_memory_operations(self, memory_service):
        """Test batch operations for memory creation and search."""
        # Create multiple memories in batch
        batch_data = []
        for i in range(10):
            memory_data = {
                "content": f"Batch memory {i}",
                "agent_id": "batch-agent",
                "importance": 0.5 + (i * 0.05),
                "tags": ["batch", f"item_{i}"],
                "access_level": AccessLevel.PRIVATE,
            }
            batch_data.append(memory_data)

        # For this test, create memories one by one (simulating batch)
        created_memories = []
        for data in batch_data:
            memory = await memory_service.create_memory(**data)
            created_memories.append(memory)

        assert len(created_memories) == 10

        # Batch search for various terms
        search_queries = ["batch memory", "item_5", "batch item"]
        for query in search_queries:
            results = await memory_service.search_memories(
                query=query, agent_id="batch-agent", limit=5
            )
            assert len(results) > 0

    async def test_memory_deletion_and_cleanup(self, memory_service, test_session):
        """Test memory deletion and database cleanup."""
        # Create memory
        memory_data = {
            "content": "Memory to be deleted",
            "agent_id": "delete-agent",
            "importance": 0.5,
            "tags": ["temporary"],
            "access_level": AccessLevel.PRIVATE,
        }

        created_memory = await memory_service.create_memory(**memory_data)
        memory_id = created_memory["id"]

        # Verify memory exists
        retrieved_memory = await memory_service.get_memory(memory_id, "delete-agent")
        assert retrieved_memory is not None

        # Delete memory
        deletion_result = await memory_service.delete_memory(memory_id, "delete-agent")
        assert deletion_result is True

        # Verify memory is deleted
        deleted_memory = await memory_service.get_memory(memory_id, "delete-agent")
        assert deleted_memory is None

        # Verify database cleanup
        db_memory = await test_session.get(Memory, memory_id)
        assert db_memory is None

    async def test_concurrent_memory_operations(self, memory_service):
        """Test concurrent memory operations for thread safety."""
        import asyncio

        async def create_memory_concurrent(index):
            """Create memory in concurrent environment."""
            memory_data = {
                "content": f"Concurrent memory {index}",
                "agent_id": f"concurrent-agent-{index % 3}",  # 3 different agents
                "importance": 0.5,
                "tags": ["concurrent", f"index_{index}"],
                "access_level": AccessLevel.PRIVATE,
            }
            return await memory_service.create_memory(**memory_data)

        # Create memories concurrently
        tasks = [create_memory_concurrent(i) for i in range(20)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Check that all operations succeeded
        successful_results = [r for r in results if not isinstance(r, Exception)]
        assert len(successful_results) == 20

        # Verify all memories were created with unique IDs
        memory_ids = {r["id"] for r in successful_results}
        assert len(memory_ids) == 20  # All unique
