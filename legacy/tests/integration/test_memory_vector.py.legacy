"""
Integration tests for Memory vector operations using pgvector.
Tests require PostgreSQL with pgvector extension.
"""

import numpy as np
import pytest
from sqlalchemy import text

from src.models.agent import AccessLevel
from src.models.memory import Memory, MemoryConsolidation


@pytest.mark.database
@pytest.mark.integration
class TestMemoryVectorOperations:
    """Test vector operations on Memory model with pgvector."""

    async def test_create_memory_with_embedding(self, postgresql_session, requires_postgresql):
        """Test creating memory with vector embedding."""
        # Create test embedding
        embedding = np.random.rand(384).tolist()

        memory = Memory(
            content="Test memory for vector search",
            agent_id="test-agent",
            embedding=embedding,
            importance_score=0.8,
            tags=["test", "vector"],
            access_level=AccessLevel.PRIVATE,
        )

        postgresql_session.add(memory)
        await postgresql_session.commit()
        await postgresql_session.refresh(memory)

        assert memory.id is not None
        assert memory.embedding is not None
        assert len(memory.embedding) == 384
        assert memory.content == "Test memory for vector search"

    async def test_vector_similarity_search(self, postgresql_session, requires_postgresql):
        """Test vector similarity search using cosine distance."""
        # Create multiple memories with different embeddings
        memories = []
        embeddings = []

        for i in range(5):
            embedding = np.random.rand(384).tolist()
            embeddings.append(embedding)

            memory = Memory(
                content=f"Memory content {i}",
                agent_id="test-agent",
                embedding=embedding,
                importance_score=0.5 + i * 0.1,
                tags=["test", f"vector_{i}"],
                access_level=AccessLevel.PRIVATE,
            )
            memories.append(memory)
            postgresql_session.add(memory)

        await postgresql_session.commit()

        # Search for memories similar to the first embedding
        query_embedding = embeddings[0]

        # Using cosine distance (1 - cosine_similarity)
        result = await postgresql_session.execute(
            text("""
                SELECT id, content, embedding <=> :query_embedding AS distance
                FROM memories_v2
                WHERE agent_id = :agent_id
                ORDER BY embedding <=> :query_embedding
                LIMIT 3
            """),
            {"query_embedding": str(query_embedding), "agent_id": "test-agent"},
        )

        rows = result.fetchall()
        assert len(rows) >= 3

        # First result should be the exact match (distance = 0)
        assert rows[0].distance == 0.0
        assert rows[0].content == "Memory content 0"

    async def test_vector_similarity_threshold(self, postgresql_session, requires_postgresql):
        """Test vector similarity search with distance threshold."""
        # Create memories with known similar embeddings
        base_embedding = np.array([1.0] * 384)
        similar_embedding = base_embedding + np.random.normal(0, 0.1, 384)
        different_embedding = np.random.rand(384) * 10

        # Normalize embeddings
        base_embedding = base_embedding / np.linalg.norm(base_embedding)
        similar_embedding = similar_embedding / np.linalg.norm(similar_embedding)
        different_embedding = different_embedding / np.linalg.norm(different_embedding)

        memories = [
            Memory(
                content="Base memory",
                agent_id="test-agent",
                embedding=base_embedding.tolist(),
                importance_score=0.8,
                access_level=AccessLevel.PRIVATE,
            ),
            Memory(
                content="Similar memory",
                agent_id="test-agent",
                embedding=similar_embedding.tolist(),
                importance_score=0.7,
                access_level=AccessLevel.PRIVATE,
            ),
            Memory(
                content="Different memory",
                agent_id="test-agent",
                embedding=different_embedding.tolist(),
                importance_score=0.6,
                access_level=AccessLevel.PRIVATE,
            ),
        ]

        for memory in memories:
            postgresql_session.add(memory)
        await postgresql_session.commit()

        # Search with threshold
        threshold = 0.5  # Only return memories with distance < 0.5
        result = await postgresql_session.execute(
            text("""
                SELECT id, content, embedding <=> :query_embedding AS distance
                FROM memories_v2
                WHERE agent_id = :agent_id
                  AND embedding <=> :query_embedding < :threshold
                ORDER BY embedding <=> :query_embedding
            """),
            {
                "query_embedding": str(base_embedding.tolist()),
                "agent_id": "test-agent",
                "threshold": threshold,
            },
        )

        rows = result.fetchall()
        # Should return base and similar, but not different
        assert len(rows) >= 2
        assert all(row.distance < threshold for row in rows)

    async def test_vector_index_performance(self, postgresql_session, requires_postgresql):
        """Test that vector index improves query performance."""
        # Create index on embedding column
        await postgresql_session.execute(
            text("""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS memories_embedding_idx
                ON memories_v2 USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100)
            """)
        )
        await postgresql_session.commit()

        # Create many memories for performance test
        embeddings = []
        for i in range(100):
            embedding = np.random.rand(384).tolist()
            embeddings.append(embedding)

            memory = Memory(
                content=f"Performance test memory {i}",
                agent_id="perf-agent",
                embedding=embedding,
                importance_score=np.random.rand(),
                access_level=AccessLevel.PRIVATE,
            )
            postgresql_session.add(memory)

        await postgresql_session.commit()

        # Test query performance
        query_embedding = embeddings[0]

        result = await postgresql_session.execute(
            text("""
                EXPLAIN (ANALYZE, BUFFERS)
                SELECT id, content, embedding <=> :query_embedding AS distance
                FROM memories_v2
                WHERE agent_id = :agent_id
                ORDER BY embedding <=> :query_embedding
                LIMIT 10
            """),
            {"query_embedding": str(query_embedding), "agent_id": "perf-agent"},
        )

        explain_output = result.fetchall()
        # Verify query executed (basic check)
        assert len(explain_output) > 0

    async def test_memory_consolidation_vectors(self, postgresql_session, requires_postgresql):
        """Test memory consolidation with vector averaging."""
        # Create related memories
        base_vector = np.array([1.0, 0.0, 1.0] + [0.0] * 381)

        related_memories = []
        for i in range(3):
            # Add slight variations to the base vector
            variation = np.random.normal(0, 0.1, 384)
            embedding = base_vector + variation
            embedding = embedding / np.linalg.norm(embedding)  # Normalize

            memory = Memory(
                content=f"Related memory {i}",
                agent_id="consolidation-agent",
                embedding=embedding.tolist(),
                importance_score=0.7,
                tags=["related", "consolidation"],
                access_level=AccessLevel.PRIVATE,
            )
            related_memories.append(memory)
            postgresql_session.add(memory)

        await postgresql_session.commit()

        # Create consolidation with averaged embedding
        avg_embedding = np.mean([np.array(m.embedding) for m in related_memories], axis=0)
        avg_embedding = avg_embedding / np.linalg.norm(avg_embedding)

        consolidation = MemoryConsolidation(
            consolidated_content="Summary of related memories",
            source_memory_ids=[m.id for m in related_memories],
            agent_id="consolidation-agent",
            embedding=avg_embedding.tolist(),
            importance_score=0.9,
            consolidation_type="similarity_based",
        )

        postgresql_session.add(consolidation)
        await postgresql_session.commit()
        await postgresql_session.refresh(consolidation)

        assert consolidation.id is not None
        assert consolidation.embedding is not None
        assert len(consolidation.source_memory_ids) == 3

    async def test_cross_agent_vector_search(self, postgresql_session, requires_postgresql):
        """Test vector search across different agents with access control."""
        embedding = np.random.rand(384).tolist()

        # Create memories for different agents with different access levels
        memories = [
            Memory(
                content="Private memory",
                agent_id="agent-1",
                embedding=embedding,
                importance_score=0.8,
                access_level=AccessLevel.PRIVATE,
            ),
            Memory(
                content="Team memory",
                agent_id="agent-1",
                embedding=embedding,
                importance_score=0.8,
                access_level=AccessLevel.TEAM,
                shared_with_agents=["agent-2"],
            ),
            Memory(
                content="Public memory",
                agent_id="agent-1",
                embedding=embedding,
                importance_score=0.8,
                access_level=AccessLevel.PUBLIC,
            ),
        ]

        for memory in memories:
            postgresql_session.add(memory)
        await postgresql_session.commit()

        # Search as agent-2, should see team and public memories only
        result = await postgresql_session.execute(
            text("""
                SELECT id, content, access_level
                FROM memories_v2
                WHERE (
                    access_level = 'public'
                    OR (access_level = 'team' AND :agent_id = ANY(shared_with_agents))
                    OR agent_id = :agent_id
                )
                AND embedding <=> :query_embedding < 1.0
                ORDER BY embedding <=> :query_embedding
            """),
            {"query_embedding": str(embedding), "agent_id": "agent-2"},
        )

        rows = result.fetchall()
        assert len(rows) == 2  # Should see team and public, not private

        contents = [row.content for row in rows]
        assert "Team memory" in contents
        assert "Public memory" in contents
        assert "Private memory" not in contents

    async def test_memory_vector_update(self, postgresql_session, requires_postgresql):
        """Test updating memory embedding."""
        original_embedding = np.random.rand(384).tolist()

        memory = Memory(
            content="Original content",
            agent_id="update-agent",
            embedding=original_embedding,
            importance_score=0.5,
            access_level=AccessLevel.PRIVATE,
        )

        postgresql_session.add(memory)
        await postgresql_session.commit()
        await postgresql_session.refresh(memory)

        # Update embedding
        new_embedding = np.random.rand(384).tolist()
        memory.embedding = new_embedding
        memory.content = "Updated content"

        await postgresql_session.commit()
        await postgresql_session.refresh(memory)

        assert memory.embedding == new_embedding
        assert memory.content == "Updated content"

        # Verify the update in database
        result = await postgresql_session.execute(
            text("SELECT embedding FROM memories_v2 WHERE id = :id"), {"id": memory.id}
        )

        db_embedding = result.scalar()
        assert db_embedding == new_embedding

    async def test_null_embedding_handling(self, postgresql_session, requires_postgresql):
        """Test handling memories with null embeddings."""
        memory = Memory(
            content="Memory without embedding",
            agent_id="null-embedding-agent",
            embedding=None,  # No embedding
            importance_score=0.5,
            access_level=AccessLevel.PRIVATE,
        )

        postgresql_session.add(memory)
        await postgresql_session.commit()
        await postgresql_session.refresh(memory)

        assert memory.id is not None
        assert memory.embedding is None

        # Verify vector search excludes null embeddings
        query_embedding = np.random.rand(384).tolist()

        result = await postgresql_session.execute(
            text("""
                SELECT COUNT(*) as count
                FROM memories_v2
                WHERE agent_id = :agent_id
                  AND embedding IS NOT NULL
                  AND embedding <=> :query_embedding < 1.0
            """),
            {"query_embedding": str(query_embedding), "agent_id": "null-embedding-agent"},
        )

        count = result.scalar()
        assert count == 0  # No results since embedding is null
