"""Unit tests for SkillChromaStore

Tests ChromaDB integration for Skills semantic search.

Author: Artemis
Created: 2025-12-13
"""

import asyncio
import tempfile
from pathlib import Path

import pytest

from src.storage.skill_chroma_store import SkillChromaStore


@pytest.fixture
async def temp_chromadb():
    """Create temporary ChromaDB directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
async def skill_store(temp_chromadb):
    """Create SkillChromaStore with temporary storage."""
    store = SkillChromaStore(persist_directory=temp_chromadb)
    await store.initialize()
    yield store
    # Cleanup
    try:
        await store.clear_collection()
    except Exception:
        pass


@pytest.mark.asyncio
async def test_skill_store_initialization(temp_chromadb):
    """Test SkillChromaStore lazy initialization."""
    store = SkillChromaStore(persist_directory=temp_chromadb)

    # Not initialized yet
    assert not store._initialized

    # Initialize
    await store.initialize()
    assert store._initialized

    # Collection exists
    assert store._collection is not None
    assert store._client is not None


@pytest.mark.asyncio
async def test_add_single_skill(skill_store):
    """Test adding single skill to ChromaDB."""
    # Create test embedding (1024-dim zeros)
    embedding = [0.0] * 1024

    # Add skill
    await skill_store.add_skill(
        skill_id="skill_123",
        embedding=embedding,
        metadata={
            "skill_name": "oauth-security",
            "namespace": "security",
            "persona": "hestia-auditor",
            "tags": "security,audit",
            "access_level": "PRIVATE",
            "version": 1,
            "created_by": "hestia-001",
        },
        content="OAuth2 security best practices",
    )

    # Verify stats
    stats = await skill_store.get_collection_stats(force_init=True)
    assert stats["skill_count"] == 1
    assert stats["collection_name"] == "tmws_skills"


@pytest.mark.asyncio
async def test_add_skills_batch(skill_store):
    """Test batch adding skills."""
    # Create test embeddings
    embeddings = [[0.0] * 1024 for _ in range(3)]

    # Create metadata
    metadatas = [
        {
            "skill_name": f"skill_{i}",
            "namespace": "test",
            "persona": "artemis-optimizer",
            "tags": "test,batch",
            "access_level": "PUBLIC",
            "version": 1,
            "created_by": "test-agent",
        }
        for i in range(3)
    ]

    # Batch add
    await skill_store.add_skills_batch(
        skill_ids=[f"skill_{i}" for i in range(3)],
        embeddings=embeddings,
        metadatas=metadatas,
        contents=[f"Content {i}" for i in range(3)],
    )

    # Verify stats
    stats = await skill_store.get_collection_stats(force_init=True)
    assert stats["skill_count"] == 3


@pytest.mark.asyncio
async def test_search_skills(skill_store):
    """Test semantic search for skills."""
    # Add test skills with different embeddings
    # Note: In real usage, these would be actual embeddings from Ollama
    # For testing, we use simple vectors

    # Skill 1: [1, 0, 0, ...]
    embedding_1 = [1.0] + [0.0] * 1023
    await skill_store.add_skill(
        skill_id="skill_1",
        embedding=embedding_1,
        metadata={
            "skill_name": "oauth-security",
            "namespace": "security",
            "persona": "hestia-auditor",
            "tags": "security,oauth",
        },
    )

    # Skill 2: [0, 1, 0, ...]
    embedding_2 = [0.0, 1.0] + [0.0] * 1022
    await skill_store.add_skill(
        skill_id="skill_2",
        embedding=embedding_2,
        metadata={
            "skill_name": "database-optimization",
            "namespace": "performance",
            "persona": "artemis-optimizer",
            "tags": "performance,database",
        },
    )

    # Search with query similar to skill 1
    query_embedding = [0.9] + [0.0] * 1023
    results = await skill_store.search(
        query_embedding=query_embedding,
        top_k=2,
        min_similarity=0.0,
    )

    # Should find both skills, but skill_1 should have higher similarity
    assert len(results) == 2
    assert results[0]["id"] == "skill_1"  # Higher similarity
    assert results[0]["similarity"] > results[1]["similarity"]


@pytest.mark.asyncio
async def test_search_with_filters(skill_store):
    """Test search with metadata filters."""
    # Add skills with different namespaces
    embedding = [1.0] + [0.0] * 1023

    await skill_store.add_skill(
        skill_id="skill_sec",
        embedding=embedding,
        metadata={"skill_name": "security-skill", "namespace": "security"},
    )

    await skill_store.add_skill(
        skill_id="skill_perf",
        embedding=embedding,
        metadata={"skill_name": "performance-skill", "namespace": "performance"},
    )

    # Search with namespace filter
    query_embedding = [1.0] + [0.0] * 1023
    results = await skill_store.search(
        query_embedding=query_embedding,
        top_k=10,
        filters={"namespace": "security"},
        min_similarity=0.0,
    )

    # Should only find security skill
    assert len(results) == 1
    assert results[0]["id"] == "skill_sec"
    assert results[0]["metadata"]["namespace"] == "security"


@pytest.mark.asyncio
async def test_update_skill(skill_store):
    """Test updating existing skill."""
    # Add original skill
    embedding_1 = [1.0] + [0.0] * 1023
    await skill_store.add_skill(
        skill_id="skill_update",
        embedding=embedding_1,
        metadata={"skill_name": "original", "version": 1},
    )

    # Update with new embedding and metadata
    embedding_2 = [0.0, 1.0] + [0.0] * 1022
    await skill_store.update_skill(
        skill_id="skill_update",
        embedding=embedding_2,
        metadata={"skill_name": "updated", "version": 2},
    )

    # Search should find updated version
    query_embedding = [0.0, 0.9] + [0.0] * 1022
    results = await skill_store.search(
        query_embedding=query_embedding,
        top_k=1,
        min_similarity=0.0,
    )

    assert len(results) == 1
    assert results[0]["id"] == "skill_update"
    assert results[0]["metadata"]["skill_name"] == "updated"
    assert results[0]["metadata"]["version"] == 2


@pytest.mark.asyncio
async def test_delete_skill(skill_store):
    """Test deleting skill from ChromaDB."""
    # Add skill
    embedding = [1.0] + [0.0] * 1023
    await skill_store.add_skill(
        skill_id="skill_delete",
        embedding=embedding,
        metadata={"skill_name": "to-delete"},
    )

    # Verify exists
    stats = await skill_store.get_collection_stats(force_init=True)
    assert stats["skill_count"] == 1

    # Delete
    await skill_store.delete_skill("skill_delete")

    # Verify deleted
    stats = await skill_store.get_collection_stats(force_init=True)
    assert stats["skill_count"] == 0


@pytest.mark.asyncio
async def test_metadata_sanitization(skill_store):
    """Test metadata sanitization for ChromaDB."""
    # Add skill with complex metadata
    embedding = [1.0] + [0.0] * 1023
    await skill_store.add_skill(
        skill_id="skill_meta",
        embedding=embedding,
        metadata={
            "skill_name": "test",
            "tags": ["tag1", "tag2", "tag3"],  # List (should be converted to CSV)
            "nested": {"key": "value"},  # Dict (should be skipped)
            "null_value": None,  # None (should be skipped)
            "int_value": 42,
            "float_value": 3.14,
            "bool_value": True,
        },
    )

    # Search and verify metadata
    query_embedding = [1.0] + [0.0] * 1023
    results = await skill_store.search(
        query_embedding=query_embedding,
        top_k=1,
    )

    assert len(results) == 1
    metadata = results[0]["metadata"]

    # Check sanitization
    assert "tags" in metadata
    assert isinstance(metadata["tags"], str)  # Converted to CSV
    assert "nested" not in metadata  # Dict skipped
    assert "null_value" not in metadata  # None skipped
    assert metadata["int_value"] == 42
    assert metadata["float_value"] == 3.14
    assert metadata["bool_value"] is True


@pytest.mark.asyncio
async def test_performance_target(skill_store):
    """Test that search meets performance target (<100ms P95)."""
    import time

    # Add 100 skills
    embeddings = [[i / 100.0] + [0.0] * 1023 for i in range(100)]
    metadatas = [
        {"skill_name": f"skill_{i}", "namespace": "test"}
        for i in range(100)
    ]

    await skill_store.add_skills_batch(
        skill_ids=[f"skill_{i}" for i in range(100)],
        embeddings=embeddings,
        metadatas=metadatas,
    )

    # Measure search latency
    query_embedding = [0.5] + [0.0] * 1023

    latencies = []
    for _ in range(20):
        start = time.time()
        await skill_store.search(
            query_embedding=query_embedding,
            top_k=10,
        )
        latencies.append((time.time() - start) * 1000)  # ms

    # Calculate P95
    p95_latency = sorted(latencies)[int(len(latencies) * 0.95)]

    # Should be < 100ms P95 (but ChromaDB is fast, usually < 20ms)
    assert p95_latency < 100, f"P95 latency {p95_latency:.2f}ms exceeds 100ms target"
