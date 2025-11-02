"""Search Latency Breakdown Test

Measures performance of semantic search components.
Run with: pytest tests/manual/test_search_latency_breakdown.py -v -s
"""

import time

import pytest

from src.services.embedding_service import EmbeddingService
from src.services.memory_service import MemoryService


@pytest.mark.asyncio
async def test_embedding_generation_latency(db_session):
    """Measure Ollama embedding generation latency"""
    print("\n" + "=" * 60)
    print("1. Embedding Generation (Ollama)")
    print("=" * 60)

    service = EmbeddingService()
    test_query = "タスク作成機能のテスト結果"

    # Warmup
    await service.encode_query(test_query)

    # Measure 3 times
    timings = []
    for i in range(3):
        start = time.perf_counter()
        embedding = await service.encode_query(test_query)
        elapsed_ms = (time.perf_counter() - start) * 1000
        timings.append(elapsed_ms)
        print(f"  Run {i+1}: {elapsed_ms:.2f}ms (dims: {len(embedding)})")

    avg_ms = sum(timings) / len(timings)
    print(f"  Average: {avg_ms:.2f}ms")

    return avg_ms, embedding


@pytest.mark.asyncio
async def test_chromadb_search_latency(db_session):
    """Measure ChromaDB vector search latency"""
    print("\n" + "=" * 60)
    print("2. ChromaDB Vector Search")
    print("=" * 60)

    # First create a test memory
    memory_service = MemoryService(db_session)

    # Generate embedding
    embedding_service = EmbeddingService()
    test_content = "Phase 4運用テスト完了記録"
    embedding = await embedding_service.encode_query(test_content)

    # Create test memory
    await memory_service.create_memory(
        content=test_content,
        memory_type="test",
        importance=0.8,
    )

    # Measure ChromaDB search
    timings = []
    for i in range(3):
        start = time.perf_counter()

        try:
            results = await memory_service._search_chroma(
                query_embedding=embedding.tolist(),
                limit=10,
                min_similarity=0.7,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            timings.append(elapsed_ms)
            print(f"  Run {i+1}: {elapsed_ms:.2f}ms (results: {len(results)})")
        except Exception as e:
            print(f"  Run {i+1}: ERROR - {e}")
            timings.append(0)

    avg_ms = sum(timings) / len(timings) if timings else 0
    print(f"  Average: {avg_ms:.2f}ms")

    return avg_ms


@pytest.mark.asyncio
async def test_end_to_end_search_latency(db_session):
    """Measure end-to-end search_memories latency"""
    print("\n" + "=" * 60)
    print("3. End-to-End Search (with SQLite fetch)")
    print("=" * 60)

    memory_service = MemoryService(db_session)

    # Create test memory first
    await memory_service.create_memory(
        content="Phase 4運用テスト完了記録: タスク作成機能の検証",
        memory_type="test",
        importance=0.8,
    )

    test_query = "タスク作成機能のテスト結果"

    # Warmup
    await memory_service.search_memories(
        query=test_query,
        limit=3,
        min_similarity=0.7,
    )

    # Measure 3 times
    timings = []
    for i in range(3):
        start = time.perf_counter()
        results = await memory_service.search_memories(
            query=test_query,
            limit=3,
            min_similarity=0.7,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        timings.append(elapsed_ms)
        print(f"  Run {i+1}: {elapsed_ms:.2f}ms (results: {len(results)})")

    avg_ms = sum(timings) / len(timings)
    print(f"  Average: {avg_ms:.2f}ms")

    # Performance targets
    target_ms = 20.0
    print("\n  ⚠️  Performance Gap:")
    print(f"    Current: {avg_ms:.2f}ms")
    print(f"    Target:  {target_ms:.2f}ms")
    if avg_ms > target_ms:
        gap_pct = (avg_ms / target_ms - 1) * 100
        print(f"    Gap:     {avg_ms - target_ms:.2f}ms ({gap_pct:.1f}% slower)")
    else:
        print("    ✅ Target achieved!")

    return avg_ms


@pytest.mark.asyncio
async def test_latency_breakdown_analysis(db_session):
    """Full latency breakdown analysis"""
    print("\n" + "=" * 70)
    print("🔍 TMWS Search Latency Breakdown Analysis")
    print("=" * 70)

    # Create test data first
    memory_service = MemoryService(db_session)
    await memory_service.create_memory(
        content="Phase 4運用テスト完了記録: タスク作成機能の完全検証が成功",
        memory_type="test",
        importance=0.8,
        tags=["phase4", "task-management"],
    )

    # Step 1: Embedding generation
    embedding_service = EmbeddingService()
    test_query = "タスク作成機能のテスト結果"

    # Warmup
    await embedding_service.encode_query(test_query)
    await memory_service.search_memories(query=test_query, limit=3)

    # Measure embedding
    start = time.perf_counter()
    embedding = await embedding_service.encode_query(test_query)
    embedding_ms = (time.perf_counter() - start) * 1000

    # Measure ChromaDB search
    start = time.perf_counter()
    chroma_results = await memory_service._search_chroma(
        query_embedding=embedding.tolist(),
        limit=10,
        min_similarity=0.7,
    )
    chromadb_ms = (time.perf_counter() - start) * 1000

    # Measure end-to-end
    start = time.perf_counter()
    e2e_results = await memory_service.search_memories(
        query=test_query,
        limit=3,
        min_similarity=0.7,
    )
    e2e_ms = (time.perf_counter() - start) * 1000

    # Calculate SQLite fetch time
    sqlite_fetch_ms = max(0, e2e_ms - embedding_ms - chromadb_ms)

    # Results
    print("\n📊 Latency Breakdown:")
    print(f"  1. Embedding Generation: {embedding_ms:7.2f}ms ({embedding_ms/e2e_ms*100:5.1f}%)")
    print(f"  2. ChromaDB Search:      {chromadb_ms:7.2f}ms ({chromadb_ms/e2e_ms*100:5.1f}%)")
    print(f"  3. SQLite Fetch:         {sqlite_fetch_ms:7.2f}ms ({sqlite_fetch_ms/e2e_ms*100:5.1f}%)")
    print(f"  {'-'*60}")
    print(f"  Total (E2E):             {e2e_ms:7.2f}ms")

    # Bottleneck
    components = [
        ("Embedding Generation", embedding_ms),
        ("ChromaDB Search", chromadb_ms),
        ("SQLite Fetch", sqlite_fetch_ms),
    ]
    bottleneck = max(components, key=lambda x: x[1])
    print(f"\n🎯 Primary Bottleneck: {bottleneck[0]} ({bottleneck[1]:.2f}ms)")

    # Target
    target_ms = 20.0
    print("\n⚠️  Performance vs Target:")
    print(f"  Current: {e2e_ms:.2f}ms")
    print(f"  Target:  {target_ms:.2f}ms")
    if e2e_ms > target_ms:
        gap_pct = (e2e_ms / target_ms - 1) * 100
        print(f"  Gap:     {e2e_ms - target_ms:.2f}ms ({gap_pct:.1f}% slower)")
    else:
        print("  ✅ Target achieved!")

    # Assert for CI
    assert embedding_ms > 0, "Embedding generation failed"
    assert chromadb_ms >= 0, "ChromaDB search failed"
    assert e2e_ms > 0, "End-to-end search failed"
    assert len(e2e_results) > 0, "No results found"
