#!/usr/bin/env python3
"""Search Latency Measurement Script

Measures breakdown of semantic search latency:
1. Embedding generation (Ollama)
2. ChromaDB vector search
3. SQLite metadata fetch
"""

import asyncio
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from services.embedding_service import EmbeddingService
from services.memory_service import MemoryService
from core.database import get_session


async def measure_embedding_generation():
    """Measure Ollama embedding generation time"""
    print("=" * 60)
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
    print()

    return avg_ms, embedding


async def measure_chromadb_search(embedding):
    """Measure ChromaDB vector search time"""
    print("=" * 60)
    print("2. ChromaDB Vector Search")
    print("=" * 60)

    async with get_session() as session:
        memory_service = MemoryService(session)

        # Direct ChromaDB search (bypass embedding generation)
        timings = []
        for i in range(3):
            start = time.perf_counter()

            # Call internal ChromaDB search method
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
        print()

        return avg_ms


async def measure_end_to_end():
    """Measure end-to-end search_memories time"""
    print("=" * 60)
    print("3. End-to-End Search (with SQLite fetch)")
    print("=" * 60)

    async with get_session() as session:
        memory_service = MemoryService(session)

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
        print()

        return avg_ms


async def main():
    """Run all measurements"""
    print("\n🔍 TMWS Search Latency Breakdown Analysis")
    print()

    # Step 1: Embedding generation
    embedding_ms, embedding = await measure_embedding_generation()

    # Step 2: ChromaDB search
    chromadb_ms = await measure_chromadb_search(embedding)

    # Step 3: End-to-end
    e2e_ms = await measure_end_to_end()

    # Analysis
    print("=" * 60)
    print("📊 Analysis")
    print("=" * 60)

    sqlite_fetch_ms = e2e_ms - embedding_ms - chromadb_ms

    print(f"  1. Embedding Generation: {embedding_ms:.2f}ms ({embedding_ms/e2e_ms*100:.1f}%)")
    print(f"  2. ChromaDB Search:      {chromadb_ms:.2f}ms ({chromadb_ms/e2e_ms*100:.1f}%)")
    print(f"  3. SQLite Fetch:         {sqlite_fetch_ms:.2f}ms ({sqlite_fetch_ms/e2e_ms*100:.1f}%)")
    print(f"  {'='*40}")
    print(f"  Total (E2E):             {e2e_ms:.2f}ms")
    print()

    # Bottleneck identification
    print("🎯 Bottleneck Identification:")
    components = [
        ("Embedding Generation", embedding_ms),
        ("ChromaDB Search", chromadb_ms),
        ("SQLite Fetch", sqlite_fetch_ms),
    ]
    bottleneck = max(components, key=lambda x: x[1])
    print(f"  Primary bottleneck: {bottleneck[0]} ({bottleneck[1]:.2f}ms)")
    print()

    # Target comparison
    target_ms = 20.0
    print(f"⚠️  Performance Gap:")
    print(f"  Current: {e2e_ms:.2f}ms")
    print(f"  Target:  {target_ms:.2f}ms")
    print(f"  Gap:     {e2e_ms - target_ms:.2f}ms ({(e2e_ms/target_ms - 1)*100:.1f}% slower)")
    print()


if __name__ == "__main__":
    asyncio.run(main())
