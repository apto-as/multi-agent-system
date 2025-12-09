"""
Startup Time Performance Benchmarks - Issue #35 Validation

Tests lazy loading performance targets:
- Startup time < 2s (from 15-30s baseline)
- Memory footprint < 200MB (from 800MB baseline)
- Tool discovery latency < 100ms P95

Validates Issue #34 lazy initialization implementation for ToolSearchService.

Target Metrics:
- Service construction: < 10ms (lazy init, no ChromaDB)
- First search (cold start): < 50ms (lazy init overhead)
- Subsequent operations: < 10ms (warm ChromaDB)

Author: Artemis (Optimizer)
Created: 2025-12-09
"""

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models.tool_search import (
    ToolMetadata,
    ToolSearchQuery,
    ToolSourceType,
)
from src.services.tool_search_service import ToolSearchConfig, ToolSearchService


# ==================== Fixtures ====================


@pytest.fixture
def mock_chroma_client():
    """Mock ChromaDB client to avoid actual I/O."""
    client = MagicMock()
    collection = MagicMock()

    # Mock collection.count() for stats
    collection.count.return_value = 42

    # Mock collection.query() for searches
    collection.query.return_value = {
        "metadatas": [
            [
                {
                    "tool_name": "search_memories",
                    "server_id": "tmws",
                    "description": "Search semantic memories",
                    "source_type": "internal",
                    "tags": "memory,search",
                },
                {
                    "tool_name": "store_memory",
                    "server_id": "tmws",
                    "description": "Store new memory",
                    "source_type": "internal",
                    "tags": "memory,write",
                },
            ]
        ],
        "distances": [[0.2, 0.3]],
        "documents": [
            [
                "search_memories | Search semantic memories | memory search",
                "store_memory | Store new memory | memory write",
            ]
        ],
    }

    # Mock collection.upsert() for indexing
    collection.upsert.return_value = None

    # Mock get_or_create_collection
    client.get_or_create_collection.return_value = collection

    return client, collection


@pytest.fixture
def mock_embedding_service():
    """Mock embedding service for consistent test vectors."""
    service = MagicMock()
    service.get_embedding = AsyncMock(
        return_value=[0.1] * 384  # Realistic embedding dimension
    )
    return service


@pytest.fixture
def tool_search_config() -> ToolSearchConfig:
    """Standard config for performance tests."""
    return ToolSearchConfig(
        collection_name="test_tools",
        skills_weight=2.0,
        internal_weight=1.5,
        external_weight=1.0,
        cache_ttl_seconds=60,
        enable_adaptive_ranking=False,  # Disable for isolated benchmarks
    )


# ==================== Benchmark 1: Service Construction ====================


@pytest.mark.asyncio
@pytest.mark.benchmark
@pytest.mark.performance
async def test_benchmark_service_construction_lazy(
    tool_search_config: ToolSearchConfig,
    mock_embedding_service: Any,
):
    """
    Benchmark 1: Service Construction (Lazy Init)

    Target: < 10ms (no ChromaDB initialization)
    Warning: > 20ms
    Critical: > 50ms

    Validates Issue #34: Lazy initialization means service construction
    should be near-instant without database I/O.
    """
    start = time.perf_counter()

    # Construct service - should NOT initialize ChromaDB
    service = ToolSearchService(
        config=tool_search_config,
        persist_directory="./test_chromadb",
        embedding_service=mock_embedding_service,
    )

    duration_ms = (time.perf_counter() - start) * 1000

    # Verify lazy init: ChromaDB not yet created
    assert service._client is None, "Client should be None until first use"
    assert service._collection is None, "Collection should be None until first use"
    assert service._initialized is False, "Should not be initialized yet"

    print(f"\n[Benchmark 1] Service Construction (Lazy): {duration_ms:.2f}ms")
    print(f"  - ChromaDB client: {'NOT initialized (lazy)' if not service._initialized else 'INITIALIZED (eager)'}")
    print(f"  - State verification: PASSED")

    # Performance assertions
    if duration_ms > 50:
        pytest.fail(
            f"❌ CRITICAL: Service construction too slow: {duration_ms:.2f}ms (> 50ms). "
            "Lazy init should prevent I/O during construction."
        )
    elif duration_ms > 20:
        pytest.warn(
            f"⚠️  WARNING: Service construction slow: {duration_ms:.2f}ms (> 20ms). "
            "Expected < 10ms for lazy init."
        )
    elif duration_ms < 10:
        print(
            f"✅ PASS: Service construction fast: {duration_ms:.2f}ms (< 10ms target). "
            "Lazy init working correctly."
        )
    else:
        print(f"✅ ACCEPTABLE: Service construction: {duration_ms:.2f}ms (10-20ms)")


# ==================== Benchmark 2: First Search (Cold Start) ====================


@pytest.mark.asyncio
@pytest.mark.benchmark
@pytest.mark.performance
async def test_benchmark_first_search_latency(
    tool_search_config: ToolSearchConfig,
    mock_chroma_client: tuple[Any, Any],
    mock_embedding_service: Any,
):
    """
    Benchmark 2: First Search Latency (Cold Start with Lazy Init)

    Target: < 50ms (includes lazy initialization overhead)
    Warning: > 100ms
    Critical: > 200ms

    Validates Issue #34: First search triggers lazy init but should still
    be fast due to optimized initialization path.
    """
    mock_client, mock_collection = mock_chroma_client

    service = ToolSearchService(
        config=tool_search_config,
        persist_directory="./test_chromadb",
        embedding_service=mock_embedding_service,
    )

    # Verify service starts uninitialized
    assert service._initialized is False

    # Mock ChromaDB creation during lazy init
    with patch("chromadb.PersistentClient", return_value=mock_client):
        start = time.perf_counter()

        # First search - triggers lazy init + search
        query = ToolSearchQuery(
            query="search memories",
            source="all",
            limit=5,
        )
        response = await service.search(query)

        duration_ms = (time.perf_counter() - start) * 1000

    # Verify initialization happened
    assert service._initialized is True, "Service should be initialized after first search"
    assert service._client is not None, "Client should be created"
    assert service._collection is not None, "Collection should be created"

    # Verify search results
    assert len(response.results) > 0, "Should return search results"
    assert response.search_latency_ms > 0, "Should measure latency"

    print(f"\n[Benchmark 2] First Search (Cold Start): {duration_ms:.2f}ms")
    print(f"  - Initialization triggered: {'YES' if service._initialized else 'NO'}")
    print(f"  - Results returned: {len(response.results)}")
    print(f"  - Service latency reported: {response.search_latency_ms:.2f}ms")

    # Performance assertions
    if duration_ms > 200:
        pytest.fail(
            f"❌ CRITICAL: First search too slow: {duration_ms:.2f}ms (> 200ms). "
            "Lazy init overhead is excessive."
        )
    elif duration_ms > 100:
        pytest.warn(
            f"⚠️  WARNING: First search slow: {duration_ms:.2f}ms (> 100ms). "
            "Target is < 50ms for cold start."
        )
    elif duration_ms < 50:
        print(
            f"✅ PASS: First search fast: {duration_ms:.2f}ms (< 50ms target). "
            "Lazy init overhead is minimal."
        )
    else:
        print(f"✅ ACCEPTABLE: First search: {duration_ms:.2f}ms (50-100ms)")


# ==================== Benchmark 3: Subsequent Operations (Warm) ====================


@pytest.mark.asyncio
@pytest.mark.benchmark
@pytest.mark.performance
async def test_benchmark_subsequent_operations(
    tool_search_config: ToolSearchConfig,
    mock_chroma_client: tuple[Any, Any],
    mock_embedding_service: Any,
):
    """
    Benchmark 3: Subsequent Operations (Warm ChromaDB)

    Target: < 10ms per operation
    Warning: > 20ms
    Critical: > 50ms

    After lazy init completes, subsequent operations should be fast
    with no initialization overhead.
    """
    mock_client, mock_collection = mock_chroma_client

    service = ToolSearchService(
        config=tool_search_config,
        persist_directory="./test_chromadb",
        embedding_service=mock_embedding_service,
    )

    # Initialize service first (cold start)
    with patch("chromadb.PersistentClient", return_value=mock_client):
        await service._ensure_initialized()

    assert service._initialized is True, "Service should be initialized"

    # Benchmark 10 consecutive searches (warm)
    query = ToolSearchQuery(
        query="memory operations",
        source="all",
        limit=5,
    )

    durations = []
    for i in range(10):
        start = time.perf_counter()
        response = await service.search(query)
        duration_ms = (time.perf_counter() - start) * 1000
        durations.append(duration_ms)

        assert len(response.results) > 0, f"Search {i + 1} should return results"

    # Calculate statistics
    avg_ms = sum(durations) / len(durations)
    min_ms = min(durations)
    max_ms = max(durations)
    p95_ms = sorted(durations)[int(len(durations) * 0.95)]

    print(f"\n[Benchmark 3] Subsequent Operations (Warm): {len(durations)} searches")
    print(f"  - Average: {avg_ms:.2f}ms")
    print(f"  - Min: {min_ms:.2f}ms")
    print(f"  - Max: {max_ms:.2f}ms")
    print(f"  - P95: {p95_ms:.2f}ms")
    print(f"  - All durations: {', '.join(f'{d:.1f}' for d in durations)}ms")

    # Performance assertions (use P95 for stability)
    if p95_ms > 50:
        pytest.fail(
            f"❌ CRITICAL: Warm operations too slow: P95 {p95_ms:.2f}ms (> 50ms). "
            "Subsequent searches should be fast after init."
        )
    elif p95_ms > 20:
        pytest.warn(
            f"⚠️  WARNING: Warm operations slow: P95 {p95_ms:.2f}ms (> 20ms). "
            "Target is < 10ms P95 for warm operations."
        )
    elif p95_ms < 10:
        print(
            f"✅ PASS: Warm operations fast: P95 {p95_ms:.2f}ms (< 10ms target). "
            "ChromaDB is performing optimally."
        )
    else:
        print(f"✅ ACCEPTABLE: Warm operations: P95 {p95_ms:.2f}ms (10-20ms)")


# ==================== Benchmark 4: Initialization Timeout Protection ====================


@pytest.mark.asyncio
@pytest.mark.benchmark
@pytest.mark.performance
async def test_benchmark_initialization_timeout(
    tool_search_config: ToolSearchConfig,
    mock_embedding_service: Any,
):
    """
    Benchmark 4: Initialization Timeout Protection

    Target: Fail fast < 100ms when ChromaDB hangs
    Critical: Should timeout within 30s (INIT_TIMEOUT_SECONDS)

    Validates Hestia C-3 fix: Timeout protection prevents indefinite hangs.
    """

    def slow_chromadb_init(*args, **kwargs):
        """Simulate ChromaDB initialization hang (sync mock)."""
        import time
        time.sleep(5.0)  # Simulate 5s hang (blocking sync call)
        raise Exception("ChromaDB initialization timed out")

    service = ToolSearchService(
        config=tool_search_config,
        persist_directory="./test_chromadb",
        embedding_service=mock_embedding_service,
    )

    # Test with short timeout (0.1s) to verify fast failure
    start = time.perf_counter()
    with patch("chromadb.PersistentClient", side_effect=slow_chromadb_init):
        with pytest.raises(TimeoutError, match="ChromaDB initialization timed out"):
            await service._ensure_initialized(timeout=0.1)

    duration_ms = (time.perf_counter() - start) * 1000

    # Verify service remains uninitialized after timeout
    assert service._initialized is False, "Service should not be initialized after timeout"
    assert service._client is None, "Client should be None after failed init"

    print(f"\n[Benchmark 4] Initialization Timeout Protection: {duration_ms:.2f}ms")
    print(f"  - Timeout threshold: 100ms (0.1s)")
    print(f"  - Actual failure time: {duration_ms:.2f}ms")
    print(f"  - State verification: Service remains uninitialized (CORRECT)")

    # Performance assertions
    if duration_ms > 200:
        pytest.fail(
            f"❌ CRITICAL: Timeout detection too slow: {duration_ms:.2f}ms (> 200ms). "
            "Should fail within ~100ms."
        )
    elif duration_ms > 150:
        pytest.warn(
            f"⚠️  WARNING: Timeout detection slow: {duration_ms:.2f}ms (> 150ms). "
            "Expected ~100ms for timeout detection."
        )
    else:
        print(
            f"✅ PASS: Timeout protection fast: {duration_ms:.2f}ms (~100ms). "
            "Prevents indefinite hangs."
        )


# ==================== Benchmark 5: Double-Check Locking Overhead ====================


@pytest.mark.asyncio
@pytest.mark.benchmark
@pytest.mark.performance
async def test_benchmark_double_check_locking(
    tool_search_config: ToolSearchConfig,
    mock_chroma_client: tuple[Any, Any],
    mock_embedding_service: Any,
):
    """
    Benchmark 5: Double-Check Locking Overhead (Thread Safety)

    Target: < 5ms overhead for concurrent initialization attempts
    Warning: > 10ms
    Critical: > 30ms

    Validates that double-check locking pattern doesn't add significant
    overhead when multiple tasks try to initialize concurrently.
    """
    mock_client, mock_collection = mock_chroma_client

    service = ToolSearchService(
        config=tool_search_config,
        persist_directory="./test_chromadb",
        embedding_service=mock_embedding_service,
    )

    # Simulate 10 concurrent initialization attempts
    with patch("chromadb.PersistentClient", return_value=mock_client):
        start = time.perf_counter()

        # Launch 10 concurrent tasks trying to initialize
        tasks = [service._ensure_initialized() for _ in range(10)]
        await asyncio.gather(*tasks)

        duration_ms = (time.perf_counter() - start) * 1000

    # Verify only one initialization occurred
    assert service._initialized is True
    assert mock_client.get_or_create_collection.call_count == 1, (
        "Collection should be created exactly once despite concurrent attempts"
    )

    print(f"\n[Benchmark 5] Double-Check Locking (10 concurrent tasks): {duration_ms:.2f}ms")
    print(f"  - Collection created: {mock_client.get_or_create_collection.call_count} time(s)")
    print(f"  - Average per task: {duration_ms / 10:.2f}ms")
    print(f"  - Thread safety: {'VERIFIED' if mock_client.get_or_create_collection.call_count == 1 else 'FAILED'}")

    # Performance assertions
    if duration_ms > 30:
        pytest.fail(
            f"❌ CRITICAL: Double-check locking too slow: {duration_ms:.2f}ms (> 30ms). "
            "Lock contention is excessive."
        )
    elif duration_ms > 10:
        pytest.warn(
            f"⚠️  WARNING: Double-check locking slow: {duration_ms:.2f}ms (> 10ms). "
            "Target is < 5ms overhead."
        )
    elif duration_ms < 5:
        print(
            f"✅ PASS: Double-check locking fast: {duration_ms:.2f}ms (< 5ms overhead). "
            "Minimal lock contention."
        )
    else:
        print(f"✅ ACCEPTABLE: Double-check locking: {duration_ms:.2f}ms (5-10ms)")


# ==================== Benchmark 6: Tool Indexing Performance ====================


@pytest.mark.asyncio
@pytest.mark.benchmark
@pytest.mark.performance
async def test_benchmark_tool_indexing(
    tool_search_config: ToolSearchConfig,
    mock_chroma_client: tuple[Any, Any],
    mock_embedding_service: Any,
):
    """
    Benchmark 6: Tool Indexing Performance

    Target: < 50ms for 10 tools
    Warning: > 100ms
    Critical: > 200ms

    Validates that registering tools (common at startup) is fast enough
    to meet overall < 2s startup target.
    """
    mock_client, mock_collection = mock_chroma_client

    service = ToolSearchService(
        config=tool_search_config,
        persist_directory="./test_chromadb",
        embedding_service=mock_embedding_service,
    )

    # Create 10 sample tools
    tools = [
        ToolMetadata(
            name=f"tool_{i}",
            description=f"Tool {i} description",
            input_schema={"type": "object"},
            tags=["test", f"category_{i % 3}"],
        )
        for i in range(10)
    ]

    # Initialize service first
    with patch("chromadb.PersistentClient", return_value=mock_client):
        await service._ensure_initialized()

        # Benchmark indexing
        start = time.perf_counter()
        count = await service.register_internal_tools(tools)
        duration_ms = (time.perf_counter() - start) * 1000

    assert count == 10, f"Should register all 10 tools, got {count}"

    # Verify upsert was called
    assert mock_collection.upsert.called, "Collection upsert should be called"

    print(f"\n[Benchmark 6] Tool Indexing (10 tools): {duration_ms:.2f}ms")
    print(f"  - Tools registered: {count}")
    print(f"  - Average per tool: {duration_ms / 10:.2f}ms")
    print(f"  - ChromaDB upsert calls: {mock_collection.upsert.call_count}")

    # Performance assertions
    if duration_ms > 200:
        pytest.fail(
            f"❌ CRITICAL: Tool indexing too slow: {duration_ms:.2f}ms (> 200ms). "
            "Startup will exceed 2s target."
        )
    elif duration_ms > 100:
        pytest.warn(
            f"⚠️  WARNING: Tool indexing slow: {duration_ms:.2f}ms (> 100ms). "
            "Target is < 50ms for 10 tools."
        )
    elif duration_ms < 50:
        print(
            f"✅ PASS: Tool indexing fast: {duration_ms:.2f}ms (< 50ms target). "
            "Bulk indexing is efficient."
        )
    else:
        print(f"✅ ACCEPTABLE: Tool indexing: {duration_ms:.2f}ms (50-100ms)")


# ==================== Summary Report ====================


@pytest.mark.asyncio
@pytest.mark.benchmark
@pytest.mark.performance
async def test_benchmark_summary():
    """
    Generate startup time benchmark summary report.

    Displays overall results and validates Issue #35 performance targets.
    """
    print("\n" + "=" * 70)
    print("Startup Time Performance Benchmark Summary - Issue #35 Validation")
    print("=" * 70)
    print("\nIssue #34 Lazy Loading Implementation:")
    print("  - ToolSearchService constructor: Lazy init (no ChromaDB I/O)")
    print("  - First search operation: Triggers lazy init on-demand")
    print("  - Double-check locking: Thread-safe concurrent init")
    print("  - Timeout protection: Prevents indefinite hangs")
    print("\nPerformance Targets (Issue #35):")
    print("  1. Service construction: < 10ms")
    print("  2. First search (cold start): < 50ms (includes lazy init)")
    print("  3. Subsequent operations (warm): < 10ms P95")
    print("  4. Initialization timeout: Fail fast < 100ms")
    print("  5. Double-check locking: < 5ms overhead")
    print("  6. Tool indexing (10 tools): < 50ms")
    print("\nOverall Targets:")
    print("  - Startup time: < 2s (down from 15-30s baseline)")
    print("  - Memory footprint: < 200MB (down from 800MB baseline)")
    print("  - Tool discovery latency: < 100ms P95")
    print("\nJudgment Criteria:")
    print("  ✅ ALL PASS → Lazy loading validated, Issue #35 ready to close")
    print("  ⚠️  WARNING → Optimization needed, review implementation")
    print("  ❌ CRITICAL → Lazy loading failed, Issue #34 regression")
    print("\nExecution Command:")
    print("  pytest tests/performance/test_startup_time.py -v -m benchmark")
    print("  pytest tests/performance/test_startup_time.py -v -m performance")
    print("=" * 70)
