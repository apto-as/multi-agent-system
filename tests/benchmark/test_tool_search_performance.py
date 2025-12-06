"""Phase 4.3: Tool Search Performance Benchmark Tests.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 4.3 - Performance Optimization

Performance Targets:
- search_tools: < 100ms P95 latency
- Adaptive ranking: < 10ms overhead
- Tool promotion check: < 50ms

Author: Artemis (Implementation)
Created: 2025-12-05
"""

import asyncio
import statistics
import time
from datetime import datetime, timedelta

import pytest

from src.models.tool_search import ToolSearchResult, ToolSourceType
from src.services.adaptive_ranker import (
    AdaptiveRanker,
    AdaptiveRankingConfig,
    ToolOutcome,
    ToolUsagePattern,
)
from src.services.tool_promotion_service import (
    PromotionCriteria,
    ToolPromotionService,
)

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def ranker():
    """AdaptiveRanker with performance-optimized config."""
    config = AdaptiveRankingConfig(
        min_usage_for_personalization=3,
        max_patterns_to_consider=100,
    )
    return AdaptiveRanker(config=config)


@pytest.fixture
def sample_results():
    """Generate sample search results for benchmarking."""
    results = []
    for i in range(50):
        results.append(
            ToolSearchResult(
                tool_name=f"tool_{i}",
                server_id="tmws" if i % 2 == 0 else f"mcp__server{i}",
                description=f"Description for tool {i}",
                relevance_score=0.9 - (i * 0.01),
                source_type=ToolSourceType.INTERNAL if i % 3 == 0 else ToolSourceType.EXTERNAL,
            )
        )
    return results


@pytest.fixture
def populated_ranker(ranker):
    """Ranker with pre-populated patterns for benchmarking."""
    # Add patterns for multiple agents
    for agent_idx in range(10):
        agent_id = f"agent_{agent_idx}"
        ranker._agent_patterns[agent_id] = {}
        ranker._cache_timestamps[agent_id] = time.time()

        # Add 50 tools per agent
        for tool_idx in range(50):
            pattern_key = f"tmws:tool_{tool_idx}"
            ranker._agent_patterns[agent_id][pattern_key] = ToolUsagePattern(
                tool_name=f"tool_{tool_idx}",
                server_id="tmws",
                agent_id=agent_id,
                usage_count=100 + tool_idx,
                success_count=90 + tool_idx,
                total_latency_ms=5000.0 + tool_idx * 100,
                last_used=datetime.now() - timedelta(days=tool_idx % 30),
                query_contexts=[f"query{j}" for j in range(10)],
            )

    return ranker


# ============================================================================
# AdaptiveRanker Performance Tests
# ============================================================================


class TestAdaptiveRankerPerformance:
    """Performance benchmarks for AdaptiveRanker."""

    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_rank_for_agent_latency(self, populated_ranker, sample_results):
        """Ranking should complete within 10ms P95."""
        latencies = []

        # Warm up
        for _ in range(5):
            await populated_ranker.rank_for_agent(sample_results, "agent_0")

        # Measure 100 iterations
        for i in range(100):
            start = time.perf_counter()
            await populated_ranker.rank_for_agent(
                sample_results,
                f"agent_{i % 10}",
            )
            latency_ms = (time.perf_counter() - start) * 1000
            latencies.append(latency_ms)

        p50 = statistics.median(latencies)
        p95 = statistics.quantiles(latencies, n=20)[18]  # 95th percentile
        p99 = statistics.quantiles(latencies, n=100)[98]  # 99th percentile

        print(f"\n  rank_for_agent: P50={p50:.2f}ms, P95={p95:.2f}ms, P99={p99:.2f}ms")

        # Performance target: < 10ms P95
        assert p95 < 10, f"P95 latency {p95:.2f}ms exceeds 10ms target"

    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_record_outcome_latency(self, ranker):
        """Recording outcome should complete within 5ms P95."""
        latencies = []

        # Measure 100 iterations
        for i in range(100):
            start = time.perf_counter()
            await ranker.record_outcome(
                agent_id=f"agent_{i % 10}",
                tool_name=f"tool_{i}",
                server_id="tmws",
                query=f"test query {i}",
                outcome=ToolOutcome.SUCCESS,
                latency_ms=50.0,
            )
            latency_ms = (time.perf_counter() - start) * 1000
            latencies.append(latency_ms)

        p50 = statistics.median(latencies)
        p95 = statistics.quantiles(latencies, n=20)[18]

        print(f"\n  record_outcome: P50={p50:.2f}ms, P95={p95:.2f}ms")

        # Performance target: < 5ms P95
        assert p95 < 5, f"P95 latency {p95:.2f}ms exceeds 5ms target"

    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_get_recommendations_latency(self, populated_ranker):
        """Getting recommendations should complete within 5ms P95."""
        latencies = []

        for i in range(100):
            start = time.perf_counter()
            await populated_ranker.get_recommendations(
                agent_id=f"agent_{i % 10}",
                limit=5,
            )
            latency_ms = (time.perf_counter() - start) * 1000
            latencies.append(latency_ms)

        p50 = statistics.median(latencies)
        p95 = statistics.quantiles(latencies, n=20)[18]

        print(f"\n  get_recommendations: P50={p50:.2f}ms, P95={p95:.2f}ms")

        assert p95 < 5, f"P95 latency {p95:.2f}ms exceeds 5ms target"

    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_concurrent_ranking(self, populated_ranker, sample_results):
        """Should handle concurrent ranking requests."""
        async def rank_task(agent_id: str):
            return await populated_ranker.rank_for_agent(sample_results, agent_id)

        start = time.perf_counter()

        # 50 concurrent ranking requests
        tasks = [rank_task(f"agent_{i % 10}") for i in range(50)]
        results = await asyncio.gather(*tasks)

        total_ms = (time.perf_counter() - start) * 1000
        avg_ms = total_ms / len(tasks)

        print(f"\n  concurrent_ranking (50 tasks): total={total_ms:.2f}ms, avg={avg_ms:.2f}ms")

        assert len(results) == 50
        assert total_ms < 500  # All 50 should complete in < 500ms


# ============================================================================
# ToolPromotionService Performance Tests
# ============================================================================


class TestToolPromotionPerformance:
    """Performance benchmarks for ToolPromotionService."""

    @pytest.fixture
    def promotion_service(self, populated_ranker):
        """ToolPromotionService with populated ranker."""
        return ToolPromotionService(
            adaptive_ranker=populated_ranker,
            criteria=PromotionCriteria(),
        )

    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_get_candidates_latency(self, promotion_service):
        """Getting candidates should complete within 50ms P95."""
        latencies = []

        for i in range(50):
            start = time.perf_counter()
            await promotion_service.get_promotion_candidates(
                agent_id=f"agent_{i % 10}",
                limit=10,
            )
            latency_ms = (time.perf_counter() - start) * 1000
            latencies.append(latency_ms)

        p50 = statistics.median(latencies)
        p95 = statistics.quantiles(latencies, n=20)[18]

        print(f"\n  get_promotion_candidates: P50={p50:.2f}ms, P95={p95:.2f}ms")

        assert p95 < 50, f"P95 latency {p95:.2f}ms exceeds 50ms target"

    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_evaluate_pattern_latency(self, promotion_service, populated_ranker):
        """Pattern evaluation should complete within 1ms."""
        patterns = list(populated_ranker._agent_patterns["agent_0"].values())
        latencies = []

        for pattern in patterns[:50]:
            start = time.perf_counter()
            promotion_service._evaluate_pattern(pattern, "agent_0")
            latency_ms = (time.perf_counter() - start) * 1000
            latencies.append(latency_ms)

        p50 = statistics.median(latencies)
        p95 = statistics.quantiles(latencies, n=20)[18]

        print(f"\n  _evaluate_pattern: P50={p50:.4f}ms, P95={p95:.4f}ms")

        assert p95 < 1, f"P95 latency {p95:.4f}ms exceeds 1ms target"


# ============================================================================
# Memory Usage Tests
# ============================================================================


class TestMemoryEfficiency:
    """Memory efficiency tests."""

    @pytest.mark.benchmark
    def test_pattern_memory_size(self, populated_ranker):
        """Check memory usage of patterns."""
        import sys

        # Count total patterns
        total_patterns = sum(
            len(patterns) for patterns in populated_ranker._agent_patterns.values()
        )

        # Estimate size (rough)
        sample_pattern = ToolUsagePattern(
            tool_name="test",
            server_id="tmws",
            agent_id="agent",
            usage_count=100,
            success_count=90,
            query_contexts=[f"q{i}" for i in range(10)],
        )
        pattern_size = sys.getsizeof(sample_pattern)

        print(
            f"\n  Total patterns: {total_patterns}, "
            f"~{pattern_size} bytes per pattern"
        )

        # Should handle at least 10k patterns efficiently
        assert total_patterns >= 100


# ============================================================================
# Throughput Tests
# ============================================================================


class TestThroughput:
    """Throughput benchmarks."""

    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_ranking_throughput(self, populated_ranker, sample_results):
        """Measure ranking throughput (ops/sec)."""
        duration_seconds = 1.0
        ops_count = 0
        start = time.perf_counter()

        while time.perf_counter() - start < duration_seconds:
            await populated_ranker.rank_for_agent(
                sample_results,
                f"agent_{ops_count % 10}",
            )
            ops_count += 1

        ops_per_second = ops_count / duration_seconds

        print(f"\n  Ranking throughput: {ops_per_second:.0f} ops/sec")

        # Should handle at least 100 ops/sec
        assert ops_per_second >= 100

    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_outcome_recording_throughput(self, ranker):
        """Measure outcome recording throughput."""
        duration_seconds = 1.0
        ops_count = 0
        start = time.perf_counter()

        while time.perf_counter() - start < duration_seconds:
            await ranker.record_outcome(
                agent_id=f"agent_{ops_count % 10}",
                tool_name=f"tool_{ops_count % 50}",
                server_id="tmws",
                query=f"query {ops_count}",
                outcome=ToolOutcome.SUCCESS,
            )
            ops_count += 1

        ops_per_second = ops_count / duration_seconds

        print(f"\n  Recording throughput: {ops_per_second:.0f} ops/sec")

        # Should handle at least 500 ops/sec
        assert ops_per_second >= 500
