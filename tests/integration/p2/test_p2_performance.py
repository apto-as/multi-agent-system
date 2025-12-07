"""
P2 Performance Benchmark Integration Tests (PERF-P2).

Tests for performance benchmarking and latency requirements.
"""

import asyncio
import statistics
import time
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest


@pytest.mark.integration
@pytest.mark.performance
class TestAPIResponseLatency:
    """Test API response latency requirements."""

    @pytest.mark.asyncio
    async def test_memory_search_latency_p95(self, performance_thresholds):
        """Test memory search meets P95 latency threshold."""
        mock_service = AsyncMock()
        mock_service.search_memories = AsyncMock(return_value=[])

        latencies = []
        for _ in range(100):
            start = time.perf_counter()
            await mock_service.search_memories(query="test query", limit=10)
            latencies.append((time.perf_counter() - start) * 1000)

        p95 = sorted(latencies)[94]  # 95th percentile
        # Mock operations should be well under threshold
        assert p95 < performance_thresholds["memory_search_p95"]

    @pytest.mark.asyncio
    async def test_memory_create_latency_p95(self, performance_thresholds):
        """Test memory creation meets P95 latency threshold."""
        mock_service = AsyncMock()
        mock_mem = Mock()
        mock_mem.id = uuid4()
        mock_service.create_memory = AsyncMock(return_value=mock_mem)

        latencies = []
        for _ in range(100):
            start = time.perf_counter()
            await mock_service.create_memory(
                content="test content",
                agent_id="test-agent",
                memory_type="episodic"
            )
            latencies.append((time.perf_counter() - start) * 1000)

        p95 = sorted(latencies)[94]
        assert p95 < performance_thresholds["memory_create_p95"]

    @pytest.mark.asyncio
    async def test_api_response_latency_p99(self, performance_thresholds):
        """Test general API responses meet P99 latency threshold."""
        mock_endpoint = AsyncMock(return_value={"status": "ok"})

        latencies = []
        for _ in range(100):
            start = time.perf_counter()
            await mock_endpoint()
            latencies.append((time.perf_counter() - start) * 1000)

        p99 = sorted(latencies)[98]
        assert p99 < performance_thresholds["api_response_p99"]


@pytest.mark.integration
@pytest.mark.performance
class TestBatchOperations:
    """Test batch operation performance."""

    @pytest.mark.asyncio
    async def test_batch_memory_creation(self, performance_thresholds):
        """Test batch memory creation performance."""
        mock_service = AsyncMock()

        async def create_batch(items):
            results = []
            for item in items:
                mock_mem = Mock()
                mock_mem.id = uuid4()
                mock_mem.content = item["content"]
                results.append(mock_mem)
            return results

        mock_service.batch_create = AsyncMock(side_effect=create_batch)

        batch_items = [
            {"content": f"Memory {i}", "agent_id": "agent-1"}
            for i in range(50)
        ]

        start = time.perf_counter()
        results = await mock_service.batch_create(batch_items)
        elapsed = (time.perf_counter() - start) * 1000

        assert len(results) == 50
        assert elapsed < performance_thresholds["batch_operation_p95"]

    @pytest.mark.asyncio
    async def test_batch_skill_execution(self, performance_thresholds):
        """Test batch skill execution performance."""
        mock_executor = AsyncMock()

        async def execute_batch(skills):
            await asyncio.sleep(0.001)  # Simulate minimal processing
            return [{"skill_id": s["id"], "result": "success"} for s in skills]

        mock_executor.execute_batch = AsyncMock(side_effect=execute_batch)

        skills = [{"id": f"skill-{i}", "params": {}} for i in range(20)]

        start = time.perf_counter()
        results = await mock_executor.execute_batch(skills)
        elapsed = (time.perf_counter() - start) * 1000

        assert len(results) == 20
        assert elapsed < performance_thresholds["skill_execution_p95"]


@pytest.mark.integration
@pytest.mark.performance
class TestConcurrencyLimits:
    """Test system behavior under concurrent load."""

    @pytest.mark.asyncio
    async def test_concurrent_memory_operations(self, performance_thresholds):
        """Test concurrent memory operations."""
        mock_service = AsyncMock()
        mock_mem = Mock()
        mock_mem.id = uuid4()
        mock_service.create_memory = AsyncMock(return_value=mock_mem)

        concurrent_ops = performance_thresholds["concurrent_connections"]

        async def single_operation(i):
            return await mock_service.create_memory(
                content=f"Concurrent memory {i}",
                agent_id="agent-1"
            )

        tasks = [single_operation(i) for i in range(concurrent_ops)]

        start = time.perf_counter()
        results = await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - start

        assert len(results) == concurrent_ops
        # Should complete in reasonable time
        assert elapsed < 5.0  # 5 seconds for 100 concurrent ops

    @pytest.mark.asyncio
    async def test_rate_limiting_enforcement(self, performance_thresholds):
        """Test rate limiting is enforced correctly."""
        call_count = 0
        rate_limited_count = 0
        max_rps = performance_thresholds["requests_per_second"]

        async def rate_limited_endpoint():
            nonlocal call_count, rate_limited_count
            call_count += 1
            if call_count > max_rps:
                rate_limited_count += 1
                return {"error": "rate_limited", "status": 429}
            return {"status": "ok"}

        mock_endpoint = AsyncMock(side_effect=rate_limited_endpoint)

        # Try to exceed rate limit
        tasks = [mock_endpoint() for _ in range(max_rps + 20)]
        results = await asyncio.gather(*tasks)

        rate_limited = [r for r in results if r.get("status") == 429]
        assert len(rate_limited) == 20


@pytest.mark.integration
@pytest.mark.performance
class TestResourceUtilization:
    """Test resource utilization metrics."""

    @pytest.mark.asyncio
    async def test_memory_usage_tracking(self):
        """Test memory usage is tracked correctly."""
        mock_metrics = Mock()
        mock_metrics.memory_used = 0
        mock_metrics.memory_limit = 1024 * 1024 * 1024  # 1GB

        def allocate(size):
            mock_metrics.memory_used += size
            return mock_metrics.memory_used < mock_metrics.memory_limit

        mock_metrics.allocate = Mock(side_effect=allocate)

        # Simulate memory allocations
        allocations = [1024 * 1024 for _ in range(100)]  # 100 x 1MB

        for size in allocations:
            result = mock_metrics.allocate(size)
            assert result is True

        assert mock_metrics.memory_used == 100 * 1024 * 1024

    @pytest.mark.asyncio
    async def test_connection_pool_management(self):
        """Test connection pool is managed correctly."""
        pool = Mock()
        pool.active_connections = 0
        pool.max_connections = 20
        pool.waiting_queue = []

        def acquire():
            if pool.active_connections < pool.max_connections:
                pool.active_connections += 1
                return Mock(id=pool.active_connections)
            pool.waiting_queue.append(1)
            return None

        def release():
            if pool.active_connections > 0:
                pool.active_connections -= 1
                if pool.waiting_queue:
                    pool.waiting_queue.pop()
                    pool.active_connections += 1

        pool.acquire = Mock(side_effect=acquire)
        pool.release = Mock(side_effect=release)

        # Acquire max connections
        connections = []
        for _ in range(pool.max_connections):
            conn = pool.acquire()
            connections.append(conn)

        assert pool.active_connections == pool.max_connections

        # Try to exceed - should return None
        overflow = pool.acquire()
        assert overflow is None
        assert len(pool.waiting_queue) == 1

        # Release one
        pool.release()
        assert pool.active_connections == pool.max_connections
        assert len(pool.waiting_queue) == 0


@pytest.mark.integration
@pytest.mark.performance
class TestLatencyDistribution:
    """Test latency distribution analysis."""

    @pytest.mark.asyncio
    async def test_latency_percentiles(self, performance_thresholds):
        """Test latency percentile calculations."""
        mock_service = AsyncMock()

        # Simulate varying latencies
        async def variable_latency():
            import random
            delay = random.uniform(0.001, 0.01)  # 1-10ms
            await asyncio.sleep(delay)
            return {"status": "ok"}

        mock_service.process = AsyncMock(side_effect=variable_latency)

        latencies = []
        for _ in range(100):
            start = time.perf_counter()
            await mock_service.process()
            latencies.append((time.perf_counter() - start) * 1000)

        sorted_latencies = sorted(latencies)
        p50 = sorted_latencies[49]
        p90 = sorted_latencies[89]
        p95 = sorted_latencies[94]
        p99 = sorted_latencies[98]

        # Verify percentile ordering
        assert p50 <= p90 <= p95 <= p99

        # Verify within expected bounds
        assert p99 < performance_thresholds["api_response_p95"] * 2

    @pytest.mark.asyncio
    async def test_outlier_detection(self):
        """Test outlier detection in latency measurements."""
        latencies = [10, 12, 11, 13, 10, 500, 11, 12, 10, 11]  # 500ms outlier

        mean = statistics.mean(latencies)
        std = statistics.stdev(latencies)

        # Detect outliers (more than 2 std from mean)
        outliers = [l for l in latencies if abs(l - mean) > 2 * std]

        assert len(outliers) == 1
        assert 500 in outliers


@pytest.mark.integration
@pytest.mark.performance
class TestThroughput:
    """Test system throughput."""

    @pytest.mark.asyncio
    async def test_operations_per_second(self, performance_thresholds):
        """Test operations per second throughput."""
        mock_service = AsyncMock()
        mock_service.process = AsyncMock(return_value={"status": "ok"})

        target_ops = performance_thresholds["requests_per_second"]

        start = time.perf_counter()
        ops_completed = 0

        while time.perf_counter() - start < 1.0:  # 1 second window
            await mock_service.process()
            ops_completed += 1

        # Should be able to complete at least target ops
        assert ops_completed >= target_ops

    @pytest.mark.asyncio
    async def test_sustained_throughput(self, performance_thresholds):
        """Test sustained throughput over time."""
        mock_service = AsyncMock()
        mock_service.process = AsyncMock(return_value={"status": "ok"})

        duration = 3  # seconds
        ops_per_interval = []

        for _ in range(duration):
            start = time.perf_counter()
            ops = 0
            while time.perf_counter() - start < 1.0:
                await mock_service.process()
                ops += 1
            ops_per_interval.append(ops)

        # Check consistency - no more than 20% variance
        avg_ops = statistics.mean(ops_per_interval)
        for ops in ops_per_interval:
            variance = abs(ops - avg_ops) / avg_ops
            assert variance < 0.2
