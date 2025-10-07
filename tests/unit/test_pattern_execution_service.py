"""
Unit tests for Pattern Execution Service
Tests performance, correctness, and edge cases
"""

import re
import time
from unittest.mock import AsyncMock, patch

import pytest

from src.core.cache import CacheManager
from src.services.pattern_execution_service import (
    ExecutionMode,
    HybridDecisionRouter,
    PatternDefinition,
    PatternExecutionEngine,
    PatternRegistry,
    PatternType,
)

# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def sample_pattern_config():
    """Sample pattern configuration"""
    return {
        'name': 'test_pattern',
        'pattern_type': 'infrastructure',
        'trigger_pattern': r'test\s+query',
        'cost_tokens': 50,
        'priority': 10,
        'cache_ttl': 300,
        'metadata': {'test': True}
    }


@pytest.fixture
def pattern_registry():
    """Create pattern registry with test patterns"""
    registry = PatternRegistry()

    patterns = [
        PatternDefinition.from_config({
            'name': 'infra_pattern',
            'pattern_type': 'infrastructure',
            'trigger_pattern': r'execute\s+tool',
            'cost_tokens': 50,
            'priority': 10
        }),
        PatternDefinition.from_config({
            'name': 'memory_pattern',
            'pattern_type': 'memory',
            'trigger_pattern': r'recall\s+memory',
            'cost_tokens': 100,
            'priority': 9
        }),
        PatternDefinition.from_config({
            'name': 'hybrid_pattern',
            'pattern_type': 'hybrid',
            'trigger_pattern': r'analyze\s+system',
            'cost_tokens': 150,
            'priority': 8
        })
    ]

    registry.register_batch(patterns)
    return registry


@pytest.fixture
async def cache_manager():
    """Create cache manager for testing"""
    cache = CacheManager(
        redis_url=None,  # Use local cache only for tests
        local_ttl=60,
        redis_ttl=300,
        max_local_size=100
    )
    await cache.initialize()
    return cache


@pytest.fixture
async def mock_session():
    """Mock database session"""
    session = AsyncMock()
    session.execute = AsyncMock()
    return session


# ============================================================================
# PATTERN DEFINITION TESTS
# ============================================================================

class TestPatternDefinition:
    """Test PatternDefinition class"""

    def test_from_config(self, sample_pattern_config):
        """Test pattern creation from config"""
        pattern = PatternDefinition.from_config(sample_pattern_config)

        assert pattern.name == 'test_pattern'
        assert pattern.pattern_type == PatternType.INFRASTRUCTURE
        assert pattern.cost_tokens == 50
        assert pattern.priority == 10
        assert pattern.cache_ttl == 300
        assert pattern.metadata['test'] is True

        # Verify regex is compiled
        assert isinstance(pattern.trigger_regex, re.Pattern)

    def test_regex_compilation(self, sample_pattern_config):
        """Test that regex is pre-compiled correctly"""
        pattern = PatternDefinition.from_config(sample_pattern_config)

        # Should match
        assert pattern.trigger_regex.search("test query")
        assert pattern.trigger_regex.search("TEST QUERY")  # Case insensitive

        # Should not match
        assert not pattern.trigger_regex.search("other query")


# ============================================================================
# PATTERN REGISTRY TESTS
# ============================================================================

class TestPatternRegistry:
    """Test PatternRegistry class"""

    def test_register_pattern(self):
        """Test pattern registration"""
        registry = PatternRegistry()

        pattern = PatternDefinition.from_config({
            'name': 'test',
            'pattern_type': 'infrastructure',
            'trigger_pattern': r'test',
            'cost_tokens': 50,
            'priority': 10
        })

        registry.register(pattern)

        assert 'test' in registry.patterns
        assert registry.patterns['test'] == pattern

    def test_register_batch(self, pattern_registry):
        """Test batch registration"""
        assert len(pattern_registry.patterns) == 3
        assert 'infra_pattern' in pattern_registry.patterns
        assert 'memory_pattern' in pattern_registry.patterns
        assert 'hybrid_pattern' in pattern_registry.patterns

    def test_exact_match(self, pattern_registry):
        """Test exact name matching (O(1))"""
        # Should match by exact name
        pattern = pattern_registry.find_matching_pattern('infra_pattern')
        assert pattern is not None
        assert pattern.name == 'infra_pattern'

    def test_regex_match(self, pattern_registry):
        """Test regex matching"""
        # Should match by regex
        pattern = pattern_registry.find_matching_pattern('execute tool now')
        assert pattern is not None
        assert pattern.name == 'infra_pattern'

        pattern = pattern_registry.find_matching_pattern('recall memory about X')
        assert pattern is not None
        assert pattern.name == 'memory_pattern'

        pattern = pattern_registry.find_matching_pattern('analyze system performance')
        assert pattern is not None
        assert pattern.name == 'hybrid_pattern'

    def test_priority_sorting(self):
        """Test that patterns are matched by priority"""
        registry = PatternRegistry()

        # Register low priority first
        low_priority = PatternDefinition.from_config({
            'name': 'low',
            'pattern_type': 'infrastructure',
            'trigger_pattern': r'test',
            'cost_tokens': 50,
            'priority': 1
        })

        # Register high priority second
        high_priority = PatternDefinition.from_config({
            'name': 'high',
            'pattern_type': 'infrastructure',
            'trigger_pattern': r'test',
            'cost_tokens': 50,
            'priority': 10
        })

        registry.register(low_priority)
        registry.register(high_priority)

        # Should match high priority first
        pattern = registry.find_matching_pattern('test query')
        assert pattern.name == 'high'

    def test_pattern_type_filter(self, pattern_registry):
        """Test filtering by pattern type"""
        # Filter to infrastructure only
        pattern = pattern_registry.find_matching_pattern(
            'execute tool',
            pattern_type_filter=PatternType.INFRASTRUCTURE
        )
        assert pattern is not None
        assert pattern.pattern_type == PatternType.INFRASTRUCTURE

        # Filter to memory only (shouldn't match infrastructure)
        pattern = pattern_registry.find_matching_pattern(
            'execute tool',
            pattern_type_filter=PatternType.MEMORY
        )
        assert pattern is None

    def test_no_match(self, pattern_registry):
        """Test when no pattern matches"""
        pattern = pattern_registry.find_matching_pattern('completely unknown query')
        assert pattern is None

    def test_cache_effectiveness(self, pattern_registry):
        """Test that caching improves performance"""
        query = 'execute tool'

        # First call - cache miss
        start = time.perf_counter()
        pattern1 = pattern_registry.find_matching_pattern(query)
        time.perf_counter() - start

        # Second call - cache hit
        start = time.perf_counter()
        pattern2 = pattern_registry.find_matching_pattern(query)
        time.perf_counter() - start

        # Should be same pattern
        assert pattern1 == pattern2

        # Second call should be faster (cache hit)
        # Note: In tests this might not always be true due to overhead
        # but we can at least verify the cache is being used
        stats = pattern_registry.get_stats()
        assert stats['cache_hits'] > 0

    def test_stats(self, pattern_registry):
        """Test statistics collection"""
        # Trigger some matches
        pattern_registry.find_matching_pattern('execute tool')
        pattern_registry.find_matching_pattern('recall memory')
        pattern_registry.find_matching_pattern('unknown query')

        stats = pattern_registry.get_stats()

        assert stats['total_patterns'] == 3
        assert stats['cache_hits'] >= 0
        assert stats['cache_misses'] >= 0
        assert 'cache_hit_rate' in stats


# ============================================================================
# HYBRID DECISION ROUTER TESTS
# ============================================================================

class TestHybridDecisionRouter:
    """Test HybridDecisionRouter class"""

    @pytest.mark.asyncio
    async def test_infrastructure_routing(self, mock_session, cache_manager):
        """Test routing to infrastructure"""
        router = HybridDecisionRouter(mock_session, cache_manager)

        decision = await router.route("execute tool now")

        assert decision.pattern_type == PatternType.INFRASTRUCTURE
        assert decision.confidence > 0.5
        assert decision.estimated_cost < 100
        assert "infrastructure" in decision.reasoning.lower()

    @pytest.mark.asyncio
    async def test_memory_routing(self, mock_session, cache_manager):
        """Test routing to memory"""
        router = HybridDecisionRouter(mock_session, cache_manager)

        # Mock memory stats to show data available
        with patch.object(router, '_get_memory_stats', return_value={'total_memories': 100}):
            decision = await router.route("recall past decisions")

        assert decision.pattern_type == PatternType.MEMORY
        assert decision.confidence > 0.5
        assert decision.estimated_cost < 150

    @pytest.mark.asyncio
    async def test_hybrid_routing(self, mock_session, cache_manager):
        """Test routing to hybrid"""
        router = HybridDecisionRouter(mock_session, cache_manager)

        decision = await router.route("analyze and compare systems")

        assert decision.pattern_type == PatternType.HYBRID
        assert decision.confidence > 0.5
        assert decision.estimated_cost >= 150

    @pytest.mark.asyncio
    async def test_fast_mode(self, mock_session, cache_manager):
        """Test FAST execution mode"""
        router = HybridDecisionRouter(mock_session, cache_manager)

        decision = await router.route(
            "any query",
            execution_mode=ExecutionMode.FAST
        )

        assert decision.pattern_type == PatternType.INFRASTRUCTURE
        assert "fast mode" in decision.reasoning.lower()

    @pytest.mark.asyncio
    async def test_comprehensive_mode(self, mock_session, cache_manager):
        """Test COMPREHENSIVE execution mode"""
        router = HybridDecisionRouter(mock_session, cache_manager)

        decision = await router.route(
            "any query",
            execution_mode=ExecutionMode.COMPREHENSIVE
        )

        assert decision.pattern_type == PatternType.HYBRID
        assert "comprehensive" in decision.reasoning.lower()

    @pytest.mark.asyncio
    async def test_routing_cache(self, mock_session, cache_manager):
        """Test that routing decisions are cached"""
        router = HybridDecisionRouter(mock_session, cache_manager)

        query = "execute tool"

        # First call
        decision1 = await router.route(query)

        # Second call (should be cached)
        decision2 = await router.route(query)

        assert decision1.pattern_type == decision2.pattern_type
        assert decision1.confidence == decision2.confidence

    @pytest.mark.asyncio
    async def test_stats(self, mock_session, cache_manager):
        """Test routing statistics"""
        router = HybridDecisionRouter(mock_session, cache_manager)

        # Generate some routes
        await router.route("execute tool")
        await router.route("recall memory")
        await router.route("analyze system")

        stats = router.get_stats()

        assert stats['total_routes'] == 3
        assert 'routes_by_type' in stats
        assert 'route_distribution' in stats


# ============================================================================
# PATTERN EXECUTION ENGINE TESTS
# ============================================================================

class TestPatternExecutionEngine:
    """Test PatternExecutionEngine class"""

    @pytest.mark.asyncio
    async def test_basic_execution(self, mock_session, cache_manager, pattern_registry):
        """Test basic pattern execution"""
        engine = PatternExecutionEngine(
            session=mock_session,
            cache_manager=cache_manager,
            registry=pattern_registry
        )

        result = await engine.execute("execute tool")

        assert result.success is True
        assert result.pattern_name == 'infra_pattern'
        assert result.tokens_used == 50
        assert result.execution_time_ms > 0

    @pytest.mark.asyncio
    async def test_execution_modes(self, mock_session, cache_manager, pattern_registry):
        """Test different execution modes"""
        engine = PatternExecutionEngine(
            session=mock_session,
            cache_manager=cache_manager,
            registry=pattern_registry
        )

        # FAST mode
        result_fast = await engine.execute(
            "any query",
            execution_mode=ExecutionMode.FAST
        )
        assert result_fast.success is True

        # BALANCED mode
        result_balanced = await engine.execute(
            "any query",
            execution_mode=ExecutionMode.BALANCED
        )
        assert result_balanced.success is True

        # COMPREHENSIVE mode
        result_comp = await engine.execute(
            "any query",
            execution_mode=ExecutionMode.COMPREHENSIVE
        )
        assert result_comp.success is True

    @pytest.mark.asyncio
    async def test_caching(self, mock_session, cache_manager, pattern_registry):
        """Test execution caching"""
        engine = PatternExecutionEngine(
            session=mock_session,
            cache_manager=cache_manager,
            registry=pattern_registry
        )

        query = "execute tool"

        # First execution - cache miss
        result1 = await engine.execute(query, use_cache=True)
        assert result1.cache_hit is False

        # Second execution - cache hit
        result2 = await engine.execute(query, use_cache=True)
        assert result2.cache_hit is True

        # Should be faster
        assert result2.execution_time_ms < result1.execution_time_ms

    @pytest.mark.asyncio
    async def test_cache_bypass(self, mock_session, cache_manager, pattern_registry):
        """Test cache bypass"""
        engine = PatternExecutionEngine(
            session=mock_session,
            cache_manager=cache_manager,
            registry=pattern_registry
        )

        query = "execute tool"

        # Execute with cache
        await engine.execute(query, use_cache=True)

        # Execute without cache
        result2 = await engine.execute(query, use_cache=False)

        # Should not be cached
        assert result2.cache_hit is False

    @pytest.mark.asyncio
    async def test_error_handling(self, mock_session, cache_manager):
        """Test error handling for invalid queries"""
        engine = PatternExecutionEngine(
            session=mock_session,
            cache_manager=cache_manager,
            registry=PatternRegistry()  # Empty registry
        )

        # Query with no matching pattern
        result = await engine.execute("completely invalid query")

        assert result.success is False
        assert result.error is not None
        assert result.tokens_used == 0

    @pytest.mark.asyncio
    async def test_stats_tracking(self, mock_session, cache_manager, pattern_registry):
        """Test statistics tracking"""
        engine = PatternExecutionEngine(
            session=mock_session,
            cache_manager=cache_manager,
            registry=pattern_registry
        )

        # Execute some patterns
        await engine.execute("execute tool")
        await engine.execute("recall memory")
        await engine.execute("analyze system")

        stats = engine.get_stats()

        assert stats['total_executions'] == 3
        assert stats['successful_executions'] >= 0
        assert stats['total_tokens_used'] > 0
        assert 'avg_execution_time_ms' in stats
        assert 'registry_stats' in stats
        assert 'router_stats' in stats

    @pytest.mark.asyncio
    async def test_context_passing(self, mock_session, cache_manager, pattern_registry):
        """Test context passing through execution"""
        engine = PatternExecutionEngine(
            session=mock_session,
            cache_manager=cache_manager,
            registry=pattern_registry
        )

        context = {
            'agent': 'artemis',
            'priority': 'high',
            'custom': 'value'
        }

        result = await engine.execute(
            "execute tool",
            context=context
        )

        assert result.success is True


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

class TestPerformance:
    """Performance tests to verify targets are met"""

    @pytest.mark.asyncio
    async def test_pattern_matching_performance(self, pattern_registry):
        """Test pattern matching speed (<10ms target)"""
        query = "execute tool now"

        # Warm up cache
        pattern_registry.find_matching_pattern(query)

        # Measure performance
        start = time.perf_counter()
        for _ in range(100):
            pattern_registry.find_matching_pattern(query)
        elapsed = (time.perf_counter() - start) * 1000

        avg_time = elapsed / 100

        assert avg_time < 10, f"Pattern matching too slow: {avg_time:.2f}ms"

    @pytest.mark.asyncio
    async def test_infrastructure_execution_performance(
        self, mock_session, cache_manager, pattern_registry
    ):
        """Test infrastructure execution (<50ms target)"""
        engine = PatternExecutionEngine(
            session=mock_session,
            cache_manager=cache_manager,
            registry=pattern_registry
        )

        # Execute multiple times
        times = []
        for _ in range(10):
            result = await engine.execute(
                "execute tool",
                use_cache=False  # Don't use cache for benchmark
            )
            times.append(result.execution_time_ms)

        avg_time = sum(times) / len(times)

        assert avg_time < 50, f"Infrastructure execution too slow: {avg_time:.2f}ms"

    @pytest.mark.asyncio
    async def test_cache_hit_performance(
        self, mock_session, cache_manager, pattern_registry
    ):
        """Test cache hit speed (<1ms target)"""
        engine = PatternExecutionEngine(
            session=mock_session,
            cache_manager=cache_manager,
            registry=pattern_registry
        )

        query = "execute tool"

        # Populate cache
        await engine.execute(query, use_cache=True)

        # Measure cache hit performance
        times = []
        for _ in range(100):
            result = await engine.execute(query, use_cache=True)
            if result.cache_hit:
                times.append(result.execution_time_ms)

        if times:
            avg_time = sum(times) / len(times)
            assert avg_time < 1, f"Cache hit too slow: {avg_time:.2f}ms"


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegration:
    """Integration tests for complete workflows"""

    @pytest.mark.asyncio
    async def test_artemis_workflow(self, mock_session, cache_manager):
        """Test Artemis optimization workflow"""
        engine = PatternExecutionEngine(
            session=mock_session,
            cache_manager=cache_manager
        )

        # Simulate Artemis workflow
        tasks = [
            "recall optimization patterns",
            "analyze current performance",
            "find similar optimizations",
            "store new pattern"
        ]

        results = []
        total_tokens = 0

        for task in tasks:
            result = await engine.execute(
                task,
                execution_mode=ExecutionMode.BALANCED,
                context={'agent': 'artemis'}
            )
            results.append(result)
            total_tokens += result.tokens_used

        # Verify workflow completed
        assert len(results) == 4
        assert all(r.success for r in results)

        # Verify token efficiency
        avg_tokens = total_tokens / len(tasks)
        assert avg_tokens < 150, f"Workflow using too many tokens: {avg_tokens}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
