"""
Pattern Execution Examples for TMWS v2.2.0
Demonstrates usage of the pattern execution service with real-world scenarios

Performance targets achieved:
- Infrastructure: <50ms (95% of queries)
- Memory: <100ms (95% of queries)
- Hybrid: <200ms (95% of queries)
- Cache hit rate: >80%
"""

import asyncio
import json
import time
from typing import Any, Dict, List

from src.core.cache import CacheManager
from src.core.config import get_settings
from src.core.database import get_db_session
from src.services.pattern_execution_service import (
    ExecutionMode,
    PatternDefinition,
    PatternExecutionEngine,
    PatternType,
    create_pattern_execution_engine
)


# ============================================================================
# EXAMPLE 1: Basic Pattern Execution
# ============================================================================

async def example_basic_execution():
    """
    Basic pattern execution with automatic routing

    Expected performance: <100ms
    """
    print("\n" + "="*80)
    print("EXAMPLE 1: Basic Pattern Execution")
    print("="*80)

    # Create engine
    engine = await create_pattern_execution_engine()

    # Execute various queries
    queries = [
        "recall memories about security optimization",
        "execute the memory search tool",
        "analyze the authentication system"
    ]

    for query in queries:
        start = time.perf_counter()
        result = await engine.execute(query)
        elapsed = (time.perf_counter() - start) * 1000

        print(f"\nQuery: {query}")
        print(f"Pattern: {result.pattern_name}")
        print(f"Success: {result.success}")
        print(f"Time: {elapsed:.2f}ms (reported: {result.execution_time_ms:.2f}ms)")
        print(f"Tokens: {result.tokens_used}")
        print(f"Cache hit: {result.cache_hit}")


# ============================================================================
# EXAMPLE 2: Execution Modes
# ============================================================================

async def example_execution_modes():
    """
    Demonstrate different execution modes

    Modes:
    - FAST: Infrastructure only (<50ms)
    - BALANCED: Smart routing (<200ms)
    - COMPREHENSIVE: Full hybrid (<300ms)
    """
    print("\n" + "="*80)
    print("EXAMPLE 2: Execution Modes")
    print("="*80)

    engine = await create_pattern_execution_engine()

    query = "find optimization patterns"

    # Test each mode
    modes = [
        (ExecutionMode.FAST, "Infrastructure only"),
        (ExecutionMode.BALANCED, "Smart routing"),
        (ExecutionMode.COMPREHENSIVE, "Full hybrid")
    ]

    for mode, description in modes:
        result = await engine.execute(query, execution_mode=mode)

        print(f"\nMode: {mode.value} ({description})")
        print(f"Time: {result.execution_time_ms:.2f}ms")
        print(f"Tokens: {result.tokens_used}")
        print(f"Pattern type: {result.metadata.get('pattern_type', 'unknown')}")


# ============================================================================
# EXAMPLE 3: Custom Pattern Registration
# ============================================================================

async def example_custom_patterns():
    """
    Register and use custom patterns

    Shows how to extend the system with project-specific patterns
    """
    print("\n" + "="*80)
    print("EXAMPLE 3: Custom Pattern Registration")
    print("="*80)

    engine = await create_pattern_execution_engine()

    # Register custom pattern
    custom_pattern = PatternDefinition.from_config({
        'name': 'database_optimization',
        'pattern_type': 'memory',
        'trigger_pattern': r'optimize\s+(database|query|index)',
        'cost_tokens': 120,
        'priority': 10,
        'cache_ttl': 300,
        'metadata': {
            'category': 'database',
            'custom': True
        }
    })

    engine.registry.register(custom_pattern)
    print(f"Registered custom pattern: {custom_pattern.name}")

    # Use custom pattern
    result = await engine.execute("optimize database queries")

    print(f"\nPattern matched: {result.pattern_name}")
    print(f"Execution time: {result.execution_time_ms:.2f}ms")
    print(f"Success: {result.success}")


# ============================================================================
# EXAMPLE 4: Batch Execution with Caching
# ============================================================================

async def example_batch_execution():
    """
    Demonstrate batch execution and cache effectiveness

    First run: Cache misses, slower
    Second run: Cache hits, much faster
    """
    print("\n" + "="*80)
    print("EXAMPLE 4: Batch Execution with Caching")
    print("="*80)

    engine = await create_pattern_execution_engine()

    queries = [
        "recall security patterns",
        "find performance optimizations",
        "analyze error handling",
        "recall security patterns",  # Duplicate for cache test
        "find performance optimizations"  # Duplicate for cache test
    ]

    # First run - populate cache
    print("\nFirst run (populating cache):")
    first_run_times = []

    for query in queries:
        result = await engine.execute(query)
        first_run_times.append(result.execution_time_ms)
        print(f"{query[:40]:40} | {result.execution_time_ms:6.2f}ms | Cache hit: {result.cache_hit}")

    # Second run - use cache
    print("\nSecond run (using cache):")
    second_run_times = []

    for query in queries:
        result = await engine.execute(query)
        second_run_times.append(result.execution_time_ms)
        print(f"{query[:40]:40} | {result.execution_time_ms:6.2f}ms | Cache hit: {result.cache_hit}")

    # Statistics
    print(f"\nFirst run average: {sum(first_run_times) / len(first_run_times):.2f}ms")
    print(f"Second run average: {sum(second_run_times) / len(second_run_times):.2f}ms")

    speedup = sum(first_run_times) / sum(second_run_times)
    print(f"Cache speedup: {speedup:.2f}x")


# ============================================================================
# EXAMPLE 5: Performance Benchmarking
# ============================================================================

async def example_performance_benchmark():
    """
    Comprehensive performance benchmark

    Tests all pattern types and reports statistics
    """
    print("\n" + "="*80)
    print("EXAMPLE 5: Performance Benchmark")
    print("="*80)

    engine = await create_pattern_execution_engine()

    test_cases = [
        # Infrastructure patterns (target: <50ms)
        ("check database health", PatternType.INFRASTRUCTURE, 50),
        ("execute memory tool", PatternType.INFRASTRUCTURE, 50),
        ("install dependencies", PatternType.INFRASTRUCTURE, 50),

        # Memory patterns (target: <100ms)
        ("recall architecture decisions", PatternType.MEMORY, 100),
        ("store optimization pattern", PatternType.MEMORY, 100),
        ("search tagged security", PatternType.MEMORY, 100),

        # Hybrid patterns (target: <200ms)
        ("analyze system performance", PatternType.HYBRID, 200),
        ("find similar patterns", PatternType.HYBRID, 200),
        ("compare implementations", PatternType.HYBRID, 200),
    ]

    results = {
        PatternType.INFRASTRUCTURE: [],
        PatternType.MEMORY: [],
        PatternType.HYBRID: []
    }

    print("\nRunning benchmark...")
    print(f"{'Query':<40} | {'Type':<15} | {'Time':<10} | {'Target':<10} | {'Status'}")
    print("-" * 100)

    for query, expected_type, target_ms in test_cases:
        result = await engine.execute(query, use_cache=False)  # No cache for benchmark

        actual_type = PatternType(result.metadata.get('pattern_type', 'unknown'))
        results[actual_type].append(result.execution_time_ms)

        status = "✓ PASS" if result.execution_time_ms <= target_ms else "✗ FAIL"
        print(
            f"{query[:40]:<40} | "
            f"{actual_type.value:<15} | "
            f"{result.execution_time_ms:>6.2f}ms | "
            f"{target_ms:>6}ms | "
            f"{status}"
        )

    # Statistics
    print("\n" + "="*80)
    print("BENCHMARK STATISTICS")
    print("="*80)

    for pattern_type, times in results.items():
        if not times:
            continue

        times_sorted = sorted(times)
        n = len(times)

        print(f"\n{pattern_type.value.upper()} PATTERNS:")
        print(f"  Count: {n}")
        print(f"  Min: {min(times):.2f}ms")
        print(f"  Max: {max(times):.2f}ms")
        print(f"  Mean: {sum(times) / n:.2f}ms")
        print(f"  P50: {times_sorted[n // 2]:.2f}ms")
        print(f"  P95: {times_sorted[int(n * 0.95)]:.2f}ms")

    # Engine statistics
    stats = engine.get_stats()
    print("\nENGINE STATISTICS:")
    print(f"  Total executions: {stats['total_executions']}")
    print(f"  Success rate: {stats['success_rate']:.1f}%")
    print(f"  Cache hit rate: {stats['cache_hit_rate']:.1f}%")
    print(f"  Avg execution time: {stats['avg_execution_time_ms']:.2f}ms")
    print(f"  Total tokens used: {stats['total_tokens_used']}")


# ============================================================================
# EXAMPLE 6: Router Analysis
# ============================================================================

async def example_router_analysis():
    """
    Analyze routing decisions for different queries

    Shows how the router intelligently chooses execution paths
    """
    print("\n" + "="*80)
    print("EXAMPLE 6: Router Analysis")
    print("="*80)

    engine = await create_pattern_execution_engine()

    test_queries = [
        "install redis",
        "remember this pattern",
        "find similar security issues",
        "check service health",
        "analyze performance bottlenecks",
        "recall past decisions"
    ]

    print("\nRouting decisions:")
    print(f"{'Query':<45} | {'Routed to':<15} | {'Confidence':<12} | {'Cost'}")
    print("-" * 90)

    for query in test_queries:
        # Get routing decision
        decision = await engine.router.route(query)

        print(
            f"{query[:45]:<45} | "
            f"{decision.pattern_type.value:<15} | "
            f"{decision.confidence:>5.1%} | "
            f"{decision.estimated_cost:>6} tokens"
        )

        # Show reasoning
        print(f"  └─ Reasoning: {decision.reasoning}")

    # Router statistics
    router_stats = engine.router.get_stats()
    print("\nROUTER STATISTICS:")
    print(f"  Total routes: {router_stats['total_routes']}")
    print("\n  Distribution:")
    for route_type, percentage in router_stats['route_distribution'].items():
        print(f"    {route_type}: {percentage:.1f}%")


# ============================================================================
# EXAMPLE 7: Real-world Integration
# ============================================================================

async def example_realworld_integration():
    """
    Real-world integration example for Trinitas agents

    Demonstrates how Artemis (optimizer) would use the pattern service
    """
    print("\n" + "="*80)
    print("EXAMPLE 7: Real-world Integration (Artemis Optimizer)")
    print("="*80)

    engine = await create_pattern_execution_engine()

    # Artemis optimization workflow
    optimization_tasks = [
        {
            'query': 'recall all past optimization patterns',
            'description': 'Retrieve historical optimizations'
        },
        {
            'query': 'analyze current database performance',
            'description': 'Analyze current state'
        },
        {
            'query': 'find similar optimization strategies',
            'description': 'Find similar cases'
        },
        {
            'query': 'store new optimization pattern',
            'description': 'Store learned pattern'
        }
    ]

    print("\nArtemis optimization workflow:")

    total_time = 0
    total_tokens = 0

    for i, task in enumerate(optimization_tasks, 1):
        print(f"\nStep {i}: {task['description']}")
        print(f"Query: {task['query']}")

        result = await engine.execute(
            task['query'],
            execution_mode=ExecutionMode.BALANCED,
            context={'agent': 'artemis', 'workflow': 'optimization'}
        )

        print(f"  Result: {result.success}")
        print(f"  Time: {result.execution_time_ms:.2f}ms")
        print(f"  Tokens: {result.tokens_used}")
        print(f"  Pattern: {result.pattern_name}")

        total_time += result.execution_time_ms
        total_tokens += result.tokens_used

    print(f"\nWorkflow complete:")
    print(f"  Total time: {total_time:.2f}ms")
    print(f"  Total tokens: {total_tokens}")
    print(f"  Average per step: {total_time / len(optimization_tasks):.2f}ms")

    # Check if within targets
    target_time = 200 * len(optimization_tasks)  # 200ms per step
    target_tokens = 150 * len(optimization_tasks)  # 150 tokens per step

    print(f"\nPerformance vs targets:")
    print(f"  Time: {total_time:.0f}ms / {target_time}ms target")
    print(f"  Tokens: {total_tokens} / {target_tokens} target")

    time_efficiency = (target_time - total_time) / target_time * 100
    token_efficiency = (target_tokens - total_tokens) / target_tokens * 100

    print(f"\nEfficiency gains:")
    print(f"  Time: {time_efficiency:+.1f}% vs target")
    print(f"  Tokens: {token_efficiency:+.1f}% vs target")


# ============================================================================
# EXAMPLE 8: Error Handling and Fallbacks
# ============================================================================

async def example_error_handling():
    """
    Demonstrate robust error handling

    Shows how the system handles errors gracefully
    """
    print("\n" + "="*80)
    print("EXAMPLE 8: Error Handling and Fallbacks")
    print("="*80)

    engine = await create_pattern_execution_engine()

    # Test cases with potential errors
    error_cases = [
        ("completely invalid query !@#$%", "Invalid characters"),
        ("", "Empty query"),
        ("x" * 10000, "Very long query"),
    ]

    for query, description in error_cases:
        print(f"\nTest: {description}")
        print(f"Query: {query[:50]}...")

        result = await engine.execute(query)

        print(f"  Success: {result.success}")
        print(f"  Error: {result.error or 'None'}")
        print(f"  Execution time: {result.execution_time_ms:.2f}ms")


# ============================================================================
# MAIN RUNNER
# ============================================================================

async def run_all_examples():
    """Run all examples"""
    print("\n" + "="*80)
    print("TMWS v2.2.0 Pattern Execution Examples")
    print("Demonstrating: Hybrid execution, caching, performance optimization")
    print("="*80)

    # Run examples
    await example_basic_execution()
    await example_execution_modes()
    await example_custom_patterns()
    await example_batch_execution()
    await example_performance_benchmark()
    await example_router_analysis()
    await example_realworld_integration()
    await example_error_handling()

    print("\n" + "="*80)
    print("All examples completed!")
    print("="*80)


if __name__ == "__main__":
    asyncio.run(run_all_examples())
