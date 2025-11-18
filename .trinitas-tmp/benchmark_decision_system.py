#!/usr/bin/env python3
"""
Performance Benchmark for Decision System
==========================================

Measures latency and throughput under various scenarios.
"""

import asyncio
import time
from pathlib import Path
import sys

# Add hooks/core to path
sys.path.insert(0, str(Path('.claude/hooks/core')))

from decision_check import DecisionCheckHook


async def benchmark():
    hook = DecisionCheckHook()

    # Warm-up
    print("Warming up...")
    for _ in range(5):
        await hook.process_hook({'prompt': {'text': 'warmup'}})

    print("Running benchmarks...\n")

    # Benchmark: Level 1 prompts (no intervention)
    level1_prompt = {'prompt': {'text': 'fix bug in code'}}
    level1_times = []

    for _ in range(100):
        start = time.perf_counter()
        await hook.process_hook(level1_prompt)
        duration = (time.perf_counter() - start) * 1000  # ms
        level1_times.append(duration)

    # Benchmark: Level 2 prompts (approval needed)
    level2_prompt = {'prompt': {'text': 'implement new feature'}}
    level2_times = []

    for _ in range(100):
        start = time.perf_counter()
        await hook.process_hook(level2_prompt)
        duration = (time.perf_counter() - start) * 1000  # ms
        level2_times.append(duration)

    # Statistics
    def stats(times):
        times_sorted = sorted(times)
        return {
            'min': min(times),
            'max': max(times),
            'avg': sum(times) / len(times),
            'p50': times_sorted[len(times_sorted) // 2],
            'p95': times_sorted[int(len(times_sorted) * 0.95)],
            'p99': times_sorted[int(len(times_sorted) * 0.99)]
        }

    l1_stats = stats(level1_times)
    l2_stats = stats(level2_times)

    print('=== Performance Benchmark Results ===\n')
    print('Samples: 100 iterations per scenario\n')

    print('**Level 1 Latency (autonomous, no intervention)**:')
    print(f'- Average: {l1_stats["avg"]:.2f}ms')
    print(f'- Min: {l1_stats["min"]:.2f}ms')
    print(f'- Max: {l1_stats["max"]:.2f}ms')
    print(f'- P50 (median): {l1_stats["p50"]:.2f}ms')
    print(f'- P95: {l1_stats["p95"]:.2f}ms')
    print(f'- P99: {l1_stats["p99"]:.2f}ms')
    status = "✅ PASS" if l1_stats["avg"] < 50 else "❌ FAIL"
    print(f'- Target: <50ms | Status: {status}\n')

    print('**Level 2 Latency (approval request generation)**:')
    print(f'- Average: {l2_stats["avg"]:.2f}ms')
    print(f'- Min: {l2_stats["min"]:.2f}ms')
    print(f'- Max: {l2_stats["max"]:.2f}ms')
    print(f'- P50 (median): {l2_stats["p50"]:.2f}ms')
    print(f'- P95: {l2_stats["p95"]:.2f}ms')
    print(f'- P99: {l2_stats["p99"]:.2f}ms')
    status = "✅ PASS" if l2_stats["avg"] < 50 else "❌ FAIL"
    print(f'- Target: <50ms | Status: {status}\n')

    # Throughput test
    print('**Throughput Test (10 seconds)**:')
    start_time = time.perf_counter()
    count = 0

    while (time.perf_counter() - start_time) < 10:
        await hook.process_hook(level1_prompt)
        count += 1

    duration = time.perf_counter() - start_time
    throughput = count / duration

    print(f'- Total requests: {count}')
    print(f'- Duration: {duration:.2f}s')
    print(f'- Throughput: {throughput:.2f} requests/second')
    status = "✅ PASS" if throughput > 20 else "❌ FAIL"
    print(f'- Target: >20 req/s | Status: {status}\n')


if __name__ == "__main__":
    asyncio.run(benchmark())
