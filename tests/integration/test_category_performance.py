"""Performance validation for category inference.

This test validates that the 10→5 category reduction achieved
the expected performance improvement.

Benchmark Targets:
- Category inference: < 1ms per call (P95)
- No regression from 10-category baseline
"""

import time

import pytest

from src.domain.value_objects.tool_category import ToolCategory


class TestCategoryInferencePerformance:
    """Performance benchmarks for category inference."""

    def test_single_inference_performance(self):
        """Single category inference should be fast."""
        test_names = [
            "data_processor",
            "api_client",
            "file_handler",
            "auth_service",
            "monitoring_tool",
        ]

        timings = []
        for _ in range(100):
            for name in test_names:
                start = time.perf_counter()
                ToolCategory.infer_from_name(name)
                end = time.perf_counter()
                timings.append((end - start) * 1000)  # Convert to ms

        avg_time = sum(timings) / len(timings)
        p95_time = sorted(timings)[int(len(timings) * 0.95)]
        p99_time = sorted(timings)[int(len(timings) * 0.99)]

        print("\nPerformance Results:")
        print(f"  Average: {avg_time:.3f}ms")
        print(f"  P95: {p95_time:.3f}ms")
        print(f"  P99: {p99_time:.3f}ms")

        assert avg_time < 0.5, f"Average too slow: {avg_time:.3f}ms (target: <0.5ms)"
        assert p95_time < 1.0, f"P95 too slow: {p95_time:.3f}ms (target: <1.0ms)"

    def test_batch_inference_throughput(self):
        """Test throughput for batch inference operations."""
        test_names = [
            "data_transformer",
            "api_integration_service",
            "file_storage_manager",
            "security_validator",
            "monitoring_agent",
        ] * 200  # 1000 total inferences

        start = time.perf_counter()
        for name in test_names:
            try:
                ToolCategory.infer_from_name(name)
            except ValueError:
                pass  # Expected for some edge cases
        end = time.perf_counter()

        total_time = (end - start) * 1000  # Convert to ms
        throughput = len(test_names) / (total_time / 1000)  # ops/sec

        print("\nBatch Performance:")
        print(f"  Total time: {total_time:.2f}ms")
        print(f"  Throughput: {throughput:.0f} ops/sec")

        assert throughput > 1000, (
            f"Throughput too low: {throughput:.0f} ops/sec (target: >1000 ops/sec)"
        )

    def test_worst_case_performance(self):
        """Test performance for tools that fail to match any category."""
        unknown_tools = [
            "completely_unknown_xyz_12345",
            "nonexistent_tool_abcdef",
            "random_string_999999",
        ]

        timings = []
        for _ in range(100):
            for name in unknown_tools:
                start = time.perf_counter()
                try:
                    ToolCategory.infer_from_name(name)
                except ValueError:
                    pass  # Expected failure
                end = time.perf_counter()
                timings.append((end - start) * 1000)  # Convert to ms

        avg_time = sum(timings) / len(timings)
        p95_time = sorted(timings)[int(len(timings) * 0.95)]

        print("\nWorst-Case Performance:")
        print(f"  Average: {avg_time:.3f}ms")
        print(f"  P95: {p95_time:.3f}ms")

        # Worst-case should still be fast (even when failing)
        assert p95_time < 1.0, f"Worst-case too slow: {p95_time:.3f}ms (target: <1.0ms)"

    @pytest.mark.benchmark
    def test_regression_vs_10_category_baseline(self):
        """Verify no performance regression from 10-category version.

        Baseline (10 categories): ~0.5ms avg, ~1.0ms P95
        Target (5 categories): ≤0.5ms avg, ≤1.0ms P95
        """
        test_names = [
            "data_processing_tool",
            "api_integration_client",
            "file_management_handler",
            "security_authentication_service",
            "monitoring_metrics_collector",
        ] * 100  # 500 inferences

        timings = []
        for name in test_names:
            start = time.perf_counter()
            ToolCategory.infer_from_name(name)
            end = time.perf_counter()
            timings.append((end - start) * 1000)

        avg_time = sum(timings) / len(timings)
        p95_time = sorted(timings)[int(len(timings) * 0.95)]

        print("\nRegression Test Results:")
        print(f"  5-category avg: {avg_time:.3f}ms")
        print(f"  5-category P95: {p95_time:.3f}ms")
        print("  Baseline (10-cat) avg: ~0.5ms")
        print("  Baseline (10-cat) P95: ~1.0ms")

        # Should be same or better than 10-category baseline
        assert avg_time <= 0.5, (
            f"Performance regression detected: {avg_time:.3f}ms > 0.5ms baseline"
        )
        assert p95_time <= 1.0, f"P95 regression detected: {p95_time:.3f}ms > 1.0ms baseline"


if __name__ == "__main__":
    # Run performance tests with verbose output
    pytest.main([__file__, "-v", "-s"])
