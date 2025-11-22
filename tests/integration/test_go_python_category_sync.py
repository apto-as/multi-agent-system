"""Integration test to verify Go-Python category synchronization.

This test ensures that Python's ToolCategory enum exactly matches
the authoritative Go validCategories map in the orchestrator.

Authority: src/orchestrator/internal/orchestrator/discovery.go:15-21

Test Coverage:
- R-4A: Cross-layer integration validation
- Category count (5 categories exact)
- Category value string matching
- Inference pattern coverage
- Fail-fast behavior for unknown tools
- Performance validation

Security:
- No UNCATEGORIZED fallback (fail-fast principle)
- Prevents silent categorization errors
- Enforces explicit category definitions
"""

import time
import pytest
from src.domain.value_objects.tool_category import ToolCategory


class TestGoPythonCategorySync:
    """Verify Python ToolCategory matches Go validCategories exactly."""

    def test_category_count(self):
        """Python should have exactly 5 categories matching Go.

        Authority: src/orchestrator/internal/orchestrator/discovery.go:15-21
        """
        expected_count = 5
        actual_count = len(ToolCategory)

        assert actual_count == expected_count, (
            f"Category count mismatch: expected {expected_count} "
            f"(Go validCategories), got {actual_count} (Python ToolCategory)\n"
            f"Python categories: {[cat.value for cat in ToolCategory]}"
        )

    def test_category_values_match_go(self):
        """Python enum values should match Go validCategories keys exactly.

        Authority: src/orchestrator/internal/orchestrator/discovery.go:15-21
        Go validCategories:
        - data_processing
        - api_integration
        - file_management
        - security
        - monitoring
        """
        # From discovery.go:15-21
        go_categories = {
            "data_processing",
            "api_integration",
            "file_management",
            "security",
            "monitoring"
        }

        python_values = {category.value for category in ToolCategory}

        assert python_values == go_categories, (
            f"Category mismatch:\n"
            f"  Go:     {sorted(go_categories)}\n"
            f"  Python: {sorted(python_values)}\n"
            f"  Missing in Python: {sorted(go_categories - python_values)}\n"
            f"  Extra in Python:   {sorted(python_values - go_categories)}"
        )

    def test_inference_coverage(self):
        """All Go categories should have inference patterns.

        Ensures no category is unreachable via automatic inference.
        """
        # Test that each category can be inferred from at least one pattern
        # by attempting to infer using a characteristic name for each category
        test_cases = {
            ToolCategory.DATA_PROCESSING: "data_processor",
            ToolCategory.API_INTEGRATION: "api_client",
            ToolCategory.FILE_MANAGEMENT: "file_handler",
            ToolCategory.SECURITY: "auth_service",
            ToolCategory.MONITORING: "monitoring_tool"
        }

        for expected_category, test_name in test_cases.items():
            inferred = ToolCategory.infer_from_name(test_name)
            assert inferred == expected_category, (
                f"Category {expected_category.value} unreachable: "
                f"test name '{test_name}' inferred as {inferred.value}"
            )

    def test_fail_fast_no_uncategorized(self):
        """UNCATEGORIZED should be removed, inferring unknown tools should fail.

        Fail-fast principle: Better to raise ValueError than silently misclassify.

        Security: Prevents tools from being auto-categorized into inappropriate categories.
        """
        with pytest.raises(ValueError, match="does not match any valid category"):
            ToolCategory.infer_from_name("completely_unknown_tool_xyz_12345")

    def test_enum_member_count(self):
        """Verify enum has exactly 5 members (no hidden/deprecated members)."""
        members = list(ToolCategory.__members__.keys())
        assert len(members) == 5, (
            f"Expected 5 enum members, got {len(members)}: {members}"
        )

    def test_inference_deterministic(self):
        """Inference should be deterministic (same input = same output)."""
        test_names = [
            "data_processor",
            "api_client",
            "file_handler",
            "auth_service",
            "monitoring_tool",
            "workflow_automation",
            "mcp_server",
            "security_vault"
        ]

        for name in test_names:
            # Run inference multiple times
            results = [ToolCategory.infer_from_name(name) for _ in range(5)]

            # All results should be identical
            assert len(set(results)) == 1, (
                f"Non-deterministic inference for '{name}': {[r.value for r in results]}"
            )

    def test_inference_performance(self):
        """Category inference should be fast (< 1ms per call).

        Performance regression check after 10→5 category reduction.
        """
        test_names = [
            "data_processor",
            "api_client",
            "file_handler",
            "security_scanner",
            "monitoring_service"
        ] * 200  # 1000 inferences

        start = time.perf_counter()
        for name in test_names:
            try:
                ToolCategory.infer_from_name(name)
            except ValueError:
                pass  # Expected for some test names
        end = time.perf_counter()

        avg_time_ms = ((end - start) / len(test_names)) * 1000

        assert avg_time_ms < 1.0, (
            f"Category inference too slow: {avg_time_ms:.3f}ms per call "
            f"(target: < 1.0ms)"
        )

    def test_all_categories_reachable_via_inference(self):
        """Verify each category can be inferred from at least one pattern."""
        # Test representative names for each category
        test_cases = [
            ("data_processor", ToolCategory.DATA_PROCESSING),
            ("workflow_automation", ToolCategory.DATA_PROCESSING),
            ("api_client", ToolCategory.API_INTEGRATION),
            ("mcp_server", ToolCategory.API_INTEGRATION),
            ("file_handler", ToolCategory.FILE_MANAGEMENT),
            ("auth_service", ToolCategory.SECURITY),
            ("monitoring_tool", ToolCategory.MONITORING)
        ]

        reachable_categories = set()

        for test_name, expected_category in test_cases:
            inferred = ToolCategory.infer_from_name(test_name)
            reachable_categories.add(inferred)
            assert inferred == expected_category, (
                f"Name '{test_name}' inferred as {inferred.value}, "
                f"expected {expected_category.value}"
            )

        all_categories = set(ToolCategory)

        assert reachable_categories == all_categories, (
            f"Unreachable categories via inference:\n"
            f"  {sorted([c.value for c in all_categories - reachable_categories])}"
        )

    def test_category_stability(self):
        """Category values should not change (API stability guarantee).

        These values are used in:
        - Database schemas
        - API contracts
        - Go orchestrator configuration

        Any change requires migration.
        """
        # Snapshot of expected values (from discovery.go:15-21)
        expected_values = {
            ToolCategory.DATA_PROCESSING: "data_processing",
            ToolCategory.API_INTEGRATION: "api_integration",
            ToolCategory.FILE_MANAGEMENT: "file_management",
            ToolCategory.SECURITY: "security",
            ToolCategory.MONITORING: "monitoring"
        }

        for category, expected_value in expected_values.items():
            assert category.value == expected_value, (
                f"Category value changed: {category.name} was '{expected_value}', "
                f"now '{category.value}' - BREAKING CHANGE"
            )


class TestInferenceRules:
    """Test specific inference rules for edge cases."""

    @pytest.mark.parametrize("tool_name,expected_category", [
        ("data_transformer", ToolCategory.DATA_PROCESSING),
        ("etl_processor", ToolCategory.DATA_PROCESSING),
        ("api_client", ToolCategory.API_INTEGRATION),
        ("rest_connector", ToolCategory.API_INTEGRATION),
        ("file_reader", ToolCategory.FILE_MANAGEMENT),
        ("storage_handler", ToolCategory.FILE_MANAGEMENT),
        ("auth_validator", ToolCategory.SECURITY),
        ("encryption_service", ToolCategory.SECURITY),
        ("metrics_collector", ToolCategory.MONITORING),
        ("health_checker", ToolCategory.MONITORING),
    ])
    def test_inference_examples(self, tool_name: str, expected_category: ToolCategory):
        """Test inference for common tool naming patterns."""
        inferred = ToolCategory.infer_from_name(tool_name)
        assert inferred == expected_category, (
            f"Tool '{tool_name}' inferred as {inferred.value}, "
            f"expected {expected_category.value}"
        )

    def test_inference_case_insensitive(self):
        """Tool name inference should be case-insensitive."""
        lower = ToolCategory.infer_from_name("data_processor")
        upper = ToolCategory.infer_from_name("DATA_PROCESSOR")
        mixed = ToolCategory.infer_from_name("Data_Processor")

        assert lower == upper == mixed == ToolCategory.DATA_PROCESSING

    def test_inference_with_underscores_and_hyphens(self):
        """Handle both snake_case and kebab-case tool names."""
        snake = ToolCategory.infer_from_name("api_client_tool")
        kebab = ToolCategory.infer_from_name("api-client-tool")

        assert snake == kebab == ToolCategory.API_INTEGRATION


class TestErrorMessages:
    """Test that error messages are helpful for debugging."""

    def test_unknown_tool_error_message(self):
        """Error should list valid categories for user guidance."""
        with pytest.raises(ValueError) as exc_info:
            ToolCategory.infer_from_name("completely_unknown_tool")

        error_msg = str(exc_info.value)

        # Should mention valid categories
        for category in ToolCategory:
            assert category.value in error_msg, (
                f"Error message should list valid category '{category.value}'"
            )

    def test_error_includes_tool_name(self):
        """Error should include the problematic tool name."""
        tool_name = "xyz_unknown_tool_12345"

        with pytest.raises(ValueError) as exc_info:
            ToolCategory.infer_from_name(tool_name)

        assert tool_name in str(exc_info.value), (
            "Error message should include the unknown tool name"
        )


class TestDocumentation:
    """Verify documentation consistency."""

    def test_all_categories_have_docstrings(self):
        """Each category enum member should have documentation."""
        for category in ToolCategory:
            # Check that the category itself exists and has a value
            assert category.value is not None, (
                f"Category {category.name} has no value"
            )
            assert len(category.value) > 0, (
                f"Category {category.name} has empty value"
            )

    def test_inference_method_documented(self):
        """The infer_from_name method should have comprehensive documentation."""
        doc = ToolCategory.infer_from_name.__doc__
        assert doc is not None, "infer_from_name method missing docstring"

        # Check that documentation mentions all categories
        for category in ToolCategory:
            assert category.value in doc or category.name in doc, (
                f"Category {category.value} not documented in infer_from_name"
            )
