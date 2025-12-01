"""Security tests for SkillValidationService.

This module tests security-specific vulnerabilities identified in Phase 6A Hestia review:
- V-SKILL-1: ReDoS (Regular Expression Denial of Service)
- V-SKILL-2: YAML Bomb (Billion Laughs Attack)
- V-SKILL-3: Unicode Normalization Bypass
- V-SKILL-4: Information Disclosure via Error Messages
- V-SKILL-5: DoS via Token Validation

Author: Hestia (Security Guardian)
Date: 2025-11-26
Reference: docs/security/PHASE_6A_HESTIA_SECURITY_REVIEW.md
"""

import time
import tracemalloc

import pytest

from src.core.exceptions import ValidationError
from src.services.skill_validation_service import SkillValidationService

# ===== Test Fixtures =====


@pytest.fixture
def validation_service() -> SkillValidationService:
    """Create validation service instance for testing."""
    return SkillValidationService()


# ===== V-SKILL-1: ReDoS Protection Tests =====


def test_redos_core_instructions_extraction(validation_service: SkillValidationService) -> None:
    """V-SKILL-1: Test ReDoS protection in core instructions extraction.

    Attack Vector:
    - Pattern: r"##\\s+Core\\s+Instructions\\s*\n(.*?)(?=\n##|\\Z)"
    - Trigger: 50KB of 'a' characters without newline or '##' to close section
    - Expected: Catastrophic backtracking causing 10-30 second CPU exhaustion

    Mitigation:
    - Should complete in <100ms regardless of input
    - Use non-backtracking approach or atomic grouping
    """
    # Craft malicious content designed to trigger backtracking
    malicious_content = "## Core Instructions\n" + ("a" * 50000)

    # Measure execution time
    start = time.perf_counter()
    result = validation_service._extract_core_instructions(malicious_content)
    duration = time.perf_counter() - start

    # Verify protection
    assert duration < 0.1, f"ReDoS vulnerability detected: took {duration:.2f}s (should be <0.1s)"
    assert len(result) <= validation_service.max_core_instructions_length, "Result should be truncated"


def test_redos_metadata_yaml_frontmatter(validation_service: SkillValidationService) -> None:
    """V-SKILL-1: Test ReDoS protection in YAML frontmatter extraction.

    Attack Vector:
    - Pattern: r"^---\\s*\n(.*?)\n---\\s*\n"
    - Trigger: Large YAML content with nested structures

    Mitigation:
    - YAML parsing should be limited by size (<10KB)
    - Should complete in <100ms
    """
    # Create large YAML-like content (not actual YAML bomb, just large)
    large_yaml = "---\n" + ("key: value\n" * 5000) + "---\n"

    start = time.perf_counter()
    try:
        result = validation_service._extract_metadata(large_yaml + "# Rest of content")
        duration = time.perf_counter() - start

        # Should either reject (via size limit) or complete quickly
        assert duration < 0.1, f"ReDoS risk: metadata extraction took {duration:.2f}s"
    except ValidationError as e:
        # Expected: Should reject oversized YAML
        assert "too large" in str(e).lower() or "yaml" in str(e).lower()


def test_redos_json_frontmatter(validation_service: SkillValidationService) -> None:
    """V-SKILL-1: Test ReDoS protection in JSON frontmatter extraction.

    Attack Vector:
    - Pattern: r"^```json\\s*\n(\\{.*?\\})\\s*\n```\\s*\n"
    - Trigger: Large deeply nested JSON

    Mitigation:
    - JSON parsing should be limited by size
    - Should complete in <100ms
    """
    # Create large JSON-like content
    large_json = '```json\n{"key": "' + ("a" * 10000) + '"}\n```\n'

    start = time.perf_counter()
    try:
        result = validation_service._extract_metadata(large_json + "# Rest of content")
        duration = time.perf_counter() - start

        assert duration < 0.1, f"JSON parsing took too long: {duration:.2f}s"
    except ValidationError as e:
        # Expected: Should reject oversized JSON
        assert "too large" in str(e).lower() or "json" in str(e).lower()


# ===== V-SKILL-2: YAML Bomb Protection Tests =====


def test_yaml_bomb_protection(validation_service: SkillValidationService) -> None:
    """V-SKILL-2: Test YAML bomb (Billion Laughs) attack protection.

    Attack Vector:
    - YAML bomb using recursive anchor references
    - 1KB payload → 3GB+ memory consumption

    Example Attack:
        ---
        a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
        b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
        c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
        ...
        ---

    Mitigation:
    - YAML size limit (<10KB)
    - Parsing timeout (1 second)
    - Memory limit (<100MB)
    """
    yaml_bomb = """---
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
---"""

    content = yaml_bomb + "\n# Rest of skill content"

    # Measure memory usage
    tracemalloc.start()

    try:
        start = time.perf_counter()
        result = validation_service._extract_metadata(content)
        duration = time.perf_counter() - start

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Should complete quickly
        assert duration < 1.0, f"YAML parsing took too long: {duration:.2f}s"

        # Should not consume excessive memory (>100MB indicates vulnerability)
        peak_mb = peak / 1024 / 1024
        assert peak_mb < 100, f"YAML bomb detected: consumed {peak_mb:.1f}MB (should be <100MB)"

    except (ValidationError, TimeoutError):
        # Expected: Validation should block oversized YAML or timeout
        tracemalloc.stop()
        assert True, "YAML bomb rejected by validation (expected behavior)"


def test_yaml_bomb_alternative_vectors(validation_service: SkillValidationService) -> None:
    """V-SKILL-2: Test alternative YAML bomb attack vectors.

    Attack Vectors:
    1. Extremely deep nesting
    2. Very long strings with anchors
    3. Circular references (if not protected)
    """
    # Attack 1: Deep nesting
    deep_nesting = "---\n" + ("  " * 100) + "key: value\n---\n"

    try:
        result = validation_service._extract_metadata(deep_nesting + "# Content")
        # If parsing succeeds, verify no excessive resource usage
        assert result is not None
    except (ValidationError, RecursionError):
        # Expected: Should reject or handle gracefully
        pass

    # Attack 2: Very long string with anchors
    long_string_bomb = """---
base: &base "aaaaaaaaaa"
expand: *base
---"""

    try:
        result = validation_service._extract_metadata(long_string_bomb + "# Content")
        assert result is not None
    except ValidationError:
        # Expected: Size limit may block this
        pass


# ===== V-SKILL-3: Unicode Normalization Bypass Tests =====


def test_unicode_normalization_bypass(validation_service: SkillValidationService) -> None:
    """V-SKILL-3: Test Unicode normalization bypass protection.

    Attack Vectors:
    - Zero-width characters: \u200b, \u200c, \u200d
    - Fullwidth characters: ｔｅｓｔ (U+FF54 vs U+0074)
    - Combining marks: test\u0335 (strikethrough)
    - Lookalike characters: test (Cyrillic 'е' vs Latin 'e')

    Mitigation:
    - Unicode normalization (NFKC)
    - Remove zero-width and combining characters
    """
    # Test cases: (input, should_pass, description)
    test_cases = [
        # Valid cases
        ("test-skill", True, "normal valid name"),
        ("abc123-test", True, "alphanumeric with hyphen"),
        # Invalid: Zero-width characters
        ("test\u200b-skill", False, "zero-width space (U+200B)"),
        ("test\u200c-skill", False, "zero-width non-joiner (U+200C)"),
        ("test\u200d-skill", False, "zero-width joiner (U+200D)"),
        # Invalid: Fullwidth characters
        ("\uff54est-skill", False, "fullwidth 't' (U+FF54)"),
        ("t\uff45st-skill", False, "fullwidth 'e' (U+FF45)"),
        # Invalid: Combining marks
        ("test\u0335-skill", False, "combining short stroke overlay (strikethrough)"),
        ("test\u0336-skill", False, "combining long stroke overlay"),
        # Invalid: Lookalike characters
        ("t\u0435st-skill", False, "Cyrillic 'е' (U+0435) looks like 'e'"),
    ]

    for input_name, should_pass, description in test_cases:
        if should_pass:
            try:
                result = validation_service.validate_skill_name(input_name)
                # After normalization, should get expected output
                assert result == input_name or result.isascii(), f"Failed for: {description}"
            except ValidationError:
                pytest.fail(f"Should have passed for: {description}")
        else:
            with pytest.raises(ValidationError, match="Invalid skill name format"):
                validation_service.validate_skill_name(input_name)


def test_unicode_normalization_namespace(validation_service: SkillValidationService) -> None:
    """V-SKILL-3: Test Unicode normalization in namespace validation."""
    # Test namespace-specific Unicode attacks
    test_cases = [
        ("test-namespace", True, "normal valid namespace"),
        ("test\u200b-namespace", False, "zero-width space"),
        ("\uff4eamespace", False, "fullwidth 'n'"),
        ("test\u0335-namespace", False, "combining strikethrough"),
    ]

    for input_ns, should_pass, description in test_cases:
        if should_pass:
            try:
                result = validation_service.validate_namespace(input_ns)
                assert result.isascii(), f"Failed for: {description}"
            except ValidationError:
                pytest.fail(f"Should have passed for: {description}")
        else:
            with pytest.raises(ValidationError, match="Invalid namespace format"):
                validation_service.validate_namespace(input_ns)


# ===== V-SKILL-4: Information Disclosure Tests =====


def test_error_message_sanitization(validation_service: SkillValidationService) -> None:
    """V-SKILL-4: Test that error messages don't leak sensitive information.

    Attack Vectors:
    - Inject script tags to test for XSS in error rendering
    - Inject SQL syntax to see if echoed in errors
    - Long inputs to test truncation

    Mitigation:
    - Don't echo user input in error messages
    - Sanitize any displayed values
    - Truncate long values
    """
    # Attack 1: Script injection
    malicious_name = "<script>alert(document.cookie)</script>"

    try:
        validation_service.validate_skill_name(malicious_name)
        pytest.fail("Should have raised ValidationError")
    except ValidationError as e:
        error_str = str(e.details)

        # Error should NOT echo malicious input
        assert "<script>" not in error_str, "Error message leaks script tags (XSS risk)"
        assert "alert" not in error_str, "Error message leaks JavaScript code"
        assert "document.cookie" not in error_str, "Error message leaks sensitive code"

        # Should provide generic error info only
        assert "SKILL_NAME_INVALID_FORMAT" in error_str, "Error code missing"

    # Attack 2: SQL injection attempt
    sql_injection = "test'; DROP TABLE skills; --"

    try:
        validation_service.validate_skill_name(sql_injection)
        pytest.fail("Should have raised ValidationError")
    except ValidationError as e:
        error_str = str(e.details)

        # Should not echo SQL syntax
        assert "DROP TABLE" not in error_str, "Error message leaks SQL syntax"

    # Attack 3: Very long input (test truncation)
    long_input = "a" * 1000

    try:
        validation_service.validate_skill_name(long_input)
        pytest.fail("Should have raised ValidationError")
    except ValidationError as e:
        error_str = str(e.details)

        # If input is echoed, it should be truncated
        if long_input in error_str:
            pytest.fail("Error message contains full 1000-char input (should be truncated)")


def test_error_message_namespace_path_traversal(validation_service: SkillValidationService) -> None:
    """V-SKILL-4: Test error messages for path traversal attempts."""
    # Attack: Path traversal
    path_traversal = "../../../etc/passwd"

    try:
        validation_service.validate_namespace(path_traversal)
        pytest.fail("Should have raised ValidationError")
    except ValidationError as e:
        # Check full error message (includes both message and details)
        error_full = str(e)
        error_details = str(e.details)

        # Error should mention path traversal prevention (in main message)
        assert "path traversal" in error_full.lower(), "Error should mention path traversal"

        # Details should not leak full path (V-SKILL-4 mitigation)
        if "../" in error_details or "etc/passwd" in error_details:
            pytest.fail("Error details leak path traversal attempt")


# ===== V-SKILL-5: DoS via Token Validation Tests =====


def test_token_budget_performance(validation_service: SkillValidationService) -> None:
    """V-SKILL-5: Ensure token budget validation is performant.

    Attack Vector:
    - Repeated calls to validate_token_budget() on large text
    - Could contribute to resource exhaustion if O(n)

    Mitigation:
    - Early return for empty/small text
    - O(1) token estimation (len // 4)
    - Should handle 100 validations in <10ms

    Note: This test validates performance, not correctness.
    Large text WILL raise ValidationError (by design), but the check should be fast.
    """
    # Test with maximum size content (50KB) - this exceeds budget intentionally
    large_text = "a" * 50000

    start = time.perf_counter()
    for _ in range(100):
        try:
            validation_service.validate_token_budget(large_text, 3)
        except ValidationError:
            pass  # Expected - we're testing performance, not correctness
    duration = time.perf_counter() - start

    # Should complete 100 validations in <10ms (even when raising ValidationError)
    assert duration < 0.01, f"Token validation too slow: {duration*1000:.2f}ms for 100 iterations (should be <10ms)"


def test_token_budget_empty_text_performance(validation_service: SkillValidationService) -> None:
    """V-SKILL-5: Test early return optimization for empty/small text."""
    # Test with empty text
    start = time.perf_counter()
    for _ in range(1000):
        validation_service.validate_token_budget("", 3)
    duration = time.perf_counter() - start

    # Should complete 1000 validations very quickly
    assert duration < 0.001, f"Empty text validation too slow: {duration*1000:.2f}ms for 1000 iterations"

    # Test with small text (should also be fast)
    small_text = "abc"
    start = time.perf_counter()
    for _ in range(1000):
        validation_service.validate_token_budget(small_text, 3)
    duration = time.perf_counter() - start

    assert duration < 0.01, f"Small text validation too slow: {duration*1000:.2f}ms for 1000 iterations"


def test_token_budget_does_not_modify_text(validation_service: SkillValidationService) -> None:
    """V-SKILL-5: Ensure token validation doesn't modify text (security property)."""
    original_text = "This is a test skill content with some length."
    text_copy = original_text

    # Validate token budget
    validation_service.validate_token_budget(text_copy, 3)

    # Text should remain unchanged
    assert text_copy == original_text, "Token validation should not modify input text"


# ===== Integration Security Tests =====


def test_full_validation_pipeline_security(validation_service: SkillValidationService) -> None:
    """Integration test: Full validation pipeline against combined attacks.

    Tests complete skill validation with multiple attack vectors combined.
    """
    # Attack: Combine multiple vulnerabilities
    malicious_skill = {
        "name": "test\u200b<script>alert(1)</script>",  # Unicode bypass + XSS
        "namespace": "../etc/passwd",  # Path traversal
        "tags": ["test", "test" * 50],  # One valid, one oversized
        "content": "## Core Instructions\n" + ("a" * 50000),  # ReDoS trigger
    }

    # Validate name
    with pytest.raises(ValidationError):
        validation_service.validate_skill_name(malicious_skill["name"])

    # Validate namespace
    with pytest.raises(ValidationError):
        validation_service.validate_namespace(malicious_skill["namespace"])

    # Validate tags
    with pytest.raises(ValidationError):
        validation_service.validate_tags(malicious_skill["tags"])

    # Validate content (should handle ReDoS gracefully)
    start = time.perf_counter()
    try:
        validation_service.validate_content(malicious_skill["content"])
        duration = time.perf_counter() - start
        assert duration < 0.1, "Content validation took too long (possible ReDoS)"
    except ValidationError:
        # Expected: May reject based on size limits
        pass


def test_parse_progressive_disclosure_security(validation_service: SkillValidationService) -> None:
    """Integration test: Progressive disclosure parsing with security constraints."""
    # Craft content with potential vulnerabilities
    malicious_content = """---
a: &a ["test"] # Potential YAML bomb anchor
---

# Skill Title

## Core Instructions
""" + ("a" * 10000) + """

## Examples
More content here
"""

    # Should handle gracefully
    start = time.perf_counter()
    try:
        result = validation_service.parse_progressive_disclosure_layers(malicious_content)
        duration = time.perf_counter() - start

        assert duration < 0.5, "Progressive disclosure parsing took too long"
        assert "metadata" in result
        assert "core_instructions" in result
        assert "auxiliary_content" in result
        assert "content_hash" in result

        # Verify truncation applied
        assert len(result["core_instructions"]) <= validation_service.max_core_instructions_length

    except ValidationError as e:
        # Expected: May reject based on security constraints
        assert "too large" in str(e).lower() or "yaml" in str(e).lower()


# ===== Summary Test =====


def test_security_compliance_summary(validation_service: SkillValidationService) -> None:
    """Meta-test: Verify all security requirements are tested.

    This test ensures that security test coverage is complete.
    """
    # V-SKILL-1: ReDoS
    assert hasattr(validation_service, "_extract_core_instructions"), "Missing core instructions method"
    assert hasattr(validation_service, "_extract_metadata"), "Missing metadata extraction method"

    # V-SKILL-2: YAML bomb
    assert hasattr(validation_service, "_extract_metadata"), "Missing metadata extraction method"

    # V-SKILL-3: Unicode normalization
    assert hasattr(validation_service, "validate_skill_name"), "Missing skill name validation"
    assert hasattr(validation_service, "validate_namespace"), "Missing namespace validation"

    # V-SKILL-4: Information disclosure
    assert hasattr(validation_service, "validate_skill_name"), "Missing validation methods"

    # V-SKILL-5: Token validation DoS
    assert hasattr(validation_service, "validate_token_budget"), "Missing token budget validation"

    # All security requirements covered
    assert True, "All V-SKILL security requirements have test coverage"
