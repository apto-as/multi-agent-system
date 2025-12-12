"""Unit tests for skill content validation (Issue #70).

This module tests security validation in DynamicToolRegistry._validate_skill_content()
to prevent injection attacks via malicious skill content.

Security Requirements:
- Detect and block XSS via markdown image javascript: protocol
- Detect and block script tag injection
- Detect and block event handler injection
- Detect and block variable/template injection
- Detect and block code execution attempts
- Detect and block command execution attempts
- Detect and block file access attempts
- Log security events on detection
- Provide clear error messages without exposing attack payload

Author: Hestia (Security Guardian)
Date: 2025-12-12
Reference: Issue #70
"""

import logging
import re

import pytest

from src.core.exceptions import ValidationError
from src.services.skill_service.skill_activation import (
    COMPILED_DANGEROUS_PATTERNS,
    DANGEROUS_PATTERNS,
    DynamicToolRegistry,
)


# ===== Test Fixtures =====


@pytest.fixture
def registry() -> DynamicToolRegistry:
    """Create registry instance for testing."""
    return DynamicToolRegistry()


# ===== Dangerous Pattern Detection Tests =====


def test_xss_javascript_protocol_detection(registry: DynamicToolRegistry) -> None:
    """Test detection of XSS via markdown image with javascript: protocol.

    Attack Vector:
    - ![alt](javascript:alert(document.cookie))
    - ![](javascript:void(0))

    Expected: ValidationError raised, security event logged
    """
    malicious_contents = [
        "![click me](javascript:alert(1))",
        "![](javascript:void(0))",
        "![xss](JavaScript:alert('XSS'))",  # Case variation
        "Some text\n![](javascript:fetch('evil.com'))\nMore text",
    ]

    for content in malicious_contents:
        with pytest.raises(ValidationError) as exc_info:
            registry._validate_skill_content("test-skill", content)

        error = exc_info.value
        assert "XSS via markdown image" in str(error)
        assert error.details["error_code"] == "DANGEROUS_CONTENT_DETECTED"
        # Don't leak attack payload (alert, fetch, etc.)
        assert "alert" not in str(error.details).lower()
        assert "fetch" not in str(error.details).lower()


def test_script_tag_injection_detection(registry: DynamicToolRegistry) -> None:
    """Test detection of script tag injection.

    Attack Vector:
    - <script>alert(1)</script>
    - <SCRIPT>malicious()</SCRIPT>
    - <script src="evil.js"></script>

    Expected: ValidationError raised, security event logged
    """
    malicious_contents = [
        "<script>alert(1)</script>",
        "<SCRIPT>malicious()</SCRIPT>",  # Case variation
        "Text before <script src='evil.js'></script> text after",
        "<!-- <script>alert('comment')</script> -->",
    ]

    for content in malicious_contents:
        with pytest.raises(ValidationError) as exc_info:
            registry._validate_skill_content("test-skill", content)

        error = exc_info.value
        assert "Script tag injection" in str(error)
        assert error.details["error_code"] == "DANGEROUS_CONTENT_DETECTED"
        assert "<script" not in str(error.details).lower()  # Don't leak attack


def test_event_handler_injection_detection(registry: DynamicToolRegistry) -> None:
    """Test detection of event handler injection.

    Attack Vector:
    - onclick=alert(1)
    - onerror="malicious()"
    - onload='fetch(evil)'

    Expected: ValidationError raised, security event logged
    """
    malicious_contents = [
        'onclick=alert(1)',
        'onerror="malicious()"',
        "onload='fetch(evil)'",
        "ONMOUSEOVER=alert(1)",  # Case variation
        "<img src=x onerror=alert(1)>",
        "onsubmit=return false",
    ]

    for content in malicious_contents:
        with pytest.raises(ValidationError) as exc_info:
            registry._validate_skill_content("test-skill", content)

        error = exc_info.value
        assert "Event handler injection" in str(error)
        assert error.details["error_code"] == "DANGEROUS_CONTENT_DETECTED"


def test_variable_injection_detection(registry: DynamicToolRegistry) -> None:
    """Test detection of variable/template injection.

    Attack Vector:
    - ${malicious_var}
    - ${process.env.SECRET}

    Expected: ValidationError raised, security event logged
    """
    malicious_contents = [
        "${malicious_var}",
        "${process.env.SECRET}",
        "Text ${user.password} text",
        "${eval('alert(1)')}",
    ]

    for content in malicious_contents:
        with pytest.raises(ValidationError) as exc_info:
            registry._validate_skill_content("test-skill", content)

        error = exc_info.value
        assert "Variable/template injection" in str(error)
        assert error.details["error_code"] == "DANGEROUS_CONTENT_DETECTED"


def test_eval_code_execution_detection(registry: DynamicToolRegistry) -> None:
    """Test detection of JavaScript eval() code execution.

    Attack Vector:
    - eval('malicious code')
    - eval(user_input)

    Expected: ValidationError raised, security event logged
    """
    malicious_contents = [
        "eval('alert(1)')",
        "eval(user_input)",
        "EVAL('malicious')",  # Case variation
        "window.eval('code')",
    ]

    for content in malicious_contents:
        with pytest.raises(ValidationError) as exc_info:
            registry._validate_skill_content("test-skill", content)

        error = exc_info.value
        assert "eval() code execution" in str(error)
        assert error.details["error_code"] == "DANGEROUS_CONTENT_DETECTED"


def test_exec_code_execution_detection(registry: DynamicToolRegistry) -> None:
    """Test detection of Python exec() code execution.

    Attack Vector:
    - exec('malicious code')
    - exec(user_input)

    Expected: ValidationError raised, security event logged
    """
    malicious_contents = [
        "exec('import os; os.system(\"rm -rf /\")')",
        "exec(user_input)",
        "EXEC('malicious')",  # Case variation
    ]

    for content in malicious_contents:
        with pytest.raises(ValidationError) as exc_info:
            registry._validate_skill_content("test-skill", content)

        error = exc_info.value
        assert "exec() code execution" in str(error)
        assert error.details["error_code"] == "DANGEROUS_CONTENT_DETECTED"


def test_import_injection_detection(registry: DynamicToolRegistry) -> None:
    """Test detection of Python __import__ injection.

    Attack Vector:
    - __import__('os').system('malicious')
    - __import__('subprocess')

    Expected: ValidationError raised, security event logged
    """
    malicious_contents = [
        "__import__('os').system('rm -rf /')",
        "__import__('subprocess').run(['malicious'])",
        "__IMPORT__('os')",  # Case variation
    ]

    for content in malicious_contents:
        with pytest.raises(ValidationError) as exc_info:
            registry._validate_skill_content("test-skill", content)

        error = exc_info.value
        assert "import injection" in str(error)
        assert error.details["error_code"] == "DANGEROUS_CONTENT_DETECTED"


def test_subprocess_command_execution_detection(registry: DynamicToolRegistry) -> None:
    """Test detection of Python subprocess command execution.

    Attack Vector:
    - subprocess.run(['rm', '-rf', '/'])
    - subprocess.Popen('malicious')

    Expected: ValidationError raised, security event logged
    """
    malicious_contents = [
        "subprocess.run(['rm', '-rf', '/'])",
        "subprocess.Popen('malicious')",
        "import subprocess\nsubprocess.call(['ls'])",
        "SUBPROCESS.run(['cmd'])",  # Case variation
    ]

    for content in malicious_contents:
        with pytest.raises(ValidationError) as exc_info:
            registry._validate_skill_content("test-skill", content)

        error = exc_info.value
        assert "subprocess command execution" in str(error)
        assert error.details["error_code"] == "DANGEROUS_CONTENT_DETECTED"


def test_os_system_command_execution_detection(registry: DynamicToolRegistry) -> None:
    """Test detection of os.system command execution.

    Attack Vector:
    - os.system('rm -rf /')
    - os.system(user_input)

    Expected: ValidationError raised, security event logged
    """
    malicious_contents = [
        "os.system('rm -rf /')",
        "os.system(user_input)",
        "OS.SYSTEM('malicious')",  # Case variation
    ]

    for content in malicious_contents:
        with pytest.raises(ValidationError) as exc_info:
            registry._validate_skill_content("test-skill", content)

        error = exc_info.value
        assert "os.system command execution" in str(error)
        assert error.details["error_code"] == "DANGEROUS_CONTENT_DETECTED"


def test_file_access_detection(registry: DynamicToolRegistry) -> None:
    """Test detection of file access attempts.

    Attack Vector:
    - open('/etc/passwd')
    - open(user_file, 'w')

    Expected: ValidationError raised, security event logged
    """
    malicious_contents = [
        "open('/etc/passwd')",
        "open(user_file, 'w')",
        "OPEN('/etc/shadow')",  # Case variation
        "with open('sensitive.txt') as f:",
    ]

    for content in malicious_contents:
        with pytest.raises(ValidationError) as exc_info:
            registry._validate_skill_content("test-skill", content)

        error = exc_info.value
        assert "File access attempt" in str(error)
        assert error.details["error_code"] == "DANGEROUS_CONTENT_DETECTED"


# ===== Safe Content Tests =====


def test_safe_markdown_content_passes(registry: DynamicToolRegistry) -> None:
    """Test that safe markdown content passes validation.

    Safe content should not trigger any dangerous pattern detection.
    """
    safe_contents = [
        # Normal markdown
        "# Skill Title\n\n## Instructions\n\nThis is safe content.",
        # Code blocks (not executable)
        "```python\nprint('hello')\n```",
        # Links (not javascript:)
        "[Click here](https://example.com)",
        "[Documentation](./docs/README.md)",
        # Images (safe URLs)
        "![Logo](https://example.com/logo.png)",
        "![Diagram](./assets/diagram.svg)",
        # Mentions of keywords in safe context
        "This skill evaluates performance metrics.",
        "Execute the following subprocess: step 1, step 2.",
        "Open the documentation for more details.",
    ]

    for content in safe_contents:
        # Should not raise ValidationError
        try:
            registry._validate_skill_content("test-skill", content)
        except ValidationError as e:
            pytest.fail(
                f"Safe content incorrectly flagged as dangerous: {content[:50]}\nError: {e}"
            )


def test_safe_content_with_escaped_patterns(registry: DynamicToolRegistry) -> None:
    """Test that escaped or quoted dangerous patterns are safe.

    When dangerous patterns appear in code blocks or as examples,
    they should still be blocked (defense in depth).
    """
    # These SHOULD be blocked even in code blocks (conservative approach)
    potentially_dangerous = [
        "```javascript\neval('code')\n```",
        "Example: `<script>alert(1)</script>`",
        "Don't use: `onclick=handler`",
    ]

    for content in potentially_dangerous:
        with pytest.raises(ValidationError):
            registry._validate_skill_content("test-skill", content)


# ===== Edge Cases and Integration Tests =====


def test_multiple_dangerous_patterns_in_one_content(registry: DynamicToolRegistry) -> None:
    """Test content with multiple dangerous patterns.

    Should detect and report the first match encountered.
    """
    malicious_content = """
    # Skill with Multiple Attacks

    ![xss](javascript:alert(1))

    <script>malicious()</script>

    ${template_injection}

    eval('code')
    """

    with pytest.raises(ValidationError) as exc_info:
        registry._validate_skill_content("multi-attack-skill", malicious_content)

    error = exc_info.value
    # Should catch the first pattern (order matters)
    assert error.details["error_code"] == "DANGEROUS_CONTENT_DETECTED"


def test_unicode_variations_detected(registry: DynamicToolRegistry) -> None:
    """Test that unicode variations of dangerous patterns are detected.

    Case-insensitive matching should catch unicode variations.
    """
    # Unicode variations should still match (case-insensitive regex)
    unicode_attacks = [
        "![](JAVASCRIPT:alert(1))",  # Uppercase
        "![](JaVaScRiPt:alert(1))",  # Mixed case
    ]

    for content in unicode_attacks:
        with pytest.raises(ValidationError):
            registry._validate_skill_content("test-skill", content)


def test_empty_content_validation(registry: DynamicToolRegistry) -> None:
    """Test that empty content is rejected before pattern checking."""
    with pytest.raises(ValidationError) as exc_info:
        registry._validate_skill_content("test-skill", "")

    error = exc_info.value
    assert "cannot be empty" in str(error)
    # Should fail on emptiness, not dangerous patterns
    assert "DANGEROUS_CONTENT_DETECTED" not in str(error.details)


def test_oversized_content_validation(registry: DynamicToolRegistry) -> None:
    """Test that oversized content is rejected before pattern checking."""
    oversized_content = "a" * 60000  # >50KB limit

    with pytest.raises(ValidationError) as exc_info:
        registry._validate_skill_content("test-skill", oversized_content)

    error = exc_info.value
    assert "too large" in str(error)
    # Should fail on size, not dangerous patterns
    assert "DANGEROUS_CONTENT_DETECTED" not in str(error.details)


def test_security_event_logging(registry: DynamicToolRegistry, caplog) -> None:
    """Test that security events are logged when dangerous patterns detected."""
    malicious_content = "![](javascript:alert(1))"

    with caplog.at_level(logging.WARNING):
        with pytest.raises(ValidationError):
            registry._validate_skill_content("attack-skill", malicious_content)

    # Verify security event was logged
    assert len(caplog.records) > 0
    log_record = caplog.records[0]
    assert log_record.levelname == "WARNING"
    assert "dangerous pattern detected" in log_record.message
    assert "attack-skill" in str(log_record.__dict__)
    assert "SKILL_INJECTION_ATTEMPT" in str(log_record.__dict__)


def test_error_message_does_not_leak_attack_payload(registry: DynamicToolRegistry) -> None:
    """Test that error messages don't expose attack payload (V-SKILL-4 compliance)."""
    attack_payload = "<script>alert(document.cookie)</script>"

    with pytest.raises(ValidationError) as exc_info:
        registry._validate_skill_content("test-skill", attack_payload)

    error = exc_info.value
    error_str = str(error)
    error_details_str = str(error.details)

    # Error should not contain full attack payload
    assert "document.cookie" not in error_details_str
    assert "<script>" not in error_details_str

    # Should contain security issue description
    assert "Script tag injection" in error_str
    assert "DANGEROUS_CONTENT_DETECTED" in error_details_str


def test_pattern_compilation_correctness() -> None:
    """Test that DANGEROUS_PATTERNS are correctly compiled."""
    # Verify all patterns compile without errors
    assert len(COMPILED_DANGEROUS_PATTERNS) == len(DANGEROUS_PATTERNS)

    for compiled, (original, description) in zip(COMPILED_DANGEROUS_PATTERNS, DANGEROUS_PATTERNS):
        pattern, desc = compiled
        assert isinstance(pattern, re.Pattern)
        assert pattern.flags & re.IGNORECASE  # Should be case-insensitive
        assert desc == description


def test_performance_on_large_safe_content(registry: DynamicToolRegistry) -> None:
    """Test that pattern checking performs well on large safe content.

    Large safe content (40KB) should complete validation quickly.
    """
    import time

    # Create 40KB of safe content
    safe_content = "# Safe Skill\n\n" + ("This is safe content. " * 2000)

    start = time.perf_counter()
    registry._validate_skill_content("large-skill", safe_content)
    duration = time.perf_counter() - start

    # Should complete in <100ms
    assert duration < 0.1, f"Validation too slow: {duration * 1000:.2f}ms"


# ===== Summary Test =====


def test_all_dangerous_patterns_covered() -> None:
    """Meta-test: Verify all dangerous patterns have test coverage."""
    expected_patterns = [
        "javascript:",  # XSS
        "<script",  # Script injection
        r"on\w+\s*=",  # Event handlers
        r"\$\{.*\}",  # Variable injection
        r"eval\s*\(",  # eval()
        r"exec\s*\(",  # exec()
        "__import__",  # __import__
        r"subprocess\.",  # subprocess
        r"os\.system",  # os.system
        r"open\s*\(",  # file access
    ]

    pattern_strings = [pattern for pattern, _ in DANGEROUS_PATTERNS]

    for expected in expected_patterns:
        found = any(expected in pattern for pattern in pattern_strings)
        assert found, f"Missing test coverage for pattern: {expected}"
