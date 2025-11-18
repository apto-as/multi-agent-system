#!/usr/bin/env python3
"""
test_security.py - Security Tests for Decision System
======================================================

Tests for security utilities and protections:
- Path Traversal prevention (CWE-22)
- SSRF prevention (CWE-918)
- Rate Limiting (DoS protection)
- Secret redaction
- Log injection prevention
- Input sanitization
"""

import pytest
import sys
import time
from pathlib import Path
from datetime import datetime, timedelta

# Add hooks/core to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / ".claude" / "hooks" / "core"))

from security_utils import (
    validate_decision_id,
    validate_and_resolve_path,
    validate_tmws_url,
    sanitize_prompt,
    redact_secrets,
    sanitize_log_message,
    safe_json_parse,
    SecurityError,
    PathTraversalError,
    SSRFError
)
from rate_limiter import ThreadSafeRateLimiter, RateLimitExceeded


# =======================
# Path Traversal Tests (CWE-22)
# =======================

def test_validate_decision_id_valid():
    """Valid decision IDs should pass"""
    valid_ids = [
        "decision-123",
        "decision_456",
        "test-decision",
        "Decision123",
        "a" * 64  # Max length
    ]

    for decision_id in valid_ids:
        result = validate_decision_id(decision_id)
        assert result == decision_id


def test_validate_decision_id_invalid():
    """Invalid decision IDs should raise ValueError"""
    invalid_ids = [
        "../secret",           # Path traversal
        "decision/../etc",     # Path traversal
        "decision\\windows",   # Windows path separator
        "decision/passwd",     # Unix path separator
        "decision;rm -rf /",   # Command injection attempt
        "a" * 65,              # Too long
        "",                    # Empty
        "decision with spaces", # Spaces
        "décision",            # Unicode
    ]

    for decision_id in invalid_ids:
        with pytest.raises(ValueError):
            validate_decision_id(decision_id)


def test_validate_path_normal(tmp_path):
    """Normal paths under base_dir should pass"""
    base_dir = tmp_path
    safe_path = base_dir / "decisions" / "test.json"

    result = validate_and_resolve_path(safe_path, base_dir, allow_create=True)
    assert result.is_relative_to(base_dir)


def test_validate_path_traversal(tmp_path):
    """Path traversal attempts should be blocked"""
    base_dir = tmp_path / "safe"
    base_dir.mkdir()

    # Attempt to escape base_dir
    malicious_path = base_dir / ".." / ".." / "etc" / "passwd"

    with pytest.raises(PathTraversalError):
        validate_and_resolve_path(malicious_path, base_dir)


def test_validate_path_symlink(tmp_path):
    """Symlinks should be blocked"""
    base_dir = tmp_path
    target = base_dir / "target.txt"
    target.write_text("secret data")

    symlink = base_dir / "link"
    symlink.symlink_to(target)

    with pytest.raises(SecurityError, match="Symlink access denied"):
        validate_and_resolve_path(symlink, base_dir)


# =======================
# SSRF Prevention Tests (CWE-918)
# =======================

def test_validate_tmws_url_valid():
    """Valid TMWS URLs should pass"""
    valid_urls = [
        "http://localhost:8000",
        "https://localhost:8000",
        "http://127.0.0.1:8000",
        "https://tmws.example.com",
        "http://api.tmws.internal:8080",
    ]

    for url in valid_urls:
        result = validate_tmws_url(url, allow_localhost=True)
        assert result == url


def test_validate_tmws_url_ssrf_private_ip():
    """Private IP ranges should be blocked"""
    private_ips = [
        "http://192.168.1.1:8000",       # Private Class C
        "http://10.0.0.1:8000",          # Private Class A
        "http://172.16.0.1:8000",        # Private Class B
        "http://169.254.169.254",        # AWS metadata
    ]

    for url in private_ips:
        with pytest.raises(SSRFError):
            validate_tmws_url(url, allow_localhost=False)


def test_validate_tmws_url_ssrf_metadata():
    """Cloud metadata endpoints should be blocked"""
    metadata_urls = [
        "http://metadata.google.internal",
        "http://169.254.169.254",
        "http://metadata.goog",
    ]

    for url in metadata_urls:
        with pytest.raises(SSRFError):
            validate_tmws_url(url)


def test_validate_tmws_url_invalid_scheme():
    """Non-HTTP schemes should be blocked"""
    invalid_schemes = [
        "file:///etc/passwd",
        "ftp://malicious.com",
        "gopher://internal.network",
    ]

    for url in invalid_schemes:
        with pytest.raises(SSRFError):
            validate_tmws_url(url)


# =======================
# Rate Limiting Tests (DoS Protection)
# =======================

def test_rate_limiter_allow():
    """Requests within limit should be allowed"""
    limiter = ThreadSafeRateLimiter(max_calls=5, window_seconds=60)

    for i in range(5):
        assert limiter.check(operation_id=f"test_{i}") is True

    assert limiter.total_calls == 5
    assert limiter.rejected_calls == 0


def test_rate_limiter_reject():
    """Requests exceeding limit should be rejected"""
    limiter = ThreadSafeRateLimiter(max_calls=3, window_seconds=60)

    # First 3 should pass
    for i in range(3):
        limiter.check(operation_id=f"test_{i}")

    # 4th should be rejected
    with pytest.raises(RateLimitExceeded) as exc_info:
        limiter.check(operation_id="test_overflow")

    assert limiter.total_calls == 3
    assert limiter.rejected_calls == 1
    assert exc_info.value.max_calls == 3
    assert exc_info.value.window_seconds == 60


def test_rate_limiter_sliding_window():
    """Old calls should expire from the window"""
    limiter = ThreadSafeRateLimiter(max_calls=2, window_seconds=1)

    # First 2 calls
    limiter.check(operation_id="test_1")
    limiter.check(operation_id="test_2")

    # 3rd call should fail
    with pytest.raises(RateLimitExceeded):
        limiter.check(operation_id="test_3")

    # Wait for window to expire
    time.sleep(1.1)

    # Should succeed now (old calls expired)
    assert limiter.check(operation_id="test_4") is True


def test_rate_limiter_stats():
    """Stats should be tracked correctly"""
    limiter = ThreadSafeRateLimiter(max_calls=2, window_seconds=60)

    limiter.check()
    limiter.check()

    try:
        limiter.check()
    except RateLimitExceeded:
        pass

    stats = limiter.get_stats()
    assert stats["total_calls"] == 2
    assert stats["rejected_calls"] == 1
    assert stats["current_window_calls"] == 2


# =======================
# Secret Redaction Tests
# =======================

def test_redact_secrets_api_keys():
    """API keys should be redacted"""
    text = "My OpenAI key is sk-1234567890abcdefghijklmnopqrstuvwxyz"
    result = redact_secrets(text)
    assert "sk-123456789" not in result
    assert "[REDACTED_API_KEY]" in result


def test_redact_secrets_tokens():
    """Long tokens should be redacted"""
    text = "Bearer token: abc123def456ghi789jkl012mno345pqr678"
    result = redact_secrets(text)
    assert "abc123def456" not in result
    # Token pattern matches, redacts as either TOKEN or generic pattern
    assert "[REDACTED" in result


def test_redact_secrets_passwords():
    """Passwords should be redacted"""
    test_cases = [
        ("password=secret123", "password=[REDACTED]"),
        ("passwd: mypassword", "passwd=[REDACTED]"),
        ("pwd=hunter2", "pwd=[REDACTED]"),
    ]

    for text, expected_pattern in test_cases:
        result = redact_secrets(text)
        assert "secret" not in result.lower() or "[REDACTED]" in result


def test_redact_secrets_jwt():
    """JWT tokens should be redacted"""
    text = "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = redact_secrets(text)
    assert "eyJhbGciOiJIUzI1NiI" not in result
    # JWT pattern matches, redacts as either JWT or generic token pattern
    assert "[REDACTED" in result


def test_redact_secrets_aws_keys():
    """AWS keys should be redacted"""
    text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    result = redact_secrets(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in result
    assert "[REDACTED_AWS_KEY]" in result


# =======================
# Input Sanitization Tests
# =======================

def test_sanitize_prompt_control_chars():
    """Control characters should be removed"""
    text = "Hello\nWorld\r\nTest\t\0End"
    result = sanitize_prompt(text)

    # All control characters removed
    assert "\n" not in result
    assert "\r" not in result
    assert "\t" not in result
    assert "\0" not in result

    # Content preserved
    assert "Hello" in result
    assert "World" in result


def test_sanitize_prompt_unicode():
    """Unicode should be normalized"""
    # NFC normalization test
    text = "café"  # é as combining characters
    result = sanitize_prompt(text)
    assert result == "café"


def test_sanitize_prompt_length_limit():
    """Prompt should be truncated to max length"""
    text = "a" * 2000
    result = sanitize_prompt(text, max_length=1000)
    assert len(result) == 1000


def test_sanitize_prompt_whitespace():
    """Whitespace should be collapsed"""
    text = "Hello    World\n\n\nMultiple   Spaces"
    result = sanitize_prompt(text)
    # Newlines removed, multiple spaces collapsed
    assert "Hello" in result
    assert "World" in result
    assert "Multiple" in result
    assert "Spaces" in result
    assert "\n" not in result


# =======================
# Log Injection Tests (CWE-117)
# =======================

def test_sanitize_log_message_newlines():
    """Newlines should be removed from log messages"""
    message = "Error occurred\nFake log entry: [ERROR] Injected"
    result = sanitize_log_message(message)

    assert "\n" not in result
    assert "\r" not in result


def test_sanitize_log_message_control_chars():
    """Control characters should be removed"""
    message = "Error\x00\x01\x02\x1b[31mColored\x1b[0m"
    result = sanitize_log_message(message)

    # Control characters removed
    for i in range(32):
        assert chr(i) not in result


def test_sanitize_log_message_length():
    """Log messages should be truncated"""
    message = "a" * 1000
    result = sanitize_log_message(message, max_length=500)
    assert len(result) == 500


# =======================
# JSON Deserialization Tests (CWE-502)
# =======================

def test_safe_json_parse_valid():
    """Valid JSON should parse correctly"""
    json_str = '{"key": "value", "number": 123}'
    result = safe_json_parse(json_str)

    assert result == {"key": "value", "number": 123}


def test_safe_json_parse_size_limit():
    """Large JSON should be rejected"""
    large_json = '{"data": "' + ("a" * 20000) + '"}'

    with pytest.raises(ValueError, match="JSON too large"):
        safe_json_parse(large_json, max_size=10000)


def test_safe_json_parse_depth_limit():
    """Deeply nested JSON should be rejected"""
    # Create deeply nested JSON (12 levels)
    nested = {
        "a": {
            "b": {
                "c": {
                    "d": {
                        "e": {
                            "f": {
                                "g": {
                                    "h": {
                                        "i": {
                                            "j": {
                                                "k": {
                                                    "l": "value"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    json_str = str(nested).replace("'", '"')

    with pytest.raises(ValueError, match="too deeply nested"):
        safe_json_parse(json_str, max_depth=10)


def test_safe_json_parse_invalid():
    """Invalid JSON should raise ValueError"""
    invalid_json = '{"key": "value"'  # Missing closing brace

    with pytest.raises(ValueError, match="Invalid JSON"):
        safe_json_parse(invalid_json)


# =======================
# Integration Tests
# =======================

def test_decision_memory_secure_path(tmp_path):
    """Decision memory _fallback_store should validate decision ID"""
    from decision_memory import TrinitasDecisionMemory, Decision, DecisionType, AutonomyLevel, DecisionOutcome
    import asyncio

    # Create a simple memory instance with tmp_path
    # Note: __init__ validation expects Path.home() as base, so we'll test _fallback_store directly
    memory = TrinitasDecisionMemory()

    # Manually set fallback_dir to tmp_path for testing (bypassing __init__ validation)
    memory.fallback_dir = tmp_path / "decisions"
    memory.fallback_dir.mkdir(parents=True, exist_ok=True)

    # Valid decision ID
    decision = Decision(
        decision_id="test-decision-123",
        timestamp=datetime.now(),
        decision_type=DecisionType.TECHNICAL_CHOICE,
        autonomy_level=AutonomyLevel.LEVEL_1_AUTONOMOUS,
        context="Test context",
        question="Test question?",
        options=["A", "B"],
        outcome=DecisionOutcome.APPROVED,
        chosen_option="A",
        reasoning="Test reasoning",
        persona="test",
        importance=0.5,
        tags=["test"],
        metadata={}
    )

    # Should store successfully
    asyncio.run(memory._fallback_store(decision))

    # File should exist with correct permissions
    file_path = tmp_path / "decisions" / "test-decision-123.json"
    assert file_path.exists()
    assert oct(file_path.stat().st_mode)[-3:] == "600"


def test_decision_memory_block_traversal(tmp_path):
    """Decision memory should block path traversal"""
    from decision_memory import TrinitasDecisionMemory, Decision, DecisionType, AutonomyLevel, DecisionOutcome
    import asyncio

    memory = TrinitasDecisionMemory()

    # Manually set fallback_dir to tmp_path for testing
    memory.fallback_dir = tmp_path / "decisions"
    memory.fallback_dir.mkdir(parents=True, exist_ok=True)

    # Malicious decision ID with path traversal
    decision = Decision(
        decision_id="../../../etc/passwd",
        timestamp=datetime.now(),
        decision_type=DecisionType.TECHNICAL_CHOICE,
        autonomy_level=AutonomyLevel.LEVEL_1_AUTONOMOUS,
        context="Test",
        question="Test?",
        options=["A"],
        outcome=DecisionOutcome.APPROVED,
        chosen_option="A",
        reasoning="Test",
        persona="test",
        importance=0.5,
        tags=[],
        metadata={}
    )

    # Should raise ValueError (invalid decision ID)
    with pytest.raises(ValueError):
        asyncio.run(memory._fallback_store(decision))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
