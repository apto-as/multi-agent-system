"""Test path traversal vulnerability in namespace sanitization.

This test suite validates that the namespace sanitization function properly
blocks path traversal attacks and prevents malicious namespace values.

Security Issue: V-1 (CVSS 7.5)
Reference: SECURITY_AUDIT_PHASE_0-3.md
"""

import pytest

from src.utils.namespace import (
    NamespaceError,
    namespace_from_git_url,
    sanitize_namespace,
    validate_namespace,
)


class TestPathTraversalDefense:
    """Test that path traversal sequences are blocked.

    These tests verify that malicious input containing path traversal
    sequences (../ and ./) are properly rejected or sanitized.
    """

    def test_parent_directory_traversal(self):
        """Test that ../ sequences are rejected."""
        # CURRENT BEHAVIOR: This test will FAIL until V-1 is fixed
        # EXPECTED BEHAVIOR: Should raise NamespaceError

        # Test direct ../ input
        with pytest.raises((NamespaceError, ValueError)):
            namespace = sanitize_namespace("../../../etc/passwd")
            validate_namespace(namespace)

    def test_current_directory_traversal(self):
        """Test that ./ sequences are rejected."""
        # CURRENT BEHAVIOR: This test will FAIL until V-1 is fixed
        # EXPECTED BEHAVIOR: Should raise NamespaceError

        with pytest.raises((NamespaceError, ValueError)):
            namespace = sanitize_namespace("./../../etc/shadow")
            validate_namespace(namespace)

    def test_embedded_path_traversal(self):
        """Test that path traversal in middle of namespace is blocked."""
        # CURRENT BEHAVIOR: This test will FAIL until V-1 is fixed
        # EXPECTED BEHAVIOR: Should raise NamespaceError

        with pytest.raises((NamespaceError, ValueError)):
            namespace = sanitize_namespace("project/../../../secrets")
            validate_namespace(namespace)

    def test_absolute_path_rejection(self):
        """Test that absolute paths are rejected."""
        # CURRENT BEHAVIOR: This test will FAIL until V-1 is fixed
        # EXPECTED BEHAVIOR: Should raise NamespaceError

        with pytest.raises((NamespaceError, ValueError)):
            namespace = sanitize_namespace("/etc/passwd")
            validate_namespace(namespace)

    def test_mixed_path_traversal(self):
        """Test that mixed path traversal patterns are blocked."""
        # CURRENT BEHAVIOR: This test will FAIL until V-1 is fixed
        # EXPECTED BEHAVIOR: Should raise NamespaceError

        test_cases = [
            "project/./../../secrets",
            "../project/../secrets",
            "../.././etc/passwd",
        ]

        for malicious_input in test_cases:
            with pytest.raises((NamespaceError, ValueError)):
                namespace = sanitize_namespace(malicious_input)
                validate_namespace(namespace)


class TestGitUrlPathTraversal:
    """Test that malicious git URLs are properly sanitized."""

    def test_git_url_path_traversal(self):
        """Test that malicious git URLs are blocked (V-1 fix verified)."""
        # V-1 FIX: Path traversal in git URLs should be REJECTED
        # After "/" → "-" conversion: "evil.com-..-..-etc-passwd"
        # Then ".." detection raises NamespaceError (correct behavior)

        malicious_url = "git@evil.com:../../etc/passwd.git"

        with pytest.raises(NamespaceError, match="path traversal"):
            namespace_from_git_url(malicious_url)

    def test_https_url_path_traversal(self):
        """Test that HTTPS URLs with path traversal are blocked (V-1 fix verified)."""
        # V-1 FIX: Path traversal in HTTPS URLs should be REJECTED
        # After "/" → "-" conversion: "evil.com-..-..-etc-passwd"
        # Then ".." detection raises NamespaceError (correct behavior)

        malicious_url = "https://evil.com/../../etc/passwd"

        with pytest.raises(NamespaceError, match="path traversal"):
            namespace_from_git_url(malicious_url)

    def test_legitimate_git_urls_unaffected(self):
        """Test that legitimate git URLs are converted correctly (V-1 fix verified)."""
        # V-1 FIX: "/" → "-" conversion allows legitimate URLs to work
        # Expected format: "github-com-apto-as-tmws" (all / become -)
        legitimate_urls = [
            ("git@github.com:apto-as/tmws.git", "github-com-apto-as-tmws"),
            ("https://github.com/apto-as/tmws", "github-com-apto-as-tmws"),
            ("git@gitlab.com:user/repo.git", "gitlab-com-user-repo"),
        ]

        for url, expected in legitimate_urls:
            namespace = namespace_from_git_url(url)
            assert namespace == expected, f"Legitimate URL broken: {url} → {namespace}"


class TestNamespaceSanitizationCompliance:
    """Test that namespace sanitization follows security requirements."""

    def test_no_dots_allowed(self):
        """Verify dots are removed from namespaces.

        This test will FAIL until V-1 is fixed.
        Expected behavior: Dots should be replaced with hyphens.
        """
        namespace = sanitize_namespace("project.with.dots")
        assert "." not in namespace, f"Dots found in sanitized namespace: {namespace}"
        # Expected: "project-with-dots"

    def test_no_slashes_allowed(self):
        """Verify slashes are rejected (V-1 fix verified).

        V-1 FIX: Slashes should be REJECTED, not replaced.
        This prevents path traversal attacks at the earliest point.
        """
        with pytest.raises(NamespaceError, match="path separator"):
            sanitize_namespace("project/with/slashes")

    def test_alphanumeric_only(self):
        """Verify only alphanumeric, hyphens, underscores allowed."""
        namespace = sanitize_namespace("project@#$%test")
        allowed_chars = set("abcdefghijklmnopqrstuvwxyz0123456789-_")
        assert all(
            c in allowed_chars for c in namespace
        ), f"Invalid characters in namespace: {namespace}"

    def test_no_leading_slash(self):
        """Verify leading slash is rejected (V-1 fix verified)."""
        # V-1 FIX: Slashes should be REJECTED, not removed
        with pytest.raises(NamespaceError, match="path separator"):
            sanitize_namespace("/project")

    def test_no_trailing_slash(self):
        """Verify trailing slash is rejected (V-1 fix verified)."""
        # V-1 FIX: Slashes should be REJECTED, not removed
        with pytest.raises(NamespaceError, match="path separator"):
            sanitize_namespace("project/")


class TestSecurityRegression:
    """Regression tests to ensure security fixes are not reverted."""

    def test_default_namespace_rejection(self):
        """Verify 'default' namespace is still rejected (C-1 fix)."""
        with pytest.raises(NamespaceError):
            validate_namespace("default")

    def test_case_insensitive_default_rejection(self):
        """Verify 'DEFAULT' is also rejected."""
        with pytest.raises(NamespaceError):
            validate_namespace("DEFAULT")

    def test_sanitized_default_rejection(self):
        """Verify sanitized 'default' is still rejected."""
        namespace = sanitize_namespace("default")
        with pytest.raises(NamespaceError):
            validate_namespace(namespace)


class TestNamespaceValidationEdgeCases:
    """Test edge cases in namespace validation."""

    def test_empty_namespace_rejected(self):
        """Empty namespace should be rejected."""
        with pytest.raises(NamespaceError):
            sanitize_namespace("")

    def test_whitespace_only_rejected(self):
        """Whitespace-only namespace should be rejected."""
        with pytest.raises(NamespaceError):
            sanitize_namespace("   ")

    def test_max_length_enforcement(self):
        """Namespace should be truncated to 128 chars."""
        long_namespace = "a" * 200
        namespace = sanitize_namespace(long_namespace)
        assert len(namespace) <= 128, f"Namespace too long: {len(namespace)} chars"

    def test_unicode_handling(self):
        """Unicode characters should be replaced with hyphens."""
        namespace = sanitize_namespace("project-🚀-emoji")
        assert "🚀" not in namespace, f"Unicode emoji found: {namespace}"
        assert all(ord(c) < 128 for c in namespace), "Non-ASCII characters found"


@pytest.mark.parametrize(
    "malicious_input,description",
    [
        ("../../../etc/passwd", "Basic path traversal"),
        ("../../../../", "Multiple parent directories"),
        ("./../../etc/shadow", "Current + parent directory"),
        ("project/../../../secrets", "Embedded traversal"),
        ("project/./../../passwords", "Mixed traversal"),
        ("/etc/passwd", "Absolute path"),
        ("//etc/passwd", "Double slash"),
        ("./../secrets", "Dot-slash-parent"),
    ],
)
class TestPathTraversalParameterized:
    """Parameterized tests for various path traversal patterns."""

    def test_path_traversal_blocked(self, malicious_input, description):
        """Test that path traversal pattern is blocked.

        This parameterized test covers multiple attack vectors.
        All tests will FAIL until V-1 is fixed.
        """
        with pytest.raises((NamespaceError, ValueError)):
            namespace = sanitize_namespace(malicious_input)
            validate_namespace(namespace)


# Run with: pytest tests/security/test_path_traversal.py -v
# Expected: FAIL until V-1 is fixed, then all tests should PASS
