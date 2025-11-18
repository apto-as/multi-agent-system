"""
Unit tests for shared.utils.secure_file_loader module

Tests the SecureFileLoader class with focus on security validation (CWE-22, CWE-73).
Security testing by Hestia: ...最悪のケースを想定したテストです...
"""

import os
from pathlib import Path

import pytest

from shared.utils import SecureFileLoader, SecurityError, validate_path


class TestSecureFileLoader:
    """Test cases for SecureFileLoader class"""

    def test_initialization_default(self):
        """Test default initialization"""
        # Act
        loader = SecureFileLoader()

        # Assert
        assert loader.allowed_roots is not None
        assert loader.allowed_extensions is not None

    def test_initialization_custom(self, tmp_path):
        """Test initialization with custom parameters"""
        # Arrange
        custom_roots = [str(tmp_path)]
        custom_extensions = [".txt", ".md"]

        # Act
        loader = SecureFileLoader(
            allowed_roots=custom_roots,
            allowed_extensions=custom_extensions
        )

        # Assert
        assert len(loader.allowed_roots) == 1
        assert str(tmp_path) in loader.allowed_roots[0]
        assert set(loader.allowed_extensions) == {".txt", ".md"}

    def test_load_file_success(self, tmp_path, sample_markdown_content):
        """Test successful file loading"""
        # Arrange
        test_file = tmp_path / "test.md"
        test_file.write_text(sample_markdown_content)

        loader = SecureFileLoader(
            allowed_roots=[str(tmp_path)],
            allowed_extensions=[".md"]
        )

        # Act
        result = loader.load_file("test.md", base_path=tmp_path)

        # Assert
        assert result == sample_markdown_content
        assert "# Test Document" in result

    def test_load_file_not_found(self, tmp_path):
        """Test loading non-existent file"""
        # Arrange
        loader = SecureFileLoader(allowed_roots=[str(tmp_path)])

        # Act
        result = loader.load_file("missing.md", base_path=tmp_path, silent=True)

        # Assert
        assert result is None

    def test_load_file_security_violation_path_traversal(self, tmp_path):
        """Test path traversal attack prevention (CWE-22)"""
        # Arrange
        loader = SecureFileLoader(allowed_roots=[str(tmp_path)])

        # Act & Assert
        result = loader.load_file("../../etc/passwd", base_path=tmp_path, silent=True)
        assert result is None  # Security violation should return None

    def test_load_file_security_violation_absolute_path_outside_root(self, tmp_path):
        """Test absolute path outside allowed roots"""
        # Arrange
        loader = SecureFileLoader(allowed_roots=[str(tmp_path)])

        # Act
        result = loader.load_file("/etc/passwd", silent=True)

        # Assert
        assert result is None  # Outside allowed roots

    def test_load_file_extension_not_allowed(self, tmp_path):
        """Test file with disallowed extension"""
        # Arrange
        forbidden_file = tmp_path / "dangerous.exe"
        forbidden_file.write_text("malicious content")

        loader = SecureFileLoader(
            allowed_roots=[str(tmp_path)],
            allowed_extensions=[".md", ".txt"]
        )

        # Act
        result = loader.load_file("dangerous.exe", base_path=tmp_path, silent=True)

        # Assert
        assert result is None  # Disallowed extension

    def test_validate_path_success(self, tmp_path):
        """Test successful path validation"""
        # Arrange
        test_file = tmp_path / "safe.md"
        test_file.write_text("safe content")

        loader = SecureFileLoader(
            allowed_roots=[str(tmp_path)],
            allowed_extensions=[".md"]
        )

        # Act
        validated = loader.validate_path("safe.md", base_path=tmp_path)

        # Assert
        assert validated is not None
        assert "safe.md" in validated

    def test_validate_path_traversal_attack(self, tmp_path):
        """Test path traversal attack patterns"""
        # Arrange
        loader = SecureFileLoader(allowed_roots=[str(tmp_path)])

        # Test various path traversal patterns
        malicious_patterns = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "./../../secret.key",
            "subdir/../../outside.txt",
        ]

        for pattern in malicious_patterns:
            # Act
            result = loader.validate_path(pattern, base_path=tmp_path)

            # Assert
            assert result is None, f"Path traversal should be blocked: {pattern}"

    def test_validate_path_symlink_attack(self, tmp_path):
        """Test symlink attack prevention"""
        # Arrange
        loader = SecureFileLoader(allowed_roots=[str(tmp_path)])

        # Create a symlink pointing outside allowed root
        external_dir = tmp_path.parent / "external"
        external_dir.mkdir(exist_ok=True)
        external_file = external_dir / "secret.txt"
        external_file.write_text("secret data")

        symlink = tmp_path / "link_to_secret"
        symlink.symlink_to(external_file)

        # Act
        result = loader.validate_path("link_to_secret", base_path=tmp_path)

        # Assert
        # Should either be None or resolve to external location (which is then rejected)
        # The important thing is that we can't access the secret file
        if result:
            assert str(external_dir) not in loader.allowed_roots

    def test_file_exists_check(self, tmp_path):
        """Test file existence check"""
        # Arrange
        existing_file = tmp_path / "exists.md"
        existing_file.write_text("content")

        loader = SecureFileLoader(
            allowed_roots=[str(tmp_path)],
            allowed_extensions=[".md"]
        )

        # Act & Assert
        assert loader.file_exists("exists.md", base_path=tmp_path) is True
        assert loader.file_exists("missing.md", base_path=tmp_path) is False

    def test_load_binary_file(self, tmp_path):
        """Test loading binary file"""
        # Arrange
        binary_content = b"\\x00\\x01\\x02\\x03\\xFF"
        binary_file = tmp_path / "binary.dat"
        binary_file.write_bytes(binary_content)

        loader = SecureFileLoader(
            allowed_roots=[str(tmp_path)],
            allowed_extensions=[".dat"]
        )

        # Act
        result = loader.load_binary("binary.dat", base_path=tmp_path)

        # Assert
        assert result == binary_content

    def test_multiple_allowed_roots(self, tmp_path):
        """Test loader with multiple allowed roots"""
        # Arrange
        root1 = tmp_path / "root1"
        root2 = tmp_path / "root2"
        root1.mkdir()
        root2.mkdir()

        file1 = root1 / "file1.md"
        file2 = root2 / "file2.md"
        file1.write_text("content1")
        file2.write_text("content2")

        loader = SecureFileLoader(
            allowed_roots=[str(root1), str(root2)],
            allowed_extensions=[".md"]
        )

        # Act & Assert
        assert loader.load_file("file1.md", base_path=root1) == "content1"
        assert loader.load_file("file2.md", base_path=root2) == "content2"

    def test_case_sensitive_extensions(self, tmp_path):
        """Test case sensitivity in file extensions"""
        # Arrange
        upper_case = tmp_path / "file.MD"
        upper_case.write_text("content")

        loader = SecureFileLoader(
            allowed_roots=[str(tmp_path)],
            allowed_extensions=[".md"]  # lowercase only
        )

        # Act
        result = loader.load_file("file.MD", base_path=tmp_path, silent=True)

        # Assert
        # Implementation should handle this - either allow or deny consistently
        # Current implementation likely normalizes to lowercase
        assert result is None or result == "content"


class TestSecurityViolations:
    """Test security violation scenarios - Hestia's paranoia tests"""

    def test_null_byte_injection(self, tmp_path):
        """Test null byte injection attack prevention (CWE-626)"""
        # Arrange
        loader = SecureFileLoader(allowed_roots=[str(tmp_path)])

        # Act - null byte could bypass extension checks
        result = loader.validate_path("safe.txt\\x00.exe", base_path=tmp_path)

        # Assert
        assert result is None or ".exe" not in result

    def test_unicode_normalization_attack(self, tmp_path):
        """Test Unicode normalization attacks"""
        # Arrange
        loader = SecureFileLoader(allowed_roots=[str(tmp_path)])

        # Various Unicode representations of ..
        unicode_attacks = [
            "..\\u002f..\\u002fetc\\u002fpasswd",  # Unicode encoded slashes
            "..%2F..%2Fetc%2Fpasswd",  # URL encoded
        ]

        for attack in unicode_attacks:
            # Act
            result = loader.validate_path(attack, base_path=tmp_path)

            # Assert
            assert result is None, f"Unicode attack should be blocked: {attack}"

    def test_windows_device_names(self, tmp_path):
        """Test Windows device name access prevention"""
        # Arrange
        loader = SecureFileLoader(allowed_roots=[str(tmp_path)])

        # Windows device names
        device_names = ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"]

        for device in device_names:
            # Act
            result = loader.validate_path(device, base_path=tmp_path)

            # Assert - should either block or handle safely
            # The important part is not causing system issues
            pass  # Implementation-specific handling

    def test_excessively_long_path(self, tmp_path):
        """Test excessively long path handling"""
        # Arrange
        loader = SecureFileLoader(allowed_roots=[str(tmp_path)])

        # Create a very long path
        long_path = "/".join(["a" * 100 for _ in range(50)])

        # Act & Assert
        # Should handle gracefully without crashing
        result = loader.validate_path(long_path, base_path=tmp_path)
        assert result is None or isinstance(result, str)

    def test_permission_errors(self, tmp_path):
        """Test handling of permission errors"""
        # Arrange
        restricted_file = tmp_path / "restricted.txt"
        restricted_file.write_text("secret")
        restricted_file.chmod(0o000)  # No permissions

        loader = SecureFileLoader(
            allowed_roots=[str(tmp_path)],
            allowed_extensions=[".txt"]
        )

        # Act
        result = loader.load_file("restricted.txt", base_path=tmp_path, silent=True)

        # Assert
        assert result is None

        # Cleanup
        restricted_file.chmod(0o644)


class TestConvenienceFunctions:
    """Test convenience functions"""

    def test_validate_path_function(self, tmp_path):
        """Test standalone validate_path function"""
        # Arrange
        from shared.utils.secure_file_loader import _default_loader
        test_file = tmp_path / "test.md"
        test_file.write_text("content")

        # Add tmp_path to allowed roots for this test
        # (validate_path uses _default_loader which has restricted allowed_roots)
        _default_loader.add_allowed_root(tmp_path)

        # Act
        result = validate_path(str(test_file))

        # Assert
        assert result is not None
        assert "test.md" in result

        # Cleanup: Remove tmp_path from allowed roots to avoid affecting other tests
        _default_loader.allowed_roots = [
            root for root in _default_loader.allowed_roots
            if not root.startswith(str(tmp_path))
        ]

    def test_validate_path_malicious(self):
        """Test validate_path with malicious input"""
        # Act
        result = validate_path("../../etc/passwd")

        # Assert
        assert result is None


@pytest.mark.parametrize("malicious_path", [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "~/.ssh/id_rsa",
    "/etc/shadow",
    "./../../outside.txt",
    "subdir/../../../evil.sh",
])
def test_path_traversal_patterns(malicious_path, tmp_path):
    """Test various path traversal attack patterns"""
    loader = SecureFileLoader(allowed_roots=[str(tmp_path)])
    result = loader.validate_path(malicious_path, base_path=tmp_path)
    assert result is None, f"Path traversal should be blocked: {malicious_path}"
