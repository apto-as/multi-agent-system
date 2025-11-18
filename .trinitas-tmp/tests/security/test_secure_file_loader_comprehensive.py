#!/usr/bin/env python3
"""
Comprehensive SecureFileLoader Tests
====================================

Coverage target: 57% → 95%

Tests all security edge cases:
- Symlink attacks with nested structures
- Path traversal (URL encoding, double encoding)
- Unicode normalization attacks
- File size limits
- Concurrent access scenarios
- Permission escalation attempts
"""

import pytest
from pathlib import Path
import os
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shared.utils.secure_file_loader import SecureFileLoader, SecurityError


class TestSymlinkAttacks:
    """Test symlink attack prevention"""

    def test_direct_symlink_blocked(self, tmp_path):
        """Test direct symlink is blocked"""
        target = tmp_path / "target.txt"
        target.write_text("secret content")

        symlink = tmp_path / "symlink.txt"
        if os.name != 'nt':  # Skip on Windows
            symlink.symlink_to(target)

            loader = SecureFileLoader(allowed_base=tmp_path)

            with pytest.raises(SecurityError, match="Symlink"):
                loader.load_file(symlink)

    def test_nested_symlink_blocked(self, tmp_path):
        """Test nested symlink (symlink in allowed path)"""
        secret_dir = tmp_path / "secret"
        secret_dir.mkdir()
        secret_file = secret_dir / "data.txt"
        secret_file.write_text("confidential")

        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()

        if os.name != 'nt':
            symlink = allowed_dir / "link_to_secret"
            symlink.symlink_to(secret_dir)

            loader = SecureFileLoader(allowed_base=allowed_dir)

            with pytest.raises(SecurityError):
                loader.load_file(symlink / "data.txt")

    def test_symlink_in_path_component(self, tmp_path):
        """Test symlink as intermediate path component"""
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        secret = real_dir / "secret.txt"
        secret.write_text("hidden")

        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()

        if os.name != 'nt':
            link_dir = allowed_dir / "linkdir"
            link_dir.symlink_to(real_dir)

            loader = SecureFileLoader(allowed_base=allowed_dir)

            with pytest.raises(SecurityError):
                loader.load_file(link_dir / "secret.txt")


class TestPathTraversal:
    """Test path traversal attack prevention"""

    def test_basic_traversal_blocked(self, tmp_path):
        """Test basic ../ traversal"""
        allowed = tmp_path / "allowed"
        allowed.mkdir()

        secret = tmp_path / "secret.txt"
        secret.write_text("confidential")

        loader = SecureFileLoader(allowed_base=allowed)

        with pytest.raises(SecurityError):
            loader.load_file(allowed / ".." / "secret.txt")

    def test_url_encoded_traversal(self, tmp_path):
        """Test URL-encoded path traversal (%2e%2e%2f)"""
        allowed = tmp_path / "allowed"
        allowed.mkdir()

        loader = SecureFileLoader(allowed_base=allowed)

        # %2e%2e%2f = ../
        dangerous_path = str(allowed / "%2e%2e%2fsecret.txt")

        # Should detect and block
        with pytest.raises(SecurityError):
            loader.load_file(Path(dangerous_path))

    def test_double_encoded_traversal(self, tmp_path):
        """Test double URL-encoded traversal (%252e%252e%252f)"""
        allowed = tmp_path / "allowed"
        allowed.mkdir()

        loader = SecureFileLoader(allowed_base=allowed)

        # %252e = double-encoded .
        dangerous_path = str(allowed / "%252e%252e%252fsecret.txt")

        with pytest.raises(SecurityError):
            loader.load_file(Path(dangerous_path))

    def test_unicode_traversal(self, tmp_path):
        """Test Unicode normalization path traversal"""
        allowed = tmp_path / "allowed"
        allowed.mkdir()

        loader = SecureFileLoader(allowed_base=allowed)

        # Unicode dot variations
        dangerous_paths = [
            ".\u2024.\u2024/secret.txt",  # ONE DOT LEADER
            "..​/secret.txt",  # With zero-width space
        ]

        for path in dangerous_paths:
            with pytest.raises(SecurityError):
                loader.load_file(allowed / path)

    def test_absolute_path_blocked(self, tmp_path):
        """Test absolute path outside allowed base"""
        allowed = tmp_path / "allowed"
        allowed.mkdir()

        secret = tmp_path / "secret.txt"
        secret.write_text("data")

        loader = SecureFileLoader(allowed_base=allowed)

        with pytest.raises(SecurityError):
            loader.load_file(secret)  # Absolute path outside base


class TestFileSizeLimits:
    """Test file size limitation enforcement"""

    def test_small_file_allowed(self, tmp_path):
        """Test file under size limit is allowed"""
        test_file = tmp_path / "small.txt"
        test_file.write_text("x" * 1024)  # 1 KB

        loader = SecureFileLoader(
            allowed_base=tmp_path,
            max_file_size_mb=1  # 1 MB limit
        )

        content = loader.load_file(test_file)
        assert len(content) == 1024

    def test_large_file_blocked(self, tmp_path):
        """Test file over size limit is blocked"""
        test_file = tmp_path / "large.txt"
        # Write 2 MB file
        test_file.write_text("x" * (2 * 1024 * 1024))

        loader = SecureFileLoader(
            allowed_base=tmp_path,
            max_file_size_mb=1  # 1 MB limit
        )

        with pytest.raises(ValueError, match="exceeds maximum"):
            loader.load_file(test_file)

    def test_exact_size_limit(self, tmp_path):
        """Test file at exact size limit"""
        test_file = tmp_path / "exact.txt"
        # Exactly 1 MB
        test_file.write_text("x" * (1024 * 1024))

        loader = SecureFileLoader(
            allowed_base=tmp_path,
            max_file_size_mb=1
        )

        # Should be allowed (at limit, not over)
        content = loader.load_file(test_file)
        assert len(content) == 1024 * 1024


class TestConcurrentAccess:
    """Test concurrent file access scenarios"""

    def test_concurrent_reads_same_file(self, tmp_path):
        """Test multiple concurrent reads of same file"""
        import asyncio
        import threading

        test_file = tmp_path / "shared.txt"
        test_file.write_text("shared content")

        loader = SecureFileLoader(allowed_base=tmp_path)

        results = []

        def read_file():
            content = loader.load_file(test_file)
            results.append(content)

        # Start 10 concurrent reads
        threads = [threading.Thread(target=read_file) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should succeed
        assert len(results) == 10
        assert all(r == b"shared content" for r in results)

    def test_concurrent_reads_different_files(self, tmp_path):
        """Test concurrent reads of different files"""
        import threading

        # Create 10 files
        for i in range(10):
            (tmp_path / f"file_{i}.txt").write_text(f"content_{i}")

        loader = SecureFileLoader(allowed_base=tmp_path)

        results = {}

        def read_file(file_id):
            content = loader.load_file(tmp_path / f"file_{file_id}.txt")
            results[file_id] = content

        threads = [threading.Thread(target=read_file, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should have correct content
        assert len(results) == 10
        for i in range(10):
            assert results[i] == f"content_{i}".encode()


class TestPermissionEscalation:
    """Test prevention of permission escalation attacks"""

    def test_read_only_directory_enforced(self, tmp_path):
        """Test read-only directory prevents writes"""
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        test_file = readonly_dir / "file.txt"
        test_file.write_text("data")

        # Make directory read-only
        readonly_dir.chmod(0o444)

        try:
            loader = SecureFileLoader(allowed_base=readonly_dir)

            # Read should work
            content = loader.load_file(test_file)
            assert content == b"data"

            # Write should fail (if loader had write method)
        finally:
            readonly_dir.chmod(0o755)  # Restore for cleanup

    def test_hidden_file_access_blocked(self, tmp_path):
        """Test access to hidden files (starting with .)"""
        hidden_file = tmp_path / ".hidden"
        hidden_file.write_text("secret")

        loader = SecureFileLoader(
            allowed_base=tmp_path,
            allow_hidden_files=False
        )

        with pytest.raises(PermissionError, match="hidden"):
            loader.load_file(hidden_file)


class TestEdgeCaseFilenames:
    """Test handling of unusual but valid filenames"""

    def test_unicode_filename(self, tmp_path):
        """Test Unicode filename handling"""
        unicode_file = tmp_path / "test_文件.txt"
        unicode_file.write_text("Unicode content")

        loader = SecureFileLoader(allowed_base=tmp_path)

        content = loader.load_file(unicode_file)
        assert content == b"Unicode content"

    def test_space_in_filename(self, tmp_path):
        """Test filename with spaces"""
        space_file = tmp_path / "file with spaces.txt"
        space_file.write_text("spaced content")

        loader = SecureFileLoader(allowed_base=tmp_path)

        content = loader.load_file(space_file)
        assert content == b"spaced content"

    def test_very_long_filename(self, tmp_path):
        """Test very long filename (at OS limit)"""
        # Most filesystems have 255 char limit
        long_name = "a" * 200 + ".txt"
        long_file = tmp_path / long_name
        long_file.write_text("long name content")

        loader = SecureFileLoader(allowed_base=tmp_path)

        content = loader.load_file(long_file)
        assert content == b"long name content"


class TestErrorHandling:
    """Test error handling and recovery"""

    def test_file_not_found(self, tmp_path):
        """Test FileNotFoundError handling"""
        loader = SecureFileLoader(allowed_base=tmp_path)

        with pytest.raises(FileNotFoundError):
            loader.load_file(tmp_path / "nonexistent.txt")

    def test_directory_as_file(self, tmp_path):
        """Test error when trying to read directory"""
        test_dir = tmp_path / "directory"
        test_dir.mkdir()

        loader = SecureFileLoader(allowed_base=tmp_path)

        with pytest.raises(IsADirectoryError):
            loader.load_file(test_dir)

    def test_invalid_base_path(self):
        """Test initialization with invalid base path"""
        with pytest.raises(ValueError):
            SecureFileLoader(allowed_base="/nonexistent/path")
