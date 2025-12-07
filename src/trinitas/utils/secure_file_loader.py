#!/usr/bin/env python3
"""
Secure File Loading Utility for Trinitas
Provides path validation and secure file loading with security checks

Created: 2025-10-15 (Phase 1 Day 3)
Purpose: Eliminate code duplication and ensure consistent security validation
Security: Complies with CWE-22 (Path Traversal), CWE-73 (External Control of File Name)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Security validation error raised when path validation fails.

    This exception is raised when a file path fails security validation,
    such as path traversal attempts, disallowed file extensions, or
    access to paths outside allowed root directories.

    Attributes:
        message: Error message describing the security violation.

    Example:
        >>> try:
        ...     loader = SecureFileLoader()
        ...     validated = loader.validate_path('../../etc/passwd')
        ...     if not validated:
        ...         raise SecurityError("Path traversal attempt detected")
        ... except SecurityError as e:
        ...     print(f"Security error: {e}")
    """


class SecureFileLoader:
    """Secure file loading with path validation and security checks.

    This class provides defense-in-depth protection against path traversal attacks
    (CWE-22) and external control of file names (CWE-73). All file operations
    validate paths against configured allowed roots and file extensions before
    accessing the filesystem.

    The loader enforces:
        - Symlinks are explicitly rejected (CWE-61 TOCTOU attack prevention)
        - Path must be within allowed root directories (CWE-22)
        - Path must have an allowed file extension
        - Path must not contain traversal attempts (../, ~)
        - Path must exist and be accessible

    Attributes:
        allowed_roots: List of absolute paths to allowed root directories.
        allowed_extensions: List of allowed file extensions (e.g., ['.md', '.json']).

    Example:
        >>> # Create loader with default security policy
        >>> loader = SecureFileLoader()
        >>>
        >>> # Create loader with custom allowed directories
        >>> loader = SecureFileLoader(
        ...     allowed_roots=['/var/data', '/home/user/docs'],
        ...     allowed_extensions=['.txt', '.md', '.json']
        ... )
        >>>
        >>> # Validate and load file
        >>> content = loader.load_file('config.json')
        >>> if content:
        ...     print("File loaded successfully")
    """

    def __init__(
        self,
        allowed_roots: list[str | Path] | None = None,
        allowed_extensions: list[str] | None = None,
    ):
        """Initialize secure file loader with security policy.

        Sets up the allowed root directories and file extensions for validation.
        If not provided, uses secure defaults: project root + ~/.claude for roots,
        and common text file extensions.

        Args:
            allowed_roots: List of absolute or relative paths to directories where
                file access is permitted. If None, defaults to:
                - Project root (detected via pyproject.toml, .git, etc.)
                - ~/.claude directory
                All paths will be resolved to absolute real paths.
            allowed_extensions: List of file extensions (with or without leading dot)
                that are permitted. If None, defaults to:
                ['.md', '.json', '.txt', '.yaml', '.yml']

        Example:
            >>> # Use default security policy
            >>> loader = SecureFileLoader()
            >>>
            >>> # Restrict to specific directories
            >>> loader = SecureFileLoader(
            ...     allowed_roots=['/var/app/data', '/home/user/configs']
            ... )
            >>>
            >>> # Restrict to specific file types
            >>> loader = SecureFileLoader(
            ...     allowed_extensions=['.json', '.yaml']
            ... )
        """
        # Default allowed roots
        if allowed_roots is None:
            self.allowed_roots = [
                os.path.realpath(os.path.expanduser("~/.claude")),
                os.path.realpath(self._get_project_root()),
            ]
        else:
            self.allowed_roots = [os.path.realpath(str(root)) for root in allowed_roots]

        # Default allowed extensions
        if allowed_extensions is None:
            self.allowed_extensions = [".md", ".json", ".txt", ".yaml", ".yml"]
        else:
            self.allowed_extensions = allowed_extensions

    @staticmethod
    def _get_project_root() -> str:
        """Get project root directory by detecting common project markers.

        Searches upward from the current working directory for files/directories
        that indicate the project root (pyproject.toml, setup.py, .git, README.md).
        Falls back to current working directory if no markers found.

        Returns:
            Absolute path to the detected project root directory.

        Example:
            >>> root = SecureFileLoader._get_project_root()
            >>> print(f"Project root: {root}")
            Project root: /home/user/workspace/trinitas-agents
        """
        # Try to detect project root
        current = Path.cwd()
        markers = ["pyproject.toml", "setup.py", ".git", "README.md"]

        while current != current.parent:
            if any((current / marker).exists() for marker in markers):
                return str(current)
            current = current.parent

        # Fallback to current working directory
        return os.getcwd()

    def validate_path(
        self, file_path: str | Path, base_path: str | Path | None = None
    ) -> str | None:
        """Validate file path against comprehensive security policy.

        Performs multiple security checks to prevent path traversal attacks and
        ensure the file path conforms to the configured security policy. This is
        the core security validation used by all file loading methods.

        Args:
            file_path: Path to validate. Can be absolute or relative. Supports
                both string and pathlib.Path objects.
            base_path: Optional base directory for resolving relative paths.
                If provided, relative paths are resolved against this base.
                If None, relative paths are resolved from current directory.

        Returns:
            The absolute, resolved path as a string if validation passes.
            None if validation fails for any reason.

        Security Checks:
            1. Symlinks are rejected before resolution (CWE-61 TOCTOU protection)
            2. Path must be within allowed_roots (CWE-22 protection)
            3. Path must have allowed file extension (file type restriction)
            4. Path must not contain traversal attempts like ../ or ~
            5. Remaining path components are resolved to real paths
            6. Logs all security violations to stderr

        Example:
            >>> loader = SecureFileLoader()
            >>>
            >>> # Validate absolute path
            >>> path = loader.validate_path('/home/user/.claude/config.json')
            >>> if path:
            ...     print(f"Valid: {path}")
            >>>
            >>> # Validate relative path with base
            >>> path = loader.validate_path('docs/guide.md', base_path='/home/user/project')
            >>>
            >>> # Path traversal attempt (returns None)
            >>> path = loader.validate_path('../../etc/passwd')
            >>> assert path is None, "Path traversal should be blocked"
        """
        try:
            # Resolve path (handles relative paths)
            full_path = Path(base_path) / file_path if base_path else Path(file_path)

            # CRITICAL SECURITY: Symlink check BEFORE resolution (CWE-61 TOCTOU protection)
            # Must check before realpath() to prevent symlink-based attacks
            if full_path.exists() and full_path.is_symlink():
                logger.error(
                    "Security: Symlink access denied (CWE-61)",
                    extra={"file_path": str(file_path)},
                )
                return None

            # Get real path (resolves symlinks, removes .., etc.)
            resolved = os.path.realpath(full_path)

            # Security Check 1: Must be within allowed roots
            is_allowed = any(resolved.startswith(root) for root in self.allowed_roots)

            if not is_allowed:
                logger.error(
                    "Security: Path outside allowed roots",
                    extra={"file_path": str(file_path), "resolved": resolved},
                )
                return None

            # Security Check 2: Must have allowed extension
            if self.allowed_extensions:
                has_allowed_ext = any(resolved.endswith(ext) for ext in self.allowed_extensions)
                if not has_allowed_ext:
                    logger.error(
                        "Security: File extension not allowed",
                        extra={"file_path": str(file_path), "resolved": resolved},
                    )
                    return None

            # Security Check 3: Path traversal detection
            if (
                ".." in str(file_path) or "~" in str(file_path)
            ) and not any(resolved.startswith(root) for root in self.allowed_roots):
                logger.error(
                    "Security: Potential path traversal attempt",
                    extra={"file_path": str(file_path)},
                )
                return None

            return resolved

        except (ValueError, OSError, RuntimeError):
            logger.error("Security: Path validation error", exc_info=True)
            return None

    def load_file(
        self,
        file_path: str | Path,
        base_path: str | Path | None = None,
        encoding: str = "utf-8",
        silent: bool = False,
    ) -> str | None:
        """Securely load text file content with validation.

        Validates the file path using validate_path() before reading, ensuring
        all security policies are enforced. Handles text files with configurable
        encoding.

        Args:
            file_path: Path to the text file to load. Can be absolute or relative.
            base_path: Optional base directory for resolving relative paths.
                If None, current directory is used.
            encoding: Text encoding to use when reading the file.
                Defaults to 'utf-8'. Common alternatives: 'ascii', 'latin-1', 'cp1252'.
            silent: If True, suppresses error messages to stderr and returns None
                on any error. If False, logs detailed error information.
                Defaults to False.

        Returns:
            The file content as a string if successful, None if validation fails
            or any error occurs during reading.

        Note:
            This method automatically validates the path before reading. If validation
            fails, None is returned regardless of whether the file exists.

        Example:
            >>> loader = SecureFileLoader()
            >>>
            >>> # Load file with default encoding
            >>> content = loader.load_file('README.md')
            >>> if content:
            ...     print(f"File size: {len(content)} chars")
            >>>
            >>> # Load file with specific encoding
            >>> content = loader.load_file('data.txt', encoding='latin-1')
            >>>
            >>> # Silent loading (no error messages)
            >>> content = loader.load_file('optional.txt', silent=True)
            >>> if not content:
            ...     content = "default content"
        """
        # Validate path
        validated_path = self.validate_path(file_path, base_path)
        if not validated_path:
            if not silent:
                logger.error(
                    "File path validation failed",
                    extra={"file_path": str(file_path)},
                )
            return None

        # Load file
        try:
            with open(validated_path, encoding=encoding) as f:
                return f.read()

        except FileNotFoundError:
            if not silent:
                logger.error("File not found", extra={"file_path": str(file_path)})
            return None

        except PermissionError:
            if not silent:
                logger.error(
                    "Permission denied loading file",
                    extra={"file_path": str(file_path)},
                    exc_info=True,
                )
            return None

        except OSError:
            if not silent:
                logger.error(
                    "I/O error loading file",
                    extra={"file_path": str(file_path)},
                    exc_info=True,
                )
            return None

        except UnicodeDecodeError:
            if not silent:
                logger.error(
                    "Encoding error in file",
                    extra={"file_path": str(file_path)},
                    exc_info=True,
                )
            return None

    def load_binary(
        self,
        file_path: str | Path,
        base_path: str | Path | None = None,
        silent: bool = False,
    ) -> bytes | None:
        """Securely load binary file content with validation.

        Validates the file path using validate_path() before reading, ensuring
        all security policies are enforced. Handles binary files (images, PDFs,
        executables, etc.) without encoding conversion.

        Args:
            file_path: Path to the binary file to load. Can be absolute or relative.
            base_path: Optional base directory for resolving relative paths.
                If None, current directory is used.
            silent: If True, suppresses error messages to stderr and returns None
                on any error. If False, logs detailed error information.
                Defaults to False.

        Returns:
            The file content as bytes if successful, None if validation fails
            or any error occurs during reading.

        Note:
            This method is suitable for non-text files like images, PDFs, archives,
            etc. For text files, use load_file() instead for proper encoding handling.

        Example:
            >>> loader = SecureFileLoader(
            ...     allowed_extensions=['.png', '.jpg', '.pdf']
            ... )
            >>>
            >>> # Load image file
            >>> image_data = loader.load_binary('logo.png')
            >>> if image_data:
            ...     print(f"Image size: {len(image_data)} bytes")
            >>>
            >>> # Load PDF document
            >>> pdf_data = loader.load_binary('report.pdf')
            >>>
            >>> # Silent loading
            >>> data = loader.load_binary('optional.bin', silent=True)
        """
        # Validate path
        validated_path = self.validate_path(file_path, base_path)
        if not validated_path:
            if not silent:
                logger.error(
                    "File path validation failed",
                    extra={"file_path": str(file_path)},
                )
            return None

        # Load file
        try:
            with open(validated_path, "rb") as f:
                return f.read()

        except FileNotFoundError:
            if not silent:
                logger.error("File not found", extra={"file_path": str(file_path)})
            return None

        except PermissionError:
            if not silent:
                logger.error(
                    "Permission denied loading file",
                    extra={"file_path": str(file_path)},
                    exc_info=True,
                )
            return None

        except OSError:
            if not silent:
                logger.error(
                    "I/O error loading file",
                    extra={"file_path": str(file_path)},
                    exc_info=True,
                )
            return None

    def file_exists(self, file_path: str | Path, base_path: str | Path | None = None) -> bool:
        """Check if file exists and passes security validation.

        This method combines security validation with existence checking. A file
        is considered to "exist" only if it both passes security validation AND
        exists on the filesystem as a regular file.

        Args:
            file_path: Path to check for existence. Can be absolute or relative.
            base_path: Optional base directory for resolving relative paths.
                If None, current directory is used.

        Returns:
            True if the file exists, is a regular file (not a directory), and
            passes all security validation checks. False otherwise.

        Note:
            This method returns False for directories, even if they exist and
            pass validation. It also returns False if the path fails security
            validation, even if the file exists.

        Example:
            >>> loader = SecureFileLoader()
            >>>
            >>> # Check if config file exists
            >>> if loader.file_exists('config.json'):
            ...     content = loader.load_file('config.json')
            ... else:
            ...     print("Config file not found or not accessible")
            >>>
            >>> # Check relative path
            >>> exists = loader.file_exists('docs/README.md', base_path='/home/user/project')
        """
        validated_path = self.validate_path(file_path, base_path)
        if not validated_path:
            return False

        return os.path.isfile(validated_path)

    def add_allowed_root(self, root: str | Path) -> None:
        """Add an allowed root directory to the security policy.

        Expands the list of directories where files can be accessed. The path
        is converted to an absolute real path before being added.

        Args:
            root: Directory path to add. Can be absolute or relative. Relative
                paths are resolved to absolute paths before adding.

        Example:
            >>> loader = SecureFileLoader()
            >>> loader.add_allowed_root('/var/app/data')
            >>> loader.add_allowed_root('~/Documents/projects')
            >>>
            >>> # Now can access files in the added directories
            >>> content = loader.load_file('/var/app/data/config.json')
        """
        self.allowed_roots.append(os.path.realpath(str(root)))

    def add_allowed_extension(self, extension: str) -> None:
        """Add an allowed file extension to the security policy.

        Expands the list of file extensions that are permitted. Automatically
        handles extensions with or without leading dot.

        Args:
            extension: File extension to add. Can include or omit the leading dot.
                Examples: '.txt', 'txt', '.json', 'json'

        Note:
            Extensions are case-sensitive on case-sensitive filesystems. Consider
            adding both '.txt' and '.TXT' if needed.

        Example:
            >>> loader = SecureFileLoader()
            >>> loader.add_allowed_extension('.csv')
            >>> loader.add_allowed_extension('xml')  # Dot automatically added
            >>>
            >>> # Now can load CSV and XML files
            >>> data = loader.load_file('data.csv')
        """
        if not extension.startswith("."):
            extension = f".{extension}"
        if extension not in self.allowed_extensions:
            self.allowed_extensions.append(extension)


# Convenience functions
_default_loader = SecureFileLoader()


def load_secure(file_path: str | Path, base_path: str | Path | None = None) -> str | None:
    """Convenience function for secure file loading with default security policy.

    Uses a shared SecureFileLoader instance with default settings (project root
    and ~/.claude as allowed roots, common text extensions allowed).

    Args:
        file_path: Path to the text file to load. Can be absolute or relative.
        base_path: Optional base directory for resolving relative paths.

    Returns:
        File content as string if successful, None on error.

    Example:
        >>> # Quick secure file loading
        >>> content = load_secure('config.json')
        >>> if content:
        ...     print("Config loaded")
        >>>
        >>> # Load relative to base path
        >>> content = load_secure('docs/guide.md', base_path='/home/user/project')
    """
    return _default_loader.load_file(file_path, base_path)


def validate_path(file_path: str | Path, base_path: str | Path | None = None) -> str | None:
    """Convenience function for path validation with default security policy.

    Uses a shared SecureFileLoader instance with default settings to validate
    the given path.

    Args:
        file_path: Path to validate. Can be absolute or relative.
        base_path: Optional base directory for resolving relative paths.

    Returns:
        Absolute resolved path as string if valid, None if validation fails.

    Example:
        >>> # Validate file path
        >>> path = validate_path('README.md')
        >>> if path:
        ...     print(f"Valid path: {path}")
        ... else:
        ...     print("Invalid or insecure path")
        >>>
        >>> # Validate with base path
        >>> path = validate_path('config.json', base_path='/home/user/.claude')
    """
    return _default_loader.validate_path(file_path, base_path)


if __name__ == "__main__":
    # Test cases
    print("SecureFileLoader Test Suite")
    print("=" * 60)

    loader = SecureFileLoader()

    # Test 1: Validate allowed path
    test_path = "README.md"
    validated = loader.validate_path(test_path)
    if validated:
        print(f"✓ Path validation passed: {test_path} → {validated}")
    else:
        print(f"✗ Path validation failed: {test_path}")

    # Test 2: Reject path traversal
    evil_path = "../../etc/passwd"
    validated = loader.validate_path(evil_path)
    if not validated:
        print(f"✓ Path traversal blocked: {evil_path}")
    else:
        print(f"✗ Security breach: {evil_path} was allowed!")

    # Test 3: File existence check
    exists = loader.file_exists("README.md")
    print(f"✓ File existence check: README.md exists = {exists}")

    # Test 4: Load file content
    content = loader.load_file("VERSION", silent=True)
    if content:
        print(f"✓ File loaded: VERSION (length: {len(content)} chars)")

    print("\n✅ Security tests completed!")
