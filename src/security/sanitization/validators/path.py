"""Path traversal prevention validator.

Provides comprehensive path traversal detection:
- Directory traversal detection (../)
- URL-encoded traversal detection
- Absolute path detection
- UNC path detection (Windows)

Security:
- Prevents access to files outside allowed directories
- Defense-in-depth with multiple detection patterns
- Platform-aware detection (Unix and Windows)

Author: Artemis (Implementation)
Created: 2025-12-07 (Issue #22: Unified Sanitization)
"""

import os
import posixpath
from pathlib import Path
from typing import Any

from ..base import BaseValidator, Severity, ValidationResult
from ..core.patterns import get_pattern_registry
from ..exceptions import PathTraversalError


class PathValidator(BaseValidator[str]):
    """Validator for path traversal prevention.

    Detects and prevents path traversal attacks by:
    - Checking for directory traversal sequences
    - Detecting URL-encoded traversal
    - Validating against base directory
    - Checking for absolute paths

    Example:
        >>> validator = PathValidator(base_path="/data/uploads")
        >>> result = validator.validate("../../etc/passwd")
        >>> result.is_valid
        False
        >>> result.severity
        <Severity.CRITICAL: 'critical'>
    """

    def __init__(
        self,
        base_path: str | None = None,
        max_length: int = 500,
        allow_absolute: bool = False,
        allow_symlinks: bool = False,
    ):
        """Initialize path validator.

        Args:
            base_path: Base directory for relative path validation (optional)
            max_length: Maximum path length (default 500)
            allow_absolute: Allow absolute paths (default False)
            allow_symlinks: Allow symlinks (default False)
        """
        self.base_path = Path(base_path).resolve() if base_path else None
        self.max_length = max_length
        self.allow_absolute = allow_absolute
        self.allow_symlinks = allow_symlinks
        self._patterns = get_pattern_registry()

    def validate(self, value: Any, **kwargs: Any) -> ValidationResult[str]:
        """Validate path for traversal patterns.

        Args:
            value: The path string to validate
            **kwargs: Override options (base_path, max_length, etc.)

        Returns:
            ValidationResult indicating if path is safe
        """
        # Type check
        if not isinstance(value, str):
            return ValidationResult.failure(
                f"Path must be string, got {type(value).__name__}",
                severity=Severity.CRITICAL,
            )

        # Length check
        max_length = kwargs.get("max_length", self.max_length)
        if len(value) > max_length:
            return ValidationResult.failure(
                f"Path exceeds maximum length of {max_length}",
                severity=Severity.WARNING,
                details={"original_length": len(value)},
            )

        # NULL byte check
        if self._patterns.test("null_bytes", value):
            return ValidationResult.failure(
                "NULL byte detected in path",
                severity=Severity.CRITICAL,
                details={"security_event": "null_byte_injection"},
            )

        # Path traversal pattern check
        if self._patterns.test("path_traversal", value):
            return ValidationResult.failure(
                "Potential path traversal detected",
                severity=Severity.CRITICAL,
                details={
                    "security_event": "path_traversal_attempt",
                    "pattern_matched": "path_traversal",
                },
            )

        # Normalize and check for hidden traversal
        normalized = self._normalize_path(value)
        if normalized is None:
            return ValidationResult.failure(
                "Invalid path format",
                severity=Severity.CRITICAL,
            )

        # Check for traversal after normalization
        if ".." in normalized.split(os.sep):
            return ValidationResult.failure(
                "Path traversal detected after normalization",
                severity=Severity.CRITICAL,
                details={"normalized_path": normalized},
            )

        # Absolute path check
        allow_absolute = kwargs.get("allow_absolute", self.allow_absolute)
        if not allow_absolute and os.path.isabs(value):
            return ValidationResult.failure(
                "Absolute paths not allowed",
                severity=Severity.WARNING,
                details={"path": value},
            )

        # Base path validation
        base_path_str = kwargs.get("base_path")
        base_path = Path(base_path_str).resolve() if base_path_str else self.base_path

        if base_path:
            result = self._validate_within_base(normalized, base_path)
            if not result.is_valid:
                return result

        return ValidationResult.success(normalized)

    def _normalize_path(self, path: str) -> str | None:
        """Normalize a path string safely.

        Args:
            path: Path string to normalize

        Returns:
            Normalized path or None if invalid
        """
        try:
            # URL decode if needed
            path = self._url_decode(path)

            # Replace backslashes with forward slashes
            path = path.replace("\\", "/")

            # Remove null bytes
            path = path.replace("\x00", "")

            # Normalize using posixpath (cross-platform)
            normalized = posixpath.normpath(path)

            # Remove leading slashes for relative path handling
            if not self.allow_absolute:
                normalized = normalized.lstrip("/")

            return normalized

        except (ValueError, TypeError):
            return None

    def _url_decode(self, path: str) -> str:
        """Decode URL-encoded path components.

        Args:
            path: Path that may contain URL encoding

        Returns:
            Decoded path
        """
        # Decode common URL encodings
        replacements = [
            ("%2e", "."),
            ("%2E", "."),
            ("%2f", "/"),
            ("%2F", "/"),
            ("%5c", "\\"),
            ("%5C", "\\"),
            ("%00", ""),  # NULL byte
        ]
        result = path
        for encoded, decoded in replacements:
            result = result.replace(encoded, decoded)
        return result

    def _validate_within_base(
        self, path: str, base_path: Path
    ) -> ValidationResult[str]:
        """Validate that path stays within base directory.

        Args:
            path: Normalized path to validate
            base_path: Base directory

        Returns:
            ValidationResult
        """
        try:
            # Resolve the full path
            full_path = (base_path / path).resolve()

            # Check if resolved path is within base
            try:
                full_path.relative_to(base_path)
            except ValueError:
                return ValidationResult.failure(
                    "Path escapes base directory",
                    severity=Severity.CRITICAL,
                    details={
                        "security_event": "path_escape_attempt",
                        "base_path": str(base_path),
                        "resolved_path": str(full_path),
                    },
                )

            # Symlink check
            if (
                not self.allow_symlinks
                and full_path.exists()
                and full_path.is_symlink()
            ):
                return ValidationResult.failure(
                    "Symlinks not allowed",
                    severity=Severity.WARNING,
                    details={"path": str(full_path)},
                )

            return ValidationResult.success(path)

        except (OSError, ValueError) as e:
            return ValidationResult.failure(
                f"Path validation error: {e}",
                severity=Severity.CRITICAL,
            )

    def get_validation_rules(self) -> dict[str, Any]:
        """Return validation rules for documentation/audit.

        Returns:
            Dictionary describing the validation rules
        """
        return {
            "type": "path",
            "max_length": self.max_length,
            "base_path": str(self.base_path) if self.base_path else None,
            "allow_absolute": self.allow_absolute,
            "allow_symlinks": self.allow_symlinks,
            "blocked_patterns": [
                "Directory traversal (../)",
                "URL-encoded traversal (%2e%2e/)",
                "UNC paths (\\\\)",
                "Null bytes",
            ],
        }


def validate_path_safe(
    path: str,
    base_path: str | None = None,
    raise_on_traversal: bool = True,
) -> str:
    """Convenience function for quick path validation.

    Args:
        path: Path string to validate
        base_path: Base directory for validation
        raise_on_traversal: Raise exception on traversal (default True)

    Returns:
        Normalized path if safe

    Raises:
        PathTraversalError: If traversal detected and raise_on_traversal is True
    """
    validator = PathValidator(base_path=base_path)
    result = validator.validate(path)

    if not result.is_valid:
        if raise_on_traversal and result.severity == Severity.CRITICAL:
            raise PathTraversalError(result.error_message or "Path traversal detected")
        # Return sanitized or empty
        return result.sanitized_value or ""

    return result.sanitized_value or path
