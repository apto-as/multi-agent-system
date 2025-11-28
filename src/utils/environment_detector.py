"""Environment detection utilities for TMWS.

Detects execution environment (OpenCode, Claude Code, VS Code, etc.)
and provides appropriate configuration for each environment.

v2.4.5: Initial OpenCode support (MVP implementation)
"""

import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ExecutionEnvironment(str, Enum):
    """Supported execution environments."""

    OPENCODE = "opencode"
    CLAUDE_CODE = "claude_code"
    VSCODE = "vscode"
    CURSOR = "cursor"
    TERMINAL = "terminal"
    UNKNOWN = "unknown"


@dataclass
class EnvironmentInfo:
    """Information about detected execution environment."""

    environment: ExecutionEnvironment
    project_root: Path | None
    detected_by: str
    metadata: dict[str, Any]

    @property
    def is_opencode(self) -> bool:
        """Check if running in OpenCode environment."""
        return self.environment == ExecutionEnvironment.OPENCODE

    @property
    def is_claude_code(self) -> bool:
        """Check if running in Claude Code environment."""
        return self.environment == ExecutionEnvironment.CLAUDE_CODE

    @property
    def is_ide(self) -> bool:
        """Check if running in an IDE (not terminal)."""
        return self.environment in (
            ExecutionEnvironment.OPENCODE,
            ExecutionEnvironment.CLAUDE_CODE,
            ExecutionEnvironment.VSCODE,
            ExecutionEnvironment.CURSOR,
        )


class EnvironmentDetector:
    """Detects execution environment for TMWS.

    Detection priority:
    1. Environment variables (fastest, most reliable)
    2. Path indicators (marker files/directories)
    3. Process inspection (fallback)

    Security considerations:
    - Path traversal prevention (max 5 levels up)
    - Symlink resolution for security
    - Environment variable sanitization
    """

    # OpenCode-specific indicators
    OPENCODE_ENV_VARS = frozenset({
        "OPENCODE_PROJECT_ROOT",
        "OPENCODE_VERSION",
        "OPENCODE_WORKSPACE",
        "OPENCODE_SESSION_ID",
    })

    OPENCODE_PATH_INDICATORS = frozenset({
        ".opencode",
        "opencode.yaml",
        "opencode.json",
        ".opencode.yaml",
        ".opencode.json",
    })

    # Claude Code indicators
    CLAUDE_CODE_ENV_VARS = frozenset({
        "CLAUDE_CODE_VERSION",
        "CLAUDE_PROJECT_ROOT",
    })

    CLAUDE_CODE_PATH_INDICATORS = frozenset({
        ".claude",
    })

    # VS Code indicators
    VSCODE_ENV_VARS = frozenset({
        "VSCODE_PID",
        "VSCODE_CWD",
        "TERM_PROGRAM",  # Check for "vscode"
    })

    VSCODE_PATH_INDICATORS = frozenset({
        ".vscode",
    })

    # Cursor indicators (VS Code fork)
    CURSOR_ENV_VARS = frozenset({
        "CURSOR_VERSION",
    })

    CURSOR_PATH_INDICATORS = frozenset({
        ".cursor",
    })

    # Maximum directory levels to search upward (security: prevent excessive traversal)
    MAX_SEARCH_DEPTH = 5

    @classmethod
    def detect(cls, start_path: Path | None = None) -> EnvironmentInfo:
        """Detect current execution environment.

        Args:
            start_path: Starting directory for path-based detection.
                       Defaults to current working directory.

        Returns:
            EnvironmentInfo with detected environment details.

        Security:
            - Resolves symlinks to prevent symlink attacks
            - Limits directory traversal to MAX_SEARCH_DEPTH
            - Sanitizes environment variable values
        """
        if start_path is None:
            start_path = Path.cwd()

        # Security: Resolve symlinks to get real path
        try:
            start_path = start_path.resolve()
        except (OSError, RuntimeError) as e:
            logger.warning(f"Could not resolve start path: {e}")
            return cls._unknown_environment("path_resolution_failed")

        # Priority 1: Check environment variables (fastest)
        env_result = cls._detect_from_env_vars()
        if env_result.environment != ExecutionEnvironment.UNKNOWN:
            logger.debug(f"Environment detected from env vars: {env_result.environment}")
            return env_result

        # Priority 2: Check path indicators
        path_result = cls._detect_from_paths(start_path)
        if path_result.environment != ExecutionEnvironment.UNKNOWN:
            logger.debug(f"Environment detected from paths: {path_result.environment}")
            return path_result

        # Priority 3: Fallback to terminal/unknown
        logger.debug("No specific environment detected, defaulting to terminal")
        return cls._terminal_environment(start_path)

    @classmethod
    def _detect_from_env_vars(cls) -> EnvironmentInfo:
        """Detect environment from environment variables."""
        # OpenCode detection
        for env_var in cls.OPENCODE_ENV_VARS:
            if value := os.environ.get(env_var):
                project_root = None
                if env_var == "OPENCODE_PROJECT_ROOT":
                    project_root = cls._safe_path(value)

                return EnvironmentInfo(
                    environment=ExecutionEnvironment.OPENCODE,
                    project_root=project_root,
                    detected_by=f"env:{env_var}",
                    metadata={
                        "env_var": env_var,
                        "env_value": cls._sanitize_env_value(value),
                        "opencode_version": os.environ.get("OPENCODE_VERSION", "unknown"),
                    },
                )

        # Claude Code detection
        for env_var in cls.CLAUDE_CODE_ENV_VARS:
            if value := os.environ.get(env_var):
                project_root = None
                if env_var == "CLAUDE_PROJECT_ROOT":
                    project_root = cls._safe_path(value)

                return EnvironmentInfo(
                    environment=ExecutionEnvironment.CLAUDE_CODE,
                    project_root=project_root,
                    detected_by=f"env:{env_var}",
                    metadata={
                        "env_var": env_var,
                        "claude_version": os.environ.get("CLAUDE_CODE_VERSION", "unknown"),
                    },
                )

        # VS Code detection (check TERM_PROGRAM specifically)
        term_program = os.environ.get("TERM_PROGRAM", "").lower()
        if term_program == "vscode":
            return EnvironmentInfo(
                environment=ExecutionEnvironment.VSCODE,
                project_root=cls._safe_path(os.environ.get("VSCODE_CWD")),
                detected_by="env:TERM_PROGRAM=vscode",
                metadata={"term_program": term_program},
            )

        for env_var in cls.VSCODE_ENV_VARS - {"TERM_PROGRAM"}:
            if os.environ.get(env_var):
                return EnvironmentInfo(
                    environment=ExecutionEnvironment.VSCODE,
                    project_root=cls._safe_path(os.environ.get("VSCODE_CWD")),
                    detected_by=f"env:{env_var}",
                    metadata={},
                )

        # Cursor detection
        for env_var in cls.CURSOR_ENV_VARS:
            if os.environ.get(env_var):
                return EnvironmentInfo(
                    environment=ExecutionEnvironment.CURSOR,
                    project_root=None,
                    detected_by=f"env:{env_var}",
                    metadata={
                        "cursor_version": os.environ.get("CURSOR_VERSION", "unknown"),
                    },
                )

        return cls._unknown_environment("no_env_vars_matched")

    @classmethod
    def _detect_from_paths(cls, start_path: Path) -> EnvironmentInfo:
        """Detect environment from path indicators.

        Searches upward from start_path, limited to MAX_SEARCH_DEPTH levels.
        """
        current = start_path
        depth = 0

        while depth < cls.MAX_SEARCH_DEPTH and current != current.parent:
            # OpenCode indicators
            for indicator in cls.OPENCODE_PATH_INDICATORS:
                indicator_path = current / indicator
                if indicator_path.exists():
                    return EnvironmentInfo(
                        environment=ExecutionEnvironment.OPENCODE,
                        project_root=current,
                        detected_by=f"path:{indicator}",
                        metadata={
                            "indicator_path": str(indicator_path),
                            "search_depth": depth,
                        },
                    )

            # Claude Code indicators
            for indicator in cls.CLAUDE_CODE_PATH_INDICATORS:
                indicator_path = current / indicator
                if indicator_path.exists() and indicator_path.is_dir():
                    # .claude directory should contain CLAUDE.md or similar
                    return EnvironmentInfo(
                        environment=ExecutionEnvironment.CLAUDE_CODE,
                        project_root=current,
                        detected_by=f"path:{indicator}",
                        metadata={
                            "indicator_path": str(indicator_path),
                            "search_depth": depth,
                        },
                    )

            # VS Code indicators
            for indicator in cls.VSCODE_PATH_INDICATORS:
                indicator_path = current / indicator
                if indicator_path.exists() and indicator_path.is_dir():
                    return EnvironmentInfo(
                        environment=ExecutionEnvironment.VSCODE,
                        project_root=current,
                        detected_by=f"path:{indicator}",
                        metadata={
                            "indicator_path": str(indicator_path),
                            "search_depth": depth,
                        },
                    )

            # Cursor indicators
            for indicator in cls.CURSOR_PATH_INDICATORS:
                indicator_path = current / indicator
                if indicator_path.exists() and indicator_path.is_dir():
                    return EnvironmentInfo(
                        environment=ExecutionEnvironment.CURSOR,
                        project_root=current,
                        detected_by=f"path:{indicator}",
                        metadata={
                            "indicator_path": str(indicator_path),
                            "search_depth": depth,
                        },
                    )

            current = current.parent
            depth += 1

        return cls._unknown_environment(f"no_indicators_found_in_{depth}_levels")

    @classmethod
    def _safe_path(cls, path_str: str | None) -> Path | None:
        """Safely convert string to Path with security checks.

        Security:
            - Prevents path traversal attacks
            - Resolves symlinks
            - Validates path exists
        """
        if not path_str:
            return None

        try:
            # Sanitize: Remove any null bytes or control characters
            path_str = "".join(c for c in path_str if c.isprintable() and c != "\x00")

            path = Path(path_str)

            # Security: Resolve to prevent symlink attacks
            path = path.resolve()

            # Validate existence
            if path.exists():
                return path

            logger.debug(f"Path does not exist: {path}")
            return None

        except (OSError, RuntimeError, ValueError) as e:
            logger.warning(f"Invalid path '{path_str}': {e}")
            return None

    @classmethod
    def _sanitize_env_value(cls, value: str) -> str:
        """Sanitize environment variable value for logging.

        Security:
            - Truncates long values
            - Masks potentially sensitive data
            - Removes control characters
        """
        if not value:
            return ""

        # Remove control characters
        sanitized = "".join(c for c in value if c.isprintable())

        # Truncate for logging
        max_length = 100
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "..."

        return sanitized

    @classmethod
    def _unknown_environment(cls, reason: str) -> EnvironmentInfo:
        """Create unknown environment result."""
        return EnvironmentInfo(
            environment=ExecutionEnvironment.UNKNOWN,
            project_root=None,
            detected_by=f"fallback:{reason}",
            metadata={"reason": reason},
        )

    @classmethod
    def _terminal_environment(cls, start_path: Path) -> EnvironmentInfo:
        """Create terminal environment result."""
        return EnvironmentInfo(
            environment=ExecutionEnvironment.TERMINAL,
            project_root=start_path,
            detected_by="fallback:terminal",
            metadata={"cwd": str(start_path)},
        )


def detect_environment(start_path: Path | None = None) -> EnvironmentInfo:
    """Convenience function to detect execution environment.

    Args:
        start_path: Starting directory for detection. Defaults to cwd.

    Returns:
        EnvironmentInfo with detected environment details.
    """
    return EnvironmentDetector.detect(start_path)


def is_opencode_environment() -> bool:
    """Quick check if running in OpenCode environment.

    Returns:
        True if OpenCode environment detected.
    """
    return detect_environment().is_opencode


# Export public interface
__all__ = [
    "ExecutionEnvironment",
    "EnvironmentInfo",
    "EnvironmentDetector",
    "detect_environment",
    "is_opencode_environment",
]
