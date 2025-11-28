"""Tests for environment detection utilities.

v2.4.5: OpenCode environment detection tests.
"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from src.utils.environment_detector import (
    EnvironmentDetector,
    EnvironmentInfo,
    ExecutionEnvironment,
    detect_environment,
    is_opencode_environment,
)


class TestExecutionEnvironment:
    """Tests for ExecutionEnvironment enum."""

    def test_enum_values(self):
        """Test all expected environment values exist."""
        assert ExecutionEnvironment.OPENCODE.value == "opencode"
        assert ExecutionEnvironment.CLAUDE_CODE.value == "claude_code"
        assert ExecutionEnvironment.VSCODE.value == "vscode"
        assert ExecutionEnvironment.CURSOR.value == "cursor"
        assert ExecutionEnvironment.TERMINAL.value == "terminal"
        assert ExecutionEnvironment.UNKNOWN.value == "unknown"


class TestEnvironmentInfo:
    """Tests for EnvironmentInfo dataclass."""

    def test_is_opencode_true(self):
        """Test is_opencode returns True for OpenCode environment."""
        info = EnvironmentInfo(
            environment=ExecutionEnvironment.OPENCODE,
            project_root=Path("/test"),
            detected_by="test",
            metadata={},
        )
        assert info.is_opencode is True

    def test_is_opencode_false(self):
        """Test is_opencode returns False for other environments."""
        info = EnvironmentInfo(
            environment=ExecutionEnvironment.VSCODE,
            project_root=Path("/test"),
            detected_by="test",
            metadata={},
        )
        assert info.is_opencode is False

    def test_is_claude_code(self):
        """Test is_claude_code property."""
        info = EnvironmentInfo(
            environment=ExecutionEnvironment.CLAUDE_CODE,
            project_root=Path("/test"),
            detected_by="test",
            metadata={},
        )
        assert info.is_claude_code is True

    def test_is_ide_true_for_opencode(self):
        """Test is_ide returns True for IDE environments."""
        for env in [
            ExecutionEnvironment.OPENCODE,
            ExecutionEnvironment.CLAUDE_CODE,
            ExecutionEnvironment.VSCODE,
            ExecutionEnvironment.CURSOR,
        ]:
            info = EnvironmentInfo(
                environment=env,
                project_root=Path("/test"),
                detected_by="test",
                metadata={},
            )
            assert info.is_ide is True, f"Expected is_ide=True for {env}"

    def test_is_ide_false_for_terminal(self):
        """Test is_ide returns False for terminal/unknown."""
        for env in [ExecutionEnvironment.TERMINAL, ExecutionEnvironment.UNKNOWN]:
            info = EnvironmentInfo(
                environment=env,
                project_root=None,
                detected_by="test",
                metadata={},
            )
            assert info.is_ide is False, f"Expected is_ide=False for {env}"


class TestEnvironmentDetectorEnvVars:
    """Tests for environment variable detection."""

    def test_detect_opencode_from_project_root_env(self):
        """Test OpenCode detection from OPENCODE_PROJECT_ROOT."""
        with patch.dict(os.environ, {"OPENCODE_PROJECT_ROOT": "/test/project"}, clear=False):
            with patch.object(Path, "exists", return_value=True):
                with patch.object(Path, "resolve", return_value=Path("/test/project")):
                    result = EnvironmentDetector._detect_from_env_vars()

        assert result.environment == ExecutionEnvironment.OPENCODE
        assert result.detected_by == "env:OPENCODE_PROJECT_ROOT"
        assert result.metadata["env_var"] == "OPENCODE_PROJECT_ROOT"

    def test_detect_opencode_from_version_env(self):
        """Test OpenCode detection from OPENCODE_VERSION."""
        with patch.dict(os.environ, {"OPENCODE_VERSION": "1.0.0"}, clear=False):
            result = EnvironmentDetector._detect_from_env_vars()

        assert result.environment == ExecutionEnvironment.OPENCODE
        assert result.detected_by == "env:OPENCODE_VERSION"
        assert result.metadata["opencode_version"] == "1.0.0"

    def test_detect_claude_code_from_env(self):
        """Test Claude Code detection from environment variables."""
        with patch.dict(os.environ, {"CLAUDE_CODE_VERSION": "2.0"}, clear=False):
            result = EnvironmentDetector._detect_from_env_vars()

        assert result.environment == ExecutionEnvironment.CLAUDE_CODE
        assert "CLAUDE_CODE_VERSION" in result.detected_by

    def test_detect_vscode_from_term_program(self):
        """Test VS Code detection from TERM_PROGRAM."""
        with patch.dict(os.environ, {"TERM_PROGRAM": "vscode"}, clear=False):
            result = EnvironmentDetector._detect_from_env_vars()

        assert result.environment == ExecutionEnvironment.VSCODE
        assert "TERM_PROGRAM" in result.detected_by

    def test_detect_cursor_from_env(self):
        """Test Cursor detection from environment variables."""
        with patch.dict(os.environ, {"CURSOR_VERSION": "0.5"}, clear=False):
            result = EnvironmentDetector._detect_from_env_vars()

        assert result.environment == ExecutionEnvironment.CURSOR

    def test_detect_unknown_no_env_vars(self):
        """Test unknown when no relevant env vars are set."""
        # Clear all detection env vars
        env_vars_to_clear = {
            "OPENCODE_PROJECT_ROOT", "OPENCODE_VERSION", "OPENCODE_WORKSPACE",
            "OPENCODE_SESSION_ID", "CLAUDE_CODE_VERSION", "CLAUDE_PROJECT_ROOT",
            "VSCODE_PID", "VSCODE_CWD", "TERM_PROGRAM", "CURSOR_VERSION",
        }
        clean_env = {k: v for k, v in os.environ.items() if k not in env_vars_to_clear}

        with patch.dict(os.environ, clean_env, clear=True):
            result = EnvironmentDetector._detect_from_env_vars()

        assert result.environment == ExecutionEnvironment.UNKNOWN


class TestEnvironmentDetectorPaths:
    """Tests for path-based detection."""

    def test_detect_opencode_from_directory(self, tmp_path):
        """Test OpenCode detection from .opencode directory."""
        opencode_dir = tmp_path / ".opencode"
        opencode_dir.mkdir()

        result = EnvironmentDetector._detect_from_paths(tmp_path)

        assert result.environment == ExecutionEnvironment.OPENCODE
        assert result.project_root == tmp_path
        assert result.detected_by == "path:.opencode"

    def test_detect_opencode_from_yaml(self, tmp_path):
        """Test OpenCode detection from opencode.yaml file."""
        config_file = tmp_path / "opencode.yaml"
        config_file.write_text("version: 1.0")

        result = EnvironmentDetector._detect_from_paths(tmp_path)

        assert result.environment == ExecutionEnvironment.OPENCODE
        assert result.detected_by == "path:opencode.yaml"

    def test_detect_claude_from_directory(self, tmp_path):
        """Test Claude Code detection from .claude directory."""
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()

        result = EnvironmentDetector._detect_from_paths(tmp_path)

        assert result.environment == ExecutionEnvironment.CLAUDE_CODE
        assert result.project_root == tmp_path

    def test_detect_vscode_from_directory(self, tmp_path):
        """Test VS Code detection from .vscode directory."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()

        result = EnvironmentDetector._detect_from_paths(tmp_path)

        assert result.environment == ExecutionEnvironment.VSCODE

    def test_detect_cursor_from_directory(self, tmp_path):
        """Test Cursor detection from .cursor directory."""
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()

        result = EnvironmentDetector._detect_from_paths(tmp_path)

        assert result.environment == ExecutionEnvironment.CURSOR

    def test_detect_searches_parent_directories(self, tmp_path):
        """Test that detection searches parent directories."""
        # Create .opencode in root
        opencode_dir = tmp_path / ".opencode"
        opencode_dir.mkdir()

        # Create nested directory
        nested = tmp_path / "src" / "components"
        nested.mkdir(parents=True)

        result = EnvironmentDetector._detect_from_paths(nested)

        assert result.environment == ExecutionEnvironment.OPENCODE
        assert result.project_root == tmp_path
        assert result.metadata["search_depth"] == 2

    def test_detect_respects_max_depth(self, tmp_path):
        """Test that detection respects MAX_SEARCH_DEPTH."""
        # Create deeply nested directory (beyond max depth)
        nested = tmp_path
        for i in range(EnvironmentDetector.MAX_SEARCH_DEPTH + 2):
            nested = nested / f"level{i}"
        nested.mkdir(parents=True)

        # Create .opencode at root (beyond search depth)
        opencode_dir = tmp_path / ".opencode"
        opencode_dir.mkdir()

        result = EnvironmentDetector._detect_from_paths(nested)

        # Should not find it due to depth limit
        assert result.environment == ExecutionEnvironment.UNKNOWN

    def test_detect_unknown_no_indicators(self, tmp_path):
        """Test unknown when no indicators are found."""
        result = EnvironmentDetector._detect_from_paths(tmp_path)
        assert result.environment == ExecutionEnvironment.UNKNOWN


class TestEnvironmentDetectorSecurity:
    """Security-related tests for environment detector."""

    def test_safe_path_prevents_null_bytes(self):
        """Test that null bytes are stripped from paths."""
        result = EnvironmentDetector._safe_path("/test/\x00path")
        # Should sanitize the path or return None
        assert result is None or "\x00" not in str(result)

    def test_safe_path_handles_none(self):
        """Test safe_path handles None input."""
        assert EnvironmentDetector._safe_path(None) is None

    def test_safe_path_handles_empty_string(self):
        """Test safe_path handles empty string."""
        assert EnvironmentDetector._safe_path("") is None

    def test_sanitize_env_value_truncates_long_values(self):
        """Test environment value sanitization truncates long strings."""
        long_value = "x" * 200
        result = EnvironmentDetector._sanitize_env_value(long_value)
        assert len(result) <= 103  # 100 + "..."

    def test_sanitize_env_value_removes_control_chars(self):
        """Test control characters are removed from env values."""
        value_with_control = "test\x00\x01\x02value"
        result = EnvironmentDetector._sanitize_env_value(value_with_control)
        assert "\x00" not in result
        assert "\x01" not in result
        assert "\x02" not in result


class TestDetectEnvironment:
    """Tests for the convenience function."""

    def test_detect_environment_returns_info(self, tmp_path):
        """Test detect_environment returns EnvironmentInfo."""
        result = detect_environment(tmp_path)
        assert isinstance(result, EnvironmentInfo)

    def test_detect_environment_defaults_to_cwd(self):
        """Test detect_environment uses cwd when no path provided."""
        with patch.object(Path, "cwd", return_value=Path("/fake/cwd")):
            with patch.object(EnvironmentDetector, "detect") as mock_detect:
                mock_detect.return_value = EnvironmentInfo(
                    environment=ExecutionEnvironment.TERMINAL,
                    project_root=Path("/fake/cwd"),
                    detected_by="test",
                    metadata={},
                )
                result = detect_environment()

        assert isinstance(result, EnvironmentInfo)


class TestIsOpencodeEnvironment:
    """Tests for is_opencode_environment convenience function."""

    def test_returns_true_when_opencode(self):
        """Test returns True when OpenCode detected."""
        with patch.dict(os.environ, {"OPENCODE_VERSION": "1.0"}, clear=False):
            # The function should detect OpenCode
            result = is_opencode_environment()
            assert result is True

    def test_returns_false_when_not_opencode(self, tmp_path):
        """Test returns False when not OpenCode."""
        # Clear OpenCode env vars
        env_vars_to_clear = {
            "OPENCODE_PROJECT_ROOT", "OPENCODE_VERSION", "OPENCODE_WORKSPACE",
            "OPENCODE_SESSION_ID",
        }
        clean_env = {k: v for k, v in os.environ.items() if k not in env_vars_to_clear}

        with patch.dict(os.environ, clean_env, clear=True):
            with patch.object(Path, "cwd", return_value=tmp_path):
                result = is_opencode_environment()
                assert result is False


class TestEnvironmentDetectorIntegration:
    """Integration tests for full detection flow."""

    def test_env_vars_take_precedence_over_paths(self, tmp_path):
        """Test environment variables take precedence over path indicators."""
        # Create VS Code indicator
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()

        # Set OpenCode env var
        with patch.dict(os.environ, {"OPENCODE_VERSION": "1.0"}, clear=False):
            result = EnvironmentDetector.detect(tmp_path)

        # Should detect OpenCode (from env) not VS Code (from path)
        assert result.environment == ExecutionEnvironment.OPENCODE
        assert "env:" in result.detected_by

    def test_fallback_to_terminal(self, tmp_path):
        """Test fallback to terminal when nothing detected."""
        # Clear all detection env vars
        env_vars_to_clear = {
            "OPENCODE_PROJECT_ROOT", "OPENCODE_VERSION", "OPENCODE_WORKSPACE",
            "OPENCODE_SESSION_ID", "CLAUDE_CODE_VERSION", "CLAUDE_PROJECT_ROOT",
            "VSCODE_PID", "VSCODE_CWD", "TERM_PROGRAM", "CURSOR_VERSION",
        }
        clean_env = {k: v for k, v in os.environ.items() if k not in env_vars_to_clear}

        with patch.dict(os.environ, clean_env, clear=True):
            result = EnvironmentDetector.detect(tmp_path)

        assert result.environment == ExecutionEnvironment.TERMINAL
        assert result.project_root == tmp_path


class TestR1SensitiveDataMasking:
    """R-1 Security tests: Enhanced environment variable masking (v2.4.6)."""

    def test_masks_api_key_env_var(self):
        """Test that API_KEY environment variables are masked."""
        result = EnvironmentDetector._sanitize_env_value(
            "sk-1234567890abcdef", "MY_API_KEY"
        )
        assert "MASKED" in result
        assert "sk-" not in result

    def test_masks_secret_env_var(self):
        """Test that SECRET environment variables are masked."""
        result = EnvironmentDetector._sanitize_env_value(
            "supersecretvalue123", "APP_SECRET"
        )
        assert "MASKED" in result
        assert "supersecret" not in result

    def test_masks_password_env_var(self):
        """Test that PASSWORD environment variables are masked."""
        result = EnvironmentDetector._sanitize_env_value(
            "mypassword123", "DATABASE_PASSWORD"
        )
        assert "MASKED" in result
        assert "mypassword" not in result

    def test_masks_token_env_var(self):
        """Test that TOKEN environment variables are masked."""
        result = EnvironmentDetector._sanitize_env_value(
            "bearer_token_value", "AUTH_TOKEN"
        )
        assert "MASKED" in result
        assert "bearer" not in result

    def test_masks_database_url(self):
        """Test that DATABASE_URL is masked."""
        result = EnvironmentDetector._sanitize_env_value(
            "postgresql://user:pass@localhost/db", "DATABASE_URL"
        )
        assert "MASKED" in result
        assert "user:pass" not in result

    def test_does_not_mask_safe_env_var(self):
        """Test that safe environment variables are not masked."""
        result = EnvironmentDetector._sanitize_env_value(
            "/test/project/path", "OPENCODE_PROJECT_ROOT"
        )
        assert "MASKED" not in result
        assert "/test/project/path" in result

    def test_detects_jwt_token(self):
        """Test that JWT tokens are detected and masked."""
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = EnvironmentDetector._sanitize_env_value(jwt, "SOME_VALUE")
        assert "MASKED" in result
        assert "eyJ" not in result

    def test_detects_openai_style_key(self):
        """Test that OpenAI-style API keys are detected."""
        assert EnvironmentDetector._looks_like_secret("sk-1234567890abcdefghijklmnop") is True

    def test_detects_github_pat(self):
        """Test that GitHub PATs are detected."""
        assert EnvironmentDetector._looks_like_secret("ghp_1234567890abcdefghijklmnop") is True

    def test_detects_aws_access_key(self):
        """Test that AWS access keys are detected."""
        assert EnvironmentDetector._looks_like_secret("AKIAIOSFODNN7EXAMPLE") is True

    def test_detects_hex_encoded_secret(self):
        """Test that hex-encoded secrets are detected."""
        hex_secret = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        assert EnvironmentDetector._looks_like_secret(hex_secret) is True

    def test_short_values_not_treated_as_secrets(self):
        """Test that short values are not mistaken for secrets."""
        assert EnvironmentDetector._looks_like_secret("short") is False
        assert EnvironmentDetector._looks_like_secret("123") is False

    def test_normal_paths_not_treated_as_secrets(self):
        """Test that normal paths are not mistaken for secrets."""
        assert EnvironmentDetector._looks_like_secret("/usr/local/bin") is False
        assert EnvironmentDetector._looks_like_secret("C:\\Users\\test") is False

    def test_entropy_calculation(self):
        """Test entropy calculation for secret detection."""
        # Low entropy (repetitive)
        low_entropy = EnvironmentDetector._calculate_entropy_score("aaaaaaaaaa")
        # High entropy (random)
        high_entropy = EnvironmentDetector._calculate_entropy_score("a1B2c3D4e5")

        assert high_entropy > low_entropy

    def test_masked_output_shows_length(self):
        """Test that masked output shows character length."""
        result = EnvironmentDetector._sanitize_env_value(
            "secret123456", "MY_SECRET"
        )
        assert "12 chars" in result
