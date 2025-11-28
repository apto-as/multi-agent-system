"""Tests for configuration file generator.

v2.4.5: OpenCode MCP config generation tests.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.utils.config_generator import (
    ConfigGenerator,
    ConfigGeneratorError,
    MCPServerConfig,
    generate_opencode_config,
)
from src.utils.environment_detector import EnvironmentInfo, ExecutionEnvironment


class TestMCPServerConfig:
    """Tests for MCPServerConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = MCPServerConfig()
        assert config.name == "tmws"
        assert config.command == "uv"
        assert config.args == ["run", "tmws-mcp-server"]
        assert config.env == {}

    def test_custom_values(self):
        """Test custom configuration values."""
        config = MCPServerConfig(
            name="custom",
            command="python",
            args=["-m", "tmws"],
            env={"KEY": "value"},
        )
        assert config.name == "custom"
        assert config.command == "python"
        assert config.args == ["-m", "tmws"]
        assert config.env == {"KEY": "value"}

    def test_to_dict(self):
        """Test conversion to dictionary."""
        config = MCPServerConfig(env={"KEY": "value"})
        result = config.to_dict()

        assert result["command"] == "uv"
        assert result["args"] == ["run", "tmws-mcp-server"]
        assert result["env"] == {"KEY": "value"}

    def test_to_dict_without_env(self):
        """Test conversion excludes empty env."""
        config = MCPServerConfig()
        result = config.to_dict()

        assert "env" not in result


class TestConfigGeneratorBuildStructure:
    """Tests for configuration structure building."""

    def test_opencode_structure(self):
        """Test OpenCode configuration structure."""
        result = ConfigGenerator._build_config_structure(
            ExecutionEnvironment.OPENCODE,
            "tmws",
            "uv",
            ["run", "tmws-mcp-server"],
            {"TMWS_ENVIRONMENT": "development"},
        )

        assert "$schema" in result
        assert result["version"] == "1.0"
        assert "mcpServers" in result
        assert "tmws" in result["mcpServers"]
        assert result["mcpServers"]["tmws"]["command"] == "uv"

    def test_claude_code_structure(self):
        """Test Claude Code configuration structure."""
        result = ConfigGenerator._build_config_structure(
            ExecutionEnvironment.CLAUDE_CODE,
            "tmws",
            "uv",
            ["run", "tmws-mcp-server"],
            {},
        )

        assert "$schema" not in result  # Claude format doesn't have schema
        assert "mcpServers" in result
        assert "tmws" in result["mcpServers"]

    def test_vscode_structure(self):
        """Test VS Code configuration structure."""
        result = ConfigGenerator._build_config_structure(
            ExecutionEnvironment.VSCODE,
            "tmws",
            "uv",
            ["run", "tmws-mcp-server"],
            {},
        )

        assert "mcpServers" in result
        assert "tmws" in result["mcpServers"]

    def test_env_included_when_present(self):
        """Test environment variables are included."""
        result = ConfigGenerator._build_config_structure(
            ExecutionEnvironment.OPENCODE,
            "tmws",
            "uv",
            ["run"],
            {"KEY": "value"},
        )

        assert result["mcpServers"]["tmws"]["env"] == {"KEY": "value"}

    def test_env_excluded_when_empty(self):
        """Test empty env is excluded."""
        result = ConfigGenerator._build_config_structure(
            ExecutionEnvironment.OPENCODE,
            "tmws",
            "uv",
            ["run"],
            {},
        )

        assert "env" not in result["mcpServers"]["tmws"]


class TestConfigGeneratorWriteConfig:
    """Tests for configuration file writing."""

    def test_write_creates_file(self, tmp_path):
        """Test configuration file is created."""
        output_path = tmp_path / "config.json"
        config = {"key": "value"}

        result = ConfigGenerator._write_config(output_path, config)

        assert result == output_path
        assert output_path.exists()

    def test_write_creates_parent_directories(self, tmp_path):
        """Test parent directories are created."""
        output_path = tmp_path / "nested" / "dir" / "config.json"
        config = {"key": "value"}

        ConfigGenerator._write_config(output_path, config)

        assert output_path.exists()
        assert output_path.parent.exists()

    def test_write_valid_json(self, tmp_path):
        """Test written content is valid JSON."""
        output_path = tmp_path / "config.json"
        config = {"mcpServers": {"tmws": {"command": "uv"}}}

        ConfigGenerator._write_config(output_path, config)

        with open(output_path) as f:
            loaded = json.load(f)

        assert loaded == config

    def test_write_with_trailing_newline(self, tmp_path):
        """Test file ends with newline."""
        output_path = tmp_path / "config.json"
        config = {"key": "value"}

        ConfigGenerator._write_config(output_path, config)

        content = output_path.read_text()
        assert content.endswith("\n")

    def test_write_sets_permissions(self, tmp_path):
        """Test file permissions are set correctly."""
        output_path = tmp_path / "config.json"
        config = {"key": "value"}

        ConfigGenerator._write_config(output_path, config)

        # Check permissions (0o644 = rw-r--r--)
        mode = output_path.stat().st_mode & 0o777
        assert mode == 0o644


class TestConfigGeneratorGenerateMCPConfig:
    """Tests for MCP config generation."""

    def test_generate_for_opencode(self, tmp_path):
        """Test generating OpenCode configuration."""
        env_info = EnvironmentInfo(
            environment=ExecutionEnvironment.OPENCODE,
            project_root=tmp_path,
            detected_by="test",
            metadata={},
        )

        result = ConfigGenerator.generate_mcp_config(env_info=env_info)

        assert result.exists()
        assert result == tmp_path / ".opencode" / "mcp_config.json"

        with open(result) as f:
            config = json.load(f)

        assert "mcpServers" in config
        assert "tmws" in config["mcpServers"]

    def test_generate_for_claude_code(self, tmp_path):
        """Test generating Claude Code configuration."""
        env_info = EnvironmentInfo(
            environment=ExecutionEnvironment.CLAUDE_CODE,
            project_root=tmp_path,
            detected_by="test",
            metadata={},
        )

        result = ConfigGenerator.generate_mcp_config(env_info=env_info)

        assert result.exists()
        assert result == tmp_path / ".claude" / "claude_desktop_config.json"

    def test_generate_with_custom_output_path(self, tmp_path):
        """Test generating with custom output path."""
        env_info = EnvironmentInfo(
            environment=ExecutionEnvironment.OPENCODE,
            project_root=tmp_path,
            detected_by="test",
            metadata={},
        )
        custom_path = tmp_path / "custom" / "config.json"

        result = ConfigGenerator.generate_mcp_config(
            env_info=env_info,
            output_path=custom_path,
        )

        assert result == custom_path
        assert custom_path.exists()

    def test_generate_with_extra_env(self, tmp_path):
        """Test generating with extra environment variables."""
        env_info = EnvironmentInfo(
            environment=ExecutionEnvironment.OPENCODE,
            project_root=tmp_path,
            detected_by="test",
            metadata={},
        )

        result = ConfigGenerator.generate_mcp_config(
            env_info=env_info,
            extra_env={"CUSTOM_VAR": "custom_value"},
        )

        with open(result) as f:
            config = json.load(f)

        assert config["mcpServers"]["tmws"]["env"]["CUSTOM_VAR"] == "custom_value"

    def test_generate_with_custom_server_config(self, tmp_path):
        """Test generating with custom server configuration."""
        env_info = EnvironmentInfo(
            environment=ExecutionEnvironment.OPENCODE,
            project_root=tmp_path,
            detected_by="test",
            metadata={},
        )
        server_config = MCPServerConfig(
            name="custom-tmws",
            command="python",
            args=["-m", "tmws.mcp"],
        )

        result = ConfigGenerator.generate_mcp_config(
            env_info=env_info,
            server_config=server_config,
        )

        with open(result) as f:
            config = json.load(f)

        assert "custom-tmws" in config["mcpServers"]
        assert config["mcpServers"]["custom-tmws"]["command"] == "python"

    def test_generate_auto_detects_environment(self, tmp_path):
        """Test auto-detection when env_info not provided."""
        # Create OpenCode indicator
        opencode_dir = tmp_path / ".opencode"
        opencode_dir.mkdir()

        with patch("src.utils.config_generator.detect_environment") as mock_detect:
            mock_detect.return_value = EnvironmentInfo(
                environment=ExecutionEnvironment.OPENCODE,
                project_root=tmp_path,
                detected_by="test",
                metadata={},
            )
            result = ConfigGenerator.generate_mcp_config()

        assert result.exists()

    def test_generate_raises_for_unknown_environment(self, tmp_path):
        """Test error when environment has no default path."""
        env_info = EnvironmentInfo(
            environment=ExecutionEnvironment.UNKNOWN,
            project_root=tmp_path,
            detected_by="test",
            metadata={},
        )

        with pytest.raises(ConfigGeneratorError) as exc_info:
            ConfigGenerator.generate_mcp_config(env_info=env_info)

        assert "No default config path" in str(exc_info.value)


class TestConfigGeneratorSecurity:
    """Security tests for config generator."""

    def test_rejects_output_outside_project_root(self, tmp_path):
        """Test rejection of output path outside project root."""
        env_info = EnvironmentInfo(
            environment=ExecutionEnvironment.OPENCODE,
            project_root=tmp_path / "project",
            detected_by="test",
            metadata={},
        )
        (tmp_path / "project").mkdir()

        # Try to write outside project root
        outside_path = tmp_path / "outside" / "config.json"

        with pytest.raises(ConfigGeneratorError) as exc_info:
            ConfigGenerator.generate_mcp_config(
                env_info=env_info,
                output_path=outside_path,
            )

        assert "outside project root" in str(exc_info.value)

    def test_atomic_write_cleans_up_on_failure(self, tmp_path):
        """Test temp file is cleaned up on write failure."""
        from unittest.mock import patch, mock_open

        output_path = tmp_path / "config.json"

        # Mock open to raise an exception after creating temp file
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            with pytest.raises(ConfigGeneratorError) as exc_info:
                ConfigGenerator._write_config(
                    output_path,
                    {"key": "value"},
                )

        assert "Permission denied" in str(exc_info.value)

        # Temp file should not exist after cleanup
        temp_path = output_path.with_suffix(".tmp")
        assert not temp_path.exists()


class TestGenerateOpencodeConfig:
    """Tests for the convenience function."""

    def test_generates_opencode_config(self, tmp_path):
        """Test convenience function generates OpenCode config."""
        result = generate_opencode_config(project_root=tmp_path)

        assert result.exists()
        assert result == tmp_path / ".opencode" / "mcp_config.json"

        with open(result) as f:
            config = json.load(f)

        assert "$schema" in config
        assert "mcpServers" in config

    def test_generates_with_extra_env(self, tmp_path):
        """Test convenience function with extra env vars."""
        result = generate_opencode_config(
            project_root=tmp_path,
            extra_env={"MY_VAR": "my_value"},
        )

        with open(result) as f:
            config = json.load(f)

        assert config["mcpServers"]["tmws"]["env"]["MY_VAR"] == "my_value"


class TestConfigGeneratorGetTemplate:
    """Tests for configuration template generation."""

    def test_get_template_opencode(self):
        """Test getting OpenCode template."""
        template = ConfigGenerator.get_config_template(ExecutionEnvironment.OPENCODE)

        # Should be valid JSON
        config = json.loads(template)

        assert "$schema" in config
        assert "mcpServers" in config
        assert "tmws" in config["mcpServers"]

    def test_get_template_claude_code(self):
        """Test getting Claude Code template."""
        template = ConfigGenerator.get_config_template(ExecutionEnvironment.CLAUDE_CODE)

        config = json.loads(template)

        assert "mcpServers" in config
        assert "$schema" not in config  # Claude format doesn't have schema

    def test_get_template_vscode(self):
        """Test getting VS Code template."""
        template = ConfigGenerator.get_config_template(ExecutionEnvironment.VSCODE)

        config = json.loads(template)

        assert "mcpServers" in config
