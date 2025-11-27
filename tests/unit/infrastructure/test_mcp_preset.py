"""Unit tests for MCP Preset Configuration.

Tests:
- MCPServerPreset dataclass validation
- MCPPresetConfig loading
- MCPPresetLoader file parsing
- Environment variable resolution

Author: Artemis (Testing) + Hestia (Security Review)
Created: 2025-11-27 (Phase: MCP Preset Integration)
"""

import json
import os
import pytest
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from unittest.mock import patch

from src.infrastructure.mcp.preset_config import (
    MCPPresetConfig,
    MCPPresetLoader,
    MCPServerPreset,
    MCPTransportType,
    load_mcp_presets,
)


class TestMCPTransportType:
    """Test MCPTransportType enum."""

    def test_stdio_value(self):
        """STDIO transport type has correct value."""
        assert MCPTransportType.STDIO.value == "stdio"

    def test_http_value(self):
        """HTTP transport type has correct value."""
        assert MCPTransportType.HTTP.value == "http"

    def test_sse_value(self):
        """SSE transport type has correct value."""
        assert MCPTransportType.SSE.value == "sse"


class TestMCPServerPreset:
    """Test MCPServerPreset dataclass."""

    def test_stdio_preset_valid(self):
        """Valid STDIO preset creates successfully."""
        preset = MCPServerPreset(
            name="test-server",
            transport_type=MCPTransportType.STDIO,
            command="npx",
            args=["-y", "@test/mcp-server"],
        )
        assert preset.name == "test-server"
        assert preset.transport_type == MCPTransportType.STDIO
        assert preset.command == "npx"
        assert preset.args == ["-y", "@test/mcp-server"]
        assert preset.auto_connect is False

    def test_stdio_preset_missing_command_raises(self):
        """STDIO preset without command raises ValueError."""
        with pytest.raises(ValueError, match="requires 'command' field"):
            MCPServerPreset(
                name="test-server",
                transport_type=MCPTransportType.STDIO,
            )

    def test_http_preset_valid(self):
        """Valid HTTP preset creates successfully."""
        preset = MCPServerPreset(
            name="http-server",
            transport_type=MCPTransportType.HTTP,
            url="http://localhost:8080/mcp",
        )
        assert preset.name == "http-server"
        assert preset.transport_type == MCPTransportType.HTTP
        assert preset.url == "http://localhost:8080/mcp"

    def test_http_preset_missing_url_raises(self):
        """HTTP preset without URL raises ValueError."""
        with pytest.raises(ValueError, match="requires 'url' field"):
            MCPServerPreset(
                name="http-server",
                transport_type=MCPTransportType.HTTP,
            )

    def test_sse_preset_missing_url_raises(self):
        """SSE preset without URL raises ValueError."""
        with pytest.raises(ValueError, match="requires 'url' field"):
            MCPServerPreset(
                name="sse-server",
                transport_type=MCPTransportType.SSE,
            )

    def test_auto_connect_default_false(self):
        """auto_connect defaults to False."""
        preset = MCPServerPreset(
            name="test",
            command="echo",
        )
        assert preset.auto_connect is False

    def test_auto_connect_true(self):
        """auto_connect can be set to True."""
        preset = MCPServerPreset(
            name="test",
            command="echo",
            auto_connect=True,
        )
        assert preset.auto_connect is True

    def test_get_resolved_env_no_variables(self):
        """Environment resolution with no variables returns as-is."""
        preset = MCPServerPreset(
            name="test",
            command="echo",
            env={"API_KEY": "literal-value"},
        )
        assert preset.get_resolved_env() == {"API_KEY": "literal-value"}

    def test_get_resolved_env_with_variables(self):
        """Environment resolution expands ${VAR} references."""
        with patch.dict(os.environ, {"MY_API_KEY": "secret123"}):
            preset = MCPServerPreset(
                name="test",
                command="echo",
                env={"API_KEY": "${MY_API_KEY}"},
            )
            assert preset.get_resolved_env() == {"API_KEY": "secret123"}

    def test_get_resolved_env_missing_variable_warning(self):
        """Missing environment variable returns empty string with warning."""
        # Clear the variable if it exists
        with patch.dict(os.environ, clear=True):
            preset = MCPServerPreset(
                name="test",
                command="echo",
                env={"API_KEY": "${NONEXISTENT_VAR}"},
            )
            result = preset.get_resolved_env()
            assert result == {"API_KEY": ""}

    def test_get_api_key_from_env(self):
        """API key is retrieved from environment variable."""
        with patch.dict(os.environ, {"TEST_API_KEY": "my-api-key"}):
            preset = MCPServerPreset(
                name="test",
                transport_type=MCPTransportType.HTTP,
                url="http://localhost:8080",
                api_key_env="TEST_API_KEY",
            )
            assert preset.get_api_key() == "my-api-key"

    def test_get_api_key_not_configured(self):
        """API key returns None when not configured."""
        preset = MCPServerPreset(
            name="test",
            transport_type=MCPTransportType.HTTP,
            url="http://localhost:8080",
        )
        assert preset.get_api_key() is None

    def test_to_dict_stdio(self):
        """to_dict() produces correct dictionary for STDIO preset."""
        preset = MCPServerPreset(
            name="test-server",
            transport_type=MCPTransportType.STDIO,
            command="npx",
            args=["-y", "@test/server"],
            env={"KEY": "value"},
            cwd="/tmp",
            auto_connect=True,
        )
        result = preset.to_dict()
        assert result["name"] == "test-server"
        assert result["type"] == "stdio"
        assert result["command"] == "npx"
        assert result["args"] == ["-y", "@test/server"]
        assert result["env"] == {"KEY": "value"}
        assert result["cwd"] == "/tmp"
        assert result["autoConnect"] is True

    def test_to_dict_http(self):
        """to_dict() produces correct dictionary for HTTP preset."""
        preset = MCPServerPreset(
            name="http-server",
            transport_type=MCPTransportType.HTTP,
            url="http://localhost:8080/mcp",
            timeout=60,
            retry_attempts=5,
            auth_required=True,
            api_key_env="API_KEY",
            auto_connect=False,
        )
        result = preset.to_dict()
        assert result["name"] == "http-server"
        assert result["type"] == "http"
        assert result["url"] == "http://localhost:8080/mcp"
        assert result["timeout"] == 60
        assert result["retryAttempts"] == 5
        assert result["authRequired"] is True
        assert result["apiKeyEnv"] == "API_KEY"


class TestMCPPresetConfig:
    """Test MCPPresetConfig dataclass."""

    def test_empty_config(self):
        """Empty config has no servers."""
        config = MCPPresetConfig()
        assert len(config.servers) == 0
        assert config.get_auto_connect_servers() == []

    def test_get_server(self):
        """get_server() returns correct server by name."""
        preset = MCPServerPreset(name="test", command="echo")
        config = MCPPresetConfig(servers={"test": preset})
        assert config.get_server("test") == preset
        assert config.get_server("nonexistent") is None

    def test_get_auto_connect_servers(self):
        """get_auto_connect_servers() filters correctly."""
        preset1 = MCPServerPreset(name="auto", command="echo", auto_connect=True)
        preset2 = MCPServerPreset(name="manual", command="echo", auto_connect=False)
        config = MCPPresetConfig(servers={"auto": preset1, "manual": preset2})

        auto_servers = config.get_auto_connect_servers()
        assert len(auto_servers) == 1
        assert auto_servers[0].name == "auto"

    def test_to_dict(self):
        """to_dict() produces Claude Code compatible format."""
        preset = MCPServerPreset(name="test", command="echo", auto_connect=True)
        config = MCPPresetConfig(servers={"test": preset})

        result = config.to_dict()
        assert "mcpServers" in result
        assert "test" in result["mcpServers"]


class TestMCPPresetLoader:
    """Test MCPPresetLoader class."""

    def test_load_from_file_stdio(self):
        """Loader parses STDIO server correctly."""
        config_data = {
            "mcpServers": {
                "context7": {
                    "type": "stdio",
                    "command": "npx",
                    "args": ["-y", "@context7/mcp-server"],
                    "autoConnect": True,
                }
            }
        }

        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            f.flush()

            try:
                loader = MCPPresetLoader()
                config = MCPPresetConfig()
                loader._load_from_file(config, Path(f.name))

                assert "context7" in config.servers
                server = config.servers["context7"]
                assert server.transport_type == MCPTransportType.STDIO
                assert server.command == "npx"
                assert server.args == ["-y", "@context7/mcp-server"]
                assert server.auto_connect is True
            finally:
                os.unlink(f.name)

    def test_load_from_file_http(self):
        """Loader parses HTTP server correctly."""
        config_data = {
            "mcpServers": {
                "custom": {
                    "type": "http",
                    "url": "http://localhost:8080/mcp",
                    "timeout": 60,
                    "retryAttempts": 5,
                    "authRequired": True,
                    "apiKeyEnv": "CUSTOM_API_KEY",
                    "autoConnect": False,
                }
            }
        }

        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            f.flush()

            try:
                loader = MCPPresetLoader()
                config = MCPPresetConfig()
                loader._load_from_file(config, Path(f.name))

                assert "custom" in config.servers
                server = config.servers["custom"]
                assert server.transport_type == MCPTransportType.HTTP
                assert server.url == "http://localhost:8080/mcp"
                assert server.timeout == 60
                assert server.retry_attempts == 5
                assert server.auth_required is True
                assert server.api_key_env == "CUSTOM_API_KEY"
            finally:
                os.unlink(f.name)

    def test_load_invalid_json_skipped(self):
        """Invalid JSON file is skipped with warning."""
        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {}")
            f.flush()

            try:
                loader = MCPPresetLoader()
                config = MCPPresetConfig()
                loader._load_from_file(config, Path(f.name))

                # Should not raise, config should be empty
                assert len(config.servers) == 0
            finally:
                os.unlink(f.name)

    def test_load_invalid_server_config_skipped(self):
        """Invalid server config is skipped."""
        config_data = {
            "mcpServers": {
                "invalid-stdio": {
                    "type": "stdio",
                    # Missing command - should be skipped
                },
                "valid": {
                    "type": "stdio",
                    "command": "echo",
                }
            }
        }

        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            f.flush()

            try:
                loader = MCPPresetLoader()
                config = MCPPresetConfig()
                loader._load_from_file(config, Path(f.name))

                # Only valid server should be loaded
                assert len(config.servers) == 1
                assert "valid" in config.servers
            finally:
                os.unlink(f.name)

    def test_load_priority_env_variable(self):
        """TMWS_MCP_SERVERS_PATH takes priority."""
        config_data = {
            "mcpServers": {
                "env-server": {
                    "type": "stdio",
                    "command": "env-command",
                }
            }
        }

        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            f.flush()

            try:
                with patch.dict(os.environ, {"TMWS_MCP_SERVERS_PATH": f.name}):
                    loader = MCPPresetLoader()
                    config = loader.load()

                    assert "env-server" in config.servers
            finally:
                os.unlink(f.name)

    def test_load_merge_user_config(self):
        """User config is merged with project config."""
        project_data = {
            "mcpServers": {
                "project-server": {
                    "type": "stdio",
                    "command": "project-cmd",
                }
            }
        }

        user_data = {
            "mcpServers": {
                "user-server": {
                    "type": "stdio",
                    "command": "user-cmd",
                }
            }
        }

        with TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            project_config = project_dir / ".mcp.json"

            with open(project_config, "w") as f:
                json.dump(project_data, f)

            with TemporaryDirectory() as home:
                tmws_home = Path(home) / ".tmws"
                tmws_home.mkdir()
                user_config = tmws_home / "mcp.json"  # Changed from mcp_servers.json

                with open(user_config, "w") as f:
                    json.dump(user_data, f)

                loader = MCPPresetLoader(tmws_home=tmws_home)
                config = loader.load(project_dir=project_dir)

                # Both servers should be loaded
                assert "project-server" in config.servers
                assert "user-server" in config.servers

    def test_save_example_config(self):
        """save_example_config() creates valid example file."""
        with TemporaryDirectory() as tmpdir:
            tmws_home = Path(tmpdir) / ".tmws"
            loader = MCPPresetLoader(tmws_home=tmws_home)

            path = loader.save_example_config()

            assert path.exists()
            assert path.suffix == ".example"

            # Should be valid JSON
            with open(path) as f:
                data = json.load(f)
                assert "mcpServers" in data
                assert "context7" in data["mcpServers"]
                assert "playwright" in data["mcpServers"]


class TestLoadMCPPresets:
    """Test convenience function."""

    def test_load_mcp_presets_returns_config(self):
        """load_mcp_presets() returns MCPPresetConfig."""
        config = load_mcp_presets()
        assert isinstance(config, MCPPresetConfig)


class TestSecurityConcerns:
    """Security-focused tests (Hestia)."""

    def test_env_var_injection_blocked(self):
        """Environment variable values are not executed as shell commands."""
        # This test ensures that environment variables are passed as-is
        # and not shell-expanded in dangerous ways
        with patch.dict(os.environ, {"SAFE_VAR": "$(malicious)"}):
            preset = MCPServerPreset(
                name="test",
                command="echo",
                env={"KEY": "${SAFE_VAR}"},
            )
            result = preset.get_resolved_env()
            # The value should be literal, not executed
            assert result["KEY"] == "$(malicious)"

    def test_path_traversal_in_cwd_not_validated(self):
        """CWD validation note: paths are passed as-is.

        Note: The actual path validation happens at subprocess execution time.
        This test documents the behavior.
        """
        preset = MCPServerPreset(
            name="test",
            command="echo",
            cwd="../../../etc",
        )
        assert preset.cwd == "../../../etc"
        # Actual security enforcement happens in STDIOTransport.connect()
        # where the OS validates the path exists and is accessible
