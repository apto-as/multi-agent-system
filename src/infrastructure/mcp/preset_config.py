"""MCP Server Preset Configuration.

This module provides configuration loading and validation for preset MCP servers.
Supports both STDIO and HTTP transport types, compatible with Claude Code's .mcp.json format.

Transport Types:
- STDIO: Launches MCP server as subprocess, communicates via stdin/stdout
- HTTP/SSE: Connects to HTTP endpoint with optional Server-Sent Events

Configuration Locations (in priority order):
1. Project-level: ./.mcp.json (version controlled)
2. User-level: ~/.tmws/mcp_servers.json (personal presets)
3. Environment: TMWS_MCP_SERVERS_PATH (custom location)

Author: Artemis (Implementation) + Hera (Architecture)
Created: 2025-11-27 (Phase: MCP Preset Integration)
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class MCPTransportType(Enum):
    """MCP transport types supported by TMWS."""

    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"  # Server-Sent Events (subset of HTTP)


@dataclass
class MCPServerPreset:
    """Configuration for a single MCP server preset.

    Attributes:
        name: Unique identifier for the server
        transport_type: STDIO or HTTP transport
        auto_connect: Whether to connect on TMWS startup

        # STDIO-specific
        command: Executable command (e.g., "npx", "uvx", "python")
        args: Command line arguments
        env: Environment variables for the subprocess
        cwd: Working directory for subprocess

        # HTTP-specific
        url: HTTP endpoint URL
        timeout: Connection timeout in seconds
        retry_attempts: Number of retry attempts
        auth_required: Whether authentication is needed
        api_key_env: Environment variable name for API key
    """

    name: str
    transport_type: MCPTransportType = MCPTransportType.STDIO
    auto_connect: bool = False

    # STDIO transport
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None

    # HTTP transport
    url: str | None = None
    timeout: int = 30
    retry_attempts: int = 3
    auth_required: bool = False
    api_key_env: str | None = None

    def __post_init__(self):
        """Validate configuration after initialization."""
        if self.transport_type == MCPTransportType.STDIO:
            if not self.command:
                raise ValueError(f"STDIO server '{self.name}' requires 'command' field")
        elif self.transport_type in (MCPTransportType.HTTP, MCPTransportType.SSE):
            if not self.url:
                raise ValueError(f"HTTP server '{self.name}' requires 'url' field")

    def get_resolved_env(self) -> dict[str, str]:
        """Get environment variables with ${VAR} references resolved.

        Returns:
            Dictionary with resolved environment variables

        Example:
            >>> preset = MCPServerPreset(
            ...     name="test",
            ...     command="node",
            ...     env={"API_KEY": "${MY_API_KEY}"}
            ... )
            >>> # If MY_API_KEY=secret123 in environment
            >>> preset.get_resolved_env()
            {'API_KEY': 'secret123'}
        """
        resolved = {}
        pattern = re.compile(r'\$\{([^}]+)\}')

        for key, value in self.env.items():
            # Replace ${VAR_NAME} with actual environment variable value
            def replace_var(match):
                var_name = match.group(1)
                env_value = os.environ.get(var_name, "")
                if not env_value:
                    logger.warning(
                        f"Environment variable '{var_name}' not set for MCP server '{self.name}'"
                    )
                return env_value

            resolved[key] = pattern.sub(replace_var, value)

        return resolved

    def get_api_key(self) -> str | None:
        """Get API key from environment variable.

        Returns:
            API key value or None if not configured/found
        """
        if not self.api_key_env:
            return None
        return os.environ.get(self.api_key_env)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary suitable for JSON serialization
        """
        result = {
            "name": self.name,
            "type": self.transport_type.value,
            "autoConnect": self.auto_connect,
        }

        if self.transport_type == MCPTransportType.STDIO:
            result["command"] = self.command
            if self.args:
                result["args"] = self.args
            if self.env:
                result["env"] = self.env
            if self.cwd:
                result["cwd"] = self.cwd
        else:
            result["url"] = self.url
            result["timeout"] = self.timeout
            result["retryAttempts"] = self.retry_attempts
            if self.auth_required:
                result["authRequired"] = self.auth_required
                if self.api_key_env:
                    result["apiKeyEnv"] = self.api_key_env

        return result


@dataclass
class MCPPresetConfig:
    """Collection of MCP server presets.

    Attributes:
        servers: Dictionary of server name -> MCPServerPreset
        config_path: Path where configuration was loaded from
    """

    servers: dict[str, MCPServerPreset] = field(default_factory=dict)
    config_path: Path | None = None

    def get_auto_connect_servers(self) -> list[MCPServerPreset]:
        """Get list of servers configured for auto-connection.

        Returns:
            List of MCPServerPreset with auto_connect=True
        """
        return [s for s in self.servers.values() if s.auto_connect]

    def get_server(self, name: str) -> MCPServerPreset | None:
        """Get server preset by name.

        Args:
            name: Server name

        Returns:
            MCPServerPreset or None if not found
        """
        return self.servers.get(name)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation (Claude Code compatible).

        Returns:
            Dictionary in .mcp.json format
        """
        return {
            "mcpServers": {
                name: preset.to_dict()
                for name, preset in self.servers.items()
            }
        }


class MCPPresetLoader:
    """Loads MCP server presets from configuration files.

    Searches for configuration in the following order:
    1. TMWS_MCP_SERVERS_PATH environment variable
    2. Project-level: ./.mcp.json
    3. User-level: ~/.tmws/mcp.json

    Example:
        >>> loader = MCPPresetLoader()
        >>> config = loader.load()
        >>> for server in config.get_auto_connect_servers():
        ...     print(f"Auto-connect: {server.name}")
    """

    # Default configuration file names
    PROJECT_CONFIG = ".mcp.json"
    USER_CONFIG = "mcp.json"  # User config: ~/.tmws/mcp.json

    def __init__(self, tmws_home: Path | None = None):
        """Initialize preset loader.

        Args:
            tmws_home: TMWS home directory (default: ~/.tmws)
        """
        self.tmws_home = tmws_home or Path.home() / ".tmws"

    def load(self, project_dir: Path | None = None) -> MCPPresetConfig:
        """Load MCP server presets from configuration files.

        Args:
            project_dir: Project directory for project-level config

        Returns:
            MCPPresetConfig with all loaded servers
        """
        config = MCPPresetConfig()

        # Priority 1: Environment variable
        env_path = os.environ.get("TMWS_MCP_SERVERS_PATH")
        if env_path:
            path = Path(env_path)
            if path.exists():
                self._load_from_file(config, path)
                return config
            else:
                logger.warning(f"TMWS_MCP_SERVERS_PATH points to non-existent file: {env_path}")

        # Priority 2: Project-level config
        if project_dir:
            project_config = project_dir / self.PROJECT_CONFIG
            if project_config.exists():
                self._load_from_file(config, project_config)

        # Priority 3: User-level config (merge with project config)
        user_config = self.tmws_home / self.USER_CONFIG
        if user_config.exists():
            self._load_from_file(config, user_config, merge=True)

        return config

    def _load_from_file(
        self,
        config: MCPPresetConfig,
        path: Path,
        merge: bool = False
    ) -> None:
        """Load configuration from a JSON file.

        Args:
            config: MCPPresetConfig to populate
            path: Path to JSON configuration file
            merge: If True, merge with existing config instead of replacing
        """
        try:
            with open(path) as f:
                data = json.load(f)

            if not merge:
                config.servers.clear()

            config.config_path = path

            # Parse mcpServers section
            mcp_servers = data.get("mcpServers", {})

            for name, server_config in mcp_servers.items():
                try:
                    preset = self._parse_server_config(name, server_config)

                    # Don't override existing servers when merging
                    if merge and name in config.servers:
                        logger.debug(f"Skipping duplicate server '{name}' during merge")
                        continue

                    config.servers[name] = preset
                    logger.info(f"Loaded MCP preset: {name} ({preset.transport_type.value})")

                except (ValueError, KeyError) as e:
                    logger.warning(f"Invalid MCP server config '{name}': {e}")
                    continue

            logger.info(f"Loaded {len(mcp_servers)} MCP server presets from {path}")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {path}: {e}")
        except Exception as e:
            logger.error(f"Failed to load MCP config from {path}: {e}")

    def _parse_server_config(self, name: str, config: dict[str, Any]) -> MCPServerPreset:
        """Parse a single server configuration.

        Args:
            name: Server name
            config: Server configuration dictionary

        Returns:
            MCPServerPreset instance

        Raises:
            ValueError: If configuration is invalid
        """
        # Determine transport type
        transport_str = config.get("type", "stdio").lower()
        try:
            transport_type = MCPTransportType(transport_str)
        except ValueError:
            raise ValueError(f"Unknown transport type: {transport_str}")

        # Common fields
        auto_connect = config.get("autoConnect", False)

        if transport_type == MCPTransportType.STDIO:
            return MCPServerPreset(
                name=name,
                transport_type=transport_type,
                auto_connect=auto_connect,
                command=config.get("command"),
                args=config.get("args", []),
                env=config.get("env", {}),
                cwd=config.get("cwd"),
            )
        else:
            return MCPServerPreset(
                name=name,
                transport_type=transport_type,
                auto_connect=auto_connect,
                url=config.get("url"),
                timeout=config.get("timeout", 30),
                retry_attempts=config.get("retryAttempts", 3),
                auth_required=config.get("authRequired", False),
                api_key_env=config.get("apiKeyEnv"),
            )

    def save_example_config(self, path: Path | None = None) -> Path:
        """Save an example configuration file.

        Args:
            path: Output path (default: ~/.tmws/mcp_servers.json.example)

        Returns:
            Path where example was saved
        """
        if path is None:
            path = self.tmws_home / "mcp_servers.json.example"

        example = {
            "mcpServers": {
                "context7": {
                    "type": "stdio",
                    "command": "npx",
                    "args": ["-y", "@upstash/context7-mcp@latest"],
                    "autoConnect": True
                },
                "playwright": {
                    "type": "stdio",
                    "command": "npx",
                    "args": ["-y", "@anthropic/mcp-playwright@latest"],
                    "autoConnect": True
                },
                "serena": {
                    "type": "stdio",
                    "command": "uvx",
                    "args": ["--from", "serena-mcp-server", "serena"],
                    "autoConnect": True
                },
                "chrome-devtools": {
                    "type": "stdio",
                    "command": "npx",
                    "args": ["-y", "@anthropic/mcp-chrome-devtools@latest"],
                    "autoConnect": False
                },
                "custom-http-server": {
                    "type": "http",
                    "url": "http://localhost:8080/mcp",
                    "timeout": 30,
                    "retryAttempts": 3,
                    "authRequired": True,
                    "apiKeyEnv": "CUSTOM_SERVER_API_KEY",
                    "autoConnect": False
                }
            }
        }

        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            json.dump(example, f, indent=2)

        logger.info(f"Saved example MCP config to {path}")
        return path


# Singleton loader instance
_preset_loader: MCPPresetLoader | None = None


def get_preset_loader() -> MCPPresetLoader:
    """Get singleton preset loader instance.

    Returns:
        MCPPresetLoader instance
    """
    global _preset_loader
    if _preset_loader is None:
        _preset_loader = MCPPresetLoader()
    return _preset_loader


def load_mcp_presets(project_dir: Path | None = None) -> MCPPresetConfig:
    """Convenience function to load MCP presets.

    Args:
        project_dir: Optional project directory

    Returns:
        MCPPresetConfig with loaded servers
    """
    return get_preset_loader().load(project_dir)
