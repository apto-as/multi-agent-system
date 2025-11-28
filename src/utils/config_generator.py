"""Configuration file generator for different execution environments.

Generates appropriate configuration files (MCP config, etc.) for
OpenCode, Claude Code, VS Code, and other supported environments.

v2.4.5: Initial OpenCode support (MVP implementation)
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .environment_detector import EnvironmentInfo, ExecutionEnvironment, detect_environment

logger = logging.getLogger(__name__)


class ConfigGeneratorError(Exception):
    """Raised when configuration generation fails."""
    pass


@dataclass
class MCPServerConfig:
    """MCP server configuration for an environment."""

    name: str = "tmws"
    command: str = "uv"
    args: list[str] = field(default_factory=lambda: ["run", "tmws-mcp-server"])
    env: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary format for JSON serialization."""
        config: dict[str, Any] = {
            "command": self.command,
            "args": self.args,
        }
        if self.env:
            config["env"] = self.env
        return config


class ConfigGenerator:
    """Generates configuration files for different execution environments.

    Supports:
    - OpenCode: .opencode/mcp_config.json
    - Claude Code: .claude/claude_desktop_config.json (reference only)
    - VS Code: .vscode/mcp_config.json

    Security considerations:
    - Validates output paths to prevent directory traversal
    - Uses atomic writes to prevent partial file corruption
    - Sets appropriate file permissions (0o644)
    """

    # Default MCP server configuration
    DEFAULT_MCP_CONFIG = MCPServerConfig()

    # Environment-specific output paths
    OUTPUT_PATHS = {
        ExecutionEnvironment.OPENCODE: ".opencode/mcp_config.json",
        ExecutionEnvironment.CLAUDE_CODE: ".claude/claude_desktop_config.json",
        ExecutionEnvironment.VSCODE: ".vscode/mcp_config.json",
        ExecutionEnvironment.CURSOR: ".cursor/mcp_config.json",
    }

    @classmethod
    def generate_mcp_config(
        cls,
        env_info: EnvironmentInfo | None = None,
        output_path: Path | None = None,
        server_config: MCPServerConfig | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> Path:
        """Generate MCP configuration file for the detected environment.

        Args:
            env_info: Environment information. Auto-detected if not provided.
            output_path: Custom output path. Uses environment default if not provided.
            server_config: Custom MCP server config. Uses default if not provided.
            extra_env: Additional environment variables to include.

        Returns:
            Path to the generated configuration file.

        Raises:
            ConfigGeneratorError: If generation fails.
        """
        # Auto-detect environment if not provided
        if env_info is None:
            env_info = detect_environment()

        # Determine project root
        project_root = env_info.project_root
        if project_root is None:
            project_root = Path.cwd()

        # Determine output path
        if output_path is None:
            relative_path = cls.OUTPUT_PATHS.get(env_info.environment)
            if relative_path is None:
                raise ConfigGeneratorError(
                    f"No default config path for environment: {env_info.environment}. "
                    "Please provide explicit output_path."
                )
            output_path = project_root / relative_path

        # Security: Validate output path is within project root
        try:
            output_path = output_path.resolve()
            project_root = project_root.resolve()

            # Check output is under project root (prevent directory traversal)
            try:
                output_path.relative_to(project_root)
            except ValueError:
                raise ConfigGeneratorError(
                    f"Output path {output_path} is outside project root {project_root}. "
                    "This is not allowed for security reasons."
                )
        except (OSError, RuntimeError) as e:
            raise ConfigGeneratorError(f"Failed to resolve paths: {e}") from e

        # Prepare server configuration
        if server_config is None:
            server_config = cls.DEFAULT_MCP_CONFIG

        # Merge extra environment variables
        env_vars = dict(server_config.env)
        if extra_env:
            env_vars.update(extra_env)

        # Add TMWS-specific environment variables if not present
        if "TMWS_ENVIRONMENT" not in env_vars:
            env_vars["TMWS_ENVIRONMENT"] = os.environ.get("TMWS_ENVIRONMENT", "development")

        # Build configuration structure
        config = cls._build_config_structure(
            env_info.environment,
            server_config.name,
            server_config.command,
            server_config.args,
            env_vars,
        )

        # Write configuration file
        return cls._write_config(output_path, config)

    @classmethod
    def _build_config_structure(
        cls,
        environment: ExecutionEnvironment,
        name: str,
        command: str,
        args: list[str],
        env: dict[str, str],
    ) -> dict[str, Any]:
        """Build configuration structure for the specific environment.

        Different environments may have slightly different config formats.
        """
        server_config: dict[str, Any] = {
            "command": command,
            "args": args,
        }
        if env:
            server_config["env"] = env

        # OpenCode format
        if environment == ExecutionEnvironment.OPENCODE:
            return {
                "$schema": "https://opencode.ai/schemas/mcp_config.json",
                "version": "1.0",
                "mcpServers": {
                    name: server_config,
                },
            }

        # Claude Code / Claude Desktop format
        if environment == ExecutionEnvironment.CLAUDE_CODE:
            return {
                "mcpServers": {
                    name: server_config,
                },
            }

        # VS Code / Cursor format (similar to Claude)
        return {
            "mcpServers": {
                name: server_config,
            },
        }

    @classmethod
    def _write_config(cls, output_path: Path, config: dict[str, Any]) -> Path:
        """Write configuration to file with atomic write and proper permissions.

        Security:
            - Uses atomic write (write to temp, then rename)
            - Sets file permissions to 0o644
            - Creates parent directories with 0o755
        """
        try:
            # Create parent directory if needed
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Atomic write: write to temp file first
            temp_path = output_path.with_suffix(".tmp")

            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
                f.write("\n")  # Trailing newline

            # Set permissions before rename (security)
            temp_path.chmod(0o644)

            # Atomic rename
            temp_path.rename(output_path)

            logger.info(f"Generated MCP config: {output_path}")
            return output_path

        except (OSError, TypeError, ValueError) as e:
            # Clean up temp file if it exists
            import contextlib
            if temp_path.exists():
                with contextlib.suppress(OSError):
                    temp_path.unlink()
            raise ConfigGeneratorError(f"Failed to write config to {output_path}: {e}") from e

    @classmethod
    def get_config_template(cls, environment: ExecutionEnvironment) -> str:
        """Get configuration template as a string for reference.

        Args:
            environment: Target environment.

        Returns:
            JSON template string.
        """
        config = cls._build_config_structure(
            environment,
            "tmws",
            "uv",
            ["run", "tmws-mcp-server"],
            {"TMWS_ENVIRONMENT": "development"},
        )
        return json.dumps(config, indent=2, ensure_ascii=False)


def generate_opencode_config(
    project_root: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> Path:
    """Convenience function to generate OpenCode MCP configuration.

    Args:
        project_root: Project root directory. Auto-detected if not provided.
        extra_env: Additional environment variables.

    Returns:
        Path to generated configuration file.

    Raises:
        ConfigGeneratorError: If generation fails.
    """
    if project_root is None:
        project_root = Path.cwd()

    env_info = EnvironmentInfo(
        environment=ExecutionEnvironment.OPENCODE,
        project_root=project_root,
        detected_by="manual",
        metadata={},
    )

    return ConfigGenerator.generate_mcp_config(
        env_info=env_info,
        extra_env=extra_env,
    )


# Export public interface
__all__ = [
    "ConfigGeneratorError",
    "MCPServerConfig",
    "ConfigGenerator",
    "generate_opencode_config",
]
