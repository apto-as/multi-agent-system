"""MCP Infrastructure Module.

This module provides infrastructure components for MCP (Model Context Protocol)
server integration, including:

- Preset configuration loading (preset_config.py)
- STDIO transport for subprocess-based servers (stdio_transport.py)
- Unified MCP manager for all transport types (manager.py)
- Version resolution and compatibility checking (Phase 4.2)

Usage:
    >>> from src.infrastructure.mcp import load_mcp_presets, MCPManager
    >>>
    >>> # Load presets from configuration files
    >>> presets = load_mcp_presets()
    >>>
    >>> # Create manager and connect to servers
    >>> manager = MCPManager()
    >>> await manager.auto_connect(presets)
    >>>
    >>> # List all available tools
    >>> tools = await manager.list_all_tools()
    >>>
    >>> # Check version compatibility (Phase 4.2)
    >>> from src.infrastructure.mcp import check_server_compatibility
    >>> result = check_server_compatibility("tmws", "2.4.16", "2.4.0")

Author: Artemis (Implementation)
Created: 2025-11-27 (Phase: MCP Preset Integration)
Updated: 2025-12-09 (Phase 4.2: MCP Server Versioning)
"""

from .compatibility_checker import (
    CheckSeverity,
    CompatibilityChecker,
    CompatibilityIssue,
    CompatibilityResult,
    check_server_compatibility,
)
from .manager import (
    MCPConnection,
    MCPManager,
    auto_connect_mcp_servers,
    get_mcp_manager,
)
from .preset_config import (
    MCPPresetConfig,
    MCPPresetLoader,
    MCPServerPreset,
    MCPTransportType,
    get_preset_loader,
    load_mcp_presets,
)
from .stdio_transport import (
    MCPMessage,
    STDIOTransport,
    STDIOTransportManager,
)
from .version_resolver import (
    CompatibilityLevel,
    SemanticVersion,
    VersionParseError,
    VersionResolver,
    compare_versions,
    is_version_compatible,
    parse_version,
)

__all__ = [
    # Preset configuration
    "MCPPresetConfig",
    "MCPPresetLoader",
    "MCPServerPreset",
    "MCPTransportType",
    "get_preset_loader",
    "load_mcp_presets",
    # STDIO transport
    "MCPMessage",
    "STDIOTransport",
    "STDIOTransportManager",
    # Manager
    "MCPConnection",
    "MCPManager",
    "auto_connect_mcp_servers",
    "get_mcp_manager",
    # Version resolver (Phase 4.2)
    "CompatibilityLevel",
    "SemanticVersion",
    "VersionParseError",
    "VersionResolver",
    "compare_versions",
    "is_version_compatible",
    "parse_version",
    # Compatibility checker (Phase 4.2)
    "CheckSeverity",
    "CompatibilityChecker",
    "CompatibilityIssue",
    "CompatibilityResult",
    "check_server_compatibility",
]
