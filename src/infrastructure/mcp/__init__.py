"""MCP Infrastructure Module.

This module provides infrastructure components for MCP (Model Context Protocol)
server integration, including:

- Preset configuration loading (preset_config.py)
- STDIO transport for subprocess-based servers (stdio_transport.py)
- Unified MCP manager for all transport types (manager.py)

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

Author: Artemis (Implementation)
Created: 2025-11-27 (Phase: MCP Preset Integration)
"""

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
]
