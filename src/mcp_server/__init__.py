"""TMWS MCP Server Package.

This package provides the MCP server implementation with hybrid memory architecture.

Main components:
- HybridMCPServer: Core server class (SQLite + ChromaDB)
- register_core_tools: MCP tool registration
- initialize_server: Server initialization logic
- main: CLI entry point

Backward compatibility aliases:
- TMWSFastMCPServer: Alias for HybridMCPServer
- create_server: Factory function
- run_server: Convenience runner
"""

from .constants import TRINITAS_AGENTS, __version__
from .server import HybridMCPServer
from .startup import async_main, first_run_setup, main, validate_license_at_startup

# Backward compatibility alias
TMWSFastMCPServer = HybridMCPServer


def create_server() -> HybridMCPServer:
    """Create a new HybridMCPServer instance.

    Returns:
        HybridMCPServer: Initialized server instance (not yet started)
    """
    return HybridMCPServer()


def run_server():
    """Run the TMWS MCP server.

    This is a convenience function that calls main() directly.
    It performs license validation and starts the server.
    """
    main()


__all__ = [
    # Core classes
    "HybridMCPServer",
    "TMWSFastMCPServer",
    # Constants
    "TRINITAS_AGENTS",
    "__version__",
    # Entry points
    "main",
    "async_main",
    "first_run_setup",
    "validate_license_at_startup",
    # Convenience functions
    "create_server",
    "run_server",
]
