"""TMWS Integration Package
Provides integration modules for various protocols and frameworks.

Note: FastAPI integration has been removed in v3.0.
TMWS now operates as a pure MCP server.
"""

from .genai_toolbox_bridge import GenAIToolboxBridge

__all__ = ["GenAIToolboxBridge"]
