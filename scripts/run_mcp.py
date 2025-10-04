#!/usr/bin/env python3
"""
Simple TMWS MCP Server Runner v2.1.0
For direct Claude Desktop integration.

Usage:
    python run_mcp.py

Environment Variables:
    TMWS_AGENT_ID - Agent identifier
    TMWS_AGENT_NAMESPACE - Agent namespace (default: "default")
    TMWS_AGENT_CAPABILITIES - JSON string of agent capabilities
"""

import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import and run the MCP server
from src.mcp_server import run_server

if __name__ == "__main__":
    run_server()
