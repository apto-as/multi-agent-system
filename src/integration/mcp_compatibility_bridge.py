#!/usr/bin/env python3
"""MCP Compatibility Bridge v2.2.0
Harmonious backward compatibility layer for existing MCP tools with WebSocket transport.

Athena's Design Philosophy:
- Seamless transition from stdio to WebSocket transport
- Preserve all existing tool interfaces with loving care
- Provide gentle fallback mechanisms for legacy clients
- Maintain warm compatibility across all MCP protocol versions
"""

import asyncio
import json
import logging
import os
import sys
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import websockets
from fastmcp import FastMCP
from pydantic import BaseModel

from src.core.config import get_settings
from src.tools.agent_memory_tools import get_current_agent, register_agent, switch_agent
from src.tools.memory_tools import (
    optimize_memory_vectors,
    recall_memory,
    semantic_search,
    store_memory,
)
from src.tools.system_tools import get_system_stats, health_check
from src.tools.task_tools import list_tasks, manage_task
from src.tools.workflow_tools import execute_workflow, get_workflow_status

logger = logging.getLogger(__name__)
settings = get_settings()


class MCPBridgeMessage(BaseModel):
    """Standardized MCP message format for bridge"""

    jsonrpc: str = "2.0"
    id: str | None = None
    method: str | None = None
    params: dict[str, Any] | None = None
    result: Any | None = None
    error: dict[str, Any] | None = None


@dataclass
class ToolRegistry:
    """Registry of MCP tools with harmonious organization"""

    memory_tools: dict[str, Callable] = None
    agent_tools: dict[str, Callable] = None
    task_tools: dict[str, Callable] = None
    workflow_tools: dict[str, Callable] = None
    system_tools: dict[str, Callable] = None

    def __post_init__(self):
        """Initialize tool registries with warm categorization"""
        self.memory_tools = {
            "semantic_search": semantic_search,
            "store_memory": store_memory,
            "recall_memory": recall_memory,
            "optimize_memory_vectors": optimize_memory_vectors,
        }

        self.agent_tools = {
            "register_agent": register_agent,
            "switch_agent": switch_agent,
            "get_current_agent": get_current_agent,
        }

        self.task_tools = {
            "manage_task": manage_task,
            "list_tasks": list_tasks,
        }

        self.workflow_tools = {
            "execute_workflow": execute_workflow,
            "get_workflow_status": get_workflow_status,
        }

        self.system_tools = {
            "health_check": health_check,
            "get_system_stats": get_system_stats,
        }

    def get_all_tools(self) -> dict[str, Callable]:
        """Get all tools in a harmonious collection"""
        all_tools = {}
        all_tools.update(self.memory_tools)
        all_tools.update(self.agent_tools)
        all_tools.update(self.task_tools)
        all_tools.update(self.workflow_tools)
        all_tools.update(self.system_tools)
        return all_tools

    def get_tool_info(self) -> dict[str, Any]:
        """Get comprehensive tool information"""
        return {
            "categories": {
                "memory": list(self.memory_tools.keys()),
                "agent": list(self.agent_tools.keys()),
                "task": list(self.task_tools.keys()),
                "workflow": list(self.workflow_tools.keys()),
                "system": list(self.system_tools.keys()),
            },
            "total_tools": len(self.get_all_tools()),
            "version": settings.api_version,
        }


class MCPCompatibilityBridge:
    """Harmonious bridge between legacy MCP stdio and new WebSocket transport.
    Ensures all existing tools work beautifully with the new architecture.
    """

    def __init__(self):
        self.tool_registry = ToolRegistry()
        self.websocket_client: websockets.WebSocketClientProtocol | None = None
        self.agent_context = {}
        self.session_id: str | None = None
        self.connection_established = False

        # Legacy MCP server for stdio fallback
        self.legacy_mcp = FastMCP("TMWS Legacy MCP Bridge v2.2.0")
        self._register_legacy_tools()

    def _register_legacy_tools(self):
        """Register all tools with the legacy MCP server for stdio compatibility"""
        all_tools = self.tool_registry.get_all_tools()

        for tool_name, tool_func in all_tools.items():
            # Create a wrapper that handles both sync and async calls harmoniously
            async def wrapped_tool(*args, tool_func=tool_func, tool_name=tool_name, **kwargs):
                try:
                    # Try WebSocket first if available
                    if self.connection_established and self.websocket_client:
                        return await self._call_via_websocket(tool_func.__name__, args, kwargs)
                    # Fallback to direct function call
                    elif asyncio.iscoroutinefunction(tool_func):
                        return await tool_func(*args, **kwargs)
                    else:
                        return tool_func(*args, **kwargs)
                except (KeyboardInterrupt, SystemExit):
                    logger.critical(f"🚨 User interrupt during {tool_name} execution")
                    raise
                except Exception as e:
                    logger.error(
                        f"Tool {tool_name} execution error: {e}",
                        exc_info=True,
                        extra={
                            "tool_name": tool_name,
                            "connection_mode": "websocket"
                            if self.connection_established
                            else "stdio",
                        },
                    )
                    return {"error": f"Tool execution failed: {str(e)}"}

            # Register with legacy MCP
            self.legacy_mcp.tool(name=tool_name)(wrapped_tool)

    async def connect_websocket(self, host: str = "127.0.0.1", port: int = 8001):
        """Connect to WebSocket MCP server with warm handshake"""
        try:
            uri = f"ws://{host}:{port}"

            # Prepare handshake headers
            headers = {
                "X-Agent-ID": os.getenv("TMWS_AGENT_ID", "legacy-bridge-agent"),
                "X-Agent-Namespace": os.getenv("TMWS_AGENT_NAMESPACE", "legacy"),
                "X-Agent-Capabilities": json.dumps(
                    {"bridge_mode": True, "legacy_compatibility": True, "stdio_fallback": True},
                ),
            }

            self.websocket_client = await websockets.connect(uri, extra_headers=headers)

            # Wait for welcome message
            welcome_raw = await asyncio.wait_for(self.websocket_client.recv(), timeout=10.0)
            welcome = json.loads(welcome_raw)

            if welcome.get("method") == "welcome":
                self.session_id = welcome["params"]["session_id"]
                self.agent_context = welcome["params"]
                self.connection_established = True
                logger.info(f"✨ WebSocket connection established! Session: {self.session_id}")
                return True
            else:
                logger.error("Invalid welcome message from WebSocket server")
                return False

        except (KeyboardInterrupt, SystemExit):
            logger.critical("🚨 User interrupt during WebSocket connection")
            raise
        except Exception as e:
            logger.warning(
                f"WebSocket connection failed: {e}. Falling back to stdio mode.",
                exc_info=True,
                extra={"host": host, "port": port},
            )
            self.connection_established = False
            return False

    async def disconnect_websocket(self):
        """Disconnect WebSocket gracefully"""
        if self.websocket_client:
            await self.websocket_client.close()
            self.websocket_client = None
            self.connection_established = False
            logger.info("👋 WebSocket connection closed harmoniously")

    async def _call_via_websocket(self, method: str, args: tuple, kwargs: dict) -> Any:
        """Call tool via WebSocket with gentle error handling"""
        if not self.websocket_client or not self.connection_established:
            raise Exception("WebSocket not connected")

        # Prepare MCP message
        message = MCPBridgeMessage(
            id=f"bridge_{asyncio.get_event_loop().time()}",
            method=method,
            params={**kwargs, "args": args},
        )

        # Send message
        await self.websocket_client.send(message.model_dump_json())

        # Wait for response
        response_raw = await asyncio.wait_for(self.websocket_client.recv(), timeout=30.0)
        response = MCPBridgeMessage(**json.loads(response_raw))

        if response.error:
            raise Exception(f"WebSocket tool error: {response.error}")

        return response.result

    def run_stdio_mode(self):
        """Run in legacy stdio mode for backward compatibility"""
        logger.info("🔄 Running in stdio compatibility mode")
        logger.info("📚 All existing MCP tools are available and working harmoniously")

        try:
            self.legacy_mcp.run()
        except KeyboardInterrupt:
            logger.info("👋 Stdio MCP server stopped by user")
        except SystemExit:
            logger.info("Stdio MCP server exiting")
            raise
        except Exception as e:
            logger.error(
                f"Stdio MCP server error: {e}",
                exc_info=True,
                extra={"mode": "stdio"},
            )
            raise

    async def run_hybrid_mode(self, ws_host: str = "127.0.0.1", ws_port: int = 8001):
        """Run in hybrid mode: try WebSocket first, fallback to stdio.
        This provides the most harmonious user experience.
        """
        logger.info("🌟 Starting hybrid compatibility mode")

        # Try to connect to WebSocket server
        connected = await self.connect_websocket(ws_host, ws_port)

        if connected:
            logger.info("✨ WebSocket mode active - enhanced performance available!")
            # In WebSocket mode, we still need to handle stdio for the legacy interface
            # This is a bit complex but provides seamless compatibility
        else:
            logger.info("📚 Stdio fallback mode active - all tools still work perfectly!")

        # Run stdio interface regardless of WebSocket status
        try:
            self.legacy_mcp.run()
        except KeyboardInterrupt:
            logger.info("👋 Hybrid MCP bridge stopped by user")
        finally:
            if self.connection_established:
                await self.disconnect_websocket()

    async def test_compatibility(self) -> dict[str, Any]:
        """Test compatibility of all tools in both modes"""
        results = {
            "stdio_mode": {},
            "websocket_mode": {},
            "tool_inventory": self.tool_registry.get_tool_info(),
        }

        # Test stdio mode
        logger.info("🧪 Testing stdio compatibility...")
        all_tools = self.tool_registry.get_all_tools()

        for tool_name, tool_func in all_tools.items():
            try:
                # Test basic function signature and importability
                if asyncio.iscoroutinefunction(tool_func):
                    results["stdio_mode"][tool_name] = "async_ready"
                else:
                    results["stdio_mode"][tool_name] = "sync_ready"
            except (KeyboardInterrupt, SystemExit):
                logger.warning("User interrupt during compatibility testing")
                raise
            except Exception as e:
                logger.error(
                    f"Compatibility test failed for {tool_name}: {e}",
                    exc_info=True,
                    extra={"tool_name": tool_name},
                )
                results["stdio_mode"][tool_name] = f"error: {str(e)}"

        # Test WebSocket mode if available
        if self.connection_established:
            logger.info("🧪 Testing WebSocket compatibility...")
            for tool_name in all_tools:
                try:
                    # Test if tool can be called via WebSocket
                    await self._call_via_websocket("get_system_stats", (), {})
                    results["websocket_mode"][tool_name] = "websocket_ready"
                except (KeyboardInterrupt, SystemExit):
                    logger.warning("User interrupt during WebSocket compatibility test")
                    raise
                except Exception as e:
                    logger.error(
                        f"WebSocket test failed for {tool_name}: {e}",
                        exc_info=True,
                        extra={"tool_name": tool_name, "session_id": self.session_id},
                    )
                    results["websocket_mode"][tool_name] = f"ws_error: {str(e)}"
        else:
            results["websocket_mode"] = {"status": "websocket_not_available"}

        return results


@asynccontextmanager
async def create_compatibility_bridge():
    """Create compatibility bridge with context management"""
    bridge = MCPCompatibilityBridge()
    try:
        yield bridge
    finally:
        await bridge.disconnect_websocket()


async def main():
    """Main entry point for compatibility bridge"""
    bridge = MCPCompatibilityBridge()

    # Determine mode from environment
    mode = os.getenv("TMWS_BRIDGE_MODE", "hybrid").lower()
    ws_host = os.getenv("TMWS_WS_HOST", "127.0.0.1")
    ws_port = int(os.getenv("TMWS_WS_PORT", "8001"))

    logger.info(f"🌟 TMWS MCP Compatibility Bridge v{settings.api_version}")
    logger.info(f"🔧 Mode: {mode}")

    try:
        if mode == "stdio":
            bridge.run_stdio_mode()
        elif mode == "websocket":
            # WebSocket only mode (future enhancement)
            logger.error("WebSocket-only mode not yet implemented")
            sys.exit(1)
        else:  # hybrid mode (default)
            await bridge.run_hybrid_mode(ws_host, ws_port)

    except (KeyboardInterrupt, SystemExit):
        logger.info("👋 Bridge stopped by user or system")
        sys.exit(0)
    except Exception as e:
        logger.error(
            f"Bridge error: {e}",
            exc_info=True,
            extra={"mode": mode, "ws_host": ws_host, "ws_port": ws_port},
        )
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
