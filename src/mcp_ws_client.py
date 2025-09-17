#!/usr/bin/env python3
"""
TMWS WebSocket MCP Client v2.2.0
Harmonious client implementation for connecting Claude Desktop to WebSocket MCP server.

Athena's Design Philosophy:
- Gentle connection management with automatic reconnection
- Seamless protocol translation between Claude Desktop and WebSocket
- Warm error handling with graceful degradation
- Beautiful integration with existing MCP ecosystem
"""

import asyncio
import json
import logging
import os
import sys
import uuid
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from contextlib import asynccontextmanager

import websockets
from websockets.client import WebSocketClientProtocol
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class MCPClientMessage(BaseModel):
    """MCP client message format"""
    jsonrpc: str = "2.0"
    id: Optional[str] = None
    method: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None


@dataclass
class ConnectionConfig:
    """WebSocket connection configuration"""
    host: str = "127.0.0.1"
    port: int = 8001
    agent_id: str = "claude-desktop-client"
    namespace: str = "default"
    capabilities: Dict[str, Any] = None
    timeout: float = 30.0
    reconnect_attempts: int = 3
    reconnect_delay: float = 5.0

    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = {
                "client_type": "claude_desktop",
                "protocol_version": "2.2.0",
                "supports_websocket": True
            }

    @property
    def uri(self) -> str:
        """Get WebSocket URI"""
        return f"ws://{self.host}:{self.port}"

    @property
    def headers(self) -> Dict[str, str]:
        """Get connection headers"""
        return {
            "X-Agent-ID": self.agent_id,
            "X-Agent-Namespace": self.namespace,
            "X-Agent-Capabilities": json.dumps(self.capabilities)
        }


class WebSocketMCPClient:
    """
    Harmonious WebSocket MCP client for Claude Desktop integration.
    Provides seamless communication with TMWS WebSocket server.
    """

    def __init__(self, config: ConnectionConfig):
        self.config = config
        self.websocket: Optional[WebSocketClientProtocol] = None
        self.session_id: Optional[str] = None
        self.connected = False
        self.running = False
        self.pending_requests: Dict[str, asyncio.Future] = {}
        self.message_queue = asyncio.Queue()

    async def connect(self) -> bool:
        """Connect to WebSocket server with warm handshake"""
        for attempt in range(self.config.reconnect_attempts):
            try:
                logger.info(f"🌟 Connecting to TMWS WebSocket server at {self.config.uri}")

                self.websocket = await websockets.connect(
                    self.config.uri,
                    extra_headers=self.config.headers,
                    ping_interval=20,
                    ping_timeout=10,
                    close_timeout=10
                )

                # Wait for welcome message
                welcome_raw = await asyncio.wait_for(
                    self.websocket.recv(),
                    timeout=self.config.timeout
                )

                welcome_data = json.loads(welcome_raw)
                welcome = MCPClientMessage(**welcome_data)

                if welcome.method == "welcome" and welcome.params:
                    self.session_id = welcome.params.get("session_id")
                    self.connected = True
                    logger.info(f"✨ Connected! Session ID: {self.session_id}")
                    return True
                else:
                    logger.error("Invalid welcome message received")
                    return False

            except Exception as e:
                logger.warning(f"Connection attempt {attempt + 1} failed: {e}")
                if attempt < self.config.reconnect_attempts - 1:
                    logger.info(f"⏳ Retrying in {self.config.reconnect_delay} seconds...")
                    await asyncio.sleep(self.config.reconnect_delay)

        logger.error("❌ Failed to connect after all attempts")
        return False

    async def disconnect(self):
        """Disconnect gracefully"""
        if self.websocket:
            try:
                await self.websocket.close()
                logger.info("👋 Disconnected gracefully")
            except Exception as e:
                logger.error(f"Disconnect error: {e}")
            finally:
                self.websocket = None
                self.connected = False
                self.session_id = None

    async def send_request(self, method: str, params: Dict[str, Any] = None) -> Any:
        """Send MCP request and wait for response"""
        if not self.connected or not self.websocket:
            raise Exception("Not connected to server")

        request_id = str(uuid.uuid4())
        message = MCPClientMessage(
            id=request_id,
            method=method,
            params=params or {}
        )

        # Create future for response
        response_future = asyncio.Future()
        self.pending_requests[request_id] = response_future

        try:
            # Send request
            await self.websocket.send(message.model_dump_json())
            logger.debug(f"📤 Sent request: {method} (ID: {request_id})")

            # Wait for response
            result = await asyncio.wait_for(
                response_future,
                timeout=self.config.timeout
            )

            return result

        except asyncio.TimeoutError:
            raise Exception(f"Request {method} timed out")
        except Exception as e:
            raise Exception(f"Request {method} failed: {str(e)}")
        finally:
            # Cleanup
            self.pending_requests.pop(request_id, None)

    async def _handle_incoming_messages(self):
        """Handle incoming WebSocket messages"""
        try:
            async for raw_message in self.websocket:
                try:
                    data = json.loads(raw_message)
                    message = MCPClientMessage(**data)

                    if message.id and message.id in self.pending_requests:
                        # This is a response to a pending request
                        future = self.pending_requests[message.id]
                        if message.error:
                            future.set_exception(Exception(message.error.get("message", "Unknown error")))
                        else:
                            future.set_result(message.result)
                    else:
                        # This is a notification or unsolicited message
                        await self.message_queue.put(message)
                        logger.debug(f"📥 Received notification: {message.method}")

                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON received: {e}")
                except Exception as e:
                    logger.error(f"Message processing error: {e}")

        except websockets.exceptions.ConnectionClosed:
            logger.info("🔌 WebSocket connection closed")
            self.connected = False
        except Exception as e:
            logger.error(f"Message handling error: {e}")
            self.connected = False

    async def start_message_loop(self):
        """Start the message handling loop"""
        if not self.connected:
            raise Exception("Not connected to server")

        self.running = True
        logger.info("🔄 Message loop started")

        try:
            await self._handle_incoming_messages()
        finally:
            self.running = False
            logger.info("🛑 Message loop stopped")

    async def stop(self):
        """Stop client gracefully"""
        self.running = False
        await self.disconnect()

    # Convenience methods for common MCP operations

    async def get_agent_info(self) -> Dict[str, Any]:
        """Get agent information"""
        return await self.send_request("get_agent_info")

    async def create_memory(
        self,
        content: str,
        tags: List[str] = None,
        importance: float = 0.5,
        access_level: str = "private"
    ) -> Dict[str, Any]:
        """Create a memory"""
        return await self.send_request("create_memory", {
            "content": content,
            "tags": tags or [],
            "importance": importance,
            "access_level": access_level
        })

    async def search_memories(
        self,
        query: str,
        limit: int = 10,
        min_importance: float = 0.0,
        include_shared: bool = True
    ) -> Dict[str, Any]:
        """Search memories"""
        return await self.send_request("search_memories", {
            "query": query,
            "limit": limit,
            "min_importance": min_importance,
            "include_shared": include_shared
        })

    async def get_session_statistics(self) -> Dict[str, Any]:
        """Get session statistics"""
        return await self.send_request("get_session_statistics")


class StdioToWebSocketBridge:
    """
    Bridge that translates stdio MCP protocol to WebSocket.
    This allows Claude Desktop to use WebSocket server transparently.
    """

    def __init__(self, config: ConnectionConfig):
        self.client = WebSocketMCPClient(config)
        self.stdio_running = False

    async def start_bridge(self):
        """Start the stdio-to-WebSocket bridge"""
        logger.info("🌉 Starting stdio-to-WebSocket bridge")

        # Connect to WebSocket server
        if not await self.client.connect():
            logger.error("❌ Failed to connect to WebSocket server")
            sys.exit(1)

        # Start message loop in background
        message_task = asyncio.create_task(self.client.start_message_loop())

        try:
            # Handle stdio communication
            await self._handle_stdio_communication()
        finally:
            # Cleanup
            message_task.cancel()
            await self.client.stop()

    async def _handle_stdio_communication(self):
        """Handle stdio MCP protocol communication"""
        self.stdio_running = True
        logger.info("📖 Stdio communication started")

        try:
            # Read from stdin and write to stdout
            while self.stdio_running and self.client.connected:
                # Read line from stdin
                try:
                    line = await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline),
                        timeout=1.0
                    )

                    if not line:
                        break

                    line = line.strip()
                    if not line:
                        continue

                    # Parse MCP message
                    try:
                        data = json.loads(line)
                        message = MCPClientMessage(**data)

                        # Forward to WebSocket server
                        if message.method:
                            result = await self.client.send_request(message.method, message.params)

                            # Send response to stdout
                            response = MCPClientMessage(
                                id=message.id,
                                result=result
                            )
                            print(response.model_dump_json(), flush=True)

                    except json.JSONDecodeError:
                        # Send error response
                        error_response = MCPClientMessage(
                            id=getattr(message, 'id', None),
                            error={"code": -32700, "message": "Parse error"}
                        )
                        print(error_response.model_dump_json(), flush=True)

                except asyncio.TimeoutError:
                    # No input, continue
                    continue
                except Exception as e:
                    logger.error(f"Stdio handling error: {e}")
                    break

        except Exception as e:
            logger.error(f"Stdio communication error: {e}")
        finally:
            self.stdio_running = False
            logger.info("📖 Stdio communication stopped")


def create_claude_desktop_config(
    ws_host: str = "127.0.0.1",
    ws_port: int = 8001,
    agent_id: str = "claude-desktop-client"
) -> str:
    """Create Claude Desktop configuration for WebSocket MCP"""
    bridge_script = os.path.abspath(__file__)

    config = {
        "mcpServers": {
            "tmws-websocket": {
                "command": "python",
                "args": [bridge_script, "--bridge-mode"],
                "env": {
                    "TMWS_WS_HOST": ws_host,
                    "TMWS_WS_PORT": str(ws_port),
                    "TMWS_AGENT_ID": agent_id,
                    "TMWS_CLIENT_MODE": "claude_desktop"
                }
            }
        }
    }

    return json.dumps(config, indent=2)


async def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="TMWS WebSocket MCP Client")
    parser.add_argument("--host", default="127.0.0.1", help="WebSocket server host")
    parser.add_argument("--port", type=int, default=8001, help="WebSocket server port")
    parser.add_argument("--agent-id", default="claude-desktop-client", help="Agent ID")
    parser.add_argument("--bridge-mode", action="store_true", help="Run as stdio bridge")
    parser.add_argument("--test", action="store_true", help="Run connection test")
    parser.add_argument("--config", action="store_true", help="Generate Claude Desktop config")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    if args.config:
        # Generate Claude Desktop configuration
        config = create_claude_desktop_config(args.host, args.port, args.agent_id)
        print("📋 Claude Desktop configuration:")
        print(config)
        return

    # Create connection config
    config = ConnectionConfig(
        host=args.host,
        port=args.port,
        agent_id=args.agent_id
    )

    if args.bridge_mode:
        # Run as stdio-to-WebSocket bridge
        bridge = StdioToWebSocketBridge(config)
        try:
            await bridge.start_bridge()
        except KeyboardInterrupt:
            logger.info("👋 Bridge stopped by user")
    elif args.test:
        # Run connection test
        client = WebSocketMCPClient(config)
        try:
            if await client.connect():
                logger.info("✅ Connection test successful!")

                # Test basic operations
                info = await client.get_agent_info()
                logger.info(f"Agent info: {info}")

                stats = await client.get_session_statistics()
                logger.info(f"Session stats: {stats}")

            else:
                logger.error("❌ Connection test failed")
                sys.exit(1)
        finally:
            await client.disconnect()
    else:
        # Interactive mode
        client = WebSocketMCPClient(config)
        try:
            if await client.connect():
                logger.info("🎉 Connected! You can now use the client interactively.")
                logger.info("💡 Try: client.create_memory('Hello WebSocket world!')")

                # Keep alive
                while client.connected:
                    await asyncio.sleep(1)
            else:
                logger.error("❌ Failed to connect")
                sys.exit(1)
        except KeyboardInterrupt:
            logger.info("👋 Client stopped by user")
        finally:
            await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())