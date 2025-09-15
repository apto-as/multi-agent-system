#!/usr/bin/env python3
"""
TMWS MCP WebSocket Client
Bridges stdio MCP protocol to WebSocket server for multi-client support.
"""

import sys
import json
import asyncio
import argparse
import logging
from typing import Optional, Dict, Any
import websockets
from websockets.client import WebSocketClientProtocol

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MCPWebSocketBridge:
    """Bridge between stdio MCP protocol and WebSocket server."""
    
    def __init__(self, server_url: str):
        """Initialize the bridge with server URL."""
        self.server_url = server_url
        self.websocket: Optional[WebSocketClientProtocol] = None
        self.running = False
        
    async def connect(self) -> bool:
        """Connect to the WebSocket server."""
        try:
            self.websocket = await websockets.connect(self.server_url)
            logger.info(f"Connected to WebSocket server at {self.server_url}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to server: {e}")
            return False
    
    async def stdin_reader(self):
        """Read from stdin and forward to WebSocket."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)
        
        while self.running:
            try:
                # Read line from stdin
                line = await reader.readline()
                if not line:
                    break
                    
                # Parse and forward to WebSocket
                message = line.decode('utf-8').strip()
                if message:
                    await self.websocket.send(message)
                    logger.debug(f"Sent to server: {message[:100]}...")
                    
            except Exception as e:
                logger.error(f"Error reading stdin: {e}")
                break
    
    async def websocket_reader(self):
        """Read from WebSocket and forward to stdout."""
        while self.running:
            try:
                # Receive from WebSocket
                message = await self.websocket.recv()
                
                # Forward to stdout
                sys.stdout.write(message)
                if not message.endswith('\n'):
                    sys.stdout.write('\n')
                sys.stdout.flush()
                
                logger.debug(f"Received from server: {message[:100]}...")
                
            except websockets.exceptions.ConnectionClosed:
                logger.info("WebSocket connection closed")
                break
            except Exception as e:
                logger.error(f"Error reading WebSocket: {e}")
                break
    
    async def run(self):
        """Run the bridge."""
        # Connect to server
        if not await self.connect():
            return 1
        
        self.running = True
        
        try:
            # Run both readers concurrently
            await asyncio.gather(
                self.stdin_reader(),
                self.websocket_reader()
            )
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        finally:
            self.running = False
            if self.websocket:
                await self.websocket.close()
            logger.info("Bridge shutdown complete")
        
        return 0


def main():
    """Main entry point for the WebSocket client."""
    parser = argparse.ArgumentParser(description="TMWS MCP WebSocket Client")
    parser.add_argument(
        "--server",
        default="ws://localhost:8000/ws/mcp",
        help="WebSocket server URL (default: ws://localhost:8000/ws/mcp)"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create and run bridge
    bridge = MCPWebSocketBridge(args.server)
    
    # Run event loop
    try:
        exit_code = asyncio.run(bridge.run())
        sys.exit(exit_code)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()