"""STDIO Transport for MCP Servers.

This module implements STDIO-based communication with MCP servers.
The MCP server is launched as a subprocess and communication happens via stdin/stdout
using JSON-RPC 2.0 protocol.

Protocol:
- Each message is a JSON object on a single line
- Messages are separated by newlines
- Request format: {"jsonrpc": "2.0", "method": "...", "params": {...}, "id": 1}
- Response format: {"jsonrpc": "2.0", "result": {...}, "id": 1}
- Notification format: {"jsonrpc": "2.0", "method": "...", "params": {...}}

Author: Artemis (Implementation)
Created: 2025-11-27 (Phase: MCP Preset Integration)
"""

import asyncio
import contextlib
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from src.domain.entities.tool import Tool
from src.infrastructure.acl.mcp_protocol_translator import MCPProtocolTranslator
from src.infrastructure.exceptions import (
    MCPConnectionError,
    MCPProtocolError,
)
from src.infrastructure.mcp.preset_config import MCPServerPreset, MCPTransportType

logger = logging.getLogger(__name__)


@dataclass
class MCPMessage:
    """JSON-RPC 2.0 message for MCP protocol."""

    jsonrpc: str = "2.0"
    method: str | None = None
    params: dict[str, Any] | None = None
    result: Any = None
    error: dict[str, Any] | None = None
    id: str | int | None = None

    def to_json(self) -> str:
        """Serialize message to JSON string."""
        msg = {"jsonrpc": self.jsonrpc}

        if self.method:
            msg["method"] = self.method
        if self.params is not None:
            msg["params"] = self.params
        if self.result is not None:
            msg["result"] = self.result
        if self.error is not None:
            msg["error"] = self.error
        if self.id is not None:
            msg["id"] = self.id

        return json.dumps(msg)

    @classmethod
    def from_json(cls, data: str) -> "MCPMessage":
        """Parse JSON string into MCPMessage."""
        parsed = json.loads(data)
        return cls(
            jsonrpc=parsed.get("jsonrpc", "2.0"),
            method=parsed.get("method"),
            params=parsed.get("params"),
            result=parsed.get("result"),
            error=parsed.get("error"),
            id=parsed.get("id"),
        )


@dataclass
class STDIOTransport:
    """STDIO transport for MCP server communication.

    Launches an MCP server as a subprocess and communicates via stdin/stdout.
    Uses JSON-RPC 2.0 protocol for message exchange.

    Attributes:
        preset: MCP server preset configuration
        process: Subprocess running the MCP server
        translator: Protocol translator for domain conversion
        pending_requests: Map of request ID -> Future for pending responses
        _request_id: Counter for generating unique request IDs
        _reader_task: Background task for reading responses

    Example:
        >>> preset = MCPServerPreset(
        ...     name="context7",
        ...     command="npx",
        ...     args=["-y", "@context7/mcp-server"]
        ... )
        >>> transport = STDIOTransport(preset)
        >>> await transport.connect()
        >>> tools = await transport.list_tools()
        >>> await transport.disconnect()
    """

    preset: MCPServerPreset
    process: asyncio.subprocess.Process | None = None
    translator: MCPProtocolTranslator = field(default_factory=MCPProtocolTranslator)
    pending_requests: dict[str | int, asyncio.Future] = field(default_factory=dict)
    _request_id: int = 0
    _reader_task: asyncio.Task | None = None
    _connected: bool = False

    async def connect(self) -> bool:
        """Start the MCP server subprocess and establish communication.

        Returns:
            True if connection successful

        Raises:
            MCPConnectionError: If server fails to start
        """
        if self.preset.transport_type != MCPTransportType.STDIO:
            raise MCPConnectionError(
                f"STDIOTransport requires STDIO preset, got {self.preset.transport_type}",
                details={"server_name": self.preset.name},
            )

        if not self.preset.command:
            raise MCPConnectionError(
                "STDIO preset missing command", details={"server_name": self.preset.name}
            )

        try:
            # Build command
            cmd = [self.preset.command] + self.preset.args

            # Build environment
            env = os.environ.copy()
            env.update(self.preset.get_resolved_env())

            # Determine working directory
            cwd = self.preset.cwd or os.getcwd()

            logger.info(f"Starting MCP server: {' '.join(cmd)}")
            logger.debug(f"Working directory: {cwd}")

            # Start subprocess
            self.process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
            )

            # Start background reader for responses
            self._reader_task = asyncio.create_task(self._read_responses())

            # Initialize MCP connection
            await self._initialize()

            self._connected = True
            logger.info(f"Connected to MCP server: {self.preset.name}")
            return True

        except FileNotFoundError as e:
            raise MCPConnectionError(
                f"MCP server command not found: {self.preset.command}",
                details={"server_name": self.preset.name, "error": str(e)},
            ) from e
        except Exception as e:
            raise MCPConnectionError(
                f"Failed to start MCP server: {e}",
                details={"server_name": self.preset.name, "error": str(e)},
            ) from e

    async def disconnect(self) -> None:
        """Stop the MCP server subprocess."""
        self._connected = False

        # Cancel reader task
        if self._reader_task:
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reader_task
            self._reader_task = None

        # Terminate process
        if self.process:
            try:
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()
            except Exception as e:
                logger.warning(f"Error terminating MCP server: {e}")
            finally:
                self.process = None

        # Clear pending requests
        for future in self.pending_requests.values():
            if not future.done():
                future.set_exception(MCPConnectionError("Connection closed"))
        self.pending_requests.clear()

        logger.info(f"Disconnected from MCP server: {self.preset.name}")

    async def list_tools(self) -> list[Tool]:
        """Get list of available tools from MCP server.

        Returns:
            List of Tool entities

        Raises:
            MCPConnectionError: If not connected
            MCPProtocolError: If response format is invalid
        """
        if not self._connected:
            raise MCPConnectionError(
                "Not connected to MCP server", details={"server_name": self.preset.name}
            )

        response = await self._send_request("tools/list", {})

        if "tools" not in response:
            raise MCPProtocolError(
                "Invalid tools/list response: missing 'tools' field", details={"response": response}
            )

        # Convert to domain Tool entities
        tools = []
        for tool_data in response["tools"]:
            try:
                tool = self.translator.mcp_tool_to_domain(tool_data)
                tools.append(tool)
            except Exception as e:
                logger.warning(f"Failed to parse tool: {e}")
                continue

        return tools

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool on the MCP server.

        Args:
            tool_name: Name of tool to execute
            arguments: Tool arguments

        Returns:
            Tool execution result

        Raises:
            MCPConnectionError: If not connected
            MCPToolNotFoundError: If tool doesn't exist
            MCPProtocolError: If execution fails
        """
        if not self._connected:
            raise MCPConnectionError(
                "Not connected to MCP server", details={"server_name": self.preset.name}
            )

        response = await self._send_request(
            "tools/call",
            {
                "name": tool_name,
                "arguments": arguments,
            },
        )

        return response

    async def _initialize(self) -> None:
        """Initialize MCP connection with handshake.

        Sends initialize request and waits for server capabilities.
        """
        # Send initialize request
        response = await self._send_request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "roots": {"listChanged": True},
                },
                "clientInfo": {
                    "name": "tmws",
                    "version": "2.4.2",
                },
            },
        )

        logger.debug(f"MCP server capabilities: {response.get('capabilities', {})}")

        # Send initialized notification
        await self._send_notification("notifications/initialized", {})

    async def _send_request(
        self, method: str, params: dict[str, Any], timeout: float = 30.0
    ) -> dict[str, Any]:
        """Send a request and wait for response.

        Args:
            method: RPC method name
            params: Method parameters
            timeout: Response timeout in seconds

        Returns:
            Response result

        Raises:
            MCPProtocolError: If request fails or times out
        """
        if not self.process or not self.process.stdin:
            raise MCPConnectionError("Not connected")

        # Generate request ID
        self._request_id += 1
        request_id = self._request_id

        # Create request message
        message = MCPMessage(
            method=method,
            params=params,
            id=request_id,
        )

        # Create future for response
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self.pending_requests[request_id] = future

        try:
            # Send request
            line = message.to_json() + "\n"
            self.process.stdin.write(line.encode())
            await self.process.stdin.drain()

            logger.debug(f"Sent request: {method} (id={request_id})")

            # Wait for response
            response = await asyncio.wait_for(future, timeout=timeout)
            return response

        except asyncio.TimeoutError:
            self.pending_requests.pop(request_id, None)
            raise MCPProtocolError(
                f"Request timeout: {method}", details={"method": method, "timeout": timeout}
            )
        except Exception:
            self.pending_requests.pop(request_id, None)
            raise

    async def _send_notification(self, method: str, params: dict[str, Any]) -> None:
        """Send a notification (no response expected).

        Args:
            method: Notification method name
            params: Notification parameters
        """
        if not self.process or not self.process.stdin:
            raise MCPConnectionError("Not connected")

        message = MCPMessage(
            method=method,
            params=params,
            # No ID for notifications
        )

        line = message.to_json() + "\n"
        self.process.stdin.write(line.encode())
        await self.process.stdin.drain()

        logger.debug(f"Sent notification: {method}")

    async def _read_responses(self) -> None:
        """Background task to read responses from stdout."""
        if not self.process or not self.process.stdout:
            return

        try:
            while True:
                line = await self.process.stdout.readline()
                if not line:
                    break

                try:
                    message = MCPMessage.from_json(line.decode().strip())
                    await self._handle_message(message)
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON from MCP server: {e}")
                    continue

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Error reading from MCP server: {e}")

    async def _handle_message(self, message: MCPMessage) -> None:
        """Handle incoming message from MCP server.

        Args:
            message: Parsed MCP message
        """
        # Response to a request
        if message.id is not None:
            future = self.pending_requests.pop(message.id, None)
            if future:
                if message.error:
                    future.set_exception(
                        MCPProtocolError(
                            f"MCP error: {message.error.get('message', 'Unknown error')}",
                            details=message.error,
                        )
                    )
                else:
                    future.set_result(message.result or {})
            else:
                logger.warning(f"Received response for unknown request: {message.id}")

        # Notification from server
        elif message.method:
            logger.debug(f"Received notification: {message.method}")
            # Handle specific notifications if needed
            if message.method == "notifications/tools/list_changed":
                logger.info("MCP server tools changed, consider refreshing tool list")

    @property
    def is_connected(self) -> bool:
        """Check if transport is connected."""
        return self._connected and self.process is not None


class STDIOTransportManager:
    """Manages multiple STDIO transports.

    Handles lifecycle of multiple MCP server connections,
    including auto-connect on startup.

    Example:
        >>> manager = STDIOTransportManager()
        >>> await manager.connect_preset(context7_preset)
        >>> tools = await manager.list_all_tools()
        >>> await manager.disconnect_all()
    """

    def __init__(self):
        """Initialize transport manager."""
        self.transports: dict[str, STDIOTransport] = {}

    async def connect_preset(self, preset: MCPServerPreset) -> STDIOTransport:
        """Connect to an MCP server using preset configuration.

        Args:
            preset: Server preset configuration

        Returns:
            Connected STDIOTransport

        Raises:
            MCPConnectionError: If connection fails
        """
        if preset.name in self.transports:
            existing = self.transports[preset.name]
            if existing.is_connected:
                return existing
            # Reconnect if disconnected
            await existing.disconnect()

        transport = STDIOTransport(preset=preset)
        await transport.connect()
        self.transports[preset.name] = transport
        return transport

    async def disconnect(self, server_name: str) -> None:
        """Disconnect from a specific server.

        Args:
            server_name: Name of server to disconnect
        """
        transport = self.transports.pop(server_name, None)
        if transport:
            await transport.disconnect()

    async def disconnect_all(self) -> None:
        """Disconnect from all servers."""
        for name in list(self.transports.keys()):
            await self.disconnect(name)

    def get_transport(self, server_name: str) -> STDIOTransport | None:
        """Get transport by server name.

        Args:
            server_name: Name of server

        Returns:
            STDIOTransport or None if not connected
        """
        return self.transports.get(server_name)

    async def list_all_tools(self) -> dict[str, list[Tool]]:
        """List tools from all connected servers.

        Returns:
            Dictionary of server_name -> list of Tools
        """
        result = {}
        for name, transport in self.transports.items():
            if transport.is_connected:
                try:
                    tools = await transport.list_tools()
                    result[name] = tools
                except Exception as e:
                    logger.warning(f"Failed to list tools from {name}: {e}")
                    result[name] = []
        return result
