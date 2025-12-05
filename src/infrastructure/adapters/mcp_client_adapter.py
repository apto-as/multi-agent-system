"""MCP Client Adapter (Infrastructure Layer).

This adapter communicates with external MCP servers via HTTP.
It handles connection lifecycle, authentication, retries, and timeouts.

Responsibilities:
- HTTP communication with MCP servers
- Connection lifecycle management
- Authentication (API key in Authorization header)
- Retry logic for failed requests
- Timeout handling
- Converting MCP protocol responses to domain objects

Design Pattern: Adapter (Infrastructure to External System)

Author: Artemis (Implementation)
Created: 2025-11-12 (Phase 1-1-B: Infrastructure Layer)
"""

import asyncio
from typing import Any

import httpx

from src.domain.entities.tool import Tool
from src.domain.value_objects.connection_config import ConnectionConfig
from src.infrastructure.acl.mcp_protocol_translator import MCPProtocolTranslator
from src.infrastructure.exceptions import (
    MCPConnectionError,
    MCPProtocolError,
    MCPToolNotFoundError,
)


class MCPClientAdapter:
    """Adapter for communicating with external MCP servers.

    This adapter handles all HTTP communication with MCP servers,
    including connection management, authentication, and error handling.

    Attributes:
        config: Connection configuration (URL, timeout, retries, etc.)
        _client: HTTP client instance (httpx.AsyncClient)
        _translator: Protocol translator (ACL)

    Example:
        >>> config = ConnectionConfig(
        ...     server_name="tmws",
        ...     url="http://localhost:8080/mcp"
        ... )
        >>> adapter = MCPClientAdapter(config)
        >>> await adapter.connect()
        >>> tools = await adapter.discover_tools()
        >>> await adapter.disconnect()
    """

    def __init__(self, config: ConnectionConfig):
        """Initialize MCP client adapter.

        Args:
            config: Connection configuration
        """
        self.config = config
        self._client: httpx.AsyncClient | None = None
        self._translator = MCPProtocolTranslator()
        self._connected = False

    async def connect(self) -> bool:
        """Establish connection to MCP server.

        Returns:
            True if connection successful

        Raises:
            MCPConnectionError: If connection fails after all retries
            TimeoutError: If connection timeout is reached

        Example:
            >>> adapter = MCPClientAdapter(config)
            >>> success = await adapter.connect()
            >>> assert success is True
        """
        # Build headers (with authentication if required)
        headers = self._build_headers()

        # Create HTTP client with timeout
        timeout = httpx.Timeout(self.config.timeout)
        self._client = httpx.AsyncClient(timeout=timeout, headers=headers)

        # Retry logic
        last_exception = None
        for attempt in range(self.config.retry_attempts):
            try:
                # Test connection with health check
                response = await self._client.get(f"{self.config.url}/health")

                if response.status_code == 200:
                    self._connected = True
                    return True

                # Non-200 response on final attempt
                if attempt == self.config.retry_attempts - 1:
                    raise MCPConnectionError(
                        f"Connection failed with status {response.status_code}",
                        details={"url": self.config.url, "status": response.status_code},
                    )

            except TimeoutError as e:
                last_exception = e
                if attempt == self.config.retry_attempts - 1:
                    raise
                await asyncio.sleep(0.5 * (attempt + 1))  # Exponential backoff

            except httpx.TimeoutException as e:
                # Convert httpx timeout to standard TimeoutError
                last_exception = TimeoutError(str(e))
                if attempt == self.config.retry_attempts - 1:
                    raise TimeoutError(str(e))
                await asyncio.sleep(0.5 * (attempt + 1))

            except Exception as e:
                last_exception = e
                if attempt == self.config.retry_attempts - 1:
                    raise MCPConnectionError(
                        f"Connection failed: {str(e)}",
                        details={"url": self.config.url, "error": str(e)},
                    )
                await asyncio.sleep(0.5 * (attempt + 1))

        # Should not reach here, but safety fallback
        if last_exception:
            raise last_exception

        return False

    async def disconnect(self) -> None:
        """Close connection to MCP server.

        Example:
            >>> await adapter.disconnect()
        """
        if self._client:
            await self._client.aclose()
            self._client = None
            self._connected = False

    async def discover_tools(self) -> list[Tool]:
        """Discover available tools from MCP server.

        Returns:
            List of Tool entities

        Raises:
            MCPConnectionError: If not connected
            MCPProtocolError: If response format is invalid

        Example:
            >>> tools = await adapter.discover_tools()
            >>> len(tools)
            5
        """
        if not self._client:
            raise MCPConnectionError(
                "Not connected to MCP server", details={"server_name": self.config.server_name}
            )

        # Get tools from MCP server
        response = await self._client.get(f"{self.config.url}/tools")

        if response.status_code != 200:
            raise MCPProtocolError(
                f"Failed to discover tools: HTTP {response.status_code}",
                details={"status_code": response.status_code},
            )

        # Parse response
        mcp_response = response.json()

        # Use ACL to convert to domain objects
        tools = self._translator.mcp_tools_response_to_domain(mcp_response)

        return tools

    async def execute_tool(self, tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool on the MCP server.

        Args:
            tool_name: Name of the tool to execute
            tool_args: Arguments for the tool

        Returns:
            Tool execution result (as dict)

        Raises:
            MCPConnectionError: If not connected
            MCPToolNotFoundError: If tool does not exist
            MCPProtocolError: If execution fails

        Example:
            >>> result = await adapter.execute_tool(
            ...     "search_memory", {"query": "test", "limit": 5}
            ... )
            >>> result["results"]
            ["memory1", "memory2"]
        """
        if not self._client:
            raise MCPConnectionError(
                "Not connected to MCP server", details={"server_name": self.config.server_name}
            )

        # Use ACL to convert domain request to MCP protocol format
        mcp_request = self._translator.domain_tool_execution_to_mcp(tool_name, tool_args)

        # Execute tool via POST request
        response = await self._client.post(f"{self.config.url}/tools/execute", json=mcp_request)

        # Handle error responses
        if response.status_code == 404:
            error_data = response.json()
            if "error" in error_data:
                # Use ACL to convert MCP error to exception
                exc = self._translator.mcp_error_to_exception(error_data)
                raise exc
            raise MCPToolNotFoundError(tool_name, available_tools=[])

        if response.status_code != 200:
            raise MCPProtocolError(
                f"Tool execution failed: HTTP {response.status_code}",
                details={"tool_name": tool_name, "status_code": response.status_code},
            )

        # Return result
        return response.json()

    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers for requests.

        Includes authentication if auth_required is True.

        Returns:
            Dictionary of HTTP headers

        Example:
            >>> headers = adapter._build_headers()
            >>> headers["Authorization"]
            'Bearer test_api_key_123'
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Add authentication if required
        if self.config.auth_required and self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        return headers
