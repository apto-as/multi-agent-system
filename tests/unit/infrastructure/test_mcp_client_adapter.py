"""Unit Tests for MCPClientAdapter (Infrastructure Layer).

TDD Approach: Write these tests BEFORE implementing MCPClientAdapter.
These tests define the contract between infrastructure and domain.

Test Strategy:
- Mock external MCP server calls
- Verify protocol compliance
- Test error handling and retries
- Validate timeouts and connection management

Author: Athena (TDD) + Artemis (Technical)
Created: 2025-11-12 (Phase 1-1: Day 1 Afternoon)
Status: RED (tests will fail until implementation)
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

# Infrastructure imports (to be implemented)
try:
    from src.infrastructure.adapters.mcp_client_adapter import MCPClientAdapter
    from src.domain.value_objects.connection_config import ConnectionConfig
    from src.domain.entities.tool import Tool
except ImportError:
    # Expected in TDD RED phase
    pass


class TestMCPClientAdapter:
    """
    Unit Tests for MCPClientAdapter

    MCPClientAdapter is responsible for:
    - Communicating with external MCP servers
    - Converting MCP protocol responses to domain objects
    - Handling connection lifecycle
    - Implementing retry logic and timeouts
    """

    @pytest.mark.asyncio
    async def test_connect_to_mcp_server_success(self):
        """
        Test: Successfully connect to MCP server

        Given: Valid connection configuration
        When: connect() is called
        Then: Should establish connection without error
        And: Should return True
        """
        Arrange
        config = ConnectionConfig(
            server_name="test_server",
            url="http://localhost:8080/mcp",
            timeout=30,
            retry_attempts=3
        )

        Mock HTTP client
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"status": "ok"}
            mock_client.return_value.__aenter__.return_value.get.return_value = mock_response

            Act
            adapter = MCPClientAdapter(config)
            result = await adapter.connect()

            Assert
            assert result is True
            mock_client.return_value.__aenter__.return_value.get.assert_called_once()
    @pytest.mark.asyncio
    async def test_connect_with_authentication(self):
        """
        Test: Connect with API key authentication

        Given: Connection config with auth_required=True
        When: connect() is called
        Then: Should include API key in request headers
        """
        Arrange
        config = ConnectionConfig(
            server_name="auth_server",
            url="http://localhost:8080/mcp",
            auth_required=True,
            api_key="test_api_key_123"
        )

        Mock HTTP client
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_client.return_value.__aenter__.return_value.get.return_value = mock_response

            Act
            adapter = MCPClientAdapter(config)
            await adapter.connect()

            Assert
            call_args = mock_client.return_value.__aenter__.return_value.get.call_args
            assert 'headers' in call_args.kwargs
            assert call_args.kwargs['headers']['Authorization'] == 'Bearer test_api_key_123'
    @pytest.mark.asyncio
    async def test_discover_tools_returns_tool_list(self):
        """
        Test: Discover tools from MCP server

        Given: Connected to MCP server
        When: discover_tools() is called
        Then: Should return list of Tool entities
        And: Tools should have valid metadata
        """
        Arrange
        config = ConnectionConfig(
            server_name="test_server",
            url="http://localhost:8080/mcp"
        )

        mock_tools_response = {
            "tools": [
                {
                    "name": "search_memory",
                    "description": "Search semantic memories",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"}
                        }
                    }
                },
                {
                    "name": "create_task",
                    "description": "Create a new task",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "description": {"type": "string"}
                        }
                    }
                }
            ]
        }

        Mock HTTP client
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_tools_response
            mock_client.return_value.__aenter__.return_value.get.return_value = mock_response

            Act
            adapter = MCPClientAdapter(config)
            await adapter.connect()
            tools = await adapter.discover_tools()

            Assert
            assert isinstance(tools, list)
            assert len(tools) == 2
            assert all(isinstance(t, Tool) for t in tools)
            assert tools[0].name == "search_memory"
            assert tools[1].name == "create_task"
    @pytest.mark.asyncio
    async def test_connection_timeout_raises_error(self):
        """
        Test: Connection timeout handling

        Given: MCP server is slow to respond
        When: Connection timeout is reached
        Then: Should raise TimeoutError
        """
        Arrange
        config = ConnectionConfig(
            server_name="slow_server",
            url="http://localhost:8080/mcp",
            timeout=1  # 1 second timeout
        )

        Mock timeout
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.get.side_effect = TimeoutError()

            Act & Assert
            adapter = MCPClientAdapter(config)
            with pytest.raises(TimeoutError):
                await adapter.connect()
    @pytest.mark.asyncio
    async def test_connection_retry_on_failure(self):
        """
        Test: Retry logic on connection failure

        Given: MCP server fails initially but succeeds on retry
        When: connect() is called
        Then: Should retry up to retry_attempts times
        And: Should succeed if server recovers
        """
        Arrange
        config = ConnectionConfig(
            server_name="flaky_server",
            url="http://localhost:8080/mcp",
            retry_attempts=3
        )

        Mock: Fail twice, succeed on third attempt
        with patch('httpx.AsyncClient') as mock_client:
            mock_response_fail = AsyncMock()
            mock_response_fail.status_code = 500

            mock_response_success = AsyncMock()
            mock_response_success.status_code = 200
            mock_response_success.json.return_value = {"status": "ok"}

            mock_client.return_value.__aenter__.return_value.get.side_effect = [
                mock_response_fail,  # 1st attempt: fail
                mock_response_fail,  # 2nd attempt: fail
                mock_response_success  # 3rd attempt: success
            ]

            Act
            adapter = MCPClientAdapter(config)
            result = await adapter.connect()

            Assert
            assert result is True
            assert mock_client.return_value.__aenter__.return_value.get.call_count == 3
    @pytest.mark.asyncio
    async def test_disconnect_closes_connection(self):
        """
        Test: Disconnect closes HTTP connection

        Given: Connected to MCP server
        When: disconnect() is called
        Then: Should close HTTP client
        """
        Arrange
        config = ConnectionConfig(
            server_name="test_server",
            url="http://localhost:8080/mcp"
        )

        with patch('httpx.AsyncClient') as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_client.return_value.__aenter__.return_value.get.return_value = mock_response

            Act
            adapter = MCPClientAdapter(config)
            await adapter.connect()
            await adapter.disconnect()

            Assert
            mock_client.return_value.__aexit__.assert_called_once()
    @pytest.mark.asyncio
    async def test_execute_tool_sends_correct_request(self):
        """
        Test: Execute tool via MCP protocol

        Given: Connected to MCP server with discovered tools
        When: execute_tool() is called with tool name and arguments
        Then: Should send POST request with correct payload
        And: Should return execution result
        """
        Arrange
        config = ConnectionConfig(
            server_name="test_server",
            url="http://localhost:8080/mcp"
        )

        tool_name = "search_memory"
        tool_args = {"query": "test query", "limit": 10}
        expected_result = {"results": ["memory1", "memory2"]}

        with patch('httpx.AsyncClient') as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = expected_result
            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response

            Act
            adapter = MCPClientAdapter(config)
            await adapter.connect()
            result = await adapter.execute_tool(tool_name, tool_args)

            Assert
            assert result == expected_result
            mock_client.return_value.__aenter__.return_value.post.assert_called_once()
            call_kwargs = mock_client.return_value.__aenter__.return_value.post.call_args.kwargs
            assert call_kwargs['json']['tool'] == tool_name
            assert call_kwargs['json']['arguments'] == tool_args
class TestMCPProtocolCompliance:
    """
    Tests for MCP Protocol Compliance

    These tests verify that MCPClientAdapter correctly implements
    the Model Context Protocol specification.
    """

    @pytest.mark.asyncio
    async def test_tool_schema_validation(self):
        """
        Test: Validate tool schema conforms to JSON Schema

        Given: Tool response from MCP server
        When: Tool is parsed
        Then: inputSchema should be valid JSON Schema
        """
        MCP protocol: inputSchema must have "type" field
        mock_tool = {
            "name": "test_tool",
            "description": "Test tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "param1": {"type": "string"}
                },
                "required": ["param1"]
            }
        }

        Act
        tool = parse_mcp_tool(mock_tool)

        Assert
        assert tool.input_schema["type"] == "object"
        assert "properties" in tool.input_schema
        assert "required" in tool.input_schema
    @pytest.mark.asyncio
    async def test_error_response_handling(self):
        """
        Test: Handle MCP error responses

        Given: MCP server returns error response
        When: Request is made
        Then: Should raise appropriate exception with error details
        """
        config = ConnectionConfig(
            server_name="test_server",
            url="http://localhost:8080/mcp"
        )

        error_response = {
            "error": {
                "code": "TOOL_NOT_FOUND",
                "message": "Tool 'invalid_tool' not found",
                "details": {"available_tools": ["tool1", "tool2"]}
            }
        }

        with patch('httpx.AsyncClient') as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 404
            mock_response.json.return_value = error_response
            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response

            Act & Assert
            adapter = MCPClientAdapter(config)
            await adapter.connect()
            with pytest.raises(MCPToolNotFoundError) as exc_info:
                await adapter.execute_tool("invalid_tool", {})
            assert "TOOL_NOT_FOUND" in str(exc_info.value)
