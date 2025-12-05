"""MCP Anti-Corruption Layer (ACL).

The ACL protects the domain model from external protocol changes.
It translates between MCP protocol format and domain objects.

Purpose:
- Convert MCP responses → Domain objects (Tool, ConnectionConfig)
- Convert Domain requests → MCP protocol format
- Isolate domain from MCP protocol changes
- Validate protocol compliance

Design Pattern: Anti-Corruption Layer (DDD)

Author: Artemis (Implementation)
Created: 2025-11-12 (Phase 1-1-B: Infrastructure Layer)
"""

import uuid
from typing import Any

from src.domain.entities.tool import Tool
from src.domain.value_objects.tool_category import ToolCategory
from src.infrastructure.exceptions import MCPProtocolError, ToolExecutionError


class MCPProtocolTranslator:
    """Translates between MCP protocol format and domain objects.

    This is the Anti-Corruption Layer that prevents MCP protocol changes
    from affecting the domain model.

    Methods:
        mcp_tool_to_domain: Convert MCP tool → Domain Tool entity
        mcp_tools_response_to_domain: Convert MCP tools list → List of Tools
        domain_tool_execution_to_mcp: Convert domain execution → MCP request
        mcp_error_to_exception: Convert MCP error → Domain exception

    Example:
        >>> translator = MCPProtocolTranslator()
        >>> mcp_tool = {"name": "search", "description": "Search tool"}
        >>> tool = translator.mcp_tool_to_domain(mcp_tool)
        >>> tool.name
        'search'
    """

    def mcp_tool_to_domain(self, mcp_tool: dict[str, Any]) -> Tool:
        """Convert MCP tool response to domain Tool entity.

        Args:
            mcp_tool: MCP tool in protocol format

        Returns:
            Tool entity

        Raises:
            MCPProtocolError: If required fields are missing or invalid

        Example:
            >>> translator = MCPProtocolTranslator()
            >>> mcp_tool = {
            ...     "name": "search-api",
            ...     "description": "Search API endpoint",
            ...     "inputSchema": {"type": "object"}
            ... }
            >>> tool = translator.mcp_tool_to_domain(mcp_tool)
            >>> tool.category
            ToolCategory.API_INTEGRATION
        """
        # Validate required fields
        if "name" not in mcp_tool:
            raise MCPProtocolError("Missing required field: name", details={"mcp_tool": mcp_tool})

        if "description" not in mcp_tool:
            raise MCPProtocolError(
                "Missing required field: description", details={"mcp_tool": mcp_tool}
            )

        # Extract fields with defaults
        name = mcp_tool["name"]
        description = mcp_tool["description"]
        input_schema = mcp_tool.get("inputSchema", {})

        # Auto-infer category from name and description
        category = ToolCategory.infer_from_name(name, description)

        # Create domain Tool entity
        return Tool(
            name=name,
            description=description,
            input_schema=input_schema,
            category=category,
        )

    def mcp_tools_response_to_domain(self, mcp_response: dict[str, Any]) -> list[Tool]:
        """Convert MCP tools list response to domain Tool entities.

        Args:
            mcp_response: MCP response containing tools list

        Returns:
            List of Tool entities

        Raises:
            MCPProtocolError: If response format is invalid

        Example:
            >>> translator = MCPProtocolTranslator()
            >>> response = {
            ...     "tools": [
            ...         {"name": "tool1", "description": "First tool"},
            ...         {"name": "tool2", "description": "Second tool"}
            ...     ]
            ... }
            >>> tools = translator.mcp_tools_response_to_domain(response)
            >>> len(tools)
            2
        """
        if "tools" not in mcp_response:
            raise MCPProtocolError(
                "Invalid MCP response: missing 'tools' field",
                details={"mcp_response": mcp_response},
            )

        tools_list = mcp_response["tools"]
        if not isinstance(tools_list, list):
            raise MCPProtocolError(
                "Invalid MCP response: 'tools' must be a list",
                details={"type": type(tools_list).__name__},
            )

        # Convert each MCP tool to domain Tool
        return [self.mcp_tool_to_domain(mcp_tool) for mcp_tool in tools_list]

    def domain_tool_execution_to_mcp(
        self, tool_name: str, tool_args: dict[str, Any]
    ) -> dict[str, Any]:
        """Convert domain tool execution to MCP request format.

        Args:
            tool_name: Name of the tool to execute
            tool_args: Arguments for the tool

        Returns:
            MCP tool execution request

        Example:
            >>> translator = MCPProtocolTranslator()
            >>> request = translator.domain_tool_execution_to_mcp(
            ...     "search_memory", {"query": "test", "limit": 5}
            ... )
            >>> request["tool"]
            'search_memory'
            >>> "requestId" in request
            True
        """
        # Generate unique request ID (MCP protocol requirement)
        request_id = str(uuid.uuid4())

        return {
            "tool": tool_name,
            "arguments": tool_args,
            "requestId": request_id,
        }

    def mcp_error_to_exception(self, mcp_error: dict[str, Any]) -> Exception:
        """Convert MCP error response to domain exception.

        Args:
            mcp_error: MCP error response

        Returns:
            Appropriate exception based on error type

        Raises:
            ToolExecutionError: For tool execution failures
            MCPProtocolError: For protocol-level errors

        Example:
            >>> translator = MCPProtocolTranslator()
            >>> error = {
            ...     "error": {
            ...         "code": "TOOL_EXECUTION_FAILED",
            ...         "message": "Timeout",
            ...         "details": {"tool": "slow_tool"}
            ...     }
            ... }
            >>> exc = translator.mcp_error_to_exception(error)
            >>> isinstance(exc, ToolExecutionError)
            True
        """
        if "error" not in mcp_error:
            raise MCPProtocolError(
                "Invalid MCP error response: missing 'error' field",
                details={"mcp_error": mcp_error},
            )

        error_data = mcp_error["error"]
        error_code = error_data.get("code", "UNKNOWN_ERROR")
        error_message = error_data.get("message", "Unknown error")
        error_details = error_data.get("details", {})

        # Tool execution errors
        if error_code == "TOOL_EXECUTION_FAILED":
            tool_name = error_details.get("tool", "unknown")
            return ToolExecutionError(
                tool_name=tool_name,
                error_message=error_message,
                details=error_details,
            )

        # Protocol-level errors
        return MCPProtocolError(
            f"MCP protocol error: {error_code} - {error_message}",
            details=error_details,
        )
