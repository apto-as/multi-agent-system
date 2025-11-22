"""Unit Tests for MCP Anti-Corruption Layer (ACL).

TDD Approach: Write these tests BEFORE implementing MCP ACL.

The Anti-Corruption Layer protects the domain model from external protocol changes.
It translates between MCP protocol format and domain objects.

Purpose of ACL:
- Convert MCP responses → Domain objects (Tool, ConnectionConfig)
- Convert Domain requests → MCP protocol format
- Isolate domain from MCP protocol changes
- Validate protocol compliance

Author: Athena (TDD) + Hera (DDD Architecture)
Created: 2025-11-12 (Phase 1-1: Day 1 Afternoon)
Status: RED (tests will fail until implementation)
"""

import pytest
from datetime import datetime

# Domain imports
from src.domain.entities.tool import Tool
from src.domain.value_objects.tool_category import ToolCategory

# ACL imports (to be implemented)
try:
    from src.infrastructure.acl.mcp_protocol_translator import MCPProtocolTranslator
except ImportError:
    # Expected in TDD RED phase
    pass


class TestMCPProtocolTranslator:
    """
    Unit Tests for MCPProtocolTranslator

    The translator is responsible for converting between:
    - MCP protocol format ↔ Domain objects
    """

    def test_translate_mcp_tool_to_domain_tool(self):
        """
        Test: Translate MCP tool response to domain Tool entity

        Given: MCP tool response in protocol format
        When: Translator converts to domain object
        Then: Should return valid Tool entity
        And: All fields should be correctly mapped
        """
        # Arrange
        mcp_tool = {
            "name": "mcp-memory-search",
            "description": "Search semantic memories with vector similarity",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 10
                    }
                },
                "required": ["query"]
            }
        }

        # Act
        translator = MCPProtocolTranslator()
        tool = translator.mcp_tool_to_domain(mcp_tool)

        # Assert
        assert isinstance(tool, Tool)
        assert tool.name == "mcp-memory-search"
        assert tool.description == "Search semantic memories with vector similarity"
        assert tool.input_schema == mcp_tool["inputSchema"]
        assert tool.category == ToolCategory.API_INTEGRATION  # Auto-inferred from name (mcp- prefix)

    def test_translate_mcp_tool_list_to_domain_tools(self):
        """
        Test: Translate list of MCP tools to domain Tool entities

        Given: MCP tools list response
        When: Translator converts to domain objects
        Then: Should return list of Tool entities
        """
        # Arrange (updated for v2.3.0: use patterns that match 5 Go categories)
        mcp_tools = {
            "tools": [
                {
                    "name": "store_memory",
                    "description": "Store and process memory data",
                    "inputSchema": {"type": "object"}
                },
                {
                    "name": "create_workflow",
                    "description": "Create workflow automation task",
                    "inputSchema": {"type": "object"}
                }
            ]
        }

        # Act
        translator = MCPProtocolTranslator()
        tools = translator.mcp_tools_response_to_domain(mcp_tools)

        # Assert
        assert isinstance(tools, list)
        assert len(tools) == 2
        assert all(isinstance(t, Tool) for t in tools)
        assert tools[0].name == "store_memory"
        assert tools[1].name == "create_workflow"

    def test_translate_domain_tool_execution_to_mcp_request(self):
        """
        Test: Translate domain tool execution to MCP request format

        Given: Tool name and arguments from domain
        When: Translator converts to MCP protocol format
        Then: Should return valid MCP tool execution request
        """
        # Arrange
        tool_name = "search_memory"
        tool_args = {
            "query": "machine learning",
            "limit": 5
        }

        # Act
        translator = MCPProtocolTranslator()
        mcp_request = translator.domain_tool_execution_to_mcp(tool_name, tool_args)

        # Assert
        assert mcp_request["tool"] == tool_name
        assert mcp_request["arguments"] == tool_args
        assert "requestId" in mcp_request  # MCP protocol requirement

    def test_handle_missing_optional_fields(self):
        """
        Test: Handle MCP tool with missing optional fields

        Given: MCP tool response with minimal fields
        When: Translator converts to domain object
        Then: Should use default values for missing fields
        """
        # Arrange (updated for v2.3.0: description must match a category pattern)
        mcp_tool = {
            "name": "minimal_tool",
            "description": "Data processing tool example"
            # inputSchema is optional in MCP protocol
        }

        # Act
        translator = MCPProtocolTranslator()
        tool = translator.mcp_tool_to_domain(mcp_tool)

        # Assert
        assert tool.name == "minimal_tool"
        assert tool.input_schema == {}  # Default empty schema

    def test_validate_mcp_tool_schema(self):
        """
        Test: Validate MCP tool conforms to protocol

        Given: Invalid MCP tool response (missing required fields)
        When: Translator attempts to convert
        Then: Should raise validation error
        """
        # Arrange
        invalid_mcp_tool = {
            # Missing "name" field (required)
            "description": "Invalid tool"
        }

        # Act & Assert
        from src.infrastructure.exceptions import MCPProtocolError

        translator = MCPProtocolTranslator()
        with pytest.raises(MCPProtocolError) as exc_info:
            translator.mcp_tool_to_domain(invalid_mcp_tool)
        assert "Missing required field: name" in str(exc_info.value)

    def test_translate_mcp_error_response(self):
        """
        Test: Translate MCP error response to domain exception

        Given: MCP error response
        When: Translator processes error
        Then: Should raise appropriate domain exception
        """
        # Arrange
        mcp_error = {
            "error": {
                "code": "TOOL_EXECUTION_FAILED",
                "message": "Tool execution failed due to timeout",
                "details": {
                    "tool": "slow_tool",
                    "timeout": 30
                }
            }
        }

        # Act & Assert
        from src.infrastructure.exceptions import ToolExecutionError

        translator = MCPProtocolTranslator()
        exc = translator.mcp_error_to_exception(mcp_error)
        assert isinstance(exc, ToolExecutionError)
        assert "TOOL_EXECUTION_FAILED" in str(exc) or "timeout" in str(exc).lower()
        assert exc.details["tool"] == "slow_tool"

    def test_category_inference_from_tool_metadata(self):
        """
        Test: Infer ToolCategory from MCP tool metadata

        Given: MCP tool with specific name patterns
        When: Translator converts to domain
        Then: Should auto-infer correct category from 5 Go-defined categories

        Note: Updated for v2.3.0 - ToolCategory now has exactly 5 categories
        matching Go orchestrator/discovery.go validCategories.
        """
        # Arrange (updated for v2.3.0: 5 Go categories)
        test_cases = [
            ({"name": "mcp-server", "description": "MCP server tool"}, ToolCategory.API_INTEGRATION),
            ({"name": "data-processor", "description": "Process data"}, ToolCategory.DATA_PROCESSING),
            ({"name": "rest-api", "description": "REST API client"}, ToolCategory.API_INTEGRATION),
            ({"name": "file-uploader", "description": "Upload files"}, ToolCategory.FILE_MANAGEMENT),
            ({"name": "auth-service", "description": "Authentication"}, ToolCategory.SECURITY),
            ({"name": "log-monitor", "description": "Monitor logs"}, ToolCategory.MONITORING),
        ]

        translator = MCPProtocolTranslator()

        # Act & Assert
        for mcp_tool, expected_category in test_cases:
            tool = translator.mcp_tool_to_domain(mcp_tool)
            assert tool.category == expected_category, f"Failed for {mcp_tool['name']}"

    def test_preserve_original_mcp_schema(self):
        """
        Test: Preserve original MCP inputSchema without modification

        Given: MCP tool with complex inputSchema
        When: Translator converts to domain
        Then: inputSchema should be preserved exactly as-is
        """
        # Arrange
        complex_schema = {
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "properties": {
                        "field1": {"type": "string"},
                        "field2": {"type": "number"}
                    }
                },
                "array": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            },
            "required": ["nested"],
            "additionalProperties": False
        }

        mcp_tool = {
            "name": "complex_tool",
            "description": "API integration tool with complex schema",
            "inputSchema": complex_schema
        }

        # Act
        translator = MCPProtocolTranslator()
        tool = translator.mcp_tool_to_domain(mcp_tool)

        # Assert
        assert tool.input_schema == complex_schema  # Exact match
