"""
Unit tests for Response DTOs

This module tests Response DTO mapping and serialization logic.
Tests follow TDD RED phase methodology - expecting failures until implementation exists.
"""

from datetime import datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from src.application.dtos.response_dtos import (
    DisconnectionResultDTO,
    MCPConnectionDTO,
    ToolDTO,
    ToolExecutionResultDTO,
)


class TestMCPConnectionDTO:
    """Test suite for MCPConnectionDTO"""

    @pytest.fixture
    def mock_tool(self):
        """Mock Tool entity"""
        tool = MagicMock()
        tool.name = "test_tool"
        tool.description = "Test Tool"
        tool.input_schema = {"type": "object"}
        tool.category = MagicMock()
        tool.category.value = "general"
        return tool

    @pytest.fixture
    def mock_connection(self, mock_tool):
        """Mock MCPConnection aggregate"""
        connection = MagicMock()
        connection.id = uuid4()
        connection.server_name = MagicMock()
        connection.server_name.__str__.return_value = "test_server"

        # Mock config.url to return string when str() is called
        connection.config = MagicMock()
        connection.config.url = "http://localhost:8080/mcp"

        connection.namespace = "test-namespace"
        connection.agent_id = uuid4()
        connection.status = MagicMock()
        connection.status.value = "ACTIVE"
        connection.tools = [mock_tool]
        connection.created_at = datetime(2024, 1, 1, 12, 0, 0)
        connection.connected_at = datetime(2024, 1, 1, 12, 0, 5)
        connection.disconnected_at = None
        connection.error_message = None
        return connection

    def test_mcp_connection_dto_from_aggregate(self, mock_connection, mock_tool):
        """
        Test MCPConnectionDTO.from_aggregate() correctly maps all fields

        Arrange:
            - Mock MCPConnection aggregate with all fields

        Act:
            - Convert to DTO via from_aggregate()

        Assert:
            - All fields mapped correctly
            - UUID fields preserved as UUID objects
            - Datetime fields preserved as datetime objects
            - Tools converted to ToolDTO list
            - Status converted to string
        """
        # Act
        dto = MCPConnectionDTO.from_aggregate(mock_connection)

        # Assert - Basic fields
        assert dto.id == mock_connection.id
        assert dto.server_name == "test_server"
        assert dto.url == "http://localhost:8080/mcp"
        assert dto.namespace == mock_connection.namespace
        assert dto.agent_id == mock_connection.agent_id
        assert dto.status == "ACTIVE"

        # Assert - Tools conversion
        assert len(dto.tools) == 1
        assert isinstance(dto.tools[0], ToolDTO)
        assert dto.tools[0].name == "test_tool"

        # Assert - Datetime fields
        assert dto.created_at == datetime(2024, 1, 1, 12, 0, 0)
        assert dto.connected_at == datetime(2024, 1, 1, 12, 0, 5)
        assert dto.disconnected_at is None
        assert dto.error_message is None

    def test_mcp_connection_dto_to_dict(self, mock_connection):
        """
        Test MCPConnectionDTO.to_dict() serializes correctly for JSON

        Arrange:
            - Create MCPConnectionDTO from aggregate

        Act:
            - Convert to dict via to_dict()

        Assert:
            - UUID fields converted to strings
            - Datetime fields converted to ISO format strings
            - Nested tools converted to dicts
            - All fields JSON-serializable
        """
        # Arrange
        dto = MCPConnectionDTO.from_aggregate(mock_connection)

        # Act
        result = dto.to_dict()

        # Assert - UUID fields as strings
        assert isinstance(result["id"], str)
        assert isinstance(result["agent_id"], str)

        # Assert - Datetime fields as ISO format strings
        assert isinstance(result["created_at"], str)
        assert result["created_at"] == "2024-01-01T12:00:00"
        assert isinstance(result["connected_at"], str)
        assert result["connected_at"] == "2024-01-01T12:00:05"
        assert result["disconnected_at"] is None

        # Assert - Status as string
        assert result["status"] == "ACTIVE"

        # Assert - Tools as list of dicts
        assert isinstance(result["tools"], list)
        assert len(result["tools"]) == 1
        assert isinstance(result["tools"][0], dict)
        assert result["tools"][0]["name"] == "test_tool"


class TestToolDTO:
    """Test suite for ToolDTO"""

    @pytest.fixture
    def mock_tool(self):
        """Mock Tool entity"""
        tool = MagicMock()
        tool.name = "test_tool"
        tool.description = "Test Tool"
        tool.input_schema = {"type": "object", "properties": {"param1": {"type": "string"}}}
        tool.category = MagicMock()
        tool.category.value = "general"
        return tool

    def test_tool_dto_from_entity(self, mock_tool):
        """
        Test ToolDTO.from_entity() correctly maps all fields

        Arrange:
            - Mock Tool entity

        Act:
            - Convert to DTO via from_entity()

        Assert:
            - All fields mapped correctly
            - Category converted to string
        """
        # Act
        dto = ToolDTO.from_entity(mock_tool)

        # Assert
        assert dto.name == "test_tool"
        assert dto.description == "Test Tool"
        assert dto.input_schema == {"type": "object", "properties": {"param1": {"type": "string"}}}
        assert dto.category == "general"

    def test_tool_dto_to_dict(self, mock_tool):
        """
        Test ToolDTO.to_dict() serializes correctly

        Arrange:
            - Create ToolDTO from entity

        Act:
            - Convert to dict via to_dict()

        Assert:
            - All fields serialized correctly
            - Result is JSON-compatible dict
        """
        # Arrange
        dto = ToolDTO.from_entity(mock_tool)

        # Act
        result = dto.to_dict()

        # Assert
        assert isinstance(result, dict)
        assert result["name"] == "test_tool"
        assert result["description"] == "Test Tool"
        assert result["category"] == "general"
        assert isinstance(result["input_schema"], dict)


class TestToolExecutionResultDTO:
    """Test suite for ToolExecutionResultDTO"""

    def test_tool_execution_result_dto_to_dict(self):
        """
        Test ToolExecutionResultDTO.to_dict() serialization

        Arrange:
            - Create ToolExecutionResultDTO

        Act:
            - Convert to dict via to_dict()

        Assert:
            - UUID converted to string
            - Result dict preserved
            - All fields serialized correctly
        """
        # Arrange
        connection_id = uuid4()
        dto = ToolExecutionResultDTO(
            connection_id=connection_id,
            tool_name="test_tool",
            result={"output": "success", "data": [1, 2, 3]},
        )

        # Act
        result = dto.to_dict()

        # Assert
        assert isinstance(result["connection_id"], str)
        assert result["connection_id"] == str(connection_id)
        assert result["tool_name"] == "test_tool"
        assert result["result"] == {"output": "success", "data": [1, 2, 3]}


class TestDisconnectionResultDTO:
    """Test suite for DisconnectionResultDTO"""

    def test_disconnection_result_dto_to_dict(self):
        """
        Test DisconnectionResultDTO.to_dict() serialization

        Arrange:
            - Create DisconnectionResultDTO

        Act:
            - Convert to dict via to_dict()

        Assert:
            - UUID converted to string
            - Datetime converted to ISO format string
            - All fields serialized correctly
        """
        # Arrange
        connection_id = uuid4()
        disconnected_at = datetime(2024, 1, 1, 12, 30, 0)

        dto = DisconnectionResultDTO(
            connection_id=connection_id,
            server_name="test_server",
            disconnected_at=disconnected_at,
        )

        # Act
        result = dto.to_dict()

        # Assert
        assert isinstance(result["connection_id"], str)
        assert result["connection_id"] == str(connection_id)
        assert result["server_name"] == "test_server"
        assert isinstance(result["disconnected_at"], str)
        assert result["disconnected_at"] == "2024-01-01T12:30:00"
