"""
Unit tests for Request DTOs

This module tests Pydantic request DTOs validation logic.
Tests follow TDD RED phase methodology - expecting failures until implementation exists.
"""

from uuid import uuid4

import pytest

from src.application.dtos.request_dtos import (
    CreateConnectionRequest,
    DisconnectRequest,
    DiscoverToolsRequest,
    ExecuteToolRequest,
)


class TestCreateConnectionRequest:
    """Test suite for CreateConnectionRequest validation"""

    def test_create_connection_request_validation_success(self):
        """
        Test valid CreateConnectionRequest passes validation

        Arrange:
            - All required fields provided with valid values

        Act:
            - Create CreateConnectionRequest instance

        Assert:
            - No validation error raised
            - All fields accessible
            - Field values match input
        """
        # Arrange & Act
        request = CreateConnectionRequest(
            server_name="test_server",
            url="http://localhost:8080/mcp",
            namespace="test-namespace",
            agent_id=uuid4(),
            timeout=30,
            retry_attempts=3,
            auth_required=False,
        )

        # Assert
        assert request.server_name == "test_server"
        # Pydantic may or may not add trailing slash - accept both
        assert str(request.url).rstrip("/") == "http://localhost:8080/mcp"
        assert request.namespace == "test-namespace"
        assert request.timeout == 30
        assert request.retry_attempts == 3
        assert request.auth_required is False

    def test_create_connection_request_validation_invalid_server_name(self):
        """
        Test CreateConnectionRequest validation fails with invalid server name

        Arrange:
            - Server name with special characters (e.g., "server@name")

        Act:
            - Create CreateConnectionRequest instance

        Assert:
            - ValidationError raised
            - Error message indicates server name validation failure
        """
        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            CreateConnectionRequest(
                server_name="server@name",  # Invalid: @ not allowed
                url="http://localhost:8080/mcp",
                namespace="test-namespace",
                agent_id=uuid4(),
            )

        # Should raise validation error for server_name
        assert (
            "server_name" in str(exc_info.value).lower()
            or "validation" in str(exc_info.value).lower()
        )

    def test_create_connection_request_validation_invalid_url(self):
        """
        Test CreateConnectionRequest validation fails with invalid URL

        Arrange:
            - Invalid URL format (not HTTP/HTTPS)

        Act:
            - Create CreateConnectionRequest instance

        Assert:
            - ValidationError raised
            - Error message indicates URL validation failure
        """
        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            CreateConnectionRequest(
                server_name="test_server",
                url="not-a-valid-url",  # Invalid URL
                namespace="test-namespace",
                agent_id=uuid4(),
            )

        # Should raise validation error for url
        assert "url" in str(exc_info.value).lower() or "validation" in str(exc_info.value).lower()

    def test_create_connection_request_validation_missing_api_key(self):
        """
        Test CreateConnectionRequest validation fails when auth_required=True but api_key=None

        Arrange:
            - auth_required=True
            - api_key=None

        Act:
            - Create CreateConnectionRequest instance

        Assert:
            - ValidationError raised
            - Error message indicates "API key required"
        """
        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            CreateConnectionRequest(
                server_name="test_server",
                url="http://localhost:8080/mcp",
                namespace="test-namespace",
                agent_id=uuid4(),
                auth_required=True,
                api_key=None,  # Should fail validation
            )

        # Should raise validation error about API key
        assert "api" in str(exc_info.value).lower() or "key" in str(exc_info.value).lower()

    def test_create_connection_request_validation_timeout_out_of_range(self):
        """
        Test CreateConnectionRequest validation fails with timeout out of range

        Arrange:
            - timeout=500 (exceeds max of 300)

        Act:
            - Create CreateConnectionRequest instance

        Assert:
            - ValidationError raised
            - Error message indicates timeout validation failure
        """
        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            CreateConnectionRequest(
                server_name="test_server",
                url="http://localhost:8080/mcp",
                namespace="test-namespace",
                agent_id=uuid4(),
                timeout=500,  # Exceeds maximum of 300
            )

        # Should raise validation error for timeout
        assert "timeout" in str(exc_info.value).lower() or "300" in str(exc_info.value).lower()


class TestDiscoverToolsRequest:
    """Test suite for DiscoverToolsRequest validation"""

    def test_discover_tools_request_validation_success(self):
        """
        Test valid DiscoverToolsRequest passes validation

        Arrange:
            - All required fields provided

        Act:
            - Create DiscoverToolsRequest instance

        Assert:
            - No validation error raised
            - All fields accessible
        """
        # Arrange
        connection_id = uuid4()
        agent_id = uuid4()

        # Act
        request = DiscoverToolsRequest(
            connection_id=connection_id,
            namespace="test-namespace",
            agent_id=agent_id,
        )

        # Assert
        assert request.connection_id == connection_id
        assert request.namespace == "test-namespace"
        assert request.agent_id == agent_id


class TestExecuteToolRequest:
    """Test suite for ExecuteToolRequest validation"""

    def test_execute_tool_request_validation_success(self):
        """
        Test valid ExecuteToolRequest passes validation

        Arrange:
            - All required fields provided

        Act:
            - Create ExecuteToolRequest instance

        Assert:
            - No validation error raised
            - All fields accessible
        """
        # Arrange
        connection_id = uuid4()
        agent_id = uuid4()

        # Act
        request = ExecuteToolRequest(
            connection_id=connection_id,
            tool_name="test_tool",
            arguments={"param1": "value1"},
            namespace="test-namespace",
            agent_id=agent_id,
        )

        # Assert
        assert request.connection_id == connection_id
        assert request.tool_name == "test_tool"
        assert request.arguments == {"param1": "value1"}
        assert request.namespace == "test-namespace"
        assert request.agent_id == agent_id


class TestDisconnectRequest:
    """Test suite for DisconnectRequest validation"""

    def test_disconnect_request_validation_success(self):
        """
        Test valid DisconnectRequest passes validation

        Arrange:
            - All required fields provided

        Act:
            - Create DisconnectRequest instance

        Assert:
            - No validation error raised
            - All fields accessible
        """
        # Arrange
        connection_id = uuid4()
        agent_id = uuid4()

        # Act
        request = DisconnectRequest(
            connection_id=connection_id,
            namespace="test-namespace",
            agent_id=agent_id,
        )

        # Assert
        assert request.connection_id == connection_id
        assert request.namespace == "test-namespace"
        assert request.agent_id == agent_id
