"""Unit tests for MCP connections FastAPI router

This module tests the Presentation Layer (FastAPI router) in isolation.
All dependencies (use cases, authentication) are mocked.

Test Coverage:
- POST   /api/v1/mcp/connections (3 tests)
- DELETE /api/v1/mcp/connections/{connection_id} (3 tests)
- GET    /api/v1/mcp/connections/{connection_id}/tools (3 tests)
- POST   /api/v1/mcp/connections/{connection_id}/tools/{tool_name}/execute (3 tests)

Total: 12 tests

This is the RED phase of TDD - tests will fail until router is implemented.
"""

from unittest.mock import AsyncMock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.application.exceptions import (
    AuthorizationError,
    ExternalServiceError,
    ValidationError,
)
from src.domain.exceptions import AggregateNotFoundError

# Import the FastAPI app (will fail if router not implemented yet)
try:
    from src.api.dependencies import (
        get_connect_use_case,
        get_current_user,
        get_disconnect_use_case,
        get_discover_tools_use_case,
        get_execute_tool_use_case,
    )
    from src.api.main import app

    APP_AVAILABLE = True
except ImportError:
    APP_AVAILABLE = False


@pytest.fixture
def test_client(
    mock_current_user,
    mock_connect_use_case,
    mock_disconnect_use_case,
    mock_discover_tools_use_case,
    mock_execute_tool_use_case,
):
    """FastAPI test client with mocked dependencies

    All dependencies are overridden with mocks to isolate router testing.
    """
    if not APP_AVAILABLE:
        pytest.skip("FastAPI app not yet implemented")

    # Override all dependencies with mocks
    app.dependency_overrides[get_current_user] = lambda: mock_current_user
    app.dependency_overrides[get_connect_use_case] = lambda: mock_connect_use_case
    app.dependency_overrides[get_disconnect_use_case] = lambda: mock_disconnect_use_case
    app.dependency_overrides[get_discover_tools_use_case] = lambda: mock_discover_tools_use_case
    app.dependency_overrides[get_execute_tool_use_case] = lambda: mock_execute_tool_use_case

    client = TestClient(app)
    yield client

    # Clean up overrides
    app.dependency_overrides.clear()


# ============================================================================
# POST /api/v1/mcp/connections (3 tests)
# ============================================================================


@pytest.mark.skipif(not APP_AVAILABLE, reason="FastAPI app not yet implemented")
def test_create_connection_success_201(
    test_client: TestClient,
    mock_connect_use_case: AsyncMock,
    mock_connection_dto,
    test_agent_id,
    test_namespace,
):
    """Test POST /api/v1/mcp/connections returns 201 Created

    Expected behavior:
    - Valid request body → use case called with correct parameters
    - Use case returns MCPConnectionDTO
    - Response: 201 with Location header
    - Response body contains connection details
    """
    # Arrange
    request_body = {
        "server_name": "test_server",
        "url": "http://localhost:8080",
        "namespace": test_namespace,
        "agent_id": str(test_agent_id),
        "timeout": 30,
        "retry_attempts": 3,
    }

    # Act
    response = test_client.post("/api/v1/mcp/connections", json=request_body)

    # Assert
    assert response.status_code == status.HTTP_201_CREATED
    assert "Location" in response.headers
    assert f"/api/v1/mcp/connections/{mock_connection_dto.id}" in response.headers["Location"]

    response_json = response.json()
    assert response_json["id"] == str(mock_connection_dto.id)
    assert response_json["server_name"] == mock_connection_dto.server_name
    assert response_json["status"] == mock_connection_dto.status
    assert response_json["namespace"] == test_namespace

    # Verify use case was called
    mock_connect_use_case.execute.assert_called_once()


@pytest.mark.skipif(not APP_AVAILABLE, reason="FastAPI app not yet implemented")
def test_create_connection_validation_error_400(
    test_client: TestClient,
    test_agent_id,
    test_namespace,
):
    """Test POST /api/v1/mcp/connections returns 400 on invalid input

    Expected behavior:
    - Invalid URL format → Pydantic validation fails
    - Response: 400 Bad Request
    - Response body contains validation error details
    """
    # Arrange
    request_body = {
        "server_name": "test_server",
        "url": "not-a-valid-url",  # Invalid URL
        "namespace": test_namespace,
        "agent_id": str(test_agent_id),
    }

    # Act
    response = test_client.post("/api/v1/mcp/connections", json=request_body)

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    response_json = response.json()
    assert "detail" in response_json


@pytest.mark.skipif(not APP_AVAILABLE, reason="FastAPI app not yet implemented")
def test_create_connection_unauthorized_403(
    test_client: TestClient,
    mock_connect_use_case: AsyncMock,
    test_agent_id,
):
    """Test POST /api/v1/mcp/connections returns 403 on namespace mismatch

    Expected behavior:
    - Request namespace ≠ user's verified namespace
    - Use case raises AuthorizationError
    - Response: 403 Forbidden
    """
    # Arrange
    mock_connect_use_case.execute = AsyncMock(
        side_effect=AuthorizationError("Namespace mismatch")
    )

    request_body = {
        "server_name": "test_server",
        "url": "http://localhost:8080",
        "namespace": "different-namespace",  # Different from user's namespace
        "agent_id": str(test_agent_id),
    }

    # Act
    response = test_client.post("/api/v1/mcp/connections", json=request_body)

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN
    response_json = response.json()
    assert "detail" in response_json
    assert "Namespace mismatch" in response_json["detail"]


# ============================================================================
# DELETE /api/v1/mcp/connections/{connection_id} (3 tests)
# ============================================================================


@pytest.mark.skipif(not APP_AVAILABLE, reason="FastAPI app not yet implemented")
def test_disconnect_success_204(
    test_client: TestClient,
    mock_disconnect_use_case: AsyncMock,
    test_connection_id,
):
    """Test DELETE /api/v1/mcp/connections/{connection_id} returns 204

    Expected behavior:
    - Valid disconnect request → use case called
    - Use case completes successfully
    - Response: 204 No Content (no body)
    """
    # Act
    response = test_client.delete(f"/api/v1/mcp/connections/{test_connection_id}")

    # Assert
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert not response.text  # No content in response body

    # Verify use case was called
    mock_disconnect_use_case.execute.assert_called_once()


@pytest.mark.skipif(not APP_AVAILABLE, reason="FastAPI app not yet implemented")
def test_disconnect_not_found_404(
    test_client: TestClient,
    mock_disconnect_use_case: AsyncMock,
    test_connection_id,
):
    """Test DELETE /api/v1/mcp/connections/{connection_id} returns 404

    Expected behavior:
    - Connection not found in database
    - Use case raises AggregateNotFoundError
    - Response: 404 Not Found
    """
    # Arrange
    mock_disconnect_use_case.execute = AsyncMock(
        side_effect=AggregateNotFoundError("MCPConnection", str(test_connection_id))
    )

    # Act
    response = test_client.delete(f"/api/v1/mcp/connections/{test_connection_id}")

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND
    response_json = response.json()
    assert "detail" in response_json


@pytest.mark.skipif(not APP_AVAILABLE, reason="FastAPI app not yet implemented")
def test_disconnect_unauthorized_403(
    test_client: TestClient,
    mock_disconnect_use_case: AsyncMock,
    test_connection_id,
):
    """Test DELETE /api/v1/mcp/connections/{connection_id} returns 403

    Expected behavior:
    - Connection belongs to different agent/namespace
    - Use case raises AuthorizationError
    - Response: 403 Forbidden
    """
    # Arrange
    mock_disconnect_use_case.execute = AsyncMock(
        side_effect=AuthorizationError("Connection belongs to different agent")
    )

    # Act
    response = test_client.delete(f"/api/v1/mcp/connections/{test_connection_id}")

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN
    response_json = response.json()
    assert "detail" in response_json


# ============================================================================
# GET /api/v1/mcp/connections/{connection_id}/tools (3 tests)
# ============================================================================


@pytest.mark.skipif(not APP_AVAILABLE, reason="FastAPI app not yet implemented")
def test_discover_tools_success_200(
    test_client: TestClient,
    mock_discover_tools_use_case: AsyncMock,
    mock_connection_dto,
    test_connection_id,
):
    """Test GET /api/v1/mcp/connections/{connection_id}/tools returns 200

    Expected behavior:
    - Active connection → tools discovered
    - Use case returns MCPConnectionDTO with tools
    - Response: 200 OK with tools list
    """
    # Act
    response = test_client.get(f"/api/v1/mcp/connections/{test_connection_id}/tools")

    # Assert
    assert response.status_code == status.HTTP_200_OK

    response_json = response.json()
    assert "id" in response_json
    assert "tools" in response_json
    assert len(response_json["tools"]) > 0
    assert response_json["tools"][0]["name"] == "test_tool"

    # Verify use case was called
    mock_discover_tools_use_case.execute.assert_called_once()


@pytest.mark.skipif(not APP_AVAILABLE, reason="FastAPI app not yet implemented")
def test_discover_tools_not_found_404(
    test_client: TestClient,
    mock_discover_tools_use_case: AsyncMock,
    test_connection_id,
):
    """Test GET /api/v1/mcp/connections/{connection_id}/tools returns 404

    Expected behavior:
    - Connection not found in database
    - Use case raises AggregateNotFoundError
    - Response: 404 Not Found
    """
    # Arrange
    mock_discover_tools_use_case.execute = AsyncMock(
        side_effect=AggregateNotFoundError("MCPConnection", str(test_connection_id))
    )

    # Act
    response = test_client.get(f"/api/v1/mcp/connections/{test_connection_id}/tools")

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND
    response_json = response.json()
    assert "detail" in response_json


@pytest.mark.skipif(not APP_AVAILABLE, reason="FastAPI app not yet implemented")
def test_discover_tools_external_error_502(
    test_client: TestClient,
    mock_discover_tools_use_case: AsyncMock,
    test_connection_id,
):
    """Test GET /api/v1/mcp/connections/{connection_id}/tools returns 502

    Expected behavior:
    - MCP server connection fails
    - Use case raises ExternalServiceError
    - Response: 502 Bad Gateway
    """
    # Arrange
    mock_discover_tools_use_case.execute = AsyncMock(
        side_effect=ExternalServiceError("MCP server not responding")
    )

    # Act
    response = test_client.get(f"/api/v1/mcp/connections/{test_connection_id}/tools")

    # Assert
    assert response.status_code == status.HTTP_502_BAD_GATEWAY
    response_json = response.json()
    assert "detail" in response_json


# ============================================================================
# POST /api/v1/mcp/connections/{connection_id}/tools/{tool_name}/execute (3 tests)
# ============================================================================


@pytest.mark.skipif(not APP_AVAILABLE, reason="FastAPI app not yet implemented")
def test_execute_tool_success_200(
    test_client: TestClient,
    mock_execute_tool_use_case: AsyncMock,
    mock_tool_execution_result_dto,
    test_connection_id,
):
    """Test POST /api/v1/mcp/connections/{id}/tools/{name}/execute returns 200

    Expected behavior:
    - Valid tool execution request
    - Use case returns ToolExecutionResultDTO
    - Response: 200 OK with execution result
    """
    # Arrange
    tool_name = "test_tool"
    request_body = {
        "arguments": {"param1": "value1", "param2": "value2"}
    }

    # Act
    response = test_client.post(
        f"/api/v1/mcp/connections/{test_connection_id}/tools/{tool_name}/execute",
        json=request_body,
    )

    # Assert
    assert response.status_code == status.HTTP_200_OK

    response_json = response.json()
    assert "connection_id" in response_json
    assert "tool_name" in response_json
    assert "result" in response_json
    assert response_json["tool_name"] == tool_name
    assert response_json["result"]["status"] == "success"

    # Verify use case was called
    mock_execute_tool_use_case.execute.assert_called_once()


@pytest.mark.skipif(not APP_AVAILABLE, reason="FastAPI app not yet implemented")
def test_execute_tool_not_found_400(
    test_client: TestClient,
    mock_execute_tool_use_case: AsyncMock,
    test_connection_id,
):
    """Test POST /api/v1/mcp/connections/{id}/tools/{name}/execute returns 400

    Expected behavior:
    - Tool not found in connection
    - Use case raises ValidationError
    - Response: 400 Bad Request
    """
    # Arrange
    tool_name = "nonexistent_tool"
    mock_execute_tool_use_case.execute = AsyncMock(
        side_effect=ValidationError(f"Tool '{tool_name}' not found in connection")
    )

    request_body = {"arguments": {}}

    # Act
    response = test_client.post(
        f"/api/v1/mcp/connections/{test_connection_id}/tools/{tool_name}/execute",
        json=request_body,
    )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    response_json = response.json()
    assert "detail" in response_json


@pytest.mark.skipif(not APP_AVAILABLE, reason="FastAPI app not yet implemented")
def test_execute_tool_unauthorized_403(
    test_client: TestClient,
    mock_execute_tool_use_case: AsyncMock,
    test_connection_id,
):
    """Test POST /api/v1/mcp/connections/{id}/tools/{name}/execute returns 403

    Expected behavior:
    - Connection belongs to different namespace
    - Use case raises AuthorizationError
    - Response: 403 Forbidden
    """
    # Arrange
    tool_name = "test_tool"
    mock_execute_tool_use_case.execute = AsyncMock(
        side_effect=AuthorizationError("Namespace mismatch")
    )

    request_body = {"arguments": {}}

    # Act
    response = test_client.post(
        f"/api/v1/mcp/connections/{test_connection_id}/tools/{tool_name}/execute",
        json=request_body,
    )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN
    response_json = response.json()
    assert "detail" in response_json
