"""Integration tests for MCP Connection API (Router → Use Case → Repository → DB).

This test suite verifies the full stack integration:
- FastAPI Router (request/response handling)
- Application Use Cases (business logic)
- Infrastructure Repositories (data access)
- Real SQLite Database (:memory:)

Architecture:
- REAL: Database, Router, Use Cases, Repositories
- MOCK: Only MCPClientAdapter (external MCP server)

Security:
- P0-1: Namespace isolation verified
- JWT authentication with real tokens
- Cross-namespace access blocked

Author: Artemis (Technical Perfectionist)
Created: 2025-11-12 (Phase 1-3-D: Integration Tests)
"""

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.value_objects.connection_status import ConnectionStatus
from src.infrastructure.adapters.mcp_client_adapter import MCPConnectionError
from src.models.agent import Agent
from src.models.mcp_connection import MCPConnectionModel

# ============================================================================
# Test 1: Full Connection Workflow (Happy Path)
# ============================================================================


@pytest.mark.asyncio
async def test_full_connection_workflow_integration(
    test_client: TestClient,
    test_session: AsyncSession,
    auth_headers: dict[str, str],
    test_agent: Agent,
    mock_mcp_adapter: AsyncMock,
):
    """Test complete workflow: create → discover tools → execute tool → disconnect.

    This is the happy path integration test that verifies all components
    work together correctly.

    Verifies:
    - Create connection (POST /api/v1/mcp/connections)
    - Discover tools (GET /api/v1/mcp/connections/{id}/tools)
    - Execute tool (POST /api/v1/mcp/connections/{id}/tools/{name}/execute)
    - Disconnect (DELETE /api/v1/mcp/connections/{id})
    - Adapter methods called correctly
    - Database persistence

    Note: MCPClientAdapter is already mocked in test_client fixture
    """
    # Step 1: Create connection
    create_response = test_client.post(
        "/api/v1/mcp/connections",
        json={
            "server_name": "test_server",
            "url": "http://localhost:8080",
            "timeout": 30,
            "namespace": test_agent.namespace,
            "agent_id": test_agent.agent_id,
        },
        headers=auth_headers,
    )

    assert create_response.status_code == 201, f"Create failed: {create_response.json()}"
    connection_data = create_response.json()
    connection_id = connection_data["id"]

    # Verify Location header
    assert "Location" in create_response.headers
    assert f"/api/v1/mcp/connections/{connection_id}" in create_response.headers["Location"]

    # Verify response structure
    assert connection_data["server_name"] == "test_server"
    assert connection_data["status"] == "active"
    assert connection_data["namespace"] == test_agent.namespace
    assert connection_data["agent_id"] == test_agent.agent_id

    # Verify adapter.connect was called
    mock_mcp_adapter.connect.assert_called_once()

    # Step 2: Discover tools
    tools_response = test_client.get(
        f"/api/v1/mcp/connections/{connection_id}/tools",
        headers=auth_headers,
    )

    assert tools_response.status_code == 200, f"Discover failed: {tools_response.json()}"
    tools_data = tools_response.json()

    # Verify tools structure
    assert "tools" in tools_data
    assert len(tools_data["tools"]) == 1
    assert tools_data["tools"][0]["name"] == "test_tool"
    assert tools_data["tools"][0]["description"] == "Test tool for integration testing"

    # Verify adapter.discover_tools was called twice:
    # 1. During connection creation (to populate ACTIVE connection with tools)
    # 2. During explicit discovery endpoint call
    assert mock_mcp_adapter.discover_tools.call_count == 2

    # Step 3: Execute tool
    execute_response = test_client.post(
        f"/api/v1/mcp/connections/{connection_id}/tools/test_tool/execute",
        json={"arguments": {"param": "test_value"}},
        headers=auth_headers,
    )

    assert execute_response.status_code == 200, f"Execute failed: {execute_response.json()}"
    execute_data = execute_response.json()

    # Verify execution result
    assert execute_data["result"]["result"] == "success"
    assert execute_data["result"]["status"] == "completed"

    # Verify adapter.execute_tool was called
    mock_mcp_adapter.execute_tool.assert_called_once()

    # Step 4: Disconnect
    disconnect_response = test_client.delete(
        f"/api/v1/mcp/connections/{connection_id}",
        headers=auth_headers,
    )

    assert disconnect_response.status_code == 204, f"Disconnect failed: {disconnect_response.text}"

    # Verify adapter.disconnect was called
    mock_mcp_adapter.disconnect.assert_called_once()

    # Verify database state (connection should be in DISCONNECTED status)
    stmt = select(MCPConnectionModel).where(MCPConnectionModel.id == connection_id)
    result = await test_session.execute(stmt)
    db_connection = result.scalar_one_or_none()

    assert db_connection is not None
    assert db_connection.status == "disconnected"  # Enum stored as lowercase
    assert db_connection.disconnected_at is not None


# ============================================================================
# Test 2: Cross-Namespace Access Blocked (P0-1 Security)
# ============================================================================


@pytest.mark.asyncio
async def test_cross_namespace_access_blocked(
    test_client: TestClient,
    test_session: AsyncSession,
    test_agent: Agent,
    test_agent_other_namespace: Agent,
    mock_mcp_adapter: AsyncMock,
):
    """Test P0-1 security: Cannot access connection from different namespace.

    This is a CRITICAL security test that verifies namespace isolation.

    Verifies:
    - Agent in namespace-1 creates connection
    - Agent in namespace-2 CANNOT access connection
    - 403 Forbidden returned with proper error code
    - Authorization layer enforces namespace verification

    Note: MC PCl ientAdapter is already mocked in test_client fixture
    """
    from tests.integration.api.conftest import create_jwt_token

    # Agent1 creates connection
    token1 = create_jwt_token(test_agent)
    headers1 = {"Authorization": f"Bearer {token1}"}

    create_response = test_client.post(
        "/api/v1/mcp/connections",
        json={
            "server_name": "test_server",
            "url": "http://localhost:8080",
            "timeout": 30,
            "namespace": test_agent.namespace,
            "agent_id": test_agent.agent_id,
        },
        headers=headers1,
    )

    assert create_response.status_code == 201
    connection_id = create_response.json()["id"]

    # Agent2 tries to access agent1's connection
    token2 = create_jwt_token(test_agent_other_namespace)
    headers2 = {"Authorization": f"Bearer {token2}"}

    # Override current_user to return agent2
    from src.api.dependencies import User, get_current_user

    async def override_get_current_user_agent2():
        return User(
            agent_id=test_agent_other_namespace.agent_id,
            namespace=test_agent_other_namespace.namespace,
            roles=["user"],
        )

    # Apply override for agent2
    from src.api.main import app

    app.dependency_overrides[get_current_user] = override_get_current_user_agent2

    # Attempt to discover tools (should fail with 403)
    discover_response = test_client.get(
        f"/api/v1/mcp/connections/{connection_id}/tools",
        headers=headers2,
    )

    # Verify 403 Forbidden (or 404 if namespace filtering in repository)
    assert discover_response.status_code in [403, 404], (
        f"Expected 403/404, got {discover_response.status_code}: {discover_response.json()}"
    )

    if discover_response.status_code == 403:
        error = discover_response.json()
        assert "AUTHORIZATION_ERROR" in str(error.get("error_code", ""))

    # Cleanup override
    app.dependency_overrides.clear()


# ============================================================================
# Test 3: Database Persistence Verified
# ============================================================================


@pytest.mark.asyncio
async def test_connection_persisted_in_database(
    test_client: TestClient,
    test_session: AsyncSession,
    auth_headers: dict[str, str],
    test_agent: Agent,
    mock_mcp_adapter: AsyncMock,
):
    """Test that connection is actually persisted to database.

    This test verifies database integration by:
    - Creating connection via API
    - Querying database directly to verify persistence
    - Checking all fields are correctly stored

    Verifies:
    - Database record created
    - All fields correctly persisted
    - Timestamps set correctly
    - Configuration stored as JSON

    Note: MCPClientAdapter is already mocked in test_client fixture
    """
    # Create connection via API
    create_response = test_client.post(
        "/api/v1/mcp/connections",
        json={
            "server_name": "persisted_server",
            "url": "http://localhost:8080",
            "timeout": 30,
            "namespace": test_agent.namespace,
            "agent_id": test_agent.agent_id,
        },
        headers=auth_headers,
    )

    assert create_response.status_code == 201
    connection_id = create_response.json()["id"]

    # Query database directly to verify persistence
    stmt = select(MCPConnectionModel).where(MCPConnectionModel.id == connection_id)
    result = await test_session.execute(stmt)
    db_connection = result.scalar_one_or_none()

    # Verify record exists
    assert db_connection is not None, "Connection not found in database"

    # Verify fields
    assert db_connection.server_name == "persisted_server"
    assert db_connection.namespace == test_agent.namespace
    assert db_connection.agent_id == test_agent.agent_id
    assert db_connection.status == ConnectionStatus.ACTIVE

    # Verify configuration JSON
    assert db_connection.config_json is not None
    assert "url" in db_connection.config_json
    assert db_connection.config_json["url"] == "http://localhost:8080/"

    # Verify timestamps
    assert db_connection.created_at is not None
    assert db_connection.updated_at is not None
    assert db_connection.connected_at is not None

    # Verify tools list (discovered on connection, per domain rule)
    assert db_connection.tools_json is not None
    assert len(db_connection.tools_json) == 1
    assert db_connection.tools_json[0]["name"] == "test_tool"


# ============================================================================
# Test 4: Validation Error Handling
# ============================================================================


@pytest.mark.asyncio
async def test_validation_error_returns_400(
    test_client: TestClient,
    auth_headers: dict[str, str],
    test_agent: Agent,
):
    """Test that invalid input returns 400 with validation details.

    This test verifies request validation by:
    - Sending invalid data (malformed URL)
    - Verifying 400 Bad Request response
    - Checking error message contains validation details

    Verifies:
    - Pydantic validation works
    - Error response format correct
    - No internal details leaked
    """
    # Invalid URL format
    response = test_client.post(
        "/api/v1/mcp/connections",
        json={
            "server_name": "test_server",
            "url": "not-a-valid-url",  # Invalid URL
            "timeout": 30,
            "namespace": test_agent.namespace,
            "agent_id": test_agent.agent_id,
        },
        headers=auth_headers,
    )

    # Verify 400 Bad Request
    assert response.status_code == 400, (
        f"Expected 400, got {response.status_code}: {response.json()}"
    )

    error = response.json()

    # Verify error structure
    assert "error_code" in error
    assert error["error_code"] == "VALIDATION_ERROR"

    # Verify error message mentions URL
    assert "url" in str(error).lower() or "validation" in str(error).lower()

    # Verify no internal stack traces
    assert "stack_trace" not in str(error).lower()
    assert "traceback" not in str(error).lower()


# ============================================================================
# Test 5: External Service Failure Handling
# ============================================================================


@pytest.mark.asyncio
async def test_external_service_failure_returns_502(
    test_client: TestClient,
    auth_headers: dict[str, str],
    test_agent: Agent,
    mock_mcp_adapter: AsyncMock,
):
    """Test that MCP adapter failure returns 502 Bad Gateway.

    This test verifies external service error handling by:
    - Mocking adapter to raise MCPConnectionError
    - Verifying 502 Bad Gateway response
    - Checking error message is sanitized

    Verifies:
    - External service errors mapped to 502
    - Error message sanitized (no internal details)
    - Error code correct

    Note: MCPClientAdapter is already mocked in test_client fixture
    """
    # Mock adapter to raise connection error
    mock_mcp_adapter.connect.side_effect = MCPConnectionError("Connection refused by MCP server")

    response = test_client.post(
        "/api/v1/mcp/connections",
        json={
            "server_name": "failing_server",
            "url": "http://localhost:8080",
            "timeout": 30,
            "namespace": test_agent.namespace,
            "agent_id": test_agent.agent_id,
        },
        headers=auth_headers,
    )

    # Verify 502 Bad Gateway
    assert response.status_code == 502, (
        f"Expected 502, got {response.status_code}: {response.json()}"
    )

    error = response.json()

    # Verify error structure
    assert "error_code" in error
    assert error["error_code"] == "EXTERNAL_SERVICE_ERROR"

    # Verify error message is sanitized (no internal stack traces)
    assert "stack_trace" not in str(error).lower()
    assert "traceback" not in str(error).lower()

    # Verify message mentions external service issue
    assert "external" in str(error).lower() or "service" in str(error).lower()
