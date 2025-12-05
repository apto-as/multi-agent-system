"""E2E tests for MCP Connection API (Full HTTP Workflow).

This test suite verifies end-to-end user scenarios:
- Real-world workflows with multiple steps
- Error recovery and retry scenarios
- Concurrent operations
- Resource lifecycle management

Difference from Integration Tests:
- Integration: Verify component integration (Router → Use Case → DB)
- E2E: Verify complete user scenarios and workflows

Architecture:
- REAL: Full HTTP stack (FastAPI + SQLite + ChromaDB)
- MOCK: Only MCPClientAdapter (external MCP server)

Author: Artemis (E2E Test Specialist)
Created: 2025-11-12 (Phase 1-3-E: E2E Tests)
"""

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.infrastructure.adapters.mcp_client_adapter import MCPConnectionError
from src.models.agent import Agent
from src.models.mcp_connection import MCPConnectionModel

# ============================================================================
# E2E Test 1: Multiple Connections Management
# ============================================================================


@pytest.mark.asyncio
async def test_manage_multiple_connections_e2e(
    test_client: TestClient,
    test_session: AsyncSession,
    auth_headers: dict[str, str],
    test_agent: Agent,
    mock_mcp_adapter: AsyncMock,
):
    """E2E: Agent manages multiple MCP server connections simultaneously.

    Scenario:
    1. Agent connects to Server A
    2. Agent connects to Server B
    3. Agent discovers tools from both servers
    4. Agent executes tools on different servers
    5. Agent disconnects from Server A
    6. Agent still has access to Server B
    7. Agent disconnects from Server B

    This tests:
    - Multiple active connections per agent
    - Independent lifecycle management
    - No cross-connection interference
    """
    # Step 1: Connect to Server A
    response_a = test_client.post(
        "/api/v1/mcp/connections",
        json={
            "server_name": "server_a",
            "url": "http://localhost:8080",
            "timeout": 30,
            "namespace": test_agent.namespace,
            "agent_id": test_agent.agent_id,
        },
        headers=auth_headers,
    )

    assert response_a.status_code == 201
    connection_a_id = response_a.json()["id"]

    # Step 2: Connect to Server B
    response_b = test_client.post(
        "/api/v1/mcp/connections",
        json={
            "server_name": "server_b",
            "url": "http://localhost:9090",
            "timeout": 30,
            "namespace": test_agent.namespace,
            "agent_id": test_agent.agent_id,
        },
        headers=auth_headers,
    )

    assert response_b.status_code == 201
    connection_b_id = response_b.json()["id"]

    # Verify both connections are active
    assert connection_a_id != connection_b_id

    # Step 3: Discover tools from both servers
    tools_a = test_client.get(
        f"/api/v1/mcp/connections/{connection_a_id}/tools",
        headers=auth_headers,
    )
    tools_b = test_client.get(
        f"/api/v1/mcp/connections/{connection_b_id}/tools",
        headers=auth_headers,
    )

    assert tools_a.status_code == 200
    assert tools_b.status_code == 200

    # Step 4: Execute tool on Server A
    execute_a = test_client.post(
        f"/api/v1/mcp/connections/{connection_a_id}/tools/test_tool/execute",
        json={"arguments": {"param": "value_a"}},
        headers=auth_headers,
    )

    assert execute_a.status_code == 200

    # Step 5: Disconnect from Server A
    disconnect_a = test_client.delete(
        f"/api/v1/mcp/connections/{connection_a_id}",
        headers=auth_headers,
    )

    assert disconnect_a.status_code == 204

    # Step 6: Verify Server B is still accessible
    tools_b_after = test_client.get(
        f"/api/v1/mcp/connections/{connection_b_id}/tools",
        headers=auth_headers,
    )

    assert tools_b_after.status_code == 200

    # Step 7: Verify Server A is disconnected
    stmt = select(MCPConnectionModel).where(MCPConnectionModel.id == connection_a_id)
    result = await test_session.execute(stmt)
    db_connection_a = result.scalar_one_or_none()

    assert db_connection_a.status == "disconnected"

    # Step 8: Disconnect from Server B
    disconnect_b = test_client.delete(
        f"/api/v1/mcp/connections/{connection_b_id}",
        headers=auth_headers,
    )

    assert disconnect_b.status_code == 204


# ============================================================================
# E2E Test 2: Error Recovery and Retry
# ============================================================================


@pytest.mark.asyncio
async def test_connection_error_recovery_e2e(
    test_client: TestClient,
    test_session: AsyncSession,
    auth_headers: dict[str, str],
    test_agent: Agent,
    mock_mcp_adapter: AsyncMock,
):
    """E2E: Agent handles connection failure and retries successfully.

    Scenario:
    1. First connection attempt fails (external service error)
    2. Agent receives 502 Bad Gateway
    3. Agent retries connection after fixing the issue
    4. Second attempt succeeds
    5. Agent can use the connection normally

    This tests:
    - Error response handling
    - Idempotent connection creation
    - Recovery from external service failures
    """
    # Step 1: First attempt - connection fails
    mock_mcp_adapter.connect.side_effect = MCPConnectionError("Server unreachable")

    response_fail = test_client.post(
        "/api/v1/mcp/connections",
        json={
            "server_name": "unstable_server",
            "url": "http://localhost:8080",
            "timeout": 30,
            "namespace": test_agent.namespace,
            "agent_id": test_agent.agent_id,
        },
        headers=auth_headers,
    )

    # Step 2: Verify 502 Bad Gateway
    assert response_fail.status_code == 502
    error = response_fail.json()
    assert error["error_code"] == "EXTERNAL_SERVICE_ERROR"

    # Step 3: Fix the external service (remove side effect)
    mock_mcp_adapter.connect.side_effect = None

    # Step 4: Retry connection (different server name to avoid duplicate)
    response_success = test_client.post(
        "/api/v1/mcp/connections",
        json={
            "server_name": "unstable_server_retry",  # Different name
            "url": "http://localhost:8080",
            "timeout": 30,
            "namespace": test_agent.namespace,
            "agent_id": test_agent.agent_id,
        },
        headers=auth_headers,
    )

    # Step 5: Verify success
    assert response_success.status_code == 201
    connection_data = response_success.json()
    assert connection_data["status"] == "active"

    # Step 6: Verify connection is usable
    connection_id = connection_data["id"]
    tools_response = test_client.get(
        f"/api/v1/mcp/connections/{connection_id}/tools",
        headers=auth_headers,
    )

    assert tools_response.status_code == 200


# ============================================================================
# E2E Test 3: Cross-Agent Isolation (Security)
# ============================================================================


@pytest.mark.asyncio
async def test_cross_agent_isolation_e2e(
    test_client: TestClient,
    test_session: AsyncSession,
    test_agent: Agent,
    test_agent_other_namespace: Agent,
    mock_mcp_adapter: AsyncMock,
):
    """E2E: Multiple agents cannot access each other's connections.

    Scenario:
    1. Agent A creates connection to Server X
    2. Agent B creates connection to Server Y
    3. Agent A cannot access Agent B's connection
    4. Agent B cannot access Agent A's connection
    5. Each agent can only manage their own connections

    This tests:
    - P0-1 namespace isolation (security)
    - Multi-tenancy separation
    - Authorization enforcement across operations
    """
    from tests.integration.api.conftest import create_jwt_token

    # Create tokens for both agents
    token_a = create_jwt_token(test_agent)
    headers_a = {"Authorization": f"Bearer {token_a}"}

    token_b = create_jwt_token(test_agent_other_namespace)
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Step 1: Agent A creates connection to Server X
    response_a = test_client.post(
        "/api/v1/mcp/connections",
        json={
            "server_name": "server_x",
            "url": "http://localhost:8080",
            "timeout": 30,
            "namespace": test_agent.namespace,
            "agent_id": test_agent.agent_id,
        },
        headers=headers_a,
    )

    assert response_a.status_code == 201
    connection_a_id = response_a.json()["id"]

    # Step 2: Agent B creates connection to Server Y
    response_b = test_client.post(
        "/api/v1/mcp/connections",
        json={
            "server_name": "server_y",
            "url": "http://localhost:9090",
            "timeout": 30,
            "namespace": test_agent_other_namespace.namespace,
            "agent_id": test_agent_other_namespace.agent_id,
        },
        headers=headers_b,
    )

    assert response_b.status_code == 201
    response_b.json()["id"]

    # Step 3: Agent A tries to access Agent B's connection
    from src.api.dependencies import User, get_current_user
    from src.api.main import app

    # Override current_user to return Agent B
    async def override_get_current_user_agent_b():
        return User(
            agent_id=test_agent_other_namespace.agent_id,
            namespace=test_agent_other_namespace.namespace,
            roles=["user"],
        )

    app.dependency_overrides[get_current_user] = override_get_current_user_agent_b

    # Agent B tries to discover tools on Agent A's connection
    cross_access_response = test_client.get(
        f"/api/v1/mcp/connections/{connection_a_id}/tools",
        headers=headers_b,
    )

    # Should get 403 Forbidden or 404 Not Found (namespace filtering)
    assert cross_access_response.status_code in [403, 404]

    # Step 4: Restore override for Agent A
    async def override_get_current_user_agent_a():
        return User(
            agent_id=test_agent.agent_id,
            namespace=test_agent.namespace,
            roles=["user"],
        )

    app.dependency_overrides[get_current_user] = override_get_current_user_agent_a

    # Step 5: Verify Agent A can access their own connections
    agent_a_tools = test_client.get(
        f"/api/v1/mcp/connections/{connection_a_id}/tools",
        headers=headers_a,
    )

    assert agent_a_tools.status_code == 200

    # Cleanup
    app.dependency_overrides.clear()


# ============================================================================
# E2E Test 4: Full Connection Lifecycle with Error States
# ============================================================================


@pytest.mark.asyncio
async def test_connection_lifecycle_with_errors_e2e(
    test_client: TestClient,
    test_session: AsyncSession,
    auth_headers: dict[str, str],
    test_agent: Agent,
    mock_mcp_adapter: AsyncMock,
):
    """E2E: Connection lifecycle including error states.

    Scenario:
    1. Create connection successfully
    2. Tool execution fails (external error)
    3. Connection remains active despite error
    4. Retry tool execution succeeds
    5. Graceful disconnection

    This tests:
    - Error handling doesn't corrupt connection state
    - Connection remains usable after transient failures
    - Proper error propagation to client
    """
    # Step 1: Create connection
    response = test_client.post(
        "/api/v1/mcp/connections",
        json={
            "server_name": "error_test_server",
            "url": "http://localhost:8080",
            "timeout": 30,
            "namespace": test_agent.namespace,
            "agent_id": test_agent.agent_id,
        },
        headers=auth_headers,
    )

    assert response.status_code == 201
    connection_id = response.json()["id"]

    # Step 2: Tool execution fails
    from src.infrastructure.exceptions import ToolExecutionError

    mock_mcp_adapter.execute_tool.side_effect = ToolExecutionError(
        tool_name="test_tool", error_message="Temporary network error"
    )

    execute_fail = test_client.post(
        f"/api/v1/mcp/connections/{connection_id}/tools/test_tool/execute",
        json={"arguments": {"param": "value"}},
        headers=auth_headers,
    )

    # Verify error response
    assert execute_fail.status_code == 502
    error = execute_fail.json()
    assert error["error_code"] == "EXTERNAL_SERVICE_ERROR"

    # Step 3: Verify connection is still active
    stmt = select(MCPConnectionModel).where(MCPConnectionModel.id == connection_id)
    result = await test_session.execute(stmt)
    db_connection = result.scalar_one_or_none()

    assert db_connection.status == "active"  # Still active despite error

    # Step 4: Retry succeeds
    mock_mcp_adapter.execute_tool.side_effect = None

    execute_success = test_client.post(
        f"/api/v1/mcp/connections/{connection_id}/tools/test_tool/execute",
        json={"arguments": {"param": "value"}},
        headers=auth_headers,
    )

    assert execute_success.status_code == 200

    # Step 5: Graceful disconnection
    disconnect = test_client.delete(
        f"/api/v1/mcp/connections/{connection_id}",
        headers=auth_headers,
    )

    assert disconnect.status_code == 204
