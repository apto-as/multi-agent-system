"""Fixtures for MCP connections router unit tests

This module provides mocked dependencies for testing FastAPI routers
without actual database or external service connections.

All fixtures are mocked for fast, isolated unit tests.
"""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest

from src.application.dtos.response_dtos import (
    DisconnectionResultDTO,
    MCPConnectionDTO,
    ToolDTO,
    ToolExecutionResultDTO,
)
from src.application.exceptions import (
    AuthorizationError,
    ExternalServiceError,
    ValidationError,
)
from src.domain.exceptions import AggregateNotFoundError


@pytest.fixture
def test_agent_id() -> UUID:
    """Fixed agent ID for testing"""
    return UUID("12345678-1234-5678-1234-567812345678")


@pytest.fixture
def test_namespace() -> str:
    """Fixed namespace for testing"""
    return "test-namespace"


@pytest.fixture
def test_connection_id() -> UUID:
    """Fixed connection ID for testing"""
    return UUID("87654321-4321-8765-4321-876543218765")


@pytest.fixture
def mock_tool_dto() -> ToolDTO:
    """Mock ToolDTO for testing"""
    return ToolDTO(
        name="test_tool",
        description="Test tool description",
        input_schema={"type": "object", "properties": {}},
        category="testing",
    )


@pytest.fixture
def mock_connection_dto(
    test_connection_id: UUID, test_agent_id: UUID, test_namespace: str, mock_tool_dto: ToolDTO
) -> MCPConnectionDTO:
    """Mock MCPConnectionDTO for testing"""
    return MCPConnectionDTO(
        id=test_connection_id,
        server_name="test_server",
        url="http://localhost:8080",
        namespace=test_namespace,
        agent_id=test_agent_id,
        status="ACTIVE",
        tools=[mock_tool_dto],
        created_at=datetime.now(),
        connected_at=datetime.now(),
        disconnected_at=None,
        error_message=None,
    )


@pytest.fixture
def mock_disconnection_result_dto(
    test_connection_id: UUID,
) -> DisconnectionResultDTO:
    """Mock DisconnectionResultDTO for testing"""
    return DisconnectionResultDTO(
        connection_id=test_connection_id,
        server_name="test_server",
        disconnected_at=datetime.now(),
    )


@pytest.fixture
def mock_tool_execution_result_dto(
    test_connection_id: UUID,
) -> ToolExecutionResultDTO:
    """Mock ToolExecutionResultDTO for testing"""
    return ToolExecutionResultDTO(
        connection_id=test_connection_id,
        tool_name="test_tool",
        result={"status": "success", "data": {"message": "Tool executed successfully"}},
    )


@pytest.fixture
def mock_current_user(test_agent_id: UUID, test_namespace: str):
    """Mock authenticated user from JWT

    This represents the User object extracted from JWT token
    by the authentication middleware.
    """
    user = MagicMock()
    user.agent_id = test_agent_id
    user.namespace = test_namespace
    user.roles = ["user"]
    return user


@pytest.fixture
def mock_connect_use_case(mock_connection_dto: MCPConnectionDTO):
    """Mock ConnectMCPServerUseCase

    Returns:
        AsyncMock with execute() method returning MCPConnectionDTO
    """
    use_case = AsyncMock()
    use_case.execute = AsyncMock(return_value=mock_connection_dto)
    return use_case


@pytest.fixture
def mock_disconnect_use_case(mock_disconnection_result_dto: DisconnectionResultDTO):
    """Mock DisconnectMCPServerUseCase

    Returns:
        AsyncMock with execute() method returning DisconnectionResultDTO
    """
    use_case = AsyncMock()
    use_case.execute = AsyncMock(return_value=mock_disconnection_result_dto)
    return use_case


@pytest.fixture
def mock_discover_tools_use_case(mock_connection_dto: MCPConnectionDTO):
    """Mock DiscoverToolsUseCase

    Returns:
        AsyncMock with execute() method returning MCPConnectionDTO
    """
    use_case = AsyncMock()
    use_case.execute = AsyncMock(return_value=mock_connection_dto)
    return use_case


@pytest.fixture
def mock_execute_tool_use_case(mock_tool_execution_result_dto: ToolExecutionResultDTO):
    """Mock ExecuteToolUseCase

    Returns:
        AsyncMock with execute() method returning ToolExecutionResultDTO
    """
    use_case = AsyncMock()
    use_case.execute = AsyncMock(return_value=mock_tool_execution_result_dto)
    return use_case


# Exception helper fixtures for error testing


@pytest.fixture
def mock_validation_error():
    """Mock ValidationError for testing 400 responses"""
    return ValidationError("Invalid input parameters")


@pytest.fixture
def mock_authorization_error():
    """Mock AuthorizationError for testing 403 responses"""
    return AuthorizationError("Namespace mismatch")


@pytest.fixture
def mock_not_found_error():
    """Mock AggregateNotFoundError for testing 404 responses"""
    return AggregateNotFoundError("MCPConnection", "connection-id")


@pytest.fixture
def mock_external_service_error():
    """Mock ExternalServiceError for testing 502 responses"""
    return ExternalServiceError("MCP server connection failed")
