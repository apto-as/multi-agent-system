"""
Unit tests for ExecuteToolUseCase

This module tests the ExecuteToolUseCase in isolation with all dependencies mocked.
Tests follow TDD RED phase methodology - expecting failures until implementation exists.
"""

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from src.application.dtos.request_dtos import ExecuteToolRequest
from src.application.dtos.response_dtos import ToolExecutionResultDTO
from src.application.use_cases.execute_tool_use_case import (
    ExecuteToolUseCase,
)


@pytest.mark.asyncio
class TestExecuteToolUseCase:
    """Test suite for ExecuteToolUseCase"""

    @pytest.fixture
    def mock_repository(self):
        """Mock MCPConnectionRepository"""
        return AsyncMock()

    @pytest.fixture
    def mock_adapter(self):
        """Mock MCPClientAdapter"""
        return AsyncMock()

    @pytest.fixture
    def mock_agent_repository(self):
        """Mock AgentRepository"""
        return AsyncMock()

    @pytest.fixture
    def use_case(
        self,
        mock_repository,
        mock_adapter,
        mock_agent_repository,
    ):
        """Create ExecuteToolUseCase with all dependencies mocked"""
        return ExecuteToolUseCase(
            repository=mock_repository,
            adapter=mock_adapter,
            agent_repository=mock_agent_repository,
        )

    @pytest.fixture
    def valid_request(self):
        """Create valid ExecuteToolRequest"""
        return ExecuteToolRequest(
            connection_id=uuid4(),
            tool_name="test_tool",
            arguments={"param1": "value1"},
            namespace="test-namespace",
            agent_id=uuid4(),
        )

    @pytest.fixture
    def mock_agent(self, valid_request):
        """Mock Agent entity"""
        agent = MagicMock()
        agent.id = valid_request.agent_id
        agent.namespace = valid_request.namespace
        return agent

    @pytest.fixture
    def mock_tool(self, valid_request):
        """Mock Tool entity"""
        tool = MagicMock()
        tool.name = valid_request.tool_name
        tool.description = "Test Tool"
        tool.input_schema = {}
        tool.category = MagicMock()
        tool.category.value = "general"
        return tool

    @pytest.fixture
    def mock_active_connection(self, valid_request, mock_tool):
        """Mock ACTIVE MCPConnection aggregate with tool"""
        from src.domain.value_objects.connection_status import ConnectionStatus

        connection = MagicMock()
        connection.id = valid_request.connection_id
        # Use actual ConnectionStatus enum for status comparison
        connection.status = ConnectionStatus.ACTIVE
        connection.namespace = valid_request.namespace
        connection.tools = [mock_tool]
        connection.get_tool_by_name.return_value = mock_tool
        return connection

    @pytest.fixture
    def mock_failed_connection(self, valid_request):
        """Mock ERROR MCPConnection aggregate"""
        from src.domain.value_objects.connection_status import ConnectionStatus

        connection = MagicMock()
        connection.id = valid_request.connection_id
        # Use actual ConnectionStatus enum for status comparison
        connection.status = ConnectionStatus.ERROR
        connection.namespace = valid_request.namespace
        return connection

    async def test_execute_tool_success(
        self,
        use_case,
        valid_request,
        mock_agent,
        mock_active_connection,
        mock_tool,
        mock_repository,
        mock_adapter,
        mock_agent_repository,
    ):
        """
        Test successful tool execution

        Arrange:
            - Mock agent repository to return agent with matching namespace
            - Mock repository to return ACTIVE connection with tool
            - Mock adapter to return execution result

        Act:
            - Execute use case

        Assert:
            - Namespace verified from database
            - Connection retrieved with verified namespace
            - Connection status checked (ACTIVE)
            - Tool existence verified
            - Adapter.execute_tool() called with correct arguments
            - ToolExecutionResultDTO returned with result
        """
        # Arrange
        mock_agent_repository.get_by_id.return_value = mock_agent
        mock_repository.get_by_id.return_value = mock_active_connection

        mock_execution_result = {"output": "success", "data": [1, 2, 3]}
        mock_adapter.execute_tool.return_value = mock_execution_result

        # Act
        result = await use_case.execute(valid_request)

        # Assert - Namespace verification
        mock_agent_repository.get_by_id.assert_called_once_with(valid_request.agent_id)

        # Assert - Connection retrieval
        mock_repository.get_by_id.assert_called_once_with(
            valid_request.connection_id, mock_agent.namespace
        )

        # Assert - Tool verification
        mock_active_connection.get_tool_by_name.assert_called_once_with(valid_request.tool_name)

        # Assert - Tool execution
        mock_adapter.execute_tool.assert_called_once_with(
            connection_id=mock_active_connection.id,
            tool_name=valid_request.tool_name,
            arguments=valid_request.arguments,
        )

        # Assert - Result DTO
        assert isinstance(result, ToolExecutionResultDTO)
        assert result.connection_id == valid_request.connection_id
        assert result.tool_name == valid_request.tool_name
        assert result.result == mock_execution_result

    async def test_execute_tool_fails_tool_not_found(
        self,
        use_case,
        valid_request,
        mock_agent,
        mock_active_connection,
        mock_agent_repository,
        mock_repository,
        mock_adapter,
    ):
        """
        Test tool execution fails when tool not found in connection

        Arrange:
            - Mock connection WITHOUT the requested tool

        Act:
            - Execute use case

        Assert:
            - ValidationError raised with "not found in connection" message
            - No adapter operations performed
        """
        # Arrange
        mock_agent_repository.get_by_id.return_value = mock_agent
        mock_repository.get_by_id.return_value = mock_active_connection

        # Mock connection to return None for the requested tool
        mock_active_connection.get_tool_by_name.return_value = None

        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            await use_case.execute(valid_request)

        # Should raise ValidationError with "not found in connection"
        assert "not found" in str(exc_info.value).lower()

        # Verify no adapter calls
        mock_adapter.execute_tool.assert_not_called()

    async def test_execute_tool_fails_connection_not_active(
        self,
        use_case,
        valid_request,
        mock_agent,
        mock_failed_connection,
        mock_agent_repository,
        mock_repository,
        mock_adapter,
    ):
        """
        Test tool execution fails when connection is not ACTIVE

        Arrange:
            - Mock repository to return FAILED connection

        Act:
            - Execute use case

        Assert:
            - ValidationError raised with "not active" message
            - No tool verification or execution performed
        """
        # Arrange
        mock_agent_repository.get_by_id.return_value = mock_agent
        mock_repository.get_by_id.return_value = mock_failed_connection

        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            await use_case.execute(valid_request)

        # Should raise ValidationError with "not active"
        assert (
            "not active" in str(exc_info.value).lower() or "failed" in str(exc_info.value).lower()
        )

        # Verify no adapter calls
        mock_adapter.execute_tool.assert_not_called()
