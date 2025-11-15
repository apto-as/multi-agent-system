"""
Unit tests for DiscoverToolsUseCase

This module tests the DiscoverToolsUseCase in isolation with all dependencies mocked.
Tests follow TDD RED phase methodology - expecting failures until implementation exists.
"""

import pytest
from datetime import datetime
from uuid import uuid4, UUID
from unittest.mock import AsyncMock, MagicMock

from src.application.use_cases.discover_tools_use_case import (
    DiscoverToolsUseCase,
)
from src.application.dtos.request_dtos import DiscoverToolsRequest
from src.application.dtos.response_dtos import MCPConnectionDTO


@pytest.mark.asyncio
class TestDiscoverToolsUseCase:
    """Test suite for DiscoverToolsUseCase"""

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
    def mock_uow(self):
        """Mock UnitOfWork"""
        uow = AsyncMock()
        uow.__aenter__.return_value = uow
        uow.__aexit__.return_value = None
        return uow

    @pytest.fixture
    def mock_event_dispatcher(self):
        """Mock DomainEventDispatcher"""
        return AsyncMock()

    @pytest.fixture
    def use_case(
        self,
        mock_repository,
        mock_adapter,
        mock_agent_repository,
        mock_uow,
        mock_event_dispatcher,
    ):
        """Create DiscoverToolsUseCase with all dependencies mocked"""
        return DiscoverToolsUseCase(
            repository=mock_repository,
            adapter=mock_adapter,
            agent_repository=mock_agent_repository,
            uow=mock_uow,
            event_dispatcher=mock_event_dispatcher,
        )

    @pytest.fixture
    def valid_request(self):
        """Create valid DiscoverToolsRequest"""
        return DiscoverToolsRequest(
            connection_id=uuid4(),
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
    def mock_active_connection(self, valid_request):
        """Mock ACTIVE MCPConnection aggregate"""
        from src.domain.value_objects.connection_status import ConnectionStatus

        connection = MagicMock()
        connection.id = valid_request.connection_id
        connection.server_name = MagicMock()
        connection.server_name.__str__.return_value = "test_server"
        # Use actual ConnectionStatus enum for status comparison
        connection.status = ConnectionStatus.ACTIVE
        connection.namespace = valid_request.namespace
        connection.tools = []
        connection.domain_events = []
        return connection

    @pytest.fixture
    def mock_disconnected_connection(self, valid_request):
        """Mock DISCONNECTED MCPConnection aggregate"""
        from src.domain.value_objects.connection_status import ConnectionStatus

        connection = MagicMock()
        connection.id = valid_request.connection_id
        # Use actual ConnectionStatus enum for status comparison
        connection.status = ConnectionStatus.DISCONNECTED
        connection.namespace = valid_request.namespace
        return connection

    async def test_discover_tools_success(
        self,
        use_case,
        valid_request,
        mock_agent,
        mock_active_connection,
        mock_repository,
        mock_adapter,
        mock_agent_repository,
        mock_uow,
        mock_event_dispatcher,
    ):
        """
        Test successful tool discovery

        Arrange:
            - Mock agent repository to return agent with matching namespace
            - Mock repository to return ACTIVE connection
            - Mock adapter to return new tools

        Act:
            - Execute use case

        Assert:
            - Namespace verified from database
            - Connection retrieved with verified namespace
            - Connection status checked (ACTIVE)
            - Adapter.discover_tools() called
            - Connection.update_tools() called
            - Repository.update() called
            - UoW.commit() called
            - Events dispatched AFTER commit
            - Updated MCPConnectionDTO returned
        """
        # Arrange
        mock_agent_repository.get_by_id.return_value = mock_agent
        mock_repository.get_by_id.return_value = mock_active_connection

        # Import Tool entity
        from src.domain.entities.tool import Tool
        from src.domain.value_objects.tool_category import ToolCategory

        mock_new_tools = [
            Tool(name="new_tool", description="New Tool", input_schema={}, category=ToolCategory.GENERAL)
        ]
        mock_adapter.discover_tools.return_value = mock_new_tools

        # Act
        result = await use_case.execute(valid_request)

        # Assert - Namespace verification
        mock_agent_repository.get_by_id.assert_called_once_with(valid_request.agent_id)

        # Assert - Connection retrieval with verified namespace
        mock_repository.get_by_id.assert_called_once_with(
            valid_request.connection_id, mock_agent.namespace
        )

        # Assert - Tool discovery
        mock_adapter.discover_tools.assert_called_once_with(mock_active_connection.id)

        # Assert - Connection update
        mock_active_connection.update_tools.assert_called_once_with(mock_new_tools)

        # Assert - Repository operations
        mock_repository.update.assert_called_once_with(mock_active_connection)

        # Assert - Transaction
        mock_uow.__aenter__.assert_called_once()
        mock_uow.commit.assert_called_once()

        # Assert - Event dispatch
        mock_event_dispatcher.dispatch_all.assert_called_once()

        # Assert - DTO returned
        assert isinstance(result, MCPConnectionDTO)

    async def test_discover_tools_fails_connection_not_found(
        self,
        use_case,
        valid_request,
        mock_agent,
        mock_agent_repository,
        mock_repository,
    ):
        """
        Test tool discovery fails when connection not found

        Arrange:
            - Mock repository to return None (connection not found)

        Act:
            - Execute use case

        Assert:
            - AggregateNotFoundError raised
            - No adapter operations performed
        """
        # Arrange
        mock_agent_repository.get_by_id.return_value = mock_agent
        mock_repository.get_by_id.return_value = None

        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            await use_case.execute(valid_request)

        # Should raise AggregateNotFoundError
        assert "not found" in str(exc_info.value).lower()

        # Verify no repository updates
        mock_repository.update.assert_not_called()

    async def test_discover_tools_fails_connection_not_active(
        self,
        use_case,
        valid_request,
        mock_agent,
        mock_disconnected_connection,
        mock_agent_repository,
        mock_repository,
        mock_adapter,
    ):
        """
        Test tool discovery fails when connection is not ACTIVE

        Arrange:
            - Mock repository to return DISCONNECTED connection

        Act:
            - Execute use case

        Assert:
            - ValidationError raised with "not active" message
            - No adapter operations performed
        """
        # Arrange
        mock_agent_repository.get_by_id.return_value = mock_agent
        mock_repository.get_by_id.return_value = mock_disconnected_connection

        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            await use_case.execute(valid_request)

        # Should raise ValidationError with "not active"
        assert "not active" in str(exc_info.value).lower() or "disconnected" in str(exc_info.value).lower()

        # Verify no adapter calls
        mock_adapter.discover_tools.assert_not_called()

        # Verify no repository updates
        mock_repository.update.assert_not_called()
