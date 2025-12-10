"""
Unit tests for DisconnectMCPServerUseCase

This module tests the DisconnectMCPServerUseCase in isolation with all dependencies mocked.
Tests follow TDD RED phase methodology - expecting failures until implementation exists.
"""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from src.application.dtos.request_dtos import DisconnectRequest
from src.application.dtos.response_dtos import DisconnectionResultDTO
from src.application.use_cases.disconnect_mcp_server_use_case import (
    DisconnectMCPServerUseCase,
)


@pytest.mark.asyncio
class TestDisconnectMCPServerUseCase:
    """Test suite for DisconnectMCPServerUseCase"""

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
        """Create DisconnectMCPServerUseCase with all dependencies mocked"""
        return DisconnectMCPServerUseCase(
            repository=mock_repository,
            adapter=mock_adapter,
            agent_repository=mock_agent_repository,
            uow=mock_uow,
            event_dispatcher=mock_event_dispatcher,
        )

    @pytest.fixture
    def valid_request(self):
        """Create valid DisconnectRequest"""
        return DisconnectRequest(
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
    def mock_connection(self, valid_request):
        """Mock MCPConnection aggregate"""
        connection = MagicMock()
        connection.id = valid_request.connection_id
        connection.server_name = MagicMock()
        connection.server_name.__str__.return_value = "test_server"
        connection.namespace = valid_request.namespace
        connection.status = MagicMock()
        connection.status.value = "ACTIVE"
        connection.disconnected_at = datetime.utcnow()
        connection.domain_events = []
        return connection

    async def test_disconnect_success(
        self,
        use_case,
        valid_request,
        mock_agent,
        mock_connection,
        mock_repository,
        mock_adapter,
        mock_agent_repository,
        mock_uow,
        mock_event_dispatcher,
    ):
        """
        Test successful disconnection

        Arrange:
            - Mock agent repository to return agent with matching namespace
            - Mock repository to return connection
            - Mock adapter to successfully disconnect

        Act:
            - Execute use case

        Assert:
            - Namespace verified from database
            - Connection retrieved with verified namespace
            - Adapter.disconnect() called
            - Connection.mark_as_disconnected() called
            - Repository.update() called
            - UoW.commit() called
            - Events dispatched AFTER commit
            - DisconnectionResultDTO returned
        """
        # Arrange
        mock_agent_repository.get_by_id.return_value = mock_agent
        mock_repository.get_by_id.return_value = mock_connection
        mock_adapter.disconnect.return_value = None  # Successful disconnect

        # Act
        result = await use_case.execute(valid_request)

        # Assert - Namespace verification
        mock_agent_repository.get_by_id.assert_called_once_with(valid_request.agent_id)

        # Assert - Connection retrieval
        mock_repository.get_by_id.assert_called_once_with(
            valid_request.connection_id, mock_agent.namespace
        )

        # Assert - Adapter disconnect
        mock_adapter.disconnect.assert_called_once_with(mock_connection.id)

        # Assert - Connection state update
        # Implementation uses disconnect() method, not mark_as_disconnected()
        mock_connection.disconnect.assert_called_once()

        # Assert - Repository save (implementation uses save(), not update())
        mock_repository.save.assert_called_once_with(mock_connection)

        # Assert - Transaction
        mock_uow.__aenter__.assert_called_once()
        mock_uow.commit.assert_called_once()

        # Assert - Event dispatch
        mock_event_dispatcher.dispatch_all.assert_called_once()

        # Assert - Result DTO
        assert isinstance(result, DisconnectionResultDTO)
        assert result.connection_id == valid_request.connection_id
        assert result.server_name == "test_server"

    async def test_disconnect_with_external_failure_still_succeeds(
        self,
        use_case,
        valid_request,
        mock_agent,
        mock_connection,
        mock_repository,
        mock_adapter,
        mock_agent_repository,
        mock_uow,
        mock_event_dispatcher,
    ):
        """
        Test disconnection succeeds even when external disconnect fails (graceful degradation)

        Arrange:
            - Mock adapter.disconnect() to raise MCPConnectionError

        Act:
            - Execute use case

        Assert:
            - Error logged but NOT raised
            - Connection still marked as DISCONNECTED
            - Repository.update() called
            - UoW.commit() called
            - DisconnectionResultDTO returned
        """
        # Arrange
        mock_agent_repository.get_by_id.return_value = mock_agent
        mock_repository.get_by_id.return_value = mock_connection

        # Import MCPConnectionError
        from src.infrastructure.exceptions import MCPConnectionError

        # Mock adapter to raise MCPConnectionError
        mock_adapter.disconnect.side_effect = MCPConnectionError("External disconnect failed")

        # Act - Should NOT raise exception (graceful degradation)
        result = await use_case.execute(valid_request)

        # Assert - Adapter disconnect was attempted
        mock_adapter.disconnect.assert_called_once_with(mock_connection.id)

        # Assert - Connection still marked as disconnected despite external failure
        # Implementation uses disconnect() method, not mark_as_disconnected()
        mock_connection.disconnect.assert_called_once()

        # Assert - Repository save still performed (implementation uses save(), not update())
        mock_repository.save.assert_called_once_with(mock_connection)

        # Assert - Transaction still committed
        mock_uow.commit.assert_called_once()

        # Assert - Result still returned
        assert isinstance(result, DisconnectionResultDTO)
        assert result.connection_id == valid_request.connection_id
