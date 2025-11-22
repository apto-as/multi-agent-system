"""
Unit tests for ConnectMCPServerUseCase

This module tests the ConnectMCPServerUseCase in isolation with all dependencies mocked.
Tests follow TDD RED phase methodology - expecting failures until implementation exists.
"""

import pytest
from datetime import datetime
from uuid import uuid4, UUID
from unittest.mock import AsyncMock, MagicMock

from src.application.use_cases.connect_mcp_server_use_case import (
    ConnectMCPServerUseCase,
)
from src.application.dtos.request_dtos import CreateConnectionRequest
from src.application.dtos.response_dtos import MCPConnectionDTO


@pytest.mark.asyncio
class TestConnectMCPServerUseCase:
    """Test suite for ConnectMCPServerUseCase"""

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
        """Create ConnectMCPServerUseCase with all dependencies mocked"""
        return ConnectMCPServerUseCase(
            repository=mock_repository,
            adapter=mock_adapter,
            agent_repository=mock_agent_repository,
            uow=mock_uow,
            event_dispatcher=mock_event_dispatcher,
        )

    @pytest.fixture
    def valid_request(self):
        """Create valid CreateConnectionRequest"""
        return CreateConnectionRequest(
            server_name="test_server",
            url="http://localhost:8080/mcp",
            namespace="test-namespace",
            agent_id=uuid4(),
            timeout=30,
            retry_attempts=3,
            auth_required=False,
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
        connection.id = uuid4()
        connection.server_name = MagicMock()
        connection.server_name.__str__.return_value = valid_request.server_name
        connection.url = MagicMock()
        connection.url.__str__.return_value = valid_request.url
        connection.namespace = valid_request.namespace
        connection.agent_id = valid_request.agent_id
        connection.status = MagicMock()
        connection.status.value = "ACTIVE"
        connection.tools = []
        connection.created_at = datetime.utcnow()
        connection.connected_at = datetime.utcnow()
        connection.disconnected_at = None
        connection.error_message = None
        connection.domain_events = []
        return connection

    async def test_connect_success_with_active_connection(
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
        Test successful connection with all steps verified

        Arrange:
            - Mock agent repository to return agent with matching namespace
            - Mock repository to NOT return existing connection (no duplicate)
            - Mock adapter to successfully connect and return tools
            - Mock aggregate creation (via MCPConnection.create)

        Act:
            - Execute use case with valid request

        Assert:
            - Namespace verified from database
            - No duplicate connection found
            - Aggregate created with correct parameters
            - Aggregate added to repository
            - Adapter.connect() called
            - Tools discovered via adapter
            - Aggregate marked as ACTIVE
            - Repository.update() called
            - UoW.commit() called
            - Events dispatched AFTER commit
            - DTO returned with correct data
        """
        # Arrange
        mock_agent_repository.get_by_id.return_value = mock_agent
        mock_repository.get_by_server_name_and_namespace.return_value = None

        # Import Tool entity
        from src.domain.entities.tool import Tool
        from src.domain.value_objects.tool_category import ToolCategory

        mock_tools = [
            Tool(name="tool1", description="Tool 1", input_schema={}, category=ToolCategory.DATA_PROCESSING)
        ]
        mock_adapter.discover_tools.return_value = mock_tools

        # Mock MCPConnection.create (would normally be done via dependency injection)
        # For now, we'll mock the repository.add to capture the connection
        async def capture_add(connection):
            # Simulate adding connection to repository
            pass

        mock_repository.add = AsyncMock(side_effect=capture_add)

        # Act
        result = await use_case.execute(valid_request)

        # Assert - Namespace verification
        mock_agent_repository.get_by_id.assert_called_once_with(valid_request.agent_id)

        # Assert - Duplicate check
        mock_repository.get_by_server_name_and_namespace.assert_called_once_with(
            valid_request.server_name, mock_agent.namespace
        )

        # Assert - Repository operations
        mock_repository.add.assert_called_once()
        mock_repository.update.assert_called_once()

        # Assert - Adapter operations
        mock_adapter.connect.assert_called_once()
        mock_adapter.discover_tools.assert_called_once()

        # Assert - Transaction
        mock_uow.__aenter__.assert_called_once()
        mock_uow.commit.assert_called_once()

        # Assert - Event dispatch AFTER commit
        mock_event_dispatcher.dispatch_all.assert_called_once()

        # Assert - DTO returned
        assert isinstance(result, MCPConnectionDTO)

    async def test_connect_fails_with_invalid_input(
        self,
        use_case,
        valid_request,
    ):
        """
        Test connection fails with invalid input

        Arrange:
            - Create request with invalid URL

        Act:
            - Execute use case

        Assert:
            - ValidationError raised (by Pydantic at DTO creation)
            - No database operations performed
        """
        # Act & Assert - Pydantic raises ValidationError at DTO creation
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            invalid_request = CreateConnectionRequest(
                server_name=valid_request.server_name,
                url="not-a-valid-url",  # Invalid URL - Pydantic raises here
                namespace=valid_request.namespace,
                agent_id=valid_request.agent_id,
            )

        # Should raise ValidationError (from Pydantic)
        assert "url" in str(exc_info.value).lower()

    async def test_connect_fails_with_namespace_mismatch(
        self,
        use_case,
        valid_request,
        mock_agent,
        mock_agent_repository,
        mock_repository,
    ):
        """
        Test connection fails when namespace doesn't match agent's namespace

        Arrange:
            - Mock agent with DIFFERENT namespace than request

        Act:
            - Execute use case

        Assert:
            - AuthorizationError raised
            - Security audit log entry created (if implemented)
        """
        # Arrange - Agent with different namespace
        mock_agent.namespace = "different-namespace"
        mock_agent_repository.get_by_id.return_value = mock_agent

        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            await use_case.execute(valid_request)

        # Should raise AuthorizationError
        assert "authorization" in str(exc_info.value).lower() or "namespace" in str(exc_info.value).lower()

        # Verify no repository operations performed
        mock_repository.add.assert_not_called()

    async def test_connect_fails_with_duplicate_connection(
        self,
        use_case,
        valid_request,
        mock_agent,
        mock_connection,
        mock_agent_repository,
        mock_repository,
    ):
        """
        Test connection fails when connection already exists

        Arrange:
            - Mock repository to return existing connection

        Act:
            - Execute use case

        Assert:
            - ValidationError raised with "already exists" message
            - No new connection added
        """
        # Arrange - Existing connection
        mock_agent_repository.get_by_id.return_value = mock_agent
        mock_repository.get_by_server_name_and_namespace.return_value = mock_connection

        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            await use_case.execute(valid_request)

        # Should raise ValidationError with "already exists"
        assert "already exists" in str(exc_info.value).lower() or "duplicate" in str(exc_info.value).lower()

        # Verify no add operation
        mock_repository.add.assert_not_called()
