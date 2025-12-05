"""Discover Tools Use Case

Purpose: Discover or refresh tools from active MCP connection

Flow:
1. Namespace verification from DB
2. Authorization check
3. Retrieve connection from repository
4. Verify connection is ACTIVE
5. Discover tools from MCP server
6. Begin transaction
7. Update connection with new tools
8. Persist updated connection
9. Commit transaction
10. Dispatch ToolsDiscoveredEvent
11. Return updated MCPConnectionDTO
"""

import logging

from src.application.dtos.request_dtos import DiscoverToolsRequest
from src.application.dtos.response_dtos import MCPConnectionDTO
from src.application.events.dispatcher import EventDispatcher
from src.application.exceptions import (
    AuthorizationError,
    ExternalServiceError,
    ValidationError,
)
from src.domain.exceptions import AggregateNotFoundError
from src.domain.repositories.agent_repository import AgentRepository
from src.domain.repositories.mcp_connection_repository import (
    MCPConnectionRepository,
)
from src.domain.value_objects.connection_status import ConnectionStatus
from src.infrastructure.adapters.mcp_client_adapter import (
    MCPClientAdapter,
    MCPConnectionError,
)
from src.infrastructure.unit_of_work import UnitOfWork

logger = logging.getLogger(__name__)


class DiscoverToolsUseCase:
    def __init__(
        self,
        repository: MCPConnectionRepository,
        adapter: MCPClientAdapter,
        agent_repository: AgentRepository,
        uow: UnitOfWork,
        event_dispatcher: EventDispatcher,
    ):
        self._repository = repository
        self._adapter = adapter
        self._agent_repository = agent_repository
        self._uow = uow
        self._event_dispatcher = event_dispatcher

    async def execute(self, request: DiscoverToolsRequest) -> MCPConnectionDTO:
        # [1-2] Namespace verification
        verified_namespace = await self._verify_namespace(request.agent_id, request.namespace)

        # [3] Retrieve connection
        connection = await self._repository.get_by_id(request.connection_id, verified_namespace)
        if not connection:
            raise AggregateNotFoundError("MCPConnection", str(request.connection_id))

        # [4] Verify active
        if connection.status != ConnectionStatus.ACTIVE:
            raise ValidationError(f"Connection is not active (status: {connection.status.value})")

        # [5] Discover tools
        try:
            tools = await self._adapter.discover_tools(connection.id)
        except MCPConnectionError as e:
            raise ExternalServiceError(f"Failed to discover tools: {e}") from e

        async with self._uow:
            # [6-7] Update connection (replace tools, not append)
            connection.tools = []  # Clear existing tools
            connection.add_tools(tools)  # Add fresh tools from discovery

            # [8] Persist
            await self._repository.save(connection)

            # [9] Commit
            await self._uow.commit()

        # [10] Dispatch events
        await self._event_dispatcher.dispatch_all(connection.domain_events)

        # [11] Return DTO
        return MCPConnectionDTO.from_aggregate(connection)

    async def _verify_namespace(self, agent_id, claimed_namespace: str) -> str:
        """
        Verify namespace from database (SECURITY CRITICAL)

        Args:
            agent_id: Agent making the request
            claimed_namespace: Namespace from request DTO

        Returns:
            Verified namespace from database

        Raises:
            AuthorizationError: If namespace mismatch (possible attack)
        """
        # [1] Fetch agent from database (NEVER from JWT claims)
        agent = await self._agent_repository.get_by_id(agent_id)

        if not agent:
            raise AuthorizationError(f"Agent {agent_id} not found")

        # [2] Verify namespace matches database
        verified_namespace = agent.namespace

        if claimed_namespace != verified_namespace:
            # Log potential attack attempt
            logger.warning(
                f"Namespace mismatch for agent {agent_id}: "
                f"claimed={claimed_namespace}, actual={verified_namespace}"
            )

            raise AuthorizationError("Namespace verification failed (access denied)")

        # [3] Return verified namespace
        return verified_namespace
