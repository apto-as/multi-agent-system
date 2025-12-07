"""Disconnect MCP Server Use Case

Purpose: Gracefully disconnect from MCP server

Flow:
1. Namespace verification from DB
2. Authorization check
3. Retrieve connection from repository
4. Disconnect from MCP server (external)
5. Begin transaction
6. Update aggregate (DISCONNECTED state)
7. Persist updated aggregate
8. Commit transaction
9. Dispatch MCPDisconnectedEvent
10. Return DisconnectionResultDTO
"""

import logging

from src.application.dtos.request_dtos import DisconnectRequest
from src.application.dtos.response_dtos import DisconnectionResultDTO
from src.application.events.dispatcher import EventDispatcher
from src.application.exceptions import AuthorizationError
from src.domain.exceptions import AggregateNotFoundError
from src.domain.repositories.agent_repository import AgentRepository
from src.domain.repositories.mcp_connection_repository import (
    MCPConnectionRepository,
)
from src.infrastructure.adapters.mcp_client_adapter import (
    MCPClientAdapter,
    MCPConnectionError,
)
from src.infrastructure.unit_of_work import UnitOfWork

logger = logging.getLogger(__name__)


class DisconnectMCPServerUseCase:
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

    async def execute(self, request: DisconnectRequest) -> DisconnectionResultDTO:
        # [1-2] Namespace verification
        verified_namespace = await self._verify_namespace(request.agent_id, request.namespace)

        # [3] Retrieve connection
        connection = await self._repository.get_by_id(request.connection_id, verified_namespace)
        if not connection:
            logger.error(
                "MCPConnection not found during disconnect",
                extra={
                    "connection_id": str(request.connection_id),
                    "namespace": verified_namespace,
                }
            )
            raise AggregateNotFoundError("MCPConnection", str(request.connection_id))

        # [4] Disconnect from external server
        try:
            await self._adapter.disconnect(connection.id)
        except MCPConnectionError as e:
            # Log but don't fail - allow graceful degradation
            logger.warning(f"Failed to disconnect from MCP server: {e}")

        async with self._uow:
            # [5-6] Update aggregate
            connection.disconnect(reason="User requested disconnection")

            # [7] Persist
            await self._repository.save(connection)

            # [8] Commit
            await self._uow.commit()

        # [9] Dispatch events
        await self._event_dispatcher.dispatch_all(connection.domain_events)

        # [10] Return result
        return DisconnectionResultDTO(
            connection_id=connection.id,
            server_name=str(connection.server_name),
            disconnected_at=connection.disconnected_at,
        )

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
            logger.error(
                "Agent not found during namespace verification",
                extra={"agent_id": agent_id}
            )
            raise AuthorizationError(
                f"Agent {agent_id} not found",
                details={"agent_id": agent_id}
            )

        # [2] Verify namespace matches database
        verified_namespace = agent.namespace

        if claimed_namespace != verified_namespace:
            # Log potential attack attempt (SECURITY-CRITICAL)
            logger.error(
                "Namespace verification failed - possible attack attempt",
                extra={
                    "agent_id": agent_id,
                    "claimed_namespace": claimed_namespace,
                    "verified_namespace": verified_namespace,
                    "security_event": "namespace_mismatch",
                }
            )

            raise AuthorizationError(
                "Namespace verification failed (access denied)",
                details={
                    "agent_id": agent_id,
                    "claimed_namespace": claimed_namespace,
                    "verified_namespace": verified_namespace,
                }
            )

        # [3] Return verified namespace
        return verified_namespace
