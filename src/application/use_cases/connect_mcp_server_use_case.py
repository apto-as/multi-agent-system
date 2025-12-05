"""Connect MCP Server Use Case

Purpose: Create new MCP connection, establish external connection, discover tools

Flow:
1. Input validation (ConnectionConfig creation)
2. Namespace verification from DB (SECURITY CRITICAL)
3. Authorization check (namespace match)
4. Check duplicate connection
5. Begin transaction
6. Create MCPConnection aggregate
7. Persist aggregate (DISCONNECTED state)
8. Attempt external connection (MCPClientAdapter)
9. Discover tools from MCP server
10. Update aggregate (ACTIVE state with tools)
11. Persist updated aggregate
12. Commit transaction
13. Dispatch MCPConnectedEvent
14. Return MCPConnectionDTO
"""

import logging

from src.application.dtos.request_dtos import CreateConnectionRequest
from src.application.dtos.response_dtos import MCPConnectionDTO
from src.application.events.dispatcher import EventDispatcher
from src.application.exceptions import (
    AuthorizationError,
    ExternalServiceError,
    ValidationError,
)
from src.domain.aggregates.mcp_connection import MCPConnection
from src.domain.repositories.agent_repository import AgentRepository
from src.domain.repositories.mcp_connection_repository import (
    MCPConnectionRepository,
)
from src.domain.value_objects.connection_config import ConnectionConfig
from src.domain.value_objects.server_name import ServerName
from src.domain.value_objects.server_url import ServerURL
from src.infrastructure.adapters.mcp_client_adapter import (
    MCPClientAdapter,
    MCPConnectionError,
)
from src.infrastructure.unit_of_work import UnitOfWork

logger = logging.getLogger(__name__)


class ConnectMCPServerUseCase:
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

    async def execute(self, request: CreateConnectionRequest) -> MCPConnectionDTO:
        # [1] Input validation
        try:
            # Validate inputs (ConnectionConfig will validate server_name internally)
            server_name = ServerName(request.server_name)  # Validate
            server_url = ServerURL(str(request.url))  # Validate

            config = ConnectionConfig(
                server_name=str(server_name),  # Pass string, not ServerName object
                url=str(server_url),  # Pass string, not ServerURL object
                timeout=request.timeout,
                retry_attempts=request.retry_attempts,
            )
        except ValueError as e:
            raise ValidationError(f"Invalid input: {e}") from e

        # [2] Namespace verification from DB (SECURITY CRITICAL)
        agent = await self._agent_repository.get_by_id(request.agent_id)
        if not agent:
            raise AuthorizationError("Agent not found")

        verified_namespace = agent.namespace  # ✅ From DB, not from request

        # [3] Authorization check
        if request.namespace != verified_namespace:
            raise AuthorizationError("Namespace mismatch")

        # [4] Check for duplicate connection
        existing = await self._repository.get_by_server_name_and_namespace(
            request.server_name, verified_namespace
        )
        if existing:
            raise ValidationError(f"Connection to {request.server_name} already exists")

        async with self._uow:
            # [5-6] Create aggregate
            from uuid import uuid4

            connection = MCPConnection(
                id=uuid4(),
                server_name=config.server_name,
                config=config,
                namespace=verified_namespace,  # ✅ Verified
                agent_id=str(request.agent_id),
            )

            # [7] Persist aggregate
            await self._repository.save(connection)

            # [8-9] Attempt external connection
            try:
                await self._adapter.connect(
                    connection_id=connection.id,
                    url=str(connection.config.url),  # URL is in config
                    config=config,
                )

                tools = await self._adapter.discover_tools(connection.id)

                # [10] Update aggregate state
                connection.mark_as_active(tools)

            except MCPConnectionError as e:
                # Mark as failed but still persist
                connection.mark_as_error(str(e))  # Use correct method name
                await self._repository.save(connection)
                await self._uow.commit()

                raise ExternalServiceError(f"Failed to connect to MCP server: {e}") from e

            # [11] Persist updated state
            await self._repository.save(connection)

            # [12] Commit transaction
            await self._uow.commit()

        # [13] Dispatch domain events (AFTER commit)
        await self._event_dispatcher.dispatch_all(connection.domain_events)

        # [14] Return DTO
        return MCPConnectionDTO.from_aggregate(connection)
