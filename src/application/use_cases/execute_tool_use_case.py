"""Execute Tool Use Case

Purpose: Execute tool via active MCP connection

Flow:
1. Namespace verification from DB
2. Authorization check
3. Retrieve connection from repository
4. Verify connection is ACTIVE
5. Verify tool exists in connection
6. Execute tool via adapter
7. Return execution result

Note: Tool execution is READ-ONLY (no state change in aggregate)
"""

import logging

from src.application.dtos.request_dtos import ExecuteToolRequest
from src.application.dtos.response_dtos import ToolExecutionResultDTO
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
from src.infrastructure.adapters.mcp_client_adapter import MCPClientAdapter
from src.infrastructure.exceptions import MCPToolExecutionError

logger = logging.getLogger(__name__)


class ExecuteToolUseCase:
    def __init__(
        self,
        repository: MCPConnectionRepository,
        adapter: MCPClientAdapter,
        agent_repository: AgentRepository,
    ):
        self._repository = repository
        self._adapter = adapter
        self._agent_repository = agent_repository

    async def execute(
        self, request: ExecuteToolRequest
    ) -> ToolExecutionResultDTO:
        # [1-2] Namespace verification
        verified_namespace = await self._verify_namespace(
            request.agent_id, request.namespace
        )

        # [3] Retrieve connection
        connection = await self._repository.get_by_id(
            request.connection_id, verified_namespace
        )
        if not connection:
            raise AggregateNotFoundError(
                "MCPConnection", str(request.connection_id)
            )

        # [4] Verify active
        if connection.status != ConnectionStatus.ACTIVE:
            raise ValidationError(
                f"Connection is not active (status: {connection.status.value})"
            )

        # [5] Verify tool exists
        tool = connection.get_tool_by_name(request.tool_name)
        if not tool:
            raise ValidationError(
                f"Tool '{request.tool_name}' not found in connection"
            )

        # [6] Execute tool
        try:
            result = await self._adapter.execute_tool(
                connection_id=connection.id,
                tool_name=request.tool_name,
                arguments=request.arguments,
            )
        except MCPToolExecutionError as e:
            raise ExternalServiceError(f"Tool execution failed: {e}") from e

        # [7] Return result
        return ToolExecutionResultDTO(
            connection_id=connection.id,
            tool_name=request.tool_name,
            result=result,
        )

    async def _verify_namespace(
        self, agent_id, claimed_namespace: str
    ) -> str:
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

            raise AuthorizationError(
                "Namespace verification failed (access denied)"
            )

        # [3] Return verified namespace
        return verified_namespace
