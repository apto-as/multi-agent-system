"""MCP Connections FastAPI Router

This module provides HTTP endpoints for MCP connection management.
All endpoints are thin controllers that delegate to use cases.

Endpoints:
- POST   /api/v1/mcp/connections - Create new MCP connection
- DELETE /api/v1/mcp/connections/{connection_id} - Disconnect
- GET    /api/v1/mcp/connections/{connection_id}/tools - Discover tools
- POST   /api/v1/mcp/connections/{connection_id}/tools/{tool_name}/execute - Execute tool

Design Principles:
1. Thin controllers - no business logic in routers
2. All logic delegated to use cases
3. P0-1 security - namespace verified from DB
4. Error sanitization - no sensitive details exposed
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Response, status
from fastapi.responses import JSONResponse

from src.api.dependencies import (
    User,
    check_rate_limit_mcp_create,
    check_rate_limit_mcp_disconnect,
    check_rate_limit_mcp_discover,
    check_rate_limit_mcp_execute,
    get_connect_use_case,
    get_current_user,
    get_disconnect_use_case,
    get_discover_tools_use_case,
    get_execute_tool_use_case,
)
from src.application.dtos.request_dtos import (
    CreateConnectionRequest,
    DisconnectRequest,
    DiscoverToolsRequest,
    ExecuteToolRequest,
)
from src.application.use_cases.connect_mcp_server_use_case import (
    ConnectMCPServerUseCase,
)
from src.application.use_cases.disconnect_mcp_server_use_case import (
    DisconnectMCPServerUseCase,
)
from src.application.use_cases.discover_tools_use_case import DiscoverToolsUseCase
from src.application.use_cases.execute_tool_use_case import ExecuteToolUseCase

router = APIRouter(prefix="/api/v1/mcp", tags=["MCP Connections"])


# ============================================================================
# POST /api/v1/mcp/connections - Create MCP Connection
# ============================================================================


@router.post("/connections", status_code=status.HTTP_201_CREATED)
async def create_connection(
    request: CreateConnectionRequest,
    current_user: Annotated[User, Depends(get_current_user)],  # noqa: ARG001
    use_case: Annotated[ConnectMCPServerUseCase, Depends(get_connect_use_case)],
    _rate_limit: Annotated[None, Depends(check_rate_limit_mcp_create)],
) -> Response:
    """Create new MCP connection

    Security:
    - Requires JWT authentication
    - Namespace verified from database (P0-1 compliant)
    - Request namespace must match user's verified namespace

    Args:
        request: Connection creation request with server details
        current_user: Authenticated user (namespace verified from DB)
        use_case: Injected use case for creating connection

    Returns:
        Response with 201 status, Location header, and connection details

    Raises:
        HTTPException 400: Invalid request parameters
        HTTPException 403: Namespace mismatch (authorization failure)
        HTTPException 502: MCP server connection failed
    """
    # Execute use case (all validation happens in use case)
    connection_dto = await use_case.execute(request)

    # Return 201 Created with Location header and JSON body
    return JSONResponse(
        content=connection_dto.to_dict(),
        status_code=status.HTTP_201_CREATED,
        headers={"Location": f"/api/v1/mcp/connections/{connection_dto.id}"},
    )


# ============================================================================
# DELETE /api/v1/mcp/connections/{connection_id} - Disconnect
# ============================================================================


@router.delete("/connections/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def disconnect(
    connection_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    use_case: Annotated[
        DisconnectMCPServerUseCase, Depends(get_disconnect_use_case)
    ],
    _rate_limit: Annotated[None, Depends(check_rate_limit_mcp_disconnect)],
) -> Response:
    """Disconnect MCP server

    Security:
    - Requires JWT authentication
    - Connection ownership verified by use case
    - Namespace isolation enforced (P0-1 compliant)

    Args:
        connection_id: UUID of connection to disconnect
        current_user: Authenticated user (namespace verified from DB)
        use_case: Injected use case for disconnecting

    Returns:
        Response with 204 No Content (empty body)

    Raises:
        HTTPException 403: Connection belongs to different agent/namespace
        HTTPException 404: Connection not found
    """
    # Build request DTO with verified namespace (P0-1)
    request = DisconnectRequest(
        connection_id=connection_id,
        agent_id=current_user.agent_id,  # Already a string
        namespace=current_user.namespace,  # ✅ Verified from DB
    )

    # Execute use case
    await use_case.execute(request)

    # Return 204 No Content
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ============================================================================
# GET /api/v1/mcp/connections/{connection_id}/tools - Discover Tools
# ============================================================================


@router.get("/connections/{connection_id}/tools", status_code=status.HTTP_200_OK)
async def discover_tools(
    connection_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    use_case: Annotated[DiscoverToolsUseCase, Depends(get_discover_tools_use_case)],
    _rate_limit: Annotated[None, Depends(check_rate_limit_mcp_discover)],
) -> dict:
    """Discover available tools on MCP server

    Security:
    - Requires JWT authentication
    - Connection ownership verified by use case
    - Namespace isolation enforced (P0-1 compliant)

    Args:
        connection_id: UUID of connection to query
        current_user: Authenticated user (namespace verified from DB)
        use_case: Injected use case for tool discovery

    Returns:
        Dict with connection details and available tools

    Raises:
        HTTPException 403: Connection belongs to different agent/namespace
        HTTPException 404: Connection not found
        HTTPException 502: MCP server connection failed
    """
    # Build request DTO with verified namespace (P0-1)
    request = DiscoverToolsRequest(
        connection_id=connection_id,
        agent_id=current_user.agent_id,  # Already a string
        namespace=current_user.namespace,  # ✅ Verified from DB
    )

    # Execute use case
    connection_dto = await use_case.execute(request)

    # Return connection with discovered tools
    return connection_dto.to_dict()


# ============================================================================
# POST /api/v1/mcp/connections/{connection_id}/tools/{tool_name}/execute
# ============================================================================


@router.post(
    "/connections/{connection_id}/tools/{tool_name}/execute",
    status_code=status.HTTP_200_OK,
)
async def execute_tool(
    connection_id: UUID,
    tool_name: str,
    request_body: dict,  # Tool arguments are dynamic
    current_user: Annotated[User, Depends(get_current_user)],
    use_case: Annotated[ExecuteToolUseCase, Depends(get_execute_tool_use_case)],
    _rate_limit: Annotated[None, Depends(check_rate_limit_mcp_execute)],
) -> dict:
    """Execute MCP tool with provided arguments

    Security:
    - Requires JWT authentication
    - Connection ownership verified by use case
    - Namespace isolation enforced (P0-1 compliant)
    - Tool execution sandboxed by MCP server

    Args:
        connection_id: UUID of connection containing the tool
        tool_name: Name of tool to execute
        request_body: Dict with "arguments" key containing tool-specific parameters
        current_user: Authenticated user (namespace verified from DB)
        use_case: Injected use case for tool execution

    Returns:
        Dict with execution result from MCP server

    Raises:
        HTTPException 400: Tool not found in connection
        HTTPException 403: Connection belongs to different agent/namespace
        HTTPException 404: Connection not found
        HTTPException 502: MCP server connection failed
    """
    # Build request DTO with verified namespace (P0-1)
    request = ExecuteToolRequest(
        connection_id=connection_id,
        tool_name=tool_name,
        arguments=request_body.get("arguments", {}),
        agent_id=current_user.agent_id,  # Already a string
        namespace=current_user.namespace,  # ✅ Verified from DB
    )

    # Execute use case
    result_dto = await use_case.execute(request)

    # Return execution result
    return result_dto.to_dict()
