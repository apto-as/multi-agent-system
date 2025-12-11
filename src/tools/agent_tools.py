"""MCP Tools for Agent Management (TMWS v2.4.7).

Provides MCP-first interface for agent lifecycle management.
Implements Hestia's security requirements (REQ-1, REQ-2, REQ-4, REQ-5).

Security Architecture:
- REQ-1: Authentication required (via mcp_auth)
- REQ-2: Namespace isolation (P0-1 pattern)
- REQ-4: Rate limiting (tool-specific)
- REQ-5: Role-based access control (admin operations)

Tool Categories:
1. Discovery: list_agents, get_agent, search_agents
2. Lifecycle: register_agent, update_agent, deactivate_agent
3. Status: get_agent_stats, get_agent_capabilities
4. Team Management: add_to_team, remove_from_team

MCP-First Architecture:
- These tools are the PRIMARY interface for agent-to-agent discovery
- 9 Trinitas agents use these tools for coordination
- REST API exists as secondary for admin/web UI
"""

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastmcp import FastMCP

from ..security.mcp_auth import (
    MCPAuthenticationError,
    MCPAuthorizationError,
    MCPOperation,
    authenticate_mcp_request,
    authorize_mcp_request,
)
from ..security.mcp_rate_limiter import require_mcp_rate_limit
from ..services.agent_service import AgentService

logger = logging.getLogger(__name__)


class AgentTools:
    """MCP tools for agent management.

    Security:
    - All tools require authentication (REQ-1)
    - All tools enforce namespace isolation (REQ-2)
    - All tools have rate limits (REQ-4)
    - Admin operations require elevated role (REQ-5)
    """

    def __init__(self):
        """Initialize agent tools."""
        pass

    async def register_tools(self, mcp: FastMCP, session_factory) -> None:
        """Register all MCP tools using FastMCP decorator pattern.

        Args:
            mcp: FastMCP instance
            session_factory: Async session factory for database access
        """

        # ============================================================
        # AGENT DISCOVERY TOOLS
        # ============================================================

        @mcp.tool()
        @require_mcp_rate_limit("agent_list")
        async def list_agents(
            agent_id: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
            namespace: str | None = None,
            status: str | None = None,
            limit: int = 50,
            offset: int = 0,
        ) -> dict[str, Any]:
            """List agents accessible to the requesting agent.

            Security:
            - Requires authentication (REQ-1)
            - Returns agents in same namespace or public agents (REQ-2)
            - Rate limited: 60 calls/min (REQ-4)

            Args:
                agent_id: Requesting agent identifier
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication
                namespace: Filter by namespace (defaults to agent's namespace)
                status: Filter by status (active, inactive, suspended)
                limit: Maximum results (1-100, default 50)
                offset: Pagination offset

            Returns:
                Dict with agents list:
                - success: True if operation completed
                - agents: List of agent summaries
                - total: Total matching agents
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="list_agents",
                    )

                    # Step 2: Authorization (REQ-2)
                    target_namespace = namespace or context.namespace
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=target_namespace,
                        operation=MCPOperation.AGENT_READ,
                    )

                    # Step 3: Validate parameters
                    limit = max(1, min(100, limit))
                    offset = max(0, offset)

                    # Step 4: Execute service method
                    agent_service = AgentService(session)
                    agents = await agent_service.list_agents(
                        namespace=target_namespace,
                        status=status,
                        limit=limit,
                        offset=offset,
                    )

                    # Convert to summary format
                    agent_summaries = [
                        {
                            "id": str(a.id),
                            "display_name": a.display_name,
                            "namespace": a.namespace,
                            "status": a.status.value if hasattr(a.status, "value") else a.status,
                            "trust_score": a.trust_score,
                            "capabilities": a.capabilities or [],
                        }
                        for a in agents
                    ]

                    logger.info(
                        f"list_agents: agent={context.agent_id}, "
                        f"namespace={target_namespace}, count={len(agent_summaries)}"
                    )

                    return {
                        "success": True,
                        "agents": agent_summaries,
                        "total": len(agent_summaries),
                        "limit": limit,
                        "offset": offset,
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"list_agents auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"list_agents authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"list_agents failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        @mcp.tool()
        @require_mcp_rate_limit("agent_get")
        async def get_agent(
            agent_id: str,
            target_agent_id: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Get detailed information about a specific agent.

            Security:
            - Requires authentication (REQ-1)
            - Must have access to target agent's namespace (REQ-2)
            - Rate limited: 120 calls/min (REQ-4)

            Args:
                agent_id: Requesting agent identifier
                target_agent_id: Agent UUID to retrieve
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication

            Returns:
                Dict with agent details:
                - success: True if operation completed
                - agent: Full agent data
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="get_agent",
                    )

                    # Step 2: Validate UUID
                    try:
                        target_uuid = UUID(target_agent_id)
                    except ValueError:
                        return {
                            "success": False,
                            "error": "Invalid target_agent_id format",
                            "error_type": "validation",
                        }

                    # Step 3: Execute service method
                    agent_service = AgentService(session)
                    agent = await agent_service.get_agent_by_id(target_uuid)

                    if not agent:
                        return {
                            "success": False,
                            "error": "Agent not found",
                            "error_type": "not_found",
                        }

                    # Step 4: Authorization check (REQ-2)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=agent.namespace,
                        operation=MCPOperation.AGENT_READ,
                    )

                    logger.info(f"get_agent: agent={context.agent_id}, target={target_agent_id}")

                    return {
                        "success": True,
                        "agent": {
                            "id": str(agent.id),
                            "display_name": agent.display_name,
                            "namespace": agent.namespace,
                            "status": agent.status.value
                            if hasattr(agent.status, "value")
                            else agent.status,
                            "trust_score": agent.trust_score,
                            "capabilities": agent.capabilities or [],
                            "metadata": agent.metadata or {},
                            "created_at": agent.created_at.isoformat()
                            if agent.created_at
                            else None,
                            "last_active": agent.last_active.isoformat()
                            if agent.last_active
                            else None,
                        },
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"get_agent auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"get_agent authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"get_agent failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        @mcp.tool()
        @require_mcp_rate_limit("agent_search")
        async def search_agents(
            agent_id: str,
            query: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
            capabilities: list[str] | None = None,
            min_trust_score: float | None = None,
            limit: int = 20,
        ) -> dict[str, Any]:
            """Search for agents by name, capabilities, or trust score.

            Security:
            - Requires authentication (REQ-1)
            - Returns only accessible agents (REQ-2)
            - Rate limited: 30 calls/min (REQ-4)

            Args:
                agent_id: Requesting agent identifier
                query: Search query (matches display_name)
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication
                capabilities: Filter by required capabilities
                min_trust_score: Minimum trust score (0.0-1.0)
                limit: Maximum results (1-50, default 20)

            Returns:
                Dict with search results:
                - success: True if operation completed
                - agents: List of matching agents
                - total: Total matches
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="search_agents",
                    )

                    # Step 2: Authorization (REQ-2)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=context.namespace,
                        operation=MCPOperation.AGENT_READ,
                    )

                    # Step 3: Validate parameters
                    limit = max(1, min(50, limit))
                    if min_trust_score is not None:
                        min_trust_score = max(0.0, min(1.0, min_trust_score))

                    # Step 4: Execute service method
                    agent_service = AgentService(session)
                    agents = await agent_service.search_agents(
                        query=query,
                        namespace=context.namespace,
                        capabilities=capabilities,
                        min_trust_score=min_trust_score,
                        limit=limit,
                    )

                    agent_summaries = [
                        {
                            "id": str(a.id),
                            "display_name": a.display_name,
                            "namespace": a.namespace,
                            "trust_score": a.trust_score,
                            "capabilities": a.capabilities or [],
                        }
                        for a in agents
                    ]

                    logger.info(
                        f"search_agents: agent={context.agent_id}, "
                        f"query={query}, results={len(agent_summaries)}"
                    )

                    return {
                        "success": True,
                        "agents": agent_summaries,
                        "total": len(agent_summaries),
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"search_agents auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"search_agents authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"search_agents failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        # ============================================================
        # AGENT LIFECYCLE TOOLS
        # ============================================================

        @mcp.tool()
        @require_mcp_rate_limit("agent_register")
        async def register_agent(
            agent_id: str,
            display_name: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
            capabilities: list[str] | None = None,
            metadata: dict | None = None,
        ) -> dict[str, Any]:
            """Register a new agent in the system.

            Security:
            - Requires authentication (REQ-1)
            - Created in authenticated agent's namespace (REQ-2)
            - Rate limited: 5 calls/hour (REQ-4)

            Args:
                agent_id: Requesting agent identifier (becomes creator)
                display_name: Human-readable agent name
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication
                capabilities: List of agent capabilities
                metadata: Additional agent metadata

            Returns:
                Dict with created agent:
                - success: True if operation completed
                - agent: Created agent data
                - agent_id: UUID of created agent
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="register_agent",
                    )

                    # Step 2: Authorization (REQ-2)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=context.namespace,
                        operation=MCPOperation.AGENT_WRITE,
                    )

                    # Step 3: Validate input
                    if not display_name or not display_name.strip():
                        return {
                            "success": False,
                            "error": "display_name is required",
                            "error_type": "validation",
                        }

                    # Step 4: Execute service method
                    agent_service = AgentService(session)
                    agent = await agent_service.create_agent(
                        display_name=display_name.strip(),
                        namespace=context.namespace,
                        capabilities=capabilities or [],
                        metadata=metadata or {},
                    )

                    logger.info(
                        f"register_agent: by={context.agent_id}, "
                        f"name={display_name}, new_id={agent.id}"
                    )

                    return {
                        "success": True,
                        "agent": {
                            "id": str(agent.id),
                            "display_name": agent.display_name,
                            "namespace": agent.namespace,
                            "status": agent.status.value
                            if hasattr(agent.status, "value")
                            else agent.status,
                            "capabilities": agent.capabilities or [],
                        },
                        "agent_id": str(agent.id),
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"register_agent auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"register_agent authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"register_agent failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        @mcp.tool()
        @require_mcp_rate_limit("agent_update")
        async def update_agent(
            agent_id: str,
            target_agent_id: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
            display_name: str | None = None,
            capabilities: list[str] | None = None,
            metadata: dict | None = None,
        ) -> dict[str, Any]:
            """Update an existing agent's information.

            Security:
            - Requires authentication (REQ-1)
            - Must be same agent or namespace admin (REQ-2, REQ-5)
            - Rate limited: 30 calls/hour (REQ-4)

            Args:
                agent_id: Requesting agent identifier
                target_agent_id: Agent UUID to update
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication
                display_name: New display name
                capabilities: New capabilities list
                metadata: New metadata (merged with existing)

            Returns:
                Dict with updated agent:
                - success: True if operation completed
                - agent: Updated agent data
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="update_agent",
                    )

                    # Step 2: Validate UUID
                    try:
                        target_uuid = UUID(target_agent_id)
                    except ValueError:
                        return {
                            "success": False,
                            "error": "Invalid target_agent_id format",
                            "error_type": "validation",
                        }

                    # Step 3: Get target agent for namespace check
                    agent_service = AgentService(session)
                    target_agent = await agent_service.get_agent_by_id(target_uuid)

                    if not target_agent:
                        return {
                            "success": False,
                            "error": "Agent not found",
                            "error_type": "not_found",
                        }

                    # Step 4: Authorization (REQ-2)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=target_agent.namespace,
                        operation=MCPOperation.AGENT_WRITE,
                    )

                    # Step 5: Build update data
                    update_data = {}
                    if display_name is not None:
                        update_data["display_name"] = display_name.strip()
                    if capabilities is not None:
                        update_data["capabilities"] = capabilities
                    if metadata is not None:
                        update_data["metadata"] = metadata

                    if not update_data:
                        return {
                            "success": False,
                            "error": "No update fields provided",
                            "error_type": "validation",
                        }

                    # Step 6: Execute service method
                    updated_agent = await agent_service.update_agent(
                        agent_id=target_uuid,
                        **update_data,
                    )

                    logger.info(
                        f"update_agent: by={context.agent_id}, "
                        f"target={target_agent_id}, fields={list(update_data.keys())}"
                    )

                    return {
                        "success": True,
                        "agent": {
                            "id": str(updated_agent.id),
                            "display_name": updated_agent.display_name,
                            "namespace": updated_agent.namespace,
                            "capabilities": updated_agent.capabilities or [],
                            "metadata": updated_agent.metadata or {},
                        },
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"update_agent auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"update_agent authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"update_agent failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        @mcp.tool()
        @require_mcp_rate_limit("agent_deactivate")
        async def deactivate_agent(
            agent_id: str,
            target_agent_id: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Deactivate an agent (set status to inactive).

            Security:
            - Requires authentication (REQ-1)
            - Must be namespace admin (REQ-5)
            - Rate limited: 5 calls/hour (REQ-4)

            Args:
                agent_id: Requesting agent identifier (must be admin)
                target_agent_id: Agent UUID to deactivate
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication

            Returns:
                Dict with deactivation result:
                - success: True if operation completed
                - deactivated_at: Timestamp of deactivation
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="deactivate_agent",
                    )

                    # Step 2: Validate UUID
                    try:
                        target_uuid = UUID(target_agent_id)
                    except ValueError:
                        return {
                            "success": False,
                            "error": "Invalid target_agent_id format",
                            "error_type": "validation",
                        }

                    # Step 3: Get target agent for namespace check
                    agent_service = AgentService(session)
                    target_agent = await agent_service.get_agent_by_id(target_uuid)

                    if not target_agent:
                        return {
                            "success": False,
                            "error": "Agent not found",
                            "error_type": "not_found",
                        }

                    # Step 4: Authorization (REQ-5: Admin required)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=target_agent.namespace,
                        operation=MCPOperation.AGENT_ADMIN,
                    )

                    # Step 5: Execute service method
                    await agent_service.deactivate_agent(target_uuid)

                    logger.info(
                        f"deactivate_agent: by={context.agent_id}, target={target_agent_id}"
                    )

                    return {
                        "success": True,
                        "deactivated_at": datetime.now(timezone.utc).isoformat(),
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"deactivate_agent auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"deactivate_agent authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"deactivate_agent failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        @mcp.tool()
        @require_mcp_rate_limit("agent_activate")
        async def activate_agent(
            agent_id: str,
            target_agent_id: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Activate an inactive agent (set status to active).

            Security:
            - Requires authentication (REQ-1)
            - Must be namespace admin (REQ-5)
            - Rate limited: 10 calls/hour (REQ-4)

            Args:
                agent_id: Requesting agent identifier (must be admin)
                target_agent_id: Agent UUID to activate
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication

            Returns:
                Dict with activation result:
                - success: True if operation completed
                - activated_at: Timestamp of activation
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="activate_agent",
                    )

                    # Step 2: Validate UUID
                    try:
                        target_uuid = UUID(target_agent_id)
                    except ValueError:
                        return {
                            "success": False,
                            "error": "Invalid target_agent_id format",
                            "error_type": "validation",
                        }

                    # Step 3: Get target agent for namespace check
                    agent_service = AgentService(session)
                    target_agent = await agent_service.get_agent_by_id(target_uuid)

                    if not target_agent:
                        return {
                            "success": False,
                            "error": "Agent not found",
                            "error_type": "not_found",
                        }

                    # Step 4: Authorization (REQ-5: Admin required)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=target_agent.namespace,
                        operation=MCPOperation.AGENT_ADMIN,
                    )

                    # Step 5: Execute service method
                    await agent_service.activate_agent(target_uuid)

                    logger.info(f"activate_agent: by={context.agent_id}, target={target_agent_id}")

                    return {
                        "success": True,
                        "activated_at": datetime.now(timezone.utc).isoformat(),
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"activate_agent auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"activate_agent authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"activate_agent failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        # ============================================================
        # AGENT STATUS TOOLS
        # ============================================================

        @mcp.tool()
        @require_mcp_rate_limit("agent_stats")
        async def get_agent_stats(
            agent_id: str,
            target_agent_id: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Get performance statistics for an agent.

            Security:
            - Requires authentication (REQ-1)
            - Must have access to target agent (REQ-2)
            - Rate limited: 60 calls/min (REQ-4)

            Args:
                agent_id: Requesting agent identifier
                target_agent_id: Agent UUID to get stats for
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication

            Returns:
                Dict with agent statistics:
                - success: True if operation completed
                - stats: Performance metrics and statistics
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="get_agent_stats",
                    )

                    # Step 2: Validate UUID
                    try:
                        target_uuid = UUID(target_agent_id)
                    except ValueError:
                        return {
                            "success": False,
                            "error": "Invalid target_agent_id format",
                            "error_type": "validation",
                        }

                    # Step 3: Get target agent for namespace check
                    agent_service = AgentService(session)
                    target_agent = await agent_service.get_agent_by_id(target_uuid)

                    if not target_agent:
                        return {
                            "success": False,
                            "error": "Agent not found",
                            "error_type": "not_found",
                        }

                    # Step 4: Authorization (REQ-2)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=target_agent.namespace,
                        operation=MCPOperation.AGENT_READ,
                    )

                    # Step 5: Execute service method
                    stats = await agent_service.get_agent_stats(target_uuid)

                    logger.info(
                        f"get_agent_stats: agent={context.agent_id}, target={target_agent_id}"
                    )

                    return {
                        "success": True,
                        "stats": stats,
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"get_agent_stats auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"get_agent_stats authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"get_agent_stats failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        @mcp.tool()
        @require_mcp_rate_limit("agent_recommend")
        async def get_recommended_agents(
            agent_id: str,
            task_type: str | None = None,
            api_key: str | None = None,
            jwt_token: str | None = None,
            capabilities: list[str] | None = None,
            namespace: str | None = None,
            limit: int = 10,
            min_trust_score: float = 0.0,
        ) -> dict[str, Any]:
            """Get recommended agents for a specific task type.

            Security:
            - Requires authentication (REQ-1)
            - Returns only accessible agents (REQ-2)
            - Rate limited: 30 calls/min (REQ-4)

            Args:
                agent_id: Requesting agent identifier
                task_type: Type of task (reserved for future use)
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication
                capabilities: Required agent capabilities
                namespace: Target namespace (defaults to agent's namespace)
                limit: Maximum recommendations (1-10, default 10)
                min_trust_score: Minimum trust score (0.0-1.0, default 0.0)

            Returns:
                Dict with recommended agents:
                - success: True if operation completed
                - recommendations: List of recommended agents with scores
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="get_recommended_agents",
                    )

                    # Step 2: Authorization (REQ-2)
                    effective_namespace = namespace or context.namespace
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=effective_namespace,
                        operation=MCPOperation.AGENT_READ,
                    )

                    # Step 3: Validate parameters
                    limit = max(1, min(10, limit))
                    min_trust_score = max(0.0, min(1.0, min_trust_score))

                    # Step 4: Execute service method
                    agent_service = AgentService(session)
                    recommendations = await agent_service.get_recommended_agents(
                        _task_type=task_type,
                        capabilities=capabilities,
                        namespace=effective_namespace,
                        min_trust_score=min_trust_score,
                        limit=limit,
                    )

                    logger.info(
                        f"get_recommended_agents: agent={context.agent_id}, "
                        f"task_type={task_type}, results={len(recommendations)}"
                    )

                    return {
                        "success": True,
                        "recommendations": recommendations,
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"get_recommended_agents auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"get_recommended_agents authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"get_recommended_agents failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        logger.info("Agent MCP tools registered (9 tools)")
