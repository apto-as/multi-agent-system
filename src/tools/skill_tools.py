"""MCP Tools for Skills Management (TMWS v2.4.7).

Provides MCP-first interface for skill lifecycle management.
Implements Hestia's security requirements (REQ-1, REQ-2, REQ-4, REQ-5).

Security Architecture:
- REQ-1: Authentication required (via mcp_auth)
- REQ-2: Namespace isolation (P0-1 pattern)
- REQ-4: Rate limiting (tool-specific)
- REQ-5: Role-based access control

Tool Categories:
1. Discovery: list_skills, get_skill
2. Lifecycle: create_skill, update_skill, delete_skill
3. Sharing: share_skill
4. Activation: activate_skill, deactivate_skill

MCP-First Architecture:
- These tools are the PRIMARY interface for agents
- REST API exists as secondary for web UI/external clients
- 9 Trinitas agents access skills via these MCP tools
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
from ..services.skill_service import SkillService

logger = logging.getLogger(__name__)


class SkillTools:
    """MCP tools for skill management.

    Security:
    - All tools require authentication (REQ-1)
    - All tools enforce namespace isolation (REQ-2)
    - All tools have rate limits (REQ-4)
    - Delete/Share/Activate require ownership (REQ-5)
    """

    def __init__(self):
        """Initialize skill tools."""
        pass

    async def register_tools(self, mcp: FastMCP, session_factory) -> None:
        """Register all MCP tools using FastMCP decorator pattern.

        Args:
            mcp: FastMCP instance
            session_factory: Async session factory for database access
        """

        # ============================================================
        # SKILL DISCOVERY TOOLS
        # ============================================================

        @mcp.tool()
        @require_mcp_rate_limit("skill_list")
        async def list_skills(
            agent_id: str,
            namespace: str | None = None,
            api_key: str | None = None,
            jwt_token: str | None = None,
            detail_level: int = 1,
            include_shared: bool = True,
            tags: list[str] | None = None,
            limit: int = 50,
            offset: int = 0,
        ) -> dict[str, Any]:
            """List skills accessible to the agent.

            Security:
            - Requires authentication (REQ-1)
            - Returns only accessible skills (REQ-2)
            - Rate limited: 60 calls/min (REQ-4)

            Args:
                agent_id: Agent identifier
                namespace: Filter by namespace (defaults to agent's namespace)
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication
                detail_level: Progressive disclosure level (1=metadata, 2=core, 3=full)
                include_shared: Include skills shared with this agent
                tags: Filter by tags
                limit: Maximum results (1-100, default 50)
                offset: Pagination offset

            Returns:
                Dict with skills list:
                - success: True if operation completed
                - skills: List of skill DTOs
                - total: Total matching skills
                - limit: Applied limit
                - offset: Applied offset
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="list_skills",
                    )

                    # Step 2: Authorization (REQ-2)
                    target_namespace = namespace or context.namespace
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=target_namespace,
                        operation=MCPOperation.SKILL_READ,
                    )

                    # Step 3: Validate parameters
                    if detail_level not in (1, 2, 3):
                        detail_level = 1
                    limit = max(1, min(100, limit))
                    offset = max(0, offset)

                    # Step 4: Execute service method
                    skill_service = SkillService(session)
                    result = await skill_service.list_skills(
                        agent_id=context.agent_id,
                        namespace=target_namespace,
                        detail_level=detail_level,
                        include_shared=include_shared,
                        tags=tags,
                        limit=limit,
                        offset=offset,
                    )

                    logger.info(
                        f"list_skills: agent={context.agent_id}, "
                        f"namespace={target_namespace}, count={len(result.get('skills', []))}"
                    )

                    return {
                        "success": True,
                        "skills": result.get("skills", []),
                        "total": result.get("total", 0),
                        "limit": limit,
                        "offset": offset,
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"list_skills auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"list_skills authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"list_skills failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        @mcp.tool()
        @require_mcp_rate_limit("skill_get")
        async def get_skill(
            agent_id: str,
            skill_id: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
            detail_level: int = 2,
        ) -> dict[str, Any]:
            """Get a specific skill by ID.

            Security:
            - Requires authentication (REQ-1)
            - Must have access to skill (REQ-2)
            - Rate limited: 120 calls/min (REQ-4)

            Args:
                agent_id: Agent identifier
                skill_id: Skill UUID
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication
                detail_level: Progressive disclosure level (1=metadata, 2=core, 3=full)

            Returns:
                Dict with skill data:
                - success: True if operation completed
                - skill: Skill DTO with requested detail level
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="get_skill",
                    )

                    # Step 2: Validate UUID
                    try:
                        skill_uuid = UUID(skill_id)
                    except ValueError:
                        return {"success": False, "error": "Invalid skill_id format", "error_type": "validation"}

                    # Step 3: Execute service method (authorization checked inside)
                    skill_service = SkillService(session)
                    result = await skill_service.get_skill(
                        skill_id=skill_uuid,
                        agent_id=context.agent_id,
                        namespace=context.namespace,
                        detail_level=detail_level if detail_level in (1, 2, 3) else 2,
                    )

                    if not result:
                        return {"success": False, "error": "Skill not found or access denied", "error_type": "not_found"}

                    logger.info(f"get_skill: agent={context.agent_id}, skill_id={skill_id}")

                    return {
                        "success": True,
                        "skill": result,
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"get_skill auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"get_skill authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"get_skill failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        # ============================================================
        # SKILL LIFECYCLE TOOLS
        # ============================================================

        @mcp.tool()
        @require_mcp_rate_limit("skill_create")
        async def create_skill(
            agent_id: str,
            name: str,
            content: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
            display_name: str | None = None,
            description: str | None = None,
            persona: str | None = None,
            tags: list[str] | None = None,
        ) -> dict[str, Any]:
            """Create a new skill.

            Security:
            - Requires authentication (REQ-1)
            - Created in agent's namespace (REQ-2)
            - Rate limited: 10 calls/hour (REQ-4)

            Args:
                agent_id: Agent identifier (becomes skill owner)
                name: Unique skill name (within namespace)
                content: Full skill content (markdown)
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication
                display_name: Optional display name
                description: Optional description
                persona: Optional persona identifier
                tags: Optional tags for categorization

            Returns:
                Dict with created skill:
                - success: True if operation completed
                - skill: Created skill DTO
                - skill_id: UUID of created skill
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="create_skill",
                    )

                    # Step 2: Authorization (REQ-2)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=context.namespace,
                        operation=MCPOperation.SKILL_WRITE,
                    )

                    # Step 3: Validate input
                    if not name or not name.strip():
                        return {"success": False, "error": "Skill name is required", "error_type": "validation"}
                    if not content or not content.strip():
                        return {"success": False, "error": "Skill content is required", "error_type": "validation"}

                    # Step 4: Execute service method
                    skill_service = SkillService(session)
                    result = await skill_service.create_skill(
                        name=name.strip(),
                        content=content,
                        created_by=context.agent_id,
                        namespace=context.namespace,
                        display_name=display_name,
                        description=description,
                        persona=persona,
                        tags=tags or [],
                    )

                    logger.info(
                        f"create_skill: agent={context.agent_id}, "
                        f"name={name}, skill_id={result.get('id')}"
                    )

                    return {
                        "success": True,
                        "skill": result,
                        "skill_id": result.get("id"),
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"create_skill auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"create_skill authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"create_skill failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        @mcp.tool()
        @require_mcp_rate_limit("skill_update")
        async def update_skill(
            agent_id: str,
            skill_id: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
            content: str | None = None,
            display_name: str | None = None,
            description: str | None = None,
            persona: str | None = None,
            tags: list[str] | None = None,
        ) -> dict[str, Any]:
            """Update an existing skill.

            Security:
            - Requires authentication (REQ-1)
            - Must be skill owner (REQ-2, REQ-5)
            - Rate limited: 30 calls/hour (REQ-4)

            Args:
                agent_id: Agent identifier (must be owner)
                skill_id: Skill UUID to update
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication
                content: New content (creates new version if changed)
                display_name: New display name
                description: New description
                persona: New persona
                tags: New tags

            Returns:
                Dict with updated skill:
                - success: True if operation completed
                - skill: Updated skill DTO
                - version: New version number (if content changed)
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="update_skill",
                    )

                    # Step 2: Validate UUID
                    try:
                        skill_uuid = UUID(skill_id)
                    except ValueError:
                        return {"success": False, "error": "Invalid skill_id format", "error_type": "validation"}

                    # Step 3: Authorization (REQ-2) - owner check done in service
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=context.namespace,
                        operation=MCPOperation.SKILL_WRITE,
                    )

                    # Step 4: Build update data
                    update_data = {}
                    if content is not None:
                        update_data["content"] = content
                    if display_name is not None:
                        update_data["display_name"] = display_name
                    if description is not None:
                        update_data["description"] = description
                    if persona is not None:
                        update_data["persona"] = persona
                    if tags is not None:
                        update_data["tags"] = tags

                    if not update_data:
                        return {"success": False, "error": "No update fields provided", "error_type": "validation"}

                    # Step 5: Execute service method
                    skill_service = SkillService(session)
                    result = await skill_service.update_skill(
                        skill_id=skill_uuid,
                        agent_id=context.agent_id,
                        namespace=context.namespace,
                        **update_data,
                    )

                    if not result:
                        return {"success": False, "error": "Skill not found or access denied", "error_type": "not_found"}

                    logger.info(
                        f"update_skill: agent={context.agent_id}, "
                        f"skill_id={skill_id}, fields={list(update_data.keys())}"
                    )

                    return {
                        "success": True,
                        "skill": result,
                        "version": result.get("version"),
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"update_skill auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"update_skill authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"update_skill failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        @mcp.tool()
        @require_mcp_rate_limit("skill_delete")
        async def delete_skill(
            agent_id: str,
            skill_id: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Delete a skill (soft delete).

            Security:
            - Requires authentication (REQ-1)
            - Must be skill owner (REQ-2, REQ-5)
            - Rate limited: 5 calls/hour (REQ-4)

            Args:
                agent_id: Agent identifier (must be owner)
                skill_id: Skill UUID to delete
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication

            Returns:
                Dict with deletion result:
                - success: True if operation completed
                - deleted_at: Timestamp of deletion
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="delete_skill",
                    )

                    # Step 2: Validate UUID
                    try:
                        skill_uuid = UUID(skill_id)
                    except ValueError:
                        return {"success": False, "error": "Invalid skill_id format", "error_type": "validation"}

                    # Step 3: Authorization (REQ-2)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=context.namespace,
                        operation=MCPOperation.SKILL_DELETE,
                    )

                    # Step 4: Execute service method
                    skill_service = SkillService(session)
                    result = await skill_service.delete_skill(
                        skill_id=skill_uuid,
                        agent_id=context.agent_id,
                        namespace=context.namespace,
                    )

                    if not result:
                        return {"success": False, "error": "Skill not found or access denied", "error_type": "not_found"}

                    logger.info(f"delete_skill: agent={context.agent_id}, skill_id={skill_id}")

                    return {
                        "success": True,
                        "deleted_at": datetime.now(timezone.utc).isoformat(),
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"delete_skill auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"delete_skill authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"delete_skill failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        # ============================================================
        # SKILL SHARING TOOLS
        # ============================================================

        @mcp.tool()
        @require_mcp_rate_limit("skill_share")
        async def share_skill(
            agent_id: str,
            skill_id: str,
            target_agent_ids: list[str],
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Share a skill with other agents.

            Security:
            - Requires authentication (REQ-1)
            - Must be skill owner (REQ-2, REQ-5)
            - Rate limited: 20 calls/hour (REQ-4)

            Args:
                agent_id: Agent identifier (must be owner)
                skill_id: Skill UUID to share
                target_agent_ids: List of agent IDs to share with
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication

            Returns:
                Dict with sharing result:
                - success: True if operation completed
                - shared_with: List of agents skill was shared with
                - already_shared: List of agents already having access
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="share_skill",
                    )

                    # Step 2: Validate UUID
                    try:
                        skill_uuid = UUID(skill_id)
                    except ValueError:
                        return {"success": False, "error": "Invalid skill_id format", "error_type": "validation"}

                    # Step 3: Validate target agents
                    if not target_agent_ids:
                        return {"success": False, "error": "target_agent_ids is required", "error_type": "validation"}

                    # Step 4: Authorization (REQ-2)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=context.namespace,
                        operation=MCPOperation.SKILL_SHARE,
                    )

                    # Step 5: Execute service method
                    skill_service = SkillService(session)
                    result = await skill_service.share_skill(
                        skill_id=skill_uuid,
                        agent_id=context.agent_id,
                        namespace=context.namespace,
                        target_agent_ids=target_agent_ids,
                    )

                    if not result:
                        return {"success": False, "error": "Skill not found or access denied", "error_type": "not_found"}

                    logger.info(
                        f"share_skill: agent={context.agent_id}, "
                        f"skill_id={skill_id}, targets={target_agent_ids}"
                    )

                    return {
                        "success": True,
                        "shared_with": result.get("shared_with", []),
                        "already_shared": result.get("already_shared", []),
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"share_skill auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"share_skill authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"share_skill failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        # ============================================================
        # SKILL ACTIVATION TOOLS
        # ============================================================

        @mcp.tool()
        @require_mcp_rate_limit("skill_activate")
        async def activate_skill(
            agent_id: str,
            skill_id: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Activate a skill (register as MCP tool).

            Security:
            - Requires authentication (REQ-1)
            - Must have access to skill (REQ-2)
            - Rate limited: 20 calls/hour (REQ-4)

            Args:
                agent_id: Agent identifier
                skill_id: Skill UUID to activate
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication

            Returns:
                Dict with activation result:
                - success: True if operation completed
                - tool_name: Registered MCP tool name
                - activated_at: Activation timestamp
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="activate_skill",
                    )

                    # Step 2: Validate UUID
                    try:
                        skill_uuid = UUID(skill_id)
                    except ValueError:
                        return {"success": False, "error": "Invalid skill_id format", "error_type": "validation"}

                    # Step 3: Authorization (REQ-2)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=context.namespace,
                        operation=MCPOperation.SKILL_ACTIVATE,
                    )

                    # Step 4: Execute service method
                    skill_service = SkillService(session)
                    result = await skill_service.activate_skill(
                        skill_id=skill_uuid,
                        agent_id=context.agent_id,
                        namespace=context.namespace,
                    )

                    if not result:
                        return {"success": False, "error": "Skill not found or access denied", "error_type": "not_found"}

                    logger.info(f"activate_skill: agent={context.agent_id}, skill_id={skill_id}")

                    return {
                        "success": True,
                        "tool_name": result.get("tool_name"),
                        "activated_at": datetime.now(timezone.utc).isoformat(),
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"activate_skill auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"activate_skill authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"activate_skill failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        @mcp.tool()
        @require_mcp_rate_limit("skill_deactivate")
        async def deactivate_skill(
            agent_id: str,
            skill_id: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Deactivate a skill (unregister MCP tool).

            Security:
            - Requires authentication (REQ-1)
            - Must have access to skill (REQ-2)
            - Rate limited: 20 calls/hour (REQ-4)

            Args:
                agent_id: Agent identifier
                skill_id: Skill UUID to deactivate
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication

            Returns:
                Dict with deactivation result:
                - success: True if operation completed
                - deactivated_at: Deactivation timestamp
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="deactivate_skill",
                    )

                    # Step 2: Validate UUID
                    try:
                        skill_uuid = UUID(skill_id)
                    except ValueError:
                        return {"success": False, "error": "Invalid skill_id format", "error_type": "validation"}

                    # Step 3: Authorization (REQ-2)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=context.namespace,
                        operation=MCPOperation.SKILL_DEACTIVATE,
                    )

                    # Step 4: Execute service method
                    skill_service = SkillService(session)
                    result = await skill_service.deactivate_skill(
                        skill_id=skill_uuid,
                        agent_id=context.agent_id,
                        namespace=context.namespace,
                    )

                    if not result:
                        return {"success": False, "error": "Skill not found or access denied", "error_type": "not_found"}

                    logger.info(f"deactivate_skill: agent={context.agent_id}, skill_id={skill_id}")

                    return {
                        "success": True,
                        "deactivated_at": datetime.now(timezone.utc).isoformat(),
                    }

                except MCPAuthenticationError as e:
                    logger.warning(f"deactivate_skill auth failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authentication"}
                except MCPAuthorizationError as e:
                    logger.warning(f"deactivate_skill authz failed: {e}")
                    return {"success": False, "error": str(e), "error_type": "authorization"}
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(f"deactivate_skill failed: {e}", exc_info=True)
                    return {"success": False, "error": str(e), "error_type": "internal"}

        logger.info("Skill MCP tools registered (8 tools)")
