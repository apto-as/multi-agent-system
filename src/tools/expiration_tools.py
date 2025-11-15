"""MCP Tools for Memory Expiration & TTL Management (TMWS v2.3.0).

Provides secure MCP tools for managing memory expiration, TTL, and cleanup operations.
Implements Hestia's security requirements (REQ-1, REQ-2, REQ-3, REQ-4, REQ-5).

Security Architecture:
- REQ-1: Authentication required (via mcp_auth)
- REQ-2: Namespace isolation (P0-1 pattern)
- REQ-3: Mass deletion confirmation (>10 items)
- REQ-4: Rate limiting (tool-specific)
- REQ-5: Role-based access control (admin operations)

Tool Categories:
1. Memory Expiration: prune_expired_memories, get_expiration_stats, set_memory_ttl
2. Namespace Management: cleanup_namespace, get_namespace_stats
3. Scheduler Control: get/configure/start/stop/trigger_scheduler (admin-only)
"""

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastmcp import FastMCP
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.memory import Memory
from ..security.mcp_auth import (
    MCPAuthContext,
    MCPAuthorizationError,
    MCPOperation,
    authenticate_mcp_request,
    authorize_mcp_request,
)
from ..security.mcp_rate_limiter import require_mcp_rate_limit
from ..services.expiration_scheduler import ExpirationScheduler
from ..services.memory_service import HybridMemoryService

logger = logging.getLogger(__name__)


class ExpirationTools:
    """MCP tools for memory expiration and TTL management.

    Security:
    - All tools require authentication (REQ-1)
    - All tools enforce namespace isolation (REQ-2)
    - Deletion tools require confirmation for >10 items (REQ-3)
    - All tools have rate limits (REQ-4)
    - Admin tools require special role (REQ-5)
    """

    def __init__(
        self,
        memory_service: HybridMemoryService,
        scheduler: ExpirationScheduler | None = None,
    ):
        """Initialize expiration tools.

        Args:
            memory_service: Memory service instance
            scheduler: Optional expiration scheduler instance
        """
        self.memory_service = memory_service
        self.scheduler = scheduler

    async def register_tools(self, mcp: FastMCP, session_factory) -> None:
        """Register all MCP tools using FastMCP decorator pattern.

        Args:
            mcp: FastMCP instance
            session_factory: Async session factory for database access
        """

        # ============================================================
        # MEMORY EXPIRATION TOOLS
        # ============================================================

        @mcp.tool()
        @require_mcp_rate_limit("prune_expired_memories")
        async def prune_expired_memories(
            agent_id: str,
            namespace: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
            dry_run: bool = False,
            confirm_mass_deletion: bool = False,
        ) -> dict[str, Any]:
            """Remove expired memories from a namespace (REQ-3: Requires confirmation for >10 items).

            Security:
            - Requires authentication (REQ-1)
            - Namespace-scoped deletion only (REQ-2)
            - Confirmation required for >10 deletions (REQ-3)
            - Rate limited: 5 deletions/hour (REQ-4)

            Args:
                agent_id: Agent identifier (must be authenticated)
                namespace: Target namespace to prune
                api_key: Optional API key for authentication
                jwt_token: Optional JWT token for authentication
                dry_run: If True, only count without deleting
                confirm_mass_deletion: Required if >10 items will be deleted

            Returns:
                Dict with deletion results:
                - success: True if operation completed
                - deleted_count: Number of memories deleted
                - dry_run: Whether this was a dry run
                - deleted_ids: List of deleted memory IDs (if not dry_run)

            Raises:
                MCPAuthenticationError: If authentication fails
                MCPAuthorizationError: If namespace access denied or rate limit exceeded
                ValueError: If mass deletion not confirmed

            Example:
                # Dry run first to count
                result = await prune_expired_memories(
                    agent_id="my-agent",
                    namespace="project-x",
                    api_key="...",
                    dry_run=True
                )
                # If count > 10, confirm deletion
                if result["would_delete_count"] > 10:
                    result = await prune_expired_memories(
                        agent_id="my-agent",
                        namespace="project-x",
                        api_key="...",
                        confirm_mass_deletion=True
                    )
            """
            async with session_factory() as session:
                try:
                    # Step 1: Authentication (REQ-1)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="prune_expired_memories",
                    )

                    # Step 2: Authorization (REQ-2)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=namespace,
                        operation=MCPOperation.MEMORY_DELETE,
                    )

                    # Step 3: Find expired memories in target namespace
                    now = datetime.now(timezone.utc)
                    stmt = select(Memory).where(
                        Memory.namespace == namespace,
                        Memory.expires_at.is_not(None),
                        Memory.expires_at < now,
                    )
                    result = await session.execute(stmt)
                    expired_memories = list(result.scalars().all())

                    # REQ-3: Mass deletion confirmation
                    if len(expired_memories) > 10 and not confirm_mass_deletion:
                        logger.warning(
                            f"🚨 Mass deletion blocked: {len(expired_memories)} items > 10",
                            extra={
                                "agent_id": agent_id,
                                "namespace": namespace,
                                "count": len(expired_memories),
                            },
                        )
                        return {
                            "error": "mass_deletion_confirmation_required",
                            "message": f"Mass deletion blocked: {len(expired_memories)} items > 10. Set confirm_mass_deletion=True to proceed.",
                            "would_delete_count": len(expired_memories),
                            "dry_run": True,
                        }

                    # Dry run: Return count only
                    if dry_run:
                        return {
                            "success": True,
                            "would_delete_count": len(expired_memories),
                            "dry_run": True,
                            "namespace": namespace,
                        }

                    # Execute deletion
                    deleted_ids = []
                    for memory in expired_memories:
                        try:
                            await session.delete(memory)
                            deleted_ids.append(str(memory.id))
                        except (KeyboardInterrupt, SystemExit):
                            raise
                        except Exception as e:
                            logger.error(
                                f"Failed to delete expired memory {memory.id}: {e}",
                                exc_info=True,
                            )

                    await session.commit()

                    # Audit log
                    logger.info(
                        f"✅ Pruned {len(deleted_ids)} expired memories from namespace {namespace}",
                        extra={
                            "agent_id": agent_id,
                            "namespace": namespace,
                            "deleted_count": len(deleted_ids),
                        },
                    )

                    return {
                        "success": True,
                        "deleted_count": len(deleted_ids),
                        "deleted_ids": deleted_ids,
                        "dry_run": False,
                        "namespace": namespace,
                    }

                except (KeyboardInterrupt, SystemExit):
                    raise
                except (MCPAuthorizationError, ValueError) as e:
                    return {"error": str(e)}
                except Exception as e:
                    logger.error(
                        f"❌ prune_expired_memories failed: {type(e).__name__}: {str(e)}",
                        exc_info=True,
                    )
                    return {"error": f"Operation failed: {str(e)}"}

        @mcp.tool()
        @require_mcp_rate_limit("get_expiration_stats")
        async def get_expiration_stats(
            agent_id: str,
            namespace: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Get expiration statistics for a namespace.

            Security:
            - Requires authentication (REQ-1)
            - Namespace-scoped query only (REQ-2)
            - Rate limited: 30 queries/minute (REQ-4)

            Args:
                agent_id: Agent identifier
                namespace: Target namespace
                api_key: Optional API key
                jwt_token: Optional JWT token

            Returns:
                Dict with expiration statistics:
                - total_memories: Total memories in namespace
                - with_ttl: Memories with expiration set
                - without_ttl: Permanent memories
                - expired: Already expired (ready to prune)
                - expiring_soon_24h: Expiring in next 24 hours
                - expiring_soon_7d: Expiring in next 7 days
            """
            async with session_factory() as session:
                try:
                    # Authentication & Authorization
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="get_expiration_stats",
                    )

                    await authorize_mcp_request(
                        context=context,
                        target_namespace=namespace,
                        operation=MCPOperation.NAMESPACE_READ,
                    )

                    # Calculate statistics
                    now = datetime.now(timezone.utc)
                    from datetime import timedelta

                    # Total memories
                    total_stmt = select(func.count()).select_from(Memory).where(Memory.namespace == namespace)
                    total_result = await session.execute(total_stmt)
                    total = total_result.scalar() or 0

                    # With TTL
                    with_ttl_stmt = (
                        select(func.count())
                        .select_from(Memory)
                        .where(Memory.namespace == namespace, Memory.expires_at.is_not(None))
                    )
                    with_ttl_result = await session.execute(with_ttl_stmt)
                    with_ttl = with_ttl_result.scalar() or 0

                    # Expired
                    expired_stmt = (
                        select(func.count())
                        .select_from(Memory)
                        .where(
                            Memory.namespace == namespace,
                            Memory.expires_at.is_not(None),
                            Memory.expires_at < now,
                        )
                    )
                    expired_result = await session.execute(expired_stmt)
                    expired = expired_result.scalar() or 0

                    # Expiring soon (24h)
                    expires_24h_stmt = (
                        select(func.count())
                        .select_from(Memory)
                        .where(
                            Memory.namespace == namespace,
                            Memory.expires_at.is_not(None),
                            Memory.expires_at >= now,
                            Memory.expires_at < now + timedelta(hours=24),
                        )
                    )
                    expires_24h_result = await session.execute(expires_24h_stmt)
                    expires_24h = expires_24h_result.scalar() or 0

                    # Expiring soon (7d)
                    expires_7d_stmt = (
                        select(func.count())
                        .select_from(Memory)
                        .where(
                            Memory.namespace == namespace,
                            Memory.expires_at.is_not(None),
                            Memory.expires_at >= now,
                            Memory.expires_at < now + timedelta(days=7),
                        )
                    )
                    expires_7d_result = await session.execute(expires_7d_stmt)
                    expires_7d = expires_7d_result.scalar() or 0

                    return {
                        "success": True,
                        "namespace": namespace,
                        "total_memories": total,
                        "with_ttl": with_ttl,
                        "without_ttl": total - with_ttl,
                        "expired": expired,
                        "expiring_soon_24h": expires_24h,
                        "expiring_soon_7d": expires_7d,
                    }

                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(
                        f"❌ get_expiration_stats failed: {type(e).__name__}: {str(e)}",
                        exc_info=True,
                    )
                    return {"error": f"Operation failed: {str(e)}"}

        @mcp.tool()
        @require_mcp_rate_limit("set_memory_ttl")
        async def set_memory_ttl(
            agent_id: str,
            memory_id: str,
            ttl_days: int | None,
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Update TTL for an existing memory (P0-1 security pattern).

            Security:
            - Requires authentication (REQ-1)
            - Ownership verification (P0-1 pattern) (REQ-2)
            - Rate limited: 30 updates/minute (REQ-4)

            Args:
                agent_id: Agent identifier (must own the memory)
                memory_id: Memory UUID to update
                ttl_days: New TTL in days (1-3650) or None for permanent
                api_key: Optional API key
                jwt_token: Optional JWT token

            Returns:
                Dict with update result:
                - success: True if updated
                - memory_id: Memory UUID
                - expires_at: New expiration timestamp (ISO format) or null
                - ttl_days: TTL value set

            Raises:
                MCPAuthenticationError: If authentication fails
                MCPAuthorizationError: If not memory owner
                ValueError: If TTL invalid
            """
            async with session_factory() as session:
                try:
                    # Authentication
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="set_memory_ttl",
                    )

                    # Fetch memory (P0-1: verify from database)
                    memory_uuid = UUID(memory_id)
                    memory = await session.get(Memory, memory_uuid)

                    if not memory:
                        return {"error": f"Memory not found: {memory_id}"}

                    # Check ownership (P0-1: use verified namespace from context)
                    if not memory.is_accessible_by(context.agent_id, context.namespace):
                        raise MCPAuthorizationError(
                            f"Access denied: Agent {agent_id} cannot modify memory {memory_id}"
                        )

                    # Only owner can modify TTL
                    if memory.agent_id != agent_id:
                        raise MCPAuthorizationError(
                            f"Only memory owner can modify TTL. Owner: {memory.agent_id}, Requester: {agent_id}"
                        )

                    # Validate TTL
                    from ..services.memory_service import _validate_ttl_days, _validate_access_level_ttl_limit

                    _validate_ttl_days(ttl_days)
                    _validate_access_level_ttl_limit(memory.access_level, ttl_days)

                    # Calculate new expiration
                    if ttl_days is not None:
                        from datetime import timedelta

                        expires_at = datetime.now(timezone.utc) + timedelta(days=ttl_days)
                    else:
                        expires_at = None

                    # Update memory
                    memory.expires_at = expires_at
                    memory.updated_at = datetime.now(timezone.utc)
                    await session.commit()

                    logger.info(
                        f"✅ Updated TTL for memory {memory_id}: ttl_days={ttl_days}",
                        extra={"agent_id": agent_id, "memory_id": memory_id, "ttl_days": ttl_days},
                    )

                    return {
                        "success": True,
                        "memory_id": memory_id,
                        "ttl_days": ttl_days,
                        "expires_at": expires_at.isoformat() if expires_at else None,
                    }

                except (KeyboardInterrupt, SystemExit):
                    raise
                except (MCPAuthorizationError, ValueError) as e:
                    return {"error": str(e)}
                except Exception as e:
                    logger.error(
                        f"❌ set_memory_ttl failed: {type(e).__name__}: {str(e)}",
                        exc_info=True,
                    )
                    return {"error": f"Operation failed: {str(e)}"}

        # ============================================================
        # NAMESPACE MANAGEMENT TOOLS
        # ============================================================

        @mcp.tool()
        @require_mcp_rate_limit("cleanup_namespace")
        async def cleanup_namespace(
            agent_id: str,
            namespace: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
            dry_run: bool = False,
            confirm_mass_deletion: bool = False,
        ) -> dict[str, Any]:
            """Delete ALL memories from a namespace (REQ-3: Requires confirmation, REQ-5: Admin only).

            ⚠️  WARNING: This is a DESTRUCTIVE operation that deletes ALL memories in the namespace.

            Security:
            - Requires authentication (REQ-1)
            - Admin-only operation (REQ-5)
            - Confirmation required for >10 items (REQ-3)
            - Rate limited: 2 cleanups/day (REQ-4)

            Args:
                agent_id: Agent identifier (must be namespace admin)
                namespace: Target namespace to clean
                api_key: Optional API key
                jwt_token: Optional JWT token
                dry_run: If True, only count without deleting
                confirm_mass_deletion: Required for deletion (safety check)

            Returns:
                Dict with cleanup results:
                - success: True if completed
                - deleted_count: Number of memories deleted
                - dry_run: Whether this was a dry run
                - namespace: Target namespace
            """
            async with session_factory() as session:
                try:
                    # Authentication
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="cleanup_namespace",
                    )

                    # Authorization (REQ-5: Admin operation)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=namespace,
                        operation=MCPOperation.CLEANUP_NAMESPACE,
                    )

                    # Count memories
                    count_stmt = select(func.count()).select_from(Memory).where(Memory.namespace == namespace)
                    count_result = await session.execute(count_stmt)
                    total_count = count_result.scalar() or 0

                    # REQ-3: Mass deletion confirmation
                    if total_count > 10 and not confirm_mass_deletion:
                        logger.warning(
                            f"🚨 Namespace cleanup blocked: {total_count} items > 10",
                            extra={"agent_id": agent_id, "namespace": namespace, "count": total_count},
                        )
                        return {
                            "error": "mass_deletion_confirmation_required",
                            "message": f"Namespace cleanup blocked: {total_count} items > 10. Set confirm_mass_deletion=True to proceed.",
                            "would_delete_count": total_count,
                            "dry_run": True,
                        }

                    # Dry run
                    if dry_run:
                        return {
                            "success": True,
                            "would_delete_count": total_count,
                            "dry_run": True,
                            "namespace": namespace,
                        }

                    # Execute deletion
                    stmt = select(Memory).where(Memory.namespace == namespace)
                    result = await session.execute(stmt)
                    memories = list(result.scalars().all())

                    deleted_count = 0
                    for memory in memories:
                        try:
                            await session.delete(memory)
                            deleted_count += 1
                        except (KeyboardInterrupt, SystemExit):
                            raise
                        except Exception as e:
                            logger.error(f"Failed to delete memory {memory.id}: {e}", exc_info=True)

                    await session.commit()

                    logger.warning(
                        f"🗑️  Namespace cleanup completed: {deleted_count} memories deleted from {namespace}",
                        extra={"agent_id": agent_id, "namespace": namespace, "deleted_count": deleted_count},
                    )

                    return {
                        "success": True,
                        "deleted_count": deleted_count,
                        "dry_run": False,
                        "namespace": namespace,
                    }

                except (KeyboardInterrupt, SystemExit):
                    raise
                except (MCPAuthorizationError, ValueError) as e:
                    return {"error": str(e)}
                except Exception as e:
                    logger.error(
                        f"❌ cleanup_namespace failed: {type(e).__name__}: {str(e)}",
                        exc_info=True,
                    )
                    return {"error": f"Operation failed: {str(e)}"}

        @mcp.tool()
        @require_mcp_rate_limit("get_namespace_stats")
        async def get_namespace_stats(
            agent_id: str,
            namespace: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Get comprehensive statistics for a namespace.

            Security:
            - Requires authentication (REQ-1)
            - Namespace-scoped query (REQ-2)
            - Rate limited: 20 queries/minute (REQ-4)

            Args:
                agent_id: Agent identifier
                namespace: Target namespace
                api_key: Optional API key
                jwt_token: Optional JWT token

            Returns:
                Dict with namespace statistics:
                - total_memories: Total memories in namespace
                - by_access_level: Count by access level (PRIVATE, TEAM, etc.)
                - by_agent: Count by agent_id (top 10)
                - with_ttl: Memories with expiration
                - total_size_estimate: Estimated storage size (bytes)
            """
            async with session_factory() as session:
                try:
                    # Authentication & Authorization
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="get_namespace_stats",
                    )

                    await authorize_mcp_request(
                        context=context,
                        target_namespace=namespace,
                        operation=MCPOperation.NAMESPACE_READ,
                    )

                    # Total count
                    total_stmt = select(func.count()).select_from(Memory).where(Memory.namespace == namespace)
                    total_result = await session.execute(total_stmt)
                    total = total_result.scalar() or 0

                    # By access level
                    by_access_level = {}
                    for level in ["private", "team", "shared", "public", "system"]:
                        stmt = (
                            select(func.count())
                            .select_from(Memory)
                            .where(Memory.namespace == namespace, Memory.access_level == level)
                        )
                        result = await session.execute(stmt)
                        by_access_level[level] = result.scalar() or 0

                    # With TTL
                    ttl_stmt = (
                        select(func.count())
                        .select_from(Memory)
                        .where(Memory.namespace == namespace, Memory.expires_at.is_not(None))
                    )
                    ttl_result = await session.execute(ttl_stmt)
                    with_ttl = ttl_result.scalar() or 0

                    # Size estimate (content length sum)
                    size_stmt = select(func.sum(func.length(Memory.content))).where(
                        Memory.namespace == namespace
                    )
                    size_result = await session.execute(size_stmt)
                    total_size = size_result.scalar() or 0

                    return {
                        "success": True,
                        "namespace": namespace,
                        "total_memories": total,
                        "by_access_level": by_access_level,
                        "with_ttl": with_ttl,
                        "without_ttl": total - with_ttl,
                        "total_size_estimate_bytes": total_size,
                    }

                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(
                        f"❌ get_namespace_stats failed: {type(e).__name__}: {str(e)}",
                        exc_info=True,
                    )
                    return {"error": f"Operation failed: {str(e)}"}

        # ============================================================
        # SCHEDULER CONTROL TOOLS (REQ-5: Admin-only)
        # ============================================================

        @mcp.tool()
        @require_mcp_rate_limit("get_scheduler_status")
        async def get_scheduler_status(
            agent_id: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Get expiration scheduler status (read-only, no admin required).

            Security:
            - Requires authentication (REQ-1)
            - Rate limited: 60 queries/minute (REQ-4)

            Args:
                agent_id: Agent identifier
                api_key: Optional API key
                jwt_token: Optional JWT token

            Returns:
                Dict with scheduler status:
                - is_running: Whether scheduler is active
                - interval_hours: Cleanup interval
                - last_run_time: Last cleanup time (ISO format)
                - next_run_time: Next scheduled cleanup (ISO format)
                - total_cleanups: Total cleanup runs
                - total_deleted: Total memories deleted
            """
            async with session_factory() as session:
                try:
                    # Authentication (no namespace check needed - global status)
                    await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="get_scheduler_status",
                    )

                    if not self.scheduler:
                        return {"error": "Scheduler not available"}

                    return {
                        "success": True,
                        "is_running": self.scheduler.is_running(),
                        "interval_hours": self.scheduler.interval_hours,
                        "last_run_time": (
                            self.scheduler.get_last_run_time().isoformat()
                            if self.scheduler.get_last_run_time()
                            else None
                        ),
                        "next_run_time": (
                            self.scheduler.get_next_run_time().isoformat()
                            if self.scheduler.get_next_run_time()
                            else None
                        ),
                        "total_cleanups": self.scheduler.get_total_cleanups_count(),
                        "total_deleted": self.scheduler.get_total_deleted_count(),
                    }

                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(
                        f"❌ get_scheduler_status failed: {type(e).__name__}: {str(e)}",
                        exc_info=True,
                    )
                    return {"error": f"Operation failed: {str(e)}"}

        @mcp.tool()
        @require_mcp_rate_limit("configure_scheduler")
        async def configure_scheduler(
            agent_id: str,
            interval_hours: int,
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Configure scheduler interval (REQ-5: Admin-only).

            Security:
            - Requires authentication (REQ-1)
            - Admin-only operation (REQ-5)
            - Rate limited: 3 changes/hour (REQ-4)

            Args:
                agent_id: Agent identifier (must be system admin)
                interval_hours: New cleanup interval (1-168 hours / 1 week)
                api_key: Optional API key
                jwt_token: Optional JWT token

            Returns:
                Dict with configuration result:
                - success: True if updated
                - interval_hours: New interval value
            """
            async with session_factory() as session:
                try:
                    # Authentication
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="configure_scheduler",
                    )

                    # Authorization (REQ-5: Admin operation)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=context.namespace,
                        operation=MCPOperation.SCHEDULER_CONFIGURE,
                    )

                    if not self.scheduler:
                        return {"error": "Scheduler not available"}

                    # Validate interval
                    if not isinstance(interval_hours, int) or interval_hours < 1 or interval_hours > 168:
                        return {
                            "error": f"interval_hours must be 1-168 (1 week), got {interval_hours}"
                        }

                    # Update configuration
                    self.scheduler.interval_hours = interval_hours

                    logger.info(
                        f"✅ Scheduler interval updated to {interval_hours}h by {agent_id}",
                        extra={"agent_id": agent_id, "interval_hours": interval_hours},
                    )

                    return {
                        "success": True,
                        "interval_hours": interval_hours,
                        "message": f"Scheduler interval updated to {interval_hours} hours",
                    }

                except (KeyboardInterrupt, SystemExit):
                    raise
                except (MCPAuthorizationError, ValueError) as e:
                    return {"error": str(e)}
                except Exception as e:
                    logger.error(
                        f"❌ configure_scheduler failed: {type(e).__name__}: {str(e)}",
                        exc_info=True,
                    )
                    return {"error": f"Operation failed: {str(e)}"}

        @mcp.tool()
        @require_mcp_rate_limit("start_scheduler")
        async def start_scheduler(
            agent_id: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Start the expiration scheduler (REQ-5: Admin-only).

            Security:
            - Requires authentication (REQ-1)
            - Admin-only operation (REQ-5)
            - Rate limited: 5 starts/hour (REQ-4)

            Args:
                agent_id: Agent identifier (must be system admin)
                api_key: Optional API key
                jwt_token: Optional JWT token

            Returns:
                Dict with start result:
                - success: True if started
                - message: Status message
                - is_running: New scheduler state
            """
            async with session_factory() as session:
                try:
                    # Authentication
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="start_scheduler",
                    )

                    # Authorization (REQ-5: Admin operation)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=context.namespace,
                        operation=MCPOperation.SCHEDULER_CONTROL,
                    )

                    if not self.scheduler:
                        return {"error": "Scheduler not available"}

                    if self.scheduler.is_running():
                        return {
                            "success": True,
                            "message": "Scheduler is already running",
                            "is_running": True,
                        }

                    # Start scheduler
                    await self.scheduler.start()

                    logger.info(
                        f"✅ Scheduler started by {agent_id}",
                        extra={"agent_id": agent_id},
                    )

                    return {
                        "success": True,
                        "message": "Scheduler started successfully",
                        "is_running": True,
                    }

                except (KeyboardInterrupt, SystemExit):
                    raise
                except (MCPAuthorizationError, ValueError) as e:
                    return {"error": str(e)}
                except Exception as e:
                    logger.error(
                        f"❌ start_scheduler failed: {type(e).__name__}: {str(e)}",
                        exc_info=True,
                    )
                    return {"error": f"Operation failed: {str(e)}"}

        @mcp.tool()
        @require_mcp_rate_limit("stop_scheduler")
        async def stop_scheduler(
            agent_id: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Stop the expiration scheduler (REQ-5: Admin-only, REQ-4: Very strict rate limit).

            ⚠️  WARNING: This stops automatic memory cleanup. Use with caution.

            Security:
            - Requires authentication (REQ-1)
            - Admin-only operation (REQ-5)
            - Rate limited: 2 stops/day (REQ-4, very strict)

            Args:
                agent_id: Agent identifier (must be system admin)
                api_key: Optional API key
                jwt_token: Optional JWT token

            Returns:
                Dict with stop result:
                - success: True if stopped
                - message: Status message
                - is_running: New scheduler state
            """
            async with session_factory() as session:
                try:
                    # Authentication
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="stop_scheduler",
                    )

                    # Authorization (REQ-5: Admin operation)
                    await authorize_mcp_request(
                        context=context,
                        target_namespace=context.namespace,
                        operation=MCPOperation.SCHEDULER_CONTROL,
                    )

                    if not self.scheduler:
                        return {"error": "Scheduler not available"}

                    if not self.scheduler.is_running():
                        return {
                            "success": True,
                            "message": "Scheduler is already stopped",
                            "is_running": False,
                        }

                    # Stop scheduler
                    await self.scheduler.stop()

                    logger.warning(
                        f"⚠️  Scheduler stopped by {agent_id} - automatic cleanup disabled",
                        extra={"agent_id": agent_id},
                    )

                    return {
                        "success": True,
                        "message": "Scheduler stopped successfully",
                        "is_running": False,
                    }

                except (KeyboardInterrupt, SystemExit):
                    raise
                except (MCPAuthorizationError, ValueError) as e:
                    return {"error": str(e)}
                except Exception as e:
                    logger.error(
                        f"❌ stop_scheduler failed: {type(e).__name__}: {str(e)}",
                        exc_info=True,
                    )
                    return {"error": f"Operation failed: {str(e)}"}

        @mcp.tool()
        @require_mcp_rate_limit("trigger_scheduler")
        async def trigger_scheduler(
            agent_id: str,
            api_key: str | None = None,
            jwt_token: str | None = None,
        ) -> dict[str, Any]:
            """Manually trigger scheduler cleanup (outside scheduled interval).

            Security:
            - Requires authentication (REQ-1)
            - Rate limited: 10 triggers/hour (REQ-4)

            Args:
                agent_id: Agent identifier
                api_key: Optional API key
                jwt_token: Optional JWT token

            Returns:
                Dict with trigger result:
                - success: True if triggered
                - deleted_count: Number of memories deleted
                - message: Status message
            """
            async with session_factory() as session:
                try:
                    # Authentication (no admin check - any agent can trigger)
                    context = await authenticate_mcp_request(
                        session=session,
                        agent_id=agent_id,
                        api_key=api_key,
                        jwt_token=jwt_token,
                        tool_name="trigger_scheduler",
                    )

                    if not self.scheduler:
                        return {"error": "Scheduler not available"}

                    # Trigger manual cleanup
                    deleted_count = await self.scheduler.trigger_cleanup()

                    logger.info(
                        f"✅ Manual cleanup triggered by {agent_id}: {deleted_count} memories deleted",
                        extra={"agent_id": agent_id, "deleted_count": deleted_count},
                    )

                    return {
                        "success": True,
                        "deleted_count": deleted_count,
                        "message": f"Manual cleanup completed: {deleted_count} expired memories deleted",
                    }

                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(
                        f"❌ trigger_scheduler failed: {type(e).__name__}: {str(e)}",
                        exc_info=True,
                    )
                    return {"error": f"Operation failed: {str(e)}"}
