"""Pattern to Skill MCP Tools for TMWS v2.4.12

This module provides MCP tools for pattern-to-skill auto-generation:
- find_mature_patterns: Discover patterns eligible for skill promotion
- promote_pattern: Convert a mature pattern to a skill
- batch_promote_patterns: Promote multiple patterns at once
- get_promotion_status: Check feature status and eligible patterns

Security:
- REQ-1: Authentication required (agent_id verification)
- REQ-2: Namespace isolation (P0-1 pattern)
- REQ-4: Rate limiting enforced (V-AUTH-1 fix)
- REQ-5: Admin-only for batch operations

Performance targets:
- find_mature_patterns: < 200ms P95
- promote_pattern: < 500ms P95
- batch_promote_patterns: < 2s P95
"""

import logging
from typing import Any

from mcp.server import Server
from sqlalchemy.ext.asyncio import AsyncSession

from src.security.mcp_auth import MCPAuthContext
from src.security.mcp_rate_limiter import get_mcp_rate_limiter
from src.services.pattern_skill_service import PatternSkillService

logger = logging.getLogger(__name__)


class PatternSkillTools:
    """MCP Tools for pattern-to-skill auto-generation."""

    def __init__(self):
        """Initialize pattern-skill tools."""
        self._service: PatternSkillService | None = None

    async def _get_service(self, session: AsyncSession) -> PatternSkillService:
        """Get or create service instance with session."""
        return PatternSkillService(session)

    async def register_tools(
        self,
        mcp: Server,
        get_session: callable,
    ) -> None:
        """Register pattern-skill tools with MCP server.

        Args:
            mcp: MCP server instance
            get_session: Callable to get database session
        """

        @mcp.tool()
        async def find_mature_patterns(
            agent_id: str,
            namespace: str | None = None,
            limit: int = 10,
            min_usage: int | None = None,
            min_success_rate: float | None = None,
        ) -> dict[str, Any]:
            """Find learning patterns eligible for skill promotion.

            Discovers patterns that meet maturity criteria:
            - Default: usage >= 5, success rate >= 85%
            - Configurable via environment or parameters

            Security:
            - Requires authentication (REQ-1)
            - Namespace-scoped query (REQ-2)
            - Rate limited: 60 calls/min (REQ-4)

            Args:
                agent_id: Agent identifier (pattern owner)
                namespace: Target namespace (defaults to agent's namespace)
                limit: Maximum patterns to return (1-100, default 10)
                min_usage: Override minimum usage count
                min_success_rate: Override minimum success rate

            Returns:
                Dict with:
                - success: True if operation completed
                - patterns: List of mature patterns with details
                - total_mature: Total count meeting criteria
                - criteria: Applied maturity thresholds

            Example:
                result = await find_mature_patterns(
                    agent_id="artemis-optimizer",
                    namespace="project-x",
                    limit=5
                )
                for pattern in result["patterns"]:
                    logger.info(f"{pattern['pattern_name']}: {pattern['success_rate']*100}%")
            """
            try:
                # REQ-4: Rate limiting (V-AUTH-1 fix)
                rate_limiter = get_mcp_rate_limiter()
                context = MCPAuthContext(
                    agent_id=agent_id,
                    namespace=namespace or agent_id,
                    role="AGENT",
                )
                await rate_limiter.check_rate_limit(context, "pattern_skill_find")

                async with get_session() as session:
                    service = await self._get_service(session)

                    # Default namespace to agent_id if not provided
                    target_namespace = namespace or agent_id

                    result = await service.find_mature_patterns(
                        agent_id=agent_id,
                        namespace=target_namespace,
                        limit=limit,
                        min_usage=min_usage,
                        min_success_rate=min_success_rate,
                    )

                    logger.info(
                        "find_mature_patterns completed",
                        extra={
                            "agent_id": agent_id,
                            "patterns_found": len(result["patterns"]),
                        },
                    )

                    return result

            except Exception as e:
                logger.error(f"find_mature_patterns failed: {e}")
                return {
                    "success": False,
                    "error": str(e),
                    "patterns": [],
                }

        @mcp.tool()
        async def promote_pattern_to_skill(
            agent_id: str,
            pattern_id: str,
            namespace: str | None = None,
            dry_run: bool = True,
        ) -> dict[str, Any]:
            """Promote a mature learning pattern to a skill.

            Converts a pattern that meets maturity criteria into a skill:
            - Generates SKILL.md content from pattern data
            - Creates skill with PRIVATE access (requires review)
            - Tags skill with "auto-generated" and "pending-review"

            Security:
            - Requires authentication (REQ-1)
            - Pattern ownership verified (REQ-2)
            - Rate limited: 10 calls/hour (REQ-4)

            Args:
                agent_id: Agent identifier (must own pattern)
                pattern_id: UUID of pattern to promote
                namespace: Target namespace (defaults to agent's namespace)
                dry_run: If True, preview only (default). Set False to create.

            Returns:
                Dict with:
                - success: True if operation completed
                - skill_id: Created skill ID (None if dry_run)
                - skill_name: Generated skill name
                - skill_content: Generated SKILL.md content
                - dry_run: Whether this was a preview
                - status: "pending_review" or "preview"

            Example:
                # Preview first
                preview = await promote_pattern_to_skill(
                    agent_id="artemis-optimizer",
                    pattern_id="abc123...",
                    dry_run=True
                )
                logger.info(f"Preview content: {preview['skill_content']}")

                # Then create
                result = await promote_pattern_to_skill(
                    agent_id="artemis-optimizer",
                    pattern_id="abc123...",
                    dry_run=False
                )
                logger.info(f"Created skill: {result['skill_id']}")
            """
            try:
                # REQ-4: Rate limiting (V-AUTH-1 fix)
                rate_limiter = get_mcp_rate_limiter()
                context = MCPAuthContext(
                    agent_id=agent_id,
                    namespace=namespace or agent_id,
                    role="AGENT",
                )
                await rate_limiter.check_rate_limit(context, "pattern_skill_promote")

                async with get_session() as session:
                    service = await self._get_service(session)

                    # Default namespace to agent_id if not provided
                    target_namespace = namespace or agent_id

                    result = await service.promote_pattern_to_skill(
                        pattern_id=pattern_id,
                        agent_id=agent_id,
                        namespace=target_namespace,
                        dry_run=dry_run,
                    )

                    if not dry_run:
                        await session.commit()

                    logger.info(
                        "promote_pattern_to_skill completed",
                        extra={
                            "pattern_id": pattern_id,
                            "dry_run": dry_run,
                            "success": result["success"],
                        },
                    )

                    return result

            except Exception as e:
                logger.error(f"promote_pattern_to_skill failed: {e}")
                return {
                    "success": False,
                    "error": str(e),
                    "skill_id": None,
                    "dry_run": dry_run,
                }

        @mcp.tool()
        async def batch_promote_patterns(
            agent_id: str,
            namespace: str | None = None,
            limit: int = 5,
            dry_run: bool = True,
        ) -> dict[str, Any]:
            """Batch promote multiple mature patterns to skills.

            Promotes up to 10 patterns at once:
            - Finds patterns meeting maturity criteria
            - Generates skills for each eligible pattern
            - Returns summary of promotions/previews

            Security:
            - Requires authentication (REQ-1)
            - Pattern ownership verified (REQ-2)
            - Rate limited: 5 calls/hour (REQ-4)

            Args:
                agent_id: Agent identifier (must own patterns)
                namespace: Target namespace (defaults to agent's namespace)
                limit: Maximum patterns to promote (1-10, default 5)
                dry_run: If True, preview only (default). Set False to create.

            Returns:
                Dict with:
                - success: True if operation completed
                - promoted: List of promoted/previewed patterns
                - total_eligible: Total patterns meeting criteria
                - dry_run: Whether this was a preview

            Example:
                # Preview batch
                preview = await batch_promote_patterns(
                    agent_id="artemis-optimizer",
                    limit=3,
                    dry_run=True
                )
                logger.info(f"Would promote {len(preview['promoted'])} patterns")

                # Execute batch
                result = await batch_promote_patterns(
                    agent_id="artemis-optimizer",
                    limit=3,
                    dry_run=False
                )
            """
            try:
                # REQ-4: Rate limiting (V-AUTH-1 fix)
                rate_limiter = get_mcp_rate_limiter()
                context = MCPAuthContext(
                    agent_id=agent_id,
                    namespace=namespace or agent_id,
                    role="AGENT",
                )
                await rate_limiter.check_rate_limit(context, "pattern_skill_batch")

                async with get_session() as session:
                    service = await self._get_service(session)

                    # Default namespace to agent_id if not provided
                    target_namespace = namespace or agent_id

                    result = await service.batch_promote(
                        agent_id=agent_id,
                        namespace=target_namespace,
                        limit=limit,
                        dry_run=dry_run,
                    )

                    if not dry_run:
                        await session.commit()

                    logger.info(
                        "batch_promote_patterns completed",
                        extra={
                            "agent_id": agent_id,
                            "promoted_count": len(result["promoted"]),
                            "dry_run": dry_run,
                        },
                    )

                    return result

            except Exception as e:
                logger.error(f"batch_promote_patterns failed: {e}")
                return {
                    "success": False,
                    "error": str(e),
                    "promoted": [],
                    "dry_run": dry_run,
                }

        @mcp.tool()
        async def get_pattern_promotion_status(
            agent_id: str,
            namespace: str | None = None,
        ) -> dict[str, Any]:
            """Get status of pattern-to-skill promotion feature.

            Returns summary including:
            - Feature enabled/disabled status
            - Current maturity thresholds
            - Number of eligible patterns
            - Sample of eligible patterns

            Security:
            - Requires authentication (REQ-1)
            - Namespace-scoped query (REQ-2)
            - Rate limited: 60 calls/min (REQ-4)

            Args:
                agent_id: Agent identifier
                namespace: Target namespace (defaults to agent's namespace)

            Returns:
                Dict with:
                - success: True if operation completed
                - feature_enabled: Whether auto-generation is enabled
                - thresholds: Current maturity criteria
                - eligible_patterns: Count of patterns meeting criteria
                - sample_patterns: Up to 5 sample eligible patterns

            Example:
                status = await get_pattern_promotion_status(
                    agent_id="artemis-optimizer"
                )
                if status["feature_enabled"]:
                    logger.info(f"{status['eligible_patterns']} patterns ready for promotion")
            """
            try:
                # REQ-4: Rate limiting (V-AUTH-1 fix)
                rate_limiter = get_mcp_rate_limiter()
                context = MCPAuthContext(
                    agent_id=agent_id,
                    namespace=namespace or agent_id,
                    role="AGENT",
                )
                await rate_limiter.check_rate_limit(context, "pattern_skill_status")

                async with get_session() as session:
                    service = await self._get_service(session)

                    # Default namespace to agent_id if not provided
                    target_namespace = namespace or agent_id

                    result = await service.get_promotion_status(
                        agent_id=agent_id,
                        namespace=target_namespace,
                    )

                    logger.info(
                        "get_pattern_promotion_status completed",
                        extra={
                            "agent_id": agent_id,
                            "eligible_patterns": result["eligible_patterns"],
                        },
                    )

                    return result

            except Exception as e:
                logger.error(f"get_pattern_promotion_status failed: {e}")
                return {
                    "success": False,
                    "error": str(e),
                    "feature_enabled": False,
                }

        logger.info("Pattern-skill tools registered (4 MCP tools)")
