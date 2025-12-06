"""Tool Promotion Service for TMWS.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 4.2 - Tool → Skill Promotion Logic

Promotes frequently used and successful tools to Skills (3rd core feature).
Integration with:
- AdaptiveRanker: Usage patterns and success rates
- SkillService: Skill creation and management
- LearningService: Pattern history

Author: Artemis (Implementation)
Created: 2025-12-05
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .adaptive_ranker import (
    AdaptiveRanker,
    ToolUsagePattern,
    validate_agent_id,
    validate_server_id,
    validate_tool_name,
)

# Admin agents that can use force promotion (H-2 security fix)
ADMIN_AGENTS = frozenset([
    "athena-conductor",
    "hera-strategist",
    "system",
    "admin",
])

logger = logging.getLogger(__name__)


@dataclass
class PromotionCriteria:
    """Criteria for tool promotion to Skill.

    A tool must meet ALL criteria to be promoted.
    """

    # Minimum usage count
    min_usage_count: int = 50

    # Minimum success rate (0.0 - 1.0)
    min_success_rate: float = 0.85

    # Minimum number of successful queries
    min_success_count: int = 40

    # Maximum average latency (ms)
    max_average_latency_ms: float = 5000.0

    # Minimum days of usage history
    min_days_active: int = 7

    # Minimum unique query contexts
    min_query_contexts: int = 5


@dataclass
class PromotionCandidate:
    """A tool that is a candidate for promotion."""

    tool_name: str
    server_id: str
    agent_id: str
    usage_count: int
    success_rate: float
    average_latency_ms: float
    days_active: int
    query_contexts: int
    promotion_score: float
    meets_criteria: bool
    missing_criteria: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tool_name": self.tool_name,
            "server_id": self.server_id,
            "agent_id": self.agent_id,
            "usage_count": self.usage_count,
            "success_rate": self.success_rate,
            "average_latency_ms": self.average_latency_ms,
            "days_active": self.days_active,
            "query_contexts": self.query_contexts,
            "promotion_score": self.promotion_score,
            "meets_criteria": self.meets_criteria,
            "missing_criteria": self.missing_criteria,
        }


@dataclass
class PromotionResult:
    """Result of a promotion operation."""

    success: bool
    tool_name: str
    server_id: str
    skill_id: str | None = None
    skill_name: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "tool_name": self.tool_name,
            "server_id": self.server_id,
            "skill_id": self.skill_id,
            "skill_name": self.skill_name,
            "error": self.error,
        }


class ToolPromotionService:
    """Service for promoting tools to Skills.

    Automatically identifies tools that should be promoted based on:
    - Usage frequency
    - Success rate
    - Performance (latency)
    - Query diversity

    Integrates with:
    - AdaptiveRanker: For usage patterns
    - SkillService: For skill creation
    - LearningService: For pattern history
    """

    def __init__(
        self,
        adaptive_ranker: AdaptiveRanker | None = None,
        skill_service: Any = None,
        criteria: PromotionCriteria | None = None,
    ):
        """Initialize ToolPromotionService.

        Args:
            adaptive_ranker: AdaptiveRanker for usage patterns
            skill_service: SkillService for skill creation
            criteria: Promotion criteria (defaults to standard criteria)
        """
        self._adaptive_ranker = adaptive_ranker
        self._skill_service = skill_service
        self.criteria = criteria or PromotionCriteria()

        # Track promoted tools to avoid duplicates
        self._promoted_tools: set[str] = set()

        logger.info("ToolPromotionService initialized")

    def set_adaptive_ranker(self, ranker: AdaptiveRanker) -> None:
        """Set the adaptive ranker.

        Args:
            ranker: AdaptiveRanker instance
        """
        self._adaptive_ranker = ranker

    def set_skill_service(self, service: Any) -> None:
        """Set the skill service.

        Args:
            service: SkillService instance
        """
        self._skill_service = service

    async def get_promotion_candidates(
        self,
        agent_id: str | None = None,
        limit: int = 10,
    ) -> list[PromotionCandidate]:
        """Get tools that are candidates for promotion.

        Args:
            agent_id: Optional agent ID to filter by
            limit: Maximum candidates to return

        Returns:
            List of promotion candidates sorted by score
        """
        if not self._adaptive_ranker:
            logger.warning("AdaptiveRanker not set, cannot get candidates")
            return []

        candidates: list[PromotionCandidate] = []

        # Get all agent patterns
        agent_ids = (
            [agent_id]
            if agent_id
            else list(self._adaptive_ranker._agent_patterns.keys())
        )

        for aid in agent_ids:
            patterns = await self._adaptive_ranker._get_agent_patterns(aid)

            for pattern_key, pattern in patterns.items():
                # Skip already promoted
                if pattern_key in self._promoted_tools:
                    continue

                candidate = self._evaluate_pattern(pattern, aid)
                candidates.append(candidate)

        # Sort by promotion score (descending)
        candidates.sort(key=lambda c: c.promotion_score, reverse=True)

        return candidates[:limit]

    async def promote_tool(
        self,
        tool_name: str,
        server_id: str,
        agent_id: str,
        skill_name: str | None = None,
        description: str | None = None,
        force: bool = False,
    ) -> PromotionResult:
        """Promote a tool to a Skill.

        Args:
            tool_name: Name of the tool to promote
            server_id: Server ID of the tool
            agent_id: Agent requesting promotion
            skill_name: Optional custom skill name
            description: Optional skill description
            force: Skip criteria check if True (requires admin agent)

        Returns:
            PromotionResult with success status

        Raises:
            ValueError: If parameters are invalid
            PermissionError: If force=True without admin privileges
        """
        # H-1 Security Fix: Validate inputs
        tool_name = validate_tool_name(tool_name)
        server_id = validate_server_id(server_id)
        agent_id = validate_agent_id(agent_id)

        # H-2 Security Fix: Force requires admin privileges
        if force:
            if agent_id not in ADMIN_AGENTS:
                logger.warning(
                    f"SECURITY: Unauthorized force promotion attempt by {agent_id}"
                )
                raise PermissionError(
                    f"Force promotion requires admin privileges. "
                    f"Agent '{agent_id}' is not authorized."
                )
            logger.info(
                f"AUDIT: Force promotion authorized for {agent_id} on {tool_name}"
            )

        pattern_key = f"{server_id}:{tool_name}"

        # Check if already promoted
        if pattern_key in self._promoted_tools:
            return PromotionResult(
                success=False,
                tool_name=tool_name,
                server_id=server_id,
                error="Tool already promoted",
            )

        # Check criteria unless forced
        if not force and self._adaptive_ranker:
            patterns = await self._adaptive_ranker._get_agent_patterns(agent_id)
            pattern = patterns.get(pattern_key)

            if not pattern:
                return PromotionResult(
                    success=False,
                    tool_name=tool_name,
                    server_id=server_id,
                    error="No usage pattern found for tool",
                )

            candidate = self._evaluate_pattern(pattern, agent_id)
            if not candidate.meets_criteria:
                return PromotionResult(
                    success=False,
                    tool_name=tool_name,
                    server_id=server_id,
                    error=f"Does not meet criteria: {', '.join(candidate.missing_criteria)}",
                )

        # Create skill
        if not self._skill_service:
            return PromotionResult(
                success=False,
                tool_name=tool_name,
                server_id=server_id,
                error="SkillService not configured",
            )

        try:
            # Generate skill name if not provided
            final_skill_name = skill_name or f"Promoted: {tool_name}"

            # Generate description if not provided
            final_description = description or (
                f"Skill promoted from tool '{tool_name}' on server '{server_id}'. "
                f"This tool has been frequently used with high success rate."
            )

            # Create the skill via SkillService
            skill = await self._skill_service.create_skill(
                name=final_skill_name,
                description=final_description,
                category="promoted",
                creator_agent_id=agent_id,
                pattern_type="tool_wrapper",
                parameters={
                    "original_tool": tool_name,
                    "original_server": server_id,
                    "promoted_at": datetime.now().isoformat(),
                    "promoted_by": agent_id,
                },
            )

            # Mark as promoted
            self._promoted_tools.add(pattern_key)

            logger.info(
                f"Promoted tool '{tool_name}' to skill '{final_skill_name}' "
                f"(id: {skill.get('skill_id', 'unknown')})"
            )

            return PromotionResult(
                success=True,
                tool_name=tool_name,
                server_id=server_id,
                skill_id=skill.get("skill_id"),
                skill_name=final_skill_name,
            )

        except Exception as e:
            logger.error(f"Failed to promote tool '{tool_name}': {e}")
            return PromotionResult(
                success=False,
                tool_name=tool_name,
                server_id=server_id,
                error=str(e),
            )

    async def auto_promote(
        self,
        agent_id: str | None = None,
        max_promotions: int = 5,
    ) -> list[PromotionResult]:
        """Automatically promote eligible tools.

        Args:
            agent_id: Optional agent ID to filter by
            max_promotions: Maximum tools to promote

        Returns:
            List of promotion results
        """
        results: list[PromotionResult] = []

        # Get eligible candidates
        candidates = await self.get_promotion_candidates(
            agent_id=agent_id,
            limit=max_promotions * 2,  # Get more than needed in case some fail
        )

        # Promote eligible candidates
        for candidate in candidates:
            if not candidate.meets_criteria:
                continue

            if len(results) >= max_promotions:
                break

            result = await self.promote_tool(
                tool_name=candidate.tool_name,
                server_id=candidate.server_id,
                agent_id=candidate.agent_id,
            )
            results.append(result)

        logger.info(f"Auto-promotion completed: {len(results)} tools promoted")
        return results

    async def get_promotion_stats(self) -> dict[str, Any]:
        """Get promotion statistics.

        Returns:
            Dictionary with promotion stats
        """
        return {
            "total_promoted": len(self._promoted_tools),
            "promoted_tools": list(self._promoted_tools),
            "criteria": {
                "min_usage_count": self.criteria.min_usage_count,
                "min_success_rate": self.criteria.min_success_rate,
                "min_success_count": self.criteria.min_success_count,
                "max_average_latency_ms": self.criteria.max_average_latency_ms,
                "min_days_active": self.criteria.min_days_active,
                "min_query_contexts": self.criteria.min_query_contexts,
            },
        }

    def _evaluate_pattern(
        self,
        pattern: ToolUsagePattern,
        agent_id: str,
    ) -> PromotionCandidate:
        """Evaluate a usage pattern for promotion.

        Args:
            pattern: Usage pattern to evaluate
            agent_id: Agent ID

        Returns:
            PromotionCandidate with evaluation results
        """
        missing_criteria: list[str] = []

        # Check each criterion
        if pattern.usage_count < self.criteria.min_usage_count:
            missing_criteria.append(
                f"usage_count ({pattern.usage_count} < {self.criteria.min_usage_count})"
            )

        if pattern.success_rate < self.criteria.min_success_rate:
            missing_criteria.append(
                f"success_rate ({pattern.success_rate:.2%} < {self.criteria.min_success_rate:.0%})"
            )

        if pattern.success_count < self.criteria.min_success_count:
            missing_criteria.append(
                f"success_count ({pattern.success_count} < {self.criteria.min_success_count})"
            )

        if pattern.average_latency_ms > self.criteria.max_average_latency_ms:
            missing_criteria.append(
                f"latency ({pattern.average_latency_ms:.0f}ms > "
                f"{self.criteria.max_average_latency_ms:.0f}ms)"
            )

        # Calculate days active (from last_used)
        days_active = 0
        if pattern.last_used:
            delta = datetime.now() - pattern.last_used
            days_active = max(1, delta.days)

        if days_active < self.criteria.min_days_active:
            missing_criteria.append(
                f"days_active ({days_active} < {self.criteria.min_days_active})"
            )

        # Count unique query contexts
        query_contexts = len(set(pattern.query_contexts))
        if query_contexts < self.criteria.min_query_contexts:
            missing_criteria.append(
                f"query_contexts ({query_contexts} < {self.criteria.min_query_contexts})"
            )

        # Calculate promotion score (0.0 - 1.0)
        score = self._calculate_promotion_score(pattern, days_active, query_contexts)

        return PromotionCandidate(
            tool_name=pattern.tool_name,
            server_id=pattern.server_id,
            agent_id=agent_id,
            usage_count=pattern.usage_count,
            success_rate=pattern.success_rate,
            average_latency_ms=pattern.average_latency_ms,
            days_active=days_active,
            query_contexts=query_contexts,
            promotion_score=score,
            meets_criteria=len(missing_criteria) == 0,
            missing_criteria=missing_criteria,
        )

    def _calculate_promotion_score(
        self,
        pattern: ToolUsagePattern,
        days_active: int,
        query_contexts: int,
    ) -> float:
        """Calculate promotion score for a pattern.

        Args:
            pattern: Usage pattern
            days_active: Days since first usage
            query_contexts: Number of unique query contexts

        Returns:
            Score between 0.0 and 1.0
        """
        # Weight factors
        usage_weight = 0.3
        success_weight = 0.4
        diversity_weight = 0.2
        longevity_weight = 0.1

        # Normalize usage count (log scale, capped at 1000)
        import math

        usage_score = min(math.log10(pattern.usage_count + 1) / 3, 1.0)

        # Success rate is already 0-1
        success_score = pattern.success_rate

        # Normalize query diversity (capped at 20)
        diversity_score = min(query_contexts / 20, 1.0)

        # Normalize longevity (capped at 30 days)
        longevity_score = min(days_active / 30, 1.0)

        return (
            usage_score * usage_weight
            + success_score * success_weight
            + diversity_score * diversity_weight
            + longevity_score * longevity_weight
        )
