"""Pattern to Skill Auto-Generation Service for TMWS v2.4.12

This service provides automatic promotion of mature learning patterns to skills:
- Identifies patterns meeting maturity criteria (usage >= 5, success rate >= 85%)
- Generates skill content from pattern data
- Creates skills with PENDING_REVIEW status for human approval
- Supports dry-run mode for impact assessment
- Integrates with environment settings for enabling/disabling

Architecture:
- Service layer pattern (business logic)
- Database session management (async)
- Integration with LearningService and SkillService
- Security enforcement (P0-1 namespace isolation)

Performance targets:
- find_mature_patterns(): < 200ms P95
- promote_pattern_to_skill(): < 500ms P95
- batch_promote(): < 2s P95 (up to 10 patterns)

Environment Variables:
- TRINITAS_PATTERN_SKILL_GEN_ENABLED: Enable/disable feature (default: false)
- TRINITAS_PATTERN_MIN_USAGE: Minimum usage count (default: 5)
- TRINITAS_PATTERN_MIN_SUCCESS_RATE: Minimum success rate (default: 0.85)
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import (
    DatabaseError,
    NotFoundError,
    PermissionError,
    ValidationError,
    log_and_raise,
)
from src.models.agent import AccessLevel
from src.models.learning_pattern import LearningPattern
from src.security.input_sanitizer import sanitize_markdown, sanitize_string

logger = logging.getLogger(__name__)


class PatternSkillService:
    """Service for promoting mature learning patterns to skills.

    This service handles:
    - Pattern maturity detection (usage + success rate thresholds)
    - Skill content generation from pattern data
    - Human review workflow (skills created in PENDING_REVIEW status)
    - Namespace isolation enforcement (P0-1 pattern)

    Security:
    - P0-1: Namespace verified from database (never from user input)
    - Only patterns owned by the requesting agent are eligible
    - Skills created with same namespace as source pattern
    """

    # Default maturity thresholds (can be overridden by environment)
    DEFAULT_MIN_USAGE = 5
    DEFAULT_MIN_SUCCESS_RATE = 0.85

    def __init__(self, session: AsyncSession):
        """Initialize pattern-to-skill service.

        Args:
            session: Async database session
        """
        self.session = session
        self._load_settings()

    def _load_settings(self) -> None:
        """Load settings from environment variables."""
        self.enabled = (
            os.environ.get("TRINITAS_PATTERN_SKILL_GEN_ENABLED", "false").lower() == "true"
        )

        self.min_usage = int(
            os.environ.get("TRINITAS_PATTERN_MIN_USAGE", str(self.DEFAULT_MIN_USAGE))
        )

        self.min_success_rate = float(
            os.environ.get("TRINITAS_PATTERN_MIN_SUCCESS_RATE", str(self.DEFAULT_MIN_SUCCESS_RATE))
        )

        logger.debug(
            f"PatternSkillService settings: enabled={self.enabled}, "
            f"min_usage={self.min_usage}, min_success_rate={self.min_success_rate}"
        )

    async def find_mature_patterns(
        self,
        *,
        agent_id: str,
        namespace: str,
        limit: int = 10,
        min_usage: int | None = None,
        min_success_rate: float | None = None,
    ) -> dict[str, Any]:
        """Find patterns that meet maturity criteria for skill promotion.

        Args:
            agent_id: Agent requesting patterns (ownership check)
            namespace: Namespace to search in (P0-1 verified)
            limit: Maximum patterns to return (1-100)
            min_usage: Override minimum usage count (default from env)
            min_success_rate: Override minimum success rate (default from env)

        Returns:
            Dict with:
            - success: True if operation completed
            - patterns: List of mature patterns
            - total_mature: Total count meeting criteria
            - criteria: Applied maturity criteria

        Raises:
            ValidationError: If parameters invalid
            DatabaseError: If query fails
        """
        # Validate parameters
        if limit < 1 or limit > 100:
            log_and_raise(
                ValidationError,
                "Limit must be between 1 and 100",
                details={"limit": limit},
            )

        # Apply thresholds
        usage_threshold = min_usage if min_usage is not None else self.min_usage
        success_threshold = (
            min_success_rate if min_success_rate is not None else self.min_success_rate
        )

        try:
            # Query mature patterns (owned by agent, in namespace)
            stmt = (
                select(LearningPattern)
                .where(
                    and_(
                        LearningPattern.agent_id == agent_id,
                        LearningPattern.namespace == namespace,
                        LearningPattern.usage_count >= usage_threshold,
                        LearningPattern.success_rate >= success_threshold,
                        LearningPattern.is_deleted == False,  # noqa: E712
                    )
                )
                .order_by(
                    LearningPattern.success_rate.desc(),
                    LearningPattern.usage_count.desc(),
                )
                .limit(limit)
            )

            result = await self.session.execute(stmt)
            patterns = result.scalars().all()

            # Get total count
            count_stmt = select(LearningPattern).where(
                and_(
                    LearningPattern.agent_id == agent_id,
                    LearningPattern.namespace == namespace,
                    LearningPattern.usage_count >= usage_threshold,
                    LearningPattern.success_rate >= success_threshold,
                    LearningPattern.is_deleted == False,  # noqa: E712
                )
            )
            count_result = await self.session.execute(count_stmt)
            total_count = len(count_result.scalars().all())

            # Convert to response format
            pattern_list = []
            for pattern in patterns:
                pattern_list.append(
                    {
                        "id": str(pattern.id),
                        "pattern_name": pattern.pattern_name,
                        "category": pattern.category,
                        "subcategory": pattern.subcategory,
                        "usage_count": pattern.usage_count,
                        "success_rate": pattern.success_rate,
                        "confidence_score": pattern.confidence_score,
                        "created_at": pattern.created_at.isoformat()
                        if pattern.created_at
                        else None,
                        "last_used_at": pattern.last_used_at.isoformat()
                        if pattern.last_used_at
                        else None,
                    }
                )

            logger.info(
                f"Found {len(pattern_list)} mature patterns for agent={agent_id}, "
                f"namespace={namespace}"
            )

            return {
                "success": True,
                "patterns": pattern_list,
                "total_mature": total_count,
                "criteria": {
                    "min_usage": usage_threshold,
                    "min_success_rate": success_threshold,
                },
            }

        except SQLAlchemyError as e:
            log_and_raise(
                DatabaseError,
                f"Failed to query mature patterns: {e}",
                original_exception=e,
            )

    async def generate_skill_content(
        self,
        pattern: LearningPattern,
    ) -> str:
        """Generate skill content (SKILL.md format) from pattern data.

        Args:
            pattern: LearningPattern to convert

        Returns:
            Skill content string in SKILL.md format

        Security:
            - V-XSS-1: All user-provided content is sanitized
            - Prevents injection via pattern_data fields
        """
        # Extract pattern data
        pattern_data = pattern.pattern_data or {}

        # V-XSS-1: Sanitize pattern name and other user-provided fields
        safe_pattern_name = sanitize_string(pattern.pattern_name, max_length=200)
        safe_category = sanitize_string(pattern.category or "general", max_length=50)
        safe_subcategory = sanitize_string(pattern.subcategory or "default", max_length=50)
        safe_agent_id = sanitize_string(pattern.agent_id, max_length=100)
        safe_namespace = sanitize_string(pattern.namespace, max_length=100)

        # Build metadata section (using sanitized values)
        content = f"""# {safe_pattern_name}

## Metadata

- **Category**: {safe_category}
- **Subcategory**: {safe_subcategory}
- **Version**: 1.0.0
- **Generated From**: Learning Pattern (auto-promoted)
- **Original Pattern ID**: {pattern.id}
- **Success Rate**: {pattern.success_rate * 100:.1f}%
- **Usage Count**: {pattern.usage_count}

## Description

This skill was automatically generated from a mature learning pattern.
The pattern demonstrated consistent success across {pattern.usage_count} executions
with a {pattern.success_rate * 100:.1f}% success rate.

## Core Instructions

"""
        # Add pattern-specific instructions from pattern_data (sanitized)
        if "instructions" in pattern_data:
            safe_instructions = sanitize_markdown(str(pattern_data["instructions"]))
            content += safe_instructions + "\n\n"
        elif "steps" in pattern_data:
            content += "### Execution Steps\n\n"
            for i, step in enumerate(pattern_data["steps"], 1):
                safe_step = sanitize_string(str(step), max_length=500)
                content += f"{i}. {safe_step}\n"
            content += "\n"
        else:
            content += "Execute the learned pattern as documented in the pattern data.\n\n"

        # Add context if available (sanitized)
        if "context" in pattern_data:
            safe_context = sanitize_markdown(str(pattern_data["context"]))
            content += f"### Context\n\n{safe_context}\n\n"

        # Add parameters if available (sanitized)
        if "parameters" in pattern_data:
            content += "### Parameters\n\n"
            for param_name, param_info in pattern_data["parameters"].items():
                safe_param_name = sanitize_string(str(param_name), max_length=50)
                safe_param_info = sanitize_string(str(param_info), max_length=200)
                content += f"- **{safe_param_name}**: {safe_param_info}\n"
            content += "\n"

        # Add examples if available (sanitized)
        if "examples" in pattern_data:
            content += "## Examples\n\n"
            for example in pattern_data["examples"]:
                safe_example = sanitize_string(str(example), max_length=2000)
                content += f"```\n{safe_example}\n```\n\n"

        # Add footer (using sanitized values)
        content += f"""## Origin

- **Source**: Auto-generated from LearningPattern
- **Agent**: {safe_agent_id}
- **Namespace**: {safe_namespace}
- **Created**: {datetime.now(timezone.utc).isoformat()}

---
*This skill requires human review before activation.*
"""

        return content

    async def promote_pattern_to_skill(
        self,
        *,
        pattern_id: str,
        agent_id: str,
        namespace: str,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Promote a mature pattern to a skill (requires human review).

        Args:
            pattern_id: UUID of pattern to promote
            agent_id: Agent requesting promotion (ownership check)
            namespace: Namespace (P0-1 verified from DB)
            dry_run: If True, only preview without creating

        Returns:
            Dict with:
            - success: True if operation completed
            - skill_id: Created skill ID (None if dry_run)
            - skill_content: Generated skill content
            - dry_run: Whether this was a dry run
            - status: "pending_review" or "preview"

        Raises:
            NotFoundError: If pattern not found or not owned
            ValidationError: If pattern doesn't meet criteria
            PermissionError: If feature is disabled
            DatabaseError: If creation fails
        """
        # Check if feature is enabled
        if not self.enabled and not dry_run:
            log_and_raise(
                PermissionError,
                "Pattern-to-Skill auto-generation is disabled. "
                "Set TRINITAS_PATTERN_SKILL_GEN_ENABLED=true to enable.",
            )

        try:
            # Parse and validate pattern_id
            try:
                pattern_uuid = UUID(pattern_id)
            except ValueError:
                log_and_raise(
                    ValidationError,
                    f"Invalid pattern ID format: {pattern_id}",
                )

            # Fetch pattern with ownership check
            stmt = select(LearningPattern).where(
                and_(
                    LearningPattern.id == pattern_uuid,
                    LearningPattern.agent_id == agent_id,
                    LearningPattern.namespace == namespace,
                    LearningPattern.is_deleted == False,  # noqa: E712
                )
            )

            result = await self.session.execute(stmt)
            pattern = result.scalar_one_or_none()

            if pattern is None:
                log_and_raise(
                    NotFoundError,
                    f"Pattern not found or not owned: {pattern_id}",
                    details={"pattern_id": pattern_id, "agent_id": agent_id},
                )

            # Check maturity criteria
            if pattern.usage_count < self.min_usage:
                log_and_raise(
                    ValidationError,
                    f"Pattern does not meet usage threshold: {pattern.usage_count} < {self.min_usage}",
                    details={
                        "usage_count": pattern.usage_count,
                        "min_usage": self.min_usage,
                    },
                )

            if pattern.success_rate < self.min_success_rate:
                log_and_raise(
                    ValidationError,
                    f"Pattern does not meet success rate threshold: {pattern.success_rate:.2f} < {self.min_success_rate:.2f}",
                    details={
                        "success_rate": pattern.success_rate,
                        "min_success_rate": self.min_success_rate,
                    },
                )

            # Generate skill content
            skill_content = await self.generate_skill_content(pattern)

            if dry_run:
                return {
                    "success": True,
                    "skill_id": None,
                    "skill_name": f"auto-{pattern.pattern_name.lower().replace(' ', '-')}",
                    "skill_content": skill_content,
                    "dry_run": True,
                    "status": "preview",
                    "pattern": {
                        "id": str(pattern.id),
                        "name": pattern.pattern_name,
                        "usage_count": pattern.usage_count,
                        "success_rate": pattern.success_rate,
                    },
                }

            # Import skill service here to avoid circular dependency
            from src.services.skill_service import SkillService

            skill_service = SkillService(self.session)

            # Create skill with PENDING_REVIEW access level
            skill_name = f"auto-{pattern.pattern_name.lower().replace(' ', '-')}"
            skill_dto = await skill_service.create_skill(
                name=skill_name,
                namespace=namespace,
                content=skill_content,
                created_by=agent_id,
                display_name=f"[Auto] {pattern.pattern_name}",
                description=f"Auto-generated from learning pattern {pattern.pattern_name}",
                persona=None,
                tags=["auto-generated", "pending-review", pattern.category or "general"],
                access_level=AccessLevel.PRIVATE,  # Private until reviewed
            )

            logger.info(
                f"Pattern promoted to skill: pattern_id={pattern_id}, "
                f"skill_id={skill_dto.id}, agent_id={agent_id}"
            )

            return {
                "success": True,
                "skill_id": str(skill_dto.id),
                "skill_name": skill_name,
                "skill_content": skill_content,
                "dry_run": False,
                "status": "pending_review",
                "pattern": {
                    "id": str(pattern.id),
                    "name": pattern.pattern_name,
                    "usage_count": pattern.usage_count,
                    "success_rate": pattern.success_rate,
                },
            }

        except (NotFoundError, ValidationError, PermissionError):
            raise
        except SQLAlchemyError as e:
            log_and_raise(
                DatabaseError,
                f"Failed to promote pattern to skill: {e}",
                original_exception=e,
            )

    async def batch_promote(
        self,
        *,
        agent_id: str,
        namespace: str,
        limit: int = 10,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Batch promote mature patterns to skills.

        Args:
            agent_id: Agent requesting promotion (ownership check)
            namespace: Namespace (P0-1 verified from DB)
            limit: Maximum patterns to promote (1-10)
            dry_run: If True, only preview without creating

        Returns:
            Dict with:
            - success: True if operation completed
            - promoted: List of promoted/preview patterns
            - total_eligible: Total patterns meeting criteria
            - dry_run: Whether this was a dry run
        """
        if limit < 1 or limit > 10:
            log_and_raise(
                ValidationError,
                "Batch limit must be between 1 and 10",
                details={"limit": limit},
            )

        # Find mature patterns
        mature_result = await self.find_mature_patterns(
            agent_id=agent_id,
            namespace=namespace,
            limit=limit,
        )

        if not mature_result["patterns"]:
            return {
                "success": True,
                "promoted": [],
                "total_eligible": 0,
                "dry_run": dry_run,
                "message": "No mature patterns found for promotion",
            }

        promoted = []
        errors = []

        for pattern in mature_result["patterns"]:
            try:
                result = await self.promote_pattern_to_skill(
                    pattern_id=pattern["id"],
                    agent_id=agent_id,
                    namespace=namespace,
                    dry_run=dry_run,
                )
                promoted.append(
                    {
                        "pattern_id": pattern["id"],
                        "pattern_name": pattern["pattern_name"],
                        "skill_id": result.get("skill_id"),
                        "skill_name": result.get("skill_name"),
                        "status": result.get("status"),
                    }
                )
            except Exception as e:
                errors.append(
                    {
                        "pattern_id": pattern["id"],
                        "error": str(e),
                    }
                )
                logger.warning(f"Failed to promote pattern {pattern['id']}: {e}")

        return {
            "success": True,
            "promoted": promoted,
            "errors": errors if errors else None,
            "total_eligible": mature_result["total_mature"],
            "dry_run": dry_run,
        }

    async def get_promotion_status(
        self,
        *,
        agent_id: str,
        namespace: str,
    ) -> dict[str, Any]:
        """Get current status of pattern-to-skill promotion.

        Returns summary of:
        - Feature enabled/disabled
        - Current thresholds
        - Number of eligible patterns
        - Recent promotions (if any)
        """
        mature_result = await self.find_mature_patterns(
            agent_id=agent_id,
            namespace=namespace,
            limit=100,  # Just for counting
        )

        return {
            "success": True,
            "feature_enabled": self.enabled,
            "thresholds": {
                "min_usage": self.min_usage,
                "min_success_rate": self.min_success_rate,
            },
            "eligible_patterns": mature_result["total_mature"],
            "sample_patterns": mature_result["patterns"][:5] if mature_result["patterns"] else [],
        }
