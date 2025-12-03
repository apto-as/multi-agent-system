"""Learning Loop Service for TMWS Autonomous Learning System.

Orchestrates the continuous improvement pipeline (Layer 3):
- Validates detected patterns against quality thresholds
- Promotes validated patterns to Skills
- Monitors skill performance and collects feedback
- Adjusts detection thresholds based on feedback

Architecture: Layer 3 of TMWS Native Autonomous Learning
- Receives patterns from Layer 2 (PatternDetectionService)
- Creates skills via SkillService
- Prepares data for Layer 4 (ProactiveContextService)

Performance Targets:
- run_learning_cycle(): <500ms P95
- validate_pattern(): <100ms P95
- promote_to_skill(): <200ms P95
- collect_feedback(): <100ms P95

Security:
- P0-1 Namespace isolation enforced
- Skill quota (circuit breaker): max 10 promotions/hour
- Race condition protection with asyncio.Lock
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import Integer, and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import ValidationError
from ..models.execution_trace import DetectedPattern, SkillSuggestion
from .base_service import BaseService
from .pattern_detection_service import PatternDetectionService
from .skill_service import SkillService

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of pattern validation."""

    pattern_id: str
    passed: bool
    scores: dict[str, float] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    elapsed_ms: float = 0.0


@dataclass
class PromotionResult:
    """Result of skill promotion."""

    pattern_id: str
    skill_id: str | None
    success: bool
    error: str | None = None
    elapsed_ms: float = 0.0


@dataclass
class FeedbackResult:
    """Result of feedback collection."""

    total_suggestions: int
    activation_rate: float
    helpfulness_rate: float
    patterns_updated: int
    elapsed_ms: float = 0.0


@dataclass
class LearningCycleResult:
    """Result of one learning cycle iteration."""

    validated: int
    approved: int
    promoted: int
    feedback_collected: int
    elapsed_ms: float
    errors: list[str] = field(default_factory=list)


class LearningLoopService(BaseService):
    """Service for continuous improvement pipeline (Layer 3).

    Implements the Event-Driven Pipeline with Circuit Breakers (Hera's Option B+):
    - Parallel validation of patterns
    - Skill quota enforcement
    - Feedback-based threshold adjustment
    - Race condition protection

    Key Features:
    - Pattern validation with multi-metric scoring
    - Skill creation from approved patterns
    - Performance monitoring and feedback loops
    - asyncio.Lock for promotion serialization
    - P0-1 namespace isolation compliance
    """

    # Circuit breaker limits
    MAX_PROMOTIONS_PER_HOUR = 10
    MIN_VALIDATION_INTERVAL_HOURS = 6
    REVALIDATION_PERIOD_DAYS = 30
    SKILL_DEPRECATION_DAYS = 90

    # Validation thresholds (adjustable via feedback)
    DEFAULT_STABILITY_THRESHOLD = 0.8
    DEFAULT_SUCCESS_RATE_THRESHOLD = 0.75
    DEFAULT_RELEVANCE_THRESHOLD = 0.6

    # Security-sensitive tools to exclude
    SECURITY_SENSITIVE_TOOLS = frozenset([
        "delete_file",
        "delete_directory",
        "rm",
        "rmdir",
        "drop_table",
        "truncate_table",
        "execute_raw_sql",
        "eval",
        "exec",
        "system",
        "shell_exec",
        "subprocess",
    ])

    def __init__(
        self,
        session: AsyncSession,
        pattern_service: PatternDetectionService | None = None,
        skill_service: SkillService | None = None,
    ):
        """Initialize the learning loop service.

        Args:
            session: Async database session
            pattern_service: Pattern detection service (lazy-loaded)
            skill_service: Skill management service (lazy-loaded)
        """
        super().__init__(session)
        self._pattern_service = pattern_service
        self._skill_service = skill_service
        # Lock for promotion serialization
        self._promotion_locks: dict[str, asyncio.Lock] = {}
        # Threshold configuration (can be adjusted via feedback)
        self._thresholds = {
            "stability": self.DEFAULT_STABILITY_THRESHOLD,
            "success_rate": self.DEFAULT_SUCCESS_RATE_THRESHOLD,
            "relevance": self.DEFAULT_RELEVANCE_THRESHOLD,
        }
        # Promotion counter for quota enforcement
        self._promotion_count: dict[str, int] = {}  # namespace -> count
        self._promotion_reset_time: dict[str, datetime] = {}  # namespace -> reset time

    @property
    def pattern_service(self) -> PatternDetectionService:
        """Lazy-load PatternDetectionService."""
        if self._pattern_service is None:
            self._pattern_service = PatternDetectionService(self.session)
        return self._pattern_service

    @property
    def skill_service(self) -> SkillService:
        """Lazy-load SkillService."""
        if self._skill_service is None:
            self._skill_service = SkillService(session=self.session)
        return self._skill_service

    def _get_promotion_lock(self, pattern_id: str) -> asyncio.Lock:
        """Get or create a lock for a specific pattern.

        Args:
            pattern_id: Pattern UUID

        Returns:
            asyncio.Lock for the pattern
        """
        if pattern_id not in self._promotion_locks:
            self._promotion_locks[pattern_id] = asyncio.Lock()
        return self._promotion_locks[pattern_id]

    async def run_learning_cycle(
        self,
        namespace: str,
        max_validations: int = 10,
    ) -> LearningCycleResult:
        """Execute one learning cycle iteration.

        Phases:
        1. Validation: Validate DETECTED patterns (parallel)
        2. Approval Check: Notify about VALIDATED patterns
        3. Promotion: Promote APPROVED patterns to skills
        4. Feedback: Collect and process feedback

        Target latency: <500ms P95

        Args:
            namespace: Namespace for P0-1 isolation
            max_validations: Max patterns to validate per cycle

        Returns:
            LearningCycleResult with counts and timing
        """
        import time

        cycle_start = time.monotonic()
        errors: list[str] = []

        # Phase 1: Validation (parallel)
        validated_count = 0
        try:
            detected_patterns = await self.pattern_service.get_patterns_by_state(
                namespace=namespace,
                state="DETECTED",
                limit=max_validations,
            )

            if detected_patterns:
                validation_results = await asyncio.gather(
                    *[self.validate_pattern(p, namespace) for p in detected_patterns],
                    return_exceptions=True,
                )

                for result in validation_results:
                    if isinstance(result, Exception):
                        errors.append(str(result))
                    elif isinstance(result, ValidationResult) and result.passed:
                        validated_count += 1

        except Exception as e:
            errors.append(f"Validation phase error: {e}")
            logger.error(f"Validation phase error: {e}")

        # Phase 2: Check VALIDATED patterns (for notification)
        approved_count = 0
        try:
            validated_patterns = await self.pattern_service.get_patterns_by_state(
                namespace=namespace,
                state="VALIDATED",
                limit=100,
            )
            approved_count = len(validated_patterns)
            # In production, would send notifications here
        except Exception as e:
            errors.append(f"Approval check error: {e}")
            logger.error(f"Approval check error: {e}")

        # Phase 3: Promotion (APPROVED patterns only)
        promoted_count = 0
        try:
            approved_patterns = await self.pattern_service.get_patterns_by_state(
                namespace=namespace,
                state="APPROVED",
                limit=self.MAX_PROMOTIONS_PER_HOUR,
            )

            for pattern in approved_patterns:
                try:
                    result = await self.promote_to_skill(
                        pattern=pattern,
                        namespace=namespace,
                        approved_by="learning-system",
                    )
                    if result.success:
                        promoted_count += 1
                except Exception as e:
                    errors.append(f"Promotion error for {pattern.id}: {e}")

        except Exception as e:
            errors.append(f"Promotion phase error: {e}")
            logger.error(f"Promotion phase error: {e}")

        # Phase 4: Feedback collection
        feedback_count = 0
        try:
            feedback = await self.collect_feedback(namespace)
            feedback_count = feedback.patterns_updated
        except Exception as e:
            errors.append(f"Feedback collection error: {e}")
            logger.error(f"Feedback collection error: {e}")

        elapsed = (time.monotonic() - cycle_start) * 1000

        logger.info(
            f"Learning cycle complete for {namespace}: "
            f"validated={validated_count}, approved={approved_count}, "
            f"promoted={promoted_count}, feedback={feedback_count}, "
            f"elapsed={elapsed:.1f}ms"
        )

        return LearningCycleResult(
            validated=validated_count,
            approved=approved_count,
            promoted=promoted_count,
            feedback_collected=feedback_count,
            elapsed_ms=elapsed,
            errors=errors,
        )

    async def validate_pattern(
        self,
        pattern: DetectedPattern,
        namespace: str,
    ) -> ValidationResult:
        """Validate pattern against quality thresholds.

        Target latency: <100ms P95

        Checks:
        1. Stability: >80% occurrence rate (14-day window)
        2. Success rate: >75% tool executions succeed
        3. No security-sensitive tools
        4. No trivial patterns (<2 tools)

        Args:
            pattern: DetectedPattern to validate
            namespace: Namespace for P0-1 validation

        Returns:
            ValidationResult with scores and pass/fail
        """
        import time

        start = time.monotonic()
        errors: list[str] = []
        scores: dict[str, float] = {}

        # Namespace validation
        if pattern.namespace != namespace:
            return ValidationResult(
                pattern_id=str(pattern.id),
                passed=False,
                errors=["Namespace mismatch"],
                elapsed_ms=(time.monotonic() - start) * 1000,
            )

        # 1. Check success rate from pattern data
        success_rate = pattern.avg_success_rate or 0.0
        scores["success_rate"] = success_rate
        if success_rate < self._thresholds["success_rate"]:
            errors.append(
                f"Success rate too low: {success_rate:.1%} < "
                f"{self._thresholds['success_rate']:.1%}"
            )

        # 2. Check stability (frequency threshold)
        frequency = pattern.frequency or 0
        # Stability = frequency / expected_occurrences
        # For 14-day window, expect at least 3 occurrences
        stability = min(1.0, frequency / 14.0)  # Normalize to 0-1
        scores["stability"] = stability
        if stability < self._thresholds["stability"]:
            errors.append(
                f"Pattern not stable enough: {stability:.1%} < "
                f"{self._thresholds['stability']:.1%}"
            )

        # 3. Security check
        tools = pattern.tool_sequence or []
        sensitive_tools = set(tools) & self.SECURITY_SENSITIVE_TOOLS
        if sensitive_tools:
            errors.append(f"Security-sensitive tools detected: {sensitive_tools}")
            scores["security"] = 0.0
        else:
            scores["security"] = 1.0

        # 4. Trivial pattern check
        if len(tools) < 2:
            errors.append(f"Pattern too trivial: only {len(tools)} tool(s)")
            scores["complexity"] = 0.0
        else:
            scores["complexity"] = min(1.0, len(tools) / 5.0)  # Normalize

        # Determine pass/fail
        passed = len(errors) == 0

        # If passed, transition to VALIDATING
        if passed:
            try:
                await self.pattern_service.transition_pattern_state(
                    pattern_id=pattern.id,
                    new_state="VALIDATING",
                    actor_id="learning-system",
                    namespace=namespace,
                )
                logger.info(f"Pattern {pattern.id} validated, transitioning to VALIDATING")
            except Exception as e:
                passed = False
                errors.append(f"State transition failed: {e}")

        elapsed = (time.monotonic() - start) * 1000

        return ValidationResult(
            pattern_id=str(pattern.id),
            passed=passed,
            scores=scores,
            errors=errors,
            elapsed_ms=elapsed,
        )

    async def approve_pattern(
        self,
        pattern_id: str | UUID,
        namespace: str,
        approved_by: str,
    ) -> DetectedPattern:
        """Approve a validated pattern for skill promotion.

        Args:
            pattern_id: Pattern UUID
            namespace: Namespace for P0-1 validation
            approved_by: Agent ID approving the pattern

        Returns:
            Updated DetectedPattern

        Raises:
            NotFoundError: If pattern not found
            ValidationError: If pattern not in VALIDATED state
        """
        pattern = await self.pattern_service.get_pattern_by_id(pattern_id, namespace)

        if pattern.state != "VALIDATED":
            raise ValidationError(
                f"Pattern must be in VALIDATED state to approve. "
                f"Current state: {pattern.state}"
            )

        # Transition to APPROVED
        pattern = await self.pattern_service.transition_pattern_state(
            pattern_id=pattern_id,
            new_state="APPROVED",
            actor_id=approved_by,
            namespace=namespace,
        )

        logger.info(f"Pattern {pattern_id} approved by {approved_by}")

        return pattern

    async def promote_to_skill(
        self,
        pattern: DetectedPattern,
        namespace: str,
        approved_by: str,
    ) -> PromotionResult:
        """Promote approved pattern to Skill.

        Target latency: <200ms P95 (async, non-blocking)

        Steps:
        1. Check skill quota (circuit breaker)
        2. Generate skill content from SOP draft
        3. Create skill via SkillService
        4. Link pattern to skill

        Args:
            pattern: Approved DetectedPattern
            namespace: Namespace for P0-1 validation
            approved_by: Agent ID who approved

        Returns:
            PromotionResult with skill_id if successful
        """
        import time

        start = time.monotonic()
        pattern_id_str = str(pattern.id)

        # Acquire lock for this pattern
        lock = self._get_promotion_lock(pattern_id_str)

        async with lock:
            try:
                # 1. Check skill quota
                if not self._check_quota(namespace):
                    return PromotionResult(
                        pattern_id=pattern_id_str,
                        skill_id=None,
                        success=False,
                        error=f"Skill quota exceeded: {self.MAX_PROMOTIONS_PER_HOUR}/hour",
                        elapsed_ms=(time.monotonic() - start) * 1000,
                    )

                # 2. Validate pattern state
                if pattern.state != "APPROVED":
                    return PromotionResult(
                        pattern_id=pattern_id_str,
                        skill_id=None,
                        success=False,
                        error=f"Pattern not in APPROVED state: {pattern.state}",
                        elapsed_ms=(time.monotonic() - start) * 1000,
                    )

                # 3. Generate skill content
                if not pattern.sop_draft:
                    # Generate SOP draft if not exists
                    await self.pattern_service.generate_sop_draft(pattern)

                skill_name = self._generate_skill_name(pattern)
                skill_content = pattern.sop_draft or self._generate_default_content(pattern)

                # 4. Create skill via SkillService
                try:
                    skill_dto = await self.skill_service.create_skill(
                        name=skill_name,
                        namespace=namespace,
                        content=skill_content,
                        created_by=approved_by,
                        display_name=pattern.sop_title or skill_name,
                        description=f"Auto-generated from pattern {pattern.pattern_hash[:8]}",
                        persona="learning",
                        tags=["auto-generated", "pattern-based"],
                    )
                    skill_id = str(skill_dto.id)
                except Exception as e:
                    logger.error(f"Skill creation failed: {e}")
                    return PromotionResult(
                        pattern_id=pattern_id_str,
                        skill_id=None,
                        success=False,
                        error=f"Skill creation failed: {e}",
                        elapsed_ms=(time.monotonic() - start) * 1000,
                    )

                # 5. Link pattern to skill
                await self.pattern_service.link_pattern_to_skill(
                    pattern_id=pattern.id,
                    skill_id=skill_id,
                    namespace=namespace,
                )

                # 6. Update quota counter
                self._increment_quota(namespace)

                elapsed = (time.monotonic() - start) * 1000

                logger.info(
                    f"Pattern {pattern_id_str[:8]} promoted to skill {skill_id} "
                    f"in {elapsed:.1f}ms"
                )

                return PromotionResult(
                    pattern_id=pattern_id_str,
                    skill_id=skill_id,
                    success=True,
                    elapsed_ms=elapsed,
                )

            except Exception as e:
                logger.error(f"Promotion failed for pattern {pattern_id_str}: {e}")
                return PromotionResult(
                    pattern_id=pattern_id_str,
                    skill_id=None,
                    success=False,
                    error=str(e),
                    elapsed_ms=(time.monotonic() - start) * 1000,
                )

    async def collect_feedback(
        self,
        namespace: str,
        days: int = 7,
    ) -> FeedbackResult:
        """Collect effectiveness feedback from SkillSuggestion records.

        Target latency: <100ms P95

        Args:
            namespace: Namespace for P0-1 isolation
            days: Number of days to look back

        Returns:
            FeedbackResult with metrics
        """
        import time

        start = time.monotonic()

        since = datetime.now(timezone.utc) - timedelta(days=days)

        # Get recent skill suggestions
        result = await self.session.execute(
            select(SkillSuggestion).where(
                and_(
                    SkillSuggestion.namespace == namespace,
                    SkillSuggestion.created_at >= since,
                )
            )
        )
        suggestions = list(result.scalars().all())

        total = len(suggestions)
        activated = sum(1 for s in suggestions if s.was_activated)
        helpful = sum(1 for s in suggestions if s.was_helpful)

        activation_rate = activated / total if total > 0 else 0.0
        helpfulness_rate = helpful / activated if activated > 0 else 0.0

        # Group feedback by pattern
        pattern_feedback: dict[str, dict[str, int]] = {}
        for suggestion in suggestions:
            pid = str(suggestion.pattern_id) if suggestion.pattern_id else None
            if pid:
                if pid not in pattern_feedback:
                    pattern_feedback[pid] = {
                        "activations": 0,
                        "helpful": 0,
                        "total": 0,
                    }
                pattern_feedback[pid]["total"] += 1
                if suggestion.was_activated:
                    pattern_feedback[pid]["activations"] += 1
                if suggestion.was_helpful:
                    pattern_feedback[pid]["helpful"] += 1

        # Update pattern metadata with feedback
        patterns_updated = 0
        for pid, metrics in pattern_feedback.items():
            try:
                pattern = await self.session.get(DetectedPattern, pid)
                if pattern and pattern.namespace == namespace:
                    # Update validation_metadata with feedback
                    current_metadata = pattern.validation_metadata or {}
                    current_metadata["feedback"] = metrics
                    current_metadata["feedback_updated_at"] = datetime.now(
                        timezone.utc
                    ).isoformat()
                    pattern.validation_metadata = current_metadata
                    patterns_updated += 1
            except Exception as e:
                logger.warning(f"Failed to update pattern {pid} with feedback: {e}")

        await self.session.flush()

        elapsed = (time.monotonic() - start) * 1000

        logger.info(
            f"Collected feedback for {namespace}: "
            f"total={total}, activation_rate={activation_rate:.1%}, "
            f"helpfulness_rate={helpfulness_rate:.1%}"
        )

        return FeedbackResult(
            total_suggestions=total,
            activation_rate=activation_rate,
            helpfulness_rate=helpfulness_rate,
            patterns_updated=patterns_updated,
            elapsed_ms=elapsed,
        )

    async def adjust_thresholds(
        self,
        feedback: FeedbackResult,
    ) -> dict[str, Any]:
        """Adjust detection thresholds based on feedback.

        Strategy:
        - If activation_rate < 0.3: Increase thresholds (fewer skills)
        - If activation_rate > 0.7: Decrease thresholds (more skills)
        - If helpfulness_rate < 0.5: Increase relevance threshold

        Args:
            feedback: FeedbackResult from collect_feedback

        Returns:
            Dict with old and new thresholds
        """
        old_thresholds = dict(self._thresholds)

        # Adjust stability threshold based on activation rate
        if feedback.activation_rate < 0.3:
            self._thresholds["stability"] = min(
                self._thresholds["stability"] + 0.05,
                0.95,  # max
            )
        elif feedback.activation_rate > 0.7:
            self._thresholds["stability"] = max(
                self._thresholds["stability"] - 0.05,
                0.7,  # min
            )

        # Adjust relevance threshold based on helpfulness
        if feedback.helpfulness_rate < 0.5:
            self._thresholds["relevance"] = min(
                self._thresholds["relevance"] + 0.05,
                0.8,  # max
            )

        logger.info(
            f"Thresholds adjusted: old={old_thresholds}, new={self._thresholds}, "
            f"reason=activation_rate={feedback.activation_rate:.1%}, "
            f"helpfulness={feedback.helpfulness_rate:.1%}"
        )

        return {
            "old_thresholds": old_thresholds,
            "new_thresholds": dict(self._thresholds),
            "activation_rate": feedback.activation_rate,
            "helpfulness_rate": feedback.helpfulness_rate,
        }

    async def get_learning_statistics(
        self,
        namespace: str,
        since: datetime | None = None,
    ) -> dict[str, Any]:
        """Get learning loop statistics.

        Args:
            namespace: Namespace for P0-1 isolation
            since: Statistics since this time

        Returns:
            Statistics dictionary
        """
        since = since or (datetime.now(timezone.utc) - timedelta(days=30))

        # Get pattern statistics
        pattern_stats = await self.pattern_service.get_pattern_statistics(
            namespace=namespace,
            since=since,
        )

        # Get skill suggestion statistics
        result = await self.session.execute(
            select(
                func.count(SkillSuggestion.id).label("total"),
                func.sum(
                    func.cast(SkillSuggestion.was_activated, Integer)
                ).label("activated"),
                func.sum(
                    func.cast(SkillSuggestion.was_helpful, Integer)
                ).label("helpful"),
            ).where(
                and_(
                    SkillSuggestion.namespace == namespace,
                    SkillSuggestion.created_at >= since,
                )
            )
        )
        suggestion_row = result.one()
        total_suggestions = suggestion_row.total or 0
        activated = suggestion_row.activated or 0
        helpful = suggestion_row.helpful or 0

        return {
            "namespace": namespace,
            "since": since.isoformat(),
            "patterns": pattern_stats,
            "suggestions": {
                "total": total_suggestions,
                "activated": activated,
                "helpful": helpful,
                "activation_rate": activated / total_suggestions if total_suggestions > 0 else 0,
                "helpfulness_rate": helpful / activated if activated > 0 else 0,
            },
            "thresholds": dict(self._thresholds),
            "quota": {
                "max_per_hour": self.MAX_PROMOTIONS_PER_HOUR,
                "current": self._promotion_count.get(namespace, 0),
            },
        }

    def _check_quota(self, namespace: str) -> bool:
        """Check if promotion quota allows another promotion.

        Args:
            namespace: Namespace to check

        Returns:
            True if promotion allowed, False if quota exceeded
        """
        now = datetime.now(timezone.utc)

        # Check if reset time has passed
        reset_time = self._promotion_reset_time.get(namespace)
        if reset_time and now >= reset_time:
            self._promotion_count[namespace] = 0
            self._promotion_reset_time[namespace] = now + timedelta(hours=1)

        # Initialize if needed
        if namespace not in self._promotion_count:
            self._promotion_count[namespace] = 0
            self._promotion_reset_time[namespace] = now + timedelta(hours=1)

        return self._promotion_count[namespace] < self.MAX_PROMOTIONS_PER_HOUR

    def _increment_quota(self, namespace: str) -> None:
        """Increment promotion counter for namespace.

        Args:
            namespace: Namespace to increment
        """
        if namespace not in self._promotion_count:
            self._promotion_count[namespace] = 0
        self._promotion_count[namespace] += 1

    def _generate_skill_name(self, pattern: DetectedPattern) -> str:
        """Generate skill name from pattern.

        Args:
            pattern: DetectedPattern

        Returns:
            Skill name (lowercase, alphanumeric, hyphens)
        """
        tools = pattern.tool_sequence or []
        if not tools:
            return f"pattern-{pattern.pattern_hash[:8]}"

        # Take first and last tool names
        first = tools[0].replace("_", "-").lower()
        last = tools[-1].replace("_", "-").lower() if len(tools) > 1 else ""

        if len(tools) == 1:
            name = first
        elif len(tools) == 2:
            name = f"{first}-to-{last}"
        else:
            name = f"{first}-to-{last}-{len(tools)}step"

        # Append hash for uniqueness
        return f"{name}-{pattern.pattern_hash[:6]}"

    def _generate_default_content(self, pattern: DetectedPattern) -> str:
        """Generate default skill content if SOP draft not available.

        Args:
            pattern: DetectedPattern

        Returns:
            Markdown skill content
        """
        tools = pattern.tool_sequence or []
        return f"""# Auto-Generated Skill

## Pattern Information

- **Pattern Hash**: `{pattern.pattern_hash[:16]}...`
- **Frequency**: {pattern.frequency}
- **Success Rate**: {(pattern.avg_success_rate or 0) * 100:.1f}%

## Tool Sequence

{chr(10).join(f'{i+1}. `{tool}`' for i, tool in enumerate(tools))}

## Usage

This skill was automatically generated from a detected tool execution pattern.
Please review and customize before using in production.
"""
