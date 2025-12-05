"""Learning-Trust Integration Service

Connects learning pattern success/failure to agent trust scores.

Architecture:
- Decoupled design (Option D - Hybrid Integration)
- Non-invasive integration with graceful degradation
- Security: V-TRUST-1/4 compliant (namespace isolation, verification required)
- Performance: <10ms P95

Design Philosophy:
- Pattern usage success → modest trust boost (+0.02)
- Pattern usage failure → modest trust penalty (-0.02)
- Public patterns only (prevents self-boosting via private patterns)
- Graceful degradation (pattern operations succeed even if trust update fails)

Security Model:
- V-TRUST-1: Automated updates require pattern_id as implicit verification
- V-TRUST-4: Namespace isolation enforced via TrustService
- Pattern ownership verified before trust propagation
- Only public/system patterns contribute to trust (prevents gaming)

Performance Targets:
- propagate_learning_success: <5ms P95
- propagate_learning_failure: <5ms P95
- evaluate_pattern_reliability: <3ms P95
- batch_update_from_patterns: <100ms for 100 patterns

@author Artemis
@version v2.2.6
@date 2025-11-10
"""

import logging
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import (
    AgentNotFoundError,
    AuthorizationError,
    DatabaseError,
    NotFoundError,
    ValidationError,
    log_and_raise,
)
from src.models.learning_pattern import LearningPattern
from src.services.trust_service import TrustService

logger = logging.getLogger(__name__)


class LearningTrustIntegration:
    """Integration service connecting learning patterns to agent trust scores

    This service implements Option D (Hybrid Integration) from Phase 1 design:
    - Lightweight trust updates for public pattern success/failure
    - Security-first: Only verified, public patterns affect trust
    - Performance-optimized: <10ms P95 for all operations
    - Non-invasive: Graceful degradation if trust update fails

    Key Design Decisions:
    1. Public patterns only (prevents gaming via self-owned private patterns)
    2. Modest trust delta (±0.02) to prevent rapid score manipulation
    3. Pattern ID as implicit verification (satisfies V-TRUST-1)
    4. Namespace isolation enforced (satisfies V-TRUST-4)
    5. Async-first for non-blocking integration

    Usage:
        ```python
        integration = LearningTrustIntegration(session)

        # After successful pattern usage
        new_score = await integration.propagate_learning_success(
            agent_id="agent-123",
            pattern_id=pattern.id,
            requesting_namespace="default"
        )

        # After failed pattern usage
        new_score = await integration.propagate_learning_failure(
            agent_id="agent-123",
            pattern_id=pattern.id,
            requesting_namespace="default"
        )
        ```

    Security:
        - V-TRUST-1: Uses pattern_id as verification_id for automated updates
        - V-TRUST-4: Namespace isolation via TrustService.update_trust_score()
        - Pattern access level validated before trust propagation
        - No manual override allowed (user=None enforced)

    Performance:
        - All operations <10ms P95
        - Database queries optimized with indexes
        - Minimal overhead to existing LearningService.use_pattern()
    """

    # Trust score deltas (aligned with TrustService EWMA alpha=0.1)
    TRUST_BOOST_SUCCESS = 0.02  # Modest boost for successful pattern usage
    TRUST_PENALTY_FAILURE = -0.02  # Modest penalty for failed pattern usage

    # Pattern reliability thresholds
    MIN_USAGE_FOR_RELIABILITY = 5  # Minimum uses before pattern considered reliable
    HIGH_RELIABILITY_THRESHOLD = 0.8  # 80%+ success rate = reliable
    LOW_RELIABILITY_THRESHOLD = 0.3  # <30% success rate = unreliable

    def __init__(self, session: AsyncSession):
        """Initialize Learning-Trust integration service

        Args:
            session: Database session (shared with LearningService)

        Performance: O(1) - instantaneous
        """
        self.session = session
        self.trust_service = TrustService(session)

    async def propagate_learning_success(
        self,
        agent_id: str,
        pattern_id: UUID,
        requesting_namespace: str,
    ) -> float:
        """Propagate learning pattern success to agent trust score

        Updates agent trust score when they successfully use a public pattern.
        This demonstrates the agent's ability to select and apply proven patterns,
        which is a reliability indicator.

        Security:
        - V-TRUST-1: Uses pattern_id as verification_id (implicit verification)
        - V-TRUST-4: Namespace isolation enforced via trust_service
        - Only public/system patterns boost trust (prevents self-gaming)
        - Pattern ownership verified before propagation

        Args:
            agent_id: Agent identifier
            pattern_id: Learning pattern UUID (used as verification context)
            requesting_namespace: Requesting namespace (for isolation check)

        Returns:
            New trust score (0.0-1.0)

        Raises:
            AgentNotFoundError: If agent doesn't exist or namespace mismatch
            NotFoundError: If pattern doesn't exist
            ValidationError: If pattern not eligible for trust propagation

        Performance: <5ms P95

        Example:
            ```python
            # After successful pattern usage in LearningService.use_pattern()
            if success and pattern.access_level in ["public", "system"]:
                try:
                    new_score = await integration.propagate_learning_success(
                        agent_id=using_agent_id,
                        pattern_id=pattern.id,
                        requesting_namespace=agent.namespace
                    )
                    logger.info(f"Trust boosted to {new_score} for {agent_id}")
                except Exception as e:
                    # Graceful degradation: Pattern usage succeeds even if trust fails
                    logger.warning(f"Trust update failed but pattern usage succeeded: {e}")
            ```
        """
        try:
            # Validate pattern eligibility
            pattern = await self._get_and_validate_pattern(
                pattern_id=pattern_id, agent_id=agent_id, operation="propagate_success"
            )

            # Update trust score via TrustService
            # Security: pattern_id serves as verification_id (V-TRUST-1)
            new_score = await self.trust_service.update_trust_score(
                agent_id=agent_id,
                accurate=True,  # Success = accurate pattern selection
                verification_id=pattern_id,  # Pattern usage is implicit verification
                reason=f"pattern_success:{pattern.pattern_name}",
                user=None,  # Automated update (not manual)
                requesting_namespace=requesting_namespace,
            )

            logger.info(
                f"Trust boosted for {agent_id}: pattern={pattern.pattern_name}, "
                f"new_score={new_score:.3f}"
            )

            return new_score

        except (AgentNotFoundError, NotFoundError, ValidationError, AuthorizationError):
            # Re-raise domain exceptions without wrapping
            raise
        except DatabaseError:
            # Re-raise DatabaseError without double-wrapping
            raise
        except Exception as e:
            # Wrap unexpected exceptions
            log_and_raise(
                DatabaseError,
                f"Failed to propagate learning success for agent {agent_id}",
                original_exception=e,
                details={
                    "agent_id": agent_id,
                    "pattern_id": str(pattern_id),
                    "requesting_namespace": requesting_namespace,
                },
            )

    async def propagate_learning_failure(
        self,
        agent_id: str,
        pattern_id: UUID,
        requesting_namespace: str,
    ) -> float:
        """Propagate learning pattern failure to agent trust score

        Updates agent trust score when they fail to successfully use a public pattern.
        This indicates potential issues with pattern selection or application,
        which affects reliability assessment.

        Security:
        - V-TRUST-1: Uses pattern_id as verification_id (implicit verification)
        - V-TRUST-4: Namespace isolation enforced via trust_service
        - Only public/system patterns affect trust (prevents gaming)

        Args:
            agent_id: Agent identifier
            pattern_id: Learning pattern UUID (used as verification context)
            requesting_namespace: Requesting namespace (for isolation check)

        Returns:
            New trust score (0.0-1.0)

        Raises:
            AgentNotFoundError: If agent doesn't exist or namespace mismatch
            NotFoundError: If pattern doesn't exist
            ValidationError: If pattern not eligible for trust propagation

        Performance: <5ms P95

        Example:
            ```python
            # After failed pattern usage in LearningService.use_pattern()
            if not success and pattern.access_level in ["public", "system"]:
                try:
                    new_score = await integration.propagate_learning_failure(
                        agent_id=using_agent_id,
                        pattern_id=pattern.id,
                        requesting_namespace=agent.namespace
                    )
                    logger.info(f"Trust penalized to {new_score} for {agent_id}")
                except Exception as e:
                    logger.warning(f"Trust update failed but pattern usage recorded: {e}")
            ```
        """
        try:
            # Validate pattern eligibility
            pattern = await self._get_and_validate_pattern(
                pattern_id=pattern_id, agent_id=agent_id, operation="propagate_failure"
            )

            # Update trust score via TrustService
            # Security: pattern_id serves as verification_id (V-TRUST-1)
            new_score = await self.trust_service.update_trust_score(
                agent_id=agent_id,
                accurate=False,  # Failure = inaccurate pattern selection/application
                verification_id=pattern_id,  # Pattern usage is implicit verification
                reason=f"pattern_failure:{pattern.pattern_name}",
                user=None,  # Automated update (not manual)
                requesting_namespace=requesting_namespace,
            )

            logger.info(
                f"Trust penalized for {agent_id}: pattern={pattern.pattern_name}, "
                f"new_score={new_score:.3f}"
            )

            return new_score

        except (AgentNotFoundError, NotFoundError, ValidationError, AuthorizationError):
            # Re-raise domain exceptions without wrapping
            raise
        except DatabaseError:
            # Re-raise DatabaseError without double-wrapping
            raise
        except Exception as e:
            # Wrap unexpected exceptions
            log_and_raise(
                DatabaseError,
                f"Failed to propagate learning failure for agent {agent_id}",
                original_exception=e,
                details={
                    "agent_id": agent_id,
                    "pattern_id": str(pattern_id),
                    "requesting_namespace": requesting_namespace,
                },
            )

    async def evaluate_pattern_reliability(self, pattern_id: UUID) -> dict[str, Any]:
        """Evaluate pattern reliability for trust scoring decisions

        Analyzes pattern usage statistics to determine if it's eligible for
        trust score propagation and what weight it should carry.

        Reliability Criteria:
        - Minimum usage count (>= 5 uses for statistical significance)
        - Success rate thresholds (>= 80% = reliable, < 30% = unreliable)
        - Public/system access level (prevents gaming)

        Args:
            pattern_id: Learning pattern UUID

        Returns:
            Dictionary with reliability assessment:
                {
                    "pattern_id": str,
                    "pattern_name": str,
                    "is_reliable": bool,
                    "reliability_score": float (0.0-1.0),
                    "usage_count": int,
                    "success_rate": float,
                    "access_level": str,
                    "eligible_for_trust": bool,
                    "recommendation": str
                }

        Raises:
            NotFoundError: If pattern doesn't exist

        Performance: <3ms P95

        Example:
            ```python
            reliability = await integration.evaluate_pattern_reliability(pattern.id)
            if reliability["eligible_for_trust"]:
                # Safe to propagate to trust score
                await integration.propagate_learning_success(...)
            else:
                logger.info(f"Pattern not reliable enough: {reliability['recommendation']}")
            ```
        """
        try:
            # Fetch pattern
            result = await self.session.execute(
                select(LearningPattern).where(LearningPattern.id == pattern_id)
            )
            pattern = result.scalar_one_or_none()

            if not pattern:
                log_and_raise(NotFoundError, "LearningPattern", str(pattern_id))

            # Calculate reliability metrics
            usage_count = pattern.usage_count
            success_rate = pattern.success_rate
            access_level = pattern.access_level

            # Reliability criteria
            has_sufficient_usage = usage_count >= self.MIN_USAGE_FOR_RELIABILITY
            is_high_success = success_rate >= self.HIGH_RELIABILITY_THRESHOLD
            is_low_success = success_rate < self.LOW_RELIABILITY_THRESHOLD
            is_public_or_system = access_level in ["public", "system"]

            # Reliability score (0.0-1.0)
            # Factors: usage count (40%), success rate (40%), access level (20%)
            usage_factor = min(usage_count / (self.MIN_USAGE_FOR_RELIABILITY * 2), 1.0)
            reliability_score = (
                usage_factor * 0.4
                + success_rate * 0.4
                + (1.0 if is_public_or_system else 0.5) * 0.2
            )

            # Overall reliability judgment
            is_reliable = has_sufficient_usage and is_high_success and is_public_or_system

            # Eligibility for trust propagation
            eligible_for_trust = is_public_or_system  # Minimum requirement

            # Recommendation message
            if not eligible_for_trust:
                recommendation = f"Pattern is {access_level}, not eligible for trust updates (must be public/system)"
            elif not has_sufficient_usage:
                recommendation = f"Needs {self.MIN_USAGE_FOR_RELIABILITY - usage_count} more uses for reliability"
            elif is_low_success:
                recommendation = "Low success rate (<30%), may penalize trust heavily"
            elif is_high_success:
                recommendation = "Highly reliable pattern (>80% success), boosts trust"
            else:
                recommendation = "Moderately reliable pattern (30-80% success)"

            return {
                "pattern_id": str(pattern.id),
                "pattern_name": pattern.pattern_name,
                "is_reliable": is_reliable,
                "reliability_score": reliability_score,
                "usage_count": usage_count,
                "success_rate": success_rate,
                "access_level": access_level,
                "eligible_for_trust": eligible_for_trust,
                "has_sufficient_usage": has_sufficient_usage,
                "recommendation": recommendation,
            }

        except NotFoundError:
            raise
        except Exception as e:
            log_and_raise(
                DatabaseError,
                f"Failed to evaluate pattern reliability for {pattern_id}",
                original_exception=e,
                details={"pattern_id": str(pattern_id)},
            )

    async def batch_update_from_patterns(
        self,
        updates: list[tuple[str, UUID, bool, str]],
    ) -> dict[str, float]:
        """Batch update trust scores from multiple pattern usages

        Efficiently processes multiple pattern usage events in a single transaction.
        Useful for analytics workflows or batch processing of historical data.

        Args:
            updates: List of (agent_id, pattern_id, success, requesting_namespace) tuples

        Returns:
            Dictionary mapping agent_id to new trust score

        Raises:
            AgentNotFoundError: If agent doesn't exist or namespace mismatch
            NotFoundError: If pattern doesn't exist

        Performance: <100ms for 100 updates (<1ms per update)

        Security:
            - V-TRUST-1: Each update uses pattern_id as verification
            - V-TRUST-4: Namespace isolation enforced per agent
            - Individual failures don't block batch (graceful degradation)

        Example:
            ```python
            updates = [
                ("agent-1", pattern_a.id, True, "namespace-1"),
                ("agent-2", pattern_b.id, False, "namespace-2"),
                ("agent-1", pattern_c.id, True, "namespace-1"),
            ]

            results = await integration.batch_update_from_patterns(updates)
            # results = {"agent-1": 0.72, "agent-2": 0.48}
            ```
        """
        results = {}
        errors = []

        for agent_id, pattern_id, success, requesting_namespace in updates:
            try:
                if success:
                    new_score = await self.propagate_learning_success(
                        agent_id=agent_id,
                        pattern_id=pattern_id,
                        requesting_namespace=requesting_namespace,
                    )
                else:
                    new_score = await self.propagate_learning_failure(
                        agent_id=agent_id,
                        pattern_id=pattern_id,
                        requesting_namespace=requesting_namespace,
                    )

                results[agent_id] = new_score

            except Exception as e:
                # Graceful degradation: Log error but continue with other updates
                errors.append(
                    {
                        "agent_id": agent_id,
                        "pattern_id": str(pattern_id),
                        "success": success,
                        "error": str(e),
                    }
                )
                logger.warning(f"Failed to update trust for {agent_id} (pattern {pattern_id}): {e}")

        # Log summary
        logger.info(f"Batch update complete: {len(results)} successful, {len(errors)} failed")

        if errors:
            logger.warning(f"Batch update errors: {errors}")

        return results

    async def _get_and_validate_pattern(
        self, pattern_id: UUID, agent_id: str, operation: str
    ) -> LearningPattern:
        """Internal: Fetch and validate pattern for trust propagation

        Validates:
        1. Pattern exists
        2. Pattern is public or system (prevents gaming)
        3. Agent is not the pattern owner (prevents self-boosting)

        Args:
            pattern_id: Pattern UUID
            agent_id: Agent using the pattern
            operation: Operation name (for error messages)

        Returns:
            Validated LearningPattern

        Raises:
            NotFoundError: If pattern doesn't exist
            ValidationError: If pattern not eligible

        Performance: <2ms (single SELECT query)
        """
        # Fetch pattern
        result = await self.session.execute(
            select(LearningPattern).where(LearningPattern.id == pattern_id)
        )
        pattern = result.scalar_one_or_none()

        if not pattern:
            raise NotFoundError("LearningPattern", str(pattern_id))

        # Validate access level (must be public or system)
        if pattern.access_level not in ["public", "system"]:
            log_and_raise(
                ValidationError,
                f"Pattern '{pattern.pattern_name}' is {pattern.access_level}, not eligible for trust updates",
                details={
                    "pattern_id": str(pattern_id),
                    "pattern_name": pattern.pattern_name,
                    "access_level": pattern.access_level,
                    "operation": operation,
                    "reason": "Only public/system patterns affect trust (prevents gaming)",
                },
            )

        # Validate not self-owned (prevent self-boosting)
        if pattern.agent_id == agent_id:
            log_and_raise(
                ValidationError,
                f"Agent cannot boost trust via own pattern '{pattern.pattern_name}'",
                details={
                    "pattern_id": str(pattern_id),
                    "pattern_name": pattern.pattern_name,
                    "agent_id": agent_id,
                    "operation": operation,
                    "reason": "Prevents self-gaming trust scores via owned patterns",
                },
            )

        return pattern
