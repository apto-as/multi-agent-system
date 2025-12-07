"""Trust score calculation and management service

Implements Exponential Weighted Moving Average (EWMA) for trust scores
with configurable decay factor and minimum observation threshold.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import (
    AgentNotFoundError,
    AuthorizationError,
    DatabaseError,
    log_and_raise,
)
from src.models.agent import Agent
from src.models.verification import TrustScoreHistory
from src.services.base_service import BaseService


class TrustScoreCalculator:
    """Trust score calculation using EWMA algorithm

    Formula: new_score = alpha * result + (1 - alpha) * old_score

    where:
    - alpha: Learning rate (0.0 - 1.0) - higher = more weight to recent observations
    - result: 1.0 for accurate, 0.0 for inaccurate
    - old_score: Previous trust score

    Performance target: <1ms per calculation
    """

    def __init__(self, alpha: float = 0.1, min_observations: int = 5, initial_score: float = 0.5):
        """Initialize trust score calculator

        Args:
            alpha: Learning rate (0.0-1.0). Default 0.1 means 10% weight to new observation
            min_observations: Minimum verifications before trust score is reliable
            initial_score: Starting trust score for new agents
        """
        if not 0.0 <= alpha <= 1.0:
            raise ValueError(f"alpha must be in [0.0, 1.0], got {alpha}")
        if min_observations < 1:
            raise ValueError(f"min_observations must be >= 1, got {min_observations}")
        if not 0.0 <= initial_score <= 1.0:
            raise ValueError(f"initial_score must be in [0.0, 1.0], got {initial_score}")

        self.alpha = alpha
        self.min_observations = min_observations
        self.initial_score = initial_score

    def calculate_new_score(self, old_score: float, accurate: bool) -> float:
        """Calculate new trust score using EWMA

        Args:
            old_score: Previous trust score (0.0-1.0)
            accurate: Whether the verification was accurate

        Returns:
            New trust score (0.0-1.0)

        Performance: O(1) - <0.1ms
        """
        observation = 1.0 if accurate else 0.0
        new_score = self.alpha * observation + (1.0 - self.alpha) * old_score
        # Clamp to [0.0, 1.0] for safety
        return max(0.0, min(1.0, new_score))

    def is_reliable(self, total_verifications: int) -> bool:
        """Check if trust score is reliable based on observation count

        Args:
            total_verifications: Number of verifications performed

        Returns:
            True if score is reliable (>= min_observations)
        """
        return total_verifications >= self.min_observations


class TrustService(BaseService):
    """Service for managing agent trust scores"""

    def __init__(self, session: AsyncSession, calculator: TrustScoreCalculator | None = None):
        """Initialize trust service

        Args:
            session: Database session
            calculator: Trust score calculator (uses default if None)
        """
        super().__init__(session)
        self.calculator = calculator or TrustScoreCalculator()

    async def update_trust_score(
        self,
        agent_id: str,
        accurate: bool,
        verification_id: UUID | None = None,
        reason: str = "verification_result",
        user: Any | None = None,  # Authorization user (required for manual updates)
        requesting_namespace: str | None = None,  # Namespace isolation
    ) -> float:
        """Update agent trust score based on verification result

        Args:
            agent_id: Agent identifier
            accurate: Whether the verification was accurate
            verification_id: Optional verification record ID
            reason: Reason for score change
            user: User performing update (None = automated from VerificationService)
            requesting_namespace: Requesting namespace (for isolation check)

        Returns:
            New trust score

        Raises:
            AgentNotFoundError: If agent doesn't exist or namespace mismatch
            AuthorizationError: If user lacks required privilege (V-TRUST-1 fix)
            DatabaseError: If update fails

        Performance target: <1ms P95

        Security:
            - V-TRUST-1: Only SYSTEM users or automated verification can update trust
            - V-TRUST-4: Namespace isolation enforced (agent must be in requesting namespace)
        """
        from src.core.authorization import verify_system_privilege

        try:
            # V-TRUST-1: Authorization check
            # - Automated (user=None): Must have verification_id (from VerificationService)
            # - Manual (user provided): Must have SYSTEM privilege
            if user is None:
                # Automated: Require verification_id as proof of legitimate verification
                if verification_id is None:
                    log_and_raise(
                        AuthorizationError,
                        (
                            "Unauthorized trust score update: verification_id "
                            "required for automated updates"
                        ),
                        details={
                            "agent_id": agent_id,
                            "reason": reason,
                            "user": "None (automated)",
                            "verification_id": "None (MISSING)",
                        },
                    )
            else:
                # Manual update requires SYSTEM privilege
                await verify_system_privilege(
                    user,
                    operation="update_trust_score",
                    details={"agent_id": agent_id, "reason": reason},
                )

            # Fetch agent with row-level lock (V-TRUST-2)
            result = await self.session.execute(
                select(Agent)
                .where(Agent.agent_id == agent_id)
                .with_for_update()  # Row-level lock prevents race condition
            )
            agent = result.scalar_one_or_none()

            if not agent:
                log_and_raise(
                    AgentNotFoundError,
                    f"Agent not found: {agent_id}",
                    details={"agent_id": agent_id},
                )

            # V-TRUST-4: Namespace isolation check
            if requesting_namespace is not None and agent.namespace != requesting_namespace:
                # Cross-namespace access denied
                log_and_raise(
                    AuthorizationError,
                    f"Agent {agent_id} not found in namespace {requesting_namespace}",
                    details={
                        "agent_id": agent_id,
                        "agent_namespace": agent.namespace,
                        "requesting_namespace": requesting_namespace,
                    },
                )

            # Calculate new score
            old_score = agent.trust_score
            new_score = self.calculator.calculate_new_score(old_score, accurate)

            # Update agent metrics
            agent.trust_score = new_score
            agent.total_verifications += 1
            if accurate:
                agent.accurate_verifications += 1

            # Record history
            history = TrustScoreHistory(
                agent_id=agent_id,
                old_score=old_score,
                new_score=new_score,
                verification_record_id=verification_id,
                reason=reason,
                changed_at=datetime.utcnow(),
            )
            self.session.add(history)

            await self.session.flush()

            return new_score

        except (AgentNotFoundError, AuthorizationError):
            raise
        except Exception as e:
            log_and_raise(
                DatabaseError,
                f"Failed to update trust score for agent {agent_id}",
                original_exception=e,
                details={"agent_id": agent_id, "accurate": accurate},
            )

    async def get_trust_score(self, agent_id: str) -> dict[str, Any]:
        """Get agent trust score and statistics

        Args:
            agent_id: Agent identifier

        Returns:
            Dictionary with trust score and metadata

        Raises:
            AgentNotFoundError: If agent doesn't exist
        """
        try:
            result = await self.session.execute(select(Agent).where(Agent.agent_id == agent_id))
            agent = result.scalar_one_or_none()

            if not agent:
                log_and_raise(
                    AgentNotFoundError,
                    f"Agent not found: {agent_id}",
                    details={"agent_id": agent_id},
                )

            return {
                "agent_id": agent_id,
                "trust_score": agent.trust_score,
                "total_verifications": agent.total_verifications,
                "accurate_verifications": agent.accurate_verifications,
                "verification_accuracy": agent.verification_accuracy,
                "requires_verification": agent.requires_verification,
                "is_reliable": self.calculator.is_reliable(agent.total_verifications),
            }

        except AgentNotFoundError:
            raise
        except Exception as e:
            log_and_raise(
                DatabaseError,
                f"Failed to get trust score for agent {agent_id}",
                original_exception=e,
                details={"agent_id": agent_id},
            )

    async def get_trust_history(self, agent_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """Get agent trust score history

        Args:
            agent_id: Agent identifier
            limit: Maximum number of records to return

        Returns:
            List of trust score changes

        Raises:
            AgentNotFoundError: If agent doesn't exist
        """
        try:
            # Verify agent exists
            result = await self.session.execute(select(Agent).where(Agent.agent_id == agent_id))
            if not result.scalar_one_or_none():
                log_and_raise(
                    AgentNotFoundError,
                    f"Agent not found: {agent_id}",
                    details={"agent_id": agent_id},
                )

            # Get history
            result = await self.session.execute(
                select(TrustScoreHistory)
                .where(TrustScoreHistory.agent_id == agent_id)
                .order_by(TrustScoreHistory.changed_at.desc())
                .limit(limit)
            )
            history = result.scalars().all()

            return [
                {
                    "id": str(record.id),
                    "old_score": record.old_score,
                    "new_score": record.new_score,
                    "delta": record.new_score - record.old_score,
                    "verification_id": str(record.verification_record_id)
                    if record.verification_record_id
                    else None,
                    "reason": record.reason,
                    "changed_at": record.changed_at.isoformat(),
                }
                for record in history
            ]

        except AgentNotFoundError:
            raise
        except Exception as e:
            log_and_raise(
                DatabaseError,
                f"Failed to get trust history for agent {agent_id}",
                original_exception=e,
                details={"agent_id": agent_id},
            )

    async def batch_update_trust_scores(
        self,
        updates: list[tuple[str, bool, UUID | None]],
        user: Any | None = None,
        requesting_namespace: str | None = None,
    ) -> dict[str, float]:
        """Batch update trust scores for multiple agents

        SECURITY FIX (2025-11-09): Added authorization and namespace isolation
        Prevents batch trust manipulation from AI agent mistakes (CVSS 6.5-7.0 LOCAL)

        Args:
            updates: List of (agent_id, accurate, verification_id) tuples
            user: User performing update (None = automated from VerificationService)
            requesting_namespace: Requesting namespace (for isolation check)

        Returns:
            Dictionary mapping agent_id to new trust score

        Raises:
            AgentNotFoundError: If agent doesn't exist or namespace mismatch
            AuthorizationError: If user lacks required privilege

        Performance: <10ms for 100 updates

        Security:
            - V-TRUST-7: Authorization enforced (same as single update)
            - V-TRUST-11: Namespace isolation enforced per agent
        """
        results = {}

        for agent_id, accurate, verification_id in updates:
            new_score = await self.update_trust_score(
                agent_id=agent_id,
                accurate=accurate,
                verification_id=verification_id,
                user=user,
                requesting_namespace=requesting_namespace,
            )
            results[agent_id] = new_score

        return results
