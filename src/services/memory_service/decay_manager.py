"""Memory Decay Manager - Exponential decay with access boost.

Implements Issue #30: Memory Decay System for Phase 4.1.
Formula: decayed_score = base_score * exp(-λ * age_days) * access_boost

Security Notes:
- All decay calculations are pure math (no external input)
- Score clamping prevents overflow/underflow (0.0 - 1.0)
- Batch operations use transactions for consistency
- Access boost is capped to prevent runaway scores

Author: Metis (Implementation)
Created: 2025-12-09 (Phase 4.1: Issue #30)
"""

import logging
import math
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.memory import Memory

logger = logging.getLogger(__name__)


class DecayConfig:
    """Configuration for memory decay parameters.

    Attributes:
        half_life_days: Time for score to decay by 50% (default: 30 days)
        min_score: Minimum score threshold (default: 0.01)
        max_access_boost: Maximum boost from frequent access (default: 1.5)
        access_boost_factor: Score boost per access (default: 0.05)
        batch_size: Number of memories to process per batch (default: 100)
    """

    def __init__(
        self,
        half_life_days: float = 30.0,
        min_score: float = 0.01,
        max_access_boost: float = 1.5,
        access_boost_factor: float = 0.05,
        batch_size: int = 100,
    ):
        # Validation
        if half_life_days <= 0:
            raise ValueError("half_life_days must be positive")
        if not 0.0 <= min_score <= 1.0:
            raise ValueError("min_score must be between 0.0 and 1.0")
        if max_access_boost < 1.0:
            raise ValueError("max_access_boost must be >= 1.0")
        if access_boost_factor < 0:
            raise ValueError("access_boost_factor must be non-negative")
        if batch_size < 1:
            raise ValueError("batch_size must be at least 1")

        self.half_life_days = half_life_days
        self.min_score = min_score
        self.max_access_boost = max_access_boost
        self.access_boost_factor = access_boost_factor
        self.batch_size = batch_size

        # Pre-compute decay constant: λ = ln(2) / half_life
        self.decay_constant = math.log(2) / half_life_days


class MemoryDecayManager:
    """Manager for memory decay operations with access boost."""

    def __init__(
        self,
        session: AsyncSession,
        config: DecayConfig | None = None,
    ):
        """Initialize decay manager.

        Args:
            session: Async database session
            config: Decay configuration (uses defaults if None)
        """
        self.session = session
        self.config = config or DecayConfig()

        # Metrics
        self._total_decayed = 0
        self._total_boosted = 0

    def calculate_decay_factor(self, age_days: float) -> float:
        """Calculate time decay factor.

        Args:
            age_days: Age of memory in days

        Returns:
            Decay factor between 0.0 and 1.0
        """
        if age_days < 0:
            return 1.0  # Future dates don't decay
        return math.exp(-self.config.decay_constant * age_days)

    def calculate_access_boost(self, access_count: int) -> float:
        """Calculate access boost multiplier.

        Args:
            access_count: Number of times memory was accessed

        Returns:
            Boost factor between 1.0 and max_access_boost
        """
        if access_count <= 0:
            return 1.0
        boost = 1.0 + (access_count * self.config.access_boost_factor)
        return min(boost, self.config.max_access_boost)

    def calculate_decayed_score(
        self,
        base_score: float,
        age_days: float,
        access_count: int = 0,
    ) -> float:
        """Calculate decayed score with access boost.

        Formula: decayed = base * exp(-λ * age) * access_boost

        Args:
            base_score: Original score (0.0 - 1.0)
            age_days: Age in days since creation
            access_count: Number of accesses

        Returns:
            Decayed score clamped to [min_score, 1.0]
        """
        decay_factor = self.calculate_decay_factor(age_days)
        access_boost = self.calculate_access_boost(access_count)

        decayed = base_score * decay_factor * access_boost

        # Clamp to valid range
        return max(self.config.min_score, min(1.0, decayed))

    async def apply_decay_to_memory(self, memory: Memory) -> tuple[float, float]:
        """Apply decay to a single memory's scores.

        Args:
            memory: Memory object to decay

        Returns:
            Tuple of (new_importance, new_relevance)
        """
        now = datetime.now(timezone.utc)
        created_at = memory.created_at

        # Handle timezone-naive datetime
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        age_days = (now - created_at).total_seconds() / 86400.0

        new_importance = self.calculate_decayed_score(
            memory.importance_score,
            age_days,
            memory.access_count,
        )

        new_relevance = self.calculate_decayed_score(
            memory.relevance_score,
            age_days,
            memory.access_count,
        )

        return new_importance, new_relevance

    async def run_batch_decay(
        self,
        namespace: str | None = None,
        agent_id: str | None = None,
    ) -> dict[str, int]:
        """Apply decay to all eligible memories in batches.

        Args:
            namespace: Optional filter by namespace
            agent_id: Optional filter by agent

        Returns:
            Dict with decay statistics
        """
        # Build query for memories to decay
        query = select(Memory)

        if namespace:
            query = query.where(Memory.namespace == namespace)
        if agent_id:
            query = query.where(Memory.agent_id == agent_id)

        result = await self.session.execute(query)
        memories = result.scalars().all()

        decayed_count = 0
        boosted_count = 0

        for memory in memories:
            old_importance = memory.importance_score
            old_relevance = memory.relevance_score

            new_importance, new_relevance = await self.apply_decay_to_memory(memory)

            # Update if changed
            if abs(new_importance - old_importance) > 0.001 or abs(new_relevance - old_relevance) > 0.001:
                memory.importance_score = new_importance
                memory.relevance_score = new_relevance
                decayed_count += 1

                # Track if access boost was applied
                if memory.access_count > 0:
                    boosted_count += 1

        # Commit all changes
        await self.session.commit()

        # Update metrics
        self._total_decayed += decayed_count
        self._total_boosted += boosted_count

        logger.info(
            "Batch decay completed",
            extra={
                "decayed_count": decayed_count,
                "boosted_count": boosted_count,
                "total_processed": len(memories),
            },
        )

        return {
            "decayed_count": decayed_count,
            "boosted_count": boosted_count,
            "total_processed": len(memories),
        }

    async def boost_on_access(self, memory_id: str) -> float | None:
        """Boost memory score when accessed.

        Called when a memory is retrieved to update its access metrics.

        Args:
            memory_id: ID of accessed memory

        Returns:
            New relevance score, or None if memory not found
        """
        query = select(Memory).where(Memory.id == memory_id)
        result = await self.session.execute(query)
        memory = result.scalar_one_or_none()

        if memory is None:
            logger.warning(f"Memory not found for access boost: {memory_id}")
            return None

        # Update access tracking
        memory.access_count += 1
        memory.accessed_at = datetime.now(timezone.utc)

        # Recalculate relevance with new access count
        new_importance, new_relevance = await self.apply_decay_to_memory(memory)
        memory.importance_score = new_importance
        memory.relevance_score = new_relevance

        await self.session.commit()

        logger.debug(
            f"Access boost applied to memory {memory_id}",
            extra={
                "memory_id": memory_id,
                "access_count": memory.access_count,
                "new_relevance": new_relevance,
            },
        )

        return new_relevance

    def get_stats(self) -> dict[str, int]:
        """Get decay manager statistics."""
        return {
            "total_decayed": self._total_decayed,
            "total_boosted": self._total_boosted,
        }
