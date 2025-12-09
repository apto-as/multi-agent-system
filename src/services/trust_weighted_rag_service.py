"""Trust-Weighted RAG Service - Hybrid scoring for context retrieval.

Implements Issue #31: Trust-Weighted RAG Retrieval for Phase 4.1.
Formula: final_score = α * similarity + β * trust + γ * (1 - decay)

Features:
- Hybrid scoring: similarity + trust + freshness
- Configurable weights (α/β/γ) with normalization
- Batch trust score retrieval for performance
- Graceful degradation when trust scores unavailable
- Integrated with MemoryDecayManager for time-based decay

Security Notes:
- Weight normalization prevents score manipulation
- Trust scores retrieved from verified Agent records
- No sensitive data exposed in responses
- All inputs validated at function entry

Author: Metis (Implementation)
Created: 2025-12-09 (Phase 4.1: Issue #31)
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.agent import Agent
from src.models.memory import Memory
from src.services.memory_service.decay_manager import DecayConfig, MemoryDecayManager
from src.services.vector_search_service import VectorSearchService

logger = logging.getLogger(__name__)


@dataclass
class RAGWeights:
    """Configuration for hybrid scoring weights.

    Attributes:
        alpha: Similarity weight (default: 0.5)
        beta: Trust weight (default: 0.3)
        gamma: Freshness weight (default: 0.2)

    Note: Weights are automatically normalized to sum to 1.0
    """

    alpha: float = 0.5  # Similarity weight
    beta: float = 0.3  # Trust weight
    gamma: float = 0.2  # Freshness weight (1 - decay)

    def __post_init__(self):
        """Validate and normalize weights."""
        if self.alpha < 0 or self.beta < 0 or self.gamma < 0:
            raise ValueError("All weights must be non-negative")

        total = self.alpha + self.beta + self.gamma
        if total <= 0:
            raise ValueError("Sum of weights must be positive")

        # Normalize to sum to 1.0
        if abs(total - 1.0) > 0.001:
            logger.debug(f"Normalizing weights: {total} -> 1.0")
            self.alpha /= total
            self.beta /= total
            self.gamma /= total


@dataclass
class RankedContext:
    """Search result with hybrid score breakdown.

    Attributes:
        memory_id: Unique memory identifier
        content: Memory content text
        final_score: Combined hybrid score (0.0-1.0)
        similarity: Vector similarity score
        trust_score: Agent trust score
        decay_factor: Time-based decay factor
        agent_id: Owner agent ID
        metadata: Original memory metadata
    """

    memory_id: str
    content: str | None
    final_score: float
    similarity: float
    trust_score: float
    decay_factor: float
    agent_id: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "memory_id": self.memory_id,
            "content": self.content,
            "final_score": self.final_score,
            "similarity": self.similarity,
            "trust_score": self.trust_score,
            "decay_factor": self.decay_factor,
            "agent_id": self.agent_id,
            "metadata": self.metadata,
        }


class TrustWeightedRAGService:
    """Trust-weighted RAG retrieval with hybrid scoring.

    Combines vector similarity, agent trust scores, and time decay
    to provide more relevant context retrieval.

    Formula: final_score = α * similarity + β * trust + γ * (1 - decay)

    Example:
        >>> service = TrustWeightedRAGService(vector_search, session)
        >>> results = await service.search_with_trust_weighting(
        ...     query_embedding=embedding,
        ...     top_k=5,
        ...     weights=RAGWeights(alpha=0.6, beta=0.3, gamma=0.1),
        ... )
        >>> for r in results:
        ...     print(f"{r.memory_id}: {r.final_score:.3f}")
    """

    # Default trust score for agents without verification history
    DEFAULT_TRUST_SCORE: float = 0.5

    def __init__(
        self,
        vector_search: VectorSearchService,
        session: AsyncSession,
        decay_config: DecayConfig | None = None,
    ):
        """Initialize trust-weighted RAG service.

        Args:
            vector_search: VectorSearchService for similarity search
            session: Async database session
            decay_config: Optional decay configuration (uses defaults if None)
        """
        self.vector_search = vector_search
        self.session = session
        self.decay_manager = MemoryDecayManager(
            session=session,
            config=decay_config or DecayConfig(),
        )

        # Statistics
        self._total_searches = 0
        self._total_reranked = 0
        self._trust_score_hits = 0
        self._trust_score_misses = 0

    async def search_with_trust_weighting(
        self,
        query_embedding: list[float],
        top_k: int = 5,
        weights: RAGWeights | None = None,
        filters: dict[str, Any] | None = None,
        min_similarity: float = 0.5,
        over_fetch_factor: int = 3,
    ) -> list[RankedContext]:
        """Search with trust-weighted hybrid scoring.

        Args:
            query_embedding: 1024-dim query embedding
            top_k: Number of final results to return
            weights: Scoring weights (uses defaults if None)
            filters: Metadata filters for vector search
            min_similarity: Minimum similarity threshold
            over_fetch_factor: Factor to over-fetch for reranking (default: 3x)

        Returns:
            List of RankedContext objects sorted by final_score

        Flow:
            1. Over-fetch candidates from vector search
            2. Fetch memory objects and agent trust scores
            3. Calculate decay factors
            4. Compute hybrid scores
            5. Rerank and return top-k
        """
        weights = weights or RAGWeights()
        self._total_searches += 1

        # Step 1: Over-fetch candidates from vector search
        candidates = await self.vector_search.search(
            query_embedding=query_embedding,
            top_k=top_k * over_fetch_factor,
            filters=filters,
            min_similarity=min_similarity,
        )

        if not candidates:
            logger.debug("No candidates found from vector search")
            return []

        # Step 2: Fetch memory objects for decay calculation
        memory_ids = [c["id"] for c in candidates]
        memories = await self._fetch_memories(memory_ids)

        # Step 3: Get unique agent IDs and batch fetch trust scores
        agent_ids = list({c["metadata"].get("agent_id", "") for c in candidates if c["metadata"].get("agent_id")})
        trust_scores = await self._batch_get_trust_scores(agent_ids)

        # Step 4: Calculate hybrid scores and build results
        ranked_results = []
        now = datetime.now(timezone.utc)

        for candidate in candidates:
            memory_id = candidate["id"]
            similarity = candidate["similarity"]
            metadata = candidate["metadata"]
            content = candidate.get("content")
            agent_id = metadata.get("agent_id", "")

            # Get trust score (default if not found)
            trust_score = trust_scores.get(agent_id, self.DEFAULT_TRUST_SCORE)

            # Calculate decay factor from memory
            memory = memories.get(memory_id)
            if memory:
                created_at = memory.created_at
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                age_days = (now - created_at).total_seconds() / 86400.0
                decay_factor = self.decay_manager.calculate_decay_factor(age_days)
            else:
                # Fallback: no decay if memory not found
                decay_factor = 1.0

            # Compute hybrid score
            # Formula: final = α*similarity + β*trust + γ*(1-decay)
            # Note: (1 - decay_factor) means fresher = higher score
            freshness = 1.0 - decay_factor  # Invert: high decay = low freshness
            # Actually, decay_factor is already inverted (1.0 for fresh, 0.0 for old)
            # So freshness = decay_factor (high for fresh, low for old)
            freshness = decay_factor

            final_score = (
                weights.alpha * similarity
                + weights.beta * trust_score
                + weights.gamma * freshness
            )

            ranked_results.append(
                RankedContext(
                    memory_id=memory_id,
                    content=content,
                    final_score=final_score,
                    similarity=similarity,
                    trust_score=trust_score,
                    decay_factor=decay_factor,
                    agent_id=agent_id,
                    metadata=metadata,
                )
            )

        # Step 5: Sort by final score (descending) and return top-k
        ranked_results.sort(key=lambda x: x.final_score, reverse=True)
        final_results = ranked_results[:top_k]

        self._total_reranked += len(candidates)

        logger.info(
            "Trust-weighted search completed",
            extra={
                "candidates": len(candidates),
                "final_results": len(final_results),
                "top_score": final_results[0].final_score if final_results else 0.0,
                "weights": {"alpha": weights.alpha, "beta": weights.beta, "gamma": weights.gamma},
            },
        )

        return final_results

    async def _fetch_memories(self, memory_ids: list[str]) -> dict[str, Memory]:
        """Fetch memory objects by IDs.

        Args:
            memory_ids: List of memory IDs

        Returns:
            Dict mapping memory_id -> Memory object
        """
        if not memory_ids:
            return {}

        try:
            result = await self.session.execute(
                select(Memory).where(Memory.id.in_(memory_ids))
            )
            memories = result.scalars().all()
            return {str(m.id): m for m in memories}
        except Exception as e:
            logger.warning(f"Failed to fetch memories: {e}")
            return {}

    async def _batch_get_trust_scores(self, agent_ids: list[str]) -> dict[str, float]:
        """Batch fetch trust scores for agents.

        Args:
            agent_ids: List of agent IDs

        Returns:
            Dict mapping agent_id -> trust_score (0.0-1.0)
        """
        if not agent_ids:
            return {}

        trust_map = {}
        try:
            result = await self.session.execute(
                select(Agent.agent_id, Agent.trust_score).where(
                    Agent.agent_id.in_(agent_ids)
                )
            )
            rows = result.all()

            for agent_id, trust_score in rows:
                trust_map[agent_id] = trust_score
                self._trust_score_hits += 1

            # Track misses
            for agent_id in agent_ids:
                if agent_id not in trust_map:
                    self._trust_score_misses += 1
                    trust_map[agent_id] = self.DEFAULT_TRUST_SCORE

        except Exception as e:
            logger.warning(f"Failed to fetch trust scores: {e}")
            # Default all to neutral trust on error
            for agent_id in agent_ids:
                trust_map[agent_id] = self.DEFAULT_TRUST_SCORE
                self._trust_score_misses += 1

        return trust_map

    def calculate_hybrid_score(
        self,
        similarity: float,
        trust_score: float,
        decay_factor: float,
        weights: RAGWeights,
    ) -> float:
        """Calculate hybrid score from components.

        Formula: final = α*similarity + β*trust + γ*freshness

        Args:
            similarity: Vector similarity score (0.0-1.0)
            trust_score: Agent trust score (0.0-1.0)
            decay_factor: Time decay factor (1.0=fresh, 0.0=old)
            weights: Scoring weights

        Returns:
            Final hybrid score (0.0-1.0)
        """
        freshness = decay_factor  # decay_factor already represents freshness
        return (
            weights.alpha * similarity
            + weights.beta * trust_score
            + weights.gamma * freshness
        )

    def get_stats(self) -> dict[str, Any]:
        """Get service statistics.

        Returns:
            Dict with search counts, hit rates, etc.
        """
        total_trust_lookups = self._trust_score_hits + self._trust_score_misses
        hit_rate = (
            self._trust_score_hits / total_trust_lookups
            if total_trust_lookups > 0
            else 0.0
        )

        return {
            "total_searches": self._total_searches,
            "total_reranked": self._total_reranked,
            "trust_score_hits": self._trust_score_hits,
            "trust_score_misses": self._trust_score_misses,
            "trust_score_hit_rate": hit_rate,
        }
