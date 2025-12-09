"""Unit tests for Trust-Weighted RAG Service.

Tests:
1. RAGWeights validation and normalization
2. Hybrid score calculation
3. Trust score batch retrieval
4. Memory decay integration
5. Search with reranking
6. Edge cases and error handling

Author: Metis (Testing)
Created: 2025-12-09 (Phase 4.1: Issue #31)
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.services.trust_weighted_rag_service import (
    RAGWeights,
    RankedContext,
    TrustWeightedRAGService,
)


class TestRAGWeights:
    """Test RAGWeights configuration."""

    def test_default_weights(self):
        """Test default weight values."""
        weights = RAGWeights()

        assert weights.alpha == 0.5
        assert weights.beta == 0.3
        assert weights.gamma == 0.2

        # Should sum to 1.0
        total = weights.alpha + weights.beta + weights.gamma
        assert abs(total - 1.0) < 0.001

    def test_custom_weights_already_normalized(self):
        """Test custom weights that already sum to 1.0."""
        weights = RAGWeights(alpha=0.6, beta=0.3, gamma=0.1)

        assert weights.alpha == 0.6
        assert weights.beta == 0.3
        assert weights.gamma == 0.1

    def test_custom_weights_auto_normalized(self):
        """Test that weights are auto-normalized to sum to 1.0."""
        # These sum to 2.0, should be normalized
        weights = RAGWeights(alpha=1.0, beta=0.6, gamma=0.4)

        total = weights.alpha + weights.beta + weights.gamma
        assert abs(total - 1.0) < 0.001

        # Check proportions preserved
        assert abs(weights.alpha - 0.5) < 0.001  # 1.0/2.0
        assert abs(weights.beta - 0.3) < 0.001  # 0.6/2.0
        assert abs(weights.gamma - 0.2) < 0.001  # 0.4/2.0

    def test_negative_weights_raise_error(self):
        """Test that negative weights raise ValueError."""
        with pytest.raises(ValueError, match="non-negative"):
            RAGWeights(alpha=-0.5, beta=0.3, gamma=0.2)

    def test_zero_sum_weights_raise_error(self):
        """Test that all-zero weights raise ValueError."""
        with pytest.raises(ValueError, match="positive"):
            RAGWeights(alpha=0.0, beta=0.0, gamma=0.0)

    def test_weights_with_zero_component(self):
        """Test weights with one zero component (trust disabled)."""
        weights = RAGWeights(alpha=0.7, beta=0.0, gamma=0.3)

        total = weights.alpha + weights.beta + weights.gamma
        assert abs(total - 1.0) < 0.001
        assert weights.beta == 0.0


class TestRankedContext:
    """Test RankedContext dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        context = RankedContext(
            memory_id="mem-1",
            content="Test content",
            final_score=0.85,
            similarity=0.9,
            trust_score=0.7,
            decay_factor=0.8,
            agent_id="agent-1",
            metadata={"namespace": "test"},
        )

        result = context.to_dict()

        assert result["memory_id"] == "mem-1"
        assert result["content"] == "Test content"
        assert result["final_score"] == 0.85
        assert result["similarity"] == 0.9
        assert result["trust_score"] == 0.7
        assert result["decay_factor"] == 0.8
        assert result["agent_id"] == "agent-1"
        assert result["metadata"] == {"namespace": "test"}


class TestHybridScoreCalculation:
    """Test hybrid score calculation."""

    @pytest.fixture
    def service(self):
        """Create service with mock dependencies."""
        mock_vector_search = MagicMock()
        mock_session = AsyncMock()
        return TrustWeightedRAGService(
            vector_search=mock_vector_search,
            session=mock_session,
        )

    def test_hybrid_score_equal_weights(self, service):
        """Test hybrid score with equal weights."""
        weights = RAGWeights(alpha=1/3, beta=1/3, gamma=1/3)

        score = service.calculate_hybrid_score(
            similarity=0.9,
            trust_score=0.6,
            decay_factor=0.8,
            weights=weights,
        )

        # (0.9 + 0.6 + 0.8) / 3 = 0.767
        expected = (0.9 + 0.6 + 0.8) / 3
        assert abs(score - expected) < 0.001

    def test_hybrid_score_similarity_dominant(self, service):
        """Test hybrid score with similarity-dominant weights."""
        weights = RAGWeights(alpha=0.8, beta=0.1, gamma=0.1)

        score = service.calculate_hybrid_score(
            similarity=0.9,
            trust_score=0.1,
            decay_factor=0.1,
            weights=weights,
        )

        # 0.8*0.9 + 0.1*0.1 + 0.1*0.1 = 0.72 + 0.01 + 0.01 = 0.74
        expected = 0.8 * 0.9 + 0.1 * 0.1 + 0.1 * 0.1
        assert abs(score - expected) < 0.001

    def test_hybrid_score_trust_dominant(self, service):
        """Test hybrid score with trust-dominant weights."""
        weights = RAGWeights(alpha=0.2, beta=0.6, gamma=0.2)

        score = service.calculate_hybrid_score(
            similarity=0.5,
            trust_score=0.9,
            decay_factor=0.5,
            weights=weights,
        )

        # 0.2*0.5 + 0.6*0.9 + 0.2*0.5 = 0.1 + 0.54 + 0.1 = 0.74
        expected = 0.2 * 0.5 + 0.6 * 0.9 + 0.2 * 0.5
        assert abs(score - expected) < 0.001

    def test_hybrid_score_freshness_dominant(self, service):
        """Test hybrid score with freshness-dominant weights."""
        weights = RAGWeights(alpha=0.2, beta=0.2, gamma=0.6)

        score = service.calculate_hybrid_score(
            similarity=0.3,
            trust_score=0.3,
            decay_factor=0.95,  # Very fresh
            weights=weights,
        )

        # 0.2*0.3 + 0.2*0.3 + 0.6*0.95 = 0.06 + 0.06 + 0.57 = 0.69
        expected = 0.2 * 0.3 + 0.2 * 0.3 + 0.6 * 0.95
        assert abs(score - expected) < 0.001

    def test_hybrid_score_all_perfect(self, service):
        """Test hybrid score with all perfect scores."""
        weights = RAGWeights()

        score = service.calculate_hybrid_score(
            similarity=1.0,
            trust_score=1.0,
            decay_factor=1.0,
            weights=weights,
        )

        # Should be 1.0 (sum of normalized weights * 1.0)
        assert abs(score - 1.0) < 0.001

    def test_hybrid_score_all_zero(self, service):
        """Test hybrid score with all zero scores."""
        weights = RAGWeights()

        score = service.calculate_hybrid_score(
            similarity=0.0,
            trust_score=0.0,
            decay_factor=0.0,
            weights=weights,
        )

        assert score == 0.0


class TestTrustScoreBatchRetrieval:
    """Test batch trust score retrieval."""

    @pytest.fixture
    def mock_session(self):
        """Create mock async session."""
        session = AsyncMock()
        return session

    @pytest.mark.asyncio
    async def test_batch_get_trust_scores_found(self, mock_session):
        """Test batch retrieval when agents found."""
        # Setup mock result
        mock_result = MagicMock()
        mock_result.all.return_value = [
            ("agent-1", 0.8),
            ("agent-2", 0.6),
        ]
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = TrustWeightedRAGService(
            vector_search=MagicMock(),
            session=mock_session,
        )

        trust_scores = await service._batch_get_trust_scores(["agent-1", "agent-2"])

        assert trust_scores["agent-1"] == 0.8
        assert trust_scores["agent-2"] == 0.6
        assert service._trust_score_hits == 2
        assert service._trust_score_misses == 0

    @pytest.mark.asyncio
    async def test_batch_get_trust_scores_missing(self, mock_session):
        """Test batch retrieval with missing agents defaults to 0.5."""
        mock_result = MagicMock()
        mock_result.all.return_value = [("agent-1", 0.8)]
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = TrustWeightedRAGService(
            vector_search=MagicMock(),
            session=mock_session,
        )

        trust_scores = await service._batch_get_trust_scores(["agent-1", "agent-2"])

        assert trust_scores["agent-1"] == 0.8
        assert trust_scores["agent-2"] == 0.5  # Default
        assert service._trust_score_hits == 1
        assert service._trust_score_misses == 1

    @pytest.mark.asyncio
    async def test_batch_get_trust_scores_error(self, mock_session):
        """Test batch retrieval defaults all to 0.5 on error."""
        mock_session.execute = AsyncMock(side_effect=Exception("DB error"))

        service = TrustWeightedRAGService(
            vector_search=MagicMock(),
            session=mock_session,
        )

        trust_scores = await service._batch_get_trust_scores(["agent-1", "agent-2"])

        assert trust_scores["agent-1"] == 0.5
        assert trust_scores["agent-2"] == 0.5
        assert service._trust_score_misses == 2

    @pytest.mark.asyncio
    async def test_batch_get_trust_scores_empty_list(self, mock_session):
        """Test batch retrieval with empty list."""
        service = TrustWeightedRAGService(
            vector_search=MagicMock(),
            session=mock_session,
        )

        trust_scores = await service._batch_get_trust_scores([])

        assert trust_scores == {}


class TestSearchWithTrustWeighting:
    """Test full search with trust weighting."""

    @pytest.fixture
    def mock_vector_search(self):
        """Create mock vector search service."""
        service = MagicMock()
        service.search = AsyncMock(
            return_value=[
                {
                    "id": "mem-1",
                    "similarity": 0.9,
                    "metadata": {"agent_id": "agent-1", "namespace": "test"},
                    "content": "Content 1",
                },
                {
                    "id": "mem-2",
                    "similarity": 0.7,
                    "metadata": {"agent_id": "agent-2", "namespace": "test"},
                    "content": "Content 2",
                },
            ]
        )
        return service

    @pytest.fixture
    def mock_session(self):
        """Create mock async session."""
        session = AsyncMock()

        # Mock memory fetch
        mock_memory_result = MagicMock()
        mock_memory1 = MagicMock()
        mock_memory1.id = "mem-1"
        mock_memory1.created_at = datetime.now(timezone.utc) - timedelta(days=5)

        mock_memory2 = MagicMock()
        mock_memory2.id = "mem-2"
        mock_memory2.created_at = datetime.now(timezone.utc) - timedelta(days=30)

        mock_memory_result.scalars.return_value.all.return_value = [
            mock_memory1,
            mock_memory2,
        ]

        # Mock trust score fetch
        mock_trust_result = MagicMock()
        mock_trust_result.all.return_value = [
            ("agent-1", 0.8),
            ("agent-2", 0.4),
        ]

        # Return different results for different queries
        async def mock_execute(query):
            query_str = str(query)
            if "memories" in query_str.lower():
                return mock_memory_result
            elif "agent" in query_str.lower():
                return mock_trust_result
            return MagicMock()

        session.execute = mock_execute
        return session

    @pytest.mark.asyncio
    async def test_search_reranking_by_trust(self, mock_vector_search, mock_session):
        """Test that results are reranked by trust score."""
        service = TrustWeightedRAGService(
            vector_search=mock_vector_search,
            session=mock_session,
        )

        # Use trust-dominant weights to make reranking visible
        weights = RAGWeights(alpha=0.2, beta=0.7, gamma=0.1)

        results = await service.search_with_trust_weighting(
            query_embedding=[0.1] * 1024,
            top_k=2,
            weights=weights,
        )

        assert len(results) == 2
        # With high trust weight, mem-1 (high trust) should rank higher
        # even though similarity difference exists
        assert results[0].memory_id == "mem-1"
        assert results[0].trust_score == 0.8

    @pytest.mark.asyncio
    async def test_search_empty_results(self, mock_session):
        """Test search with no candidates."""
        mock_vector_search = MagicMock()
        mock_vector_search.search = AsyncMock(return_value=[])

        service = TrustWeightedRAGService(
            vector_search=mock_vector_search,
            session=mock_session,
        )

        results = await service.search_with_trust_weighting(
            query_embedding=[0.1] * 1024,
            top_k=5,
        )

        assert results == []

    @pytest.mark.asyncio
    async def test_search_over_fetch_factor(self, mock_vector_search, mock_session):
        """Test that over-fetch factor is applied."""
        service = TrustWeightedRAGService(
            vector_search=mock_vector_search,
            session=mock_session,
        )

        await service.search_with_trust_weighting(
            query_embedding=[0.1] * 1024,
            top_k=5,
            over_fetch_factor=3,
        )

        # Vector search should be called with top_k * factor = 15
        mock_vector_search.search.assert_called_once()
        call_args = mock_vector_search.search.call_args
        assert call_args.kwargs["top_k"] == 15


class TestStatistics:
    """Test service statistics."""

    def test_get_stats_initial(self):
        """Test initial statistics are zero."""
        service = TrustWeightedRAGService(
            vector_search=MagicMock(),
            session=AsyncMock(),
        )

        stats = service.get_stats()

        assert stats["total_searches"] == 0
        assert stats["total_reranked"] == 0
        assert stats["trust_score_hits"] == 0
        assert stats["trust_score_misses"] == 0
        assert stats["trust_score_hit_rate"] == 0.0

    def test_get_stats_hit_rate(self):
        """Test hit rate calculation."""
        service = TrustWeightedRAGService(
            vector_search=MagicMock(),
            session=AsyncMock(),
        )

        # Simulate some lookups
        service._trust_score_hits = 8
        service._trust_score_misses = 2

        stats = service.get_stats()

        assert stats["trust_score_hit_rate"] == 0.8


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.fixture
    def service(self):
        """Create service with mock dependencies."""
        return TrustWeightedRAGService(
            vector_search=MagicMock(),
            session=AsyncMock(),
        )

    def test_hybrid_score_boundary_values(self, service):
        """Test hybrid score with boundary values."""
        weights = RAGWeights(alpha=0.5, beta=0.3, gamma=0.2)

        # All minimum
        score_min = service.calculate_hybrid_score(
            similarity=0.0,
            trust_score=0.0,
            decay_factor=0.0,
            weights=weights,
        )
        assert score_min == 0.0

        # All maximum
        score_max = service.calculate_hybrid_score(
            similarity=1.0,
            trust_score=1.0,
            decay_factor=1.0,
            weights=weights,
        )
        assert abs(score_max - 1.0) < 0.001

    def test_single_weight_active(self, service):
        """Test with only one weight active."""
        # Only similarity
        weights_sim = RAGWeights(alpha=1.0, beta=0.0, gamma=0.0)
        score_sim = service.calculate_hybrid_score(
            similarity=0.8,
            trust_score=0.0,
            decay_factor=0.0,
            weights=weights_sim,
        )
        assert abs(score_sim - 0.8) < 0.001

        # Only trust
        weights_trust = RAGWeights(alpha=0.0, beta=1.0, gamma=0.0)
        score_trust = service.calculate_hybrid_score(
            similarity=0.0,
            trust_score=0.7,
            decay_factor=0.0,
            weights=weights_trust,
        )
        assert abs(score_trust - 0.7) < 0.001

    @pytest.mark.asyncio
    async def test_fetch_memories_empty(self, service):
        """Test memory fetch with empty list."""
        result = await service._fetch_memories([])
        assert result == {}

    @pytest.mark.asyncio
    async def test_fetch_memories_error(self, service):
        """Test memory fetch handles errors gracefully."""
        service.session.execute = AsyncMock(side_effect=Exception("DB error"))

        result = await service._fetch_memories(["mem-1"])
        assert result == {}
