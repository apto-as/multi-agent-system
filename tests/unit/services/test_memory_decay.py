"""Unit tests for Memory Decay System.

Tests:
1. DecayConfig validation
2. Decay factor calculation (exponential)
3. Access boost calculation
4. Combined decay + boost calculation
5. Batch decay operations
6. Boost on access
7. Scheduler lifecycle
8. Edge cases (negative age, zero access)

Author: Metis (Testing)
Created: 2025-12-09 (Phase 4.1: Issue #30)
"""

import math
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.services.memory_decay_scheduler import MemoryDecayScheduler
from src.services.memory_service.decay_manager import DecayConfig, MemoryDecayManager


class TestDecayConfig:
    """Test DecayConfig validation and initialization."""

    def test_default_config(self):
        """Test default configuration values."""
        config = DecayConfig()

        assert config.half_life_days == 30.0
        assert config.min_score == 0.01
        assert config.max_access_boost == 1.5
        assert config.access_boost_factor == 0.05
        assert config.batch_size == 100

        # Verify decay constant: λ = ln(2) / half_life
        expected_lambda = math.log(2) / 30.0
        assert abs(config.decay_constant - expected_lambda) < 0.0001

    def test_custom_config(self):
        """Test custom configuration values."""
        config = DecayConfig(
            half_life_days=7.0,
            min_score=0.05,
            max_access_boost=2.0,
            access_boost_factor=0.1,
            batch_size=50,
        )

        assert config.half_life_days == 7.0
        assert config.min_score == 0.05
        assert config.max_access_boost == 2.0
        assert config.access_boost_factor == 0.1
        assert config.batch_size == 50

        # Faster decay for shorter half-life
        expected_lambda = math.log(2) / 7.0
        assert abs(config.decay_constant - expected_lambda) < 0.0001

    def test_invalid_half_life_raises_error(self):
        """Test that non-positive half_life raises ValueError."""
        with pytest.raises(ValueError, match="half_life_days must be positive"):
            DecayConfig(half_life_days=0)

        with pytest.raises(ValueError, match="half_life_days must be positive"):
            DecayConfig(half_life_days=-10)

    def test_invalid_min_score_raises_error(self):
        """Test that out-of-range min_score raises ValueError."""
        with pytest.raises(ValueError, match="min_score must be between"):
            DecayConfig(min_score=-0.1)

        with pytest.raises(ValueError, match="min_score must be between"):
            DecayConfig(min_score=1.5)

    def test_invalid_max_access_boost_raises_error(self):
        """Test that max_access_boost < 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="max_access_boost must be >= 1.0"):
            DecayConfig(max_access_boost=0.9)

    def test_invalid_access_boost_factor_raises_error(self):
        """Test that negative access_boost_factor raises ValueError."""
        with pytest.raises(ValueError, match="access_boost_factor must be non-negative"):
            DecayConfig(access_boost_factor=-0.05)

    def test_invalid_batch_size_raises_error(self):
        """Test that batch_size < 1 raises ValueError."""
        with pytest.raises(ValueError, match="batch_size must be at least 1"):
            DecayConfig(batch_size=0)


class TestDecayCalculations:
    """Test decay factor and access boost calculations."""

    @pytest.fixture
    def manager(self):
        """Create MemoryDecayManager with mock session."""
        mock_session = MagicMock()
        return MemoryDecayManager(session=mock_session)

    def test_decay_factor_at_zero_days(self, manager):
        """Test decay factor is 1.0 at age 0."""
        factor = manager.calculate_decay_factor(0.0)
        assert factor == 1.0

    def test_decay_factor_at_half_life(self, manager):
        """Test decay factor is ~0.5 at half-life (30 days)."""
        factor = manager.calculate_decay_factor(30.0)
        # e^(-ln(2)) = 0.5
        assert abs(factor - 0.5) < 0.001

    def test_decay_factor_at_double_half_life(self, manager):
        """Test decay factor is ~0.25 at 2x half-life (60 days)."""
        factor = manager.calculate_decay_factor(60.0)
        # e^(-2*ln(2)) = 0.25
        assert abs(factor - 0.25) < 0.001

    def test_decay_factor_negative_age(self, manager):
        """Test decay factor is 1.0 for negative age (future dates)."""
        factor = manager.calculate_decay_factor(-10.0)
        assert factor == 1.0

    def test_access_boost_zero_count(self, manager):
        """Test access boost is 1.0 with zero access."""
        boost = manager.calculate_access_boost(0)
        assert boost == 1.0

    def test_access_boost_negative_count(self, manager):
        """Test access boost is 1.0 with negative access count."""
        boost = manager.calculate_access_boost(-5)
        assert boost == 1.0

    def test_access_boost_single_access(self, manager):
        """Test access boost with single access."""
        boost = manager.calculate_access_boost(1)
        # 1.0 + 1 * 0.05 = 1.05
        assert abs(boost - 1.05) < 0.001

    def test_access_boost_multiple_accesses(self, manager):
        """Test access boost with multiple accesses."""
        boost = manager.calculate_access_boost(5)
        # 1.0 + 5 * 0.05 = 1.25
        assert abs(boost - 1.25) < 0.001

    def test_access_boost_capped_at_max(self, manager):
        """Test access boost is capped at max_access_boost."""
        boost = manager.calculate_access_boost(100)
        # Would be 1.0 + 100 * 0.05 = 6.0, but capped at 1.5
        assert boost == 1.5

    def test_decayed_score_fresh_memory(self, manager):
        """Test decayed score for fresh memory (0 days)."""
        score = manager.calculate_decayed_score(
            base_score=0.8,
            age_days=0.0,
            access_count=0,
        )
        # 0.8 * 1.0 * 1.0 = 0.8
        assert abs(score - 0.8) < 0.001

    def test_decayed_score_with_decay_and_boost(self, manager):
        """Test decayed score with both decay and access boost."""
        score = manager.calculate_decayed_score(
            base_score=0.8,
            age_days=30.0,  # Half-life
            access_count=5,  # 1.25x boost
        )
        # 0.8 * 0.5 * 1.25 = 0.5
        assert abs(score - 0.5) < 0.01

    def test_decayed_score_clamped_to_min(self, manager):
        """Test decayed score is clamped to min_score."""
        score = manager.calculate_decayed_score(
            base_score=0.01,
            age_days=365.0,  # Very old
            access_count=0,
        )
        # Should not go below min_score (0.01)
        assert score >= manager.config.min_score

    def test_decayed_score_clamped_to_max(self, manager):
        """Test decayed score is clamped to 1.0."""
        score = manager.calculate_decayed_score(
            base_score=0.9,
            age_days=0.0,
            access_count=10,  # High boost
        )
        # 0.9 * 1.0 * 1.5 = 1.35, but clamped to 1.0
        assert score == 1.0


class TestBatchDecay:
    """Test batch decay operations."""

    @pytest.fixture
    def mock_session(self):
        """Create mock async session."""
        session = AsyncMock()
        session.commit = AsyncMock()
        return session

    @pytest.fixture
    def mock_memories(self):
        """Create mock memory objects."""
        now = datetime.now(timezone.utc)

        # Fresh memory (1 day old)
        memory1 = MagicMock()
        memory1.id = "mem-1"
        memory1.importance_score = 0.8
        memory1.relevance_score = 0.7
        memory1.access_count = 0
        memory1.created_at = now - timedelta(days=1)

        # Old memory with accesses (60 days old)
        memory2 = MagicMock()
        memory2.id = "mem-2"
        memory2.importance_score = 0.9
        memory2.relevance_score = 0.8
        memory2.access_count = 10
        memory2.created_at = now - timedelta(days=60)

        return [memory1, memory2]

    @pytest.mark.asyncio
    async def test_batch_decay_processes_all_memories(self, mock_session, mock_memories):
        """Test batch decay processes all memories."""
        # Setup mock query result
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_memories
        mock_session.execute = AsyncMock(return_value=mock_result)

        manager = MemoryDecayManager(session=mock_session)
        stats = await manager.run_batch_decay()

        assert stats["total_processed"] == 2
        assert mock_session.commit.called

    @pytest.mark.asyncio
    async def test_batch_decay_with_namespace_filter(self, mock_session, mock_memories):
        """Test batch decay with namespace filter."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_memories
        mock_session.execute = AsyncMock(return_value=mock_result)

        manager = MemoryDecayManager(session=mock_session)
        await manager.run_batch_decay(namespace="test-namespace")

        # Verify query was executed
        assert mock_session.execute.called

    @pytest.mark.asyncio
    async def test_boost_on_access_updates_memory(self, mock_session):
        """Test boost_on_access updates memory correctly."""
        now = datetime.now(timezone.utc)

        mock_memory = MagicMock()
        mock_memory.id = "mem-1"
        mock_memory.importance_score = 0.8
        mock_memory.relevance_score = 0.7
        mock_memory.access_count = 5
        mock_memory.created_at = now - timedelta(days=10)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_memory
        mock_session.execute = AsyncMock(return_value=mock_result)

        manager = MemoryDecayManager(session=mock_session)
        new_relevance = await manager.boost_on_access("mem-1")

        assert new_relevance is not None
        assert mock_memory.access_count == 6
        assert mock_memory.accessed_at is not None
        assert mock_session.commit.called

    @pytest.mark.asyncio
    async def test_boost_on_access_memory_not_found(self, mock_session):
        """Test boost_on_access returns None for missing memory."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        manager = MemoryDecayManager(session=mock_session)
        result = await manager.boost_on_access("nonexistent-id")

        assert result is None


class TestMemoryDecayScheduler:
    """Test MemoryDecayScheduler lifecycle and operations."""

    @pytest.fixture
    def mock_decay_manager(self):
        """Create mock MemoryDecayManager."""
        manager = MagicMock(spec=MemoryDecayManager)
        manager.run_batch_decay = AsyncMock(
            return_value={
                "decayed_count": 10,
                "boosted_count": 3,
                "total_processed": 50,
            }
        )
        return manager

    def test_scheduler_invalid_interval_raises_error(self, mock_decay_manager):
        """Test that too-short interval raises ValueError."""
        with pytest.raises(ValueError, match="Decay interval must be at least 1 second"):
            MemoryDecayScheduler(
                decay_manager=mock_decay_manager,
                interval_hours=0.0,  # Less than 1 second
            )

    @pytest.mark.asyncio
    async def test_scheduler_start_stop(self, mock_decay_manager):
        """Test scheduler start and stop lifecycle."""
        scheduler = MemoryDecayScheduler(
            decay_manager=mock_decay_manager,
            interval_hours=24.0,
        )

        assert not scheduler.is_running()

        await scheduler.start()
        assert scheduler.is_running()
        assert scheduler.get_next_run_time() is not None

        await scheduler.stop()
        assert not scheduler.is_running()

    @pytest.mark.asyncio
    async def test_scheduler_double_start_raises_error(self, mock_decay_manager):
        """Test that starting already-running scheduler raises error."""
        scheduler = MemoryDecayScheduler(
            decay_manager=mock_decay_manager,
            interval_hours=24.0,
        )

        await scheduler.start()

        with pytest.raises(RuntimeError, match="already running"):
            await scheduler.start()

        await scheduler.stop()

    @pytest.mark.asyncio
    async def test_scheduler_manual_trigger(self, mock_decay_manager):
        """Test manual trigger_decay operation."""
        scheduler = MemoryDecayScheduler(
            decay_manager=mock_decay_manager,
            interval_hours=24.0,
        )

        stats = await scheduler.trigger_decay()

        assert stats["decayed_count"] == 10
        assert scheduler.get_total_runs() == 1
        assert scheduler.get_total_decayed() == 10
        assert scheduler.get_last_run_time() is not None

    @pytest.mark.asyncio
    async def test_scheduler_metrics_accumulate(self, mock_decay_manager):
        """Test that scheduler metrics accumulate across runs."""
        scheduler = MemoryDecayScheduler(
            decay_manager=mock_decay_manager,
            interval_hours=24.0,
        )

        await scheduler.trigger_decay()
        await scheduler.trigger_decay()

        assert scheduler.get_total_runs() == 2
        assert scheduler.get_total_decayed() == 20

    @pytest.mark.asyncio
    async def test_scheduler_stop_when_not_running(self, mock_decay_manager):
        """Test that stopping non-running scheduler is safe."""
        scheduler = MemoryDecayScheduler(
            decay_manager=mock_decay_manager,
            interval_hours=24.0,
        )

        # Should not raise
        await scheduler.stop()
        assert not scheduler.is_running()


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.fixture
    def manager(self):
        """Create MemoryDecayManager with mock session."""
        mock_session = MagicMock()
        return MemoryDecayManager(session=mock_session)

    def test_very_old_memory_decay(self, manager):
        """Test decay for very old memory (1 year)."""
        score = manager.calculate_decayed_score(
            base_score=1.0,
            age_days=365.0,
            access_count=0,
        )
        # Should be clamped to min_score (0.01)
        # At 365 days with 30-day half-life: e^(-ln(2)*365/30) ≈ 4.5e-4
        # This is below min_score, so it gets clamped
        assert score == manager.config.min_score

    def test_custom_half_life(self):
        """Test decay with custom half-life (7 days)."""
        mock_session = MagicMock()
        config = DecayConfig(half_life_days=7.0)
        manager = MemoryDecayManager(session=mock_session, config=config)

        # At 7 days, should be ~0.5
        factor = manager.calculate_decay_factor(7.0)
        assert abs(factor - 0.5) < 0.001

    def test_high_access_count(self, manager):
        """Test with very high access count."""
        boost = manager.calculate_access_boost(1000)
        # Should be capped at max_access_boost
        assert boost == manager.config.max_access_boost

    def test_zero_base_score(self, manager):
        """Test decay with zero base score."""
        score = manager.calculate_decayed_score(
            base_score=0.0,
            age_days=10.0,
            access_count=5,
        )
        # 0.0 * any = 0.0, but clamped to min_score
        assert score == manager.config.min_score

    def test_stats_tracking(self, manager):
        """Test that stats are properly initialized."""
        stats = manager.get_stats()

        assert stats["total_decayed"] == 0
        assert stats["total_boosted"] == 0
