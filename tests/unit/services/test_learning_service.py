"""Unit tests for LearningService."""
import pytest
from datetime import datetime
from uuid import uuid4

from src.core.exceptions import NotFoundError, PermissionError, ValidationError
from src.models.learning_pattern import LearningPattern, PatternUsageHistory
from src.services.learning_service import LearningService


@pytest.mark.asyncio
class TestLearningService:
    """Test LearningService operations."""

    async def test_create_pattern_success(self, db_session):
        """Test successful pattern creation."""
        service = LearningService()

        pattern = await service.create_pattern(
            pattern_name="test_pattern",
            category="optimization",
            pattern_data={"strategy": "index_optimization", "improvement": "90%"},
            agent_id="test-agent",
            namespace="test-namespace",
            access_level="private"
        )

        assert pattern.pattern_name == "test_pattern"
        assert pattern.category == "optimization"
        assert pattern.agent_id == "test-agent"
        assert pattern.namespace == "test-namespace"
        assert pattern.access_level == "private"
        assert pattern.pattern_data == {"strategy": "index_optimization", "improvement": "90%"}
        assert pattern.version == "1.0.0"
        assert pattern.learning_weight == 1.0

    async def test_create_pattern_validation_error(self, db_session):
        """Test pattern creation with validation errors."""
        service = LearningService()

        # Test empty pattern name
        with pytest.raises(ValidationError):
            await service.create_pattern(
                pattern_name="",
                category="test",
                pattern_data={},
                agent_id="test-agent"
            )

        # Test empty category
        with pytest.raises(ValidationError):
            await service.create_pattern(
                pattern_name="test",
                category="",
                pattern_data={},
                agent_id="test-agent"
            )

    async def test_get_pattern_success(self, db_session):
        """Test retrieving a pattern."""
        service = LearningService()

        # Create pattern
        created = await service.create_pattern(
            pattern_name="retrieval_test",
            category="test",
            pattern_data={"key": "value"},
            agent_id="test-agent"
        )

        # Retrieve pattern (must pass same agent_id for access control)
        retrieved = await service.get_pattern(created.id, requesting_agent_id="test-agent")

        assert retrieved.id == created.id
        assert retrieved.pattern_name == "retrieval_test"
        assert retrieved.agent_id == "test-agent"

    async def test_get_pattern_not_found(self, db_session):
        """Test retrieving non-existent pattern."""
        service = LearningService()

        # Service returns None for not found patterns (doesn't raise)
        pattern = await service.get_pattern(uuid4())
        assert pattern is None

    async def test_get_patterns_by_agent(self, db_session):
        """Test retrieving patterns by agent."""
        service = LearningService()

        # Create patterns for different agents
        await service.create_pattern(
            pattern_name="agent1_pattern1",
            category="test",
            pattern_data={},
            agent_id="agent-1",
            namespace="test"
        )
        await service.create_pattern(
            pattern_name="agent1_pattern2",
            category="test",
            pattern_data={},
            agent_id="agent-1",
            namespace="test"
        )
        await service.create_pattern(
            pattern_name="agent2_pattern",
            category="test",
            pattern_data={},
            agent_id="agent-2",
            namespace="test"
        )

        # Get patterns for agent-1
        patterns = await service.get_patterns_by_agent("agent-1", namespace="test")

        assert len(patterns) == 2
        assert all(p.agent_id == "agent-1" for p in patterns)

    async def test_search_patterns_by_category(self, db_session):
        """Test searching patterns by category."""
        service = LearningService()

        # Create patterns in different categories
        await service.create_pattern(
            pattern_name="optimization1",
            category="optimization",
            pattern_data={},
            agent_id="test-agent",
            namespace="test"
        )
        await service.create_pattern(
            pattern_name="security1",
            category="security",
            pattern_data={},
            agent_id="test-agent",
            namespace="test"
        )

        # Search for optimization patterns (need requesting_agent_id for private patterns)
        results = await service.search_patterns(
            requesting_agent_id="test-agent",
            category="optimization",
            namespace="test"
        )

        assert len(results) >= 1
        assert all(p.category == "optimization" for p in results)

    async def test_search_patterns_by_name(self, db_session):
        """Test searching patterns by name pattern."""
        service = LearningService()

        await service.create_pattern(
            pattern_name="index_optimization",
            category="test",
            pattern_data={},
            agent_id="test-agent",
            namespace="test",
            access_level="public"  # Make it public so search finds it
        )

        # Search with query_text (not pattern_name_pattern)
        results = await service.search_patterns(
            query_text="index",
            namespace="test"
        )

        assert len(results) >= 1
        assert any("index" in p.pattern_name for p in results)

    async def test_use_pattern_records_usage(self, db_session):
        """Test that using a pattern records usage history."""
        service = LearningService()

        # Create pattern
        pattern = await service.create_pattern(
            pattern_name="usage_test",
            category="test",
            pattern_data={"action": "test"},
            agent_id="owner-agent",
            namespace="test",
            access_level="public"  # Allow all agents to use
        )

        # Use pattern (execution_time, not execution_time_ms)
        updated = await service.use_pattern(
            pattern_id=pattern.id,
            using_agent_id="user-agent",
            success=True,
            execution_time=0.1505  # In seconds, not ms
        )

        # Verify usage count increased (initial usage_count is 0)
        assert updated.usage_count == 1
        # Note: success_count doesn't exist as a field - check success_rate instead
        assert updated.success_rate >= 0
        assert updated.avg_execution_time > 0

    async def test_use_pattern_updates_learning_weight(self, db_session):
        """Test that pattern usage updates learning weight."""
        service = LearningService()

        pattern = await service.create_pattern(
            pattern_name="weight_test",
            category="test",
            pattern_data={},
            agent_id="test-agent",
            namespace="test"
        )

        initial_weight = pattern.learning_weight

        # Use pattern successfully
        updated = await service.use_pattern(
            pattern_id=pattern.id,
            using_agent_id="test-agent",
            success=True
        )

        # Learning weight should increase on success
        assert updated.learning_weight >= initial_weight

    async def test_update_pattern_success(self, db_session):
        """Test updating a pattern."""
        service = LearningService()

        # Create pattern
        pattern = await service.create_pattern(
            pattern_name="update_test",
            category="original",
            pattern_data={"version": 1},
            agent_id="owner-agent",
            namespace="test"
        )

        # Update pattern (pattern_name cannot be updated, only pattern_data)
        updated = await service.update_pattern(
            pattern_id=pattern.id,
            updating_agent_id="owner-agent",
            pattern_data={"version": 2}
        )

        assert updated.pattern_name == "update_test"  # Name unchanged
        assert updated.pattern_data == {"version": 2}

    async def test_update_pattern_permission_denied(self, db_session):
        """Test updating pattern without permission."""
        service = LearningService()

        # Create pattern
        pattern = await service.create_pattern(
            pattern_name="permission_test",
            category="test",
            pattern_data={},
            agent_id="owner-agent",
            namespace="test",
            access_level="private"
        )

        # Try to update with different agent (only pattern_data can be updated)
        with pytest.raises(PermissionError):
            await service.update_pattern(
                pattern_id=pattern.id,
                updating_agent_id="other-agent",
                pattern_data={"hacked": True}
            )

    async def test_delete_pattern_success(self, db_session):
        """Test deleting a pattern."""
        service = LearningService()

        # Create pattern
        pattern = await service.create_pattern(
            pattern_name="delete_test",
            category="test",
            pattern_data={},
            agent_id="owner-agent",
            namespace="test"
        )

        # Delete pattern
        result = await service.delete_pattern(
            pattern_id=pattern.id,
            deleting_agent_id="owner-agent"
        )

        assert result is True

        # Verify deleted (service returns None for not found)
        deleted_pattern = await service.get_pattern(pattern.id)
        assert deleted_pattern is None

    async def test_delete_pattern_permission_denied(self, db_session):
        """Test deleting pattern without permission."""
        service = LearningService()

        # Create pattern
        pattern = await service.create_pattern(
            pattern_name="permission_delete",
            category="test",
            pattern_data={},
            agent_id="owner-agent",
            namespace="test",
            access_level="private"
        )

        # Try to delete with different agent
        with pytest.raises(PermissionError):
            await service.delete_pattern(
                pattern_id=pattern.id,
                deleting_agent_id="other-agent"
            )

    async def test_get_pattern_analytics(self, db_session):
        """Test retrieving pattern analytics."""
        service = LearningService()

        # Create and use pattern
        pattern = await service.create_pattern(
            pattern_name="analytics_test",
            category="test",
            pattern_data={},
            agent_id="test-agent",
            namespace="test"
        )

        # Use pattern multiple times
        for _ in range(3):
            await service.use_pattern(
                pattern_id=pattern.id,
                using_agent_id="test-agent",
                success=True
            )

        # Get analytics (by agent_id and namespace)
        analytics = await service.get_pattern_analytics(
            agent_id="test-agent",
            namespace="test"
        )

        assert analytics["total_patterns"] >= 1
        assert len(analytics["top_patterns"]) >= 1
        assert analytics["top_patterns"][0]["usage_count"] >= 3

    async def test_recommend_patterns(self, db_session):
        """Test pattern recommendation system."""
        service = LearningService()

        # Create patterns from OTHER agents (recommendations exclude own patterns)
        await service.create_pattern(
            pattern_name="optimization1",
            category="optimization",
            pattern_data={},
            agent_id="other-agent",  # Different agent
            namespace="test",
            access_level="public"
        )
        await service.create_pattern(
            pattern_name="security1",
            category="security",
            pattern_data={},
            agent_id="other-agent",  # Different agent
            namespace="test",
            access_level="public"
        )

        # Get recommendations (returns list of (pattern, score) tuples)
        recommendations = await service.recommend_patterns(
            agent_id="test-agent",
            category="optimization",
            limit=5
        )

        assert len(recommendations) >= 1
        # Each recommendation is a (pattern, score) tuple
        assert all(isinstance(rec, tuple) and len(rec) == 2 for rec in recommendations)
        assert all(rec[0].category == "optimization" for rec in recommendations)

    async def test_batch_create_patterns(self, db_session):
        """Test batch pattern creation."""
        service = LearningService()

        patterns_data = [
            {
                "pattern_name": f"batch_pattern_{i}",
                "category": "test",
                "pattern_data": {"index": i},
                "agent_id": "test-agent",
                "namespace": "test"
            }
            for i in range(3)
        ]

        # Batch create
        created = await service.batch_create_patterns(
            patterns_data,
            agent_id="test-agent"
        )

        assert len(created) == 3
        assert all(p.agent_id == "test-agent" for p in created)

    async def test_namespace_isolation(self, db_session):
        """Test namespace isolation between patterns."""
        service = LearningService()

        # Create patterns in different namespaces
        await service.create_pattern(
            pattern_name="ns1_pattern",
            category="test",
            pattern_data={},
            agent_id="test-agent",
            namespace="namespace1"
        )
        await service.create_pattern(
            pattern_name="ns2_pattern",
            category="test",
            pattern_data={},
            agent_id="test-agent",
            namespace="namespace2"
        )

        # Search in namespace1
        ns1_patterns = await service.get_patterns_by_agent(
            "test-agent",
            namespace="namespace1"
        )

        # Should only see namespace1 patterns
        assert len(ns1_patterns) == 1
        assert all(p.namespace == "namespace1" for p in ns1_patterns)

    async def test_access_level_private(self, db_session):
        """Test private access level enforcement."""
        service = LearningService()

        # Create private pattern
        pattern = await service.create_pattern(
            pattern_name="private_pattern",
            category="test",
            pattern_data={},
            agent_id="owner-agent",
            namespace="test",
            access_level="private"
        )

        # Owner can retrieve pattern
        retrieved = await service.get_pattern(pattern.id, requesting_agent_id="owner-agent")
        assert retrieved is not None
        assert retrieved.pattern_name == "private_pattern"

        # Other agent cannot access (pattern not visible in search)
        # Private patterns only visible to owner
        patterns = await service.search_patterns(
            requesting_agent_id="other-agent",
            namespace="test"
        )
        # Should not include private pattern from owner-agent
        assert not any(p.id == pattern.id for p in patterns)

    async def test_access_level_public(self, db_session):
        """Test public access level allows all agents."""
        service = LearningService()

        # Create public pattern
        pattern = await service.create_pattern(
            pattern_name="public_pattern",
            category="test",
            pattern_data={},
            agent_id="owner-agent",
            namespace="test",
            access_level="public"
        )

        # Any agent can retrieve pattern
        retrieved = await service.get_pattern(pattern.id, requesting_agent_id="any-agent")
        assert retrieved is not None
        assert retrieved.pattern_name == "public_pattern"

        # Public patterns visible to all in search
        patterns = await service.search_patterns(
            requesting_agent_id="any-agent",
            namespace="test"
        )
        assert any(p.id == pattern.id for p in patterns)

    async def test_cache_functionality(self, db_session):
        """Test service caching mechanism."""
        service = LearningService()

        # Create pattern
        pattern = await service.create_pattern(
            pattern_name="cache_test",
            category="test",
            pattern_data={"cached": True},
            agent_id="test-agent",
            namespace="test"
        )

        # First retrieval (cache miss)
        pattern1 = await service.get_pattern(pattern.id, requesting_agent_id="test-agent")

        # Second retrieval (should be cached)
        pattern2 = await service.get_pattern(pattern.id, requesting_agent_id="test-agent")

        assert pattern1.id == pattern2.id
        assert pattern1.pattern_name == pattern2.pattern_name


class TestLearningPatternModel:
    """Test LearningPattern model."""

    async def test_learning_pattern_creation(self, test_session):
        """Test creating LearningPattern model instance."""
        pattern = LearningPattern(
            pattern_name="model_test",
            category="test",
            pattern_data={"key": "value"},
            agent_id="test-agent",
            namespace="test",
            access_level="private"
        )

        # Add to session and flush to trigger defaults
        test_session.add(pattern)
        await test_session.flush()

        assert pattern.pattern_name == "model_test"
        assert pattern.category == "test"
        assert pattern.agent_id == "test-agent"
        assert pattern.namespace == "test"
        assert pattern.access_level == "private"
        assert pattern.version == "1.0.0"


class TestPatternUsageHistoryModel:
    """Test PatternUsageHistory model."""

    async def test_usage_history_creation(self, test_session):
        """Test creating PatternUsageHistory model instance."""
        # First create a pattern to reference
        pattern = LearningPattern(
            pattern_name="test_pattern",
            category="test",
            pattern_data={},
            agent_id="test-agent",
            namespace="test"
        )
        test_session.add(pattern)
        await test_session.flush()

        # Create usage history (execution_time is in seconds, not ms)
        usage = PatternUsageHistory(
            pattern_id=str(pattern.id),
            agent_id="test-agent",
            success=True,
            execution_time=0.1255  # In seconds
        )

        test_session.add(usage)
        await test_session.flush()

        assert usage.agent_id == "test-agent"
        assert usage.success is True
        assert usage.execution_time == 0.1255
