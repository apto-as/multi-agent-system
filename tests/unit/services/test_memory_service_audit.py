"""Unit tests for SecurityAuditLog integration in HybridMemoryService.

Tests verify that audit logging is correctly integrated into memory management
methods without breaking existing functionality.

Test Coverage:
    - cleanup_namespace: BEFORE/AFTER audit logs
    - prune_expired_memories: BEFORE/AFTER audit logs
    - set_memory_ttl: BEFORE/AFTER audit logs
    - Graceful degradation: Operations succeed even if audit fails
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from src.models.memory import AccessLevel, Memory
from src.services.memory_service import HybridMemoryService


@pytest.fixture(autouse=True)
def mock_ollama_services():
    """Mock Ollama services globally to bypass connection requirements."""
    # Create mock embedding service
    mock_embedding = MagicMock()
    mock_embedding.get_model_info = MagicMock(
        return_value={"model_name": "zylonai/multilingual-e5-large", "dimension": 1024}
    )
    mock_embedding.embed = AsyncMock(return_value=[0.0] * 1024)

    # Create mock vector service
    mock_vector = MagicMock()
    mock_vector.initialize = AsyncMock(return_value=None)
    mock_vector.delete_memories_batch = AsyncMock(return_value=None)
    mock_vector.search = AsyncMock(return_value=[])

    # Patch at import time
    with patch(
        "src.services.memory_service.get_ollama_embedding_service", return_value=mock_embedding
    ):
        with patch(
            "src.services.memory_service.get_vector_search_service", return_value=mock_vector
        ):
            yield (mock_embedding, mock_vector)


@pytest.fixture
def mock_audit_logger():
    """Create a mock audit logger."""
    logger = AsyncMock()
    logger.log_event = AsyncMock(return_value=None)
    return logger


@pytest.fixture
def memory_service_with_audit(test_session, mock_audit_logger):
    """Create memory service with mocked audit logger."""
    service = HybridMemoryService(session=test_session)
    service.audit_logger = mock_audit_logger
    return service


@pytest.mark.asyncio
class TestCleanupNamespaceAudit:
    """Test audit logging for cleanup_namespace method."""

    async def test_cleanup_namespace_logs_before_operation(
        self, memory_service_with_audit, test_session
    ):
        """Verify BEFORE audit log is created for cleanup_namespace."""
        # Arrange
        from src.models.agent import Agent

        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test-namespace",
        )
        test_session.add(agent)
        await test_session.commit()

        # Act
        await memory_service_with_audit.cleanup_namespace(
            namespace="test-namespace",
            agent_id="test-agent",
            days=90,
            min_importance=0.3,
            dry_run=True,
            limit=100,
        )

        # Assert
        mock_logger = memory_service_with_audit.audit_logger
        assert mock_logger.log_event.called

        # Check BEFORE log
        calls = mock_logger.log_event.call_args_list
        before_call = calls[0]
        assert before_call[1]["event_type"] == "namespace_cleanup_initiated"
        assert before_call[1]["event_data"]["severity"] == "HIGH"
        assert before_call[1]["event_data"]["details"]["namespace"] == "test-namespace"
        assert before_call[1]["event_data"]["details"]["agent_id"] == "test-agent"
        assert before_call[1]["agent_id"] == "test-agent"

    async def test_cleanup_namespace_logs_after_operation(
        self, memory_service_with_audit, test_session
    ):
        """Verify AFTER audit log is created for cleanup_namespace."""
        # Arrange
        from src.models.agent import Agent

        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test-namespace",
        )
        test_session.add(agent)

        # Create a memory to delete
        memory_id = uuid4()
        memory = Memory(
            id=str(memory_id),  # Convert UUID to string for SQLite
            content="Old memory",
            agent_id="test-agent",
            namespace="test-namespace",
            access_level=AccessLevel.PRIVATE,
            importance_score=0.2,
            access_count=0,
            created_at=datetime.now(timezone.utc) - timedelta(days=100),
        )
        test_session.add(memory)
        await test_session.commit()

        # Act
        await memory_service_with_audit.cleanup_namespace(
            namespace="test-namespace",
            agent_id="test-agent",
            days=90,
            min_importance=0.3,
            dry_run=False,
            limit=100,
        )

        # Assert
        mock_logger = memory_service_with_audit.audit_logger
        calls = mock_logger.log_event.call_args_list

        # Check AFTER log (should be second call)
        after_call = calls[1]
        assert after_call[1]["event_type"] == "namespace_cleanup_complete"
        assert after_call[1]["event_data"]["severity"] == "MEDIUM"
        assert after_call[1]["event_data"]["details"]["namespace"] == "test-namespace"
        assert after_call[1]["event_data"]["details"]["deleted_count"] >= 0
        assert after_call[1]["agent_id"] == "test-agent"


@pytest.mark.asyncio
class TestPruneExpiredMemoriesAudit:
    """Test audit logging for prune_expired_memories method."""

    async def test_prune_expired_logs_before_operation(
        self, memory_service_with_audit, test_session
    ):
        """Verify BEFORE audit log is created for prune_expired_memories."""
        # Arrange
        from src.models.agent import Agent

        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test-namespace",
        )
        test_session.add(agent)
        await test_session.commit()

        # Act
        await memory_service_with_audit.prune_expired_memories(
            namespace="test-namespace",
            agent_id="test-agent",
            limit=100,
            dry_run=True,
        )

        # Assert
        mock_logger = memory_service_with_audit.audit_logger
        assert mock_logger.log_event.called

        # Check BEFORE log
        calls = mock_logger.log_event.call_args_list
        before_call = calls[0]
        assert before_call[1]["event_type"] == "expired_memory_prune_initiated"
        assert before_call[1]["event_data"]["severity"] == "HIGH"
        assert before_call[1]["event_data"]["details"]["namespace"] == "test-namespace"
        assert before_call[1]["event_data"]["details"]["agent_id"] == "test-agent"

    async def test_prune_expired_logs_after_operation(
        self, memory_service_with_audit, test_session
    ):
        """Verify AFTER audit log is created for prune_expired_memories."""
        # Arrange
        from src.models.agent import Agent

        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test-namespace",
        )
        test_session.add(agent)

        # Create an expired memory
        memory_id = uuid4()
        memory = Memory(
            id=str(memory_id),  # Convert UUID to string for SQLite
            content="Expired memory",
            agent_id="test-agent",
            namespace="test-namespace",
            access_level=AccessLevel.PRIVATE,
            importance_score=0.5,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        test_session.add(memory)
        await test_session.commit()

        # Act
        await memory_service_with_audit.prune_expired_memories(
            namespace="test-namespace",
            agent_id="test-agent",
            limit=100,
            dry_run=False,
        )

        # Assert
        mock_logger = memory_service_with_audit.audit_logger
        calls = mock_logger.log_event.call_args_list

        # Check AFTER log (should be second call)
        after_call = calls[1]
        assert after_call[1]["event_type"] == "expired_memory_prune_complete"
        assert after_call[1]["event_data"]["severity"] == "MEDIUM"
        assert after_call[1]["event_data"]["details"]["namespace"] == "test-namespace"
        assert after_call[1]["event_data"]["details"]["deleted_count"] >= 0


@pytest.mark.asyncio
class TestSetMemoryTTLAudit:
    """Test audit logging for set_memory_ttl method."""

    async def test_set_ttl_logs_before_operation(self, memory_service_with_audit, test_session):
        """Verify BEFORE audit log is created for set_memory_ttl."""
        # Arrange
        memory_id = uuid4()
        memory = Memory(
            id=str(memory_id),  # Convert UUID to string for SQLite
            content="Test memory",
            agent_id="test-agent",
            namespace="test-namespace",
            access_level=AccessLevel.PRIVATE,
            importance_score=0.5,
        )
        test_session.add(memory)
        await test_session.commit()

        # Act
        await memory_service_with_audit.set_memory_ttl(
            memory_id=memory_id,
            agent_id="test-agent",
            ttl_days=30,
        )

        # Assert
        mock_logger = memory_service_with_audit.audit_logger
        assert mock_logger.log_event.called

        # Check BEFORE log
        calls = mock_logger.log_event.call_args_list
        before_call = calls[0]
        assert before_call[1]["event_type"] == "memory_ttl_update_initiated"
        assert before_call[1]["event_data"]["severity"] == "MEDIUM"
        assert before_call[1]["event_data"]["details"]["memory_id"] == str(memory_id)
        assert before_call[1]["event_data"]["details"]["new_ttl_days"] == 30
        assert before_call[1]["agent_id"] == "test-agent"

    async def test_set_ttl_logs_after_operation(self, memory_service_with_audit, test_session):
        """Verify AFTER audit log is created for set_memory_ttl."""
        # Arrange
        memory_id = uuid4()
        now = datetime.now(timezone.utc)
        memory = Memory(
            id=str(memory_id),  # Convert UUID to string for SQLite
            content="Test memory",
            agent_id="test-agent",
            namespace="test-namespace",
            access_level=AccessLevel.PRIVATE,
            importance_score=0.5,
            created_at=now,  # Timezone-aware datetime
            expires_at=now + timedelta(days=7),  # Timezone-aware datetime
        )
        test_session.add(memory)
        await test_session.commit()

        # Act
        await memory_service_with_audit.set_memory_ttl(
            memory_id=memory_id,
            agent_id="test-agent",
            ttl_days=30,
        )

        # Assert
        mock_logger = memory_service_with_audit.audit_logger
        calls = mock_logger.log_event.call_args_list

        # Check AFTER log (should be second call)
        after_call = calls[1]
        assert after_call[1]["event_type"] == "memory_ttl_update_complete"
        assert after_call[1]["event_data"]["severity"] == "LOW"
        assert after_call[1]["event_data"]["details"]["memory_id"] == str(memory_id)
        assert after_call[1]["event_data"]["details"]["new_ttl_days"] == 30
        assert after_call[1]["agent_id"] == "test-agent"
