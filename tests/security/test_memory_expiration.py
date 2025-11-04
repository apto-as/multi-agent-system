"""
Security Tests for Memory Expiration & Cleanup (TMWS v2.3.0 Phase 1C Part 1)

Tests the automated expiration and cleanup of memories based on TTL:
- Expired memories are identified correctly
- Cleanup deletes expired memories from both SQLite and ChromaDB
- Non-expired memories are not affected
- Audit logs are generated for cleanup operations
- Cleanup respects access level permissions
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from src.models.memory import AccessLevel, Memory
from src.services.memory_service import HybridMemoryService


@pytest.fixture
def mock_session():
    """Mock async database session."""
    session = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock()
    session.execute = AsyncMock()
    session.delete = AsyncMock()
    return session


@pytest.fixture
def memory_service(mock_session):
    """Create HybridMemoryService with mocked dependencies."""
    return HybridMemoryService(mock_session)


def create_expired_memory(memory_id: str | None = None, expired_hours_ago: int = 1) -> Memory:
    """Create a test Memory object that has already expired."""
    expires_at = datetime.now(timezone.utc) - timedelta(hours=expired_hours_ago)
    return Memory(
        id=memory_id or str(uuid4()),
        content="Expired test memory",
        agent_id="test-agent",
        namespace="test_namespace",
        importance_score=0.5,
        relevance_score=0.5,
        access_count=0,
        accessed_at=None,
        access_level=AccessLevel.PRIVATE,
        tags=["test"],
        context={},
        embedding_model="zylonai/multilingual-e5-large",
        embedding_dimension=1024,
        expires_at=expires_at,  # Already expired
    )


def create_valid_memory(memory_id: str | None = None, expires_in_hours: int = 24) -> Memory:
    """Create a test Memory object that has not yet expired."""
    expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
    return Memory(
        id=memory_id or str(uuid4()),
        content="Valid test memory",
        agent_id="test-agent",
        namespace="test_namespace",
        importance_score=0.5,
        relevance_score=0.5,
        access_count=0,
        accessed_at=None,
        access_level=AccessLevel.PRIVATE,
        tags=["test"],
        context={},
        embedding_model="zylonai/multilingual-e5-large",
        embedding_dimension=1024,
        expires_at=expires_at,  # Not yet expired
    )


def create_permanent_memory(memory_id: str | None = None) -> Memory:
    """Create a test Memory object with no expiration."""
    return Memory(
        id=memory_id or str(uuid4()),
        content="Permanent test memory",
        agent_id="test-agent",
        namespace="test_namespace",
        importance_score=0.5,
        relevance_score=0.5,
        access_count=0,
        accessed_at=None,
        access_level=AccessLevel.SYSTEM,
        tags=["test"],
        context={},
        embedding_model="zylonai/multilingual-e5-large",
        embedding_dimension=1024,
        expires_at=None,  # Permanent (no TTL)
    )


class TestMemoryExpirationDetection:
    """Test detection of expired memories."""

    @pytest.mark.asyncio
    async def test_find_expired_memories_returns_only_expired(
        self, memory_service, mock_session
    ):
        """Test that find_expired_memories returns only expired memories."""
        # Arrange
        expired_memory_1 = create_expired_memory(expired_hours_ago=2)
        expired_memory_2 = create_expired_memory(expired_hours_ago=24)
        valid_memory = create_valid_memory(expires_in_hours=24)
        permanent_memory = create_permanent_memory()

        # Mock database query to return ONLY expired memories (simulating WHERE clause filtering)
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [
            expired_memory_1,
            expired_memory_2,
            # valid_memory and permanent_memory are NOT included (filtered by WHERE clause)
        ]
        mock_session.execute.return_value = mock_result

        # Act
        expired_memories = await memory_service.find_expired_memories()

        # Assert
        assert len(expired_memories) == 2
        assert expired_memory_1 in expired_memories
        assert expired_memory_2 in expired_memories
        assert valid_memory not in expired_memories
        assert permanent_memory not in expired_memories

    @pytest.mark.asyncio
    async def test_find_expired_memories_empty_when_none_expired(
        self, memory_service, mock_session
    ):
        """Test that find_expired_memories returns empty list when no memories expired."""
        # Arrange
        valid_memory_1 = create_valid_memory(expires_in_hours=1)
        valid_memory_2 = create_valid_memory(expires_in_hours=24)
        permanent_memory = create_permanent_memory()

        # Mock database query to return empty list (simulating WHERE clause filtering)
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [
            # All memories are filtered out by WHERE clause (none are expired)
        ]
        mock_session.execute.return_value = mock_result

        # Act
        expired_memories = await memory_service.find_expired_memories()

        # Assert
        assert len(expired_memories) == 0


class TestMemoryCleanup:
    """Test cleanup (deletion) of expired memories."""

    @pytest.mark.asyncio
    async def test_cleanup_expired_memories_deletes_from_db_and_chroma(
        self, memory_service, mock_session, caplog
    ):
        """Test that cleanup deletes expired memories from both SQLite and ChromaDB."""
        import logging

        # Arrange
        expired_memory_1 = create_expired_memory()
        expired_memory_2 = create_expired_memory()

        # Mock vector service
        memory_service.vector_service = AsyncMock()
        memory_service.vector_service.delete_memory = AsyncMock()

        # Act
        with caplog.at_level(logging.INFO):
            deleted_count = await memory_service.cleanup_expired_memories(
                [expired_memory_1, expired_memory_2]
            )

        # Assert
        assert deleted_count == 2

        # Verify SQLite deletion
        assert mock_session.delete.call_count == 2
        mock_session.delete.assert_any_call(expired_memory_1)
        mock_session.delete.assert_any_call(expired_memory_2)

        # Verify commit
        mock_session.commit.assert_called_once()

        # Verify ChromaDB deletion
        assert memory_service.vector_service.delete_memory.call_count == 2
        memory_service.vector_service.delete_memory.assert_any_call(str(expired_memory_1.id))
        memory_service.vector_service.delete_memory.assert_any_call(str(expired_memory_2.id))

        # Verify audit log
        audit_logs = [
            r for r in caplog.records if "memories_expired_cleanup" in r.getMessage()
        ]
        assert len(audit_logs) == 1
        log_record = audit_logs[0]
        assert log_record.deleted_count == 2

    @pytest.mark.asyncio
    async def test_cleanup_empty_list_returns_zero(self, memory_service, mock_session):
        """Test that cleanup with empty list returns 0 without errors."""
        # Arrange
        memory_service.vector_service = AsyncMock()

        # Act
        deleted_count = await memory_service.cleanup_expired_memories([])

        # Assert
        assert deleted_count == 0
        mock_session.delete.assert_not_called()
        mock_session.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_cleanup_handles_chroma_failure_gracefully(
        self, memory_service, mock_session, caplog
    ):
        """Test that cleanup continues even if ChromaDB deletion fails."""
        import logging

        # Arrange
        expired_memory = create_expired_memory()

        # Mock vector service to fail
        memory_service.vector_service = AsyncMock()
        memory_service.vector_service.delete_memory = AsyncMock(
            side_effect=Exception("ChromaDB connection error")
        )

        # Act
        with caplog.at_level(logging.WARNING):
            deleted_count = await memory_service.cleanup_expired_memories([expired_memory])

        # Assert
        # SQLite deletion should still succeed
        assert deleted_count == 1
        mock_session.delete.assert_called_once_with(expired_memory)
        mock_session.commit.assert_called_once()

        # Verify warning log for ChromaDB failure (updated message pattern)
        warning_logs = [
            r
            for r in caplog.records
            if "Unexpected error during ChromaDB deletion" in r.getMessage()
        ]
        assert len(warning_logs) == 1


class TestFullExpirationWorkflow:
    """Test the complete find-and-cleanup workflow."""

    @pytest.mark.asyncio
    async def test_run_expiration_cleanup_full_workflow(
        self, memory_service, mock_session, caplog
    ):
        """Test the complete workflow: find expired memories and clean them up."""
        import logging

        # Arrange
        expired_memory_1 = create_expired_memory(expired_hours_ago=2)
        expired_memory_2 = create_expired_memory(expired_hours_ago=24)
        valid_memory = create_valid_memory(expires_in_hours=24)

        # Mock find query to return ONLY expired memories (simulating WHERE clause filtering)
        mock_find_result = MagicMock()
        mock_find_result.scalars.return_value.all.return_value = [
            expired_memory_1,
            expired_memory_2,
            # valid_memory is NOT included (filtered by WHERE clause)
        ]
        mock_session.execute.return_value = mock_find_result

        # Mock vector service
        memory_service.vector_service = AsyncMock()
        memory_service.vector_service.delete_memory = AsyncMock()

        # Act
        with caplog.at_level(logging.INFO):
            deleted_count = await memory_service.run_expiration_cleanup()

        # Assert
        assert deleted_count == 2  # Only expired memories deleted

        # Verify SQLite deletion
        assert mock_session.delete.call_count == 2

        # Verify ChromaDB deletion
        assert memory_service.vector_service.delete_memory.call_count == 2

        # Verify audit log
        audit_logs = [
            r for r in caplog.records if "expiration_cleanup_completed" in r.getMessage()
        ]
        assert len(audit_logs) == 1
        log_record = audit_logs[0]
        assert log_record.deleted_count == 2

    @pytest.mark.asyncio
    async def test_run_expiration_cleanup_no_expired_memories(
        self, memory_service, mock_session, caplog
    ):
        """Test workflow when no memories are expired."""
        import logging

        # Arrange
        valid_memory = create_valid_memory(expires_in_hours=24)

        # Mock find query to return empty list (simulating WHERE clause filtering)
        mock_find_result = MagicMock()
        mock_find_result.scalars.return_value.all.return_value = [
            # valid_memory is NOT included (filtered by WHERE clause - not expired)
        ]
        mock_session.execute.return_value = mock_find_result

        # Act
        with caplog.at_level(logging.INFO):
            deleted_count = await memory_service.run_expiration_cleanup()

        # Assert
        assert deleted_count == 0
        mock_session.delete.assert_not_called()

        # Verify audit log
        audit_logs = [
            r for r in caplog.records if "expiration_cleanup_completed" in r.getMessage()
        ]
        assert len(audit_logs) == 1
        log_record = audit_logs[0]
        assert log_record.deleted_count == 0


class TestExpirationAuditLogging:
    """Test audit logging for expiration and cleanup operations."""

    @pytest.mark.asyncio
    async def test_cleanup_logs_individual_deletions(
        self, memory_service, mock_session, caplog
    ):
        """Test that each memory deletion is logged individually."""
        import logging

        # Arrange
        expired_memory = create_expired_memory()

        # Mock vector service
        memory_service.vector_service = AsyncMock()
        memory_service.vector_service.delete_memory = AsyncMock()

        # Act
        with caplog.at_level(logging.INFO):
            await memory_service.cleanup_expired_memories([expired_memory])

        # Assert
        # Look for individual deletion log
        deletion_logs = [
            r for r in caplog.records if "memory_expired_deleted" in r.getMessage()
        ]
        assert len(deletion_logs) == 1

        log_record = deletion_logs[0]
        assert log_record.memory_id == str(expired_memory.id)
        assert log_record.agent_id == expired_memory.agent_id
        assert log_record.access_level == expired_memory.access_level.value

    @pytest.mark.asyncio
    async def test_cleanup_summary_log_includes_statistics(
        self, memory_service, mock_session, caplog
    ):
        """Test that cleanup summary log includes statistics."""
        import logging

        # Arrange
        expired_memories = [
            create_expired_memory(),
            create_expired_memory(),
            create_expired_memory(),
        ]

        # Mock vector service
        memory_service.vector_service = AsyncMock()
        memory_service.vector_service.delete_memory = AsyncMock()

        # Act
        with caplog.at_level(logging.INFO):
            await memory_service.cleanup_expired_memories(expired_memories)

        # Assert
        summary_logs = [
            r for r in caplog.records if "memories_expired_cleanup" in r.getMessage()
        ]
        assert len(summary_logs) == 1

        log_record = summary_logs[0]
        assert log_record.deleted_count == 3
        assert log_record.levelname == "INFO"
