"""
Security Tests for Audit Logging (TMWS v2.3.0 Phase 1B Part 4)

Tests structured audit logging for security-critical operations:
- memory_access_tracked: When access tracking succeeds/fails (rate limiting)
- memory_ttl_set: When TTL is set during memory creation
- ttl_validation_failed: When TTL validation fails
- access_level_ttl_limit_exceeded: When access-level TTL limit is exceeded

This uses Python's standard logging with structured fields for audit trail.
"""

import logging
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from src.core.exceptions import ValidationError
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
    return session


@pytest.fixture
def memory_service(mock_session):
    """Create HybridMemoryService with mocked dependencies."""
    return HybridMemoryService(mock_session)


def create_test_memory(memory_id: str | None = None, **kwargs) -> Memory:
    """Create a test Memory object with optional overrides."""
    defaults = {
        "id": memory_id or str(uuid4()),
        "content": "Test memory content",
        "agent_id": "test-agent",
        "namespace": "test_namespace",
        "importance_score": 0.8,
        "relevance_score": 0.5,
        "access_count": 0,
        "accessed_at": None,
        "access_level": AccessLevel.PRIVATE,
        "tags": ["test"],
        "context": {},
        "embedding_model": "zylonai/multilingual-e5-large",
        "embedding_dimension": 1024,
    }
    defaults.update(kwargs)
    return Memory(**defaults)


class TestAccessTrackingAuditLogs:
    """Test audit logs for memory access tracking."""

    @pytest.mark.asyncio
    async def test_access_tracked_logs_success(self, memory_service, mock_session, caplog):
        """Test that successful access tracking logs audit event."""
        # Arrange
        memory_id = str(uuid4())
        test_memory = create_test_memory(memory_id)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result

        # Act
        with caplog.at_level(logging.INFO):
            result = await memory_service.get_memory(memory_id, track_access=True)

        # Assert
        assert result is not None
        # Look for audit log with structured fields
        audit_logs = [r for r in caplog.records if "memory_access_tracked" in r.getMessage()]
        assert len(audit_logs) == 1

        log_record = audit_logs[0]
        assert log_record.levelname == "INFO"
        assert log_record.memory_id == memory_id
        assert log_record.agent_id == "test-agent"
        assert log_record.access_count == 1
        assert log_record.tracked is True

    @pytest.mark.asyncio
    async def test_access_rate_limited_logs_event(self, memory_service, mock_session, caplog):
        """Test that rate-limited access logs audit event with tracked=False."""
        # Arrange
        memory_id = str(uuid4())
        base_time = datetime.now(timezone.utc)

        test_memory = create_test_memory(
            memory_id=memory_id,
            accessed_at=base_time,  # Recent access
            access_count=5,
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result

        # Act - Access within 5-second window
        current_time = base_time  # Same time = within window
        with patch("src.services.memory_service.datetime") as mock_dt, caplog.at_level(logging.INFO):
            mock_dt.now.return_value = current_time
            mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)

            result = await memory_service.get_memory(memory_id, track_access=True)

        # Assert
        assert result is not None
        # Look for rate limit audit log
        audit_logs = [r for r in caplog.records if "memory_access_rate_limited" in r.getMessage()]
        assert len(audit_logs) == 1

        log_record = audit_logs[0]
        assert log_record.levelname == "INFO"
        assert log_record.memory_id == memory_id
        assert log_record.agent_id == "test-agent"
        assert log_record.tracked is False
        assert log_record.reason == "rate_limited"


class TestTTLValidationAuditLogs:
    """Test audit logs for TTL validation."""

    @pytest.mark.asyncio
    async def test_ttl_set_logs_success(self, memory_service, mock_session, caplog):
        """Test that setting TTL logs audit event."""
        # Arrange
        memory_data = {
            "content": "Test content",
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "ttl_days": 30,
        }

        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)
        memory_service.vector_service.add_memory = AsyncMock()

        # Act
        with caplog.at_level(logging.INFO):
            result = await memory_service.create_memory(**memory_data)

        # Assert
        assert result is not None
        # Look for TTL set audit log
        audit_logs = [r for r in caplog.records if "memory_ttl_set" in r.getMessage()]
        assert len(audit_logs) == 1

        log_record = audit_logs[0]
        assert log_record.levelname == "INFO"
        assert log_record.agent_id == "test-agent"
        assert log_record.ttl_days == 30
        assert log_record.access_level == "private"

    @pytest.mark.asyncio
    async def test_ttl_validation_failed_logs_error(self, memory_service, mock_session, caplog):
        """Test that TTL validation failure logs audit event."""
        # Arrange
        memory_data = {
            "content": "Test content",
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "ttl_days": 4000,  # Exceeds max 3650 days
        }

        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)

        # Act
        with caplog.at_level(logging.WARNING), pytest.raises(ValueError):
            await memory_service.create_memory(**memory_data)

        # Assert
        # Look for TTL validation failure audit log
        audit_logs = [r for r in caplog.records if "ttl_validation_failed" in r.getMessage()]
        assert len(audit_logs) == 1

        log_record = audit_logs[0]
        assert log_record.levelname == "WARNING"
        assert log_record.agent_id == "test-agent"
        assert log_record.ttl_days == 4000
        assert log_record.validation_error == "value_too_high"


class TestAccessLevelTTLLimitAuditLogs:
    """Test audit logs for access-level TTL limit validation."""

    @pytest.mark.asyncio
    async def test_access_level_ttl_limit_exceeded_logs_warning(
        self, memory_service, mock_session, caplog
    ):
        """Test that access-level TTL limit exceeded logs audit event."""
        # Arrange
        memory_data = {
            "content": "Private data",
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "access_level": AccessLevel.PRIVATE,
            "ttl_days": 366,  # Exceeds PRIVATE max of 365
        }

        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)

        # Act
        with caplog.at_level(logging.WARNING), pytest.raises(ValidationError):
            await memory_service.create_memory(**memory_data)

        # Assert
        # Look for access-level TTL limit audit log
        audit_logs = [
            r for r in caplog.records if "access_level_ttl_limit_exceeded" in r.getMessage()
        ]
        assert len(audit_logs) == 1

        log_record = audit_logs[0]
        assert log_record.levelname == "WARNING"
        assert log_record.agent_id == "test-agent"
        assert log_record.access_level == "private"
        assert log_record.ttl_days == 366
        assert log_record.max_allowed == 365

    @pytest.mark.asyncio
    async def test_system_ttl_not_none_logs_warning(self, memory_service, mock_session, caplog):
        """Test that SYSTEM memory with TTL logs audit event."""
        # Arrange
        memory_data = {
            "content": "System data",
            "agent_id": "system",
            "namespace": "system",
            "access_level": AccessLevel.SYSTEM,
            "ttl_days": 30,  # SYSTEM requires None only
        }

        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)

        # Act
        with caplog.at_level(logging.WARNING), pytest.raises(ValidationError):
            await memory_service.create_memory(**memory_data)

        # Assert
        # Look for SYSTEM TTL violation audit log
        audit_logs = [
            r for r in caplog.records if "access_level_ttl_limit_exceeded" in r.getMessage()
        ]
        assert len(audit_logs) == 1

        log_record = audit_logs[0]
        assert log_record.levelname == "WARNING"
        assert log_record.agent_id == "system"
        assert log_record.access_level == "system"
        assert log_record.ttl_days == 30
        assert log_record.max_allowed is None  # None = permanent only


class TestAuditLogStructure:
    """Test audit log structure and format."""

    @pytest.mark.asyncio
    async def test_audit_logs_include_timestamp(self, memory_service, mock_session, caplog):
        """Test that all audit logs include timestamp."""
        # Arrange
        memory_id = str(uuid4())
        test_memory = create_test_memory(memory_id)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result

        # Act
        with caplog.at_level(logging.INFO):
            await memory_service.get_memory(memory_id, track_access=True)

        # Assert
        audit_logs = [r for r in caplog.records if "memory_access_tracked" in r.getMessage()]
        assert len(audit_logs) == 1

        log_record = audit_logs[0]
        assert hasattr(log_record, "created")
        assert isinstance(log_record.created, float)

    @pytest.mark.asyncio
    async def test_audit_logs_json_serializable(self, memory_service, mock_session, caplog):
        """Test that audit log extra fields are JSON serializable."""
        import json

        # Arrange
        memory_id = str(uuid4())
        test_memory = create_test_memory(memory_id)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result

        # Act
        with caplog.at_level(logging.INFO):
            await memory_service.get_memory(memory_id, track_access=True)

        # Assert
        audit_logs = [r for r in caplog.records if "memory_access_tracked" in r.getMessage()]
        assert len(audit_logs) == 1

        log_record = audit_logs[0]
        # Extract extra fields
        extra_fields = {
            "memory_id": log_record.memory_id,
            "agent_id": log_record.agent_id,
            "access_count": log_record.access_count,
            "tracked": log_record.tracked,
        }

        # Should be JSON serializable
        json_str = json.dumps(extra_fields)
        assert json_str is not None
        assert "memory_id" in json_str
