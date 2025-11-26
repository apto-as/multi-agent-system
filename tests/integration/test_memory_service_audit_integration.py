"""Integration tests for SecurityAuditLog integration in HybridMemoryService.

These tests verify that audit logs are actually persisted to the database
and that the system gracefully handles audit logging failures.

Test Coverage:
    - Audit logs are persisted to SecurityAuditLog table
    - Graceful degradation when audit logging fails
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from sqlalchemy import select

from src.models.audit_log import SecurityAuditLog
from src.models.memory import Memory, AccessLevel
from src.models.agent import Agent
from src.services.memory_service import HybridMemoryService


@pytest.mark.asyncio
class TestAuditLogPersistence:
    """Test that audit logs are persisted to database."""

    async def test_audit_logs_persisted_to_database(self, test_session):
        """Verify audit logs are saved to SecurityAuditLog table."""
        # Arrange
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test-namespace",
        )
        test_session.add(agent)

        memory_id = uuid4()
        memory = Memory(
            id=memory_id,
            content="Test memory for TTL update",
            agent_id="test-agent",
            namespace="test-namespace",
            access_level=AccessLevel.PRIVATE,
            importance_score=0.5,
        )
        test_session.add(memory)
        await test_session.commit()

        # Create service and initialize audit logger
        service = HybridMemoryService(session=test_session)
        await service._ensure_audit_initialized()

        # Act: Perform operation that should create audit logs
        await service.set_memory_ttl(
            memory_id=memory_id,
            agent_id="test-agent",
            ttl_days=30,
        )

        # Assert: Check audit logs were created in database
        stmt = select(SecurityAuditLog).where(
            SecurityAuditLog.event_type.in_([
                "memory_ttl_update_initiated",
                "memory_ttl_update_complete"
            ])
        )
        result = await test_session.execute(stmt)
        audit_logs = result.scalars().all()

        # Should have 2 logs (BEFORE and AFTER)
        assert len(audit_logs) >= 2, f"Expected at least 2 audit logs, got {len(audit_logs)}"

        # Verify BEFORE log
        before_log = next(
            (log for log in audit_logs if log.event_type == "memory_ttl_update_initiated"),
            None
        )
        assert before_log is not None, "BEFORE audit log not found"
        assert before_log.severity == "MEDIUM"
        assert before_log.agent_id == "test-agent"

        # Verify AFTER log
        after_log = next(
            (log for log in audit_logs if log.event_type == "memory_ttl_update_complete"),
            None
        )
        assert after_log is not None, "AFTER audit log not found"
        assert after_log.severity == "LOW"
        assert after_log.agent_id == "test-agent"


@pytest.mark.asyncio
class TestGracefulDegradation:
    """Test that operations succeed even if audit logging fails."""

    async def test_audit_graceful_degradation(self, test_session):
        """Verify operations succeed even if audit logging fails."""
        # Arrange
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test-namespace",
        )
        test_session.add(agent)

        memory_id = uuid4()
        memory = Memory(
            id=memory_id,
            content="Test memory",
            agent_id="test-agent",
            namespace="test-namespace",
            access_level=AccessLevel.PRIVATE,
            importance_score=0.5,
        )
        test_session.add(memory)
        await test_session.commit()

        # Create service
        service = HybridMemoryService(session=test_session)

        # Mock audit logger to raise exception
        mock_logger = AsyncMock()
        mock_logger.log_event = AsyncMock(side_effect=Exception("Audit logging failed"))
        service.audit_logger = mock_logger

        # Act: Operation should succeed despite audit failure
        result = await service.set_memory_ttl(
            memory_id=memory_id,
            agent_id="test-agent",
            ttl_days=30,
        )

        # Assert: Operation succeeded
        assert result["success"] is True
        assert result["ttl_days"] == 30
        assert result["memory_id"] == str(memory_id)

        # Verify memory was actually updated in database
        stmt = select(Memory).where(Memory.id == memory_id)
        db_result = await test_session.execute(stmt)
        updated_memory = db_result.scalar_one()
        assert updated_memory.expires_at is not None
        assert updated_memory.updated_at is not None
