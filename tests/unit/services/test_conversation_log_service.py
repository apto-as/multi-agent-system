"""Tests for ConversationLogService."""

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from src.models.conversation_log import ConversationLog, ConversationSession
from src.models.memory import Memory
from src.services.conversation_log_service import ConversationLogService


@pytest.fixture
async def conversation_service(db_session):
    """Create conversation log service."""
    return ConversationLogService(db_session)


@pytest.fixture
async def sample_session_id():
    """Generate sample session ID."""
    return f"session-{uuid4()}"


@pytest.fixture
async def sample_agent_id():
    """Return sample agent ID."""
    return "artemis-optimizer"


class TestLogMessage:
    """Tests for log_message method."""

    async def test_log_user_message(self, conversation_service, sample_session_id, sample_agent_id):
        """Test logging a user message."""
        log = await conversation_service.log_message(
            agent_id=sample_agent_id,
            session_id=sample_session_id,
            role="user",
            content="Optimize this query performance",
            metadata={"task_type": "optimization", "phase": "phase_2_implementation"},
        )

        assert log.agent_id == sample_agent_id
        assert log.session_id == sample_session_id
        assert log.role == "user"
        assert log.content == "Optimize this query performance"
        assert log.context_metadata["task_type"] == "optimization"
        assert log.pattern_extracted is False
        assert log.skill_candidate is False

    async def test_log_assistant_message_with_timing(
        self, conversation_service, sample_session_id, sample_agent_id
    ):
        """Test logging an assistant message with response time."""
        log = await conversation_service.log_message(
            agent_id=sample_agent_id,
            session_id=sample_session_id,
            role="assistant",
            content="I'll analyze the query and suggest optimizations...",
            response_time_ms=1234,
        )

        assert log.role == "assistant"
        assert log.response_time_ms == 1234

    async def test_log_message_with_parent(
        self, conversation_service, sample_session_id, sample_agent_id
    ):
        """Test logging a threaded message with parent."""
        parent = await conversation_service.log_message(
            agent_id=sample_agent_id,
            session_id=sample_session_id,
            role="user",
            content="Parent message",
        )

        child = await conversation_service.log_message(
            agent_id=sample_agent_id,
            session_id=sample_session_id,
            role="assistant",
            content="Reply to parent",
            parent_message_id=str(parent.id),
        )

        assert child.parent_message_id == str(parent.id)

    async def test_log_message_invalid_role(
        self, conversation_service, sample_session_id, sample_agent_id
    ):
        """Test that invalid role raises ValidationError."""
        from src.core.exceptions import ValidationError

        with pytest.raises(ValidationError, match="Invalid role"):
            await conversation_service.log_message(
                agent_id=sample_agent_id,
                session_id=sample_session_id,
                role="invalid_role",
                content="Test",
            )


class TestLogMessageWithMemory:
    """Tests for log_message_with_memory method."""

    async def test_log_and_store_in_memory(
        self, conversation_service, sample_session_id, sample_agent_id, db_session
    ):
        """Test logging message and storing in TMWS memory."""
        log, memory = await conversation_service.log_message_with_memory(
            agent_id=sample_agent_id,
            session_id=sample_session_id,
            role="user",
            content="Test message for memory storage",
            store_in_memory=True,
        )

        assert log is not None
        assert memory is not None
        assert memory.namespace == ConversationLogService.CONVERSATION_NAMESPACE
        assert sample_agent_id in memory.tags
        assert sample_session_id in memory.tags
        assert "conversation" in memory.tags
        assert memory.context["conversation_log_id"] == str(log.id)

    async def test_log_without_memory_storage(
        self, conversation_service, sample_session_id, sample_agent_id
    ):
        """Test logging message without memory storage."""
        log, memory = await conversation_service.log_message_with_memory(
            agent_id=sample_agent_id,
            session_id=sample_session_id,
            role="user",
            content="Test message",
            store_in_memory=False,
        )

        assert log is not None
        assert memory is None


class TestSessionOperations:
    """Tests for session management."""

    async def test_create_session(self, conversation_service, sample_session_id, sample_agent_id):
        """Test creating a conversation session."""
        session = await conversation_service.create_session(
            session_id=sample_session_id,
            agent_id=sample_agent_id,
            task_type="optimization",
            phase="phase_2_implementation",
        )

        assert session.session_id == sample_session_id
        assert session.agent_id == sample_agent_id
        assert session.task_type == "optimization"
        assert session.phase == "phase_2_implementation"
        assert session.success is None
        assert session.started_at is not None
        assert session.completed_at is None

    async def test_get_session(self, conversation_service, sample_session_id, sample_agent_id):
        """Test retrieving a session."""
        # Create session
        await conversation_service.create_session(
            session_id=sample_session_id, agent_id=sample_agent_id
        )

        # Retrieve it
        session = await conversation_service.get_session(sample_session_id)
        assert session.session_id == sample_session_id

    async def test_get_session_not_found(self, conversation_service):
        """Test getting non-existent session raises NotFoundError."""
        from src.core.exceptions import NotFoundError

        with pytest.raises(NotFoundError):
            await conversation_service.get_session("nonexistent-session")

    async def test_complete_session(self, conversation_service, sample_session_id, sample_agent_id):
        """Test completing a session."""
        # Create session
        await conversation_service.create_session(
            session_id=sample_session_id, agent_id=sample_agent_id
        )

        # Complete it
        session = await conversation_service.complete_session(
            session_id=sample_session_id,
            success=True,
            outcome={"metrics": {"performance_gain": "40%"}, "artifacts": ["optimized_query.sql"]},
        )

        assert session.success is True
        assert session.completed_at is not None
        assert session.outcome["metrics"]["performance_gain"] == "40%"


class TestGetSessionLogs:
    """Tests for get_session_logs method."""

    async def test_get_logs_for_session(
        self, conversation_service, sample_session_id, sample_agent_id
    ):
        """Test retrieving all logs for a session."""
        # Create multiple logs
        await conversation_service.log_message(
            agent_id=sample_agent_id,
            session_id=sample_session_id,
            role="user",
            content="Message 1",
        )
        await conversation_service.log_message(
            agent_id=sample_agent_id,
            session_id=sample_session_id,
            role="assistant",
            content="Response 1",
        )
        await conversation_service.log_message(
            agent_id=sample_agent_id,
            session_id=sample_session_id,
            role="user",
            content="Message 2",
        )

        # Retrieve logs
        logs = await conversation_service.get_session_logs(sample_session_id)

        assert len(logs) == 3
        assert logs[0].content == "Message 1"  # Ordered by timestamp
        assert logs[1].content == "Response 1"
        assert logs[2].content == "Message 2"

    async def test_get_logs_filtered_by_agent(
        self, conversation_service, sample_session_id, sample_agent_id
    ):
        """Test retrieving logs filtered by agent."""
        # Create logs from different agents
        await conversation_service.log_message(
            agent_id=sample_agent_id,
            session_id=sample_session_id,
            role="user",
            content="Artemis message",
        )
        await conversation_service.log_message(
            agent_id="hestia-auditor",
            session_id=sample_session_id,
            role="assistant",
            content="Hestia message",
        )

        # Filter by agent
        logs = await conversation_service.get_session_logs(
            sample_session_id, agent_id=sample_agent_id
        )

        assert len(logs) == 1
        assert logs[0].agent_id == sample_agent_id


class TestSearchLogs:
    """Tests for search_logs method."""

    async def test_search_by_agent(self, conversation_service, sample_session_id):
        """Test searching logs by agent."""
        await conversation_service.log_message(
            agent_id="artemis-optimizer",
            session_id=sample_session_id,
            role="user",
            content="Artemis task",
        )
        await conversation_service.log_message(
            agent_id="hestia-auditor",
            session_id=sample_session_id,
            role="user",
            content="Hestia task",
        )

        logs = await conversation_service.search_logs(agent_id="artemis-optimizer")
        assert len(logs) == 1
        assert logs[0].agent_id == "artemis-optimizer"

    async def test_search_by_content(self, conversation_service, sample_session_id):
        """Test searching logs by content."""
        await conversation_service.log_message(
            agent_id="artemis-optimizer",
            session_id=sample_session_id,
            role="user",
            content="Optimize query performance",
        )
        await conversation_service.log_message(
            agent_id="artemis-optimizer",
            session_id=sample_session_id,
            role="user",
            content="Review security audit",
        )

        logs = await conversation_service.search_logs(content_contains="optimize")
        assert len(logs) == 1
        assert "Optimize" in logs[0].content

    async def test_search_by_time_range(self, conversation_service, sample_session_id):
        """Test searching logs by time range."""
        now = datetime.now(timezone.utc)
        past = now - timedelta(hours=2)
        future = now + timedelta(hours=2)

        await conversation_service.log_message(
            agent_id="artemis-optimizer",
            session_id=sample_session_id,
            role="user",
            content="Recent message",
        )

        logs = await conversation_service.search_logs(start_time=past, end_time=future)
        assert len(logs) >= 1

    async def test_search_skill_candidates(
        self, conversation_service, sample_session_id, db_session
    ):
        """Test searching for skill candidate logs."""
        log = await conversation_service.log_message(
            agent_id="artemis-optimizer",
            session_id=sample_session_id,
            role="user",
            content="Candidate message",
        )

        # Mark as skill candidate
        log.skill_candidate = True
        await db_session.flush()

        logs = await conversation_service.search_logs(skill_candidate=True)
        assert len(logs) >= 1
        assert all(log.skill_candidate for log in logs)


class TestExportForLearning:
    """Tests for export_for_learning method."""

    async def test_export_successful_sessions(
        self, conversation_service, sample_agent_id, db_session
    ):
        """Test exporting successful sessions for learning."""
        # Create a successful session with messages
        session_id = f"session-{uuid4()}"
        await conversation_service.create_session(
            session_id=session_id, agent_id=sample_agent_id, task_type="optimization"
        )

        await conversation_service.log_message(
            agent_id=sample_agent_id,
            session_id=session_id,
            role="user",
            content="Optimize query",
        )
        await conversation_service.log_message(
            agent_id=sample_agent_id,
            session_id=session_id,
            role="assistant",
            content="Analysis complete",
        )

        await conversation_service.complete_session(session_id=session_id, success=True)

        # Export
        export_data = await conversation_service.export_for_learning(
            agent_id=sample_agent_id, success_only=True
        )

        assert len(export_data) >= 1
        session_data = export_data[0]
        assert session_data["session"]["success"] is True
        assert session_data["message_count"] == 2
        assert "duration_seconds" in session_data

    async def test_export_by_task_type(self, conversation_service, sample_agent_id):
        """Test exporting sessions filtered by task type."""
        # Create sessions with different task types
        session_1 = f"session-{uuid4()}"
        await conversation_service.create_session(
            session_id=session_1, agent_id=sample_agent_id, task_type="optimization"
        )
        await conversation_service.complete_session(session_id=session_1, success=True)

        session_2 = f"session-{uuid4()}"
        await conversation_service.create_session(
            session_id=session_2, agent_id=sample_agent_id, task_type="security_audit"
        )
        await conversation_service.complete_session(session_id=session_2, success=True)

        # Export only optimization
        export_data = await conversation_service.export_for_learning(task_type="optimization")
        assert all(s["session"]["task_type"] == "optimization" for s in export_data)


class TestPatternExtraction:
    """Tests for pattern extraction flags."""

    async def test_mark_for_pattern_extraction(
        self, conversation_service, sample_session_id, sample_agent_id, db_session
    ):
        """Test marking logs for pattern extraction."""
        # Create logs
        log1 = await conversation_service.log_message(
            agent_id=sample_agent_id, session_id=sample_session_id, role="user", content="Test 1"
        )
        log2 = await conversation_service.log_message(
            agent_id=sample_agent_id, session_id=sample_session_id, role="user", content="Test 2"
        )

        # Mark for extraction
        count = await conversation_service.mark_for_pattern_extraction([log1.id, log2.id])

        assert count == 2

        # Verify flags
        await db_session.refresh(log1)
        await db_session.refresh(log2)
        assert log1.pattern_extracted is True
        assert log2.pattern_extracted is True

    async def test_mark_as_skill_candidate(
        self, conversation_service, sample_session_id, sample_agent_id, db_session
    ):
        """Test marking session as skill candidate."""
        # Create logs
        log1 = await conversation_service.log_message(
            agent_id=sample_agent_id, session_id=sample_session_id, role="user", content="Test 1"
        )
        log2 = await conversation_service.log_message(
            agent_id=sample_agent_id, session_id=sample_session_id, role="user", content="Test 2"
        )

        # Mark session
        count = await conversation_service.mark_as_skill_candidate(sample_session_id)

        assert count == 2

        # Verify flags
        await db_session.refresh(log1)
        await db_session.refresh(log2)
        assert log1.skill_candidate is True
        assert log2.skill_candidate is True


class TestStatistics:
    """Tests for get_statistics method."""

    async def test_get_overall_statistics(
        self, conversation_service, sample_session_id, sample_agent_id, db_session
    ):
        """Test getting overall conversation statistics."""
        # Create some data
        await conversation_service.create_session(
            session_id=sample_session_id, agent_id=sample_agent_id
        )
        await conversation_service.log_message(
            agent_id=sample_agent_id, session_id=sample_session_id, role="user", content="Test 1"
        )
        await conversation_service.log_message(
            agent_id=sample_agent_id, session_id=sample_session_id, role="user", content="Test 2"
        )

        stats = await conversation_service.get_statistics()

        assert stats["total_logs"] >= 2
        assert stats["total_sessions"] >= 1
        assert sample_agent_id in stats["logs_by_agent"]

    async def test_get_statistics_filtered_by_agent(
        self, conversation_service, sample_session_id, db_session
    ):
        """Test statistics filtered by agent."""
        await conversation_service.log_message(
            agent_id="artemis-optimizer",
            session_id=sample_session_id,
            role="user",
            content="Artemis",
        )
        await conversation_service.log_message(
            agent_id="hestia-auditor", session_id=sample_session_id, role="user", content="Hestia"
        )

        stats = await conversation_service.get_statistics(agent_id="artemis-optimizer")

        assert stats["total_logs"] == 1
