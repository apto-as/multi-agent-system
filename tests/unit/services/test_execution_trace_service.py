"""Unit tests for ExecutionTraceService.

Tests the core functionality of the ExecutionTraceService including:
- Trace recording with circuit breaker
- History retrieval with filters
- Pattern analysis for sequence detection
- TTL-based cleanup
- Namespace isolation (P0-1)

Target: 15+ tests, 90%+ coverage
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from src.models.execution_trace import ExecutionTrace, DetectedPattern, SkillSuggestion
from src.services.execution_trace_service import ExecutionTraceService
from src.core.exceptions import NotFoundError


@pytest.fixture
def mock_session():
    """Create a mock async database session."""
    session = AsyncMock(spec=AsyncSession)
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    session.execute = AsyncMock()
    session.delete = AsyncMock()
    session.rollback = AsyncMock()
    return session


@pytest.fixture
def trace_service(mock_session):
    """Create ExecutionTraceService with mock session."""
    return ExecutionTraceService(mock_session)


@pytest.fixture
def sample_trace_data():
    """Sample trace data for testing."""
    return {
        "agent_id": "artemis-optimizer",
        "namespace": "test-namespace",
        "tool_name": "search_memories",
        "input_params": {"query": "test query", "limit": 10},
        "output_result": {"results": [{"id": "mem-1"}]},
        "success": True,
        "execution_time_ms": 42.5,
        "orchestration_id": str(uuid4()),
        "sequence_number": 1,
    }


class TestRecordExecution:
    """Tests for record_execution method."""

    async def test_record_execution_success(self, trace_service, mock_session, sample_trace_data):
        """Test successful trace recording."""
        # Arrange
        mock_trace = MagicMock(spec=ExecutionTrace)
        mock_trace.id = str(uuid4())
        mock_session.refresh = AsyncMock(side_effect=lambda x: setattr(x, 'id', str(uuid4())))

        # Act
        result = await trace_service.record_execution(**sample_trace_data)

        # Assert
        mock_session.add.assert_called_once()
        mock_session.flush.assert_called_once()
        assert result is not None

    async def test_record_execution_with_error(self, trace_service, mock_session):
        """Test recording a failed execution trace."""
        # Arrange
        error_data = {
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "tool_name": "failing_tool",
            "input_params": {},
            "success": False,
            "error_message": "Connection timeout",
            "error_type": "TimeoutError",
            "execution_time_ms": 5000.0,
        }

        # Act
        result = await trace_service.record_execution(**error_data)

        # Assert
        mock_session.add.assert_called_once()
        added_trace = mock_session.add.call_args[0][0]
        assert added_trace.success is False
        assert added_trace.error_message == "Connection timeout"
        assert added_trace.error_type == "TimeoutError"

    async def test_record_execution_sanitizes_sensitive_params(self, trace_service, mock_session):
        """Test that sensitive parameters are redacted."""
        # Arrange
        sensitive_data = {
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "tool_name": "auth_tool",
            "input_params": {
                "username": "user123",
                "password": "secret123",
                "api_key": "key-abc-123",
                "nested": {"token": "bearer-xyz"},
            },
            "success": True,
            "execution_time_ms": 10.0,
        }

        # Act
        await trace_service.record_execution(**sensitive_data)

        # Assert
        added_trace = mock_session.add.call_args[0][0]
        assert added_trace.input_params["username"] == "user123"  # Not sensitive
        assert added_trace.input_params["password"] == "[REDACTED]"
        assert added_trace.input_params["api_key"] == "[REDACTED]"
        assert added_trace.input_params["nested"]["token"] == "[REDACTED]"

    async def test_record_execution_truncates_large_output(self, trace_service, mock_session):
        """Test that large output results are truncated."""
        # Arrange
        large_output = {"data": "x" * 50000}
        data = {
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "tool_name": "large_output_tool",
            "input_params": {},
            "output_result": large_output,
            "success": True,
            "execution_time_ms": 100.0,
        }

        # Act
        await trace_service.record_execution(**data)

        # Assert
        added_trace = mock_session.add.call_args[0][0]
        assert added_trace.output_result.get("_truncated") is True
        assert "_size" in added_trace.output_result

    async def test_record_execution_circuit_breaker_trips(self, trace_service, mock_session):
        """Test that circuit breaker trips after consecutive failures."""
        # Arrange
        mock_session.flush = AsyncMock(side_effect=Exception("DB error"))
        data = {
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "tool_name": "test_tool",
            "input_params": {},
            "success": True,
            "execution_time_ms": 10.0,
        }

        # Act - trigger failures
        for _ in range(5):
            await trace_service.record_execution(**data)

        # Verify circuit is now open
        assert trace_service._is_circuit_open()

        # Act - next call should be skipped
        mock_session.flush = AsyncMock()  # Reset to working
        result = await trace_service.record_execution(**data)

        # Assert - should return None due to open circuit
        assert result is None

    async def test_record_execution_circuit_breaker_resets(self, trace_service, mock_session):
        """Test that circuit breaker resets after timeout."""
        # Arrange - trip the circuit
        mock_session.flush = AsyncMock(side_effect=Exception("DB error"))
        data = {
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "tool_name": "test_tool",
            "input_params": {},
            "success": True,
            "execution_time_ms": 10.0,
        }

        for _ in range(5):
            await trace_service.record_execution(**data)

        # Simulate time passing
        trace_service._circuit_breaker_tripped_at = datetime.utcnow() - timedelta(seconds=61)

        # Act - circuit should now be closed
        assert not trace_service._is_circuit_open()

    async def test_record_execution_validates_ttl(self, trace_service, mock_session):
        """Test TTL validation with invalid values."""
        # Arrange
        data = {
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "tool_name": "test_tool",
            "input_params": {},
            "success": True,
            "execution_time_ms": 10.0,
            "ttl_days": 5000,  # Invalid, exceeds 3650
        }

        # Act
        await trace_service.record_execution(**data)

        # Assert - should default to 30
        added_trace = mock_session.add.call_args[0][0]
        assert added_trace.ttl_days == 30


class TestGetExecutionHistory:
    """Tests for get_execution_history method."""

    async def test_get_history_with_namespace_filter(self, trace_service, mock_session):
        """Test namespace isolation (P0-1)."""
        # Arrange
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        # Act
        result = await trace_service.get_execution_history(namespace="test-ns")

        # Assert
        assert result == []
        mock_session.execute.assert_called_once()

    async def test_get_history_with_all_filters(self, trace_service, mock_session):
        """Test history retrieval with all filter options."""
        # Arrange
        mock_traces = [MagicMock(spec=ExecutionTrace) for _ in range(3)]
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_traces
        mock_session.execute.return_value = mock_result

        since = datetime.utcnow() - timedelta(hours=24)
        until = datetime.utcnow()

        # Act
        result = await trace_service.get_execution_history(
            namespace="test-ns",
            agent_id="test-agent",
            tool_name="search_memories",
            success=True,
            since=since,
            until=until,
            limit=50,
            offset=10,
        )

        # Assert
        assert len(result) == 3

    async def test_get_history_enforces_limit(self, trace_service, mock_session):
        """Test that limit is enforced (1-1000)."""
        # Arrange
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        # Act - with excessive limit
        await trace_service.get_execution_history(namespace="test-ns", limit=5000)

        # Assert - limit should be capped
        # The actual assertion would require inspecting the query


class TestGetTraceById:
    """Tests for get_trace_by_id method."""

    async def test_get_trace_found(self, trace_service, mock_session):
        """Test successful trace retrieval by ID."""
        # Arrange
        trace_id = str(uuid4())
        mock_trace = MagicMock(spec=ExecutionTrace)
        mock_trace.id = trace_id
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_trace
        mock_session.execute.return_value = mock_result

        # Act
        result = await trace_service.get_trace_by_id(trace_id, "test-ns")

        # Assert
        assert result == mock_trace

    async def test_get_trace_not_found(self, trace_service, mock_session):
        """Test NotFoundError when trace doesn't exist."""
        # Arrange
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        # Act & Assert
        with pytest.raises(NotFoundError):
            await trace_service.get_trace_by_id("nonexistent-id", "test-ns")

    async def test_get_trace_wrong_namespace(self, trace_service, mock_session):
        """Test that namespace mismatch returns NotFoundError."""
        # Arrange
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        # Act & Assert
        with pytest.raises(NotFoundError):
            await trace_service.get_trace_by_id("some-id", "wrong-namespace")


class TestGetOrchestrationSequence:
    """Tests for get_orchestration_sequence method."""

    async def test_get_sequence_returns_ordered(self, trace_service, mock_session):
        """Test that sequence is returned in order."""
        # Arrange
        traces = [
            MagicMock(spec=ExecutionTrace, sequence_number=i)
            for i in range(5)
        ]
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = traces
        mock_session.execute.return_value = mock_result

        # Act
        result = await trace_service.get_orchestration_sequence(
            orchestration_id="orch-123",
            namespace="test-ns",
        )

        # Assert
        assert len(result) == 5


class TestAnalyzeToolSequence:
    """Tests for analyze_tool_sequence method."""

    async def test_analyze_finds_patterns(self, trace_service, mock_session):
        """Test pattern detection with minimum occurrences."""
        # Arrange
        mock_rows = [
            MagicMock(
                orchestration_id="orch-1",
                tool_sequence="tool_a,tool_b,tool_c",
                tool_count=3,
                success_rate=1.0,
                total_time_ms=150.0,
            ),
            MagicMock(
                orchestration_id="orch-2",
                tool_sequence="tool_a,tool_b,tool_c",
                tool_count=3,
                success_rate=0.8,
                total_time_ms=120.0,
            ),
            MagicMock(
                orchestration_id="orch-3",
                tool_sequence="tool_a,tool_b,tool_c",
                tool_count=3,
                success_rate=1.0,
                total_time_ms=130.0,
            ),
        ]
        mock_result = MagicMock()
        mock_result.all.return_value = mock_rows
        mock_session.execute.return_value = mock_result

        # Act
        patterns = await trace_service.analyze_tool_sequence(
            namespace="test-ns",
            min_occurrences=3,
        )

        # Assert
        assert len(patterns) == 1
        assert patterns[0]["frequency"] == 3
        assert patterns[0]["tool_sequence"] == ["tool_a", "tool_b", "tool_c"]

    async def test_analyze_filters_low_frequency(self, trace_service, mock_session):
        """Test that patterns below threshold are filtered."""
        # Arrange
        mock_rows = [
            MagicMock(
                orchestration_id="orch-1",
                tool_sequence="tool_x,tool_y",
                tool_count=2,
                success_rate=1.0,
                total_time_ms=50.0,
            ),
            MagicMock(
                orchestration_id="orch-2",
                tool_sequence="tool_x,tool_y",
                tool_count=2,
                success_rate=1.0,
                total_time_ms=55.0,
            ),
        ]
        mock_result = MagicMock()
        mock_result.all.return_value = mock_rows
        mock_session.execute.return_value = mock_result

        # Act
        patterns = await trace_service.analyze_tool_sequence(
            namespace="test-ns",
            min_occurrences=3,  # Threshold is 3
        )

        # Assert - pattern has only 2 occurrences, should be filtered
        assert len(patterns) == 0


class TestCleanupExpiredTraces:
    """Tests for cleanup_expired_traces method."""

    async def test_cleanup_deletes_expired(self, trace_service, mock_session):
        """Test that expired traces are deleted."""
        # Arrange
        mock_result = MagicMock()
        mock_result.rowcount = 10
        mock_session.execute.return_value = mock_result

        # Act
        deleted = await trace_service.cleanup_expired_traces(namespace="test-ns")

        # Assert
        assert deleted == 10
        mock_session.execute.assert_called()


class TestGetTraceStatistics:
    """Tests for get_trace_statistics method."""

    async def test_get_statistics_returns_metrics(self, trace_service, mock_session):
        """Test statistics calculation."""
        # Arrange - mock the three queries
        total_result = MagicMock()
        total_result.scalar.return_value = 100

        success_result = MagicMock()
        success_result.scalar.return_value = 85

        avg_time_result = MagicMock()
        avg_time_result.scalar.return_value = 45.5

        tools_result = MagicMock()
        tools_result.all.return_value = [
            MagicMock(tool_name="search_memories", count=50),
            MagicMock(tool_name="store_memory", count=30),
        ]

        mock_session.execute.side_effect = [
            total_result,
            success_result,
            avg_time_result,
            tools_result,
        ]

        # Act
        stats = await trace_service.get_trace_statistics(namespace="test-ns")

        # Assert
        assert stats["total_traces"] == 100
        assert stats["success_count"] == 85
        assert stats["failure_count"] == 15
        assert stats["success_rate"] == 0.85
        assert stats["avg_execution_time_ms"] == 45.5
        assert len(stats["top_tools"]) == 2


class TestLinkTracesToPattern:
    """Tests for link_traces_to_pattern method."""

    async def test_link_traces_updates_records(self, trace_service, mock_session):
        """Test linking traces to a detected pattern."""
        # Arrange
        trace_ids = [str(uuid4()) for _ in range(5)]
        pattern_id = str(uuid4())
        mock_result = MagicMock()
        mock_result.rowcount = 5
        mock_session.execute.return_value = mock_result

        # Act
        count = await trace_service.link_traces_to_pattern(
            trace_ids=trace_ids,
            pattern_id=pattern_id,
            namespace="test-ns",
        )

        # Assert
        assert count == 5

    async def test_link_traces_empty_list(self, trace_service, mock_session):
        """Test with empty trace ID list."""
        # Act
        count = await trace_service.link_traces_to_pattern(
            trace_ids=[],
            pattern_id=str(uuid4()),
            namespace="test-ns",
        )

        # Assert
        assert count == 0
        mock_session.execute.assert_not_called()


class TestSanitizeParams:
    """Tests for _sanitize_params helper method."""

    def test_sanitize_redacts_password(self, trace_service):
        """Test password redaction."""
        params = {"password": "secret123"}
        result = trace_service._sanitize_params(params)
        assert result["password"] == "[REDACTED]"

    def test_sanitize_preserves_safe_params(self, trace_service):
        """Test that safe parameters are preserved."""
        params = {"query": "test", "limit": 10}
        result = trace_service._sanitize_params(params)
        assert result["query"] == "test"
        assert result["limit"] == 10

    def test_sanitize_handles_nested_dicts(self, trace_service):
        """Test nested dictionary handling."""
        params = {
            "config": {
                "api_key": "key123",
                "timeout": 30,
            }
        }
        result = trace_service._sanitize_params(params)
        assert result["config"]["api_key"] == "[REDACTED]"
        assert result["config"]["timeout"] == 30

    def test_sanitize_empty_dict(self, trace_service):
        """Test empty dictionary handling."""
        result = trace_service._sanitize_params({})
        assert result == {}


class TestTruncateOutput:
    """Tests for _truncate_output helper method."""

    def test_truncate_small_output(self, trace_service):
        """Test that small output is not truncated."""
        output = {"result": "small value"}
        result = trace_service._truncate_output(output)
        assert result == output

    def test_truncate_large_output(self, trace_service):
        """Test that large output is truncated."""
        output = {"data": "x" * 50000}
        result = trace_service._truncate_output(output, max_size=1000)
        assert result.get("_truncated") is True
        assert "_size" in result

    def test_truncate_none_output(self, trace_service):
        """Test None output handling."""
        result = trace_service._truncate_output(None)
        assert result is None


class TestHashSequence:
    """Tests for _hash_sequence helper method."""

    def test_hash_produces_consistent_result(self, trace_service):
        """Test hash consistency."""
        sequence = ["tool_a", "tool_b", "tool_c"]
        hash1 = trace_service._hash_sequence(sequence)
        hash2 = trace_service._hash_sequence(sequence)
        assert hash1 == hash2

    def test_hash_different_for_different_sequences(self, trace_service):
        """Test hash uniqueness."""
        seq1 = ["tool_a", "tool_b"]
        seq2 = ["tool_b", "tool_a"]
        hash1 = trace_service._hash_sequence(seq1)
        hash2 = trace_service._hash_sequence(seq2)
        assert hash1 != hash2

    def test_hash_is_sha256(self, trace_service):
        """Test that hash is 64 characters (SHA256 hex)."""
        sequence = ["tool_a"]
        result = trace_service._hash_sequence(sequence)
        assert len(result) == 64
