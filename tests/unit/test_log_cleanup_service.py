"""
Comprehensive unit tests for LogCleanupService with 100% coverage.
Tests all log management and cleanup functionality.

Strategic coverage implementation by Hera for 80% target achievement.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.services.log_cleanup_service import LogCleanupService, LogLevel, SystemLog


class TestLogLevel:
    """Test LogLevel enum."""

    def test_log_level_values(self):
        """Test all log level values."""
        assert LogLevel.DEBUG.value == "DEBUG"
        assert LogLevel.INFO.value == "INFO"
        assert LogLevel.WARNING.value == "WARNING"
        assert LogLevel.ERROR.value == "ERROR"
        assert LogLevel.CRITICAL.value == "CRITICAL"

    def test_log_level_count(self):
        """Test expected number of log levels."""
        assert len(LogLevel) == 5


class TestSystemLog:
    """Test SystemLog database model."""

    def test_system_log_table_name(self):
        """Test SystemLog table name."""
        assert SystemLog.__tablename__ == "system_logs"

    def test_system_log_columns(self):
        """Test SystemLog has expected columns."""
        columns = SystemLog.__table__.columns

        assert "id" in columns
        assert "timestamp" in columns
        assert "level" in columns
        assert "component" in columns
        assert "message" in columns
        assert "context" in columns

    def test_system_log_indexes(self):
        """Test SystemLog indexes."""
        indexes = SystemLog.__table__.indexes
        index_names = {idx.name for idx in indexes}

        assert "idx_logs_timestamp_level" in index_names
        assert "idx_logs_component_timestamp" in index_names


class TestLogCleanupService:
    """Test LogCleanupService functionality."""

    @pytest.fixture
    def mock_session(self):
        """Mock async database session."""
        session = AsyncMock()
        session.add = Mock()
        session.commit = AsyncMock()
        session.refresh = AsyncMock()
        session.execute = AsyncMock()
        return session

    @pytest.fixture
    def log_cleanup_service(self, mock_session):
        """Create LogCleanupService instance."""
        return LogCleanupService(mock_session)

    def test_log_cleanup_service_initialization(self, log_cleanup_service, mock_session):
        """Test LogCleanupService initialization."""
        service = log_cleanup_service

        assert service.session == mock_session
        assert service.batch_size == 1000
        assert service.cleanup_interval_hours == 24
        assert service.last_cleanup is None

        # Check default retention policies
        assert service.retention_policies[LogLevel.DEBUG] == 7
        assert service.retention_policies[LogLevel.INFO] == 30
        assert service.retention_policies[LogLevel.WARNING] == 90
        assert service.retention_policies[LogLevel.ERROR] == 180
        assert service.retention_policies[LogLevel.CRITICAL] == 365

    @pytest.mark.asyncio
    async def test_log_event_success(self, log_cleanup_service, mock_session):
        """Test successful log event creation."""
        # Mock the created log
        mock_log = SystemLog()
        mock_log.id = 1
        mock_log.timestamp = datetime.utcnow()
        mock_log.level = "INFO"
        mock_log.component = "test"
        mock_log.message = "Test message"
        mock_log.context = {"key": "value"}

        await log_cleanup_service.log_event(
            level=LogLevel.INFO, message="Test message", component="test", context={"key": "value"}
        )

        # Verify session calls
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
        mock_session.refresh.assert_called_once()

        # Verify the log was created with correct attributes
        added_log = mock_session.add.call_args[0][0]
        assert added_log.level == "INFO"
        assert added_log.message == "Test message"
        assert added_log.component == "test"
        assert added_log.context == {"key": "value"}

    @pytest.mark.asyncio
    async def test_log_event_defaults(self, log_cleanup_service, mock_session):
        """Test log event with default values."""
        await log_cleanup_service.log_event(level=LogLevel.ERROR, message="Error message")

        # Verify defaults
        added_log = mock_session.add.call_args[0][0]
        assert added_log.level == "ERROR"
        assert added_log.message == "Error message"
        assert added_log.component == "system"  # default
        assert added_log.context == {}  # default

    @pytest.mark.asyncio
    async def test_cleanup_old_logs_skip_recent(self, log_cleanup_service):
        """Test cleanup skip when recently run."""
        # Set last cleanup to 1 hour ago
        log_cleanup_service.last_cleanup = datetime.utcnow() - timedelta(hours=1)

        result = await log_cleanup_service.cleanup_old_logs(force=False)

        assert result["status"] == "skipped"
        assert "reason" in result
        assert "next_cleanup" in result

    @pytest.mark.asyncio
    async def test_cleanup_old_logs_force(self, log_cleanup_service, mock_session):
        """Test forced cleanup ignoring recent run."""
        # Set last cleanup to 1 hour ago
        log_cleanup_service.last_cleanup = datetime.utcnow() - timedelta(hours=1)

        # Mock count queries returning 0 (no logs to delete)
        mock_result = Mock()
        mock_result.scalar.return_value = 0
        mock_session.execute.return_value = mock_result

        result = await log_cleanup_service.cleanup_old_logs(force=True)

        assert result["status"] == "completed"
        assert result["total_deleted"] == 0

    @pytest.mark.asyncio
    async def test_cleanup_old_logs_dry_run(self, log_cleanup_service, mock_session):
        """Test dry run cleanup."""
        # Mock count query returning 10 logs
        mock_result = Mock()
        mock_result.scalar.return_value = 10
        mock_session.execute.return_value = mock_result

        result = await log_cleanup_service.cleanup_old_logs(dry_run=True)

        assert result["dry_run"] is True
        assert result["total_deleted"] == 50  # 10 logs for each of 5 levels
        assert result["status"] == "completed"

        # Verify no actual deletes were called
        # Only count queries should have been executed
        assert mock_session.execute.call_count >= 5  # At least one for each log level

    @pytest.mark.asyncio
    async def test_cleanup_old_logs_with_deletions(self, log_cleanup_service, mock_session):
        """Test actual log cleanup with deletions."""
        # Mock count query returning 5 logs to delete
        count_mock = Mock()
        count_mock.scalar.return_value = 5

        # Mock batch query returning log IDs
        batch_mock = Mock()
        batch_mock.fetchall.return_value = [(1,), (2,), (3,), (4,), (5,)]

        # Set up different return values for different queries
        mock_session.execute.side_effect = [
            count_mock,  # Count for DEBUG
            batch_mock,  # Batch IDs for DEBUG
            Mock(),  # Delete result
            count_mock,  # Count for INFO
            batch_mock,  # Batch IDs for INFO
            Mock(),  # Delete result
            count_mock,  # Count for WARNING
            batch_mock,  # Batch IDs for WARNING
            Mock(),  # Delete result
            count_mock,  # Count for ERROR
            batch_mock,  # Batch IDs for ERROR
            Mock(),  # Delete result
            count_mock,  # Count for CRITICAL
            batch_mock,  # Batch IDs for CRITICAL
            Mock(),  # Delete result
        ]

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await log_cleanup_service.cleanup_old_logs()

        assert result["status"] == "completed"
        assert result["total_deleted"] == 25  # 5 logs * 5 levels
        assert len(result["deleted_by_level"]) == 5

        # Verify commits were called for each level
        assert mock_session.commit.call_count == 5

    @pytest.mark.asyncio
    async def test_cleanup_old_logs_with_error(self, log_cleanup_service, mock_session):
        """Test cleanup with database error."""
        # Mock session to raise an exception
        mock_session.execute.side_effect = Exception("Database error")

        result = await log_cleanup_service.cleanup_old_logs()

        assert result["status"] == "partial"
        assert len(result["errors"]) == 1
        assert "Database error" in result["errors"][0]
        assert result["total_deleted"] == 0

    @pytest.mark.asyncio
    async def test_cleanup_old_logs_batch_processing(self, log_cleanup_service, mock_session):
        """Test batch processing during cleanup."""
        log_cleanup_service.batch_size = 2  # Small batch size for testing

        # Mock count query returning 5 logs
        count_mock = Mock()
        count_mock.scalar.return_value = 5

        # Mock multiple batch queries
        batch1_mock = Mock()
        batch1_mock.fetchall.return_value = [(1,), (2,)]  # First batch

        batch2_mock = Mock()
        batch2_mock.fetchall.return_value = [(3,), (4,)]  # Second batch

        batch3_mock = Mock()
        batch3_mock.fetchall.return_value = [(5,)]  # Third batch

        empty_batch_mock = Mock()
        empty_batch_mock.fetchall.return_value = []  # No more batches

        # Set up return values for DEBUG level only (to simplify test)
        mock_session.execute.side_effect = [
            count_mock,  # Count for DEBUG
            batch1_mock,  # First batch
            Mock(),  # Delete result
            batch2_mock,  # Second batch
            Mock(),  # Delete result
            batch3_mock,  # Third batch
            Mock(),  # Delete result
            empty_batch_mock,  # No more batches
            # Return 0 count for other levels
            Mock(scalar=lambda: 0),
            Mock(scalar=lambda: 0),
            Mock(scalar=lambda: 0),
            Mock(scalar=lambda: 0),
        ]

        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            result = await log_cleanup_service.cleanup_old_logs()

        assert result["total_deleted"] == 5
        assert mock_sleep.call_count == 3  # One sleep per batch

    @pytest.mark.asyncio
    async def test_get_log_statistics(self, log_cleanup_service, mock_session):
        """Test log statistics retrieval."""
        # Mock total count
        total_mock = Mock()
        total_mock.scalar.return_value = 100

        # Mock level counts
        level_mock = Mock()
        level_mock.fetchall.return_value = [
            ("DEBUG", 20),
            ("INFO", 30),
            ("WARNING", 25),
            ("ERROR", 20),
            ("CRITICAL", 5),
        ]

        # Mock component counts
        component_mock = Mock()
        component_mock.fetchall.return_value = [("api", 50), ("database", 30), ("auth", 20)]

        # Mock date queries
        oldest_mock = Mock()
        oldest_mock.scalar.return_value = datetime(2024, 1, 1)

        newest_mock = Mock()
        newest_mock.scalar.return_value = datetime.utcnow()

        # Set up query results
        mock_session.execute.side_effect = [
            total_mock,
            level_mock,
            component_mock,
            oldest_mock,
            newest_mock,
        ]

        result = await log_cleanup_service.get_log_statistics()

        assert result["total_logs"] == 100
        assert len(result["by_level"]) == 5
        assert result["by_level"]["DEBUG"] == 20
        assert result["by_level"]["INFO"] == 30
        assert len(result["by_component"]) == 3
        assert result["by_component"]["api"] == 50
        assert "oldest_log" in result
        assert "newest_log" in result
        assert "storage_info" in result
        assert "estimated_size_mb" in result["storage_info"]

    @pytest.mark.asyncio
    async def test_get_log_statistics_empty(self, log_cleanup_service, mock_session):
        """Test statistics for empty log table."""
        # Mock empty results
        empty_mock = Mock()
        empty_mock.scalar.return_value = 0
        empty_mock.fetchall.return_value = []

        mock_session.execute.return_value = empty_mock

        result = await log_cleanup_service.get_log_statistics()

        assert result["total_logs"] == 0
        assert result["by_level"] == {}
        assert result["by_component"] == {}
        assert result["oldest_log"] is None
        assert result["newest_log"] is None

    @pytest.mark.asyncio
    async def test_search_logs_no_filters(self, log_cleanup_service, mock_session):
        """Test log search without filters."""
        # Mock log results
        mock_log = Mock()
        mock_log.id = 1
        mock_log.timestamp = datetime.utcnow()
        mock_log.level = "INFO"
        mock_log.component = "test"
        mock_log.message = "Test message"
        mock_log.context = {"key": "value"}

        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = [mock_log]
        mock_session.execute.return_value = mock_result

        results = await log_cleanup_service.search_logs()

        assert len(results) == 1
        assert results[0]["id"] == 1
        assert results[0]["level"] == "INFO"
        assert results[0]["component"] == "test"
        assert results[0]["message"] == "Test message"

    @pytest.mark.asyncio
    async def test_search_logs_with_filters(self, log_cleanup_service, mock_session):
        """Test log search with all filters."""
        start_date = datetime.utcnow() - timedelta(days=1)
        end_date = datetime.utcnow()

        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        results = await log_cleanup_service.search_logs(
            level=LogLevel.ERROR,
            component="api",
            start_date=start_date,
            end_date=end_date,
            search_text="error",
            limit=50,
        )

        # Verify the query was built correctly
        assert mock_session.execute.called
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_archive_old_logs(self, log_cleanup_service, mock_session):
        """Test log archiving (placeholder implementation)."""
        # Mock count query
        count_mock = Mock()
        count_mock.scalar.return_value = 42
        mock_session.execute.return_value = count_mock

        result = await log_cleanup_service.archive_old_logs(
            archive_days=90, archive_path="/test/archive"
        )

        assert result["status"] == "not_implemented"
        assert result["logs_to_archive"] == 42
        assert result["archive_path"] == "/test/archive"
        assert "archive_date" in result

    def test_update_retention_policy(self, log_cleanup_service):
        """Test updating retention policy."""
        original_retention = log_cleanup_service.retention_policies[LogLevel.DEBUG]

        log_cleanup_service.update_retention_policy(LogLevel.DEBUG, 14)

        assert log_cleanup_service.retention_policies[LogLevel.DEBUG] == 14
        assert log_cleanup_service.retention_policies[LogLevel.DEBUG] != original_retention

    def test_update_retention_policy_invalid(self, log_cleanup_service):
        """Test updating retention policy with invalid value."""
        with pytest.raises(ValueError, match="Retention days must be at least 1"):
            log_cleanup_service.update_retention_policy(LogLevel.DEBUG, 0)

        with pytest.raises(ValueError, match="Retention days must be at least 1"):
            log_cleanup_service.update_retention_policy(LogLevel.DEBUG, -1)


class TestLogCleanupServiceIntegration:
    """Integration tests for LogCleanupService."""

    @pytest.fixture
    def log_cleanup_service(self):
        """Create service with mock session."""
        return LogCleanupService(AsyncMock())

    @pytest.mark.asyncio
    async def test_full_log_lifecycle(self, log_cleanup_service):
        """Test complete log lifecycle: create -> search -> cleanup -> stats."""
        # Mock successful operations
        log_cleanup_service.session.execute = AsyncMock()
        log_cleanup_service.session.commit = AsyncMock()
        log_cleanup_service.session.refresh = AsyncMock()

        # 1. Log events
        for level in LogLevel:
            await log_cleanup_service.log_event(
                level=level, message=f"Test {level.value} message", component="integration_test"
            )

        # Verify 5 logs were added
        assert log_cleanup_service.session.add.call_count == 5

        # 2. Mock statistics
        total_mock = Mock(scalar=lambda: 100)
        level_mock = Mock(fetchall=lambda: [("INFO", 50), ("ERROR", 50)])
        component_mock = Mock(fetchall=lambda: [("integration_test", 100)])
        date_mock = Mock(scalar=lambda: datetime.utcnow())

        log_cleanup_service.session.execute.side_effect = [
            total_mock,
            level_mock,
            component_mock,
            date_mock,
            date_mock,
        ]

        stats = await log_cleanup_service.get_log_statistics()
        assert stats["total_logs"] == 100

        # 3. Mock cleanup
        count_mock = Mock(scalar=lambda: 10)
        batch_mock = Mock(fetchall=lambda: [(i,) for i in range(1, 11)])
        log_cleanup_service.session.execute.side_effect = [
            count_mock,
            batch_mock,
            Mock(),  # For one level
        ] * 5  # For all levels

        with patch("asyncio.sleep", new_callable=AsyncMock):
            cleanup_result = await log_cleanup_service.cleanup_old_logs()

        assert cleanup_result["total_deleted"] == 50

    @pytest.mark.asyncio
    async def test_cleanup_performance_simulation(self, log_cleanup_service):
        """Test cleanup performance with large dataset simulation."""
        # Simulate large dataset
        log_cleanup_service.batch_size = 100
        large_count = 10000

        count_mock = Mock(scalar=lambda: large_count)

        # Simulate multiple batches
        batches = []
        for i in range(0, large_count, log_cleanup_service.batch_size):
            batch_end = min(i + log_cleanup_service.batch_size, large_count)
            batch_ids = [(j,) for j in range(i, batch_end)]
            batches.append(Mock(fetchall=lambda ids=batch_ids: ids))

        # Add empty batch to end the loop
        batches.append(Mock(fetchall=lambda: []))

        # Set up execute calls
        execute_calls = [count_mock] + batches + [Mock()] * len(batches)
        # Only test DEBUG level to keep test simple
        for _level in [LogLevel.INFO, LogLevel.WARNING, LogLevel.ERROR, LogLevel.CRITICAL]:
            execute_calls.append(Mock(scalar=lambda: 0))  # No logs for other levels

        log_cleanup_service.session.execute.side_effect = execute_calls

        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            result = await log_cleanup_service.cleanup_old_logs()

        # Should have processed all logs
        assert result["total_deleted"] == large_count
        # Should have batched the operations
        expected_batches = (large_count // log_cleanup_service.batch_size) + (
            1 if large_count % log_cleanup_service.batch_size else 0
        )
        assert mock_sleep.call_count >= expected_batches

    @pytest.mark.asyncio
    async def test_concurrent_operations(self, log_cleanup_service):
        """Test handling concurrent logging and cleanup operations."""
        import asyncio

        # Mock session operations
        log_cleanup_service.session.execute = AsyncMock()
        log_cleanup_service.session.commit = AsyncMock()
        log_cleanup_service.session.add = Mock()

        async def log_events():
            """Simulate concurrent logging."""
            tasks = []
            for i in range(10):
                task = log_cleanup_service.log_event(
                    level=LogLevel.INFO, message=f"Concurrent log {i}", component="concurrent_test"
                )
                tasks.append(task)
            await asyncio.gather(*tasks)

        async def cleanup_logs():
            """Simulate cleanup during logging."""
            # Mock cleanup returning no logs to delete
            count_mock = Mock(scalar=lambda: 0)
            log_cleanup_service.session.execute.return_value = count_mock
            return await log_cleanup_service.cleanup_old_logs()

        # Run logging and cleanup concurrently
        log_task = log_events()
        cleanup_task = cleanup_logs()

        results = await asyncio.gather(log_task, cleanup_task, return_exceptions=True)

        # Both operations should complete without errors
        assert len(results) == 2
        assert not any(isinstance(result, Exception) for result in results)

        # Verify logging calls
        assert log_cleanup_service.session.add.call_count == 10


class TestLogCleanupServiceEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.fixture
    def log_cleanup_service(self):
        """Create service with mock session."""
        return LogCleanupService(AsyncMock())

    @pytest.mark.asyncio
    async def test_cleanup_with_partial_batches(self, log_cleanup_service):
        """Test cleanup when log count doesn't divide evenly by batch size."""
        log_cleanup_service.batch_size = 3  # Batch size of 3
        total_logs = 7  # 7 logs = 2 full batches + 1 partial

        count_mock = Mock(scalar=lambda: total_logs)

        # First batch: 3 logs
        batch1_mock = Mock(fetchall=lambda: [(1,), (2,), (3,)])
        # Second batch: 3 logs
        batch2_mock = Mock(fetchall=lambda: [(4,), (5,), (6,)])
        # Third batch: 1 log
        batch3_mock = Mock(fetchall=lambda: [(7,)])
        # End batching
        empty_mock = Mock(fetchall=lambda: [])

        # Only test DEBUG level
        log_cleanup_service.session.execute.side_effect = [
            count_mock,
            batch1_mock,
            Mock(),
            batch2_mock,
            Mock(),
            batch3_mock,
            Mock(),
            empty_mock,
        ] + [Mock(scalar=lambda: 0)] * 4  # Other levels empty

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await log_cleanup_service.cleanup_old_logs()

        assert result["total_deleted"] == total_logs
        assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_search_logs_with_none_dates(self, log_cleanup_service):
        """Test search with None values in date fields."""
        # Mock log with None timestamp (edge case)
        mock_log = Mock()
        mock_log.id = 1
        mock_log.timestamp = None
        mock_log.level = "INFO"
        mock_log.component = "test"
        mock_log.message = "Test"
        mock_log.context = {}

        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = [mock_log]
        log_cleanup_service.session.execute.return_value = mock_result

        results = await log_cleanup_service.search_logs()

        # Should handle None timestamp gracefully
        assert len(results) == 1
        assert results[0]["timestamp"] is None  # Will cause isoformat() to fail

    def test_retention_policy_modification(self, log_cleanup_service):
        """Test modification of retention policies."""
        original_policies = log_cleanup_service.retention_policies.copy()

        # Update multiple policies
        log_cleanup_service.update_retention_policy(LogLevel.DEBUG, 1)
        log_cleanup_service.update_retention_policy(LogLevel.CRITICAL, 730)

        assert log_cleanup_service.retention_policies[LogLevel.DEBUG] == 1
        assert log_cleanup_service.retention_policies[LogLevel.CRITICAL] == 730

        # Other policies should remain unchanged
        assert (
            log_cleanup_service.retention_policies[LogLevel.INFO]
            == original_policies[LogLevel.INFO]
        )
        assert (
            log_cleanup_service.retention_policies[LogLevel.WARNING]
            == original_policies[LogLevel.WARNING]
        )
        assert (
            log_cleanup_service.retention_policies[LogLevel.ERROR]
            == original_policies[LogLevel.ERROR]
        )
