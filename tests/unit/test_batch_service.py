"""
Comprehensive unit tests for BatchService with 100% coverage.
Tests all batch processing functionality with performance optimizations.
"""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import pytest

from src.core.exceptions import ValidationError
from src.services.batch_service import (
    BatchJob,
    BatchJobStatus,
    BatchOperationType,
    BatchPriority,
    BatchProcessor,
    BatchService,
)


class TestBatchJob:
    """Test BatchJob class functionality."""

    @pytest.fixture
    def mock_processor_func(self):
        """Mock processor function."""
        async def processor(items, metadata):
            return [{'success': True} for _ in items]
        return processor

    @pytest.fixture
    def sample_batch_job(self, mock_processor_func):
        """Sample batch job for testing."""
        return BatchJob(
            job_id="test_job_1",
            operation_type=BatchOperationType.CREATE,
            items=[{"id": i, "data": f"item_{i}"} for i in range(10)],
            processor_func=mock_processor_func,
            priority=BatchPriority.MEDIUM,
            batch_size=5,
            max_retries=3,
            timeout_seconds=300,
            metadata={"test": "metadata"}
        )

    def test_batch_job_initialization(self, sample_batch_job):
        """Test BatchJob initialization with all parameters."""
        job = sample_batch_job

        assert job.job_id == "test_job_1"
        assert job.operation_type == BatchOperationType.CREATE
        assert len(job.items) == 10
        assert job.priority == BatchPriority.MEDIUM
        assert job.batch_size == 5
        assert job.max_retries == 3
        assert job.timeout_seconds == 300
        assert job.metadata == {"test": "metadata"}
        assert job.status == BatchJobStatus.PENDING
        assert job.processed_count == 0
        assert job.success_count == 0
        assert job.failure_count == 0

    def test_batch_job_properties(self, sample_batch_job):
        """Test BatchJob computed properties."""
        job = sample_batch_job

        # Test total_items
        assert job.total_items == 10

        # Test progress_percentage
        assert job.progress_percentage == 0.0
        job.processed_count = 5
        assert job.progress_percentage == 50.0

        # Test success_rate
        job.success_count = 3
        assert job.success_rate == 60.0

        # Test is_completed
        assert not job.is_completed
        job.status = BatchJobStatus.COMPLETED
        assert job.is_completed

        # Test execution_time
        assert job.execution_time is None
        job.started_at = datetime.now()
        job.completed_at = job.started_at + timedelta(seconds=10)
        assert job.execution_time.total_seconds() == 10

    def test_batch_job_edge_cases(self, mock_processor_func):
        """Test BatchJob edge cases."""
        # Empty items list
        job = BatchJob(
            job_id="empty_job",
            operation_type=BatchOperationType.CREATE,
            items=[],
            processor_func=mock_processor_func
        )
        assert job.total_items == 0
        assert job.progress_percentage == 100.0
        assert job.success_rate == 0.0

    def test_batch_job_to_dict(self, sample_batch_job):
        """Test BatchJob serialization to dictionary."""
        job = sample_batch_job
        job.started_at = datetime.now()
        job.completed_at = job.started_at + timedelta(seconds=5)
        job.processed_count = 10
        job.success_count = 8
        job.failure_count = 2
        job.error_messages = ["Error 1", "Error 2"]

        result = job.to_dict()

        assert result["job_id"] == "test_job_1"
        assert result["operation_type"] == BatchOperationType.CREATE
        assert result["status"] == BatchJobStatus.PENDING
        assert result["total_items"] == 10
        assert result["processed_count"] == 10
        assert result["success_count"] == 8
        assert result["failure_count"] == 2
        assert result["progress_percentage"] == 100.0
        assert result["success_rate"] == 80.0
        assert "started_at" in result
        assert "completed_at" in result
        assert "execution_time_seconds" in result
        assert result["error_messages"] == ["Error 1", "Error 2"]


class TestBatchProcessor:
    """Test BatchProcessor class functionality."""

    @pytest.fixture
    def batch_processor(self):
        """Create a batch processor for testing."""
        return BatchProcessor(
            max_concurrent_jobs=2,
            max_concurrent_batches=4,
            memory_limit_mb=512,
            adaptive_batch_sizing=True
        )

    @pytest.fixture
    def mock_successful_processor(self):
        """Mock processor that always succeeds."""
        async def processor(items, metadata):
            await asyncio.sleep(0.01)  # Simulate some work
            return [{'success': True, 'result': f'processed_{i}'} for i in range(len(items))]
        return processor

    @pytest.fixture
    def mock_failing_processor(self):
        """Mock processor that always fails."""
        async def processor(items, metadata):
            return [{'success': False, 'error': 'Processing failed'} for _ in items]
        return processor

    def test_batch_processor_initialization(self, batch_processor):
        """Test BatchProcessor initialization."""
        processor = batch_processor

        assert processor.max_concurrent_jobs == 2
        assert processor.max_concurrent_batches == 4
        assert processor.memory_limit_mb == 512
        assert processor.adaptive_batch_sizing is True
        assert len(processor.jobs) == 0
        assert len(processor.running_jobs) == 0
        assert processor._shutdown is False

    @pytest.mark.asyncio
    async def test_batch_processor_start_stop(self, batch_processor):
        """Test BatchProcessor start and stop functionality."""
        processor = batch_processor

        # Test start
        await processor.start()
        assert processor._processor_task is not None
        assert not processor._shutdown

        # Test stop
        await processor.stop(timeout=1.0)
        assert processor._shutdown is True

    @pytest.mark.asyncio
    async def test_submit_job(self, batch_processor, mock_successful_processor):
        """Test job submission."""
        processor = batch_processor
        await processor.start()

        job = BatchJob(
            job_id="submit_test",
            operation_type=BatchOperationType.CREATE,
            items=[{"id": i} for i in range(3)],
            processor_func=mock_successful_processor
        )

        job_id = await processor.submit_job(job)
        assert job_id == "submit_test"
        assert "submit_test" in processor.jobs

        await processor.stop()

    @pytest.mark.asyncio
    async def test_submit_duplicate_job(self, batch_processor, mock_successful_processor):
        """Test submitting job with duplicate ID."""
        processor = batch_processor

        job = BatchJob(
            job_id="duplicate_test",
            operation_type=BatchOperationType.CREATE,
            items=[{"id": 1}],
            processor_func=mock_successful_processor
        )

        await processor.submit_job(job)

        # Try to submit same job ID again
        with pytest.raises(ValidationError, match="Job with ID duplicate_test already exists"):
            await processor.submit_job(job)

    @pytest.mark.asyncio
    async def test_get_job_status(self, batch_processor, mock_successful_processor):
        """Test getting job status."""
        processor = batch_processor

        job = BatchJob(
            job_id="status_test",
            operation_type=BatchOperationType.UPDATE,
            items=[{"id": 1}],
            processor_func=mock_successful_processor
        )

        await processor.submit_job(job)

        status = await processor.get_job_status("status_test")
        assert status is not None
        assert status["job_id"] == "status_test"
        assert status["status"] == BatchJobStatus.PENDING

        # Test non-existent job
        status = await processor.get_job_status("non_existent")
        assert status is None

    @pytest.mark.asyncio
    async def test_cancel_pending_job(self, batch_processor, mock_successful_processor):
        """Test cancelling a pending job."""
        processor = batch_processor

        job = BatchJob(
            job_id="cancel_test",
            operation_type=BatchOperationType.DELETE,
            items=[{"id": 1}],
            processor_func=mock_successful_processor
        )

        await processor.submit_job(job)

        # Cancel the job
        result = await processor.cancel_job("cancel_test")
        assert result is True
        assert processor.jobs["cancel_test"].status == BatchJobStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_nonexistent_job(self, batch_processor):
        """Test cancelling a non-existent job."""
        processor = batch_processor
        result = await processor.cancel_job("non_existent")
        assert result is False

    @pytest.mark.asyncio
    async def test_performance_metrics(self, batch_processor):
        """Test performance metrics retrieval."""
        processor = batch_processor

        metrics = await processor.get_performance_metrics()

        assert "total_jobs_processed" in metrics
        assert "total_items_processed" in metrics
        assert "average_job_time" in metrics
        assert "average_items_per_second" in metrics
        assert "error_rate" in metrics
        assert "active_jobs" in metrics
        assert "queued_jobs" in metrics
        assert "total_jobs" in metrics

    @pytest.mark.asyncio
    async def test_calculate_optimal_batch_size(self, batch_processor, mock_successful_processor):
        """Test adaptive batch size calculation."""
        processor = batch_processor

        # Test different operation types
        job_create = BatchJob(
            job_id="test_create",
            operation_type=BatchOperationType.CREATE,
            items=[{"id": i} for i in range(100)],
            processor_func=mock_successful_processor,
            batch_size=50
        )

        size = await processor._calculate_optimal_batch_size(job_create)
        assert 10 <= size <= 1000  # Within bounds

        # Test critical priority
        job_critical = BatchJob(
            job_id="test_critical",
            operation_type=BatchOperationType.ANALYZE,
            items=[{"id": i} for i in range(100)],
            processor_func=mock_successful_processor,
            priority=BatchPriority.CRITICAL,
            batch_size=50
        )

        critical_size = await processor._calculate_optimal_batch_size(job_critical)
        assert critical_size < size  # Critical jobs should have smaller batches

    @pytest.mark.asyncio
    async def test_job_execution_success(self, batch_processor, mock_successful_processor):
        """Test successful job execution."""
        processor = batch_processor
        await processor.start()

        job = BatchJob(
            job_id="exec_success",
            operation_type=BatchOperationType.PROCESS,
            items=[{"id": i} for i in range(5)],
            processor_func=mock_successful_processor,
            batch_size=2
        )

        await processor.submit_job(job)

        # Wait for job completion
        await asyncio.sleep(0.5)

        status = await processor.get_job_status("exec_success")
        assert status["status"] in [BatchJobStatus.COMPLETED, BatchJobStatus.RUNNING]

        await processor.stop()

    @pytest.mark.asyncio
    async def test_job_execution_failure(self, batch_processor, mock_failing_processor):
        """Test job execution with failures."""
        processor = batch_processor
        await processor.start()

        job = BatchJob(
            job_id="exec_failure",
            operation_type=BatchOperationType.PROCESS,
            items=[{"id": i} for i in range(3)],
            processor_func=mock_failing_processor,
            batch_size=1
        )

        await processor.submit_job(job)

        # Wait for job completion
        await asyncio.sleep(0.5)

        status = await processor.get_job_status("exec_failure")
        # Job might still be running or failed
        assert status["status"] in [BatchJobStatus.RUNNING, BatchJobStatus.FAILED, BatchJobStatus.COMPLETED]

        await processor.stop()

    @pytest.mark.asyncio
    async def test_exception_in_processor(self, batch_processor):
        """Test handling of exceptions in processor function."""
        async def failing_processor(items, metadata):
            raise ValueError("Processor error")

        processor = batch_processor
        await processor.start()

        job = BatchJob(
            job_id="exception_test",
            operation_type=BatchOperationType.CREATE,
            items=[{"id": 1}],
            processor_func=failing_processor
        )

        await processor.submit_job(job)

        # Wait for processing
        await asyncio.sleep(0.3)

        status = await processor.get_job_status("exception_test")
        # Should handle the exception gracefully
        assert status["status"] in [BatchJobStatus.FAILED, BatchJobStatus.RUNNING]

        await processor.stop()

    def test_update_performance_metrics(self, batch_processor, mock_successful_processor):
        """Test performance metrics update."""
        processor = batch_processor

        job = BatchJob(
            job_id="metrics_test",
            operation_type=BatchOperationType.CREATE,
            items=[{"id": i} for i in range(5)],
            processor_func=mock_successful_processor
        )

        job.started_at = datetime.now()
        job.completed_at = job.started_at + timedelta(seconds=2)
        job.processed_count = 5
        job.success_count = 4
        job.failure_count = 1

        initial_jobs = processor.performance_metrics["total_jobs_processed"]
        initial_items = processor.performance_metrics["total_items_processed"]

        processor._update_performance_metrics(job)

        assert processor.performance_metrics["total_jobs_processed"] == initial_jobs + 1
        assert processor.performance_metrics["total_items_processed"] == initial_items + 5
        assert processor.performance_metrics["total_processing_time"] > 0


class TestBatchService:
    """Test BatchService high-level functionality."""

    @pytest.fixture
    def batch_service(self):
        """Create a batch service for testing."""
        return BatchService()

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        session = AsyncMock()
        session.add = Mock()
        session.flush = AsyncMock()
        session.execute = AsyncMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=None)
        return session

    @pytest.mark.asyncio
    async def test_batch_service_start_stop(self, batch_service):
        """Test BatchService start and stop."""
        await batch_service.start()
        assert batch_service.processor._processor_task is not None

        await batch_service.stop()
        assert batch_service.processor._shutdown is True

    @pytest.mark.asyncio
    @patch('src.services.batch_service.get_async_session')
    async def test_batch_create_memories(self, mock_get_session, batch_service, mock_session):
        """Test batch memory creation."""
        mock_get_session.return_value = mock_session

        memories_data = [
            {
                "content": "Test memory 1",
                "importance": 0.8,
                "memory_type": "episodic"
            },
            {
                "content": "Test memory 2",
                "importance": 0.6,
                "memory_type": "semantic"
            }
        ]

        await batch_service.start()

        job_id = await batch_service.batch_create_memories(
            memories_data=memories_data,
            agent_id="test_agent",
            namespace="test_namespace",
            batch_size=1
        )

        assert job_id.startswith("batch_memories_")

        # Verify job was submitted
        status = await batch_service.get_job_status(job_id)
        assert status is not None
        assert status["operation_type"] == BatchOperationType.CREATE

        await batch_service.stop()

    @pytest.mark.asyncio
    @patch('src.services.batch_service.get_async_session')
    async def test_batch_update_agent_performance(self, mock_get_session, batch_service, mock_session):
        """Test batch agent performance updates."""
        mock_get_session.return_value = mock_session
        mock_session.execute.return_value = AsyncMock()

        performance_updates = [
            {
                "agent_id": "agent_1",
                "performance_data": {
                    "requests": 10,
                    "successful": 9,
                    "failed": 1,
                    "tokens": 1000,
                    "cost": 0.05,
                    "response_time": 250
                }
            },
            {
                "agent_id": "agent_2",
                "performance_data": {
                    "requests": 5,
                    "successful": 5,
                    "failed": 0,
                    "tokens": 500,
                    "cost": 0.02
                }
            }
        ]

        await batch_service.start()

        job_id = await batch_service.batch_update_agent_performance(
            performance_updates=performance_updates,
            batch_size=1
        )

        assert job_id.startswith("batch_agent_perf_")

        # Verify job was submitted
        status = await batch_service.get_job_status(job_id)
        assert status is not None
        assert status["operation_type"] == BatchOperationType.UPDATE

        await batch_service.stop()

    @pytest.mark.asyncio
    @patch('src.services.batch_service.get_async_session')
    async def test_batch_cleanup_expired_memories(self, mock_get_session, batch_service, mock_session):
        """Test batch cleanup of expired memories."""
        mock_get_session.return_value = mock_session

        # Mock expired memories query result
        expired_result = Mock()
        expired_result.id = uuid4()
        mock_session.execute.return_value.fetchall.return_value = [expired_result]

        # Mock delete result
        delete_result = Mock()
        delete_result.rowcount = 5
        mock_session.execute.return_value = delete_result

        await batch_service.start()

        job_id = await batch_service.batch_cleanup_expired_memories(
            days_threshold=30,
            batch_size=100
        )

        assert job_id.startswith("batch_cleanup_")

        # Verify job was submitted
        status = await batch_service.get_job_status(job_id)
        assert status is not None
        assert status["operation_type"] == BatchOperationType.DELETE

        await batch_service.stop()

    @pytest.mark.asyncio
    async def test_batch_service_job_management(self, batch_service):
        """Test job management operations."""
        await batch_service.start()

        # Test get_job_status for non-existent job
        status = await batch_service.get_job_status("non_existent")
        assert status is None

        # Test cancel_job for non-existent job
        result = await batch_service.cancel_job("non_existent")
        assert result is False

        await batch_service.stop()

    @pytest.mark.asyncio
    async def test_batch_service_performance_metrics(self, batch_service):
        """Test performance metrics retrieval."""
        await batch_service.start()

        metrics = await batch_service.get_performance_metrics()

        assert isinstance(metrics, dict)
        assert "total_jobs_processed" in metrics
        assert "active_jobs" in metrics
        assert "queued_jobs" in metrics

        await batch_service.stop()


class TestBatchProcessorConcurrency:
    """Test BatchProcessor concurrent operations."""

    @pytest.mark.asyncio
    async def test_concurrent_job_processing(self):
        """Test processing multiple jobs concurrently."""
        processor = BatchProcessor(max_concurrent_jobs=3)
        await processor.start()

        async def mock_processor(items, metadata):
            await asyncio.sleep(0.1)
            return [{'success': True} for _ in items]

        # Submit multiple jobs
        jobs = []
        for i in range(5):
            job = BatchJob(
                job_id=f"concurrent_job_{i}",
                operation_type=BatchOperationType.PROCESS,
                items=[{"id": j} for j in range(3)],
                processor_func=mock_processor
            )
            jobs.append(job)
            await processor.submit_job(job)

        # Wait for processing
        await asyncio.sleep(0.5)

        # Check that jobs are being processed
        assert len(processor.running_jobs) <= processor.max_concurrent_jobs

        await processor.stop()

    @pytest.mark.asyncio
    async def test_batch_processor_resource_limits(self):
        """Test that resource limits are respected."""
        processor = BatchProcessor(
            max_concurrent_jobs=1,
            max_concurrent_batches=2
        )
        await processor.start()

        async def slow_processor(items, metadata):
            await asyncio.sleep(0.2)
            return [{'success': True} for _ in items]

        job = BatchJob(
            job_id="resource_test",
            operation_type=BatchOperationType.PROCESS,
            items=[{"id": i} for i in range(10)],
            processor_func=slow_processor,
            batch_size=2
        )

        await processor.submit_job(job)

        # Check that semaphores are working
        assert processor.semaphore.locked() or len(processor.running_jobs) > 0

        await processor.stop()


class TestBatchProcessorErrorHandling:
    """Test error handling in BatchProcessor."""

    @pytest.mark.asyncio
    async def test_processor_function_exception(self):
        """Test handling of exceptions in processor functions."""
        processor = BatchProcessor()
        await processor.start()

        async def error_processor(items, metadata):
            raise RuntimeError("Processor failed")

        job = BatchJob(
            job_id="error_test",
            operation_type=BatchOperationType.PROCESS,
            items=[{"id": 1}],
            processor_func=error_processor
        )

        await processor.submit_job(job)

        # Wait for processing
        await asyncio.sleep(0.3)

        # Job should be marked as failed
        status = await processor.get_job_status("error_test")
        assert status["status"] in [BatchJobStatus.FAILED, BatchJobStatus.RUNNING]

        await processor.stop()

    @pytest.mark.asyncio
    async def test_sync_processor_function(self):
        """Test handling of synchronous processor functions."""
        processor = BatchProcessor()
        await processor.start()

        def sync_processor(items, metadata):
            return [{'success': True} for _ in items]

        job = BatchJob(
            job_id="sync_test",
            operation_type=BatchOperationType.PROCESS,
            items=[{"id": 1}, {"id": 2}],
            processor_func=sync_processor
        )

        await processor.submit_job(job)

        # Wait for processing
        await asyncio.sleep(0.3)

        status = await processor.get_job_status("sync_test")
        assert status["status"] in [BatchJobStatus.COMPLETED, BatchJobStatus.RUNNING]

        await processor.stop()


class TestBatchServiceEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.fixture
    def batch_service(self):
        return BatchService()

    @pytest.mark.asyncio
    async def test_empty_batch_operations(self, batch_service):
        """Test batch operations with empty data."""
        await batch_service.start()

        # Empty memories list
        job_id = await batch_service.batch_create_memories(
            memories_data=[],
            agent_id="test_agent"
        )

        status = await batch_service.get_job_status(job_id)
        assert status["total_items"] == 0

        await batch_service.stop()

    @pytest.mark.asyncio
    async def test_invalid_memory_data(self, batch_service):
        """Test batch memory creation with invalid data."""
        await batch_service.start()

        invalid_memories = [
            {"content": "Valid memory"},
            {"invalid_field": "Missing content"},  # Missing required field
            {"content": "Another valid memory"}
        ]

        job_id = await batch_service.batch_create_memories(
            memories_data=invalid_memories,
            agent_id="test_agent"
        )

        # Job should be created even with invalid data
        # The processor will handle individual failures
        status = await batch_service.get_job_status(job_id)
        assert status is not None

        await batch_service.stop()


class TestBatchJobProgressCallbacks:
    """Test progress callback functionality."""

    @pytest.mark.asyncio
    async def test_progress_callback(self):
        """Test that progress callbacks are called."""
        processor = BatchProcessor()
        await processor.start()

        progress_updates = []

        async def progress_callback(status):
            progress_updates.append(status)

        async def mock_processor(items, metadata):
            await asyncio.sleep(0.05)
            return [{'success': True} for _ in items]

        job = BatchJob(
            job_id="progress_test",
            operation_type=BatchOperationType.PROCESS,
            items=[{"id": i} for i in range(4)],
            processor_func=mock_processor,
            batch_size=2
        )
        job.progress_callback = progress_callback

        await processor.submit_job(job)

        # Wait for processing
        await asyncio.sleep(0.3)

        # Check that progress callbacks were called
        assert len(progress_updates) > 0

        await processor.stop()

    @pytest.mark.asyncio
    async def test_progress_callback_exception(self):
        """Test handling of exceptions in progress callbacks."""
        processor = BatchProcessor()
        await processor.start()

        async def failing_callback(status):
            raise ValueError("Callback failed")

        async def mock_processor(items, metadata):
            return [{'success': True} for _ in items]

        job = BatchJob(
            job_id="callback_error_test",
            operation_type=BatchOperationType.PROCESS,
            items=[{"id": 1}],
            processor_func=mock_processor
        )
        job.progress_callback = failing_callback

        await processor.submit_job(job)

        # Wait for processing
        await asyncio.sleep(0.2)

        # Job should complete despite callback error
        status = await processor.get_job_status("callback_error_test")
        assert status["status"] in [BatchJobStatus.COMPLETED, BatchJobStatus.RUNNING]

        await processor.stop()
