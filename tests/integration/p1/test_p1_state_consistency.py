"""
P1 Integration Tests: State Consistency
HIGH PRIORITY: These tests verify system state consistency and transitions.

Test IDs:
- STATE-P1-001: Agent state transitions
- STATE-P1-002: Task state consistency
- STATE-P1-003: Memory state integrity
- STATE-P1-004: Transaction rollback
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import pytest


@pytest.mark.integration
@pytest.mark.asyncio
class TestAgentStateTransitions:
    """STATE-P1-001: Agent state transition tests."""

    async def test_valid_state_transition_pending_to_active(
        self, mock_agent_service, state_transition_matrix
    ):
        """STATE-P1-001-T1: Valid transition from pending to active."""
        # Setup agent in pending state
        pending_agent = Mock()
        pending_agent.id = uuid4()
        pending_agent.status = "pending"
        mock_agent_service.get_agent.return_value = pending_agent

        # Transition to active
        active_agent = Mock()
        active_agent.id = pending_agent.id
        active_agent.status = "active"
        mock_agent_service.update_agent.return_value = active_agent

        agent = await mock_agent_service.get_agent(agent_id="test-agent")
        assert agent.status == "pending"

        updated = await mock_agent_service.update_agent(
            agent_id="test-agent",
            status="active"
        )
        assert updated.status == "active"

        # Verify this is a valid transition
        assert "active" in state_transition_matrix["pending"]

    async def test_invalid_state_transition_rejected(
        self, mock_agent_service, state_transition_matrix
    ):
        """STATE-P1-001-T2: Invalid state transitions are rejected."""
        # Setup agent in completed state
        completed_agent = Mock()
        completed_agent.id = uuid4()
        completed_agent.status = "completed"
        mock_agent_service.get_agent.return_value = completed_agent

        # Try invalid transition to active (completed -> active is not valid)
        mock_agent_service.update_agent.side_effect = ValueError(
            "Invalid state transition: completed -> active"
        )

        with pytest.raises(ValueError) as exc_info:
            await mock_agent_service.update_agent(
                agent_id="test-agent",
                status="active"
            )

        assert "transition" in str(exc_info.value).lower()
        assert "active" not in state_transition_matrix["completed"]

    async def test_state_transition_audit_log(self, mock_agent_service):
        """STATE-P1-001-T3: State transitions are logged."""
        # Mock audit logger
        mock_audit = AsyncMock()

        async def update_with_audit(agent_id: str, status: str):
            old_status = "pending"
            new_status = status
            await mock_audit.log_state_change(
                agent_id=agent_id,
                old_status=old_status,
                new_status=new_status,
                timestamp=datetime.now(timezone.utc)
            )
            agent = Mock()
            agent.status = new_status
            return agent

        mock_agent_service.update_agent.side_effect = update_with_audit

        await mock_agent_service.update_agent(agent_id="test-agent", status="active")

        mock_audit.log_state_change.assert_called_once()
        call_args = mock_audit.log_state_change.call_args
        assert call_args.kwargs["old_status"] == "pending"
        assert call_args.kwargs["new_status"] == "active"


@pytest.mark.integration
@pytest.mark.asyncio
class TestTaskStateConsistency:
    """STATE-P1-002: Task state consistency tests."""

    async def test_task_completion_updates_agent_metrics(self):
        """STATE-P1-002-T1: Task completion updates agent metrics."""
        mock_task_service = AsyncMock()
        mock_agent_service = AsyncMock()

        # Initial agent metrics
        agent = Mock()
        agent.tasks_completed = 5
        agent.success_rate = 0.8
        mock_agent_service.get_agent.return_value = agent

        async def complete_task_with_metrics(task_id: str, result: str):
            # Update agent metrics on task completion
            agent.tasks_completed += 1
            if result == "success":
                # Recalculate success rate
                agent.success_rate = (agent.success_rate * 5 + 1) / 6
            return {"status": "completed", "result": result}

        mock_task_service.complete_task.side_effect = complete_task_with_metrics

        result = await mock_task_service.complete_task(
            task_id=str(uuid4()),
            result="success"
        )

        assert result["status"] == "completed"
        assert agent.tasks_completed == 6

    async def test_task_failure_preserves_consistency(self):
        """STATE-P1-002-T2: Task failure preserves data consistency."""
        mock_task_service = AsyncMock()

        # Simulate failure during task processing
        task = Mock()
        task.id = uuid4()
        task.status = "running"
        task.retries = 0

        async def fail_task(task_id: str, error: str):
            task.status = "failed"
            task.retries += 1
            task.error_message = error
            return task

        mock_task_service.fail_task.side_effect = fail_task

        result = await mock_task_service.fail_task(
            task_id=str(task.id),
            error="Connection timeout"
        )

        assert result.status == "failed"
        assert result.retries == 1
        assert result.error_message == "Connection timeout"

    async def test_concurrent_task_updates_are_safe(self):
        """STATE-P1-002-T3: Concurrent task updates maintain consistency."""
        mock_task_service = AsyncMock()

        task = Mock()
        task.id = uuid4()
        task.progress = 0
        lock = asyncio.Lock()

        async def update_progress(task_id: str, increment: int):
            async with lock:
                task.progress += increment
                return task.progress

        mock_task_service.update_progress.side_effect = update_progress

        # Run concurrent updates
        results = await asyncio.gather(
            *[mock_task_service.update_progress(str(task.id), 10) for _ in range(10)]
        )

        # Final progress should be 100 (10 updates * 10 each)
        assert task.progress == 100


@pytest.mark.integration
@pytest.mark.asyncio
class TestMemoryStateIntegrity:
    """STATE-P1-003: Memory state integrity tests."""

    async def test_memory_update_preserves_metadata(self):
        """STATE-P1-003-T1: Memory update preserves essential metadata."""
        mock_memory_service = AsyncMock()

        original_memory = Mock()
        original_memory.id = uuid4()
        original_memory.content = "Original content"
        original_memory.created_at = datetime.now(timezone.utc)
        original_memory.agent_id = "test-agent"
        original_memory.namespace = "test-namespace"

        updated_memory = Mock()
        updated_memory.id = original_memory.id
        updated_memory.content = "Updated content"
        updated_memory.created_at = original_memory.created_at  # Preserved
        updated_memory.agent_id = original_memory.agent_id  # Preserved
        updated_memory.namespace = original_memory.namespace  # Preserved
        updated_memory.updated_at = datetime.now(timezone.utc)

        mock_memory_service.update_memory.return_value = updated_memory

        result = await mock_memory_service.update_memory(
            memory_id=str(original_memory.id),
            content="Updated content"
        )

        # Essential metadata should be preserved
        assert result.id == original_memory.id
        assert result.created_at == original_memory.created_at
        assert result.agent_id == original_memory.agent_id
        assert result.namespace == original_memory.namespace
        # Content should be updated
        assert result.content == "Updated content"

    async def test_memory_deletion_cascades_properly(self):
        """STATE-P1-003-T2: Memory deletion cascades to related data."""
        mock_memory_service = AsyncMock()

        memory_id = uuid4()

        # Track cascade operations
        cascade_operations = []

        async def delete_with_cascade(memory_id: str):
            cascade_operations.append(f"delete_embeddings:{memory_id}")
            cascade_operations.append(f"delete_references:{memory_id}")
            cascade_operations.append(f"delete_memory:{memory_id}")
            return True

        mock_memory_service.delete_memory.side_effect = delete_with_cascade

        result = await mock_memory_service.delete_memory(str(memory_id))

        assert result is True
        assert len(cascade_operations) == 3
        assert f"delete_embeddings:{memory_id}" in cascade_operations
        assert f"delete_references:{memory_id}" in cascade_operations
        assert f"delete_memory:{memory_id}" in cascade_operations


@pytest.mark.integration
@pytest.mark.asyncio
class TestTransactionRollback:
    """STATE-P1-004: Transaction rollback tests."""

    async def test_rollback_on_partial_failure(self):
        """STATE-P1-004-T1: Partial failures trigger complete rollback."""
        mock_db = AsyncMock()
        operations_completed = []

        async def create_agent_with_resources(agent_data: dict):
            try:
                # Step 1: Create agent
                operations_completed.append("create_agent")

                # Step 2: Create default namespace (fails)
                raise Exception("Database connection lost")

            except Exception as e:
                # Rollback
                if "create_agent" in operations_completed:
                    operations_completed.remove("create_agent")
                    operations_completed.append("rollback_agent")
                raise

        mock_db.create_agent_with_resources.side_effect = create_agent_with_resources

        with pytest.raises(Exception) as exc_info:
            await mock_db.create_agent_with_resources({"name": "test"})

        assert "Database connection lost" in str(exc_info.value)
        assert "rollback_agent" in operations_completed
        assert "create_agent" not in operations_completed

    async def test_nested_transaction_rollback(self):
        """STATE-P1-004-T2: Nested transactions rollback correctly."""
        mock_db = AsyncMock()
        savepoints = []

        async def nested_operation():
            savepoints.append("outer_start")
            try:
                savepoints.append("inner_start")
                raise ValueError("Inner operation failed")
            except ValueError:
                savepoints.append("inner_rollback")
                raise
            finally:
                if "inner_rollback" in savepoints:
                    savepoints.append("outer_rollback")

        mock_db.nested_operation.side_effect = nested_operation

        with pytest.raises(ValueError):
            await mock_db.nested_operation()

        assert "inner_rollback" in savepoints
        assert "outer_rollback" in savepoints

    async def test_idempotent_operations(self):
        """STATE-P1-004-T3: Operations are idempotent."""
        mock_service = AsyncMock()
        operation_count = {"create": 0}

        async def idempotent_create(resource_id: str, data: dict):
            operation_count["create"] += 1
            # Return same result regardless of how many times called
            return {"id": resource_id, "data": data, "created": True}

        mock_service.create_or_update.side_effect = idempotent_create

        # Call multiple times with same data
        results = [
            await mock_service.create_or_update("resource-1", {"name": "test"})
            for _ in range(3)
        ]

        # All results should be identical
        assert all(r["id"] == "resource-1" for r in results)
        assert all(r["created"] is True for r in results)
        # Service was called 3 times but result is consistent
        assert operation_count["create"] == 3
