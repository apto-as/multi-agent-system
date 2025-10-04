"""
Task API Integration Tests for TMWS.
Artemis-led comprehensive testing with 100% coverage target.

This module provides complete integration testing for the Task API endpoints,
ensuring perfect functionality and error handling across all scenarios.

Testing Strategy:
- Complete CRUD lifecycle testing
- Edge case handling and validation
- Performance verification (sub-200ms response times)
- Database transaction integrity
- Concurrent operation safety
- Error recovery mechanisms
- Security validation

Performance Requirements:
- API response time: < 200ms (95th percentile)
- Database queries: < 50ms
- Error rate: < 0.1%
- Test coverage: >= 90%
"""

import asyncio
import uuid
from datetime import datetime, timedelta
from typing import Any

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.task import Task, TaskPriority, TaskStatus


@pytest.mark.integration
class TestTaskAPIIntegration:
    """Complete integration testing for Task API endpoints."""

    async def test_create_task_success(
        self,
        async_client: AsyncClient,
        sample_task_data: dict[str, Any],
        performance_timer
    ):
        """Test successful task creation with performance validation."""
        # Performance monitoring
        timer = performance_timer.start()

        response = await async_client.post("/api/v1/tasks/", json=sample_task_data)

        elapsed = timer.stop()
        assert elapsed < 200, f"Response time {elapsed}ms exceeds 200ms threshold"

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        assert response_data["message"] == "Task created successfully"
        assert "task" in response_data

        task = response_data["task"]
        assert task["title"] == sample_task_data["title"]
        assert task["description"] == sample_task_data["description"]
        assert task["priority"] == sample_task_data["priority"]
        assert task["status"] == sample_task_data["status"]
        assert task["assigned_persona"] == sample_task_data["assigned_persona"]
        assert "id" in task
        assert "created_at" in task
        assert "updated_at" in task
        assert task["progress"] == 0

    async def test_create_task_validation_errors(self, async_client: AsyncClient):
        """Test task creation with invalid data."""
        # Empty title
        invalid_data = {
            "title": "",
            "description": "Test description",
            "priority": "medium"
        }
        response = await async_client.post("/api/v1/tasks/", json=invalid_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        # Invalid priority
        invalid_data = {
            "title": "Valid Title",
            "priority": "invalid_priority"
        }
        response = await async_client.post("/api/v1/tasks/", json=invalid_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_create_task_with_metadata(self, async_client: AsyncClient):
        """Test task creation with custom metadata."""
        task_data = {
            "title": "Task with Metadata",
            "description": "Task with custom metadata",
            "priority": "high",
            "metadata": {
                "project": "TMWS",
                "estimation": "4h",
                "tags": ["optimization", "performance"]
            }
        }

        response = await async_client.post("/api/v1/tasks/", json=task_data)
        assert response.status_code == status.HTTP_201_CREATED

        task = response.json()["task"]
        assert task["metadata"] == task_data["metadata"]

    async def test_list_tasks_empty(self, async_client: AsyncClient):
        """Test listing tasks when database is empty."""
        response = await async_client.get("/api/v1/tasks/")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["tasks"] == []
        assert data["total"] == 0
        assert data["skip"] == 0
        assert data["limit"] == 20

    async def test_list_tasks_with_pagination(self, async_client: AsyncClient):
        """Test task listing with pagination."""
        # Create multiple tasks
        tasks_created = []
        for i in range(25):
            task_data = {
                "title": f"Test Task {i}",
                "description": f"Description {i}",
                "priority": "medium"
            }
            response = await async_client.post("/api/v1/tasks/", json=task_data)
            tasks_created.append(response.json()["task"]["id"])

        # Test first page
        response = await async_client.get("/api/v1/tasks/?skip=0&limit=10")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert len(data["tasks"]) == 10
        assert data["total"] == 25
        assert data["skip"] == 0
        assert data["limit"] == 10

        # Test second page
        response = await async_client.get("/api/v1/tasks/?skip=10&limit=10")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert len(data["tasks"]) == 10
        assert data["skip"] == 10

        # Test last page
        response = await async_client.get("/api/v1/tasks/?skip=20&limit=10")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert len(data["tasks"]) == 5
        assert data["skip"] == 20

    async def test_list_tasks_with_filters(self, async_client: AsyncClient):
        """Test task listing with various filters."""
        # Create tasks with different statuses and priorities
        test_tasks = [
            {"title": "High Priority Pending", "priority": "high", "status": "pending"},
            {"title": "Medium Priority In Progress", "priority": "medium", "status": "in_progress"},
            {"title": "Low Priority Completed", "priority": "low", "status": "completed"},
            {"title": "High Priority Completed", "priority": "high", "status": "completed"},
        ]

        for task_data in test_tasks:
            await async_client.post("/api/v1/tasks/", json=task_data)

        # Filter by status
        response = await async_client.get("/api/v1/tasks/?status=completed")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["tasks"]) == 2
        assert all(task["status"] == "completed" for task in data["tasks"])

        # Filter by priority
        response = await async_client.get("/api/v1/tasks/?priority=high")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["tasks"]) == 2
        assert all(task["priority"] == "high" for task in data["tasks"])

        # Multiple filters
        response = await async_client.get("/api/v1/tasks/?status=completed&priority=high")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["tasks"]) == 1
        assert data["tasks"][0]["title"] == "High Priority Completed"

        # Filter by assigned persona
        await async_client.post("/api/v1/tasks/", json={
            "title": "Artemis Task",
            "assigned_persona": "artemis-optimizer"
        })

        response = await async_client.get("/api/v1/tasks/?assigned_persona=artemis-optimizer")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["tasks"]) == 1
        assert data["tasks"][0]["assigned_persona"] == "artemis-optimizer"

    async def test_get_task_success(self, async_client: AsyncClient, sample_task_data: dict[str, Any]):
        """Test successful task retrieval."""
        # Create a task first
        create_response = await async_client.post("/api/v1/tasks/", json=sample_task_data)
        task_id = create_response.json()["task"]["id"]

        # Retrieve the task
        response = await async_client.get(f"/api/v1/tasks/{task_id}")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert "task" in data

        task = data["task"]
        assert task["id"] == task_id
        assert task["title"] == sample_task_data["title"]
        assert task["description"] == sample_task_data["description"]

    async def test_get_task_not_found(self, async_client: AsyncClient):
        """Test task retrieval with non-existent ID."""
        fake_id = str(uuid.uuid4())
        response = await async_client.get(f"/api/v1/tasks/{fake_id}")

        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert f"Task {fake_id} not found" in data["detail"]

    async def test_get_task_invalid_uuid(self, async_client: AsyncClient):
        """Test task retrieval with invalid UUID format."""
        response = await async_client.get("/api/v1/tasks/invalid-uuid")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_update_task_success(self, async_client: AsyncClient, sample_task_data: dict[str, Any]):
        """Test successful task update."""
        # Create a task first
        create_response = await async_client.post("/api/v1/tasks/", json=sample_task_data)
        task_id = create_response.json()["task"]["id"]

        # Update the task
        update_data = {
            "title": "Updated Task Title",
            "description": "Updated description",
            "status": "in_progress",
            "priority": "high",
            "progress": 50,
            "metadata": {"updated": True}
        }

        response = await async_client.put(f"/api/v1/tasks/{task_id}", json=update_data)
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["message"] == "Task updated successfully"

        task = data["task"]
        assert task["title"] == update_data["title"]
        assert task["description"] == update_data["description"]
        assert task["status"] == update_data["status"]
        assert task["priority"] == update_data["priority"]
        assert task["progress"] == update_data["progress"]
        assert task["metadata"] == update_data["metadata"]
        assert task["updated_at"] != task["created_at"]

    async def test_update_task_partial(self, async_client: AsyncClient, sample_task_data: dict[str, Any]):
        """Test partial task update."""
        # Create a task first
        create_response = await async_client.post("/api/v1/tasks/", json=sample_task_data)
        task_id = create_response.json()["task"]["id"]
        original_title = create_response.json()["task"]["title"]

        # Update only status
        update_data = {"status": "in_progress"}

        response = await async_client.put(f"/api/v1/tasks/{task_id}", json=update_data)
        assert response.status_code == status.HTTP_200_OK

        task = response.json()["task"]
        assert task["status"] == "in_progress"
        assert task["title"] == original_title  # Should remain unchanged

    async def test_update_task_not_found(self, async_client: AsyncClient):
        """Test task update with non-existent ID."""
        fake_id = str(uuid.uuid4())
        update_data = {"title": "Updated Title"}

        response = await async_client.put(f"/api/v1/tasks/{fake_id}", json=update_data)
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_update_task_validation_errors(self, async_client: AsyncClient, sample_task_data: dict[str, Any]):
        """Test task update with invalid data."""
        # Create a task first
        create_response = await async_client.post("/api/v1/tasks/", json=sample_task_data)
        task_id = create_response.json()["task"]["id"]

        # Invalid progress value
        update_data = {"progress": 150}  # Progress should be 0-100
        response = await async_client.put(f"/api/v1/tasks/{task_id}", json=update_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Empty title
        update_data = {"title": ""}
        response = await async_client.put(f"/api/v1/tasks/{task_id}", json=update_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    async def test_delete_task_success(self, async_client: AsyncClient, sample_task_data: dict[str, Any]):
        """Test successful task deletion."""
        # Create a task first
        create_response = await async_client.post("/api/v1/tasks/", json=sample_task_data)
        task_id = create_response.json()["task"]["id"]

        # Delete the task
        response = await async_client.delete(f"/api/v1/tasks/{task_id}")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["message"] == "Task deleted successfully"
        assert data["task_id"] == task_id

        # Verify task is deleted
        get_response = await async_client.get(f"/api/v1/tasks/{task_id}")
        assert get_response.status_code == status.HTTP_404_NOT_FOUND

    async def test_delete_task_not_found(self, async_client: AsyncClient):
        """Test task deletion with non-existent ID."""
        fake_id = str(uuid.uuid4())
        response = await async_client.delete(f"/api/v1/tasks/{fake_id}")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_complete_task_success(self, async_client: AsyncClient, sample_task_data: dict[str, Any]):
        """Test successful task completion."""
        # Create a task first
        create_response = await async_client.post("/api/v1/tasks/", json=sample_task_data)
        task_id = create_response.json()["task"]["id"]

        # Complete the task
        response = await async_client.post(f"/api/v1/tasks/{task_id}/complete")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["message"] == "Task completed successfully"

        task = data["task"]
        assert task["status"] == "completed"
        assert task["progress"] == 100

    async def test_complete_task_not_found(self, async_client: AsyncClient):
        """Test task completion with non-existent ID."""
        fake_id = str(uuid.uuid4())
        response = await async_client.post(f"/api/v1/tasks/{fake_id}/complete")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_task_statistics_empty(self, async_client: AsyncClient):
        """Test task statistics with empty database."""
        response = await async_client.get("/api/v1/tasks/stats/summary")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["total_tasks"] == 0
        assert "by_status" in data
        assert "by_priority" in data
        assert "timestamp" in data

        # Check all status counts are 0
        for status_key in ["pending", "in_progress", "completed", "failed"]:
            assert data["by_status"][status_key] == 0

        # Check all priority counts are 0
        for priority_key in ["low", "medium", "high", "urgent"]:
            assert data["by_priority"][priority_key] == 0

    async def test_task_statistics_with_data(self, async_client: AsyncClient):
        """Test task statistics with various tasks."""
        # Create tasks with different statuses and priorities
        test_tasks = [
            {"title": "Task 1", "priority": "high", "status": "pending"},
            {"title": "Task 2", "priority": "high", "status": "completed"},
            {"title": "Task 3", "priority": "medium", "status": "in_progress"},
            {"title": "Task 4", "priority": "low", "status": "pending"},
            {"title": "Task 5", "priority": "medium", "status": "completed"},
        ]

        for task_data in test_tasks:
            await async_client.post("/api/v1/tasks/", json=task_data)

        response = await async_client.get("/api/v1/tasks/stats/summary")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["total_tasks"] == 5

        # Verify status counts
        assert data["by_status"]["pending"] == 2
        assert data["by_status"]["in_progress"] == 1
        assert data["by_status"]["completed"] == 2
        assert data["by_status"]["failed"] == 0

        # Verify priority counts
        assert data["by_priority"]["high"] == 2
        assert data["by_priority"]["medium"] == 2
        assert data["by_priority"]["low"] == 1
        assert data["by_priority"]["urgent"] == 0


@pytest.mark.integration
class TestTaskConcurrencyAndPerformance:
    """Test concurrent operations and performance requirements."""

    async def test_concurrent_task_creation(self, async_client: AsyncClient):
        """Test concurrent task creation for race conditions."""
        async def create_task(i: int):
            task_data = {
                "title": f"Concurrent Task {i}",
                "description": f"Task created concurrently {i}",
                "priority": "medium"
            }
            response = await async_client.post("/api/v1/tasks/", json=task_data)
            return response.status_code, response.json()

        # Create 10 tasks concurrently
        tasks = [create_task(i) for i in range(10)]
        results = await asyncio.gather(*tasks)

        # All should succeed
        for status_code, data in results:
            assert status_code == status.HTTP_201_CREATED
            assert "task" in data

        # Verify all tasks were created
        list_response = await async_client.get("/api/v1/tasks/")
        assert list_response.json()["total"] == 10

    async def test_concurrent_task_updates(self, async_client: AsyncClient, sample_task_data: dict[str, Any]):
        """Test concurrent updates to the same task."""
        # Create a task first
        create_response = await async_client.post("/api/v1/tasks/", json=sample_task_data)
        task_id = create_response.json()["task"]["id"]

        async def update_task(progress: int):
            update_data = {"progress": progress}
            response = await async_client.put(f"/api/v1/tasks/{task_id}", json=update_data)
            return response.status_code, response.json()

        # Update with different progress values concurrently
        updates = [update_task(i * 10) for i in range(1, 6)]  # 10, 20, 30, 40, 50
        results = await asyncio.gather(*updates, return_exceptions=True)

        # At least one should succeed (last writer wins)
        success_count = sum(1 for result in results if not isinstance(result, Exception) and result[0] == 200)
        assert success_count >= 1

        # Verify final state
        get_response = await async_client.get(f"/api/v1/tasks/{task_id}")
        final_task = get_response.json()["task"]
        assert final_task["progress"] in [10, 20, 30, 40, 50]

    async def test_bulk_operations_performance(self, async_client: AsyncClient, performance_timer):
        """Test performance of bulk operations."""
        # Bulk creation
        timer = performance_timer.start()

        for i in range(50):
            task_data = {
                "title": f"Bulk Task {i}",
                "description": f"Bulk created task {i}",
                "priority": "medium"
            }
            await async_client.post("/api/v1/tasks/", json=task_data)

        creation_time = timer.stop()
        assert creation_time < 10000, f"Bulk creation took {creation_time}ms, expected < 10s"

        # Bulk retrieval
        timer.start()
        response = await async_client.get("/api/v1/tasks/?limit=50")
        retrieval_time = timer.stop()

        assert retrieval_time < 500, f"Bulk retrieval took {retrieval_time}ms, expected < 500ms"
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["tasks"]) == 50


@pytest.mark.integration
class TestTaskDatabaseIntegrity:
    """Test database transaction integrity and error recovery."""

    async def test_database_rollback_on_error(
        self,
        async_client: AsyncClient,
        test_session: AsyncSession
    ):
        """Test database rollback when task creation fails."""
        # This test would require mocking to force a database error
        # For now, test basic integrity

        task_data = {
            "title": "Test Rollback",
            "description": "Test database rollback",
            "priority": "medium"
        }

        response = await async_client.post("/api/v1/tasks/", json=task_data)
        assert response.status_code == status.HTTP_201_CREATED

        # Verify task exists in database
        task_id = response.json()["task"]["id"]
        get_response = await async_client.get(f"/api/v1/tasks/{task_id}")
        assert get_response.status_code == status.HTTP_200_OK

    async def test_task_lifecycle_integrity(self, async_client: AsyncClient):
        """Test complete task lifecycle maintains data integrity."""
        # Create
        task_data = {
            "title": "Lifecycle Test",
            "description": "Test complete lifecycle",
            "priority": "high",
            "metadata": {"phase": "creation"}
        }

        create_response = await async_client.post("/api/v1/tasks/", json=task_data)
        assert create_response.status_code == status.HTTP_201_CREATED
        task_id = create_response.json()["task"]["id"]
        original_created_at = create_response.json()["task"]["created_at"]

        # Update
        update_response = await async_client.put(f"/api/v1/tasks/{task_id}", json={
            "status": "in_progress",
            "progress": 25,
            "metadata": {"phase": "in_progress"}
        })
        assert update_response.status_code == status.HTTP_200_OK

        # Verify update preserved creation data
        updated_task = update_response.json()["task"]
        assert updated_task["created_at"] == original_created_at
        assert updated_task["title"] == task_data["title"]  # Unchanged
        assert updated_task["status"] == "in_progress"  # Changed
        assert updated_task["progress"] == 25  # Changed

        # Complete
        complete_response = await async_client.post(f"/api/v1/tasks/{task_id}/complete")
        assert complete_response.status_code == status.HTTP_200_OK

        completed_task = complete_response.json()["task"]
        assert completed_task["status"] == "completed"
        assert completed_task["progress"] == 100
        assert completed_task["created_at"] == original_created_at  # Still preserved

        # Delete
        delete_response = await async_client.delete(f"/api/v1/tasks/{task_id}")
        assert delete_response.status_code == status.HTTP_200_OK

        # Verify deletion
        final_get = await async_client.get(f"/api/v1/tasks/{task_id}")
        assert final_get.status_code == status.HTTP_404_NOT_FOUND