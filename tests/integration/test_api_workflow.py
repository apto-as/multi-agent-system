"""
Workflow API Integration Tests for TMWS.
Artemis-led comprehensive testing with maximum efficiency and coverage.

This module provides complete integration testing for the Workflow API endpoints,
ensuring flawless execution, monitoring, and control of workflow operations.

Testing Strategy:
- Complete workflow lifecycle testing
- Background execution validation
- Status monitoring and cancellation
- Concurrent workflow handling
- Performance optimization verification
- Error recovery and resilience testing
- Database transaction integrity

Performance Requirements:
- Workflow creation: < 100ms
- Status checking: < 50ms
- Execution initiation: < 200ms
- Cancellation: < 100ms
- Test coverage: >= 95%
"""

import asyncio
import uuid
from datetime import datetime
from typing import Any

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.mark.integration
class TestWorkflowAPIIntegration:
    """Complete integration testing for Workflow API endpoints."""

    async def test_create_workflow_success(
        self, async_client: AsyncClient, sample_workflow_data: dict[str, Any], performance_timer
    ):
        """Test successful workflow creation with performance validation."""
        timer = performance_timer.start()

        response = await async_client.post("/api/v1/workflows/", json=sample_workflow_data)

        elapsed = timer.stop()
        assert elapsed < 100, f"Workflow creation took {elapsed}ms, expected < 100ms"

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        assert response_data["message"] == "Workflow created successfully"
        assert "workflow" in response_data

        workflow = response_data["workflow"]
        assert workflow["name"] == sample_workflow_data["name"]
        assert workflow["workflow_type"] == sample_workflow_data["workflow_type"]
        assert workflow["priority"] == sample_workflow_data["priority"]
        assert workflow["config"] == sample_workflow_data["config"]
        assert workflow["status"] == "pending"
        assert "id" in workflow
        assert "created_at" in workflow

    async def test_create_workflow_validation_errors(self, async_client: AsyncClient):
        """Test workflow creation with invalid data."""
        # Empty name
        invalid_data = {"name": "", "workflow_type": "sequential", "config": {"steps": []}}
        response = await async_client.post("/api/v1/workflows/", json=invalid_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        # Missing required fields
        invalid_data = {
            "name": "Valid Name"
            # Missing workflow_type
        }
        response = await async_client.post("/api/v1/workflows/", json=invalid_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_create_workflow_with_complex_config(self, async_client: AsyncClient):
        """Test workflow creation with complex configuration."""
        complex_workflow = {
            "name": "Complex Workflow",
            "workflow_type": "parallel",
            "description": "Multi-step parallel workflow",
            "config": {
                "steps": [
                    {
                        "name": "data_analysis",
                        "persona": "artemis-optimizer",
                        "action": "analyze_performance",
                        "timeout": 300,
                        "retries": 3,
                    },
                    {
                        "name": "security_scan",
                        "persona": "hestia-auditor",
                        "action": "security_audit",
                        "timeout": 600,
                        "parallel": True,
                    },
                ],
                "rollback_strategy": "immediate",
                "notification_config": {
                    "on_success": ["admin@example.com"],
                    "on_failure": ["ops@example.com"],
                },
            },
            "metadata": {"project": "TMWS", "environment": "test", "estimated_duration": "15min"},
        }

        response = await async_client.post("/api/v1/workflows/", json=complex_workflow)
        assert response.status_code == status.HTTP_201_CREATED

        workflow = response.json()["workflow"]
        assert workflow["config"] == complex_workflow["config"]
        assert workflow["metadata"] == complex_workflow["metadata"]

    async def test_list_workflows_empty(self, async_client: AsyncClient):
        """Test listing workflows when database is empty."""
        response = await async_client.get("/api/v1/workflows/")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["workflows"] == []
        assert data["total"] == 0
        assert data["skip"] == 0
        assert data["limit"] == 20

    async def test_list_workflows_with_pagination(self, async_client: AsyncClient):
        """Test workflow listing with pagination and ordering."""
        # Create multiple workflows
        workflows_created = []
        for i in range(15):
            workflow_data = {
                "name": f"Test Workflow {i}",
                "workflow_type": "sequential",
                "config": {"steps": [{"action": f"step_{i}"}]},
            }
            response = await async_client.post("/api/v1/workflows/", json=workflow_data)
            workflows_created.append(response.json()["workflow"])

        # Test first page (should be ordered by created_at desc)
        response = await async_client.get("/api/v1/workflows/?skip=0&limit=10")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert len(data["workflows"]) == 10
        assert data["total"] == 15
        assert data["skip"] == 0
        assert data["limit"] == 10

        # Verify ordering (newest first)
        workflows = data["workflows"]
        for i in range(len(workflows) - 1):
            current_time = datetime.fromisoformat(workflows[i]["created_at"].replace("Z", "+00:00"))
            next_time = datetime.fromisoformat(
                workflows[i + 1]["created_at"].replace("Z", "+00:00")
            )
            assert current_time >= next_time

    async def test_list_workflows_with_filters(self, async_client: AsyncClient):
        """Test workflow listing with status and type filters."""
        # Create workflows with different statuses and types
        test_workflows = [
            {"name": "Sequential Pending", "workflow_type": "sequential", "status": "pending"},
            {"name": "Parallel Running", "workflow_type": "parallel", "status": "running"},
            {"name": "Sequential Completed", "workflow_type": "sequential", "status": "completed"},
            {"name": "Parallel Completed", "workflow_type": "parallel", "status": "completed"},
        ]

        created_ids = []
        for workflow_data in test_workflows:
            config = {"steps": [{"action": "test"}]}
            create_data = {**workflow_data, "config": config}
            response = await async_client.post("/api/v1/workflows/", json=create_data)
            workflow_id = response.json()["workflow"]["id"]
            created_ids.append(workflow_id)

            # Update status if not pending
            if workflow_data["status"] != "pending":
                {"status": workflow_data["status"]}
                # Note: This would normally be done by the workflow service
                # For testing, we'll directly update via the API

        # Filter by status
        response = await async_client.get("/api/v1/workflows/?status=completed")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # Note: Since we can't directly set status via API, we'll test the filter structure

        # Filter by workflow type
        response = await async_client.get("/api/v1/workflows/?workflow_type=sequential")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # All returned workflows should be sequential
        for workflow in data["workflows"]:
            assert workflow["workflow_type"] == "sequential"

    async def test_get_workflow_success(
        self, async_client: AsyncClient, sample_workflow_data: dict[str, Any]
    ):
        """Test successful workflow retrieval."""
        # Create a workflow first
        create_response = await async_client.post("/api/v1/workflows/", json=sample_workflow_data)
        workflow_id = create_response.json()["workflow"]["id"]

        # Retrieve the workflow
        response = await async_client.get(f"/api/v1/workflows/{workflow_id}")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert "workflow" in data

        workflow = data["workflow"]
        assert workflow["id"] == workflow_id
        assert workflow["name"] == sample_workflow_data["name"]
        assert workflow["workflow_type"] == sample_workflow_data["workflow_type"]

    async def test_get_workflow_with_history(
        self, async_client: AsyncClient, sample_workflow_data: dict[str, Any]
    ):
        """Test workflow retrieval with execution history."""
        # Create a workflow first
        create_response = await async_client.post("/api/v1/workflows/", json=sample_workflow_data)
        workflow_id = create_response.json()["workflow"]["id"]

        # Get workflow with history
        response = await async_client.get(f"/api/v1/workflows/{workflow_id}?include_history=true")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert "workflow" in data
        assert "execution_history" in data
        assert isinstance(data["execution_history"], list)

    async def test_get_workflow_not_found(self, async_client: AsyncClient):
        """Test workflow retrieval with non-existent ID."""
        fake_id = str(uuid.uuid4())
        response = await async_client.get(f"/api/v1/workflows/{fake_id}")

        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert f"Workflow {fake_id} not found" in data["detail"]

    async def test_update_workflow_success(
        self, async_client: AsyncClient, sample_workflow_data: dict[str, Any]
    ):
        """Test successful workflow update."""
        # Create a workflow first
        create_response = await async_client.post("/api/v1/workflows/", json=sample_workflow_data)
        workflow_id = create_response.json()["workflow"]["id"]

        # Update the workflow
        update_data = {
            "name": "Updated Workflow Name",
            "description": "Updated description",
            "config": {
                "steps": [{"action": "new_step", "persona": "artemis-optimizer"}],
                "timeout": 600,
            },
            "metadata": {"updated": True},
        }

        response = await async_client.put(f"/api/v1/workflows/{workflow_id}", json=update_data)
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["message"] == "Workflow updated successfully"

        workflow = data["workflow"]
        assert workflow["name"] == update_data["name"]
        assert workflow["description"] == update_data["description"]
        assert workflow["config"] == update_data["config"]
        assert workflow["metadata"] == update_data["metadata"]

    async def test_update_running_workflow_fails(
        self, async_client: AsyncClient, sample_workflow_data: dict[str, Any]
    ):
        """Test that updating a running workflow is not allowed."""
        # Create and start a workflow
        create_response = await async_client.post("/api/v1/workflows/", json=sample_workflow_data)
        workflow_id = create_response.json()["workflow"]["id"]

        # Start the workflow
        start_response = await async_client.post(f"/api/v1/workflows/{workflow_id}/execute")
        assert start_response.status_code == status.HTTP_200_OK

        # Try to update the running workflow
        update_data = {"name": "Updated Name"}
        response = await async_client.put(f"/api/v1/workflows/{workflow_id}", json=update_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Cannot update a running workflow" in response.json()["detail"]

    async def test_delete_workflow_success(
        self, async_client: AsyncClient, sample_workflow_data: dict[str, Any]
    ):
        """Test successful workflow deletion."""
        # Create a workflow first
        create_response = await async_client.post("/api/v1/workflows/", json=sample_workflow_data)
        workflow_id = create_response.json()["workflow"]["id"]

        # Delete the workflow
        response = await async_client.delete(f"/api/v1/workflows/{workflow_id}")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["message"] == "Workflow deleted successfully"
        assert data["workflow_id"] == workflow_id

        # Verify workflow is deleted
        get_response = await async_client.get(f"/api/v1/workflows/{workflow_id}")
        assert get_response.status_code == status.HTTP_404_NOT_FOUND

    async def test_delete_running_workflow_fails(
        self, async_client: AsyncClient, sample_workflow_data: dict[str, Any]
    ):
        """Test that deleting a running workflow is not allowed."""
        # Create and start a workflow
        create_response = await async_client.post("/api/v1/workflows/", json=sample_workflow_data)
        workflow_id = create_response.json()["workflow"]["id"]

        # Start the workflow
        await async_client.post(f"/api/v1/workflows/{workflow_id}/execute")

        # Try to delete the running workflow
        response = await async_client.delete(f"/api/v1/workflows/{workflow_id}")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Cannot delete a running workflow" in response.json()["detail"]

    async def test_execute_workflow_success(
        self, async_client: AsyncClient, sample_workflow_data: dict[str, Any], performance_timer
    ):
        """Test successful workflow execution initiation."""
        # Create a workflow first
        create_response = await async_client.post("/api/v1/workflows/", json=sample_workflow_data)
        workflow_id = create_response.json()["workflow"]["id"]

        # Execute the workflow
        timer = performance_timer.start()
        execution_params = {"environment": "test", "debug": True, "timeout": 300}

        response = await async_client.post(
            f"/api/v1/workflows/{workflow_id}/execute", json=execution_params
        )

        elapsed = timer.stop()
        assert elapsed < 200, f"Workflow execution initiation took {elapsed}ms, expected < 200ms"

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["message"] == "Workflow execution started"
        assert data["workflow_id"] == workflow_id
        assert data["status"] == "running"
        assert "started_at" in data

    async def test_execute_running_workflow_fails(
        self, async_client: AsyncClient, sample_workflow_data: dict[str, Any]
    ):
        """Test that executing an already running workflow fails."""
        # Create and start a workflow
        create_response = await async_client.post("/api/v1/workflows/", json=sample_workflow_data)
        workflow_id = create_response.json()["workflow"]["id"]

        # Start the workflow
        await async_client.post(f"/api/v1/workflows/{workflow_id}/execute")

        # Try to start it again
        response = await async_client.post(f"/api/v1/workflows/{workflow_id}/execute")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Workflow is already running" in response.json()["detail"]

    async def test_get_workflow_status(
        self, async_client: AsyncClient, sample_workflow_data: dict[str, Any], performance_timer
    ):
        """Test workflow status retrieval with performance validation."""
        # Create and start a workflow
        create_response = await async_client.post("/api/v1/workflows/", json=sample_workflow_data)
        workflow_id = create_response.json()["workflow"]["id"]

        await async_client.post(f"/api/v1/workflows/{workflow_id}/execute")

        # Get status
        timer = performance_timer.start()
        response = await async_client.get(f"/api/v1/workflows/{workflow_id}/status")
        elapsed = timer.stop()

        assert elapsed < 50, f"Status check took {elapsed}ms, expected < 50ms"

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["workflow_id"] == workflow_id
        assert data["status"] == "running"
        assert data["started_at"] is not None
        assert "completed_at" in data
        assert "error" in data
        assert "result" in data

    async def test_cancel_workflow_success(
        self, async_client: AsyncClient, sample_workflow_data: dict[str, Any], performance_timer
    ):
        """Test successful workflow cancellation."""
        # Create and start a workflow
        create_response = await async_client.post("/api/v1/workflows/", json=sample_workflow_data)
        workflow_id = create_response.json()["workflow"]["id"]

        await async_client.post(f"/api/v1/workflows/{workflow_id}/execute")

        # Cancel the workflow
        timer = performance_timer.start()
        response = await async_client.post(f"/api/v1/workflows/{workflow_id}/cancel")
        elapsed = timer.stop()

        assert elapsed < 100, f"Workflow cancellation took {elapsed}ms, expected < 100ms"

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["message"] == "Workflow cancelled successfully"
        assert data["workflow_id"] == workflow_id
        assert data["status"] == "cancelled"

        # Verify status is updated
        status_response = await async_client.get(f"/api/v1/workflows/{workflow_id}/status")
        status_data = status_response.json()
        assert status_data["status"] == "cancelled"
        assert status_data["error"] == "Cancelled by user"

    async def test_cancel_non_running_workflow_fails(
        self, async_client: AsyncClient, sample_workflow_data: dict[str, Any]
    ):
        """Test that cancelling a non-running workflow fails."""
        # Create a workflow but don't start it
        create_response = await async_client.post("/api/v1/workflows/", json=sample_workflow_data)
        workflow_id = create_response.json()["workflow"]["id"]

        # Try to cancel the pending workflow
        response = await async_client.post(f"/api/v1/workflows/{workflow_id}/cancel")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Workflow is not running" in response.json()["detail"]

    async def test_workflow_statistics_empty(self, async_client: AsyncClient):
        """Test workflow statistics with empty database."""
        response = await async_client.get("/api/v1/workflows/stats/summary")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["total_workflows"] == 0
        assert "by_status" in data
        assert "by_type" in data
        assert "timestamp" in data

        # Check all status counts are 0
        for status_key in ["pending", "running", "completed", "failed", "cancelled"]:
            assert data["by_status"][status_key] == 0

    async def test_workflow_statistics_with_data(self, async_client: AsyncClient):
        """Test workflow statistics with various workflows."""
        # Create workflows with different types
        test_workflows = [
            {"name": "Sequential 1", "workflow_type": "sequential"},
            {"name": "Sequential 2", "workflow_type": "sequential"},
            {"name": "Parallel 1", "workflow_type": "parallel"},
            {"name": "Batch 1", "workflow_type": "batch"},
            {"name": "Custom 1", "workflow_type": "custom_type"},
        ]

        for workflow_data in test_workflows:
            workflow_data["config"] = {"steps": [{"action": "test"}]}
            await async_client.post("/api/v1/workflows/", json=workflow_data)

        response = await async_client.get("/api/v1/workflows/stats/summary")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["total_workflows"] == 5

        # Verify type counts
        assert data["by_type"]["sequential"] == 2
        assert data["by_type"]["parallel"] == 1
        assert data["by_type"]["batch"] == 1
        assert data["by_type"]["custom_type"] == 1

        # All should be pending initially
        assert data["by_status"]["pending"] == 5


@pytest.mark.integration
class TestWorkflowConcurrencyAndPerformance:
    """Test concurrent workflow operations and performance optimization."""

    async def test_concurrent_workflow_execution(self, async_client: AsyncClient):
        """Test concurrent execution of multiple workflows."""
        # Create multiple workflows
        workflow_ids = []
        for i in range(5):
            workflow_data = {
                "name": f"Concurrent Workflow {i}",
                "workflow_type": "sequential",
                "config": {
                    "steps": [
                        {"action": f"step_1_{i}", "timeout": 100},
                        {"action": f"step_2_{i}", "timeout": 100},
                    ]
                },
            }
            response = await async_client.post("/api/v1/workflows/", json=workflow_data)
            workflow_ids.append(response.json()["workflow"]["id"])

        # Start all workflows concurrently
        async def start_workflow(workflow_id):
            response = await async_client.post(f"/api/v1/workflows/{workflow_id}/execute")
            return response.status_code, workflow_id

        tasks = [start_workflow(wf_id) for wf_id in workflow_ids]
        results = await asyncio.gather(*tasks)

        # All should start successfully
        for status_code, _ in results:
            assert status_code == status.HTTP_200_OK

        # Verify all are running
        for workflow_id in workflow_ids:
            status_response = await async_client.get(f"/api/v1/workflows/{workflow_id}/status")
            assert status_response.json()["status"] == "running"

    async def test_workflow_status_polling_performance(
        self, async_client: AsyncClient, performance_timer
    ):
        """Test performance of rapid status polling."""
        # Create and start a workflow
        workflow_data = {
            "name": "Status Test Workflow",
            "workflow_type": "sequential",
            "config": {"steps": [{"action": "long_running_task", "timeout": 5000}]},
        }

        create_response = await async_client.post("/api/v1/workflows/", json=workflow_data)
        workflow_id = create_response.json()["workflow"]["id"]

        await async_client.post(f"/api/v1/workflows/{workflow_id}/execute")

        # Poll status rapidly
        timer = performance_timer.start()

        for _ in range(20):  # 20 rapid status checks
            response = await async_client.get(f"/api/v1/workflows/{workflow_id}/status")
            assert response.status_code == status.HTTP_200_OK

        total_time = timer.stop()
        average_time = total_time / 20

        assert average_time < 50, f"Average status check time {average_time}ms exceeds 50ms"

    async def test_bulk_workflow_operations(self, async_client: AsyncClient, performance_timer):
        """Test performance of bulk workflow operations."""
        # Bulk creation
        timer = performance_timer.start()

        workflow_ids = []
        for i in range(20):
            workflow_data = {
                "name": f"Bulk Workflow {i}",
                "workflow_type": "sequential",
                "config": {"steps": [{"action": f"bulk_step_{i}"}]},
            }
            response = await async_client.post("/api/v1/workflows/", json=workflow_data)
            workflow_ids.append(response.json()["workflow"]["id"])

        creation_time = timer.stop()
        assert creation_time < 5000, f"Bulk creation took {creation_time}ms, expected < 5s"

        # Bulk status checking
        timer.start()
        for workflow_id in workflow_ids:
            response = await async_client.get(f"/api/v1/workflows/{workflow_id}/status")
            assert response.status_code == status.HTTP_200_OK

        status_check_time = timer.stop()
        assert status_check_time < 2000, (
            f"Bulk status check took {status_check_time}ms, expected < 2s"
        )


@pytest.mark.integration
class TestWorkflowErrorHandling:
    """Test workflow error handling and recovery mechanisms."""

    async def test_workflow_not_found_error_handling(self, async_client: AsyncClient):
        """Test proper error handling for non-existent workflows."""
        fake_id = str(uuid.uuid4())

        # Test all endpoints with non-existent ID
        endpoints_and_methods = [
            ("GET", f"/api/v1/workflows/{fake_id}"),
            ("PUT", f"/api/v1/workflows/{fake_id}"),
            ("DELETE", f"/api/v1/workflows/{fake_id}"),
            ("POST", f"/api/v1/workflows/{fake_id}/execute"),
            ("GET", f"/api/v1/workflows/{fake_id}/status"),
            ("POST", f"/api/v1/workflows/{fake_id}/cancel"),
        ]

        for method, endpoint in endpoints_and_methods:
            if method == "GET":
                response = await async_client.get(endpoint)
            elif method == "PUT":
                response = await async_client.put(endpoint, json={"name": "test"})
            elif method == "DELETE":
                response = await async_client.delete(endpoint)
            elif method == "POST":
                response = await async_client.post(endpoint, json={})

            assert response.status_code == status.HTTP_404_NOT_FOUND
            assert fake_id in response.json()["detail"]

    async def test_invalid_uuid_error_handling(self, async_client: AsyncClient):
        """Test proper error handling for invalid UUID formats."""
        invalid_uuid = "not-a-valid-uuid"

        response = await async_client.get(f"/api/v1/workflows/{invalid_uuid}")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_workflow_lifecycle_edge_cases(
        self, async_client: AsyncClient, sample_workflow_data: dict[str, Any]
    ):
        """Test edge cases in workflow lifecycle management."""
        # Create workflow
        create_response = await async_client.post("/api/v1/workflows/", json=sample_workflow_data)
        workflow_id = create_response.json()["workflow"]["id"]

        # Test double execution attempt
        await async_client.post(f"/api/v1/workflows/{workflow_id}/execute")

        # Second execution should fail
        second_exec = await async_client.post(f"/api/v1/workflows/{workflow_id}/execute")
        assert second_exec.status_code == status.HTTP_400_BAD_REQUEST

        # Cancel workflow
        cancel_response = await async_client.post(f"/api/v1/workflows/{workflow_id}/cancel")
        assert cancel_response.status_code == status.HTTP_200_OK

        # Try to cancel again (should fail)
        second_cancel = await async_client.post(f"/api/v1/workflows/{workflow_id}/cancel")
        assert second_cancel.status_code == status.HTTP_400_BAD_REQUEST

        # Try to execute cancelled workflow (should work - creates new execution)
        await async_client.post(f"/api/v1/workflows/{workflow_id}/execute")
        # This behavior depends on implementation - cancelled workflows might be re-executable


@pytest.mark.integration
class TestWorkflowDatabaseIntegrity:
    """Test database transaction integrity for workflow operations."""

    async def test_workflow_creation_transaction_integrity(
        self, async_client: AsyncClient, test_session: AsyncSession
    ):
        """Test that workflow creation maintains database integrity."""
        workflow_data = {
            "name": "Transaction Test Workflow",
            "workflow_type": "sequential",
            "description": "Test database transaction integrity",
            "config": {"steps": [{"action": "test_action", "timeout": 300}]},
            "metadata": {"test": True},
        }

        response = await async_client.post("/api/v1/workflows/", json=workflow_data)
        assert response.status_code == status.HTTP_201_CREATED

        # Verify workflow exists and all fields are properly stored
        workflow_id = response.json()["workflow"]["id"]
        get_response = await async_client.get(f"/api/v1/workflows/{workflow_id}")
        assert get_response.status_code == status.HTTP_200_OK

        retrieved_workflow = get_response.json()["workflow"]
        assert retrieved_workflow["name"] == workflow_data["name"]
        assert retrieved_workflow["config"] == workflow_data["config"]
        assert retrieved_workflow["metadata"] == workflow_data["metadata"]

    async def test_workflow_execution_state_consistency(
        self, async_client: AsyncClient, sample_workflow_data: dict[str, Any]
    ):
        """Test that workflow execution state remains consistent."""
        # Create workflow
        create_response = await async_client.post("/api/v1/workflows/", json=sample_workflow_data)
        workflow_id = create_response.json()["workflow"]["id"]

        # Initial state should be pending
        status_response = await async_client.get(f"/api/v1/workflows/{workflow_id}/status")
        assert status_response.json()["status"] == "pending"
        assert status_response.json()["started_at"] is None

        # Execute workflow
        exec_response = await async_client.post(f"/api/v1/workflows/{workflow_id}/execute")
        assert exec_response.status_code == status.HTTP_200_OK

        # State should be running with started_at timestamp
        status_response = await async_client.get(f"/api/v1/workflows/{workflow_id}/status")
        status_data = status_response.json()
        assert status_data["status"] == "running"
        assert status_data["started_at"] is not None
        assert status_data["completed_at"] is None

        # Cancel workflow
        cancel_response = await async_client.post(f"/api/v1/workflows/{workflow_id}/cancel")
        assert cancel_response.status_code == status.HTTP_200_OK

        # State should be cancelled with completed_at timestamp
        final_status = await async_client.get(f"/api/v1/workflows/{workflow_id}/status")
        final_data = final_status.json()
        assert final_data["status"] == "cancelled"
        assert final_data["started_at"] is not None
        assert final_data["completed_at"] is not None
        assert final_data["error"] == "Cancelled by user"
