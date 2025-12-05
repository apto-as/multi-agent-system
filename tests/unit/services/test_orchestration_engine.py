"""Unit tests for OrchestrationEngine.

Tests the Trinitas Phase-Based Execution Protocol for multi-agent orchestration.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from src.services.agent_communication_service import MessagePriority
from src.services.orchestration_engine import (
    ApprovalStatus,
    ExecutionPhase,
    OrchestrationEngine,
    OrchestrationTask,
    PhaseConfig,
    PhaseResult,
)


class TestExecutionPhase:
    """Tests for ExecutionPhase enum."""

    def test_phase_values(self):
        """Test phase enum values."""
        assert ExecutionPhase.STRATEGIC_PLANNING.value == "phase_1_strategic"
        assert ExecutionPhase.IMPLEMENTATION.value == "phase_2_implementation"
        assert ExecutionPhase.VERIFICATION.value == "phase_3_verification"
        assert ExecutionPhase.DOCUMENTATION.value == "phase_4_documentation"
        assert ExecutionPhase.COMPLETED.value == "completed"
        assert ExecutionPhase.FAILED.value == "failed"


class TestApprovalStatus:
    """Tests for ApprovalStatus enum."""

    def test_approval_status_values(self):
        """Test approval status enum values."""
        assert ApprovalStatus.PENDING.value == "pending"
        assert ApprovalStatus.APPROVED.value == "approved"
        assert ApprovalStatus.REJECTED.value == "rejected"
        assert ApprovalStatus.CONDITIONAL.value == "conditional"


class TestPhaseConfig:
    """Tests for PhaseConfig dataclass."""

    def test_phase_config_creation(self):
        """Test creating a phase config."""
        config = PhaseConfig(
            phase=ExecutionPhase.STRATEGIC_PLANNING,
            name="Test Phase",
            description="Test description",
            agents=["agent1", "agent2"],
            approval_gate="test_gate",
            timeout_minutes=30,
            required_outputs=["output1"],
        )
        assert config.phase == ExecutionPhase.STRATEGIC_PLANNING
        assert config.name == "Test Phase"
        assert len(config.agents) == 2
        assert config.timeout_minutes == 30
        assert config.required_outputs == ["output1"]

    def test_phase_config_defaults(self):
        """Test phase config default values."""
        config = PhaseConfig(
            phase=ExecutionPhase.IMPLEMENTATION,
            name="Impl",
            description="Desc",
            agents=["agent1"],
            approval_gate="gate",
        )
        assert config.timeout_minutes == 60
        assert config.required_outputs == []


class TestPhaseResult:
    """Tests for PhaseResult dataclass."""

    def test_phase_result_creation(self):
        """Test creating a phase result."""
        now = datetime.now(UTC)
        result = PhaseResult(
            phase=ExecutionPhase.STRATEGIC_PLANNING,
            status="completed",
            agents_involved=["hera-strategist", "athena-conductor"],
            outputs={"strategy": "approved"},
            started_at=now,
            completed_at=now,
        )
        assert result.phase == ExecutionPhase.STRATEGIC_PLANNING
        assert result.status == "completed"
        assert len(result.agents_involved) == 2
        assert result.approval_status == ApprovalStatus.PENDING

    def test_phase_result_defaults(self):
        """Test phase result default values."""
        now = datetime.now(UTC)
        result = PhaseResult(
            phase=ExecutionPhase.IMPLEMENTATION,
            status="in_progress",
            agents_involved=["artemis-optimizer"],
            outputs={},
            started_at=now,
        )
        assert result.completed_at is None
        assert result.approval_status == ApprovalStatus.PENDING
        assert result.approval_notes is None


class TestOrchestrationTask:
    """Tests for OrchestrationTask dataclass."""

    def test_orchestration_task_creation(self):
        """Test creating an orchestration task."""
        task_id = uuid4()
        now = datetime.now(UTC)
        task = OrchestrationTask(
            id=task_id,
            title="Test Task",
            content="Test content",
            created_by="athena-conductor",
            created_at=now,
            current_phase=ExecutionPhase.STRATEGIC_PLANNING,
            phase_results={},
        )
        assert task.id == task_id
        assert task.title == "Test Task"
        assert task.current_phase == ExecutionPhase.STRATEGIC_PLANNING
        assert task.status == "pending"
        assert task.priority == MessagePriority.MEDIUM

    def test_orchestration_task_defaults(self):
        """Test orchestration task default values."""
        task = OrchestrationTask(
            id=uuid4(),
            title="Test",
            content="Content",
            created_by="agent",
            created_at=datetime.now(UTC),
            current_phase=ExecutionPhase.STRATEGIC_PLANNING,
            phase_results={},
        )
        assert task.routing_result is None
        assert task.metadata == {}
        assert task.priority == MessagePriority.MEDIUM
        assert task.status == "pending"


class TestOrchestrationEngine:
    """Tests for OrchestrationEngine."""

    @pytest.fixture
    def engine(self):
        """Create an OrchestrationEngine instance."""
        return OrchestrationEngine(session=None)

    def test_phase_configs_exist(self, engine):
        """Test that all phase configs are defined."""
        assert ExecutionPhase.STRATEGIC_PLANNING in engine.PHASE_CONFIGS
        assert ExecutionPhase.IMPLEMENTATION in engine.PHASE_CONFIGS
        assert ExecutionPhase.VERIFICATION in engine.PHASE_CONFIGS
        assert ExecutionPhase.DOCUMENTATION in engine.PHASE_CONFIGS

    def test_strategic_planning_config(self, engine):
        """Test strategic planning phase config."""
        config = engine.PHASE_CONFIGS[ExecutionPhase.STRATEGIC_PLANNING]
        assert config.name == "Strategic Planning"
        assert "hera-strategist" in config.agents
        assert "athena-conductor" in config.agents
        assert "strategy_document" in config.required_outputs
        assert "resource_plan" in config.required_outputs

    def test_implementation_config(self, engine):
        """Test implementation phase config."""
        config = engine.PHASE_CONFIGS[ExecutionPhase.IMPLEMENTATION]
        assert config.name == "Implementation"
        # Agents are dynamically assigned based on routing
        assert config.agents == []
        assert "implementation_summary" in config.required_outputs
        assert "test_results" in config.required_outputs

    def test_verification_config(self, engine):
        """Test verification phase config."""
        config = engine.PHASE_CONFIGS[ExecutionPhase.VERIFICATION]
        assert config.name == "Verification"
        assert "hestia-auditor" in config.agents
        assert "aurora-researcher" in config.agents
        assert "security_report" in config.required_outputs
        assert "verification_summary" in config.required_outputs

    def test_documentation_config(self, engine):
        """Test documentation phase config."""
        config = engine.PHASE_CONFIGS[ExecutionPhase.DOCUMENTATION]
        assert config.name == "Documentation"
        assert "muses-documenter" in config.agents
        assert "documentation" in config.required_outputs

    @pytest.mark.asyncio
    async def test_create_orchestration(self, engine):
        """Test creating an orchestration."""
        task = await engine.create_orchestration(
            title="Test Orchestration",
            content="Implement user authentication",
            created_by="athena-conductor",
        )
        assert task is not None
        assert task.title == "Test Orchestration"
        assert task.content == "Implement user authentication"
        assert task.created_by == "athena-conductor"
        assert task.current_phase == ExecutionPhase.STRATEGIC_PLANNING
        assert task.status == "pending"
        assert task.routing_result is not None

    @pytest.mark.asyncio
    async def test_create_orchestration_with_priority(self, engine):
        """Test creating an orchestration with custom priority."""
        task = await engine.create_orchestration(
            title="Urgent Task",
            content="Fix critical security vulnerability",
            created_by="hestia-auditor",
            priority=MessagePriority.CRITICAL,
        )
        assert task.priority == MessagePriority.CRITICAL

    @pytest.mark.asyncio
    async def test_create_orchestration_with_metadata(self, engine):
        """Test creating an orchestration with metadata."""
        metadata = {"project": "TMWS", "sprint": 5}
        task = await engine.create_orchestration(
            title="Sprint Task",
            content="Implement feature X",
            created_by="athena-conductor",
            metadata=metadata,
        )
        assert task.metadata == metadata

    @pytest.mark.asyncio
    async def test_start_orchestration(self, engine):
        """Test starting an orchestration."""
        task = await engine.create_orchestration(
            title="Test Task",
            content="Test content",
            created_by="athena-conductor",
        )
        started_task = await engine.start_orchestration(task.id)
        assert started_task.status == "in_progress"

    @pytest.mark.asyncio
    async def test_start_orchestration_not_found(self, engine):
        """Test starting a non-existent orchestration."""
        with pytest.raises(ValueError, match="Orchestration not found"):
            await engine.start_orchestration(uuid4())

    @pytest.mark.asyncio
    async def test_execute_phase(self, engine):
        """Test executing a phase."""
        task = await engine.create_orchestration(
            title="Test Task",
            content="Test content",
            created_by="athena-conductor",
        )
        await engine.start_orchestration(task.id)

        result = await engine.execute_phase(
            task.id,
            outputs={"strategy_document": "Test strategy", "resource_plan": {}},
        )
        assert result.phase == ExecutionPhase.STRATEGIC_PLANNING
        assert result.status == "completed"
        assert "strategy_document" in result.outputs

    @pytest.mark.asyncio
    async def test_execute_phase_not_found(self, engine):
        """Test executing a phase for non-existent orchestration."""
        with pytest.raises(ValueError, match="Orchestration not found"):
            await engine.execute_phase(uuid4(), outputs={})

    @pytest.mark.asyncio
    async def test_approve_phase(self, engine):
        """Test approving a phase."""
        task = await engine.create_orchestration(
            title="Test Task",
            content="Test content",
            created_by="athena-conductor",
        )
        await engine.start_orchestration(task.id)
        await engine.execute_phase(
            task.id,
            outputs={"strategy_document": "Test", "resource_plan": {}},
        )

        updated_task = await engine.approve_phase(
            task_id=task.id,
            agent_id="hera-strategist",
            approved=True,
            notes="Strategy approved",
        )
        assert updated_task.current_phase == ExecutionPhase.IMPLEMENTATION

    @pytest.mark.asyncio
    async def test_reject_phase(self, engine):
        """Test rejecting a phase."""
        task = await engine.create_orchestration(
            title="Test Task",
            content="Test content",
            created_by="athena-conductor",
        )
        await engine.start_orchestration(task.id)
        await engine.execute_phase(
            task.id,
            outputs={"strategy_document": "Test", "resource_plan": {}},
        )

        updated_task = await engine.approve_phase(
            task_id=task.id,
            agent_id="athena-conductor",
            approved=False,
            notes="Strategy needs revision",
        )
        # Rejection marks the task as failed (current implementation)
        assert updated_task.current_phase == ExecutionPhase.FAILED
        assert updated_task.status == "failed"
        # Check rejection status
        phase_result = updated_task.phase_results.get(ExecutionPhase.STRATEGIC_PLANNING.value)
        assert phase_result.approval_status == ApprovalStatus.REJECTED

    @pytest.mark.asyncio
    async def test_approve_phase_not_found(self, engine):
        """Test approving a phase for non-existent orchestration."""
        with pytest.raises(ValueError, match="Orchestration not found"):
            await engine.approve_phase(
                task_id=uuid4(),
                agent_id="agent",
                approved=True,
            )

    @pytest.mark.asyncio
    async def test_approve_phase_no_result(self, engine):
        """Test approving a phase with no executed result."""
        task = await engine.create_orchestration(
            title="Test Task",
            content="Test content",
            created_by="athena-conductor",
        )
        await engine.start_orchestration(task.id)

        with pytest.raises(ValueError, match="No result to approve"):
            await engine.approve_phase(
                task_id=task.id,
                agent_id="agent",
                approved=True,
            )

    @pytest.mark.asyncio
    async def test_full_workflow(self, engine):
        """Test a complete 4-phase workflow."""
        # Create orchestration
        task = await engine.create_orchestration(
            title="Full Workflow Test",
            content="Implement comprehensive feature",
            created_by="athena-conductor",
        )

        # Start
        await engine.start_orchestration(task.id)
        assert task.status == "in_progress"

        # Phase 1: Strategic Planning
        await engine.execute_phase(
            task.id,
            outputs={"strategy_document": "Strategy", "resource_plan": {}},
        )
        task = await engine.approve_phase(task.id, "hera-strategist", True, "Approved")
        assert task.current_phase == ExecutionPhase.IMPLEMENTATION

        # Phase 2: Implementation
        await engine.execute_phase(
            task.id,
            outputs={"code_changes": ["file1.py"], "test_results": {"passed": 10}},
        )
        task = await engine.approve_phase(task.id, "artemis-optimizer", True, "Tests pass")
        assert task.current_phase == ExecutionPhase.VERIFICATION

        # Phase 3: Verification
        await engine.execute_phase(
            task.id,
            outputs={
                "security_audit": {"issues": 0},
                "performance_results": {"p95": "50ms"},
            },
        )
        task = await engine.approve_phase(task.id, "hestia-auditor", True, "Security approved")
        assert task.current_phase == ExecutionPhase.DOCUMENTATION

        # Phase 4: Documentation
        await engine.execute_phase(
            task.id,
            outputs={"documentation": "API docs", "changelog": "v1.0.0"},
        )
        task = await engine.approve_phase(task.id, "muses-documenter", True, "Docs complete")
        assert task.current_phase == ExecutionPhase.COMPLETED
        assert task.status == "completed"

    @pytest.mark.asyncio
    async def test_get_orchestration_status(self, engine):
        """Test getting orchestration status."""
        task = await engine.create_orchestration(
            title="Status Test",
            content="Test content",
            created_by="athena-conductor",
        )
        status = await engine.get_orchestration_status(task.id)

        assert status["task_id"] == str(task.id)
        assert status["title"] == "Status Test"
        assert status["status"] == "pending"
        assert status["current_phase"] == ExecutionPhase.STRATEGIC_PLANNING.value
        assert "progress" in status
        assert "phases" in status

    @pytest.mark.asyncio
    async def test_get_orchestration_status_not_found(self, engine):
        """Test getting status of non-existent orchestration."""
        with pytest.raises(ValueError, match="Orchestration not found"):
            await engine.get_orchestration_status(uuid4())

    def test_list_orchestrations_empty(self, engine):
        """Test listing orchestrations when none exist."""
        orchestrations = engine.list_orchestrations()
        assert orchestrations == []

    @pytest.mark.asyncio
    async def test_list_orchestrations(self, engine):
        """Test listing orchestrations."""
        await engine.create_orchestration(title="Task 1", content="Content 1", created_by="agent1")
        await engine.create_orchestration(title="Task 2", content="Content 2", created_by="agent2")

        orchestrations = engine.list_orchestrations()
        assert len(orchestrations) == 2

    @pytest.mark.asyncio
    async def test_list_orchestrations_filter_by_status(self, engine):
        """Test listing orchestrations filtered by status."""
        task1 = await engine.create_orchestration(
            title="Task 1", content="Content 1", created_by="agent1"
        )
        await engine.create_orchestration(title="Task 2", content="Content 2", created_by="agent2")
        await engine.start_orchestration(task1.id)

        in_progress = engine.list_orchestrations(status="in_progress")
        assert len(in_progress) == 1
        assert in_progress[0].title == "Task 1"

        pending = engine.list_orchestrations(status="pending")
        assert len(pending) == 1
        assert pending[0].title == "Task 2"

    @pytest.mark.asyncio
    async def test_list_orchestrations_filter_by_creator(self, engine):
        """Test listing orchestrations filtered by creator."""
        await engine.create_orchestration(
            title="Task 1", content="Content 1", created_by="athena-conductor"
        )
        await engine.create_orchestration(
            title="Task 2", content="Content 2", created_by="hera-strategist"
        )

        athena_tasks = engine.list_orchestrations(created_by="athena-conductor")
        assert len(athena_tasks) == 1
        assert athena_tasks[0].created_by == "athena-conductor"

    @pytest.mark.asyncio
    async def test_cancel_orchestration(self, engine):
        """Test cancelling an orchestration."""
        task = await engine.create_orchestration(
            title="Cancel Test",
            content="Test content",
            created_by="athena-conductor",
        )
        await engine.start_orchestration(task.id)

        cancelled = await engine.cancel_orchestration(task.id, reason="Test cancel")
        assert cancelled.status == "cancelled"
        assert cancelled.metadata.get("cancellation_reason") == "Test cancel"

    @pytest.mark.asyncio
    async def test_cancel_orchestration_not_found(self, engine):
        """Test cancelling a non-existent orchestration."""
        with pytest.raises(ValueError, match="Orchestration not found"):
            await engine.cancel_orchestration(uuid4(), reason="Test")

    def test_get_next_phase(self, engine):
        """Test phase transition logic."""
        assert engine._get_next_phase(ExecutionPhase.STRATEGIC_PLANNING) == (
            ExecutionPhase.IMPLEMENTATION
        )
        assert engine._get_next_phase(ExecutionPhase.IMPLEMENTATION) == (
            ExecutionPhase.VERIFICATION
        )
        assert engine._get_next_phase(ExecutionPhase.VERIFICATION) == (ExecutionPhase.DOCUMENTATION)
        assert engine._get_next_phase(ExecutionPhase.DOCUMENTATION) == (ExecutionPhase.COMPLETED)
        assert engine._get_next_phase(ExecutionPhase.COMPLETED) == (ExecutionPhase.COMPLETED)


class TestOrchestrationEngineIntegration:
    """Integration tests for orchestration with routing."""

    @pytest.fixture
    def engine(self):
        """Create an OrchestrationEngine instance."""
        return OrchestrationEngine(session=None)

    @pytest.mark.asyncio
    async def test_routing_integration(self, engine):
        """Test that orchestration integrates with task routing."""
        task = await engine.create_orchestration(
            title="Performance Optimization",
            content="Optimize database query performance and reduce latency",
            created_by="athena-conductor",
        )

        # Check routing result was populated (trinitas_full mode)
        assert task.routing_result is not None
        assert "routing" in task.routing_result
        assert "primary" in task.routing_result["routing"]
        # Performance tasks should route to Artemis
        assert task.routing_result["routing"]["primary"] == "artemis-optimizer"

    @pytest.mark.asyncio
    async def test_security_task_routing(self, engine):
        """Test routing for security-related tasks."""
        task = await engine.create_orchestration(
            title="Security Audit",
            content="Perform security audit and vulnerability assessment",
            created_by="athena-conductor",
        )

        assert task.routing_result is not None
        # Security tasks should route to Hestia
        assert task.routing_result["routing"]["primary"] == "hestia-auditor"

    @pytest.mark.asyncio
    async def test_documentation_task_routing(self, engine):
        """Test routing for documentation tasks."""
        task = await engine.create_orchestration(
            title="API Documentation",
            content="Create comprehensive API documentation and guides",
            created_by="athena-conductor",
        )

        assert task.routing_result is not None
        # Muses pattern is detected even if another agent is primary
        assert "detected_patterns" in task.routing_result
        assert "muses-documenter" in task.routing_result["detected_patterns"]
