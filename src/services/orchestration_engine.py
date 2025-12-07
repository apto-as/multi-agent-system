"""Trinitas Orchestration Engine for TMWS.

Implements the Phase-Based Execution Protocol for multi-agent task orchestration.
Coordinates 9 Trinitas agents through 4-phase execution with approval gates.

This engine provides:
- Phase-based workflow execution (Strategy → Implementation → Verification → Documentation)
- Approval gates between phases
- Agent assignment based on routing
- Progress tracking and status reporting
- Integration with communication service for agent coordination
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from .agent_communication_service import (
    AgentCommunicationService,
    MessagePriority,
)
from .task_routing_service import AgentTier, TaskRoutingService

logger = logging.getLogger(__name__)


class ExecutionPhase(Enum):
    """Execution phases in Trinitas Full Mode."""

    STRATEGIC_PLANNING = "phase_1_strategic"
    IMPLEMENTATION = "phase_2_implementation"
    VERIFICATION = "phase_3_verification"
    DOCUMENTATION = "phase_4_documentation"
    COMPLETED = "completed"
    FAILED = "failed"


class ApprovalStatus(Enum):
    """Status of phase approval gates."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CONDITIONAL = "conditional"


@dataclass
class PhaseConfig:
    """Configuration for an execution phase."""

    phase: ExecutionPhase
    name: str
    description: str
    agents: list[str]
    approval_gate: str
    timeout_minutes: int = 60
    required_outputs: list[str] = field(default_factory=list)


@dataclass
class PhaseResult:
    """Result of a phase execution."""

    phase: ExecutionPhase
    status: str  # completed, failed, timeout
    agents_involved: list[str]
    outputs: dict[str, Any]
    started_at: datetime
    completed_at: datetime | None = None
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approval_notes: str | None = None


@dataclass
class OrchestrationTask:
    """A task being orchestrated through the Trinitas protocol."""

    id: UUID
    title: str
    content: str
    created_by: str
    created_at: datetime
    current_phase: ExecutionPhase
    phase_results: dict[str, PhaseResult]
    routing_result: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    priority: MessagePriority = MessagePriority.MEDIUM
    status: str = "pending"  # pending, in_progress, completed, failed


class OrchestrationEngine:
    """Engine for orchestrating multi-agent task execution.

    Implements the Trinitas Phase-Based Execution Protocol:

    Phase 1: Strategic Planning
        - Hera: Strategic design & architecture
        - Athena: Resource coordination & harmony
        - Approval Gate: Both agents agree

    Phase 2: Implementation
        - Primary agent from routing (e.g., Artemis)
        - Support agents as needed
        - Approval Gate: Tests pass, zero regression

    Phase 3: Verification
        - Hestia: Security audit
        - Aurora: Context verification
        - Approval Gate: Security sign-off

    Phase 4: Documentation
        - Muses: Documentation creation
        - Aphrodite: Visual guides (optional)
        - Final Gate: Completion confirmed
    """

    # Default phase configurations
    PHASE_CONFIGS = {
        ExecutionPhase.STRATEGIC_PLANNING: PhaseConfig(
            phase=ExecutionPhase.STRATEGIC_PLANNING,
            name="Strategic Planning",
            description="Strategy design and resource coordination",
            agents=["hera-strategist", "athena-conductor"],
            approval_gate="strategic_consensus",
            timeout_minutes=60,
            required_outputs=["strategy_document", "resource_plan"],
        ),
        ExecutionPhase.IMPLEMENTATION: PhaseConfig(
            phase=ExecutionPhase.IMPLEMENTATION,
            name="Implementation",
            description="Technical implementation and testing",
            agents=[],  # Dynamically assigned based on routing
            approval_gate="tests_pass",
            timeout_minutes=120,
            required_outputs=["implementation_summary", "test_results"],
        ),
        ExecutionPhase.VERIFICATION: PhaseConfig(
            phase=ExecutionPhase.VERIFICATION,
            name="Verification",
            description="Security audit and impact verification",
            agents=["hestia-auditor", "aurora-researcher"],
            approval_gate="security_approval",
            timeout_minutes=60,
            required_outputs=["security_report", "verification_summary"],
        ),
        ExecutionPhase.DOCUMENTATION: PhaseConfig(
            phase=ExecutionPhase.DOCUMENTATION,
            name="Documentation",
            description="Documentation and visual guides",
            agents=["muses-documenter", "aphrodite-designer"],
            approval_gate="completion_confirmed",
            timeout_minutes=30,
            required_outputs=["documentation"],
        ),
    }

    def __init__(self, session: AsyncSession | None = None):
        """Initialize orchestration engine.

        Args:
            session: Optional async database session.
        """
        self.session = session
        self._routing_service = TaskRoutingService(session)
        self._comm_service = AgentCommunicationService(session)

        # Active orchestrations
        self._tasks: dict[UUID, OrchestrationTask] = {}

        # Phase execution locks (prevent concurrent phase execution)
        self._phase_locks: dict[UUID, asyncio.Lock] = {}

    async def create_orchestration(
        self,
        title: str,
        content: str,
        created_by: str,
        priority: MessagePriority = MessagePriority.MEDIUM,
        metadata: dict[str, Any] | None = None,
    ) -> OrchestrationTask:
        """Create a new orchestration task.

        Routes the task to optimal agents and prepares for phase execution.

        Args:
            title: Task title
            content: Task description
            created_by: Creating agent ID
            priority: Task priority
            metadata: Additional metadata

        Returns:
            The created OrchestrationTask
        """
        # Route the task to determine optimal agents
        routing_result = self._routing_service.get_trinitas_full_mode_routing(content)

        task = OrchestrationTask(
            id=uuid4(),
            title=title,
            content=content,
            created_by=created_by,
            created_at=datetime.now(UTC),
            current_phase=ExecutionPhase.STRATEGIC_PLANNING,
            phase_results={},
            routing_result=routing_result,
            metadata=metadata or {},
            priority=priority,
        )

        self._tasks[task.id] = task
        self._phase_locks[task.id] = asyncio.Lock()

        logger.info(
            f"Orchestration {task.id} created: '{title}' "
            f"(primary={routing_result['routing']['primary']})",
        )

        return task

    async def start_orchestration(self, task_id: UUID) -> OrchestrationTask:
        """Start executing an orchestration task.

        Begins Phase 1 (Strategic Planning) and coordinates through all phases.

        Args:
            task_id: ID of the orchestration to start

        Returns:
            Updated OrchestrationTask

        Raises:
            ValueError: If task not found or already started
        """
        task = self._tasks.get(task_id)
        if not task:
            raise ValueError(f"Orchestration not found: {task_id}")

        if task.status != "pending":
            raise ValueError(f"Orchestration already started: {task_id}")

        task.status = "in_progress"

        # Notify strategic agents to begin Phase 1
        await self._notify_phase_start(task, ExecutionPhase.STRATEGIC_PLANNING)

        logger.info(f"Orchestration {task_id} started, entering Phase 1")

        return task

    async def execute_phase(
        self,
        task_id: UUID,
        outputs: dict[str, Any] | None = None,
    ) -> PhaseResult:
        """Execute the current phase of an orchestration.

        Args:
            task_id: ID of the orchestration
            outputs: Phase execution outputs

        Returns:
            PhaseResult for the executed phase

        Raises:
            ValueError: If task not found or invalid state
        """
        task = self._tasks.get(task_id)
        if not task:
            raise ValueError(f"Orchestration not found: {task_id}")

        if task.current_phase in [ExecutionPhase.COMPLETED, ExecutionPhase.FAILED]:
            raise ValueError(f"Orchestration already finished: {task_id}")

        async with self._phase_locks[task_id]:
            phase_config = self.PHASE_CONFIGS.get(task.current_phase)
            if not phase_config:
                raise ValueError(f"Invalid phase: {task.current_phase}")

            # Get agents for this phase
            agents = self._get_phase_agents(task, task.current_phase)

            # Create phase result
            result = PhaseResult(
                phase=task.current_phase,
                status="completed",
                agents_involved=agents,
                outputs=outputs or {},
                started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
            )

            # Store result
            task.phase_results[task.current_phase.value] = result

            logger.info(
                f"Orchestration {task_id}: Phase {task.current_phase.value} executed by {agents}",
            )

            return result

    async def approve_phase(
        self,
        task_id: UUID,
        agent_id: str,  # noqa: ARG002 - Will be used for audit logging
        approved: bool,
        notes: str | None = None,
    ) -> OrchestrationTask:
        """Approve or reject the current phase and advance if approved.

        Args:
            task_id: ID of the orchestration
            agent_id: Approving agent ID
            approved: Whether to approve
            notes: Optional approval notes

        Returns:
            Updated OrchestrationTask

        Raises:
            ValueError: If task not found or no result to approve
        """
        task = self._tasks.get(task_id)
        if not task:
            raise ValueError(f"Orchestration not found: {task_id}")

        phase_result = task.phase_results.get(task.current_phase.value)
        if not phase_result:
            raise ValueError(f"No result to approve for phase: {task.current_phase}")

        # Update approval status
        phase_result.approval_status = (
            ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
        )
        phase_result.approval_notes = notes

        if approved:
            # Advance to next phase
            next_phase = self._get_next_phase(task.current_phase)
            task.current_phase = next_phase

            if next_phase == ExecutionPhase.COMPLETED:
                task.status = "completed"
                logger.info(f"Orchestration {task_id} completed successfully")
            else:
                # Notify agents for next phase
                await self._notify_phase_start(task, next_phase)
                logger.info(
                    f"Orchestration {task_id}: Advanced to {next_phase.value}",
                )
        else:
            # Mark as failed if rejected
            task.status = "failed"
            task.current_phase = ExecutionPhase.FAILED
            logger.warning(
                f"Orchestration {task_id} failed at phase {phase_result.phase.value}",
            )

        return task

    async def get_orchestration_status(self, task_id: UUID) -> dict[str, Any]:
        """Get detailed status of an orchestration.

        Args:
            task_id: ID of the orchestration

        Returns:
            Dict with comprehensive status information
        """
        task = self._tasks.get(task_id)
        if not task:
            raise ValueError(f"Orchestration not found: {task_id}")

        # Calculate progress
        completed_phases = len(
            [r for r in task.phase_results.values() if r.approval_status == ApprovalStatus.APPROVED]
        )
        total_phases = 4
        progress = completed_phases / total_phases

        return {
            "task_id": str(task.id),
            "title": task.title,
            "status": task.status,
            "current_phase": task.current_phase.value,
            "progress": progress,
            "progress_percent": f"{progress * 100:.0f}%",
            "created_at": task.created_at.isoformat(),
            "created_by": task.created_by,
            "routing": task.routing_result,
            "phases": {
                phase.value: {
                    "name": self.PHASE_CONFIGS[phase].name,
                    "agents": self._get_phase_agents(task, phase),
                    "status": (
                        task.phase_results[phase.value].status
                        if phase.value in task.phase_results
                        else "pending"
                    ),
                    "approval": (
                        task.phase_results[phase.value].approval_status.value
                        if phase.value in task.phase_results
                        else "pending"
                    ),
                }
                for phase in [
                    ExecutionPhase.STRATEGIC_PLANNING,
                    ExecutionPhase.IMPLEMENTATION,
                    ExecutionPhase.VERIFICATION,
                    ExecutionPhase.DOCUMENTATION,
                ]
            },
        }

    def get_orchestration(self, task_id: UUID) -> OrchestrationTask | None:
        """Get an orchestration by ID."""
        return self._tasks.get(task_id)

    def list_orchestrations(
        self,
        status: str | None = None,
        created_by: str | None = None,
    ) -> list[OrchestrationTask]:
        """List orchestrations with optional filters.

        Args:
            status: Filter by status
            created_by: Filter by creator

        Returns:
            List of matching orchestrations
        """
        tasks = list(self._tasks.values())

        if status:
            tasks = [t for t in tasks if t.status == status]
        if created_by:
            tasks = [t for t in tasks if t.created_by == created_by]

        return tasks

    async def cancel_orchestration(
        self,
        task_id: UUID,
        reason: str | None = None,
    ) -> OrchestrationTask:
        """Cancel an orchestration.

        Args:
            task_id: ID of the orchestration
            reason: Optional cancellation reason

        Returns:
            Updated OrchestrationTask
        """
        task = self._tasks.get(task_id)
        if not task:
            raise ValueError(f"Orchestration not found: {task_id}")

        task.status = "cancelled"
        task.metadata["cancellation_reason"] = reason

        # Notify all involved agents
        involved_agents = set()
        for result in task.phase_results.values():
            involved_agents.update(result.agents_involved)

        if involved_agents:
            await self._comm_service.send_message(
                from_agent="eris-coordinator",
                to_agents=list(involved_agents),
                content=(
                    f"Orchestration '{task.title}' has been cancelled. "
                    f"Reason: {reason or 'Not specified'}"
                ),
                priority=MessagePriority.HIGH,
            )

        logger.info(f"Orchestration {task_id} cancelled: {reason}")

        return task

    def _get_phase_agents(
        self,
        task: OrchestrationTask,
        phase: ExecutionPhase,
    ) -> list[str]:
        """Get agents assigned to a phase.

        For implementation phase, uses routing result.
        For other phases, uses default configuration.

        Args:
            task: The orchestration task
            phase: The execution phase

        Returns:
            List of agent IDs for the phase
        """
        if phase == ExecutionPhase.IMPLEMENTATION and task.routing_result:
            # Use routed agents for implementation
            routing = task.routing_result.get("routing", {})
            primary = routing.get("primary", "artemis-optimizer")
            support = routing.get("support", [])
            return [primary] + support[:1]  # Primary + 1 support

        config = self.PHASE_CONFIGS.get(phase)
        return config.agents if config else []

    def _get_next_phase(self, current: ExecutionPhase) -> ExecutionPhase:
        """Get the next phase after the current one.

        Args:
            current: Current execution phase

        Returns:
            Next execution phase
        """
        phase_order = [
            ExecutionPhase.STRATEGIC_PLANNING,
            ExecutionPhase.IMPLEMENTATION,
            ExecutionPhase.VERIFICATION,
            ExecutionPhase.DOCUMENTATION,
            ExecutionPhase.COMPLETED,
        ]

        try:
            current_idx = phase_order.index(current)
            return phase_order[current_idx + 1]
        except (ValueError, IndexError):
            return ExecutionPhase.COMPLETED

    async def _notify_phase_start(
        self,
        task: OrchestrationTask,
        phase: ExecutionPhase,
    ) -> None:
        """Notify agents that a phase is starting.

        Args:
            task: The orchestration task
            phase: The phase being started
        """
        config = self.PHASE_CONFIGS.get(phase)
        if not config:
            return

        agents = self._get_phase_agents(task, phase)
        if not agents:
            return

        # Build context for handoff
        context = {
            "orchestration_id": str(task.id),
            "task_title": task.title,
            "task_content": task.content,
            "phase": phase.value,
            "phase_name": config.name,
            "description": config.description,
            "required_outputs": config.required_outputs,
            "approval_gate": config.approval_gate,
            "previous_phases": {p: task.phase_results[p].outputs for p in task.phase_results},
        }

        # Send phase start notification
        await self._comm_service.send_message(
            from_agent="eris-coordinator",
            to_agents=agents,
            content=f"Phase '{config.name}' starting for orchestration: {task.title}",
            priority=task.priority,
            metadata=context,
        )

        logger.info(
            f"Notified {agents} about phase {phase.value} start for {task.id}",
        )

    async def get_phase_recommendations(
        self,
        task_id: UUID,
    ) -> dict[str, Any]:
        """Get recommendations for the current phase.

        Provides guidance for agents on what to do in the current phase.

        Args:
            task_id: ID of the orchestration

        Returns:
            Dict with phase-specific recommendations
        """
        task = self._tasks.get(task_id)
        if not task:
            raise ValueError(f"Orchestration not found: {task_id}")

        config = self.PHASE_CONFIGS.get(task.current_phase)
        if not config:
            return {"error": "No recommendations for current phase"}

        agents = self._get_phase_agents(task, task.current_phase)

        recommendations = {
            "phase": task.current_phase.value,
            "phase_name": config.name,
            "assigned_agents": agents,
            "required_outputs": config.required_outputs,
            "approval_gate": config.approval_gate,
            "timeout_minutes": config.timeout_minutes,
            "guidelines": [],
        }

        # Phase-specific guidelines
        if task.current_phase == ExecutionPhase.STRATEGIC_PLANNING:
            recommendations["guidelines"] = [
                "Hera: Define strategic approach and architecture",
                "Athena: Coordinate resources and ensure harmony",
                "Both agents must agree before proceeding",
                "Output: strategy_document and resource_plan",
            ]
        elif task.current_phase == ExecutionPhase.IMPLEMENTATION:
            recommendations["guidelines"] = [
                f"Primary implementer: {agents[0] if agents else 'TBD'}",
                "Follow the strategy defined in Phase 1",
                "Write tests alongside implementation",
                "Output: implementation_summary and test_results",
            ]
        elif task.current_phase == ExecutionPhase.VERIFICATION:
            recommendations["guidelines"] = [
                "Hestia: Conduct security audit",
                "Aurora: Verify context and impact",
                "Check for regressions",
                "Output: security_report and verification_summary",
            ]
        elif task.current_phase == ExecutionPhase.DOCUMENTATION:
            recommendations["guidelines"] = [
                "Muses: Create comprehensive documentation",
                "Aphrodite: Add visual guides if needed",
                "Output: documentation",
            ]

        return recommendations

    def get_agent_tier_for_phase(self, phase: ExecutionPhase) -> AgentTier:
        """Get the primary agent tier for a phase.

        Args:
            phase: The execution phase

        Returns:
            The primary AgentTier for the phase
        """
        tier_mapping = {
            ExecutionPhase.STRATEGIC_PLANNING: AgentTier.STRATEGIC,
            ExecutionPhase.IMPLEMENTATION: AgentTier.SPECIALIST,
            ExecutionPhase.VERIFICATION: AgentTier.SPECIALIST,
            ExecutionPhase.DOCUMENTATION: AgentTier.SPECIALIST,
        }
        return tier_mapping.get(phase, AgentTier.SUPPORT)
