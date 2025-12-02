"""Orchestration Tools for TMWS MCP Server.

Provides phase-based workflow orchestration capabilities through MCP.
Implements the Trinitas Full Mode execution protocol.
"""

from typing import Any
from uuid import UUID

from fastmcp import FastMCP

from ..services.agent_communication_service import MessagePriority
from ..services.orchestration_engine import (
    ApprovalStatus,
    ExecutionPhase,
    OrchestrationEngine,
)
from .base_tool import BaseTool


class OrchestrationTools(BaseTool):
    """Orchestration tools for multi-agent phase-based execution."""

    def __init__(self):
        """Initialize orchestration tools with engine reference."""
        super().__init__()
        self._engine: OrchestrationEngine | None = None

    def _get_engine(self, session) -> OrchestrationEngine:
        """Get or create orchestration engine instance."""
        if self._engine is None:
            self._engine = OrchestrationEngine(session)
        return self._engine

    async def register_tools(self, mcp: FastMCP) -> None:
        """Register orchestration tools with FastMCP instance."""

        @mcp.tool()
        async def create_orchestration(
            title: str,
            content: str,
            created_by: str,
            priority: str = "medium",
            metadata: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            """Create a new orchestration task for Trinitas Full Mode execution.

            Initializes a 4-phase orchestration workflow with intelligent
            agent routing based on task content analysis.

            Phases:
            1. Strategic Planning (Hera + Athena)
            2. Implementation (Artemis + Metis)
            3. Verification (Hestia + Artemis)
            4. Documentation (Muses + Aphrodite)

            Args:
                title: Orchestration task title
                content: Detailed task description for routing
                created_by: Initiating agent ID
                priority: Task priority (low, medium, high, urgent, critical)
                metadata: Additional task context

            Returns:
                Dict containing:
                - orchestration_id: UUID of created orchestration
                - title: Task title
                - routing_result: Intelligent routing decision
                - current_phase: Initial phase (strategic_planning)
                - status: Task status

            Example:
                create_orchestration(
                    title="Implement OAuth2 Authentication",
                    content="Add OAuth2 authentication flow with Google...",
                    created_by="athena-conductor",
                    priority="high"
                )

            """
            async def _create(session, _services):
                engine = self._get_engine(session)

                # Parse priority
                msg_priority = MessagePriority.MEDIUM
                for p in MessagePriority:
                    if p.name.lower() == priority.lower():
                        msg_priority = p
                        break

                task = await engine.create_orchestration(
                    title=title,
                    content=content,
                    created_by=created_by,
                    priority=msg_priority,
                    metadata=metadata,
                )

                return {
                    "orchestration_id": str(task.id),
                    "title": task.title,
                    "routing_result": task.routing_result,
                    "current_phase": task.current_phase.value,
                    "status": task.status,
                    "created_at": task.created_at.isoformat(),
                }

            result = await self.execute_with_session(_create)
            return self.format_success(
                result.get("data", result),
                f"Orchestration '{title}' created",
            )

        @mcp.tool()
        async def start_orchestration(
            orchestration_id: str,
        ) -> dict[str, Any]:
            """Start an orchestration workflow.

            Notifies assigned agents and begins Phase 1 (Strategic Planning).
            Sends delegation requests to Hera and Athena for strategic analysis.

            Args:
                orchestration_id: UUID of the orchestration to start

            Returns:
                Dict containing:
                - orchestration_id: UUID
                - status: Updated status (in_progress)
                - current_phase: Current execution phase
                - assigned_agents: Agents notified

            Example:
                start_orchestration(orchestration_id="abc123...")

            """
            async def _start(session, _services):
                engine = self._get_engine(session)
                task = await engine.start_orchestration(UUID(orchestration_id))

                return {
                    "orchestration_id": str(task.id),
                    "status": task.status,
                    "current_phase": task.current_phase.value,
                    "routing_result": task.routing_result,
                }

            result = await self.execute_with_session(_start)
            return self.format_success(
                result.get("data", result),
                f"Orchestration {orchestration_id} started",
            )

        @mcp.tool()
        async def execute_phase(
            orchestration_id: str,
            outputs: dict[str, Any],
        ) -> dict[str, Any]:
            """Execute the current phase of an orchestration.

            Records phase outputs and prepares for approval gate.
            Each phase requires specific outputs before advancement.

            Required outputs by phase:
            - Strategic Planning: strategy_document, resource_plan
            - Implementation: code_changes, test_results
            - Verification: security_audit, performance_results
            - Documentation: documentation, changelog

            Args:
                orchestration_id: UUID of the orchestration
                outputs: Phase outputs (varies by phase)

            Returns:
                Dict containing:
                - phase: Executed phase name
                - status: Phase execution status
                - outputs: Recorded outputs
                - approval_status: Current approval gate status

            Example:
                execute_phase(
                    orchestration_id="abc123...",
                    outputs={
                        "strategy_document": "OAuth2 with PKCE flow...",
                        "resource_plan": {"agents": ["artemis", "metis"]}
                    }
                )

            """
            async def _execute(session, _services):
                engine = self._get_engine(session)
                result = await engine.execute_phase(
                    UUID(orchestration_id), outputs,
                )

                return {
                    "phase": result.phase.value,
                    "status": result.status,
                    "agents_involved": result.agents_involved,
                    "outputs": result.outputs,
                    "approval_status": result.approval_status.value,
                    "started_at": result.started_at.isoformat(),
                    "completed_at": (
                        result.completed_at.isoformat()
                        if result.completed_at else None
                    ),
                }

            result = await self.execute_with_session(_execute)
            return self.format_success(
                result.get("data", result),
                f"Phase executed for orchestration {orchestration_id}",
            )

        @mcp.tool()
        async def approve_phase(
            orchestration_id: str,
            agent_id: str,
            approved: bool,
            notes: str | None = None,
        ) -> dict[str, Any]:
            """Approve or reject the current phase and advance workflow.

            Approval gates ensure quality and consensus before phase transitions.
            Rejections require corrective action before re-execution.

            Approval requirements:
            - Strategic Planning: Hera AND Athena must agree
            - Implementation: Tests pass, no regression
            - Verification: Hestia security sign-off
            - Documentation: Completeness check

            Args:
                orchestration_id: UUID of the orchestration
                agent_id: Approving agent ID
                approved: Whether to approve the phase
                notes: Optional approval/rejection notes

            Returns:
                Dict containing:
                - orchestration_id: UUID
                - previous_phase: Phase that was approved/rejected
                - current_phase: New current phase (if approved)
                - approval_status: Result of approval
                - status: Overall orchestration status

            Example:
                approve_phase(
                    orchestration_id="abc123...",
                    agent_id="hera-strategist",
                    approved=True,
                    notes="Strategy consensus achieved with Athena"
                )

            """
            async def _approve(session, _services):
                engine = self._get_engine(session)
                task = await engine.approve_phase(
                    task_id=UUID(orchestration_id),
                    agent_id=agent_id,
                    approved=approved,
                    notes=notes,
                )

                # Get the phase result for approval info
                phase_results = list(task.phase_results.values())
                last_result = phase_results[-1] if phase_results else None

                return {
                    "orchestration_id": str(task.id),
                    "current_phase": task.current_phase.value,
                    "status": task.status,
                    "approval_status": (
                        last_result.approval_status.value
                        if last_result else ApprovalStatus.PENDING.value
                    ),
                    "approval_notes": notes,
                    "approved_by": agent_id,
                }

            result = await self.execute_with_session(_approve)
            status = "approved" if approved else "rejected"
            return self.format_success(
                result.get("data", result),
                f"Phase {status} by {agent_id}",
            )

        @mcp.tool()
        async def get_orchestration_status(
            orchestration_id: str,
        ) -> dict[str, Any]:
            """Get detailed status of an orchestration task.

            Returns comprehensive information about the orchestration including
            phase progress, agent assignments, and execution history.

            Args:
                orchestration_id: UUID of the orchestration

            Returns:
                Dict containing:
                - orchestration_id: UUID
                - title: Task title
                - status: Overall status
                - current_phase: Current execution phase
                - phase_results: Results from completed phases
                - routing_result: Original routing decision
                - created_at: Creation timestamp
                - metadata: Additional task context

            Example:
                get_orchestration_status(orchestration_id="abc123...")

            """
            async def _status(session, _services):
                engine = self._get_engine(session)
                return await engine.get_orchestration_status(UUID(orchestration_id))

            result = await self.execute_with_session(_status)
            return self.format_success(
                result.get("data", result),
                f"Status retrieved for orchestration {orchestration_id}",
            )

        @mcp.tool()
        async def list_orchestrations(
            status_filter: str | None = None,
            created_by_filter: str | None = None,
            limit: int = 50,
        ) -> dict[str, Any]:
            """List orchestration tasks with optional filtering.

            Args:
                status_filter: Filter by status (pending, in_progress, completed, failed)
                created_by_filter: Filter by creating agent ID
                limit: Maximum tasks to return

            Returns:
                Dict containing:
                - count: Number of orchestrations
                - orchestrations: List of orchestration summaries

            Example:
                list_orchestrations(status_filter="in_progress")

            """
            async def _list(session, _services):
                engine = self._get_engine(session)
                # list_orchestrations is synchronous
                orchestrations = engine.list_orchestrations(
                    status=status_filter,
                    created_by=created_by_filter,
                )

                # Apply limit
                orchestrations = orchestrations[:limit]

                return {
                    "count": len(orchestrations),
                    "orchestrations": [
                        {
                            "id": str(o.id),
                            "title": o.title,
                            "status": o.status,
                            "current_phase": o.current_phase.value,
                            "created_by": o.created_by,
                            "created_at": o.created_at.isoformat(),
                        }
                        for o in orchestrations
                    ],
                }

            result = await self.execute_with_session(_list)
            return self.format_success(
                result.get("data", result),
                f"Retrieved {result.get('data', {}).get('count', 0)} orchestrations",
            )

        @mcp.tool()
        async def get_phase_config(
            phase: str | None = None,
        ) -> dict[str, Any]:
            """Get configuration for orchestration phases.

            Returns phase definitions including assigned agents, approval gates,
            required outputs, and timeout settings.

            Args:
                phase: Specific phase to query (optional, returns all if not specified)

            Returns:
                Dict containing phase configuration(s):
                - name: Phase display name
                - description: Phase description
                - agents: Assigned agent IDs
                - approval_gate: Gate description
                - timeout_minutes: Phase timeout
                - required_outputs: Expected outputs

            Example:
                get_phase_config(phase="phase_1_strategic")
                get_phase_config()  # Returns all phases

            """
            async def _get_config(session, _services):
                engine = self._get_engine(session)

                if phase:
                    # Find matching phase
                    for ep in ExecutionPhase:
                        if ep.value == phase:
                            config = engine.PHASE_CONFIGS.get(ep)
                            if config:
                                return {
                                    "phase": config.phase.value,
                                    "name": config.name,
                                    "description": config.description,
                                    "agents": config.agents,
                                    "approval_gate": config.approval_gate,
                                    "timeout_minutes": config.timeout_minutes,
                                    "required_outputs": config.required_outputs,
                                }
                    return {"error": f"Phase not found: {phase}"}

                # Return all phases
                return {
                    "phases": [
                        {
                            "phase": config.phase.value,
                            "name": config.name,
                            "description": config.description,
                            "agents": config.agents,
                            "approval_gate": config.approval_gate,
                            "timeout_minutes": config.timeout_minutes,
                            "required_outputs": config.required_outputs,
                        }
                        for config in engine.PHASE_CONFIGS.values()
                    ],
                }

            result = await self.execute_with_session(_get_config)
            return self.format_success(
                result.get("data", result),
                "Phase configuration retrieved",
            )
