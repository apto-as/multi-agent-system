"""Task Routing Tools for TMWS MCP Server.

Provides intelligent task-to-agent routing capabilities through MCP.
Part of the Trinitas multi-agent orchestration system.
"""

from typing import Any

from fastmcp import FastMCP

from ..services.task_routing_service import TaskRoutingService
from .base_tool import BaseTool


class RoutingTools(BaseTool):
    """Task routing tools for intelligent agent selection."""

    async def register_tools(self, mcp: FastMCP) -> None:
        """Register routing tools with FastMCP instance."""

        @mcp.tool()
        async def route_task(
            task_content: str,
            namespace: str | None = None,
            use_database: bool = True,
        ) -> dict[str, Any]:
            """Route a task to the optimal Trinitas agent(s).

            Analyzes task content using pattern matching and capability scoring
            to determine the best agent assignment. Supports both pattern-only
            and database-enhanced routing.

            Args:
                task_content: Description of the task to route
                namespace: Optional namespace filter for agent selection
                use_database: Whether to use database for enhanced routing

            Returns:
                Dict containing routing result with:
                - primary_agent: Best agent for this task
                - support_agents: Recommended supporting agents
                - confidence: Routing confidence (0.0-1.0)
                - reasoning: Explanation of routing decision
                - detected_patterns: Triggered persona patterns
                - suggested_phase: Recommended execution phase

            Example:
                route_task("Optimize database query performance")
                -> {primary_agent: "artemis-optimizer", confidence: 0.85}

            """
            async def _route_task(session, _services):
                routing_service = TaskRoutingService(session)

                if use_database:
                    result = await routing_service.route_task_with_db(
                        task_content, namespace=namespace,
                    )
                else:
                    result = routing_service.route_task(task_content)

                return {
                    "primary_agent": result.primary_agent,
                    "support_agents": result.support_agents,
                    "confidence": result.confidence,
                    "reasoning": result.reasoning,
                    "detected_patterns": result.detected_patterns,
                    "suggested_phase": result.suggested_phase,
                }

            result = await self.execute_with_session(_route_task)
            if result.get("success", True):
                data = result.get("data", result)
                return self.format_success(
                    data,
                    f"Task routed to {data.get('primary_agent', 'unknown')}",
                )
            return result

        @mcp.tool()
        async def get_trinitas_execution_plan(task_content: str) -> dict[str, Any]:
            """Get a full Trinitas execution plan with phase-based workflow.

            Creates a comprehensive 4-phase execution plan following the
            Trinitas Phase-Based Execution Protocol with approval gates.

            Args:
                task_content: Description of the task to plan

            Returns:
                Dict containing:
                - mode: "trinitas_full"
                - routing: Primary and support agent assignments
                - execution_plan: 4-phase plan with agents and gates
                - coordinator: Overall coordination agent
                - detected_patterns: Triggered patterns
                - reasoning: Planning explanation

            Example:
                get_trinitas_execution_plan("Implement new authentication system")
                -> {
                    mode: "trinitas_full",
                    execution_plan: {
                        phase_1_strategic: {agents: ["hera-strategist", "athena-conductor"]},
                        phase_2_implementation: {agents: ["artemis-optimizer"]},
                        phase_3_verification: {agents: ["hestia-auditor"]},
                        phase_4_documentation: {agents: ["muses-documenter"]}
                    }
                }

            """
            routing_service = TaskRoutingService()
            result = routing_service.get_trinitas_full_mode_routing(task_content)
            return self.format_success(result, "Trinitas execution plan generated")

        @mcp.tool()
        async def detect_personas(task_content: str) -> dict[str, Any]:
            """Detect which Trinitas personas are triggered by task content.

            Uses compiled regex patterns to identify relevant agents
            based on keywords and phrases in the task description.

            Args:
                task_content: Task description to analyze

            Returns:
                Dict mapping agent IDs to confidence scores (0.0-1.0)

            Example:
                detect_personas("Review security vulnerabilities")
                -> {"hestia-auditor": 0.75, "aurora-researcher": 0.45}

            """
            routing_service = TaskRoutingService()
            matches = routing_service.detect_personas(task_content)

            # Sort by confidence for better presentation
            sorted_matches = dict(
                sorted(matches.items(), key=lambda x: x[1], reverse=True),
            )

            return self.format_success(
                {
                    "detected_personas": sorted_matches,
                    "count": len(sorted_matches),
                    "top_match": next(iter(sorted_matches), None),
                },
                f"Detected {len(sorted_matches)} personas",
            )

        @mcp.tool()
        async def get_collaboration_matrix(task_type: str | None = None) -> dict[str, Any]:
            """Get the Trinitas collaboration matrix for task types.

            Returns recommended Primary/Support/Review agent assignments
            for each task type in the system.

            Args:
                task_type: Optional specific task type to retrieve

            Returns:
                Dict containing collaboration patterns:
                - task_type: (primary_agent, [support_agents], reviewer)

            Example:
                get_collaboration_matrix("security_audit")
                -> {"primary": "hestia-auditor", "support": ["aurora-researcher"], "review": "artemis-optimizer"}

            """
            matrix = TaskRoutingService.COLLABORATION_MATRIX

            if task_type:
                if task_type not in matrix:
                    return self.format_error(
                        f"Unknown task type: {task_type}. Valid types: {list(matrix.keys())}",
                        error_type="invalid_task_type",
                    )

                primary, support, reviewer = matrix[task_type]
                return self.format_success(
                    {
                        "task_type": task_type,
                        "primary": primary,
                        "support": support,
                        "reviewer": reviewer,
                    },
                    f"Collaboration pattern for {task_type}",
                )

            # Return full matrix
            formatted_matrix = {}
            for tt, (primary, support, reviewer) in matrix.items():
                formatted_matrix[tt] = {
                    "primary": primary,
                    "support": support,
                    "reviewer": reviewer,
                }

            return self.format_success(
                {
                    "collaboration_matrix": formatted_matrix,
                    "task_types": list(matrix.keys()),
                    "count": len(matrix),
                },
                f"Retrieved {len(matrix)} collaboration patterns",
            )

        @mcp.tool()
        async def get_agent_tiers() -> dict[str, Any]:
            """Get the Trinitas agent tier classification.

            Returns the 3-tier hierarchy of agents:
            - STRATEGIC (Tier 1): System-wide coordination (Athena, Hera)
            - SPECIALIST (Tier 2): Domain expertise (Artemis, Hestia, Eris, Muses)
            - SUPPORT (Tier 3): Task execution (Aphrodite, Metis, Aurora)

            Returns:
                Dict containing tier classifications and agent details

            """
            tiers = TaskRoutingService.AGENT_TIERS
            capabilities = TaskRoutingService.AGENT_CAPABILITIES

            # Group agents by tier
            tier_groups = {
                "STRATEGIC": [],
                "SPECIALIST": [],
                "SUPPORT": [],
            }

            for agent_id, tier in tiers.items():
                tier_groups[tier.name].append({
                    "agent_id": agent_id,
                    "tier": tier.name,
                    "tier_value": tier.value,
                    "capabilities": capabilities.get(agent_id, []),
                })

            return self.format_success(
                {
                    "tiers": tier_groups,
                    "tier_priority": ["STRATEGIC", "SPECIALIST", "SUPPORT"],
                    "total_agents": len(tiers),
                },
                "Agent tier classification retrieved",
            )
