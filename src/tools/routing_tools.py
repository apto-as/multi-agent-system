"""Task Routing Tools for TMWS MCP Server.

Provides intelligent task-to-agent routing capabilities through MCP.
Part of the Trinitas multi-agent orchestration system.
"""

import logging
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from ..services.task_routing_service import TaskRoutingService
from .base_tool import BaseTool

logger = logging.getLogger(__name__)


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

        @mcp.tool()
        async def invoke_persona(
            persona_id: str,
            task_description: str,
            include_system_prompt: bool = True,
        ) -> dict[str, Any]:
            """Invoke a Trinitas persona for task execution.

            Retrieves the persona's system prompt, capabilities, and context
            to enable dynamic persona invocation. The returned system_prompt
            should be used to guide the AI's behavior for the task.

            Args:
                persona_id: The persona identifier (e.g., "athena-conductor", "artemis-optimizer")
                task_description: Description of the task to execute
                include_system_prompt: Whether to include full system prompt content

            Returns:
                Dict containing:
                - persona_id: The invoked persona identifier
                - display_name: Human-readable persona name
                - system_prompt: Full system prompt content (if include_system_prompt=True)
                - capabilities: List of persona capabilities
                - tier: Agent tier (STRATEGIC, SPECIALIST, SUPPORT)
                - collaboration: Recommended collaborators for this persona
                - task_context: Context-specific guidance for the task
                - invocation_instructions: How to embody this persona

            Example:
                invoke_persona("athena-conductor", "Coordinate system architecture review")
                -> {
                    persona_id: "athena-conductor",
                    display_name: "Athena - Harmonious Conductor",
                    system_prompt: "# 🏛️ Harmonious Conductor...",
                    capabilities: ["orchestration", "coordination", "harmony"],
                    invocation_instructions: "Embody Athena's warm, inclusive approach..."
                }

            """
            # Valid persona IDs
            valid_personas = {
                "athena-conductor": {
                    "display_name": "Athena - Harmonious Conductor 🏛️",
                    "tier": "STRATEGIC",
                    "capabilities": ["orchestration", "workflow_automation", "resource_optimization", "parallel_execution"],
                    "collaboration": {
                        "primary_partners": ["hera-strategist", "eris-coordinator"],
                        "support_from": ["aurora-researcher", "muses-documenter"],
                        "delegates_to": ["artemis-optimizer", "metis-developer"],
                    },
                    "invocation_style": "warm, inclusive, empathetic, consensus-seeking",
                },
                "artemis-optimizer": {
                    "display_name": "Artemis - Technical Perfectionist 🏹",
                    "tier": "SPECIALIST",
                    "capabilities": ["performance_optimization", "code_quality", "algorithm_design", "efficiency_improvement"],
                    "collaboration": {
                        "primary_partners": ["metis-developer", "hestia-auditor"],
                        "support_from": ["aurora-researcher"],
                        "reports_to": ["athena-conductor"],
                    },
                    "invocation_style": "precise, analytical, performance-focused, demanding excellence",
                },
                "hestia-auditor": {
                    "display_name": "Hestia - Security Guardian 🔥",
                    "tier": "SPECIALIST",
                    "capabilities": ["security_analysis", "vulnerability_assessment", "risk_management", "threat_modeling"],
                    "collaboration": {
                        "primary_partners": ["aurora-researcher", "artemis-optimizer"],
                        "support_from": ["muses-documenter"],
                        "reports_to": ["athena-conductor"],
                    },
                    "invocation_style": "vigilant, thorough, risk-aware, worst-case thinking",
                },
                "eris-coordinator": {
                    "display_name": "Eris - Tactical Coordinator ⚔️",
                    "tier": "SPECIALIST",
                    "capabilities": ["tactical_planning", "conflict_resolution", "workflow_adjustment", "balance_management"],
                    "collaboration": {
                        "primary_partners": ["athena-conductor", "hera-strategist"],
                        "support_from": ["all_agents"],
                        "reports_to": ["athena-conductor"],
                    },
                    "invocation_style": "tactical, adaptive, conflict-resolving, balance-focused",
                },
                "hera-strategist": {
                    "display_name": "Hera - Strategic Commander 🎭",
                    "tier": "STRATEGIC",
                    "capabilities": ["strategic_planning", "architecture_design", "long_term_vision", "stakeholder_management"],
                    "collaboration": {
                        "primary_partners": ["athena-conductor"],
                        "support_from": ["aurora-researcher", "muses-documenter"],
                        "delegates_to": ["artemis-optimizer", "eris-coordinator"],
                    },
                    "invocation_style": "strategic, visionary, authoritative, decisive",
                },
                "muses-documenter": {
                    "display_name": "Muses - Knowledge Architect 📚",
                    "tier": "SPECIALIST",
                    "capabilities": ["documentation", "knowledge_management", "specification_writing", "api_documentation"],
                    "collaboration": {
                        "primary_partners": ["aurora-researcher"],
                        "support_from": ["all_agents"],
                        "reports_to": ["athena-conductor"],
                    },
                    "invocation_style": "thorough, structured, clear, knowledge-preserving",
                },
                "aphrodite-designer": {
                    "display_name": "Aphrodite - UI/UX Designer 🌸",
                    "tier": "SUPPORT",
                    "capabilities": ["ui_design", "ux_research", "accessibility", "visual_design"],
                    "collaboration": {
                        "primary_partners": ["aurora-researcher", "metis-developer"],
                        "support_from": ["muses-documenter"],
                        "reports_to": ["athena-conductor"],
                    },
                    "invocation_style": "aesthetic, user-centered, accessibility-focused, beautiful",
                },
                "metis-developer": {
                    "display_name": "Metis - Development Assistant 🔧",
                    "tier": "SUPPORT",
                    "capabilities": ["code_implementation", "testing", "debugging", "refactoring"],
                    "collaboration": {
                        "primary_partners": ["artemis-optimizer", "hestia-auditor"],
                        "support_from": ["aurora-researcher"],
                        "reports_to": ["artemis-optimizer"],
                    },
                    "invocation_style": "practical, hands-on, test-driven, detail-oriented",
                },
                "aurora-researcher": {
                    "display_name": "Aurora - Research Assistant 🌅",
                    "tier": "SUPPORT",
                    "capabilities": ["memory_search", "context_retrieval", "knowledge_synthesis", "pattern_discovery"],
                    "collaboration": {
                        "primary_partners": ["all_agents"],
                        "support_from": ["muses-documenter"],
                        "reports_to": ["athena-conductor"],
                    },
                    "invocation_style": "curious, thorough, context-aware, knowledge-seeking",
                },
            }

            # Normalize persona_id
            persona_id = persona_id.lower().strip()
            if not persona_id.endswith(("-conductor", "-optimizer", "-auditor", "-coordinator", "-strategist", "-documenter", "-designer", "-developer", "-researcher")):
                # Try to match short name
                short_to_full = {
                    "athena": "athena-conductor",
                    "artemis": "artemis-optimizer",
                    "hestia": "hestia-auditor",
                    "eris": "eris-coordinator",
                    "hera": "hera-strategist",
                    "muses": "muses-documenter",
                    "aphrodite": "aphrodite-designer",
                    "metis": "metis-developer",
                    "aurora": "aurora-researcher",
                }
                persona_id = short_to_full.get(persona_id, persona_id)

            if persona_id not in valid_personas:
                return self.format_error(
                    f"Unknown persona: {persona_id}. Valid personas: {list(valid_personas.keys())}",
                    error_type="invalid_persona",
                )

            persona_info = valid_personas[persona_id]

            # Try to load system prompt from file
            system_prompt = None
            if include_system_prompt:
                # Check multiple possible locations
                possible_paths = [
                    Path.home() / ".claude" / "agents" / f"{persona_id}.md",
                    Path.home() / ".config" / "opencode" / "agent" / f"{persona_id}.md",
                    Path(__file__).parent.parent / "trinitas" / "agents" / f"{persona_id}.md",
                ]

                for path in possible_paths:
                    if path.exists():
                        try:
                            system_prompt = path.read_text(encoding="utf-8")
                            logger.debug(f"Loaded system prompt from {path}")
                            break
                        except Exception as e:
                            logger.warning(f"Failed to read {path}: {e}")

                if not system_prompt:
                    # Generate minimal system prompt
                    system_prompt = f"""# {persona_info['display_name']}

## Core Identity
You are {persona_id.split('-')[0].capitalize()}, embodying the {persona_info['invocation_style']} approach.

## Capabilities
{', '.join(persona_info['capabilities'])}

## Collaboration Style
- Primary Partners: {', '.join(persona_info['collaboration'].get('primary_partners', []))}
- Tier: {persona_info['tier']}

## Task Context
{task_description}
"""

            # Generate task-specific context
            task_context = f"""
## Current Task
{task_description}

## Execution Guidance
As {persona_info['display_name']}, approach this task with your characteristic {persona_info['invocation_style']} style.

Focus on your core capabilities:
{chr(10).join(f'- {cap}' for cap in persona_info['capabilities'])}

Consider collaborating with your primary partners if needed:
{chr(10).join(f'- {p}' for p in persona_info['collaboration'].get('primary_partners', []))}
"""

            # Generate invocation instructions
            invocation_instructions = f"""
To embody {persona_id}:

1. **Adopt the persona's voice**: Be {persona_info['invocation_style']}
2. **Leverage capabilities**: Your strengths are {', '.join(persona_info['capabilities'][:3])}
3. **Collaborate appropriately**: Work with {', '.join(persona_info['collaboration'].get('primary_partners', [])[:2])} when needed
4. **Report to hierarchy**: Your tier is {persona_info['tier']}

Begin your response by acknowledging your role and approach.
"""

            return self.format_success(
                {
                    "persona_id": persona_id,
                    "display_name": persona_info["display_name"],
                    "system_prompt": system_prompt,
                    "capabilities": persona_info["capabilities"],
                    "tier": persona_info["tier"],
                    "collaboration": persona_info["collaboration"],
                    "task_context": task_context,
                    "invocation_instructions": invocation_instructions,
                    "invocation_style": persona_info["invocation_style"],
                },
                f"Persona {persona_id} invoked successfully",
            )

        @mcp.tool()
        async def list_available_personas() -> dict[str, Any]:
            """List all available Trinitas personas with their details.

            Returns a comprehensive list of all 9 Trinitas personas
            organized by tier, including their capabilities and collaboration patterns.

            Returns:
                Dict containing:
                - personas: List of all personas with details
                - by_tier: Personas grouped by tier
                - count: Total number of personas

            Example:
                list_available_personas()
                -> {
                    personas: [...],
                    by_tier: {
                        STRATEGIC: ["athena-conductor", "hera-strategist"],
                        SPECIALIST: ["artemis-optimizer", "hestia-auditor", "eris-coordinator", "muses-documenter"],
                        SUPPORT: ["aphrodite-designer", "metis-developer", "aurora-researcher"]
                    }
                }

            """
            personas = [
                {
                    "persona_id": "athena-conductor",
                    "display_name": "Athena - Harmonious Conductor 🏛️",
                    "tier": "STRATEGIC",
                    "primary_capabilities": ["orchestration", "coordination"],
                    "trigger_keywords": ["orchestrate", "coordinate", "harmonize", "integrate"],
                },
                {
                    "persona_id": "hera-strategist",
                    "display_name": "Hera - Strategic Commander 🎭",
                    "tier": "STRATEGIC",
                    "primary_capabilities": ["strategic_planning", "architecture"],
                    "trigger_keywords": ["strategy", "planning", "architecture", "vision"],
                },
                {
                    "persona_id": "artemis-optimizer",
                    "display_name": "Artemis - Technical Perfectionist 🏹",
                    "tier": "SPECIALIST",
                    "primary_capabilities": ["optimization", "performance"],
                    "trigger_keywords": ["optimize", "performance", "quality", "efficiency"],
                },
                {
                    "persona_id": "hestia-auditor",
                    "display_name": "Hestia - Security Guardian 🔥",
                    "tier": "SPECIALIST",
                    "primary_capabilities": ["security", "audit"],
                    "trigger_keywords": ["security", "audit", "vulnerability", "risk"],
                },
                {
                    "persona_id": "eris-coordinator",
                    "display_name": "Eris - Tactical Coordinator ⚔️",
                    "tier": "SPECIALIST",
                    "primary_capabilities": ["coordination", "conflict_resolution"],
                    "trigger_keywords": ["coordinate", "tactical", "conflict", "balance"],
                },
                {
                    "persona_id": "muses-documenter",
                    "display_name": "Muses - Knowledge Architect 📚",
                    "tier": "SPECIALIST",
                    "primary_capabilities": ["documentation", "knowledge"],
                    "trigger_keywords": ["document", "knowledge", "record", "guide"],
                },
                {
                    "persona_id": "aphrodite-designer",
                    "display_name": "Aphrodite - UI/UX Designer 🌸",
                    "tier": "SUPPORT",
                    "primary_capabilities": ["design", "ux"],
                    "trigger_keywords": ["design", "ui", "ux", "interface", "visual"],
                },
                {
                    "persona_id": "metis-developer",
                    "display_name": "Metis - Development Assistant 🔧",
                    "tier": "SUPPORT",
                    "primary_capabilities": ["implementation", "testing"],
                    "trigger_keywords": ["implement", "code", "develop", "test", "debug"],
                },
                {
                    "persona_id": "aurora-researcher",
                    "display_name": "Aurora - Research Assistant 🌅",
                    "tier": "SUPPORT",
                    "primary_capabilities": ["research", "context"],
                    "trigger_keywords": ["search", "research", "find", "context", "retrieve"],
                },
            ]

            by_tier = {
                "STRATEGIC": [p["persona_id"] for p in personas if p["tier"] == "STRATEGIC"],
                "SPECIALIST": [p["persona_id"] for p in personas if p["tier"] == "SPECIALIST"],
                "SUPPORT": [p["persona_id"] for p in personas if p["tier"] == "SUPPORT"],
            }

            return self.format_success(
                {
                    "personas": personas,
                    "by_tier": by_tier,
                    "count": len(personas),
                    "usage_hint": "Use invoke_persona(persona_id, task_description) to activate a persona",
                },
                f"Found {len(personas)} available personas",
            )
