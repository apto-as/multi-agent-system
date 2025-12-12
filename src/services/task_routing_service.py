"""Task Routing Service for TMWS Orchestration Layer.

Implements intelligent task-to-agent routing based on content analysis,
persona patterns, and agent capabilities. Part of the Trinitas multi-agent
orchestration system.

This service bridges user prompts to the optimal agent(s) for handling,
using pattern matching, semantic analysis, and capability scoring.
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from .agent_service import AgentService

logger = logging.getLogger(__name__)


class AgentTier(Enum):
    """Agent tier classification for routing priority."""

    STRATEGIC = 1  # Athena, Hera - System-wide coordination
    SPECIALIST = 2  # Artemis, Hestia, Eris, Muses - Domain expertise
    SUPPORT = 3  # Aphrodite, Metis, Aurora - Task execution


@dataclass
class RoutingResult:
    """Result of task routing analysis."""

    primary_agent: str
    support_agents: list[str]
    confidence: float
    reasoning: str
    detected_patterns: list[str]
    suggested_phase: str | None = None


class TaskRoutingService:
    """Intelligent task-to-agent routing service.

    Analyzes task content to determine optimal agent assignment using:
    - Compiled regex patterns for persona detection
    - Capability matching against agent profiles
    - Multi-tier routing priority (Strategic > Specialist > Support)
    - Phase-based execution recommendations

    Attributes:
        PERSONA_PATTERNS: Pre-compiled regex patterns for each Trinitas persona.
        AGENT_CAPABILITIES: Mapping of agents to their specialized capabilities.
        COLLABORATION_MATRIX: Default collaboration patterns for task types.
    """

    # Persona trigger patterns (compiled for performance, ~0.5ms detection)
    PERSONA_PATTERNS = {
        "athena-conductor": re.compile(
            r"\b(orchestr|workflow|automat|parallel|coordin|harmoniz|integrat|system)\w*",
            re.IGNORECASE,
        ),
        "artemis-optimizer": re.compile(
            r"\b(optim|perform|quality|technical|efficien|refactor|benchmark|speed)\w*",
            re.IGNORECASE,
        ),
        "hestia-auditor": re.compile(
            r"\b(secur|audit|risk|vulnerab|threat|validat|compliance|pentest)\w*",
            re.IGNORECASE,
        ),
        "eris-coordinator": re.compile(
            r"\b(coordinat|tactical|team|collaborat|mediat|priorit|conflict|balance)\w*",
            re.IGNORECASE,
        ),
        "hera-strategist": re.compile(
            r"\b(strateg|planning|architect|vision|roadmap|command|design|blueprint)\w*",
            re.IGNORECASE,
        ),
        "muses-documenter": re.compile(
            r"\b(document|knowledge|record|guide|archive|structur|spec|api)\w*",
            re.IGNORECASE,
        ),
        "aphrodite-designer": re.compile(
            r"\b(design|ui|ux|interface|visual|layout|usability|accessib|style)\w*",
            re.IGNORECASE,
        ),
        "metis-developer": re.compile(
            r"\b(implement|code|develop|build|test|debug|fix|program|script)\w*",
            re.IGNORECASE,
        ),
        "aurora-researcher": re.compile(
            r"\b(search|find|lookup|research|context|retrieve|history|discover|analyz)\w*",
            re.IGNORECASE,
        ),
    }

    # Agent tier classification
    AGENT_TIERS = {
        "athena-conductor": AgentTier.STRATEGIC,
        "hera-strategist": AgentTier.STRATEGIC,
        "artemis-optimizer": AgentTier.SPECIALIST,
        "hestia-auditor": AgentTier.SPECIALIST,
        "eris-coordinator": AgentTier.SPECIALIST,
        "muses-documenter": AgentTier.SPECIALIST,
        "aphrodite-designer": AgentTier.SUPPORT,
        "metis-developer": AgentTier.SUPPORT,
        "aurora-researcher": AgentTier.SUPPORT,
    }

    # Agent capabilities for capability-based routing
    AGENT_CAPABILITIES = {
        "athena-conductor": [
            "orchestration",
            "workflow",
            "coordination",
            "resource_management",
            "parallel_execution",
        ],
        "hera-strategist": [
            "strategy",
            "architecture",
            "planning",
            "vision",
            "roadmap",
        ],
        "artemis-optimizer": [
            "performance",
            "optimization",
            "code_quality",
            "refactoring",
            "benchmarking",
        ],
        "hestia-auditor": [
            "security",
            "audit",
            "vulnerability",
            "risk_assessment",
            "compliance",
        ],
        "eris-coordinator": [
            "coordination",
            "conflict_resolution",
            "team_management",
            "prioritization",
        ],
        "muses-documenter": [
            "documentation",
            "knowledge_base",
            "api_docs",
            "specifications",
        ],
        "aphrodite-designer": [
            "ui_design",
            "ux_design",
            "accessibility",
            "visual_design",
        ],
        "metis-developer": [
            "implementation",
            "testing",
            "debugging",
            "development",
        ],
        "aurora-researcher": [
            "research",
            "search",
            "context_retrieval",
            "analysis",
        ],
    }

    # Default collaboration patterns (Primary, Support, Review)
    COLLABORATION_MATRIX = {
        "architecture": (
            "athena-conductor",
            ["hera-strategist", "aurora-researcher"],
            "hestia-auditor",
        ),
        "implementation": ("artemis-optimizer", ["metis-developer"], "hestia-auditor"),
        "security_audit": ("hestia-auditor", ["aurora-researcher"], "artemis-optimizer"),
        "ui_design": ("aphrodite-designer", ["aurora-researcher"], "athena-conductor"),
        "documentation": ("muses-documenter", ["aurora-researcher"], "athena-conductor"),
        "debugging": ("metis-developer", ["aurora-researcher"], "artemis-optimizer"),
        "research": ("aurora-researcher", ["muses-documenter"], "athena-conductor"),
        "coordination": ("eris-coordinator", ["athena-conductor"], "hera-strategist"),
        "strategy": ("hera-strategist", ["athena-conductor"], "eris-coordinator"),
        "optimization": ("artemis-optimizer", ["metis-developer"], "hestia-auditor"),
    }

    def __init__(self, session: AsyncSession | None = None):
        """Initialize task routing service.

        Args:
            session: Optional async database session for agent lookups.
        """
        self.session = session
        self._agent_service: AgentService | None = None

    @property
    def agent_service(self) -> AgentService | None:
        """Lazy-load agent service if session available."""
        if self._agent_service is None and self.session is not None:
            self._agent_service = AgentService(self.session)
        return self._agent_service

    @agent_service.setter
    def agent_service(self, value: AgentService | None) -> None:
        """Set agent service (primarily for testing)."""
        self._agent_service = value

    def detect_personas(self, task_content: str) -> dict[str, float]:
        """Detect triggered personas using compiled regex patterns.

        Args:
            task_content: The task description or user prompt to analyze.

        Returns:
            Dictionary mapping agent IDs to match confidence scores (0.0-1.0).
            Scores based on match count and pattern specificity.
        """
        if not task_content:
            return {}

        matches: dict[str, float] = {}
        content_lower = task_content.lower()

        for agent_id, pattern in self.PERSONA_PATTERNS.items():
            found_matches = pattern.findall(content_lower)
            if found_matches:
                # Score based on match count relative to content length
                match_count = len(found_matches)
                # Base score: 0.3 for first match, +0.15 per additional, capped at 1.0
                score = min(0.3 + (match_count - 1) * 0.15, 1.0)
                # Boost for longer matches (more specific)
                avg_match_len = sum(len(m) for m in found_matches) / match_count
                if avg_match_len > 8:
                    score = min(score + 0.1, 1.0)
                matches[agent_id] = score

        return matches

    def detect_task_type(self, task_content: str) -> str | None:
        """Detect the primary task type from content.

        Args:
            task_content: The task description to analyze.

        Returns:
            Task type string matching COLLABORATION_MATRIX keys, or None.
        """
        content_lower = task_content.lower()

        # Task type detection patterns (order matters - more specific first)
        task_patterns = [
            ("security_audit", r"\b(security|audit|vulnerab|pentest|threat)\b"),
            ("architecture", r"\b(architect|design system|infrastructure)\b"),
            ("optimization", r"\b(optim|performance|speed|latency|benchmark)\b"),
            ("ui_design", r"\b(ui|ux|interface|layout|design|visual)\b"),
            ("documentation", r"\b(document|spec|guide|api doc|readme)\b"),
            ("debugging", r"\b(debug|fix|bug|error|issue|problem)\b"),
            ("implementation", r"\b(implement|code|develop|build|create)\b"),
            ("research", r"\b(research|search|find|lookup|discover)\b"),
            ("coordination", r"\b(coordinate|team|parallel|workflow)\b"),
            ("strategy", r"\b(strateg|plan|roadmap|vision)\b"),
        ]

        for task_type, pattern in task_patterns:
            if re.search(pattern, content_lower):
                return task_type

        return None

    def get_phase_recommendation(self, task_type: str | None) -> str | None:
        """Get recommended execution phase for task type.

        Args:
            task_type: The detected task type.

        Returns:
            Recommended phase name or None.
        """
        phase_mapping = {
            "strategy": "Phase 1: Strategic Planning",
            "architecture": "Phase 1: Strategic Planning",
            "implementation": "Phase 2: Implementation",
            "optimization": "Phase 2: Implementation",
            "debugging": "Phase 2: Implementation",
            "ui_design": "Phase 2: Implementation",
            "security_audit": "Phase 3: Verification",
            "research": "Phase 3: Verification",
            "documentation": "Phase 4: Documentation",
        }
        return phase_mapping.get(task_type) if task_type else None

    def route_task(self, task_content: str) -> RoutingResult:
        """Route a task to the optimal agent(s) based on content analysis.

        Performs multi-factor analysis:
        1. Pattern matching for persona detection
        2. Task type classification
        3. Collaboration matrix lookup
        4. Tier-based priority sorting

        Args:
            task_content: The task description or user prompt.

        Returns:
            RoutingResult with primary agent, support agents, and metadata.
        """
        # Step 1: Detect personas via pattern matching
        persona_matches = self.detect_personas(task_content)
        detected_patterns = list(persona_matches.keys())

        # Step 2: Detect task type
        task_type = self.detect_task_type(task_content)

        # Step 3: Determine primary agent
        primary_agent: str
        support_agents: list[str] = []
        confidence: float
        reasoning: str

        if task_type and task_type in self.COLLABORATION_MATRIX:
            # Use collaboration matrix for known task types
            primary, support, _reviewer = self.COLLABORATION_MATRIX[task_type]
            primary_agent = primary
            support_agents = list(support)
            confidence = 0.85  # High confidence for matrix matches
            reasoning = f"Task type '{task_type}' matched collaboration matrix"
        elif persona_matches:
            # Sort by score and tier priority
            sorted_matches = sorted(
                persona_matches.items(),
                key=lambda x: (
                    -x[1],  # Higher score first
                    self.AGENT_TIERS.get(x[0], AgentTier.SUPPORT).value,  # Lower tier first
                ),
            )
            primary_agent = sorted_matches[0][0]
            confidence = sorted_matches[0][1]
            support_agents = [agent for agent, _ in sorted_matches[1:3]]
            reasoning = f"Pattern matching detected {len(persona_matches)} relevant agents"
        else:
            # Default to strategic coordination
            primary_agent = "athena-conductor"
            support_agents = ["aurora-researcher"]
            confidence = 0.5
            reasoning = "No specific patterns detected, defaulting to coordination"

        # Step 4: Get phase recommendation
        suggested_phase = self.get_phase_recommendation(task_type)

        return RoutingResult(
            primary_agent=primary_agent,
            support_agents=support_agents,
            confidence=confidence,
            reasoning=reasoning,
            detected_patterns=detected_patterns,
            suggested_phase=suggested_phase,
        )

    async def route_task_with_db(
        self,
        task_content: str,
        namespace: str | None = None,
        include_trust_scoring: bool = True,
    ) -> RoutingResult:
        """Route task with database-backed agent recommendations.

        Enhanced routing that combines pattern matching with database-backed
        agent capability lookup and trust scores.

        Args:
            task_content: The task description or user prompt.
            namespace: Optional namespace filter for agent selection.
            include_trust_scoring: Whether to include trust scores in routing (default: True)

        Returns:
            RoutingResult with database-enhanced recommendations including trust scores.
        """
        # Get basic routing result
        result = self.route_task(task_content)

        # Enhance with database if available
        if self.agent_service and self.session:
            try:
                # Get capabilities from detected patterns
                capabilities = []
                for agent_id in result.detected_patterns:
                    agent_caps = self.AGENT_CAPABILITIES.get(agent_id, [])
                    capabilities.extend(agent_caps)

                # Get recommended agents from database
                recommended = await self.agent_service.get_recommended_agents(
                    capabilities=list(set(capabilities)),
                    namespace=namespace,
                    limit=5,
                )

                if recommended:
                    # Fetch trust scores for detected agents (if enabled)
                    trust_scores = {}
                    if include_trust_scoring and self.agent_service:
                        for agent_id in result.detected_patterns:
                            try:
                                # Fetch trust score from Agent model
                                agent = await self.agent_service.get_agent_by_id(agent_id)
                                if agent and hasattr(agent, "trust_score"):
                                    trust_scores[agent_id] = agent.trust_score
                                else:
                                    # Default trust score for new/unknown agents
                                    trust_scores[agent_id] = 0.5
                            except Exception:
                                # Fallback to default if fetch fails
                                trust_scores[agent_id] = 0.5

                    # Calculate weighted routing scores: 60% pattern + 40% trust
                    if include_trust_scoring and trust_scores:
                        # Re-calculate primary agent using weighted scores
                        agent_scores = {}
                        for agent_id in result.detected_patterns:
                            pattern_score = self._calculate_pattern_score(
                                agent_id, task_content, result
                            )
                            trust_score = trust_scores.get(agent_id, 0.5)

                            # Hybrid formula: 60% pattern match + 40% trust score
                            weighted_score = (pattern_score * 0.60) + (trust_score * 0.40)
                            agent_scores[agent_id] = weighted_score

                            logger.debug(
                                f"Routing score for {agent_id}: pattern={pattern_score:.2f}, "
                                f"trust={trust_score:.2f}, weighted={weighted_score:.2f}"
                            )

                        if agent_scores:
                            # Re-rank agents by weighted score
                            sorted_agents = sorted(
                                agent_scores.items(), key=lambda x: x[1], reverse=True
                            )
                            best_agent = sorted_agents[0][0]
                            best_score = sorted_agents[0][1]

                            # Update result with trust-weighted routing
                            if best_agent != result.primary_agent:
                                logger.info(
                                    f"Trust scoring changed primary agent from "
                                    f"{result.primary_agent} to {best_agent}"
                                )
                                result.support_agents = [result.primary_agent] + [
                                    a for a in result.support_agents if a != best_agent
                                ][:2]
                                result.primary_agent = best_agent

                            result.confidence = min(best_score, 1.0)
                            result.reasoning += f" (trust-weighted: {best_score:.2f})"

                    # Merge database recommendations with pattern matching
                    db_agent_ids = [agent.agent_id for agent in recommended]
                    # Boost confidence if database confirms pattern matching
                    if result.primary_agent in db_agent_ids:
                        result.confidence = min(result.confidence + 0.1, 1.0)
                        result.reasoning += " (confirmed by database)"
                    # Add high-performing agents from DB to support
                    for agent in recommended[:2]:
                        if agent.agent_id not in [result.primary_agent] + result.support_agents:
                            result.support_agents.append(agent.agent_id)

            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                logger.warning(f"Database agent lookup failed, using pattern-only routing: {e}")

        return result

    def _calculate_pattern_score(
        self, agent_id: str, task_content: str, result: RoutingResult
    ) -> float:
        """Calculate the pattern match score for an agent.

        Args:
            agent_id: Agent identifier
            task_content: Task description
            result: Current routing result with detected patterns

        Returns:
            Pattern match score (0.0-1.0)
        """
        # If this agent was detected, get its score from the pattern matching
        persona_matches = self.detect_personas(task_content)
        return persona_matches.get(agent_id, 0.0)

    def get_trinitas_full_mode_routing(
        self,
        task_content: str,
    ) -> dict[str, Any]:
        """Get full Trinitas mode routing with phase-based execution plan.

        Returns a complete execution plan following the Phase-Based Execution
        Protocol with all 4 phases and approval gates.

        Args:
            task_content: The task description.

        Returns:
            Dictionary with full execution plan structure.
        """
        base_result = self.route_task(task_content)

        return {
            "mode": "trinitas_full",
            "routing": {
                "primary": base_result.primary_agent,
                "support": base_result.support_agents,
                "confidence": base_result.confidence,
            },
            "execution_plan": {
                "phase_1_strategic": {
                    "name": "Strategic Planning",
                    "agents": ["hera-strategist", "athena-conductor"],
                    "approval_gate": "strategic_consensus",
                    "description": "Strategy design and resource coordination",
                },
                "phase_2_implementation": {
                    "name": "Implementation",
                    "agents": [base_result.primary_agent] + base_result.support_agents[:1],
                    "approval_gate": "tests_pass",
                    "description": "Technical implementation and testing",
                },
                "phase_3_verification": {
                    "name": "Verification",
                    "agents": ["hestia-auditor", "aurora-researcher"],
                    "approval_gate": "security_approval",
                    "description": "Security audit and impact verification",
                },
                "phase_4_documentation": {
                    "name": "Documentation",
                    "agents": ["muses-documenter", "aphrodite-designer"],
                    "approval_gate": "completion_confirmed",
                    "description": "Documentation and visual guides",
                },
            },
            "coordinator": "eris-coordinator",
            "detected_patterns": base_result.detected_patterns,
            "suggested_phase": base_result.suggested_phase,
            "reasoning": base_result.reasoning,
        }
