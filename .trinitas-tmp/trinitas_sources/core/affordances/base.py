"""Trinitas Affordance System: Capability-based persona management.

Implements Anthropic's "Affordances over Instructions" principle for explicit
capability definition and discovery. Provides structured action categorization,
token cost tracking, and optimal executor selection for multi-agent coordination.

This module defines the core affordance framework for Trinitas AI personas,
enabling declarative specification of what each persona can do rather than
imperative instructions on how to do it. Supports Thinking-Acting separation
via ActionCategory taxonomy.

Core Concepts:
    - Affordance: What an agent CAN do (action + cost + category + constraints)
    - ActionCategory: Taxonomy separating thinking, planning, acting, hybrid actions
    - PersonaAffordances: Capability registry mapping personas to their affordances
    - Token Costing: Context cost tracking for efficient resource allocation

Design Principles:
    - Affordances over Instructions: Declare capabilities, not procedures
    - Thinking-Acting Separation: Explicit categorization of read-only vs state-changing
    - Cost Transparency: Token costs visible for optimization decisions
    - Optimal Executor Selection: Automatic routing to most efficient persona

Anthropic原則の"Affordances over Instructions"を実装

Example:
    >>> # Query persona capabilities
    >>> athena = PersonaAffordances("athena-conductor")
    >>> can_do, cost = athena.can_execute("orchestrate")
    >>> print(f"Can orchestrate: {can_do}, Cost: {cost} tokens")
    Can orchestrate: True, Cost: 50 tokens

    >>> # Find optimal executor
    >>> executor, cost = PersonaAffordances.get_optimal_executor("optimize")
    >>> print(f"Best executor: {executor}")
    Best executor: artemis-optimizer
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ActionCategory(Enum):
    """Action taxonomy for Thinking-Acting separation in affordances.

    Categorizes persona actions into four distinct types based on their effect
    on system state. Enables explicit separation between read-only analysis
    (THINKING), planning without execution (PLANNING), state-changing operations
    (ACTING), and conditional execution (HYBRID).

    This taxonomy supports Anthropic's principle of making side effects explicit
    and predictable. Pure thinking actions have no side effects, while acting
    actions explicitly modify state.

    アクションカテゴリー（Thinking-Acting分離）

    Attributes:
        THINKING: Read-only analysis actions with no side effects (e.g., audit,
            analyze, assess). Safe for speculative execution and caching.
        PLANNING: Planning actions that generate plans but don't execute them
            (e.g., strategize, orchestrate, mediate). Idempotent and cacheable.
        ACTING: State-changing actions with visible side effects (e.g., refactor,
            secure, document). Must be executed exactly once.
        HYBRID: Conditional actions that may or may not modify state depending
            on input (e.g., optimize, balance). Require careful handling.

    Example:
        >>> category = ActionCategory.THINKING
        >>> print(category.value)
        thinking
        >>> is_readonly = category in [ActionCategory.THINKING, ActionCategory.PLANNING]
        >>> print(is_readonly)
        True
    """

    THINKING = "thinking"  # 読み取り専用、分析
    PLANNING = "planning"  # 計画立案
    ACTING = "acting"  # 状態変更
    HYBRID = "hybrid"  # 条件付き実行


@dataclass
class Affordance:
    """Explicit capability definition for personas ("what they CAN do").

    Structured representation of a single action that a Trinitas persona can perform.
    Includes action metadata (name, category, cost), descriptive information, and
    semantic dependencies (prerequisites and provided outputs).

    Implements Anthropic's "Affordances over Instructions" by declaring WHAT can be
    done rather than HOW to do it. Enables automatic capability discovery, optimal
    executor selection, and token cost estimation.

    ペルソナが「できること」の明示的定義

    Attributes:
        action: Unique action identifier (e.g., "orchestrate", "optimize", "audit").
            Used for capability lookup and executor selection.
        category: ActionCategory classifying the action's effect on system state
            (THINKING, PLANNING, ACTING, or HYBRID).
        tokens: Estimated context token cost for executing this action. Used for
            resource optimization and load balancing.
        description: Human-readable action description for documentation and UI.
            Should be concise (under 50 characters).
        requires: Prerequisites for executing this action. Semantic tags indicating
            required context or state (e.g., ["code_loaded", "security_baseline"]).
        provides: Outputs produced by this action. Semantic tags indicating what
            becomes available after execution (e.g., ["security_report", "metrics"]).

    Example:
        >>> affordance = Affordance(
        ...     action="audit",
        ...     category=ActionCategory.THINKING,
        ...     tokens=60,
        ...     description="Security audit",
        ...     requires=["codebase"],
        ...     provides=["security_report"]
        ... )
        >>> print(f"{affordance.action}: {affordance.tokens} tokens")
        audit: 60 tokens
        >>> print(f"Side effects: {affordance.category == ActionCategory.ACTING}")
        Side effects: False
    """

    action: str  # アクション名
    category: ActionCategory  # カテゴリー
    tokens: int  # Context cost
    description: str  # 簡潔な説明
    requires: list[str] = field(default_factory=list)  # 前提条件
    provides: list[str] = field(default_factory=list)  # 提供結果


class PersonaAffordances:
    """Capability registry and management for Trinitas AI personas.

    Manages affordance definitions for all 6 core Trinitas personas through a
    static AFFORDANCE_MAP registry. Provides methods for capability lookup,
    category-based filtering, token cost calculation, and optimal executor
    selection based on action requirements.

    This class implements the capability discovery and routing mechanisms for
    the Trinitas multi-agent system, enabling automatic delegation to the most
    cost-efficient persona for any given action.

    ペルソナの能力管理

    Attributes:
        AFFORDANCE_MAP: Static registry mapping persona IDs to their Affordance
            lists. Contains definitions for all 6 core personas:
            - athena-conductor: Orchestration, coordination, harmony (4 affordances)
            - artemis-optimizer: Performance optimization, refactoring (4 affordances)
            - hestia-auditor: Security audit, validation, risk assessment (4 affordances)
            - eris-coordinator: Mediation, prioritization, task distribution (4 affordances)
            - hera-strategist: Strategic planning, ROI evaluation (4 affordances)
            - muses-documenter: Documentation, archiving, knowledge recording (4 affordances)

        persona_id: Identifier for the managed persona (e.g., "athena-conductor").
        capabilities: List of Affordance objects available to this persona.

    Example:
        >>> # Query specific persona capabilities
        >>> athena = PersonaAffordances("athena-conductor")
        >>> can_do, cost = athena.can_execute("orchestrate")
        >>> print(f"Can execute: {can_do}, Cost: {cost} tokens")
        Can execute: True, Cost: 50 tokens

        >>> # Find optimal executor across all personas
        >>> executor, cost = PersonaAffordances.get_optimal_executor("audit")
        >>> print(f"Optimal executor: {executor}, Cost: {cost} tokens")
        Optimal executor: hestia-auditor, Cost: 60 tokens

        >>> # Get all thinking actions for a persona
        >>> thinking = athena.get_actions_by_category(ActionCategory.THINKING)
        >>> print(f"Thinking actions: {[a.action for a in thinking]}")
        Thinking actions: ['harmonize']
    """

    # 各ペルソナの基本Affordance定義
    AFFORDANCE_MAP = {
        "athena-conductor": [
            Affordance(
                "orchestrate", ActionCategory.PLANNING, 50, "Harmonize team efforts"
            ),
            Affordance(
                "coordinate", ActionCategory.PLANNING, 40, "Coordinate parallel tasks"
            ),
            Affordance("harmonize", ActionCategory.THINKING, 30, "Analyze harmony"),
            Affordance("integrate", ActionCategory.ACTING, 60, "Integrate results"),
        ],
        "artemis-optimizer": [
            Affordance("optimize", ActionCategory.HYBRID, 70, "Optimize performance"),
            Affordance(
                "analyze_performance", ActionCategory.THINKING, 40, "Analyze metrics"
            ),
            Affordance("refactor", ActionCategory.ACTING, 80, "Refactor code"),
            Affordance("benchmark", ActionCategory.THINKING, 50, "Run benchmarks"),
        ],
        "hestia-auditor": [
            Affordance("audit", ActionCategory.THINKING, 60, "Security audit"),
            Affordance("validate", ActionCategory.THINKING, 40, "Validate security"),
            Affordance("secure", ActionCategory.ACTING, 90, "Apply security fixes"),
            Affordance("assess_risk", ActionCategory.THINKING, 50, "Risk assessment"),
        ],
        "eris-coordinator": [
            Affordance("mediate", ActionCategory.PLANNING, 50, "Mediate conflicts"),
            Affordance("prioritize", ActionCategory.PLANNING, 40, "Set priorities"),
            Affordance("distribute", ActionCategory.ACTING, 60, "Distribute tasks"),
            Affordance("balance", ActionCategory.HYBRID, 55, "Balance workload"),
        ],
        "hera-strategist": [
            Affordance("strategize", ActionCategory.THINKING, 60, "Strategic analysis"),
            Affordance("plan", ActionCategory.PLANNING, 70, "Create strategic plan"),
            Affordance("command", ActionCategory.ACTING, 80, "Execute command"),
            Affordance("evaluate_roi", ActionCategory.THINKING, 45, "Calculate ROI"),
        ],
        "muses-documenter": [
            Affordance("document", ActionCategory.ACTING, 50, "Create documentation"),
            Affordance("archive", ActionCategory.ACTING, 40, "Archive knowledge"),
            Affordance(
                "structure", ActionCategory.PLANNING, 45, "Structure information"
            ),
            Affordance("record", ActionCategory.ACTING, 35, "Record results"),
        ],
    }

    def __init__(self, persona_id: str):
        """Initialize persona affordance manager with capability lookup.

        Loads the affordances for the specified persona from AFFORDANCE_MAP registry.
        If the persona ID is not found in the registry, initializes with an empty
        capability list (allowing graceful handling of unknown personas).

        Args:
            persona_id: Unique identifier for the Trinitas persona. Must match a key
                in AFFORDANCE_MAP for capability loading. Valid IDs: "athena-conductor",
                "artemis-optimizer", "hestia-auditor", "eris-coordinator",
                "hera-strategist", "muses-documenter".

        Example:
            >>> # Load valid persona
            >>> athena = PersonaAffordances("athena-conductor")
            >>> print(f"Loaded {len(athena.capabilities)} capabilities")
            Loaded 4 capabilities

            >>> # Handle unknown persona gracefully
            >>> unknown = PersonaAffordances("unknown-persona")
            >>> print(f"Capabilities: {len(unknown.capabilities)}")
            Capabilities: 0
        """
        self.persona_id = persona_id
        self.capabilities = self.AFFORDANCE_MAP.get(persona_id, [])

    def can_execute(self, action: str) -> tuple[bool, int]:
        """Check if persona can execute specified action and return token cost.

        Queries the persona's capabilities to determine if the requested action is
        supported. Returns both the capability status and the estimated token cost
        for resource planning and load balancing.

        実行可能性とコストを返す

        Args:
            action: Action identifier to query (e.g., "orchestrate", "audit", "optimize").
                Must match an action name in the persona's capability list.

        Returns:
            Tuple of (can_execute, token_cost):
                - can_execute (bool): True if persona supports this action, False otherwise.
                - token_cost (int): Estimated context tokens needed for execution. Returns
                    0 if action is not supported.

        Example:
            >>> athena = PersonaAffordances("athena-conductor")
            >>> can_do, cost = athena.can_execute("orchestrate")
            >>> print(f"Can orchestrate: {can_do}, Cost: {cost} tokens")
            Can orchestrate: True, Cost: 50 tokens

            >>> can_do, cost = athena.can_execute("audit")  # Not in athena's capabilities
            >>> print(f"Can audit: {can_do}, Cost: {cost} tokens")
            Can audit: False, Cost: 0 tokens
        """
        for capability in self.capabilities:
            if capability.action == action:
                return True, capability.tokens
        return False, 0

    def get_actions_by_category(self, category: ActionCategory) -> list[Affordance]:
        """Filter persona's affordances by action category (THINKING/PLANNING/ACTING/HYBRID).

        Retrieves all affordances that match the specified category. Useful for
        separating read-only analysis actions from state-changing operations, or for
        identifying planning actions that generate execution plans.

        カテゴリー別アクション取得

        Args:
            category: ActionCategory enum value to filter by (THINKING, PLANNING,
                ACTING, or HYBRID). Only affordances matching this category are returned.

        Returns:
            List of Affordance objects matching the specified category. Returns empty
            list if no affordances match the category.

        Example:
            >>> athena = PersonaAffordances("athena-conductor")
            >>> thinking = athena.get_actions_by_category(ActionCategory.THINKING)
            >>> print(f"Thinking actions: {[a.action for a in thinking]}")
            Thinking actions: ['harmonize']

            >>> planning = athena.get_actions_by_category(ActionCategory.PLANNING)
            >>> print(f"Planning actions: {[a.action for a in planning]}")
            Planning actions: ['orchestrate', 'coordinate']

            >>> acting = athena.get_actions_by_category(ActionCategory.ACTING)
            >>> print(f"Acting actions: {[a.action for a in acting]}")
            Acting actions: ['integrate']
        """
        return [c for c in self.capabilities if c.category == category]

    def get_total_tokens(self, actions: list[str]) -> int:
        """Calculate total token cost for executing multiple actions sequentially.

        Sums the context token costs for all supported actions in the list. Skips
        actions that the persona cannot execute (not in capabilities). Useful for
        workflow planning and resource estimation before execution.

        複数アクションの合計トークン計算

        Args:
            actions: List of action identifiers to sum token costs for. Each action
                is checked against the persona's capabilities. Unsupported actions
                contribute 0 tokens to the total.

        Returns:
            Total estimated token cost for all supported actions. Returns 0 if none
            of the actions are supported by this persona.

        Example:
            >>> athena = PersonaAffordances("athena-conductor")
            >>> workflow = ["orchestrate", "coordinate", "integrate"]
            >>> total = athena.get_total_tokens(workflow)
            >>> print(f"Total workflow cost: {total} tokens")
            Total workflow cost: 150 tokens

            >>> # Mixed supported/unsupported actions
            >>> mixed = ["orchestrate", "audit", "coordinate"]  # audit not in athena
            >>> total = athena.get_total_tokens(mixed)
            >>> print(f"Total cost (skipping unsupported): {total} tokens")
            Total cost (skipping unsupported): 90 tokens
        """
        total = 0
        for action in actions:
            can_do, tokens = self.can_execute(action)
            if can_do:
                total += tokens
        return total

    @classmethod
    def get_optimal_executor(cls, action: str) -> tuple[str, int] | None:
        """Find most cost-efficient persona for executing specified action.

        Searches across all 6 core personas to find which can execute the action at
        the lowest token cost. Implements automatic routing for optimal resource
        utilization in multi-agent coordination.

        最適な実行者を選択

        Args:
            action: Action identifier to find executor for (e.g., "audit", "optimize").
                Searches all personas in AFFORDANCE_MAP for this capability.

        Returns:
            Tuple of (persona_id, token_cost) for the most efficient executor, or None
            if no persona supports this action. If multiple personas have the same
            minimum cost, returns the first found.

        Example:
            >>> # Find optimal executor for security audit
            >>> executor, cost = PersonaAffordances.get_optimal_executor("audit")
            >>> print(f"Optimal for audit: {executor} at {cost} tokens")
            Optimal for audit: hestia-auditor at 60 tokens

            >>> # Find optimal executor for optimization
            >>> executor, cost = PersonaAffordances.get_optimal_executor("optimize")
            >>> print(f"Optimal for optimize: {executor} at {cost} tokens")
            Optimal for optimize: artemis-optimizer at 70 tokens

            >>> # Unsupported action returns None
            >>> result = PersonaAffordances.get_optimal_executor("unsupported_action")
            >>> print(f"Result: {result}")
            Result: None
        """
        candidates = []
        for persona_id in cls.AFFORDANCE_MAP:
            affordances = cls(persona_id)
            can_do, cost = affordances.can_execute(action)
            if can_do:
                candidates.append((persona_id, cost))

        if not candidates:
            return None
        return min(candidates, key=lambda x: x[1])

    def to_dict(self) -> dict:
        """Export persona affordances as dictionary for Claude Code hook integration.

        Serializes the persona's capabilities into a JSON-compatible dictionary format
        suitable for dynamic injection via protocol_injector.py hooks. Includes action
        metadata and aggregate token costs for resource monitoring.

        辞書形式でエクスポート（Hook用）

        Returns:
            Dictionary with structure:
                {
                    "persona": str,              # Persona ID
                    "actions": [                 # List of affordances
                        {
                            "name": str,         # Action identifier
                            "tokens": int,       # Token cost
                            "category": str      # Category value (thinking/planning/acting/hybrid)
                        },
                        ...
                    ],
                    "total_base_tokens": int     # Sum of all action costs
                }

        Example:
            >>> athena = PersonaAffordances("athena-conductor")
            >>> export = athena.to_dict()
            >>> print(f"Persona: {export['persona']}")
            Persona: athena-conductor
            >>> print(f"Actions: {len(export['actions'])}")
            Actions: 4
            >>> print(f"Total base tokens: {export['total_base_tokens']}")
            Total base tokens: 180
            >>> print(f"First action: {export['actions'][0]}")
            First action: {'name': 'orchestrate', 'tokens': 50, 'category': 'planning'}
        """
        return {
            "persona": self.persona_id,
            "actions": [
                {"name": c.action, "tokens": c.tokens, "category": c.category.value}
                for c in self.capabilities
            ],
            "total_base_tokens": sum(c.tokens for c in self.capabilities),
        }
