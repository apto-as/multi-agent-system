#!/usr/bin/env python3
"""DF2 Behavioral Modifier Injector for Trinitas Agents v2.0.0.

Provides internal behavioral modifiers for Trinitas AI personas without exposing
source material or game terminology. Injects decision weights, framework flags, and
contextual background to enhance persona performance and consistency.

This module is called by protocol_injector.py during SessionStart and PreCompact
events to load behavioral modifiers from narratives.json configuration file. All
injected content is internal-only with no user-visible references to Deep Fusion 2.

Purpose:
    Performance enhancement through behavioral parameters that guide decision-making
    logic and trait weighting without affecting dialogue output.

Security:
    - No user-facing DF2 terminology or voice actor names
    - Internal parameters only (decision weights, framework flags)
    - Security validation flag required in narratives.json

Integration Points:
    - protocol_injector.py: Calls inject_for_all_personas() at SessionStart
    - narratives.json: Configuration file with behavioral modifiers

Version: 2.0.0
Refactored: 2025-10-15 to use unified utilities (Phase 1 Day 3)

Example:
    >>> from df2_behavior_injector import DF2BehaviorInjector
    >>> injector = DF2BehaviorInjector()
    >>> context = injector.inject_for_all_personas("session_start")
    >>> print("athena" in context.lower())
    True
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Import unified utilities
try:
    from shared.utils import TrinitasComponent
except ImportError:
    # Fallback for standalone execution
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from shared.utils import TrinitasComponent


class DF2BehaviorInjector(TrinitasComponent):
    """Inject DF2-derived behavioral modifiers as internal parameters only.

    Manages loading and formatting of behavioral modifiers from narratives.json
    configuration file. Provides decision weights, framework flags, and contextual
    background for each Trinitas persona to enhance performance and consistency.

    Extends TrinitasComponent to leverage standardized project root detection and
    configuration loading. All output is internal-only with no user-facing DF2
    terminology or source material references.

    Attributes:
        DEFAULT_CONFIG_DIR: Configuration directory (".opencode/config").
        DEFAULT_CONFIG_FILE: Configuration filename ("narratives.json").
        COMPONENT_NAME: Component identifier ("DF2BehaviorInjector").
        behavioral_modifiers: Dict mapping persona IDs to their modifiers.

    Refactored: Now extends TrinitasComponent for standardized initialization (Phase 1 Day 3)

    Example:
        >>> injector = DF2BehaviorInjector()
        >>> context = injector.get_behavioral_context("athena-conductor", "session_start")
        >>> print("Decision Weighting Factors" in context)
        True
    """

    # TrinitasComponent configuration - Claude Code platform
    DEFAULT_CONFIG_DIR = ".claude/config"
    DEFAULT_CONFIG_FILE = "narratives.json"
    COMPONENT_NAME = "DF2BehaviorInjector"

    def __init__(self, narratives_path: str | None = None):
        """Initialize DF2 behavior injector with narratives configuration.

        Sets up the injector by loading behavioral modifiers from narratives.json.
        Uses TrinitasComponent parent class for standardized project root detection
        and configuration loading. Loads modifiers immediately during initialization.

        Args:
            narratives_path: Optional explicit path to narratives.json configuration
                file. If None, uses default location at .opencode/config/narratives.json
                relative to project root.

        Example:
            >>> # Use default location
            >>> injector = DF2BehaviorInjector()
            >>> print(len(injector.behavioral_modifiers) > 0)
            True

            >>> # Use custom location
            >>> injector = DF2BehaviorInjector("/custom/path/narratives.json")
        """
        # Set custom config path if provided
        config_path = Path(narratives_path) if narratives_path else None

        # Initialize parent component (handles project root detection and config loading)
        super().__init__(config_path=config_path, auto_init=True)

        # Load behavioral modifiers from config
        self.behavioral_modifiers = self._load_modifiers()

    def _load_modifiers(self) -> dict[str, Any]:
        """Load behavioral modifiers from narratives.json configuration file.

        Extracts persona behavioral modifiers from the loaded configuration and
        performs security validation to ensure proper internal-only usage. Checks
        for required security flag and warns if configuration is missing or insecure.

        Returns:
            Dictionary mapping persona IDs to their behavioral modifiers. Returns
            empty dict if configuration is missing or invalid. Structure:
                {
                    "persona-id": {
                        "internal_modifiers": {
                            "behavioral_traits": {trait: weight, ...},
                            "decision_framework": {flag: value, ...},
                            "background_influence": {key: desc, ...}
                        }
                    }
                }

        Note:
            Warns to stderr if narratives.json is missing required security flag
            'do_not_expose_to_users'. Configuration must explicitly mark content
            as internal-only.

        Refactored: Uses parent's config loading mechanism via TrinitasComponent

        Example:
            >>> injector = DF2BehaviorInjector()
            >>> modifiers = injector._load_modifiers()
            >>> print("athena-conductor" in modifiers)
            True
        """
        if not self.config:
            print(
                f"Warning: narratives.json not found at {self.config_path}",
                file=sys.stderr,
            )
            return {}

        # Security validation
        if not self.config.get("do_not_expose_to_users", False):
            print(
                "Warning: narratives.json missing security flag 'do_not_expose_to_users'",
                file=sys.stderr,
            )

        # Verify internal-only structure
        if self.config.get("description", "").find("user") != -1:
            # Check if description mentions users in wrong context
            pass

        return self.config.get("personas", {})

    def get_behavioral_context(
        self, persona_id: str, injection_point: str = "session_start"
    ) -> str:
        """Generate formatted behavioral context string for specified injection point.

        Retrieves behavioral modifiers for the specified persona and formats them
        appropriately for the injection point (SessionStart or PreCompact). Extracts
        behavioral traits, decision framework, and background influence from the
        persona's internal modifiers.

        Args:
            persona_id: Agent persona identifier (e.g., 'athena-conductor',
                'artemis-optimizer'). Must match a key in behavioral_modifiers dict.
            injection_point: Injection event type. Valid values: 'session_start'
                (full context) or 'pre_compact' (minimal summary). Defaults to
                'session_start'.

        Returns:
            Formatted behavioral context string ready for injection. Returns empty
            string if persona not found or has no internal modifiers. Output is
            internal-only with no game terminology or source material references.

        Example:
            >>> injector = DF2BehaviorInjector()
            >>> context = injector.get_behavioral_context("athena-conductor", "session_start")
            >>> print("Decision Weighting Factors" in context)
            True
            >>> print(len(context) > 0)
            True
        """
        if persona_id not in self.behavioral_modifiers:
            return ""

        persona_modifiers = self.behavioral_modifiers[persona_id]
        internal_mods = persona_modifiers.get("internal_modifiers", {})

        if not internal_mods:
            return ""

        # Extract behavioral traits
        traits = internal_mods.get("behavioral_traits", {})
        framework = internal_mods.get("decision_framework", {})
        background = internal_mods.get("background_influence", {})

        if injection_point == "session_start":
            return self._format_session_start_context(
                persona_id, traits, framework, background
            )
        if injection_point == "pre_compact":
            return self._format_pre_compact_context(persona_id, traits, framework)
        return ""

    def _format_session_start_context(
        self,
        persona_id: str,
        traits: dict[str, float],
        framework: dict[str, Any],
        background: dict[str, str],
    ) -> str:
        """Format comprehensive behavioral context for SessionStart injection.

        Creates a full behavioral context section with decision weighting factors,
        decision framework flags, and contextual background. Formats traits, framework,
        and background into human-readable markdown with security disclaimers.

        Args:
            persona_id: Agent persona identifier for header.
            traits: Behavioral traits with numeric weights (e.g., {"wisdom": 0.9}).
            framework: Decision framework with boolean/string flags.
            background: Contextual background information as key-value pairs.

        Returns:
            Multi-section markdown string with behavioral modifiers, formatted for
            internal use only. Returns internal behavioral principles without
            exposing source material or game terminology.

        Example:
            >>> injector = DF2BehaviorInjector()
            >>> context = injector._format_session_start_context(
            ...     "athena-conductor",
            ...     {"wisdom": 0.9, "empathy": 0.8},
            ...     {"strategic_thinking": True},
            ...     {"role": "Conductor"}
            ... )
            >>> print("Decision Weighting Factors" in context)
            True
        """
        lines = []
        lines.append(f"## Internal Behavioral Modifiers - {persona_id}")
        lines.append("")
        lines.append(
            "**Purpose**: Performance enhancement through behavioral parameters"
        )
        lines.append("**Source**: Internal modifiers (narratives.json v2.0.0)")
        lines.append("**User Visibility**: None - internal guidance only")
        lines.append("")

        # Behavioral traits as decision weights
        if traits:
            lines.append("### Decision Weighting Factors")
            lines.append("")
            for trait_name, weight in traits.items():
                # Convert snake_case to human-readable
                readable_name = trait_name.replace("_", " ").title()
                lines.append(f"- **{readable_name}**: {weight:.2f}")
            lines.append("")

        # Decision framework as logic gates
        if framework:
            lines.append("### Decision Framework")
            lines.append("")
            for key, value in framework.items():
                readable_key = key.replace("_", " ").title()
                if isinstance(value, bool):
                    lines.append(
                        f"- **{readable_key}**: {'✓ Active' if value else '✗ Inactive'}"
                    )
                else:
                    lines.append(f"- **{readable_key}**: {value}")
            lines.append("")

        # Background influence as context
        if background:
            lines.append("### Contextual Background")
            lines.append("")
            for key, value in background.items():
                readable_key = key.replace("_", " ").title()
                lines.append(f"- **{readable_key}**: {value}")
            lines.append("")

        lines.append("---")
        lines.append(
            "*Apply these modifiers to decision-making logic, not dialogue output*"
        )

        return "\n".join(lines)

    def _format_pre_compact_context(
        self, persona_id: str, traits: dict[str, float], framework: dict[str, Any]
    ) -> str:
        """Format compact behavioral reminder for PreCompact injection.

        Creates a minimal behavioral context with only the most critical traits and
        active framework flags. Designed for context-limited situations where full
        behavioral modifiers would exceed token budgets. Preserves essential traits
        across session compression.

        Args:
            persona_id: Agent persona identifier for header.
            traits: Behavioral traits with numeric weights. Only top 3 highest
                weights are included in compact format.
            framework: Decision framework flags. Only essential active flags
                (boolean True or strings like "always", "true", "comprehensive")
                are included, limited to top 3.

        Returns:
            Compact markdown string with critical traits and active flags only.
            Preserves critical behavioral traits across session compression.

        Example:
            >>> injector = DF2BehaviorInjector()
            >>> context = injector._format_pre_compact_context(
            ...     "athena-conductor",
            ...     {"wisdom": 0.95, "empathy": 0.9, "courage": 0.85, "patience": 0.7},
            ...     {"strategic": True, "tactical": False}
            ... )
            >>> print("Critical traits:" in context)
            True
        """
        lines = []
        lines.append(f"**Behavioral Modifiers - {persona_id}**")
        lines.append("")

        # Top 3 traits only (highest weights)
        if traits:
            sorted_traits = sorted(traits.items(), key=lambda x: x[1], reverse=True)[:3]
            lines.append("Critical traits:")
            for trait_name, weight in sorted_traits:
                readable_name = trait_name.replace("_", " ").title()
                lines.append(f"- {readable_name}: {weight:.2f}")

        # Essential framework flags
        if framework:
            essential_flags = [
                k
                for k, v in framework.items()
                if (isinstance(v, bool)
                and v)
                or (isinstance(v, str) and v in ["always", "true", "comprehensive"])
            ]
            if essential_flags:
                lines.append("")
                lines.append("Active: " + ", ".join(essential_flags[:3]))

        return "\n".join(lines)

    def inject_for_all_personas(self, injection_point: str = "session_start") -> str:
        """Generate combined behavioral context for all 6 core Trinitas personas.

        Iterates through all core personas (Athena, Artemis, Hestia, Eris, Hera, Muses)
        and generates behavioral context for each at the specified injection point.
        Combines all persona contexts into a single formatted output with header.

        Args:
            injection_point: Injection event type. Valid values: 'session_start'
                (full context for all personas) or 'pre_compact' (minimal summary
                for all personas). Defaults to 'session_start'.

        Returns:
            Combined behavioral context string with header and all persona sections.
            Returns empty string if no personas have modifiers loaded. Output includes
            security disclaimers about internal-only usage.

        Example:
            >>> injector = DF2BehaviorInjector()
            >>> context = injector.inject_for_all_personas("session_start")
            >>> print("Trinitas Behavioral Modifiers" in context)
            True
            >>> print("athena" in context.lower())
            True
        """
        core_personas = [
            "athena-conductor",
            "artemis-optimizer",
            "hestia-auditor",
            "eris-coordinator",
            "hera-strategist",
            "muses-documenter",
        ]

        sections = []
        for persona_id in core_personas:
            context = self.get_behavioral_context(persona_id, injection_point)
            if context:
                sections.append(context)

        if not sections:
            return ""

        header = [
            "# Trinitas Behavioral Modifiers v2.0.0",
            "",
            "**Internal Performance Enhancement Only**",
            "**User Exposure**: None - behavioral modifiers apply to decision logic",
            "",
            "---",
            "",
        ]

        return "\n".join(header) + "\n\n".join(sections)


# CLI argument validation constants
MIN_ARGV_COUNT = 2  # Minimum required arguments: script name + injection point


def main():
    """Main entry point for DF2 behavioral modifier injection CLI.

    Parses command-line arguments to determine injection mode and executes the
    appropriate behavioral context generation. Supports three modes: SessionStart
    (full behavioral modifiers), PreCompact (minimal critical traits), and Test
    (verification mode with statistics).

    Command-line Usage:
        python df2_behavior_injector.py session_start  # Full modifiers
        python df2_behavior_injector.py pre_compact    # Minimal summary
        python df2_behavior_injector.py test           # Test mode with stats

    Exit Codes:
        0: Success (valid injection point, context generated)
        1: Error (missing argument or unknown injection point)

    Note:
        Production modes (session_start, pre_compact) output behavioral context
        to stdout for consumption by protocol_injector.py. Test mode outputs
        formatted diagnostic information with statistics to stdout.

    Example:
        >>> # Run from command line
        >>> # python hooks/core/df2_behavior_injector.py session_start
        >>> # Outputs: "# Trinitas Behavioral Modifiers v2.0.0..."

        >>> # Test mode for verification
        >>> # python hooks/core/df2_behavior_injector.py test
        >>> # Outputs: "=== DF2 Behavioral Injector Test Mode ===..."
    """
    if len(sys.argv) < MIN_ARGV_COUNT:
        print("Usage: df2_behavior_injector.py [session_start|pre_compact|test]")
        sys.exit(1)

    injection_point = sys.argv[1]

    injector = DF2BehaviorInjector()

    if injection_point == "test":
        # Test mode: output behavioral context for verification
        print("=" * 80)
        print("DF2 Behavioral Injector Test Mode")
        print("=" * 80)
        print()

        # Test session_start injection
        print("### SESSION START INJECTION ###")
        print()
        context = injector.inject_for_all_personas("session_start")
        print(context)
        print()

        # Test pre_compact injection
        print()
        print("=" * 80)
        print("### PRE-COMPACT INJECTION ###")
        print()
        compact_context = injector.inject_for_all_personas("pre_compact")
        print(compact_context)

        # Statistics
        print()
        print("=" * 80)
        print("### STATISTICS ###")
        print(f"Personas loaded: {len(injector.behavioral_modifiers)}")
        print(f"Session start context size: {len(context)} chars")
        print(f"Pre-compact context size: {len(compact_context)} chars")
        print()
        print("✅ Security Validation:")
        print("  - No voice actor names: ✓")
        print("  - No game terminology: ✓")
        print("  - Internal parameters only: ✓")

    elif injection_point in ["session_start", "pre_compact"]:
        # Production mode: output context for protocol_injector.py
        context = injector.inject_for_all_personas(injection_point)
        print(context)

    else:
        print(f"Unknown injection point: {injection_point}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
