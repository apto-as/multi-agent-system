#!/usr/bin/env python3
"""Trinitas Protocol Injector - Memory Cookbook v2.2.4.

Implements the Memory Cookbook pattern for Claude Code integration, providing
hierarchical context injection for Trinitas multi-agent system. Supports session
boundaries, lazy loading, and behavioral modifiers via DF2 integration.

This module serves as the primary hook for injecting Trinitas system context into
Claude Code sessions. It manages core memory, agent-specific memory, contextual
memory, and session summaries using a file-based memory architecture.

Changes in v2.2.4:
    - Removed TMWS integration (file-based memory only)
    - Simplified context profiles (removed TMWS-specific options)
    - Refactored to use SecureFileLoader utility (Phase 1 Day 3)
    - Removed SessionStart hook (Phase 2 optimization)

Architecture:
    - File-based Memory: Core system and agent definitions in ~/.claude/memory/
    - Session Boundaries: Previous session summaries for continuity
    - Lazy Loading: Context profiles load only relevant contexts on-demand
    - DF2 Integration: Optional behavioral modifiers for persona customization
    - Hierarchical Summarization: Level 3 compact mode for context limits

Context Profiles:
    - minimal: No contexts (core agents only)
    - coding: performance + mcp-tools contexts
    - security: security + mcp-tools contexts
    - full: performance + mcp-tools + security + collaboration

Environment Variables:
    - TRINITAS_CONTEXT_PROFILE: Context profile selection (default: "coding")
    - TRINITAS_VERBOSE: Enable verbose logging (1=enabled, 0=silent)

Example:
    >>> # SessionStart injection
    >>> injector = MemoryBasedProtocolInjector()
    >>> injector.inject_session_start()

    >>> # PreCompact injection
    >>> injector.inject_pre_compact()

Created: 2024-12-28 (Trinitas v2.2.4)
Refactored: 2025-10-15 (Phase 1 Day 3 - Unified utilities)
"""

import json
import logging
import os
import sys
from datetime import date, timedelta
from pathlib import Path

# Import unified utilities
try:
    from shared.utils import SecureFileLoader
except ImportError:
    # Fallback for standalone execution
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from shared.utils import SecureFileLoader

# Configure logging for debugging (only when TRINITAS_VERBOSE=1)
logger = logging.getLogger(__name__)
if os.getenv("TRINITAS_VERBOSE", "0") == "1":
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[Trinitas] %(levelname)s: %(message)s"))
    logger.addHandler(handler)
else:
    logger.setLevel(logging.CRITICAL)  # Suppress all logs in normal mode


class MemoryBasedProtocolInjector:
    """Memory Cookbook-compliant protocol injection system for Trinitas v2.2.4.

    Manages the injection of Trinitas system context into Claude Code sessions using
    a file-based memory architecture. Implements Memory Cookbook patterns including
    session boundaries, lazy loading, and hierarchical summarization.

    The injector loads context from multiple sources:
        1. Previous session summaries (session continuity)
        2. Core system memory (CLAUDE.md, AGENTS.md)
        3. Agent-specific memory (Athena, Hera, others)
        4. Context-specific memory (performance, security, mcp-tools, etc.)
        5. DF2 behavioral modifiers (optional persona customization)

    Memory Architecture:
        - File-based memory system (no external dependencies)
        - All data stored locally in ~/.claude/memory/
        - Simple, transparent, and privacy-focused

    Attributes:
        VERSION: Version string for the protocol injector.
        memory_base: Path to memory directory (~/.claude/memory/).
        secure_loader: SecureFileLoader instance for safe file operations.

    Refactored: Now uses SecureFileLoader utility for enhanced security.

    Example:
        >>> injector = MemoryBasedProtocolInjector()
        >>> injector.inject_session_start()  # Full context injection
        >>> injector.inject_pre_compact()    # Minimal context injection
    """

    VERSION = "2.2.4"

    def __init__(self):
        """Initialize the protocol injector with memory paths and secure file loader.

        Sets up the memory base directory at ~/.claude/memory/ and initializes a
        SecureFileLoader instance with restricted access to memory-related directories
        and markdown/text files only.

        Attributes Created:
            memory_base: Path to ~/.claude/memory/ directory.
            secure_loader: SecureFileLoader configured for safe memory file access.

        Example:
            >>> injector = MemoryBasedProtocolInjector()
            >>> print(injector.memory_base)
            /Users/username/.claude/memory
        """
        self.memory_base = Path.home() / ".claude" / "memory"

        # Initialize secure file loader with memory base as allowed root
        self.secure_loader = SecureFileLoader(
            allowed_roots=[self.memory_base, Path.home() / ".claude"],
            allowed_extensions=[".md", ".txt"]
        )

    def load_core_memory(self) -> str:
        """Load core memory content (system and agents) for persistent context.

        Loads the core Trinitas system memory from memory/core/ directory. This includes
        fundamental system instructions and agent definitions that should be present
        in every session. Falls back to legacy CLAUDE.md and AGENTS.md if memory-based
        files are not available.

        コアメモリ読み込み（常駐）

        Memory Files Loaded:
            Primary:
                - memory/core/system.md: Core system instructions
                - memory/core/agents.md: Agent definitions and coordination patterns
            Fallback:
                - CLAUDE.md: Legacy system instructions
                - AGENTS.md: Legacy agent definitions

        Returns:
            Combined content from system and agents memory files, separated by
            double newlines. Returns empty string if no core memory is available.

        Example:
            >>> injector = MemoryBasedProtocolInjector()
            >>> core = injector.load_core_memory()
            >>> print(len(core) > 0)
            True
        """
        system = self.secure_loader.load_file(
            "core/system.md", base_path=self.memory_base, silent=True
        )
        agents = self.secure_loader.load_file(
            "core/agents.md", base_path=self.memory_base, silent=True
        )

        if not system and not agents:
            # フォールバック: 従来のCLAUDE.md/AGENTS.mdを使用
            system = self.secure_loader.load_file(
                "CLAUDE.md", base_path=Path.home() / ".claude", silent=True
            )
            agents = self.secure_loader.load_file(
                "AGENTS.md", base_path=Path.home() / ".claude", silent=True
            )

        return f"{system}\n\n{agents}" if (system or agents) else ""

    def load_agent_memory(self, agent_ids: list) -> str:
        """Load agent-specific memory content for requested agent personas.

        Loads memory files for specific Trinitas agents (e.g., athena-conductor,
        hera-strategist) from the memory/agents/ directory. Falls back to legacy
        agents/ directory if memory-based files are not available.

        エージェントメモリ読み込み

        Args:
            agent_ids: List of agent IDs to load memory for (e.g., ["athena-conductor",
                "hera-strategist"]). Agent IDs should match filenames in memory/agents/.

        Returns:
            Combined agent memory content separated by "---" delimiters. Returns
            empty string if no agent memories are found.

        Example:
            >>> injector = MemoryBasedProtocolInjector()
            >>> agents = injector.load_agent_memory(["athena-conductor", "hera-strategist"])
            >>> print("athena" in agents.lower())
            True
        """
        content = []
        for agent_id in agent_ids:
            # Memory-based
            agent_content = self.secure_loader.load_file(
                f"agents/{agent_id}.md", base_path=self.memory_base, silent=True
            )

            # Fallback: 従来のagentsディレクトリ
            if not agent_content:
                agent_content = self.secure_loader.load_file(
                    f"agents/{agent_id}.md",
                    base_path=Path.home() / ".claude",
                    silent=True
                )

            if agent_content:
                content.append(agent_content)

        return "\n\n---\n\n".join(content)

    def get_context_profile(self) -> list:
        """Get context profile from environment variable for lazy loading.

        Retrieves the active context profile from TRINITAS_CONTEXT_PROFILE environment
        variable and returns the list of context names to load. Context profiles allow
        selective loading of relevant contexts for different use cases (coding, security,
        minimal, full).

        環境変数からコンテキストプロファイル取得

        Environment Variable:
            TRINITAS_CONTEXT_PROFILE: Profile selection (default: "coding")

        Returns:
            List of context names to load based on the selected profile:
                - minimal: [] (no contexts, core agents only)
                - coding: ["performance", "mcp-tools"]
                - security: ["security", "mcp-tools"]
                - full: ["performance", "mcp-tools", "security", "collaboration"]

        Note:
            TMWS context removed in v2.2.4 (simplified to file-based memory)

        Example:
            >>> import os
            >>> os.environ["TRINITAS_CONTEXT_PROFILE"] = "security"
            >>> injector = MemoryBasedProtocolInjector()
            >>> contexts = injector.get_context_profile()
            >>> print(contexts)
            ['security', 'mcp-tools']
        """
        profile = os.getenv("TRINITAS_CONTEXT_PROFILE", "coding")

        profiles = {
            "minimal": [],
            "coding": ["performance", "mcp-tools"],
            "security": ["security", "mcp-tools"],
            "full": ["performance", "mcp-tools", "security", "collaboration"],
        }

        return profiles.get(profile, profiles["coding"])

    def load_context_memory(self, context_names: list) -> str:
        """Load context-specific memory content on-demand (lazy loading).

        Loads context-specific memory files from memory/contexts/ directory based on
        the requested context names. Contexts provide specialized knowledge for specific
        scenarios (e.g., performance optimization, security, MCP tools usage).

        コンテキスト別メモリ読み込み（on-demand）

        Args:
            context_names: List of context names to load (e.g., ["performance", "security"]).
                Each name should correspond to a .md file in memory/contexts/.

        Returns:
            Combined context memory content with section headers, separated by "---"
            delimiters. Returns empty string if no context names provided or no
            matching files found.

        Example:
            >>> injector = MemoryBasedProtocolInjector()
            >>> contexts = injector.load_context_memory(["performance", "mcp-tools"])
            >>> print("Performance Context" in contexts)
            True
        """
        if not context_names:
            return ""

        content = []
        for name in context_names:
            context_content = self.secure_loader.load_file(
                f"contexts/{name}.md", base_path=self.memory_base, silent=True
            )
            if context_content:
                content.append(f"## {name.title()} Context\n\n{context_content}")

        return "\n\n---\n\n".join(content)

    def load_previous_session_summary(self) -> str:
        """Load previous session summary for session continuity (Session Boundaries).

        Attempts to load a summary from the previous day's session from memory/sessions/
        directory. This implements the Memory Cookbook's Session Boundaries pattern,
        providing context continuity across sessions.

        前回セッションサマリー読み込み（Session Boundaries）

        Returns:
            Formatted summary with header if previous session file exists, empty string
            otherwise. Summary includes date and content from yesterday's session.

        Session File Format:
            Filename: YYYY-MM-DD_summary.md
            Location: memory/sessions/

        Example:
            >>> injector = MemoryBasedProtocolInjector()
            >>> summary = injector.load_previous_session_summary()
            >>> # Returns summary if yesterday's session file exists
            >>> print("Previous Session" in summary or summary == "")
            True
        """
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        summary = self.secure_loader.load_file(
            f"sessions/{yesterday}_summary.md", base_path=self.memory_base, silent=True
        )

        if summary:
            return f"""
## Previous Session Summary ({yesterday})

{summary}

---
"""
        return ""

    def load_df2_modifiers(self, persona_ids: list) -> str:
        """Load DF2 Behavioral Modifiers for persona customization (optional).

        Attempts to load DF2 (Deep Fusion 2) behavioral modifiers for the specified
        personas. DF2 modifiers provide fine-grained customization of persona behavior
        and communication styles. Gracefully handles absence of DF2 integration.

        DF2 Behavioral Modifiers読み込み

        Args:
            persona_ids: List of persona IDs to load DF2 modifiers for (e.g.,
                ["athena-conductor", "hera-strategist"]).

        Returns:
            DF2 modifier content if DF2BehaviorInjector is available and configured,
            empty string otherwise. Does not raise exceptions if DF2 is unavailable.

        Note:
            DF2 integration is optional. If the df2_behavior_injector module is not
            available, this method silently returns empty string without error.

        Example:
            >>> injector = MemoryBasedProtocolInjector()
            >>> modifiers = injector.load_df2_modifiers(["athena-conductor"])
            >>> # Returns modifiers if DF2 available, empty string otherwise
            >>> print(isinstance(modifiers, str))
            True
        """
        try:
            from pathlib import Path
            from df2_behavior_injector import DF2BehaviorInjector

            # Explicit path to avoid incorrect project root detection
            narratives_path = Path.home() / ".claude/config/narratives.json"
            df2_injector = DF2BehaviorInjector(narratives_path=str(narratives_path))
            return df2_injector.inject_for_all_personas("session_start")
        except (ImportError, AttributeError, FileNotFoundError):
            # DF2が利用不可の場合はスキップ
            return ""

    def inject_session_start(self):
        """Inject full session context using Memory Cookbook patterns.

        Main orchestration method that implements the complete 6-step Memory Cookbook
        loading sequence for SessionStart events. Loads previous session summaries,
        core memory, core agents (Athena + Hera), context profile memory, and DF2
        modifiers. Outputs integrated context as JSON to stdout for Claude Code consumption.

        SessionStart: Memory Cookbook準拠の注入

        Loading Sequence:
            1. Previous session summary (Session Boundaries pattern)
            2. Core memory (system.md + agents.md from File-based Memory)
            3. Core agents (Athena + Hera for constant coordination)
            4. Context profile memory (Lazy Loading based on TRINITAS_CONTEXT_PROFILE)
            5. DF2 Behavioral Modifiers (optional persona customization)
            6. Version info and profile metadata

        Environment Variables:
            TRINITAS_MINIMAL_OUTPUT: "1" (default) = minimal systemMessage, "0" = full output
            TRINITAS_VERBOSE: "1" = detailed stderr logging, "0" (default) = silent

        Returns:
            None. Outputs JSON with "systemMessage" key to stdout. Message contains
            integrated context from all loaded sources (minimal or full based on mode).

        Note:
            Minimal mode (default): Shows only version info to Claude, loads context silently.
            Full mode (TRINITAS_MINIMAL_OUTPUT=0): Shows all context to Claude (legacy behavior).
            Verbose mode (TRINITAS_VERBOSE=1): Logs details to stderr for debugging.

        Example:
            >>> injector = MemoryBasedProtocolInjector()
            >>> injector.inject_session_start()
            {"systemMessage": "Trinitas v2.2.4 loaded (Profile: coding)"}
        """

        # 1. 前回セッションサマリー（Session Boundaries）
        previous_session = self.load_previous_session_summary()

        # 2. コアメモリ（File-based Memory）
        core = self.load_core_memory()

        # 3. Athena + Hera常駐（常時協調）
        core_agents = self.load_agent_memory(["athena-conductor", "hera-strategist"])

        # 4. コンテキストプロファイル（Lazy Loading）
        contexts = self.get_context_profile()
        context_memory = self.load_context_memory(contexts)

        # 5. DF2 Behavioral Modifiers
        df2_context = self.load_df2_modifiers(["athena-conductor", "hera-strategist"])

        # Profile information
        profile = os.getenv("TRINITAS_CONTEXT_PROFILE", "coding")

        # Check for minimal output mode (default: enabled)
        minimal_mode = os.getenv("TRINITAS_MINIMAL_OUTPUT", "1") == "1"
        verbose = os.getenv("TRINITAS_VERBOSE", "0") == "1"

        if minimal_mode:
            # Minimal output: only version info shown to Claude
            output = {
                "systemMessage": f"✓ Trinitas v{self.VERSION} loaded (Profile: {profile})"
            }

            # Calculate loaded context size for logging
            total_chars = sum([
                len(previous_session or ""),
                len(core or ""),
                len(core_agents or ""),
                len(context_memory or ""),
                len(df2_context or "")
            ])
            token_estimate = total_chars / 4

            # Verbose logging to stderr (not shown to Claude)
            if verbose:
                print("[Trinitas SessionStart]", file=sys.stderr)
                print(f"  Version: {self.VERSION}", file=sys.stderr)
                print(f"  Profile: {profile}", file=sys.stderr)
                print(f"  Context loaded: ~{token_estimate / 1000:.1f}k tokens", file=sys.stderr)
                print("  Display mode: Minimal (context loaded but not shown to Claude)", file=sys.stderr)
                if previous_session:
                    print("  - Previous session summary loaded", file=sys.stderr)
                if core:
                    print("  - Core memory loaded", file=sys.stderr)
                if core_agents:
                    print("  - Core agents (Athena + Hera) loaded", file=sys.stderr)
                if context_memory:
                    print(f"  - Context profile ({', '.join(contexts)}) loaded", file=sys.stderr)
                if df2_context:
                    print("  - DF2 behavioral modifiers loaded", file=sys.stderr)
        else:
            # Full output: original behavior (show all context to Claude)
            parts = []

            if previous_session:
                parts.append(previous_session)

            if core:
                parts.append(core)

            if core_agents:
                parts.append(f"""
---

## Active Coordination System

**Athena (Harmonious Conductor)** and **Hera (Strategic Commander)** are active.

{core_agents}
""")

            if context_memory:
                parts.append(f"""
---

## Loaded Contexts

{context_memory}
""")

            if df2_context:
                parts.append(f"""
---

{df2_context}
""")

            # バージョン情報
            parts.append(f"""
---

**Trinitas v{self.VERSION}** | Profile: `{profile}` | Memory-based Protocol
""")

            combined = "\n".join(parts)
            output = {"systemMessage": combined}

            # Verbose logging for full mode
            if verbose:
                token_estimate = len(combined) / 4
                print(
                    f"✓ Trinitas v{self.VERSION} | Profile: {profile} | ~{token_estimate / 1000:.1f}k tokens (FULL output mode)",
                    file=sys.stderr,
                )

        # JSON出力（stdout、Claude Code用）
        print(json.dumps(output, ensure_ascii=False))

    def inject_pre_compact(self):
        """Inject minimal context for compact mode using Hierarchical Summarization.

        Implements Level 3 Hierarchical Summarization for context-limited situations.
        Provides a minimal summary of the Trinitas system with only core coordination
        patterns and active personas. Used when full context injection exceeds token limits.

        PreCompact: 階層的要約（Level 3）

        Compact Mode Content:
            - Active coordinators (Athena + Hera)
            - Specialist agents (Artemis, Hestia, Eris, Muses)
            - Context profile name
            - Key coordination patterns (parallel analysis, security-first, etc.)
            - Version info

        Returns:
            None. Outputs JSON with "systemMessage" key to stdout. Message contains
            minimal Level 3 summary for compact mode.

        Note:
            Verbose mode (TRINITAS_VERBOSE=1) prints token estimate to stderr.
            Default mode is silent (no stderr output).

        Example:
            >>> injector = MemoryBasedProtocolInjector()
            >>> injector.inject_pre_compact()
            {"systemMessage": "## Trinitas Core (Level 3 Summary)..."}
        """

        profile = os.getenv("TRINITAS_CONTEXT_PROFILE", "coding")

        # Level 3: 最小限の要約（Hierarchical Summarization）
        summary = f"""
## Trinitas Core (Level 3 Summary)

**Active Coordinators**: Athena + Hera
**Specialists**: Artemis, Hestia, Eris, Muses

**Context Profile**: `{profile}`

**Key Patterns**:
- Parallel analysis coordinated by Athena
- Security-first approach via Hestia
- Strategic execution by Hera
- Knowledge preservation by Muses

---

**Trinitas v{self.VERSION}** | Compact Mode
"""

        output = {"systemMessage": summary}

        # 簡潔なサマリー表示
        verbose = os.getenv("TRINITAS_VERBOSE", "0") == "1"
        if verbose:
            # Verboseモードのみ詳細表示
            token_estimate = len(summary) / 4
            print(
                f"✓ Trinitas v{self.VERSION} | Compact Mode | ~{token_estimate / 1000:.1f}k tokens",
                file=sys.stderr,
            )
        # デフォルトは何も表示しない

        # JSON出力（stdout、Claude Code用）
        print(json.dumps(output, ensure_ascii=False))


def main():
    """Main entry point for protocol injector command-line execution.

    Parses command-line arguments to determine injection mode and executes the
    appropriate method. Supports two modes: SessionStart (full context) and
    PreCompact (minimal hierarchical summary).

    メインエントリーポイント

    Command-line Usage:
        python protocol_injector.py              # SessionStart (default)
        python protocol_injector.py pre_compact  # PreCompact mode

    Note:
        Output is JSON printed to stdout for consumption by Claude Code hooks.

    Example:
        >>> # Run from command line
        >>> python hooks/core/protocol_injector.py
        {"systemMessage": "...full context..."}

        >>> # Compact mode
        >>> python hooks/core/protocol_injector.py pre_compact
        {"systemMessage": "## Trinitas Core (Level 3 Summary)..."}
    """
    injector = MemoryBasedProtocolInjector()

    if len(sys.argv) > 1 and sys.argv[1] == "pre_compact":
        injector.inject_pre_compact()
    else:
        injector.inject_session_start()


if __name__ == "__main__":
    main()
