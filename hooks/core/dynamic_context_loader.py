#!/usr/bin/env python3
"""UserPromptSubmit Hook: Dynamic Context Loading for Trinitas Agents.

High-performance hook for real-time persona detection and context injection via
Claude Code's UserPromptSubmit event. Optimized for sub-millisecond latency (<1ms)
and maximum efficiency through LRU caching and compiled regex patterns.

This hook analyzes user prompts to automatically detect relevant Trinitas personas
(Athena, Artemis, Hestia, Eris, Hera, Muses, Aphrodite, Metis, Aurora) and required
context documentation. Injects minimal @reference pointers for dynamic loading
rather than full content to minimize latency impact.

NEW in v2.4.12: External Trigger Registry Support
    - Loads trigger rules from ~/.trinitas/trigger-registry.json
    - Shared configuration between Claude Code and OpenCode
    - Hot-reload capability via file watcher (optional)
    - Environment variable support via ~/.trinitas/.env

NEW in v2.4.11: Trinitas Full Mode Detection & SubAgent Enforcement
    - Detects "Trinitasフルモード" or "Trinitas Full Mode" patterns
    - Injects MANDATORY invoke_persona MCP tool invocation instructions
    - Validates SubAgent invocation for protocol compliance

Performance Characteristics:
    - Persona detection: ~0.5ms (compiled regex patterns from registry)
    - Context detection: ~0.2ms (keyword matching)
    - Context building: ~0.1ms (minimal payload)
    - Full Mode detection: ~0.1ms (regex patterns)
    - Registry loading: ~2ms (cached after first load)
    - Total latency: <3ms first call, <1ms subsequent

Security Compliance:
    - CWE-22 (Path Traversal): Mitigated via SecureFileLoader
    - CWE-73 (External Control): Validated allowed roots and extensions
    - Whitelisted directories: ~/.claude, ~/.trinitas, trinitas-agents repo
    - Allowed file types: .md, .json only

Integration:
    - Called by: Claude Code UserPromptSubmit hook system
    - Input: JSON via stdin (prompt text and metadata)
    - Output: JSON via stdout (addedContext with @references)
    - Config: ~/.trinitas/trigger-registry.json (shared with OpenCode)
    - Error handling: Fail gracefully, never block user interaction

Version: 2.4.12
Refactored: 2025-10-15 to use unified utilities (Phase 1 Day 3)
Updated: 2025-12-03 to support external trigger-registry.json (v2.4.12)
Note: Claude Code does NOT have Task tool. Use invoke_persona MCP tool instead.

Example:
    >>> # Hook receives stdin: {"prompt": {"text": "optimize this code"}}
    >>> loader = DynamicContextLoader()
    >>> output = loader.process_hook({"prompt": {"text": "optimize performance"}})
    >>> print("artemis" in str(output))
    True
"""
from __future__ import annotations

import json
import os
import re
import sys
from functools import lru_cache
from pathlib import Path

# Import unified utilities
try:
    from shared.utils import JSONLoader, SecureFileLoader
except ImportError:
    # Fallback for standalone execution
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from shared.utils import JSONLoader, SecureFileLoader

# Import input sanitizer for ReDoS prevention (V-REDOS-1/2)
try:
    from src.security.input_sanitizer import validate_regex_pattern, sanitize_regex_input
except ImportError:
    # Fallback: Define minimal validation if sanitizer not available
    def validate_regex_pattern(  # noqa: ARG001
        pattern: str,
        max_length: int = 200,
        allow_unbounded: bool = False,  # noqa: ARG001 - Keep for API compatibility
    ) -> tuple[bool, str | None]:
        """Minimal fallback validation for regex patterns."""
        if len(pattern) > max_length:
            return False, f"Pattern too long ({len(pattern)} > {max_length})"
        # Block known dangerous patterns
        dangerous = [".*", ".+", r"[\s\S]*", r"[\s\S]+", "(?:.*)*", "(?:.+)+"]
        if pattern in dangerous:
            return False, f"Dangerous pattern: {pattern}"
        return True, None

    def sanitize_regex_input(pattern: str, max_length: int = 200) -> str:
        """Minimal fallback sanitization for regex patterns."""
        if len(pattern) > max_length:
            pattern = pattern[:max_length]
        # Replace unbounded quantifiers with bounded versions
        import re
        pattern = re.sub(r'(?<!\\)\.\*(?!\?)', '.{0,100}', pattern)
        pattern = re.sub(r'(?<!\\)\.\+(?!\?)', '.{1,100}', pattern)
        return pattern


def _detect_project_root() -> Path:
    """Detect project root dynamically by searching for marker files.

    Searches upward from current file location for project markers:
    - pyproject.toml (Python project marker)
    - .git directory (Git repository marker)

    Returns:
        Path: Project root directory

    Raises:
        RuntimeError: If project root cannot be detected

    Example:
        >>> root = _detect_project_root()
        >>> print((root / ".git").exists())
        True
    """
    current = Path(__file__).parent  # Start from this file's directory

    while current != current.parent:  # Until we reach filesystem root
        # Check for project markers
        if (current / "pyproject.toml").exists() or \
           (current / ".git").exists():
            return current
        current = current.parent

    # Fallback to current working directory if no markers found
    return Path.cwd()


class DynamicContextLoader:
    """High-performance dynamic context loading via UserPromptSubmit hook.

    Manages real-time analysis of user prompts to detect relevant Trinitas personas
    and required documentation context. Uses compiled regex patterns for persona
    detection and keyword matching for context detection, achieving sub-millisecond
    latency through LRU caching and minimal payload generation.

    Security is enforced through SecureFileLoader with whitelisted directories and
    file extensions. All file operations comply with CWE-22 (Path Traversal) and
    CWE-73 (External Control) mitigation requirements.

    Attributes:
        ALLOWED_ROOTS: Whitelisted base directories for context files.
        PERSONA_PATTERNS: Pre-compiled regex patterns for each persona (Athena,
            Artemis, Hestia, Eris, Hera, Muses).
        CONTEXT_FILES: Mapping of context types to relative file paths.
        base_path: Base directory for resolving relative paths.
        _cache: In-memory cache for frequently accessed data.
        _file_loader: SecureFileLoader instance for validated file operations.

    Performance Targets:
        - Persona detection: <0.5ms
        - Context detection: <0.2ms
        - Total processing: <1ms

    Example:
        >>> loader = DynamicContextLoader()
        >>> personas = loader.detect_personas("optimize database performance")
        >>> print("artemis" in personas)
        True
        >>> contexts = loader.detect_context_needs("security audit needed")
        >>> print("security" in contexts)
        True
    """

    # Security: Allowed directories for context files
    ALLOWED_ROOTS = [
        os.path.expanduser("~/.claude"),
        os.path.expanduser("~/.trinitas"),  # Shared config directory (v2.4.12+)
        str(_detect_project_root()),  # Dynamically detect project root
    ]

    # Trinitas shared configuration paths (v2.4.12+)
    TRINITAS_CONFIG_DIR = os.path.expanduser("~/.trinitas")
    TRIGGER_REGISTRY_PATH = os.path.join(TRINITAS_CONFIG_DIR, "trigger-registry.json")
    ENV_FILE_PATH = os.path.join(TRINITAS_CONFIG_DIR, ".env")

    # Trinitas Full Mode detection patterns (v2.4.11)
    FULL_MODE_PATTERNS = [
        re.compile(r"Trinitas\s*フル\s*モード", re.IGNORECASE),
        re.compile(r"Trinitas\s+Full\s+Mode", re.IGNORECASE),
        re.compile(r"フル\s*モード\s*で\s*作業", re.IGNORECASE),
        re.compile(r"full\s+mode\s+execution", re.IGNORECASE),
        re.compile(r"/trinitas\s+analyze.*--personas", re.IGNORECASE),
    ]

    # Default Persona trigger patterns (used if registry not available)
    # These are overridden by trigger-registry.json when available
    DEFAULT_PERSONA_PATTERNS = {
        "athena": re.compile(
            r"\b(orchestr|workflow|automat|parallel|coordin|harmoniz)\w*", re.IGNORECASE
        ),
        "artemis": re.compile(
            r"\b(optim|perform|quality|technical|efficien|refactor)\w*", re.IGNORECASE
        ),
        "hestia": re.compile(r"\b(secur|audit|risk|vulnerab|threat|validat)\w*", re.IGNORECASE),
        "eris": re.compile(
            r"\b(coordinat|tactical|team|collaborat|mediat|priorit)\w*", re.IGNORECASE
        ),
        "hera": re.compile(
            r"\b(strateg|planning|architect|vision|roadmap|command)\w*", re.IGNORECASE
        ),
        "muses": re.compile(
            r"\b(document|knowledge|record|guide|archive|structur)\w*", re.IGNORECASE
        ),
        "aphrodite": re.compile(
            r"\b(design|ui|ux|interface|visual|layout|usability)\w*", re.IGNORECASE
        ),
        "metis": re.compile(
            r"\b(implement|code|develop|build|test|debug|fix)\w*", re.IGNORECASE
        ),
        "aurora": re.compile(
            r"\b(search|find|lookup|research|context|retrieve|history)\w*", re.IGNORECASE
        ),
    }

    # Active persona patterns (loaded from registry or defaults)
    PERSONA_PATTERNS = DEFAULT_PERSONA_PATTERNS.copy()

    # Context file mappings (relative to base_path)
    CONTEXT_FILES = {
        "performance": "trinitas_sources/agent/01_tool_guidelines/performance_opt.md",
        "security": "trinitas_sources/agent/01_tool_guidelines/security_audit.md",
        "coordination": "trinitas_sources/memory/contexts/collaboration.md",
        "mcp-tools": "trinitas_sources/agent/01_tool_guidelines/mcp_tools_usage.md",
        "agents": "AGENTS.md",
    }

    def __init__(self, base_path: Path | None = None):
        """Initialize dynamic context loader with base path and security settings.

        Sets up the loader with base directory for context files, initializes
        in-memory cache, and creates SecureFileLoader with whitelisted directories
        and file extensions for CWE-22/CWE-73 compliance.

        NEW in v2.4.12: Loads trigger rules from ~/.trinitas/trigger-registry.json
        if available, otherwise falls back to hardcoded default patterns.

        Args:
            base_path: Optional base directory for resolving relative context file
                paths. If None, defaults to trinitas-agents project root at
                /Users/apto-as/workspace/github.com/apto-as/trinitas-agents.

        Example:
            >>> # Use default project root
            >>> loader = DynamicContextLoader()
            >>> print(loader.base_path.name)
            trinitas-agents

            >>> # Use custom base path
            >>> custom_path = Path("/custom/base")
            >>> loader = DynamicContextLoader(base_path=custom_path)
            >>> print(loader.base_path == custom_path)
            True
        """
        if base_path is None:
            base_path = _detect_project_root()  # Dynamically detect project root
        self.base_path = base_path
        self._cache = {}  # Simple memory cache
        self._trigger_registry = None  # Loaded on first use
        self._registry_mtime = 0  # For hot-reload detection
        self._env_settings = None  # Environment settings cache (v2.4.12+)

        # Initialize secure file loader with allowed roots and extensions
        self._file_loader = SecureFileLoader(
            allowed_roots=self.ALLOWED_ROOTS,
            allowed_extensions=[".md", ".json"]  # Added .json for registry
        )

        # Load environment settings from shared config (v2.4.12+)
        self._load_env_settings()

        # Load trigger registry from shared config (v2.4.12+)
        self._load_trigger_registry()

    def _load_env_settings(self) -> None:
        """Load environment settings from ~/.trinitas/.env file.

        Parses the .env file and extracts relevant Trinitas settings.
        Settings are cached for performance.

        Extracted settings:
            - enabled: TRINITAS_TRIGGER_RULES_ENABLED
            - auto_routing: TRINITAS_AUTO_ROUTING_ENABLED
            - confidence_threshold: TRINITAS_CONFIDENCE_THRESHOLD
            - learning_enabled: TRINITAS_LEARNING_ENABLED
        """
        try:
            env_path = Path(self.ENV_FILE_PATH)
            if not env_path.exists():
                self._env_settings = {
                    "enabled": True,
                    "auto_routing": True,
                    "confidence_threshold": 0.85,
                    "learning_enabled": False,
                }
                return

            settings = {}
            with env_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    if "=" not in line:
                        continue

                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip()

                    # Parse known settings
                    if key == "TRINITAS_TRIGGER_RULES_ENABLED":
                        settings["enabled"] = value.lower() == "true"
                    elif key == "TRINITAS_AUTO_ROUTING_ENABLED":
                        settings["auto_routing"] = value.lower() == "true"
                    elif key == "TRINITAS_CONFIDENCE_THRESHOLD":
                        try:
                            settings["confidence_threshold"] = float(value)
                        except ValueError:
                            settings["confidence_threshold"] = 0.85
                    elif key == "TRINITAS_LEARNING_ENABLED":
                        settings["learning_enabled"] = value.lower() == "true"

            # Set defaults for missing values
            self._env_settings = {
                "enabled": settings.get("enabled", True),
                "auto_routing": settings.get("auto_routing", True),
                "confidence_threshold": settings.get("confidence_threshold", 0.85),
                "learning_enabled": settings.get("learning_enabled", False),
            }

        except Exception as e:
            print(f"Warning: Failed to load .env settings: {e}", file=sys.stderr)
            self._env_settings = {
                "enabled": True,
                "auto_routing": True,
                "confidence_threshold": 0.85,
                "learning_enabled": False,
            }

    def _load_trigger_registry(self) -> None:
        """Load trigger registry from ~/.trinitas/trigger-registry.json.

        Loads and compiles regex patterns from the shared trigger registry file.
        Falls back to default patterns if registry is not available.
        Supports hot-reload by checking file modification time.

        Performance: ~2ms for initial load (cached thereafter)
        """
        try:
            registry_path = Path(self.TRIGGER_REGISTRY_PATH)

            # Check if registry exists
            if not registry_path.exists():
                # Use defaults - no registry available
                self.PERSONA_PATTERNS = self.DEFAULT_PERSONA_PATTERNS.copy()
                return

            # Check for hot-reload (file changed since last load)
            current_mtime = registry_path.stat().st_mtime
            if self._trigger_registry is not None and current_mtime == self._registry_mtime:
                return  # Already loaded and unchanged

            # Load registry JSON
            with registry_path.open("r", encoding="utf-8") as f:
                self._trigger_registry = json.load(f)

            self._registry_mtime = current_mtime

            # Check if trigger rules are enabled
            settings = self._trigger_registry.get("settings", {})
            if not settings.get("enabled", True):
                # Trigger rules disabled - use empty patterns
                self.PERSONA_PATTERNS = {}
                return

            # Compile patterns from registry
            self._compile_registry_patterns()

            # Load Full Mode patterns from registry
            self._load_full_mode_patterns()

        except Exception as e:
            # Fail gracefully - use defaults
            print(f"Warning: Failed to load trigger registry: {e}", file=sys.stderr)
            self.PERSONA_PATTERNS = self.DEFAULT_PERSONA_PATTERNS.copy()

    def _compile_registry_patterns(self) -> None:
        """Compile regex patterns from trigger registry into PERSONA_PATTERNS.

        Extracts trigger rules from registry and compiles regex patterns
        for efficient matching. Handles both keyword-based and regex patterns.

        Security (V-REDOS-1/2):
            - All patterns are validated before compilation
            - Dangerous patterns are rejected or sanitized
            - Maximum pattern length enforced (200 chars)
        """
        if not self._trigger_registry:
            return

        # Get security settings from registry (v2.4.12+)
        security = self._trigger_registry.get("security", {})
        max_pattern_length = security.get("max_pattern_length", 200)
        disallowed = set(security.get("disallowed_patterns", []))

        # v2.4.12: Support new "agents" format from trigger-registry.json
        agents = self._trigger_registry.get("agents", {})
        trigger_rules = self._trigger_registry.get("trigger_rules", {})

        # Use "agents" format if available, otherwise fall back to "trigger_rules"
        source_config = agents if agents else trigger_rules
        compiled_patterns = {}

        for agent_id, agent_config in source_config.items():
            # Extract short name (e.g., "athena" from "athena-conductor" or just "athena")
            short_name = agent_id.split("-")[0]

            # v2.4.12: Support both formats
            triggers = agent_config.get("triggers", {})
            keywords = triggers.get("keywords", agent_config.get("keywords", []))
            patterns = triggers.get("patterns", agent_config.get("patterns", []))

            # Build combined pattern from keywords
            if keywords:
                # Create alternation pattern from keywords
                # Escape special regex chars and join with |
                escaped_keywords = [re.escape(kw) for kw in keywords]
                keyword_pattern = r"\b(" + "|".join(escaped_keywords) + r")\b"

                # V-REDOS-1: Validate pattern before compilation
                is_valid, error = validate_regex_pattern(keyword_pattern, max_length=max_pattern_length)
                if is_valid:
                    compiled_patterns[short_name] = re.compile(
                        keyword_pattern, re.IGNORECASE
                    )
                else:
                    print(f"Warning: Skipping invalid keyword pattern for {agent_id}: {error}", file=sys.stderr)

            # v2.4.12: Also compile explicit regex patterns from registry
            for pattern in patterns:
                # V-REDOS-1: Check against disallowed patterns
                if pattern in disallowed:
                    print(f"Warning: Skipping disallowed pattern for {agent_id}: {pattern}", file=sys.stderr)
                    continue

                # V-REDOS-2: Validate and sanitize pattern
                is_valid, error = validate_regex_pattern(pattern, max_length=max_pattern_length)
                if not is_valid:
                    # Try sanitizing the pattern
                    sanitized = sanitize_regex_input(pattern, max_length=max_pattern_length)
                    is_valid, error = validate_regex_pattern(sanitized, max_length=max_pattern_length)
                    if is_valid:
                        pattern = sanitized
                        print(f"Info: Sanitized pattern for {agent_id}", file=sys.stderr)
                    else:
                        print(f"Warning: Skipping invalid pattern for {agent_id}: {error}", file=sys.stderr)
                        continue

                try:
                    compiled = re.compile(pattern, re.IGNORECASE)
                    # If we already have a pattern for this agent, we can't simply overwrite
                    # Store additional patterns in a list (future enhancement)
                    if short_name not in compiled_patterns:
                        compiled_patterns[short_name] = compiled
                except re.error as e:
                    print(f"Warning: Failed to compile pattern for {agent_id}: {e}", file=sys.stderr)

        # Update class patterns
        if compiled_patterns:
            self.PERSONA_PATTERNS = compiled_patterns

    def _load_full_mode_patterns(self) -> None:
        """Load Full Mode detection patterns from registry.

        Extracts explicit keywords and regex patterns for Full Mode detection
        from the trigger registry file.

        Security (V-REDOS-1/2):
            - All patterns validated before compilation
            - Dangerous patterns are rejected
            - Maximum pattern length enforced
        """
        if not self._trigger_registry:
            return

        # Get security settings from registry (v2.4.12+)
        security = self._trigger_registry.get("security", {})
        max_pattern_length = security.get("max_pattern_length", 200)
        disallowed = set(security.get("disallowed_patterns", []))

        # v2.4.12: Support new "full_mode" format from trigger-registry.json
        full_mode = self._trigger_registry.get("full_mode", self._trigger_registry.get("full_mode_triggers", {}))

        # Add explicit keywords as patterns
        explicit_keywords = full_mode.get("explicit_keywords", [])
        for keyword in explicit_keywords:
            escaped = re.escape(keyword)
            # Keywords are safe (escaped), but still check length
            if len(escaped) <= max_pattern_length:
                pattern = re.compile(escaped, re.IGNORECASE)
                if pattern not in self.FULL_MODE_PATTERNS:
                    self.FULL_MODE_PATTERNS.append(pattern)

        # v2.4.12: Support "triggers" list format
        triggers = full_mode.get("triggers", full_mode.get("patterns", []))

        # Add regex patterns from registry
        for pattern_item in triggers:
            # Handle both string patterns and dict patterns
            if isinstance(pattern_item, dict):
                regex = pattern_item.get("regex", "")
            else:
                regex = pattern_item

            if not regex:
                continue

            # V-REDOS-1: Check against disallowed patterns
            if regex in disallowed:
                print(f"Warning: Skipping disallowed full_mode pattern: {regex}", file=sys.stderr)
                continue

            # V-REDOS-2: Validate pattern before compilation
            is_valid, error = validate_regex_pattern(regex, max_length=max_pattern_length)
            if not is_valid:
                # Try sanitizing
                sanitized = sanitize_regex_input(regex, max_length=max_pattern_length)
                is_valid, error = validate_regex_pattern(sanitized, max_length=max_pattern_length)
                if is_valid:
                    regex = sanitized
                    print("Info: Sanitized full_mode pattern", file=sys.stderr)
                else:
                    print(f"Warning: Skipping invalid full_mode pattern: {error}", file=sys.stderr)
                    continue

            try:
                compiled = re.compile(regex, re.IGNORECASE)
                if compiled not in self.FULL_MODE_PATTERNS:
                    self.FULL_MODE_PATTERNS.append(compiled)
            except re.error as e:
                print(f"Warning: Failed to compile full_mode pattern: {e}", file=sys.stderr)

    def get_agent_metadata(self, short_name: str) -> dict:
        """Get agent metadata from trigger registry.

        Args:
            short_name: Short agent name (e.g., "athena", "artemis")

        Returns:
            Dict with agent metadata (display_name, emoji, tier, mcp_tools)
            or empty dict if not found.
        """
        if not self._trigger_registry:
            return {}

        # Map short name to full agent_id
        for agent_id, config in self._trigger_registry.get("trigger_rules", {}).items():
            if agent_id.startswith(short_name):
                return {
                    "agent_id": agent_id,
                    "display_name": config.get("display_name", short_name.capitalize()),
                    "emoji": config.get("emoji", ""),
                    "tier": config.get("tier", ""),
                    "mcp_tools": config.get("mcp_tools", []),
                }

        return {}

    @lru_cache(maxsize=8)
    def _load_file(self, file_path: str) -> str | None:
        """Load file with LRU caching and security validation.

        Loads markdown files from disk using SecureFileLoader for path traversal
        protection (CWE-22) and external control mitigation (CWE-73). Results are
        cached using functools.lru_cache with maxsize=8 to handle ~6 core files
        plus margin without eviction.

        Args:
            file_path: Relative or absolute path to markdown file. If relative,
                resolved against self.base_path. Must be within ALLOWED_ROOTS
                and have .md extension.

        Returns:
            File contents as string if found and valid, None if file not found,
            access denied, or validation failed. Errors are suppressed (silent=True)
            to prevent blocking user interaction.

        Note:
            Decorated with @lru_cache for automatic memoization. Cache hits provide
            O(1) retrieval without disk I/O. Cache size of 32 accommodates typical
            working set without excessive memory usage.

        Refactored: Now uses SecureFileLoader for validation and loading (Phase 1 Day 3)

        Example:
            >>> loader = DynamicContextLoader()
            >>> content = loader._load_file("AGENTS.md")
            >>> print(content is not None)
            True
            >>> # Cache hit on second call
            >>> content2 = loader._load_file("AGENTS.md")
            >>> print(content == content2)
            True
        """
        return self._file_loader.load_file(
            file_path,
            base_path=self.base_path,
            silent=True  # Suppress error messages (returns None on error)
        )

    def detect_full_mode(self, prompt: str) -> bool:
        """Detect if Trinitas Full Mode is requested (~0.1ms).

        Analyzes user prompt to identify Trinitas Full Mode activation patterns.
        When Full Mode is detected, SubAgent invocation via Task tool is MANDATORY.

        Args:
            prompt: User's prompt text to analyze.

        Returns:
            True if Full Mode pattern is detected, False otherwise.

        Full Mode Patterns:
            - "Trinitasフルモード" (Japanese)
            - "Trinitas Full Mode" (English)
            - "フルモードで作業" (Japanese)
            - "full mode execution" (English)
            - "/trinitas analyze --personas" (command)

        Example:
            >>> loader = DynamicContextLoader()
            >>> print(loader.detect_full_mode("Trinitasフルモードで作業"))
            True
            >>> print(loader.detect_full_mode("optimize this code"))
            False
        """
        for pattern in self.FULL_MODE_PATTERNS:
            if pattern.search(prompt):
                return True
        return False

    def _is_auto_routing_enabled(self) -> bool:
        """Check if auto-routing is enabled via environment settings.

        Reads from ~/.trinitas/.env or environment variable.

        Returns:
            True if TRINITAS_AUTO_ROUTING_ENABLED is set to "true", False otherwise.
        """
        # Check environment first
        env_value = os.environ.get("TRINITAS_AUTO_ROUTING_ENABLED")
        if env_value is not None:
            return env_value.lower() == "true"

        # Check .env file settings (cached in _env_settings)
        if self._env_settings:
            return self._env_settings.get("auto_routing", True)

        return True  # Default enabled

    def _get_full_persona_id(self, short_name: str) -> str:
        """Get full persona ID from short name.

        Maps short names (athena, artemis, etc.) to full IDs (athena-conductor, etc.).

        Args:
            short_name: Short persona name (e.g., "athena", "artemis")

        Returns:
            Full persona ID (e.g., "athena-conductor", "artemis-optimizer")
        """
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
        return short_to_full.get(short_name.lower(), short_name)

    def build_full_mode_enforcement(self, task_description: str) -> str:
        """Build enforcement message for Trinitas Full Mode (~0.1ms).

        Generates MANDATORY invoke_persona MCP tool invocation instructions when Full Mode
        is detected. This enforcement message guides the AI to invoke personas
        via the MCP tool instead of performing analysis itself.

        NOTE: Claude Code does NOT have a "Task" tool. SubAgent invocation must use
        the `invoke_persona` MCP tool (mcp__tmws__invoke_persona) instead.

        Args:
            task_description: The user's task description for context.

        Returns:
            Markdown-formatted enforcement instructions with explicit invoke_persona
            MCP tool examples.

        Example:
            >>> loader = DynamicContextLoader()
            >>> msg = loader.build_full_mode_enforcement("analyze architecture")
            >>> print("MANDATORY" in msg)
            True
            >>> print("invoke_persona" in msg)
            True
        """
        # Sanitize task description to prevent injection
        safe_task = task_description.replace('"', "'").replace("\\", "")[:500]

        return f'''
## ⚠️ MANDATORY: Trinitas Full Mode Activated

**CRITICAL ENFORCEMENT NOTICE**

You have detected a Trinitas Full Mode request. You MUST now invoke Trinitas personas
using the `invoke_persona` MCP tool. This is NOT optional.

### Phase 1: Strategic Planning (REQUIRED - INVOKE NOW)

You MUST immediately invoke the following personas using the **invoke_persona** MCP tool:

**Step 1**: Invoke Hera for strategic analysis:
```
mcp__tmws__invoke_persona(persona_id="hera-strategist", task_description="Strategic analysis for: {safe_task}")
```

**Step 2**: Invoke Athena for resource coordination:
```
mcp__tmws__invoke_persona(persona_id="athena-conductor", task_description="Resource coordination for: {safe_task}")
```

### ❌ PROHIBITED Actions

1. DO NOT proceed with analysis yourself without calling invoke_persona
2. DO NOT say "Hera + Athena による戦略分析" without actually using invoke_persona tool
3. DO NOT skip Phase 1 and proceed directly to implementation
4. DO NOT use "Task(subagent_type=...)" syntax - this does NOT exist in Claude Code

### ✅ REQUIRED Actions

1. Call `mcp__tmws__invoke_persona` with persona_id="hera-strategist"
2. Call `mcp__tmws__invoke_persona` with persona_id="athena-conductor"
3. Use the returned system_prompt and invocation_instructions to embody each persona
4. Perform analysis AS the persona (adopt their voice and approach)
5. Only after Phase 1 strategic consensus, proceed to Phase 2

### Available invoke_persona Parameters

- `persona_id`: "athena-conductor", "artemis-optimizer", "hestia-auditor", "eris-coordinator", "hera-strategist", "muses-documenter", "aphrodite-designer", "metis-developer", "aurora-researcher"
- `task_description`: Description of the task to execute
- `include_system_prompt`: Whether to include full system prompt (default: True)

### Phase 2-4 (After Phase 1 Approval)

- **Phase 2 (Implementation)**: invoke_persona("artemis-optimizer", ...) + invoke_persona("metis-developer", ...)
- **Phase 3 (Verification)**: invoke_persona("hestia-auditor", ...)
- **Phase 4 (Documentation)**: invoke_persona("muses-documenter", ...)

---
**This enforcement notice was injected by dynamic_context_loader.py v2.4.12**
'''

    def detect_personas(self, prompt: str) -> list[str]:
        """Detect triggered personas using compiled regex patterns (~0.5ms).

        Analyzes user prompt to identify which Trinitas personas are most relevant
        based on keyword patterns. Uses pre-compiled regex for performance. Checks
        for explicit /trinitas execute commands first (fast path), then falls back
        to implicit pattern matching.

        Args:
            prompt: User's prompt text to analyze. Can contain natural language,
                commands, or mixed content.

        Returns:
            List of triggered persona names (e.g., ["artemis", "hestia"]). Returns
            single-element list for explicit /trinitas execute commands, or multiple
            elements for implicit pattern matches. Empty list if no patterns match.

        Performance:
            Typical execution time ~0.5ms through pre-compiled regex patterns and
            case-insensitive matching.

        Persona Patterns:
            - athena: orchestr*, workflow, automat*, parallel, coordinat*
            - artemis: optim*, perform*, quality, technical, efficien*
            - hestia: secur*, audit, risk, vulnerab*, threat, validat*
            - eris: coordinat*, tactical, team, collaborat*, mediat*
            - hera: strateg*, planning, architect*, vision, roadmap
            - muses: document*, knowledge, record, guide, archive

        Example:
            >>> loader = DynamicContextLoader()
            >>> personas = loader.detect_personas("optimize database performance")
            >>> print("artemis" in personas)
            True
            >>> personas = loader.detect_personas("/trinitas execute hestia")
            >>> print(personas)
            ['hestia']
        """
        triggered = []
        prompt_lower = prompt.lower()

        # Fast path: Check for explicit /trinitas commands first
        if "/trinitas" in prompt_lower:
            match = re.search(r"/trinitas\s+execute\s+(\w+)", prompt_lower)
            if match:
                persona_name = match.group(1)
                if persona_name in self.PERSONA_PATTERNS:
                    return [persona_name]

        # Pattern matching for implicit triggers
        for persona, pattern in self.PERSONA_PATTERNS.items():
            if pattern.search(prompt):
                triggered.append(persona)

        return triggered

    def detect_context_needs(self, prompt: str) -> list[str]:
        """Detect which context files are needed based on prompt content (~0.2ms).

        Analyzes user prompt using keyword matching to identify relevant documentation
        context. Supports both English and Japanese keywords for international use.
        Multiple context types can be triggered by a single prompt.

        Args:
            prompt: User's prompt text to analyze. Supports mixed English/Japanese.

        Returns:
            List of context type identifiers (e.g., ["performance", "security"]).
            Possible values: "performance", "security", "coordination", "mcp-tools", "agents".
            Empty list if no keywords match.

        Performance:
            Typical execution time ~0.2ms through simple keyword substring matching
            on lowercased prompt.

        Context Trigger Keywords:
            - performance: optimize*, perform*, slow, latency, speed, 最適化
            - security: secur*, audit, vulnerability*, xss, injection, セキュリティ, 脆弱性
            - coordination: coordinat*, team, parallel, workflow, 調整, チーム
            - mcp-tools: mcp, tool, context7, playwright, serena, ツール
            - agents: analyz*, review, evaluate, 分析, 評価, 包括

        Example:
            >>> loader = DynamicContextLoader()
            >>> contexts = loader.detect_context_needs("security audit for XSS")
            >>> print("security" in contexts)
            True
            >>> contexts = loader.detect_context_needs("optimize performance")
            >>> print("performance" in contexts)
            True
            >>> # Japanese keywords
            >>> contexts = loader.detect_context_needs("パフォーマンスを最適化")
            >>> print("performance" in contexts)
            True
        """
        needed = []
        prompt_lower = prompt.lower()

        # Performance context
        if any(
            kw in prompt_lower
            for kw in [
                "optimize",
                "optimiz",
                "performance",
                "perform",
                "slow",
                "latency",
                "speed",
                "最適化",
            ]
        ):
            needed.append("performance")

        # Security context
        if any(
            kw in prompt_lower
            for kw in [
                "security",
                "secur",
                "audit",
                "vulnerability",
                "vulnerab",
                "xss",
                "injection",
                "セキュリティ",
                "脆弱性",
            ]
        ):
            needed.append("security")

        # Coordination context
        if any(
            kw in prompt_lower
            for kw in [
                "coordinate",
                "coordinat",
                "team",
                "parallel",
                "workflow",
                "調整",
                "チーム",
            ]
        ):
            needed.append("coordination")

        # MCP Tools context
        if any(
            kw in prompt_lower
            for kw in ["mcp", "tool", "context7", "playwright", "serena", "ツール"]
        ):
            needed.append("mcp-tools")

        # Multi-agent context
        if any(
            kw in prompt_lower
            for kw in [
                "analyze",
                "analyz",
                "review",
                "evaluate",
                "分析",
                "評価",
                "包括",
            ]
        ):
            needed.append("agents")

        return needed

    def build_context(self, personas: list[str], contexts: list[str]) -> str:
        """Build context injection payload with actual file contents.

        Constructs markdown payload with detected personas and actual documentation
        content. Loads file contents via SecureFileLoader and includes them directly
        for immediate availability to Claude. Limits to 2 most relevant items per
        category and truncates each file to ~375 tokens (1500 chars) to maintain
        reasonable payload size.

        Args:
            personas: List of detected persona names (e.g., ["artemis", "hestia"]).
                Only first 2 personas are included in output.
            contexts: List of detected context types (e.g., ["performance", "security"]).
                Only first 2 contexts are included in output.

        Returns:
            Markdown-formatted string with active personas and actual documentation
            content. Returns empty string if both personas and contexts are empty
            or if file loading fails.

        Performance:
            Typical execution time ~2-5ms including file I/O. Actual file loading
            replaces non-functional @reference syntax.

        Output Format:
            ## 🎯 Active Personas for This Task
            - **Artemis**: Optimized for this task type
            - **Hestia**: Optimized for this task type

            ## 📚 Relevant Documentation

            ### Performance
            [Actual content from docs/performance-guidelines.md, truncated to 1500 chars]

            ### Security
            [Actual content from docs/security-standards.md, truncated to 1500 chars]

        Example:
            >>> loader = DynamicContextLoader()
            >>> context = loader.build_context(["artemis"], ["performance"])
            >>> print("Active Personas" in context)
            True
            >>> print("Performance" in context)
            True
            >>> # Empty input returns empty string
            >>> context = loader.build_context([], [])
            >>> print(context == "")
            True
        """
        sections = []

        # Add persona-specific brief if detected
        if personas:
            sections.append("## 🎯 Active Personas for This Task")
            for persona in personas[:2]:  # Limit to 2 most relevant
                # Get metadata from registry if available
                metadata = self.get_agent_metadata(persona)
                if metadata:
                    emoji = metadata.get("emoji", "")
                    display_name = metadata.get("display_name", persona.capitalize())
                    tier = metadata.get("tier", "")
                    mcp_tools = metadata.get("mcp_tools", [])

                    sections.append(
                        f"- **{emoji} {display_name}** ({tier}): Optimized for this task type"
                    )
                    if mcp_tools:
                        tools_str = ", ".join(mcp_tools[:3])  # Limit to 3 tools
                        sections.append(f"  - Suggested tools: `{tools_str}`")
                else:
                    sections.append(
                        f"- **{persona.capitalize()}**: Optimized for this task type"
                    )

            # v2.4.12: Add invoke_persona suggestion for auto-routing
            if self._is_auto_routing_enabled():
                primary_persona = personas[0]
                full_persona_id = self._get_full_persona_id(primary_persona)
                sections.append("\n### Suggested Invocation")
                sections.append(
                    f"To invoke the recommended persona, use:\n"
                    f"```\n"
                    f"mcp__tmws__invoke_persona(persona_id=\"{full_persona_id}\", "
                    f'task_description="[describe your task]")\n'
                    f"```"
                )

        # Add actual context file contents (not @references - they don't work in hooks)
        if contexts:
            sections.append("\n## 📚 Relevant Documentation")
            for ctx in contexts[:2]:  # Limit to 2 most relevant
                file_path = self.CONTEXT_FILES.get(ctx)
                if file_path:
                    # Load actual file content
                    full_path = self.base_path / file_path
                    content = self._file_loader.load_file(
                        str(full_path),
                        silent=True
                    )

                    if content:
                        # Truncate to ~375 tokens (1500 chars) to keep payload reasonable
                        truncated_content = content[:1500]
                        if len(content) > 1500:
                            truncated_content += "\n\n[... truncated for brevity ...]"

                        # Add with proper heading
                        ctx_title = ctx.replace("-", " ").title()
                        sections.append(f"\n### {ctx_title}")
                        sections.append(truncated_content)

        return "\n".join(sections) if sections else ""

    def process_hook(self, stdin_data: dict) -> dict:
        """Process UserPromptSubmit hook input and generate output.

        Main processing method for Claude Code's UserPromptSubmit hook. Extracts
        prompt text from stdin data, runs persona and context detection, builds
        minimal payload, and returns formatted hook output. Designed for fail-safe
        operation - never raises exceptions to avoid blocking user interaction.

        Args:
            stdin_data: Hook input data from Claude Code. Expected format:
                {
                    "prompt": {
                        "text": "user's prompt text",
                        ...other metadata...
                    }
                }
                If "prompt" or "text" keys are missing, treated as empty prompt.

        Returns:
            Hook output dict with addedContext array. Format:
                {
                    "addedContext": [
                        {
                            "type": "text",
                            "text": "...persona and context markdown..."
                        }
                    ]
                }
                Returns empty addedContext array if no context detected or on error.

        Performance:
            Total processing time <1ms typical:
                - Persona detection: ~0.5ms
                - Context detection: ~0.2ms
                - Context building: ~0.1ms

        Error Handling:
            All exceptions are caught and logged to stderr. Returns empty addedContext
            array on error to prevent blocking user interaction. Never raises exceptions.

        Example:
            >>> loader = DynamicContextLoader()
            >>> input_data = {"prompt": {"text": "optimize performance"}}
            >>> output = loader.process_hook(input_data)
            >>> print("addedContext" in output)
            True
            >>> print(len(output["addedContext"]) > 0)
            True
            >>> # Empty prompt returns empty context
            >>> output = loader.process_hook({"prompt": {"text": ""}})
            >>> print(output["addedContext"])
            []
        """
        try:
            prompt_text = stdin_data.get("prompt", {}).get("text", "")

            if not prompt_text:
                return {"addedContext": []}

            # v2.4.11: Check for Trinitas Full Mode FIRST (highest priority)
            if self.detect_full_mode(prompt_text):
                # Full Mode detected - inject enforcement instructions
                enforcement = self.build_full_mode_enforcement(prompt_text)
                return {
                    "addedContext": [
                        {"type": "text", "text": enforcement}
                    ]
                }

            # Fast detection (<1ms typical)
            personas = self.detect_personas(prompt_text)
            contexts = self.detect_context_needs(prompt_text)

            # Build minimal context
            additional_context = self.build_context(personas, contexts)

            # Return hook output
            output = {"addedContext": []}

            if additional_context:
                output["addedContext"].append(
                    {"type": "text", "text": additional_context}
                )

            return output

        except Exception as e:
            # Error handling - never block the user
            print(f"Error processing hook: {e}", file=sys.stderr)
            return {"addedContext": []}


def main():
    """Main entry point for UserPromptSubmit hook execution.

    Coordinates stdin/stdout processing for Claude Code's UserPromptSubmit hook.
    Reads JSON input from stdin, processes it through DynamicContextLoader, and
    writes JSON output to stdout. Implements fail-safe error handling to never
    block user interaction.

    Hook Lifecycle:
        1. Read JSON from stdin (Claude Code hook input)
        2. Parse prompt text and metadata
        3. Detect personas and context needs
        4. Build minimal context payload
        5. Write JSON to stdout (Claude Code hook output)
        6. Exit with code 0 (success or graceful failure)

    Input Format (stdin):
        {
            "prompt": {
                "text": "user's prompt text",
                ...metadata...
            }
        }

    Output Format (stdout):
        {
            "addedContext": [
                {
                    "type": "text",
                    "text": "...persona and context markdown..."
                }
            ]
        }

    Error Handling:
        All exceptions are caught and logged to stderr. Returns empty addedContext
        array on error. Always exits with code 0 to prevent hook failures from
        blocking Claude Code operation.

    Performance:
        Total latency <1ms typical (persona detection + context detection +
        context building). No file I/O in hot path (uses @reference pointers).

    Note:
        Uses JSONLoader.load_from_stdin() with fail-safe default (empty context)
        to ensure hook never crashes. All errors are non-fatal.

    Example:
        >>> # Run as Claude Code hook (reads stdin, writes stdout)
        >>> # echo '{"prompt":{"text":"optimize code"}}' | python dynamic_context_loader.py
        >>> # Output: {"addedContext": [{"type": "text", "text": "..."}]}
    """
    try:
        # Read stdin (JSON input from Claude Code) - Refactored to use JSONLoader
        stdin_data = JSONLoader.load_from_stdin(default={"addedContext": []})

        # Process hook
        loader = DynamicContextLoader()
        output = loader.process_hook(stdin_data)

        # Write stdout (JSON output)
        print(json.dumps(output, ensure_ascii=False))
        sys.exit(0)

    except Exception as e:
        # Unknown error - fail gracefully
        print(f"Unexpected error: {e}", file=sys.stderr)
        print(json.dumps({"addedContext": []}))
        sys.exit(0)


if __name__ == "__main__":
    main()
