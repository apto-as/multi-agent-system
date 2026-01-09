#!/usr/bin/env python3
"""UserPromptSubmit Hook: Dynamic Context Loading for Trinitas Agents.

High-performance hook for real-time persona detection and context injection via
Claude Code's UserPromptSubmit event. Optimized for sub-millisecond latency (<1ms)
and maximum efficiency through LRU caching and compiled regex patterns.

This hook analyzes user prompts to automatically detect relevant Trinitas personas
(Athena, Artemis, Hestia, Eris, Hera, Muses) and required context documentation.
Injects minimal @reference pointers for dynamic loading rather than full content
to minimize latency impact.

**NEW in v2.4.11**: Trinitas Full Mode Detection & SubAgent Enforcement
    - Detects "Trinitasフルモード" or "Trinitas Full Mode" patterns
    - Injects MANDATORY Task tool invocation instructions in addedContext
    - References SUBAGENT_EXECUTION_RULES.md for enforcement

**NEW in v2.4.24**: NarrativeAutoLoader Integration (Issue #1)
    - Intercepts Task tool invocations for SubAgent narrative enrichment
    - Calls TMWS `enrich_subagent_prompt` MCP tool for automatic context injection
    - Client-side caching with 5-minute TTL for performance
    - Feature flag: TMWS_NARRATIVE_ENRICHMENT env var (default: true)
    - Graceful degradation when TMWS unavailable

Performance Characteristics:
    - Persona detection: ~0.5ms (compiled regex patterns)
    - Context detection: ~0.2ms (keyword matching)
    - Context building: ~0.1ms (minimal payload)
    - Full Mode detection: ~0.1ms (simple pattern matching)
    - Narrative enrichment: <50ms (with caching)
    - Total latency: <1ms typical (without TMWS call)

Security Compliance:
    - CWE-22 (Path Traversal): Mitigated via SecureFileLoader
    - CWE-73 (External Control): Validated allowed roots and extensions
    - CWE-918 (SSRF): TMWS URL validated to localhost only
    - Whitelisted directories: ~/.claude, trinitas-agents repo
    - Allowed file types: .md only

Integration:
    - Called by: Claude Code UserPromptSubmit hook system
    - Input: JSON via stdin (prompt text and metadata)
    - Output: JSON via stdout (addedContext with @references)
    - Error handling: Fail gracefully, never block user interaction
    - TMWS Integration: Calls enrich_subagent_prompt MCP tool

Version: 2.4.25
Updated: 2025-12-22 - Security fixes per Hestia audit: SSRF protection, input validation

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
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from collections import OrderedDict
from dataclasses import dataclass
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Import unified utilities
try:
    from shared.utils import JSONLoader, SecureFileLoader
except ImportError:
    # Fallback for standalone execution
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from shared.utils import JSONLoader, SecureFileLoader

# Import httpx for TMWS communication (with fallback)
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    logger.warning("httpx not available, TMWS narrative enrichment disabled")

# Import urllib for URL validation
import urllib.parse


# ==================== Security Constants ====================
# Maximum prompt length to prevent memory exhaustion (10KB)
MAX_PROMPT_LENGTH = 10 * 1024

# Allowed hosts for TMWS URL (SSRF protection - CWE-918)
ALLOWED_TMWS_HOSTS = frozenset(['localhost', '127.0.0.1', '::1'])


def _validate_tmws_url(url: str) -> bool:
    """Validate TMWS URL is localhost only (CWE-918 SSRF mitigation).

    Args:
        url: URL to validate

    Returns:
        True if URL points to localhost, False otherwise
    """
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname in ALLOWED_TMWS_HOSTS
    except Exception:
        return False


# ==================== Feature Flags ====================
# TMWS Narrative Enrichment feature flag (Issue #1)
# Set to "false" to disable narrative enrichment via TMWS
ENABLE_NARRATIVE_ENRICHMENT = os.environ.get("TMWS_NARRATIVE_ENRICHMENT", "true").lower() == "true"

# TMWS configuration with validation
_tmws_url_raw = os.environ.get("TMWS_URL", "http://localhost:8000")
if not _validate_tmws_url(_tmws_url_raw):
    logger.warning(f"TMWS URL '{_tmws_url_raw}' is not localhost, defaulting to localhost:8000")
    TMWS_URL = "http://localhost:8000"
else:
    TMWS_URL = _tmws_url_raw
TMWS_TIMEOUT_SECONDS = float(os.environ.get("TMWS_TIMEOUT", "5.0"))  # 5 second max timeout


# ==================== Narrative Cache ====================
@dataclass
class CachedNarrative:
    """Cached narrative entry with TTL management."""
    content: str
    enriched_prompt_template: str
    persona_id: str
    source: str
    loaded_at: float  # Unix timestamp

    def is_expired(self, ttl_seconds: float = 300.0) -> bool:
        """Check if cache entry is expired (default 5 min TTL)."""
        return time.time() - self.loaded_at > ttl_seconds


class NarrativeCache:
    """Client-side LRU cache for narrative enrichment results.

    Performance optimization: Caches enriched narratives to avoid
    redundant TMWS calls during high-frequency SubAgent invocations.

    Attributes:
        _cache: OrderedDict for LRU eviction
        _max_size: Maximum cache entries (default: 20)
        _ttl_seconds: Cache entry TTL (default: 300s / 5 min)
    """

    def __init__(self, max_size: int = 20, ttl_seconds: float = 300.0):
        """Initialize narrative cache.

        Args:
            max_size: Maximum number of cached entries
            ttl_seconds: Time-to-live for cache entries
        """
        self._cache: OrderedDict[str, CachedNarrative] = OrderedDict()
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds

    def get(self, subagent_type: str) -> Optional[CachedNarrative]:
        """Get cached narrative if present and not expired.

        Args:
            subagent_type: SubAgent type key (e.g., "hera-strategist")

        Returns:
            CachedNarrative if found and valid, None otherwise
        """
        if subagent_type not in self._cache:
            return None

        entry = self._cache[subagent_type]
        if entry.is_expired(self._ttl_seconds):
            # Remove expired entry
            del self._cache[subagent_type]
            return None

        # Move to end (LRU)
        self._cache.move_to_end(subagent_type)
        return entry

    def set(self, subagent_type: str, entry: CachedNarrative) -> None:
        """Cache a narrative entry.

        Args:
            subagent_type: SubAgent type key
            entry: Narrative entry to cache
        """
        # Remove if exists (to update order)
        if subagent_type in self._cache:
            del self._cache[subagent_type]

        # Add to end (most recent)
        self._cache[subagent_type] = entry

        # Evict oldest if over limit
        while len(self._cache) > self._max_size:
            self._cache.popitem(last=False)

    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()


# Global narrative cache instance
_narrative_cache = NarrativeCache()


# ==================== TMWS MCP Client ====================
class TMWSNarrativeClient:
    """Client for TMWS NarrativeAutoLoader MCP integration.

    Provides synchronous HTTP communication with TMWS server to call
    the `enrich_subagent_prompt` MCP tool. Implements graceful degradation
    when TMWS is unavailable.

    Security:
        - CWE-918 (SSRF): Only localhost URLs allowed
        - Timeout protection: 5 second maximum
        - Connection pooling disabled for hook execution

    Performance:
        - Target latency: <50ms including network
        - Cache integration reduces TMWS calls by >95%
    """

    # SubAgent type to persona ID mapping (mirrors TMWS NarrativeAutoLoader)
    SUBAGENT_TO_PERSONA = {
        # Tier 0: Orchestrator
        "clotho-orchestrator": "clotho",
        "lachesis-support": "lachesis",
        # Tier 1: Strategic
        "hera-strategist": "hera",
        "athena-conductor": "athena",
        # Tier 2: Specialist
        "artemis-optimizer": "artemis",
        "hestia-auditor": "hestia",
        "eris-coordinator": "eris",
        "muses-documenter": "muses",
        # Tier 3: Support
        "aphrodite-designer": "aphrodite",
        "metis-developer": "metis",
        "aurora-researcher": "aurora",
    }

    def __init__(self, tmws_url: str = TMWS_URL, timeout: float = TMWS_TIMEOUT_SECONDS):
        """Initialize TMWS client.

        Args:
            tmws_url: TMWS server URL (default: localhost:8000)
            timeout: Request timeout in seconds (default: 5.0)
        """
        self.tmws_url = tmws_url
        self.timeout = timeout
        self._available: Optional[bool] = None

    def is_subagent_type(self, text: str) -> bool:
        """Check if text is a known subagent_type.

        Args:
            text: Text to check

        Returns:
            True if text matches a known subagent_type
        """
        return text.lower() in self.SUBAGENT_TO_PERSONA

    def extract_subagent_type_from_prompt(self, prompt: str) -> Optional[str]:
        """Extract subagent_type from Task tool invocation patterns.

        Detects patterns like:
        - Task(subagent_type="hera-strategist", ...)
        - subagent_type: "artemis-optimizer"
        - SubAgent: hestia-auditor

        Args:
            prompt: User prompt text

        Returns:
            Extracted subagent_type or None if not found

        Security:
            - Input length validated (max 10KB) to prevent ReDoS
            - Only whitelisted subagent_types are returned
        """
        # Security: Validate input length to prevent ReDoS attacks
        if not prompt or len(prompt) > MAX_PROMPT_LENGTH:
            return None

        # Pattern 1: Task(subagent_type="xxx", ...)
        match = re.search(
            r'Task\s*\(\s*subagent_type\s*=\s*["\']([^"\']+)["\']',
            prompt,
            re.IGNORECASE
        )
        if match:
            subagent_type = match.group(1).lower()
            if subagent_type in self.SUBAGENT_TO_PERSONA:
                return subagent_type

        # Pattern 2: subagent_type: "xxx" (YAML-like)
        match = re.search(
            r'subagent_type\s*:\s*["\']?([a-z-]+)["\']?',
            prompt,
            re.IGNORECASE
        )
        if match:
            subagent_type = match.group(1).lower()
            if subagent_type in self.SUBAGENT_TO_PERSONA:
                return subagent_type

        # Pattern 3: Explicit SubAgent reference
        match = re.search(
            r'(?:SubAgent|subagent)\s*:\s*([a-z-]+)',
            prompt,
            re.IGNORECASE
        )
        if match:
            subagent_type = match.group(1).lower()
            if subagent_type in self.SUBAGENT_TO_PERSONA:
                return subagent_type

        return None

    def check_available(self) -> bool:
        """Check if TMWS server is available.

        Returns:
            True if TMWS is reachable, False otherwise
        """
        if not HTTPX_AVAILABLE:
            return False

        # Use cached availability for performance
        if self._available is not None:
            return self._available

        try:
            with httpx.Client(timeout=1.0) as client:
                response = client.get(f"{self.tmws_url}/health")
                self._available = response.status_code == 200
        except Exception:
            self._available = False

        return self._available

    def enrich_subagent_prompt(
        self,
        subagent_type: str,
        original_prompt: str
    ) -> Tuple[str, bool, str]:
        """Call TMWS enrich_subagent_prompt MCP tool.

        Args:
            subagent_type: SubAgent type (e.g., "hera-strategist")
            original_prompt: Original prompt to enrich

        Returns:
            Tuple of (enriched_prompt, narrative_loaded, source)
            On error, returns (original_prompt, False, "error")

        Performance:
            Target: <50ms including network round-trip
        """
        # Check cache first
        cached = _narrative_cache.get(subagent_type)
        if cached:
            # Apply cached template to new prompt
            enriched = cached.enriched_prompt_template.replace(
                "{{ORIGINAL_PROMPT}}", original_prompt
            )
            return enriched, True, "cache"

        # Check TMWS availability
        if not self.check_available():
            return original_prompt, False, "tmws_unavailable"

        try:
            # Call TMWS MCP tool via HTTP
            # Note: TMWS exposes MCP tools via /api/v1/mcp/call endpoint
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    f"{self.tmws_url}/api/v1/mcp/call",
                    json={
                        "tool": "enrich_subagent_prompt",
                        "arguments": {
                            "subagent_type": subagent_type,
                            "original_prompt": original_prompt
                        }
                    },
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code != 200:
                    logger.warning(
                        f"TMWS enrich_subagent_prompt failed: {response.status_code}"
                    )
                    return original_prompt, False, "tmws_error"

                result = response.json()

                # Extract enriched prompt from result
                enriched_prompt = result.get("enriched_prompt", original_prompt)
                narrative_loaded = result.get("narrative_loaded", False)
                source = result.get("source", "unknown")

                # Cache the result (store template for reuse)
                if narrative_loaded:
                    # Create template by replacing original prompt with placeholder
                    template = enriched_prompt.replace(
                        original_prompt, "{{ORIGINAL_PROMPT}}"
                    )
                    _narrative_cache.set(
                        subagent_type,
                        CachedNarrative(
                            content=enriched_prompt,
                            enriched_prompt_template=template,
                            persona_id=result.get("persona_id", ""),
                            source=source,
                            loaded_at=time.time()
                        )
                    )

                return enriched_prompt, narrative_loaded, source

        except httpx.TimeoutException:
            logger.warning("TMWS enrich_subagent_prompt timeout")
            return original_prompt, False, "timeout"
        except Exception as e:
            logger.warning(f"TMWS enrich_subagent_prompt error: {e}")
            return original_prompt, False, "error"


# Global TMWS client instance (lazy initialization)
_tmws_client: Optional[TMWSNarrativeClient] = None


def get_tmws_client() -> TMWSNarrativeClient:
    """Get or create global TMWS client instance.

    Returns:
        TMWSNarrativeClient singleton
    """
    global _tmws_client
    if _tmws_client is None:
        _tmws_client = TMWSNarrativeClient()
    return _tmws_client


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
        str(_detect_project_root()),  # Dynamically detect project root
    ]

    # Trinitas Full Mode detection patterns (v2.4.11)
    FULL_MODE_PATTERNS = [
        re.compile(r"Trinitas\s*フル\s*モード", re.IGNORECASE),
        re.compile(r"Trinitas\s+Full\s+Mode", re.IGNORECASE),
        re.compile(r"フル\s*モード\s*で\s*作業", re.IGNORECASE),
        re.compile(r"full\s+mode\s+execution", re.IGNORECASE),
        re.compile(r"/trinitas\s+analyze.*--personas", re.IGNORECASE),
    ]

    # Persona trigger patterns (compiled once for performance)
    PERSONA_PATTERNS = {
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
    }

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

        Args:
            base_path: Optional base directory for resolving relative context file
                paths. If None, defaults to the detected project root (searched
                upward from this file for .git or pyproject.toml markers).

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

        # Initialize secure file loader with allowed roots and extensions
        self._file_loader = SecureFileLoader(
            allowed_roots=self.ALLOWED_ROOTS,
            allowed_extensions=[".md"]
        )

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

    def detect_full_mode(self, prompt: str) -> bool:
        """Detect if Trinitas Full Mode is requested (~0.1ms).

        Checks for explicit Full Mode trigger patterns in the prompt.
        This is a fast path check before persona detection.

        Args:
            prompt: User's prompt text to analyze.

        Returns:
            True if Full Mode is detected, False otherwise.

        Patterns Detected:
            - "Trinitasフルモード" (Japanese)
            - "Trinitas Full Mode" (English)
            - "フルモードで作業" (Japanese)
            - "full mode execution" (English)
            - "/trinitas analyze" with "--personas"

        Example:
            >>> loader = DynamicContextLoader()
            >>> loader.detect_full_mode("Trinitasフルモードで作業")
            True
            >>> loader.detect_full_mode("simple task")
            False
        """
        for pattern in self.FULL_MODE_PATTERNS:
            if pattern.search(prompt):
                return True
        return False

    def build_full_mode_enforcement(self, task_description: str) -> str:
        """Build Task tool invocation enforcement instructions for Full Mode.

        Generates explicit Task tool invocation commands that MUST be executed
        when Trinitas Full Mode is triggered. This is the core enforcement
        mechanism to ensure SubAgents are actually invoked.

        Args:
            task_description: The user's task description for SubAgent prompts.

        Returns:
            Markdown-formatted enforcement instructions with explicit Task tool
            invocation commands.

        Note:
            This method generates prompts that strongly encourage the AI to
            use the Task tool with specific subagent_type parameters.
            It cannot FORCE tool invocation (that would require Claude Code API
            changes), but it makes the expected behavior extremely clear.
        """
        # Sanitize task description (remove quotes that could break JSON)
        safe_task = task_description.replace('"', "'").replace("\\", "")[:500]

        return f'''
## ⚠️ MANDATORY: Trinitas Full Mode Activated

**CRITICAL ENFORCEMENT NOTICE**

You have detected a Trinitas Full Mode request. You MUST now invoke SubAgents
using the Task tool. This is NOT optional.

### Phase 1: Strategic Planning (REQUIRED - INVOKE NOW)

You MUST immediately invoke the following SubAgents **in parallel** (single message, multiple Task tool calls):

```
Task(subagent_type="hera-strategist", prompt="Strategic analysis for: {safe_task}")
Task(subagent_type="athena-conductor", prompt="Resource coordination for: {safe_task}")
```

### ❌ PROHIBITED Actions

1. DO NOT proceed with analysis yourself without invoking SubAgents
2. DO NOT say "Hera + Athena による戦略分析" without actually using Task tool
3. DO NOT skip Phase 1 and proceed directly to implementation

### ✅ REQUIRED Actions

1. Invoke `hera-strategist` SubAgent via Task tool
2. Invoke `athena-conductor` SubAgent via Task tool
3. Wait for their results before proceeding
4. Only after Phase 1 approval, proceed to Phase 2

### Reference

Full protocol details: @SUBAGENT_EXECUTION_RULES.md

---
**This enforcement notice was injected by dynamic_context_loader.py v2.4.24**
'''

    def enrich_subagent_prompt(self, prompt: str) -> Tuple[str, bool, str]:
        """Enrich SubAgent prompt with persona narrative via TMWS.

        NEW in v2.4.24: NarrativeAutoLoader Integration (Issue #1)

        Detects Task tool invocations in the prompt and enriches them with
        persona narrative context via the TMWS `enrich_subagent_prompt` MCP tool.

        Args:
            prompt: User's prompt text that may contain Task tool invocations.

        Returns:
            Tuple of (enriched_prompt, was_enriched, source) where:
                - enriched_prompt: The prompt with narrative context injected
                - was_enriched: True if enrichment was successful
                - source: "cache", "base", "evolved", "error", or "disabled"

        Performance:
            - Cache hit: <1ms
            - TMWS call: <50ms target

        Error Handling:
            On any error, returns original prompt unchanged (graceful degradation).

        Example:
            >>> loader = DynamicContextLoader()
            >>> prompt = 'Task(subagent_type="hera-strategist", prompt="Analyze...")'
            >>> enriched, success, source = loader.enrich_subagent_prompt(prompt)
            >>> print(success)  # True if TMWS available
            True
        """
        # Check feature flag first
        if not ENABLE_NARRATIVE_ENRICHMENT:
            return prompt, False, "disabled"

        # Check if httpx is available
        if not HTTPX_AVAILABLE:
            return prompt, False, "httpx_unavailable"

        try:
            # Get TMWS client
            client = get_tmws_client()

            # Extract subagent_type from prompt
            subagent_type = client.extract_subagent_type_from_prompt(prompt)

            if not subagent_type:
                # No SubAgent invocation detected, return original
                return prompt, False, "no_subagent"

            # Call TMWS to enrich the prompt
            enriched, loaded, source = client.enrich_subagent_prompt(
                subagent_type, prompt
            )

            return enriched, loaded, source

        except Exception as e:
            # Graceful degradation - return original prompt
            print(f"[narrative_enrichment] Error: {e}", file=sys.stderr)
            return prompt, False, "error"

    def build_narrative_enrichment_context(
        self,
        subagent_type: str,
        original_prompt: str
    ) -> Optional[str]:
        """Build narrative context injection for SubAgent invocation.

        Creates a context block that includes the enriched narrative for
        the specified SubAgent type. This is injected as addedContext
        to guide the AI's behavior.

        Args:
            subagent_type: The SubAgent type (e.g., "hera-strategist")
            original_prompt: The original task prompt

        Returns:
            Markdown-formatted context string, or None if enrichment failed.

        Example:
            >>> loader = DynamicContextLoader()
            >>> context = loader.build_narrative_enrichment_context(
            ...     "artemis-optimizer",
            ...     "Optimize this code for performance"
            ... )
            >>> print("Persona Context" in context)
            True
        """
        if not ENABLE_NARRATIVE_ENRICHMENT or not HTTPX_AVAILABLE:
            return None

        try:
            client = get_tmws_client()

            # Get enriched prompt from TMWS
            enriched, loaded, source = client.enrich_subagent_prompt(
                subagent_type, original_prompt
            )

            if not loaded:
                return None

            # Build context injection block
            persona_id = TMWSNarrativeClient.SUBAGENT_TO_PERSONA.get(
                subagent_type.lower(), subagent_type
            )

            return f'''
## 🎭 Persona Narrative Loaded (NarrativeAutoLoader v2.4.24)

**SubAgent**: {subagent_type}
**Persona**: {persona_id.capitalize()}
**Source**: {source}

The following narrative context has been automatically loaded for this SubAgent invocation:

---
{enriched}
---

*Auto-enriched by TMWS NarrativeAutoLoader*
'''

        except Exception as e:
            print(f"[narrative_enrichment] Context build error: {e}", file=sys.stderr)
            return None

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
                sections.append(
                    f"- **{persona.capitalize()}**: Optimized for this task type"
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

            # Return hook output
            output = {"addedContext": []}

            # NEW v2.4.11: Check for Trinitas Full Mode FIRST (highest priority)
            if self.detect_full_mode(prompt_text):
                # Inject MANDATORY Task tool invocation instructions
                enforcement = self.build_full_mode_enforcement(prompt_text)
                output["addedContext"].append(
                    {"type": "text", "text": enforcement}
                )
                # Still continue with regular detection for additional context
                # but the enforcement notice takes priority

            # NEW v2.4.24: NarrativeAutoLoader Integration (Issue #1)
            # Detect and enrich SubAgent invocations with persona narratives
            if ENABLE_NARRATIVE_ENRICHMENT and HTTPX_AVAILABLE:
                try:
                    client = get_tmws_client()
                    subagent_type = client.extract_subagent_type_from_prompt(prompt_text)

                    if subagent_type:
                        # Build narrative enrichment context
                        narrative_context = self.build_narrative_enrichment_context(
                            subagent_type, prompt_text
                        )
                        if narrative_context:
                            output["addedContext"].append(
                                {"type": "text", "text": narrative_context}
                            )
                except Exception as e:
                    # Graceful degradation - continue without enrichment
                    print(
                        f"[narrative_enrichment] Enrichment failed, continuing: {e}",
                        file=sys.stderr
                    )

            # Fast detection (<1ms typical)
            personas = self.detect_personas(prompt_text)
            contexts = self.detect_context_needs(prompt_text)

            # Build minimal context
            additional_context = self.build_context(personas, contexts)

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
