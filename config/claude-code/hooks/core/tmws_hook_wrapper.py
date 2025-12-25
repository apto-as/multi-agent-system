#!/usr/bin/env python3
"""TMWS Hook Wrapper: Thin Python wrapper for tmws-hook CLI binary.

Provides a 3-tier fallback mechanism for TMWS operations:
1. tmws-hook binary (fastest, Go implementation)
2. TMWS HTTP API direct call (fallback)
3. Local minimal implementation (graceful degradation)

This wrapper enables seamless integration with existing Python hooks while
leveraging the performance benefits of the Go-based tmws-hook binary.

Environment Variables:
    TMWS_USE_CLI: Set to "true" to enable CLI-first mode (default: "false")
    TMWS_HOOK_PATH: Custom path to tmws-hook binary (default: "tmws-hook" in PATH)
    TMWS_URL: TMWS server URL for HTTP fallback (default: "http://localhost:8000")
    TMWS_TIMEOUT: Timeout in seconds (default: "5.0")

Version: 1.0.0
Created: 2025-12-25
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Configure logging
logger = logging.getLogger(__name__)

# Import httpx for HTTP fallback (optional)
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


# ==================== Constants ====================

# Environment variable for CLI mode toggle
TMWS_USE_CLI = os.environ.get("TMWS_USE_CLI", "false").lower() == "true"

# Path to tmws-hook binary (can be overridden)
TMWS_HOOK_PATH = os.environ.get("TMWS_HOOK_PATH", "tmws-hook")

# TMWS server URL for HTTP fallback (unified to 6231)
TMWS_URL = os.environ.get("TMWS_URL", "http://localhost:6231")

# Allowed CLI directories (CWE-426 path validation)
ALLOWED_CLI_DIRS = frozenset([
    '/usr/local/bin',
    '/opt/tmws/bin',
    str(Path.home() / '.tmws' / 'bin'),
    str(Path.home() / '.local' / 'bin'),
])

# Timeout in seconds
TMWS_TIMEOUT = float(os.environ.get("TMWS_TIMEOUT", "5.0"))

# Maximum input size (10KB) for security
MAX_INPUT_SIZE = 10 * 1024

# Allowed TMWS hosts (SSRF protection)
ALLOWED_TMWS_HOSTS = frozenset(['localhost', '127.0.0.1', '::1'])

# Known SubAgent types (whitelist for validation)
KNOWN_SUBAGENT_TYPES = frozenset([
    # Tier 0: Orchestrator
    "clotho-orchestrator",
    "lachesis-support",
    # Tier 1: Strategic
    "hera-strategist",
    "athena-conductor",
    # Tier 2: Specialist
    "artemis-optimizer",
    "hestia-auditor",
    "eris-coordinator",
    "muses-documenter",
    # Tier 3: Support
    "aphrodite-designer",
    "metis-developer",
    "aurora-researcher",
])


# ==================== Data Classes ====================

@dataclass
class TMWSResult:
    """Result from TMWS operation."""
    success: bool
    data: Dict[str, Any]
    source: str  # "cli", "http", "local", "error"
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "data": self.data,
            "source": self.source,
            "error": self.error,
        }


# ==================== Helper Functions ====================

def _validate_tmws_url(url: str) -> bool:
    """Validate TMWS URL is localhost only (CWE-918 SSRF mitigation)."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname in ALLOWED_TMWS_HOSTS
    except Exception:
        return False


def _validate_cli_path(cli_path: str) -> Optional[str]:
    """Validate CLI path is in an allowed directory (CWE-426 mitigation).

    Args:
        cli_path: Path to CLI binary

    Returns:
        Validated path or None if invalid
    """
    if not cli_path:
        return None

    # If it's just a command name (no path separator), trust PATH resolution
    if os.sep not in cli_path and cli_path == "tmws-hook":
        return cli_path

    # Resolve to absolute path
    try:
        resolved = Path(cli_path).resolve()
    except Exception:
        return None

    # Check if in allowed directory
    for allowed_dir in ALLOWED_CLI_DIRS:
        try:
            allowed_path = Path(allowed_dir).resolve()
            if str(resolved).startswith(str(allowed_path) + os.sep):
                # Verify file exists and is executable
                if resolved.exists() and os.access(resolved, os.X_OK):
                    return str(resolved)
        except Exception:
            continue

    logger.warning(f"CLI path not in allowed directory: {cli_path}")
    return None


def _sanitize_error(error: str) -> str:
    """Sanitize error messages to remove sensitive information.

    Removes file paths, stack traces, and internal details.

    Args:
        error: Error message to sanitize

    Returns:
        Sanitized error message
    """
    import re

    if not error or not isinstance(error, str):
        return "Unknown error"

    sanitized = error

    # Remove Unix file paths
    sanitized = re.sub(r'(?:/[\w.-]+)+(?::\d+)?', '[path]', sanitized)

    # Remove Windows file paths
    sanitized = re.sub(r'(?:[A-Za-z]:\\[\w\\.-]+)+(?::\d+)?', '[path]', sanitized)

    # Remove Python stack trace lines
    sanitized = re.sub(r'File "[^"]+", line \d+', '[stack]', sanitized)
    sanitized = re.sub(r'^\s+at\s+.+$', '', sanitized, flags=re.MULTILINE)

    # Remove environment variable values
    sanitized = re.sub(r'=/[^\s]+', '=[value]', sanitized)

    # Truncate to reasonable length
    if len(sanitized) > 200:
        sanitized = sanitized[:200] + "..."

    return sanitized.strip() or "Operation failed"


def _find_tmws_hook_binary() -> Optional[str]:
    """Find tmws-hook binary in PATH or allowed directories."""
    # Check custom path first (with validation)
    if TMWS_HOOK_PATH != "tmws-hook":
        validated = _validate_cli_path(TMWS_HOOK_PATH)
        if validated:
            return validated

    # Search in PATH
    path_binary = shutil.which("tmws-hook")
    if path_binary:
        return path_binary

    # Search in allowed directories
    for allowed_dir in ALLOWED_CLI_DIRS:
        candidate = Path(allowed_dir) / "tmws-hook"
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)

    return None


def _validate_input_size(data: str) -> bool:
    """Validate input size to prevent memory exhaustion."""
    return len(data) <= MAX_INPUT_SIZE


# ==================== Main Wrapper Class ====================

class TMWSHookWrapper:
    """Thin wrapper for tmws-hook CLI binary with 3-tier fallback.

    Provides a unified interface for TMWS operations with automatic
    fallback from CLI binary to HTTP API to local minimal implementation.

    Tier 1: tmws-hook binary (Go implementation, fastest)
    Tier 2: TMWS HTTP API (Python httpx)
    Tier 3: Local minimal implementation (graceful degradation)

    Attributes:
        binary_path: Path to tmws-hook binary (None if not found)
        tmws_url: TMWS server URL for HTTP fallback
        timeout: Timeout in seconds for operations
        use_cli: Whether CLI-first mode is enabled

    Example:
        >>> wrapper = TMWSHookWrapper()
        >>> result = wrapper.enrich_prompt("hera-strategist", "Analyze this...")
        >>> print(result.success)
        True
        >>> print(result.source)  # "cli", "http", or "local"
        'cli'
    """

    def __init__(
        self,
        use_cli: bool = TMWS_USE_CLI,
        tmws_url: str = TMWS_URL,
        timeout: float = TMWS_TIMEOUT,
    ):
        """Initialize wrapper with configuration.

        Args:
            use_cli: Enable CLI-first mode (default: from TMWS_USE_CLI env)
            tmws_url: TMWS server URL for HTTP fallback
            timeout: Timeout in seconds for operations
        """
        self.use_cli = use_cli
        self.timeout = timeout

        # Validate and set TMWS URL
        if _validate_tmws_url(tmws_url):
            self.tmws_url = tmws_url
        else:
            logger.warning(f"Invalid TMWS URL '{tmws_url}', using localhost:8000")
            self.tmws_url = "http://localhost:8000"

        # Find binary path (cached)
        self._binary_path: Optional[str] = None
        self._binary_checked = False

        # HTTP availability (cached)
        self._http_available: Optional[bool] = None

    @property
    def binary_path(self) -> Optional[str]:
        """Get cached binary path, finding it on first access."""
        if not self._binary_checked:
            self._binary_path = _find_tmws_hook_binary()
            self._binary_checked = True
        return self._binary_path

    def _check_http_available(self) -> bool:
        """Check if TMWS HTTP API is available."""
        if self._http_available is not None:
            return self._http_available

        if not HTTPX_AVAILABLE:
            self._http_available = False
            return False

        try:
            with httpx.Client(timeout=1.0) as client:
                response = client.get(f"{self.tmws_url}/health")
                self._http_available = response.status_code == 200
        except Exception:
            self._http_available = False

        return self._http_available

    def call(self, command: str, input_data: Dict[str, Any]) -> TMWSResult:
        """Execute a tmws-hook command with 3-tier fallback.

        Args:
            command: Command name (e.g., "enrich", "detect", "validate")
            input_data: Input data as dictionary

        Returns:
            TMWSResult with success status, data, source, and optional error

        Example:
            >>> wrapper = TMWSHookWrapper()
            >>> result = wrapper.call("enrich", {
            ...     "subagent_type": "artemis-optimizer",
            ...     "prompt": "Optimize this code..."
            ... })
        """
        # Validate input size
        input_json = json.dumps(input_data)
        if not _validate_input_size(input_json):
            return TMWSResult(
                success=False,
                data={},
                source="error",
                error="Input size exceeds maximum allowed (10KB)"
            )

        # Tier 1: Try CLI binary first (if enabled and available)
        if self.use_cli and self.binary_path:
            result = self._call_cli(command, input_data)
            if result.success:
                return result
            logger.debug(f"CLI fallback triggered: {result.error}")

        # Tier 2: Try HTTP API
        if HTTPX_AVAILABLE and self._check_http_available():
            result = self._call_http(command, input_data)
            if result.success:
                return result
            logger.debug(f"HTTP fallback triggered: {result.error}")

        # Tier 3: Local minimal implementation
        return self._call_local(command, input_data)

    def _call_cli(self, command: str, input_data: Dict[str, Any]) -> TMWSResult:
        """Execute command via tmws-hook CLI binary.

        Args:
            command: Command name
            input_data: Input data as dictionary

        Returns:
            TMWSResult from CLI execution
        """
        try:
            # Prepare command arguments
            cmd = [self.binary_path, command]

            # Execute with JSON input via stdin
            process = subprocess.run(
                cmd,
                input=json.dumps(input_data),
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            if process.returncode != 0:
                return TMWSResult(
                    success=False,
                    data={},
                    source="cli",
                    error=_sanitize_error(process.stderr) if process.stderr else f"Exit code: {process.returncode}"
                )

            # Parse JSON output
            try:
                output_data = json.loads(process.stdout)
            except json.JSONDecodeError as e:
                return TMWSResult(
                    success=False,
                    data={},
                    source="cli",
                    error=f"Invalid JSON output: {_sanitize_error(str(e))}"
                )

            return TMWSResult(
                success=True,
                data=output_data,
                source="cli"
            )

        except subprocess.TimeoutExpired:
            return TMWSResult(
                success=False,
                data={},
                source="cli",
                error="CLI command timeout"
            )
        except FileNotFoundError:
            return TMWSResult(
                success=False,
                data={},
                source="cli",
                error="tmws-hook binary not found"
            )
        except Exception as e:
            return TMWSResult(
                success=False,
                data={},
                source="cli",
                error=_sanitize_error(str(e))
            )

    def _call_http(self, command: str, input_data: Dict[str, Any]) -> TMWSResult:
        """Execute command via TMWS HTTP API.

        Args:
            command: Command name (mapped to MCP tool)
            input_data: Input data as dictionary

        Returns:
            TMWSResult from HTTP execution
        """
        # Map command to MCP tool name
        tool_mapping = {
            "enrich": "enrich_subagent_prompt",
            "detect": "detect_personas",
            "validate": "validate_subagent",
        }

        tool_name = tool_mapping.get(command, command)

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    f"{self.tmws_url}/api/v1/mcp/call",
                    json={
                        "tool": tool_name,
                        "arguments": input_data
                    },
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code != 200:
                    return TMWSResult(
                        success=False,
                        data={},
                        source="http",
                        error=f"HTTP {response.status_code}: {_sanitize_error(response.text)}"
                    )

                return TMWSResult(
                    success=True,
                    data=response.json(),
                    source="http"
                )

        except httpx.TimeoutException:
            return TMWSResult(
                success=False,
                data={},
                source="http",
                error="HTTP request timeout"
            )
        except Exception as e:
            return TMWSResult(
                success=False,
                data={},
                source="http",
                error=_sanitize_error(str(e))
            )

    def _call_local(self, command: str, input_data: Dict[str, Any]) -> TMWSResult:
        """Execute command with local minimal implementation.

        Provides graceful degradation when both CLI and HTTP are unavailable.

        Args:
            command: Command name
            input_data: Input data as dictionary

        Returns:
            TMWSResult with minimal local implementation
        """
        if command == "enrich":
            return self._local_enrich(input_data)
        elif command == "detect":
            return self._local_detect(input_data)
        elif command == "validate":
            return self._local_validate(input_data)
        else:
            return TMWSResult(
                success=False,
                data={},
                source="local",
                error=f"Unknown command: {command}"
            )

    def _local_enrich(self, input_data: Dict[str, Any]) -> TMWSResult:
        """Local implementation of prompt enrichment.

        Returns original prompt without enrichment (graceful degradation).
        """
        original_prompt = input_data.get("prompt", input_data.get("original_prompt", ""))
        subagent_type = input_data.get("subagent_type", "")

        return TMWSResult(
            success=True,
            data={
                "enriched_prompt": original_prompt,
                "narrative_loaded": False,
                "source": "local_fallback",
                "subagent_type": subagent_type,
            },
            source="local"
        )

    def _local_detect(self, input_data: Dict[str, Any]) -> TMWSResult:
        """Local implementation of persona detection.

        Uses simple keyword matching for basic detection.
        """
        import re

        text = input_data.get("text", input_data.get("task_content", ""))

        # Simple keyword patterns for persona detection
        patterns = {
            "hera": r"\b(strateg|planning|architect|vision|roadmap)\w*",
            "athena": r"\b(orchestr|workflow|automat|parallel|coordin)\w*",
            "artemis": r"\b(optim|perform|quality|technical|efficien)\w*",
            "hestia": r"\b(secur|audit|risk|vulnerab|threat)\w*",
            "eris": r"\b(coordinat|tactical|team|collaborat|mediat)\w*",
            "muses": r"\b(document|knowledge|record|guide|archive)\w*",
            "aphrodite": r"\b(design|ui|ux|visual|interface)\w*",
            "metis": r"\b(implement|code|develop|build|test)\w*",
            "aurora": r"\b(search|research|find|discover|context)\w*",
        }

        detected = []
        text_lower = text.lower()

        for persona, pattern in patterns.items():
            if re.search(pattern, text_lower, re.IGNORECASE):
                detected.append({
                    "persona_id": persona,
                    "confidence": 0.7,  # Lower confidence for local detection
                    "matched_keywords": [],
                })

        return TMWSResult(
            success=True,
            data={
                "personas": detected,
                "detection_method": "local_regex",
            },
            source="local"
        )

    def _local_validate(self, input_data: Dict[str, Any]) -> TMWSResult:
        """Local implementation of subagent validation.

        Uses whitelist for basic validation.
        """
        subagent_type = input_data.get("subagent_type", "").lower()

        is_valid = subagent_type in KNOWN_SUBAGENT_TYPES

        return TMWSResult(
            success=True,
            data={
                "valid": is_valid,
                "subagent_type": subagent_type,
                "validation_method": "local_whitelist",
            },
            source="local"
        )

    # ==================== Convenience Methods ====================

    def enrich_prompt(
        self,
        subagent_type: str,
        prompt: str
    ) -> TMWSResult:
        """Enrich a SubAgent prompt with persona narrative.

        Args:
            subagent_type: SubAgent type (e.g., "hera-strategist")
            prompt: Original prompt to enrich

        Returns:
            TMWSResult with enriched_prompt in data

        Example:
            >>> wrapper = TMWSHookWrapper()
            >>> result = wrapper.enrich_prompt(
            ...     "artemis-optimizer",
            ...     "Optimize this database query..."
            ... )
            >>> print(result.data.get("enriched_prompt"))
        """
        return self.call("enrich", {
            "subagent_type": subagent_type,
            "original_prompt": prompt,
        })

    def detect_personas(self, text: str) -> TMWSResult:
        """Detect relevant personas from text content.

        Args:
            text: Text to analyze for persona detection

        Returns:
            TMWSResult with list of detected personas

        Example:
            >>> wrapper = TMWSHookWrapper()
            >>> result = wrapper.detect_personas("Optimize performance...")
            >>> print(result.data.get("personas"))
        """
        return self.call("detect", {"task_content": text})

    def validate_subagent(self, subagent_type: str) -> bool:
        """Validate if a subagent_type is known.

        Args:
            subagent_type: SubAgent type to validate

        Returns:
            True if valid, False otherwise

        Example:
            >>> wrapper = TMWSHookWrapper()
            >>> print(wrapper.validate_subagent("hera-strategist"))
            True
            >>> print(wrapper.validate_subagent("invalid-agent"))
            False
        """
        result = self.call("validate", {"subagent_type": subagent_type})
        return result.success and result.data.get("valid", False)


# ==================== Module-level Functions ====================

# Global wrapper instance (lazy initialization)
_wrapper: Optional[TMWSHookWrapper] = None


def get_wrapper() -> TMWSHookWrapper:
    """Get or create global wrapper instance.

    Returns:
        TMWSHookWrapper singleton
    """
    global _wrapper
    if _wrapper is None:
        _wrapper = TMWSHookWrapper()
    return _wrapper


def enrich_prompt(subagent_type: str, prompt: str) -> Tuple[str, bool, str]:
    """Convenience function to enrich a SubAgent prompt.

    Args:
        subagent_type: SubAgent type
        prompt: Original prompt

    Returns:
        Tuple of (enriched_prompt, was_enriched, source)
    """
    wrapper = get_wrapper()
    result = wrapper.enrich_prompt(subagent_type, prompt)

    if result.success:
        data = result.data
        return (
            data.get("enriched_prompt", prompt),
            data.get("narrative_loaded", False),
            result.source
        )
    else:
        return (prompt, False, "error")


def detect_personas(text: str) -> List[Dict[str, Any]]:
    """Convenience function to detect personas from text.

    Args:
        text: Text to analyze

    Returns:
        List of detected persona dictionaries
    """
    wrapper = get_wrapper()
    result = wrapper.detect_personas(text)

    if result.success:
        return result.data.get("personas", [])
    else:
        return []


def validate_subagent(subagent_type: str) -> bool:
    """Convenience function to validate a subagent type.

    Args:
        subagent_type: SubAgent type to validate

    Returns:
        True if valid
    """
    return get_wrapper().validate_subagent(subagent_type)


# ==================== CLI Entry Point ====================

def main():
    """CLI entry point for testing the wrapper.

    Usage:
        python tmws_hook_wrapper.py enrich '{"subagent_type": "hera-strategist", "prompt": "..."}'
        python tmws_hook_wrapper.py detect '{"text": "optimize performance..."}'
        python tmws_hook_wrapper.py validate '{"subagent_type": "artemis-optimizer"}'
    """
    if len(sys.argv) < 3:
        print("Usage: tmws_hook_wrapper.py <command> <json_input>", file=sys.stderr)
        print("Commands: enrich, detect, validate", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]

    try:
        input_data = json.loads(sys.argv[2])
    except json.JSONDecodeError as e:
        print(f"Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)

    wrapper = TMWSHookWrapper()
    result = wrapper.call(command, input_data)

    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
