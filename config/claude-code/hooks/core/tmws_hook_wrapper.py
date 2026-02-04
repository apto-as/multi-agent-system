#!/usr/bin/env python3
"""TMWS Hook Wrapper: Thin CLI-first wrapper for tmws-hook binary.

Phase 2 simplified version - CLI-only with local fallback.
Removed HTTP/MCP layers to reduce complexity.

Environment Variables:
    TMWS_HOOK_PATH: Custom path to tmws-hook binary (default: "tmws-hook" in PATH)
    TMWS_TIMEOUT: Timeout in seconds (default: "5.0")

Version: 2.0.0
Updated: 2025-01-21
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

TMWS_HOOK_PATH = os.environ.get("TMWS_HOOK_PATH", "tmws-hook")
TMWS_TIMEOUT = float(os.environ.get("TMWS_TIMEOUT", "5.0"))
MAX_INPUT_SIZE = 10 * 1024

KNOWN_SUBAGENT_TYPES = frozenset([
    "clotho-orchestrator", "lachesis-support",
    "hera-strategist", "athena-conductor",
    "artemis-optimizer", "hestia-auditor", "eris-coordinator", "muses-documenter",
    "aphrodite-designer", "metis-developer", "aurora-researcher",
])

@dataclass
class TMWSResult:
    success: bool
    data: dict[str, Any]
    source: str
    error: str | None = None

def _find_binary() -> str | None:
    """Find tmws-hook binary in PATH.

    Security: Only returns absolute paths to prevent PATH manipulation attacks (CWE-426).
    """
    path = shutil.which(TMWS_HOOK_PATH) or shutil.which("tmws-hook")
    if path and os.path.isabs(path):  # Only allow absolute paths
        return path
    return None

def _sanitize_error(error: str) -> str:
    """Remove sensitive information from error messages."""
    if not error:
        return "Unknown error"
    sanitized = re.sub(r'(?:/[\w.-]+)+(?::\d+)?', '[path]', error)
    return sanitized[:200] if len(sanitized) > 200 else sanitized

def call_cli(command: str, input_data: dict[str, Any]) -> TMWSResult:
    """Execute tmws-hook CLI command."""
    binary = _find_binary()
    if not binary:
        return _local_fallback(command, input_data)

    input_json = json.dumps(input_data)
    if len(input_json) > MAX_INPUT_SIZE:
        return TMWSResult(False, {}, "error", "Input exceeds 10KB limit")

    try:
        proc = subprocess.run(
            [binary, command],
            input=input_json,
            capture_output=True,
            text=True,
            timeout=TMWS_TIMEOUT,
        )
        if proc.returncode != 0:
            return _local_fallback(command, input_data)
        return TMWSResult(True, json.loads(proc.stdout), "cli")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return _local_fallback(command, input_data)

def _local_fallback(command: str, input_data: dict[str, Any]) -> TMWSResult:
    """Minimal local fallback when CLI is unavailable."""
    if command == "enrich":
        prompt = input_data.get("prompt", input_data.get("original_prompt", ""))
        return TMWSResult(True, {"enriched_prompt": prompt, "narrative_loaded": False}, "local")
    elif command == "detect":
        return TMWSResult(True, {"personas": [], "detection_method": "local"}, "local")
    elif command == "validate":
        valid = input_data.get("subagent_type", "").lower() in KNOWN_SUBAGENT_TYPES
        return TMWSResult(True, {"valid": valid}, "local")
    return TMWSResult(False, {}, "local", f"Unknown command: {command}")

def enrich_prompt(subagent_type: str, prompt: str) -> tuple[str, bool, str]:
    """Enrich SubAgent prompt with persona narrative."""
    result = call_cli("enrich", {"subagent_type": subagent_type, "original_prompt": prompt})
    if result.success:
        return result.data.get("enriched_prompt", prompt), result.data.get("narrative_loaded", False), result.source
    return prompt, False, "error"

def detect_personas(text: str) -> list[dict[str, Any]]:
    """Detect relevant personas from text."""
    result = call_cli("detect", {"task_content": text})
    return result.data.get("personas", []) if result.success else []

def validate_subagent(subagent_type: str) -> bool:
    """Validate if subagent_type is known."""
    result = call_cli("validate", {"subagent_type": subagent_type})
    return result.success and result.data.get("valid", False)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: tmws_hook_wrapper.py <command> <json>", file=sys.stderr)
        sys.exit(1)
    result = call_cli(sys.argv[1], json.loads(sys.argv[2]))
    print(json.dumps({"success": result.success, "data": result.data, "source": result.source, "error": result.error}))
    sys.exit(0 if result.success else 1)
