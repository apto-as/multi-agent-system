#!/usr/bin/env python3
"""
PreToolUse Hook: Task Persona Injector v1.1.0

Intercepts Task tool calls and injects persona narratives from TMWS.
This solves GAP-3: AI autonomous Task invocation missing narrative context.

NEW in v1.1.0: Trust Recording Support
  - Stores pending SubAgent invocation in session state
  - PostToolUse hook (persona_reminder_hook.py) reads this state
  - Enables automatic trust event recording for agent growth tracking

Hook Event: PreToolUse
Matcher: Task

Usage in settings.json:
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Task",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"/Users/apto-as/.claude/hooks/core/task_persona_injector.py\""
          }
        ]
      }
    ]
  }
}

Version: 1.1.0
Updated: 2026-01-23
"""

import json
import sys
import os
import time
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Optional

# Configuration
TMWS_URL = os.environ.get("TMWS_URL", "http://localhost:8000")
TMWS_TIMEOUT = int(os.environ.get("TMWS_TIMEOUT", "5000")) / 1000  # Convert to seconds
ENABLE_ENRICHMENT = os.environ.get("TMWS_NARRATIVE_ENRICHMENT", "true").lower() == "true"
ENABLE_TRUST_RECORDING = os.environ.get("TRINITAS_TRUST_RECORDING", "true").lower() == "true"

# Session state file for pending trust recording
TRUST_STATE_FILE = Path.home() / ".claude" / "state" / "trust_recording_state.json"

# Allowed hosts for TMWS URL (SSRF protection - CWE-918)
ALLOWED_TMWS_HOSTS = frozenset(['localhost', '127.0.0.1', '::1'])

# Whitelist of valid subagent types (full names)
VALID_SUBAGENT_TYPES = {
    "hera-strategist",
    "athena-conductor",
    "artemis-optimizer",
    "hestia-auditor",
    "eris-coordinator",
    "muses-documenter",
    "aphrodite-designer",
    "metis-developer",
    "aurora-researcher",
    # Orchestrators (usually not invoked via Task, but included for completeness)
    "clotho-orchestrator",
    "lachesis-support",
}

# Maximum prompt length (10KB)
MAX_PROMPT_LENGTH = 10 * 1024


def validate_tmws_url(url: str) -> bool:
    """SSRF protection: Only allow localhost URLs."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname in ALLOWED_TMWS_HOSTS
    except Exception:
        return False


def load_narrative_from_tmws(subagent_type: str) -> Optional[str]:
    """Load persona narrative from TMWS via HTTP API.

    Uses the /api/v1/mcp/call endpoint to call the load_persona_narrative tool.
    """
    if not validate_tmws_url(TMWS_URL):
        return None

    try:
        # Use TMWS MCP call endpoint
        url = f"{TMWS_URL}/api/v1/mcp/call"
        payload = {
            "tool": "load_persona_narrative",
            "params": {
                "persona_name": subagent_type,
                "prefer_evolved": True
            }
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=TMWS_TIMEOUT) as response:
            result = json.loads(response.read().decode("utf-8"))
            # Extract context_string from the response
            return result.get("context_string", "")
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError):
        return None
    except Exception:
        return None


def enrich_prompt_with_narrative(original_prompt: str, narrative: str) -> str:
    """Prepend narrative to the original prompt."""
    return f"""## Persona Context (Auto-Injected via PreToolUse)

{narrative}

---

## Task Prompt

{original_prompt}"""


def store_pending_invocation(subagent_type: str, prompt_preview: str) -> None:
    """Store pending SubAgent invocation for trust recording in PostToolUse.

    This creates a session state file that persona_reminder_hook.py reads
    to record the trust event when the tool completes.
    """
    if not ENABLE_TRUST_RECORDING:
        return

    try:
        # Ensure state directory exists with secure permissions (CWE-276)
        TRUST_STATE_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        state = {
            "pending": True,
            "subagent_type": subagent_type,
            "prompt_preview": prompt_preview[:200],  # Truncate for storage
            "start_time": time.time(),
        }

        # Atomic write
        temp_file = TRUST_STATE_FILE.with_suffix('.tmp')
        with open(temp_file, 'w') as f:
            json.dump(state, f)
        temp_file.rename(TRUST_STATE_FILE)
    except (IOError, OSError):
        # Silently fail - don't interrupt tool execution
        pass


def main():
    """Main hook handler."""
    try:
        # Read hook input from stdin
        hook_input = json.load(sys.stdin)
    except json.JSONDecodeError:
        # Invalid input, pass through without modification
        print(json.dumps({}))
        return 0

    # Check if enrichment is enabled
    if not ENABLE_ENRICHMENT:
        print(json.dumps({}))
        return 0

    # Extract tool input
    tool_input = hook_input.get("tool_input", {})
    subagent_type = tool_input.get("subagent_type", "")
    original_prompt = tool_input.get("prompt", "")

    # Validate subagent_type
    if subagent_type not in VALID_SUBAGENT_TYPES:
        # Unknown subagent type, pass through without modification
        print(json.dumps({}))
        return 0

    # Validate prompt length
    if len(original_prompt) > MAX_PROMPT_LENGTH:
        # Prompt too large, skip enrichment to avoid issues
        print(json.dumps({}))
        return 0

    # Store pending invocation for trust recording (v1.1.0)
    # This will be read by persona_reminder_hook.py in PostToolUse
    store_pending_invocation(subagent_type, original_prompt)

    # Load narrative from TMWS
    narrative = load_narrative_from_tmws(subagent_type)

    if narrative:
        # Enrich prompt with narrative
        enriched_prompt = enrich_prompt_with_narrative(original_prompt, narrative)

        # Return updated input
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "updatedInput": {
                    "prompt": enriched_prompt
                }
            }
        }
    else:
        # No narrative available, pass through without modification
        output = {}

    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
