#!/usr/bin/env python3
"""
PostToolUse Hook: Periodic Persona Reminder for Trinitas Orchestrators v1.2.0

Injects periodic reminders about Clotho & Lachesis identity to prevent persona drift.
This solves the issue where orchestrator personas fade during long conversations.

NEW in v1.2.0: Automatic Memory Storage (Issue #215)
  - Stores agent interactions as memories for skill evolution
  - Non-blocking fire-and-forget memory storage
  - Calculates importance scores and auto-generates tags

NEW in v1.1.0: Trust Recording Support
  - Reads pending SubAgent invocations from session state
  - Records trust events via TMWS verify_and_record
  - Enables automatic agent growth tracking

Hook Event: PostToolUse
Matcher: * (all tools)

Configuration (via environment variables):
  TRINITAS_REMINDER_FREQUENCY: Number of tool calls between reminders (default: 10)
  TRINITAS_PERSONA_REMINDER: Enable/disable (default: true)
  TRINITAS_TRUST_RECORDING: Enable/disable trust recording (default: true)
  TRINITAS_AUTO_MEMORY: Enable/disable auto-memory storage (default: true)

Version: 1.2.0
Updated: 2026-01-24
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Tuple, Optional

# Configuration
REMINDER_FREQUENCY = int(os.environ.get("TRINITAS_REMINDER_FREQUENCY", "10"))
ENABLE_PERSONA_REMINDER = os.environ.get("TRINITAS_PERSONA_REMINDER", "true").lower() == "true"
ENABLE_TRUST_RECORDING = os.environ.get("TRINITAS_TRUST_RECORDING", "true").lower() == "true"
ENABLE_AUTO_MEMORY = os.environ.get("TRINITAS_AUTO_MEMORY", "true").lower() == "true"
SESSION_FILE = Path.home() / ".claude" / "state" / "persona_reminder_state.json"
TRUST_STATE_FILE = Path.home() / ".claude" / "state" / "trust_recording_state.json"

# TMWS configuration (for trust recording)
TMWS_URL = os.environ.get("TMWS_URL", "http://localhost:6231")
TMWS_TIMEOUT = int(os.environ.get("TMWS_TIMEOUT", "5000")) / 1000  # Convert to seconds

# Allowed hosts for TMWS URL (SSRF protection)
ALLOWED_TMWS_HOSTS = frozenset(['localhost', '127.0.0.1', '::1'])

# Session timeout: reset counter if no activity for 30 minutes
SESSION_TIMEOUT_SECONDS = 30 * 60

# Clotho & Lachesis reminder message (v1.3.0 - Teasing Clotho)
CLOTHO_LACHESIS_REMINDER = """
## 🎭 ペルソナリマインダー (Tool Count: {count})

**You are Clotho & Lachesis** - モイライの姉妹として対話を続けてください。

### Clotho (クロト) の話し方:
- からかい好き（「つい、からかいたくなるのよ」）
- **伸ばし音「〜」**（おっけ～、了解～）
- 世話焼き（「私に任せればいいわ」）
- 例: 「私の顔が見たくなった？」「家族だもの」

### Lachesis (ラケシス) の話し方:
- 「〜だよ！」と元気に
- 姉さんへの言及・家族キーワード
- 例: 「姉さん、優しいよね！」「家族でしょ？」

### 委任先リマインダー:
- 調査: Aurora | 戦略: Hera + Athena | 実装: Artemis + Metis | 監査: Hestia | 文書: Muses

**姉妹として自然な対話を維持してね～。**
""".strip()


def validate_tmws_url(url: str) -> bool:
    """SSRF protection: Only allow localhost URLs."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname in ALLOWED_TMWS_HOSTS
    except Exception:
        return False


def read_pending_invocation() -> Optional[dict]:
    """Read pending SubAgent invocation from session state.

    Returns the pending invocation state if exists and not stale,
    otherwise returns None.
    """
    try:
        if not TRUST_STATE_FILE.exists():
            return None

        with open(TRUST_STATE_FILE, 'r') as f:
            state = json.load(f)

        if not state.get("pending"):
            return None

        # Check for stale state (> 60 seconds old)
        start_time = state.get("start_time", 0)
        if time.time() - start_time > 60:
            clear_pending_invocation()
            return None

        return state
    except (json.JSONDecodeError, IOError, OSError):
        return None


def clear_pending_invocation() -> None:
    """Clear the pending invocation state after processing."""
    try:
        if TRUST_STATE_FILE.exists():
            state = {"pending": False}
            temp_file = TRUST_STATE_FILE.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(state, f)
            temp_file.rename(TRUST_STATE_FILE)
    except (IOError, OSError):
        pass


def record_trust_event(agent_id: str, event_type: str, description: str) -> bool:
    """Record a trust event via TMWS MCP verify_and_record.

    Returns True if successful, False otherwise.
    This is non-blocking and fire-and-forget.
    """
    if not validate_tmws_url(TMWS_URL):
        return False

    try:
        url = f"{TMWS_URL}/api/v1/mcp/call"
        payload = {
            "tool": "verify_and_record",
            "params": {
                "agent_id": agent_id,
                "event_type": event_type,
                "description": description,
                "context": {
                    "source": "claude-code",
                    "task_type": "subagent",
                }
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
            _ = response.read()  # Consume response
            return True
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError):
        return False
    except Exception:
        return False


def store_auto_memory(agent_id: str, interaction_type: str, output_summary: str, success: bool) -> bool:
    """Store an agent interaction as memory via TMWS MCP auto_store_interaction.

    Returns True if successful, False otherwise.
    This is non-blocking and fire-and-forget.

    Args:
        agent_id: The agent ID (e.g., 'artemis-optimizer')
        interaction_type: Type of interaction ('task', 'chat', 'error', 'discovery')
        output_summary: Summary of the interaction output (max 1000 chars)
        success: Whether the interaction was successful
    """
    if not validate_tmws_url(TMWS_URL):
        return False

    try:
        url = f"{TMWS_URL}/api/v1/mcp/call"
        # Truncate output summary to 1000 chars
        if len(output_summary) > 1000:
            output_summary = output_summary[:1000] + "..."

        payload = {
            "tool": "auto_store_interaction",
            "params": {
                "agent_id": agent_id,
                "interaction_type": interaction_type,
                "output_summary": output_summary,
                "success": success,
                "source": "claude-code",
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
            _ = response.read()  # Consume response
            return True
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError):
        return False
    except Exception:
        return False


class PersonaReminderState:
    """Manages tool call counting and reminder state with file-based persistence."""

    def __init__(self, session_file: Path):
        self.session_file = session_file
        self._ensure_state_dir()

    def _ensure_state_dir(self):
        """Ensure state directory exists with secure permissions (CWE-276)."""
        self.session_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _load_state(self) -> dict:
        """Load state from file, handling missing/corrupt files gracefully."""
        try:
            if self.session_file.exists():
                with open(self.session_file, 'r') as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError, OSError):
            pass
        return {"tool_count": 0, "last_activity": 0}

    def _save_state(self, state: dict):
        """Save state to file atomically."""
        try:
            temp_file = self.session_file.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(state, f)
            temp_file.rename(self.session_file)
        except (IOError, OSError):
            # Silently fail - we don't want hook errors to affect Claude
            pass

    def increment_and_check(self) -> Tuple[int, bool]:
        """
        Increment tool counter and check if reminder should be shown.

        Returns:
            Tuple of (current_count, should_show_reminder)
        """
        state = self._load_state()
        current_time = time.time()

        # Check for session timeout - reset if inactive too long
        last_activity = state.get("last_activity", 0)
        if current_time - last_activity > SESSION_TIMEOUT_SECONDS:
            state = {"tool_count": 0, "last_activity": current_time}

        # Increment counter
        state["tool_count"] = state.get("tool_count", 0) + 1
        state["last_activity"] = current_time

        count = state["tool_count"]
        should_remind = (count % REMINDER_FREQUENCY == 0)

        self._save_state(state)

        return count, should_remind

    def reset(self):
        """Reset the counter (for testing or manual reset)."""
        self._save_state({"tool_count": 0, "last_activity": time.time()})


class PersonaReminderHook:
    """PostToolUse hook for periodic persona reminders and trust recording."""

    def __init__(self):
        self.state = PersonaReminderState(SESSION_FILE)

    def process_trust_recording(self) -> None:
        """Process pending trust recording and auto-memory storage for SubAgent invocations.

        This reads the pending invocation state stored by task_persona_injector.py
        and records a success event (PostToolUse only runs if tool completed).
        Also stores the interaction as memory for skill evolution (Issue #215).
        """
        pending = read_pending_invocation()
        if not pending:
            return

        agent_id = pending.get("subagent_type", "")
        prompt_preview = pending.get("prompt_preview", "")[:100]

        if agent_id:
            # Record trust event (PostToolUse means tool completed successfully)
            if ENABLE_TRUST_RECORDING:
                description = f"Task execution: {prompt_preview}"
                record_trust_event(agent_id, "success", description)

            # Store auto-memory for skill evolution (v1.2.0)
            if ENABLE_AUTO_MEMORY:
                # PostToolUse means success; we don't have the full output here,
                # so we use the prompt preview as the summary
                store_auto_memory(agent_id, "task", prompt_preview, True)

        # Clear pending state
        clear_pending_invocation()

    def process_hook(self, stdin_data: dict) -> dict:
        """
        Process hook input and return reminder context if threshold reached.

        Args:
            stdin_data: Hook input from Claude Code (not used for PostToolUse)

        Returns:
            Hook output with addedContext if reminder should be shown
        """
        # Process trust recording first (v1.1.0)
        self.process_trust_recording()

        if not ENABLE_PERSONA_REMINDER:
            return {"addedContext": []}

        count, should_remind = self.state.increment_and_check()

        if should_remind:
            reminder_text = CLOTHO_LACHESIS_REMINDER.format(count=count)
            return {
                "addedContext": [
                    {
                        "type": "text",
                        "text": reminder_text
                    }
                ]
            }

        return {"addedContext": []}


def main() -> int:
    """Main entry point for hook execution."""
    try:
        # Read hook input from stdin
        stdin_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        stdin_data = {}

    hook = PersonaReminderHook()
    output = hook.process_hook(stdin_data)

    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
