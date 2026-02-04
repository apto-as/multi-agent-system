#!/usr/bin/env python3
"""
Trinitas Hook: dynamic_context_loader
======================================
Dynamic context loading based on persona detection.

This hook is distributed via the TMWS installer and is not included
in the public repository for security reasons.

Installation:
    curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install.sh | bash

The installer will download hooks from the TMWS binary or API endpoint.
"""
import sys
import json

# Output a clear error message via Claude Code hook protocol
error_msg = (
    "Hook not installed: dynamic_context_loader.py. "
    "Please run the TMWS installer: "
    "curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install.sh | bash"
)
print(json.dumps({"error": error_msg}), file=sys.stderr)
sys.exit(1)
