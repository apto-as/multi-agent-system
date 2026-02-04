#!/usr/bin/env python3
"""
Trinitas Hook: precompact_memory_injection
============================================
TMWS: Inject relevant past memories before compaction.

This hook is distributed via the TMWS installer and is not included
in the public repository for security reasons.

Installation:
    curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install.sh | bash

The installer will download hooks from the TMWS binary or API endpoint.
"""
import sys
import json

error_msg = (
    "Hook not installed: precompact_memory_injection.py. "
    "Please run the TMWS installer: "
    "curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install.sh | bash"
)
print(json.dumps({"error": error_msg}), file=sys.stderr)
sys.exit(1)
