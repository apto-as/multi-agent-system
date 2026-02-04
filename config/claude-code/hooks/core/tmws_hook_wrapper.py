#!/usr/bin/env python3
"""
Trinitas Hook: tmws_hook_wrapper
==================================
Wrapper for delegating hook execution to the tmws-hook binary.

This hook is distributed via the TMWS installer and is not included
in the public repository for security reasons.

Installation:
    curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install.sh | bash

The installer will download hooks from the TMWS binary or API endpoint.
"""
import sys
import json

error_msg = (
    "Hook not installed: tmws_hook_wrapper.py. "
    "Please run the TMWS installer: "
    "curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install.sh | bash"
)
print(json.dumps({"error": error_msg}), file=sys.stderr)
sys.exit(1)
