"""TMWS - Trinitas Memory & Workflow Service
MCP-only architecture (v2.3.0+)
"""

__version__ = "2.3.0"

# Core process management exports
from .core.process_manager import (
    ProcessPriority,
    ServiceState,
    TacticalProcessManager,
    create_tactical_process_manager,
)

__all__ = [
    "TacticalProcessManager",
    "ServiceState",
    "ProcessPriority",
    "create_tactical_process_manager",
]
