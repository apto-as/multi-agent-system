"""Memory monitoring and leak detection for Trinitas agents.

This module provides production-ready memory monitoring with <0.5% overhead
and log auditing for sensitive data exposure (CWE-532).
"""

from .memory_monitor import (
    MemoryMonitor,
    MemorySnapshot,
    MemoryLeakAlert,
    MonitoringTier,
)
from .log_auditor import LogAuditor

# MemoryBaseline is maintained for backwards compatibility but not recommended
try:
    from .memory_baseline import MemoryBaseline
except ImportError:
    # MemoryBaseline may not exist in new implementation
    MemoryBaseline = None

__all__ = [
    "MemoryMonitor",
    "MemorySnapshot",
    "MemoryLeakAlert",
    "MonitoringTier",
    "LogAuditor",
]

# Optional export for backwards compatibility
if MemoryBaseline is not None:
    __all__.append("MemoryBaseline")
