"""Core sanitization components.

This module exports the core pattern registry for use by validators.

Author: Artemis (Implementation)
Created: 2025-12-07 (Issue #22: Unified Sanitization)
"""

from .patterns import PatternRegistry, get_pattern_registry

__all__ = [
    "PatternRegistry",
    "get_pattern_registry",
]
