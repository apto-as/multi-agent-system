"""
Trinitas Shared Utilities Package
Provides reusable utilities for code deduplication

Created: 2025-10-15 (Phase 1 Day 3)
Purpose: Eliminate code duplication across Trinitas components
"""

from .json_loader import (
    JSONLoader,
    JSONLoadError,
    load_json,
    load_json_safe,
    save_json,
)
from .persona_pattern_loader import (
    PersonaPatternLoader,
    detect_persona,
)
from .secure_file_loader import (
    SecureFileLoader,
    SecurityError,
    load_secure,
    validate_path,
)
from .trinitas_component import (
    TrinitasComponent,
)

__all__ = [
    "JSONLoadError",
    # JSON Loading
    "JSONLoader",
    # Persona Pattern Loading
    "PersonaPatternLoader",
    # Secure File Loading
    "SecureFileLoader",
    "SecurityError",
    # Base Component
    "TrinitasComponent",
    "detect_persona",
    "load_json",
    "load_json_safe",
    "load_secure",
    "save_json",
    "validate_path",
]

__version__ = "1.0.0"
