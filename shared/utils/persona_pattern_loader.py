#!/usr/bin/env python3
"""
Persona Pattern Loader - Unified persona detection configuration.

Replaces hardcoded patterns in multiple files with single JSON source of truth.
Provides dynamic loading of persona detection patterns from centralized JSON config.

This module eliminates 95% code duplication across:
- hooks/core/dynamic_context_loader.py (Python)
- .opencode/plugin/dynamic-context-loader.js (JavaScript)
- trinitas_sources/config/opencode/plugin/dynamic-context.js (JavaScript)

Version: 2.2.4
Created: 2025-10-19 (Phase 2 cleanup)
"""
from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Pattern

logger = logging.getLogger(__name__)


class PersonaPatternLoader:
    """Load and compile persona detection patterns from JSON config.

    Provides centralized management of persona detection patterns for all
    Trinitas components. Patterns are loaded from JSON and compiled into
    regex objects for efficient matching.

    Attributes:
        config_path: Path to persona_patterns.json
        _patterns: Compiled regex patterns for each persona
        _metadata: Full metadata for each persona (display_name, emoji, etc.)

    Example:
        >>> loader = PersonaPatternLoader()
        >>> detected = loader.detect_persona("optimize performance")
        >>> print(detected)
        'artemis'

        >>> metadata = loader.get_metadata('artemis')
        >>> print(metadata['title'])
        'Technical Perfectionist'
    """

    def __init__(self, config_path: Optional[Path] = None):
        """Initialize loader with persona patterns from JSON config.

        Args:
            config_path: Optional path to persona_patterns.json. If None,
                automatically searches for config file in project structure.

        Raises:
            FileNotFoundError: If persona_patterns.json cannot be found
            json.JSONDecodeError: If JSON config is malformed
        """
        if config_path is None:
            config_path = self._find_config_file()

        self.config_path = config_path
        self._patterns: Dict[str, Pattern] = {}
        self._metadata: Dict[str, dict] = {}
        self._load_config()

    def _find_config_file(self) -> Path:
        """Auto-detect persona_patterns.json location.

        Searches upward from current file location for:
        trinitas_sources/config/shared/persona_patterns.json

        Returns:
            Path to persona_patterns.json

        Raises:
            FileNotFoundError: If config file cannot be found
        """
        current = Path(__file__).parent

        while current != current.parent:
            candidate = (
                current / "trinitas_sources" / "config" / "shared" / "persona_patterns.json"
            )
            if candidate.exists():
                logger.debug(f"Found persona patterns config: {candidate}")
                return candidate
            current = current.parent

        raise FileNotFoundError(
            "persona_patterns.json not found. Expected at: "
            "trinitas_sources/config/shared/persona_patterns.json"
        )

    def _load_config(self):
        """Load and compile patterns from JSON config.

        Reads persona_patterns.json and compiles all regex patterns
        with appropriate flags. Stores both compiled patterns and
        full metadata for each persona.

        Raises:
            json.JSONDecodeError: If JSON is malformed
            KeyError: If required fields are missing
        """
        logger.debug(f"Loading persona patterns from: {self.config_path}")

        with open(self.config_path, "r", encoding="utf-8") as f:
            config = json.load(f)

        for persona_id, persona_data in config["personas"].items():
            # Compile regex pattern
            pattern = persona_data["pattern"]
            flags_str = persona_data.get("flags", "")

            # Parse regex flags
            flags = 0
            if "i" in flags_str:
                flags |= re.IGNORECASE
            if "m" in flags_str:
                flags |= re.MULTILINE
            if "s" in flags_str:
                flags |= re.DOTALL

            self._patterns[persona_id] = re.compile(pattern, flags)
            self._metadata[persona_id] = persona_data

        logger.info(f"Loaded {len(self._patterns)} persona patterns")

    @lru_cache(maxsize=128)
    def detect_persona(self, text: str) -> Optional[str]:
        """Detect persona from text using pattern matching.

        Uses compiled regex patterns to identify which persona is most
        relevant to the given text. Returns highest priority match.

        Args:
            text: Input text to analyze (e.g., user prompt)

        Returns:
            Persona ID (e.g., 'athena', 'artemis') or None if no match

        Example:
            >>> loader = PersonaPatternLoader()
            >>> loader.detect_persona("optimize database queries")
            'artemis'

            >>> loader.detect_persona("security audit needed")
            'hestia'

            >>> loader.detect_persona("hello world")
            None
        """
        matches = []

        for persona_id, pattern in self._patterns.items():
            if pattern.search(text):
                priority = self._metadata[persona_id]["priority"]
                matches.append((priority, persona_id))

        if not matches:
            return None

        # Return highest priority match (lowest priority number)
        matches.sort()
        detected_persona = matches[0][1]

        logger.debug(f"Detected persona: {detected_persona} from text: {text[:50]}...")
        return detected_persona

    def detect_all_personas(self, text: str) -> list[str]:
        """Detect all matching personas from text.

        Similar to detect_persona() but returns all matches, not just
        the highest priority one.

        Args:
            text: Input text to analyze

        Returns:
            List of persona IDs sorted by priority (highest first)

        Example:
            >>> loader = PersonaPatternLoader()
            >>> loader.detect_all_personas("optimize security performance")
            ['hestia', 'artemis']
        """
        matches = []

        for persona_id, pattern in self._patterns.items():
            if pattern.search(text):
                priority = self._metadata[persona_id]["priority"]
                matches.append((priority, persona_id))

        # Sort by priority (ascending) and return persona IDs
        matches.sort()
        return [persona_id for _, persona_id in matches]

    def get_metadata(self, persona_id: str) -> dict:
        """Get full metadata for a persona.

        Returns all configuration data for the specified persona,
        including display_name, title, emoji, contexts, etc.

        Args:
            persona_id: Persona identifier (e.g., 'athena')

        Returns:
            Dictionary with all persona metadata

        Example:
            >>> loader = PersonaPatternLoader()
            >>> metadata = loader.get_metadata('artemis')
            >>> print(metadata['title'])
            'Technical Perfectionist'
            >>> print(metadata['emoji'])
            '🏹'
        """
        return self._metadata.get(persona_id, {})

    def get_pattern(self, persona_id: str) -> Optional[Pattern]:
        """Get compiled regex pattern for a persona.

        Args:
            persona_id: Persona identifier

        Returns:
            Compiled regex Pattern object or None if not found
        """
        return self._patterns.get(persona_id)

    def list_personas(self) -> list[str]:
        """Get list of all available persona IDs.

        Returns:
            List of persona identifiers (e.g., ['athena', 'artemis', ...])
        """
        return list(self._patterns.keys())


# Convenience function for quick usage
def detect_persona(text: str, config_path: Optional[Path] = None) -> Optional[str]:
    """Quick persona detection without creating loader instance.

    Args:
        text: Text to analyze
        config_path: Optional path to persona_patterns.json

    Returns:
        Detected persona ID or None

    Example:
        >>> from shared.utils.persona_pattern_loader import detect_persona
        >>> detect_persona("optimize this code")
        'artemis'
    """
    loader = PersonaPatternLoader(config_path=config_path)
    return loader.detect_persona(text)


if __name__ == "__main__":
    # Simple CLI for testing
    import sys

    if len(sys.argv) < 2:
        print("Usage: python persona_pattern_loader.py 'text to analyze'")
        sys.exit(1)

    text = " ".join(sys.argv[1:])
    loader = PersonaPatternLoader()

    detected = loader.detect_persona(text)
    if detected:
        metadata = loader.get_metadata(detected)
        print(f"✅ Detected: {metadata['display_name']} ({metadata['emoji']} {metadata['title']})")
        print(f"   Pattern: {metadata['pattern']}")
        print(f"   Priority: {metadata['priority']}")
    else:
        print("❌ No persona detected")
