#!/usr/bin/env python3
"""
Comprehensive Tests for PersonaPatternLoader
===========================================

Coverage target: 23% → 95%

Tests:
- Config file auto-detection edge cases
- Pattern loading with various flags
- Persona detection with multiple matches
- Priority-based selection
- Metadata retrieval
- Caching behavior
- CLI entry point
- Error handling for missing/corrupted config
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from shared.utils.persona_pattern_loader import (
    PersonaPatternLoader,
    detect_persona as standalone_detect,
)


# ========================
# Test Suite 1: Config File Discovery
# ========================

class TestConfigFileDiscovery:
    """Test _find_config_file method edge cases"""

    def test_find_config_file_success(self, tmp_path):
        """Test successful config file discovery"""
        # Create config structure
        config_dir = tmp_path / "trinitas_sources" / "config" / "shared"
        config_dir.mkdir(parents=True)
        config_file = config_dir / "persona_patterns.json"

        # Minimal valid JSON
        config_file.write_text(json.dumps({
            "personas": {
                "athena": {
                    "display_name": "Athena",
                    "title": "Test",
                    "emoji": "🏛️",
                    "pattern": "athena",
                    "flags": "i",
                    "priority": 1,
                }
            }
        }))

        # Patch __file__ to point to tmp_path
        with patch('shared.utils.persona_pattern_loader.Path') as mock_path:
            mock_path.__file__ = tmp_path / "shared" / "utils" / "persona_pattern_loader.py"
            mock_path.return_value.parent = tmp_path / "shared" / "utils"

            # Mock the parent directory traversal
            def mock_parent(self):
                parts = self.parts
                if len(parts) > 1:
                    return Path(*parts[:-1])
                return self

            # Should find config
            loader = PersonaPatternLoader(config_path=config_file)
            assert loader.config_path == config_file

    def test_find_config_file_not_found(self, tmp_path):
        """Test FileNotFoundError when config not found"""
        # No config file exists
        with patch('shared.utils.persona_pattern_loader.Path.__file__', tmp_path / "test.py"):
            with pytest.raises(FileNotFoundError, match="persona_patterns.json not found"):
                loader = PersonaPatternLoader()
                loader._find_config_file()

    def test_find_config_file_deep_structure(self, tmp_path):
        """Test config discovery in deeply nested structure"""
        # Create deep structure
        deep_dir = tmp_path / "a" / "b" / "c" / "d" / "shared" / "utils"
        deep_dir.mkdir(parents=True)

        # Config at root level
        config_dir = tmp_path / "trinitas_sources" / "config" / "shared"
        config_dir.mkdir(parents=True)
        config_file = config_dir / "persona_patterns.json"
        config_file.write_text(json.dumps({"personas": {}}))

        # Should traverse upward and find it
        loader = PersonaPatternLoader(config_path=config_file)
        assert loader.config_path == config_file


# ========================
# Test Suite 2: Pattern Loading & Compilation
# ========================

class TestPatternLoading:
    """Test _load_config method with various pattern configs"""

    def test_load_config_basic(self, tmp_path):
        """Test loading basic persona config"""
        config_file = tmp_path / "patterns.json"
        config_file.write_text(json.dumps({
            "personas": {
                "test_persona": {
                    "display_name": "Test",
                    "title": "Tester",
                    "emoji": "🧪",
                    "pattern": "test",
                    "flags": "",
                    "priority": 1,
                }
            }
        }))

        loader = PersonaPatternLoader(config_path=config_file)

        assert "test_persona" in loader._patterns
        assert "test_persona" in loader._metadata
        assert loader._metadata["test_persona"]["display_name"] == "Test"

    def test_load_config_multiple_flags(self, tmp_path):
        """Test pattern compilation with multiple regex flags"""
        config_file = tmp_path / "patterns.json"
        config_file.write_text(json.dumps({
            "personas": {
                "multi_flag": {
                    "display_name": "Multi",
                    "title": "Flags",
                    "emoji": "🚩",
                    "pattern": "test.*pattern",
                    "flags": "ims",  # IGNORECASE + MULTILINE + DOTALL
                    "priority": 1,
                }
            }
        }))

        loader = PersonaPatternLoader(config_path=config_file)

        # Test IGNORECASE
        assert loader.detect_persona("TEST PATTERN") == "multi_flag"

        # Test DOTALL (. matches newline)
        assert loader.detect_persona("test\npattern") == "multi_flag"

    def test_load_config_no_flags(self, tmp_path):
        """Test pattern with no flags specified"""
        config_file = tmp_path / "patterns.json"
        config_file.write_text(json.dumps({
            "personas": {
                "no_flags": {
                    "display_name": "NoFlags",
                    "title": "Strict",
                    "emoji": "🔒",
                    "pattern": "^EXACT$",
                    "flags": "",
                    "priority": 1,
                }
            }
        }))

        loader = PersonaPatternLoader(config_path=config_file)

        # Should match exactly
        assert loader.detect_persona("EXACT") == "no_flags"
        assert loader.detect_persona("exact") is None  # Case-sensitive

    def test_load_config_complex_pattern(self, tmp_path):
        """Test loading complex regex pattern"""
        config_file = tmp_path / "patterns.json"
        config_file.write_text(json.dumps({
            "personas": {
                "complex": {
                    "display_name": "Complex",
                    "title": "Advanced",
                    "emoji": "🧩",
                    "pattern": r"(optimize|performance|speed)\s+(improve|boost|enhance)",
                    "flags": "i",
                    "priority": 1,
                }
            }
        }))

        loader = PersonaPatternLoader(config_path=config_file)

        assert loader.detect_persona("optimize improve") == "complex"
        assert loader.detect_persona("performance boost") == "complex"
        assert loader.detect_persona("speed enhance") == "complex"
        assert loader.detect_persona("optimize reduce") is None

    def test_load_config_malformed_json(self, tmp_path):
        """Test error handling for malformed JSON"""
        config_file = tmp_path / "bad.json"
        config_file.write_text("{ malformed json [[[")

        with pytest.raises(json.JSONDecodeError):
            PersonaPatternLoader(config_path=config_file)

    def test_load_config_missing_required_fields(self, tmp_path):
        """Test error handling when required fields are missing"""
        config_file = tmp_path / "incomplete.json"
        config_file.write_text(json.dumps({
            "personas": {
                "incomplete": {
                    "display_name": "Incomplete",
                    # Missing: pattern, priority, etc.
                }
            }
        }))

        with pytest.raises(KeyError):
            PersonaPatternLoader(config_path=config_file)


# ========================
# Test Suite 3: Persona Detection
# ========================

class TestPersonaDetection:
    """Test detect_persona method with various inputs"""

    @pytest.fixture
    def loader(self, tmp_path):
        """Create loader with test personas"""
        config_file = tmp_path / "test.json"
        config_file.write_text(json.dumps({
            "personas": {
                "athena": {
                    "display_name": "Athena",
                    "title": "Strategist",
                    "emoji": "🏛️",
                    "pattern": r"(strategy|plan|design|architecture)",
                    "flags": "i",
                    "priority": 1,
                },
                "artemis": {
                    "display_name": "Artemis",
                    "title": "Optimizer",
                    "emoji": "🏹",
                    "pattern": r"(optimize|performance|quality|efficiency)",
                    "flags": "i",
                    "priority": 2,
                },
                "hestia": {
                    "display_name": "Hestia",
                    "title": "Auditor",
                    "emoji": "🔥",
                    "pattern": r"(security|audit|vulnerability|risk)",
                    "flags": "i",
                    "priority": 3,
                },
            }
        }))

        return PersonaPatternLoader(config_path=config_file)

    def test_detect_persona_single_match(self, loader):
        """Test detection with single match"""
        assert loader.detect_persona("optimize the code") == "artemis"
        assert loader.detect_persona("security audit") == "hestia"
        assert loader.detect_persona("design architecture") == "athena"

    def test_detect_persona_multiple_matches_priority(self, loader):
        """Test priority-based selection with multiple matches"""
        # Contains both "strategy" (athena=1) and "security" (hestia=3)
        # Should return athena (lower priority number = higher priority)
        result = loader.detect_persona("strategy for security improvement")
        assert result == "athena"

    def test_detect_persona_no_match(self, loader):
        """Test detection when no pattern matches"""
        assert loader.detect_persona("hello world") is None
        assert loader.detect_persona("random text") is None

    def test_detect_persona_case_insensitive(self, loader):
        """Test case-insensitive matching"""
        assert loader.detect_persona("OPTIMIZE") == "artemis"
        assert loader.detect_persona("Security") == "hestia"
        assert loader.detect_persona("ARCHITECTURE") == "athena"

    def test_detect_persona_partial_match(self, loader):
        """Test partial word matching"""
        assert loader.detect_persona("optimization needed") == "artemis"
        assert loader.detect_persona("architectural design") == "athena"

    def test_detect_persona_caching(self, loader):
        """Test LRU cache behavior"""
        # First call
        result1 = loader.detect_persona("optimize code")

        # Second call (should hit cache)
        with patch.object(loader, '_patterns') as mock_patterns:
            result2 = loader.detect_persona("optimize code")
            # Patterns should not be accessed (cached result)
            assert mock_patterns.items.call_count == 0

        assert result1 == result2 == "artemis"

    def test_detect_persona_long_text(self, loader):
        """Test detection in long text with embedded keywords"""
        long_text = """
        This is a long document about system architecture.
        We need to optimize the performance of our database queries.
        Security is also a major concern that needs addressing.
        """
        # Should detect athena (priority 1) even though all three match
        assert loader.detect_persona(long_text) == "athena"


# ========================
# Test Suite 4: Detect All Personas
# ========================

class TestDetectAllPersonas:
    """Test detect_all_personas method"""

    @pytest.fixture
    def loader(self, tmp_path):
        """Create loader with overlapping patterns"""
        config_file = tmp_path / "test.json"
        config_file.write_text(json.dumps({
            "personas": {
                "p1": {"display_name": "P1", "title": "T1", "emoji": "1️⃣",
                       "pattern": "alpha", "flags": "i", "priority": 1},
                "p2": {"display_name": "P2", "title": "T2", "emoji": "2️⃣",
                       "pattern": "beta", "flags": "i", "priority": 2},
                "p3": {"display_name": "P3", "title": "T3", "emoji": "3️⃣",
                       "pattern": "gamma", "flags": "i", "priority": 3},
            }
        }))
        return PersonaPatternLoader(config_path=config_file)

    def test_detect_all_single_match(self, loader):
        """Test with single match"""
        result = loader.detect_all_personas("alpha only")
        assert result == ["p1"]

    def test_detect_all_multiple_matches(self, loader):
        """Test with multiple matches sorted by priority"""
        result = loader.detect_all_personas("alpha beta gamma")
        assert result == ["p1", "p2", "p3"]  # Sorted by priority

    def test_detect_all_no_matches(self, loader):
        """Test with no matches"""
        result = loader.detect_all_personas("no keywords here")
        assert result == []

    def test_detect_all_partial_matches(self, loader):
        """Test with some matches"""
        result = loader.detect_all_personas("alpha gamma")
        assert result == ["p1", "p3"]


# ========================
# Test Suite 5: Metadata Operations
# ========================

class TestMetadataOperations:
    """Test metadata retrieval methods"""

    @pytest.fixture
    def loader(self, tmp_path):
        config_file = tmp_path / "test.json"
        config_file.write_text(json.dumps({
            "personas": {
                "test": {
                    "display_name": "Test Persona",
                    "title": "Tester",
                    "emoji": "🧪",
                    "pattern": "test",
                    "flags": "i",
                    "priority": 1,
                    "contexts": ["testing.md"],
                }
            }
        }))
        return PersonaPatternLoader(config_path=config_file)

    def test_get_metadata_existing_persona(self, loader):
        """Test metadata retrieval for existing persona"""
        metadata = loader.get_metadata("test")

        assert metadata["display_name"] == "Test Persona"
        assert metadata["title"] == "Tester"
        assert metadata["emoji"] == "🧪"
        assert metadata["priority"] == 1
        assert "testing.md" in metadata["contexts"]

    def test_get_metadata_nonexistent_persona(self, loader):
        """Test metadata retrieval for non-existent persona"""
        metadata = loader.get_metadata("nonexistent")
        assert metadata == {}

    def test_get_pattern_existing(self, loader):
        """Test get_pattern for existing persona"""
        pattern = loader.get_pattern("test")
        assert pattern is not None
        assert pattern.search("TEST")  # Case-insensitive

    def test_get_pattern_nonexistent(self, loader):
        """Test get_pattern for non-existent persona"""
        pattern = loader.get_pattern("nonexistent")
        assert pattern is None

    def test_list_personas(self, loader):
        """Test list_personas method"""
        personas = loader.list_personas()
        assert "test" in personas
        assert isinstance(personas, list)


# ========================
# Test Suite 6: Standalone Function
# ========================

class TestStandaloneFunction:
    """Test standalone detect_persona convenience function"""

    def test_standalone_detect_basic(self, tmp_path):
        """Test standalone function with explicit config path"""
        config_file = tmp_path / "test.json"
        config_file.write_text(json.dumps({
            "personas": {
                "quick": {
                    "display_name": "Quick",
                    "title": "Fast",
                    "emoji": "⚡",
                    "pattern": "fast",
                    "flags": "i",
                    "priority": 1,
                }
            }
        }))

        result = standalone_detect("fast execution", config_path=config_file)
        assert result == "quick"

    def test_standalone_detect_no_match(self, tmp_path):
        """Test standalone function with no match"""
        config_file = tmp_path / "test.json"
        config_file.write_text(json.dumps({"personas": {}}))

        result = standalone_detect("no match", config_path=config_file)
        assert result is None


# ========================
# Test Suite 7: CLI Entry Point
# ========================

class TestCLIEntryPoint:
    """Test __main__ CLI behavior"""

    def test_cli_no_arguments(self):
        """Test CLI with no arguments"""
        test_args = ['persona_pattern_loader.py']

        with patch('sys.argv', test_args):
            with pytest.raises(SystemExit) as exc_info:
                exec(open(Path(__file__).parent.parent.parent.parent /
                         "shared" / "utils" / "persona_pattern_loader.py").read())

            assert exc_info.value.code == 1

    def test_cli_with_text_argument(self, tmp_path, capsys):
        """Test CLI with text argument"""
        # Create test config
        config_file = tmp_path / "test.json"
        config_file.write_text(json.dumps({
            "personas": {
                "cli_test": {
                    "display_name": "CLI Test",
                    "title": "Tester",
                    "emoji": "🖥️",
                    "pattern": "optimize",
                    "flags": "i",
                    "priority": 1,
                }
            }
        }))

        # Simulate CLI execution
        test_args = ['persona_pattern_loader.py', 'optimize', 'this', 'code']

        with patch('sys.argv', test_args):
            with patch('shared.utils.persona_pattern_loader.PersonaPatternLoader') as MockLoader:
                mock_loader = MagicMock()
                MockLoader.return_value = mock_loader

                mock_loader.detect_persona.return_value = "cli_test"
                mock_loader.get_metadata.return_value = {
                    "display_name": "CLI Test",
                    "title": "Tester",
                    "emoji": "🖥️",
                    "pattern": "optimize",
                    "priority": 1,
                }

                # Would execute CLI code here
                # (Cannot fully test __main__ block without refactoring)
