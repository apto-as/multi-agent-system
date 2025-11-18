"""
Comprehensive test suite for hooks/core/df2_behavior_injector.py

Test Coverage:
- DF2BehaviorInjector initialization and TrinitasComponent inheritance
- Behavioral modifier loading from narratives.json
- Security validation (do_not_expose_to_users flag)
- get_behavioral_context for session_start and pre_compact modes
- Context formatting methods (session_start vs pre_compact)
- inject_for_all_personas for 6 core personas
- main() entry point (test/session_start/pre_compact modes)
- Error handling for missing/invalid narratives.json

Security Testing:
- Internal-only parameters (no user-facing game terminology)
- Behavioral modifier validation
- Privacy protection

Version: Phase 2 Week 1 Day 4-5
Author: Artemis (Technical Perfectionist) + Muses (Knowledge Architect)
"""

import json
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import StringIO

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from hooks.core.df2_behavior_injector import DF2BehaviorInjector


class TestDF2BehaviorInjectorInitialization:
    """Test initialization and TrinitasComponent inheritance"""

    def test_initialization_with_valid_narratives(self, tmp_path):
        """Test initialization with valid narratives.json"""
        # Create valid narratives.json
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        narratives = {
            "do_not_expose_to_users": True,
            "description": "Internal behavioral modifiers",
            "personas": {
                "athena-conductor": {
                    "internal_modifiers": {
                        "behavioral_traits": {
                            "harmony_seeking": 0.9,
                            "analytical": 0.85
                        },
                        "decision_framework": {
                            "prefer_consensus": True
                        }
                    }
                }
            }
        }

        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        injector = DF2BehaviorInjector(narratives_path=str(config_file))

        assert injector.config is not None
        assert injector.behavioral_modifiers == narratives["personas"]
        assert injector.COMPONENT_NAME == "DF2BehaviorInjector"

    def test_initialization_with_missing_narratives(self, tmp_path):
        """Test initialization when narratives.json is missing"""
        # Point to nonexistent file
        nonexistent_path = tmp_path / "nonexistent" / "narratives.json"

        # Should not raise exception, but print warning
        captured_stderr = StringIO()
        with patch('sys.stderr', new=captured_stderr):
            injector = DF2BehaviorInjector(narratives_path=str(nonexistent_path))

        # Check warning was printed
        assert "Warning" in captured_stderr.getvalue()
        assert "not found" in captured_stderr.getvalue()

        # Behavioral modifiers should be empty dict
        assert injector.behavioral_modifiers == {}

    def test_initialization_default_path(self, project_root):
        """Test initialization with default path (.opencode/config/narratives.json)"""
        # Create default narratives location
        config_dir = project_root / ".opencode" / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        narratives = {
            "do_not_expose_to_users": True,
            "personas": {}
        }

        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        # Initialize without path (should use default)
        with patch.object(Path, 'cwd', return_value=project_root):
            injector = DF2BehaviorInjector()

        assert injector.config is not None

    def test_trinitascomponent_inheritance(self, tmp_path):
        """Test TrinitasComponent parent class features"""
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        narratives = {"personas": {}, "do_not_expose_to_users": True}
        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        injector = DF2BehaviorInjector(narratives_path=str(config_file))

        # Verify TrinitasComponent attributes
        assert hasattr(injector, 'config')
        assert hasattr(injector, 'config_path')
        assert hasattr(injector, 'project_root')

        # Verify DEFAULT_CONFIG_FILE is set
        assert injector.DEFAULT_CONFIG_FILE == "narratives.json"
        assert injector.DEFAULT_CONFIG_DIR == ".opencode/config"


class TestSecurityValidation:
    """Test security validation features"""

    def test_security_flag_present(self, tmp_path):
        """Test security flag 'do_not_expose_to_users' is validated"""
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        narratives = {
            "do_not_expose_to_users": True,
            "personas": {}
        }

        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        # Should not print warning
        captured_stderr = StringIO()
        with patch('sys.stderr', new=captured_stderr):
            injector = DF2BehaviorInjector(narratives_path=str(config_file))

        # No security warning should be printed
        assert "missing security flag" not in captured_stderr.getvalue()

    def test_security_flag_missing(self, tmp_path):
        """Test warning when security flag is missing"""
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        narratives = {
            # Missing do_not_expose_to_users flag
            "personas": {}
        }

        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        # Should print warning
        captured_stderr = StringIO()
        with patch('sys.stderr', new=captured_stderr):
            injector = DF2BehaviorInjector(narratives_path=str(config_file))

        # Security warning should be printed
        assert "missing security flag" in captured_stderr.getvalue()

    def test_security_flag_false(self, tmp_path):
        """Test warning when security flag is False"""
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        narratives = {
            "do_not_expose_to_users": False,  # Explicitly set to False
            "personas": {}
        }

        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        captured_stderr = StringIO()
        with patch('sys.stderr', new=captured_stderr):
            injector = DF2BehaviorInjector(narratives_path=str(config_file))

        # Should print warning
        assert "missing security flag" in captured_stderr.getvalue()


class TestBehavioralModifierLoading:
    """Test loading of behavioral modifiers"""

    def test_load_modifiers_success(self, tmp_path):
        """Test successful loading of behavioral modifiers"""
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        narratives = {
            "do_not_expose_to_users": True,
            "personas": {
                "athena-conductor": {
                    "internal_modifiers": {
                        "behavioral_traits": {"harmony": 0.9}
                    }
                },
                "artemis-optimizer": {
                    "internal_modifiers": {
                        "behavioral_traits": {"perfectionism": 0.95}
                    }
                }
            }
        }

        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        injector = DF2BehaviorInjector(narratives_path=str(config_file))

        assert len(injector.behavioral_modifiers) == 2
        assert "athena-conductor" in injector.behavioral_modifiers
        assert "artemis-optimizer" in injector.behavioral_modifiers

    def test_load_modifiers_empty_personas(self, tmp_path):
        """Test loading with empty personas dict"""
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        narratives = {
            "do_not_expose_to_users": True,
            "personas": {}
        }

        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        injector = DF2BehaviorInjector(narratives_path=str(config_file))

        assert injector.behavioral_modifiers == {}


class TestBehavioralContextGeneration:
    """Test get_behavioral_context method"""

    @pytest.fixture
    def injector_with_data(self, tmp_path):
        """Create injector with sample behavioral data"""
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        narratives = {
            "do_not_expose_to_users": True,
            "personas": {
                "athena-conductor": {
                    "internal_modifiers": {
                        "behavioral_traits": {
                            "harmony_seeking": 0.9,
                            "analytical_thinking": 0.85,
                            "collaboration_focus": 0.88
                        },
                        "decision_framework": {
                            "prefer_consensus": True,
                            "risk_aversion": "moderate"
                        },
                        "background_influence": {
                            "strategic_perspective": "Long-term architectural vision",
                            "communication_style": "Diplomatic and inclusive"
                        }
                    }
                }
            }
        }

        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        return DF2BehaviorInjector(narratives_path=str(config_file))

    def test_get_behavioral_context_session_start(self, injector_with_data):
        """Test behavioral context for session_start"""
        context = injector_with_data.get_behavioral_context(
            "athena-conductor",
            "session_start"
        )

        # Verify structure
        assert "Internal Behavioral Modifiers" in context
        assert "athena-conductor" in context
        assert "Decision Weighting Factors" in context
        assert "Decision Framework" in context
        assert "Contextual Background" in context

        # Verify trait formatting (Markdown bold format)
        assert "**Harmony Seeking**: 0.90" in context
        assert "**Analytical Thinking**: 0.85" in context
        assert "**Collaboration Focus**: 0.88" in context

        # Verify framework formatting
        assert "Prefer Consensus" in context
        assert "✓ Active" in context

        # Verify background influence
        assert "Strategic Perspective" in context
        assert "Long-term architectural vision" in context

    def test_get_behavioral_context_pre_compact(self, injector_with_data):
        """Test behavioral context for pre_compact (compact mode)"""
        context = injector_with_data.get_behavioral_context(
            "athena-conductor",
            "pre_compact"
        )

        # Verify compact structure
        assert "Behavioral Modifiers" in context
        assert "athena-conductor" in context
        assert "Critical traits:" in context

        # Should only have top 3 traits
        assert "Harmony Seeking: 0.90" in context
        assert "Collaboration Focus: 0.88" in context
        assert "Analytical Thinking: 0.85" in context

        # Framework should be minimal
        assert "Active:" in context

    def test_get_behavioral_context_nonexistent_persona(self, injector_with_data):
        """Test with nonexistent persona ID"""
        context = injector_with_data.get_behavioral_context(
            "nonexistent-persona",
            "session_start"
        )

        assert context == ""

    def test_get_behavioral_context_invalid_injection_point(self, injector_with_data):
        """Test with invalid injection point"""
        context = injector_with_data.get_behavioral_context(
            "athena-conductor",
            "invalid_point"
        )

        assert context == ""

    def test_get_behavioral_context_empty_modifiers(self, tmp_path):
        """Test with persona that has no internal_modifiers"""
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        narratives = {
            "do_not_expose_to_users": True,
            "personas": {
                "empty-persona": {}  # No internal_modifiers
            }
        }

        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        injector = DF2BehaviorInjector(narratives_path=str(config_file))
        context = injector.get_behavioral_context("empty-persona", "session_start")

        assert context == ""


class TestContextFormatting:
    """Test _format_session_start_context and _format_pre_compact_context"""

    def test_format_session_start_context_complete(self, tmp_path):
        """Test session_start formatting with complete data"""
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        narratives = {
            "do_not_expose_to_users": True,
            "personas": {
                "test-persona": {
                    "internal_modifiers": {
                        "behavioral_traits": {"trait1": 0.5, "trait2": 0.7},
                        "decision_framework": {"flag1": True, "value1": "test"},
                        "background_influence": {"key1": "value1"}
                    }
                }
            }
        }

        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        injector = DF2BehaviorInjector(narratives_path=str(config_file))
        context = injector.get_behavioral_context("test-persona", "session_start")

        # Verify all sections present
        assert "Internal Behavioral Modifiers" in context
        assert "Decision Weighting Factors" in context
        assert "Decision Framework" in context
        assert "Contextual Background" in context
        assert "Apply these modifiers to decision-making logic" in context

    def test_format_pre_compact_context_top_traits(self, tmp_path):
        """Test pre_compact formatting prioritizes top traits"""
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        narratives = {
            "do_not_expose_to_users": True,
            "personas": {
                "test-persona": {
                    "internal_modifiers": {
                        "behavioral_traits": {
                            "trait1": 0.3,
                            "trait2": 0.9,
                            "trait3": 0.5,
                            "trait4": 0.8,
                            "trait5": 0.6
                        }
                    }
                }
            }
        }

        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        injector = DF2BehaviorInjector(narratives_path=str(config_file))
        context = injector.get_behavioral_context("test-persona", "pre_compact")

        # Should only contain top 3 traits (0.9, 0.8, 0.6)
        assert "0.90" in context
        assert "0.80" in context
        assert "0.60" in context or "0.50" in context
        # Lower traits should not be present
        assert "0.30" not in context


class TestInjectForAllPersonas:
    """Test inject_for_all_personas method"""

    @pytest.fixture
    def complete_injector(self, tmp_path):
        """Create injector with all 6 core personas"""
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        narratives = {
            "do_not_expose_to_users": True,
            "personas": {
                "athena-conductor": {
                    "internal_modifiers": {
                        "behavioral_traits": {"harmony": 0.9}
                    }
                },
                "artemis-optimizer": {
                    "internal_modifiers": {
                        "behavioral_traits": {"perfectionism": 0.95}
                    }
                },
                "hestia-auditor": {
                    "internal_modifiers": {
                        "behavioral_traits": {"vigilance": 1.0}
                    }
                },
                "eris-coordinator": {
                    "internal_modifiers": {
                        "behavioral_traits": {"tactical_thinking": 0.85}
                    }
                },
                "hera-strategist": {
                    "internal_modifiers": {
                        "behavioral_traits": {"strategic_vision": 0.9}
                    }
                },
                "muses-documenter": {
                    "internal_modifiers": {
                        "behavioral_traits": {"knowledge_structuring": 0.88}
                    }
                }
            }
        }

        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        return DF2BehaviorInjector(narratives_path=str(config_file))

    def test_inject_for_all_personas_session_start(self, complete_injector):
        """Test inject_for_all_personas with session_start"""
        result = complete_injector.inject_for_all_personas("session_start")

        # Verify header (Markdown bold format)
        assert "Trinitas Behavioral Modifiers v2.0.0" in result
        assert "Internal Performance Enhancement Only" in result
        assert "**User Exposure**: None" in result

        # Verify all personas present
        assert "athena-conductor" in result
        assert "artemis-optimizer" in result
        assert "hestia-auditor" in result
        assert "eris-coordinator" in result
        assert "hera-strategist" in result
        assert "muses-documenter" in result

    def test_inject_for_all_personas_pre_compact(self, complete_injector):
        """Test inject_for_all_personas with pre_compact"""
        result = complete_injector.inject_for_all_personas("pre_compact")

        # Verify header
        assert "Trinitas Behavioral Modifiers v2.0.0" in result

        # Verify personas present (in compact form)
        assert "athena-conductor" in result
        assert "artemis-optimizer" in result

    def test_inject_for_all_personas_empty_modifiers(self, tmp_path):
        """Test with empty behavioral modifiers"""
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        narratives = {
            "do_not_expose_to_users": True,
            "personas": {}
        }

        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        injector = DF2BehaviorInjector(narratives_path=str(config_file))
        result = injector.inject_for_all_personas("session_start")

        assert result == ""


class TestMainEntryPoint:
    """Test main() function and CLI interface"""

    def test_main_test_mode(self, tmp_path):
        """Test main() in test mode"""
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        narratives = {
            "do_not_expose_to_users": True,
            "personas": {
                "athena-conductor": {
                    "internal_modifiers": {
                        "behavioral_traits": {"harmony": 0.9}
                    }
                }
            }
        }

        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        captured_output = StringIO()

        def mock_init(self, narratives_path=None):
            """Mock __init__ that sets required attributes"""
            self.behavioral_modifiers = {"athena-conductor": {}}
            # config is a property from TrinitasComponent, use internal attribute
            self._config = {}

        with patch('sys.stdout', new=captured_output):
            with patch('sys.argv', ['df2_behavior_injector.py', 'test']):
                with patch.object(DF2BehaviorInjector, '__init__', mock_init):
                    with patch.object(DF2BehaviorInjector, 'inject_for_all_personas', return_value="Test context"):
                        from hooks.core.df2_behavior_injector import main
                        main()

        output = captured_output.getvalue()

        # Verify test mode output
        assert "=" * 80 in output
        assert "Test Mode" in output
        assert "SESSION START INJECTION" in output
        assert "PRE-COMPACT INJECTION" in output
        assert "STATISTICS" in output
        assert "Security Validation" in output

    def test_main_session_start_mode(self, tmp_path):
        """Test main() in session_start mode"""
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        narratives = {
            "do_not_expose_to_users": True,
            "personas": {
                "athena-conductor": {
                    "internal_modifiers": {
                        "behavioral_traits": {"harmony": 0.9}
                    }
                }
            }
        }

        config_file = config_dir / "narratives.json"
        with open(config_file, "w") as f:
            json.dump(narratives, f)

        captured_output = StringIO()

        with patch('sys.stdout', new=captured_output):
            with patch('sys.argv', ['df2_behavior_injector.py', 'session_start']):
                with patch.object(DF2BehaviorInjector, '__init__', lambda self, narratives_path=None: None):
                    with patch.object(DF2BehaviorInjector, 'inject_for_all_personas', return_value="Session start context"):
                        from hooks.core.df2_behavior_injector import main
                        main()

        output = captured_output.getvalue()

        # Should output context directly (no test mode headers)
        assert "Session start context" in output
        assert "Test Mode" not in output

    def test_main_pre_compact_mode(self, tmp_path):
        """Test main() in pre_compact mode"""
        captured_output = StringIO()

        with patch('sys.stdout', new=captured_output):
            with patch('sys.argv', ['df2_behavior_injector.py', 'pre_compact']):
                with patch.object(DF2BehaviorInjector, '__init__', lambda self, narratives_path=None: None):
                    with patch.object(DF2BehaviorInjector, 'inject_for_all_personas', return_value="Pre-compact context"):
                        from hooks.core.df2_behavior_injector import main
                        main()

        output = captured_output.getvalue()

        assert "Pre-compact context" in output

    def test_main_no_args(self):
        """Test main() with no arguments"""
        captured_output = StringIO()

        with patch('sys.stdout', new=captured_output):
            with patch('sys.argv', ['df2_behavior_injector.py']):
                with pytest.raises(SystemExit) as exc_info:
                    from hooks.core.df2_behavior_injector import main
                    main()

                assert exc_info.value.code == 1

        output = captured_output.getvalue()
        assert "Usage" in output

    def test_main_invalid_injection_point(self):
        """Test main() with invalid injection point"""
        captured_stderr = StringIO()

        with patch('sys.stderr', new=captured_stderr):
            with patch('sys.argv', ['df2_behavior_injector.py', 'invalid']):
                with patch.object(DF2BehaviorInjector, '__init__', lambda self, narratives_path=None: None):
                    with pytest.raises(SystemExit) as exc_info:
                        from hooks.core.df2_behavior_injector import main
                        main()

                    assert exc_info.value.code == 1

        output = captured_stderr.getvalue()
        assert "Unknown injection point" in output
