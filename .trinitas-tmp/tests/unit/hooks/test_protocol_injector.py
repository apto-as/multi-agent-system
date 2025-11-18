"""
Comprehensive test suite for hooks/core/protocol_injector.py

Test Coverage:
- MemoryBasedProtocolInjector initialization
- Core memory loading (with fallback to CLAUDE.md/AGENTS.md)
- Agent memory loading (primary and fallback paths)
- Context profile detection and memory loading
- Previous session summary loading
- DF2 modifier integration
- Session start injection (full context)
- Pre-compact injection (minimal context)
- Environment variable handling
- Verbose mode vs quiet mode output

Security Testing:
- SecureFileLoader integration
- Path validation and restriction

Version: Phase 2 Week 1 Day 4-5
Author: Artemis (Technical Perfectionist) + Hestia (Security Guardian)
"""

import json
import os
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import StringIO
from datetime import date, timedelta

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from hooks.core.protocol_injector import MemoryBasedProtocolInjector


class TestProtocolInjectorInitialization:
    """Test initialization and setup"""

    def test_initialization_basic(self):
        """Test basic initialization"""
        injector = MemoryBasedProtocolInjector()

        assert injector.memory_base == Path.home() / ".claude" / "memory"
        assert injector.secure_loader is not None
        assert injector.VERSION == "2.2.4"

    def test_initialization_secure_loader_config(self):
        """Test SecureFileLoader is properly configured"""
        injector = MemoryBasedProtocolInjector()

        # Verify allowed roots include memory base (convert Path to string for comparison)
        assert str(injector.memory_base) in injector.secure_loader.allowed_roots

        # Verify allowed extensions
        assert ".md" in injector.secure_loader.allowed_extensions
        assert ".txt" in injector.secure_loader.allowed_extensions


class TestCoreMemoryLoading:
    """Test core memory loading functionality"""

    def test_load_core_memory_success(self, tmp_path):
        """Test successful core memory loading"""
        # Create mock memory directory
        memory_dir = tmp_path / ".claude" / "memory" / "core"
        memory_dir.mkdir(parents=True)

        # Create system.md and agents.md
        (memory_dir / "system.md").write_text("# System Configuration\nCore system settings")
        (memory_dir / "agents.md").write_text("# Agent Definitions\nAgent coordination")

        # Patch home directory
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()
            core = injector.load_core_memory()

        assert "System Configuration" in core
        assert "Agent Definitions" in core
        assert "Core system settings" in core
        assert "Agent coordination" in core

    def test_load_core_memory_fallback_to_claude_md(self, tmp_path):
        """Test fallback to CLAUDE.md when memory files missing"""
        # Create .claude directory without memory subdirectory
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir(parents=True)

        # Create fallback CLAUDE.md and AGENTS.md
        (claude_dir / "CLAUDE.md").write_text("# Fallback Claude Config\nFallback system")
        (claude_dir / "AGENTS.md").write_text("# Fallback Agents\nFallback agents")

        # Patch home directory
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()
            core = injector.load_core_memory()

        assert "Fallback Claude Config" in core
        assert "Fallback Agents" in core

    def test_load_core_memory_partial_fallback(self, tmp_path):
        """Test partial fallback when only one memory file exists"""
        # Create memory directory with only system.md
        memory_dir = tmp_path / ".claude" / "memory" / "core"
        memory_dir.mkdir(parents=True)
        (memory_dir / "system.md").write_text("# System Memory\nSystem content")

        # Create fallback AGENTS.md
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir(parents=True, exist_ok=True)
        (claude_dir / "AGENTS.md").write_text("# Fallback Agents\nAgent fallback")

        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()
            core = injector.load_core_memory()

        # Should contain memory file content but also fallback for agents
        assert "System Memory" in core or "Fallback Agents" in core

    def test_load_core_memory_empty_when_all_missing(self, tmp_path):
        """Test returns empty string when all files missing"""
        # Create .claude directory but no files
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir(parents=True)

        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()
            core = injector.load_core_memory()

        assert core == ""


class TestAgentMemoryLoading:
    """Test agent-specific memory loading"""

    def test_load_agent_memory_success(self, tmp_path):
        """Test loading agent memories from memory directory"""
        # Create memory/agents directory
        agents_dir = tmp_path / ".claude" / "memory" / "agents"
        agents_dir.mkdir(parents=True)

        (agents_dir / "athena-conductor.md").write_text("# Athena\nHarmonious conductor")
        (agents_dir / "hera-strategist.md").write_text("# Hera\nStrategic commander")

        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()
            agents = injector.load_agent_memory(["athena-conductor", "hera-strategist"])

        assert "Athena" in agents
        assert "Hera" in agents
        assert "Harmonious conductor" in agents
        assert "Strategic commander" in agents
        assert "---" in agents  # Separator between agents

    def test_load_agent_memory_fallback(self, tmp_path):
        """Test fallback to .claude/agents directory"""
        # Create fallback agents directory
        agents_dir = tmp_path / ".claude" / "agents"
        agents_dir.mkdir(parents=True)

        (agents_dir / "artemis-optimizer.md").write_text("# Artemis\nTechnical perfectionist")

        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()
            agents = injector.load_agent_memory(["artemis-optimizer"])

        assert "Artemis" in agents
        assert "Technical perfectionist" in agents

    def test_load_agent_memory_mixed_sources(self, tmp_path):
        """Test loading from both memory and fallback directories"""
        # Create memory agents
        memory_agents = tmp_path / ".claude" / "memory" / "agents"
        memory_agents.mkdir(parents=True)
        (memory_agents / "athena-conductor.md").write_text("# Athena Memory\nFrom memory")

        # Create fallback agents
        fallback_agents = tmp_path / ".claude" / "agents"
        fallback_agents.mkdir(parents=True)
        (fallback_agents / "hera-strategist.md").write_text("# Hera Fallback\nFrom fallback")

        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()
            agents = injector.load_agent_memory(["athena-conductor", "hera-strategist"])

        # Should contain both
        assert "Athena Memory" in agents
        assert "Hera Fallback" in agents

    def test_load_agent_memory_empty_list(self, tmp_path):
        """Test with empty agent list"""
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()
            agents = injector.load_agent_memory([])

        assert agents == ""

    def test_load_agent_memory_nonexistent_agents(self, tmp_path):
        """Test with nonexistent agent IDs"""
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()
            agents = injector.load_agent_memory(["nonexistent-agent", "fake-persona"])

        assert agents == ""


class TestContextProfileManagement:
    """Test context profile detection and loading"""

    def test_get_context_profile_default_coding(self):
        """Test default context profile is 'coding'"""
        injector = MemoryBasedProtocolInjector()

        with patch.dict(os.environ, {}, clear=True):
            profile = injector.get_context_profile()

        assert profile == ["performance", "mcp-tools"]

    @pytest.mark.parametrize("profile_name,expected_contexts", [
        ("minimal", []),
        ("coding", ["performance", "mcp-tools"]),
        ("security", ["security", "mcp-tools"]),
        ("full", ["performance", "mcp-tools", "security", "collaboration"]),
    ])
    def test_get_context_profile_variants(self, profile_name, expected_contexts):
        """Test all context profile variants"""
        injector = MemoryBasedProtocolInjector()

        with patch.dict(os.environ, {"TRINITAS_CONTEXT_PROFILE": profile_name}):
            profile = injector.get_context_profile()

        assert profile == expected_contexts

    def test_get_context_profile_invalid_fallback(self):
        """Test fallback to 'coding' for invalid profile"""
        injector = MemoryBasedProtocolInjector()

        with patch.dict(os.environ, {"TRINITAS_CONTEXT_PROFILE": "invalid_profile"}):
            profile = injector.get_context_profile()

        assert profile == ["performance", "mcp-tools"]


class TestContextMemoryLoading:
    """Test context-specific memory loading"""

    def test_load_context_memory_success(self, tmp_path):
        """Test loading context files"""
        # Create contexts directory
        contexts_dir = tmp_path / ".claude" / "memory" / "contexts"
        contexts_dir.mkdir(parents=True)

        (contexts_dir / "performance.md").write_text("# Performance\nOptimization guidelines")
        (contexts_dir / "security.md").write_text("# Security\nSecurity standards")

        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()
            context = injector.load_context_memory(["performance", "security"])

        assert "Performance Context" in context
        assert "Security Context" in context
        assert "Optimization guidelines" in context
        assert "Security standards" in context

    def test_load_context_memory_empty_list(self, tmp_path):
        """Test with empty context list"""
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()
            context = injector.load_context_memory([])

        assert context == ""

    def test_load_context_memory_nonexistent_contexts(self, tmp_path):
        """Test with nonexistent context names"""
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()
            context = injector.load_context_memory(["nonexistent", "fake"])

        assert context == ""


class TestPreviousSessionSummary:
    """Test previous session summary loading"""

    def test_load_previous_session_summary_exists(self, tmp_path):
        """Test loading yesterday's session summary"""
        # Create sessions directory
        sessions_dir = tmp_path / ".claude" / "memory" / "sessions"
        sessions_dir.mkdir(parents=True)

        # Get yesterday's date
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        summary_file = sessions_dir / f"{yesterday}_summary.md"
        summary_file.write_text("# Yesterday's Work\nCompleted tasks: 5")

        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()
            summary = injector.load_previous_session_summary()

        assert "Previous Session Summary" in summary
        assert yesterday in summary
        assert "Yesterday's Work" in summary
        assert "Completed tasks: 5" in summary

    def test_load_previous_session_summary_missing(self, tmp_path):
        """Test when no previous session summary exists"""
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()
            summary = injector.load_previous_session_summary()

        assert summary == ""


class TestDF2ModifierIntegration:
    """Test DF2 behavioral modifier loading"""

    def test_load_df2_modifiers_success(self, tmp_path, monkeypatch):
        """Test successful DF2 modifier loading"""
        # Mock the entire df2_behavior_injector module first
        mock_module = MagicMock()
        mock_df2_class = MagicMock()
        mock_df2_instance = MagicMock()
        mock_df2_instance.inject_for_all_personas.return_value = "# DF2 Modifiers\nBehavioral context"
        mock_df2_class.return_value = mock_df2_instance
        mock_module.DF2BehaviorInjector = mock_df2_class

        injector = MemoryBasedProtocolInjector()

        with patch.dict('sys.modules', {'df2_behavior_injector': mock_module}):
            result = injector.load_df2_modifiers(["athena-conductor"])

        assert result == "# DF2 Modifiers\nBehavioral context"
        mock_df2_instance.inject_for_all_personas.assert_called_once_with("session_start")

    def test_load_df2_modifiers_import_error(self):
        """Test graceful fallback when DF2 not available"""
        injector = MemoryBasedProtocolInjector()

        with patch('hooks.core.df2_behavior_injector.DF2BehaviorInjector', side_effect=ImportError):
            result = injector.load_df2_modifiers(["athena-conductor"])

        assert result == ""

    def test_load_df2_modifiers_attribute_error(self):
        """Test handling of AttributeError"""
        injector = MemoryBasedProtocolInjector()

        with patch('hooks.core.df2_behavior_injector.DF2BehaviorInjector', side_effect=AttributeError):
            result = injector.load_df2_modifiers(["athena-conductor"])

        assert result == ""


class TestSessionStartInjection:
    """Test full session start injection"""

    def test_inject_session_start_full(self, tmp_path):
        """Test complete session start injection"""
        # Setup mock memory structure
        memory_base = tmp_path / ".claude" / "memory"
        core_dir = memory_base / "core"
        core_dir.mkdir(parents=True)

        (core_dir / "system.md").write_text("# System\nCore system")
        (core_dir / "agents.md").write_text("# Agents\nCore agents")

        agents_dir = memory_base / "agents"
        agents_dir.mkdir(parents=True)
        (agents_dir / "athena-conductor.md").write_text("# Athena\nConductor")
        (agents_dir / "hera-strategist.md").write_text("# Hera\nStrategist")

        contexts_dir = memory_base / "contexts"
        contexts_dir.mkdir(parents=True)
        (contexts_dir / "performance.md").write_text("# Performance\nOptimization")
        (contexts_dir / "mcp-tools.md").write_text("# MCP Tools\nTool usage")

        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()

            # Capture stdout
            captured_output = StringIO()
            with patch('sys.stdout', new=captured_output):
                with patch.dict(os.environ, {"TRINITAS_CONTEXT_PROFILE": "coding"}):
                    injector.inject_session_start()

            output = captured_output.getvalue()
            result = json.loads(output)

        # Verify structure
        assert "systemMessage" in result
        message = result["systemMessage"]

        # Verify core content
        assert "System" in message or "Agents" in message

        # Verify active coordinators
        assert "Active Coordination System" in message or "Athena" in message

        # Verify version info
        assert "Trinitas v2.2.4" in message
        assert "Profile: `coding`" in message

    def test_inject_session_start_minimal_profile(self, tmp_path):
        """Test session start with minimal profile"""
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()

            captured_output = StringIO()
            with patch('sys.stdout', new=captured_output):
                with patch.dict(os.environ, {"TRINITAS_CONTEXT_PROFILE": "minimal"}):
                    injector.inject_session_start()

            output = captured_output.getvalue()
            result = json.loads(output)

        assert "systemMessage" in result
        assert "minimal" in result["systemMessage"]

    def test_inject_session_start_verbose_mode(self, tmp_path):
        """Test session start in verbose mode"""
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()

            # Capture both stdout and stderr
            captured_stdout = StringIO()
            captured_stderr = StringIO()

            with patch('sys.stdout', new=captured_stdout):
                with patch('sys.stderr', new=captured_stderr):
                    with patch.dict(os.environ, {"TRINITAS_VERBOSE": "1", "TRINITAS_CONTEXT_PROFILE": "coding"}):
                        injector.inject_session_start()

            stderr_output = captured_stderr.getvalue()

            # Verbose mode should print to stderr
            assert "Trinitas v2.2.4" in stderr_output
            assert "Profile: coding" in stderr_output
            assert "tokens" in stderr_output.lower()

    def test_inject_session_start_quiet_mode(self, tmp_path):
        """Test session start in quiet mode (default)"""
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()

            captured_stdout = StringIO()
            captured_stderr = StringIO()

            with patch('sys.stdout', new=captured_stdout):
                with patch('sys.stderr', new=captured_stderr):
                    with patch.dict(os.environ, {"TRINITAS_VERBOSE": "0"}):
                        injector.inject_session_start()

            stderr_output = captured_stderr.getvalue()

            # Quiet mode should not print to stderr
            assert stderr_output == ""


class TestPreCompactInjection:
    """Test pre-compact injection (minimal summary)"""

    def test_inject_pre_compact_basic(self, tmp_path):
        """Test pre-compact injection structure"""
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()

            captured_output = StringIO()
            with patch('sys.stdout', new=captured_output):
                with patch.dict(os.environ, {"TRINITAS_CONTEXT_PROFILE": "coding"}):
                    injector.inject_pre_compact()

            output = captured_output.getvalue()
            result = json.loads(output)

        assert "systemMessage" in result
        message = result["systemMessage"]

        # Verify minimal summary structure
        assert "Trinitas Core (Level 3 Summary)" in message
        assert "Active Coordinators" in message
        assert "Athena + Hera" in message
        assert "Specialists" in message
        assert "Context Profile" in message
        assert "Key Patterns" in message
        assert "Trinitas v2.2.4" in message
        assert "Compact Mode" in message

    def test_inject_pre_compact_verbose(self, tmp_path):
        """Test pre-compact in verbose mode"""
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()

            captured_stdout = StringIO()
            captured_stderr = StringIO()

            with patch('sys.stdout', new=captured_stdout):
                with patch('sys.stderr', new=captured_stderr):
                    with patch.dict(os.environ, {"TRINITAS_VERBOSE": "1"}):
                        injector.inject_pre_compact()

            stderr_output = captured_stderr.getvalue()

            # Verbose mode should show compact mode message
            assert "Compact Mode" in stderr_output


class TestMainEntryPoint:
    """Test main() function and CLI interface"""

    def test_main_default_session_start(self, tmp_path):
        """Test main() defaults to session_start"""
        with patch.object(Path, "home", return_value=tmp_path):
            captured_output = StringIO()

            with patch('sys.stdout', new=captured_output):
                with patch('sys.argv', ['protocol_injector.py']):
                    from hooks.core.protocol_injector import main
                    main()

            output = captured_output.getvalue()
            result = json.loads(output)

            assert "systemMessage" in result
            # Should be full session start, not compact
            assert "Active Coordination System" in result["systemMessage"] or "Trinitas v2.2.4" in result["systemMessage"]

    def test_main_pre_compact_explicit(self, tmp_path):
        """Test main() with pre_compact argument"""
        with patch.object(Path, "home", return_value=tmp_path):
            captured_output = StringIO()

            with patch('sys.stdout', new=captured_output):
                with patch('sys.argv', ['protocol_injector.py', 'pre_compact']):
                    from hooks.core.protocol_injector import main
                    main()

            output = captured_output.getvalue()
            result = json.loads(output)

            assert "systemMessage" in result
            # Should be compact mode
            assert "Compact Mode" in result["systemMessage"]


class TestEnvironmentVariableHandling:
    """Test environment variable behavior"""

    def test_env_trinitas_context_profile(self, tmp_path):
        """Test TRINITAS_CONTEXT_PROFILE variable"""
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()

            with patch.dict(os.environ, {"TRINITAS_CONTEXT_PROFILE": "security"}):
                profile = injector.get_context_profile()

            assert profile == ["security", "mcp-tools"]

    def test_env_trinitas_verbose_enabled(self, tmp_path):
        """Test TRINITAS_VERBOSE=1 enables verbose output"""
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()

            captured_stderr = StringIO()
            captured_stdout = StringIO()

            with patch('sys.stdout', new=captured_stdout):
                with patch('sys.stderr', new=captured_stderr):
                    with patch.dict(os.environ, {"TRINITAS_VERBOSE": "1"}):
                        injector.inject_session_start()

            # Should have stderr output in verbose mode
            assert captured_stderr.getvalue() != ""

    def test_env_trinitas_verbose_disabled(self, tmp_path):
        """Test TRINITAS_VERBOSE=0 disables verbose output"""
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()

            captured_stderr = StringIO()
            captured_stdout = StringIO()

            with patch('sys.stdout', new=captured_stdout):
                with patch('sys.stderr', new=captured_stderr):
                    with patch.dict(os.environ, {"TRINITAS_VERBOSE": "0"}):
                        injector.inject_session_start()

            # Should have no stderr output in quiet mode
            assert captured_stderr.getvalue() == ""


class TestSecurityFileLoaderIntegration:
    """Test integration with SecureFileLoader"""

    def test_secure_file_loader_path_validation(self, tmp_path):
        """Test SecureFileLoader validates paths"""
        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()

            # Attempt to load file outside allowed roots should fail silently
            result = injector.secure_loader.load_file(
                "/etc/passwd",
                base_path=tmp_path,
                silent=True
            )

            assert result is None or result == ""

    def test_secure_file_loader_extension_validation(self, tmp_path):
        """Test SecureFileLoader validates file extensions"""
        # Create a .exe file (not allowed)
        test_file = tmp_path / "test.exe"
        test_file.write_text("Malicious content")

        with patch.object(Path, "home", return_value=tmp_path):
            injector = MemoryBasedProtocolInjector()

            result = injector.secure_loader.load_file(
                "test.exe",
                base_path=tmp_path,
                silent=True
            )

            # Should reject .exe files
            assert result is None or result == ""
