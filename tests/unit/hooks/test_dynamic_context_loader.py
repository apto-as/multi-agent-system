"""
Comprehensive test suite for hooks/core/dynamic_context_loader.py

Test Coverage:
- DynamicContextLoader initialization
- Persona detection via compiled regex patterns (6 personas)
- Explicit /trinitas command detection
- Context need detection (performance, security, coordination, tmws, agents)
- Context building (minimal payload generation)
- process_hook full integration (stdin/stdout processing)
- Error handling (graceful failure, never blocks user)
- LRU cache behavior
- SecureFileLoader integration
- main() entry point

Security Testing:
- SecureFileLoader path validation
- Allowed roots and extensions
- CWE-22, CWE-73 mitigation

Performance Testing:
- Sub-millisecond response times
- LRU cache effectiveness

Version: Phase 2 Week 1 Day 4-5
Author: Artemis (Technical Perfectionist) + Hera (Strategic Commander)
"""

import json
import os
import sys
import pytest
import re
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import StringIO

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from hooks.core.dynamic_context_loader import DynamicContextLoader


class TestDynamicContextLoaderInitialization:
    """Test initialization and setup"""

    def test_initialization_default_base_path(self):
        """Test initialization with default base path"""
        loader = DynamicContextLoader()

        expected_path = Path("/Users/apto-as/workspace/github.com/apto-as/trinitas-agents")
        assert loader.base_path == expected_path
        assert loader._cache == {}
        assert loader._file_loader is not None

    def test_initialization_custom_base_path(self, tmp_path):
        """Test initialization with custom base path"""
        loader = DynamicContextLoader(base_path=tmp_path)

        assert loader.base_path == tmp_path
        assert loader._cache == {}

    def test_initialization_secure_file_loader_config(self):
        """Test SecureFileLoader is properly configured"""
        loader = DynamicContextLoader()

        # Verify allowed roots
        assert len(loader._file_loader.allowed_roots) > 0
        assert any("trinitas-agents" in str(root) for root in loader._file_loader.allowed_roots)

        # Verify allowed extensions
        assert ".md" in loader._file_loader.allowed_extensions

    def test_persona_patterns_compiled(self):
        """Test persona patterns are pre-compiled regex objects"""
        loader = DynamicContextLoader()

        # Verify all persona patterns exist
        expected_personas = ["athena", "artemis", "hestia", "eris", "hera", "muses"]
        for persona in expected_personas:
            assert persona in loader.PERSONA_PATTERNS
            assert isinstance(loader.PERSONA_PATTERNS[persona], re.Pattern)

    def test_context_files_defined(self):
        """Test context file mappings are defined"""
        loader = DynamicContextLoader()

        expected_contexts = ["performance", "security", "coordination", "tmws", "agents"]
        for context in expected_contexts:
            assert context in loader.CONTEXT_FILES
            assert isinstance(loader.CONTEXT_FILES[context], str)


class TestPersonaDetection:
    """Test persona detection functionality"""

    @pytest.fixture
    def loader(self):
        """Create loader instance"""
        return DynamicContextLoader()

    def test_detect_athena_orchestration(self, loader):
        """Test Athena detection with orchestration keywords"""
        prompt = "Please orchestrate a workflow automation for parallel processing"
        personas = loader.detect_personas(prompt)

        assert "athena" in personas

    def test_detect_artemis_optimization(self, loader):
        """Test Artemis detection with optimization keywords"""
        prompt = "Optimize the performance and improve code quality"
        personas = loader.detect_personas(prompt)

        assert "artemis" in personas

    def test_detect_hestia_security(self, loader):
        """Test Hestia detection with security keywords"""
        prompt = "Audit the security and check for vulnerabilities"
        personas = loader.detect_personas(prompt)

        assert "hestia" in personas

    def test_detect_eris_coordination(self, loader):
        """Test Eris detection with coordination keywords"""
        prompt = "Coordinate team collaboration and mediate conflicts"
        personas = loader.detect_personas(prompt)

        assert "eris" in personas

    def test_detect_hera_strategy(self, loader):
        """Test Hera detection with strategy keywords"""
        prompt = "Design the strategic architecture and create a roadmap"
        personas = loader.detect_personas(prompt)

        assert "hera" in personas

    def test_detect_muses_documentation(self, loader):
        """Test Muses detection with documentation keywords"""
        prompt = "Document the knowledge base and create structured records"
        personas = loader.detect_personas(prompt)

        assert "muses" in personas

    def test_detect_multiple_personas(self, loader):
        """Test detection of multiple personas in one prompt"""
        prompt = "Optimize performance and audit security of the workflow"
        personas = loader.detect_personas(prompt)

        # Should detect both Artemis (optimize, performance) and Hestia (audit, security)
        assert "artemis" in personas
        assert "hestia" in personas

    def test_detect_personas_case_insensitive(self, loader):
        """Test persona detection is case-insensitive"""
        prompt = "OPTIMIZE PERFORMANCE AND SECURITY AUDIT"
        personas = loader.detect_personas(prompt)

        assert "artemis" in personas
        assert "hestia" in personas

    def test_detect_personas_empty_prompt(self, loader):
        """Test with empty prompt"""
        prompt = ""
        personas = loader.detect_personas(prompt)

        assert personas == []

    def test_detect_personas_no_triggers(self, loader):
        """Test with prompt that has no persona triggers"""
        prompt = "Hello, how are you today?"
        personas = loader.detect_personas(prompt)

        assert personas == []


class TestExplicitTrinitasCommands:
    """Test explicit /trinitas command detection"""

    @pytest.fixture
    def loader(self):
        """Create loader instance"""
        return DynamicContextLoader()

    def test_detect_explicit_trinitas_execute_athena(self, loader):
        """Test explicit /trinitas execute athena command"""
        prompt = "/trinitas execute athena 'Design system architecture'"
        personas = loader.detect_personas(prompt)

        # Should detect athena from explicit command
        assert personas == ["athena"]

    def test_detect_explicit_trinitas_execute_artemis(self, loader):
        """Test explicit /trinitas execute artemis command"""
        prompt = "/trinitas execute artemis 'Optimize database queries'"
        personas = loader.detect_personas(prompt)

        assert personas == ["artemis"]

    def test_detect_explicit_trinitas_execute_hestia(self, loader):
        """Test explicit /trinitas execute hestia command"""
        prompt = "/trinitas execute hestia 'Security audit required'"
        personas = loader.detect_personas(prompt)

        assert personas == ["hestia"]

    def test_detect_explicit_trinitas_mixed_case(self, loader):
        """Test explicit command with mixed case"""
        prompt = "/TRINITAS EXECUTE Hera 'Strategic planning'"
        personas = loader.detect_personas(prompt)

        assert personas == ["hera"]

    def test_detect_trinitas_without_execute(self, loader):
        """Test /trinitas without execute keyword"""
        prompt = "/trinitas analyze system"
        personas = loader.detect_personas(prompt)

        # Should fall back to pattern matching
        assert isinstance(personas, list)


class TestContextNeedDetection:
    """Test context need detection"""

    @pytest.fixture
    def loader(self):
        """Create loader instance"""
        return DynamicContextLoader()

    def test_detect_performance_context(self, loader):
        """Test performance context detection"""
        prompt = "Optimize the slow API latency and improve speed"
        contexts = loader.detect_context_needs(prompt)

        assert "performance" in contexts

    def test_detect_security_context(self, loader):
        """Test security context detection"""
        prompt = "Check for XSS vulnerabilities and SQL injection risks"
        contexts = loader.detect_context_needs(prompt)

        assert "security" in contexts

    def test_detect_coordination_context(self, loader):
        """Test coordination context detection"""
        prompt = "Coordinate team workflow for parallel processing"
        contexts = loader.detect_context_needs(prompt)

        assert "coordination" in contexts

    def test_detect_tmws_context(self, loader):
        """Test TMWS context detection"""
        prompt = "Use TMWS memory to recall previous decisions"
        contexts = loader.detect_context_needs(prompt)

        assert "tmws" in contexts

    def test_detect_agents_context(self, loader):
        """Test agents context detection"""
        prompt = "Analyze the system and evaluate all components"
        contexts = loader.detect_context_needs(prompt)

        assert "agents" in contexts

    def test_detect_multiple_contexts(self, loader):
        """Test detection of multiple contexts"""
        prompt = "Optimize security and coordinate team review"
        contexts = loader.detect_context_needs(prompt)

        assert "performance" in contexts or "security" in contexts
        assert "coordination" in contexts or "agents" in contexts

    def test_detect_japanese_keywords(self, loader):
        """Test Japanese keyword detection"""
        prompt = "最適化とセキュリティ監査が必要です"
        contexts = loader.detect_context_needs(prompt)

        assert "performance" in contexts or "security" in contexts

    def test_detect_context_empty_prompt(self, loader):
        """Test with empty prompt"""
        prompt = ""
        contexts = loader.detect_context_needs(prompt)

        assert contexts == []


class TestContextBuilding:
    """Test build_context method"""

    @pytest.fixture
    def loader(self):
        """Create loader instance"""
        return DynamicContextLoader()

    def test_build_context_with_personas(self, loader):
        """Test context building with personas"""
        personas = ["athena", "artemis"]
        contexts = []

        result = loader.build_context(personas, contexts)

        assert "Active Personas for This Task" in result
        assert "athena" in result.lower()
        assert "artemis" in result.lower()

    def test_build_context_with_contexts(self, loader):
        """Test context building with contexts"""
        personas = []
        contexts = ["performance", "security"]

        result = loader.build_context(personas, contexts)

        assert "Relevant Documentation" in result
        assert "performance" in result.lower()
        assert "security" in result.lower()

    def test_build_context_complete(self, loader):
        """Test context building with both personas and contexts"""
        personas = ["athena"]
        contexts = ["performance"]

        result = loader.build_context(personas, contexts)

        assert "Active Personas for This Task" in result
        assert "Relevant Documentation" in result

    def test_build_context_limits_personas(self, loader):
        """Test persona limit (max 2)"""
        personas = ["athena", "artemis", "hestia", "eris"]
        contexts = []

        result = loader.build_context(personas, contexts)

        # Should only include first 2
        lines = result.split("\n")
        persona_lines = [line for line in lines if "**" in line and ":" in line]
        assert len(persona_lines) <= 2

    def test_build_context_limits_contexts(self, loader):
        """Test context limit (max 2)"""
        personas = []
        contexts = ["performance", "security", "coordination", "tmws"]

        result = loader.build_context(personas, contexts)

        # Should only include first 2
        lines = result.split("\n")
        context_lines = [line for line in lines if "@" in line]
        assert len(context_lines) <= 2

    def test_build_context_empty_inputs(self, loader):
        """Test with empty inputs"""
        personas = []
        contexts = []

        result = loader.build_context(personas, contexts)

        assert result == ""


class TestProcessHook:
    """Test process_hook method (full integration)"""

    @pytest.fixture
    def loader(self):
        """Create loader instance"""
        return DynamicContextLoader()

    def test_process_hook_basic(self, loader):
        """Test basic hook processing"""
        stdin_data = {
            "prompt": {
                "text": "Optimize performance and audit security"
            }
        }

        result = loader.process_hook(stdin_data)

        assert "addedContext" in result
        assert isinstance(result["addedContext"], list)

        # Should have detected personas and contexts
        if result["addedContext"]:
            context_item = result["addedContext"][0]
            assert context_item["type"] == "text"
            assert "text" in context_item

    def test_process_hook_with_trinitas_command(self, loader):
        """Test hook processing with /trinitas command"""
        stdin_data = {
            "prompt": {
                "text": "/trinitas execute athena 'Design architecture'"
            }
        }

        result = loader.process_hook(stdin_data)

        assert "addedContext" in result

    def test_process_hook_empty_prompt(self, loader):
        """Test with empty prompt"""
        stdin_data = {
            "prompt": {
                "text": ""
            }
        }

        result = loader.process_hook(stdin_data)

        assert result == {"addedContext": []}

    def test_process_hook_missing_prompt_key(self, loader):
        """Test with missing prompt key"""
        stdin_data = {}

        result = loader.process_hook(stdin_data)

        assert result == {"addedContext": []}

    def test_process_hook_missing_text_key(self, loader):
        """Test with missing text key in prompt"""
        stdin_data = {
            "prompt": {}
        }

        result = loader.process_hook(stdin_data)

        assert result == {"addedContext": []}

    def test_process_hook_error_handling(self, loader):
        """Test error handling never blocks user"""
        stdin_data = {
            "prompt": {
                "text": "Test prompt"
            }
        }

        # Mock detect_personas to raise exception
        with patch.object(loader, 'detect_personas', side_effect=Exception("Test error")):
            captured_stderr = StringIO()

            with patch('sys.stderr', new=captured_stderr):
                result = loader.process_hook(stdin_data)

            # Should return empty addedContext on error
            assert result == {"addedContext": []}

            # Error should be logged to stderr
            assert "Error processing hook" in captured_stderr.getvalue()


class TestLRUCacheIntegration:
    """Test LRU cache functionality"""

    def test_load_file_caching(self, tmp_path):
        """Test file loading with LRU caching"""
        # Create test file
        test_file = tmp_path / "test.md"
        test_file.write_text("# Test Content\nCached content")

        loader = DynamicContextLoader(base_path=tmp_path)

        # Add tmp_path to allowed roots for this test
        # (SecureFileLoader uses class-level ALLOWED_ROOTS which doesn't include tmp_path)
        loader._file_loader.add_allowed_root(tmp_path)

        try:
            # First load
            result1 = loader._load_file("test.md")
            assert result1 is not None

            # Second load (should use cache)
            result2 = loader._load_file("test.md")
            assert result2 == result1

            # Verify cache info (lru_cache provides cache_info)
            cache_info = loader._load_file.cache_info()
            assert cache_info.hits >= 1  # At least one cache hit

        finally:
            # Cleanup: Remove tmp_path from allowed roots to avoid affecting other tests
            loader._file_loader.allowed_roots = [
                root for root in loader._file_loader.allowed_roots
                if not root.startswith(str(tmp_path))
            ]

    def test_lru_cache_maxsize(self, tmp_path):
        """Test LRU cache respects maxsize (32)"""
        loader = DynamicContextLoader(base_path=tmp_path)

        # Cache should have maxsize of 32
        cache_info = loader._load_file.cache_info()
        assert cache_info.maxsize == 32


class TestSecureFileLoaderIntegration:
    """Test SecureFileLoader integration"""

    def test_secure_file_loader_valid_file(self, tmp_path):
        """Test loading valid file within allowed roots"""
        # Create test file
        test_file = tmp_path / "valid.md"
        test_file.write_text("# Valid Content\nAllowed file")

        loader = DynamicContextLoader(base_path=tmp_path)

        # Add tmp_path to allowed roots for this test
        # (SecureFileLoader uses class-level ALLOWED_ROOTS which doesn't include tmp_path)
        loader._file_loader.add_allowed_root(tmp_path)

        try:
            # Should successfully load
            result = loader._load_file("valid.md")
            assert result is not None
            assert "Valid Content" in result

        finally:
            # Cleanup: Remove tmp_path from allowed roots to avoid affecting other tests
            loader._file_loader.allowed_roots = [
                root for root in loader._file_loader.allowed_roots
                if not root.startswith(str(tmp_path))
            ]

    def test_secure_file_loader_invalid_extension(self, tmp_path):
        """Test SecureFileLoader rejects invalid extensions"""
        # Create file with invalid extension
        test_file = tmp_path / "test.exe"
        test_file.write_text("Malicious content")

        loader = DynamicContextLoader(base_path=tmp_path)

        # Should reject .exe files
        result = loader._load_file("test.exe")
        assert result is None or result == ""

    def test_secure_file_loader_path_traversal_prevention(self, tmp_path):
        """Test path traversal attack prevention (CWE-22)"""
        loader = DynamicContextLoader(base_path=tmp_path)

        # Attempt path traversal
        result = loader._load_file("../../../../etc/passwd")

        # Should be blocked
        assert result is None or result == ""


class TestMainEntryPoint:
    """Test main() function and stdin/stdout integration"""

    def test_main_with_valid_input(self, tmp_path):
        """Test main() with valid stdin input"""
        stdin_data = {
            "prompt": {
                "text": "Optimize performance"
            }
        }

        # Mock stdin
        stdin_input = json.dumps(stdin_data)
        captured_stdout = StringIO()

        with patch('sys.stdin', StringIO(stdin_input)):
            with patch('sys.stdout', new=captured_stdout):
                from hooks.core.dynamic_context_loader import main

                try:
                    main()
                except SystemExit as e:
                    assert e.code == 0

        # Verify output is valid JSON
        output = captured_stdout.getvalue()
        result = json.loads(output)
        assert "addedContext" in result

    def test_main_with_empty_input(self):
        """Test main() with empty stdin"""
        stdin_input = "{}"
        captured_stdout = StringIO()

        with patch('sys.stdin', StringIO(stdin_input)):
            with patch('sys.stdout', new=captured_stdout):
                from hooks.core.dynamic_context_loader import main

                try:
                    main()
                except SystemExit as e:
                    assert e.code == 0

        # Should return empty addedContext
        output = captured_stdout.getvalue()
        result = json.loads(output)
        assert result == {"addedContext": []}

    def test_main_with_invalid_json(self):
        """Test main() handles invalid JSON gracefully"""
        stdin_input = "invalid json"
        captured_stdout = StringIO()
        captured_stderr = StringIO()

        with patch('sys.stdin', StringIO(stdin_input)):
            with patch('sys.stdout', new=captured_stdout):
                with patch('sys.stderr', new=captured_stderr):
                    from hooks.core.dynamic_context_loader import main

                    try:
                        main()
                    except SystemExit as e:
                        assert e.code == 0

        # Should return empty addedContext on error
        output = captured_stdout.getvalue()
        result = json.loads(output)
        assert result == {"addedContext": []}

    def test_main_exception_handling(self):
        """Test main() handles unexpected exceptions gracefully"""
        stdin_input = '{"prompt": {"text": "test"}}'
        captured_stdout = StringIO()
        captured_stderr = StringIO()

        with patch('sys.stdin', StringIO(stdin_input)):
            with patch('sys.stdout', new=captured_stdout):
                with patch('sys.stderr', new=captured_stderr):
                    # Mock DynamicContextLoader to raise exception
                    with patch('hooks.core.dynamic_context_loader.DynamicContextLoader', side_effect=Exception("Test error")):
                        from hooks.core.dynamic_context_loader import main

                        try:
                            main()
                        except SystemExit as e:
                            assert e.code == 0

        # Should still return valid JSON
        output = captured_stdout.getvalue()
        result = json.loads(output)
        assert result == {"addedContext": []}

        # Error should be logged
        assert "Unexpected error" in captured_stderr.getvalue()


class TestPerformanceCharacteristics:
    """Test performance characteristics (sub-millisecond requirements)"""

    @pytest.fixture
    def loader(self):
        """Create loader instance"""
        return DynamicContextLoader()

    def test_persona_detection_performance(self, loader):
        """Test persona detection is fast (< 1ms typical)"""
        import time

        prompt = "Optimize performance and audit security vulnerabilities"

        start = time.perf_counter()
        personas = loader.detect_personas(prompt)
        elapsed = time.perf_counter() - start

        # Should complete very quickly (allowing 10ms for test variability)
        assert elapsed < 0.01  # 10ms
        assert len(personas) > 0

    def test_context_detection_performance(self, loader):
        """Test context detection is fast (< 1ms typical)"""
        import time

        prompt = "Optimize performance and audit security vulnerabilities"

        start = time.perf_counter()
        contexts = loader.detect_context_needs(prompt)
        elapsed = time.perf_counter() - start

        # Should complete very quickly
        assert elapsed < 0.01  # 10ms
        assert len(contexts) > 0

    def test_build_context_performance(self, loader):
        """Test context building is fast (< 0.1ms typical)"""
        import time

        personas = ["athena", "artemis"]
        contexts = ["performance", "security"]

        start = time.perf_counter()
        result = loader.build_context(personas, contexts)
        elapsed = time.perf_counter() - start

        # Should complete very quickly
        assert elapsed < 0.001  # 1ms
        assert len(result) > 0
