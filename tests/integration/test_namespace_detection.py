"""
Integration tests for namespace detection and validation.

Tests the real-world behavior of namespace detection in various scenarios:
- Git repository detection
- Environment variable override
- Marker file detection
- CWD hash fallback
- MCP server instance isolation

Phase: 2a (Namespace detection stabilization)
"""

import asyncio
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from src.utils.namespace import (
    NamespaceError,
    detect_git_root,
    detect_project_namespace,
    get_git_remote_url,
    namespace_from_git_url,
    sanitize_namespace,
    validate_namespace,
)


class TestNamespaceSanitization:
    """Test namespace sanitization and validation."""

    def test_sanitize_basic(self):
        """Test basic sanitization."""
        assert sanitize_namespace("MyProject") == "myproject"
        assert sanitize_namespace("my-project") == "my-project"
        assert sanitize_namespace("my_project") == "my_project"
        assert sanitize_namespace("my.project") == "my.project"

    def test_sanitize_special_chars(self):
        """Test sanitization of special characters."""
        assert sanitize_namespace("my project!") == "my-project"
        assert sanitize_namespace("my@project#123") == "my-project-123"
        assert sanitize_namespace("my---project") == "my-project"

    def test_sanitize_max_length(self):
        """Test max length enforcement."""
        long_name = "a" * 200
        result = sanitize_namespace(long_name)
        assert len(result) == 128

    def test_sanitize_empty(self):
        """Test empty namespace handling."""
        with pytest.raises(NamespaceError, match="cannot be empty"):
            sanitize_namespace("")

        with pytest.raises(NamespaceError, match="cannot be empty"):
            sanitize_namespace("   ")

    def test_validate_default_rejection(self):
        """Test that 'default' namespace is rejected."""
        with pytest.raises(NamespaceError, match="not allowed for security reasons"):
            validate_namespace("default")

        with pytest.raises(NamespaceError, match="not allowed for security reasons"):
            validate_namespace("DEFAULT")

    def test_validate_proper_sanitization(self):
        """Test that validation requires proper sanitization."""
        with pytest.raises(NamespaceError, match="not properly sanitized"):
            validate_namespace("My Project!")

        # Should pass after sanitization
        sanitized = sanitize_namespace("My Project!")
        validate_namespace(sanitized)  # No exception


class TestGitDetection:
    """Test git repository detection."""

    @pytest.mark.asyncio
    async def test_detect_git_root_in_repo(self):
        """Test git root detection in TMWS repository."""
        # This test runs in TMWS repo, should find .git
        git_root = await detect_git_root()
        assert git_root is not None
        assert (git_root / ".git").exists()

    @pytest.mark.asyncio
    async def test_detect_git_root_not_in_repo(self):
        """Test git root detection outside repository."""
        # Create temporary directory without .git
        with tempfile.TemporaryDirectory() as tmpdir:
            git_root = await detect_git_root(Path(tmpdir))
            assert git_root is None

    @pytest.mark.asyncio
    async def test_get_git_remote_url(self):
        """Test git remote URL extraction."""
        git_root = await detect_git_root()
        if git_root:
            remote_url = await get_git_remote_url(git_root)
            # TMWS should have a git remote URL
            assert remote_url is not None
            assert "tmws" in remote_url.lower()

    def test_namespace_from_git_url_ssh(self):
        """Test namespace extraction from SSH git URL."""
        url = "git@github.com:apto-as/tmws.git"
        namespace = namespace_from_git_url(url)
        assert namespace == "github.com/apto-as/tmws"

    def test_namespace_from_git_url_https(self):
        """Test namespace extraction from HTTPS git URL."""
        url = "https://github.com/apto-as/tmws"
        namespace = namespace_from_git_url(url)
        assert namespace == "github.com/apto-as/tmws"

    def test_namespace_from_git_url_with_git_suffix(self):
        """Test namespace extraction with .git suffix removal."""
        url = "https://github.com/apto-as/tmws.git"
        namespace = namespace_from_git_url(url)
        assert namespace == "github.com/apto-as/tmws"


class TestProjectNamespaceDetection:
    """Test full project namespace detection flow."""

    @pytest.mark.asyncio
    async def test_env_var_priority(self):
        """Test that environment variable has highest priority."""
        with patch.dict(os.environ, {"TRINITAS_PROJECT_NAMESPACE": "test-project"}):
            namespace = await detect_project_namespace()
            assert namespace == "test-project"

    @pytest.mark.asyncio
    async def test_git_detection_in_tmws(self):
        """Test git-based detection in TMWS repository."""
        # Clear environment variable to test git detection
        with patch.dict(os.environ, {"TRINITAS_PROJECT_NAMESPACE": ""}, clear=True):
            namespace = await detect_project_namespace()

            # Should detect git root and extract namespace
            assert namespace != ""
            # TMWS repo should be detected
            assert "tmws" in namespace.lower() or "github.com" in namespace

    @pytest.mark.asyncio
    async def test_cwd_hash_fallback(self):
        """Test CWD hash fallback when no git repo found."""
        # Create temporary directory without git
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Patch Path.cwd() to return temp directory
            with (
                patch("src.utils.namespace.Path.cwd", return_value=tmpdir_path),
                patch.dict(os.environ, {"TRINITAS_PROJECT_NAMESPACE": ""}, clear=True),
            ):
                namespace = await detect_project_namespace()

                # Should generate project_<hash> namespace
                assert namespace.startswith("project_")
                assert len(namespace) == len("project_") + 16  # SHA256 truncated to 16 chars

    @pytest.mark.asyncio
    async def test_marker_file_detection(self):
        """Test .trinitas-project.yaml marker file detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create marker file
            marker_file = tmpdir_path / ".trinitas-project.yaml"
            marker_file.write_text("namespace: test-marker-project\n")

            # Patch cwd and clear env var
            with (
                patch("src.utils.namespace.Path.cwd", return_value=tmpdir_path),
                patch.dict(os.environ, {"TRINITAS_PROJECT_NAMESPACE": ""}, clear=True),
            ):
                namespace = await detect_project_namespace()
                assert namespace == "test-marker-project"


class TestNamespaceConsistency:
    """Test namespace consistency across scenarios."""

    @pytest.mark.asyncio
    async def test_same_project_consistent_namespace(self):
        """Test that same project always gets same namespace."""
        # Detect namespace multiple times
        namespace1 = await detect_project_namespace()
        await asyncio.sleep(0.01)  # Small delay
        namespace2 = await detect_project_namespace()

        assert namespace1 == namespace2, "Namespace should be consistent across calls"

    @pytest.mark.asyncio
    async def test_subdir_same_namespace(self):
        """Test that subdirectories in same project get same namespace."""
        # TMWS has subdirectories (src/, tests/, docs/)
        # All should detect the same git root

        git_root = await detect_git_root()
        if git_root:
            # Test from src/ subdirectory
            src_dir = git_root / "src"
            if src_dir.exists():
                git_root_from_subdir = await detect_git_root(src_dir)
                assert git_root_from_subdir == git_root

    @pytest.mark.asyncio
    async def test_different_projects_different_namespace(self):
        """Test that different projects get different namespaces."""
        # Project 1: TMWS (current)
        namespace1 = await detect_project_namespace()

        # Project 2: Temporary directory (simulates different project)
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            with (
                patch("src.utils.namespace.Path.cwd", return_value=tmpdir_path),
                patch.dict(os.environ, {"TRINITAS_PROJECT_NAMESPACE": ""}, clear=True),
            ):
                namespace2 = await detect_project_namespace()

                # Different projects should have different namespaces
                assert namespace1 != namespace2


class TestMCPServerIsolation:
    """Test MCP server instance isolation with different namespaces."""

    @pytest.mark.asyncio
    async def test_instance_id_includes_namespace(self):
        """Test that MCP server instance ID reflects namespace."""
        from src.mcp_server import HybridMCPServer

        # Create two server instances with different namespaces
        with patch.dict(os.environ, {"TRINITAS_PROJECT_NAMESPACE": "project-a"}):
            server_a = HybridMCPServer()
            namespace_a = await detect_project_namespace()

        with patch.dict(os.environ, {"TRINITAS_PROJECT_NAMESPACE": "project-b"}):
            server_b = HybridMCPServer()
            namespace_b = await detect_project_namespace()

        # Verify namespaces are different
        assert namespace_a != namespace_b

        # Verify instance IDs are different
        assert server_a.instance_id != server_b.instance_id


@pytest.mark.integration
class TestNamespaceSecurityBoundaries:
    """Test namespace security boundaries and isolation."""

    @pytest.mark.asyncio
    async def test_default_namespace_rejected_in_store(self):
        """Test that 'default' namespace is rejected in memory storage."""
        from src.core.database import get_session
        from src.services.memory_service import HybridMemoryService

        async with get_session() as session:
            memory_service = HybridMemoryService(session)

            # Attempt to store memory with 'default' namespace
            with pytest.raises(Exception):  # Should raise NamespaceError or similar
                await memory_service.create_memory(
                    content="Test content",
                    agent_id="test-agent",
                    namespace="default",  # Explicitly 'default' should be rejected
                )

    @pytest.mark.asyncio
    async def test_auto_detection_never_returns_default(self):
        """Test that auto-detection never returns 'default' namespace."""
        # Test in various scenarios
        scenarios = [
            {},  # No env var
            {"TRINITAS_PROJECT_NAMESPACE": ""},  # Empty env var
        ]

        for env_patch in scenarios:
            with patch.dict(os.environ, env_patch, clear=True):
                namespace = await detect_project_namespace()

                # Should never be 'default'
                assert namespace.lower() != "default"

                # Should pass validation
                validate_namespace(namespace)  # Should not raise


# Performance benchmarks
@pytest.mark.benchmark
class TestNamespaceDetectionPerformance:
    """Benchmark namespace detection performance."""

    @pytest.mark.asyncio
    async def test_env_var_latency(self, benchmark):
        """Benchmark environment variable detection latency."""

        async def detect_with_env():
            with patch.dict(os.environ, {"TRINITAS_PROJECT_NAMESPACE": "test-project"}):
                return await detect_project_namespace()

        # Target: < 1ms
        result = await benchmark(detect_with_env)
        assert result == "test-project"

    @pytest.mark.asyncio
    async def test_git_detection_latency(self, benchmark):
        """Benchmark git detection latency."""

        async def detect_with_git():
            with patch.dict(os.environ, {"TRINITAS_PROJECT_NAMESPACE": ""}, clear=True):
                return await detect_project_namespace()

        # Target: < 10ms
        result = await benchmark(detect_with_git)
        assert result != ""


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "-s"])
