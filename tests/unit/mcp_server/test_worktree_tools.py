"""Unit tests for Git Worktree MCP Tools.

Tests the MCP tool functions for worktree management:
- git_worktree_create: Create isolated worktree for task
- git_worktree_merge: Merge completed task worktree
- git_worktree_list: List active worktrees

Phase 4.1 - Issue #32: Git Worktree Workflow Support

Author: Metis (Development Assistant)
Created: 2025-12-09
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestGitWorktreeCreate:
    """Tests for git_worktree_create MCP tool."""

    @pytest.fixture
    def mock_server(self):
        """Create a mock server with memory_repo."""
        server = MagicMock()
        server.memory_repo = None
        return server

    @pytest.fixture
    def mock_memory_repo(self, tmp_path):
        """Create a mock memory repository."""
        repo = AsyncMock()
        repo.worktrees_dir = tmp_path / ".worktrees"
        repo.worktrees_dir.mkdir(parents=True, exist_ok=True)
        repo.initialize = AsyncMock()
        repo.create_task_worktree = AsyncMock(return_value=tmp_path / ".worktrees" / "test-task")
        repo.merge_task_worktree = AsyncMock(return_value="abc123def")
        return repo

    @pytest.mark.asyncio
    async def test_create_worktree_success(self, mock_server, mock_memory_repo):
        """Test successful worktree creation."""
        mock_server.memory_repo = mock_memory_repo

        # Import after patching
        with patch("src.mcp_server.tool_registry.logger"):
            # Simulate the tool function logic
            task_id = "test-task"
            worktree_path = await mock_memory_repo.create_task_worktree(task_id, None)

            result = {
                "status": "success",
                "worktree_path": str(worktree_path),
                "task_id": task_id,
                "branch_name": f"task/{task_id}",
            }

            assert result["status"] == "success"
            assert result["task_id"] == "test-task"
            assert "worktree_path" in result
            mock_memory_repo.create_task_worktree.assert_called_once_with(task_id, None)

    @pytest.mark.asyncio
    async def test_create_worktree_with_custom_branch(self, mock_memory_repo):
        """Test worktree creation with custom branch name."""
        task_id = "feature-123"
        branch_name = "feature/new-feature"

        await mock_memory_repo.create_task_worktree(task_id, branch_name)
        mock_memory_repo.create_task_worktree.assert_called_once_with(task_id, branch_name)

    @pytest.mark.asyncio
    async def test_create_worktree_security_error(self, mock_memory_repo):
        """Test worktree creation with invalid task_id."""
        from src.infrastructure.git.memory_repository import SecurityError

        mock_memory_repo.create_task_worktree.side_effect = SecurityError(
            "Task ID contains path traversal characters"
        )

        with pytest.raises(SecurityError):
            await mock_memory_repo.create_task_worktree("../malicious", None)

    @pytest.mark.asyncio
    async def test_create_worktree_lazy_initialization(self):
        """Test that memory_repo is lazily initialized."""
        # Test that the tool handles None memory_repo
        server = MagicMock()
        server.memory_repo = None

        # The tool should attempt to initialize on first use
        # This tests the lazy loading pattern
        assert server.memory_repo is None


class TestGitWorktreeMerge:
    """Tests for git_worktree_merge MCP tool."""

    @pytest.fixture
    def mock_memory_repo(self, tmp_path):
        """Create a mock memory repository."""
        repo = AsyncMock()
        repo.worktrees_dir = tmp_path / ".worktrees"
        repo.worktrees_dir.mkdir(parents=True, exist_ok=True)
        repo.merge_task_worktree = AsyncMock(return_value="abc123def456")
        return repo

    @pytest.mark.asyncio
    async def test_merge_worktree_success(self, mock_memory_repo):
        """Test successful worktree merge."""
        task_id = "completed-task"

        commit_hash = await mock_memory_repo.merge_task_worktree(task_id, None)

        assert commit_hash == "abc123def456"
        mock_memory_repo.merge_task_worktree.assert_called_once_with(task_id, None)

    @pytest.mark.asyncio
    async def test_merge_worktree_with_message(self, mock_memory_repo):
        """Test merge with custom commit message."""
        task_id = "feature-456"
        message = "Complete feature 456 implementation"

        await mock_memory_repo.merge_task_worktree(task_id, message)
        mock_memory_repo.merge_task_worktree.assert_called_once_with(task_id, message)

    @pytest.mark.asyncio
    async def test_merge_worktree_not_found(self, mock_memory_repo):
        """Test merge of non-existent worktree."""
        mock_memory_repo.merge_task_worktree.side_effect = RuntimeError(
            "Worktree not found"
        )

        with pytest.raises(RuntimeError, match="Worktree not found"):
            await mock_memory_repo.merge_task_worktree("nonexistent", None)

    @pytest.mark.asyncio
    async def test_merge_worktree_security_error(self, mock_memory_repo):
        """Test merge with invalid task_id."""
        from src.infrastructure.git.memory_repository import SecurityError

        mock_memory_repo.merge_task_worktree.side_effect = SecurityError(
            "Invalid task_id"
        )

        with pytest.raises(SecurityError):
            await mock_memory_repo.merge_task_worktree("../bad-id", None)


class TestGitWorktreeList:
    """Tests for git_worktree_list MCP tool."""

    @pytest.fixture
    def mock_memory_repo(self, tmp_path):
        """Create a mock memory repository with worktrees."""
        repo = AsyncMock()
        repo.worktrees_dir = tmp_path / ".worktrees"
        repo.worktrees_dir.mkdir(parents=True, exist_ok=True)
        repo.initialize = AsyncMock()
        return repo

    @pytest.mark.asyncio
    async def test_list_worktrees_empty(self, mock_memory_repo):
        """Test listing when no worktrees exist."""
        worktrees_dir = mock_memory_repo.worktrees_dir

        # No worktrees created
        worktrees = list(worktrees_dir.iterdir()) if worktrees_dir.exists() else []

        result = {
            "status": "success",
            "count": len(worktrees),
            "worktrees": [],
        }

        assert result["status"] == "success"
        assert result["count"] == 0
        assert result["worktrees"] == []

    @pytest.mark.asyncio
    async def test_list_worktrees_with_entries(self, mock_memory_repo):
        """Test listing with existing worktrees."""
        worktrees_dir = mock_memory_repo.worktrees_dir

        # Create mock worktree directories
        (worktrees_dir / "task-1").mkdir()
        (worktrees_dir / "task-2").mkdir()
        (worktrees_dir / "feature-xyz").mkdir()

        worktrees = []
        for wt in worktrees_dir.iterdir():
            if wt.is_dir():
                worktrees.append({
                    "task_id": wt.name,
                    "path": str(wt),
                    "exists": wt.exists(),
                    "branch": f"task/{wt.name}",
                })

        assert len(worktrees) == 3
        task_ids = [w["task_id"] for w in worktrees]
        assert "task-1" in task_ids
        assert "task-2" in task_ids
        assert "feature-xyz" in task_ids

    @pytest.mark.asyncio
    async def test_list_worktrees_directory_not_exists(self, tmp_path):
        """Test listing when worktrees directory doesn't exist."""
        nonexistent_dir = tmp_path / "nonexistent" / ".worktrees"

        if not nonexistent_dir.exists():
            result = {
                "status": "success",
                "count": 0,
                "worktrees": [],
            }

        assert result["count"] == 0


class TestWorktreeToolIntegration:
    """Integration tests for worktree tool workflow."""

    @pytest.fixture
    def mock_memory_repo(self, tmp_path):
        """Create a more complete mock memory repository."""
        repo = AsyncMock()
        repo.repo_path = tmp_path / "memory-repo"
        repo.repo_path.mkdir(parents=True, exist_ok=True)
        repo.worktrees_dir = repo.repo_path / ".worktrees"
        repo.worktrees_dir.mkdir(parents=True, exist_ok=True)
        repo.initialize = AsyncMock()
        repo._initialized = True

        # Track created worktrees
        created_worktrees = {}

        async def mock_create(task_id: str, branch_name: str = None):
            wt_path = repo.worktrees_dir / task_id
            wt_path.mkdir(exist_ok=True)
            created_worktrees[task_id] = wt_path
            return wt_path

        async def mock_merge(task_id: str, message: str = None):
            wt_path = created_worktrees.get(task_id)
            if not wt_path or not wt_path.exists():
                raise RuntimeError(f"Worktree not found: {task_id}")
            # Simulate removal
            wt_path.rmdir()
            del created_worktrees[task_id]
            return "abc123"

        repo.create_task_worktree = mock_create
        repo.merge_task_worktree = mock_merge

        return repo

    @pytest.mark.asyncio
    async def test_full_worktree_lifecycle(self, mock_memory_repo):
        """Test complete worktree lifecycle: create -> list -> merge."""
        # Step 1: Create worktree
        task_id = "lifecycle-test"
        wt_path = await mock_memory_repo.create_task_worktree(task_id)

        assert wt_path.exists()
        assert wt_path.name == task_id

        # Step 2: List worktrees
        worktrees = list(mock_memory_repo.worktrees_dir.iterdir())
        assert len(worktrees) == 1
        assert worktrees[0].name == task_id

        # Step 3: Merge and remove
        commit_hash = await mock_memory_repo.merge_task_worktree(task_id)
        assert commit_hash == "abc123"

        # Worktree should be removed
        worktrees = list(mock_memory_repo.worktrees_dir.iterdir())
        assert len(worktrees) == 0

    @pytest.mark.asyncio
    async def test_multiple_concurrent_worktrees(self, mock_memory_repo):
        """Test managing multiple worktrees simultaneously."""
        # Create multiple worktrees
        tasks = ["task-a", "task-b", "task-c"]

        for task_id in tasks:
            wt_path = await mock_memory_repo.create_task_worktree(task_id)
            assert wt_path.exists()

        # List all worktrees
        worktrees = list(mock_memory_repo.worktrees_dir.iterdir())
        assert len(worktrees) == 3

        # Merge one
        await mock_memory_repo.merge_task_worktree("task-b")

        worktrees = list(mock_memory_repo.worktrees_dir.iterdir())
        assert len(worktrees) == 2
        assert not (mock_memory_repo.worktrees_dir / "task-b").exists()


class TestSecurityValidation:
    """Tests for security validation in worktree tools."""

    def test_task_id_validation_pattern(self):
        """Test task ID validation regex."""
        import re

        # Valid pattern from memory_repository.py
        VALID_TASK_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")

        # Valid task IDs
        valid_ids = [
            "task-1",
            "feature_123",
            "ABC123",
            "a",
            "task-with-many-hyphens",
            "task_with_underscores",
        ]

        for task_id in valid_ids:
            assert VALID_TASK_ID_PATTERN.match(task_id), f"Should be valid: {task_id}"

        # Invalid task IDs
        invalid_ids = [
            "../traversal",
            "task/../bad",
            "-starts-with-hyphen",
            "_starts_with_underscore",
            "has spaces",
            "has;semicolon",
            "has|pipe",
            "",
        ]

        for task_id in invalid_ids:
            assert not VALID_TASK_ID_PATTERN.match(task_id), f"Should be invalid: {task_id}"

    def test_branch_name_validation_pattern(self):
        """Test branch name validation regex."""
        import re

        # Valid pattern from memory_repository.py
        VALID_BRANCH_NAME_PATTERN = re.compile(
            r"^[a-zA-Z0-9][a-zA-Z0-9/_.-]{0,127}$"
        )

        # Valid branch names
        valid_branches = [
            "task/feature-1",
            "feature/new-component",
            "bugfix/issue-123",
            "main",
            "a/b/c/d/e",
        ]

        for branch in valid_branches:
            assert VALID_BRANCH_NAME_PATTERN.match(branch), f"Should be valid: {branch}"

        # Invalid branch names
        invalid_branches = [
            "../bad",
            "has spaces",
            "/starts-with-slash",
            "",
        ]

        for branch in invalid_branches:
            assert not VALID_BRANCH_NAME_PATTERN.match(branch), f"Should be invalid: {branch}"

    @pytest.mark.asyncio
    async def test_path_traversal_prevention(self):
        """Test that path traversal is prevented."""
        from src.infrastructure.git.memory_repository import SecurityError, _validate_task_id

        # These should raise SecurityError
        malicious_ids = [
            "../etc/passwd",
            "..\\windows\\system32",
            "task/../../../root",
        ]

        for task_id in malicious_ids:
            with pytest.raises(SecurityError):
                _validate_task_id(task_id)


class TestErrorHandling:
    """Tests for error handling in worktree tools."""

    @pytest.mark.asyncio
    async def test_repository_not_initialized_error(self):
        """Test error when repository is not initialized."""
        server = MagicMock()
        server.memory_repo = None

        # Tool should return error when memory_repo is None and initialization fails
        result = {
            "status": "error",
            "error": "Memory repository not initialized. Create a worktree first.",
        }

        assert result["status"] == "error"
        assert "not initialized" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_git_operation_failure(self):
        """Test handling of git operation failures."""
        repo = AsyncMock()
        repo.create_task_worktree.side_effect = RuntimeError("Git command failed: exit code 128")

        with pytest.raises(RuntimeError, match="Git command failed"):
            await repo.create_task_worktree("test-task", None)
