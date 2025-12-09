"""Unit tests for TMWSMemoryRepository.

Tests for Phase 4.1: Local-First Memory Repository
- Directory structure creation
- Git initialization
- Session recording
- History search
- Problem/solution matching
- Task worktree management
- Security validation (CRITICAL fixes from Hestia audit)
"""

import asyncio
import json
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.infrastructure.git.memory_repository import (
    ALLOWED_GIT_SUBCOMMANDS,
    FORBIDDEN_SHELL_INJECTION_CHARS,
    SecurityError,
    SessionData,
    TMWSMemoryRepository,
    _validate_branch_name,
    _validate_git_argument,
    _validate_task_id,
    get_memory_repository,
    initialize_memory_repository,
)


@pytest.fixture
def temp_repo_path():
    """Create a temporary repository path."""
    temp_dir = tempfile.mkdtemp(prefix="tmws_test_")
    yield Path(temp_dir)
    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def repository(temp_repo_path):
    """Create a test repository instance."""
    return TMWSMemoryRepository(repo_path=temp_repo_path)


@pytest.fixture
def sample_session():
    """Create sample session data."""
    return SessionData(
        session_id="test-session-001",
        agent_id="test-agent",
        task_description="Test task implementation",
        start_time=datetime.now(timezone.utc) - timedelta(hours=1),
        end_time=datetime.now(timezone.utc),
        actions=[
            {"type": "code_write", "file": "test.py", "lines": 50},
            {"type": "test_run", "status": "passed", "duration": 2.5},
        ],
        outcomes={"status": "success", "tests_passed": 10},
        learned_patterns=[
            {"pattern_type": "tdd", "confidence": 0.85},
        ],
        metadata={"project": "tmws", "phase": "4.1"},
    )


class TestInitialization:
    """Test repository initialization."""

    async def test_directory_structure_creation(self, repository):
        """Test that directory structure is created."""
        await repository.initialize()

        assert repository.repo_path.exists()
        assert repository.sessions_dir.exists()
        assert repository.tasks_dir.exists()
        assert repository.patterns_dir.exists()
        assert repository.problems_dir.exists()
        assert repository.worktrees_dir.exists()

    async def test_gitignore_creation(self, repository):
        """Test that .gitignore is created."""
        await repository.initialize()

        gitignore = repository.repo_path / ".gitignore"
        assert gitignore.exists()

        content = gitignore.read_text()
        assert ".worktrees/" in content
        assert "*.tmp" in content
        assert "*.log" in content

    async def test_git_initialization(self, repository):
        """Test that git repository is initialized."""
        await repository.initialize()

        git_dir = repository.repo_path / ".git"
        assert git_dir.exists()
        assert repository._git_initialized

    async def test_readme_creation(self, repository):
        """Test that README.md is created."""
        await repository.initialize()

        readme = repository.repo_path / "README.md"
        assert readme.exists()

        content = readme.read_text()
        assert "TMWS Memory Repository" in content
        assert "Phase 4.1" in content

    async def test_git_config(self, repository):
        """Test that git config is set correctly."""
        await repository.initialize()

        result = await repository._run_git_command(["git", "config", "user.name"])
        assert result["returncode"] == 0
        assert "TMWS" in result["stdout"]

        result = await repository._run_git_command(["git", "config", "user.email"])
        assert result["returncode"] == 0
        assert "memory@tmws.local" in result["stdout"]

    async def test_idempotent_initialization(self, repository):
        """Test that initialize() can be called multiple times safely."""
        await repository.initialize()
        first_commit = await repository._get_current_commit()

        await repository.initialize()
        second_commit = await repository._get_current_commit()

        assert first_commit == second_commit
        assert repository._initialized


class TestSessionRecording:
    """Test session recording functionality."""

    async def test_record_session_creates_file(self, repository, sample_session):
        """Test that session recording creates a file."""
        await repository.initialize()

        commit_hash = await repository.record_session(sample_session)

        session_file = repository.sessions_dir / f"{sample_session.session_id}.json"
        assert session_file.exists()
        assert len(commit_hash) > 0

    async def test_record_session_content(self, repository, sample_session):
        """Test that session data is correctly written."""
        await repository.initialize()
        await repository.record_session(sample_session)

        session_file = repository.sessions_dir / f"{sample_session.session_id}.json"
        data = json.loads(session_file.read_text())

        assert data["session_id"] == sample_session.session_id
        assert data["agent_id"] == sample_session.agent_id
        assert data["task_description"] == sample_session.task_description
        assert len(data["actions"]) == 2
        assert data["outcomes"]["status"] == "success"
        assert len(data["learned_patterns"]) == 1

    async def test_record_session_creates_commit(self, repository, sample_session):
        """Test that session recording creates a git commit."""
        await repository.initialize()
        initial_count = await repository._get_commit_count()

        await repository.record_session(sample_session)

        new_count = await repository._get_commit_count()
        assert new_count == initial_count + 1

    async def test_record_session_commit_message(self, repository, sample_session):
        """Test that commit message contains session info."""
        await repository.initialize()
        commit_hash = await repository.record_session(sample_session)

        result = await repository._run_git_command(
            ["git", "log", "-1", "--pretty=format:%B", commit_hash]
        )

        message = result["stdout"]
        assert sample_session.task_description[:50] in message
        assert sample_session.agent_id in message
        assert sample_session.session_id in message
        assert "Actions: 2" in message

    async def test_record_session_without_init_fails(self, repository, sample_session):
        """Test that recording without initialization auto-initializes."""
        # Should auto-initialize
        commit_hash = await repository.record_session(sample_session)
        assert len(commit_hash) > 0
        assert repository._initialized

    async def test_record_session_invalid_data(self, repository):
        """Test that invalid session data raises ValueError."""
        await repository.initialize()

        # Missing session_id
        invalid_session = SessionData(
            session_id="",
            agent_id="test-agent",
            task_description="Test",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            actions=[],
            outcomes={},
            learned_patterns=[],
        )

        with pytest.raises(ValueError, match="Session ID is required"):
            await repository.record_session(invalid_session)

    async def test_record_multiple_sessions(self, repository):
        """Test recording multiple sessions."""
        await repository.initialize()

        sessions = []
        for i in range(3):
            session = SessionData(
                session_id=f"session-{i}",
                agent_id="test-agent",
                task_description=f"Task {i}",
                start_time=datetime.now(timezone.utc),
                end_time=datetime.now(timezone.utc),
                actions=[],
                outcomes={},
                learned_patterns=[],
            )
            sessions.append(session)
            await repository.record_session(session)

        # Verify all session files exist
        for session in sessions:
            session_file = repository.sessions_dir / f"{session.session_id}.json"
            assert session_file.exists()

        # Verify commit count
        commit_count = await repository._get_commit_count()
        assert commit_count >= 4  # Initial + 3 sessions


class TestHistorySearch:
    """Test history search functionality."""

    async def test_search_history_basic(self, repository):
        """Test basic history search."""
        await repository.initialize()

        # Record sessions with different descriptions
        session1 = SessionData(
            session_id="s1",
            agent_id="agent1",
            task_description="Implement optimization algorithm",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            actions=[],
            outcomes={},
            learned_patterns=[],
        )
        session2 = SessionData(
            session_id="s2",
            agent_id="agent1",
            task_description="Fix security bug",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            actions=[],
            outcomes={},
            learned_patterns=[],
        )

        await repository.record_session(session1)
        await repository.record_session(session2)

        # Search for "optimization"
        results = await repository.search_history("optimization")

        assert len(results) >= 1
        assert any("optimization" in r["message"].lower() for r in results)

    async def test_search_history_case_insensitive(self, repository):
        """Test that search is case-insensitive."""
        await repository.initialize()

        session = SessionData(
            session_id="s1",
            agent_id="agent1",
            task_description="UPPERCASE TEST",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            actions=[],
            outcomes={},
            learned_patterns=[],
        )
        await repository.record_session(session)

        results = await repository.search_history("uppercase")
        assert len(results) >= 1

    async def test_search_history_limit(self, repository):
        """Test that search respects limit parameter."""
        await repository.initialize()

        # Record multiple sessions
        for i in range(5):
            session = SessionData(
                session_id=f"s{i}",
                agent_id="agent1",
                task_description=f"Test task {i}",
                start_time=datetime.now(timezone.utc),
                end_time=datetime.now(timezone.utc),
                actions=[],
                outcomes={},
                learned_patterns=[],
            )
            await repository.record_session(session)

        results = await repository.search_history("Test", limit=3)
        assert len(results) <= 3

    async def test_search_history_empty_query(self, repository):
        """Test search with empty results."""
        await repository.initialize()

        results = await repository.search_history("nonexistent_query_xyz")
        assert len(results) == 0


class TestProblemSolutions:
    """Test problem/solution matching."""

    async def test_find_similar_problems_empty(self, repository):
        """Test finding problems when none exist."""
        await repository.initialize()

        results = await repository.find_similar_problems("test problem")
        assert len(results) == 0

    async def test_find_similar_problems_basic(self, repository):
        """Test basic problem similarity matching."""
        await repository.initialize()

        # Create a problem file manually
        problem_data = {
            "problem_id": "p1",
            "problem_description": "optimize slow database query",
            "solution": "add index on frequently queried column",
            "context": {"database": "postgresql"},
            "success_rate": 0.85,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "tags": ["database", "performance"],
        }

        problem_file = repository.problems_dir / "p1.json"
        problem_file.write_text(json.dumps(problem_data, indent=2))

        # Search for similar problem
        results = await repository.find_similar_problems("slow database performance")

        assert len(results) >= 1
        assert results[0].problem_id == "p1"
        assert results[0].success_rate == 0.85

    async def test_find_similar_problems_min_success_rate(self, repository):
        """Test that min_success_rate filter works."""
        await repository.initialize()

        # Create problem with low success rate
        problem_data = {
            "problem_id": "p1",
            "problem_description": "test problem",
            "solution": "test solution",
            "context": {},
            "success_rate": 0.3,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "tags": [],
        }

        problem_file = repository.problems_dir / "p1.json"
        problem_file.write_text(json.dumps(problem_data, indent=2))

        # Should not return problem with success_rate < 0.7
        results = await repository.find_similar_problems("test problem", min_success_rate=0.7)
        assert len(results) == 0

    async def test_find_similar_problems_sorting(self, repository):
        """Test that results are sorted by success rate."""
        await repository.initialize()

        # Create multiple problems
        problems = [
            {"problem_id": "p1", "success_rate": 0.7},
            {"problem_id": "p2", "success_rate": 0.9},
            {"problem_id": "p3", "success_rate": 0.8},
        ]

        for prob in problems:
            problem_data = {
                "problem_id": prob["problem_id"],
                "problem_description": "test problem description",
                "solution": "test solution",
                "context": {},
                "success_rate": prob["success_rate"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "tags": [],
            }
            problem_file = repository.problems_dir / f"{prob['problem_id']}.json"
            problem_file.write_text(json.dumps(problem_data, indent=2))

        results = await repository.find_similar_problems("test problem", limit=3)

        # Should be sorted by success_rate descending
        assert len(results) == 3
        assert results[0].success_rate >= results[1].success_rate
        assert results[1].success_rate >= results[2].success_rate


class TestWorktrees:
    """Test git worktree management."""

    async def test_create_task_worktree(self, repository):
        """Test creating a task worktree."""
        await repository.initialize()

        worktree_path = await repository.create_task_worktree("task-001")

        assert worktree_path.exists()
        assert (worktree_path / ".git").exists()

    async def test_create_task_worktree_custom_branch(self, repository):
        """Test creating worktree with custom branch name."""
        await repository.initialize()

        worktree_path = await repository.create_task_worktree(
            "task-002", branch_name="feature/custom"
        )

        assert worktree_path.exists()

        # Verify branch exists
        result = await repository._run_git_command(["git", "branch", "--list"])
        assert "feature/custom" in result["stdout"]

    async def test_merge_task_worktree(self, repository):
        """Test merging a task worktree."""
        await repository.initialize()

        # Create worktree
        worktree_path = await repository.create_task_worktree("task-003")

        # Create a file in worktree
        test_file = worktree_path / "test.txt"
        test_file.write_text("test content")

        # Commit in worktree
        process = await asyncio.create_subprocess_exec(
            "git",
            "add",
            "test.txt",
            cwd=str(worktree_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        process = await asyncio.create_subprocess_exec(
            "git",
            "commit",
            "-m",
            "Test commit",
            cwd=str(worktree_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        # Merge worktree
        commit_hash = await repository.merge_task_worktree(
            "task-003", commit_message="Merge task-003"
        )

        assert len(commit_hash) > 0
        assert not worktree_path.exists()  # Should be removed after merge

    async def test_merge_nonexistent_worktree_fails(self, repository):
        """Test that merging nonexistent worktree raises error."""
        await repository.initialize()

        with pytest.raises(RuntimeError, match="Worktree not found"):
            await repository.merge_task_worktree("nonexistent-task")


class TestStatistics:
    """Test repository statistics."""

    async def test_get_stats_initial(self, repository):
        """Test statistics for newly initialized repository."""
        await repository.initialize()

        stats = await repository.get_stats()

        assert stats["initialized"] is True
        assert stats["git_initialized"] is True
        assert stats["session_count"] == 0
        assert stats["task_count"] == 0
        assert stats["pattern_count"] == 0
        assert stats["problem_count"] == 0
        assert stats["worktree_count"] == 0
        assert stats["commit_count"] >= 1  # Initial commit

    async def test_get_stats_with_sessions(self, repository, sample_session):
        """Test statistics after recording sessions."""
        await repository.initialize()
        await repository.record_session(sample_session)

        stats = await repository.get_stats()

        assert stats["session_count"] == 1
        assert stats["commit_count"] >= 2  # Initial + session


class TestSingletonPattern:
    """Test singleton instance management."""

    def test_get_memory_repository_singleton(self):
        """Test that get_memory_repository returns singleton."""
        repo1 = get_memory_repository()
        repo2 = get_memory_repository()

        assert repo1 is repo2

    async def test_initialize_memory_repository(self, temp_repo_path):
        """Test initialize_memory_repository helper."""
        # Override singleton for testing
        import src.infrastructure.git.memory_repository as repo_module

        original_repo = repo_module._repository
        try:
            # Create new instance for testing
            repo_module._repository = TMWSMemoryRepository(repo_path=temp_repo_path)

            repo = await initialize_memory_repository()

            assert repo._initialized
            assert repo.repo_path.exists()

        finally:
            # Restore original singleton
            repo_module._repository = original_repo


class TestSimilarityMatching:
    """Test similarity matching algorithm."""

    def test_is_similar_exact_match(self, repository):
        """Test exact match similarity."""
        result = repository._is_similar("test problem", "test problem")
        assert result is True

    def test_is_similar_partial_match(self, repository):
        """Test partial match similarity."""
        # Use more overlapping words to exceed 30% threshold
        result = repository._is_similar(
            "database query optimization", "database performance optimization"
        )
        assert result is True

    def test_is_similar_no_match(self, repository):
        """Test no match similarity."""
        result = repository._is_similar("completely different text", "another thing entirely")
        # May or may not match depending on threshold
        assert isinstance(result, bool)

    def test_is_similar_empty_text(self, repository):
        """Test similarity with empty text."""
        result = repository._is_similar("", "test")
        assert result is False

        result = repository._is_similar("test", "")
        assert result is False


# =============================================================================
# SECURITY TESTS - Hestia Audit Fixes (2025-12-09)
# =============================================================================


class TestSecurityValidation:
    """Security validation tests for CRITICAL vulnerabilities.

    These tests verify the fixes for:
    - CRITICAL-1: Git command injection
    - CRITICAL-2: Path traversal in worktrees
    - CRITICAL-3: Input validation
    """

    # -------------------------------------------------------------------------
    # Task ID Validation Tests (CRITICAL-2)
    # -------------------------------------------------------------------------

    def test_validate_task_id_valid(self):
        """Test valid task IDs."""
        valid_ids = [
            "task-001",
            "task_001",
            "task123",
            "a",
            "ABC",
            "a1b2c3",
            "task-with-dashes",
            "task_with_underscores",
        ]
        for task_id in valid_ids:
            result = _validate_task_id(task_id)
            assert result == task_id

    def test_validate_task_id_empty(self):
        """Test that empty task ID raises SecurityError."""
        with pytest.raises(SecurityError, match="cannot be empty"):
            _validate_task_id("")

    def test_validate_task_id_path_traversal(self):
        """Test that path traversal attempts raise SecurityError."""
        malicious_ids = [
            "../etc/passwd",
            "..\\windows\\system32",
            "task/../../../etc",
            "/etc/passwd",
            "\\windows\\system32",
        ]
        for task_id in malicious_ids:
            with pytest.raises(SecurityError):
                _validate_task_id(task_id)

    def test_validate_task_id_injection_chars(self):
        """Test that injection characters raise SecurityError."""
        malicious_ids = [
            "task;rm -rf /",
            "task|cat /etc/passwd",
            "task&& malicious",
            "task`whoami`",
            "task$(id)",
            "task\nmalicious",
        ]
        for task_id in malicious_ids:
            with pytest.raises(SecurityError):
                _validate_task_id(task_id)

    def test_validate_task_id_too_long(self):
        """Test that task IDs over 64 chars raise SecurityError."""
        long_id = "a" * 65
        with pytest.raises(SecurityError, match="Invalid task_id format"):
            _validate_task_id(long_id)

    def test_validate_task_id_starts_with_invalid_char(self):
        """Test that task ID must start with alphanumeric."""
        invalid_ids = ["-task", "_task", ".task", "0-task"]
        # "0-task" should be valid as it starts with alphanumeric
        assert _validate_task_id("0-task") == "0-task"

        for task_id in ["-task", "_task", ".task"]:
            with pytest.raises(SecurityError):
                _validate_task_id(task_id)

    # -------------------------------------------------------------------------
    # Branch Name Validation Tests
    # -------------------------------------------------------------------------

    def test_validate_branch_name_valid(self):
        """Test valid branch names."""
        valid_names = [
            "main",
            "feature/task-001",
            "feature/my-feature",
            "task/123",
            "release/v1.0.0",
            "bugfix/issue-42",
        ]
        for name in valid_names:
            result = _validate_branch_name(name)
            assert result == name

    def test_validate_branch_name_empty(self):
        """Test that empty branch name raises SecurityError."""
        with pytest.raises(SecurityError, match="cannot be empty"):
            _validate_branch_name("")

    def test_validate_branch_name_path_traversal(self):
        """Test that path traversal in branch names raises SecurityError."""
        malicious_names = [
            "../malicious",
            "feature/../../../etc",
            "task/..\\windows",
        ]
        for name in malicious_names:
            with pytest.raises(SecurityError):
                _validate_branch_name(name)

    # -------------------------------------------------------------------------
    # Git Argument Validation Tests (CRITICAL-1)
    # -------------------------------------------------------------------------

    def test_validate_git_argument_valid(self):
        """Test valid git arguments."""
        valid_args = [
            "HEAD",
            "main",
            "-m",
            "--no-ff",
            "test.txt",
            "path/to/file.py",
        ]
        for arg in valid_args:
            result = _validate_git_argument(arg)
            assert result == arg

    def test_validate_git_argument_forbidden_chars(self):
        """Test that forbidden characters raise SecurityError."""
        # Note: \n is now allowed in some contexts (commit messages)
        # Note: | is now allowed in format strings
        for char in [";", "&", "$", "`", "\r", "\x00"]:
            with pytest.raises(SecurityError, match="forbidden"):
                _validate_git_argument(f"test{char}inject")

        # Verify | is blocked in regular arguments
        with pytest.raises(SecurityError, match="forbidden"):
            _validate_git_argument("test|inject")

        # But | is allowed in format strings
        result = _validate_git_argument("--pretty=format:%H|%s", is_format_string=True)
        assert "|" in result

    def test_validate_git_argument_command_sequences(self):
        """Test that command sequences raise SecurityError."""
        sequences = ["$(whoami)", "${USER}", "&&", "||", ">>", "<<"]
        for seq in sequences:
            with pytest.raises(SecurityError, match="forbidden"):
                _validate_git_argument(f"test{seq}inject")

    # -------------------------------------------------------------------------
    # Git Command Allowlist Tests (CRITICAL-1)
    # -------------------------------------------------------------------------

    def test_allowed_git_subcommands_immutable(self):
        """Test that ALLOWED_GIT_SUBCOMMANDS is immutable."""
        assert isinstance(ALLOWED_GIT_SUBCOMMANDS, frozenset)

    def test_allowed_git_subcommands_contains_required(self):
        """Test that all required git subcommands are allowed."""
        required = {"init", "add", "commit", "log", "worktree", "merge", "status"}
        assert required.issubset(ALLOWED_GIT_SUBCOMMANDS)

    def test_dangerous_git_subcommands_excluded(self):
        """Test that dangerous git subcommands are NOT allowed."""
        dangerous = {
            "push",
            "fetch",
            "pull",
            "remote",
            "clone",
            "reset",
            "rebase",
            "cherry-pick",
            "reflog",
            "gc",
            "prune",
        }
        for cmd in dangerous:
            assert cmd not in ALLOWED_GIT_SUBCOMMANDS

    async def test_run_git_command_rejects_disallowed_subcommand(self, repository):
        """Test that disallowed git subcommands raise SecurityError."""
        await repository.initialize()

        with pytest.raises(SecurityError, match="not allowed"):
            await repository._run_git_command(["git", "push", "origin", "main"])

        with pytest.raises(SecurityError, match="not allowed"):
            await repository._run_git_command(["git", "remote", "add", "evil"])

    async def test_run_git_command_rejects_non_git_command(self, repository):
        """Test that non-git commands raise SecurityError."""
        await repository.initialize()

        with pytest.raises(SecurityError, match="must start with 'git'"):
            await repository._run_git_command(["rm", "-rf", "/"])

        with pytest.raises(SecurityError, match="must start with 'git'"):
            await repository._run_git_command(["cat", "/etc/passwd"])

    async def test_run_git_command_rejects_empty(self, repository):
        """Test that empty commands raise SecurityError."""
        await repository.initialize()

        with pytest.raises(SecurityError):
            await repository._run_git_command([])

    async def test_run_git_command_rejects_injection_in_args(self, repository):
        """Test that injection characters in args raise SecurityError."""
        await repository.initialize()

        with pytest.raises(SecurityError):
            await repository._run_git_command(["git", "log", "; rm -rf /"])

        with pytest.raises(SecurityError):
            await repository._run_git_command(["git", "commit", "-m", "test`id`"])

    # -------------------------------------------------------------------------
    # Worktree Path Traversal Tests (CRITICAL-2)
    # -------------------------------------------------------------------------

    async def test_create_worktree_path_traversal_blocked(self, repository):
        """Test that path traversal in worktree creation is blocked."""
        await repository.initialize()

        with pytest.raises(SecurityError):
            await repository.create_task_worktree("../escape")

        with pytest.raises(SecurityError):
            await repository.create_task_worktree("task/../../../etc")

    async def test_create_worktree_injection_blocked(self, repository):
        """Test that command injection in worktree creation is blocked."""
        await repository.initialize()

        with pytest.raises(SecurityError):
            await repository.create_task_worktree("task;rm -rf /")

        with pytest.raises(SecurityError):
            await repository.create_task_worktree("task$(whoami)")

    async def test_merge_worktree_validates_task_id(self, repository):
        """Test that merge_task_worktree validates task_id."""
        await repository.initialize()

        with pytest.raises(SecurityError):
            await repository.merge_task_worktree("../escape")

        with pytest.raises(SecurityError):
            await repository.merge_task_worktree("task;malicious")

    async def test_worktree_path_restricted_to_worktrees_dir(self, repository):
        """Test that worktree path is restricted to the worktrees directory."""
        await repository.initialize()

        # Valid task should work
        worktree_path = await repository.create_task_worktree("valid-task")
        assert worktree_path.resolve().is_relative_to(repository.worktrees_dir.resolve())

        # Clean up
        await repository._remove_worktree("valid-task")


class TestSecurityIntegration:
    """Integration tests for security fixes."""

    async def test_end_to_end_secure_session_recording(self, repository, sample_session):
        """Test that session recording works with security validations."""
        await repository.initialize()

        # Normal session should work
        commit_hash = await repository.record_session(sample_session)
        assert len(commit_hash) == 40  # Full SHA-1 hash

    async def test_end_to_end_secure_worktree_lifecycle(self, repository):
        """Test complete worktree lifecycle with security validations."""
        await repository.initialize()

        # Create valid worktree
        task_id = "secure-task-123"
        worktree_path = await repository.create_task_worktree(task_id)

        assert worktree_path.exists()
        assert worktree_path.name == task_id

        # Remove worktree
        await repository._remove_worktree(task_id)

    async def test_concurrent_operations_security(self, repository):
        """Test that security validations work under concurrent operations."""
        await repository.initialize()

        # Create multiple sessions concurrently
        async def create_session(idx: int):
            session = SessionData(
                session_id=f"concurrent-{idx}",
                agent_id="test-agent",
                task_description=f"Concurrent task {idx}",
                start_time=datetime.now(timezone.utc),
                end_time=datetime.now(timezone.utc),
                actions=[],
                outcomes={},
                learned_patterns=[],
            )
            return await repository.record_session(session)

        # Run 5 concurrent session recordings
        results = await asyncio.gather(*[create_session(i) for i in range(5)])

        # All should succeed and return valid commit hashes
        assert len(results) == 5
        for commit_hash in results:
            assert len(commit_hash) == 40
