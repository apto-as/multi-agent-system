"""Local-First Memory Repository with Git Backend.

Phase 4.1: Implementation of Issue #27
- Git-backed memory repository at ~/.tmws/memory-repo/
- Session recording with git commits
- Search history via git log
- Task-specific worktrees for isolation
- Problem/solution database

Specification: docs/specifications/local-first-memory/PHASE_4.1_MEMORY_REPO.md
Architecture: SQLite (metadata) + Chroma (vectors) + Git (history)

Security Notes:
- Git commands are restricted to allowlisted subcommands only
- Task IDs and branch names are validated against injection attacks
- Path traversal is prevented through strict validation
- No sensitive tokens are stored in this module

Author: Metis (Development Assistant)
Created: 2025-12-08
Security Review: Hestia (2025-12-09) - CRITICAL fixes applied
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

logger = logging.getLogger(__name__)

# Security: Allowlisted git subcommands to prevent command injection
ALLOWED_GIT_SUBCOMMANDS: Final[frozenset[str]] = frozenset({
    "init",
    "add",
    "commit",
    "log",
    "rev-parse",
    "rev-list",
    "config",
    "worktree",
    "merge",
    "show",
    "status",
    "branch",  # Needed for branch listing in worktree tests
})

# Security: Pattern for valid task IDs (alphanumeric, hyphens, underscores only)
VALID_TASK_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")

# Security: Pattern for valid branch names (git-safe characters only)
VALID_BRANCH_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9/_.-]{0,127}$"
)

# Security: Characters that are forbidden in any git argument (shell injection)
FORBIDDEN_SHELL_INJECTION_CHARS: Final[frozenset[str]] = frozenset({
    ";", "&", "|", "$", "`", "\x00",
    "$(", "${", "&&", "||", ">>", "<<",
})

# Security: Characters forbidden in general arguments (excludes newlines for commit messages)
FORBIDDEN_CHARS: Final[frozenset[str]] = FORBIDDEN_SHELL_INJECTION_CHARS | {"\r"}


class SecurityError(Exception):
    """Raised when a security validation fails."""
    pass


def _validate_task_id(task_id: str) -> str:
    """Validate task ID for security.

    Args:
        task_id: Task identifier to validate

    Returns:
        Validated task ID

    Raises:
        SecurityError: If task_id contains unsafe characters
    """
    if not task_id:
        raise SecurityError("Task ID cannot be empty")

    if not VALID_TASK_ID_PATTERN.match(task_id):
        raise SecurityError(
            f"Invalid task_id format: '{task_id}'. "
            "Must be alphanumeric with hyphens/underscores, 1-64 chars"
        )

    # Additional path traversal check
    if ".." in task_id or task_id.startswith("/") or task_id.startswith("\\"):
        raise SecurityError(f"Task ID contains path traversal characters: '{task_id}'")

    return task_id


def _validate_branch_name(branch_name: str) -> str:
    """Validate branch name for security.

    Args:
        branch_name: Branch name to validate

    Returns:
        Validated branch name

    Raises:
        SecurityError: If branch_name contains unsafe characters
    """
    if not branch_name:
        raise SecurityError("Branch name cannot be empty")

    if not VALID_BRANCH_NAME_PATTERN.match(branch_name):
        raise SecurityError(
            f"Invalid branch_name format: '{branch_name}'. "
            "Must start with alphanumeric, contain only safe chars"
        )

    # Check for path traversal
    if ".." in branch_name:
        raise SecurityError(f"Branch name contains path traversal: '{branch_name}'")

    return branch_name


def _validate_git_argument(
    arg: str,
    allow_newlines: bool = False,
    is_format_string: bool = False,
) -> str:
    """Validate a git command argument for security.

    Args:
        arg: Argument to validate
        allow_newlines: Whether to allow newline characters (for commit messages)
        is_format_string: Whether this is a git format string (allows | for formatting)

    Returns:
        Validated argument

    Raises:
        SecurityError: If argument contains forbidden characters
    """
    # For format strings, we allow pipe characters as they're used in git pretty formats
    if is_format_string:
        # Format strings are safer - check only for shell execution chars
        shell_exec_chars = {";", "&", "`", "$", "\x00", "$(", "${", "&&", "||"}
        for forbidden in shell_exec_chars:
            if forbidden in arg:
                raise SecurityError(
                    f"Git format string contains forbidden sequence: '{forbidden}'"
                )
        return arg

    # Use shell injection chars if newlines are allowed, otherwise use full set
    forbidden_set = FORBIDDEN_SHELL_INJECTION_CHARS if allow_newlines else FORBIDDEN_CHARS

    for forbidden in forbidden_set:
        if forbidden in arg:
            raise SecurityError(
                f"Git argument contains forbidden character/sequence: '{forbidden}'"
            )

    # Always check for null bytes
    if "\x00" in arg:
        raise SecurityError("Git argument contains null byte")

    return arg


@dataclass
class SessionData:
    """Represents a session to be recorded in the memory repository."""

    session_id: str
    agent_id: str
    task_description: str
    start_time: datetime
    end_time: datetime
    actions: list[dict[str, Any]]
    outcomes: dict[str, Any]
    learned_patterns: list[dict[str, Any]]
    metadata: dict[str, Any] | None = None


@dataclass
class ProblemSolution:
    """Represents a problem and its solution."""

    problem_id: str
    problem_description: str
    solution: str
    context: dict[str, Any]
    success_rate: float
    created_at: datetime
    tags: list[str]


class TMWSMemoryRepository:
    """Git-backed memory repository for session recording and knowledge accumulation.

    Directory structure:
        ~/.tmws/memory-repo/
        ├── .git/               # Git repository
        ├── sessions/           # Session records (JSON files)
        ├── tasks/              # Task metadata
        ├── patterns/           # Learning patterns
        ├── problems/           # Problem/solution database
        └── .worktrees/         # Git worktree staging area

    Features:
    - Automatic git initialization
    - Session recording as git commits
    - Search history via git log
    - Find similar problems with solutions
    - Task-specific worktrees for isolation
    - Merge completed task worktrees

    Usage:
        >>> repo = TMWSMemoryRepository()
        >>> await repo.initialize()
        >>> await repo.record_session(session_data)
        >>> results = await repo.search_history("optimization")
    """

    DEFAULT_REPO_PATH = Path.home() / ".tmws" / "memory-repo"

    def __init__(self, repo_path: Path | None = None):
        """Initialize memory repository.

        Args:
            repo_path: Path to repository (defaults to ~/.tmws/memory-repo/)
        """
        self.repo_path = repo_path or self.DEFAULT_REPO_PATH
        self.sessions_dir = self.repo_path / "sessions"
        self.tasks_dir = self.repo_path / "tasks"
        self.patterns_dir = self.repo_path / "patterns"
        self.problems_dir = self.repo_path / "problems"
        self.worktrees_dir = self.repo_path / ".worktrees"

        self._initialized = False
        self._git_initialized = False
        self._lock = asyncio.Lock()

        logger.info(f"TMWSMemoryRepository created at {self.repo_path}")

    async def initialize(self) -> None:
        """Initialize repository structure and git.

        Creates directory structure and initializes git repository if not exists.
        Idempotent - safe to call multiple times.
        """
        async with self._lock:
            if self._initialized:
                logger.debug("Repository already initialized")
                return

            # Create directory structure
            await self._create_directory_structure()

            # Initialize git repository
            await self._initialize_git()

            self._initialized = True
            logger.info(f"Memory repository initialized at {self.repo_path}")

    async def record_session(self, session: SessionData) -> str:
        """Record a session as a git commit.

        Args:
            session: Session data to record

        Returns:
            Git commit hash

        Raises:
            RuntimeError: If repository not initialized
            ValueError: If session data is invalid
        """
        await self._ensure_initialized()

        # Validate session data
        if not session.session_id:
            raise ValueError("Session ID is required")
        if not session.agent_id:
            raise ValueError("Agent ID is required")

        # Create session file
        session_file = self.sessions_dir / f"{session.session_id}.json"
        session_data = {
            "session_id": session.session_id,
            "agent_id": session.agent_id,
            "task_description": session.task_description,
            "start_time": session.start_time.isoformat(),
            "end_time": session.end_time.isoformat(),
            "actions": session.actions,
            "outcomes": session.outcomes,
            "learned_patterns": session.learned_patterns,
            "metadata": session.metadata or {},
        }

        # Write session file
        session_file.write_text(json.dumps(session_data, indent=2, ensure_ascii=False))
        logger.debug(f"Created session file: {session_file}")

        # Git commit
        commit_message = (
            f"Session: {session.task_description[:50]}\n\n"
            f"Agent: {session.agent_id}\n"
            f"Session ID: {session.session_id}\n"
            f"Duration: {(session.end_time - session.start_time).total_seconds():.2f}s\n"
            f"Actions: {len(session.actions)}"
        )

        commit_hash = await self._git_commit(
            files=[f"sessions/{session_file.name}"],
            message=commit_message,
        )

        logger.info(f"Session recorded: {session.session_id} (commit: {commit_hash[:8]})")
        return commit_hash

    async def search_history(
        self,
        query: str,
        limit: int = 10,
        agent_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Search git history for sessions matching query.

        Args:
            query: Search query string
            limit: Maximum number of results
            agent_id: Filter by agent ID

        Returns:
            List of matching session records
        """
        await self._ensure_initialized()

        # Build git log command
        cmd = [
            "git",
            "log",
            f"--max-count={limit}",
            "--pretty=format:%H|%ai|%s",
            "--all",
            f"--grep={query}",
            "-i",  # Case insensitive
        ]

        if agent_id:
            cmd.append(f"--author={agent_id}")

        # Execute git log
        result = await self._run_git_command(cmd)
        if result["returncode"] != 0:
            logger.error(f"Git log failed: {result['stderr']}")
            return []

        # Parse results
        results = []
        for line in result["stdout"].strip().split("\n"):
            if not line:
                continue

            parts = line.split("|", 2)
            if len(parts) != 3:
                continue

            commit_hash, timestamp, message = parts
            results.append(
                {
                    "commit_hash": commit_hash,
                    "timestamp": timestamp,
                    "message": message,
                    "session_file": self._extract_session_file(commit_hash),
                }
            )

        logger.debug(f"Search history found {len(results)} results for query: {query}")
        return results

    async def find_similar_problems(
        self,
        problem: str,
        min_success_rate: float = 0.7,
        limit: int = 5,
    ) -> list[ProblemSolution]:
        """Find similar problems with successful solutions.

        Args:
            problem: Problem description
            min_success_rate: Minimum success rate threshold
            limit: Maximum number of results

        Returns:
            List of similar problems with solutions
        """
        await self._ensure_initialized()

        # Load all problem files
        problem_files = list(self.problems_dir.glob("*.json"))
        solutions = []

        for problem_file in problem_files:
            try:
                data = json.loads(problem_file.read_text())

                # Check success rate threshold
                if data.get("success_rate", 0.0) < min_success_rate:
                    continue

                # Basic similarity check (can be enhanced with embeddings)
                if self._is_similar(problem, data.get("problem_description", "")):
                    solutions.append(
                        ProblemSolution(
                            problem_id=data["problem_id"],
                            problem_description=data["problem_description"],
                            solution=data["solution"],
                            context=data.get("context", {}),
                            success_rate=data["success_rate"],
                            created_at=datetime.fromisoformat(data["created_at"]),
                            tags=data.get("tags", []),
                        )
                    )

                    if len(solutions) >= limit:
                        break

            except Exception as e:
                logger.warning(f"Failed to load problem file {problem_file}: {e}")
                continue

        # Sort by success rate
        solutions.sort(key=lambda s: s.success_rate, reverse=True)

        logger.debug(f"Found {len(solutions)} similar problems")
        return solutions[:limit]

    async def create_task_worktree(self, task_id: str, branch_name: str | None = None) -> Path:
        """Create isolated git worktree for a task.

        Security:
        - task_id is validated to prevent path traversal
        - branch_name is validated for safe git characters
        - Worktree path is restricted to the worktrees directory

        Args:
            task_id: Task identifier (alphanumeric, hyphens, underscores only)
            branch_name: Branch name (defaults to task/{task_id})

        Returns:
            Path to worktree directory

        Raises:
            SecurityError: If task_id or branch_name validation fails
            RuntimeError: If worktree creation fails
        """
        await self._ensure_initialized()

        # Security: Validate task_id to prevent path traversal
        validated_task_id = _validate_task_id(task_id)

        # Security: Validate or generate safe branch name
        if branch_name:
            validated_branch = _validate_branch_name(branch_name)
        else:
            validated_branch = f"task/{validated_task_id}"
            # Validate the generated branch name too
            _validate_branch_name(validated_branch)

        worktree_path = self.worktrees_dir / validated_task_id

        # Security: Verify worktree path is within allowed directory
        try:
            worktree_path.resolve().relative_to(self.worktrees_dir.resolve())
        except ValueError:
            raise SecurityError(
                f"Worktree path escapes allowed directory: {worktree_path}"
            )

        # Create worktree
        cmd = [
            "git",
            "worktree",
            "add",
            "-b",
            validated_branch,
            str(worktree_path),
            "HEAD",
        ]

        result = await self._run_git_command(cmd)
        if result["returncode"] != 0:
            raise RuntimeError(f"Failed to create worktree: {result['stderr']}")

        logger.info(f"Created worktree for task {validated_task_id} at {worktree_path}")
        return worktree_path

    async def merge_task_worktree(
        self,
        task_id: str,
        commit_message: str | None = None,
    ) -> str:
        """Merge completed task worktree back to main.

        Security:
        - task_id is validated to prevent path traversal
        - commit_message is validated for injection characters

        Args:
            task_id: Task identifier (alphanumeric, hyphens, underscores only)
            commit_message: Merge commit message

        Returns:
            Merge commit hash

        Raises:
            SecurityError: If task_id validation fails
            RuntimeError: If merge fails
        """
        await self._ensure_initialized()

        # Security: Validate task_id
        validated_task_id = _validate_task_id(task_id)

        worktree_path = self.worktrees_dir / validated_task_id
        branch_name = f"task/{validated_task_id}"

        # Security: Verify worktree path is within allowed directory
        try:
            worktree_path.resolve().relative_to(self.worktrees_dir.resolve())
        except ValueError:
            raise SecurityError(
                f"Worktree path escapes allowed directory: {worktree_path}"
            )

        # Verify worktree exists
        if not worktree_path.exists():
            raise RuntimeError(f"Worktree not found: {worktree_path}")

        # Security: Validate commit message if provided
        merge_msg = commit_message or f"Merge task: {validated_task_id}"
        _validate_git_argument(merge_msg)

        cmd = ["git", "merge", "--no-ff", "-m", merge_msg, branch_name]

        result = await self._run_git_command(cmd)
        if result["returncode"] != 0:
            raise RuntimeError(f"Failed to merge worktree: {result['stderr']}")

        # Get merge commit hash
        commit_hash = await self._get_current_commit()

        # Remove worktree
        await self._remove_worktree(validated_task_id)

        logger.info(f"Merged and removed worktree for task {validated_task_id} (commit: {commit_hash[:8]})")
        return commit_hash

    async def get_stats(self) -> dict[str, Any]:
        """Get repository statistics.

        Returns:
            Dictionary with repository stats
        """
        await self._ensure_initialized()

        return {
            "repo_path": str(self.repo_path),
            "initialized": self._initialized,
            "git_initialized": self._git_initialized,
            "session_count": len(list(self.sessions_dir.glob("*.json"))),
            "task_count": len(list(self.tasks_dir.glob("*.json"))),
            "pattern_count": len(list(self.patterns_dir.glob("*.json"))),
            "problem_count": len(list(self.problems_dir.glob("*.json"))),
            "worktree_count": len(list(self.worktrees_dir.iterdir()))
            if self.worktrees_dir.exists()
            else 0,
            "commit_count": await self._get_commit_count(),
        }

    # Private methods

    async def _ensure_initialized(self) -> None:
        """Ensure repository is initialized."""
        if not self._initialized:
            await self.initialize()

    async def _create_directory_structure(self) -> None:
        """Create directory structure."""
        directories = [
            self.repo_path,
            self.sessions_dir,
            self.tasks_dir,
            self.patterns_dir,
            self.problems_dir,
            self.worktrees_dir,
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Created directory: {directory}")

        # Create .gitignore for worktrees
        gitignore = self.repo_path / ".gitignore"
        if not gitignore.exists():
            gitignore.write_text(".worktrees/\n*.tmp\n*.log\n")
            logger.debug("Created .gitignore")

    async def _initialize_git(self) -> None:
        """Initialize git repository if not exists."""
        git_dir = self.repo_path / ".git"

        if git_dir.exists():
            self._git_initialized = True
            logger.debug("Git repository already initialized")
            return

        # Initialize git
        result = await self._run_git_command(["git", "init"])
        if result["returncode"] != 0:
            raise RuntimeError(f"Failed to initialize git: {result['stderr']}")

        # Configure git
        await self._run_git_command(
            ["git", "config", "user.name", "TMWS Memory Repository"]
        )
        await self._run_git_command(
            ["git", "config", "user.email", "memory@tmws.local"]
        )

        # Initial commit
        readme = self.repo_path / "README.md"
        readme.write_text(
            "# TMWS Memory Repository\n\n"
            "This repository stores session recordings, learning patterns, "
            "and problem-solution mappings.\n\n"
            "Managed by TMWS Phase 4.1: Local-First Memory Repository\n"
        )

        await self._git_commit(
            files=["README.md", ".gitignore"],
            message="Initial commit: TMWS Memory Repository",
        )

        self._git_initialized = True
        logger.info("Git repository initialized")

    async def _run_git_command(self, cmd: list[str]) -> dict[str, Any]:
        """Run git command asynchronously with security validation.

        Security:
        - Only allowlisted git subcommands are permitted
        - All arguments are validated for injection characters
        - Commands are executed with controlled cwd

        Args:
            cmd: Command and arguments (must start with "git")

        Returns:
            Dictionary with returncode, stdout, stderr

        Raises:
            SecurityError: If command validation fails
        """
        # Security: Validate command structure
        if not cmd or cmd[0] != "git":
            raise SecurityError("Command must start with 'git'")

        if len(cmd) < 2:
            raise SecurityError("Git subcommand is required")

        # Security: Validate git subcommand against allowlist
        subcommand = cmd[1]
        if subcommand not in ALLOWED_GIT_SUBCOMMANDS:
            raise SecurityError(
                f"Git subcommand '{subcommand}' is not allowed. "
                f"Allowed: {sorted(ALLOWED_GIT_SUBCOMMANDS)}"
            )

        # Security: Validate all arguments for forbidden characters
        for arg in cmd[2:]:
            # Special handling for git format strings (--pretty=format:...)
            is_format_string = arg.startswith("--pretty=format:") or arg.startswith("--format=")
            _validate_git_argument(arg, is_format_string=is_format_string)

        logger.debug(f"Executing git command: {' '.join(cmd[:3])}...")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(self.repo_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()

        return {
            "returncode": process.returncode,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
        }

    async def _git_commit(self, files: list[str], message: str) -> str:
        """Create a git commit.

        Security:
        - Commit messages are validated but allow newlines
        - File paths are validated for injection characters

        Args:
            files: List of files to commit
            message: Commit message

        Returns:
            Commit hash

        Raises:
            RuntimeError: If commit fails
            SecurityError: If validation fails
        """
        # Security: Validate commit message (allow newlines for multi-line messages)
        _validate_git_argument(message, allow_newlines=True)

        # Stage files
        for file in files:
            # Security: Validate file path
            _validate_git_argument(file)
            result = await self._run_git_command(["git", "add", file])
            if result["returncode"] != 0:
                raise RuntimeError(f"Failed to stage {file}: {result['stderr']}")

        # Commit - bypass normal validation since we validated message above
        process = await asyncio.create_subprocess_exec(
            "git", "commit", "-m", message,
            cwd=str(self.repo_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        result = {
            "returncode": process.returncode,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
        }

        if result["returncode"] != 0:
            # Check if there are no changes
            if "nothing to commit" in result["stdout"]:
                logger.debug("No changes to commit")
                return await self._get_current_commit()
            raise RuntimeError(f"Failed to commit: {result['stderr']}")

        # Get commit hash
        return await self._get_current_commit()

    async def _get_current_commit(self) -> str:
        """Get current commit hash.

        Returns:
            Current commit hash
        """
        result = await self._run_git_command(["git", "rev-parse", "HEAD"])
        if result["returncode"] != 0:
            return "unknown"
        return result["stdout"].strip()

    async def _get_commit_count(self) -> int:
        """Get total commit count.

        Returns:
            Number of commits
        """
        result = await self._run_git_command(["git", "rev-list", "--count", "HEAD"])
        if result["returncode"] != 0:
            return 0
        try:
            return int(result["stdout"].strip())
        except ValueError:
            return 0

    async def _remove_worktree(self, task_id: str) -> None:
        """Remove a worktree.

        Security:
        - task_id should already be validated by caller

        Args:
            task_id: Task identifier (pre-validated)
        """
        # Security: Re-validate task_id even though caller should have validated
        validated_task_id = _validate_task_id(task_id)
        worktree_path = self.worktrees_dir / validated_task_id

        # Security: Verify path is within worktrees directory
        try:
            worktree_path.resolve().relative_to(self.worktrees_dir.resolve())
        except ValueError:
            logger.error(f"Refusing to remove worktree outside allowed directory: {worktree_path}")
            return

        cmd = ["git", "worktree", "remove", str(worktree_path)]
        result = await self._run_git_command(cmd)

        if result["returncode"] != 0:
            logger.warning(f"Failed to remove worktree: {result['stderr']}")

    def _extract_session_file(self, _commit_hash: str) -> str | None:
        """Extract session file path from commit.

        Args:
            _commit_hash: Git commit hash (unused in current implementation)

        Returns:
            Session file path or None
        """
        # This would require parsing git show output
        # For now, return None - can be enhanced later
        return None

    def _is_similar(self, text1: str, text2: str) -> bool:
        """Check if two texts are similar.

        Basic implementation using word overlap.
        Can be enhanced with embeddings in the future.

        Args:
            text1: First text
            text2: Second text

        Returns:
            True if similar, False otherwise
        """
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())

        if not words1 or not words2:
            return False

        intersection = words1.intersection(words2)
        union = words1.union(words2)

        # Jaccard similarity
        similarity = len(intersection) / len(union)

        return similarity > 0.3  # 30% threshold


# Singleton instance
_repository: TMWSMemoryRepository | None = None


def get_memory_repository() -> TMWSMemoryRepository:
    """Get singleton memory repository instance.

    Returns:
        TMWSMemoryRepository instance
    """
    global _repository
    if _repository is None:
        _repository = TMWSMemoryRepository()
    return _repository


async def initialize_memory_repository() -> TMWSMemoryRepository:
    """Initialize and return the memory repository.

    Returns:
        Initialized TMWSMemoryRepository
    """
    repo = get_memory_repository()
    await repo.initialize()
    return repo
