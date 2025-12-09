#!/usr/bin/env python
"""Demonstration of TMWSMemoryRepository functionality.

Shows:
- Repository initialization
- Session recording
- History search
- Problem/solution matching
- Task worktree management
"""

import asyncio
from datetime import datetime, timezone
from pathlib import Path

from src.infrastructure.git.memory_repository import (
    SessionData,
    TMWSMemoryRepository,
)


async def main():
    """Run memory repository demonstration."""
    print("=== TMWS Memory Repository Demo ===\n")

    # Create repository in temporary location for demo
    demo_path = Path.home() / ".tmws" / "demo-repo"
    repo = TMWSMemoryRepository(repo_path=demo_path)

    # 1. Initialize repository
    print("1. Initializing repository...")
    await repo.initialize()
    print(f"   Repository created at: {repo.repo_path}")
    print(f"   Git initialized: {repo._git_initialized}\n")

    # 2. Record a session
    print("2. Recording a session...")
    session = SessionData(
        session_id="demo-session-001",
        agent_id="artemis",
        task_description="Implement memory repository with git backend",
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        actions=[
            {"type": "code_write", "file": "memory_repository.py", "lines": 600},
            {"type": "test_write", "file": "test_memory_repository.py", "lines": 580},
            {"type": "test_run", "status": "passed", "count": 33},
        ],
        outcomes={
            "status": "success",
            "tests_passed": 33,
            "tests_failed": 0,
            "coverage": 100.0,
        },
        learned_patterns=[
            {"pattern_type": "git_integration", "confidence": 0.95},
            {"pattern_type": "async_subprocess", "confidence": 0.90},
        ],
        metadata={"phase": "4.1", "issue": "#27"},
    )

    commit_hash = await repo.record_session(session)
    print(f"   Session recorded with commit: {commit_hash[:8]}")
    print(f"   Session file: sessions/{session.session_id}.json\n")

    # 3. Search history
    print("3. Searching history...")
    results = await repo.search_history("memory repository", limit=5)
    print(f"   Found {len(results)} results")
    for i, result in enumerate(results, 1):
        print(f"   [{i}] {result['commit_hash'][:8]} - {result['message'][:50]}...")
    print()

    # 4. Get repository statistics
    print("4. Repository statistics:")
    stats = await repo.get_stats()
    print(f"   Sessions: {stats['session_count']}")
    print(f"   Tasks: {stats['task_count']}")
    print(f"   Patterns: {stats['pattern_count']}")
    print(f"   Problems: {stats['problem_count']}")
    print(f"   Commits: {stats['commit_count']}")
    print(f"   Worktrees: {stats['worktree_count']}\n")

    # 5. Create a task worktree
    print("5. Creating task worktree...")
    worktree_path = await repo.create_task_worktree("demo-task-001")
    print(f"   Worktree created at: {worktree_path}")
    print(f"   Branch: task/demo-task-001\n")

    # 6. Final statistics
    print("6. Final repository state:")
    stats = await repo.get_stats()
    print(f"   Total commits: {stats['commit_count']}")
    print(f"   Active worktrees: {stats['worktree_count']}\n")

    print("=== Demo Complete ===")
    print(f"\nRepository location: {repo.repo_path}")
    print("You can explore the repository with standard git commands.")


if __name__ == "__main__":
    asyncio.run(main())
