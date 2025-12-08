# TMWS Phase 4.1 Specification
## True Lazy Loading with Sparse Registry Pattern

---

**Document Version**: 1.1.0
**TMWS Target Version**: v2.5.0
**Status**: DRAFT - Local-First Architecture Complete
**Created**: 2025-12-08
**Updated**: 2025-12-08 (Local-First + Git Worktree + External Bridges)
**Authors**: Trinitas Strategic Team (Hera, Athena, Aurora, Metis)

---

## Executive Summary

TMWS Phase 4.1 represents a fundamental architectural shift from eager MCP server loading to a Cargo-inspired sparse registry pattern. This evolution addresses three critical pain points identified in current production usage:

1. **Performance**: 15-30s startup times with 40+ MCP servers loaded eagerly
2. **Memory Efficiency**: Unnecessary resource consumption from unused connections
3. **Cognitive Load**: Overwhelming tool lists (200+ tools) preventing effective agent decision-making

Phase 4.1 introduces a metadata-first architecture where MCP servers remain dormant until explicitly needed, with intelligent connection pooling, TTL-based lifecycle management, and integrated memory synthesis for context-aware tool discovery.

### Key Innovations

- **Sparse Registry**: Lightweight metadata catalog (~50 bytes per server) replacing full connection state
- **Lazy Connection Pool**: On-demand server activation with 15-minute TTL and graceful eviction
- **Local-First Memory Repository**: Forced local git at `~/.tmws/memory-repo/` with optional external sync
- **Git Worktree Workflow**: Parallel task isolation using native git worktrees
- **Memory Decay System**: Time-based relevance scoring preventing stale context pollution
- **Trust-Weighted RAG**: Code context retrieval with agent trust scoring
- **External Integration (Optional)**: GitHub/GitLab bridges for enhanced context (not required)

### Expected Impact

| Metric | Current (v2.4.16) | Target (v2.5.0) | Improvement |
|--------|-------------------|-----------------|-------------|
| Startup Time | 15-30s | <2s | **85-93% faster** |
| Memory Footprint | ~800MB | ~150MB | **81% reduction** |
| Active Connections | 40+ | 3-5 avg | **87% reduction** |
| Tool List Size | 200+ | 15-20 (filtered) | **90% reduction** |
| Context Retrieval | Manual | Automatic | **∞% automation** |

---

## 1. Problem Statement

### 1.1 Current Architecture Limitations

#### Performance Bottleneck
```python
# Current: Eager loading in mcphub_mcp.py
async def _initialize_servers():
    for server_name, config in self.config.items():
        transport = await connect_mcp_server(config)  # Blocks
        await transport.initialize()  # Blocks again
        self.servers[server_name] = transport  # Full state stored
# Result: 15-30s startup, 40 sequential connections
```

**Impact**: Unusable in time-sensitive workflows (e.g., debugging sessions, quick queries)

#### Memory Inefficiency
```yaml
# Current memory profile (production measurements)
Base TMWS Process: 120 MB
+ mcp-dynamic-proxy: 25 MB
+ context7 (unused): 80 MB
+ chrome-devtools (unused): 150 MB
+ playwright (unused): 200 MB
+ serena (code analysis): 180 MB
+ gdrive (unused): 45 MB
= Total: ~800 MB (only 2-3 servers actively used per session)
```

**Impact**: Unnecessary resource consumption, poor scalability

#### Cognitive Overload
```bash
# Tool explosion example from logs
$ /trinitas status tools
Available tools: 237
├─ tmws.*: 42 tools
├─ mcp__context7__*: 2 tools
├─ mcp__chrome-devtools__*: 28 tools
├─ mcp__playwright__*: 27 tools
├─ mcp__serena-mcp-server__*: 24 tools
├─ mcp__gdrive__*: 4 tools
└─ ... (remaining 110 tools from other servers)

# Agent decision paralysis
Claude: "I see 237 tools available. Let me think about which one..."
[30 seconds of reasoning about tool selection]
```

**Impact**: Degraded agent performance, increased latency, poor UX

### 1.2 Missing Memory Integration

#### Automated Learning Gap
```python
# Current: Manual work tracking
# User must explicitly document progress in memory
await tmws.store_memory(
    content="Working on lazy loading implementation",
    namespace="project.current_work"
)
# Problem: Easy to forget, inconsistent, no automation
```

#### Work Session Synthesis Missing
```yaml
# What we need but don't have:
session_start: 2025-12-08T09:00:00Z
session_end: 2025-12-08T11:30:00Z
work_summary:
  - "Implemented sparse registry pattern"
  - "Fixed ChromaDB HNSW compatibility"
  - "Resolved 3 security vulnerabilities"
git_refs:
  - branch: "feature/lazy-loading"
  - commits: ["3782922", "e2105f7"]
external_refs: # Optional - only if connected
  - github_issues: ["#456", "#457"]
agent_trust_delta:
  artemis: +0.05 (successful optimization)
  hestia: +0.03 (security fixes verified)
```

#### Auto-Context Enrichment Missing
```python
# Current: Manual context loading
user_query = "Fix the ChromaDB issue"

# System cannot automatically:
# 1. Search related memories (ChromaDB, HNSW, vector store)
# 2. Find relevant commits (local git log --grep "ChromaDB")
# 3. Surface agent trust scores (who last worked on this?)
# 4. Search similar problems solved before
# 5. [Optional] Load external issues if GitHub/GitLab connected

# Result: Agent starts cold, must rebuild context
```

---

## 2. Proposed Architecture

### 2.1 Sparse Registry Pattern (Cargo-Inspired)

#### Design Philosophy
Borrowed from Rust's Cargo package manager:
- **Index.crates.io**: Lightweight metadata (~1KB per crate)
- **Lazy Download**: Only fetch when building
- **Version Resolution**: Metadata-driven, no network calls
- **Caching**: Local registry persists across sessions

#### TMWS Adaptation
```python
# ~/.tmws/registry/index.json (sparse registry)
{
  "version": "1.0.0",
  "last_updated": "2025-12-08T10:00:00Z",
  "servers": {
    "context7": {
      "description": "Library documentation search",
      "tools": {
        "resolve-library-id": {
          "category": "search",
          "input_schema": {"libraryName": "string"},
          "usage_hint": "Call before get-library-docs"
        },
        "get-library-docs": {
          "category": "documentation",
          "input_schema": {"context7CompatibleLibraryID": "string"},
          "dependencies": ["resolve-library-id"]
        }
      },
      "connection": {
        "type": "stdio",
        "command": "npx",
        "args": ["-y", "@cotter45/context7"],
        "env": {}
      },
      "metadata": {
        "estimated_memory": "80MB",
        "cold_start_time": "3s",
        "popularity_score": 0.15  # 15% usage in last 30 days
      }
    },
    "serena": {
      "description": "Advanced code analysis with LSP",
      "tools": {
        "find_symbol": {"category": "code-search"},
        "get_symbols_overview": {"category": "code-analysis"},
        "search_for_pattern": {"category": "code-search"}
      },
      "connection": {
        "type": "stdio",
        "command": "uvx",
        "args": ["serena-mcp"],
        "env": {}
      },
      "metadata": {
        "estimated_memory": "180MB",
        "cold_start_time": "5s",
        "popularity_score": 0.85  # 85% usage (very popular)
      }
    }
  }
}
```

**Key Benefits**:
- **Instant Startup**: Registry loads in <100ms (pure JSON parsing)
- **Memory Efficient**: ~50 bytes per server vs ~20MB per connection
- **Tool Discovery**: Fast filtering without server initialization
- **Popularity Tracking**: Usage metrics inform adaptive ranking

#### Registry Generation
```python
# tools/build_registry.py
async def build_sparse_registry(config_path: str) -> dict:
    """Generate sparse registry from MCP config."""
    registry = {"version": "1.0.0", "servers": {}}

    for server_name, config in load_mcp_config(config_path).items():
        # Step 1: Extract static metadata (no connection required)
        registry["servers"][server_name] = {
            "description": config.get("description", ""),
            "connection": {
                "type": config["type"],
                "command": config["command"],
                "args": config.get("args", []),
                "env": config.get("env", {})
            },
            "metadata": {
                "estimated_memory": estimate_memory(server_name),
                "cold_start_time": estimate_startup(server_name),
                "popularity_score": 0.0  # Updated at runtime
            }
        }

        # Step 2: Introspect tools (requires one-time connection)
        if not cached_tools_exist(server_name):
            tools = await introspect_server_tools(config)
            cache_tools(server_name, tools)

        registry["servers"][server_name]["tools"] = load_cached_tools(server_name)

    return registry
```

### 2.2 Connection Pool Design

#### Architecture Overview
```
┌─────────────────────────────────────────────────────────────┐
│                    SparseRegistryManager                    │
│  ┌───────────────────────────────────────────────────────┐  │
│  │         Metadata Index (Always in Memory)             │  │
│  │  • Server descriptions                                │  │
│  │  • Tool schemas                                       │  │
│  │  • Connection configs                                 │  │
│  │  • Popularity scores                                  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                   ConnectionPoolManager                     │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Active Connections (LRU Cache, max_size=10, TTL=15m)│  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │  │
│  │  │ serena      │  │ context7    │  │ tmws        │  │  │
│  │  │ Connected   │  │ Connected   │  │ Persistent  │  │  │
│  │  │ TTL: 12m    │  │ TTL: 5m     │  │ No TTL      │  │  │
│  │  │ Usage: High │  │ Usage: Low  │  │ Usage: Core │  │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Idle Servers (40+ servers, not connected)           │  │
│  │  • chrome-devtools (last used: 2 days ago)           │  │
│  │  • playwright (last used: never)                      │  │
│  │  • gdrive (last used: 1 week ago)                    │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                  Tool Invocation Workflow                   │
│  1. User: "Find the ChromaDB class"                         │
│  2. Tool Selection: mcp__serena__find_symbol                │
│  3. Pool Check: Is 'serena' connected?                      │
│     ├─ Yes → Use existing connection                        │
│     └─ No  → Lazy connect (5s delay, one-time cost)        │
│  4. Execute tool                                            │
│  5. Update TTL (reset to 15 minutes)                        │
│  6. Update popularity score (+0.01)                         │
└─────────────────────────────────────────────────────────────┘
```

#### Connection Lifecycle
```python
# tmws/core/connection_pool.py
from typing import Dict, Optional
from datetime import datetime, timedelta
import asyncio

class ConnectionPool:
    """LRU connection pool with TTL-based eviction."""

    def __init__(self, max_size: int = 10, default_ttl: timedelta = timedelta(minutes=15)):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.pool: Dict[str, Connection] = {}
        self.usage_stats: Dict[str, UsageStats] = {}
        self._cleanup_task: Optional[asyncio.Task] = None

    async def get_connection(self, server_name: str) -> Connection:
        """Get or create connection with lazy loading."""

        # Fast path: Already connected
        if server_name in self.pool:
            conn = self.pool[server_name]
            conn.last_used = datetime.utcnow()
            conn.expires_at = datetime.utcnow() + self.default_ttl
            conn.usage_count += 1
            return conn

        # Slow path: Lazy connect
        if len(self.pool) >= self.max_size:
            await self._evict_lru()  # Make room

        conn = await self._connect_server(server_name)
        self.pool[server_name] = conn
        return conn

    async def _evict_lru(self):
        """Evict least recently used non-persistent connection."""
        evictable = [
            (name, conn) for name, conn in self.pool.items()
            if not conn.persistent  # Never evict TMWS core
        ]

        if not evictable:
            raise RuntimeError("Pool full with only persistent connections")

        # Sort by last_used (oldest first)
        lru_name, lru_conn = min(evictable, key=lambda x: x[1].last_used)

        await lru_conn.close()
        del self.pool[lru_name]

        logger.info(f"Evicted LRU connection: {lru_name}")

    async def _cleanup_expired(self):
        """Background task to remove expired connections."""
        while True:
            await asyncio.sleep(60)  # Check every minute

            now = datetime.utcnow()
            expired = [
                name for name, conn in self.pool.items()
                if not conn.persistent and conn.expires_at < now
            ]

            for name in expired:
                await self.pool[name].close()
                del self.pool[name]
                logger.info(f"Expired connection: {name}")
```

#### TTL Configuration
```yaml
# ~/.tmws/config/pool.yaml
connection_pool:
  max_size: 10
  default_ttl: 900  # 15 minutes (seconds)

  # Per-server overrides
  ttl_overrides:
    tmws: null  # Persistent (no TTL)
    serena: 1800  # 30 minutes (heavy usage)
    context7: 600  # 10 minutes (light usage)
    chrome-devtools: 300  # 5 minutes (rare usage)

  # Eviction strategy
  eviction:
    strategy: "lru"  # Least Recently Used
    grace_period: 60  # Don't evict if used in last 60s

  # Monitoring
  metrics:
    track_usage: true
    log_evictions: true
```

### 2.3 Memory Integration Architecture

#### Design Philosophy: Local-First with Optional External Sync

TMWS Memory Repositoryは**ローカルGitリポジトリを強制作成**し、外部連携（GitHub/GitLab等）は
オプションとする設計です。これにより:

- **完全オフライン動作**: インターネット接続なしで全機能が動作
- **プライバシー保護**: データはデフォルトでローカルのみ
- **Git履歴の活用**: 強力な検索・追跡・ブランチ機能
- **柔軟な外部連携**: 必要に応じてGitHub/GitLab/Gitea/任意のgitサーバーと連携

```
┌─────────────────────────────────────────────────────────────────────┐
│                    TMWS Memory Repository Architecture              │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 0: TMWS Internal Git (強制・自動作成)                        │
│  ├─ ~/.tmws/memory-repo/  (常に存在するgitリポジトリ)               │
│  │   ├─ sessions/         セッション記録 (JSON)                    │
│  │   ├─ patterns/         学習パターン                             │
│  │   ├─ contexts/         コンテキスト履歴                         │
│  │   ├─ problems/         問題と解決策のアーカイブ                  │
│  │   └─ .git/             ローカルgit (履歴追跡)                   │
│  │                                                                  │
│  └─ Core機能 (常に動作):                                            │
│      • git log でセッション履歴検索                                 │
│      • git diff で変更追跡                                          │
│      • git blame で「誰が何をしたか」追跡                           │
│      • git worktree で並列コンテキスト管理                          │
│      • git branch でタスク/プロジェクト分離                         │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 1: External Integration (オプション)                         │
│  ├─ GitHub  → リモート追加 + Issue/PR API連携                      │
│  ├─ GitLab  → リモート追加 + Issue/MR API連携                      │
│  ├─ Gitea   → セルフホスト対応                                     │
│  ├─ Jira    → Issue連携 (git連携なし)                              │
│  └─ 純粋git → bare repo へのpush (プライベートサーバー)             │
└─────────────────────────────────────────────────────────────────────┘
```

#### TMWS Memory Repository Core
```python
# tmws/core/memory_repository.py
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict
import subprocess
import json

class TMWSMemoryRepository:
    """
    TMWS内部Git Repository - 強制作成・常時利用

    設計原則:
    1. ローカルgitは常に存在 (外部連携なしでも全機能動作)
    2. セッション/パターン/問題はgitコミットとして記録
    3. git worktreeで並列タスクを分離
    4. 外部連携は後から追加可能
    """

    REPO_PATH = Path("~/.tmws/memory-repo").expanduser()

    def __init__(self):
        self._ensure_repo_exists()
        self.external_bridges: Dict[str, "ExternalBridge"] = {}

    def _ensure_repo_exists(self):
        """強制的にローカルgitリポジトリを作成"""
        if not (self.REPO_PATH / ".git").exists():
            self.REPO_PATH.mkdir(parents=True, exist_ok=True)

            # Initialize git repository
            self._git("init")

            # Create directory structure
            for subdir in ["sessions", "patterns", "contexts", "problems"]:
                (self.REPO_PATH / subdir).mkdir(exist_ok=True)
                (self.REPO_PATH / subdir / ".gitkeep").touch()

            # Initial commit
            self._git("add", ".")
            self._git("commit", "-m", "TMWS Memory Repository initialized")

            # Create main branches
            self._git("branch", "archive")  # 完了したセッションのアーカイブ

    def _git(self, *args) -> str:
        """Execute git command in memory repository"""
        result = subprocess.run(
            ["git", *args],
            cwd=self.REPO_PATH,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise GitError(f"git {args[0]} failed: {result.stderr}")
        return result.stdout.strip()

    # === Git Worktree Management (並列タスク管理) ===

    async def create_task_worktree(self, task_id: str, base_branch: str = "main") -> Path:
        """
        タスク専用のworktreeを作成

        Usage:
            worktree = await repo.create_task_worktree("issue-123")
            # worktree内で作業 → 完了後にmerge

        Benefits:
            - タスク間のコンテキスト分離
            - 並列作業が可能
            - 切り替えなしで複数タスクのコンテキスト保持
        """
        worktree_path = self.REPO_PATH.parent / "worktrees" / task_id
        branch_name = f"task/{task_id}"

        # Create branch from base
        self._git("branch", branch_name, base_branch)

        # Create worktree
        self._git("worktree", "add", str(worktree_path), branch_name)

        return worktree_path

    async def merge_task_worktree(self, task_id: str, delete_after: bool = True):
        """タスク完了時にworktreeをmainにマージ"""
        branch_name = f"task/{task_id}"
        worktree_path = self.REPO_PATH.parent / "worktrees" / task_id

        # Merge to main
        self._git("checkout", "main")
        self._git("merge", branch_name, "--no-ff", "-m", f"Complete task: {task_id}")

        # Cleanup
        if delete_after:
            self._git("worktree", "remove", str(worktree_path))
            self._git("branch", "-d", branch_name)

    async def list_active_worktrees(self) -> List[Dict]:
        """アクティブなworktree (進行中タスク) を一覧"""
        output = self._git("worktree", "list", "--porcelain")
        worktrees = []

        current = {}
        for line in output.split("\n"):
            if line.startswith("worktree "):
                if current:
                    worktrees.append(current)
                current = {"path": line.split(" ", 1)[1]}
            elif line.startswith("branch "):
                current["branch"] = line.split(" ", 1)[1]

        if current:
            worktrees.append(current)

        return [w for w in worktrees if w.get("branch", "").startswith("refs/heads/task/")]

    # === Session Recording (セッション記録) ===

    async def record_session(self, session: "SessionData") -> str:
        """
        セッションをgitコミットとして記録

        Returns:
            commit_sha: 記録されたコミットのSHA
        """
        session_file = self.REPO_PATH / "sessions" / f"{session.id}.json"
        session_file.write_text(session.to_json())

        # Stage and commit
        self._git("add", str(session_file))

        commit_msg = self._build_session_commit_message(session)
        self._git("commit", "-m", commit_msg)

        return self._git("rev-parse", "HEAD")

    def _build_session_commit_message(self, session: "SessionData") -> str:
        """構造化されたコミットメッセージを生成"""
        lines = [
            f"Session: {session.summary}",
            "",
            f"Duration: {session.duration_minutes}min",
            f"Agents: {', '.join(session.agents)}",
        ]

        if session.problems_solved:
            lines.append(f"Problems solved: {len(session.problems_solved)}")

        if session.patterns_learned:
            lines.append(f"Patterns learned: {len(session.patterns_learned)}")

        return "\n".join(lines)

    # === History Search (履歴検索) ===

    async def search_history(self, query: str, limit: int = 10) -> List[Dict]:
        """
        git log でセッション履歴を検索

        Benefits over DB search:
            - Full-text search in commit messages
            - Semantic grouping by commits
            - Natural time-based ordering
        """
        output = self._git(
            "log",
            f"--grep={query}",
            "--format=%H|%s|%ai|%an",
            f"-n{limit}",
            "--all"  # Search all branches including worktrees
        )

        results = []
        for line in output.split("\n"):
            if line:
                sha, subject, date, author = line.split("|", 3)
                results.append({
                    "commit_sha": sha[:7],
                    "subject": subject,
                    "date": date,
                    "author": author,
                    "session_file": self._get_session_file_for_commit(sha)
                })

        return results

    async def get_similar_sessions(self, context: str, limit: int = 5) -> List["SessionData"]:
        """
        類似セッションを検索 (git履歴 + セマンティック検索)

        Hybrid search:
            1. git log --grep for keyword matches
            2. ChromaDB for semantic similarity
            3. Merge and rank results
        """
        # Git keyword search
        git_matches = await self.search_history(context, limit=limit * 2)

        # Semantic search in ChromaDB
        semantic_matches = await self.vector_service.search(
            query=context,
            collection="sessions",
            limit=limit * 2
        )

        # Merge and deduplicate
        return self._merge_search_results(git_matches, semantic_matches, limit)

    # === Problem-Solution Archive (問題解決アーカイブ) ===

    async def record_problem_solution(
        self,
        problem: str,
        solution: str,
        agents: List[str],
        success: bool = True
    ) -> str:
        """
        問題と解決策をアーカイブ

        Future queries for similar problems will find this solution.
        """
        problem_id = self._generate_id()
        problem_file = self.REPO_PATH / "problems" / f"{problem_id}.json"

        data = {
            "id": problem_id,
            "problem": problem,
            "solution": solution,
            "agents": agents,
            "success": success,
            "timestamp": datetime.utcnow().isoformat(),
        }

        problem_file.write_text(json.dumps(data, indent=2))

        self._git("add", str(problem_file))
        self._git("commit", "-m", f"Problem: {problem[:50]}...\n\nSolved by: {', '.join(agents)}")

        return problem_id

    async def find_similar_problems(self, problem: str, limit: int = 5) -> List[Dict]:
        """類似の過去の問題と解決策を検索"""
        # Keyword search
        keyword_matches = await self.search_history(problem, limit=limit)

        # Semantic search
        semantic_matches = await self.vector_service.search(
            query=problem,
            collection="problems",
            limit=limit
        )

        results = []
        for match in self._merge_search_results(keyword_matches, semantic_matches, limit):
            if match.get("session_file") and "problems" in match["session_file"]:
                problem_data = json.loads(Path(match["session_file"]).read_text())
                results.append({
                    "problem": problem_data["problem"],
                    "solution": problem_data["solution"],
                    "agents": problem_data["agents"],
                    "success": problem_data["success"],
                    "similarity": match.get("similarity", 0.0),
                })

        return results

    # === External Integration (外部連携) ===

    async def connect_github(self, repo: str, token: str):
        """
        GitHub連携を有効化

        Flow:
            1. GitHub repoをリモートとして追加
            2. GitHubBridgeを初期化 (Issue/PR API連携)
            3. 既存のローカル履歴をpush (オプション)
        """
        from .bridges import GitHubBridge

        # Add as git remote
        remote_url = f"https://github.com/{repo}.git"
        try:
            self._git("remote", "add", "github", remote_url)
        except GitError:
            self._git("remote", "set-url", "github", remote_url)

        # Initialize bridge
        self.external_bridges["github"] = GitHubBridge(
            repo=repo,
            token=token,
            memory_repo=self
        )

        return {"status": "connected", "remote": "github", "repo": repo}

    async def connect_gitlab(self, repo: str, token: str, host: str = "gitlab.com"):
        """GitLab連携を有効化"""
        from .bridges import GitLabBridge

        remote_url = f"https://{host}/{repo}.git"
        try:
            self._git("remote", "add", "gitlab", remote_url)
        except GitError:
            self._git("remote", "set-url", "gitlab", remote_url)

        self.external_bridges["gitlab"] = GitLabBridge(
            repo=repo,
            token=token,
            host=host,
            memory_repo=self
        )

        return {"status": "connected", "remote": "gitlab", "repo": repo}

    async def sync_to_remote(self, remote: str = "origin"):
        """リモートへ同期 (バックアップ/チーム共有)"""
        self._git("push", remote, "main", "--force-with-lease")
        self._git("push", remote, "archive", "--force-with-lease")
```

#### Git Workflow Patterns (ワークフローパターン)

```python
# tmws/core/git_workflows.py

class TMWSGitWorkflow:
    """
    TMWS Memory Repository用のGitワークフローパターン

    Supported workflows:
    1. Task-based branching (タスクごとにブランチ)
    2. Session-based commits (セッションごとにコミット)
    3. Problem-solution tagging (問題解決にタグ付け)
    4. Archive rotation (古いセッションをアーカイブブランチへ)
    """

    def __init__(self, repo: TMWSMemoryRepository):
        self.repo = repo

    # === Task-Based Workflow ===

    async def start_task(self, task_id: str, description: str) -> Dict:
        """
        新しいタスクを開始

        Creates:
            - New branch: task/{task_id}
            - New worktree (optional): ~/.tmws/worktrees/{task_id}
            - Task metadata file

        Usage:
            workflow.start_task("implement-lazy-loading", "Phase 4.1a implementation")
        """
        branch_name = f"task/{task_id}"

        # Create branch
        self.repo._git("checkout", "-b", branch_name)

        # Create task metadata
        task_meta = {
            "id": task_id,
            "description": description,
            "started_at": datetime.utcnow().isoformat(),
            "status": "in_progress",
        }

        task_file = self.repo.REPO_PATH / "contexts" / f"task-{task_id}.json"
        task_file.write_text(json.dumps(task_meta, indent=2))

        self.repo._git("add", str(task_file))
        self.repo._git("commit", "-m", f"Start task: {task_id}\n\n{description}")

        return {"branch": branch_name, "task_id": task_id, "status": "started"}

    async def complete_task(self, task_id: str, summary: str) -> Dict:
        """
        タスクを完了してmainにマージ

        Actions:
            1. Update task metadata
            2. Commit final state
            3. Merge to main with --no-ff
            4. Tag the completion point
            5. Optionally delete branch
        """
        branch_name = f"task/{task_id}"

        # Update task metadata
        task_file = self.repo.REPO_PATH / "contexts" / f"task-{task_id}.json"
        if task_file.exists():
            task_meta = json.loads(task_file.read_text())
            task_meta["status"] = "completed"
            task_meta["completed_at"] = datetime.utcnow().isoformat()
            task_meta["summary"] = summary
            task_file.write_text(json.dumps(task_meta, indent=2))

            self.repo._git("add", str(task_file))
            self.repo._git("commit", "-m", f"Complete task: {task_id}\n\n{summary}")

        # Merge to main
        self.repo._git("checkout", "main")
        self.repo._git("merge", branch_name, "--no-ff", "-m", f"Merge task: {task_id}")

        # Tag completion
        tag_name = f"task-complete/{task_id}"
        self.repo._git("tag", "-a", tag_name, "-m", summary)

        # Cleanup
        self.repo._git("branch", "-d", branch_name)

        return {"task_id": task_id, "status": "completed", "tag": tag_name}

    # === Session Workflow ===

    async def commit_session(self, session: "SessionData") -> str:
        """
        セッションをコミット (現在のブランチに)

        Commit message format:
            Session: {summary}

            Duration: {duration}
            Agents: {agents}
            Problems: {count}
            Patterns: {count}
        """
        return await self.repo.record_session(session)

    # === Archive Workflow ===

    async def archive_old_sessions(self, older_than_days: int = 30):
        """
        古いセッションをarchiveブランチへ移動

        Benefits:
            - mainブランチを軽量に保つ
            - 古い履歴はarchiveブランチで保持
            - git gc で効率的に圧縮
        """
        cutoff = datetime.utcnow() - timedelta(days=older_than_days)

        # Find old sessions
        sessions_dir = self.repo.REPO_PATH / "sessions"
        old_sessions = []

        for session_file in sessions_dir.glob("*.json"):
            data = json.loads(session_file.read_text())
            session_date = datetime.fromisoformat(data["timestamp"])
            if session_date < cutoff:
                old_sessions.append(session_file)

        if not old_sessions:
            return {"archived": 0}

        # Cherry-pick to archive branch
        self.repo._git("checkout", "archive")

        for session_file in old_sessions:
            # Copy to archive
            archive_file = self.repo.REPO_PATH / "sessions" / "archived" / session_file.name
            archive_file.parent.mkdir(exist_ok=True)
            archive_file.write_text(session_file.read_text())

            self.repo._git("add", str(archive_file))

        self.repo._git("commit", "-m", f"Archive {len(old_sessions)} old sessions")

        # Remove from main
        self.repo._git("checkout", "main")
        for session_file in old_sessions:
            session_file.unlink()
            self.repo._git("rm", str(session_file))

        self.repo._git("commit", "-m", f"Move {len(old_sessions)} sessions to archive")

        return {"archived": len(old_sessions)}

    # === Tag Workflow ===

    async def tag_milestone(self, name: str, description: str):
        """マイルストーンにタグ付け"""
        self.repo._git("tag", "-a", f"milestone/{name}", "-m", description)

    async def tag_problem_solved(self, problem_id: str, summary: str):
        """問題解決にタグ付け (後から検索しやすく)"""
        self.repo._git("tag", "-a", f"solved/{problem_id}", "-m", summary)
```

#### External Integration Flow (外部連携フロー)

```
┌─────────────────────────────────────────────────────────────────────┐
│                   External Integration Flow                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Phase 1: Initial Setup (初期設定)                                   │
│  ─────────────────────────────────────────                          │
│  User: /tmws connect github apto-as/tmws-memory                     │
│                                                                      │
│  TMWS:                                                               │
│    1. git remote add github https://github.com/apto-as/tmws-memory  │
│    2. Initialize GitHubBridge with PAT token                         │
│    3. Test connection (GET /repos/{repo})                            │
│    4. Optional: Push existing local history                          │
│                                                                      │
│  Result: GitHub連携が有効化。ローカルgit + GitHub API両方使用可能    │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Phase 2: Working Session (作業セッション)                           │
│  ─────────────────────────────────────────                          │
│                                                                      │
│  User starts working on Issue #123...                                │
│                                                                      │
│  TMWS (自動):                                                        │
│    1. Detect branch name: feature/123-lazy-loading                  │
│    2. Create task branch in memory-repo: task/issue-123             │
│    3. Fetch Issue #123 metadata from GitHub API                      │
│    4. Store issue context in memory:                                 │
│       {                                                              │
│         "issue_number": 123,                                         │
│         "title": "Implement lazy loading",                           │
│         "labels": ["enhancement", "phase-4.1"],                      │
│         "assignee": "user",                                          │
│         "body": "...(issue description)..."                          │
│       }                                                              │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Phase 3: Session Synthesis (セッション合成)                         │
│  ─────────────────────────────────────────                          │
│                                                                      │
│  User completes work...                                              │
│                                                                      │
│  TMWS (自動):                                                        │
│    1. Core Data (常に収集):                                          │
│       - Tool executions (from TMWS traces)                          │
│       - Memory operations                                            │
│       - Pattern detections                                           │
│       - Agent collaborations                                         │
│                                                                      │
│    2. Git Data (ローカルgit):                                        │
│       - Commits in memory-repo                                       │
│       - Branch changes                                               │
│       - File modifications                                           │
│                                                                      │
│    3. External Data (GitHub連携時のみ):                              │
│       - Issue comments added                                         │
│       - PR status changes                                            │
│       - Review comments                                              │
│       - CI/CD status                                                 │
│                                                                      │
│    4. Commit session to memory-repo:                                 │
│       git commit -m "Session: Implemented lazy loading for #123"    │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Phase 4: Sync to Remote (オプション)                                │
│  ─────────────────────────────────────                              │
│                                                                      │
│  User: /tmws sync github                                             │
│                                                                      │
│  TMWS:                                                               │
│    1. git push github main --force-with-lease                        │
│    2. Optionally create GitHub Issue for patterns learned            │
│    3. Update Issue #123 with session summary comment                 │
│                                                                      │
│  Benefits:                                                           │
│    - Backup to GitHub                                                │
│    - Team visibility                                                 │
│    - Cross-device sync                                               │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Phase 5: Context Retrieval (コンテキスト取得)                       │
│  ─────────────────────────────────────────                          │
│                                                                      │
│  User: "Similar issue we had before with ChromaDB..."               │
│                                                                      │
│  TMWS (検索順序):                                                    │
│    1. Local git: git log --grep "ChromaDB"                          │
│    2. ChromaDB: Semantic search for "ChromaDB issue"                │
│    3. GitHub API (連携時): Search issues/PRs                         │
│                                                                      │
│  Result: Merged results from all sources, ranked by relevance        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

#### External Bridge Interface (外部連携インターフェース)

```python
# tmws/core/bridges/base.py
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

class ExternalBridge(ABC):
    """外部サービス連携の基底クラス"""

    @abstractmethod
    async def fetch_issue(self, issue_id: str) -> Dict:
        """Issue/Ticketを取得"""
        pass

    @abstractmethod
    async def search_issues(self, query: str) -> List[Dict]:
        """Issueを検索"""
        pass

    @abstractmethod
    async def enrich_session(self, session: "SessionData") -> Dict:
        """セッションに外部メタデータを追加"""
        pass

    @abstractmethod
    async def post_session_summary(self, session: "SessionData", issue_id: str):
        """セッションサマリーをIssueにコメント"""
        pass


# tmws/core/bridges/github_bridge.py
class GitHubBridge(ExternalBridge):
    """GitHub連携ブリッジ"""

    def __init__(self, repo: str, token: str, memory_repo: "TMWSMemoryRepository"):
        self.repo = repo
        self.token = token
        self.memory_repo = memory_repo
        self._client = httpx.AsyncClient(
            base_url="https://api.github.com",
            headers={"Authorization": f"Bearer {token}"}
        )

    async def fetch_issue(self, issue_number: int) -> Dict:
        resp = await self._client.get(f"/repos/{self.repo}/issues/{issue_number}")
        return resp.json()

    async def search_issues(self, query: str) -> List[Dict]:
        resp = await self._client.get(
            "/search/issues",
            params={"q": f"{query} repo:{self.repo}"}
        )
        return resp.json().get("items", [])

    async def enrich_session(self, session: "SessionData") -> Dict:
        """セッションにGitHubメタデータを追加"""
        enrichment = {}

        # Extract issue references from session
        issue_refs = self._extract_issue_refs(session)

        for issue_num in issue_refs:
            issue_data = await self.fetch_issue(issue_num)
            enrichment[f"issue_{issue_num}"] = {
                "title": issue_data["title"],
                "state": issue_data["state"],
                "labels": [l["name"] for l in issue_data["labels"]],
                "assignee": issue_data.get("assignee", {}).get("login"),
            }

        return enrichment

    async def post_session_summary(self, session: "SessionData", issue_number: int):
        """セッションサマリーをIssueコメントとして投稿"""
        comment_body = f"""## TMWS Session Summary

**Duration**: {session.duration_minutes} minutes
**Agents**: {', '.join(session.agents)}

### Summary
{session.summary}

### Problems Solved
{self._format_problems(session.problems_solved)}

### Patterns Learned
{self._format_patterns(session.patterns_learned)}

---
*Auto-generated by TMWS Memory System*
"""

        await self._client.post(
            f"/repos/{self.repo}/issues/{issue_number}/comments",
            json={"body": comment_body}
        )


# tmws/core/bridges/gitlab_bridge.py
class GitLabBridge(ExternalBridge):
    """GitLab連携ブリッジ"""

    def __init__(self, repo: str, token: str, host: str, memory_repo: "TMWSMemoryRepository"):
        self.repo = repo
        self.token = token
        self.host = host
        self.memory_repo = memory_repo
        self._client = httpx.AsyncClient(
            base_url=f"https://{host}/api/v4",
            headers={"PRIVATE-TOKEN": token}
        )

    async def fetch_issue(self, issue_iid: int) -> Dict:
        project_id = self.repo.replace("/", "%2F")
        resp = await self._client.get(f"/projects/{project_id}/issues/{issue_iid}")
        return resp.json()

    # ... similar implementation to GitHubBridge
```

#### Work Session Synthesis (GitHub非依存版)
```python
# tmws/core/session_synthesizer.py
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class SessionSynthesizer:
    """
    セッション合成 - GitHub非依存で全機能動作

    Data sources (優先順位):
    1. Core (必須): TMWS内部データ - 常に利用可能
    2. Git (必須): ローカルメモリリポジトリ - 常に利用可能
    3. External (オプション): GitHub/GitLab等 - 連携時のみ
    """

    def __init__(self, memory_repo: TMWSMemoryRepository):
        self.memory_repo = memory_repo

    async def synthesize_session(
        self,
        start_time: datetime,
        end_time: datetime,
        task_id: Optional[str] = None
    ) -> "SessionData":
        """
        セッションを合成してgitコミット

        Returns:
            SessionData with commit_sha
        """

        # === Layer 1: Core Data (常に収集) ===
        core_activities = {
            "tool_executions": await self._get_tool_traces(start_time, end_time),
            "memories_created": await self._get_memories_created(start_time, end_time),
            "memories_recalled": await self._get_memories_recalled(start_time, end_time),
            "patterns_detected": await self._get_patterns_detected(start_time, end_time),
            "agents_involved": await self._get_active_agents(start_time, end_time),
            "verifications": await self._get_verifications(start_time, end_time),
            "trust_changes": await self._get_trust_changes(start_time, end_time),
        }

        # === Layer 2: Git Data (ローカルメモリリポジトリ) ===
        git_activities = {
            "commits": await self.memory_repo.get_commits_in_range(start_time, end_time),
            "branch": self.memory_repo._git("branch", "--show-current"),
            "files_changed": await self.memory_repo.get_changed_files(start_time, end_time),
        }

        # === Layer 3: External Data (オプション) ===
        external_data = {}

        for bridge_name, bridge in self.memory_repo.external_bridges.items():
            try:
                external_data[bridge_name] = await bridge.enrich_session_data(
                    core_activities, git_activities
                )
            except Exception as e:
                # External failure should not break session synthesis
                external_data[bridge_name] = {"error": str(e)}

        # === Build Session ===
        session = SessionData(
            id=self._generate_session_id(start_time),
            start_time=start_time,
            end_time=end_time,
            task_id=task_id,

            # Core metrics
            tool_count=len(core_activities["tool_executions"]),
            memory_operations=len(core_activities["memories_created"]) + len(core_activities["memories_recalled"]),
            patterns_learned=len(core_activities["patterns_detected"]),
            agents=list(core_activities["agents_involved"]),

            # Summary
            summary=self._generate_narrative(core_activities, git_activities, external_data),

            # Problems and solutions
            problems_solved=self._extract_problems(core_activities),

            # Raw data for future queries
            raw_data={
                "core": core_activities,
                "git": git_activities,
                "external": external_data,
            }
        )

        # === Commit to Memory Repository ===
        commit_sha = await self.memory_repo.record_session(session)
        session.commit_sha = commit_sha

        # === Optional: Sync to external ===
        for bridge_name, bridge in self.memory_repo.external_bridges.items():
            if external_data.get(bridge_name, {}).get("issue_number"):
                await bridge.post_session_summary(
                    session,
                    external_data[bridge_name]["issue_number"]
                )

        return session

    def _generate_narrative(
        self,
        core: Dict,
        git: Dict,
        external: Dict
    ) -> str:
        """人間可読なセッションサマリーを生成"""
        parts = []

        # Tool usage
        if core["tool_executions"]:
            tool_count = len(core["tool_executions"])
            parts.append(f"Executed {tool_count} tool operations")

        # Agent collaboration
        if core["agents_involved"]:
            agent_list = ", ".join(core["agents_involved"])
            parts.append(f"with collaboration from {agent_list}")

        # Memory activity
        mem_count = len(core["memories_created"]) + len(core["memories_recalled"])
        if mem_count > 0:
            parts.append(f"involving {mem_count} memory operations")

        # Patterns
        if core["patterns_detected"]:
            parts.append(f"detected {len(core['patterns_detected'])} patterns")

        # Git activity
        if git["commits"]:
            parts.append(f"across {len(git['commits'])} commits")

        # External (if available)
        for bridge_name, data in external.items():
            if isinstance(data, dict) and "issue_number" in data:
                parts.append(f"addressing #{data['issue_number']}")

        return ". ".join(parts).capitalize() + "." if parts else "Session completed."


#### Auto-Context Enrichment (自動コンテキスト補完)
```python
# tmws/core/context_enricher.py
from typing import List, Dict, Optional

class ContextEnricher:
    """
    自動コンテキスト補完 - GitHub非依存で全機能動作

    Search priority:
    1. TMWS Memory (ChromaDB semantic search)
    2. Local Git History (git log --grep)
    3. External API (GitHub/GitLab issues) - if connected
    """

    def __init__(self, memory_repo: TMWSMemoryRepository):
        self.memory_repo = memory_repo

    async def enrich_prompt(
        self,
        user_query: str,
        agent_id: Optional[str] = None
    ) -> str:
        """
        ユーザークエリに関連コンテキストを自動追加

        Always works (even offline):
        - Memory search
        - Git history search
        - Similar problem suggestions

        Enhanced when connected:
        - GitHub/GitLab issue search
        - PR/MR references
        """

        # === Layer 1: TMWS Memory Search (常に動作) ===
        memories = await self.memory_repo.vector_service.search(
            query=user_query,
            limit=5,
            min_similarity=0.7
        )

        # === Layer 2: Git History Search (常に動作) ===
        git_matches = await self.memory_repo.search_history(user_query, limit=5)

        # === Layer 3: Similar Problems (常に動作) ===
        similar_problems = await self.memory_repo.find_similar_problems(user_query, limit=3)

        # === Layer 4: Agent Trust (常に動作) ===
        trust_context = None
        if agent_id:
            trust_context = await self._get_agent_trust_context(agent_id)

        # === Layer 5: External Search (オプション) ===
        external_context = {}
        for bridge_name, bridge in self.memory_repo.external_bridges.items():
            try:
                external_context[bridge_name] = await bridge.search_issues(user_query)
            except Exception:
                pass  # External failure is not critical

        # === Build Enriched Prompt ===
        return self._format_enriched_prompt(
            user_query=user_query,
            memories=memories,
            git_matches=git_matches,
            similar_problems=similar_problems,
            trust_context=trust_context,
            external_context=external_context
        )

    def _format_enriched_prompt(self, **kwargs) -> str:
        """構造化されたコンテキストプロンプトを生成"""
        sections = [f"# User Query\n{kwargs['user_query']}"]

        # Memory context
        sections.append("\n## Relevant Memories")
        if kwargs["memories"]:
            for mem in kwargs["memories"]:
                sections.append(f"- [{mem['namespace']}] {mem['content'][:150]}...")
        else:
            sections.append("(No relevant memories found)")

        # Git history
        sections.append("\n## Related Sessions (Git History)")
        if kwargs["git_matches"]:
            for match in kwargs["git_matches"]:
                sections.append(f"- {match['commit_sha']}: {match['subject']}")
        else:
            sections.append("(No related sessions found)")

        # Similar problems
        sections.append("\n## Similar Problems Solved Before")
        if kwargs["similar_problems"]:
            for prob in kwargs["similar_problems"]:
                sections.append(f"- **Problem**: {prob['problem'][:100]}...")
                sections.append(f"  **Solution**: {prob['solution'][:100]}...")
                sections.append(f"  **Agents**: {', '.join(prob['agents'])}")
        else:
            sections.append("(No similar problems found)")

        # Trust context
        if kwargs["trust_context"]:
            sections.append(f"\n## Agent Trust Score")
            sections.append(f"{kwargs['trust_context']['agent']}: {kwargs['trust_context']['score']:.2f}")

        # External context (if available)
        for bridge_name, issues in kwargs["external_context"].items():
            if issues:
                sections.append(f"\n## {bridge_name.title()} Issues")
                for issue in issues[:3]:
                    sections.append(f"- #{issue.get('number', 'N/A')}: {issue.get('title', 'N/A')}")

        return "\n".join(sections)
```

### 2.4 Memory Decay System

#### Time-Based Relevance Scoring
```python
# tmws/core/memory_decay.py
from datetime import datetime, timedelta
from typing import List, Dict
import math

class MemoryDecayManager:
    """Implement time-based memory decay for relevance scoring."""

    def __init__(self, half_life_days: int = 30):
        """
        Args:
            half_life_days: Time for memory importance to decay to 50%
        """
        self.half_life_days = half_life_days
        self.decay_constant = math.log(2) / half_life_days

    def calculate_current_importance(
        self,
        original_importance: float,
        created_at: datetime,
        access_count: int = 0
    ) -> float:
        """Calculate time-decayed importance score."""

        age_days = (datetime.utcnow() - created_at).total_seconds() / 86400

        # Exponential decay: I(t) = I₀ * e^(-λt)
        time_factor = math.exp(-self.decay_constant * age_days)

        # Access boost: Recent accesses increase importance
        access_boost = min(1.0 + (access_count * 0.05), 1.5)  # Max 1.5x boost

        # Combined score
        current_importance = original_importance * time_factor * access_boost

        return max(0.0, min(1.0, current_importance))  # Clamp [0, 1]

    async def recompute_all_scores(self):
        """Batch recompute all memory importance scores."""

        memories = await self.tmws.get_all_memories()
        updates = []

        for mem in memories:
            new_score = self.calculate_current_importance(
                original_importance=mem["importance"],
                created_at=datetime.fromisoformat(mem["created_at"]),
                access_count=mem.get("access_count", 0)
            )

            if abs(new_score - mem["current_importance"]) > 0.01:
                updates.append({
                    "id": mem["id"],
                    "current_importance": new_score
                })

        # Batch update
        if updates:
            await self.tmws.batch_update_importance(updates)
            logger.info(f"Updated {len(updates)} memory importance scores")

    async def prune_low_importance(self, threshold: float = 0.1):
        """Remove memories below importance threshold."""

        pruned = await self.tmws.delete_memories_where(
            lambda m: m["current_importance"] < threshold
        )

        logger.info(f"Pruned {pruned} low-importance memories (< {threshold})")
```

#### Decay Scheduler
```python
# tmws/scheduler/decay_jobs.py
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

class DecayScheduler:
    """Schedule periodic memory decay recomputation."""

    def __init__(self, decay_manager: MemoryDecayManager):
        self.decay_manager = decay_manager
        self.scheduler = AsyncIOScheduler()

    def start(self):
        """Start decay background jobs."""

        # Recompute scores every 6 hours
        self.scheduler.add_job(
            self.decay_manager.recompute_all_scores,
            CronTrigger(hour="*/6"),
            id="memory_decay_recompute"
        )

        # Prune low-importance memories daily at 3 AM
        self.scheduler.add_job(
            self.decay_manager.prune_low_importance,
            CronTrigger(hour=3, minute=0),
            id="memory_prune_low_importance",
            kwargs={"threshold": 0.05}
        )

        self.scheduler.start()
        logger.info("Memory decay scheduler started")
```

### 2.5 Trust-Weighted RAG for Code Context

#### Agent Trust Integration
```python
# tmws/rag/trust_weighted_retrieval.py
from typing import List, Dict, Optional
import numpy as np

class TrustWeightedRAG:
    """Code context retrieval with agent trust scoring."""

    async def retrieve_code_context(
        self,
        query: str,
        agent_id: Optional[str] = None,
        top_k: int = 5
    ) -> List[Dict]:
        """Retrieve code context with trust-weighted ranking."""

        # Step 1: Semantic search in code memories
        candidates = await self.tmws.search_memories(
            query=query,
            namespace="code.*",  # Only code-related memories
            limit=top_k * 3  # Over-retrieve for reranking
        )

        # Step 2: Get agent trust scores
        trust_scores = {}
        if agent_id:
            trust_scores[agent_id] = await self.tmws.get_agent_trust_score(agent_id)

        # For referenced agents in memories
        for mem in candidates:
            if "agent" in mem["metadata"]:
                ref_agent = mem["metadata"]["agent"]
                if ref_agent not in trust_scores:
                    trust_scores[ref_agent] = await self.tmws.get_agent_trust_score(ref_agent)

        # Step 3: Rerank with trust weighting
        ranked = []
        for mem in candidates:
            base_score = mem["similarity"]

            # Trust boost if memory created by trusted agent
            trust_boost = 1.0
            if "agent" in mem["metadata"]:
                agent = mem["metadata"]["agent"]
                trust_boost = 1.0 + (trust_scores.get(agent, 0.5) * 0.5)  # Up to 1.5x

            # Recency boost
            age_days = (datetime.utcnow() - datetime.fromisoformat(mem["created_at"])).days
            recency_boost = math.exp(-age_days / 30)  # Decay over 30 days

            # Combined score
            final_score = base_score * trust_boost * recency_boost

            ranked.append({
                **mem,
                "final_score": final_score,
                "trust_boost": trust_boost,
                "recency_boost": recency_boost
            })

        # Sort by final score
        ranked.sort(key=lambda x: x["final_score"], reverse=True)

        return ranked[:top_k]
```

---

## 3. Implementation Phases

### Phase 4.1a: Metadata Registry (Week 1-2)

**Goal**: Implement sparse registry with tool introspection

#### Deliverables
1. `tmws/core/sparse_registry.py` - Core registry implementation
2. `tools/build_registry.py` - Registry generation CLI
3. `~/.tmws/registry/index.json` - Generated registry file
4. Unit tests (>90% coverage)

#### Success Criteria
- [ ] Registry loads in <100ms
- [ ] All 40+ MCP servers cataloged
- [ ] Tool schemas correctly introspected
- [ ] Popularity scores initialized to 0.0
- [ ] Registry auto-regenerates on config changes

#### Implementation Steps
```python
# Week 1: Core data structures
class SparseRegistry:
    def __init__(self, registry_path: Path):
        self.registry = self._load_registry(registry_path)
        self.index = self._build_index()

    def search_tools(self, query: str, category: Optional[str] = None) -> List[Tool]:
        """Fast tool search without server connections."""
        pass

    def get_server_config(self, server_name: str) -> ServerConfig:
        """Get connection config for lazy loading."""
        pass

# Week 2: Introspection tooling
async def introspect_server(config: dict) -> dict:
    """Connect once to extract tool schemas."""
    pass

def generate_registry(mcp_config_path: str, output_path: str):
    """CLI tool to build sparse registry."""
    pass
```

### Phase 4.1b: Connection Pool (Week 3-4)

**Goal**: Implement lazy connection pool with TTL management

#### Deliverables
1. `tmws/core/connection_pool.py` - Pool implementation
2. `tmws/core/connection.py` - Connection wrapper with TTL
3. `~/.tmws/config/pool.yaml` - Pool configuration
4. Integration with existing `mcphub_mcp.py`
5. Load tests (measure startup time improvement)

#### Success Criteria
- [ ] Startup time <2s (vs 15-30s baseline)
- [ ] Max 10 concurrent connections enforced
- [ ] LRU eviction working correctly
- [ ] TTL expiration removes idle connections
- [ ] Core TMWS connection never evicted
- [ ] Graceful handling of connection failures

#### Implementation Steps
```python
# Week 3: Connection pool core
class ConnectionPool:
    async def get_connection(self, server_name: str) -> Connection:
        """Get or lazy-create connection."""
        pass

    async def _evict_lru(self):
        """Remove least recently used connection."""
        pass

    async def _cleanup_expired(self):
        """Background task to remove TTL-expired connections."""
        pass

# Week 4: Integration
class MCPHubManager:
    def __init__(self):
        self.registry = SparseRegistry()
        self.pool = ConnectionPool()

    async def invoke_tool(self, tool_name: str, **kwargs):
        server = self.registry.get_server_for_tool(tool_name)
        conn = await self.pool.get_connection(server)
        return await conn.call_tool(tool_name, **kwargs)
```

### Phase 4.1c: GitHub Integration (Week 5-6)

**Goal**: Automatic GitHub-memory synchronization

#### Deliverables
1. `tmws/integrations/github_memory_bridge.py`
2. `tmws/core/session_synthesizer.py`
3. `~/.tmws/config/github.yaml` - GitHub API configuration
4. Hook into commit/branch operations
5. E2E tests with mock GitHub API

#### Success Criteria
- [ ] Issue numbers auto-detected from branch/commits
- [ ] Work sessions auto-summarized and stored
- [ ] GitHub API rate limiting handled gracefully
- [ ] Offline mode gracefully degrades
- [ ] Privacy: No sensitive data in GitHub metadata

#### Implementation Steps
```python
# Week 5: GitHub bridge
class GitHubMemoryBridge:
    async def enrich_work_session(self, session_id: str) -> GitHubContext:
        """Fetch GitHub metadata and store in memory."""
        pass

    async def on_commit(self, commit_sha: str):
        """Hook: Auto-store commit context."""
        pass

# Week 6: Session synthesis
class SessionSynthesizer:
    async def synthesize_session(self, start: datetime, end: datetime) -> dict:
        """Generate comprehensive session summary."""
        pass

    def _generate_narrative(self, activities: dict) -> str:
        """Natural language session summary."""
        pass
```

### Phase 4.1d: Memory Decay (Week 7-8)

**Goal**: Time-based memory importance decay

#### Deliverables
1. `tmws/core/memory_decay.py` - Decay calculation
2. `tmws/scheduler/decay_jobs.py` - Background scheduler
3. `tmws/rag/trust_weighted_retrieval.py` - RAG with trust scoring
4. Database migration to add `current_importance` column
5. Performance benchmarks (decay computation speed)

#### Success Criteria
- [ ] Decay formula mathematically sound (exponential)
- [ ] Batch recomputation completes in <1s for 10k memories
- [ ] Pruning correctly removes low-importance memories
- [ ] Trust-weighted RAG improves retrieval precision by >15%
- [ ] Scheduler jobs run reliably

#### Implementation Steps
```python
# Week 7: Decay system
class MemoryDecayManager:
    def calculate_current_importance(self, original: float, age: timedelta) -> float:
        """Exponential decay formula."""
        pass

    async def recompute_all_scores(self):
        """Batch update all memories."""
        pass

# Week 8: Trust-weighted RAG
class TrustWeightedRAG:
    async def retrieve_code_context(self, query: str, agent_id: str) -> List[Dict]:
        """Retrieve with trust + recency + similarity."""
        pass
```

---

## 4. Security Considerations

### 4.1 Connection Pool Security

#### Threat: Connection Hijacking
- **Mitigation**: Verify server identity on connection
- **Implementation**: Store SHA256 hash of server command/args in registry
```python
def verify_server_identity(config: dict, registry_entry: dict) -> bool:
    config_hash = hashlib.sha256(
        json.dumps(config, sort_keys=True).encode()
    ).hexdigest()
    return config_hash == registry_entry["config_hash"]
```

#### Threat: Resource Exhaustion
- **Mitigation**: Enforce strict pool size limits
- **Implementation**: Hardcoded `max_size=10`, no user override
```python
MAX_POOL_SIZE = 10  # Hardcoded constant
if len(self.pool) >= MAX_POOL_SIZE:
    raise PoolExhaustedError("Connection pool full")
```

### 4.2 Memory Privacy

#### Threat: Sensitive Data in Work Sessions
- **Mitigation**: Redact secrets before storage
- **Implementation**: Regex-based secret detection
```python
def redact_secrets(text: str) -> str:
    patterns = [
        r'(password|token|key|secret)[\s:=]+[\w\-]+',
        r'-----BEGIN .+ PRIVATE KEY-----',
        r'ghp_[a-zA-Z0-9]{36}'  # GitHub tokens
    ]
    for pattern in patterns:
        text = re.sub(pattern, r'\1=<REDACTED>', text)
    return text
```

#### Threat: GitHub API Token Exposure
- **Mitigation**: Store tokens in system keychain (macOS Keychain, Linux Secret Service)
- **Implementation**: Use `keyring` library
```python
import keyring

def get_github_token() -> str:
    return keyring.get_password("tmws", "github_api_token")
```

### 4.3 Trust Score Manipulation

#### Threat: Agent Self-Verification Fraud
- **Mitigation**: Agents cannot verify their own actions
- **Implementation**: Enforce `verifier != verified_agent`
```python
async def verify_and_record(self, agent: str, evidence: str, verifier: str):
    if agent == verifier:
        raise ValueError("Self-verification not allowed")
```

#### Threat: Trust Score Poisoning
- **Mitigation**: Cap trust score changes per verification
- **Implementation**: Limit delta to ±0.10 per event
```python
def update_trust_score(current: float, success: bool) -> float:
    delta = 0.05 if success else -0.10
    delta = max(min(delta, 0.10), -0.10)  # Clamp
    return max(0.0, min(1.0, current + delta))
```

---

## 5. Performance Targets

### 5.1 Latency Requirements

| Operation | Current (v2.4.16) | Target (v2.5.0) | P95 Threshold |
|-----------|-------------------|-----------------|---------------|
| **System Startup** | 15-30s | <2s | <3s |
| **Registry Load** | N/A | <100ms | <200ms |
| **Tool Search** | ~500ms | <50ms | <100ms |
| **Lazy Connect** | N/A | <5s | <8s |
| **Memory Search** | 200-500ms | <150ms | <300ms |
| **Session Synthesis** | N/A | <2s | <5s |
| **Decay Recompute (10k)** | N/A | <1s | <2s |

### 5.2 Memory Footprint

| Component | Current | Target | Notes |
|-----------|---------|--------|-------|
| **Base Process** | 120 MB | 150 MB | +30MB for registry/pool |
| **Per Active Connection** | ~20 MB | ~20 MB | Unchanged |
| **Registry Index** | N/A | 2-5 MB | 40 servers × 50KB metadata |
| **Connection Pool (10 max)** | 800 MB | 200-300 MB | 70% reduction |

### 5.3 Scalability Targets

| Metric | Current | Target | Scaling Factor |
|--------|---------|--------|----------------|
| **Max MCP Servers** | 40 | 200+ | 5x |
| **Max Tools** | 237 | 1000+ | 4x |
| **Concurrent Connections** | 40 | 10 | 0.25x (intentional reduction) |
| **Memory Records** | 10k | 100k | 10x |

---

## 6. Success Metrics

### 6.1 Quantitative KPIs

#### Performance
- [ ] **P50 startup time** < 1.5s (baseline: 20s)
- [ ] **P95 startup time** < 3s (baseline: 30s)
- [ ] **P99 memory usage** < 400MB (baseline: 800MB)

#### Reliability
- [ ] **Connection success rate** > 99% (lazy connects)
- [ ] **TTL eviction accuracy** > 99% (no premature evictions)
- [ ] **Memory sync success** > 95% (GitHub integration)

#### Usability
- [ ] **Tool discovery time** < 5s (agent decision latency)
- [ ] **Context retrieval precision** > 0.8 (RAG relevance)
- [ ] **Session synthesis coverage** > 90% (captured activities)

### 6.2 Qualitative Goals

#### Developer Experience
- [ ] Zero-config for common workflows (automatic session tracking)
- [ ] Transparent lazy loading (no user-visible latency spikes)
- [ ] Intuitive registry inspection (`tmws registry list`)

#### Agent Experience
- [ ] Reduced tool selection confusion (focused tool lists)
- [ ] Proactive context delivery (auto-enriched prompts)
- [ ] Trust-aware collaboration (high-trust agents prioritized)

### 6.3 Monitoring Dashboard

```yaml
# Grafana dashboard metrics
panels:
  - title: "Connection Pool Utilization"
    query: "tmws_connection_pool_size{state='active'}"
    threshold: 10 (max)

  - title: "Lazy Connect Latency"
    query: "histogram_quantile(0.95, tmws_lazy_connect_duration_seconds)"
    threshold: 8s (P95)

  - title: "Registry Search Performance"
    query: "histogram_quantile(0.50, tmws_registry_search_duration_ms)"
    threshold: 50ms (P50)

  - title: "Memory Decay Health"
    query: "tmws_memory_importance_distribution"
    alert: "> 50% memories with importance < 0.1"

  - title: "Trust Score Distribution"
    query: "tmws_agent_trust_scores"
    alert: "Any agent < 0.3 for > 24h"
```

---

## 7. Timeline Estimate

### 7.1 Development Schedule

```
Week 1-2: Phase 4.1a - Metadata Registry
├─ Week 1: Core registry implementation
│  ├─ SparseRegistry class
│  ├─ Tool introspection
│  └─ Unit tests
└─ Week 2: CLI tooling & integration
   ├─ build_registry.py
   ├─ Auto-regeneration hooks
   └─ Performance benchmarks

Week 3-4: Phase 4.1b - Connection Pool
├─ Week 3: Pool implementation
│  ├─ ConnectionPool class
│  ├─ LRU eviction
│  └─ TTL management
└─ Week 4: MCPHub integration
   ├─ Refactor mcphub_mcp.py
   ├─ Load testing
   └─ Graceful degradation

Week 5-6: Phase 4.1c - Local-First Memory Repository
├─ Week 5: Local git repository
│  ├─ TMWSMemoryRepository class
│  ├─ Git worktree management
│  └─ Task-based workflow
└─ Week 6: Session synthesis + External bridges
   ├─ SessionSynthesizer class (GitHub-independent)
   ├─ GitHubBridge/GitLabBridge (optional)
   └─ E2E tests

Week 7-8: Phase 4.1d - Memory Decay
├─ Week 7: Decay system
│  ├─ MemoryDecayManager class
│  ├─ Exponential decay formula
│  └─ Batch recomputation
└─ Week 8: Trust-weighted RAG
   ├─ TrustWeightedRAG class
   ├─ Retrieval benchmarks
   └─ Integration tests

Week 9: Integration & Testing
├─ E2E test suite
├─ Performance regression tests
├─ Security audit (Hestia-led)
└─ Documentation

Week 10: Beta Release
├─ Internal dogfooding
├─ Bug fixes
├─ Monitoring setup
└─ Release notes
```

### 7.2 Milestones

| Milestone | Week | Deliverables | Gate Criteria |
|-----------|------|--------------|---------------|
| **M1: Registry Beta** | Week 2 | Sparse registry working | Startup < 2s, 100% coverage |
| **M2: Pool MVP** | Week 4 | Connection pooling live | LRU eviction working, TTL verified |
| **M3: Memory Repo** | Week 6 | Local git repo + session sync | 90% session capture rate (local) |
| **M4: Decay Live** | Week 8 | Memory decay operational | <1s for 10k memories |
| **M5: Beta Release** | Week 10 | Public beta | All KPIs met, security audit passed |

### 7.3 Risk Mitigation

#### High Risk: Connection Pool Deadlocks
- **Likelihood**: Medium
- **Impact**: Critical (system hang)
- **Mitigation**: Extensive concurrency testing, timeout mechanisms
- **Contingency**: Fallback to eager loading mode

#### Medium Risk: GitHub API Rate Limits
- **Likelihood**: High
- **Impact**: Medium (degraded UX)
- **Mitigation**: Aggressive caching, exponential backoff
- **Contingency**: Offline mode with manual metadata

#### Low Risk: Memory Decay Performance
- **Likelihood**: Low
- **Impact**: Low (background job)
- **Mitigation**: Batch processing, indexing
- **Contingency**: Reduce recomputation frequency

---

## 8. Open Questions & Future Work

### 8.1 Deferred to Phase 4.2

#### Distributed Registry (Multi-Machine)
- **Problem**: Current registry is local (~/.tmws/registry/)
- **Solution**: Centralized registry server (Redis/etcd)
- **Benefit**: Shared MCP server catalog across team

#### MCP Server Versioning
- **Problem**: No version tracking in registry
- **Solution**: Semantic versioning + compatibility matrix
- **Benefit**: Prevent breaking changes from silent updates

#### Predictive Prefetching
- **Problem**: Lazy loading has cold-start penalty
- **Solution**: ML-based prediction of likely servers
- **Benefit**: Proactive connection before user request

### 8.2 Research Questions

#### Optimal TTL Values
- **Question**: What is the ideal TTL for different server types?
- **Experiment**: A/B test 5m, 15m, 30m, 60m TTLs
- **Metric**: Balance of eviction rate vs connection overhead

#### Decay Half-Life Tuning
- **Question**: Is 30-day half-life optimal for all memory types?
- **Experiment**: Per-namespace half-life customization
- **Metric**: Retrieval precision vs memory bloat

#### Trust Score Calibration
- **Question**: Are current ±0.05/±0.10 deltas appropriate?
- **Experiment**: Simulate long-term convergence
- **Metric**: Score distribution entropy

---

## 9. Appendix

### 9.1 Glossary

| Term | Definition |
|------|------------|
| **Sparse Registry** | Lightweight metadata catalog without active connections |
| **Lazy Loading** | Deferred resource initialization until first use |
| **Connection Pool** | Fixed-size cache of active MCP server connections |
| **TTL (Time-To-Live)** | Duration before idle connection auto-closes |
| **LRU (Least Recently Used)** | Eviction strategy prioritizing oldest access |
| **Memory Decay** | Time-based importance score reduction |
| **Trust Score** | Agent reliability metric (0.0-1.0) |
| **RAG (Retrieval-Augmented Generation)** | Context retrieval for LLM prompts |
| **Local-First** | Core functionality works offline, external services optional |
| **Git Worktree** | Git feature for multiple working directories from one repo |
| **External Bridge** | Abstract interface for GitHub/GitLab/Gitea integration |
| **Session Synthesis** | Automatic summarization of work sessions in git commits |

### 9.2 References

1. **Cargo Book**: [The Cargo Registry](https://doc.rust-lang.org/cargo/reference/registries.html)
2. **MCP Specification**: [Model Context Protocol](https://spec.modelcontextprotocol.io/)
3. **ChromaDB Docs**: [Vector Database Best Practices](https://docs.trychroma.com/)
4. **APScheduler**: [Advanced Python Scheduler](https://apscheduler.readthedocs.io/)
5. **TMWS v2.4.16**: [Current Architecture](../TMWS_V2.4.11_DEFINITIVE_SPECIFICATION.md)

### 9.3 Related Documents

- `SUBAGENT_EXECUTION_RULES.md` - Trinitas multi-agent protocol
- `AGENTS.md` - Agent coordination patterns
- `SECURITY_AUDIT_PHASE4.5.md` - Security best practices
- `tool-search-mcp-hub/SPECIFICATION.md` - Tool search implementation

---

## Document Control

| Field | Value |
|-------|-------|
| **Version** | 1.1.0 |
| **Status** | DRAFT |
| **Approvers** | Hera (Strategy), Athena (Architecture), Hestia (Security) |
| **Next Review** | 2025-12-15 (Post-Phase 4.1a completion) |
| **Change History** | v1.0.0: Initial specification based on Phase 1 research |
| | v1.1.0: Added Local-First Memory Repository, Git Worktree patterns, External Integration bridges (GitHub/GitLab) |

---

*TMWS Phase 4.1 - True Lazy Loading Specification*
*Trinitas Memory & Workflow System v2.5.0*
*Generated by Muses (Knowledge Architect) - 2025-12-08*
