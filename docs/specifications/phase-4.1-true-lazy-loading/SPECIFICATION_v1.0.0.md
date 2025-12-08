# TMWS Phase 4.1 Specification
## True Lazy Loading with Sparse Registry Pattern

---

**Document Version**: 1.0.0
**TMWS Target Version**: v2.5.0
**Status**: DRAFT - Strategic Planning Complete
**Created**: 2025-12-08
**Authors**: Trinitas Strategic Team (Hera, Athena, Aurora)

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
- **GitHub-Memory Integration**: Automatic issue tracking and work session synthesis
- **Memory Decay System**: Time-based relevance scoring preventing stale context pollution
- **Trust-Weighted RAG**: Code context retrieval with agent trust scoring

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

#### GitHub Issue Tracking Gap
```python
# Current: Manual issue tracking
# User must explicitly document issues/PRs in memory
await tmws.store_memory(
    content="Working on issue #123: Lazy loading implementation",
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
github_refs:
  - issues: ["#456", "#457"]
  - commits: ["3782922", "e2105f7"]
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
# 2. Find relevant commits (git log --grep "ChromaDB")
# 3. Load related issues (GitHub API)
# 4. Surface agent trust scores (who last worked on this?)
# 5. Inject context into prompt

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

#### GitHub-Memory Bridge
```python
# tmws/integrations/github_memory_bridge.py
from typing import List, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class GitHubContext:
    """Enriched GitHub context for memory storage."""
    issue_number: Optional[int]
    issue_title: Optional[str]
    commit_shas: List[str]
    branch_name: str
    files_changed: List[str]
    related_prs: List[int]

class GitHubMemoryBridge:
    """Automatically sync GitHub state with TMWS memory."""

    async def enrich_work_session(self, session_id: str) -> GitHubContext:
        """Enrich work session with GitHub metadata."""

        # Step 1: Detect current work context
        branch = await self._get_current_branch()
        commits = await self._get_recent_commits(limit=10)

        # Step 2: Parse issue numbers from branch/commits
        issue_refs = self._extract_issue_refs(branch, commits)

        # Step 3: Fetch GitHub metadata
        if issue_refs:
            issue_data = await self.github_client.get_issue(issue_refs[0])
            related_prs = await self.github_client.search_prs(
                query=f"is:pr {issue_refs[0]} in:title,body"
            )
        else:
            issue_data = None
            related_prs = []

        # Step 4: Store enriched context in memory
        context = GitHubContext(
            issue_number=issue_refs[0] if issue_refs else None,
            issue_title=issue_data.title if issue_data else None,
            commit_shas=[c.sha[:7] for c in commits],
            branch_name=branch,
            files_changed=self._get_changed_files(commits),
            related_prs=[pr.number for pr in related_prs]
        )

        await self.tmws.store_memory(
            content=self._format_context(context),
            namespace=f"session.{session_id}.github",
            importance=0.8,
            metadata={
                "source": "github_bridge",
                "auto_generated": True,
                "issue": context.issue_number,
                "commits": context.commit_shas
            }
        )

        return context

    def _extract_issue_refs(self, branch: str, commits: List) -> List[int]:
        """Extract GitHub issue numbers from branch name and commits."""
        refs = set()

        # Pattern: feature/123-lazy-loading or fix/456-security
        import re
        branch_match = re.search(r'(\d+)', branch)
        if branch_match:
            refs.add(int(branch_match.group(1)))

        # Pattern: commit messages with "#123" or "Fixes #456"
        for commit in commits:
            for match in re.finditer(r'#(\d+)', commit.message):
                refs.add(int(match.group(1)))

        return sorted(refs)
```

#### Work Session Synthesis
```python
# tmws/core/session_synthesizer.py
from datetime import datetime, timedelta
from typing import Dict, List

class SessionSynthesizer:
    """Automatically summarize work sessions for memory storage."""

    async def synthesize_session(self, start_time: datetime, end_time: datetime) -> dict:
        """Generate comprehensive session summary."""

        # Collect activities during session
        activities = await self._collect_activities(start_time, end_time)

        # Analyze patterns
        summary = {
            "session_id": self._generate_session_id(start_time),
            "duration": (end_time - start_time).total_seconds(),
            "timestamp": end_time.isoformat(),

            # Code changes
            "code_changes": {
                "commits": activities["commits"],
                "files_modified": activities["files"],
                "lines_changed": activities["lines_delta"]
            },

            # Agent involvement
            "agents": {
                agent: {
                    "actions": activities["agent_actions"][agent],
                    "trust_delta": activities["trust_changes"].get(agent, 0.0),
                    "tools_used": activities["tools_by_agent"][agent]
                }
                for agent in activities["active_agents"]
            },

            # GitHub integration
            "github": {
                "issues_referenced": activities["github"]["issues"],
                "prs_created": activities["github"]["prs"],
                "branch": activities["github"]["branch"]
            },

            # Natural language summary
            "summary": self._generate_narrative(activities),

            # Key learnings
            "learnings": activities["learnings"],

            # Problems encountered
            "problems": activities["problems"]
        }

        # Store in memory with high importance
        await self.tmws.store_memory(
            content=json.dumps(summary, indent=2),
            namespace="sessions.history",
            importance=0.85,
            metadata={
                "session_id": summary["session_id"],
                "duration": summary["duration"],
                "agents": list(summary["agents"].keys())
            }
        )

        return summary

    def _generate_narrative(self, activities: Dict) -> str:
        """Generate human-readable session summary."""
        parts = []

        if activities["commits"]:
            parts.append(f"Made {len(activities['commits'])} commits")

        if activities["agent_actions"]:
            agent_list = ", ".join(activities["active_agents"])
            parts.append(f"with collaboration from {agent_list}")

        if activities["github"]["issues"]:
            issue_list = ", ".join(f"#{n}" for n in activities["github"]["issues"])
            parts.append(f"addressing issues {issue_list}")

        if activities["problems"]:
            parts.append(f"resolved {len(activities['problems'])} problems")

        return ". ".join(parts).capitalize() + "."
```

#### Auto-Context Enrichment
```python
# tmws/core/context_enricher.py
from typing import List, Dict, Optional

class ContextEnricher:
    """Automatically enrich agent context with relevant memories."""

    async def enrich_prompt(self, user_query: str, agent_id: Optional[str] = None) -> str:
        """Enrich user query with relevant context from memory."""

        # Step 1: Semantic search in memory
        relevant_memories = await self.tmws.search_memories(
            query=user_query,
            limit=5,
            min_similarity=0.7
        )

        # Step 2: Search git history
        git_context = await self._search_git_history(user_query)

        # Step 3: Check GitHub issues
        github_context = await self._search_github_issues(user_query)

        # Step 4: Agent trust scores
        if agent_id:
            trust_context = await self._get_agent_trust_context(agent_id)
        else:
            trust_context = None

        # Step 5: Build enriched prompt
        enriched = f"""# User Query
{user_query}

# Relevant Context

## Memory System
"""
        if relevant_memories:
            for mem in relevant_memories:
                enriched += f"- [{mem['metadata']['namespace']}] {mem['content'][:200]}...\n"
        else:
            enriched += "(No relevant memories found)\n"

        enriched += "\n## Git History\n"
        if git_context:
            for commit in git_context["commits"]:
                enriched += f"- {commit['sha']}: {commit['message']}\n"
        else:
            enriched += "(No relevant commits found)\n"

        enriched += "\n## GitHub Issues\n"
        if github_context:
            for issue in github_context["issues"]:
                enriched += f"- #{issue['number']}: {issue['title']}\n"
        else:
            enriched += "(No relevant issues found)\n"

        if trust_context:
            enriched += f"\n## Agent Trust Score\n"
            enriched += f"{agent_id}: {trust_context['score']:.2f} "
            enriched += f"(based on {trust_context['verification_count']} verifications)\n"

        return enriched

    async def _search_git_history(self, query: str) -> Optional[Dict]:
        """Search git commits for relevant context."""
        import subprocess
        import json

        # Use git log --grep for semantic search
        cmd = [
            "git", "log",
            "--grep", query,
            "--format=%H|%s|%an|%ad",
            "--max-count=5"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return None

        commits = []
        for line in result.stdout.strip().split("\n"):
            if line:
                sha, message, author, date = line.split("|", 3)
                commits.append({
                    "sha": sha[:7],
                    "message": message,
                    "author": author,
                    "date": date
                })

        return {"commits": commits} if commits else None
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

Week 5-6: Phase 4.1c - GitHub Integration
├─ Week 5: GitHub bridge
│  ├─ GitHubMemoryBridge class
│  ├─ Issue detection
│  └─ API rate limiting
└─ Week 6: Session synthesis
   ├─ SessionSynthesizer class
   ├─ Activity tracking
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
| **M3: GitHub Sync** | Week 6 | Auto-session tracking | 90% session capture rate |
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
| **Version** | 1.0.0 |
| **Status** | DRAFT |
| **Approvers** | Hera (Strategy), Athena (Architecture), Hestia (Security) |
| **Next Review** | 2025-12-15 (Post-Phase 4.1a completion) |
| **Change History** | Initial specification based on Phase 1 research |

---

*TMWS Phase 4.1 - True Lazy Loading Specification*
*Trinitas Memory & Workflow System v2.5.0*
*Generated by Muses (Knowledge Architect) - 2025-12-08*
