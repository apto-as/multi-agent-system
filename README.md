# TMWS - Trinitas Memory & Workflow Service

[![Version](https://img.shields.io/badge/version-2.2.7-blue)](https://github.com/apto-as/tmws)
[![Python](https://img.shields.io/badge/python-3.11%2B-green)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-purple)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-orange)](https://modelcontextprotocol.io)

**Ultra-fast, multi-agent memory and workflow service with 3-tier hybrid architecture.**

## 🎯 What's New in v2.2.7

### 🔒 Security: V-1 Path Traversal Fix (CVSS 7.5 HIGH)

- **Vulnerability Closed**: 完全に`.`と`/`をブロックしてパス・トラバーサル攻撃を防止
- **Namespace Sanitization**: `github.com/user/repo` → `github-com-user-repo`
- **Validation Enhanced**: `..`と絶対パス`/`の明示的な検証を追加
- **Zero Regression**: 24/24 namespace tests PASSED, unit test ratio 維持

### ⚡ Performance: 12,600x Faster Namespace Detection

- **Caching Implementation**: MCP server起動時に1回検出 → 以降はキャッシュ値を使用
- **Environment Variable (P1)**: 0.00087 ms (目標 <1ms) → **125倍高速** ✅
- **Git Detection (P2)**: 0.00090 ms (目標 <10ms) → **12,600倍高速** ✅
- **CWD Hash Fallback (P4)**: 正常動作確認、`project_<16-char-hash>` フォーマット

### 🧹 Code Quality: 1,081 Violations Fixed

- **Ruff Compliance**: 100% → Implicit Optional (166件) + 未使用import (198件) + その他 (717件)
- **Code Duplication**: RateLimiter重複削除 (-49行)、単一実装に統一
- **Import Validation**: 全Pythonファイルのコンパイル成功確認

### 🔍 Systematic Verification (Phase 5)

**Phase 5A - Code Quality:**
- ✅ Ruff: 100% compliance
- ✅ Imports: All valid
- ✅ Caching: 5 correct occurrences verified

**Phase 5B - Functional:**
- ✅ 24/24 namespace integration tests PASSED
- ✅ 6 MCP tools registered correctly
- ✅ Performance benchmarks exceeded targets

### 🚀 Performance Excellence (継承)

- **Vector Search**: 0.47ms P95 (ChromaDB) vs 200ms (PostgreSQL) = **425x faster**
- **Namespace Detection**: 0.0009 ms P95 = **12,600x faster** (NEW!)
- **Agent Operations**: < 1ms P95 (Redis-based)
- **Task Management**: < 3ms P95 (Redis Streams)

---

## 🚀 Quick Start

### Prerequisites

```bash
# Required dependencies
- Python 3.11+
- Ollama (for embeddings - REQUIRED)
- ChromaDB (installed automatically via pip)
- Redis 7.0+ (optional - for enhanced performance)
```

### Installation Methods

| Method | Use Case | Time | Performance |
|--------|----------|------|-------------|
| **uvx** (推奨) | Production | 1-2 min | Full (SQLite + Chroma + Redis) |
| **自動セットアップ** | Local dev | 5-10 min | Full |
| **手動セットアップ** | Custom | 10-15 min | Full |

### Method 1: uvx（最速・推奨）

```bash
# 1. Ollama準備（REQUIRED for embeddings）
brew install ollama
brew services start ollama
ollama pull zylonai/multilingual-e5-large

# 2. Redis準備（オプションだが推奨）
brew install redis
brew services start redis

# 3. 環境変数設定
export TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"
export TMWS_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
export TMWS_REDIS_URL="redis://localhost:6379/0"  # オプション

# 4. uvxで起動（インストール不要）
uvx --from git+https://github.com/apto-as/tmws.git tmws
```

### Method 2: 自動セットアップ

```bash
git clone https://github.com/apto-as/tmws.git
cd tmws
./install.sh  # 自動セットアップスクリプト
```

詳細は [QUICKSTART.md](QUICKSTART.md) を参照。

---

## 🧠 Architecture Overview

### Hybrid Memory System

TMWS v2.3.0は2つのデータストアを統合した高性能アーキテクチャです：

#### 1. ChromaDB (Primary for Vector Search)

- **Purpose**: Ultra-fast semantic search (0.47ms P95)
- **Technology**: HNSW index (M=16, ef_construction=200) with DuckDB backend
- **Capacity**: 10,000 hot memories in-memory
- **Embedding**: Multilingual-E5-Large (1024-dimensional via Ollama)

```python
# Semantic search with ChromaDB + Ollama embeddings
results = await memory_service.search_memories(
    query="機械学習の最適化",
    min_similarity=0.7,
    limit=10
)
# → ChromaDB vector search with Ollama-generated embeddings
```

#### 2. Redis (Primary for Agent/Task Management)

- **Purpose**: Sub-millisecond agent and task operations
- **Technology**: HASH, ZADD (sorted sets), XADD (streams)
- **Performance**: < 1ms P95 (agents), < 3ms P95 (tasks)

```python
# Agent registration (< 1ms)
await redis_agent_service.register_agent(
    agent_id="athena-conductor",
    capabilities=["orchestration", "strategy"]
)

# Task creation (< 2ms)
await redis_task_service.create_task(
    title="Implement feature X",
    priority="HIGH"
)
```

#### 3. SQLite (Metadata + Authentication)

- **Purpose**: ACID guarantees, metadata storage, authentication
- **Technology**: SQLite with WAL mode for concurrent access
- **Usage**: Metadata, relationships, access control, audit logs
- **Performance**: < 20ms P95 for metadata queries

```python
# Dual Storage Pattern: SQLite (metadata) + Chroma (vectors)
memory = await memory_service.create_memory(
    content="重要な設計決定",
    importance_score=0.9
)
# → SQLite (metadata + relationships), Chroma (embedding vector)
```

### Performance Metrics (Benchmark Results)

| Operation | Target | Achieved | Technology |
|-----------|--------|----------|------------|
| Vector Search | < 20ms | 0.47ms P95 | ChromaDB + HNSW |
| Memory Store | < 5ms | 2ms P95 | SQLite WAL mode |
| Agent Register | < 1ms | 0.8ms P95 | Redis HASH |
| Task Create | < 3ms | 1.5ms P95 | Redis Streams |
| Agent Heartbeat | < 1ms | 0.3ms P95 | Redis TTL |

---

## 🔌 Claude Desktop Integration

### MCP Server Configuration

`.claude/mcp_config.json`:

```json
{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/apto-as/tmws.git", "tmws"],
      "env": {
        "TMWS_DATABASE_URL": "sqlite+aiosqlite:///./data/tmws.db",
        "TMWS_REDIS_URL": "redis://localhost:6379/0",
        "TMWS_AGENT_ID": "athena-conductor",
        "TMWS_SECRET_KEY": "your-secret-key-here",
        "TMWS_OLLAMA_BASE_URL": "http://localhost:11434"
      }
    }
  }
}
```

### Multiple Claude Code Instances

各Claude Codeターミナルは独立したMCPサーバープロセスを起動しますが、SQLiteデータベースとChromaDBを通じて状態を共有します：

1. **Instance 1**: `TMWS_AGENT_ID=athena-conductor`
2. **Instance 2**: `TMWS_AGENT_ID=artemis-optimizer`
3. **Instance 3**: `TMWS_AGENT_ID=hestia-auditor`

すべてのインスタンスが同じメモリ、タスク、ワークフローにアクセス可能です（SQLite WALモードで同時読み取りをサポート）。

---

## 🧠 Available MCP Tools

### Memory Management (HybridMemoryService)

```python
# Store memory (Write-through: PostgreSQL + Chroma)
store_memory(
    content="機械学習モデルの最適化に成功",
    importance=0.9,
    tags=["ml", "optimization", "success"]
)

# Semantic search (Chroma-first: 0.47ms P95)
search_memories(
    query="最適化の成功事例",
    limit=10,
    min_similarity=0.7
)

# Update memory
update_memory(
    memory_id="uuid-here",
    content="更新された内容",
    importance=0.95
)

# Delete memory
delete_memory(memory_id="uuid-here")
```

### Agent Management (RedisAgentService)

```python
# Register agent (< 1ms P95)
register_agent(
    agent_id="custom-analyst",
    namespace="analytics",
    capabilities=["data_analysis", "reporting"]
)

# Get agent status
get_agent(agent_id="athena-conductor")

# List agents by namespace
list_agents(namespace="trinitas", limit=10)

# Heartbeat (< 0.5ms P95)
heartbeat(agent_id="athena-conductor")

# Deregister agent
deregister_agent(agent_id="custom-analyst")
```

### Task Management (RedisTaskService)

```python
# Create task (< 2ms P95)
create_task(
    title="Implement feature X",
    description="Detailed description",
    priority="HIGH",
    assigned_persona="artemis-optimizer"
)

# Update task status
update_task_status(
    task_id="task-uuid",
    status="in_progress",
    progress=50
)

# List tasks
list_tasks(
    status="pending",
    priority="HIGH",
    limit=20
)

# Complete task
complete_task(
    task_id="task-uuid",
    result={"success": true, "metrics": {...}}
)
```

### Workflow Management

```python
# Create workflow
create_workflow(
    name="deployment_pipeline",
    steps=[
        {"persona": "hestia-auditor", "action": "security_check"},
        {"persona": "artemis-optimizer", "action": "performance_test"},
        {"persona": "athena-conductor", "action": "deploy"}
    ]
)

# Execute workflow
execute_workflow(
    workflow_id="workflow-uuid",
    parameters={"environment": "production"}
)

# Get workflow status
get_workflow_status(workflow_id="workflow-uuid")
```

### System Tools

```python
# Health check
health_check()

# System statistics
get_system_stats()

# Switch agent context
switch_agent(agent_id="artemis-optimizer")
```

詳細は [docs/MCP_TOOLS_REFERENCE.md](docs/MCP_TOOLS_REFERENCE.md) を参照。

---

## 📖 Documentation

### Installation & Setup
- [INSTALL_UVX.md](INSTALL_UVX.md) - **推奨：uvx インストール**（最速）
- [QUICKSTART.md](QUICKSTART.md) - 5分クイックスタート
- [INSTALL.md](INSTALL.md) - 詳細な手動インストール

### v2.3.0 Architecture
- [docs/PHASE_4_HYBRID_MEMORY.md](docs/PHASE_4_HYBRID_MEMORY.md) - HybridMemoryService詳細
- [docs/PHASE_6_REDIS_AGENTS.md](docs/PHASE_6_REDIS_AGENTS.md) - RedisAgentService設計
- [docs/PHASE_7_REDIS_TASKS.md](docs/PHASE_7_REDIS_TASKS.md) - RedisTaskService設計
- [docs/PHASE_9_POSTGRESQL_MINIMIZATION.md](docs/PHASE_9_POSTGRESQL_MINIMIZATION.md) - PostgreSQL最小化戦略

### MCP Integration
- [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) - **Claude Desktop統合ガイド**
- [docs/MCP_TOOLS_REFERENCE.md](docs/MCP_TOOLS_REFERENCE.md) - MCPツール完全リファレンス

### Other
- [docs/API_AUTHENTICATION.md](docs/API_AUTHENTICATION.md) - API認証設定
- [docs/TRINITAS_INTEGRATION.md](docs/TRINITAS_INTEGRATION.md) - Trinitas統合
- [CUSTOM_AGENTS_GUIDE.md](CUSTOM_AGENTS_GUIDE.md) - カスタムエージェント登録

---

## 🤖 Default Trinitas Agents

TMWS includes 6 pre-configured agents:

| Agent | ID | Specialty | Performance Target |
|-------|-----|-----------|-------------------|
| **Athena** | athena-conductor | System orchestration | < 1ms (Redis) |
| **Artemis** | artemis-optimizer | Performance optimization | < 1ms (Redis) |
| **Hestia** | hestia-auditor | Security analysis | < 1ms (Redis) |
| **Eris** | eris-coordinator | Tactical planning | < 1ms (Redis) |
| **Hera** | hera-strategist | Strategic planning | < 1ms (Redis) |
| **Muses** | muses-documenter | Documentation | < 1ms (Redis) |

All agents share a unified memory pool via HybridMemoryService (Chroma + PostgreSQL).

---

## ⚙️ Environment Variables

### Required

```bash
# SQLite Database (Metadata + Authentication)
TMWS_DATABASE_URL=sqlite+aiosqlite:///./data/tmws.db

# Security key (32+ characters)
TMWS_SECRET_KEY=your-secret-key-minimum-32-characters-long

# Environment
TMWS_ENVIRONMENT=development  # or production
```

### Optional (for full performance)

```bash
# Redis (for < 1ms agent/task operations)
TMWS_REDIS_URL=redis://localhost:6379/0

# Agent configuration
TMWS_AGENT_ID=athena-conductor
TMWS_AGENT_NAMESPACE=trinitas

# ChromaDB (auto-configured, but customizable)
TMWS_CHROMA_PERSIST_DIRECTORY=./data/chroma
TMWS_CHROMA_COLLECTION=tmws_memories

# Logging
TMWS_LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR
```

### Ollama Embedding Configuration (v2.3.0 - Required)

⚠️ **CRITICAL**: Ollama is now REQUIRED for TMWS v2.3.0+

```bash
# Ollama server configuration (REQUIRED)
TMWS_OLLAMA_BASE_URL=http://localhost:11434
TMWS_OLLAMA_EMBEDDING_MODEL=zylonai/multilingual-e5-large
TMWS_OLLAMA_TIMEOUT=30.0
```

**インストール手順**:
1. Ollamaをインストール: https://ollama.ai/download
2. モデルをダウンロード: `ollama pull zylonai/multilingual-e5-large`
3. サーバーを起動: `ollama serve`

**重要**: フォールバック機構は削除されました。Ollamaが利用できない場合は明確なエラーメッセージが表示されます。

### Performance Tuning

```bash
# Chroma cache size (default: 10000)
TMWS_CHROMA_CACHE_SIZE=10000

# Redis connection pool (default: 10)
TMWS_REDIS_POOL_SIZE=10

# SQLite connection pool (default: 10)
TMWS_DB_POOL_SIZE=10
TMWS_DB_MAX_OVERFLOW=20
```

---

## 🚀 Migration from v2.2.0 → v2.3.0

### What Changed

1. **New**: `HybridMemoryService` replaces `MemoryService`
2. **New**: `RedisAgentService` for sub-millisecond agent operations
3. **New**: `RedisTaskService` for sub-millisecond task operations
4. **New**: ChromaDB integration for 425x faster vector search
5. **Changed**: PostgreSQL minimized to audit-only usage

### Migration Steps

```bash
# 1. Install Redis (optional but recommended)
brew install redis
brew services start redis

# 2. Update environment variables
export TMWS_REDIS_URL="redis://localhost:6379/0"

# 3. Run database migrations
python -m alembic upgrade head

# 4. Initialize Chroma hot cache
python scripts/initialize_chroma.py

# 5. (Optional) Archive old PostgreSQL data
python scripts/phase9_archive.py

# 6. Restart TMWS
uvx --from git+https://github.com/apto-as/tmws.git tmws
```

### Backward Compatibility

- **MCP Tools**: 100% backward compatible (same tool names)
- **API Endpoints**: 100% compatible (same routes)
- **Database Schema**: Migrations handled automatically
- **Legacy Support**: `MemoryService` available as `LegacyMemoryService`

---

## 📊 Benchmarking

Run Phase 8 benchmarks to verify performance:

```bash
# Requires: Redis, ChromaDB dependencies
python scripts/benchmark_phase8.py
```

Expected results:
- **Vector Search P95**: < 1ms (target: 0.47ms achieved)
- **Memory Store P95**: < 5ms (target: 2ms)
- **Agent Register P95**: < 1ms (target: 0.8ms)
- **Task Create P95**: < 2ms (target: 1.5ms)

---

## 🔐 Security

### Production Checklist

- [ ] Set `TMWS_ENVIRONMENT=production`
- [ ] Generate secure `TMWS_SECRET_KEY` (32+ characters)
- [ ] Enable PostgreSQL SSL: `sslmode=require` in `DATABASE_URL`
- [ ] Enable Redis TLS if using remote Redis
- [ ] Configure firewall rules for PostgreSQL/Redis
- [ ] Review audit logs regularly: `SELECT * FROM api_audit_log;`
- [ ] Set up automated backups (PostgreSQL daily, Chroma weekly)

### Audit Logging

All operations are logged to PostgreSQL:

```sql
-- API audit logs
SELECT * FROM api_audit_log
WHERE created_at > NOW() - INTERVAL '24 hours'
ORDER BY created_at DESC;

-- Security audit logs
SELECT * FROM audit_log
WHERE event_type = 'security_event'
ORDER BY created_at DESC;
```

---

## 📈 Performance Monitoring

### Key Metrics

```python
# System statistics
stats = await get_system_stats()
# {
#   "chroma_cache_size": 10000,
#   "redis_active_agents": 6,
#   "redis_pending_tasks": 23,
#   "postgresql_connection_pool": 10,
#   "memory_search_latency_p95_ms": 0.47,
#   "agent_operation_latency_p95_ms": 0.8
# }
```

### Monitoring Tools

- **ChromaDB**: Built-in collection stats
- **Redis**: `redis-cli INFO` for metrics
- **PostgreSQL**: `pg_stat_statements` extension
- **Application**: Structured logging to stdout

---

## 🔒 Security

### Agent Trust & Verification System (v2.3.0)

TMWS includes a **cryptographically-backed trust scoring system** for multi-agent environments with comprehensive security hardening.

#### Phase 0 Security Hardening ✅ (Partial)

**Status**: 🟡 **3/8 vulnerabilities fixed** (production deployment blocked until completion)

**Completed Fixes**:

1. **V-TRUST-1: Metadata Injection (CVSS 8.1 HIGH)** ✅
   - **Impact**: Prevented any user from self-promoting trust score to 1.0
   - **Fix**: SYSTEM privilege enforcement via `update_agent_trust_score()`
   - **Performance**: <5ms P95

2. **V-ACCESS-1: Authorization Bypass (CVSS 8.5 HIGH)** ✅
   - **Impact**: Prevented unauthorized data exposure
   - **Fix**: Authorization check BEFORE access tracking
   - **Performance**: <10ms P95

3. **P0-2: Namespace Isolation (CVSS 9.1 CRITICAL)** ✅
   - **Impact**: Prevented cross-tenant access via JWT forgery
   - **Fix**: Database-verified namespace enforcement
   - **Performance**: <15ms P95

**In Progress** (5 remaining):
- V-TRUST-2: Race Condition (CVSS 7.4 HIGH) - Row-level locking
- V-TRUST-3: Evidence Deletion (CVSS 7.4 HIGH) - Immutable records
- V-TRUST-4: Namespace Bypass (CVSS 7.1 HIGH) - SQL-level filtering
- V-TRUST-5: Sybil Attack (CVSS 6.8 MEDIUM) - Verifier trust weighting
- V-TRUST-6: Audit Tampering (CVSS 7.8 HIGH) - Hash chain integrity

**Risk Reduction**: 75.5% → 48.2% (interim) → Target: 18.3%

#### Security Features

**Three-Layer Security Model**:
```
Layer 1: Request Authentication (JWT validation)
         ↓
Layer 2: Authorization Checks (verify_system_privilege, check_memory_access)
         ↓
Layer 3: Data Access (database queries with verified namespace)
```

**Trust-Based Authorization**:
- **SYSTEM (0.9-1.0)**: Admin operations, trust modification
- **HIGH (0.7-0.89)**: Cross-namespace access, delegation
- **STANDARD (0.5-0.69)**: Namespace-local operations
- **LOW (0.3-0.49)**: Read-only access
- **UNTRUSTED (0.0-0.29)**: No access

**Namespace Isolation**:
- Database-verified namespace (NEVER trust JWT claims)
- Multi-tenant security with strict separation
- Cross-namespace access requires SYSTEM privilege

**Immutability & Audit**:
- Verification records protected from deletion
- Cryptographic hash chain for audit logs (in progress)
- Comprehensive audit logging for all security events

#### Security Documentation

- **Phase 0 Implementation**: `docs/security/PHASE_0_SECURITY_INTEGRATION.md`
- **Security Architecture**: `docs/architecture/AGENT_TRUST_SECURITY.md`
- **Developer Guidelines**: `docs/dev/SECURITY_GUIDELINES.md`
- **Penetration Test Report**: `docs/security/PENETRATION_TEST_REPORT_TRUST_VULNERABILITIES.md`

#### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead, email: security@apto.as with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We aim to respond within 24 hours and provide a fix within 72 hours for critical issues.

---

## 🤝 Contributing

We welcome contributions! Areas of interest:

- Performance optimizations
- Additional MCP tools
- Custom agent implementations
- Documentation improvements
- Bug fixes
- **Security improvements** (please coordinate via security@apto.as for sensitive issues)

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📜 License

Copyright (c) 2025 Apto AS

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- **ChromaDB**: Ultra-fast vector database
- **Ollama**: Local embedding generation (Multilingual-E5-Large 1024-dim)
- **SQLite**: Lightweight metadata storage
- **Redis**: In-memory data structure store
- **FastMCP**: Model Context Protocol framework
- **Trinitas**: Multi-agent AI system
- **Claude Code**: Claude Desktop integration

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/apto-as/tmws/issues)
- **Discussions**: [GitHub Discussions](https://github.com/apto-as/tmws/discussions)
- **Documentation**: [docs/](docs/)

---

**TMWS v2.3.0** - Ultra-fast memory and workflow service for AI agents 🚀
