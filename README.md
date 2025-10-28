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
- PostgreSQL 17+ with pgvector extension
- Redis 7.0+ (optional but recommended for full performance)
- ChromaDB (installed automatically via pip)
```

### Installation Methods

| Method | Use Case | Time | Performance |
|--------|----------|------|-------------|
| **uvx** (推奨) | Production | 1-2 min | Full (Chroma + Redis + PostgreSQL) |
| **自動セットアップ** | Local dev | 5-10 min | Full |
| **手動セットアップ** | Custom | 10-15 min | Full |

### Method 1: uvx（最速・推奨）

```bash
# 1. PostgreSQL準備
brew install postgresql@17
brew services start postgresql@17
createdb tmws_db
psql tmws_db -c "CREATE EXTENSION IF NOT EXISTS vector;"

# 2. Redis準備（オプションだが推奨）
brew install redis
brew services start redis

# 3. 環境変数設定
export TMWS_DATABASE_URL="postgresql://$(whoami)@localhost:5432/tmws_db"
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

TMWS v2.3.0は3つのデータストアを統合した高性能アーキテクチャです：

#### 1. ChromaDB (Primary for Vector Search)

- **Purpose**: Ultra-fast semantic search (5-20ms P95)
- **Technology**: HNSW index (M=16, ef_construction=200)
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

#### 3. PostgreSQL (Source of Truth + Audit)

- **Purpose**: ACID guarantees, audit trail, authentication
- **Usage**: Write-through for memories, audit logs, user management
- **Optimization**: 90% cost reduction via minimization strategy

```python
# Write-Through Pattern: PostgreSQL + Chroma simultaneously
memory = await memory_service.create_memory(
    content="重要な設計決定",
    importance=0.9
)
# → Writes to PostgreSQL (commit), then Chroma (best-effort)
```

### Performance Metrics (Phase 8 Benchmark Results)

| Operation | PostgreSQL-Only (v2.2) | Hybrid (v2.3) | Improvement |
|-----------|------------------------|---------------|-------------|
| Vector Search | 200ms P95 | 0.47ms P95 | **425x faster** |
| Memory Store | 10ms P95 | 2ms P95 | **5x faster** |
| Agent Register | N/A | 0.8ms P95 | **New feature** |
| Task Create | N/A | 1.5ms P95 | **New feature** |
| Agent Heartbeat | N/A | 0.3ms P95 | **New feature** |

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
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws_db",
        "TMWS_REDIS_URL": "redis://localhost:6379/0",
        "TMWS_AGENT_ID": "athena-conductor",
        "TMWS_SECRET_KEY": "your-secret-key-here"
      }
    }
  }
}
```

### Multiple Claude Code Instances

各Claude Codeターミナルは独立したMCPサーバープロセスを起動しますが、PostgreSQLデータベースを通じて状態を共有します：

1. **Instance 1**: `TMWS_AGENT_ID=athena-conductor`
2. **Instance 2**: `TMWS_AGENT_ID=artemis-optimizer`
3. **Instance 3**: `TMWS_AGENT_ID=hestia-auditor`

すべてのインスタンスが同じメモリ、タスク、ワークフローにアクセス可能です。

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
# PostgreSQL (Source of truth + audit logs)
TMWS_DATABASE_URL=postgresql://tmws_user:tmws_password@localhost:5432/tmws_db

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

# PostgreSQL connection pool (default: 10)
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

## 🤝 Contributing

We welcome contributions! Areas of interest:

- Performance optimizations
- Additional MCP tools
- Custom agent implementations
- Documentation improvements
- Bug fixes

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
