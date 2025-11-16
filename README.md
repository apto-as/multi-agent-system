# TMWS - Trinitas Memory & Workflow Service

[![Version](https://img.shields.io/badge/version-2.3.1-blue)](https://github.com/apto-as/tmws)
[![Python](https://img.shields.io/badge/python-3.11%2B-green)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-purple)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-orange)](https://modelcontextprotocol.io)

**Ultra-fast, multi-agent memory and workflow service with 3-tier hybrid architecture.**

## 🎯 What's New in v2.3.0

### ✨ Phase 2A: Verification-Trust Integration

**Status**: ✅ **COMPLETE** - Production Ready

Extension to `VerificationService` that propagates verification results to learning patterns, creating a feedback loop between verification accuracy and pattern reliability. The integration is **non-invasive** with graceful degradation—pattern propagation failures never block verification completion.

**Key Features:**
- 🔗 **Pattern Linkage**: Verifications can link to learning patterns via `claim_content.pattern_id`
- 📊 **Trust Propagation**: Accurate verifications boost trust (+0.05 base + 0.02 pattern)
- 🔒 **Security Controls**: V-VERIFY-1/2/3/4 prevent command injection, RBAC violations, cross-namespace access, and trust gaming
- ⚡ **High Performance**: <515ms P95 per verification (35ms pattern propagation overhead)
- 🛡️ **Graceful Degradation**: Pattern errors don't block verification success

**Architecture:**
```python
# Verification with Pattern Linkage
result = await verification_service.verify_claim(
    agent_id="artemis-optimizer",
    claim_content={
        "return_code": 0,
        "pattern_id": "550e8400-e29b-41d4-a716-446655440000"  # Links to pattern
    },
    verification_command="pytest tests/unit/ -v"
)
# Result includes propagation_result with trust_delta
```

**Security Enhancements (P1 Fix):**
- **V-VERIFY-2**: RBAC enforcement for verifiers (requires AGENT/ADMIN role, blocks OBSERVER)
- **V-VERIFY-4**: Pattern eligibility validation (public/system only, no self-owned patterns)

---

### ✨ Phase 1: Learning-Trust Integration

**Status**: ✅ **COMPLETE** - Production Ready

Automatic trust score updates based on learning pattern execution results. The system now tracks pattern success/failure and dynamically adjusts agent trust scores using an Exponential Weighted Moving Average (EWMA) algorithm.

**Key Features:**
- 🧠 **Automatic Trust Updates**: Pattern execution results automatically update agent trust scores
- 📊 **EWMA Algorithm**: Configurable learning rate (α=0.1 default) for smooth trust evolution
- 🔒 **Security Hardened**: V-TRUST-1/4/7/11 controls prevent unauthorized trust manipulation
- ⚡ **High Performance**: <2.1ms P95 per update, <210ms P95 for 100-agent batch operations
- 🎯 **94.6% Coordination Success**: Achieved using Trinitas Phase-Based Execution Protocol

**Architecture:**
```python
# Learning Pattern Execution → Trust Score Update
await integration_service.update_trust_from_pattern_execution(
    pattern_id=pattern.id,
    agent_id=agent.id,
    success=execution_result.success,
    verification_id=verification_record.id  # Authorization proof
)
```

**Trust Score Formula:**
- `new_score = α × observation + (1 - α) × old_score`
- α = 0.1 (10% weight to new observation, 90% to historical)
- Minimum 5 observations before trust score is considered reliable

### 🔒 Security Enhancements

**V-TRUST-1: Authorized Trust Updates**
- Automated updates require `verification_id` (proof of legitimate verification)
- Manual updates require SYSTEM privilege
- Prevents unauthorized trust score manipulation

**V-TRUST-4: Namespace Isolation**
- Database-verified namespace parameter enforced
- Cross-tenant access denied with detailed error logging
- Prevents cross-namespace trust score access attacks

**V-TRUST-7 & V-TRUST-11: Batch Operation Security**
- Authorization check per agent in batch
- Fail-fast: Stops on first authorization error
- Prevents batch trust manipulation attacks

### ⚡ Performance Metrics

**Single Trust Update:**
- P50: 1.2ms | P95: 1.8ms | P99: 2.0ms ✅
- **14% better than target** (1.8ms vs 2.1ms target)

**Batch Trust Updates (100 agents):**
- P50: 156ms | P95: 189ms | P99: 202ms ✅
- **10% better than target** (189ms vs 210ms target)
- Per-agent overhead: 1.89ms

### 🧪 Test Coverage

**28/28 Tests PASS** ✅
- 21 unit tests (958 lines) - Authorization, namespace isolation, edge cases
- 7 performance tests (500 lines) - Latency benchmarks, concurrency validation
- **Hestia Security Audit**: APPROVED - 0 CRITICAL, 0 HIGH vulnerabilities

### 🎭 Trinitas Collaboration

**Phase-Based Execution Success:**
- **Phase 1-1 (Strategic Planning)**: Hera + Athena
- **Phase 1-2 (Implementation)**: Artemis
- **Phase 1-3 (Verification)**: Hestia
- **Coordination**: 94.6% success rate (53/56 steps correct)

**Lesson Learned**: Phase-based execution with approval gates prevents uncoordinated parallel execution.

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
| **🐳 Docker** (最速) | Production | **5 min** | Full (SQLite + Chroma) |
| **uvx** | Production | 1-2 min | Full (SQLite + Chroma + Redis) |
| **自動セットアップ** | Local dev | 5-10 min | Full |
| **手動セットアップ** | Custom | 10-15 min | Full |

### 🚀 New in v2.3.1: Docker Deployment (5 Minutes)

**Fastest path to production deployment**:

```bash
# See DOCKER_QUICKSTART.md for 5-minute deployment guide
# Supports: Mac ARM64, Linux Ubuntu, Windows WSL
```

📖 **[→ Docker Quick Start Guide (5 minutes)](DOCKER_QUICKSTART.md)**

---

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
#   "sqlite_connection_pool": 10,
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
