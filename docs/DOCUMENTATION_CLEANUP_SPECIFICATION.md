# ドキュメントクリーンアップ仕様書
## TMWS Documentation Cleanup Specification v1.0

**作成日**: 2025年10月27日
**対象バージョン**: TMWS v2.2.6 → v2.2.7
**担当**: Muses - Knowledge Architect
**承認**: Pending

---

## エグゼクティブサマリー

本仕様書は、TMWS プロジェクトのドキュメント体系を、実装の現実（SQLite + ChromaDB アーキテクチャ）に整合させるための包括的なクリーンアップ計画を定義します。

### 目標

1. **整合性の確立**: 実装とドキュメントの100%一致
2. **重複の排除**: 同一内容の重複ドキュメントを統合
3. **欠落の補完**: 必要なドキュメントの作成
4. **保守性の向上**: 将来の変更に強い構造

### Before/After比較

| 指標 | Before | After | 改善 |
|-----|--------|-------|------|
| **ドキュメント総数** | 42ファイル | 35ファイル | -17% |
| **重複箇所** | 6グループ | 0グループ | -100% |
| **リンク切れ** | 4件 | 0件 | -100% |
| **バージョン不整合** | 2件 | 0件 | -100% |
| **アーキテクチャ正確性** | 40% | 95% | +137% |

---

## Phase 1: 緊急修正 (P0 - 即日実施)

### 1.1 バージョン番号の統一

**目的**: プロジェクト全体で一貫したバージョン表記

**変更内容**:

```diff
# README.md (3行目)
- [![Version](https://img.shields.io/badge/version-2.2.5-blue)]
+ [![Version](https://img.shields.io/badge/version-2.2.6-blue)]
```

**検証方法**:
```bash
rg "version.*2\.2\.[0-9]|Version.*2\.2\.[0-9]" README.md CHANGELOG.md pyproject.toml -i
# すべて 2.2.6 であることを確認
```

---

### 1.2 存在しないリンクの削除

**目的**: ユーザーが404エラーに遭遇しないようにする

**削除対象** (README.md 356-359行目):
```markdown
- [docs/PHASE_4_HYBRID_MEMORY.md](docs/PHASE_4_HYBRID_MEMORY.md)
- [docs/PHASE_6_REDIS_AGENTS.md](docs/PHASE_6_REDIS_AGENTS.md)
- [docs/PHASE_7_REDIS_TASKS.md](docs/PHASE_7_REDIS_TASKS.md)
- [docs/PHASE_9_POSTGRESQL_MINIMIZATION.md](docs/PHASE_9_POSTGRESQL_MINIMIZATION.md)
```

**代替リンク** (追加):
```markdown
### Architecture Documentation
- [Architecture Overview](docs/architecture/TMWS_v2.2.6_ARCHITECTURE.md) - Current system design
- [PHASE 1 Benchmark Guide](docs/PHASE1_BENCHMARK_GUIDE.md) - Performance testing
- [PHASE 1 Results](docs/performance/PHASE1_BENCHMARK_REPORT.md) - Benchmark results
- [PHASE 2A Summary](docs/evaluation/PHASE_2A_SUMMARY_2025_10_27.md) - Namespace improvements
```

**検証方法**:
```bash
# README.md内の全リンクをチェック
rg '\[.*\]\((docs/[^)]+\.md)\)' README.md -o | \
  sed 's/.*(\(docs\/[^)]*\)).*/\1/' | \
  while read -r file; do
    [ -f "$file" ] || echo "BROKEN: $file"
  done
```

---

### 1.3 README.md アーキテクチャセクション修正

**目的**: 実装と一致するアーキテクチャ記述

**現在の誤った記述** (README.md 27-52行目):
```markdown
### 🏗️ New 3-Tier Hybrid Architecture

┌─────────────────────────────────────────────────────┐
│ Tier 1: ChromaDB (0.47ms P95)                      │
│ - 10,000 hot memory cache                          │
│ - HNSW vector index (768-dim Multilingual-E5)     │ ← 誤: 1024-dim
│ - Ultra-fast semantic search                       │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│ Tier 2: Redis (< 1ms P95)                          │ ← 誤: 削除済み
│ - Agent registry (HASH + ZADD)                     │
│ - Task queue (Streams + Sorted Sets)               │
│ - Workflow orchestration                           │
│ - Real-time coordination                           │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│ Tier 3: PostgreSQL (Audit-Only)                    │ ← 誤: 削除済み
│ - Source of truth for memories                     │
│ - Audit logs (API, security, workflow)             │
│ - User authentication                              │
│ - 90% cost reduction via minimization              │
└─────────────────────────────────────────────────────┘
```

**修正後** (正確な記述):
```markdown
### 🏗️ Dual Storage Architecture (v2.2.6+)

┌─────────────────────────────────────────────────────┐
│ Tier 1: ChromaDB (DuckDB Backend)                  │
│ - Vector embeddings (1024-dim via Ollama)          │
│ - HNSW index for semantic search                   │
│ - Multilingual-E5-Large model                      │
│ - Sub-millisecond vector search                    │
│ - Persistent storage: ./data/chroma/               │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│ Tier 2: SQLite (WAL Mode)                          │
│ - Metadata storage (Memory, Agent, Task, etc.)     │
│ - Relationship tracking                            │
│ - Access control (namespace + permissions)         │
│ - Audit logs (security, API, workflow)             │
│ - ACID guarantees with single-file simplicity      │
│ - Persistent storage: ./data/tmws.db               │
└─────────────────────────────────────────────────────┘
```

**変更点**:
1. 3-Tier → 2-Tier
2. Redis削除
3. PostgreSQL → SQLite
4. 768-dim → 1024-dim (正確な次元数)
5. ストレージパスの明記

---

### 1.4 CHANGELOG.md v2.2.6エントリー追加

**目的**: バージョン履歴の正確な記録

**追加内容**:
```markdown
## [2.2.6] - 2025-10-25

### Changed
- **BREAKING**: PostgreSQL → SQLite migration (complete removal)
  - All metadata now stored in SQLite with WAL mode
  - pgvector dependency removed
  - Database URL format changed: `sqlite+aiosqlite:///./data/tmws.db`

- **BREAKING**: Redis dependency removed
  - Agent registry moved to SQLite
  - Task queue moved to SQLite
  - No more `TMWS_REDIS_URL` environment variable

### Added
- SQLite WAL mode for concurrent access
- Namespace isolation security fix (P0-1)
- Critical performance indexes (P0-2, P0-3)
- Async/sync pattern fixes (P0-4)

### Removed
- PostgreSQL support (including asyncpg, psycopg2-binary)
- Redis support (including redis-py)
- WebSocket server (stdio MCP only)
- All Phase 4-9 architecture documentation

### Fixed
- Namespace verification now enforced at database level
- Duplicate indexes removed (+18-25% write performance)
- Missing indexes added (-60-85% query latency)
- ChromaDB async integration (VectorSearchService)

### Performance
- Semantic search: 5-20ms P95 (ChromaDB)
- Metadata queries: < 20ms P95 (SQLite)
- Cross-agent sharing: < 15ms P95 (SQLite)

### Migration
See [MIGRATION_v2.2.5_to_v2.2.6.md](docs/guides/MIGRATION_v2.2.5_to_v2.2.6.md) for upgrade instructions.
```

---

## Phase 2: アーカイブと整理 (P1 - 3日以内)

### 2.1 古いアーキテクチャドキュメントのアーカイブ

**目的**: 古い情報を履歴として保存し、混乱を防止

**作成ディレクトリ**:
```bash
mkdir -p docs/archive/2025-10-27-sqlite-migration
```

**アーカイブ対象** (3ファイル):

| ファイル | 理由 | 移動先 |
|---------|------|--------|
| `docs/architecture/TMWS_v2.2.0_ARCHITECTURE.md` | WebSocket/Redis/PostgreSQL記述 | `docs/archive/2025-10-27-sqlite-migration/` |
| `docs/MEM0_MIGRATION_STATUS.md` | PostgreSQL AGE提案が無効 | `docs/archive/2025-10-27-sqlite-migration/` |
| `OLLAMA_ONLY_ARCHITECTURE_ANALYSIS.md` | 移行完了、現在は不要 | `docs/archive/2025-10-27-sqlite-migration/` |

**アーカイブ実行**:
```bash
cd /Users/apto-as/workspace/github.com/apto-as/tmws

# アーカイブディレクトリ作成
mkdir -p docs/archive/2025-10-27-sqlite-migration

# ファイル移動
mv docs/architecture/TMWS_v2.2.0_ARCHITECTURE.md \
   docs/archive/2025-10-27-sqlite-migration/

mv docs/MEM0_MIGRATION_STATUS.md \
   docs/archive/2025-10-27-sqlite-migration/

mv OLLAMA_ONLY_ARCHITECTURE_ANALYSIS.md \
   docs/archive/2025-10-27-sqlite-migration/

# アーカイブREADME作成
cat > docs/archive/2025-10-27-sqlite-migration/README.md <<'EOF'
# SQLite Migration Archive (2025-10-27)

このディレクトリには、TMWS v2.2.5 → v2.2.6 移行時に削除された
PostgreSQL/Redis関連のアーキテクチャドキュメントが保存されています。

## アーカイブ理由

v2.2.6でPostgreSQL/Redisが完全に削除され、SQLite専用アーキテクチャに
移行したため、これらのドキュメントは現行の実装と一致しなくなりました。

## 保存ファイル

- `TMWS_v2.2.0_ARCHITECTURE.md`: WebSocket/Redis/PostgreSQLアーキテクチャ
- `MEM0_MIGRATION_STATUS.md`: PostgreSQL AGE Extension提案
- `OLLAMA_ONLY_ARCHITECTURE_ANALYSIS.md`: Ollama移行時の分析

## 歴史的価値

これらのドキュメントは、プロジェクトの進化を理解するための
重要な歴史的記録として保存されています。
EOF
```

---

### 2.2 新規アーキテクチャドキュメント作成

**目的**: v2.2.6の正確なアーキテクチャ記述

**作成ファイル**: `docs/architecture/TMWS_v2.2.6_ARCHITECTURE.md`

**構成**:
```markdown
# TMWS v2.2.6 Architecture
## SQLite + ChromaDB Dual Storage System

---
**Version**: 2.2.6
**Status**: Production Ready
**Created**: 2025-10-27
**Architecture Type**: Dual Storage (SQLite + ChromaDB)
---

## Overview

TMWS v2.2.6は、シンプルさと性能を両立させたデュアルストレージアーキテクチャです。
PostgreSQL/Redisを完全に削除し、SQLite + ChromaDBのみで構成されています。

## Core Components

### 1. ChromaDB (Vector Storage)
- **Purpose**: Semantic search with vector embeddings
- **Technology**: DuckDB backend + HNSW index
- **Embedding**: Ollama (Multilingual-E5-Large, 1024-dim)
- **Storage**: `./data/chroma/` (persistent)
- **Performance**: 5-20ms P95 vector search

### 2. SQLite (Metadata Storage)
- **Purpose**: Structured data, relationships, audit logs
- **Technology**: SQLite 3.x with WAL mode
- **Storage**: `./data/tmws.db` (single file)
- **Performance**: < 20ms P95 metadata queries

## Data Flow

```
┌─────────────┐
│   MCP Tool  │
└──────┬──────┘
       │
       ▼
┌──────────────────────────┐
│   Memory Service         │
│  (Async Orchestration)   │
└─────┬───────────────┬────┘
      │               │
      ▼               ▼
┌─────────────┐  ┌──────────────┐
│   SQLite    │  │  ChromaDB    │
│  (Metadata) │  │  (Vectors)   │
└─────────────┘  └──────────────┘
```

## Database Schema

### SQLite Tables
- `memories_v2`: Core memory records
- `agents`: Agent registry
- `tasks`: Task management
- `workflows`: Workflow definitions
- `memory_consolidations`: Memory merging
- `audit_log`: Security audit trail
- `api_audit_log`: API access logs

### ChromaDB Collections
- `tmws_memories`: Vector embeddings (1024-dim)

## Security Model

### Namespace Isolation
- Each agent has a verified namespace
- Cross-namespace access requires explicit permissions
- Namespace verified at database level (not JWT claims)

### Access Levels
1. `PRIVATE`: Owner only
2. `TEAM`: Same namespace
3. `SHARED`: Explicit agent list
4. `PUBLIC`: All agents
5. `SYSTEM`: Read-only for all

## Performance Characteristics

| Operation | Target | Achieved | Status |
|-----------|--------|----------|--------|
| Semantic search | < 20ms | 5-20ms | ✅ |
| Metadata query | < 20ms | 2.63ms | ✅ |
| Cross-agent sharing | < 15ms | 9.33ms | ✅ |
| Memory creation | < 50ms | 15-35ms | ✅ |

## Deployment

### Environment Variables
```bash
# Required
TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"
TMWS_SECRET_KEY="<32-char-hex>"
TMWS_OLLAMA_BASE_URL="http://localhost:11434"

# Optional
TMWS_CHROMA_PERSIST_DIRECTORY="./data/chroma"
TMWS_LOG_LEVEL="INFO"
```

### Dependencies
- Python 3.11+
- SQLite 3.x (built-in)
- Ollama server (required for embeddings)
- ChromaDB (installed via pip)

## Migration from v2.2.5

See [MIGRATION_v2.2.5_to_v2.2.6.md](../guides/MIGRATION_v2.2.5_to_v2.2.6.md)

---
```

**作成コマンド**:
```bash
# 上記内容を docs/architecture/TMWS_v2.2.6_ARCHITECTURE.md に保存
```

---

### 2.3 移行ガイド作成

**目的**: v2.2.5ユーザーが安全にv2.2.6へ移行できるようにする

**作成ファイル**: `docs/guides/MIGRATION_v2.2.5_to_v2.2.6.md`

**構成**:
```markdown
# Migration Guide: v2.2.5 → v2.2.6
## PostgreSQL/Redis Removal & SQLite Migration

**Target Users**: TMWS v2.2.5 users
**Migration Time**: 30-60 minutes
**Complexity**: Medium
**Rollback**: Possible with backup

---

## What Changed

### Removed Components
- ❌ PostgreSQL database
- ❌ pgvector extension
- ❌ Redis server
- ❌ WebSocket MCP server

### New Components
- ✅ SQLite (WAL mode)
- ✅ ChromaDB with DuckDB backend
- ✅ Ollama embeddings (required)

### Breaking Changes
1. Database URL format changed
2. Environment variables removed: `TMWS_REDIS_URL`, `TMWS_WS_*`
3. Ollama is now mandatory (no SentenceTransformers fallback)

---

## Pre-Migration Checklist

- [ ] Backup PostgreSQL database: `pg_dump tmws_db > backup.sql`
- [ ] Export existing memories: (script provided below)
- [ ] Install Ollama: `brew install ollama` (macOS)
- [ ] Pull embedding model: `ollama pull zylonai/multilingual-e5-large`
- [ ] Stop TMWS service: `systemctl stop tmws`

---

## Migration Steps

### Step 1: Install Ollama
```bash
# macOS
brew install ollama
ollama serve &
ollama pull zylonai/multilingual-e5-large

# Linux
curl -fsSL https://ollama.com/install.sh | sh
ollama pull zylonai/multilingual-e5-large

# Windows
# Download from https://ollama.com/download
```

### Step 2: Export Existing Data (PostgreSQL)
```bash
python scripts/export_postgres_data.py \
  --database-url "postgresql://user:pass@localhost/tmws_db" \
  --output ./migration/export.json
```

### Step 3: Update Environment Variables
```diff
# .env file changes

- TMWS_DATABASE_URL=postgresql://user:pass@localhost/tmws_db
+ TMWS_DATABASE_URL=sqlite+aiosqlite:///./data/tmws.db

- TMWS_REDIS_URL=redis://localhost:6379/0
  (delete this line)

- TMWS_WS_ENABLED=true
  (delete this line)

+ TMWS_OLLAMA_BASE_URL=http://localhost:11434
+ TMWS_OLLAMA_EMBEDDING_MODEL=zylonai/multilingual-e5-large
```

### Step 4: Initialize SQLite Database
```bash
# Run Alembic migrations
alembic upgrade head

# Import exported data
python scripts/import_to_sqlite.py \
  --input ./migration/export.json \
  --database-url "sqlite+aiosqlite:///./data/tmws.db"
```

### Step 5: Verify Migration
```bash
# Check database
sqlite3 data/tmws.db "SELECT COUNT(*) FROM memories_v2;"
# Should show same count as PostgreSQL

# Check ChromaDB
python scripts/verify_chroma.py
# Should show vectorized memories

# Start TMWS
uvx --from git+https://github.com/apto-as/tmws.git tmws
```

---

## Troubleshooting

### Issue: "Ollama connection failed"
```bash
# Check Ollama service
curl http://localhost:11434/api/tags

# Restart Ollama
pkill ollama
ollama serve &
```

### Issue: "Database locked"
```bash
# Check WAL mode
sqlite3 data/tmws.db "PRAGMA journal_mode;"
# Should return: wal

# Force WAL mode
sqlite3 data/tmws.db "PRAGMA journal_mode=WAL;"
```

---

## Rollback Procedure

If migration fails, rollback to v2.2.5:

```bash
# Stop new version
pkill -f tmws

# Restore PostgreSQL
psql tmws_db < backup.sql

# Revert environment variables
git checkout .env

# Reinstall v2.2.5
pip install tmws==2.2.5
```

---
```

---

## Phase 3: ドキュメント統合 (P2 - 1週間以内)

### 3.1 インストールガイド統合

**目的**: 分散した4つのインストールガイドを1つに統合

**統合元ファイル**:
1. `INSTALL.md` (237行)
2. `QUICKSTART.md` (87行)
3. `docs/installation/INSTALL_UVX.md` (251行)
4. `README.md` (84-114行、30行)

**統合先ファイル**: `docs/guides/INSTALLATION.md`

**構成**:
```markdown
# TMWS Installation Guide

## Quick Start (Recommended)

### Method 1: uvx (Fastest - 1-2 minutes)
...

### Method 2: Manual Installation (5-10 minutes)
...

## Prerequisites
...

## Detailed Setup
...

## Troubleshooting
...
```

**削除ファイル**:
- `INSTALL.md` → `docs/archive/2025-10-27-consolidated/INSTALL.md`
- `QUICKSTART.md` → `docs/archive/2025-10-27-consolidated/QUICKSTART.md`
- `docs/installation/INSTALL_UVX.md` → `docs/archive/2025-10-27-consolidated/INSTALL_UVX.md`

**README.md更新**:
```markdown
## 🚀 Quick Start

```bash
# Install Ollama
ollama pull zylonai/multilingual-e5-large

# Run TMWS
uvx --from git+https://github.com/apto-as/tmws.git tmws
```

See [Installation Guide](docs/guides/INSTALLATION.md) for detailed instructions.
```

---

### 3.2 MCP統合ガイド統合

**目的**: 重複するMCP設定ガイドを統合

**統合元ファイル**:
1. `docs/CLAUDE_DESKTOP_MCP_SETUP.md` (83行)
2. `docs/guides/MCP_SETUP_GUIDE.md` (141行)

**統合先ファイル**: `docs/guides/MCP_SETUP.md`

**保持ファイル** (概要として):
- `docs/MCP_INTEGRATION.md` (150行、高レベル概要)

**構成**:
```markdown
# MCP Setup Guide

## Overview
...

## Claude Desktop Integration
...

## Environment Configuration
...

## Multiple Instances
...

## Troubleshooting
...
```

---

## Phase 4: 新規ドキュメント作成 (P1-P2)

### 4.1 コーディング規約 (P1)

**作成ファイル**: `docs/dev/CODING_STANDARDS.md`

**構成**:
```markdown
# TMWS Coding Standards

## 禁止パターン

### 1. バージョン番号の埋め込み禁止
❌ `memories_v2`, `agent_v3`
✅ `memories`, `agents` (マイグレーションで管理)

### 2. 不要なフォールバック禁止
❌ `try: ollama except: sentence_transformers`
✅ Explicit requirement with clear error

### 3. Exception握りつぶし禁止
❌ `except Exception: pass`
✅ `except SpecificError as e: log_and_raise(...)`

## ベストプラクティス
...
```

---

### 4.2 セキュリティベストプラクティス (P2)

**作成ファイル**: `docs/dev/SECURITY_BEST_PRACTICES.md`

**構成**:
```markdown
# Security Best Practices

## Namespace Isolation

### ✅ Correct Pattern
```python
# ALWAYS verify namespace from database
agent = await get_agent_from_db(agent_id)
verified_namespace = agent.namespace
memory.is_accessible_by(agent_id, verified_namespace)
```

### ❌ Wrong Pattern
```python
# NEVER trust JWT claims directly
namespace = jwt_claims.get("namespace")  # Security risk!
```

## Access Control
...
```

---

### 4.3 トラブルシューティングガイド (P2)

**作成ファイル**: `docs/guides/TROUBLESHOOTING.md`

**構成**:
```markdown
# Troubleshooting Guide

## Common Errors

### "Ollama connection failed"
**Symptoms**: `OllamaConnectionError` on startup

**Solutions**:
1. Check Ollama service: `curl http://localhost:11434/api/tags`
2. Restart: `ollama serve &`
3. Verify model: `ollama list | grep multilingual-e5-large`

### "Database locked"
...
```

---

## Phase 5: README.md全面書き換え (P0-P1)

### 5.1 新規README.md構成

**目的**: 実装と100%一致する正確なREADME

**セクション構成**:

```markdown
# TMWS - Trinitas Memory & Workflow Service

[![Version](https://img.shields.io/badge/version-2.2.6-blue)]
...

## 🎯 What is TMWS?

Multi-agent memory and workflow service with SQLite + ChromaDB architecture.

## ✨ Key Features

- **Semantic Search**: 5-20ms P95 (ChromaDB + Ollama)
- **Dual Storage**: SQLite (metadata) + ChromaDB (vectors)
- **Namespace Isolation**: Secure multi-tenant architecture
- **MCP Compatible**: Model Context Protocol support

## 🏗️ Architecture (v2.2.6)

```
┌─────────────────────────┐
│  ChromaDB (Vectors)     │
│  - 1024-dim embeddings  │
│  - HNSW index           │
└─────────────────────────┘

┌─────────────────────────┐
│  SQLite (Metadata)      │
│  - WAL mode             │
│  - ACID guarantees      │
└─────────────────────────┘
```

## 🚀 Quick Start

```bash
# Install Ollama
ollama pull zylonai/multilingual-e5-large

# Run TMWS
uvx --from git+https://github.com/apto-as/tmws.git tmws
```

See [Installation Guide](docs/guides/INSTALLATION.md) for details.

## 🧠 MCP Tools

- `store_memory`: Create semantic memory
- `search_memories`: Semantic search
- `create_task`: Task management
- `execute_workflow`: Workflow orchestration

See [MCP Tools Reference](docs/MCP_TOOLS_REFERENCE.md).

## 📖 Documentation

### Getting Started
- [Installation Guide](docs/guides/INSTALLATION.md)
- [MCP Setup](docs/guides/MCP_SETUP.md)
- [Migration from v2.2.5](docs/guides/MIGRATION_v2.2.5_to_v2.2.6.md)

### Architecture
- [Architecture Overview](docs/architecture/TMWS_v2.2.6_ARCHITECTURE.md)
- [Database Schema](docs/DATABASE_SCHEMA.md)
- [Security Model](docs/SECURITY_MODEL.md)

### Development
- [Coding Standards](docs/dev/CODING_STANDARDS.md)
- [Exception Handling](docs/dev/EXCEPTION_HANDLING_GUIDELINES.md)
- [Testing Guide](docs/dev/TEST_SUITE_GUIDE.md)

## ⚙️ Configuration

### Required
```bash
TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"
TMWS_SECRET_KEY="<32-char-hex>"
TMWS_OLLAMA_BASE_URL="http://localhost:11434"
```

### Optional
```bash
TMWS_LOG_LEVEL="INFO"
TMWS_CHROMA_PERSIST_DIRECTORY="./data/chroma"
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## 📜 License

MIT License. See [LICENSE](LICENSE).

---

**TMWS v2.2.6** - SQLite + ChromaDB Architecture
```

---

## Phase 6: 検証とテスト

### 6.1 リンク整合性チェック

**検証スクリプト**: `scripts/verify_docs_links.sh`

```bash
#!/bin/bash
# Verify all markdown links are valid

echo "Checking markdown links..."

errors=0

for md_file in $(find . -name "*.md" -not -path "*/archive/*"); do
  echo "Checking: $md_file"

  # Extract all markdown links
  grep -o '\[.*\]([^)]*\.md)' "$md_file" | \
    sed 's/.*(\([^)]*\)).*/\1/' | \
    while read -r link; do
      # Resolve relative path
      dir=$(dirname "$md_file")
      full_path="$dir/$link"

      if [ ! -f "$full_path" ]; then
        echo "  ❌ BROKEN: $link (in $md_file)"
        ((errors++))
      fi
    done
done

if [ $errors -eq 0 ]; then
  echo "✅ All links are valid"
  exit 0
else
  echo "❌ Found $errors broken links"
  exit 1
fi
```

---

### 6.2 バージョン整合性チェック

**検証スクリプト**: `scripts/verify_version_consistency.sh`

```bash
#!/bin/bash
# Verify version consistency across files

PROJECT_VERSION=$(grep '^version = ' pyproject.toml | sed 's/version = "\(.*\)"/\1/')

echo "Project version: $PROJECT_VERSION"

# Check README.md
readme_version=$(grep 'badge/version-' README.md | sed 's/.*version-\([0-9.]*\)-.*/\1/')
if [ "$readme_version" != "$PROJECT_VERSION" ]; then
  echo "❌ README.md version mismatch: $readme_version"
  exit 1
fi

# Check CHANGELOG.md
if ! grep -q "## \[$PROJECT_VERSION\]" CHANGELOG.md; then
  echo "❌ CHANGELOG.md missing entry for $PROJECT_VERSION"
  exit 1
fi

echo "✅ Version consistency verified"
```

---

## Phase 7: 継続的メンテナンス

### 7.1 ドキュメント更新プロトコル

**ルール**:
1. コード変更時は必ず関連ドキュメントを更新
2. アーキテクチャ変更時はREADME.mdを更新
3. APIエンドポイント追加時はMCP_TOOLS_REFERENCE.mdを更新
4. 環境変数追加時はREADME.md + INSTALLATION.mdを更新

**Pre-commit hook** (`scripts/pre-commit-doc-check.sh`):
```bash
#!/bin/bash
# Pre-commit hook to verify documentation updates

# If src/ changed, check if docs/ changed too
if git diff --cached --name-only | grep '^src/'; then
  if ! git diff --cached --name-only | grep '^docs/'; then
    echo "⚠️  Warning: src/ modified but no docs/ update"
    echo "   Did you update documentation?"
    read -p "   Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      exit 1
    fi
  fi
fi
```

---

### 7.2 定期ドキュメント監査

**頻度**: 四半期ごと (3ヶ月)

**チェック項目**:
- [ ] 全リンクが有効
- [ ] バージョン番号が一致
- [ ] アーキテクチャ図が実装と一致
- [ ] 環境変数リストが完全
- [ ] コードサンプルが動作する
- [ ] TODOコメントが整理されている

---

## 実施スケジュール

### Week 1: P0緊急修正
- Day 1: Phase 1完了 (バージョン、リンク、アーキテクチャ)
- Day 2: Phase 2開始 (アーカイブ)
- Day 3: README.md書き換え完了

### Week 2: P1統合作業
- Day 4-5: Phase 3 (ドキュメント統合)
- Day 6-7: Phase 4 (新規ドキュメント作成)

### Week 3: 検証と完了
- Day 8-9: Phase 5 (検証スクリプト実行)
- Day 10: Phase 6 (継続的メンテナンス設定)

---

## 期待される成果

### 定量的改善

| 指標 | Before | After | 改善率 |
|-----|--------|-------|--------|
| ドキュメント総数 | 42ファイル | 35ファイル | -17% |
| 重複箇所 | 6グループ | 0グループ | -100% |
| リンク切れ | 4件 | 0件 | -100% |
| バージョン不整合 | 2件 | 0件 | -100% |
| アーキテクチャ正確性 | 40% | 95% | +137% |

### 定性的改善

- **新規開発者オンボーディング時間**: 3-4時間 → 1-2時間 (-50%)
- **ユーザーサポート問い合わせ**: 予想 -30% (正確なドキュメント)
- **コントリビューター参加障壁**: 大幅低下

---

## 承認とレビュー

### 承認者

- [ ] **Technical Lead**: アーキテクチャ記述の正確性
- [ ] **Project Manager**: スケジュールと優先度
- [ ] **Documentation Lead (Muses)**: 構造と品質

### レビュープロセス

1. Phase 1完了後: 緊急修正の検証
2. Phase 3完了後: 統合ドキュメントのレビュー
3. 全Phase完了後: 最終検証

---

## 付録: 禁止パターンガイドライン

### 1. バージョン番号の埋め込み

**禁止**:
```python
__tablename__ = "memories_v2"
chroma_collection = "tmws_memories_v2"
```

**推奨**:
```python
__tablename__ = "memories"
chroma_collection = "tmws_memories"
# バージョン管理はAlembicマイグレーションで
```

**理由**: v3へのアップグレード時に全コード修正が必要になる

---

### 2. 不要なフォールバック

**禁止**:
```python
try:
    embedding = ollama_service.embed(text)
except Exception:
    embedding = sentence_transformers_service.embed(text)
    # 次元不整合のリスク！
```

**推奨**:
```python
try:
    embedding = ollama_service.embed(text)
except OllamaConnectionError as e:
    log_and_raise(
        EmbeddingServiceError,
        "Ollama is required. Please install: https://ollama.com",
        original_exception=e
    )
```

**理由**: フォールバックはエラーを隠蔽し、デバッグを困難にする

---

### 3. Exception握りつぶし

**禁止**:
```python
try:
    risky_operation()
except Exception:
    pass  # Silent failure
```

**推奨**:
```python
try:
    risky_operation()
except (KeyboardInterrupt, SystemExit):
    raise  # Never suppress
except SpecificError as e:
    log_and_raise(CustomError, "Operation failed", original_exception=e)
```

**理由**: デバッグ不能、本番障害の原因

---

## 結論

本仕様書に基づいてドキュメントクリーンアップを実施することで、TMWS プロジェクトの知識基盤は、実装の現実と100%一致する、保守性の高い状態に生まれ変わります。

今後のメンテナンスプロトコルにより、この整合性を継続的に維持できる体制が確立されます。

---

**仕様書作成者**: Muses (Knowledge Architect)
**作成日**: 2025年10月27日
**バージョン**: 1.0
**ステータス**: Draft - Pending Approval

---

*"Clarity in documentation is the foundation of sustainable development."*

― Muses
