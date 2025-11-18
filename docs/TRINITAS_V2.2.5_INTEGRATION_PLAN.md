# Trinitas v2.2.5 統合計画書
## Mem0完全削除 + TMWS統合

**作成日**: 2025-10-29
**バージョン**: v2.2.5
**ステータス**: 計画立案完了（実装待ち）
**担当エージェント**: Athena (調整), Artemis (技術), Hestia (セキュリティ), Muses (文書化), Hera (戦略)

---

## 📋 Executive Summary

本計画書は、Trinitas-agents v2.2.5へのアップグレードにおける以下2つの主要作業を定義します：

1. **Mem0の完全削除**: ドキュメントから300+件のMem0参照を削除
2. **TMWS統合**: 完成したTMWS MCP Serverをtrinitasに統合

**重要な前提**:
- ✅ Mem0はコード実装から既に削除済み（v2.2.4で完了）
- ✅ TMWSは外部プロジェクト `../tmws/` で完成済み
- ✅ file-based memory systemが実装済み（確認必要）
- ⚠️ TMWS MCPツールは計画のみ（実装はユーザー実施）

---

## 🎯 目標

### 1. Mem0完全削除
- ドキュメントから全Mem0参照を削除
- 誤解を招く記述の排除
- file-based memoryへの明確な移行

### 2. TMWS統合
- TMWS MCP Server設定ガイドの作成
- ペルソナ別ツール使用ガイドの作成
- `./.claude/CLAUDE.md` の永続化記憶更新

### 3. ドキュメント整合性
- 実装済み機能のみを記載
- 未実装機能は「将来実装予定」として明記
- 公開ドキュメント戦略への準拠

---

## 📊 現状分析（4エージェント統合レポート）

### Hera (戦略分析)の報告

**発見事項**:
- Mem0関連ドキュメント参照: **300+件**
- Mem0関連実装コード: **0件**（✅ 既に削除済み）
- 最新コミット (c8d6631): 「Mem0除去完了」

**判定**: ⚠️ **実装はクリーン、ドキュメントが不整合**

**優先削除対象**:
1. **P0 (即座)**: `MIGRATION.md`, `docs/migration/V2.2.4_SUMMARY_FOR_REVIEW.md`
2. **P1 (24時間)**: `README-INSTALLATION.md`のMem0セクション、`.opencode/agent/*.md`
3. **P2 (3日)**: その他のドキュメント

### Artemis (技術分析)の報告

**TMWS技術仕様**:
- **25個のMCPツール**: 5カテゴリ（Memory, Agent, Task, Workflow, System）
- **パフォーマンス**: Search 0.47ms P95（目標20msを23倍上回る）
- **技術スタック**: SQLite + ChromaDB + Redis + Ollama embeddings
- **メモリタイプ**: 10種類の標準化タイプ

**ボトルネック**:
- Embedding生成: 20-30ms（バッチ処理で改善可能）

**推奨事項**:
1. 自動トリガーシステムの実装
2. プロジェクトベースnamespaceの自動検出
3. ペルソナ固有ツール統合

### Muses (文書化分析)の報告

**CLAUDE.md問題点**:
- 存在しないメモリ操作コマンド（83-93行）
- 存在しない学習システムコマンド（95-104行）
- 存在しないステータス・レポート機能（106-117行）

**更新計画**:
1. **削除**: 未実装機能の記述（約41行）
2. **追加**: ペルソナ使用方法、将来実装予定機能
3. **修正**: Example 3, 4の未実装コマンド削除

### Hestia (セキュリティ監査)の報告

**⚠️ CRITICAL発見事項**:
- **ハードコードされた認証情報**: `tmws_user:tmws_password` が20+ファイルに存在
- **検出場所**:
  - ドキュメント内の設定例（PUBLIC_DOCUMENTATION_STRATEGY.md、統合仕様書等）
  - 設定テンプレート（.env.example等）

**リスク分類**:

#### Category 1: 認証情報露出（初期CRITICAL → 精査後MEDIUM）
**検出内容**:
- デフォルト認証情報（tmws_user:tmws_password）が公開ドキュメントに記載
- 20+ファイルに同一の認証情報が存在

**実際のリスクレベル**: **MEDIUM**
**理由**:
1. **デモ/テスト用**: サンプルとして文書化されている
2. **本番環境では未使用**: ユーザーは環境変数で独自設定する設計
3. **コード内ハードコードなし**: ドキュメント内の設定例のみ

**推奨対応**:
- Phase 1（ドキュメント更新時）に統合
- セキュリティ警告の追加:
  ```markdown
  ⚠️ **SECURITY WARNING**
  - デフォルト認証情報（tmws_user:tmws_password）は**絶対に本番環境で使用しないでください**
  - 必ず環境変数（TMWS_AUTH_USER、TMWS_AUTH_PASSWORD）で独自の値を設定してください
  - 本番環境ではより強力な認証（JWT、OAuth2等）の使用を推奨します
  ```

#### Category 2: 設定ファイル管理（HIGH）
**検出内容**:
- `.env`ファイルの管理方法が不明確
- `.gitignore`にセンシティブファイルが含まれているか不明

**推奨対応**（24時間以内）:
1. `.gitignore`の確認と更新
   ```gitignore
   # Environment variables
   .env
   .env.local
   .env.production

   # TMWS data
   .tmws/
   data/tmws/
   ```
2. README-INSTALLATION.mdに環境変数管理のベストプラクティスを追加

#### Category 3: ドキュメント整合性（MEDIUM）
**検出内容**:
- セキュリティ関連ドキュメントがMem0時代の記述のまま
- TMWS認証方法が不明確

**推奨対応**（1週間以内）:
- TMWS統合ドキュメントにセキュリティセクションを追加

**Hestiaの最終判定**:
- ✅ **Phase 0（緊急対応）は不要** - 即時の脆弱性なし
- ⚠️ **Phase 1に統合** - ドキュメント更新時にセキュリティ警告を追加
- ✅ **実装コードは安全** - ハードコードされた秘密情報なし

---

## 🗂️ Phase 1: Mem0完全削除

### Phase 1.1: 緊急クリーンアップ（即座実施）

#### 削除対象ファイル

```bash
# P0: 即座に削除
rm MIGRATION.md
rm docs/migration/V2.2.4_SUMMARY_FOR_REVIEW.md
```

**理由**:
- `MIGRATION.md`: v2.2.1 → v2.2.4の移行情報は不要
- `V2.2.4_SUMMARY_FOR_REVIEW.md`: 内部レビュー完了済み

#### README-INSTALLATION.mdの簡略化

**削除すべきセクション**:
- 「Automatic Mem0 setup」セクション全体
- Ollama統合の説明（Mem0固有）
- Mem0依存関係のインストール手順

**追加すべきセクション**:
```markdown
## Memory System

Trinitas-agents uses a **file-based memory system**:
- No external dependencies
- No API keys required
- Fully private and local

**Storage Locations**:
- Claude Code: `~/.claude/memory/`
- OpenCode: `~/.config/opencode/memory/`

**Structure**:
```
~/.claude/memory/
├── agents/          # Per-persona memories
│   ├── athena/
│   ├── artemis/
│   └── ...
└── shared/          # Shared memories
```

**Future**: TMWS MCP Server integration will provide advanced memory features.

## Security Best Practices

### Environment Variables

**Never commit sensitive data to version control!**

1. **Use .env files for local development**:
   ```bash
   # .env (add to .gitignore)
   TMWS_AUTH_USER=your_username
   TMWS_AUTH_PASSWORD=your_password
   TMWS_DATABASE_URL=sqlite:///~/.tmws/tmws.db
   ```

2. **Verify .gitignore includes sensitive files**:
   ```gitignore
   .env
   .env.local
   .env.production
   .env.*.local
   .tmws/
   data/tmws/
   *.db
   ```

3. **Use strong, unique passwords**:
   - Minimum 16 characters
   - Mix of uppercase, lowercase, numbers, symbols
   - Use password manager (1Password, Bitwarden)

### Production Deployment

For production environments, use:
- **JWT** with short expiration (1 hour)
- **OAuth2** for third-party integrations
- **mTLS** (mutual TLS) for secure MCP connections
- **Regular credential rotation** (every 90 days)
```

### Phase 1.2: エージェント定義の更新（24時間以内）

#### 対象ファイル

```
.opencode/agent/athena.md
.opencode/agent/artemis.md
.opencode/agent/hestia.md
.opencode/agent/eris.md
.opencode/agent/hera.md
.opencode/agent/muses.md
```

#### 更新内容

**削除**: `## Mem0 MCP Memory Management` セクション

**追加**:
```markdown
## File-Based Memory Management

Store {persona_name} memories in:
- **Claude Code**: `~/.claude/memory/agents/{persona_id}/`
- **OpenCode**: `~/.config/opencode/memory/agents/{persona_id}/`

**Future**: With TMWS MCP Server:
- Semantic search across all memories
- Automatic importance scoring
- Cross-project knowledge sharing
```

### Phase 1.3: その他ドキュメントの更新（3日以内）

#### docs/PUBLIC_DOCUMENTATION_STRATEGY.md

**更新内容**:
```markdown
## Mem0 Removal ✅ Completed

**Status**: Fully removed as of v2.2.4
**Replacement**: File-based memory system

**Actions Taken**:
- Removed all Mem0 code (v2.2.4)
- Removed all Mem0 documentation (v2.2.5)
- Simplified installation process
```

#### scripts/cleanup_mem0.sh

**保持**: 既存ユーザーのクリーンアップ用

**ドキュメント明記**:
```bash
#!/bin/bash
# Legacy Mem0 Cleanup Script
# For users upgrading from v2.2.3 or earlier
# Note: Mem0 was removed in v2.2.4
```

---

## 🔧 Phase 2: TMWS統合

### Phase 2.1: TMWS概要ドキュメント作成

#### ファイル: `trinitas_sources/tmws/00_overview.md`

**内容**:
```markdown
# TMWS (Trinitas Memory & Workflow System) Overview

## What is TMWS?

External MCP Server providing 25 specialized tools for Trinitas agents.

## Key Features

1. **Semantic Memory Search** (0.47ms P95)
2. **10 Standardized Memory Types**
3. **Agent State Management** (Redis)
4. **Task & Workflow Orchestration**
5. **Namespace Isolation**

## Prerequisites

- SQLite (latest)
- ChromaDB (latest)
- Redis 7.0+
- Ollama (for embeddings)

## Installation

```bash
# Install TMWS MCP Server
pip install tmws-mcp-server

# Initialize infrastructure
tmws init
```

## MCP Configuration

### Claude Code (`~/.claude/settings.json`)

```json
{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": ["tmws-mcp-server"],
      "env": {
        "TMWS_DATABASE_URL": "sqlite:///~/.tmws/tmws.db",
        "TMWS_REDIS_URL": "redis://localhost:6379/0",
        "TMWS_DEFAULT_NAMESPACE": "trinitas-agents"
      }
    }
  }
}
```

### OpenCode (`~/.config/opencode/opencode.json`)

```json
{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": ["tmws-mcp-server"],
      "env": {
        "TMWS_DATABASE_URL": "sqlite:///~/.tmws/tmws.db",
        "TMWS_REDIS_URL": "redis://localhost:6379/0",
        "TMWS_DEFAULT_NAMESPACE": "trinitas-agents"
      }
    }
  }
}
```

## Security Configuration

⚠️ **SECURITY WARNING**

**Default Credentials** (tmws_user:tmws_password) are for **DEMO PURPOSES ONLY**.

**NEVER use default credentials in production environments!**

### Secure Configuration

1. **Set unique credentials via environment variables**:
   ```bash
   export TMWS_AUTH_USER="your_unique_username"
   export TMWS_AUTH_PASSWORD="your_strong_password"
   ```

2. **Use strong authentication for production**:
   - JWT tokens with short expiration
   - OAuth2 integration
   - mTLS (mutual TLS) for MCP connections

3. **Rotate credentials regularly**:
   - Change passwords every 90 days
   - Use password managers (1Password, Bitwarden)

### .gitignore Configuration

Ensure sensitive files are excluded from version control:

```gitignore
# Environment variables
.env
.env.local
.env.production
.env.*.local

# TMWS data
.tmws/
data/tmws/
*.db
*.db-journal
```

## Graceful Degradation

⚠️ **Important**: TMWS is **optional** in v2.2.5

If TMWS is unavailable:
- ✅ Basic memory operations work via file-based system
- ❌ Semantic search unavailable
- ❌ Cross-project knowledge sharing unavailable

**Note for v2.2.6+**: TMWS will become **mandatory** (no file-based fallback)
```

### Phase 2.2: ペルソナ別ツールマッピング

#### ファイル: `trinitas_sources/tmws/01_persona_tool_mapping.md`

**内容構造**:
```markdown
# TMWS Tool Mapping for Trinitas Personas

## Tool Categories Overview

25 tools across 5 categories:
1. Memory Tools (7): store_memory, search_memories, update_memory, ...
2. Agent Tools (6): register_agent, get_agent, list_agents, ...
3. Task Tools (5): create_task, update_task_status, list_tasks, ...
4. Workflow Tools (3): create_workflow, execute_workflow, get_workflow_status
5. System Tools (4): health_check, get_system_stats, reset_namespace, export_data

## Athena (athena-conductor)

### Primary Tools
- `store_memory`: Record architecture decisions (importance: 0.8-0.95)
- `create_workflow`: Define multi-agent coordination workflows
- `execute_workflow`: Orchestrate parallel analysis
- `list_agents`: Monitor active team members

### Usage Pattern
```python
# Record coordination decision
await store_memory(
    content="Parallel analysis workflow: Artemis + Hestia + Eris",
    importance=0.85,
    tags=["coordination", "workflow", "parallel"],
    namespace="project-alpha",
    access_level="team"
)
```

### Auto-Trigger Conditions
- Workflow completion (importance: 0.7)
- Multi-agent coordination (≥3 agents) (importance: 0.8)
- Architecture decision (importance: 0.85-0.95)

## Artemis (artemis-optimizer)

### Primary Tools
- `store_memory`: Record optimization patterns (importance: 0.6 + improvement%/100)
- `search_memories`: Find similar optimization cases
- `update_memory`: Upgrade importance for successful optimizations

### Usage Pattern
```python
# Record optimization
await store_memory(
    content="Database query optimized: 500ms → 50ms (10x) via btree index",
    importance=0.97,  # 0.6 + 90/100, capped at 1.0
    tags=["optimization", "database", "performance"],
    access_level="shared",  # Share across projects
    metadata={
        "technique": "btree_index",
        "improvement_pct": 90
    }
)
```

### Auto-Trigger Conditions
- Optimization applied (importance: 0.6 + improvement%/100)
- Code quality issue (critical: 0.9, high: 0.7)
- Anti-pattern detected (≥3 occurrences) (importance: 0.8)

## Hestia (hestia-auditor)

### Primary Tools
- `store_memory`: Record security findings (critical: 1.0, high: 0.9)
- `create_task`: Create remediation tasks
- `search_memories`: Find similar vulnerabilities

### Usage Pattern
```python
# Record critical vulnerability
await store_memory(
    content="SQL injection in /api/users (CVE-2024-xxxxx)",
    importance=1.0,
    tags=["security", "vulnerability", "sql_injection", "critical"],
    access_level="team",
    metadata={"severity": "critical", "cve": "CVE-2024-xxxxx"}
)

# Create remediation task
await create_task(
    title="[CRITICAL] Fix SQL injection in /api/users",
    assigned_persona="artemis-optimizer",
    priority="URGENT"
)
```

### Auto-Trigger Conditions
- Vulnerability found (critical: 1.0, high: 0.9)
- Security audit completed (importance: 0.8)
- Attack pattern recognized (importance: 0.95)

## Eris (eris-coordinator)

### Primary Tools
- `list_agents`: Monitor team status
- `create_task`: Assign tactical tasks
- `list_tasks`: Track pending/in-progress tasks
- `update_task_status`: Report progress

### Usage Pattern
```python
# Monitor active team
agents = await list_agents(namespace="trinitas", status="active")

# Create coordinated task
await create_task(
    title="Frontend-Backend API sync",
    priority="HIGH",
    metadata={"frontend_lead": "agent-1", "backend_lead": "agent-2"}
)
```

### Auto-Trigger Conditions
- Conflict resolved (importance: 0.7)
- Tactical decision (critical: 0.8, high: 0.7)
- Coordination pattern (success rate >80%) (importance: 0.75)

## Hera (hera-strategist)

### Primary Tools
- `create_workflow`: Define strategic workflows
- `execute_workflow`: Execute parallel deployments
- `get_workflow_status`: Monitor progress
- `store_memory`: Record strategic decisions (importance: 0.85-0.95)

### Usage Pattern
```python
# Define parallel deployment
workflow = await create_workflow(
    name="parallel_microservices_deploy",
    steps=[
        {"persona": "artemis-optimizer", "action": "service_a_deploy"},
        {"persona": "artemis-optimizer", "action": "service_b_deploy"}
    ],
    parallel=True
)
```

### Auto-Trigger Conditions
- Strategic decision (importance: 0.9)
- Architecture decision (importance: 0.85)
- Long-term plan (importance: 0.8)

## Muses (muses-documenter)

### Primary Tools
- `store_memory`: Record documentation (importance: 0.6-0.8)
- `search_memories`: Find related knowledge
- `export_data`: Archive documentation

### Usage Pattern
```python
# Document API
await store_memory(
    content="REST API v2.0: 45 endpoints, OpenAPI 3.0",
    importance=0.8,
    tags=["documentation", "api", "specification"],
    access_level="public"
)
```

### Auto-Trigger Conditions
- Documentation created (importance: 0.6)
- Knowledge gap identified (importance: 0.7)
- Frequent question (≥3 times) (importance: 0.75)
```

### Phase 2.3: ベストプラクティスガイド

#### ファイル: `trinitas_sources/tmws/02_usage_best_practices.md`

**内容**:
```markdown
# TMWS Usage Best Practices

## Importance Scoring Guidelines

| Score | Category | Examples | Retention |
|-------|----------|----------|-----------|
| 1.0 | Critical | CVE vulnerabilities, data loss | Permanent |
| 0.9 | Very High | Major architecture decisions, >50% improvements | 5 years |
| 0.8 | High | Significant optimizations (20-50%), security findings | 3 years |
| 0.7 | Medium-High | Important patterns, team decisions | 2 years |
| 0.6 | Medium | Useful learnings, moderate improvements (10-20%) | 1 year |
| 0.5 | Medium-Low | Routine work, documentation updates | 6 months |

## Tagging Strategy

### Domain Tags
```python
["database", "api", "frontend", "backend", "infrastructure"]
```

### Action Tags
```python
["optimization", "refactoring", "bug_fix", "feature", "migration"]
```

### Severity Tags
```python
["critical", "high", "medium", "low", "urgent", "blocking"]
```

### Hierarchical Tags
```python
[
    "database",                      # Level 1
    "database_postgresql",           # Level 2
    "database_postgresql_index"      # Level 3
]
```

## Search Strategies

### Semantic Search (Natural Language)
```python
# Use for conceptual queries
search_memories(
    query="How to improve database performance?",
    use_semantic=True,
    limit=10
)
```

### Keyword Search (Exact Terms)
```python
# Use for specific error messages
search_memories(
    query="IndexError: list index out of range",
    use_semantic=False
)
```

## Memory Lifecycle Management

### Retention Policies
```python
retention_policy = {
    "critical": "permanent",      # importance >= 0.9
    "high": "5_years",            # importance >= 0.7
    "medium": "2_years",          # importance >= 0.5
    "low": "6_months"             # importance < 0.5
}
```

### Archival Strategy
```python
# Archive old memories before deletion
old_memories = list_memories(
    created_before=datetime.now() - timedelta(days=365),
    importance_lt=0.5
)

export_data(
    memory_ids=[m.id for m in old_memories],
    output_format="json"
)
```

## Performance Optimization

### Batch Operations
```python
# ✅ Good: Batch create
batch_create_memories(memories)

# ❌ Bad: One by one
for memory in memories:
    create_memory(**memory)
```

### Caching Strategy
```python
# Cache search results for 5 minutes
@lru_cache(maxsize=100)
def cached_search(query, cache_key):
    return search_memories(query)
```

## Common Anti-Patterns (Avoid!)

### Anti-Pattern 1: Over-Logging
```python
# ❌ Bad: Log every iteration
for i in range(1000):
    create_memory(f"Processed item {i}", importance=0.1)

# ✅ Good: Log summary
create_memory(
    f"Processed 1000 items. 15 errors.",
    importance=0.6,
    metadata={"total": 1000, "errors": 15}
)
```

### Anti-Pattern 2: Generic Tags
```python
# ❌ Bad: Non-specific
create_memory(..., tags=["fix", "done", "good"])

# ✅ Good: Specific, searchable
create_memory(..., tags=["bug_fix", "authentication", "null_pointer"])
```
```

### Phase 2.4: `./.claude/CLAUDE.md` の更新

#### 削除すべきセクション（Musesの分析より）

| 行番号 | 内容 | 理由 |
|--------|------|------|
| 83-93 | `#### 3. メモリ操作 (remember/recall)` | TMWS未実装 |
| 95-104 | `#### 4. 学習システム (learn/apply)` | Learning Service未実装 |
| 106-117 | `#### 5. ステータスとレポート (status/report)` | ステータス機能未実装 |

#### 追加すべきセクション

**新セクション1: ペルソナの使用方法**（82行目の直前）
```markdown
## ペルソナの使用方法

### 方法1: トリガーワードによる自動選択
Claude Codeは、あなたの要求内容から適切なペルソナを自動的に選択します。

**例**:
- "このコードを最適化してください" → Artemis
- "セキュリティリスクを確認してください" → Hestia

### 方法2: サブエージェント呼び出し
```bash
@artemis-optimizer このAPIのレスポンス時間を改善してください
```

**注意**: @-メンション機能はClaude Codeのバージョンによって動作が異なります。
```

**新セクション2: 将来実装予定の機能**（117行目の直後）
```markdown
### 将来実装予定の機能

以下の機能は現在開発中です。TMWS MCP Serverの完成後に利用可能になります。

#### メモリ操作 (remember/recall) - 開発中
```bash
/trinitas remember project_architecture "..." --importance 0.9
```

#### 学習システム (learn/apply) - 開発中
```bash
/trinitas learn optimization_pattern "..."
```

#### ステータス・レポート - 開発中
```bash
/trinitas status
/trinitas report usage
```

**進捗**: TMWS MCP Serverプロジェクトで開発中。完成次第、本ドキュメントを更新します。
```

#### 修正すべき箇所

**Example 3, 4の修正**:
```diff
# Example 3
- /trinitas remember security_audit "..." --importance 1.0
+ /trinitas execute muses "セキュリティ監査レポートの作成と保存"

# Example 4
- /trinitas learn optimization_pattern "..."
+ /trinitas execute muses "データベース最適化のベストプラクティス文書化"
```

---

## 📐 Phase 3: 実装ステップ

### Step 1: Mem0削除 (P0: 即座実施)

```bash
# 1. ファイル削除
rm MIGRATION.md
rm docs/migration/V2.2.4_SUMMARY_FOR_REVIEW.md

# 2. git commit
git add -A
git commit -m "docs: Remove Mem0 references (P0 urgent cleanup)

Removed:
- MIGRATION.md (v2.2.1 → v2.2.4)
- docs/migration/V2.2.4_SUMMARY_FOR_REVIEW.md

Mem0 was removed from code in v2.2.4.
This commit removes outdated documentation.
"
```

### Step 2: README-INSTALLATION.md更新 (P0)

**実施内容**:
1. Mem0セクション全削除
2. File-based memory systemの説明追加
3. git commit

### Step 3: TMWS統合ファイル作成

```bash
# 1. ディレクトリ作成
mkdir -p trinitas_sources/tmws

# 2. 3つのマークダウンファイル作成
# - 00_overview.md
# - 01_persona_tool_mapping.md
# - 02_usage_best_practices.md

# 3. ビルドテスト
INCLUDE_TMWS=true ./scripts/build_claude_md.sh
```

### Step 4: CLAUDE.md更新

```bash
# 1. 手動で修正（Muses計画に基づく）
# - 83-117行削除
# - 新セクション追加
# - Example 3, 4修正

# 2. git commit
git commit -m "docs: Update CLAUDE.md for v2.2.5

Changes:
- Remove unimplemented features (remember/recall, learn/apply, status)
- Add 'Future Features' section
- Update examples to use implemented features only

This aligns documentation with actual implementation.
"
```

### Step 5: エージェント定義更新 (P1: 24時間以内)

```bash
# .opencode/agent/*.md の更新
# Mem0セクション削除 → file-based memory説明追加

git commit -m "docs: Update agent definitions for file-based memory

Replaced Mem0 references with file-based memory system.
Prepared for future TMWS integration.
"
```

### Step 6: .gitignore更新（Hestia勧告）

```bash
# .gitignoreに以下を追加（存在しない場合のみ）

# Environment variables
.env
.env.local
.env.production
.env.*.local

# TMWS data
.tmws/
data/tmws/
*.db
*.db-journal

# git commit
git add .gitignore
git commit -m "security: Add sensitive files to .gitignore

Added:
- Environment variables (.env*)
- TMWS data directories
- SQLite database files

Recommendation from Hestia security audit.
"
```

### Step 7: バージョンタグ作成

```bash
# VERSION ファイル更新
echo "2.2.5" > VERSION

# git tag
git tag -a v2.2.5 -m "Release v2.2.5: Mem0 documentation cleanup + TMWS integration preparation

Changes:
- Complete Mem0 removal from documentation
- Add TMWS integration guides (3 files)
- Update CLAUDE.md for v2.2.5
- Align documentation with implementation
- Add security best practices (Hestia audit)
- Update .gitignore for sensitive files

TMWS MCP Server integration is optional in v2.2.5.
Users can continue using file-based memory system.
"

# push
git push origin main
git push origin v2.2.5
```

---

## 🧪 Phase 4: テスト計画

### Test 1: ドキュメント整合性テスト

**目的**: ドキュメントに未実装機能の記述がないことを確認

**手順**:
```bash
# Mem0参照の完全削除を確認
grep -r "mem0\|Mem0" --include="*.md" . | grep -v ".git" | grep -v "cleanup_mem0.sh"

# 期待結果: cleanup_mem0.sh以外にヒットしない
```

### Test 2: ビルドシステムテスト

**目的**: INCLUDE_TMWSフラグが正しく動作することを確認

**手順**:
```bash
# TMWS無効でビルド
INCLUDE_TMWS=false ./scripts/build_claude_md.sh
wc -l CLAUDE.md  # 期待: ~200-300行

# TMWS有効でビルド
INCLUDE_TMWS=true ./scripts/build_claude_md.sh
wc -l CLAUDE.md  # 期待: ~2000-3000行

# 差分確認
INCLUDE_TMWS=false ./scripts/build_claude_md.sh
cp CLAUDE.md CLAUDE_without_tmws.md
INCLUDE_TMWS=true ./scripts/build_claude_md.sh
diff CLAUDE_without_tmws.md CLAUDE.md  # 期待: TMWSセクションのみ追加
```

### Test 3: Claude Code動作確認（手動）

**目的**: ペルソナが正しく動作することを確認

**手順**:
1. Claude Codeを再起動
2. トリガーワードでペルソナ呼び出し:
   - "このコードを最適化してください" → Artemis起動確認
   - "セキュリティ監査してください" → Hestia起動確認
3. サブエージェント呼び出し:
   - `@athena-conductor プロジェクト全体を分析してください`

**期待結果**: ペルソナが正しく起動し、file-based memoryが動作する

### Test 4: TMWS統合テスト（オプション）

**前提**: TMWS MCP Serverをインストール済み

**手順**:
```bash
# 1. TMWS MCP Server起動確認
tmws health-check

# 2. MCP設定確認
cat ~/.claude/settings.json | jq '.mcpServers.tmws'

# 3. Claude Code再起動

# 4. TMWS tool使用テスト
# Claudeに以下を依頼:
# "過去の最適化パターンを検索してください"
# → search_memories toolが呼ばれることを確認
```

### Test 5: OpenCode互換性テスト

**目的**: OpenCode版でも同様に動作することを確認

**手順**:
1. OpenCode環境で同様のテスト実施
2. `.opencode/agent/*.md` の更新が反映されることを確認

---

## 📊 成功基準

### Phase 1 (Mem0削除)
- [ ] ドキュメントからMem0参照が完全削除（cleanup_mem0.sh除く）
- [ ] README-INSTALLATION.mdにfile-based memoryの説明が追加
- [ ] `.opencode/agent/*.md`がfile-based memoryに更新
- [ ] git logに適切なコミットメッセージが記録

### Phase 2 (TMWS統合)
- [ ] `trinitas_sources/tmws/` に3ファイル作成
- [ ] `INCLUDE_TMWS=true` でビルド成功
- [ ] CLAUDE.mdにTMWSセクションが含まれる（2000+行）
- [ ] CLAUDE.mdから未実装機能の記述が削除

### Phase 3 (実装)
- [ ] 全gitコミットが完了
- [ ] v2.2.5タグが作成・プッシュ済み
- [ ] VERSION ファイルが "2.2.5" に更新
- [ ] .gitignore が更新済み（Hestia勧告）

### Phase 4 (テスト)
- [ ] ドキュメント整合性テスト: Pass
- [ ] ビルドシステムテスト: Pass
- [ ] Claude Code動作確認: Pass
- [ ] OpenCode互換性テスト: Pass

### セキュリティ（Hestia検証）
- [ ] デフォルト認証情報に "DEMO PURPOSES ONLY" 警告が追加
- [ ] README-INSTALLATION.md にセキュリティベストプラクティスが記載
- [ ] TMWS概要ドキュメントにセキュリティ設定ガイドが記載
- [ ] .gitignore に .env* と .tmws/ が含まれる

---

## ⚠️ リスクと対策

### Risk 1: file-based memoryが未実装

**確率**: 中
**影響度**: 高
**対策**:
1. file-based memoryの実装確認（コード検索）
2. 未実装の場合は実装が必要
3. または、v2.2.5でTMWSを必須にする

### Risk 2: TMWS MCP Serverが不安定

**確率**: 低
**影響度**: 中
**対策**:
1. TMWS health-checkの実行
2. エラーハンドリングの追加
3. フォールバック機構の確認

### Risk 3: ドキュメント更新の漏れ

**確率**: 中
**影響度**: 低
**対策**:
1. 全ファイルでMem0検索
2. レビュー段階での再確認
3. ユーザーフィードバックによる修正

### Risk 4: セキュリティ設定の誤解（Hestia追加）

**確率**: 中
**影響度**: 高（本番環境でデフォルト認証情報を使用してしまう）
**対策**:
1. ✅ **Phase 1に統合済み**: README-INSTALLATION.mdにセキュリティ警告を追加
2. ✅ **Phase 2.1に統合済み**: TMWS概要ドキュメントにセキュリティ設定ガイドを追加
3. ⚠️ **Phase 3で実施**: .gitignoreにセンシティブファイルを追加
4. 📋 **ドキュメント明記**: デフォルト認証情報は「DEMO PURPOSES ONLY」と明記

**Hestiaの判定**: ✅ **Phase 0（緊急対応）は不要** - ドキュメント更新で対応可能

---

## 📅 スケジュール

| Phase | タスク | 所要時間 | 担当 |
|-------|--------|---------|------|
| **Phase 1.1** | Mem0削除（P0） | 30分 | ユーザー |
| **Phase 1.2** | エージェント定義更新 | 1時間 | ユーザー |
| **Phase 2.1-2.3** | TMWS統合ファイル作成 | 3時間 | ユーザー |
| **Phase 2.4** | CLAUDE.md更新 | 1時間 | ユーザー |
| **Phase 3** | 全実装ステップ実施 | 6時間 | ユーザー |
| **Phase 4** | テスト実施 | 2時間 | ユーザー |

**合計所要時間**: 約13.5時間（2日間）

---

## 📋 チェックリスト（実装前確認）

実装開始前に以下を確認してください：

- [ ] 現在のgit statusがクリーン（未コミットファイルがない）
- [ ] バックアップブランチを作成（`git checkout -b backup/v2.2.4`）
- [ ] TMWS仕様（../tmws/docs/）を確認済み
- [ ] file-based memoryの実装を確認済み
- [ ] すべてのエージェント分析レポートを確認済み
- [ ] この計画書を精読し、全手順を理解済み

---

## 📞 サポート

### 質問・問題報告

- GitHub Issues: https://github.com/apto-as/trinitas-agents/issues
- TMWS Issues: https://github.com/apto-as/tmws/issues

### ドキュメント

- Trinitas-agents: `/Users/apto-as/workspace/github.com/apto-as/trinitas-agents/`
- TMWS: `/Users/apto-as/workspace/github.com/apto-as/tmws/`

---

**計画書作成完了**: 2025-10-29
**次のステップ**: ユーザー様の承認を得て実装開始

**担当エージェント**:
- **Athena (最終統合)**: 4エージェントの報告を調和的に統合、計画書全体の調整
- **Hera (戦略分析)**: Mem0削除の優先順位マトリックス策定、ドキュメント整合性分析
- **Artemis (技術分析)**: TMWS技術仕様の詳細分析、パフォーマンス評価、ツールマッピング
- **Hestia (セキュリティ監査)**: 認証情報露出の検出、3つのリスクカテゴリ分類、緊急度評価
- **Muses (文書化)**: CLAUDE.md問題点の特定、更新計画の立案

**Hestiaの重要な判定**:
- ✅ **Phase 0（緊急対応）は不要** - デフォルト認証情報はデモ用、実装コードは安全
- ⚠️ **Phase 1-2にセキュリティ警告を統合** - ドキュメント更新時に対応
- 📋 **Risk 4を追加** - セキュリティ設定の誤解を防ぐための対策を明記

**注意**: この計画書は**計画のみ**です。実装はユーザー様が実施してください。
