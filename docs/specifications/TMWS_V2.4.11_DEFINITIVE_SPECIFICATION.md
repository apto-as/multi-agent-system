# TMWS v2.4.11 完全仕様書
## Trinitas Memory & Workflow System - Definitive Specification

**文書バージョン**: 1.0.0
**TMWS バージョン**: v2.4.11
**作成日**: 2025-12-03
**ステータス**: AUTHORITATIVE

---

## 1. システム概要

### 1.1 定義

TMWS (Trinitas Memory & Workflow System) は、マルチエージェントAIシステム向けの統合メモリ・ワークフロー管理プラットフォームである。

### 1.2 コア技術スタック

| コンポーネント | 技術 | バージョン |
|--------------|------|-----------|
| Web Framework | FastAPI | 0.109+ |
| ORM | SQLAlchemy 2.0 | async engine |
| Primary Database | SQLite | WAL mode |
| Vector Storage | ChromaDB | DuckDB backend |
| Embedding Model | Multilingual-E5-Large | 1024次元 |
| Language | Python | 3.11+ |
| API Protocol | Model Context Protocol (MCP) | 1.0 |

### 1.3 アーキテクチャ原則

1. **Dual Storage Architecture**: SQLite (メタデータ) + ChromaDB (ベクトル)
2. **Async-First Design**: 全I/O操作はasync
3. **Multi-Tenant Security**: Namespace分離をモデルレベルで強制
4. **Single Source of Truth**: TaskRoutingServiceが9エージェント定義の正規ソース

---

## 2. Trinitas エージェントシステム

### 2.1 エージェント定義 (AUTHORITATIVE)

**正規ソース**: `src/services/task_routing_service.py`

#### Tier 1: STRATEGIC (戦略層)

| Agent ID | Display Name | Role | Capabilities |
|----------|-------------|------|--------------|
| `athena-conductor` | Athena - Harmonious Conductor | Coordinator | orchestration, workflow, coordination, resource_management, parallel_execution |
| `hera-strategist` | Hera - Strategic Commander | Strategist | strategy, planning, architecture, vision, roadmap |

#### Tier 2: SPECIALIST (専門層)

| Agent ID | Display Name | Role | Capabilities |
|----------|-------------|------|--------------|
| `artemis-optimizer` | Artemis - Technical Perfectionist | Optimizer | performance, optimization, code_quality, technical_excellence, best_practices |
| `hestia-auditor` | Hestia - Security Guardian | Auditor | security, audit, vulnerability, threat_modeling, risk_assessment |
| `eris-coordinator` | Eris - Tactical Coordinator | Coordinator | tactical, team_coordination, conflict_resolution, mediation |
| `muses-documenter` | Muses - Knowledge Architect | Documenter | documentation, knowledge, archival, specification, API_docs |

#### Tier 3: SUPPORT (支援層)

| Agent ID | Display Name | Role | Capabilities |
|----------|-------------|------|--------------|
| `aphrodite-designer` | Aphrodite - UI/UX Designer | Designer | design, ui, ux, interface, accessibility, style |
| `metis-developer` | Metis - Development Assistant | Developer | implementation, testing, debugging, refactoring |
| `aurora-researcher` | Aurora - Research Assistant | Researcher | search, research, context, retrieval, synthesis |

### 2.2 エージェント定義の実装状況

| ソース | ファイル | エージェント数 | ステータス |
|--------|---------|--------------|-----------|
| TaskRoutingService | `src/services/task_routing_service.py` | 9 | ✅ AUTHORITATIVE |
| MCP Server | `src/mcp_server.py:TRINITAS_AGENTS` | 9 | ✅ COMPLETE |
| Agent Model | `src/models/agent.py:create_trinitas_agents()` | 6 | ⚠️ LEGACY (3 missing) |
| Persona Model | `src/models/persona.py:get_default_personas()` | 5 | 🔴 DEPRECATED |
| Static Definitions | `src/trinitas/agents/*.md` | 9 | ✅ COMPLETE |

### 2.3 Agent vs Persona モデル

**アーキテクチャ決定 (ADR-2024-003)**:

| モデル | ステータス | 用途 |
|--------|----------|------|
| Agent | PRIMARY | 全新機能、認証、メトリクス、信頼スコア |
| Persona | LEGACY | 後方互換性維持、Memory.persona_id参照 |

**移行計画**: v3.0でPersonaの完全廃止を検討

---

## 3. MCP Tools 完全一覧

### 3.1 サマリー

| カテゴリ | ツール数 | ファイル |
|---------|---------|---------|
| Routing | 7 | routing_tools.py |
| Communication | 8 | communication_tools.py |
| Orchestration | 7 | orchestration_tools.py |
| Memory | 6 | memory_tools.py |
| Agent | 9 | agent_tools.py |
| Skill | 8 | skill_tools.py |
| Verification | 5 | verification_tools.py |
| Expiration | 10 | expiration_tools.py |
| Task | 7 | task_tools.py |
| Workflow | 8 | workflow_tools.py |
| Learning | 5 | learning_tools.py |
| Persona | 7 | persona_tools.py |
| System | 6 | system_tools.py |
| Agent Memory | 5 | agent_memory_tools.py |
| License | 5 | license_tools.py |
| **合計** | **103** | |

### 3.2 カテゴリ別詳細

#### 3.2.1 Routing Tools (7 tools)

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `route_task` | タスクを最適エージェントにルーティング | task_content: str |
| `get_trinitas_execution_plan` | 実行計画を生成 | task_content: str |
| `detect_personas` | タスク内容からペルソナを検出 | task_content: str |
| `get_collaboration_matrix` | コラボレーションマトリクス取得 | task_type: str? |
| `get_agent_tiers` | エージェント階層情報取得 | - |
| `invoke_persona` | ペルソナをコンテキストとして起動 | persona_id: str, task_description: str |
| `list_available_personas` | 利用可能ペルソナ一覧 | - |

#### 3.2.2 Communication Tools (8 tools)

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `send_agent_message` | エージェント間メッセージ送信 | from_agent: str, to_agent: str, message: str, priority: str? |
| `broadcast_to_tier` | 階層全体へブロードキャスト | from_agent: str, tier: str, message: str |
| `delegate_task` | タスク委譲 | from_agent: str, task_description: str, to_agent: str? |
| `respond_to_delegation` | 委譲への応答 | agent_id: str, delegation_id: str, response: str, accepted: bool |
| `complete_delegation` | 委譲完了報告 | agent_id: str, delegation_id: str, result: str |
| `get_agent_messages` | メッセージ取得 | agent_id: str, unread_only: bool? |
| `handoff_task` | タスク引継ぎ | from_agent: str, to_agent: str, context: str |
| `get_communication_stats` | 通信統計取得 | agent_id: str |

#### 3.2.3 Orchestration Tools (7 tools)

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `create_orchestration` | オーケストレーション作成 | name: str, description: str, agent_id: str |
| `start_orchestration` | オーケストレーション開始 | orchestration_id: str |
| `execute_phase` | フェーズ実行 | orchestration_id: str, phase: str, agent_id: str |
| `approve_phase` | フェーズ承認 | orchestration_id: str, phase: str, agent_id: str, approved: bool |
| `get_orchestration_status` | ステータス取得 | orchestration_id: str |
| `list_orchestrations` | オーケストレーション一覧 | status: str?, limit: int? |
| `get_phase_config` | フェーズ設定取得 | phase: str |

#### 3.2.4 Memory Tools (6 tools)

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `create_memory` | メモリ作成 | content: str, memory_type: str?, persona_id: str?, tags: list?, metadata: dict?, importance: float? |
| `recall_memory` | メモリ検索 | query: str, memory_type: str?, persona_id: str?, limit: int?, semantic_search: bool?, min_similarity: float? |
| `update_memory` | メモリ更新 | memory_id: str, content: str?, tags: list?, metadata: dict?, importance: float? |
| `delete_memory` | メモリ削除 | memory_id: str |
| `get_memory_stats` | メモリ統計取得 | - |
| `optimize_memory_vectors` | ベクトル最適化 | - |

#### 3.2.5 Agent Tools (9 tools)

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `list_agents` | エージェント一覧 | agent_id: str, namespace: str?, status: str?, limit: int?, offset: int? |
| `get_agent` | エージェント詳細取得 | agent_id: str, target_agent_id: str |
| `search_agents` | エージェント検索 | agent_id: str, query: str, capabilities: list?, min_trust_score: float?, limit: int? |
| `register_agent` | エージェント登録 | agent_id: str, display_name: str, capabilities: list?, metadata: dict? |
| `update_agent` | エージェント更新 | agent_id: str, target_agent_id: str, display_name: str?, capabilities: list?, metadata: dict? |
| `deactivate_agent` | エージェント無効化 | agent_id: str, target_agent_id: str |
| `activate_agent` | エージェント有効化 | agent_id: str, target_agent_id: str |
| `get_agent_stats` | エージェント統計取得 | agent_id: str, target_agent_id: str |
| `get_recommended_agents` | 推奨エージェント取得 | agent_id: str, task_type: str, required_capabilities: list?, min_trust_score: float?, limit: int? |

#### 3.2.6 Skill Tools (8 tools)

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `list_skills` | スキル一覧 | agent_id: str, namespace: str?, detail_level: int?, include_shared: bool?, tags: list?, limit: int?, offset: int? |
| `get_skill` | スキル詳細取得 | agent_id: str, skill_id: str, detail_level: int? |
| `create_skill` | スキル作成 | agent_id: str, name: str, content: str, display_name: str?, description: str?, persona: str?, tags: list? |
| `update_skill` | スキル更新 | agent_id: str, skill_id: str, content: str?, display_name: str?, description: str?, persona: str?, tags: list? |
| `delete_skill` | スキル削除 | agent_id: str, skill_id: str |
| `share_skill` | スキル共有 | agent_id: str, skill_id: str, target_agent_ids: list |
| `activate_skill` | スキル有効化 | agent_id: str, skill_id: str |
| `deactivate_skill` | スキル無効化 | agent_id: str, skill_id: str |

#### 3.2.7 Verification Tools (5 tools)

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `verify_and_record` | 検証実行と記録 | agent_id: str, claim_type: str, claim_content: dict, verification_command: str, verified_by_agent_id: str? |
| `get_agent_trust_score` | 信頼スコア取得 | agent_id: str |
| `get_verification_history` | 検証履歴取得 | agent_id: str, claim_type: str?, limit: int? |
| `get_verification_statistics` | 検証統計取得 | agent_id: str |
| `get_trust_history` | 信頼スコア履歴取得 | agent_id: str, limit: int? |

#### 3.2.8 Expiration Tools (10 tools)

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `prune_expired_memories` | 期限切れメモリ削除 | agent_id: str, namespace: str, dry_run: bool?, confirm_mass_deletion: bool? |
| `get_expiration_stats` | 有効期限統計取得 | agent_id: str, namespace: str |
| `set_memory_ttl` | メモリTTL設定 | agent_id: str, memory_id: str, ttl_days: int? |
| `cleanup_namespace` | 名前空間クリーンアップ | agent_id: str, namespace: str, dry_run: bool?, confirm_mass_deletion: bool? |
| `get_namespace_stats` | 名前空間統計取得 | agent_id: str, namespace: str |
| `get_scheduler_status` | スケジューラ状態取得 | agent_id: str |
| `configure_scheduler` | スケジューラ設定 | agent_id: str, interval_hours: int |
| `start_scheduler` | スケジューラ開始 | agent_id: str |
| `stop_scheduler` | スケジューラ停止 | agent_id: str |
| `trigger_scheduler` | スケジューラ手動トリガー | agent_id: str |

#### 3.2.9 Task Tools (7 tools)

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `create_task` | タスク作成 | title: str, description: str?, priority: str?, assigned_agent_id: str?, due_date: str?, estimated_duration: int? |
| `update_task` | タスク更新 | task_id: str, status: str?, title: str?, description: str?, priority: str?, assigned_agent_id: str? |
| `get_task_status` | タスクステータス取得 | task_id: str |
| `list_tasks` | タスク一覧 | status: str?, assigned_agent_id: str?, priority: str?, limit: int?, offset: int? |
| `assign_task` | タスク割当 | task_id: str, agent_id: str |
| `complete_task` | タスク完了 | task_id: str, result: str?, agent_id: str? |
| `get_task_analytics` | タスク分析取得 | - |

#### 3.2.10 Workflow Tools (8 tools)

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `create_workflow` | ワークフロー作成 | name: str, description: str?, steps: list?, config: dict? |
| `execute_workflow` | ワークフロー実行 | workflow_id: str, input_data: dict? |
| `get_workflow_status` | ワークフローステータス取得 | workflow_id: str |
| `list_workflows` | ワークフロー一覧 | is_active: bool?, limit: int?, offset: int? |
| `update_workflow` | ワークフロー更新 | workflow_id: str, name: str?, description: str?, steps: list?, config: dict? |
| `cancel_workflow_execution` | ワークフロー実行キャンセル | execution_id: str |
| `pause_workflow_execution` | ワークフロー実行一時停止 | execution_id: str |
| `get_workflow_analytics` | ワークフロー分析取得 | - |

#### 3.2.11 Learning Tools (5 tools)

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `record_learning_pattern` | 学習パターン記録 | pattern_name: str, pattern_content: str, context: dict? |
| `get_learning_patterns` | 学習パターン取得 | pattern_name: str?, limit: int? |
| `get_pattern_analytics` | パターン分析取得 | - |
| `apply_learning_pattern` | 学習パターン適用 | pattern_id: str, target_context: dict? |
| `suggest_learning_opportunities` | 学習機会提案 | - |

#### 3.2.12 Persona Tools (7 tools)

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `create_persona` | ペルソナ作成 | name: str, display_name: str, description: str, specialties: list?, capabilities: list? |
| `get_persona` | ペルソナ取得 | persona_id: str |
| `list_personas` | ペルソナ一覧 | is_active: bool?, limit: int? |
| `update_persona` | ペルソナ更新 | persona_id: str, display_name: str?, description: str?, specialties: list?, capabilities: list? |
| `delete_persona` | ペルソナ削除 | persona_id: str |
| `get_persona_capabilities` | ペルソナ能力取得 | - |
| `find_personas_by_capability` | 能力によるペルソナ検索 | capability: str |

#### 3.2.13 System Tools (6 tools)

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `get_system_status` | システムステータス取得 | - |
| `get_database_stats` | データベース統計取得 | - |
| `vacuum_database` | データベース最適化 | - |
| `get_performance_metrics` | パフォーマンスメトリクス取得 | - |
| `get_system_configuration` | システム設定取得 | - |
| `restart_services` | サービス再起動 | service_names: list? |

#### 3.2.14 Agent Memory Tools (5 tools)

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `store_agent_memory` | エージェントメモリ保存 | agent_id: str, content: str, memory_type: str?, tags: list? |
| `search_agent_memories` | エージェントメモリ検索 | agent_id: str, query: str, memory_type: str?, limit: int? |
| `get_agent_memory_context` | エージェントメモリコンテキスト取得 | agent_id: str, context_type: str? |
| `clear_agent_memories` | エージェントメモリクリア | agent_id: str, memory_type: str? |
| `sync_agent_memories` | エージェントメモリ同期 | source_agent: str, target_agent: str, memory_type: str? |

#### 3.2.15 License Tools (5 tools)

| Tool Name | Description | Parameters | RBAC |
|-----------|-------------|------------|------|
| `generate_license_key` | ライセンスキー生成 | agent_id: UUID, tier: str (FREE/PRO/ENTERPRISE), expires_days: int? | ADMIN only |
| `validate_license_key` | ライセンスキー検証 | key: str, feature_accessed: str? | All authenticated |
| `revoke_license_key` | ライセンスキー失効 | license_id: UUID, reason: str? | ADMIN only |
| `get_license_usage_history` | ライセンス使用履歴取得 | license_id: UUID, limit: int? | ADMIN/Owner |
| `get_license_info` | ライセンス情報取得 | license_id: UUID | ADMIN/Owner |

**License Key Format**: `TMWS-{tier}-{uuid}-{checksum}`

**Tier Levels**:
- `FREE`: 基本機能のみ
- `PRO`: 高度な機能 + サポート
- `ENTERPRISE`: 全機能 + 優先サポート

---

## 4. REST API エンドポイント

### 4.1 API Routers

| Router | ファイル | ベースパス |
|--------|---------|-----------|
| Memory | `memory.py` | `/api/v1/memory` |
| Verification | `verification.py` | `/api/v1/verification` |
| Skills | `skills.py` | `/api/v1/skills` |
| MCP Connections | `mcp_connections.py` | `/api/v1/mcp` |
| Health | `health.py` | `/api/v1/health` |

### 4.2 Memory API

| Method | Path | Description |
|--------|------|-------------|
| POST | `/store` | メモリ保存 |
| POST | `/search` | メモリ検索 |
| GET | `/{memory_id}` | メモリ取得 |
| DELETE | `/{memory_id}` | メモリ削除 |
| POST | `/cleanup-namespace` | 名前空間クリーンアップ |
| POST | `/prune-expired` | 期限切れ削除 |
| POST | `/set-ttl` | TTL設定 |

### 4.3 Verification API

| Method | Path | Description |
|--------|------|-------------|
| POST | `/verify-and-record` | 検証実行 |
| GET | `/trust-score/{agent_id}` | 信頼スコア取得 |
| GET | `/history/{agent_id}` | 検証履歴取得 |

### 4.4 Skills API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | スキル一覧 |
| POST | `/` | スキル作成 |
| GET | `/{skill_id}` | スキル取得 |
| PUT | `/{skill_id}` | スキル更新 |
| DELETE | `/{skill_id}` | スキル削除 |
| POST | `/{skill_id}/share` | スキル共有 |
| POST | `/{skill_id}/activate` | スキル有効化 |
| POST | `/{skill_id}/deactivate` | スキル無効化 |

### 4.5 Health API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/detailed` | 詳細ヘルスチェック |

---

## 5. データモデル

### 5.1 Core Models

| Model | Table | Description | Key Relationships |
|-------|-------|-------------|-------------------|
| Agent | `agents` | エージェント定義 | tasks, verification_records, trust_history |
| Memory | `memories` | メモリエントリ | persona_id (optional) |
| Task | `tasks` | タスク定義 | assigned_agent |
| Skill | `skills` | スキル定義 | versions, shared_agents |
| Persona | `personas` | ペルソナ定義 (LEGACY) | memories |

### 5.2 Workflow Models

| Model | Table | Description |
|-------|-------|-------------|
| Workflow | `workflows` | ワークフロー定義 |
| WorkflowExecution | `workflow_executions` | ワークフロー実行履歴 |
| WorkflowHistory | `workflow_histories` | ワークフロー変更履歴 |

### 5.3 Learning Models

| Model | Table | Description |
|-------|-------|-------------|
| LearningPattern | `learning_patterns` | 学習パターン |
| PatternUsage | `pattern_usages` | パターン使用履歴 |
| ExecutionTrace | `execution_traces` | 実行トレース (v2.5.1+) |
| DetectedPattern | `detected_patterns` | 検出パターン (v2.5.1+) |
| SkillSuggestion | `skill_suggestions` | スキル提案 (v2.5.1+) |

### 5.4 Verification Models

| Model | Table | Description |
|-------|-------|-------------|
| VerificationRecord | `verification_records` | 検証レコード |
| TrustScoreHistory | `trust_score_history` | 信頼スコア履歴 |

### 5.5 Security Models

| Model | Table | Description |
|-------|-------|-------------|
| SecurityAuditLog | `security_audit_logs` | セキュリティ監査ログ |
| APIAuditLog | `api_audit_logs` | API監査ログ |
| LicenseKey | `license_keys` | ライセンスキー |

---

## 6. サービスレイヤー

### 6.1 Core Services

| Service | File | Description |
|---------|------|-------------|
| MemoryService | `memory_service.py` | メモリCRUD、検索、TTL管理 |
| AgentService | `agent_service.py` | エージェント管理、メトリクス |
| TaskService | `task_service.py` | タスク管理 |
| WorkflowService | `workflow_service.py` | ワークフロー実行 |
| SkillService | `skill_service.py` | スキルCRUD、共有、バージョン管理 |

### 6.2 Trinitas Orchestration Services (v2.4.8+)

| Service | File | Lines | Description |
|---------|------|-------|-------------|
| TaskRoutingService | `task_routing_service.py` | 470 | タスクルーティング、パターンマッチング |
| AgentCommunicationService | `agent_communication_service.py` | 873 | エージェント間通信、タスク委譲 |
| OrchestrationEngine | `orchestration_engine.py` | 480 | 4フェーズ実行、承認ゲート |

### 6.3 Autonomous Learning Services (v2.5.1+)

| Service | File | Description |
|---------|------|-------------|
| ExecutionTraceService | `execution_trace_service.py` | Layer 1: 実行トレース記録 |
| PatternDetectionService | `pattern_detection_service.py` | Layer 2: パターン検出 |
| LearningLoopService | `learning_loop_service.py` | Layer 3: 学習ループ (計画中) |
| ProactiveContextService | `proactive_context_service.py` | Layer 4: プロアクティブコンテキスト (計画中) |

### 6.4 Support Services

| Service | File | Description |
|---------|------|-------------|
| VectorSearchService | `vector_search_service.py` | ChromaDBベクトル検索 |
| OllamaEmbeddingService | `ollama_embedding_service.py` | Ollamaエンベディング生成 |
| VerificationService | `verification_service.py` | 検証実行、信頼スコア更新 |
| TrustService | `trust_service.py` | 信頼スコア管理 |
| AuthService | `auth_service.py` | 認証処理 |
| LicenseService | `license_service.py` | ライセンス管理 |
| ExpirationScheduler | `expiration_scheduler.py` | TTL期限管理スケジューラ |
| SystemHealthService | `system_health_service.py` | システムヘルスチェック |

---

## 7. セキュリティアーキテクチャ

### 7.1 認証方式

| 方式 | 用途 | 実装 |
|------|------|------|
| API Key | MCP Tools | `src/security/agent_auth.py` |
| JWT | REST API | `src/security/jwt_service.py` |

### 7.2 認可レベル

| Level | Code | Description |
|-------|------|-------------|
| PRIVATE | `private` | オーナーのみ |
| TEAM | `team` | 同一namespace |
| SHARED | `shared` | 明示的共有先 |
| PUBLIC | `public` | 全エージェント |
| SYSTEM | `system` | システム共有 (読取専用) |

### 7.3 重要セキュリティパターン

#### P0-1: Namespace Isolation

```python
# 正しいパターン
agent = await db.get(Agent, agent_id)
verified_namespace = agent.namespace  # DBから取得
memory.is_accessible_by(agent_id, verified_namespace)

# 禁止パターン
namespace = jwt_claims.get("namespace")  # JWTから直接取得は禁止
```

### 7.4 Rate Limiting

| カテゴリ | 本番環境 | 開発環境 |
|---------|---------|---------|
| memory_cleanup | 5/min | 10/min |
| memory_prune | 5/min | 10/min |
| memory_ttl | 30/min | 60/min |
| health_detailed | 60/min | 120/min |

---

## 8. パフォーマンス目標

### 8.1 レイテンシ目標 (P95)

| 操作 | 目標 | 達成 |
|------|------|------|
| Semantic search | < 20ms | 5-20ms ✅ |
| Vector similarity | < 10ms | < 10ms ✅ |
| Metadata queries | < 20ms | 2.63ms ✅ |
| Cross-agent sharing | < 15ms | 9.33ms ✅ |
| record_execution | < 5ms | ✅ |
| analyze_patterns | < 100ms | ✅ |
| Health check | < 50ms | ✅ |

### 8.2 スループット目標

- 同時ユーザー: 100-1000
- リクエスト/秒: 100-500
- メモリ操作/秒: 50-100

---

## 9. 設定

### 9.1 必須環境変数

```bash
TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"
TMWS_SECRET_KEY="<64文字の16進数>"
TMWS_ENVIRONMENT="production"
```

### 9.2 オプション環境変数

```bash
TMWS_LOG_LEVEL="INFO"
TMWS_CORS_ORIGINS='["https://example.com"]'
TMWS_API_KEY_EXPIRE_DAYS="90"
TMWS_AUTONOMOUS_LEARNING_ENABLED="true"
TMWS_TRACE_TTL_DAYS="30"
```

---

## 10. バージョン履歴

| Version | Date | Major Changes |
|---------|------|---------------|
| v2.4.11 | 2025-12-03 | Single Source of Truth確立、SubAgent Enforcement |
| v2.4.9 | 2025-12-02 | Health Check Endpoint、Autonomous Learning Layer 1-2 |
| v2.4.8 | 2025-12-02 | Trinitas Orchestration Layer (128/128 tests) |
| v2.5.0 | 2025-11-25 | Skills System POC Validation |
| v2.4.0 | 2025-11-24 | Memory Management API & Rate Limiting |
| v2.3.0 | 2025-11-11 | Verification-Trust Integration |
| v2.2.6 | 2025-10-27 | Ollama-Only Architecture |

---

## 11. 付録

### 11.1 Trinitas Phase-Based Execution Protocol

```
Phase 1: Strategic Planning (戦略立案)
  ├─ Hera: 戦略設計
  └─ Athena: リソース調整
  → Approval Gate 1

Phase 2: Implementation (実装)
  ├─ Artemis: 技術実装
  └─ Metis: テスト作成
  → Approval Gate 2

Phase 3: Verification (検証)
  ├─ Hestia: セキュリティ監査
  └─ Aurora: コンテキスト検証
  → Approval Gate 3

Phase 4: Documentation (文書化)
  ├─ Muses: ドキュメント作成
  └─ Aphrodite: ビジュアルガイド
  → Final Approval
```

### 11.2 Collaboration Matrix

| Task Type | Primary | Support | Review |
|-----------|---------|---------|--------|
| architecture | athena | hera, aurora | hestia |
| implementation | artemis | metis | hestia |
| security | hestia | aurora | artemis |
| documentation | muses | aurora | athena |
| design | aphrodite | aurora | athena |
| coordination | eris | athena | hera |
| optimization | artemis | aurora | hestia |
| research | aurora | muses | athena |

---

**文書終了**

*この仕様書は TMWS v2.4.11 の正規仕様として扱われる。*
*最終更新: 2025-12-03 by Trinitas Full Mode Collaboration*
