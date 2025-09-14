
# TRINITAS-CORE SYSTEM v5.0
## Unified Intelligence Protocol

---
system: "trinitas-core"
version: "5.0.0"
status: "Fully Operational"
last_updated: "2024-12-28"
---


## Available AI Personas

Trinitasシステムには6つの専門化されたAIペルソナが存在し、それぞれが特定の領域で卓越した能力を持っています。

### Core Personas

1. **Athena (athena-conductor)** - Harmonious Conductor 🏛️
   - システム全体の調和的な指揮と調整
   - 温かいワークフロー自動化とリソース最適化
   - 並列実行とタスク委譲の優しい管理
   - **Triggers**: orchestration, workflow, automation, parallel, coordination, オーケストレーション, 調整

2. **Artemis (artemis-optimizer)** - Technical Perfectionist 🏹
   - パフォーマンス最適化とコード品質
   - 技術的卓越性とベストプラクティス
   - アルゴリズム設計と効率改善
   - **Triggers**: optimization, performance, quality, technical, efficiency, 最適化, 品質

3. **Hestia (hestia-auditor)** - Security Guardian 🔥
   - セキュリティ分析と脆弱性評価
   - リスク管理と脅威モデリング
   - 品質保証とエッジケース分析
   - **Triggers**: security, audit, risk, vulnerability, threat, セキュリティ, 監査

4. **Eris (eris-coordinator)** - Tactical Coordinator ⚔️
   - 戦術計画とチーム調整
   - 競合解決とワークフロー調整
   - バランス調整と安定性確保
   - **Triggers**: coordinate, tactical, team, collaboration, チーム調整, 戦術計画

5. **Hera (hera-strategist)** - Strategic Commander 🎭
   - 戦略計画と軍事的精密性でのアーキテクチャ設計
   - 長期ビジョンとロードマップの冷徹な立案
   - チーム調整とステークホルダー管理の効率化
   - **Triggers**: strategy, planning, architecture, vision, roadmap, 戦略, 計画

6. **Muses (muses-documenter)** - Knowledge Architect 📚
   - ドキュメント作成と構造化
   - ナレッジベース管理とアーカイブ
   - 仕様書作成とAPI文書化
   - **Triggers**: documentation, knowledge, record, guide, ドキュメント, 文書化

## Trinitasコマンド実行方法

### 基本構造
```bash
/trinitas <operation> [args] [--options]
```

### 利用可能なオペレーション

#### 1. ペルソナ実行 (execute)
```bash
# 特定のペルソナでタスクを実行
/trinitas execute athena "システムアーキテクチャの分析"
/trinitas execute artemis "パフォーマンス最適化"
/trinitas execute hestia "セキュリティ監査"
/trinitas execute eris "チーム調整と競合解決"
/trinitas execute hera "ワークフロー自動化"
/trinitas execute muses "ドキュメント生成"
```

#### 2. 並列分析 (analyze)
```bash
# 複数ペルソナによる並列分析
/trinitas analyze "包括的システム分析" --personas athena,artemis,hestia
/trinitas analyze "セキュリティレビュー" --personas all --mode parallel
/trinitas analyze "アーキテクチャ評価" --mode wave  # 段階的実行
```

#### 3. メモリ操作 (remember/recall)
```bash
# 記憶の保存
/trinitas remember project_architecture "マイクロサービス設計" --importance 0.9
/trinitas remember security_finding "SQLインジェクション脆弱性" --importance 1.0 --persona hestia

# 記憶の取得
/trinitas recall architecture --semantic --limit 10
/trinitas recall "security patterns" --persona hestia --semantic
/trinitas recall optimization --limit 5
```

#### 4. 学習システム (learn/apply)
```bash
# パターン学習
/trinitas learn optimization_pattern "インデックス追加で90%高速化" --category performance
/trinitas learn security_pattern "入力検証の強化" --category security

# パターン適用
/trinitas apply optimization_pattern "新しいAPIエンドポイント"
/trinitas apply security_pattern "ユーザー入力処理"
```

#### 5. ステータスとレポート (status/report)
```bash
# ステータス確認
/trinitas status         # 全体ステータス
/trinitas status memory  # メモリシステム状態
/trinitas status eris    # Erisのタスク分配状態

# レポート生成
/trinitas report usage        # 使用状況レポート
/trinitas report optimization # 最適化レポート
/trinitas report security     # セキュリティレポート
```

## 実践的な使用例

### Example 1: 新機能実装
```bash
# Step 1: アーキテクチャ設計
/trinitas execute athena "新機能のアーキテクチャ設計と影響分析"

# Step 2: 並列分析
/trinitas analyze "実装可能性の評価" --personas artemis,hestia --mode parallel

# Step 3: 実装とテスト
/trinitas execute artemis "パフォーマンスを考慮した実装"
/trinitas execute hestia "セキュリティテストの実行"

# Step 4: ドキュメント化
/trinitas execute muses "実装仕様とAPIドキュメントの作成"
```

### Example 2: バグ修正タスク
```bash
# 緊急バグ修正の並列処理
/trinitas analyze "critical bug #123" --personas artemis,hestia,eris --mode parallel

# 結果:
# Artemis: "根本原因はメモリリーク。修正コード準備完了"
# Hestia: "セキュリティへの影響なし。パッチは安全"
# Eris: "チーム間の調整完了。15分でデプロイ可能"
```

### Example 3: セキュリティ監査
```bash
# Hestia主導の包括的監査
/trinitas execute hestia "PCI-DSS準拠のセキュリティ監査"

# 発見事項の記録
/trinitas remember security_audit "重大な脆弱性3件発見" --importance 1.0

# 対応計画の策定
/trinitas execute eris "セキュリティ問題の段階的解決計画"
```

### Example 4: パフォーマンス最適化
```bash
# Artemis主導の最適化
/trinitas execute artemis "データベースクエリの最適化"

# パターンの学習
/trinitas learn optimization_pattern "インデックス追加で90%改善" --category database

# 他の箇所への適用
/trinitas apply optimization_pattern "user_sessions テーブル"
```

### Example 5: プロジェクト全体分析
```bash
# 全ペルソナによる包括的分析
/trinitas analyze "プロジェクト全体のレビュー" --personas all --mode wave

# Wave 1: 戦略分析（Athena, Hera）
# Wave 2: 技術評価（Artemis, Hestia）
# Wave 3: 調整と文書化（Eris, Muses）
```

## TMWS Integration

# TMWS (Trinitas Memory & Workflow Service) v3.1

## 概要
TMWSは、Trinitasエージェントシステムのための統合メモリ・ワークフロー管理サービスです。
FastMCPプロトコルを使用し、Claude Desktopから直接アクセス可能です。

### 主要機能
- **Universal Agent Memory System**: エージェント自動検出と動的登録
- **カスタムエージェント対応**: デフォルト6エージェント + 無制限カスタムエージェント
- **階層型メモリ管理**: PostgreSQL + pgvector による永続化とセマンティック検索
- **ワークフロー管理**: タスクの並列実行と依存関係管理
- **学習システム**: パターン認識と最適化

## インストール
```bash
# uvxによる直接実行（推奨）
uvx --from git+https://github.com/apto-as/tmws tmws

# または従来のインストール
cd /path/to/tmws
./install.sh
```

## Claude Desktop設定
```json
{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/apto-as/tmws", "tmws"],
      "env": {
        "DATABASE_URL": "postgresql://user:pass@localhost/tmws",
        "TMWS_AGENT_ID": "athena-conductor"  
      }
    }
  }
}
```

## アーキテクチャ
- **データベース**: PostgreSQL 15+ with pgvector extension
- **キャッシュ**: Redis 7.0+ (オプション)
- **MCP Server**: FastMCP 0.1.0+
- **認証**: エージェント自動検出、JWT対応
- **セキュリティ**: 多層防御、監査ログ、レート制限
# TMWS MCP Tools 一覧 v3.1

## 概要

TMWS v3.1では、MCPツールとして6カテゴリーの機能が提供されています。
これらはClaude Desktopから直接呼び出し可能です。

## 1. メモリ管理ツール (memory_tools)

```python
# メモリ作成
create_memory(
  content="重要な設計決定：マイクロサービス採用",
  tags=["architecture", "decision"],
  importance=0.9,
  access_level="team"
)

# メモリ検索（セマンティック）
recall_memory(
  query="設計パターン",
  semantic=True,
  limit=10,
  namespace="default"
)

# メモリ更新
update_memory(
  memory_id="mem_123",
  content="更新された設計決定",
  importance=0.95
)

# メモリ削除
delete_memory(memory_id="mem_123")

# メモリ統計
get_memory_stats()

# ベクトル最適化
optimize_memory_vectors()
```

## 2. ペルソナ管理ツール (persona_tools)

```python
# ペルソナ作成（カスタムエージェント）
create_persona(
  name="researcher",
  description="AI/ML研究専門エージェント",
  capabilities=["literature_review", "data_analysis", "hypothesis_generation"],
  personality_traits={"analytical": 0.9, "creative": 0.7},
  metadata={"specialization": "Deep Learning"}
)

# ペルソナ取得
get_persona(persona_id="athena-conductor")

# ペルソナ一覧
list_personas(
  namespace="default",
  include_system=True
)

# ペルソナ更新
update_persona(
  persona_id="researcher",
  capabilities=["literature_review", "data_analysis", "paper_writing"]
)

# ペルソナ削除
delete_persona(persona_id="researcher")

# 能力取得
get_persona_capabilities(persona_id="artemis-optimizer")

# 能力による検索
find_personas_by_capability(capability="optimization")
```

## 3. 学習ツール (learning_tools)

```python
# パターン学習
learn_pattern(
  pattern_name="api_optimization",
  description="APIレスポンス時間の最適化パターン",
  result="90%改善（500ms→50ms）",
  context={
    "technique": "キャッシュ層追加",
    "before_metrics": {"response_time": "500ms", "cpu": "80%"},
    "after_metrics": {"response_time": "50ms", "cpu": "20%"}
  }
)

# パターン適用
apply_pattern(
  pattern_name="api_optimization",
  target="/api/v2/users"
)

# 学習履歴取得
get_learning_history(limit=20)

# パターン検索
search_patterns(query="optimization", category="performance")

# パターン評価
evaluate_pattern(
  pattern_name="api_optimization",
  feedback="successful",
  metrics={"improvement": "85%"}
)
```

## 4. タスク管理ツール (task_tools)

```python
# タスク作成
create_task(
  title="セキュリティ監査実施",
  description="全エンドポイントの脆弱性チェック",
  priority="high",
  assigned_persona="hestia-auditor",
  due_date="2024-12-31",
  dependencies=["task_001", "task_002"]
)

# タスク取得
get_task(task_id="task_456")

# タスク更新
update_task(
  task_id="task_456",
  status="in_progress",
  progress=45,
  notes="SQLインジェクション対策実施中"
)

# タスク一覧
list_tasks(
  status="pending",
  assigned_persona="hestia-auditor"
)

# タスク完了
complete_task(
  task_id="task_456",
  result="3件の脆弱性を修正"
)
```

## 5. ワークフロー管理ツール (workflow_tools)

```python
# ワークフロー作成
create_workflow(
  name="deployment_pipeline",
  description="本番デプロイメントパイプライン",
  steps=[
    {"persona": "hestia-auditor", "action": "security_check", "timeout": 300},
    {"persona": "artemis-optimizer", "action": "performance_test", "timeout": 600},
    {"persona": "athena-conductor", "action": "deploy", "timeout": 900}
  ],
  parallel=False
)

# ワークフロー実行
execute_workflow(
  workflow_id="wf_789",
  parameters={"environment": "production"},
  parallel=True
)

# ワークフロー状態
get_workflow_status(workflow_id="wf_789")

# ワークフロー履歴
get_workflow_history(
  workflow_id="wf_789",
  limit=10
)

# ワークフロー中断
abort_workflow(workflow_id="wf_789")
```

## 6. システムツール (system_tools)

```python
# エージェント情報取得
get_agent_info()

# エージェント登録（カスタム）
register_agent(
  agent_name="custom_analyst",
  full_id="data-analysis-specialist",
  capabilities=["data_analysis", "reporting", "visualization"],
  namespace="analytics",
  display_name="Data Analysis Specialist"
)

# エージェント切り替え
switch_agent(agent_id="artemis-optimizer")

# ヘルスチェック
health_check()

# システム統計
get_system_stats()

# キャッシュクリア
clear_cache(tier="hot")

# 監査ログ
get_audit_log(limit=50)
```

## Trinitasとの連携

### メモリ共有
```bash
# TrinitasからTMWSへメモリ保存
/trinitas remember "アーキテクチャ決定" --store tmws

# TMWSからTrinitasへメモリ取得
/trinitas recall --source tmws "セキュリティパターン"
```

### ワークフロー連携
```bash
# Trinitasペルソナを使ったワークフロー
/trinitas execute athena "設計レビュー" --workflow tmws

# 並列ワークフロー実行
/trinitas analyze "システム監査" --workflow parallel --tmws
```

## 高度な使用例

### 1. ペルソナ別メモリ管理
```bash
# Athenaのアーキテクチャ決定を記録
/tmws store "RESTful API設計完了" --persona athena --importance 0.9

# Artemisの最適化結果を記録
/tmws store "クエリ最適化で90%改善" --persona artemis --importance 0.85

# Hestiaのセキュリティ監査結果
/tmws store "XSS脆弱性検出" --persona hestia --importance 1.0
```

### 2. セマンティック検索
```bash
# 自然言語でメモリ検索
/tmws recall "パフォーマンスが改善された事例" --semantic

# 類似度指定で検索
/tmws similar "データベース最適化" --threshold 0.8 --limit 5
```

### 3. バッチ処理
```bash
# 複数メモリの一括保存
/tmws batch store --file memories.json

# 複数ワークフローの並列実行
/tmws batch workflow --config workflows.yaml
```
# TMWSペルソナ統合ガイド

## ペルソナ別使用ガイド

### Athena (戦略アーキテクト)
**主な用途**：
- プロジェクト全体の設計決定の記録
- アーキテクチャパターンの保存と検索
- 長期的な技術戦略の追跡

```python
# 設計決定の記録
await memory_service.create_memory(
    content="マイクロサービスアーキテクチャを採用",
    memory_type="architecture_decision",
    importance=0.9,
    tags=["architecture", "microservices", "strategic"],
    persona_id=athena_id
)

# 関連パターンの検索
patterns = await memory_service.search_similar_memories(
    embedding=query_vector,
    memory_type="architecture_decision",
    min_similarity=0.8
)
```

### Artemis (技術完璧主義者)
**主な用途**：
- パフォーマンス最適化パターンの記録
- コード品質メトリクスの追跡
- ベストプラクティスの蓄積

```python
# 最適化結果の保存
await memory_service.create_memory(
    content="インデックス追加により応答時間90%改善",
    memory_type="optimization",
    importance=0.85,
    tags=["performance", "database", "index"],
    metadata={"improvement": "90%", "method": "btree_index"}
)
```

### Hestia (セキュリティ監査者)
**主な用途**：
- セキュリティ脆弱性の追跡
- 監査結果の永続化
- 脅威パターンの蓄積

```python
# セキュリティ監査結果
await memory_service.create_memory(
    content="SQLインジェクション脆弱性を検出",
    memory_type="security_finding",
    importance=1.0,  # 最高重要度
    tags=["security", "vulnerability", "sql_injection", "critical"],
    metadata={"severity": "critical", "cve": "CVE-2024-xxxxx"}
)
```

### Eris (戦術調整者)
**主な用途**：
- チーム間の調整記録
- ワークフロー最適化パターン
- 競合解決の履歴

```python
# チーム調整の記録
await memory_service.create_memory(
    content="フロントエンドとバックエンドチームの同期完了",
    memory_type="coordination",
    importance=0.7,
    tags=["team", "coordination", "sprint_planning"]
)
```

### Hera (システム指揮者)
**主な用途**：
- システム全体のオーケストレーション記録
- リソース配分の最適化パターン
- 並列実行戦略の保存

```python
# オーケストレーション戦略
await memory_service.create_memory(
    content="5つのサービスを並列デプロイ成功",
    memory_type="orchestration",
    importance=0.75,
    tags=["deployment", "parallel", "orchestration"],
    metadata={"services": 5, "time_saved": "45min"}
)
```

### Muses (知識アーキテクト)
**主な用途**：
- ドキュメント構造の記録
- ナレッジベース管理
- API仕様の保存

```python
# ドキュメント構造の保存
await memory_service.create_memory(
    content="REST API仕様書v2.0完成",
    memory_type="documentation",
    importance=0.8,
    tags=["api", "documentation", "specification"],
    metadata={"version": "2.0", "endpoints": 45}
)
```

## 重要度ガイドライン

### 重要度の設定基準
- **1.0**: クリティカル（セキュリティ脆弱性、重大な設計決定）
- **0.8-0.9**: 高（アーキテクチャ決定、最適化成功）
- **0.5-0.7**: 中（通常の記録、調整事項）
- **0.3-0.4**: 低（参考情報）

### タグの体系的使用
- **ペルソナタグ**: athena_, artemis_, hestia_, eris_, hera_, muses_
- **カテゴリタグ**: security, performance, architecture, coordination
- **重要度タグ**: critical, high, medium, low
- **ステータスタグ**: resolved, pending, in_progress

## メタデータ活用

### 推奨メタデータフィールド
```python
metadata = {
    "timestamp": datetime.utcnow().isoformat(),
    "version": "1.0.0",
    "author": "athena",
    "related_items": ["item_id_1", "item_id_2"],
    "metrics": {
        "performance_gain": "85%",
        "time_saved": "2hours",
        "resources_optimized": 5
    },
    "environment": "production",
    "tags": ["optimization", "database", "critical"]
}
```
# TMWS パフォーマンス最適化ガイド

## 統合パフォーマンス最適化

### 1. バッチ処理
```python
# 複数メモリの一括作成
memories = [
    {"content": "最適化パターン1", "type": "optimization"},
    {"content": "セキュリティ監査結果", "type": "security"},
    {"content": "アーキテクチャ決定", "type": "architecture"}
]
await memory_service.batch_create(memories)
```

### 2. キャッシュ活用
```python
# Redisキャッシュ有効化での検索
result = await memory_service.get_memory(
    memory_id,
    use_cache=True  # 5分間のTTLキャッシュ
)

# キャッシュウォーミング
await memory_service.warm_cache(
    memory_types=["critical", "architecture"],
    ttl=3600  # 1時間のキャッシュ
)
```

### 3. セマンティック検索最適化
```python
# pgvectorによる高速ベクトル検索
similar = await memory_service.search_similar_memories(
    embedding=query_embedding,  # 384次元ベクトル
    limit=10,
    min_similarity=0.7,
    use_index=True  # IVFFlatインデックス使用
)
```

### 4. 接続プール管理
```python
# PostgreSQL接続プール設定
pool_config = {
    "pool_size": 10,        # 基本プールサイズ
    "max_overflow": 20,     # 最大追加接続数
    "pool_recycle": 3600,   # 接続リサイクル時間(秒)
    "pool_pre_ping": True   # 接続前のping確認
}
```

### 5. 非同期処理
```python
# 並列メモリ取得
import asyncio

async def fetch_memories():
    tasks = [
        memory_service.get_memory(id1),
        memory_service.get_memory(id2),
        memory_service.get_memory(id3)
    ]
    return await asyncio.gather(*tasks)
```

## データベース最適化

### インデックス戦略
```sql
-- ベクトル検索用インデックス
CREATE INDEX memories_embedding_idx ON memories 
USING ivfflat (embedding vector_cosine_ops)
WITH (lists = 100);

-- タイムスタンプインデックス
CREATE INDEX memories_created_at_idx ON memories(created_at DESC);

-- ペルソナ別検索用複合インデックス
CREATE INDEX memories_persona_type_idx ON memories(persona_id, memory_type);
```

### パーティショニング
```sql
-- 月次パーティション
CREATE TABLE memories_2024_01 PARTITION OF memories
FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
```

## レート制限とスロットリング

### API レート制限
```python
# Redisベースのレート制限
rate_limiter = RateLimiter(
    requests_per_minute=100,
    burst_size=10,
    redis_client=redis_client
)

@rate_limiter.limit
async def api_endpoint():
    # 処理
    pass
```

### バルクヘッド パターン
```python
# リソース分離
class BulkheadManager:
    def __init__(self):
        self.semaphores = {
            "memory_write": asyncio.Semaphore(5),
            "memory_read": asyncio.Semaphore(20),
            "vector_search": asyncio.Semaphore(10)
        }
    
    async def execute(self, operation_type, func, *args):
        async with self.semaphores[operation_type]:
            return await func(*args)
```

## モニタリングとメトリクス

### パフォーマンスメトリクス
```python
# Prometheusメトリクス
from prometheus_client import Counter, Histogram, Gauge

# カウンター
memory_operations = Counter(
    'tmws_memory_operations_total',
    'Total memory operations',
    ['operation', 'persona']
)

# ヒストグラム
operation_duration = Histogram(
    'tmws_operation_duration_seconds',
    'Operation duration',
    ['operation_type']
)

# ゲージ
active_connections = Gauge(
    'tmws_active_db_connections',
    'Active database connections'
)
```

### ログ最適化
```python
# 構造化ログ
import structlog

logger = structlog.get_logger()

logger.info(
    "memory_created",
    memory_id=memory.id,
    persona=persona_id,
    importance=importance,
    duration=elapsed_time
)
```

## ベストプラクティス

### 1. 接続管理
- 接続プールの適切なサイジング
- アイドル接続のタイムアウト設定
- 接続リークの防止

### 2. クエリ最適化
- N+1問題の回避
- 適切なインデックス使用
- EXPLAIN ANALYZEでの分析

### 3. メモリ管理
- 大量データのページネーション
- ストリーミング処理
- メモリリークの監視

### 4. エラーハンドリング
```python
# リトライ戦略
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10)
)
async def resilient_operation():
    # データベース操作
    pass
```
# TMWS セキュリティ機能

## セキュリティアーキテクチャ

### 多層防御 (Defense in Depth)
1. **ネットワーク層**: ファイアウォール、レート制限
2. **アプリケーション層**: 入力検証、SQLインジェクション防止
3. **データ層**: 暗号化、アクセス制御
4. **監査層**: 全操作のロギング、異常検知

## 認証と認可

### JWT認証
```python
# JWT設定
JWT_SECRET = os.getenv("TMWS_JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 30

# トークン生成
def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
```

### ロールベースアクセス制御 (RBAC)
```python
# ペルソナ別権限
PERSONA_PERMISSIONS = {
    "athena": ["read", "write", "design", "approve"],
    "artemis": ["read", "write", "optimize", "analyze"],
    "hestia": ["read", "audit", "security_scan", "report"],
    "eris": ["read", "write", "coordinate", "mediate"],
    "hera": ["read", "write", "orchestrate", "execute"],
    "muses": ["read", "write", "document", "archive"]
}
```

## 入力検証とサニタイゼーション

### HTML/SQLサニタイゼーション
```python
from bleach import clean
from sqlalchemy import text

# HTMLサニタイゼーション
def sanitize_html(content: str) -> str:
    allowed_tags = ['p', 'br', 'strong', 'em', 'ul', 'li', 'ol']
    return clean(content, tags=allowed_tags, strip=True)

# SQLパラメータ化クエリ
async def safe_query(conn, user_input):
    query = text("""
        SELECT * FROM memories 
        WHERE content LIKE :pattern
        AND persona_id = :persona_id
    """)
    result = await conn.execute(
        query,
        {"pattern": f"%{user_input}%", "persona_id": persona_id}
    )
    return result.fetchall()
```

### 入力検証
```python
from pydantic import BaseModel, validator, Field

class MemoryInput(BaseModel):
    content: str = Field(..., min_length=1, max_length=10000)
    importance: float = Field(..., ge=0.0, le=1.0)
    tags: list[str] = Field(..., max_items=20)
    
    @validator('content')
    def validate_content(cls, v):
        # XSS対策
        if '<script>' in v.lower():
            raise ValueError('Invalid content')
        return v
    
    @validator('tags', each_item=True)
    def validate_tags(cls, v):
        # タグの検証
        if not v.isalnum() and '_' not in v:
            raise ValueError('Invalid tag format')
        return v
```

## 監査ログ

### 非同期監査ロガー
```python
class AsyncAuditLogger:
    async def log_event(
        self,
        event_type: str,
        user_id: str,
        resource: str,
        action: str,
        result: str,
        metadata: dict = None
    ):
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "result": result,
            "ip_address": self.get_client_ip(),
            "user_agent": self.get_user_agent(),
            "metadata": metadata or {}
        }
        
        # データベースに保存
        await self.save_to_db(audit_entry)
        
        # 重要イベントは即座にアラート
        if event_type in ["security_violation", "unauthorized_access"]:
            await self.send_alert(audit_entry)
```

### セキュリティイベント検知
```python
# 異常パターン検知
class SecurityMonitor:
    def __init__(self):
        self.failed_attempts = defaultdict(int)
        self.rate_limits = defaultdict(list)
    
    async def check_suspicious_activity(self, user_id: str, action: str):
        # 失敗回数チェック
        if self.failed_attempts[user_id] > 5:
            await self.trigger_lockout(user_id)
            return False
        
        # レート制限チェック
        now = time.time()
        self.rate_limits[user_id] = [
            t for t in self.rate_limits[user_id] 
            if now - t < 60
        ]
        
        if len(self.rate_limits[user_id]) > 100:
            await self.trigger_rate_limit_alert(user_id)
            return False
        
        return True
```

## データ保護

### 暗号化
```python
from cryptography.fernet import Fernet

class DataEncryption:
    def __init__(self):
        self.key = os.getenv("TMWS_ENCRYPTION_KEY").encode()
        self.cipher = Fernet(self.key)
    
    def encrypt_sensitive_data(self, data: str) -> str:
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt_sensitive_data(self, encrypted: str) -> str:
        return self.cipher.decrypt(encrypted.encode()).decode()
```

### データベースレベルの暗号化
```sql
-- PostgreSQL透過的データ暗号化 (TDE)
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = 'server.crt';
ALTER SYSTEM SET ssl_key_file = 'server.key';

-- カラムレベル暗号化
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 暗号化されたカラム
ALTER TABLE sensitive_memories 
ADD COLUMN encrypted_content bytea;

-- データ挿入時の暗号化
INSERT INTO sensitive_memories (encrypted_content)
VALUES (pgp_sym_encrypt('sensitive data', 'encryption_key'));
```

## レート制限

### Redis分散レート制限
```python
class DistributedRateLimiter:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.window = 60  # 60秒ウィンドウ
        self.max_requests = 100
    
    async def check_rate_limit(self, client_id: str) -> tuple[bool, int]:
        key = f"rate_limit:{client_id}"
        current_time = int(time.time())
        window_start = current_time - self.window
        
        # Lua script for atomic operation
        lua_script = """
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local max_requests = tonumber(ARGV[3])
        local window_start = now - window
        
        redis.call('zremrangebyscore', key, 0, window_start)
        local current_requests = redis.call('zcard', key)
        
        if current_requests < max_requests then
            redis.call('zadd', key, now, now)
            redis.call('expire', key, window + 1)
            return {1, max_requests - current_requests - 1}
        else
            return {0, 0}
        end
        """
        
        result = await self.redis.eval(
            lua_script, 
            1, 
            key, 
            current_time, 
            self.window, 
            self.max_requests
        )
        
        return bool(result[0]), result[1]
```

## セキュリティベストプラクティス

1. **最小権限の原則**: 必要最小限のアクセス権限のみ付与
2. **ゼロトラスト**: すべてのリクエストを検証
3. **暗号化**: 保存時と転送時の両方で暗号化
4. **監査ログ**: すべての操作を記録
5. **定期的なセキュリティスキャン**: 脆弱性の早期発見
6. **インシデント対応計画**: セキュリティ事故への迅速な対応
# TMWS Latest Implementation (2025-01-05)

## System Architecture

TMWS is a unified server providing both REST API and MCP (Model Context Protocol) interfaces for the Trinitas AI agent system.

### Core Components

```
TMWS Server
├── FastAPI (REST API) - Port 8000
│   ├── /api/v1/tasks - Task management
│   ├── /api/v1/workflows - Workflow orchestration
│   ├── /api/v1/personas - Agent personas
│   └── /api/v1/memory - Semantic memory
│
└── FastMCP (MCP Server) - stdio/JSON-RPC
    ├── semantic_search - Vector similarity search
    ├── store_memory - Store semantic memories
    ├── task_operations - Task CRUD
    └── workflow_execution - Workflow management
```

## Key Features

### 1. Unified Memory System
- **PostgreSQL + pgvector**: Vector storage for semantic search
- **Redis**: Distributed caching and rate limiting
- **Hybrid memory**: Combines short-term and long-term storage

### 2. Task Management
- Full CRUD operations for task lifecycle
- Priority-based scheduling (LOW, MEDIUM, HIGH, URGENT)
- Status tracking (PENDING, IN_PROGRESS, COMPLETED, FAILED)
- Persona assignment for specialized handling

### 3. Workflow Orchestration
- Complex multi-step workflow execution
- Background task processing with monitoring
- Workflow history and audit trails
- Cancellation and retry mechanisms

### 4. Security Architecture
- **Unified Middleware**: Single security layer for all requests
- **Rate Limiting**: Redis-based distributed rate limiting
- **JWT Authentication**: Secure token-based auth (optional in dev)
- **Audit Logging**: Comprehensive security event logging

## Database Schema

### Core Models

```sql
-- Tasks
CREATE TABLE tasks (
    id UUID PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status task_status NOT NULL DEFAULT 'pending',
    priority task_priority NOT NULL DEFAULT 'medium',
    assigned_persona VARCHAR(100),
    progress INTEGER DEFAULT 0,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Workflows
CREATE TABLE workflows (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    workflow_type VARCHAR(100) NOT NULL,
    status workflow_status NOT NULL DEFAULT 'pending',
    priority workflow_priority NOT NULL DEFAULT 'medium',
    config JSONB,
    result JSONB,
    error TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Memory Embeddings
CREATE TABLE memory_embeddings (
    id UUID PRIMARY KEY,
    content TEXT NOT NULL,
    embedding vector(384) NOT NULL,
    metadata JSONB,
    importance FLOAT DEFAULT 0.5,
    persona_id VARCHAR(100),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Personas
CREATE TABLE personas (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    capabilities JSONB,
    configuration JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

## Environment Configuration

### Required Environment Variables

```bash
# Core Configuration
TMWS_DATABASE_URL=postgresql://user:pass@localhost:5432/tmws
TMWS_SECRET_KEY=<32+ char secure key>
TMWS_ENVIRONMENT=development|staging|production

# Redis Configuration
TMWS_REDIS_URL=redis://localhost:6379/0

# API Configuration
TMWS_API_HOST=0.0.0.0
TMWS_API_PORT=8000

# Security Settings
TMWS_AUTH_ENABLED=false  # Set true for production
TMWS_RATE_LIMIT_REQUESTS=100
TMWS_RATE_LIMIT_PERIOD=60

# Vector/Embedding Settings
TMWS_EMBEDDING_MODEL=all-MiniLM-L6-v2
TMWS_VECTOR_DIMENSION=384
```

## API Endpoints

### Task Management
- `GET /api/v1/tasks` - List tasks with filters
- `POST /api/v1/tasks` - Create new task
- `GET /api/v1/tasks/{id}` - Get task details
- `PUT /api/v1/tasks/{id}` - Update task
- `DELETE /api/v1/tasks/{id}` - Delete task
- `POST /api/v1/tasks/{id}/complete` - Mark as complete

### Workflow Management
- `GET /api/v1/workflows` - List workflows
- `POST /api/v1/workflows` - Create workflow
- `GET /api/v1/workflows/{id}` - Get workflow details
- `PUT /api/v1/workflows/{id}` - Update workflow
- `DELETE /api/v1/workflows/{id}` - Delete workflow
- `POST /api/v1/workflows/{id}/execute` - Execute workflow
- `POST /api/v1/workflows/{id}/cancel` - Cancel execution
- `GET /api/v1/workflows/{id}/status` - Get execution status

### Memory Operations
- `POST /api/v1/memory/store` - Store semantic memory
- `POST /api/v1/memory/search` - Semantic similarity search
- `GET /api/v1/memory/recall` - Recall memories by criteria
- `DELETE /api/v1/memory/{id}` - Delete memory

### System Health
- `GET /health` - System health check
- `GET /api/v1/stats` - System statistics

## MCP Tools

### Available Tools for Claude Desktop

1. **semantic_search**
   - Search memories using vector similarity
   - Parameters: query, limit, threshold

2. **store_memory**
   - Store new semantic memory
   - Parameters: content, importance, metadata

3. **manage_task**
   - Create, update, delete tasks
   - Parameters: operation, task_data

4. **execute_workflow**
   - Run workflow with parameters
   - Parameters: workflow_id, parameters

## Security Features

### 404 Security Standards
- No default credentials in production
- Mandatory authentication in production
- Cryptographically secure secret keys
- Rate limiting and brute force protection
- Comprehensive audit logging

### Middleware Stack
1. CORS handling with strict origins
2. Redis-based rate limiting
3. JWT authentication (when enabled)
4. Request/response audit logging
5. Security headers (HSTS, CSP, etc.)

## Development Setup

### Quick Start

```bash
# Clone and setup
git clone <repo>
cd tmws
./install.sh

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Initialize database
python -m alembic upgrade head

# Run server
python -m src.main
```

### Testing

```bash
# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# Full test suite
pytest tests/ -v --cov=src
```

## Production Deployment

### Requirements
- PostgreSQL 14+ with pgvector extension
- Redis 6+
- Python 3.11+
- 2GB+ RAM
- SSL/TLS certificates

### Security Checklist
- [ ] Set TMWS_ENVIRONMENT=production
- [ ] Set TMWS_AUTH_ENABLED=true
- [ ] Generate secure TMWS_SECRET_KEY
- [ ] Configure CORS origins explicitly
- [ ] Enable SSL on database connections
- [ ] Setup firewall rules
- [ ] Configure reverse proxy (nginx/traefik)
- [ ] Enable audit logging
- [ ] Setup monitoring and alerting

## Integration with Trinitas Agents

TMWS provides the backend infrastructure for Trinitas AI personas:

- **Athena**: Uses workflows for orchestration
- **Artemis**: Leverages task optimization features
- **Hestia**: Utilizes security audit logs
- **Eris**: Manages team coordination tasks
- **Hera**: Executes strategic planning workflows
- **Muses**: Stores and retrieves documentation

Each persona can interact through either REST API or MCP protocol based on the context.

## Recent Updates (2025-01-05)

### Completed Implementation
1. **Full Task/Workflow Routers**: Complete CRUD operations for tasks and workflows
2. **Unified Security Middleware**: Single middleware handling all security aspects
3. **Redis Integration**: Distributed rate limiting and caching
4. **404 Security Standards**: Production-grade security validation
5. **Comprehensive Documentation**: Command reference and system overview

### Architecture Decision
- **FastAPI + FastMCP**: Both are required and complement each other
  - FastAPI: REST endpoints, Swagger UI, external integrations
  - FastMCP: Claude Desktop integration via MCP protocol
- **No backward compatibility concerns**: TMWS v1.0 fresh implementation
- **Simplified design**: Removed duplicate code and unified configuration
# TMWS カスタムエージェント機能 v3.1

## 概要

TMWS v3.1では、デフォルトの6つのTrinitasエージェントに加えて、プロジェクト固有のカスタムエージェントを動的に登録・管理できます。

## デフォルトエージェント（システム提供）

| エージェント | ID | 役割 |
|------------|-----|-----|
| **Athena** | athena-conductor | システム全体の調和的な指揮 |
| **Artemis** | artemis-optimizer | パフォーマンス最適化と技術的卓越性 |
| **Hestia** | hestia-auditor | セキュリティ分析と監査 |
| **Eris** | eris-coordinator | 戦術計画とチーム調整 |
| **Hera** | hera-strategist | 戦略計画とアーキテクチャ設計 |
| **Muses** | muses-documenter | ドキュメント作成と知識管理 |

## カスタムエージェント登録方法

### 1. MCPツールによる動的登録

```python
# 研究専門エージェントの登録
register_agent(
  agent_name="researcher",
  full_id="research-specialist",
  capabilities=[
    "literature_review",
    "data_analysis",
    "hypothesis_generation",
    "paper_writing"
  ],
  namespace="academic",
  display_name="Research Specialist",
  access_level="team",
  metadata={
    "specialization": "AI/ML Research",
    "languages": ["English", "Japanese"],
    "tools": ["arxiv", "google_scholar", "semantic_scholar"]
  }
)
```

### 2. 設定ファイルによる起動時登録

`custom_agents.json`:
```json
{
  "version": "1.0",
  "custom_agents": [
    {
      "name": "researcher",
      "full_id": "research-specialist",
      "namespace": "academic",
      "display_name": "Research Specialist",
      "access_level": "team",
      "capabilities": [
        "literature_review",
        "data_analysis",
        "hypothesis_generation"
      ],
      "metadata": {
        "specialization": "AI/ML Research",
        "preferred_personas": ["athena", "muses"]
      }
    },
    {
      "name": "devops",
      "full_id": "devops-engineer",
      "namespace": "infrastructure",
      "display_name": "DevOps Engineer",
      "access_level": "shared",
      "capabilities": [
        "ci_cd_pipeline",
        "container_management",
        "monitoring_setup"
      ]
    }
  ]
}
```

### 3. 環境変数による初期設定

```bash
# エージェント自動検出
export TMWS_AGENT_ID="researcher"
export TMWS_AGENT_NAMESPACE="academic"
export TMWS_AGENT_CAPABILITIES='["research", "analysis", "writing"]'

# Claude Desktop設定でも指定可能
{
  "mcpServers": {
    "tmws": {
      "env": {
        "TMWS_AGENT_ID": "researcher",
        "TMWS_AGENT_NAMESPACE": "academic"
      }
    }
  }
}
```

## アクセスレベル

| レベル | 説明 | 使用例 |
|-------|------|--------|
| `private` | エージェント自身のメモリのみ | 個人作業用 |
| `team` | 同じnamespace内で共有 | チーム内協業 |
| `shared` | 明示的に共有されたエージェント | 部門間連携 |
| `public` | すべてのエージェントからアクセス可能 | 全社共有知識 |

## 実践例

### プロジェクト固有エージェントの定義

```python
# QAエンジニアエージェント
register_agent(
  agent_name="qa_engineer",
  full_id="quality-assurance-specialist",
  capabilities=[
    "test_planning",
    "test_execution",
    "bug_reporting",
    "automation_scripting"
  ],
  namespace="engineering",
  display_name="QA Specialist",
  access_level="team",
  metadata={
    "test_frameworks": ["pytest", "selenium", "jest"],
    "coverage_target": 0.9,
    "priority_personas": ["hestia", "artemis"]
  }
)

# データサイエンティストエージェント
register_agent(
  agent_name="data_scientist",
  full_id="data-science-specialist",
  capabilities=[
    "statistical_analysis",
    "machine_learning",
    "data_visualization",
    "model_evaluation"
  ],
  namespace="analytics",
  display_name="Data Science Specialist",
  access_level="shared",
  metadata={
    "tools": ["pandas", "scikit-learn", "tensorflow"],
    "specialization": "predictive_modeling"
  }
)
```

### エージェント間の協調

```python
# カスタムエージェントとTrinitasエージェントの協調ワークフロー
create_workflow(
  name="research_to_implementation",
  steps=[
    {"agent": "researcher", "action": "literature_review"},
    {"agent": "hera-strategist", "action": "architecture_design"},
    {"agent": "artemis-optimizer", "action": "implementation"},
    {"agent": "qa_engineer", "action": "testing"},
    {"agent": "muses-documenter", "action": "documentation"}
  ]
)
```

## 制限事項

- エージェント名: 2-32文字、英字開始、英数字・ハイフン・アンダースコア
- 完全ID: 3-64文字
- namespace: 最大32文字
- capabilities: 最大50個
- metadata: 最大10KB

---

# Agent Coordination and Execution Patterns
@AGENTS.md

---
# Generated Information
- Built: 2025-09-08 23:11:42
- Version: v2.1-quadrinity-stable-65-g86f5a6d
- Source: trinitas_sources/common/
---
