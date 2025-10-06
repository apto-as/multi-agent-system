# TMWS ハイブリッドクラウド移行ロードマップ

## 概要

本ドキュメントは、TMWSをクラウド・ローカルハイブリッド型メモリシステムへ移行するための詳細な実装計画です。

**移行期間**: 6ヶ月（26週間）
**アプローチ**: 段階的・Feature Flag駆動・ロールバック可能

---

## Phase 0: 準備とセキュリティ設計 ✅

**期間**: Week 0
**成果物**:
- ✅ セキュリティポリシー文書作成 (`HYBRID_CLOUD_SECURITY_POLICY.md`)
- ✅ アーキテクチャ設計書作成
- ✅ Trinitas 6ペルソナによる妥当性評価完了

---

## Phase 1: 基盤構築（Multi-Database Support） ✅

**期間**: Week 1-2
**担当**: Artemis（技術実装）+ Athena（アーキテクチャレビュー）

### 実装内容

#### 1.1 メモリスコープ定義
- ✅ `src/core/memory_scope.py` - スコープEnum定義
  - `GLOBAL`: クラウド（全プロジェクト横断）
  - `SHARED`: クラウド（チーム共有、E2EE）
  - `PROJECT`: ローカル（プロジェクト固有）
  - `PRIVATE`: ローカル（機密情報）

#### 1.2 データベースルーター実装
- ✅ `src/core/database_router.py` - マルチDB抽象化
  - クラウドDB接続管理（PostgreSQL）
  - ローカルDB接続管理（SQLite）
  - スコープベース自動ルーティング
  - マルチセッション管理（同期操作用）

#### 1.3 設定拡張
- ✅ `src/core/config.py` - ハイブリッド設定追加
  - `cloud_database_url`: クラウドDB接続先
  - `local_database_url`: ローカルDB接続先
  - `hybrid_mode_enabled`: Feature Flag
  - `cloud_ssl_cert_path`: SSL証明書パス

### テスト計画

```bash
# Unit tests
pytest tests/unit/test_memory_scope.py -v
pytest tests/unit/test_database_router.py -v

# Integration tests
pytest tests/integration/test_hybrid_routing.py -v
```

### ロールバック戦略

```python
# Feature flag で無効化
TMWS_HYBRID_MODE_ENABLED=false

# または既存のdatabase_urlを使用
# cloud_database_urlが未設定の場合、自動的にlocalにフォールバック
```

---

## Phase 2: スコープ分類システム ✅

**期間**: Week 3-5
**担当**: Hestia（セキュリティ）+ Artemis（実装）

### 実装内容

#### 2.1 自動分類エンジン
- ✅ `src/services/scope_classifier.py`
  - `SensitiveDataDetector`: 機密情報検出（20+パターン）
  - `ProjectContextDetector`: プロジェクト固有コンテキスト検出
  - `KnowledgeTypeClassifier`: 知識タイプ分類
  - `ScopeClassifier`: 総合分類エンジン

#### 2.2 セキュリティ検証
```python
# 機密情報の自動PRIVATE化
content = "database password: secret123"
scope, details = classifier.classify(content)
assert scope == MemoryScope.PRIVATE
assert details["detected_sensitive"] == True
```

#### 2.3 手動オーバーライド機能
```python
# ユーザーが明示的にスコープ指定
await memory_service.create_memory(
    content="Team coding guidelines",
    scope=MemoryScope.SHARED,  # 手動指定
    override_auto_classification=True
)
```

### セキュリティチェックリスト

- [ ] 全ての機密情報パターンテスト完了
- [ ] False positive率 < 5%
- [ ] False negative率 = 0% (機密情報の見逃しなし)
- [ ] ユーザーオーバーライド時の警告表示
- [ ] 監査ログへの分類理由記録

### テスト計画

```bash
# Security-focused tests
pytest tests/security/test_sensitive_detection.py -v
pytest tests/security/test_scope_safety.py -v

# Classification accuracy tests
pytest tests/unit/test_scope_classifier.py -v --cov=src/services/scope_classifier.py
```

---

## Phase 3: 同期機構とオフライン対応

**期間**: Week 6-9
**担当**: Eris（調整）+ Artemis（実装）

### 実装計画

#### 3.1 Event Sourcing実装
```python
# src/services/sync_engine.py

class SyncEvent(Base):
    __tablename__ = "sync_events"

    id = Column(UUID, primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    event_type = Column(String)  # CREATE, UPDATE, DELETE
    memory_id = Column(UUID, nullable=False)
    source = Column(String)  # CLOUD, LOCAL
    data = Column(JSONB)
    synced = Column(Boolean, default=False)

class SyncEngine:
    async def sync_memory_to_cloud(self, memory: Memory):
        """Sync local memory to cloud (if appropriate scope)."""
        if memory.scope.is_cloud():
            # Create sync event
            event = SyncEvent(
                event_type="CREATE",
                memory_id=memory.id,
                source="LOCAL",
                data=memory.to_dict()
            )
            await self.push_to_cloud(event)

    async def sync_memory_to_local(self, memory: Memory):
        """Cache cloud memory locally for offline access."""
        if memory.scope == MemoryScope.GLOBAL:
            # Cache globally useful memories
            await self.cache_to_local(memory)
```

#### 3.2 Conflict Resolution
```python
class ConflictResolver:
    async def resolve_conflict(
        self,
        local_version: Memory,
        cloud_version: Memory
    ) -> Memory:
        """Resolve sync conflicts."""

        # Strategy 1: Last-Write-Wins (デフォルト)
        if cloud_version.updated_at > local_version.updated_at:
            return cloud_version

        # Strategy 2: Manual merge (重要な変更時)
        if self.requires_manual_merge(local_version, cloud_version):
            await self.request_user_merge(local_version, cloud_version)

        return local_version
```

#### 3.3 オフライン対応
```python
class OfflineManager:
    async def enable_offline_mode(self):
        """Switch to local-only operation."""
        self.offline = True
        logger.info("Offline mode enabled - all operations local")

    async def sync_when_online(self):
        """Sync pending changes when connection restored."""
        pending_events = await self.get_pending_sync_events()

        for event in pending_events:
            try:
                await self.sync_event_to_cloud(event)
                event.synced = True
            except ConnectionError:
                logger.warning(f"Sync failed for event {event.id}")
                break  # Stop and retry later
```

### テスト計画

```bash
# Sync tests
pytest tests/integration/test_sync_engine.py -v
pytest tests/integration/test_conflict_resolution.py -v

# Offline tests
pytest tests/integration/test_offline_mode.py -v
```

---

## Phase 4: セキュリティ強化と暗号化

**期間**: Week 10-12
**担当**: Hestia（セキュリティ）+ Artemis（実装）

### 実装計画

#### 4.1 エンドツーエンド暗号化（E2EE）
```python
# src/security/e2ee.py

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class E2EEManager:
    async def encrypt_for_shared_scope(
        self,
        content: str,
        team_id: UUID
    ) -> dict:
        """Encrypt content for SHARED scope."""

        # 1. Generate symmetric key (AES-256)
        symmetric_key = os.urandom(32)

        # 2. Encrypt content with symmetric key
        cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(content.encode()) + encryptor.finalize()

        # 3. Encrypt symmetric key with team's public key
        team_pubkey = await self.get_team_public_key(team_id)
        encrypted_key = team_pubkey.encrypt(
            symmetric_key,
            padding.OAEP(...)
        )

        return {
            "ciphertext": b64encode(ciphertext),
            "nonce": b64encode(nonce),
            "tag": b64encode(encryptor.tag),
            "encrypted_key": b64encode(encrypted_key)
        }
```

#### 4.2 Row-Level Security (RLS)
```sql
-- migrations/versions/XXX_rls_cloud_memories.py

def upgrade():
    # Enable RLS on cloud memories table
    op.execute("ALTER TABLE memories_cloud ENABLE ROW LEVEL SECURITY")

    # Tenant isolation policy
    op.execute("""
        CREATE POLICY tenant_isolation ON memories_cloud
        USING (tenant_id = current_setting('app.current_tenant')::uuid)
    """)

    # Scope-based access policy
    op.execute("""
        CREATE POLICY scope_access ON memories_cloud
        USING (
            CASE scope
                WHEN 'GLOBAL' THEN true
                WHEN 'SHARED' THEN tenant_id = current_setting('app.current_tenant')::uuid
                ELSE false
            END
        )
    """)
```

#### 4.3 TLS 1.3 強制
```python
# src/core/database_router.py (update)

cloud_engine = create_async_engine(
    cloud_url,
    connect_args={
        "ssl": "require",
        "sslmode": "verify-full",
        "sslrootcert": settings.cloud_ssl_cert_path,
        # TLS 1.3 minimum
        "ssl_min_protocol_version": "TLSv1.3",
    }
)
```

### セキュリティチェックリスト

- [ ] E2EE実装完了（SHARED scope）
- [ ] Row-Level Security有効化
- [ ] TLS 1.3強制（クラウド接続）
- [ ] 証明書ピンニング実装
- [ ] キー管理システム（KMS）統合
- [ ] ペネトレーションテスト実施
- [ ] OWASP Top 10チェック完了

---

## Phase 5: 段階的ロールアウト

**期間**: Week 13-18
**担当**: Hera（戦略）+ Eris（調整）

### ロールアウト計画

#### 5.1 アルファテスト（Week 13-14）
```yaml
target: 開発チーム（5名）
scope: 全機能テスト
metrics:
  - エラー率 < 1%
  - レスポンス時間 < 500ms
  - 同期成功率 > 99%
```

#### 5.2 ベータテスト（Week 15-16）
```yaml
target: パワーユーザー（20名）
feature_flags:
  hybrid_mode_enabled: true
  sync_interval: 300  # 5分ごと
monitoring:
  - ユーザーフィードバック収集
  - パフォーマンスメトリクス
  - セキュリティインシデント監視
```

#### 5.3 カナリアリリース（Week 17）
```python
# Feature flag configuration
CANARY_ROLLOUT = {
    "week_17": {
        "enabled_percentage": 10,
        "target_users": "random_selection"
    },
    "week_18": {
        "enabled_percentage": 50,
        "target_users": "all"
    }
}

async def is_hybrid_enabled_for_user(user_id: UUID) -> bool:
    """Check if hybrid mode enabled for this user."""
    rollout_config = get_current_rollout_config()

    if user_id in BETA_USERS:
        return True

    # Canary: 10% of users
    if hash(str(user_id)) % 100 < rollout_config["enabled_percentage"]:
        return True

    return False
```

#### 5.4 全体展開（Week 18）
```yaml
target: 全ユーザー
feature_flags:
  hybrid_mode_enabled: true
  default_scope: PROJECT  # Safe default
monitoring:
  - 24/7監視体制
  - インシデント対応チーム待機
  - ロールバック手順準備完了
```

### メトリクス定義

| メトリクス | 目標値 | アラート閾値 |
|----------|--------|------------|
| API応答時間 | < 200ms | > 500ms |
| 同期成功率 | > 99% | < 95% |
| エラー率 | < 0.5% | > 2% |
| クラウドDB接続率 | > 99.9% | < 99% |
| ローカルフォールバック率 | < 5% | > 20% |
| セキュリティインシデント | 0件 | > 0件 |

---

## Phase 6: 最適化と継続的改善

**期間**: Week 19-26以降
**担当**: Artemis（最適化）+ Muses（文書化）

### 最適化項目

#### 6.1 パフォーマンス最適化
```python
# キャッシュ戦略
class HybridCacheManager:
    async def optimize_cache(self):
        """Optimize cache based on access patterns."""

        # 1. Frequently accessed cloud memories → cache locally
        hot_memories = await self.get_frequently_accessed(
            scope=MemoryScope.GLOBAL,
            min_access_count=10
        )
        await self.cache_to_local(hot_memories)

        # 2. Rarely accessed local memories → archive
        cold_memories = await self.get_rarely_accessed(
            scope=MemoryScope.PROJECT,
            max_access_count=2,
            age_days=90
        )
        await self.archive_memories(cold_memories)
```

#### 6.2 コスト最適化
```python
# クラウドストレージ使用量監視
class CostOptimizer:
    async def analyze_cloud_usage(self):
        """Analyze and optimize cloud storage costs."""

        usage = await self.get_cloud_storage_usage()

        if usage.size_gb > 100:  # 100GB超過
            # 古いGLOBALメモリをアーカイブ
            old_globals = await self.get_old_memories(
                scope=MemoryScope.GLOBAL,
                age_months=12
            )
            await self.archive_to_cold_storage(old_globals)
```

#### 6.3 ML分類器の改善
```python
# 分類精度向上
class MLClassifier:
    async def train_on_feedback(self):
        """Improve classification based on user feedback."""

        # ユーザーが修正したスコープを学習データに
        training_data = await self.get_scope_corrections()

        # 分類器の再トレーニング
        model = await self.train_classifier(training_data)

        # 精度検証
        accuracy = await self.evaluate_model(model)
        if accuracy > 0.95:
            await self.deploy_new_model(model)
```

### 継続的改善サイクル

```
週次:
  - パフォーマンスレビュー
  - セキュリティスキャン
  - ユーザーフィードバック分析

月次:
  - コスト分析とレポート
  - 分類精度評価
  - 機能改善提案

四半期:
  - アーキテクチャレビュー
  - セキュリティ監査
  - ROI評価
```

---

## ロールバック戦略

各フェーズでのロールバック手順:

### Phase 1-2: Feature Flag無効化
```bash
# 即座にロールバック
export TMWS_HYBRID_MODE_ENABLED=false
systemctl restart tmws
```

### Phase 3-4: データ同期停止
```python
# Sync engine停止
await sync_engine.pause_all_sync()

# ローカルのみモードに切り替え
await router.set_local_only_mode(True)
```

### Phase 5: カナリアロールバック
```python
# 問題のあるユーザーグループのみロールバック
await rollback_users(problematic_user_ids)

# または全体ロールバック
await rollback_all_users()
```

---

## 成功基準

プロジェクト全体の成功判定基準:

### 技術的成功
- [ ] 全フェーズのテスト成功率 > 95%
- [ ] パフォーマンス劣化 < 10%
- [ ] セキュリティインシデント 0件
- [ ] データロス 0件

### ビジネス的成功
- [ ] ユーザー満足度 > 80%
- [ ] 知識再利用率向上 > 30%
- [ ] チーム間コラボレーション向上
- [ ] ROI達成（2年で124.6%）

### 運用的成功
- [ ] 99.9%以上の稼働率
- [ ] 平均復旧時間 < 1時間
- [ ] 監視・アラート体制確立
- [ ] ドキュメント完備

---

## 承認

- **プロジェクトマネージャー**: Eris (Tactical Coordinator)
- **技術リード**: Artemis (Technical Perfectionist)
- **セキュリティリード**: Hestia (Security Guardian)
- **最終承認**: Hera (Strategic Commander)

**バージョン**: 1.0
**策定日**: 2025-01-06
**開始予定**: 2025-01-20
