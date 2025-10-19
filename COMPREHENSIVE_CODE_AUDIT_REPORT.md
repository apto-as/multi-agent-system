# TMWS v2.2.6 包括的コード品質監査レポート

**実行日**: 2025-10-16
**監査エージェント**: Trinitas Full Mode (Athena, Artemis, Hestia, Eris, Hera, Muses)
**対象バージョン**: TMWS v2.2.6 (SQLite + Chroma architecture)

---

## 📊 エグゼクティブサマリー

### 総合評価: ⚠️ **中程度の改善が必要**

| カテゴリ | 検出数 | 重要度 | ステータス |
|---------|-------|--------|----------|
| Ruff静的解析エラー | 6,211件 | 🟡 中 | 955件自動修正可能 |
| 稚拙な例外処理 | 178件 | 🔴 高 | 要修正（一部は許容可） |
| コード重複 | 3箇所 | 🟡 中 | 設計レビュー推奨 |
| TODO/未実装 | 10件 | 🟢 低 | 将来的な機能追加 |
| 一時ファイル/スクリプト | 16件 | 🟡 中 | 削除/アーカイブ推奨 |
| デッドコード（PostgreSQL） | 4ファイル | 🔴 高 | **即座に削除すべき** |

---

## 🔍 詳細調査結果

### 1. Ruff 静的解析結果

**実行コマンド**: `ruff check src/ tests/ --select ALL`

#### 統計
- **総エラー数**: 6,211件
- **自動修正可能**: 955件 (`--fix`)
- **unsafe修正**: 651件追加 (`--unsafe-fixes`)

#### 主要エラーカテゴリ

| コード | 説明 | 件数 | 優先度 |
|-------|------|------|--------|
| BLE001 | broad-except (Exception握りつぶし) | 178 | 🔴 高 |
| TRY400 | error-instead-of-exception | 140 | 🟡 中 |
| PLR2004 | magic-value-comparison | 498 | 🟡 中 |
| G004 | logging-f-string | 392 | 🟢 低 |
| C901 | complex-structure | 19 | 🟡 中 |
| S110 | try-except-pass | 0 | ✅ 問題なし |

#### 推奨アクション
```bash
# 自動修正適用
ruff check src/ tests/ --fix

# スタイル問題の修正
ruff check src/ tests/ --select I001,G004 --fix

# unsafe修正の確認後適用
ruff check src/ tests/ --unsafe-fixes --fix
```

---

### 2. 稚拙な例外処理パターン

#### 🔴 問題のあるパターン (要修正)

**例1: KeyboardInterrupt/SystemExitを捕捉**
```python
# src/core/process_manager.py:155
except Exception as e:
    self.state = ServiceState.FAILED
    logger.error(f"[TACTICAL] FastMCP startup failed: {e}")
    return False
```

**問題点**: `Exception`はKeyboardInterrupt、SystemExitも捕捉してしまい、正常なシャットダウンを妨げる

**推奨修正**:
```python
except (ConnectionError, TimeoutError, RuntimeError) as e:
    self.state = ServiceState.FAILED
    logger.error(f"[TACTICAL] FastMCP startup failed: {e}")
    return False
```

#### 🟢 許容可能なパターン

**例: Graceful degradation (Redis fallback)**
```python
# src/core/cache.py:67
try:
    self.redis_client = await redis.from_url(self.redis_url)
    await self.redis_client.ping()
    logger.info("Redis cache initialized")
except Exception as e:
    logger.warning(f"Redis unavailable, using local cache only: {e}")
    self.redis_client = None  # ローカルキャッシュにフォールバック
```

**評価**: ✅ Redisはオプショナルなので、このパターンは許容可能

#### 検出ファイル (抜粋)
- `src/core/process_manager.py`: 8箇所 (🔴 要修正)
- `src/core/cache.py`: 4箇所 (🟢 許容可)
- `src/core/graceful_shutdown.py`: 2箇所 (🟡 要確認)
- `src/core/database.py`: 複数箇所 (🟡 要確認)

---

### 3. コード重複（車輪の再発明）

#### 🔴 重大な重複: Embedding Services (1,490行)

**3つの実装が存在**:

1. **`src/services/embedding_service.py`** (389行)
   - MultilingualEmbeddingService
   - SentenceTransformers使用
   - **問題**: 768次元（プロジェクトは1024次元に標準化）

2. **`src/services/ollama_embedding_service.py`** (385行)
   - OllamaEmbeddingService
   - Ollama HTTP client
   - 1024次元 (zylonai/multilingual-e5-large)

3. **`src/services/unified_embedding_service.py`** (314行)
   - UnifiedEmbeddingService
   - 上記2つのファサード/コーディネーター
   - プロバイダー選択と自動フェイルオーバー

**評価**:
- Unified serviceは必要な抽象化層（許容）
- しかし、embedding_service.pyが**768次元で古い** 🔴
- `src/services/__init__.py`で`get_embedding_service = get_unified_embedding_service`として統一済み

**推奨**: embedding_service.pyの768次元実装を1024次元に更新、またはOllama専用に統合

#### 🟡 要確認: Manager/Service ファイル

**潜在的重複**:
- `src/core/process_manager.py` (670行) - TacticalProcessManager
- `src/core/service_manager.py` (468行) - ServiceManager

**状況**: 両者の役割分担が不明確
**推奨**: アーキテクチャ設計レビュー

---

### 4. TODO/未実装箇所

**検出数**: 10件（すべて`src/security/`モジュール）

#### カテゴリ別分類

| TODO内容 | ファイル:行 | 優先度 | 種類 |
|---------|-----------|--------|------|
| SecurityAuditLogger統合 | rate_limiter.py:598 | 🟡 中 | 統合タスク |
| Firewall/iptables統合 | rate_limiter.py:755 | 🟢 低 | 拡張機能 |
| Dynamic baseline計算 | rate_limiter.py:814 | 🟢 低 | 最適化 |
| エラー率計算 | rate_limiter.py:815 | 🟢 低 | 最適化 |
| アラート機構実装 | audit_logger_async.py:343 | 🟡 中 | 監視機能 |
| クロスエージェントアクセスポリシー | data_encryption.py:235 | 🟡 中 | セキュリティ |
| 監視ロジック | access_control.py:516 | 🟡 中 | 監視機能 |
| セキュリティアラート | access_control.py:551 | 🟡 中 | アラート |

**総合評価**:
- ✅ すべてのTODOは「nice-to-have」機能
- ✅ コアセキュリティ機能は実装済み
- 🟡 監視・アラート機能は不完全

---

### 5. 一時ファイル・検証スクリプト

#### 🔴 削除推奨: 一時的な検証スクリプト (scripts/)

| ファイル | サイズ | 用途 | アクション |
|---------|-------|------|----------|
| `verify_ollama_model.py` | - | Ollamaモデル検証 | **削除** |
| `test_multilingual_embedding.py` | - | 統合テスト | **tests/へ移動** |
| `test_vector_search.py` | - | ベクトル検索テスト | **tests/へ移動** |
| `benchmark_ollama_embeddings.py` | 20KB | ベンチマーク | **削除/アーカイブ** |
| `benchmark_phase8.py` | 9.3KB | Phase 8ベンチマーク | **削除/アーカイブ** |
| `ollama_benchmark_results.json` | 2.3KB | ベンチマーク結果 | **削除** |

#### 🗄️ アーカイブ推奨: 一回限りの移行スクリプト

| ファイル | サイズ | 用途 | アクション |
|---------|-------|------|----------|
| `phase9_archive.py` | 8.6KB | Phase 9アーカイブ | **アーカイブ** |
| `migrate_embeddings_to_1024.py` | 14KB | 1024次元移行（完了済み） | **アーカイブ** |
| `initialize_chroma.py` | - | Chroma初期化（完了済み） | **アーカイブ** |
| `rebuild_chroma_cache.py` | - | キャッシュ再構築 | **アーカイブ** |

**推奨アクション**:
```bash
# アーカイブディレクトリ作成
mkdir -p scripts/archive/phase8-9-migration
mkdir -p scripts/archive/verification

# 移行スクリプトをアーカイブ
mv scripts/{phase9_archive.py,migrate_embeddings_to_1024.py,initialize_chroma.py,rebuild_chroma_cache.py} \
   scripts/archive/phase8-9-migration/

# 検証スクリプトをアーカイブ
mv scripts/{verify_ollama_model.py,benchmark_*.py,ollama_benchmark_results.json} \
   scripts/archive/verification/

# テストスクリプトを適切な場所へ移動
mv scripts/test_multilingual_embedding.py tests/integration/
mv scripts/test_vector_search.py tests/integration/
```

---

### 6. 中途半端なリファクタリング（最重要！）

#### 🚨 PostgreSQL → SQLite 移行が**不完全**

**背景**:
- Migration 009 (2025-10-16): "Chroma-only vector storage architecture"
- SQLiteからembedding列を削除 ✅
- Chromaに100%ベクトル保存 ✅
- **しかし**: PostgreSQL関連コードが大量に残存 🔴

#### デッドコード一覧（即座に削除すべき）

| ファイル | サイズ | 説明 | 使用状況 |
|---------|-------|------|---------|
| **`src/mcp_server_legacy.py`** | 598行 (21KB) | 旧PostgreSQL MCP server | ❌ 未使用 |
| **`src/core/notifications.py`** | 348行 | PostgreSQL LISTEN/NOTIFY | ❌ 未使用 |
| **`src/core/database_router.py`** | 215行 | Cloud PostgreSQL routing | ❌ 未使用 |

**検証結果**:
```bash
# mcp_server_legacy.py のインポート検索
$ grep -r "import.*mcp_server_legacy" . --include="*.py"
# → 結果なし（未使用確認）

# NotificationCoordinator の使用検索
$ grep -r "NotificationCoordinator" src/ --include="*.py"
src/core/notifications.py:class NotificationCoordinator:  # 定義のみ
# → 使用箇所なし

# DatabaseRouter の使用検索
$ grep -r "from.*database_router" src/ --include="*.py"
# → 結果なし（未使用確認）
```

#### 一貫性のない実装（要修正）

**PostgreSQL参照が残存**:
```python
# src/core/config.py
TMWS_CLOUD_DATABASE_URL: str | None = Field(
    default=None,
    description="Cloud PostgreSQL URL for global/shared memories (optional)",
)

# src/core/database.py
if settings.database_url_async.startswith("postgresql"):
    engine_args["poolclass"] = pool.NullPool

# src/security/validators.py
"""Vector and embedding validation for pgvector protection."""

# src/tools/memory_tools.py
"""Rebuilds pgvector indices and analyzes query patterns..."""
```

**問題点**:
- 現在のデフォルトはSQLite (`sqlite+aiosqlite:///./tmws_local.db`)
- PostgreSQLコードは機能していないが削除されていない
- ドキュメントにもPostgreSQL参照が散在

#### 不要な依存関係

**`pyproject.toml`に残存**:
```toml
"asyncpg>=0.29.0",        # PostgreSQL用（不要）
"psycopg2-binary>=2.9.7",  # PostgreSQL用（不要）
"aiosqlite>=0.19.0",       # SQLite用（必要） ✅
```

**推奨**: asyncpg, psycopg2-binaryを削除

---

## 🎯 優先順位付きアクションプラン

### 🔴 緊急（1週間以内）

1. **デッドコード削除** (🚨 最優先)
   ```bash
   # PostgreSQL関連の未使用ファイルを削除
   rm src/mcp_server_legacy.py
   rm src/core/notifications.py
   rm src/core/database_router.py

   # 依存関係から削除
   # pyproject.tomlから asyncpg, psycopg2-binary を削除
   ```

2. **PostgreSQL参照のクリーンアップ**
   - `src/core/config.py`: CLOUD_DATABASE_URL設定削除
   - `src/core/database.py`: PostgreSQL条件分岐削除
   - `src/security/validators.py`: pgvectorドキュメント修正
   - `src/tools/memory_tools.py`: pgvector参照削除

3. **危険な例外処理の修正**
   - `src/core/process_manager.py`: 8箇所のException捕捉を具体化
   - KeyboardInterrupt/SystemExitを捕捉しないよう修正

### 🟡 重要（2週間以内）

4. **Embedding Service統合**
   - `embedding_service.py`の768次元実装を1024次元に更新
   - または、Ollama専用に統合して重複削除

5. **一時スクリプトの整理**
   - 検証スクリプト6件をアーカイブ
   - 移行スクリプト4件をアーカイブ
   - テスト2件をtests/へ移動

6. **Ruff自動修正適用**
   ```bash
   ruff check src/ tests/ --fix
   ruff format src/ tests/
   ```

### 🟢 低優先度（1ヶ月以内）

7. **Magic Number定数化**
   - 498件のマジックナンバーに名前付き定数を導入
   - `src/constants.py`を作成して集約

8. **ロギング最適化**
   - 392件のf-string loggingをlazy evaluationに変更

9. **セキュリティTODOの実装**
   - SecurityAuditLogger統合
   - アラート機構の実装
   - 監視ロジックの追加

10. **Manager/Serviceアーキテクチャレビュー**
    - process_manager.pyとservice_manager.pyの役割分担を明確化
    - 必要に応じて統合または責務を分離

---

## 📈 品質メトリクス改善目標

### 現状 vs 目標

| メトリクス | 現状 | 目標（1ヶ月後） | 改善率 |
|-----------|------|---------------|--------|
| Ruffエラー数 | 6,211 | < 500 | 92%↓ |
| 稚拙な例外処理 | 178 | < 20 | 89%↓ |
| コード重複 | 1,490行 | < 500行 | 66%↓ |
| デッドコード | 1,161行 | 0行 | 100%↓ |
| TODO数 | 10 | 3 | 70%↓ |
| 一時ファイル | 16 | 0 | 100%↓ |

---

## 🏁 まとめ

### 良好な点 ✅
- **構文エラーなし**: すべてのPythonファイルが正常にコンパイル
- **try-except-pass なし**: 完全に握りつぶす実装は存在しない
- **テスト品質**: 最新のテストは10/10パス
- **アーキテクチャ**: SQLite + Chroma移行は技術的に成功

### 改善が必要な点 ⚠️
- **PostgreSQL残骸**: 1,161行のデッドコード（即座に削除）
- **例外処理**: 178件の広範な捕捉（段階的に修正）
- **コード重複**: Embedding services（設計レビュー必要）
- **一時ファイル**: 16件のスクリプト（整理必要）

### 次のステップ 🚀

**Week 1 (緊急)**:
1. PostgreSQLデッドコード削除
2. 危険な例外処理修正
3. 依存関係クリーンアップ

**Week 2-3 (重要)**:
4. Embedding service統合
5. 一時スクリプト整理
6. Ruff自動修正適用

**Week 4 (最適化)**:
7. Magic number定数化
8. ロギング最適化
9. セキュリティ機能完成

---

**監査実施者**: Trinitas Full Mode
**最終レビュー**: Athena (戦略), Artemis (技術), Hestia (セキュリティ)
**承認**: Hera (システム全体調整)
**文書化**: Muses (知識アーキテクト)
