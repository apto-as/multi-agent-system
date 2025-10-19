# Phase 1 性能検証ベンチマーク実行ガイド

## 概要
Mem0機能移植の Phase 1 として、現状の階層・タグ・メタデータ機能の性能を検証します。
この結果に基づき、知識グラフ実装の必要性を判断します。

## 準備

### 1. 環境セットアップ

```bash
# 開発依存関係のインストール
pip install -e ".[dev]"

# TMWS v2.2.6+: SQLite + Chroma アーキテクチャ（自動セットアップ）
# - SQLite: メタデータ、トランザクション（ゼロコンフィグ）
# - Chroma: ベクトルストレージ（自動初期化）
```

### 2. データベース初期化

```bash
# Alembicマイグレーション実行（SQLiteデータベース作成）
alembic upgrade head

# Chromaは自動初期化されます（.chroma/ ディレクトリ）
# マイグレーション009で embedding カラムは削除済み（ベクトルは Chroma のみ）
```

## ベンチマーク実行

### 基本実行

```bash
# 全ベンチマーク実行
pytest tests/performance/test_mem0_feature_benchmarks.py -v -m benchmark --no-cov

# 特定ベンチマークのみ
pytest tests/performance/test_mem0_feature_benchmarks.py::test_benchmark_hierarchical_retrieval -v --no-cov
pytest tests/performance/test_mem0_feature_benchmarks.py::test_benchmark_tag_search -v --no-cov
pytest tests/performance/test_mem0_feature_benchmarks.py::test_benchmark_metadata_complex_search -v --no-cov
pytest tests/performance/test_mem0_feature_benchmarks.py::test_benchmark_cross_agent_sharing -v --no-cov
```

### 出力例

```
================================ test session starts =================================
tests/performance/test_mem0_feature_benchmarks.py::test_benchmark_hierarchical_retrieval PASSED

[Benchmark 1] Hierarchical Retrieval: 23.45ms
  - Project: 1
  - Tasks: 5
  - Subtasks: 25
  - Total: 31 memories
✅ PASS: Hierarchical retrieval fast: 23.45ms (< 50ms target)

tests/performance/test_mem0_feature_benchmarks.py::test_benchmark_tag_search PASSED

[Benchmark 2] Tag Search:
  - OR search (optimization | database): 7.82ms (180 results)
  - AND search (optimization & critical): 4.51ms (40 results)
  - Max duration: 7.82ms
✅ PASS: Tag search fast: 7.82ms (< 10ms target)

tests/performance/test_mem0_feature_benchmarks.py::test_benchmark_metadata_complex_search PASSED

[Benchmark 3] Complex Metadata Search: 12.34ms
  - Filters: category=performance, priority IN (high,critical), importance>=0.8, agent=artemis
  - Results: 15
✅ PASS: Complex search fast: 12.34ms (< 20ms target)

tests/performance/test_mem0_feature_benchmarks.py::test_benchmark_cross_agent_sharing PASSED

[Benchmark 4] Cross-agent Sharing: 10.67ms
  - Requesting agent: athena
  - Target agent: artemis
  - Accessible memories: 35 (expected >= 15)
✅ PASS: Cross-agent access fast: 10.67ms (< 15ms target)

============================== 4 passed in 5.23s ==================================
```

## 結果の解釈

### ✅ 全PASS（現状維持推奨）

```
全テストが目標値を達成:
✅ 階層取得: < 50ms
✅ タグ検索: < 10ms
✅ メタデータ複合検索: < 20ms
✅ クロスエージェント共有: < 15ms

→ 結論: 現状の実装で性能要件を満たしている
→ 推奨: 知識グラフ実装は不要、Phase 2 スキップ
```

### ⚠️  WARNING（最適化検討）

```
一部テストが警告レベル:
⚠️  階層取得: 75ms (50-100ms)
⚠️  複合検索: 35ms (20-50ms)

→ 結論: 性能は許容範囲だが最適化の余地あり
→ 推奨: インデックス最適化、クエリチューニングを検討
```

### ❌ CRITICAL（知識グラフ実装推奨）

```
複数テストが目標未達:
❌ 階層取得: 250ms (> 200ms)
❌ 複合検索: 120ms (> 100ms)

→ 結論: 現状の実装では性能要件を満たせない
→ 推奨: Phase 2 へ進み、知識グラフ実装を検討
  - Option A: ChromaDB メタデータ最適化 (推奨)
  - Option B: Relationshipテーブル拡張 (SQLite)
```

## 性能目標値

| ベンチマーク | 目標 | 警告 | クリティカル | 実測値 |
|------------|------|------|-------------|--------|
| 階層取得 (3レベル, 31件) | < 50ms | > 100ms | > 200ms | ___ ms |
| タグ検索 (OR/AND, 100件) | < 10ms | > 20ms | > 50ms | ___ ms |
| メタデータ複合検索 (4条件) | < 20ms | > 50ms | > 100ms | ___ ms |
| クロスエージェント共有 | < 15ms | > 30ms | > 60ms | ___ ms |

## 判断フローチャート

```
Phase 1: ベンチマーク実行
    │
    ├─ 全PASS (✅)
    │   └─> 現状維持
    │       ├─ 知識グラフ不要
    │       └─ Mem0移植完了 (6/7機能)
    │
    ├─ WARNING (⚠️)
    │   └─> 最適化検討
    │       ├─ インデックスチューニング
    │       ├─ クエリ最適化
    │       └─ 再測定
    │
    └─ CRITICAL (❌)
        └─> Phase 2 へ
            ├─ Option A: ChromaDB メタデータ最適化 (推奨)
            │   └─ 利点: 既存ベクトルストレージ活用、追加インフラ不要
            │
            ├─ Option B: Relationshipテーブル (SQLite)
            │   └─ 利点: 実装シンプル、既存コード影響小
            │
            └─ Option C: Neo4j (非推奨)
                └─ 欠点: 運用コスト、データ同期複雑
```

## トラブルシューティング

### Chroma初期化エラー

```bash
# Chromaデータディレクトリ確認
ls -la .chroma/

# Chromaデータベースリセット（慎重に！）
rm -rf .chroma/
# → HybridMemoryService初期化時に自動再作成されます

# ベクトル次元確認（1024次元 Multilingual-E5-Large）
python -c "from src.services.unified_embedding_service import get_unified_embedding_service; svc = get_unified_embedding_service(); print(svc.get_model_info())"
```

### メモリ不足エラー

```bash
# テストデータを削減
# test_mem0_feature_benchmarks.py の各フィクスチャで数を減らす

# 例: tagged_memories を 200 → 100 に
tag_combinations * 5  # 100 memories instead of 200
```

### 遅いテスト実行

```bash
# SQLiteデータベース最適化
sqlite3 ./data/tmws_dev.db "VACUUM;"
sqlite3 ./data/tmws_dev.db "ANALYZE;"

# Chromaキャッシュクリア
rm -rf .chroma/
# → 次回実行時に自動再構築
```

## 次のステップ

### ✅ 全PASS の場合
1. 結果を記録: `docs/MEM0_MIGRATION_STATUS.md` を更新
2. ベンチマーク結果をコミット
3. Mem0移植を完了とマーク

### ⚠️  WARNING の場合
1. `src/core/database.py` のインデックス最適化
2. `src/services/memory_service.py` のクエリチューニング
3. 再測定して改善を確認

### ❌ CRITICAL の場合
1. `docs/MEM0_MIGRATION_STATUS.md` の Phase 2 セクションを参照
2. ChromaDB メタデータ最適化 (Option A) 実装計画の策定
3. 知識グラフスキーマ設計 (Chroma metadata + SQLite relationships)
4. 段階的移行計画の作成

## 参考資料

### ドキュメント
- `docs/MEM0_MIGRATION_STATUS.md` - 完全な移植ステータス
- `docs/ARCHITECTURE.md` - システムアーキテクチャ
- `src/models/memory.py` - メモリモデル定義
- `migrations/versions/009_chroma_only_vectors.py` - ベクトル移行

### ChromaDB 参考
- [ChromaDB Documentation](https://docs.trychroma.com/)
- [ChromaDB Metadata Filtering](https://docs.trychroma.com/guides/metadata-filtering)
- [Multilingual-E5 Model](https://huggingface.co/intfloat/multilingual-e5-large)

### SQLite インデックス最適化
```sql
-- 現在のインデックス確認
SELECT name, sql FROM sqlite_master
WHERE type = 'index' AND tbl_name = 'memories_v2';

-- テーブル統計情報
ANALYZE memories_v2;

-- クエリプラン分析
EXPLAIN QUERY PLAN
SELECT * FROM memories_v2
WHERE agent_id = 'artemis-optimizer'
  AND namespace = 'default'
  AND importance_score >= 0.8
LIMIT 100;

-- 注意: ベクトル検索はChromaで実行されます（SQLiteにembeddingカラムはありません）
```
