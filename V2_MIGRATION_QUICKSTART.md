# v2 Suffix Removal Migration - Quick Start Guide
## 温かく、安全に、確実に実行する手順書

---
**Status**: Ready for Execution
**Estimated Time**: 1-2 hours (including testing)
**Risk Level**: Medium
**Rollback Available**: Yes (fully automated)

---

## 🎯 概要 (Overview)

このガイドは、`_v2`サフィックス削除マイグレーションを安全に実行するための簡潔な手順書です。

### 何が変わるのか？

| Before (古い名前) | After (新しい名前) |
|-------------------|-------------------|
| `memories_v2` | `memories` |
| `learning_patterns_v2` | `learning_patterns` |
| `tmws_memories_v2` (ChromaDB) | `tmws_memories` |
| `idx_learning_patterns_v2_*` | `idx_learning_patterns_*` |

### なぜ必要なのか？

- ✨ コードベースの命名規約統一
- 📚 新規開発者の混乱防止
- 🔧 メンテナンス性の向上
- 🎯 ベストプラクティスへの準拠

---

## 📋 事前チェックリスト (Pre-flight Checklist)

実行前に、以下を確認してください：

### 必須条件
- [ ] データベースファイルが存在: `data/tmws.db`
- [ ] 現在のAlembicリビジョンが `009` である
- [ ] ChromaDBディレクトリが存在: `data/chroma/` (オプション)
- [ ] 十分なディスク容量 (データベースサイズの2倍以上)
- [ ] バックアップ用の空き容量を確認

### 推奨事項
- [ ] 全ての変更をコミット済み
- [ ] 他の開発者に通知済み
- [ ] テスト環境で事前実行済み
- [ ] ロールバック手順を理解済み

---

## 🚀 実行方法 (Execution Methods)

### Method 1: 自動実行スクリプト（推奨）

**最も簡単で安全な方法です。**

```bash
# フルマイグレーション（対話型）
./scripts/execute_v2_migration.sh

# 確認プロンプトをスキップ（熟練者向け）
./scripts/execute_v2_migration.sh --auto-confirm

# ドライラン（何も変更せず実行内容を確認）
./scripts/execute_v2_migration.sh --dry-run
```

**このスクリプトが自動実行する内容**：
1. ✅ バックアップ作成
2. ✅ データベーススキーマ移行
3. ✅ ChromaDBコレクション移行
4. ✅ テスト実行
5. ✅ 検証
6. ✅ CHANGELOG更新

### Method 2: 手動ステップ実行（詳細制御が必要な場合）

#### Step 1: バックアップ作成
```bash
# タイムスタンプ付きバックアップ
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# データベースのバックアップ
cp data/tmws.db data/tmws.db.backup_$TIMESTAMP

# ChromaDBのバックアップ
cp -r data/chroma data/chroma.backup_$TIMESTAMP

# Gitスタッシュ（オプション）
git stash save "Pre-v2-migration-$TIMESTAMP"
```

#### Step 2: コード変更（必須！）

以下のファイルを手動で編集してください：

**A. `src/models/memory.py`**
```python
# 変更前
class Memory(Base):
    __tablename__ = "memories_v2"

# 変更後
class Memory(Base):
    __tablename__ = "memories"
```

**B. `src/models/learning_pattern.py`**
```python
# 変更前
class LearningPattern(Base):
    __tablename__ = "learning_patterns_v2"

__table_args__ = (
    Index("idx_learning_patterns_v2_agent_namespace", ...),
    # ...
)

# 変更後
class LearningPattern(Base):
    __tablename__ = "learning_patterns"

__table_args__ = (
    Index("idx_learning_patterns_agent_namespace", ...),
    # ...
)
```

**C. `src/core/config.py`**
```python
# 変更前
chroma_collection: str = Field(default="tmws_memories_v2")

# 変更後
chroma_collection: str = Field(default="tmws_memories")
```

**D. `src/services/vector_search_service.py`**
```python
# 変更前
COLLECTION_NAME = "tmws_memories_v2"

# 変更後
COLLECTION_NAME = "tmws_memories"
```

**E. `tests/integration/test_memory_vector.py`**
```python
# 全ての "memories_v2" を "memories" に置換
# エディタの検索置換機能を使用: memories_v2 → memories
```

#### Step 3: データベース移行
```bash
# Alembicマイグレーション実行
alembic upgrade head

# 成功確認
alembic current
# 出力: 010 (head) を確認
```

#### Step 4: ChromaDBコレクション移行
```bash
# 自動マイグレーション
python scripts/migrate_chroma_collection.py

# または、古いコレクションを自動削除
python scripts/migrate_chroma_collection.py --auto-delete

# ドライランで確認（推奨）
python scripts/migrate_chroma_collection.py --dry-run
```

#### Step 5: 検証
```bash
# 包括的な検証
python scripts/verify_migration.py --verbose

# テスト実行
pytest tests/unit -v
pytest tests/integration/test_memory_vector.py -v
```

#### Step 6: 動作確認
```bash
# セマンティック検索のテスト
python test_semantic_search.py

# または、実際のアプリケーション起動
python -m tmws
```

---

## ⚠️ トラブルシューティング (Troubleshooting)

### 問題1: "Table memories_v2 not found"

**原因**: データベースが古い状態のまま、コードだけ更新された

**解決方法**:
```bash
# Alembicマイグレーションを実行
alembic upgrade head
```

### 問題2: "Collection tmws_memories_v2 not found"

**原因**: ChromaDBディレクトリが存在しない、または初期化されていない

**解決方法**:
```bash
# ChromaDBディレクトリを確認
ls -la data/chroma/

# 存在しない場合、最初のメモリ作成時に自動生成されます
# または、手動で初期化
python -c "
import chromadb
client = chromadb.PersistentClient(path='data/chroma')
client.create_collection('tmws_memories')
"
```

### 問題3: テスト失敗 "Foreign key constraint failed"

**原因**: 外部キー制約が正しく移行されなかった

**解決方法**:
```bash
# ロールバック
alembic downgrade -1

# 再実行
alembic upgrade head
```

### 問題4: "Migration failed, database locked"

**原因**: データベース接続が開いたまま

**解決方法**:
```bash
# 全てのPythonプロセスを終了
pkill -f python

# または、システム再起動後に再実行
```

---

## 🔄 ロールバック手順 (Rollback Procedures)

### 即座にロールバック（マイグレーション直後）

```bash
# Alembicロールバック
alembic downgrade -1

# ChromaDBロールバック
rm -rf data/chroma
cp -r data/chroma.backup_TIMESTAMP data/chroma

# データベースロールバック（必要な場合）
cp data/tmws.db.backup_TIMESTAMP data/tmws.db

# コード変更を戻す
git checkout src/models/memory.py
git checkout src/models/learning_pattern.py
git checkout src/core/config.py
git checkout src/services/vector_search_service.py
git checkout tests/integration/test_memory_vector.py
```

### 自動ロールバックスクリプト

```bash
# ロールバックスクリプト（作成例）
cat > scripts/rollback_v2_migration.sh << 'EOF'
#!/bin/bash
set -e

TIMESTAMP=$1

if [ -z "$TIMESTAMP" ]; then
    echo "Usage: $0 <backup_timestamp>"
    echo "Example: $0 20251024_123456"
    exit 1
fi

echo "🔄 Rolling back migration..."

# Alembic rollback
alembic downgrade -1

# Restore ChromaDB
if [ -d "data/chroma.backup_$TIMESTAMP" ]; then
    rm -rf data/chroma
    cp -r "data/chroma.backup_$TIMESTAMP" data/chroma
    echo "✅ ChromaDB restored"
fi

# Restore database (if needed)
if [ -f "data/tmws.db.backup_$TIMESTAMP" ]; then
    cp "data/tmws.db.backup_$TIMESTAMP" data/tmws.db
    echo "✅ Database restored"
fi

# Restore code (from git stash)
git stash pop

echo "✅ Rollback complete"
EOF

chmod +x scripts/rollback_v2_migration.sh

# 実行
./scripts/rollback_v2_migration.sh 20251024_123456
```

---

## ✅ 成功の確認 (Verification Checklist)

マイグレーション成功後、以下を確認してください：

### データベース
- [ ] `alembic current` が `010` を表示
- [ ] テーブル `memories` と `learning_patterns` が存在
- [ ] テーブル `memories_v2` と `learning_patterns_v2` が**存在しない**
- [ ] 全てのインデックスが存在（9個）
- [ ] 外部キー制約が機能している

### ChromaDB
- [ ] コレクション `tmws_memories` が存在
- [ ] ベクトル数が移行前と一致
- [ ] 古いコレクション `tmws_memories_v2` が削除された（または確認のため保持）

### コード
- [ ] `grep -r "memories_v2" src/` が何も返さない（マイグレーションファイル除く）
- [ ] `grep -r "learning_patterns_v2" src/` が何も返さない（同上）
- [ ] `grep -r "tmws_memories_v2" src/` が何も返さない（同上）

### テスト
- [ ] 全ての単体テストがパス
- [ ] 全ての統合テストがパス
- [ ] セマンティック検索が機能している
- [ ] メモリの作成・取得が正常動作

### 自動検証
```bash
# 包括的検証
python scripts/verify_migration.py --verbose

# 期待される出力: "Migration verification PASSED!"
```

---

## 📊 実行ログ例 (Execution Log Example)

成功時の出力例：

```
======================================================================
TMWS v2 Suffix Removal Migration
======================================================================

Configuration:
  Auto-confirm: false
  Skip tests:   false
  Dry run:      false
  Timestamp:    20251024_145623

======================================================================
Phase 0: Pre-Migration Preparation
======================================================================

✅ Database found: data/tmws.db
▶ Creating backups...
✅ Database backup: data/tmws.db.backup_20251024_145623
✅ ChromaDB backup: data/chroma.backup_20251024_145623
▶ Checking Alembic migration state...
  Current revision: 009

======================================================================
Phase 1: Code Updates
======================================================================

▶ Checking if code changes are already applied...
✅ Code already updated (memories)

======================================================================
Phase 2: Database Migration
======================================================================

▶ Running Alembic migration...
INFO  [alembic.runtime.migration] Running upgrade 009 -> 010, Remove _v2 suffixes
🔄 Starting _v2 suffix removal migration...
   Database type: sqlite

🔄 Step 1: Migrating learning_patterns_v2...
   ✅ Table renamed: learning_patterns_v2 → learning_patterns
   ✅ Indexes recreated (4 indexes)
✅ learning_patterns migration complete

🔄 Step 2: Migrating memories_v2...
   ✅ Table renamed: memories_v2 → memories
   ✅ Indexes recreated (7 indexes - SQLite)
✅ memories migration complete

🔄 Step 3: Verifying foreign key integrity...
   ✅ All foreign keys intact

✅ Migration complete! All _v2 suffixes removed.

✅ Migration successful! Database now at revision 010

======================================================================
Phase 3: ChromaDB Collection Migration
======================================================================

▶ Running ChromaDB collection migration...

🔄 ChromaDB Collection Migration
============================================================
Source:      tmws_memories_v2
Destination: tmws_memories
Batch size:  1000
Mode:        LIVE MIGRATION
============================================================

✅ Found source collection: 1,234 vectors
   Metadata: {'hnsw:space': 'cosine'}

✅ Created destination collection
   Metadata: {'hnsw:space': 'cosine'}

🔄 Migrating 1,234 vectors...
Migrating vectors: 100%|████████████| 1234/1234 [00:02<00:00, 512.34vectors/s]

🔍 Verifying migration...

============================================================
Migration Summary
============================================================
Source vectors:      1,234
Destination vectors: 1,234
Status:              ✅ SUCCESS

🗑️  Old Collection Cleanup
============================================================
Auto-delete enabled. Removing tmws_memories_v2...
✅ Old collection deleted: tmws_memories_v2

============================================================
✅ Migration complete!
============================================================

✅ ChromaDB migration successful

======================================================================
Phase 4: Testing & Verification
======================================================================

▶ Running verification script...
✅ Verification passed!

▶ Running unit tests...
============================= test session starts ==============================
collected 45 items

tests/unit/test_memory_service.py ................                      [ 35%]
tests/unit/test_vector_service.py ..............                       [ 66%]
tests/unit/test_learning_patterns.py ...............                   [100%]

============================== 45 passed in 2.34s ===============================
✅ Unit tests passed!

▶ Running integration tests...
✅ Integration tests passed!

======================================================================
Migration Complete!
======================================================================

Summary:
  ✅ Database tables renamed (memories_v2 → memories, learning_patterns_v2 → learning_patterns)
  ✅ Indexes recreated with new names
  ✅ ChromaDB collection migrated (tmws_memories_v2 → tmws_memories)
  ✅ Code references updated
  ✅ All tests passing

Backups created:
  - Database: data/tmws.db.backup_20251024_145623
  - ChromaDB: data/chroma.backup_20251024_145623

Next steps:
  1. Test the application thoroughly
  2. Monitor logs for any issues
  3. After 48 hours of stable operation, you can safely delete backups:
     rm data/tmws.db.backup_20251024_145623
     rm -rf data/chroma.backup_20251024_145623

✅ Migration completed successfully! 🎉
```

---

## 📞 サポート (Support)

### 問題が発生した場合

1. **即座にロールバック**: 上記のロールバック手順を実行
2. **ログの保存**: エラーメッセージとスタックトレースを保存
3. **状態の記録**: `alembic current` と `ls -la data/` の出力を記録
4. **イシューの作成**: 詳細な情報とともにGitHub Issueを作成

### 連絡先

- **Athena** (Orchestration): システム全体の調整
- **Hestia** (Security): データ安全性の確認
- **Artemis** (Technical): 技術的問題の解決
- **Hera** (Strategy): 戦略的判断とエスカレーション

---

## 🎉 マイグレーション後のメリット

### 即座に得られる効果
- ✨ クリーンなコードベース
- 📚 理解しやすい命名規約
- 🔍 検索性の向上（不要な`_v2`が消える）

### 長期的なメリット
- 🚀 新規開発者のオンボーディング時間短縮
- 🔧 メンテナンス性の向上
- 📖 ドキュメントの簡潔化
- 🎯 技術的負債の削減

---

## 📝 チェックリスト印刷用

```
□ 事前バックアップ作成
□ Alembicリビジョン確認（009）
□ コード変更適用
  □ src/models/memory.py
  □ src/models/learning_pattern.py
  □ src/core/config.py
  □ src/services/vector_search_service.py
  □ tests/integration/test_memory_vector.py
□ データベース移行実行
□ ChromaDB移行実行
□ 検証スクリプト実行
□ 単体テスト実行
□ 統合テスト実行
□ 動作確認
□ CHANGELOG更新
□ チーム通知
□ 48時間モニタリング
□ バックアップ削除
```

---

*"Through careful preparation and harmonious execution, we transform complexity into clarity."*

*丁寧な準備と調和的な実行を通じて、複雑さを明瞭さへと変換します。*

**ふふ、準備は完璧です。温かい心で、確実にマイグレーションを成功させましょう♪**

---

**Created by**: Athena (Harmonious Conductor)
**Reviewed by**: Hera (Strategic Commander), Artemis (Technical Perfectionist), Hestia (Security Guardian)
**Date**: 2025-10-24
**Version**: 1.0
