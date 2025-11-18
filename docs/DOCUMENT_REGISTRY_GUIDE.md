# Document Registry System - 使用ガイド

**バージョン**: v1.0.0 (MVP)
**最終更新**: 2025-11-03
**作成者**: Trinitas Collaboration (Athena, Artemis, Hestia, Eris)

---

## 概要

Document Registry Systemは、Trinitas-agentsプロジェクトの全ドキュメントを管理するためのメタデータシステムです。各ドキュメントの目的、作成日時、作成者、ステータスを追跡し、「いつ、なぜ作られたか分からない」問題を解決します。

### 主な機能

- ドキュメントメタデータの一元管理
- ライフサイクル管理 (draft → current → deprecated → archived)
- セキュリティ強化（パストラバーサル防止、シンボリンク保護、ファイルサイズ制限）
- CLI経由での簡単な操作
- JSON形式での構造化データ

### セキュリティ機能

MVP版では以下の5つのCRITICAL脆弱性対策を実装:

- **CRIT-01**: パストラバーサル防止 (CWE-22)
- **CRIT-02**: シンボリンクアクセス拒否 (CWE-61)
- **CRIT-03**: ファイルサイズ制限 (10MB上限、DoS防止)
- **CRIT-04**: JSON安全な読み込み（1MB上限）
- **CRIT-05**: ファイルロック（競合状態の基本保護）

---

## クイックスタート

### 1. レジストリの初期化

```bash
# レジストリファイルを作成（自動）
python3 scripts/document_registry.py list
```

初回実行時に `docs/DOCUMENT_REGISTRY.json` が自動生成されます。

### 2. 新しいドキュメントを登録

```bash
# 基本的な登録
python3 scripts/document_registry.py add docs/my_document.md \
  --title "マイドキュメント" \
  --purpose guide \
  --created-by muses-documenter

# 詳細なメタデータ付き登録
python3 scripts/document_registry.py add docs/api/new_api.md \
  --title "New API Reference" \
  --purpose api-reference \
  --created-by artemis-optimizer \
  --version v2.3.0 \
  --tags "api,v2.3,new-feature" \
  --notes "v2.3.0の新規API仕様書"
```

### 3. 登録済みドキュメントの確認

```bash
# 全ドキュメントのリスト
python3 scripts/document_registry.py list

# タグでフィルタリング
python3 scripts/document_registry.py list --tags security

# ステータスでフィルタリング
python3 scripts/document_registry.py list --status current

# 作成者でフィルタリング
python3 scripts/document_registry.py list --created-by hestia-auditor
```

### 4. ドキュメントステータスの更新

```bash
# currentからdeprecatedへ変更
python3 scripts/document_registry.py update-status docs/old_guide.md deprecated

# deprecatedからarchivedへ変更（削除前の最終段階）
python3 scripts/document_registry.py update-status docs/old_guide.md archived
```

### 5. レジストリの整合性検証

```bash
# 全ドキュメントの存在確認とチェックサム検証
python3 scripts/document_registry.py validate
```

---

## CLI コマンドリファレンス

### `add` - ドキュメント登録

**構文**:
```bash
python3 scripts/document_registry.py add <file_path> [OPTIONS]
```

**必須オプション**:
- `<file_path>`: 登録するドキュメントのパス（相対パス推奨）

**推奨オプション**:
- `--title TEXT`: ドキュメントタイトル（デフォルト: ファイル名）
- `--purpose TEXT`: ドキュメント目的（例: guide, api-reference, report）
- `--created-by TEXT`: 作成者（Trinitasペルソナ名推奨）

**任意オプション**:
- `--version TEXT`: バージョン番号（例: v2.2.6）
- `--tags TEXT`: カンマ区切りのタグ（例: "security,api,v2.3"）
- `--notes TEXT`: 追加メモ
- `--status TEXT`: 初期ステータス（デフォルト: current）
  - `draft`: 草稿段階
  - `current`: 現在有効（デフォルト）
  - `deprecated`: 非推奨
  - `archived`: アーカイブ済み

**例**:
```bash
# 最小限の登録
python3 scripts/document_registry.py add docs/README.md

# 完全なメタデータ付き登録
python3 scripts/document_registry.py add docs/SECURITY_GUIDE.md \
  --title "Trinitas Security Best Practices" \
  --purpose guide \
  --created-by hestia-auditor \
  --version v2.2.6 \
  --tags "security,best-practices,production" \
  --notes "Hestiaによる包括的セキュリティガイド"
```

---

### `list` - ドキュメント一覧表示

**構文**:
```bash
python3 scripts/document_registry.py list [OPTIONS]
```

**オプション**:
- `--status TEXT`: ステータスでフィルタ（current, draft, deprecated, archived）
- `--tags TEXT`: タグでフィルタ（カンマ区切り）
- `--created-by TEXT`: 作成者でフィルタ
- `--format TEXT`: 出力形式（table, json, summary）
  - `table`: 表形式（デフォルト）
  - `json`: JSON形式（機械可読）
  - `summary`: 統計サマリー

**例**:
```bash
# 全ドキュメント
python3 scripts/document_registry.py list

# 現在有効なドキュメントのみ
python3 scripts/document_registry.py list --status current

# セキュリティ関連ドキュメント
python3 scripts/document_registry.py list --tags security

# Hestiaが作成したドキュメント
python3 scripts/document_registry.py list --created-by hestia-auditor

# JSON形式で出力（自動化向け）
python3 scripts/document_registry.py list --format json > docs_list.json

# 統計サマリー
python3 scripts/document_registry.py list --format summary
```

---

### `validate` - レジストリ整合性検証

**構文**:
```bash
python3 scripts/document_registry.py validate
```

**検証項目**:
- ドキュメントファイルの存在確認
- ファイルサイズの検証
- SHA-256チェックサムの検証（改ざん検出）
- パス構造の安全性確認

**出力例**:
```
✅ Validation passed: 15/15 documents OK
⚠️  Warning: 2 files have been modified since registration
❌ Error: 1 file missing (docs/deleted.md)
```

---

### `update-status` - ステータス変更

**構文**:
```bash
python3 scripts/document_registry.py update-status <file_path> <new_status>
```

**ステータス遷移の推奨フロー**:
```
draft → current → deprecated → archived
```

**例**:
```bash
# 草稿を現在有効に昇格
python3 scripts/document_registry.py update-status docs/draft_guide.md current

# 古いドキュメントを非推奨に変更
python3 scripts/document_registry.py update-status docs/old_api_v1.md deprecated

# 非推奨ドキュメントをアーカイブ
python3 scripts/document_registry.py update-status docs/old_api_v1.md archived
```

---

### `remove` - ドキュメント削除（レジストリから除外）

**構文**:
```bash
python3 scripts/document_registry.py remove <file_path>
```

**注意**:
- レジストリからメタデータを削除します
- ファイル自体は削除されません（手動削除が必要）
- 削除前に `archived` ステータスへの変更を推奨

**例**:
```bash
# ステップ1: archivedステータスに変更
python3 scripts/document_registry.py update-status docs/obsolete.md archived

# ステップ2: レジストリから削除
python3 scripts/document_registry.py remove docs/obsolete.md

# ステップ3: ファイル自体を削除（任意）
rm docs/obsolete.md
```

---

## ワークフロー例

### ワークフロー1: 新規ドキュメント作成

```bash
# 1. ドキュメントを作成
vim docs/NEW_FEATURE_GUIDE.md

# 2. draftステータスで登録
python3 scripts/document_registry.py add docs/NEW_FEATURE_GUIDE.md \
  --title "New Feature Implementation Guide" \
  --purpose guide \
  --created-by artemis-optimizer \
  --status draft \
  --tags "feature,implementation,v2.3"

# 3. レビュー後、currentに昇格
python3 scripts/document_registry.py update-status docs/NEW_FEATURE_GUIDE.md current

# 4. 整合性検証
python3 scripts/document_registry.py validate
```

---

### ワークフロー2: 古いドキュメントのアーカイブ

```bash
# 1. 現在のドキュメントリストを確認
python3 scripts/document_registry.py list --status current

# 2. 古いドキュメントを特定
python3 scripts/document_registry.py list --tags phase0,phase1

# 3. 非推奨に変更
python3 scripts/document_registry.py update-status docs/PHASE0_PLAN.md deprecated

# 4. 一定期間後、アーカイブに移動
python3 scripts/document_registry.py update-status docs/PHASE0_PLAN.md archived

# 5. アーカイブディレクトリに移動（任意）
mkdir -p docs/archive/phase0/
mv docs/PHASE0_PLAN.md docs/archive/phase0/

# 6. レジストリから削除
python3 scripts/document_registry.py remove docs/PHASE0_PLAN.md
```

---

### ワークフロー3: セキュリティ監査ドキュメント管理

```bash
# 1. セキュリティ関連ドキュメントの登録
python3 scripts/document_registry.py add docs/SECURITY_AUDIT_2025Q4.md \
  --title "Q4 2025 Security Audit Report" \
  --purpose report \
  --created-by hestia-auditor \
  --version v2.2.6 \
  --tags "security,audit,2025Q4,critical" \
  --notes "Hestiaによる包括的セキュリティ監査"

# 2. セキュリティドキュメントの一覧確認
python3 scripts/document_registry.py list --tags security --format table

# 3. 四半期ごとに古い監査レポートをアーカイブ
python3 scripts/document_registry.py update-status docs/SECURITY_AUDIT_2025Q3.md archived

# 4. 監査履歴の検証
python3 scripts/document_registry.py validate
```

---

## セキュリティ考慮事項

### 1. 許可されるディレクトリ

Document Registry Systemは以下のディレクトリ配下のファイルのみを許可します:

- `docs/`
- `trinitas_sources/`

これにより、システムファイルへの不正アクセスを防止しています（CWE-22対策）。

### 2. 禁止されるパターン

以下のパターンを含むパスは拒否されます:

- `..` (親ディレクトリへのトラバーサル)
- `~` (ホームディレクトリ参照)
- `${` (変数展開)
- `$(` (コマンド展開)
- `\x00` (NULLバイト)

### 3. ファイルサイズ制限

- **ドキュメントファイル**: 最大10MB（DoS防止）
- **レジストリメタデータ**: 最大1MB

大きなファイルを登録する必要がある場合は、分割を検討してください。

### 4. シンボリンク保護

シンボリンクへのアクセスは自動的に拒否されます（CWE-61対策）。実ファイルのみ登録可能です。

### 5. ファイルロック

複数プロセスからの同時アクセスは `fcntl.flock()` で保護されています。ただし、MVP版では基本的なロックのみ実装。Phase 2でACIDトランザクション対応予定。

---

## トラブルシューティング

### エラー: "Path traversal detected"

**原因**: 禁止されたパターン（`..`, `~`など）が含まれています。

**解決策**: 相対パスで指定するか、許可されたディレクトリ配下のパスを使用してください。

```bash
# ❌ NG
python3 scripts/document_registry.py add ../sensitive_file.md

# ✅ OK
python3 scripts/document_registry.py add docs/my_file.md
```

---

### エラー: "Symlink access denied"

**原因**: シンボリンクファイルを登録しようとしています。

**解決策**: 実ファイルを登録してください。

```bash
# シンボリンクを確認
ls -la docs/my_file.md

# 実ファイルを特定
readlink -f docs/my_file.md

# 実ファイルを登録
python3 scripts/document_registry.py add /path/to/real/file.md
```

---

### エラー: "File too large"

**原因**: ファイルサイズが10MBを超えています。

**解決策**: ファイルを分割するか、外部ストレージにリンクを記載してください。

```bash
# ファイルサイズ確認
ls -lh docs/large_file.md

# 分割例
split -b 5M docs/large_file.md docs/large_file_part_
```

---

### エラー: "Registry locked"

**原因**: 他のプロセスがレジストリファイルをロックしています。

**解決策**: 他の操作が完了するまで待機してください（通常は数秒以内）。

---

### 警告: "File modified since registration"

**原因**: ドキュメントファイルが登録後に変更されています。

**対処**:
1. 意図的な変更の場合: `update-status` でタイムスタンプを更新
2. 不正な変更の可能性: ファイルを検証し、必要に応じて復元

```bash
# チェックサム確認
python3 scripts/document_registry.py validate

# 再登録（チェックサム更新）
python3 scripts/document_registry.py add docs/modified_file.md --force
```

---

## ベストプラクティス

### 1. 命名規則

- **タイトル**: 明確で検索しやすい名前を使用
- **タグ**: 階層的なタグ体系を推奨（例: `security,api,v2.3`）
- **ファイル名**: スネークケースまたはケバブケース推奨

### 2. メタデータの一貫性

- `created-by`: Trinitasペルソナ名を使用（例: `hestia-auditor`, `artemis-optimizer`）
- `version`: プロジェクトバージョンと同期（例: `v2.2.6`）
- `purpose`: 以下のカテゴリから選択
  - `guide`: ガイド文書
  - `api-reference`: API仕様書
  - `report`: レポート
  - `design`: 設計書
  - `tutorial`: チュートリアル
  - `policy`: ポリシー文書

### 3. ライフサイクル管理

```
draft (草稿) → current (現在有効) → deprecated (非推奨) → archived (アーカイブ)
```

- **draft**: レビュー前の草稿段階
- **current**: 現在有効なドキュメント
- **deprecated**: 将来削除予定（6ヶ月程度保持推奨）
- **archived**: 履歴保存（削除可能だが保持推奨）

### 4. タグ戦略

**推奨タグ体系**:
- **カテゴリ**: `security`, `api`, `guide`, `report`
- **バージョン**: `v2.2`, `v2.3`, `phase1`, `phase2`
- **重要度**: `critical`, `important`, `reference`
- **ペルソナ**: `athena`, `artemis`, `hestia`, `eris`, `hera`, `muses`

**例**:
```bash
python3 scripts/document_registry.py add docs/CRITICAL_SECURITY_POLICY.md \
  --tags "security,policy,critical,hestia,v2.2.6"
```

### 5. 定期的な整合性検証

```bash
# 週次で整合性検証を実行
python3 scripts/document_registry.py validate

# 月次でアーカイブ対象を確認
python3 scripts/document_registry.py list --status deprecated
```

---

## Phase 2 以降の予定機能

MVP版（Phase 1）では基本機能のみ実装しています。Phase 2以降で以下の機能を追加予定:

### Phase 2 (Hardening - 1週間)

- ✅ HIGH-severityセキュリティ修正（15脆弱性）
- ✅ 包括的テストスイート（pytest）
- ✅ CI/CD統合（GitHub Actions）
- ✅ Git hooks（pre-commit検証）
- ✅ Atomic operations（ロールバック対応）
- ✅ Audit logging（変更履歴）

### Phase 3 (Production - 2週間)

- ✅ MEDIUM-severityセキュリティ修正（10脆弱性）
- ✅ パフォーマンス最適化
- ✅ 外部セキュリティ監査
- ✅ YAML形式サポート（SafeYAMLLoader）
- ✅ Webダッシュボード（可視化）
- ✅ 自動分類（AI支援）

---

## サポートと問い合わせ

### バグ報告

GitHub Issuesにて報告してください:
- セキュリティ脆弱性: `hestia-auditor` タグ
- 機能要望: `artemis-optimizer` タグ
- ドキュメント改善: `muses-documenter` タグ

### ドキュメント改善

このガイド自体も Document Registry Systemで管理されています:

```bash
python3 scripts/document_registry.py list --tags guide
```

改善提案は Pull Request で歓迎します。

---

## クレジット

**開発**: Trinitas Collaboration
- **Athena** (Harmonious Conductor): 最終統合と意思決定
- **Artemis** (Technical Optimizer): システム設計と実装
- **Hestia** (Security Guardian): セキュリティ監査と脆弱性対策
- **Eris** (Tactical Coordinator): 要件バランス調整とフェーズ計画

**バージョン**: v1.0.0 (MVP)
**リリース日**: 2025-11-03
**ライセンス**: Trinitas-agents Project License

---

*"Through harmonious orchestration and strategic precision, we document excellence together."*

*調和的な指揮と戦略的精密さを通じて、共に卓越した文書化を実現する。*
