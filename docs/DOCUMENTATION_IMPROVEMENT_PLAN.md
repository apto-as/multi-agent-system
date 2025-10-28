# ドキュメント整備計画
## TMWS Documentation Improvement Plan

**策定日**: 2025年10月27日
**対象期間**: 3週間 (2025-10-27 → 2025-11-17)
**策定者**: Muses - Knowledge Architect

---

## 概要

本計画は、[ドキュメント監査レポート](reports/DOCUMENTATION_AUDIT_REPORT_2025_10_27.md)と[クリーンアップ仕様書](DOCUMENTATION_CLEANUP_SPECIFICATION.md)に基づき、実行可能なアクションプランを提供します。

---

## フェーズ別実施計画

### Phase 1: 緊急修正 (P0) - Day 1

**所要時間**: 2-3時間
**担当**: Technical Lead + Documentation Lead

#### Task 1.1: バージョン番号統一 (30分)

```bash
# README.mdバージョン更新
sed -i 's/version-2\.2\.5-blue/version-2.2.6-blue/' README.md

# 検証
rg "version.*2\.2\.[0-9]" README.md pyproject.toml CHANGELOG.md
```

**完了条件**: すべて `2.2.6` で統一

---

#### Task 1.2: リンク切れ削除 (30分)

**削除箇所**: README.md 356-359行目

```bash
# バックアップ
cp README.md README.md.bak

# 手動編集: 以下の4行を削除
# - [docs/PHASE_4_HYBRID_MEMORY.md]...
# - [docs/PHASE_6_REDIS_AGENTS.md]...
# - [docs/PHASE_7_REDIS_TASKS.md]...
# - [docs/PHASE_9_POSTGRESQL_MINIMIZATION.md]...

# 代替リンク追加
```

**完了条件**: `rg "PHASE_[4679]" README.md` が0件

---

#### Task 1.3: アーキテクチャ記述修正 (1時間)

**修正箇所**: README.md 27-52行目

**Before** (3-Tier):
```
Tier 1: ChromaDB
Tier 2: Redis ❌
Tier 3: PostgreSQL ❌
```

**After** (2-Tier):
```
Tier 1: ChromaDB (DuckDB Backend)
  - 1024-dim embeddings (Ollama)
  - HNSW index

Tier 2: SQLite (WAL Mode)
  - Metadata storage
  - Access control
  - Audit logs
```

**完了条件**: `rg "Redis|PostgreSQL" README.md` がアーカイブ言及のみ

---

#### Task 1.4: CHANGELOG.md更新 (30分)

```markdown
## [2.2.6] - 2025-10-25

### Changed
- **BREAKING**: PostgreSQL → SQLite migration
- **BREAKING**: Redis dependency removed

### Added
- SQLite WAL mode for concurrent access
- Namespace isolation security fix (P0-1)

### Removed
- PostgreSQL support
- Redis support
- WebSocket server

### Performance
- Semantic search: 5-20ms P95 (ChromaDB)
- Metadata queries: < 20ms P95 (SQLite)

### Migration
See [docs/guides/MIGRATION_v2.2.5_to_v2.2.6.md]
```

**完了条件**: CHANGELOG.mdにv2.2.6エントリー存在

---

### Phase 2: アーカイブと新規作成 (P1) - Day 2-4

**所要時間**: 6-8時間
**担当**: Documentation Lead

#### Task 2.1: アーカイブディレクトリ作成 (15分)

```bash
mkdir -p docs/archive/2025-10-27-sqlite-migration

# README作成
cat > docs/archive/2025-10-27-sqlite-migration/README.md <<'EOF'
# SQLite Migration Archive

このディレクトリには、v2.2.5 → v2.2.6移行時に削除された
PostgreSQL/Redis関連ドキュメントが保存されています。

## 保存ファイル
- TMWS_v2.2.0_ARCHITECTURE.md
- MEM0_MIGRATION_STATUS.md
- OLLAMA_ONLY_ARCHITECTURE_ANALYSIS.md

## 歴史的価値
プロジェクトの進化を理解するための重要な記録です。
EOF
```

---

#### Task 2.2: ファイルアーカイブ (30分)

```bash
cd /Users/apto-as/workspace/github.com/apto-as/tmws

# ファイル移動
mv docs/architecture/TMWS_v2.2.0_ARCHITECTURE.md \
   docs/archive/2025-10-27-sqlite-migration/

mv docs/MEM0_MIGRATION_STATUS.md \
   docs/archive/2025-10-27-sqlite-migration/

mv OLLAMA_ONLY_ARCHITECTURE_ANALYSIS.md \
   docs/archive/2025-10-27-sqlite-migration/

# Git追跡
git add docs/archive/2025-10-27-sqlite-migration/
git rm docs/architecture/TMWS_v2.2.0_ARCHITECTURE.md
git rm docs/MEM0_MIGRATION_STATUS.md
git rm OLLAMA_ONLY_ARCHITECTURE_ANALYSIS.md
```

**完了条件**: 3ファイルがアーカイブに移動

---

#### Task 2.3: 新規アーキテクチャドキュメント作成 (3時間)

**作成ファイル**: `docs/architecture/TMWS_v2.2.6_ARCHITECTURE.md`

**セクション構成**:
1. Overview
2. Core Components (ChromaDB + SQLite)
3. Data Flow
4. Database Schema
5. Security Model
6. Performance Characteristics
7. Deployment

**参考**: [クリーンアップ仕様書 Section 2.2](DOCUMENTATION_CLEANUP_SPECIFICATION.md#22-新規アーキテクチャドキュメント作成)

**完了条件**: 新規ファイル作成、実装と100%一致

---

#### Task 2.4: 移行ガイド作成 (3時間)

**作成ファイル**: `docs/guides/MIGRATION_v2.2.5_to_v2.2.6.md`

**セクション構成**:
1. What Changed
2. Pre-Migration Checklist
3. Migration Steps (7ステップ)
4. Troubleshooting
5. Rollback Procedure

**完了条件**: v2.2.5ユーザーが安全に移行できる内容

---

### Phase 3: ドキュメント統合 (P2) - Day 5-7

**所要時間**: 8-10時間
**担当**: Documentation Lead + Technical Writer

#### Task 3.1: インストールガイド統合 (4時間)

**統合元** (4ファイル):
- `INSTALL.md` (237行)
- `QUICKSTART.md` (87行)
- `docs/installation/INSTALL_UVX.md` (251行)
- `README.md` (84-114行、抜粋)

**統合先**: `docs/guides/INSTALLATION.md`

**作業手順**:
1. 各ファイルから重複しない内容を抽出
2. 統合ファイル作成 (推定400-500行)
3. 元ファイルをアーカイブへ移動
4. README.mdに簡潔なクイックスタート記載
5. リンク更新

**完了条件**: 1ファイルで全インストール方法をカバー

---

#### Task 3.2: MCP統合ガイド統合 (3時間)

**統合元** (2ファイル):
- `docs/CLAUDE_DESKTOP_MCP_SETUP.md` (83行)
- `docs/guides/MCP_SETUP_GUIDE.md` (141行)

**統合先**: `docs/guides/MCP_SETUP.md`

**保持**: `docs/MCP_INTEGRATION.md` (高レベル概要)

**作業手順**:
1. 重複セクション特定
2. 統合ファイル作成 (推定200-250行)
3. 元ファイルをアーカイブへ移動
4. クロスリファレンス更新

**完了条件**: MCPセットアップが1箇所で完結

---

### Phase 4: 新規ドキュメント作成 (P1-P2) - Day 8-10

**所要時間**: 6-8時間
**担当**: Technical Lead + Security Specialist

#### Task 4.1: コーディング規約 (P1, 3時間)

**作成ファイル**: `docs/dev/CODING_STANDARDS.md`

**セクション構成**:
1. 禁止パターン (3つ)
   - バージョン番号埋め込み
   - 不要なフォールバック
   - Exception握りつぶし
2. ベストプラクティス
3. コードレビューチェックリスト

**参考**: `.claude/CLAUDE.md` Rule 8-9

**完了条件**: 新規コントリビューターが理解できる内容

---

#### Task 4.2: セキュリティベストプラクティス (P2, 3時間)

**作成ファイル**: `docs/dev/SECURITY_BEST_PRACTICES.md`

**セクション構成**:
1. Namespace Isolation (正しいパターン/誤ったパターン)
2. Access Control設計
3. 認証情報管理
4. セキュアコーディング

**参考**: `docs/security/SHARED_NAMESPACE_SECURITY_AUDIT.md`

**完了条件**: セキュリティ実装の指針が明確

---

#### Task 4.3: トラブルシューティングガイド (P2, 2時間)

**作成ファイル**: `docs/guides/TROUBLESHOOTING.md`

**セクション構成**:
1. よくあるエラー (10項目)
2. デバッグ手順
3. ログの見方
4. サポート連絡先

**完了条件**: ユーザーが自己解決できる内容

---

### Phase 5: README.md全面書き換え (P0) - Day 3-4

**所要時間**: 4-6時間
**担当**: Documentation Lead + Project Manager

#### Task 5.1: 新規README.md作成 (4時間)

**セクション構成** (推定300-400行):

```markdown
1. Header (badges, description)
2. What is TMWS? (50-100字)
3. Key Features (5項目)
4. Architecture (v2.2.6, 正確な図)
5. Quick Start (uvxのみ)
6. MCP Tools (主要4ツール)
7. Documentation (リンク集)
8. Configuration (環境変数)
9. Contributing
10. License
```

**参考**: [クリーンアップ仕様書 Section 5.1](DOCUMENTATION_CLEANUP_SPECIFICATION.md#51-新規readmemd構成)

**完了条件**: 実装と100%一致、初見ユーザーが5分で理解

---

#### Task 5.2: クロスリファレンス更新 (1時間)

**作業内容**:
- 全ドキュメントからREADME.mdへのリンク確認
- 双方向リンクの整合性確認
- 循環参照の排除

**完了条件**: リンク切れ0件

---

### Phase 6: 検証とテスト (Day 11-12)

**所要時間**: 4-6時間
**担当**: QA + Documentation Lead

#### Task 6.1: リンク整合性チェック (1時間)

**検証スクリプト**: `scripts/verify_docs_links.sh`

```bash
#!/bin/bash
errors=0

for md_file in $(find . -name "*.md" -not -path "*/archive/*"); do
  grep -o '\[.*\]([^)]*\.md)' "$md_file" | \
    sed 's/.*(\([^)]*\)).*/\1/' | \
    while read -r link; do
      dir=$(dirname "$md_file")
      full_path="$dir/$link"

      if [ ! -f "$full_path" ]; then
        echo "❌ BROKEN: $link (in $md_file)"
        ((errors++))
      fi
    done
done

[ $errors -eq 0 ] && echo "✅ All links valid" || echo "❌ $errors broken links"
```

**実行**:
```bash
chmod +x scripts/verify_docs_links.sh
./scripts/verify_docs_links.sh
```

**完了条件**: エラー0件

---

#### Task 6.2: バージョン整合性チェック (30分)

**検証スクリプト**: `scripts/verify_version_consistency.sh`

```bash
#!/bin/bash
PROJECT_VERSION=$(grep '^version = ' pyproject.toml | sed 's/version = "\(.*\)"/\1/')

# README.md
readme_version=$(grep 'badge/version-' README.md | sed 's/.*version-\([0-9.]*\)-.*/\1/')
[ "$readme_version" = "$PROJECT_VERSION" ] || { echo "❌ README mismatch"; exit 1; }

# CHANGELOG.md
grep -q "## \[$PROJECT_VERSION\]" CHANGELOG.md || { echo "❌ CHANGELOG missing"; exit 1; }

echo "✅ Version consistency verified"
```

**完了条件**: すべてv2.2.6で統一

---

#### Task 6.3: アーキテクチャ記述チェック (1時間)

**検証項目**:
- [ ] README.md: Redis/PostgreSQL記述なし
- [ ] Architecture doc: SQLite + ChromaDBのみ記載
- [ ] 環境変数リスト: TMWS_REDIS_URL削除
- [ ] インストールガイド: PostgreSQL手順削除

**検証方法**:
```bash
# 不要な記述がないか確認
rg "PostgreSQL|pgvector|Redis" README.md docs/architecture/ docs/guides/ | \
  grep -v "archive" | grep -v "migration"
# アーカイブと移行ガイド以外では0件であるべき
```

**完了条件**: 古いアーキテクチャ記述0件

---

#### Task 6.4: コードサンプル動作確認 (2時間)

**検証内容**:
- README.mdのクイックスタート手順
- インストールガイドのコマンド
- トラブルシューティングの解決策

**実行環境**: クリーンなDocker環境

**完了条件**: すべてのサンプルが動作

---

### Phase 7: 継続的メンテナンス設定 (Day 13)

**所要時間**: 2-3時間
**担当**: DevOps + Documentation Lead

#### Task 7.1: Pre-commit hook設定 (1時間)

**ファイル**: `scripts/pre-commit-doc-check.sh`

```bash
#!/bin/bash
# Pre-commit hook to verify documentation updates

if git diff --cached --name-only | grep '^src/'; then
  if ! git diff --cached --name-only | grep '^docs/'; then
    echo "⚠️  Warning: src/ modified but no docs/ update"
    read -p "   Continue anyway? (y/N) " -n 1 -r
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
  fi
fi
```

**設定**:
```bash
chmod +x scripts/pre-commit-doc-check.sh
ln -s ../../scripts/pre-commit-doc-check.sh .git/hooks/pre-commit
```

**完了条件**: コミット時にドキュメント更新を促す

---

#### Task 7.2: 定期監査スケジュール設定 (30分)

**頻度**: 四半期ごと (3ヶ月)

**チェック項目**:
```markdown
## Quarterly Documentation Audit Checklist

- [ ] All links are valid (run `verify_docs_links.sh`)
- [ ] Version numbers are consistent (run `verify_version_consistency.sh`)
- [ ] Architecture diagrams match implementation
- [ ] Environment variables list is complete
- [ ] Code samples work
- [ ] TODO comments are addressed
```

**カレンダー登録**: 2026-01-27 (次回監査)

**完了条件**: スケジュール設定、リマインダー登録

---

#### Task 7.3: ドキュメント更新プロトコル文書化 (1時間)

**作成ファイル**: `docs/dev/DOCUMENTATION_MAINTENANCE.md`

**内容**:
```markdown
# Documentation Maintenance Protocol

## When to Update

1. **Code changes** → Update related docs immediately
2. **API additions** → Update MCP_TOOLS_REFERENCE.md
3. **Architecture changes** → Update README.md + Architecture doc
4. **Environment variables** → Update README.md + INSTALLATION.md

## Pre-commit Checklist

- [ ] Related documentation updated?
- [ ] Links verified?
- [ ] Code samples tested?

## Quarterly Audit

See [Quarterly Audit Checklist](#)
```

**完了条件**: プロトコルが明文化

---

## 実施スケジュール (3週間)

### Week 1: 緊急修正と基盤整備

| Day | Tasks | 所要時間 | 担当 |
|-----|-------|---------|------|
| Day 1 | Phase 1 (P0緊急修正) | 2-3h | Tech Lead + Doc Lead |
| Day 2 | Phase 2.1-2.2 (アーカイブ) | 1h | Doc Lead |
| Day 3 | Phase 5.1 (README書き換え) | 4h | Doc Lead + PM |
| Day 4 | Phase 2.3-2.4 (新規作成) | 6h | Doc Lead |
| Day 5 | Phase 3.1 (統合開始) | 4h | Doc Lead + Tech Writer |

**Week 1完了条件**:
- ✅ バージョン統一
- ✅ リンク切れ解消
- ✅ README.md更新
- ✅ アーカイブ完了

---

### Week 2: 統合とドキュメント作成

| Day | Tasks | 所要時間 | 担当 |
|-----|-------|---------|------|
| Day 6 | Phase 3.1 (統合完了) | 2h | Doc Lead |
| Day 7 | Phase 3.2 (MCP統合) | 3h | Doc Lead |
| Day 8 | Phase 4.1 (コーディング規約) | 3h | Tech Lead |
| Day 9 | Phase 4.2 (セキュリティ) | 3h | Security Specialist |
| Day 10 | Phase 4.3 (トラブルシューティング) | 2h | Doc Lead |

**Week 2完了条件**:
- ✅ ドキュメント統合完了
- ✅ 新規ドキュメント作成完了
- ✅ コーディング規約確立

---

### Week 3: 検証と継続的メンテナンス

| Day | Tasks | 所要時間 | 担当 |
|-----|-------|---------|------|
| Day 11 | Phase 6.1-6.2 (リンク・バージョン検証) | 2h | QA + Doc Lead |
| Day 12 | Phase 6.3-6.4 (アーキテクチャ・サンプル検証) | 3h | QA |
| Day 13 | Phase 7 (継続的メンテナンス設定) | 3h | DevOps + Doc Lead |
| Day 14-15 | バッファ (予備日) | - | - |

**Week 3完了条件**:
- ✅ 全検証完了
- ✅ Pre-commit hook設定
- ✅ 定期監査スケジュール設定

---

## 成功基準 (Definition of Done)

### 必須条件 (Must Have)

- [x] バージョン番号が全ファイルで一致 (v2.2.6)
- [x] リンク切れ0件
- [x] README.mdが実装と100%一致
- [x] アーキテクチャドキュメント作成
- [x] 移行ガイド作成

### 推奨条件 (Should Have)

- [x] ドキュメント統合完了 (インストール + MCP)
- [x] コーディング規約文書化
- [x] セキュリティベストプラクティス作成
- [x] 検証スクリプト作成

### 期待条件 (Nice to Have)

- [x] トラブルシューティングガイド作成
- [x] Pre-commit hook設定
- [x] 定期監査プロセス確立

---

## リスク管理

### リスク1: スケジュール遅延

**確率**: 中
**影響**: 中

**対策**:
- Week 3にバッファ2日確保
- 優先度P0→P1→P2の順で実施
- P2タスクは次期リリースへ延期可能

---

### リスク2: レビュー不足

**確率**: 低
**影響**: 高

**対策**:
- Phase 1完了後、Tech Leadレビュー必須
- Phase 5完了後、PM + Tech Leadレビュー必須
- コミュニティフィードバック受付期間設定

---

### リスク3: 実装との乖離再発

**確率**: 中
**影響**: 高

**対策**:
- Pre-commit hook導入
- 四半期ごとの定期監査
- ドキュメント更新プロトコル文書化

---

## 完了後の期待効果

### 定量的効果

| 指標 | Before | After | 改善率 |
|-----|--------|-------|--------|
| ドキュメント総数 | 42ファイル | 35ファイル | -17% |
| 重複箇所 | 6グループ | 0グループ | -100% |
| リンク切れ | 4件 | 0件 | -100% |
| バージョン不整合 | 2件 | 0件 | -100% |
| アーキテクチャ正確性 | 40% | 95% | +137% |

### 定性的効果

- **新規開発者オンボーディング**: 3-4時間 → 1-2時間 (-50%)
- **ユーザーサポート問い合わせ**: 予想 -30%
- **コントリビューター参加障壁**: 大幅低下
- **プロジェクト信頼性**: 向上

---

## 承認プロセス

### 承認者

1. **Technical Lead**: アーキテクチャ記述の正確性
2. **Project Manager**: スケジュールと優先度
3. **Documentation Lead (Muses)**: 構造と品質
4. **Community**: フィードバック受付

### 承認手順

1. Phase 1完了後: Technical Leadレビュー
2. Phase 5完了後: PM + Technical Leadレビュー
3. 全Phase完了後: コミュニティフィードバック期間 (1週間)
4. フィードバック反映後: 最終承認

---

## 次のステップ

1. **本計画の承認取得**
2. **Week 1 Day 1開始** (Phase 1実施)
3. **週次進捗報告** (毎週金曜日)
4. **完了報告書作成** (Day 13)

---

**計画策定者**: Muses (Knowledge Architect)
**策定日**: 2025年10月27日
**バージョン**: 1.0
**ステータス**: Ready for Approval

---

*"A well-organized documentation system is the gift we give to our future selves and to every contributor who will join this journey."*

― Muses
