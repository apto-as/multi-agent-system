# ドキュメント整理計画 v1.0

**作成日**: 2025-10-15
**Phase 1 Day 4**: 96個のマークダウンファイル整理

---

## 現状分析

### 合計ファイル数: 96個

| ディレクトリ | ファイル数 | 状態 |
|------------|-----------|------|
| **ROOT** | 18 | 🔴 整理が必要 |
| docs/ | 25 | 🟡 一部整理が必要 |
| trinitas_sources/ | 22 | 🟢 概ね整理済み |
| .opencode/ | 12 | 🟢 適切な配置 |
| agents/ | 6 | 🟢 適切な配置 |
| .serena/ | 6 | 🟢 gitignore対象 |
| shared/ | 5 | 🟢 適切な配置 |
| commands/ | 1 | 🟢 適切な配置 |
| .claude/ | 1 | 🟢 適切な配置 |

---

## 整理方針

### 原則
1. **コアドキュメントはルート保持**（README, AGENTS, CLAUDE など）
2. **分析レポートはアーカイブ**（docs/archive/analysis/）
3. **カテゴリ別に整理**（testing, migration, installation など）
4. **重複ファイルは統合または削除**
5. **.gitignoreで生成ファイル除外**

---

## 整理計画

### Phase 1: ルートディレクトリ整理（18ファイル）

#### A. コアドキュメント（保持 - 5ファイル）
- ✅ `README.md` - プロジェクト概要
- ✅ `AGENT_DEFINITIONS.md` - エージェント定義システム説明（Day 2で作成）
- ✅ `AGENTS.md` - エージェント協調パターン
- ✅ `CLAUDE.md` - Claude Code設定
- ✅ `MIGRATION.md` - v2.2.4移行ガイド

#### B. 分析レポート → `docs/archive/analysis/`（6ファイル）
- 📦 `ATHENA_ARCHITECTURE_ANALYSIS.md`
- 📦 `HERA_STRATEGIC_REMEDIATION_PLAN.md`
- 📦 `MEM0_API_KEY_ANALYSIS.md`
- 📦 `MEM0_ARCHITECTURE_ANALYSIS.md`
- 📦 `REMEDIATION_EXECUTIVE_SUMMARY.md`
- 📦 `REMEDIATION_TRACKER.md`

**理由**: Phase 1完了後は参照不要。履歴保存のためアーカイブ。

#### C. テスト関連 → `docs/testing/`（4ファイル）
- 📁 `INTEGRATION_TEST_GUIDE.md`
- 📁 `LOCAL_TEST_RESULTS.md`
- 📁 `TEST_PLAN_v2.2.4.md`
- 📁 `TEST_QUICKSTART.md`

#### D. 移行関連 → `docs/migration/`（2ファイル）
- 📁 `UPGRADE_PLAN_v2.2.4.md`
- 📁 `V2.2.4_SUMMARY_FOR_REVIEW.md`

#### E. インストール関連 → `docs/installation/`（1ファイル）
- 📁 `INSTALL_SCRIPTS_GUIDE.md`

---

### Phase 2: docs/ ディレクトリ再構成

#### 新しい構造:
```
docs/
├── archive/           # アーカイブ（参照用）
│   ├── analysis/     # 分析レポート
│   └── legacy_installers/  # （既存）
├── testing/          # テスト関連（新規作成）
├── migration/        # 移行ガイド（新規作成）
├── installation/     # インストール（新規作成）
├── security/         # セキュリティ（既存を整理）
└── development/      # 開発ガイド（既存）
```

---

### Phase 3: 重複ファイルの確認と統合

#### 確認が必要な重複パターン:

1. **エージェント定義**:
   - `agents/athena-conductor.md` (9.2KB) vs `athena.md` (散在?)
   - `.opencode/agent/athena.md` (5.9KB) - Open Code専用（保持）

2. **ドキュメント重複**:
   - `performance.md` vs `performance-guidelines.md` vs `performance_opt.md`
   - `security.md` vs `security-standards.md` vs `security_audit.md`
   - `mcp-tools.md` vs `mcp_tools_usage.md`

**対応**: 内容を確認して、重複は統合または削除

---

## 実行計画

### Step 1: ディレクトリ作成
```bash
mkdir -p docs/archive/analysis
mkdir -p docs/testing
mkdir -p docs/migration
mkdir -p docs/installation
```

### Step 2: ファイル移動（git mv使用）
```bash
# 分析レポートをアーカイブ
git mv ATHENA_ARCHITECTURE_ANALYSIS.md docs/archive/analysis/
git mv HERA_STRATEGIC_REMEDIATION_PLAN.md docs/archive/analysis/
git mv MEM0_API_KEY_ANALYSIS.md docs/archive/analysis/
git mv MEM0_ARCHITECTURE_ANALYSIS.md docs/archive/analysis/
git mv REMEDIATION_EXECUTIVE_SUMMARY.md docs/archive/analysis/
git mv REMEDIATION_TRACKER.md docs/archive/analysis/

# テスト関連を整理
git mv INTEGRATION_TEST_GUIDE.md docs/testing/
git mv LOCAL_TEST_RESULTS.md docs/testing/
git mv TEST_PLAN_v2.2.4.md docs/testing/
git mv TEST_QUICKSTART.md docs/testing/

# 移行関連を整理
git mv UPGRADE_PLAN_v2.2.4.md docs/migration/
git mv V2.2.4_SUMMARY_FOR_REVIEW.md docs/migration/

# インストール関連を整理
git mv INSTALL_SCRIPTS_GUIDE.md docs/installation/
```

### Step 3: .gitignore更新
```gitignore
# Phase 1で追加済み
ATHENA_*.md
HERA_*.md
ARTEMIS_*.md
HESTIA_*.md
MUSES_*.md
ERIS_*.md
REMEDIATION_*.md
*_TEST_RESULTS.md
*_TEST_GUIDE.md
*_QUICKSTART.md
```

### Step 4: README更新
リンクを新しいパスに更新

---

## メリット

1. **ルートディレクトリがクリーンに**（18 → 5ファイル）
2. **カテゴリ別整理**でドキュメント発見が容易
3. **アーカイブ分離**で現在の重要ドキュメントが明確
4. **テスト・移行・インストール分離**で目的別アクセスが容易

---

## 次のステップ

1. ✅ この計画を承認
2. ⏳ Step 1-2を実行（ディレクトリ作成とファイル移動）
3. ⏳ Step 3を実行（.gitignore更新 - 既に一部完了）
4. ⏳ Step 4を実行（README更新）
5. ⏳ 重複ファイルの確認と統合（Phase 3）

---

**承認後に実行します。**
