# Trinitas for OpenCode

**Version**: 2.1.0 → 2.2.0 (Platform Separation)
**Platform**: OpenCode AI (by SST)
**Status**: Production Ready (v2.1.0) / Development (v2.2.0)

> **⚠️ NOTE**: This system is undergoing Platform Separation (v2.2.0).
> See [OPENCODE_ORCHESTRATION_REPORT.md](/Users/apto-as/workspace/github.com/apto-as/trinitas-agents/OPENCODE_ORCHESTRATION_REPORT.md) for details.
>
> **Current v2.1.0** remains stable and production-ready.
> **Upcoming v2.2.0** will have enhanced plugin system and better agent integration.

---

## 概要

### Trinitas for OpenCodeとは

Trinitas for OpenCodeは、6つの専門化されたAIペルソナによる高度なコード開発システムです。各ペルソナは特定の領域で卓越した能力を持ち、協調して複雑な開発タスクを遂行します。

**主な特徴**:
- 6つの専門化されたAIペルソナ（Athena, Artemis, Hestia, Eris, Hera, Muses）
- ファイルベースのローカルメモリシステム（完全プライベート）
- プラグインベースの品質管理とパフォーマンス監視
- モジュール化された協調パターン

### Claude Code版との違い

| 機能 | OpenCode版 | Claude Code版 |
|------|-----------|--------------|
| **インストール先** | `~/.config/opencode/` | `~/.claude/` |
| **エージェント形式** | Markdown (YAML frontmatter) | JSON |
| **プラグイン** | JavaScriptプラグイン（4種） | Pythonフック |
| **メモリシステム** | ファイルベース (ローカル) | ファイルベース (ローカル) |
| **設定ファイル** | `opencode.json` | `settings.json` |
| **コマンド** | `@athena`, `/trinitas` | `/trinitas` |
| **プロジェクト設定** | `.opencode/` | `.claude/` |

### 主な機能

1. **専門化されたペルソナ**
   - システムアーキテクチャ（Athena）
   - パフォーマンス最適化（Artemis）
   - セキュリティ監査（Hestia）
   - チーム調整（Eris）
   - 戦略計画（Hera）
   - ドキュメント作成（Muses）

2. **ファイルベースメモリ**
   - 完全ローカル実行（外部依存なし）
   - プライバシー重視（全てのデータはローカル保存）
   - シンプルで透明性の高いアーキテクチャ

3. **インテリジェントプラグイン**
   - 動的コンテキスト読み込み
   - ナラティブエンジン
   - パフォーマンス監視
   - 品質管理

---

## インストール

### 前提条件

```bash
# OpenCode CLIのインストール
npm i -g opencode-ai@latest

# または Homebrew (macOS)
brew install sst/tap/opencode

# バージョン確認
opencode --version
```

### 自動インストール（推奨）

```bash
# リポジトリのクローン
git clone https://github.com/apto-as/trinitas-agents.git
cd trinitas-agents

# インストールスクリプトの実行
./install_opencode.sh
```

インストーラーは以下を自動で行います:
1. 既存の設定のバックアップ
2. 6つのTrinitasエージェントのインストール
3. プラグインのインストール（4種）
4. システム指示（AGENTS.md）のインストール

### 手動インストール

```bash
# ディレクトリ作成
mkdir -p ~/.config/opencode/{agent,plugin,docs}

# エージェントのコピー
cp .opencode/agent/*.md ~/.config/opencode/agent/

# プラグインのコピー
cp .opencode/plugin/*.js ~/.config/opencode/plugin/

# システム指示のコピー
cp .opencode/AGENTS.md ~/.config/opencode/

# ドキュメントのコピー（オプション）
cp -r .opencode/docs ~/.config/opencode/
```

---

## 設定

### opencode.json の設定

プロジェクトルートまたは `~/.config/opencode/opencode.json` に配置:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "agent": {
    "default": "athena"
  },
  "instructions": [
    "# Trinitas AI System Instructions",
    "@~/.config/opencode/AGENTS.md"
  ],
  "permission": {
    "edit": "allow",
    "bash": {
      "*": "allow",
      "rm -rf /*": "deny",
      "sudo *": "ask"
    },
    "webfetch": "allow"
  },
  "tools": {
    "write": true,
    "edit": true,
    "bash": true,
    "read": true,
    "grep": true,
    "glob": true
  }
}
```

### Permissions設定

各エージェントには個別のパーミッション設定が可能です:

```yaml
# agent/athena.md のフロントマター例
permission:
  edit: allow
  bash:
    "*": allow
    "rm -rf /*": deny
    "sudo *": ask
  webfetch: allow
```

---

## 使用方法

### Agentsの起動

#### デフォルトエージェントでの起動

```bash
# プロジェクトディレクトリで
opencode

# デフォルトはAthena（システムアーキテクト）
```

#### 特定のエージェントを指定して起動

```bash
# システムアーキテクト（Athena）
opencode --agent athena

# パフォーマンス最適化（Artemis）
opencode --agent artemis

# セキュリティ監査（Hestia）
opencode --agent hestia

# チーム調整（Eris）
opencode --agent eris

# 戦略計画（Hera）
opencode --agent hera

# ドキュメント作成（Muses）
opencode --agent muses
```

#### インタラクティブなエージェント切り替え

OpenCode実行中に:
- **Tab キー**: エージェント選択メニューを表示
- **矢印キー**: エージェントを選択
- **Enter**: エージェントを切り替え

### Commandsの使用

#### `/trinitas` コマンド

```bash
# 特定のペルソナでタスクを実行
/trinitas execute athena "システムアーキテクチャの分析"
/trinitas execute artemis "パフォーマンス最適化"
/trinitas execute hestia "セキュリティ監査"

# 並列分析
/trinitas analyze "包括的システム分析" --personas athena,artemis,hestia
/trinitas analyze "セキュリティレビュー" --personas all --mode parallel
```

#### Trinitasコマンド

```bash
# 記憶の保存
/trinitas remember project_architecture "マイクロサービス設計" --importance 0.9
/trinitas remember security_finding "SQLインジェクション脆弱性" --importance 1.0 --persona hestia

# 記憶の取得
/trinitas recall architecture --semantic --limit 10
/trinitas recall "security patterns" --persona hestia --semantic
```

#### 学習システム

```bash
# パターン学習
/trinitas learn optimization_pattern "インデックス追加で90%高速化" --category performance

# パターン適用
/trinitas apply optimization_pattern "新しいAPIエンドポイント"
```

### Pluginsの動作確認

#### プラグインの有効化確認

```bash
# OpenCode起動時のログで確認
opencode

# 以下のようなログが表示されるべき:
# ✓ Loaded plugin: dynamic-context-loader
# ✓ Loaded plugin: narrative-engine
# ✓ Loaded plugin: performance-monitor
# ✓ Loaded plugin: quality-enforcer
```

#### プラグイン機能のテスト

```javascript
// 1. Dynamic Context Loader のテスト
// セキュリティ関連のファイルを開くと自動的にHestiaが提案される

// 2. Narrative Engine のテスト
// エージェントが自然なトーンで応答することを確認

// 3. Performance Monitor のテスト
// 大きなファイルの処理時にパフォーマンスメトリクスが表示される

// 4. Quality Enforcer のテスト
// コード変更時に自動的に品質チェックが実行される
```

---

## Trinitasペルソナ一覧

| ペルソナ | ID | 役割 | トリガーワード | 特性 |
|---------|---|------|--------------|-----|
| **Athena** | `athena` | Harmonious Conductor | orchestration, workflow, automation | システム全体の調和的な指揮と調整 |
| **Artemis** | `artemis` | Technical Perfectionist | optimization, performance, quality | パフォーマンス最適化とコード品質 |
| **Hestia** | `hestia` | Security Guardian | security, audit, vulnerability | セキュリティ分析と脆弱性評価 |
| **Eris** | `eris` | Tactical Coordinator | coordinate, team, tactical | 戦術計画とチーム調整 |
| **Hera** | `hera` | Strategic Commander | strategy, planning, architecture | 戦略計画とアーキテクチャ設計 |
| **Muses** | `muses` | Knowledge Architect | documentation, knowledge, record | ドキュメント作成と構造化 |

### 各ペルソナの詳細

#### Athena - Harmonious Conductor 🏛️

**専門領域**:
- システムアーキテクチャ設計と検証
- ワークフローオーケストレーション
- リソース最適化と調整
- チーム間の橋渡し

**使用例**:
```bash
opencode --agent athena
# "新しいマイクロサービスのアーキテクチャを設計してください"
# "既存システムとの統合計画を立ててください"
```

#### Artemis - Technical Perfectionist 🏹

**専門領域**:
- パフォーマンス最適化
- コード品質分析
- アルゴリズム改善
- ベストプラクティス適用

**使用例**:
```bash
opencode --agent artemis
# "このコードのパフォーマンスを最適化してください"
# "データベースクエリを高速化してください"
```

#### Hestia - Security Guardian 🔥

**専門領域**:
- セキュリティ監査
- 脆弱性評価
- リスク管理
- コンプライアンスチェック

**使用例**:
```bash
opencode --agent hestia
# "認証システムのセキュリティ監査を実施してください"
# "XSS脆弱性をチェックしてください"
```

#### Eris - Tactical Coordinator ⚔️

**専門領域**:
- チーム調整
- 競合解決
- ワークフロー調整
- 実装の優先順位付け

**使用例**:
```bash
opencode --agent eris
# "複数のフィーチャーブランチの統合を調整してください"
# "チーム間の技術的な競合を解決してください"
```

#### Hera - Strategic Commander 🎭

**専門領域**:
- 戦略計画
- 長期ビジョン
- ロードマップ策定
- ステークホルダー管理

**使用例**:
```bash
opencode --agent hera
# "Q2のプロダクトロードマップを策定してください"
# "技術負債解消の戦略を立ててください"
```

#### Muses - Knowledge Architect 📚

**専門領域**:
- ドキュメント作成
- API文書化
- ナレッジベース管理
- 技術仕様書作成

**使用例**:
```bash
opencode --agent muses
# "このAPIの完全なドキュメントを作成してください"
# "新機能のユーザーガイドを作成してください"
```

---

## 実践的な使用例

### Example 1: 新機能の実装

```bash
# Step 1: アーキテクチャ設計（Athena）
opencode --agent athena
# "ユーザー認証システムの設計をお願いします"

# Step 2: セキュリティレビュー（Hestia）
opencode --agent hestia
# "設計のセキュリティレビューをお願いします"

# Step 3: 実装（Artemis）
opencode --agent artemis
# "パフォーマンスを考慮した実装をお願いします"

# Step 4: ドキュメント化（Muses）
opencode --agent muses
# "実装のドキュメントを作成してください"
```

### Example 2: パフォーマンス最適化

```bash
# Step 1: ボトルネック特定（Artemis）
opencode --agent artemis
# "データベースクエリのボトルネックを特定してください"

# Step 2: 最適化実装（Artemis）
# "特定したボトルネックを最適化してください"

# Step 3: セキュリティ影響確認（Hestia）
opencode --agent hestia
# "最適化がセキュリティに影響しないか確認してください"

# Step 4: ドキュメント更新（Muses）
opencode --agent muses
# "最適化の結果をドキュメント化してください"
```

### Example 3: セキュリティ監査

```bash
# 包括的セキュリティ監査
opencode --agent hestia
# "PCI-DSS準拠のセキュリティ監査を実施してください"

# 修正計画（Eris）
opencode --agent eris
# "セキュリティ問題の段階的な修正計画を立ててください"
```

---

## トラブルシューティング

### よくある問題と解決方法

#### 1. エージェントが読み込まれない

**症状**: `opencode --agent athena` でエラー

**原因と解決策**:
```bash
# 1. エージェントファイルの確認
ls -la ~/.config/opencode/agent/

# 2. パーミッションの確認
chmod 644 ~/.config/opencode/agent/*.md

# 3. フロントマターの検証
# agent/*.md ファイルの先頭が --- で始まり、YAMLが正しいか確認
```

#### 2. プラグインが読み込まれない

**症状**: プラグイン機能が動作しない

**原因と解決策**:
```bash
# 1. プラグインファイルの確認
ls -la ~/.config/opencode/plugin/

# 2. JavaScriptファイルの構文チェック
node ~/.config/opencode/plugin/dynamic-context-loader.js
# エラーがないか確認

# 3. OpenCodeのバージョン確認
opencode --version
# 最新版へアップデート推奨
npm i -g opencode-ai@latest
```

#### 3. パフォーマンスが遅い

**症状**: エージェントの応答が遅い

**原因と解決策**:
```bash
# 1. モデルの確認（軽量モデルへの変更を検討）
# agent/*.md のフロントマターで model を変更:
model: anthropic/claude-sonnet-4-5-20250929  # 高速
# または
model: anthropic/claude-3-5-sonnet-20241022  # バランス

# 2. キャッシュのクリア
rm -rf ~/.config/opencode/cache/
```

### ログの確認方法

#### OpenCodeのログ

```bash
# 標準出力でログを確認
opencode --verbose

# ログファイルの場所（存在する場合）
tail -f ~/.config/opencode/logs/opencode.log
```

### サポートとコミュニティ

問題が解決しない場合:

1. **GitHub Issues**: https://github.com/apto-as/trinitas-agents/issues
2. **ドキュメント**: `~/.config/opencode/docs/` の詳細ドキュメントを参照
3. **OpenCode公式**: https://opencode.ai/docs

---

## 互換性

### プラットフォーム互換性マトリクス

完全な互換性マトリクスは、グローバル設定 `~/.claude/CLAUDE.md` を参照してください。

| プラットフォーム | エージェント | プラグイン | メモリシステム |
|----------------|------------|----------|------------|
| **OpenCode** | ✓ (6種) | ✓ (4種) | ファイルベース |
| **Claude Code** | ✓ (6種) | Pythonフック | ファイルベース |

### Claude Code版との機能比較

詳細な機能比較:

| 機能 | OpenCode版 | Claude Code版 | 備考 |
|------|-----------|--------------|------|
| **エージェント数** | 6 | 6 | 同一ペルソナ |
| **メモリシステム** | ファイルベース (ローカル) | ファイルベース (ローカル) | 両方完全プライベート |
| **プラグインシステム** | ✓ JavaScript | Pythonフック | OpenCodeはJavaScript、Claude CodeはPython |
| **コンテキスト自動選択** | ✓ | ✓ | プラグイン/フック経由 |
| **ナラティブエンジン** | ✓ | - | OpenCode独自機能 |
| **パフォーマンス監視** | ✓ | - | OpenCode独自機能 |
| **設定ファイル** | opencode.json | settings.json | 形式が異なる |
| **インストール場所** | ~/.config/opencode/ | ~/.claude/ | ディレクトリ構造の違い |

### マイグレーション

**Claude Code → OpenCode**:
```bash
# 1. OpenCode用の設定をインストール
./install_opencode.sh

# 2. Claude Code版は維持（干渉しません）
# 両方を同時に使用可能
```

**OpenCode → Claude Code**:
```bash
# 1. Claude Code用のインストーラー実行
./install_trinitas_config_v2.2.4.sh

# 2. OpenCode版は維持（干渉しません）
```

---

## 高度な設定

### カスタムエージェントの作成

```bash
# 1. エージェントファイルの作成
cat > ~/.config/opencode/agent/custom.md << 'EOF'
---
description: Custom agent for specific tasks
mode: subagent
model: anthropic/claude-sonnet-4-5-20250929
temperature: 0.5
tools:
  write: true
  edit: true
  bash: true
permission:
  edit: allow
  bash:
    "*": allow
---

# Custom Agent

## Core Identity
I am a custom agent specialized in...

## Responsibilities
- Task 1
- Task 2
EOF

# 2. 使用
opencode --agent custom
```

### プロジェクト固有の設定

```bash
# プロジェクトルートに .opencode/ ディレクトリを作成
mkdir -p .opencode/agent

# プロジェクト固有のエージェントを定義
cp ~/.config/opencode/agent/athena.md .opencode/agent/project-athena.md

# .opencode/opencode.json で設定をオーバーライド
cat > .opencode/opencode.json << 'EOF'
{
  "agent": {
    "default": "project-athena"
  },
  "instructions": [
    "# Project-specific instructions",
    "This project uses..."
  ]
}
EOF
```

### パフォーマンスチューニング

```yaml
# agent/*.md のフロントマターで調整

# 速度優先
temperature: 0.1
model: anthropic/claude-sonnet-4-5-20250929

# 創造性優先
temperature: 0.9
model: anthropic/claude-sonnet-4-5-20250929

# バランス型
temperature: 0.5
model: anthropic/claude-3-5-sonnet-20241022
```

---

## ベストプラクティス

### エージェントの選択基準

1. **アーキテクチャ設計** → Athena
2. **パフォーマンス改善** → Artemis
3. **セキュリティ監査** → Hestia
4. **チーム調整・競合解決** → Eris
5. **戦略計画・ロードマップ** → Hera
6. **ドキュメント作成** → Muses

### メモリの効果的な使用

```bash
# 重要度を指定して記録
/trinitas remember critical_config "本番環境のAPI URLは..." --importance 1.0
/trinitas remember team_decision "認証方式としてOAuth2.0を採用" --importance 0.9
/trinitas remember minor_note "開発環境のポート番号は3000" --importance 0.3

# ペルソナ固有の記憶
opencode --agent hestia
# "セキュリティ: APIキーは環境変数で管理" (自動的にHestiaの記憶として保存)
```

### チームでの活用

```bash
# 1. プロジェクトの .opencode/ に共通設定を配置
# 2. .gitignore に個人設定を追加
echo ".opencode/local/" >> .gitignore

# 3. チーム共通のエージェント設定を Git で管理
git add .opencode/agent/
git add .opencode/opencode.json

# 4. 個人設定は .opencode/local/ に配置
mkdir -p .opencode/local/
```

---

## ライセンスとクレジット

**Trinitas AI System**
Version: 2.1.0
License: MIT

**Credits**:
- OpenCode by SST: https://opencode.ai/
- Claude AI by Anthropic: https://claude.ai/

**開発者**:
- Repository: https://github.com/apto-as/trinitas-agents
- Author: apto-as

---

## 変更履歴

### v2.1.0 (2025-10-19)
- OpenCode版の初回リリース
- 6つのTrinitasエージェント実装
- ファイルベースメモリシステム
- 4つのJavaScriptプラグイン追加
- 自動インストールスクリプト提供

### 今後の予定

- [ ] ワークフロー管理機能の強化
- [ ] チーム間協調の自動化
- [ ] プラグインエコシステムの拡充

---

**Quick Start**:
```bash
# インストール
./install_opencode.sh

# 起動
opencode --agent athena

# エージェントの切り替え
opencode --agent artemis  # パフォーマンス最適化
opencode --agent hestia   # セキュリティ監査
```

Happy coding with Trinitas! 🚀
