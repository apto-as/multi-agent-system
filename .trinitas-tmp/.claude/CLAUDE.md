# 一番重要な事
- ~/.claude/以下のディレクトリはアクセス禁止。如何なる理由でもユーザーの許可が必要。
- /Users/apto-as/workspace/github.com/apto-as/trinitas-agents/がワーキングディレクトリであり、この外で作業をしてはいけない。

# Trinitas Agents プロジェクト開発設定

このファイルは trinitas-agents システムの開発・保守専用の設定です。

## プロジェクト基本情報
**プロジェクト名**: trinitas-agents  
**ルートディレクトリ**: /Users/apto-as/workspace/github.com/apto-as/trinitas-agents/  

## 開発固有ルール
1. このプロジェクトディレクトリ内でのみ作業
2. git commitは明示的指示がある場合のみ実行
3. システム設定ファイルは trinitas_sources/ 配下で管理
4. ユーザー向け機能は install_trinitas_config.sh で提供

## プロジェクト構造
```
trinitas-agents/
├── agents/                     # エージェント定義ファイル
├── trinitas_sources/          # システムソースファイル
│   ├── config/               # 設定テンプレート
│   ├── tmws/                # TMWS関連ドキュメント
│   └── common/              # 共通ドキュメント
├── hooks/                    # Git hooks
├── scripts/                 # 実行スクリプト群
├── shared/                  # 共有リソース
├── .claude/                 # プロジェクト開発設定（このディレクトリ）
├── CLAUDE.md               # プロジェクト参照用設定
├── AGENTS.md               # エージェント協調設定
└── install_trinitas_config.sh # ユーザー向けインストーラー
```

## 開発コマンド
```bash
# ドキュメント生成
./scripts/build_claude_md.sh
./scripts/build_agents_md.sh

# 設定最適化
./scripts/optimize_loading.sh

# ユーザー向けインストール
./install_trinitas_config.sh
```

## 開発時の重要な区別
- **システム機能**: trinitas_sources/ に配置
- **ユーザー設定**: install_trinitas_config.sh 経由で ~/.claude/ に配置
- **プロジェクト開発**: .claude/ 配下（このディレクトリ）で管理

## Trinitas開発者向けガイダンス
このプロジェクトの修正・改善を行う際は：
1. システム設定の変更は trinitas_sources/config/ で実施
2. 新機能は該当するエージェントファイルを更新
3. ユーザー向けの変更はインストールスクリプト経由で提供
4. パフォーマンス最適化は scripts/ のツールを活用

## 重要な注意事項
- このプロジェクト開発設定とシステム機能を混同しないこと
- ユーザーの実環境への直接変更は禁止（インストールスクリプト使用）
- すべての変更は git 管理対象として適切にトラッキング

## バージョン体系変更: 複雑な番号体系 (v4.0.0/v5.0) から シンプルなセマンティックバージョニング (v2.0.0) へ移行
  - 将来のバージョン管理: 今後は v2.x.x 形式でインクリメント
  - Git タグ: 適切なリリースノート付きでタグを作成
  これでTrinitasプロジェクトは新しいバージョン管理体系 v2.0.0 でベースラインが設定されました。今後のアップデートは：
  - パッチ版: v2.0.1（バグ修正）
  - マイナー版: v2.1.0（機能追加・改善）
  - メジャー版: v3.0.0（破壊的変更）

---

## プラットフォーム分離戦略: Claude Code vs OpenCode

**決定日**: 2025-10-19
**戦略**: 2つのプラットフォーム向けに別々のディレクトリ構造で開発

### 重要な方針

1. **Claude Code版とOpenCode版は完全に分離**
   - 共通コア: `trinitas_sources/` で管理
   - Claude Code固有: `trinitas_sources/config/claude/`
   - OpenCode固有: `trinitas_sources/config/opencode/`

2. **両プラットフォームの互換性維持**
   - 6つのTrinitasペルソナ（Athena, Artemis, Hestia, Eris, Hera, Muses）は両方で同一
   - コンテキストファイル（performance.md, security.md等）は共有
   - 実装方法のみプラットフォーム固有

---

## Claude Code ↔ OpenCode 互換マトリクス

### 📋 機能マッピング一覧

| 機能カテゴリ | Claude Code | OpenCode | 互換性 | 備考 |
|-------------|-------------|----------|--------|------|
| **イベントフック** | Hooks (Python) | Plugins (JavaScript) | ✅ 95% | イベント名が異なる |
| **専門化AI** | Agents (Markdown) | Agents (Markdown + JSON) | ✅ 100% | 完全互換 |
| **カスタムコマンド** | Slash Commands | Commands (Markdown) | ✅ 100% | OpenCodeの方が高機能 |
| **設定ファイル** | settings.json | opencode.json | ✅ 90% | 構造は類似 |
| **配置場所** | ~/.claude/ | ~/.config/opencode/ | ✅ 同構造 | パスが異なるのみ |
| **MCP対応** | MCP Servers | MCP Servers | ✅ 100% | 完全互換 |

### 🔧 技術詳細マッピング

#### Hooks/Plugins イベント対応表

| Claude Code Hook | OpenCode Plugin Event | 用途 | 実装状態 |
|------------------|----------------------|------|---------|
| `SessionStart` | `session.idle` | セッション開始通知 | ❌ 削除済み（Phase 2） |
| `UserPromptSubmit` | `prompt.submit` | プロンプト送信時 | ✅ 実装済み |
| `PreCompact` | `session.compact.before` | コンパクト前処理 | ✅ 実装済み |
| - | `event` | 汎用イベントハンドラ | ⚠️ OpenCode独自 |
| - | `tool.execute.before` | ツール実行前 | ⚠️ OpenCode独自 |

#### Agents設定形式の違い

**Claude Code形式** (`agents/athena-conductor.md`):
```markdown
---
subagent_type: athena-conductor
description: Harmonious conductor for orchestration
---
# Athena Conductor

System prompt content...
```

**OpenCode形式** (`~/.config/opencode/agent/athena.md`):
```markdown
---
description: Harmonious conductor for orchestration
mode: subagent
model: anthropic/claude-sonnet-4-5-20250929
temperature: 0.3
tools:
  write: true
  edit: true
  bash: true
permission:
  bash:
    "git push --force": ask
---
# Athena - Harmonious Conductor 🏛️

System prompt content...
```

**主な違い**:
- OpenCode: `mode`, `model`, `temperature`, `tools`, `permission` を明示的に設定可能
- Claude Code: `subagent_type` で識別、設定は外部（settings.json）で管理

#### Commands設定の違い

**Claude Code** (Slash Command):
- `.claude/commands/review.md` に配置
- 設定項目は限定的
- `$ARGUMENTS` 非対応

**OpenCode** (Command):
- `~/.config/opencode/command/review.md` に配置
- `$ARGUMENTS`, `!`command`` (shell output), `@file` (file reference) サポート
- `agent`, `subtask`, `model` などの高度な設定が可能

### 🚀 実装難易度マトリクス

| 機能 | Claude Code実装 | OpenCode実装 | 難易度 | 理由 |
|------|----------------|-------------|--------|------|
| **Dynamic Context Loading** | ✅ Python (614行) | ⚠️ JavaScript | 🟡 Medium | ロジックは同じ、言語が異なる |
| **Persona Detection** | ✅ Regex (Python re) | ⚠️ JavaScript RegExp | 🟢 Easy | パターンは同一 |
| **Rate Limiting** | ✅ deque (100/60s) | ⚠️ Array + timestamp | 🟢 Easy | アルゴリズムは同じ |
| **Symlink Protection** | ✅ Path.is_symlink() | ⚠️ fs.lstatSync().isSymbolicLink() | 🟡 Medium | Node.js APIの違い |
| **Secure File Loader** | ✅ SecureFileLoader class | ⚠️ Plugin validation | 🟡 Medium | 設計パターンが異なる |
| **Agent Markdown** | ✅ Native support | ✅ Native support | 🟢 Easy | 完全互換 |
| **MCP Servers** | ✅ settings.json | ✅ opencode.json | 🟢 Easy | 設定キーが同じ |

### 📁 ディレクトリ構造対応表

```
trinitas-agents/
├── trinitas_sources/
│   ├── config/
│   │   ├── claude/              # Claude Code固有
│   │   │   ├── hooks/          # Python hooks
│   │   │   └── settings.json   # Claude Code設定テンプレート
│   │   └── opencode/           # OpenCode固有
│   │       ├── plugin/         # JavaScript plugins
│   │       ├── agent/          # Agent定義（Markdown）
│   │       ├── command/        # Command定義（Markdown）
│   │       └── opencode.json   # OpenCode設定テンプレート
│   └── common/                 # 共通リソース
│       ├── CLAUDE.md           # 共通システムプロンプト
│       ├── AGENTS.md           # 共通エージェント協調設定
│       └── contexts/           # 共通コンテキストファイル
│           ├── performance.md
│           ├── security.md
│           └── collaboration.md
└── shared/
    └── utils/                  # 共通ユーティリティ
        ├── json_loader.py
        └── secure_file_loader.py
```

### ⚠️ 移行時の注意事項

#### 1. セキュリティ機能の実装差異

**Symlink Protection**:
- **Claude Code**: `Path.is_symlink()` でチェック後、`os.path.realpath()` で解決
- **OpenCode**: Plugin内で `fs.lstatSync().isSymbolicLink()` を使用

```javascript
// OpenCode plugin implementation
import fs from 'fs';
import path from 'path';

function validatePath(filePath) {
  const stats = fs.lstatSync(filePath);
  if (stats.isSymbolicLink()) {
    throw new Error(`Symlink access denied (CWE-61): ${filePath}`);
  }
  // Continue with realpath resolution...
}
```

**Rate Limiting**:
- **Claude Code**: `collections.deque` (O(1) popleft)
- **OpenCode**: JavaScript Array (filter for sliding window)

```javascript
// OpenCode plugin implementation
class RateLimiter {
  constructor(maxCalls = 100, windowMs = 60000) {
    this.maxCalls = maxCalls;
    this.windowMs = windowMs;
    this.calls = [];
  }

  check() {
    const now = Date.now();
    // Remove old calls
    this.calls = this.calls.filter(t => t > now - this.windowMs);

    if (this.calls.length >= this.maxCalls) {
      const oldestCall = this.calls[0];
      const retryAfter = Math.ceil((oldestCall + this.windowMs - now) / 1000);
      throw new Error(`Rate limit exceeded. Retry after ${retryAfter}s`);
    }

    this.calls.push(now);
  }
}
```

#### 2. Plugin実装のベストプラクティス

**推奨事項**:
- TypeScript使用を推奨（`@opencode-ai/plugin` で型安全性確保）
- エラーハンドリングを徹底（ユーザー操作をブロックしない）
- Bunのshell API (`$`) を活用してパフォーマンス向上

**非推奨**:
- 同期的なファイルI/O（非同期を推奨）
- グローバル状態の過度な使用
- 外部依存関係の乱用

#### 3. Agent移行チェックリスト

OpenCode版Agentを作成する際の確認項目：

- [ ] `description` フィールドを追加（必須）
- [ ] `mode` を `subagent` または `primary` に設定
- [ ] `model` で使用するモデルを明示
- [ ] `temperature` を用途に応じて設定（0.1-0.8）
- [ ] `tools` で許可するツールを明示
- [ ] `permission` でbash/edit等の権限を設定
- [ ] システムプロンプトを共通リソースから参照

### 🔄 今後の開発フロー

1. **共通機能の開発**:
   - `trinitas_sources/common/` で共通プロンプト・コンテキストを管理
   - 両プラットフォームから参照

2. **プラットフォーム固有機能**:
   - Claude Code: `trinitas_sources/config/claude/` で実装
   - OpenCode: `trinitas_sources/config/opencode/` で実装

3. **テスト戦略**:
   - 両プラットフォームで同じテストケースを実行
   - ペルソナ検出、コンテキスト注入の整合性を確認

4. **ドキュメント管理**:
   - プラットフォーム共通: `CLAUDE.md`, `AGENTS.md`
   - プラットフォーム固有: `README-claude.md`, `README-opencode.md`

---

## 参照ドキュメント

- **Claude Code Hooks**: `~/.claude/hooks/core/`
- **OpenCode Plugins**: `.opencode/plugin/`
- **共通Agents**: `trinitas_sources/common/agents/`
- **互換マトリクス**: 本セクション（常に最新に保つ）

**最終更新**: 2025-10-19
**バージョン**: v2.2.4
**プラットフォーム**: Claude Code (primary), OpenCode (in development)