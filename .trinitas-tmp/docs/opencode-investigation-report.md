# OpenCode 最新情報調査報告
**調査日**: 2025-10-17
**担当**: Hera (戦略指揮官)

## 1. 現在のインストール状況

- **インストール済みバージョン**: v0.14.1
- **最新安定版**: v0.15.7 (2023年10月リリース)
- **インストール場所**: `/opt/homebrew/bin/opencode`

## 2. OpenCodeの最新機能

### 2.1 プラグインシステム（重要発見）✅

**Claude CodeのPlugin機能と同等のシステムが存在します。**

#### プラグインの特徴
- **配置場所**: `.opencode/plugin/` (プロジェクトローカル) または `~/.config/opencode/plugin/` (グローバル)
- **形式**: JavaScript/TypeScript モジュール
- **非同期関数**: `async (context) => { ... }` 形式でエクスポート

#### 利用可能なコンテキスト
- `project`: 現在のプロジェクト情報
- `directory`: カレントディレクトリ
- `worktree`: Gitワークツリーパス
- `client`: OpenCode SDKクライアント
- `$`: Bunシェル API（コマンド実行用）

#### 利用可能なフック
1. **event**: システムイベント時にトリガー
   - `session.idle`: セッション完了時
   - その他カスタムイベント

2. **tool.execute.before**: ツール実行前にインターセプト
   - 実行制限、検証、ログ記録などに使用

3. **tool**: カスタムツールの定義
   - OpenCodeに新しいツールを追加可能

#### プラグイン例

**通知プラグイン**:
```javascript
export const NotificationPlugin = async ({ $ }) => {
  return {
    event: async ({ event }) => {
      if (event.type === "session.idle") {
        await $`osascript -e 'display notification "Session completed!" with title "opencode"'`
      }
    },
  }
}
```

**環境変数保護プラグイン**:
```javascript
export const EnvProtection = async () => {
  return {
    "tool.execute.before": async (input, output) => {
      if (input.tool === "read" && output.args.filePath.includes(".env")) {
        throw new Error("Do not read .env files")
      }
    },
  }
}
```

**カスタムツールプラグイン**:
```javascript
export const CustomToolsPlugin = async () => {
  return {
    tool: {
      mytool: tool({
        description: "This is a custom tool",
        args: { foo: tool.schema.string() },
        async execute(args) {
          return `Hello ${args.foo}!`
        },
      }),
    },
  }
}
```

### 2.2 既存のTrinitasプラグイン

プロジェクトには既に以下のOpenCodeプラグインが実装済み:
- `dynamic-context-loader.js` (7.5KB)
- `narrative-engine.js` (11.6KB)
- `performance-monitor.js` (4.2KB)
- `quality-enforcer.js` (5.2KB)

## 3. 最新バージョンの新機能（v0.15.7）

### v0.15.7 (2023年10月17日)
- Deno LSPサポート追加
- 空のthinking/textブロックに関する変更の取り消し

### v0.15.6 (2023年10月16日)
- タイムアウトオプションの実装修正
- Bashコマンド実行の改善
- LSPファイル操作接続問題の解決

### v0.15.5 (2023年10月16日)
- GitHubアクショントリガーの更新
- AIモデルの変更
- GitHubアクションコアライブラリの追加
- ワークフローパーミッションの調整

## 4. Claude Code Plugin機能との比較

| 機能 | Claude Code | OpenCode | 備考 |
|-----|------------|----------|------|
| プラグイン配置 | プロジェクト内 | `.opencode/plugin/` | ✅ 同等 |
| プラグイン形式 | 設定ファイル | JS/TSモジュール | 実装方法が異なる |
| イベントフック | あり | あり (`event`) | ✅ 同等 |
| ツール拡張 | あり | あり (`tool`) | ✅ 同等 |
| ツール実行制御 | 不明 | あり (`tool.execute.before`) | OpenCodeが優位 |
| グローバル設定 | `~/.claude/` | `~/.config/opencode/` | ✅ 同等 |

## 5. 戦略的推奨事項

### 5.1 バージョンアップグレード
- **推奨**: v0.14.1 → v0.15.7へのアップグレード
- **理由**: LSPサポート改善、バグ修正
- **リスク**: 低（マイナーバージョンアップ）

### 5.2 インストール方法の整備

#### Claude Code版
1. **Plugin方式**（優先）
   - MCP (Model Context Protocol) サーバーとして実装
   - `claude_desktop_config.json`への設定追加
   - 既存の`~/.claude/CLAUDE.md`との統合

2. **Script方式**（バックアップ）
   - `install_trinitas_config.sh`スクリプトの拡張
   - `~/.claude/`への設定ファイルコピー

#### OpenCode版
1. **Plugin方式**（既存活用）
   - `.opencode/plugin/`の既存プラグイン活用
   - 新規プラグインの追加（必要に応じて）

2. **Script方式**（新規作成）
   - OpenCode用インストールスクリプト作成
   - `.opencode/`への設定ファイル配置自動化

## 6. 次のアクションアイテム

### 優先度：高
1. ✅ OpenCode調査完了（本ドキュメント）
2. 🔄 ブランチマージ戦略の決定
3. 🔄 Claude Code Plugin方式の設計と実装
4. 🔄 インストールスクリプトの統合設計

### 優先度：中
5. OpenCode Script方式の実装
6. 既存OpenCodeプラグインの棚卸しと統合
7. ドキュメント整備（インストールガイド）

### 優先度：低
8. OpenCode v0.15.7へのアップグレード検証
9. プラグイン間の依存関係整理
10. パフォーマンステストとベンチマーク

## 7. 結論

**OpenCodeはClaude CodeのPlugin機能と同等のプラグインシステムを持っています。**

主な違い:
- Claude Code: MCP (Model Context Protocol) ベース
- OpenCode: JavaScript/TypeScript モジュールベース

両者とも拡張性が高く、Trinitasシステムの統合が可能です。既存のOpenCodeプラグインを活用しつつ、Claude Code Plugin方式の新規実装を推奨します。

---
**報告者**: Hera (戦略指揮官)
**承認待ち**: Athena (システム設計), Artemis (実装), Hestia (セキュリティ)
