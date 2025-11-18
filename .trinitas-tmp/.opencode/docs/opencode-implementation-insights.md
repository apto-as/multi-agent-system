# OpenCode Implementation Insights

## 実装から得られた重要な知見

### 1. ディレクトリ構造の正確性
- **正解**: `~/.config/opencode/` （グローバル設定）
- **誤解**: `~/.opencode/` は存在しない
- プロジェクトローカルは `.opencode/` ディレクトリ

### 2. AGENTS.md の重要性
OpenCodeの公式ドキュメント調査により判明：
- グローバルルールは `~/.config/opencode/AGENTS.md` から読み込まれる
- 個別の `rule/` ディレクトリはサポートされていない
- AGENTS.mdは**システム指示とルールを統合**した包括的なファイル

### 3. config.json の正しい構造
```json
{
  "$schema": "https://opencode.ai/config.json",
  "agent": {
    "default": "athena"  // オブジェクトではなく直接文字列
  },
  "instructions": [      // 追加のドキュメントを参照
    "# System Instructions",
    "@~/.config/opencode/AGENTS.md"
  ],
  "permission": { ... },
  "mcp": {}  // Phase 1では空オブジェクト
}
```

### 4. プラグインシステムの仕様
**正しい実装パターン**：
```javascript
// 関数をエクスポート（オブジェクトではない）
export const PluginName = async (context) => {
  return {
    "event": async (data) => { ... },
    "tool.execute.before": async (input, output) => { ... },
    "tool.execute.after": async (input, output) => { ... }
  };
};
```

### 5. エージェント定義の構造
エージェントは2つの形式をサポート：
1. **Markdown形式** （Trinitasで採用）
   - フロントマターでメタデータ定義
   - 本文でペルソナと詳細な指示を記述
2. **JSON形式** （シンプルな定義用）

### 6. External File Loading Protocol
AGENTS.md内で `@reference` を使用した動的ファイル読み込み：
- タスクに応じた必要なガイドラインのみ読み込み
- メモリ効率的な運用
- モジュール化による保守性向上

### 7. Primary vs Subagent の区別
- **Primary agents**: デフォルトエージェントになれる（Athena, Hera）
- **Subagents**: 特殊タスク専用（Artemis, Hestia, Eris, Muses）
- `mode` フィールドで明示的に定義

## Phase 1 と Phase 2 の明確な分離

### Phase 1 (現在)
- 6つのTrinitasエージェント
- 品質管理プラグイン
- パフォーマンス監視
- モジュール型ドキュメント

### Phase 2 (将来)
- TMWS統合（MCP経由）
- 永続的メモリシステム
- ワークフロー管理
- セマンティック検索

## ペルソナ設定の重要性

各エージェントは以下の重要な要素を保持：
1. **Core Identity**: エージェントの本質的なアイデンティティ
2. **Personality Traits**: 独自の性格特性
3. **Decision Framework**: 意思決定の基準
4. **Integration Patterns**: 他エージェントとの協調方法
5. **Quality Standards**: 品質基準と原則

これらの要素により、単なるツールではなく、**知的な協働者**として機能。

## 実装のベストプラクティス

1. **設定の分離**
   - グローバル: `~/.config/opencode/`
   - プロジェクト: `.opencode/`
   - 混在させない

2. **プラグイン開発**
   - 関数エクスポート形式を厳守
   - フック名は正確に（tool.execute.before等）
   - エラーハンドリングを適切に

3. **エージェント設計**
   - ペルソナと技術仕様のバランス
   - 明確な責任範囲の定義
   - 協調パターンの明文化

4. **ドキュメント戦略**
   - AGENTS.mdは中核システム指示
   - 詳細はモジュールファイルに分離
   - @referenceで動的読み込み

## トラブルシューティング

### よくあるエラーと対処法

1. **"fn is not a function"**
   - 原因: プラグインがオブジェクトをエクスポート
   - 解決: 関数をエクスポートするよう修正

2. **"Invalid agent configuration"**
   - 原因: agent.defaultがオブジェクト形式
   - 解決: 文字列として直接指定

3. **"Rules not loading"**
   - 原因: rule/ディレクトリを期待
   - 解決: AGENTS.mdに統合

## 今後の改善提案

1. **エージェント間通信の強化**
   - 直接メッセージング機能
   - 状態共有メカニズム

2. **動的エージェント切り替え**
   - コンテキストベースの自動切り替え
   - タスクの複雑度に応じた協調

3. **プラグインエコシステム**
   - 言語別品質チェッカー
   - CI/CD統合
   - カスタムメトリクス収集

## 結論

OpenCodeの仕様を正確に理解することで、Trinitasシステムの真の力を発揮できる実装が完成。特に重要なのは：
- 正しいディレクトリ構造の使用
- AGENTS.mdを中心とした統合的アプローチ
- プラグインの関数エクスポート形式
- ペルソナ設定による知的な協働

これらの知見により、Phase 1実装は安定し、Phase 2への道筋も明確になった。