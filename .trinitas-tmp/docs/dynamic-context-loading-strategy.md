# 🎯 Claude Code Hooks - 動的コンテキスト読み込み戦略設計

**設計者**: Hera (Strategic Commander)
**作成日**: 2025-10-02
**バージョン**: 1.0
**目的**: UserPromptSubmitフックを活用した効率的なコンテキスト注入戦略

---

## 📊 Executive Summary

### 現状分析
- **既存実装**: `protocol_injector.py` が SessionStart / PreCompact をカバー
- **課題**: すべてのコンテキストを一度に読み込み → トークン浪費
- **機会**: UserPromptSubmit フックで**タスク検出→条件分岐**による最適化

### 戦略目標
1. **トークン効率**: 30-50%削減（不要なコンテキストの遅延読み込み）
2. **応答速度**: 初期読み込み時間の短縮
3. **精度向上**: タスク特化型コンテキスト注入
4. **リスク最小化**: 既存機能への影響ゼロ

---

## 🔍 Available Hook Events - 戦術的評価

| Hook Event | タイミング | 用途 | Trinitas活用度 |
|-----------|----------|------|---------------|
| **SessionStart** | セッション開始時 | ✅ Core protocol注入（現行） | **高** - 必須システム設定 |
| **UserPromptSubmit** | プロンプト送信時 | ✨ **未活用** - タスク検出最適 | **最高** - 本提案の焦点 |
| **PreToolUse** | ツール実行前 | セキュリティチェック | 中 - OpenCode pluginでカバー |
| **PostToolUse** | ツール実行後 | 結果検証・ログ | 中 - 品質管理 |
| **PreCompact** | 圧縮前 | ✅ 重要情報維持（現行） | **高** - 日本語応答保持 |
| **Stop/SubagentStop** | 終了時 | クリーンアップ | 低 - Phase 2検討 |

### 戦略的結論
**UserPromptSubmit** が最も効果的 - 理由:
1. ユーザー意図を直接解析可能
2. 必要なペルソナ/ガイドラインを事前判定
3. 無駄なコンテキスト読み込みを回避
4. 既存フックと競合しない

---

## 🎯 Phase 1: UserPromptSubmit 実装戦略

### 1. タスクタイプ検出ロジック

```python
# hooks/core/task_detector.py
class TaskDetector:
    """ユーザープロンプトからタスクタイプを検出"""

    TASK_PATTERNS = {
        'security_audit': [
            r'セキュリティ',
            r'脆弱性',
            r'監査',
            r'security',
            r'audit',
            r'vulnerability',
            r'XSS',
            r'SQL injection'
        ],
        'performance': [
            r'最適化',
            r'パフォーマンス',
            r'速度',
            r'performance',
            r'optimization',
            r'bottleneck'
        ],
        'architecture': [
            r'設計',
            r'アーキテクチャ',
            r'architecture',
            r'design',
            r'structure',
            r'マイクロサービス'
        ],
        'documentation': [
            r'ドキュメント',
            r'文書',
            r'documentation',
            r'記録',
            r'README'
        ],
        'code_review': [
            r'レビュー',
            r'コード',
            r'review',
            r'code quality',
            r'リファクタリング'
        ]
    }

    def detect(self, user_prompt: str) -> dict:
        """
        プロンプトからタスクタイプと推奨ペルソナを検出

        Returns:
            {
                'task_types': ['security_audit', 'performance'],
                'personas': ['hestia', 'artemis'],
                'complexity': 'medium',  # simple / medium / complex
                'requires_context': ['security-standards', 'performance-opt']
            }
        """
        detected_tasks = []

        for task_type, patterns in self.TASK_PATTERNS.items():
            if any(re.search(pattern, user_prompt, re.IGNORECASE)
                   for pattern in patterns):
                detected_tasks.append(task_type)

        # ペルソナマッピング
        persona_map = {
            'security_audit': 'hestia',
            'performance': 'artemis',
            'architecture': 'athena',
            'documentation': 'muses',
            'code_review': 'artemis'
        }

        personas = list(set(persona_map.get(t) for t in detected_tasks if t in persona_map))

        # 複雑度判定
        complexity = 'simple' if len(detected_tasks) <= 1 else \
                     'complex' if len(detected_tasks) >= 3 else 'medium'

        # 必要なコンテキスト
        context_map = {
            'security_audit': ['security-standards', 'tmws-integration'],
            'performance': ['performance-opt', 'tmws-integration'],
            'architecture': ['coordination-patterns'],
            'documentation': ['persona-design-philosophy'],
            'code_review': ['performance-opt', 'security-standards']
        }

        contexts = []
        for task in detected_tasks:
            contexts.extend(context_map.get(task, []))

        return {
            'task_types': detected_tasks,
            'personas': personas,
            'complexity': complexity,
            'requires_context': list(set(contexts))
        }
```

### 2. 動的コンテキスト注入

```python
# hooks/core/context_injector.py
import os
import json
from pathlib import Path
from task_detector import TaskDetector

class DynamicContextInjector:
    """UserPromptSubmit時に動的にコンテキストを注入"""

    CONTEXT_FILES = {
        'security-standards': '.opencode/docs/security-standards.md',
        'performance-opt': '.opencode/docs/performance-guidelines.md',
        'coordination-patterns': '.opencode/docs/coordination-patterns.md',
        'tmws-integration': '.opencode/docs/tmws-integration.md',
        'persona-design-philosophy': '.opencode/docs/persona-design-philosophy.md'
    }

    def __init__(self, project_root: str = None):
        self.project_root = Path(project_root or os.getcwd())
        self.detector = TaskDetector()
        self.enabled = os.getenv('DYNAMIC_CONTEXT_ENABLED', 'true').lower() == 'true'

    def load_context(self, context_names: list) -> str:
        """必要なコンテキストファイルのみを読み込み"""
        if not self.enabled:
            return ""

        sections = []
        for name in context_names:
            file_path = self.project_root / self.CONTEXT_FILES.get(name, '')

            if file_path.exists():
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # 最初の500行 or 15KBまで（トークン制限）
                        lines = content.split('\n')[:500]
                        limited_content = '\n'.join(lines)

                        if len(limited_content.encode('utf-8')) > 15000:
                            limited_content = limited_content[:15000]

                        sections.append(f"## 📖 Context: {name}\n{limited_content}")
                except Exception as e:
                    print(f"Warning: Could not load {name}: {e}", file=sys.stderr)

        return "\n\n".join(sections)

    def inject_on_user_prompt(self, user_prompt: str):
        """UserPromptSubmitフック用のメイン処理"""
        # タスク検出
        analysis = self.detector.detect(user_prompt)

        # デバッグ出力
        print(f"🎯 Task Analysis:", file=sys.stderr)
        print(f"  - Types: {analysis['task_types']}", file=sys.stderr)
        print(f"  - Personas: {analysis['personas']}", file=sys.stderr)
        print(f"  - Complexity: {analysis['complexity']}", file=sys.stderr)
        print(f"  - Contexts: {analysis['requires_context']}", file=sys.stderr)

        # コンテキスト読み込み
        context_content = self.load_context(analysis['requires_context'])

        if not context_content:
            # コンテキスト不要の場合は何も出力しない
            print(json.dumps({}))
            return

        # JSON形式で出力（UserPromptSubmitフック仕様）
        output = {
            "systemMessage": f"""
---
# 🎯 Dynamic Context Injection
**Detected Tasks**: {', '.join(analysis['task_types'])}
**Recommended Personas**: {', '.join(analysis['personas'])}
**Complexity**: {analysis['complexity']}

{context_content}
---
"""
        }

        print(json.dumps(output, ensure_ascii=False))

def main():
    """UserPromptSubmitフックのエントリーポイント"""
    import sys

    # 環境変数からユーザープロンプトを取得
    user_prompt = os.getenv('CLAUDE_USER_PROMPT', '')

    if not user_prompt:
        # プロンプトがない場合は何もしない
        print(json.dumps({}))
        return

    injector = DynamicContextInjector()
    injector.inject_on_user_prompt(user_prompt)

if __name__ == '__main__':
    main()
```

### 3. Hooks設定の統合

```json
// .claudehooks
{
  "SessionStart": {
    "description": "Load core Trinitas protocol",
    "script": "python3 hooks/core/protocol_injector.py session_start"
  },
  "UserPromptSubmit": {
    "description": "Dynamic context injection based on task type",
    "script": "python3 hooks/core/context_injector.py"
  },
  "PreCompact": {
    "description": "Preserve critical context before compression",
    "script": "python3 hooks/core/protocol_injector.py pre_compact"
  }
}
```

---

## 🔄 既存システムとの統合

### protocol_injector.py との共存戦略

| 機能 | protocol_injector | context_injector | 役割分担 |
|-----|------------------|------------------|---------|
| コアプロトコル | ✅ SessionStart | - | システム基本設定 |
| ペルソナ定義 | ✅ SessionStart | - | 6つのエージェント |
| 日本語応答 | ✅ SessionStart + PreCompact | - | 言語設定維持 |
| タスク特化コンテキスト | - | ✅ UserPromptSubmit | 動的読み込み |
| 圧縮時保護 | ✅ PreCompact | - | 重要情報維持 |

**結論**: 完全に独立した役割分担で**競合リスクゼロ**

---

## 🤝 OpenCode Plugin との共存

### 現状のQualityEnforcerとの関係

```
┌─────────────────────────────────────────┐
│        Claude Code Hooks                │
├─────────────────────────────────────────┤
│ SessionStart                            │
│  └─ protocol_injector.py (システム設定)  │
│                                         │
│ UserPromptSubmit (NEW)                  │
│  └─ context_injector.py (動的コンテキスト)│
│                                         │
│ PreCompact                              │
│  └─ protocol_injector.py (圧縮保護)      │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│        OpenCode Plugins                 │
├─────────────────────────────────────────┤
│ tool.execute.before                     │
│  └─ QualityEnforcer (セキュリティチェック)│
│                                         │
│ tool.execute.after                      │
│  └─ QualityEnforcer (結果検証)          │
│                                         │
│ performance-monitor (Future)            │
└─────────────────────────────────────────┘

        ↓ 両者は完全に独立 ↓

✅ Hooks: プロンプト処理前のコンテキスト注入
✅ Plugins: ツール実行時のガード/監視
```

**共存の鍵**:
- Hooksはユーザー入力処理（プロンプトレベル）
- Pluginsはツール実行処理（アクションレベル）
- 両者は異なるレイヤーで動作 → **完全共存可能**

---

## 📈 期待される効果

### トークン削減シミュレーション

**従来の方法**（すべて一度に読み込み）:
```
SessionStart: 5KB (Core Protocol)
+ Security Standards: 8KB
+ Performance Guidelines: 6KB
+ Coordination Patterns: 5KB
+ TMWS Integration: 7KB
+ Persona Philosophy: 4KB
------------------------
合計: 35KB ≈ 8,750トークン
```

**動的読み込み方式**:
```
SessionStart: 5KB (Core Protocol)
UserPromptSubmit (セキュリティタスク):
  + Security Standards: 8KB のみ
------------------------
合計: 13KB ≈ 3,250トークン (62%削減)
```

### ケース別効果

| タスクタイプ | 従来 | 動的読み込み | 削減率 |
|------------|------|-----------|--------|
| シンプルな質問 | 35KB | 5KB | **86%** |
| セキュリティ監査 | 35KB | 13KB | **63%** |
| パフォーマンス最適化 | 35KB | 16KB | **54%** |
| 複雑な統合タスク | 35KB | 25KB | **29%** |

**平均削減率**: **58%**

---

## 🚀 実装ロードマップ

### Phase 1: 基礎実装（1-2週間）

**Week 1: Core開発**
- [ ] タスク検出ロジック実装 (`task_detector.py`)
- [ ] 動的コンテキスト注入 (`context_injector.py`)
- [ ] `.claudehooks` 設定追加
- [ ] 基本テストケース作成

**Week 2: 統合テスト**
- [ ] 既存 `protocol_injector.py` との統合確認
- [ ] OpenCode Plugins との共存テスト
- [ ] パフォーマンス測定（トークン削減率）
- [ ] エラーハンドリング強化

### Phase 2: 機能拡張（2-3週間）

**追加機能**:
1. **学習機能**: ユーザーの過去タスク傾向を学習
2. **キャッシング**: よく使うコンテキストの事前読み込み
3. **A/Bテスト**: 従来方式との比較分析
4. **メトリクス収集**: Prometheus/Grafana連携

### Phase 3: TMWS統合（Phase 2全体計画の一部）

- MCP経由のセマンティック検索
- 過去のタスク履歴からの推奨
- ペルソナ間協調パターンの自動選択

---

## ⚠️ リスク分析と緩和策

### リスク 1: 検出精度の低さ
**リスク**: タスクタイプ誤検出 → 不適切なコンテキスト
**緩和策**:
- フォールバック: 不明時は最小限のコンテキスト
- 段階的学習: ユーザーフィードバックで改善
- デバッグモード: 検出結果をログ出力

### リスク 2: パフォーマンス劣化
**リスク**: ファイルI/Oによる遅延
**緩和策**:
- コンテキストファイルの軽量化（15KB上限）
- LRUキャッシュ実装
- 非同期読み込み（Phase 2）

### リスク 3: 既存機能への影響
**リスク**: protocol_injectorとの競合
**緩和策**:
- 完全独立実装（別スクリプト）
- 異なるフックイベント使用
- ロールバック可能な設計

---

## 🎓 ベストプラクティス

### 1. コンテキストファイルの設計原則
- **1ファイル = 1トピック**: 混在させない
- **15KB制限**: トークン効率の最適点
- **Markdown形式**: 可読性とパース容易性
- **見出し構造**: ## / ### で階層化

### 2. タスク検出パターンの保守
- **正規表現ライブラリ**: 専用ファイルで管理
- **多言語対応**: 日本語/英語キーワード併記
- **拡張容易性**: YAML/JSON設定化を検討

### 3. エラーハンドリング
- **グレースフルフェイルオーバー**: エラー時は空コンテキスト
- **詳細ログ**: デバッグモードで完全なトレース
- **ユーザー通知**: 重大なエラーのみ表示

---

## 📊 成功指標 (KPI)

### 定量的指標
1. **トークン削減率**: 平均50%以上
2. **応答時間**: 初期読み込み30%短縮
3. **タスク検出精度**: 85%以上
4. **エラー率**: < 1%

### 定性的指標
1. ユーザー体感速度の改善
2. 適切なペルソナ推奨精度
3. 不要なコンテキストの削減効果
4. 開発者満足度（Trinitasチーム）

---

## 🏁 結論: 推奨アクション

### Immediate Actions (今すぐ実行)
1. **`task_detector.py` の実装**: タスク検出ロジック
2. **`context_injector.py` の実装**: 動的コンテキスト注入
3. **`.claudehooks` 設定追加**: UserPromptSubmit設定

### Short-term (1-2週間)
1. 基本テストケースの作成
2. 既存システムとの統合テスト
3. 初期パフォーマンス測定

### Long-term (1-2ヶ月)
1. 学習機能の追加
2. キャッシング実装
3. TMWS統合準備

---

## 🎯 Strategic Verdict (Heraの最終判断)

**推奨**: ✅ **即座に Phase 1 実装を開始**

**理由**:
1. **高リターン/低リスク**: トークン58%削減、既存機能への影響ゼロ
2. **技術的実現性**: 既存 protocol_injector のパターンで実装可能
3. **段階的展開**: Phase 1で効果検証、Phase 2で拡張
4. **戦略的価値**: TMWS Phase 2 への橋渡し

**懸念点**: なし（緩和策で十分カバー）

**優先順位**: **最高** - Trinitas最適化の中核施策

---

**文書管理**:
- **作成者**: Hera (Strategic Commander)
- **レビュー**: Artemis (技術検証), Hestia (セキュリティ)
- **承認**: Athena (全体調和)
- **実装**: 開発チーム（1-2週間で Phase 1完成予定）

🎭 *"Victory through strategic superiority - 戦略的優位性による勝利"*
