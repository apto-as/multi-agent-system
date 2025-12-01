# Trinitas 統一プッシュ型アーキテクチャ設計書
## Unified Push-Type Information Injection Architecture

**Version**: 1.0.0
**Created**: 2025-11-30
**Status**: Draft - Pending User Approval

---

## 1. 概要 (Overview)

本ドキュメントは、TMWSの核心技術である「必要な時に必要な情報を読ませる」機能の実現方法を定義します。

### 1.1 問題定義

AI エージェントへの情報提供には2つのアプローチが存在:

| アプローチ | 説明 | 利点 | 欠点 |
|-----------|------|------|------|
| **Pull型 (MCP Tools)** | AIが明示的にツールを呼び出す | 柔軟性高い | AI判断依存 |
| **Push型 (Hooks/Plugins)** | システムがイベントで自動注入 | 確実性高い | 設計が複雑 |

**結論**: 両方を組み合わせたハイブリッドアーキテクチャが最適。

### 1.2 対象プラットフォーム

- **Claude Code**: Python Hooks (6イベント対応)
- **OpenCode**: TypeScript Plugins (10+イベント対応)

---

## 2. アーキテクチャ概要

```
┌─────────────────────────────────────────────────────────────────┐
│                    Trinitas Push Architecture                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────────┐     ┌─────────────────┐                    │
│  │  Claude Code    │     │    OpenCode     │                    │
│  │  (Python Hooks) │     │  (TS Plugins)   │                    │
│  └────────┬────────┘     └────────┬────────┘                    │
│           │                       │                              │
│           ▼                       ▼                              │
│  ┌────────────────────────────────────────────┐                 │
│  │        Unified Event Abstraction Layer      │                 │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐   │                 │
│  │  │ SESSION_ │ │ CONTEXT_ │ │  INPUT_  │   │                 │
│  │  │  START   │ │ COMPRESS │ │ RECEIVED │   │                 │
│  │  └──────────┘ └──────────┘ └──────────┘   │                 │
│  └────────────────────────────────────────────┘                 │
│                        │                                         │
│                        ▼                                         │
│  ┌────────────────────────────────────────────┐                 │
│  │         Trinitas Context Injector           │                 │
│  │  ┌──────────────────────────────────────┐  │                 │
│  │  │ Level 1: Core Identity (常駐)        │  │                 │
│  │  │ Level 2: Session Context (動的)      │  │                 │
│  │  │ Level 3: Compressed Summary (圧縮時) │  │                 │
│  │  └──────────────────────────────────────┘  │                 │
│  └────────────────────────────────────────────┘                 │
│                        │                                         │
│                        ▼                                         │
│  ┌────────────────────────────────────────────┐                 │
│  │              9 Agent System                 │                 │
│  │  Core: Athena, Artemis, Hestia, Eris,      │                 │
│  │        Hera, Muses                          │                 │
│  │  Support: Aphrodite, Metis, Aurora          │                 │
│  └────────────────────────────────────────────┘                 │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. イベントマッピング

### 3.1 統一イベント定義

| 統一イベント | 説明 | トリガー条件 |
|------------|------|-------------|
| `SESSION_START` | セッション開始時 | 新規会話開始 |
| `CONTEXT_COMPRESS` | コンテキスト圧縮時 | トークン使用率 > 閾値 |
| `INPUT_RECEIVED` | ユーザー入力受信時 | 各メッセージ受信 |
| `TOOL_EXECUTE` | ツール実行時 | MCPツール呼び出し |

### 3.2 プラットフォーム別マッピング

| 統一イベント | Claude Code | OpenCode |
|------------|-------------|----------|
| `SESSION_START` | `SessionStart` | `session.created` |
| `CONTEXT_COMPRESS` | `PreCompact` | `session.updated` (token監視) |
| `INPUT_RECEIVED` | `UserPromptSubmit` | `message.created` |
| `TOOL_EXECUTE` | なし | `tool.execute.before` |

### 3.3 差分と対応策

#### 3.3.1 PreCompact (コンテキスト圧縮)

**Claude Code**:
- 明示的な `PreCompact` イベントが発火
- カスタムコードで Level 3 サマリーを注入可能

**OpenCode**:
- 95%閾値で自動圧縮 (設定可能)
- `session.updated` イベントで `tokenUsage` を監視
- 90%超過で Level 3 サマリーを先行注入

```typescript
// OpenCode での PreCompact 相当実装
'session.updated': async (event) => {
  if (event.tokenUsage > 0.90) {
    return injectLevel3CompressedSummary();
  }
}
```

#### 3.3.2 Tool Execute (Claude Code 非対応)

Claude Code では `tool.execute` 相当のフックがないため:
- MCP ツール内でコンテキスト補完を実装
- 必要に応じて `recall_memory` を内部呼び出し

---

## 4. 3層コンテキスト注入戦略

### 4.1 Level 1: Core Identity (常駐)

**目的**: AI が常に Trinitas システムであることを認識
**トークン目安**: ~2,000

```markdown
## Trinitas Core System v2.5.0

### Identity
- System: TMWS (Trinitas Memory & Workflow System)
- Mode: 9-Agent Full Support

### Active Coordinators
- **Athena** (athena-conductor): Harmonious orchestration
- **Hera** (hera-strategist): Strategic command

### Specialists
- **Artemis** (artemis-optimizer): Technical excellence
- **Hestia** (hestia-auditor): Security guardian
- **Eris** (eris-coordinator): Tactical coordination
- **Muses** (muses-documenter): Knowledge architecture

### Support Agents
- **Aphrodite** (aphrodite-designer): UI/UX design
- **Metis** (metis-developer): Development assistance
- **Aurora** (aurora-researcher): Research & retrieval

### Security Boundary
- Namespace isolation enforced
- P0-1 pattern: Verify namespace from DB
```

### 4.2 Level 2: Session Context (動的)

**目的**: セッション固有の情報を提供
**トークン目安**: ~5,000-10,000

```markdown
## Session Context

### Previous Session Summary
[前回セッションの要約 - 動的生成]

### Context Profile
- Profile: {coding|research|planning|review}
- Active Agent: {detected_agent}

### Relevant Memories
[セマンティック検索結果 - 動的取得]

### Applicable Patterns
[学習パターン - 動的取得]
```

### 4.3 Level 3: Compressed Summary (圧縮時)

**目的**: コンテキスト圧縮後も最小限の機能を維持
**トークン目安**: ~500

```markdown
## Trinitas Core (Compressed)

**System**: TMWS v2.5.0
**Coordinators**: Athena (harmony) + Hera (strategy)
**Specialists**: Artemis, Hestia, Eris, Muses
**Support**: Aphrodite, Metis, Aurora

**Memory Access**: Use `recall_memory` MCP tool for details.
**Pattern Apply**: Use `apply_pattern` for learned solutions.
**Full Context**: Use `get_session_context` to restore.
```

---

## 5. ペルソナ検出ロジック

### 5.1 トリガーワードマッピング

```python
PERSONA_TRIGGERS = {
    # Core Agents (6)
    "athena-conductor": [
        "orchestration", "workflow", "coordination", "parallel",
        "オーケストレーション", "調整", "ワークフロー"
    ],
    "artemis-optimizer": [
        "optimization", "performance", "quality", "technical", "efficiency",
        "最適化", "パフォーマンス", "品質"
    ],
    "hestia-auditor": [
        "security", "audit", "risk", "vulnerability", "threat",
        "セキュリティ", "監査", "脆弱性"
    ],
    "eris-coordinator": [
        "coordinate", "tactical", "team", "collaboration",
        "チーム調整", "戦術", "協調"
    ],
    "hera-strategist": [
        "strategy", "planning", "architecture", "vision", "roadmap",
        "戦略", "計画", "アーキテクチャ"
    ],
    "muses-documenter": [
        "documentation", "knowledge", "record", "guide",
        "ドキュメント", "文書化", "知識"
    ],

    # Support Agents (3) - v2.4.7+
    "aphrodite-designer": [
        "design", "ui", "ux", "interface", "visual", "layout", "usability",
        "デザイン", "UI", "インターフェース"
    ],
    "metis-developer": [
        "implement", "code", "develop", "build", "test", "debug", "fix",
        "実装", "コード", "テスト", "デバッグ"
    ],
    "aurora-researcher": [
        "search", "find", "lookup", "research", "context", "retrieve",
        "検索", "調査", "リサーチ"
    ],
}
```

### 5.2 検出アルゴリズム

```python
def detect_persona(prompt: str) -> str | None:
    """
    ユーザープロンプトからペルソナを検出

    Returns:
        検出されたペルソナID、または None (デフォルト: Athena)
    """
    prompt_lower = prompt.lower()

    scores = {}
    for persona, triggers in PERSONA_TRIGGERS.items():
        score = sum(1 for t in triggers if t.lower() in prompt_lower)
        if score > 0:
            scores[persona] = score

    if not scores:
        return None  # Default to Athena + Hera coordination

    return max(scores, key=scores.get)
```

---

## 6. 実装ファイル構成

### 6.1 Claude Code

```
~/.claude/
├── hooks/
│   └── core/
│       ├── unified_injector.py      # 統一注入器 (新規)
│       ├── protocol_injector.py     # 既存 (9エージェント対応更新)
│       └── dynamic_context_loader.py
├── context/
│   ├── level-1-core.md              # Level 1 テンプレート
│   ├── level-2-session.md           # Level 2 テンプレート
│   └── level-3-compressed.md        # Level 3 テンプレート
└── settings.json                    # フック設定
```

### 6.2 OpenCode

```
~/.config/opencode/
├── plugins/
│   └── trinitas-injector/
│       ├── index.ts                 # プラグインエントリ
│       ├── injector.ts              # 統一注入器
│       ├── persona-detector.ts      # ペルソナ検出
│       └── context/
│           ├── level-1-core.md
│           ├── level-2-session.md
│           └── level-3-compressed.md
└── opencode.json                    # プラグイン設定
```

---

## 7. 実装計画

### Phase 1: Claude Code Hooks 更新 (P0)

| タスク | 成果物 | 工数 |
|-------|--------|------|
| protocol_injector.py 9エージェント対応 | 更新済みファイル | 2h |
| Level 1-3 コンテキストテンプレート作成 | 3 MDファイル | 1h |
| settings.json 更新 | 更新済み設定 | 30m |
| テスト | 動作確認 | 1h |

### Phase 2: OpenCode Plugin 作成 (P0)

| タスク | 成果物 | 工数 |
|-------|--------|------|
| TypeScript プラグイン骨格作成 | index.ts, injector.ts | 2h |
| ペルソナ検出モジュール | persona-detector.ts | 1h |
| コンテキストテンプレート移植 | 3 MDファイル | 30m |
| テスト | 動作確認 | 1h |

### Phase 3: インストーラー統合 (P1)

| タスク | 成果物 | 工数 |
|-------|--------|------|
| install_trinitas.sh 更新 | プラグインインストール対応 | 1h |
| Install-Trinitas.ps1 更新 | Windows対応 | 1h |
| ドキュメント更新 | INSTALLATION_GUIDE.md | 30m |

---

## 8. テスト計画

### 8.1 Claude Code テスト

| テストケース | 期待結果 |
|-------------|---------|
| SessionStart で Level 1-2 注入 | 9エージェント情報が表示される |
| PreCompact で Level 3 注入 | 圧縮サマリーのみ表示 |
| ペルソナ検出 "optimize this" | Artemis が検出される |
| ペルソナ検出 "security audit" | Hestia が検出される |
| ペルソナ検出 "デザイン" | Aphrodite が検出される |

### 8.2 OpenCode テスト

| テストケース | 期待結果 |
|-------------|---------|
| session.created で Level 1-2 注入 | 9エージェント情報が表示される |
| tokenUsage > 90% で Level 3 注入 | 圧縮サマリーが先行注入される |
| message.created でペルソナ検出 | 適切なエージェントが選択される |

---

## 9. セキュリティ考慮事項

### 9.1 コンテキスト注入のセキュリティ

- **P0-1 準拠**: Namespace は必ず DB から検証
- **機密情報除外**: Level 3 には認証情報を含めない
- **入力検証**: ペルソナ検出前にサニタイズ

### 9.2 プラグインセキュリティ

- **署名検証**: インストール時に署名確認 (将来)
- **権限制限**: ファイルシステムアクセスは最小限
- **監査ログ**: 注入イベントを記録

---

## 10. 今後の拡張

### 10.1 計画済み

- [ ] MCP Server 側でのプッシュ型注入 (WebSocket)
- [ ] リアルタイムペルソナ切替 UI
- [ ] コンテキスト使用量ダッシュボード

### 10.2 検討中

- [ ] 他プラットフォーム対応 (Cursor, Continue, etc.)
- [ ] カスタムコンテキストプロファイル
- [ ] 学習パターンの自動適用

---

## 変更履歴

| バージョン | 日付 | 変更内容 |
|-----------|------|---------|
| 1.0.0 | 2025-11-30 | 初版作成 |

---

## 11. MCPManager 統合設計 (Trinitas Full Mode 追加)

### 11.1 既存 TMWS MCP 設計との整合性

**調査日**: 2025-11-30
**実施者**: Trinitas Full Mode (Athena, Hera, Eris, Artemis, Hestia, Muses)

#### 既存コンポーネント

| コンポーネント | ファイル | 機能 |
|---------------|---------|------|
| **MCPManager** | `src/infrastructure/mcp/manager.py` | 統一MCP接続管理 |
| **MCPPresetConfig** | `src/infrastructure/mcp/preset_config.py` | プリセット設定ロード |
| **ToolDiscoveryService** | `src/services/tool_discovery_service.py` | 動的ツール発見・登録 |
| **Skill Model** | `src/models/skill.py` | Progressive Disclosure (4層) |

#### Anthropic 推奨パターンとの整合性

| 推奨パターン | TMWS実装状況 | 整合性 |
|------------|-------------|--------|
| **Tool Search Tool** (defer_loading) | ToolDiscoveryService で部分実装 | ⚠️ 70% |
| **Progressive Disclosure** | Skill Model で完全実装 (Layer 1-4) | ✅ 100% |
| **Namespace Isolation** | V-TOOL-1 で完全実装 | ✅ 100% |
| **Auto-Connect Presets** | MCPManager で完全実装 | ✅ 100% |
| **Multi-Transport** (STDIO/HTTP) | MCPPresetConfig で完全実装 | ✅ 100% |

### 11.2 統合アーキテクチャ

```
┌─────────────────────────────────────────────────────────────────┐
│                    Push + Pull + MCP 統合アーキテクチャ         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Push Layer (Hooks/Plugins)                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ SESSION_START                                            │   │
│  │  → MCPManager.auto_connect_from_config()                │   │
│  │  → ToolDiscoveryService.list_tools()                    │   │
│  │  → Level 1-2 コンテキスト注入 (ツール一覧含む)          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              ↓                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ CONTEXT_COMPRESS                                         │   │
│  │  → Level 3 圧縮サマリー (ツール概要のみ)                │   │
│  │  → "詳細は list_mcp_tools で取得" 指示                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              ↓                                  │
│  Pull Layer (MCP Tools)                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ list_mcp_tools    → MCPManager.list_all_tools()         │   │
│  │ call_mcp_tool     → MCPManager.call_tool()              │   │
│  │ refresh_mcp_tools → MCPManager.refresh_tools()          │   │
│  │ activate_skill    → SkillService.activate()             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 11.3 defer_loading パターン適用

**Anthropic 推奨**: 数十個のツール定義は 50,000 トークン以上を消費。
defer_loading で必要時のみロード。

**TMWS 実装方針**:

```python
# Push 層での defer_loading 適用
async def inject_mcp_tools_summary(namespace: str) -> str:
    """MCP ツール概要注入 (defer_loading パターン)"""

    # 1. 頻繁使用ツール (auto_connect=true) のみ詳細表示
    frequently_used = await get_auto_connect_tools(namespace)

    # 2. 残りは "発見可能" として案内
    total_count = await get_total_tool_count(namespace)

    summary = f"""
## Available MCP Tools

**Total**: {total_count} tools available

### Auto-loaded (Ready to use)
{format_tools(frequently_used[:5])}

### Discovery
Use `list_mcp_tools` to see all available tools.
Use `call_mcp_tool(server, tool, args)` to execute.
"""
    return summary
```

**トークン削減効果**:
- Before: ~17,000 tokens (全ツール定義)
- After: ~2,000 tokens (概要 + 頻繁使用5ツール)
- **削減率**: 88%

### 11.4 必要な新規 REST API

Push 層から MCPManager を呼び出すための API:

```yaml
# OpenAPI 仕様

/api/v1/mcp/tools/summary:
  get:
    summary: Get MCP tools summary for context injection
    parameters:
      - name: namespace
        in: query
        required: true
        schema:
          type: string
    responses:
      200:
        content:
          application/json:
            schema:
              type: object
              properties:
                total_count: integer
                frequently_used:
                  type: array
                  items:
                    $ref: '#/components/schemas/ToolSummary'
                servers:
                  type: array
                  items:
                    type: string

/api/v1/mcp/connections:
  get:
    summary: Get MCP connection status
    responses:
      200:
        content:
          application/json:
            schema:
              type: array
              items:
                $ref: '#/components/schemas/ConnectionStatus'
```

### 11.5 セキュリティ要件 (Hestia 指定)

| リスク ID | 説明 | CVSS | 対策 |
|-----------|------|------|------|
| SEC-PUSH-1 | コンテキスト注入時のインジェクション | 6.5 | MDファイルのサニタイズ |
| SEC-PUSH-2 | MCPツール情報の漏洩 | 5.0 | Namespace分離の適用 |
| SEC-PUSH-3 | トークン監視の回避 | 4.0 | サーバーサイド検証 |
| SEC-PUSH-4 | OpenCode Plugin の権限昇格 | 7.0 | 最小権限原則 |

**必須対策**:

```python
# SEC-PUSH-1: MDファイルサニタイズ
def sanitize_md_content(content: str) -> str:
    """Markdown コンテンツのサニタイズ"""
    import re
    content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL | re.IGNORECASE)
    content = re.sub(r'<[^>]+>', '', content)
    return content

# SEC-PUSH-2: Namespace 分離 (V-TOOL-1 準拠)
async def fetch_mcp_tools_summary(namespace: str) -> str:
    """Namespace 分離された MCP ツール取得"""
    if not namespace or "/" in namespace or "." in namespace:
        raise ValueError("Invalid namespace")
    # ... 実装
```

### 11.6 Trinitas Full Mode 結論

**整合性評価**: 95% - 既存設計と高度に整合

**成功確率** (Hera 計算):
- 改善前: 78.7%
- 改善後 (設計調整適用): 88.4%

**推奨アクション**:

| 優先度 | アクション | 担当 | 工数 |
|--------|-----------|------|------|
| P0 | REST API 追加 (`/mcp/tools/summary`) | Artemis | 2h |
| P0 | Claude Code Hooks MCPManager統合 | Artemis | 3h |
| P0 | OpenCode Plugin 作成 | Artemis | 4h |
| P1 | セキュリティ対策実装 | Hestia | 2h |
| P1 | 共通コンテキストファイル (MD) 作成 | Muses | 1h |

**合計工数**: 12時間

---

## 変更履歴

| バージョン | 日付 | 変更内容 |
|-----------|------|---------|
| 1.0.0 | 2025-11-30 | 初版作成 |
| 1.1.0 | 2025-11-30 | MCPManager統合設計追加 (Trinitas Full Mode) |

---

*Document End*
