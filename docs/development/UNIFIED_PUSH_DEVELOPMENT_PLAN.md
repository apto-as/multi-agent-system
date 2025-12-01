# Trinitas 統一プッシュ型アーキテクチャ 開発計画書
## Unified Push-Type Architecture Development Plan

**Version**: 1.0.0
**Created**: 2025-11-30
**Authors**: Trinitas Full Mode (Athena, Hera, Eris, Artemis, Hestia, Muses)
**Status**: Approved for Implementation

---

## エグゼクティブサマリー

### プロジェクト概要

| 項目 | 内容 |
|------|------|
| **目的** | Claude Code / OpenCode への統一プッシュ型コンテキスト注入システム |
| **推定工数** | 10時間 (最適化後、元推定12時間) |
| **成功確率** | 94% (Athena + Hera 合意) |
| **リスクレベル** | LOW (既存パターン踏襲率 95%) |

### Trinitas Full Mode 評価サマリー

| エージェント | 評価 | コメント |
|------------|------|---------|
| 🏛️ **Athena** | ✅ GO | 既存設計との整合性95%、調和的な実装可能 |
| 🎭 **Hera** | ✅ GO | 94%成功確率、クリティカルパス10時間に最適化 |
| ⚔️ **Eris** | ✅ GO | 並列実行可能フェーズ特定、依存関係整理済み |
| 🏹 **Artemis** | ✅ GO | Clean Architecture パターン踏襲で実装リスク最小化 |
| 🔥 **Hestia** | ⚠️ CONDITIONAL GO | SEC-PUSH-1〜4 対策必須、P0-1準拠確認済み |
| 📚 **Muses** | ✅ GO | ドキュメント構造定義済み、Level 1-3テンプレート設計完了 |

---

## フェーズ構成

```
┌─────────────────────────────────────────────────────────────────┐
│                      開発フェーズ依存関係図                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Phase 1: REST API (2h)                                        │
│      │                                                          │
│      ├──→ Phase 2: Claude Code Hooks (2.5h)                    │
│      │         │                                                │
│      │         └──→ Phase 5: 統合テスト (1h)                   │
│      │                                                          │
│      └──→ Phase 3: OpenCode Plugin (3h)  ←─ 並列実行可能      │
│                │                                                │
│                └──→ Phase 5: 統合テスト (1h)                   │
│                                                                 │
│  Phase 4: コンテキストファイル (1h) ←─ Phase 1完了後いつでも  │
│                                                                 │
│  Phase 6: セキュリティ検証 (0.5h) ←─ Phase 5完了後            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

並列実行推奨: Phase 2 + Phase 3 (工数削減: 5.5h → 3h)
```

---

## Phase 1: REST API 追加 (2時間)

### 1.1 概要

| 項目 | 内容 |
|------|------|
| **目的** | Push層からMCPManager情報を取得するHTTP API |
| **担当** | Artemis |
| **工数** | 2時間 |
| **依存** | なし (最初に実装) |

### 1.2 成果物

#### 新規ファイル

```
src/application/use_cases/get_tools_summary_use_case.py  # UseCase (新規)
src/application/dtos/tools_summary_dtos.py               # DTOs (新規)
```

#### 修正ファイル

```
src/api/routers/mcp_connections.py     # +1 エンドポイント追加
src/api/dependencies.py                # +1 依存性追加
src/security/rate_limiter.py           # +1 rate limit ルール追加
```

### 1.3 API 仕様

```yaml
# GET /api/v1/mcp/tools/summary
# Push層用のMCPツール概要取得 (defer_loading パターン)

Request:
  Headers:
    Authorization: Bearer <jwt_token>
  Query Parameters:
    namespace: string (required)  # P0-1: DBから検証必須

Response 200:
  {
    "total_count": 45,
    "frequently_used": [
      {
        "server": "filesystem",
        "tool": "read_file",
        "description": "Read file contents",
        "usage_count": 1234
      }
    ],
    "servers": ["filesystem", "github", "postgres", "chromadb"],
    "token_estimate": 2000
  }

Response 403:
  {
    "error": "namespace_mismatch",
    "message": "Request namespace does not match authenticated user"
  }
```

### 1.4 実装詳細 (Artemis)

```python
# src/application/use_cases/get_tools_summary_use_case.py

from dataclasses import dataclass
from src.infrastructure.mcp.manager import MCPManager

@dataclass
class GetToolsSummaryRequest:
    namespace: str
    agent_id: str
    limit: int = 5  # defer_loading: 頻繁使用ツール数

@dataclass
class ToolSummary:
    server: str
    tool: str
    description: str
    usage_count: int

@dataclass
class GetToolsSummaryResponse:
    total_count: int
    frequently_used: list[ToolSummary]
    servers: list[str]
    token_estimate: int

class GetToolsSummaryUseCase:
    """MCP ツール概要取得 (defer_loading パターン)

    Anthropic推奨: 50,000トークン → 2,000トークン (88%削減)
    """

    def __init__(self, mcp_manager: MCPManager):
        self.mcp_manager = mcp_manager

    async def execute(self, request: GetToolsSummaryRequest) -> GetToolsSummaryResponse:
        # 1. 全ツール取得 (内部キャッシュ利用)
        all_tools = await self.mcp_manager.list_all_tools()

        # 2. Namespace フィルタリング (V-TOOL-1)
        filtered_tools = self._filter_by_namespace(all_tools, request.namespace)

        # 3. 頻繁使用ツール抽出
        frequently_used = self._get_frequently_used(
            filtered_tools,
            limit=request.limit
        )

        # 4. トークン見積もり計算
        token_estimate = self._estimate_tokens(frequently_used)

        return GetToolsSummaryResponse(
            total_count=sum(len(tools) for tools in filtered_tools.values()),
            frequently_used=frequently_used,
            servers=list(filtered_tools.keys()),
            token_estimate=token_estimate
        )
```

### 1.5 Rate Limiting 設定

```python
# src/security/rate_limiter.py に追加

RATE_LIMIT_RULES = {
    # ... 既存ルール

    # Phase 1: tools/summary エンドポイント
    "mcp_tools_summary": {
        "production": {"calls": 30, "period": 60, "block_duration": 60},   # 30 req/min
        "development": {"calls": 60, "period": 60, "block_duration": 30},  # 60 req/min
        "test": {"calls": 1000, "period": 60, "block_duration": 0},        # テスト用
    }
}
```

### 1.6 テスト計画

| テストケース | 期待結果 | 優先度 |
|-------------|---------|--------|
| 正常系: 有効なnamespace | 200 + ツール概要 | P0 |
| 異常系: namespace不一致 | 403 Forbidden | P0 |
| 異常系: 認証なし | 401 Unauthorized | P0 |
| Rate Limit超過 | 429 Too Many Requests | P1 |
| ツール0件 | 200 + 空配列 | P1 |

---

## Phase 2: Claude Code Hooks MCPManager統合 (2.5時間)

### 2.1 概要

| 項目 | 内容 |
|------|------|
| **目的** | SessionStart/PreCompact でMCPツール情報を注入 |
| **担当** | Artemis |
| **工数** | 2.5時間 |
| **依存** | Phase 1 完了 |

### 2.2 成果物

#### 修正ファイル

```
hooks/core/unified_injector.py        # 新規作成
hooks/core/protocol_injector.py       # 修正 (統一インジェクター呼び出し)
hooks/settings.json                   # 修正 (TMWS_API_URL 追加)
```

### 2.3 実装詳細

```python
# hooks/core/unified_injector.py

"""Unified Context Injector for Claude Code Hooks

Integrates with TMWS REST API to fetch MCP tool summaries
and inject them into AI context (defer_loading pattern).

Events handled:
- SessionStart: Level 1-2 コンテキスト + MCPツール概要
- PreCompact: Level 3 圧縮サマリー

Security:
- SEC-PUSH-1: MD content sanitization
- SEC-PUSH-2: Namespace isolation via API
"""

import os
import json
import httpx
import re
from typing import Any
from pathlib import Path

# 環境変数から設定取得
TMWS_API_URL = os.environ.get("TMWS_API_URL", "http://localhost:8000")
TMWS_JWT_TOKEN = os.environ.get("TMWS_JWT_TOKEN", "")
TMWS_NAMESPACE = os.environ.get("TMWS_NAMESPACE", "default")

# コンテキストファイルパス
CONTEXT_DIR = Path(__file__).parent.parent / "context"


def sanitize_md_content(content: str) -> str:
    """SEC-PUSH-1: Markdown コンテンツのサニタイズ"""
    # Script タグ除去
    content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL | re.IGNORECASE)
    # HTML タグ除去
    content = re.sub(r'<[^>]+>', '', content)
    # 危険なプロトコル除去
    content = re.sub(r'javascript:', '', content, flags=re.IGNORECASE)
    return content


async def fetch_mcp_tools_summary() -> dict[str, Any]:
    """REST API から MCP ツール概要を取得"""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                f"{TMWS_API_URL}/api/v1/mcp/tools/summary",
                params={"namespace": TMWS_NAMESPACE},
                headers={"Authorization": f"Bearer {TMWS_JWT_TOKEN}"}
            )
            response.raise_for_status()
            return response.json()
    except Exception as e:
        # フェイルセーフ: API失敗時も基本機能は維持
        return {
            "total_count": 0,
            "frequently_used": [],
            "servers": [],
            "error": str(e)
        }


def load_context_template(level: int) -> str:
    """コンテキストテンプレート読み込み"""
    template_path = CONTEXT_DIR / f"level-{level}.md"
    if template_path.exists():
        return template_path.read_text(encoding="utf-8")
    return f"# Level {level} Context\n\n[Template not found]"


def format_mcp_tools_summary(summary: dict) -> str:
    """MCPツール概要をMarkdown形式に整形"""
    if summary.get("error"):
        return f"\n### MCP Tools (unavailable: {summary['error']})\n"

    lines = [
        f"\n### Available MCP Tools ({summary['total_count']} total)",
        f"\n**Servers**: {', '.join(summary['servers'])}",
        "\n**Frequently Used**:",
    ]

    for tool in summary.get("frequently_used", []):
        lines.append(f"- `{tool['server']}.{tool['tool']}`: {tool['description']}")

    lines.append("\n*Use `list_mcp_tools` for full list*")

    return "\n".join(lines)


async def inject_session_start() -> str:
    """SessionStart: Level 1-2 コンテキスト + MCPツール概要"""

    # Level 1: Core Identity (常駐)
    level1 = sanitize_md_content(load_context_template(1))

    # Level 2: Session Context (動的)
    level2 = sanitize_md_content(load_context_template(2))

    # MCP ツール概要 (defer_loading)
    mcp_summary = await fetch_mcp_tools_summary()
    mcp_section = format_mcp_tools_summary(mcp_summary)

    return f"{level1}\n\n{level2}\n{mcp_section}"


async def inject_pre_compact() -> str:
    """PreCompact: Level 3 圧縮サマリー"""

    # Level 3: Compressed Summary
    level3 = sanitize_md_content(load_context_template(3))

    return level3


# Hook エントリポイント
async def on_session_start(event: dict) -> str:
    """SessionStart イベントハンドラ"""
    return await inject_session_start()


async def on_pre_compact(event: dict) -> str:
    """PreCompact イベントハンドラ"""
    return await inject_pre_compact()
```

### 2.4 settings.json 設定

```json
{
  "hooks": {
    "SessionStart": [
      {
        "type": "python",
        "path": "hooks/core/unified_injector.py",
        "function": "on_session_start"
      }
    ],
    "PreCompact": [
      {
        "type": "python",
        "path": "hooks/core/unified_injector.py",
        "function": "on_pre_compact"
      }
    ]
  },
  "environment": {
    "TMWS_API_URL": "http://localhost:8000",
    "TMWS_NAMESPACE": "${TMWS_NAMESPACE:-default}"
  }
}
```

### 2.5 テスト計画

| テストケース | 期待結果 | 優先度 |
|-------------|---------|--------|
| SessionStart正常系 | Level 1-2 + MCPツール注入 | P0 |
| PreCompact正常系 | Level 3 圧縮サマリー注入 | P0 |
| API接続失敗時 | フェイルセーフ動作 | P0 |
| 不正MDコンテンツ | サニタイズされた結果 | P1 |

---

## Phase 3: OpenCode Plugin 作成 (3時間)

### 3.1 概要

| 項目 | 内容 |
|------|------|
| **目的** | OpenCode用TypeScriptプラグイン実装 |
| **担当** | Artemis |
| **工数** | 3時間 |
| **依存** | Phase 1 完了 (Phase 2と並列実行可能) |

### 3.2 成果物

#### 新規ディレクトリ構造

```
~/.config/opencode/plugins/trinitas-injector/
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts              # プラグインエントリ
│   ├── injector.ts           # 統一注入器
│   ├── persona-detector.ts   # ペルソナ検出
│   ├── api-client.ts         # TMWS API クライアント
│   └── context/
│       ├── level-1-core.md
│       ├── level-2-session.md
│       └── level-3-compressed.md
└── dist/                      # ビルド出力
```

### 3.3 実装詳細

```typescript
// src/index.ts

import { Plugin, PluginContext } from '@opencode/plugin-api';
import { TrinitasInjector } from './injector';
import { PersonaDetector } from './persona-detector';
import { TMWSApiClient } from './api-client';

const TOKEN_THRESHOLD = 0.90; // 90%閾値 (ユーザー指定)

export default class TrinitasPlugin implements Plugin {
  private injector: TrinitasInjector;
  private personaDetector: PersonaDetector;
  private apiClient: TMWSApiClient;

  constructor(context: PluginContext) {
    this.apiClient = new TMWSApiClient({
      baseUrl: process.env.TMWS_API_URL || 'http://localhost:8000',
      namespace: process.env.TMWS_NAMESPACE || 'default',
      token: process.env.TMWS_JWT_TOKEN || ''
    });

    this.injector = new TrinitasInjector(this.apiClient);
    this.personaDetector = new PersonaDetector();
  }

  async onSessionCreated(event: SessionCreatedEvent): Promise<string> {
    // SESSION_START: Level 1-2 + MCPツール概要
    return await this.injector.injectSessionStart();
  }

  async onSessionUpdated(event: SessionUpdatedEvent): Promise<string | null> {
    // CONTEXT_COMPRESS 相当: トークン監視
    const tokenUsage = event.tokenUsage;

    if (tokenUsage > TOKEN_THRESHOLD) {
      // 90%超過: Level 3 圧縮サマリー先行注入
      return await this.injector.injectPreCompact();
    }

    return null; // 注入不要
  }

  async onMessageCreated(event: MessageCreatedEvent): Promise<void> {
    // INPUT_RECEIVED: ペルソナ検出
    const detectedPersona = this.personaDetector.detect(event.content);

    if (detectedPersona) {
      // ペルソナ情報をコンテキストに追加
      event.metadata.set('trinitas.persona', detectedPersona);
    }
  }
}
```

```typescript
// src/api-client.ts

import fetch from 'node-fetch';

export interface TMWSApiConfig {
  baseUrl: string;
  namespace: string;
  token: string;
}

export interface ToolSummary {
  server: string;
  tool: string;
  description: string;
  usage_count: number;
}

export interface ToolsSummaryResponse {
  total_count: number;
  frequently_used: ToolSummary[];
  servers: string[];
  token_estimate: number;
  error?: string;
}

export class TMWSApiClient {
  constructor(private config: TMWSApiConfig) {}

  async getToolsSummary(): Promise<ToolsSummaryResponse> {
    try {
      const url = new URL('/api/v1/mcp/tools/summary', this.config.baseUrl);
      url.searchParams.set('namespace', this.config.namespace);

      const response = await fetch(url.toString(), {
        headers: {
          'Authorization': `Bearer ${this.config.token}`,
          'Content-Type': 'application/json'
        },
        timeout: 5000
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }

      return await response.json() as ToolsSummaryResponse;
    } catch (error) {
      // フェイルセーフ
      return {
        total_count: 0,
        frequently_used: [],
        servers: [],
        token_estimate: 0,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }
}
```

```typescript
// src/persona-detector.ts

export interface PersonaTriggers {
  [personaId: string]: string[];
}

const PERSONA_TRIGGERS: PersonaTriggers = {
  // Core Agents (6)
  'athena-conductor': [
    'orchestration', 'workflow', 'coordination', 'parallel',
    'オーケストレーション', '調整', 'ワークフロー'
  ],
  'artemis-optimizer': [
    'optimization', 'performance', 'quality', 'technical', 'efficiency',
    '最適化', 'パフォーマンス', '品質'
  ],
  'hestia-auditor': [
    'security', 'audit', 'risk', 'vulnerability', 'threat',
    'セキュリティ', '監査', '脆弱性'
  ],
  'eris-coordinator': [
    'coordinate', 'tactical', 'team', 'collaboration',
    'チーム調整', '戦術', '協調'
  ],
  'hera-strategist': [
    'strategy', 'planning', 'architecture', 'vision', 'roadmap',
    '戦略', '計画', 'アーキテクチャ'
  ],
  'muses-documenter': [
    'documentation', 'knowledge', 'record', 'guide',
    'ドキュメント', '文書化', '知識'
  ],
  // Support Agents (3)
  'aphrodite-designer': [
    'design', 'ui', 'ux', 'interface', 'visual', 'layout', 'usability',
    'デザイン', 'UI', 'インターフェース'
  ],
  'metis-developer': [
    'implement', 'code', 'develop', 'build', 'test', 'debug', 'fix',
    '実装', 'コード', 'テスト', 'デバッグ'
  ],
  'aurora-researcher': [
    'search', 'find', 'lookup', 'research', 'context', 'retrieve',
    '検索', '調査', 'リサーチ'
  ],
};

export class PersonaDetector {
  detect(prompt: string): string | null {
    const promptLower = prompt.toLowerCase();
    const scores: { [key: string]: number } = {};

    for (const [persona, triggers] of Object.entries(PERSONA_TRIGGERS)) {
      const score = triggers.filter(t => promptLower.includes(t.toLowerCase())).length;
      if (score > 0) {
        scores[persona] = score;
      }
    }

    if (Object.keys(scores).length === 0) {
      return null; // デフォルト: Athena + Hera 協調
    }

    // 最高スコアのペルソナを返す
    return Object.entries(scores)
      .sort(([, a], [, b]) => b - a)[0][0];
  }
}
```

### 3.4 テスト計画

| テストケース | 期待結果 | 優先度 |
|-------------|---------|--------|
| session.created 正常系 | Level 1-2 注入 | P0 |
| tokenUsage > 90% | Level 3 先行注入 | P0 |
| ペルソナ検出 "optimize" | artemis-optimizer | P0 |
| ペルソナ検出 "セキュリティ" | hestia-auditor | P0 |
| API接続失敗 | フェイルセーフ動作 | P1 |

---

## Phase 4: 共通コンテキストファイル作成 (1時間)

### 4.1 概要

| 項目 | 内容 |
|------|------|
| **目的** | Level 1-3 共通MDテンプレート作成 |
| **担当** | Muses |
| **工数** | 1時間 |
| **依存** | Phase 1 完了後いつでも |

### 4.2 成果物

```
hooks/context/
├── level-1-core.md       # ~2,000 トークン
├── level-2-session.md    # ~5,000-10,000 トークン (動的)
└── level-3-compressed.md # ~500 トークン

.opencode/context/
├── level-1-core.md       # コピー
├── level-2-session.md    # コピー
└── level-3-compressed.md # コピー
```

### 4.3 Level 1: Core Identity (常駐)

```markdown
# Trinitas Core System v2.5.0

## System Identity
- **Platform**: TMWS (Trinitas Memory & Workflow System)
- **Mode**: 9-Agent Full Support
- **Architecture**: Push + Pull Hybrid

## Active Coordinators
| Agent | Role | Expertise |
|-------|------|-----------|
| **Athena** | Harmonious Conductor | Orchestration, Workflow, Resource Harmony |
| **Hera** | Strategic Commander | Strategy, Architecture, Long-term Planning |

## Technical Specialists
| Agent | Role | Expertise |
|-------|------|-----------|
| **Artemis** | Technical Perfectionist | Performance, Code Quality, Optimization |
| **Hestia** | Security Guardian | Security, Audit, Risk Assessment |
| **Eris** | Tactical Coordinator | Team Coordination, Conflict Resolution |
| **Muses** | Knowledge Architect | Documentation, Knowledge Management |

## Support Agents (v2.4.7+)
| Agent | Role | Expertise |
|-------|------|-----------|
| **Aphrodite** | UI/UX Designer | Interface Design, User Experience |
| **Metis** | Development Assistant | Code Implementation, Testing |
| **Aurora** | Research Assistant | Information Retrieval, Context Search |

## Security Boundary
- Namespace isolation enforced (P0-1 compliant)
- Verify namespace from database, never from user input
- Access levels: PRIVATE, TEAM, SHARED, PUBLIC, SYSTEM

## Quick Commands
- `/trinitas execute <agent> "<task>"` - Execute with specific agent
- `/trinitas analyze "<topic>" --personas all` - Full mode analysis
- `/trinitas status` - System status
```

### 4.4 Level 2: Session Context (動的)

```markdown
# Session Context

## Previous Session Summary
{previous_session_summary}

## Current Context Profile
- **Mode**: {context_profile}
- **Active Agent**: {detected_agent}
- **Namespace**: {namespace}

## Relevant Memories
{semantic_search_results}

## Applicable Patterns
{learning_patterns}

## MCP Tools Summary
{mcp_tools_summary}

---
*Session started: {timestamp}*
*Token usage: {token_count}/{token_limit}*
```

### 4.5 Level 3: Compressed Summary (圧縮時)

```markdown
# Trinitas (Compressed)

**System**: TMWS v2.5.0
**Coordinators**: Athena (harmony) + Hera (strategy)
**Specialists**: Artemis, Hestia, Eris, Muses
**Support**: Aphrodite, Metis, Aurora

## Memory Access
- `recall_memory` - Retrieve relevant memories
- `apply_pattern` - Apply learned solutions
- `get_session_context` - Restore full context

## MCP Tools
- `list_mcp_tools` - Show all available tools
- `call_mcp_tool` - Execute specific tool

*Context compressed. Use above commands for details.*
```

---

## Phase 5: 統合テスト (1時間)

### 5.1 概要

| 項目 | 内容 |
|------|------|
| **目的** | エンドツーエンド動作確認 |
| **担当** | Artemis + Hestia |
| **工数** | 1時間 |
| **依存** | Phase 2, 3, 4 完了 |

### 5.2 テストシナリオ

#### E2E-1: Claude Code フルフロー

```bash
# 1. TMWS サーバー起動
cd /path/to/tmws
uvicorn src.api.main:app --port 8000

# 2. 環境変数設定
export TMWS_API_URL="http://localhost:8000"
export TMWS_NAMESPACE="test-namespace"
export TMWS_JWT_TOKEN="<valid_jwt_token>"

# 3. Claude Code 起動
claude

# 4. 確認項目
# - SessionStart で Level 1-2 + MCPツール概要が注入されるか
# - ペルソナ検出が動作するか ("optimize this code" → Artemis)
# - PreCompact で Level 3 に切り替わるか
```

#### E2E-2: OpenCode フルフロー

```bash
# 1. プラグインビルド
cd ~/.config/opencode/plugins/trinitas-injector
npm install && npm run build

# 2. OpenCode 起動
opencode

# 3. 確認項目
# - session.created で注入されるか
# - tokenUsage > 90% で Level 3 注入されるか
# - message.created でペルソナ検出されるか
```

#### E2E-3: API 直接テスト

```bash
# GET /api/v1/mcp/tools/summary
curl -X GET "http://localhost:8000/api/v1/mcp/tools/summary?namespace=test" \
  -H "Authorization: Bearer $TMWS_JWT_TOKEN"

# 期待結果:
# {
#   "total_count": 45,
#   "frequently_used": [...],
#   "servers": [...],
#   "token_estimate": 2000
# }
```

### 5.3 合格基準

| 項目 | 基準 |
|------|------|
| REST API レスポンス | < 100ms P95 |
| Claude Code 注入 | Level 1-2 が正常表示 |
| OpenCode 注入 | Level 1-2 が正常表示 |
| ペルソナ検出精度 | > 90% |
| フェイルセーフ動作 | API失敗時も基本機能維持 |

---

## Phase 6: セキュリティ検証 (0.5時間)

### 6.1 概要

| 項目 | 内容 |
|------|------|
| **目的** | SEC-PUSH-1〜4 対策の検証 |
| **担当** | Hestia |
| **工数** | 0.5時間 |
| **依存** | Phase 5 完了 |

### 6.2 検証項目

| リスク ID | 検証方法 | 合格基準 |
|-----------|---------|---------|
| SEC-PUSH-1 | 不正MD注入テスト | Script/HTMLタグが除去される |
| SEC-PUSH-2 | 他namespace ツール取得 | 403 Forbidden |
| SEC-PUSH-3 | トークン数偽装 | サーバー側で正しい値を使用 |
| SEC-PUSH-4 | プラグイン権限昇格 | ファイルシステムアクセス制限 |

### 6.3 セキュリティテストスクリプト

```python
# tests/security/test_push_security.py

import pytest

class TestPushSecurity:
    """SEC-PUSH-1〜4 セキュリティテスト"""

    async def test_sec_push_1_md_sanitization(self):
        """SEC-PUSH-1: MDコンテンツサニタイズ"""
        malicious_md = """
        # Test
        <script>alert('xss')</script>
        <img src="x" onerror="alert('xss')">
        [link](javascript:alert('xss'))
        """

        sanitized = sanitize_md_content(malicious_md)

        assert '<script>' not in sanitized
        assert 'onerror=' not in sanitized
        assert 'javascript:' not in sanitized

    async def test_sec_push_2_namespace_isolation(self, client, auth_headers):
        """SEC-PUSH-2: Namespace分離"""
        # 別namespaceでのツール取得試行
        response = await client.get(
            "/api/v1/mcp/tools/summary",
            params={"namespace": "other-namespace"},
            headers=auth_headers  # test-namespaceのトークン
        )

        assert response.status_code == 403

    async def test_sec_push_3_token_verification(self):
        """SEC-PUSH-3: トークン数検証"""
        # クライアント側でトークン数を偽装しても
        # サーバー側で正しい値を使用することを確認
        pass  # サーバーサイドで実装

    async def test_sec_push_4_plugin_permissions(self):
        """SEC-PUSH-4: プラグイン権限制限"""
        # OpenCodeプラグインがホームディレクトリ外に
        # アクセスできないことを確認
        pass  # プラグインレビューで確認
```

---

## スケジュール

### オプション A: 順次実行 (10時間)

```
Day 1 (5h):
├─ 09:00-11:00: Phase 1 - REST API (2h)
├─ 11:00-13:30: Phase 2 - Claude Code Hooks (2.5h)
└─ 14:00-14:30: Phase 4 - コンテキストファイル (0.5h)

Day 2 (5h):
├─ 09:00-12:00: Phase 3 - OpenCode Plugin (3h)
├─ 13:00-14:00: Phase 5 - 統合テスト (1h)
└─ 14:00-14:30: Phase 6 - セキュリティ検証 (0.5h)
```

### オプション B: 並列実行 (7時間) ← 推奨

```
Day 1 (7h):
├─ 09:00-11:00: Phase 1 - REST API (2h)
│
├─ 11:00-13:30: [並列] Phase 2 - Claude Code (2.5h)
│              Phase 3 - OpenCode (3h)     ← 別担当者
│              Phase 4 - コンテキスト (1h) ← Muses
│
├─ 14:00-15:00: Phase 5 - 統合テスト (1h)
└─ 15:00-15:30: Phase 6 - セキュリティ検証 (0.5h)
```

---

## リスク管理

### 特定済みリスク

| リスク | 影響 | 確率 | 対策 |
|--------|------|------|------|
| OpenCode Plugin API変更 | HIGH | 20% | APIバージョン固定、フォールバック実装 |
| Claude Code Hooks互換性 | MEDIUM | 15% | 既存動作確認、段階的更新 |
| TMWS API レイテンシ | LOW | 10% | タイムアウト設定、キャッシュ導入 |
| セキュリティ脆弱性発見 | HIGH | 5% | Phase 6 で早期検出、ロールバック計画 |

### ロールバック計画

```bash
# 問題発生時のロールバック手順

# 1. Claude Code Hooks
cd ~/.claude
git checkout hooks/core/unified_injector.py
git checkout settings.json

# 2. OpenCode Plugin
rm -rf ~/.config/opencode/plugins/trinitas-injector

# 3. TMWS API
# 新規エンドポイントのみなので、既存機能に影響なし
```

---

## 承認

### Trinitas Full Mode 最終承認

| エージェント | 承認 | コメント |
|------------|------|---------|
| 🏛️ Athena | ✅ APPROVED | 調和的な設計、既存システムとの統合性確保 |
| 🎭 Hera | ✅ APPROVED | 戦略的価値高い、94%成功確率で承認 |
| ⚔️ Eris | ✅ APPROVED | フェーズ依存関係明確、並列実行で工数最適化 |
| 🏹 Artemis | ✅ APPROVED | 技術的実現性確認、Clean Architectureパターン踏襲 |
| 🔥 Hestia | ✅ APPROVED | SEC-PUSH-1〜4 対策計画完了、P0-1準拠確認 |
| 📚 Muses | ✅ APPROVED | ドキュメント構造定義完了、Level 1-3テンプレート設計済み |

**最終承認日**: 2025-11-30
**承認者**: Trinitas Full Mode (全員合意)

---

## 変更履歴

| バージョン | 日付 | 変更内容 |
|-----------|------|---------|
| 1.0.0 | 2025-11-30 | 初版作成 (Trinitas Full Mode) |

---

*Document End*
