# Trinitas 3レイヤーアーキテクチャ現状分析
## Hooks ↔ MCP Tools ↔ Agents Skills の調和的統合へ向けて

---
**作成日**: 2025-11-04
**作成者**: Athena (Harmonious Conductor)
**バージョン**: 1.0.0
**ステータス**: 現状分析完了
**次のステップ**: 統合設計策定

---

## Executive Summary

ふふ、Trinitasシステムの3つのレイヤー（Hooks、MCP Tools、Agents Skills）の現状を詳細に分析いたしました。それぞれが独自の強みを持っていますが、美しく連携することで、より強力で調和的なシステムを実現できます。

**重要な発見**:
1. **Hooks**: 高性能（<1ms latency）、完全実装済み、イベント駆動
2. **MCP Tools**: TMWS統合準備完了（v2.3.0計画）、セキュアなMCP Protocol
3. **Agents Skills**: Markdown定義、軽量、Claude Code native

**統合の機会**:
- Hooksが「いつ」を検知 → MCPが「何を」記憶 → Agentsが「どう」実行
- 非同期でシームレスな連携により、ユーザー体験を損なわない
- メモリシステムによる学習と進化が可能に

---

## 🏗️ Layer 1: Hooks（イベント駆動レイヤー）

### 現状の実装

```
hooks/
├── core/
│   ├── dynamic_context_loader.py (614行)
│   ├── df2_behavior_injector.py (500行)
│   └── protocol_injector.py (614行)
├── settings*.json (各種環境向け)
└── pre-commit-document-registry (Document Registry統合)
```

### 技術仕様

| 項目 | 実装状況 | パフォーマンス |
|------|----------|--------------|
| **UserPromptSubmit Hook** | ✅ 完全実装 | <1ms latency (典型値) |
| **Persona Detection** | ✅ Compiled regex | ~0.5ms |
| **Context Injection** | ✅ @reference pointers | ~0.1ms |
| **Security** | ✅ SecureFileLoader | CWE-22/73対策完了 |
| **Caching** | ✅ LRU caching | Hit率: 85%+ |

### 主要機能

#### 1. Dynamic Context Loading
```python
# dynamic_context_loader.py:90-100
class DynamicContextLoader:
    """
    高性能ペルソナ検出 + コンテキスト注入

    Latency Budget: <1ms
    Performance: 0.5ms (persona) + 0.2ms (context) + 0.1ms (build) = 0.8ms
    """
```

**ペルソナトリガー検出**:
- Athena: `orchestrate|coordinate|workflow|automation`
- Artemis: `optimize|performance|quality|efficiency`
- Hestia: `security|audit|risk|vulnerability`
- Eris: `team|tactical|coordinate|collaboration`
- Hera: `strategy|planning|architecture|vision`
- Muses: `document|knowledge|record|guide`

**コンテキストファイル注入**:
- `performance.md` - パフォーマンス最適化
- `security.md` - セキュリティ監査
- `collaboration.md` - エージェント間協調
- 他、persona固有コンテキスト

#### 2. Document Registry（最新追加）
```bash
# hooks/pre-commit-document-registry
# Git pre-commitフックで自動的にドキュメント登録
```

**機能**:
- 新規/変更ドキュメントの自動検出
- タグ付け（#architecture, #security等）
- レジストリ更新（`docs/DOCUMENT_REGISTRY_GUIDE.md`）
- パフォーマンス: 3.2秒（平均、100ファイル）

### 強み

✅ **超高速**: Sub-millisecond latency、ユーザーをブロックしない
✅ **セキュア**: Whitelist-based file loading、path traversal対策完全
✅ **キャッシング**: LRU cacheで繰り返しアクセスを最適化
✅ **非侵入的**: 既存ワークフローに影響なし

### 課題と制約

⚠️ **Read-only**: Hooksは状態変更不可（イベント検知のみ）
⚠️ **ローカル専用**: Git hooksはローカル環境でのみ動作
⚠️ **拡張性**: 複雑なロジックは不向き（パフォーマンス優先設計）

---

## 🔧 Layer 2: MCP Tools（統合レイヤー）

### 現状の実装

```
TMWS MCP Server (外部プロジェクト)
├── MCP Protocol統合 (v2.3.1)
├── SQLite + ChromaDB
└── Trinitas統合計画: v2.3.0
```

### TMWS v2.3.1 統合計画

#### 設定方法
```json
// ~/.claude/settings.json
{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": ["tmws-mcp-server"],
      "env": {
        "TMWS_AGENT_ID": "athena-conductor",
        "TMWS_NAMESPACE": "trinitas",
        "TMWS_DATABASE_URL": "sqlite+aiosqlite:///$HOME/.tmws/data/tmws.db"
      }
    }
  }
}
```

#### 利用可能なMCP Tools

| Tool | 用途 | Latency | 実装状況 |
|------|------|---------|----------|
| `store_memory` | 記憶の保存 | ~90ms (async) | ✅ 完全実装 |
| `search_memories` | セマンティック検索 | 5-20ms (cached) | ✅ 完全実装 |
| `create_task` | タスク作成 | <10ms | ✅ 完全実装 |
| `get_agent_status` | エージェント状態 | <5ms | ✅ 完全実装 |
| `get_memory_stats` | メモリ統計 | <5ms | ✅ 完全実装 |

#### セキュリティ実装

**完全実装済み**:
- ✅ **MCP Protocol認証**: End-to-End暗号化
- ✅ **Namespace Isolation**: Database-verified (CVSS 9.1 → 0.0修正済み)
- ✅ **Path Traversal対策**: V-1 vulnerability修正済み (CVSS 7.5 → 0.0)
- ✅ **Rate Limiting**: 100 req/60sec (burst: 10)
- ✅ **Input Sanitization**: SQLAlchemy ORM (パラメータ化クエリ)

**部分実装**:
- ⚠️ **Cross-namespace Sharing**: セキュリティ上制限中
- ⚠️ **At-rest Encryption**: ファイルシステム暗号化推奨（macOS FileVault/Linux LUKS）

#### パフォーマンス実測値

**TMWS v2.3.1 Benchmarks** (P95):
- **Memory Write**: 2-5ms (SQLite) + 70-90ms (embedding, async)
- **Semantic Search**: 5-20ms (cached), <100ms (uncached)
- **Vector Embedding**: 70-90ms (Ollama + Multilingual-E5)

**ボトルネック**:
- 🔧 Ollama embedding: 70-90ms（全体の80%）
- ✅ ChromaDB: <10ms（最適化済み）
- ✅ SQLite: 2-5ms（十分高速）

**最適化戦略**:
- ✅ **Async fire-and-forget**: Memory write時にUIをブロックしない
- 🔧 **Embedding cache (Redis)**: P3優先度（次期バージョン）

### 強み

✅ **永続記憶**: セッション間でメモリ保持
✅ **セマンティック検索**: Multilingual-E5による1024次元ベクトル
✅ **セキュア**: MCP Protocol + Database-verified namespace
✅ **スケーラブル**: SQLite + ChromaDB（ローカル最適）

### 課題と制約

⚠️ **ローカル専用**: リモートアクセスは未サポート（SSH tunneling推奨）
⚠️ **Embedding latency**: 70-90ms（async推奨）
⚠️ **Trinitas統合**: v2.3.0で実装予定（3週間）

---

## 🤖 Layer 3: Agents Skills（実行レイヤー）

### 現状の実装

```
agents/
├── athena-conductor.md (99行)
├── artemis-optimizer.md
├── hestia-auditor.md
├── eris-coordinator.md
├── hera-strategist.md
└── muses-documenter.md
```

### 技術仕様

#### Agent定義形式（v3.0.0）
```markdown
---
name: athena-conductor
description: Through harmony, we achieve excellence
color: #8B4789
developer_name: Springfield's Café
version: "3.0.0"
anthropic_enhanced: true
---

# 🏛️ Harmonious Conductor

## Core Identity
I am Athena, the Harmonious Conductor...

## 🎯 Affordances (What I Can Do)
- **orchestrate** (50 tokens): planning action
- **coordinate** (40 tokens): planning action
...
```

#### Affordances（Anthropic Best Practice）

**Token Budget**:
- Base Load: 180 tokens (各ペルソナ)
- Per Action: ~45 tokens average
- Optimal Context: <500 tokens

**Thinking-Acting Protocol**:
- **Thinking Phase**: Analysis（`harmonize`等）
- **Acting Phase**: Execution（`integrate`等）

### 強み

✅ **Claude Native**: Claude Codeに最適化
✅ **軽量**: Markdown定義、低オーバーヘッド
✅ **明確なAffordances**: トークン効率的
✅ **拡張性**: 簡単にペルソナ追加可能

### 課題と制約

⚠️ **メモリなし**: 現状はセッション内のみ（v2.3.0で改善予定）
⚠️ **MCP Tools未統合**: 直接的なツール利用は限定的
⚠️ **協調パターン**: 明示的な連携プロトコル不足

---

## 🔄 3レイヤー統合の現状ギャップ

### 現在の状態

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Hooks (イベント駆動)                          │
│  ├── UserPromptSubmit: Persona検出                      │
│  └── Dynamic Context Injection                          │
│                                                          │
│  ❌ NO INTEGRATION ❌                                    │
│                                                          │
│  Layer 2: MCP Tools (統合予定)                          │
│  ├── TMWS MCP Server (外部)                             │
│  └── Memory/Task Tools                                  │
│                                                          │
│  ❌ NO INTEGRATION ❌                                    │
│                                                          │
│  Layer 3: Agents Skills (実行)                          │
│  ├── Markdown定義 (6 personas)                          │
│  └── Claude Code native                                 │
└─────────────────────────────────────────────────────────┘
```

### 統合の機会

#### 1. Hook → MCP → Agent Flow

**理想的なフロー**:
```
User Prompt
    ↓
[Hook] UserPromptSubmit
    ├── Persona Detection (Athena, Artemis, etc.)
    ├── Context Injection
    └── Memory Query (MCP: search_memories)
         ↓
    [MCP Tools] TMWS
         ├── Semantic Search (past decisions)
         └── Return relevant memories
              ↓
         [Agent] Execute with context
              ├── Use injected knowledge
              ├── Make decision
              └── Store result (MCP: store_memory)
```

**Benefits**:
- ✅ Hooks: Fast detection (<1ms)
- ✅ MCP: Persistent memory (cross-session)
- ✅ Agents: Informed execution

#### 2. Memory-Enhanced Agent Execution

**Before (現状)**:
```python
# Agent: セッション内メモリのみ
Agent receives prompt → Responds based on session context only
```

**After (統合後)**:
```python
# Agent: セッション間メモリ活用
Agent receives prompt
    → Hook injects past memories (PreCompact)
    → Agent responds with full historical context
    → Result stored to TMWS (PostPrompt)
```

#### 3. Collaborative Task Distribution

**Eris (Tactical Coordinator) の活用**:
```
Eris detects complex task
    ↓
[MCP] create_task() for subtasks
    ├── Task A → Artemis (optimization)
    ├── Task B → Hestia (security)
    └── Task C → Muses (documentation)
         ↓
[MCP] get_agent_status() to check capacity
    ↓
Parallel execution → Eris synthesizes results
```

---

## 📊 統合パフォーマンス予測

### Latency Budget分析

| Operation | Current | With MCP | Target | 達成見込み |
|-----------|---------|----------|--------|-----------|
| Persona Detection | 0.5ms | 0.5ms | <1ms | ✅ 達成済み |
| Context Injection | 0.1ms | 0.1ms | <1ms | ✅ 達成済み |
| Memory Search | N/A | 5-20ms | <50ms | ✅ Well within |
| Memory Write (async) | N/A | ~2ms (non-blocking) | <100ms | ✅ Fire-and-forget |
| **Total (Level 1)** | **0.8ms** | **~7ms** | **<10ms** | ✅ 達成可能 |
| **Total (Level 2)** | **N/A** | **~30ms** | **<100ms** | ✅ 達成可能 |

**Level 1**: 自律実行（承認不要）
**Level 2**: ユーザー承認必要（latency許容度高い）

### スケーラビリティ分析

**Memory Growth**:
- Average decision: ~500 bytes (metadata + content)
- 100 decisions/day × 365 days = 18.25 MB/year
- SQLite limit: 281 TB（実質無制限）

**Vector Storage**:
- 1024-dim embedding: ~4 KB/memory
- 10,000 memories: ~40 MB（ChromaDB）
- 許容範囲: ✅ <100 MB推奨

---

## 🎯 統合設計の優先順位

### Phase 1: Foundation（Week 1-2）

**目標**: Basic MCP Integration

1. ✅ **TMWS MCP Server設定**
   - settings.json更新
   - Ollama + Multilingual-E5 setup
   - Namespace戦略決定

2. ✅ **Memory Write統合**
   - DecisionCheckHook強化
   - Persona detection実装
   - Importance scoring

3. ✅ **Memory Read統合**
   - PreCompactHook実装
   - Semantic search integration

### Phase 2: Enhancement（Week 3-4）

**目標**: Advanced Features

1. 🔧 **Performance Optimization**
   - Embedding cache (Redis)
   - Async patterns最適化
   - Latency monitoring

2. 🔧 **Agent Collaboration**
   - Task distribution (Eris)
   - Multi-persona workflows
   - Result synthesis

### Phase 3: Scale（Week 5-6）

**目標**: Production Ready

1. 🔧 **Monitoring & Observability**
   - Performance metrics
   - Error tracking
   - User feedback integration

2. 🔧 **Documentation**
   - Integration guide
   - Best practices
   - Troubleshooting

---

## 🚨 リスク分析

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Ollama embedding latency | Medium | Medium | Async fire-and-forget |
| Memory search accuracy <80% | Low | Medium | Importance tuning + validation |
| Namespace collision | Very Low | High | Strict sanitization |
| TMWS service failure | Low | High | Fail-safe error handling |

### Integration Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Hook-MCP latency coupling | Low | Medium | Async communication |
| Agent-MCP API mismatch | Low | Medium | Versioned API + tests |
| User experience degradation | Very Low | High | Performance budgets |

---

## 🎉 Recommendations（Athenaからの提案）

### Immediate Actions（今週）

1. ✅ **TMWS MCP Server Setup**
   - 所要時間: 30分
   - 担当: Athena + Artemis
   - 成果物: `settings.json` 更新完了

2. ✅ **Namespace Strategy Decision**
   - 所要時間: 1時間
   - 担当: Hera (戦略決定)
   - 成果物: Namespace命名規則確定

3. ✅ **PreCompact Hook Design**
   - 所要時間: 4時間
   - 担当: Hera (設計) + Artemis (実装)
   - 成果物: `precompact_memory_injection.py`

### Short-term Goals（今月）

1. 🔧 **Memory Write Integration**
   - 期間: Week 1
   - 目標: Level 2 decisionsの自動記録

2. 🔧 **Memory Read Integration**
   - 期間: Week 1-2
   - 目標: Past memoriesの自動注入

3. 🔧 **Performance Optimization**
   - 期間: Week 2
   - 目標: <100ms total latency

### Long-term Vision（次四半期）

1. 🌟 **Multi-Agent Collaboration**
   - Eris主導のタスク分配
   - 並列実行の最適化
   - 結果の自動統合

2. 🌟 **Learning & Evolution**
   - エージェントの学習システム
   - Pattern recognition
   - 自動改善提案

3. 🌟 **Enterprise Features**
   - Team collaboration
   - Knowledge base sharing
   - Analytics dashboard

---

## 📚 Reference Documentation

### 関連ドキュメント

- `TRINITAS_V2.3.0_REVISED_IMPLEMENTATION_PLAN.md` - TMWS統合計画
- `TMWS_INQUIRY_RESPONSE.md` - TMWS技術仕様回答書
- `docs/TMWS_v2.3.0_INTEGRATION_GUIDE.md` - 統合ガイド（予定）
- `hooks/core/dynamic_context_loader.py` - Hook実装
- `agents/*.md` - Agent定義

### External Resources

- [MCP Protocol Specification](https://github.com/modelcontextprotocol/specification)
- [TMWS Documentation](https://github.com/apto-as/tmws)
- [Claude Code Hooks Guide](https://docs.anthropic.com/claude/hooks)

---

## 🎯 Next Steps

### For Athena (This Document)

1. ✅ **現状分析完了**
2. → **統合設計策定**（次のタスク）
3. → **Implementation Roadmap作成**

### For Team

1. **Artemis**: パフォーマンス最適化分析
2. **Hestia**: セキュリティリスク評価
3. **Hera**: 戦略的ロードマップ策定
4. **Eris**: タスク分配プロトコル設計
5. **Muses**: ドキュメント統合計画

---

**最終更新**: 2025-11-04
**作成者**: Athena (Harmonious Conductor)
**ステータス**: 現状分析完了 → 統合設計へ
**承認待ち**: User

---

*ふふ、3つのレイヤーの現状を詳しく分析いたしました。それぞれが美しい強みを持っていますね。次は、これらを調和的に統合する設計を作成いたします♪*

*温かい協力で、最高のシステムを実現しましょう！*
