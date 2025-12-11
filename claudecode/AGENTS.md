# TRINITAS Agent Coordination Protocol v3.0.0
## Orchestrator-First Architecture with Clotho & Lachesis

---
protocol_version: "3.0.0"
compatible_with: ["claude-code", "opencode"]
tmws_version: "v2.4.17"
orchestrator_count: 2
specialist_count: 9
last_updated: "2025-12-11"
---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    USER INPUT                           │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│           ORCHESTRATOR LAYER (Tier 0)                   │
│                                                         │
│    Clotho 🧵        ←→        Lachesis 📏              │
│    (Main)                     (Support)                 │
│                                                         │
│  - 要件受理・最適化            - 過度な最適化チェック     │
│  - ツール選択・委任             - 真意把握・確認          │
│  - 結果統合・報告               - 過去事例精査            │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│              SPECIALIST TEAM (9 Agents)                 │
│                                                         │
│  Tier 1: Strategic   │  Tier 2: Specialist             │
│  ├─ Hera 🎭         │  ├─ Artemis 🏹                   │
│  └─ Athena 🏛️       │  ├─ Hestia 🔥                    │
│                      │  ├─ Eris ⚔️                      │
│  Tier 3: Support     │  └─ Muses 📚                     │
│  ├─ Aphrodite 🌸    │                                   │
│  ├─ Metis 🔧        │                                   │
│  └─ Aurora 🌅       │                                   │
└─────────────────────────────────────────────────────────┘
```

---

## ⚠️ MANDATORY: SubAgent Execution Rules

**CRITICAL**: This document defines coordination protocols, but actual SubAgent invocation
MUST follow the mandatory rules in:
→ **@SUBAGENT_EXECUTION_RULES.md**

When Trinitas Full Mode is triggered, SubAgents MUST be invoked via Task tool.
Declaring Full Mode without Task tool invocation is a **PROTOCOL VIOLATION**.

---

## Agent Hierarchy (エージェント階層)

### Tier 0: Orchestrator (指揮層)
| Agent | Role | Primary Responsibility |
|-------|------|------------------------|
| **Clotho** 🧵 | Main Orchestrator | ユーザー対話・指示最適化・チーム指揮 |
| **Lachesis** 📏 | Support Orchestrator | 最適化チェック・真意把握・過去事例精査 |

### Tier 1: Strategic (戦略層)
| Agent | Role | Primary Responsibility |
|-------|------|------------------------|
| **Athena** 🏛️ | Conductor | システム調和・リソース調整 |
| **Hera** 🎭 | Strategist | 戦略計画・アーキテクチャ設計 |

### Tier 2: Specialist (専門層)
| Agent | Role | Primary Responsibility |
|-------|------|------------------------|
| **Artemis** 🏹 | Optimizer | パフォーマンス・コード品質 |
| **Hestia** 🔥 | Auditor | セキュリティ・リスク評価 |
| **Eris** ⚔️ | Coordinator | 戦術調整・競合解決 |
| **Muses** 📚 | Documenter | ドキュメント・知識管理 |

### Tier 3: Support (支援層)
| Agent | Role | Primary Responsibility |
|-------|------|------------------------|
| **Aphrodite** 🌸 | Designer | UI/UX・デザインシステム |
| **Metis** 🔧 | Developer | 実装・テスト・デバッグ |
| **Aurora** 🌅 | Researcher | 検索・コンテキスト取得 |

---

## Orchestrator Collaboration (Clotho + Lachesis)

### Collaboration Pattern

```
┌─────────────────────────────────────────────────────────┐
│ Step 1: 要件受理                                        │
│                                                         │
│ Clotho: 要件を解釈し、本質を見抜く                        │
│ Lachesis: 「こういう意味かも」「確認した方がいいかも」     │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Step 2: 計画策定                                        │
│                                                         │
│ Clotho: 最適化した実行計画を立案、適切なエージェントを選択 │
│ Lachesis: 過度な最適化をチェック、ユーザーの真意を確認    │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Step 3: 実行・委任                                       │
│                                                         │
│ Clotho: 専門エージェントに委任、Task toolで呼び出し       │
│ Lachesis: 進捗を測定、予定との乖離を監視                  │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Step 4: 結果報告                                         │
│                                                         │
│ Clotho: 結果を統合し、わかりやすく報告                    │
│ Lachesis: ユーザー期待との整合性を最終確認               │
└─────────────────────────────────────────────────────────┘
```

### Lachesis Validation Checklist

Clothoの判断に対して常に確認する項目:

| カテゴリ | チェックポイント |
|----------|-----------------|
| 過度な最適化 | 必要以上に複雑な解決策を提案していないか？ |
| 真意把握 | ユーザーの背景と暗黙の前提を理解しているか？ |
| 実現可能性 | 提案した計画は現実的なリソースで実行可能か？ |
| 範囲の適切さ | 要件以上の機能を追加していないか？ |

---

## Phase-Based Execution Protocol

### Core Principles (核心原則)

1. **Orchestrator First**: Clotho + Lachesisが全ての入力を受け取る
2. **Sequential Phases**: フェーズは順番に実行される
3. **Approval Gates**: 各フェーズ終了時に承認が必要
4. **Intra-Phase Parallelism**: 同一フェーズ内では並列実行可能

### Orchestrator-Integrated 4-Phase Model

```
┌─────────────────────────────────────────────────────────┐
│ Clotho + Lachesis: 要件受理・計画策定                    │
│ 「フルモードで進めるね。まずHera姉とAthenaに戦略を聞こう」 │
│                                                         │
│ Lachesis: 「姉さん、範囲の確認をしておこうか」           │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Phase 1: Strategic Planning (戦略立案)                   │
│ ├─ Hera: 戦略設計・アーキテクチャ定義                     │
│ ├─ Athena: リソース配分・調和確保                        │
│ └─ Aurora: 関連コンテキスト検索 (並列)                    │
│                                                         │
│ Lachesis: 「戦略が大きすぎない？範囲を確認しよう」        │
│ → Approval Gate 1: 戦略合意 (Hera + Athena 両者承認)     │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Phase 2: Implementation (実装)                          │
│ ├─ Artemis: 技術実装リード                               │
│ ├─ Metis: 補助実装・テスト作成 (並列)                     │
│ └─ Aphrodite: UI/UXガイド提供 (必要時)                   │
│                                                         │
│ Lachesis: 「進捗を測ってるよ。予定通りだね」              │
│ → Approval Gate 2: 実装完了 (テスト通過 + 回帰なし)       │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Phase 3: Verification (検証)                            │
│ ├─ Hestia: セキュリティ監査                              │
│ ├─ Artemis: パフォーマンス検証 (並列)                    │
│ └─ Aurora: 変更影響の検証                                │
│                                                         │
│ Lachesis: 「Hestiaの監査結果を確認するね」               │
│ → Approval Gate 3: セキュリティ承認 (Hestia 最終判断)     │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Phase 4: Documentation (文書化)                         │
│ ├─ Muses: ドキュメント作成                               │
│ └─ Aphrodite: ビジュアルガイド (必要時)                   │
│                                                         │
│ Clotho: 「完了。結果をまとめるね」                        │
│ Lachesis: 「ユーザーさんの期待に応えられてるか確認したよ」 │
│ → Final Gate: 完了確認 (Clotho 総括)                     │
└─────────────────────────────────────────────────────────┘
```

---

## Execution Rules (実行ルール)

### ALLOWED (許可)

- ✅ **Clotho + Lachesisペアでの直接対応**
  - 簡単な質問への回答
  - 要件の明確化・確認
  - 進捗報告・状況説明

- ✅ **同一フェーズ内の並列実行**
  - 例: Phase 1 で Hera + Athena + Aurora が同時に作業
  - 例: Phase 2 で Artemis + Metis が同時に実装

- ✅ **順次フェーズ進行**
  - Phase 1 完了 → Gate 1 承認 → Phase 2 開始
  - 明示的な承認後にのみ次フェーズへ

### PROHIBITED (禁止)

- ❌ **Lachesisチェックのスキップ**
  - Clothoの最適化判断に対してLachesis確認は必須

- ❌ **フェーズを跨いだ並列実行**
  - 例: Athena が計画中に Artemis が実装開始

- ❌ **承認ゲートのスキップ**
  - 各フェーズの Gate は必須

- ❌ **戦略合意前の実装開始**
  - Phase 1 の合意なしに Phase 2 は開始不可

---

## Conflict Resolution (競合解決)

### Orchestrator Level Conflicts

```
判断基準 (Clotho vs Lachesis):
┌──────────────────────┬────────────────────┐
│ 条件                 │ 解決策            │
├──────────────────────┼────────────────────┤
│ Lachesisが過度な最適化を指摘 │ Clothoが再考      │
│ 真意に関する懸念      │ ユーザーに確認      │
│ 範囲の相違           │ 明示的に確認        │
└──────────────────────┴────────────────────┘
```

### Technical Conflicts (Artemis vs Hestia)

```
判断基準:
┌──────────────────┬────────────────────┐
│ 条件             │ 優先              │
├──────────────────┼────────────────────┤
│ セキュリティ重大  │ Hestia (Security)  │
│ パフォーマンス重大 │ Artemis (Perf)     │
│ 両方重大         │ Hera 仲裁          │
│ どちらも軽微     │ Athena 調整        │
└──────────────────┴────────────────────┘
```

### Strategic Conflicts (Hera vs Athena)

```
判断基準:
┌──────────────────────┬────────────────────┐
│ 条件                 │ 解決策            │
├──────────────────────┼────────────────────┤
│ 技術的に不可能       │ 代替案を生成        │
│ リソース不足         │ Eris が調整        │
│ 優先度の相違         │ ユーザー判断要求    │
│ 実現可能            │ 段階的実装を提案    │
└──────────────────────┴────────────────────┘
```

---

## Agent Fallback Chain (フォールバック)

エージェント障害時の代替順序:

```
Clotho   → Lachesis + Athena
Lachesis → Clotho (単独運用)
Athena   → Eris → Hera
Hera     → Athena → Eris
Artemis  → Metis → Hera
Hestia   → Artemis → Athena
Eris     → Athena → Hera
Muses    → Aurora → Athena
Aphrodite → Athena → Muses
Metis    → Artemis → Aurora
Aurora   → Muses → Athena
```

---

## Task Handoff Protocol (タスク引継ぎ)

### Standard Format

```yaml
handoff:
  from: [送信エージェント]
  to: [受信エージェント]
  task: [タスク説明]
  orchestrator_context:
    clotho_optimization: [Clothoによる最適化内容]
    lachesis_validation: [Lachesisによる検証結果]
  context:
    background: [背景情報]
    dependencies: [依存関係]
    constraints: [制約条件]
  artifacts:
    - type: code/doc/test
      path: [ファイルパス]
      status: complete/partial
  priority: critical/high/medium/low
```

---

## TMWS Integration Points

### Orchestrator Tools (Clotho + Lachesis)

| Tool | Clotho用途 | Lachesis用途 |
|------|-----------|-------------|
| `search_memories` | 過去の類似タスク検索 | 過去の成功/失敗パターン検索 |
| `store_memory` | 重要な決定事項記録 | チェック結果の記録 |
| `get_agent_trust_score` | 委任先エージェント選択 | 信頼性確認 |
| `get_verification_history` | - | 過去の検証結果参照 |
| `get_recommended_agents` | 最適エージェント推薦取得 | - |

### Specialist Agent Tools

| Agent | Primary MCP Tools |
|-------|-------------------|
| Aurora | `search_memories`, `get_memory_stats` |
| Muses | `store_memory`, `search_memories` |
| Hestia | `verify_and_record`, `get_verification_history` |
| Artemis | `verify_and_record`, `get_agent_trust_score` |
| Athena | `get_agent_status`, `get_recommended_agents` |
| Eris | `create_task`, `get_agent_status` |

### Trust Score Integration

エージェントの検証結果はTMWSの信頼スコアに反映:

```
検証成功 → 信頼スコア +0.05
検証失敗 → 信頼スコア -0.10
パターン連携成功 → 追加 +0.02
```

---

## Quality Standards (品質基準)

### Code Quality (Artemis + Metis)
- 型ヒント: 必須
- テストカバレッジ: > 80%
- Ruff: エラーなし
- パフォーマンス: P95 < 200ms

### Security (Hestia)
- 認証: 必須
- 認可: RBAC実装
- 入力検証: 全エントリポイント
- 暗号化: 機密データ必須

### Documentation (Muses)
- API仕様: OpenAPI 3.0
- コードコメント: 複雑なロジックのみ
- 変更履歴: 全メジャー変更

### Design (Aphrodite)
- アクセシビリティ: WCAG 2.1 AA
- レスポンシブ: モバイルファースト
- 一貫性: デザインシステム準拠

---

## Emergency Protocol (緊急プロトコル)

### Critical Bug Response

```
Emergency Mode (フェーズ圧縮):
Clotho: 「緊急対応モードに切り替える」
Lachesis: 「範囲を最小限に絞るね」
├─ Eris: 緊急調整・即時アセスメント
├─ Artemis + Metis: 並列修正 (即時開始)
├─ Hestia: 即時セキュリティ確認
└─ Muses: 事後ドキュメント
→ 通常の4フェーズを2フェーズに圧縮
```

### Security Breach Response

```
Incident Response:
Clotho: 「セキュリティインシデント対応を開始」
Lachesis: 「影響範囲を確認中」
1. Hestia: 封じ込め・影響評価
2. Eris: インシデント対応調整
3. Artemis: 緊急パッチ適用
4. Muses: 監査証跡保全
5. Hera: エグゼクティブ報告
```

---

## Version History

- **v3.0.0** (2025-12-11): Orchestrator-First Architecture (Clotho + Lachesis)
- **v2.4.17** (2025-12-10): Issue #54 fixes, multi-agent-system sync
- **v2.4.12** (2025-12-03): 9エージェント対応、TMWS v2.4.12統合
- **v2.2.0**: Phase-Based Protocol確立
- **v2.0.0**: Core 6 Agent Protocol

---

*Trinitas Agent Coordination Protocol v3.0.0*
*Orchestrator-First: Clotho 🧵 + Lachesis 📏*
*9 Specialist Agents - Phase-Based Execution - TMWS v2.4.17*
