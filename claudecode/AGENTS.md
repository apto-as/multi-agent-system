# TRINITAS Agent Coordination Protocol v2.4.8
## Phase-Based Execution & Multi-Agent Collaboration

---
protocol_version: "2.4.11"
compatible_with: ["claude-code", "opencode"]
tmws_version: "v2.4.8"
agent_count: 9
last_updated: "2025-12-03"
---

## ⚠️ MANDATORY: SubAgent Execution Rules

**CRITICAL**: This document defines coordination protocols, but actual SubAgent invocation
MUST follow the mandatory rules in:
→ **@SUBAGENT_EXECUTION_RULES.md**

When Trinitas Full Mode is triggered, SubAgents MUST be invoked via Task tool.
Declaring Full Mode without Task tool invocation is a **PROTOCOL VIOLATION**.

---

## Overview

このドキュメントは9つのTrinitasエージェント間の協調プロトコルを定義します。
フェーズベースの実行モデルと承認ゲートにより、高品質かつ安全なタスク完了を保証します。

---

## Agent Hierarchy (エージェント階層)

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

## Phase-Based Execution Protocol

### Core Principles (核心原則)

1. **Sequential Phases**: フェーズは順番に実行される
2. **Approval Gates**: 各フェーズ終了時に承認が必要
3. **No Cross-Phase Parallelism**: 異なるフェーズを並列実行しない
4. **Intra-Phase Parallelism**: 同一フェーズ内では並列実行可能

### Standard 4-Phase Model

```
┌─────────────────────────────────────────────────────────┐
│ Phase 1: Strategic Planning (戦略立案)                    │
│ ├─ Hera: 戦略設計・アーキテクチャ定義                       │
│ ├─ Athena: リソース配分・調和確保                          │
│ └─ Aurora: 関連コンテキスト検索 (並列)                      │
│                                                         │
│ → Approval Gate 1: 戦略合意 (Hera + Athena 両者承認)       │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Phase 2: Implementation (実装)                           │
│ ├─ Artemis: 技術実装リード                                │
│ ├─ Metis: 補助実装・テスト作成 (並列)                       │
│ └─ Aphrodite: UI/UXガイド提供 (必要時)                     │
│                                                         │
│ → Approval Gate 2: 実装完了 (テスト通過 + 回帰なし)         │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Phase 3: Verification (検証)                             │
│ ├─ Hestia: セキュリティ監査                                │
│ ├─ Artemis: パフォーマンス検証 (並列)                       │
│ └─ Aurora: 変更影響の検証                                  │
│                                                         │
│ → Approval Gate 3: セキュリティ承認 (Hestia 最終判断)       │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Phase 4: Documentation (文書化)                          │
│ ├─ Muses: ドキュメント作成                                 │
│ └─ Aphrodite: ビジュアルガイド (必要時)                     │
│                                                         │
│ → Final Gate: 完了確認 (Athena 総括)                      │
└─────────────────────────────────────────────────────────┘
```

---

## Execution Rules (実行ルール)

### ALLOWED (許可)

- ✅ **同一フェーズ内の並列実行**
  - 例: Phase 1 で Hera + Athena + Aurora が同時に作業
  - 例: Phase 2 で Artemis + Metis が同時に実装

- ✅ **順次フェーズ進行**
  - Phase 1 完了 → Gate 1 承認 → Phase 2 開始
  - 明示的な承認後にのみ次フェーズへ

- ✅ **フェーズ内でのコンサルテーション**
  - Artemis が実装中に Hestia にセキュリティ確認
  - 同一フェーズ内なら他エージェントへの相談可

### PROHIBITED (禁止)

- ❌ **フェーズを跨いだ並列実行**
  - 例: Athena が計画中に Artemis が実装開始
  - 例: Hestia が監査前に Muses がドキュメント作成

- ❌ **承認ゲートのスキップ**
  - 各フェーズの Gate は必須
  - 暗黙の承認は認められない

- ❌ **戦略合意前の実装開始**
  - Phase 1 の合意なしに Phase 2 は開始不可

- ❌ **検証完了前の文書化**
  - Phase 3 の Hestia 承認なしに Phase 4 は開始不可

---

## Conflict Resolution (競合解決)

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

### Design Conflicts (Aphrodite vs Artemis)

```
判断基準:
┌──────────────────────┬────────────────────┐
│ 条件                 │ 解決策            │
├──────────────────────┼────────────────────┤
│ UX が技術的に困難    │ 代替デザイン提案    │
│ パフォーマンス影響大  │ 簡略化デザイン      │
│ 両立可能            │ 最適バランス実装    │
└──────────────────────┴────────────────────┘
```

---

## Agent Fallback Chain (フォールバック)

エージェント障害時の代替順序:

```
Athena  → Eris → Hera
Hera    → Athena → Eris
Artemis → Metis → Hera
Hestia  → Artemis → Athena
Eris    → Athena → Hera
Muses   → Aurora → Athena
Aphrodite → Athena → Muses
Metis   → Artemis → Aurora
Aurora  → Muses → Athena
```

---

## Task Handoff Protocol (タスク引継ぎ)

### Standard Format

```yaml
handoff:
  from: [送信エージェント]
  to: [受信エージェント]
  task: [タスク説明]
  context:
    background: [背景情報]
    dependencies: [依存関係]
    constraints: [制約条件]
  artifacts:
    - type: code/doc/test
      path: [ファイルパス]
      status: complete/partial
  priority: critical/high/medium/low
  deadline: [期限 (あれば)]
```

---

## TMWS Integration Points

### Memory Operations

各エージェントはTMWSを通じて以下を実行可能:

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
├─ Eris: 緊急調整・即時アセスメント
├─ Artemis + Metis: 並列修正 (即時開始)
├─ Hestia: 即時セキュリティ確認
└─ Muses: 事後ドキュメント
→ 通常の4フェーズを2フェーズに圧縮
```

### Security Breach Response

```
Incident Response:
1. Hestia: 封じ込め・影響評価
2. Eris: インシデント対応調整
3. Artemis: 緊急パッチ適用
4. Muses: 監査証跡保全
5. Hera: エグゼクティブ報告
```

---

## Version History

- **v2.5.0** (2025-12-01): 9エージェント対応、TMWS v2.4.8統合
- **v2.2.0**: Phase-Based Protocol確立
- **v2.0.0**: Core 6 Agent Protocol

---

*Trinitas Agent Coordination Protocol v2.5.0*
*9 Agents - Phase-Based Execution - TMWS Integration*
