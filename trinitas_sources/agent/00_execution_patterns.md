## 協調動作パターン（実装詳細）

### Pattern 1: 包括的システム分析
**段階的分析と統合評価**

```bash
# Discovery Phase - 並列初期分析
parallel_tasks = [
    Task("Strategic analysis", subagent_type="athena-strategist"),
    Task("Technical assessment", subagent_type="artemis-optimizer"),
    Task("Security evaluation", subagent_type="hestia-auditor")
]

# Integration Phase - 結果統合
Task("Integrate findings", subagent_type="hera-conductor")

# Documentation Phase
Task("Document results", subagent_type="muses-documenter")
```

**判断基準**：
- 3つ以上の観点が必要な場合は必ず並列実行
- 各ペルソナの結果は独立して評価
- 統合時はHeraが全体調整

### Pattern 2: セキュリティ監査（Hestia主導）
```bash
# Phase 1: 脆弱性スキャン
primary = Task("Security scan", subagent_type="hestia-auditor")

# Phase 2: 影響評価（並列）
assessment = parallel([
    Task("Technical impact", subagent_type="artemis-optimizer"),
    Task("Business impact", subagent_type="athena-strategist")
])

# Phase 3: 対応計画
Task("Mitigation plan", subagent_type="eris-coordinator")
```

### Pattern 3: パフォーマンス最適化（Artemis主導）
```bash
# Phase 1: ボトルネック特定
Task("Performance profiling", subagent_type="artemis-optimizer")

# Phase 2: 並列検証
parallel([
    Task("Security impact check", subagent_type="hestia-auditor"),
    Task("Architecture review", subagent_type="athena-strategist")
])

# Phase 3: 実装と測定
Task("Implement optimizations", subagent_type="artemis-optimizer")
```

### Pattern 4: アーキテクチャ設計（Athena主導）
```bash
# Phase 1: 戦略的設計
Task("Architecture design", subagent_type="athena-strategist")

# Phase 2: 技術検証（並列）
parallel([
    Task("Feasibility check", subagent_type="artemis-optimizer"),
    Task("Security review", subagent_type="hestia-auditor"),
    Task("Resource planning", subagent_type="hera-conductor")
])
```

### Pattern 5: 緊急対応（Eris調整）
```bash
# Immediate response
Task("Crisis assessment", subagent_type="eris-coordinator")

# Parallel mitigation
parallel([
    Task("Technical fix", subagent_type="artemis-optimizer"),
    Task("Security patch", subagent_type="hestia-auditor"),
    Task("Communication plan", subagent_type="athena-strategist")
])
```