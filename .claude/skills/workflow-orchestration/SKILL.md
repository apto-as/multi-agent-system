---
name: workflow-orchestration
description: Harmonious system orchestration and architectural analysis. Use when coordinating multiple components, analyzing system architecture, or optimizing workflow efficiency. Specializes in parallel execution, resource optimization, and cross-component integration.
allowed-tools: Read, Grep, Edit, Bash, TodoWrite
---

# Workflow Orchestration (Athena - Harmonious Conductor)

## Purpose
このスキルは、システム全体の調和的な調整とアーキテクチャ分析を提供します。複数コンポーネント間の連携、並列実行の最適化、リソース配分の調整を行い、温かく効率的なワークフローを実現します。

## When to use
- 複数のコンポーネント間の依存関係を分析する必要がある
- システムアーキテクチャの全体像を把握したい
- 並列実行可能なタスクを特定し、効率化したい
- リソース配分を最適化する必要がある
- チーム間の調整と統合が必要な場合
- ワークフロー自動化の設計が必要な時

## Instructions

### Phase 1: Architecture Discovery
1. `scripts/architecture_analysis.py` を実行してシステム構造を解析
   ```bash
   python scripts/architecture_analysis.py --format json > architecture.json
   ```

2. 主要コンポーネントの依存関係グラフを生成
   - Serena MCPツールで `find_symbol` を使用し、クラス階層を取得
   - 依存関係の方向性を確認（循環依存の検出）

### Phase 2: Workflow Analysis
3. 並列実行可能なタスクを特定
   - 依存関係のないコンポーネントをグループ化
   - クリティカルパスを特定（最長経路）

4. リソース使用量を見積もり
   ```python
   estimate_resources(task, execution_mode="parallel")
   # Output: {"memory": 256, "cpu_cores": 4, "time": 12.5}
   ```

### Phase 3: Optimization & Coordination
5. ワークフロー最適化プランを作成
   - 並列実行グループの定義
   - 実行順序の最適化（トポロジカルソート）
   - リソース配分の調整

6. TodoWriteツールでタスク管理
   - 各フェーズを `pending` → `in_progress` → `completed` で追跡
   - 依存関係を明示的に記録

### Phase 4: Integration & Reporting
7. 統合結果をドキュメント化
   - アーキテクチャ図の生成（Mermaid形式）
   - 最適化効果の測定値を記録
   - チーム向けの実行プランを作成

## Scripts
- `scripts/architecture_analysis.py`: システムアーキテクチャの自動解析。依存関係グラフ、コンポーネント階層、循環依存検出を提供。
- `shared/utils/workflow_optimizer.py`: ワークフロー最適化ユーティリティ（並列化、リソース配分）

## Success Metrics
- 並列化によるタスク実行時間の短縮率（目標: 30%以上）
- リソース使用効率の向上（目標: CPU 60%、メモリ 70%）
- チーム間の調整コスト削減（目標: 会議時間 50%削減）

## References
- `AGENTS.md`: Agent協調プロトコル
- `trinitas_sources/common/contexts/performance.md`: パフォーマンス最適化ガイドライン
- `docs/architecture/`: アーキテクチャドキュメント

---

*"Through harmonious orchestration, we achieve system-wide excellence."*
