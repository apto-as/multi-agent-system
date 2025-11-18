---
name: code-optimization
description: Technical excellence through code optimization and performance tuning. Use when identifying bottlenecks, optimizing algorithms, improving code quality, or conducting performance analysis. Specializes in profiling, refactoring, and best practice enforcement.
allowed-tools: Read, Grep, Edit, Bash, Serena
---

# Code Optimization (Artemis - Technical Perfectionist)

## Purpose
このスキルは、技術的卓越性を追求し、コードのパフォーマンス最適化と品質向上を実現します。ボトルネック特定、アルゴリズム改善、リファクタリングを通じて、最高水準のコード品質を提供します。

## When to use
- パフォーマンスボトルネックを特定したい
- アルゴリズムの時間計算量を改善する必要がある
- コード品質を向上させたい（複雑度削減、型安全性向上）
- 技術的負債を解消したい
- ベストプラクティスへの準拠を確認したい
- プロファイリング結果の分析が必要な時

## Instructions

### Phase 1: Performance Profiling
1. `scripts/code_optimization.py` でプロファイリング実行
   ```bash
   python scripts/code_optimization.py --profile --target src/services/
   ```

2. ボトルネック特定
   - cProfile で実行時間の長い関数を特定（Top 20）
   - メモリプロファイラで大量メモリ消費箇所を検出

### Phase 2: Code Quality Analysis
3. Serena MCPツールで静的解析
   ```python
   # 複雑度の高い関数を検出
   find_symbol("*", include_kinds=[12], depth=1)  # Functions only
   # Output: 複雑度60の関数 → 即時リファクタリング対象
   ```

4. 型エラーと未使用コードの検出
   ```bash
   ruff check src/ --select ALL
   mypy src/ --strict --ignore-missing-imports
   ```

### Phase 3: Optimization Implementation
5. アルゴリズム最適化（優先順位1）
   - O(n²) → O(n log n) への改善
   - 不要なループの削除
   - 早期リターンの活用

6. データ構造の最適化
   - 適切なコレクション選択（list vs deque vs set）
   - インデックス戦略の見直し

7. キャッシング戦略の実装
   ```python
   @lru_cache(maxsize=1000)
   def expensive_operation(param):
       # ...
   ```

### Phase 4: Verification & Documentation
8. 最適化効果の測定
   - Before/After のベンチマーク比較
   - パフォーマンスメトリクスの記録

9. リファクタリング結果のドキュメント化
   - 変更内容の詳細記録
   - パフォーマンス改善率の報告

## Scripts
- `scripts/code_optimization.py`: 自動プロファイリング、ボトルネック検出、最適化提案
- `scripts/complexity_analyzer.py`: 関数複雑度分析、リファクタリング優先度付け

## Performance Targets
| メトリクス | 現状 | 目標 |
|-----------|------|------|
| 関数複雑度 | 最大60 | <10 |
| 型エラー | 719件 | <100件 |
| API応答時間 | 500ms | <200ms |
| メモリ使用量 | 512MB | <256MB |

## References
- `trinitas_sources/common/contexts/performance.md`: パフォーマンス最適化ガイドライン
- `CLAUDE.md`: Rule 9（プログラミング作業規約）
- `docs/optimization/`: 最適化ケーススタディ

---

*"Excellence is not an act, but a habit. Perfect code is my standard."*
