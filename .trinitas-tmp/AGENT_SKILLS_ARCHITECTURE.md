# Agent Skills Architecture Plan
## Trinitas System - Comprehensive Skill Design

---
**Version**: 1.0.0
**Created**: 2025-11-09
**Status**: Design Document
**Purpose**: Define Agent Skills for 6 Trinitas personas
---

## Executive Summary

このドキュメントでは、6つのTrinitasペルソナ（Athena, Artemis, Hestia, Eris, Hera, Muses）のAgent Skillsを設計します。各ペルソナの専門性を活かしつつ、重複を避け、相互連携を促進する包括的なスキルアーキテクチャを提案します。

## 1. Skill Directory Structure

### 全体構造 (Claude Code版)
```
.claude/skills/
├── athena/
│   ├── SKILL.md                      # メインスキル定義
│   ├── workflow_orchestration.py    # ワークフロー自動化
│   ├── resource_optimization.py     # リソース最適化
│   └── parallel_execution.py        # 並列実行調整
│
├── artemis/
│   ├── SKILL.md
│   ├── code_optimization.py         # 既存: コード最適化
│   ├── algorithm_analysis.py        # アルゴリズム分析
│   └── performance_profiling.py     # パフォーマンスプロファイリング
│
├── hestia/
│   ├── SKILL.md
│   ├── security_audit.py            # セキュリティ監査
│   ├── vulnerability_scanner.py     # 脆弱性スキャン
│   └── threat_modeling.py           # 脅威モデリング
│
├── eris/
│   ├── SKILL.md
│   ├── task_coordination.py         # タスク調整
│   ├── conflict_resolution.py       # 競合解決
│   └── team_balancing.py            # チームバランス調整
│
├── hera/
│   ├── SKILL.md
│   ├── strategic_planning.py        # 戦略計画
│   ├── architecture_design.py       # アーキテクチャ設計
│   └── roadmap_generation.py        # ロードマップ生成
│
└── muses/
    ├── SKILL.md
    ├── documentation_generation.py  # ドキュメント生成
    ├── knowledge_structuring.py     # ナレッジ構造化
    └── api_documentation.py         # API文書化
```

### OpenCode版との互換性
```
~/.config/opencode/skill/
├── athena/
│   ├── SKILL.md                     # 同一構造
│   ├── workflow_orchestration.js   # JavaScript版 (Bun runtime)
│   └── ...
└── ...
```

**互換性ポイント**:
- SKILL.mdフォーマットは完全互換
- Python実装 → JavaScript実装への移行は可能
- OpenCode版は`@opencode-ai/skill` パッケージでラップ

---

## 2. Skill Scopes (重複防止と専門性の明確化)

### 2.1 Athena - Harmonious Conductor 🏛️

**役割**: システム全体の調和的な指揮と調整

**Core Skills**:

#### Skill 1: Workflow Orchestration (ワークフロー自動化)
```yaml
Skill Name: workflow_orchestration
Purpose: 複数ペルソナの並列実行と統合管理
Unique Scope:
  - ペルソナ間のタスク委譲
  - 実行順序の最適化
  - リソース配分の調整
Not In Scope:
  - コード最適化 (Artemis担当)
  - セキュリティ検証 (Hestia担当)
```

**主な機能**:
- Trinitasペルソナの並列実行調整
- 依存関係に基づく実行順序の決定
- 実行結果の統合と整合性確保

#### Skill 2: Resource Optimization (リソース最適化)
```yaml
Skill Name: resource_optimization
Purpose: システムリソースの効率的な配分
Unique Scope:
  - メモリ・CPU使用率の監視
  - タスク優先度に基づくリソース配分
  - 並列度の動的調整
Not In Scope:
  - アルゴリズムレベルの最適化 (Artemis担当)
```

#### Skill 3: Parallel Execution (並列実行調整)
```yaml
Skill Name: parallel_execution
Purpose: 複数タスクの並列実行管理
Unique Scope:
  - Wave実行モードの制御
  - タスク間の依存関係解決
  - エラー時のフォールバック処理
```

**Athena vs Hera の違い**:
- Athena: **実行時**の調整とオーケストレーション（運用レベル）
- Hera: **計画時**の戦略設計とアーキテクチャ（設計レベル）

---

### 2.2 Artemis - Technical Perfectionist 🏹

**役割**: パフォーマンス最適化とコード品質

**Core Skills**:

#### Skill 1: Code Optimization (既存)
```yaml
Skill Name: code_optimization
Purpose: コードの品質とパフォーマンス向上
Unique Scope:
  - ループ・アルゴリズムの最適化
  - リスト内包表記への変換
  - 複雑度削減
Security:
  - CWE-94: Code Injection Prevention
  - AST解析による安全検証
```

#### Skill 2: Algorithm Analysis (アルゴリズム分析)
```yaml
Skill Name: algorithm_analysis
Purpose: アルゴリズムの時間・空間計算量分析
Unique Scope:
  - Big-O記法での複雑度評価
  - ベンチマーク比較
  - データ構造の最適選択提案
Not In Scope:
  - セキュリティ脆弱性の検出 (Hestia担当)
```

#### Skill 3: Performance Profiling (パフォーマンスプロファイリング)
```yaml
Skill Name: performance_profiling
Purpose: 実行時パフォーマンスの測定と分析
Unique Scope:
  - cProfile/line_profilerの実行
  - ボトルネック特定
  - 最適化箇所の優先順位付け
```

**Artemis vs Athena の違い**:
- Artemis: **コードレベル**の最適化（ミクロ）
- Athena: **システムレベル**のリソース配分（マクロ）

---

### 2.3 Hestia - Security Guardian 🔥

**役割**: セキュリティ分析と脆弱性評価

**Core Skills**:

#### Skill 1: Security Audit (セキュリティ監査)
```yaml
Skill Name: security_audit
Purpose: 包括的なセキュリティ監査
Unique Scope:
  - OWASP Top 10チェック
  - 依存関係の脆弱性スキャン (npm audit, pip-audit)
  - セキュリティベストプラクティス検証
Not In Scope:
  - パフォーマンス影響の評価 (Artemis担当)
```

#### Skill 2: Vulnerability Scanner (脆弱性スキャン)
```yaml
Skill Name: vulnerability_scanner
Purpose: コードベース内の脆弱性検出
Unique Scope:
  - CWE (Common Weakness Enumeration) パターン検出
  - Bandit/Semgrep実行
  - SQLインジェクション・XSS検出
Security Checks:
  - CWE-22: Path Traversal
  - CWE-61: Symlink Following
  - CWE-94: Code Injection
  - CWE-79: XSS
  - CWE-89: SQL Injection
```

#### Skill 3: Threat Modeling (脅威モデリング)
```yaml
Skill Name: threat_modeling
Purpose: システムの脅威分析とリスク評価
Unique Scope:
  - STRIDE脅威モデリング
  - Attack Treeの生成
  - リスク優先度付け (Critical/High/Medium/Low)
```

**Hestia vs Artemis の違い**:
- Hestia: **セキュリティリスク**の検出と対策
- Artemis: **技術的品質**の向上（セキュリティ以外）

---

### 2.4 Eris - Tactical Coordinator ⚔️

**役割**: 戦術計画とチーム調整

**Core Skills**:

#### Skill 1: Task Coordination (タスク調整)
```yaml
Skill Name: task_coordination
Purpose: 複数タスクの調整と分配
Unique Scope:
  - タスクの並列・逐次判定
  - 依存関係の解析
  - デッドロック検出と回避
Not In Scope:
  - 長期戦略の立案 (Hera担当)
```

#### Skill 2: Conflict Resolution (競合解決)
```yaml
Skill Name: conflict_resolution
Purpose: ペルソナ間の競合解決
Unique Scope:
  - Artemis (Performance) vs Hestia (Security) の調停
  - 優先順位マトリックスに基づく判断
  - 妥協案の生成
Example Conflicts:
  - パフォーマンス最適化がセキュリティを犠牲にする場合
  - 複数のアーキテクチャ案が競合する場合
```

#### Skill 3: Team Balancing (チームバランス調整)
```yaml
Skill Name: team_balancing
Purpose: ペルソナの負荷分散
Unique Scope:
  - 各ペルソナの負荷状況監視
  - タスクの再割り当て
  - 並列実行のスケジューリング
```

**Eris vs Athena の違い**:
- Eris: **戦術レベル**の調整（短期・具体的）
- Athena: **運用レベル**のオーケストレーション（全体調和）

---

### 2.5 Hera - Strategic Commander 🎭

**役割**: 戦略計画と軍事的精密性でのアーキテクチャ設計

**Core Skills**:

#### Skill 1: Strategic Planning (戦略計画)
```yaml
Skill Name: strategic_planning
Purpose: 長期戦略とロードマップの立案
Unique Scope:
  - 3ヶ月〜1年の計画策定
  - マイルストーンの設定
  - リソース要件の見積もり
Not In Scope:
  - 日常的なタスク調整 (Eris担当)
```

#### Skill 2: Architecture Design (アーキテクチャ設計)
```yaml
Skill Name: architecture_design
Purpose: システムアーキテクチャの設計と評価
Unique Scope:
  - マイクロサービス vs モノリス判定
  - データフロー設計
  - スケーラビリティ評価
Analysis:
  - 既存: architecture_analysis.py (Athena作成)
  - Hera版: より戦略的・長期的な視点を追加
```

#### Skill 3: Roadmap Generation (ロードマップ生成)
```yaml
Skill Name: roadmap_generation
Purpose: 技術ロードマップの作成
Unique Scope:
  - フェーズ分けと優先順位付け
  - 依存関係の可視化
  - リスクと代替案の提示
Output Format:
  - Markdown roadmap
  - Mermaid Gantt chart
```

**Hera vs Athena の違い**:
- Hera: **戦略レベル**の設計（長期・抽象的）
- Athena: **実装レベル**の調整（短期・具体的）

---

### 2.6 Muses - Knowledge Architect 📚

**役割**: ドキュメント作成と構造化

**Core Skills**:

#### Skill 1: Documentation Generation (ドキュメント生成)
```yaml
Skill Name: documentation_generation
Purpose: 包括的なドキュメント自動生成
Unique Scope:
  - README.md生成
  - CHANGELOG.md生成
  - プロジェクト概要文書の作成
Supported Formats:
  - Markdown
  - reStructuredText
  - AsciiDoc
```

#### Skill 2: Knowledge Structuring (ナレッジ構造化)
```yaml
Skill Name: knowledge_structuring
Purpose: ナレッジベースの構造化と整理
Unique Scope:
  - Trinitasメモリシステムとの統合
  - タグ付けと分類
  - 検索インデックスの最適化
Integration:
  - TMWS (Trinitas Memory & Workflow System)
  - ChromaDB vector embeddings
```

#### Skill 3: API Documentation (API文書化)
```yaml
Skill Name: api_documentation
Purpose: API仕様書の自動生成
Unique Scope:
  - OpenAPI/Swagger生成
  - コード例の自動抽出
  - Postmanコレクション生成
Supported Formats:
  - OpenAPI 3.0
  - AsyncAPI (for async APIs)
  - GraphQL schema documentation
```

**Muses vs Hera の違い**:
- Muses: **ドキュメント生成**（知識の記録）
- Hera: **戦略文書作成**（計画の立案）

---

## 3. Inter-Skill Dependencies (スキル間連携パターン)

### Pattern 1: Security-First Development (Hestia → Artemis → Muses)
```python
# Step 1: Hestia - セキュリティ監査
security_result = await hestia.security_audit(project_path)

# Step 2: Artemis - 監査で発見された問題の修正
if security_result["vulnerabilities"]:
    optimized = await artemis.code_optimization(
        vulnerable_code,
        security_constraints=security_result["constraints"]
    )

# Step 3: Muses - セキュリティ修正のドキュメント化
await muses.documentation_generation(
    title="Security Fixes Report",
    content={
        "vulnerabilities": security_result,
        "fixes": optimized
    }
)
```

### Pattern 2: Strategic Architecture Implementation (Hera → Athena → Artemis)
```python
# Step 1: Hera - 戦略的アーキテクチャ設計
architecture = await hera.architecture_design(
    requirements=user_requirements,
    constraints=technical_constraints
)

# Step 2: Athena - 実装フェーズの調整
workflow = await athena.workflow_orchestration(
    architecture=architecture,
    available_resources=resources
)

# Step 3: Artemis - 各コンポーネントの最適化実装
for component in workflow["components"]:
    await artemis.code_optimization(component)
```

### Pattern 3: Conflict-Driven Optimization (Artemis ↔ Hestia → Eris)
```python
# Step 1: Artemis - パフォーマンス最適化提案
perf_proposal = await artemis.performance_profiling(code)

# Step 2: Hestia - セキュリティ影響評価
security_impact = await hestia.vulnerability_scanner(
    perf_proposal["optimized_code"]
)

# Step 3: Eris - 競合解決
if security_impact["issues"]:
    balanced_solution = await eris.conflict_resolution(
        proposal_a=perf_proposal,  # Performance優先
        proposal_b=security_impact,  # Security優先
        priority_matrix={
            ("critical_security", "minor_performance"): "security_first",
            ("minor_security", "critical_performance"): "performance_first"
        }
    )
```

### Pattern 4: Documentation-Driven Development (Muses → All)
```python
# Step 1: Muses - プロジェクト構造の分析とドキュメント化
project_docs = await muses.knowledge_structuring(project_path)

# Step 2: 各ペルソナがドキュメントを参照して作業
# Hera: ドキュメントから戦略立案
strategy = await hera.strategic_planning(
    current_state=project_docs["architecture"]
)

# Artemis: ドキュメントから最適化箇所を特定
optimization_targets = await artemis.algorithm_analysis(
    codebase=project_docs["modules"]
)

# Hestia: ドキュメントからセキュリティギャップを発見
security_gaps = await hestia.threat_modeling(
    attack_surface=project_docs["endpoints"]
)
```

### Pattern 5: Parallel Full-System Analysis (Athena orchestrates All)
```python
# Athena主導の並列分析
analysis_results = await athena.parallel_execution([
    ("hera", "strategic_planning", project_requirements),
    ("artemis", "code_optimization", codebase),
    ("hestia", "security_audit", codebase),
    ("eris", "task_coordination", team_structure),
    ("muses", "documentation_generation", project_path)
])

# 結果統合
integrated_report = await athena.workflow_orchestration(
    results=analysis_results,
    integration_strategy="consensus"
)
```

---

## 4. OpenCode Compatibility Analysis

### 4.1 SKILL.md Format Comparison

**Claude Code版**:
```markdown
---
skill_name: code_optimization
description: Optimize code for performance and quality
author: Artemis
version: 1.1.0
---

# Code Optimization Skill

## Purpose
Optimizes code for performance, reduces complexity...

## Usage
```python
result = await optimize_code(monitor, code, language="python")
```

## Security
- CWE-94: Code Injection Prevention
- AST validation before execution
```

**OpenCode版** (推測):
```markdown
---
name: code_optimization
description: Optimize code for performance and quality
author: Artemis
version: 1.1.0
mode: skill
runtime: bun
entry: index.js
tools:
  - read
  - write
  - bash
---

# Code Optimization Skill

[Same content as Claude Code version]

## Installation
```bash
bun install
```

## API
```typescript
export async function optimizeCode(
  code: string,
  language: string
): Promise<OptimizationResult>
```
```

**互換性**:
- ✅ SKILL.md のコンテンツ部分は完全互換
- ✅ Frontmatter (YAML) はキーが若干異なるが移行可能
- ⚠️ OpenCode版は`runtime`, `entry`, `tools` を追加で指定

### 4.2 Implementation Language Mapping

| Claude Code | OpenCode | Migration Effort |
|-------------|----------|------------------|
| Python 3.11+ | JavaScript (Bun) | 🟡 Medium |
| asyncio | async/await | ✅ Easy |
| AST parsing | esprima/acorn | 🟡 Medium |
| pathlib | Node.js `path` | ✅ Easy |
| typing | TypeScript | ✅ Easy |

**Migration Strategy**:
1. **Phase 1**: SKILL.md の統一（両プラットフォーム共通）
2. **Phase 2**: Python → TypeScript 移行（型安全性確保）
3. **Phase 3**: Bun runtime 最適化（`$` shell API活用）

### 4.3 Security Implementation Differences

**Claude Code (Python)**:
```python
def _validate_python_code(code: str) -> None:
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            # Check dangerous imports
```

**OpenCode (JavaScript/Bun)**:
```typescript
import { parse } from 'acorn';
import { simple as walk } from 'acorn-walk';

function validateJavaScriptCode(code: string): void {
  const ast = parse(code, { ecmaVersion: 2022 });
  walk(ast, {
    ImportDeclaration(node) {
      // Check dangerous imports
    }
  });
}
```

**互換性**:
- ✅ セキュリティロジックは同一
- ✅ AST解析の概念は共通
- 🟡 ライブラリが異なる（ast vs acorn）

### 4.4 Plugin/Hook Integration

**Claude Code Hook Integration**:
```python
# .claude/hooks/core/precompact_memory_injection.py
from skills.artemis.code_optimization import optimize_code

async def hook(event_type: str, context: dict) -> dict:
    if event_type == "PreCompact":
        # Use Artemis skill
        result = await optimize_code(monitor, code)
```

**OpenCode Plugin Integration** (推測):
```typescript
// ~/.config/opencode/plugin/optimization_trigger.js
import { optimizeCode } from '@opencode/skill/artemis/code_optimization';

export async function onEvent(event: Event): Promise<void> {
  if (event.type === 'session.compact.before') {
    const result = await optimizeCode(event.context.code);
  }
}
```

**互換性**:
- ✅ 両方とも外部スキル呼び出しをサポート
- 🟡 イベント名が異なる（PreCompact vs session.compact.before）
- ✅ 統合パターンは同一

### 4.5 Directory Structure Compatibility

**Claude Code**:
```
.claude/skills/artemis/
├── SKILL.md
├── code_optimization.py
├── algorithm_analysis.py
└── __init__.py
```

**OpenCode**:
```
~/.config/opencode/skill/artemis/
├── SKILL.md                # 同一
├── code_optimization.js   # JavaScript版
├── algorithm_analysis.js
├── package.json
└── tsconfig.json
```

**互換性**:
- ✅ ディレクトリ構造は完全互換
- ✅ SKILL.md の配置場所は同一
- 🟡 実装ファイルの拡張子のみ異なる（.py vs .js）

---

## 5. Implementation Priority & Roadmap

### Phase 1: Core Skills (Priority: High)
**期間**: 2週間

1. **Artemis**:
   - ✅ code_optimization.py (既存)
   - 🔲 algorithm_analysis.py

2. **Hestia**:
   - 🔲 security_audit.py
   - 🔲 vulnerability_scanner.py

3. **Muses**:
   - 🔲 documentation_generation.py

**理由**: この3つが最も頻繁に使われるため優先実装

### Phase 2: Coordination Skills (Priority: Medium)
**期間**: 3週間

4. **Athena**:
   - 🔲 workflow_orchestration.py
   - 🔲 parallel_execution.py

5. **Eris**:
   - 🔲 task_coordination.py
   - 🔲 conflict_resolution.py

**理由**: 複数ペルソナの連携が必要なため、Phase 1完了後に実装

### Phase 3: Strategic Skills (Priority: Medium-Low)
**期間**: 2週間

6. **Hera**:
   - 🔲 strategic_planning.py
   - 🔲 architecture_design.py (既存のarchitecture_analysis.pyを拡張)

**理由**: 長期計画は頻度が低いため後回し

### Phase 4: OpenCode Migration (Priority: Low)
**期間**: 4週間

- 🔲 SKILL.md 統一フォーマット策定
- 🔲 Python → TypeScript 移行ガイド作成
- 🔲 各スキルのOpenCode版実装
- 🔲 互換性テストスイート作成

---

## 6. Skill Development Guidelines

### 6.1 Security-First Development
すべてのスキルは以下のセキュリティチェックを必須とする:

```python
# 1. Input Validation
def validate_input(data: Any, expected_type: type) -> None:
    if not isinstance(data, expected_type):
        raise SecurityError(f"Invalid input type: {type(data)}")

# 2. Path Traversal Prevention (CWE-22)
def validate_path(path: Path) -> Path:
    if path.is_symlink():
        raise SecurityError("Symlink access denied (CWE-61)")
    resolved = path.resolve()
    if not resolved.is_relative_to(Path.cwd()):
        raise SecurityError("Path traversal attempt (CWE-22)")
    return resolved

# 3. Code Injection Prevention (CWE-94)
def validate_code(code: str, language: str) -> None:
    if language == "python":
        _validate_python_code(code)  # AST parsing
    # No eval(), exec(), compile()
```

### 6.2 Async/Await Pattern
すべてのスキルは非同期実行をサポート:

```python
async def skill_function(
    monitor: Any,
    *args,
    **kwargs
) -> Dict[str, Any]:
    logger.info(f"Starting {skill_name}...")

    try:
        # Phase 1: Validation
        validate_input(args, kwargs)

        # Phase 2: Processing (with await)
        result = await process_data(args)

        # Phase 3: Return standardized format
        return {
            "status": "success",
            "data": result,
            "metrics": calculate_metrics(result)
        }
    except Exception as e:
        logger.error(f"{skill_name} failed: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e),
            "data": None
        }
```

### 6.3 Standardized Return Format
すべてのスキルは統一されたレスポンス形式を返す:

```python
{
    "status": "success" | "error",
    "data": {
        # スキル固有のデータ
    },
    "metrics": {
        # パフォーマンスメトリクス
        "execution_time_ms": 123.45,
        "memory_used_mb": 12.34
    },
    "summary": {
        # 人間が読みやすいサマリー
        "total_items_processed": 42,
        "success_rate": 95.2
    },
    "error": "Error message (if status == error)",
    "recommendations": [
        # オプション: 推奨事項
    ]
}
```

### 6.4 Logging Standards
```python
import logging
logger = logging.getLogger(__name__)

# Info: 正常な実行ステップ
logger.info("Phase 1: Analyzing code...")

# Warning: 潜在的な問題
logger.warning("High complexity detected: 25")

# Error: 実行エラー
logger.error("Security validation failed: CWE-94", exc_info=True)

# Debug: 詳細なデバッグ情報
logger.debug(f"Processing module: {module_name}")
```

---

## 7. Testing Strategy

### 7.1 Unit Tests (各スキル)
```python
# tests/skills/artemis/test_code_optimization.py
import pytest
from skills.artemis.code_optimization import optimize_code

@pytest.mark.asyncio
async def test_optimize_simple_loop():
    code = """
for i in range(len(items)):
    print(items[i])
"""
    result = await optimize_code(monitor, code, language="python")

    assert result["status"] == "success"
    assert "for item in items" in result["data"]["optimized_code"]
    assert result["metrics"]["performance_gain_percent"] > 0

@pytest.mark.asyncio
async def test_security_validation_blocks_eval():
    code = "eval('malicious code')"
    result = await optimize_code(monitor, code, language="python")

    assert result["status"] == "error"
    assert "CWE-94" in result["error"]
```

### 7.2 Integration Tests (スキル間連携)
```python
# tests/integration/test_security_optimization_flow.py
@pytest.mark.asyncio
async def test_hestia_to_artemis_flow():
    # Step 1: Hestia - セキュリティ監査
    audit_result = await hestia.security_audit(project_path)

    # Step 2: Artemis - 脆弱性修正
    for vuln in audit_result["vulnerabilities"]:
        fix_result = await artemis.code_optimization(
            vuln["code"],
            security_constraints=vuln["constraints"]
        )
        assert fix_result["status"] == "success"

    # Step 3: Hestia - 再検証
    reaudit_result = await hestia.vulnerability_scanner(project_path)
    assert len(reaudit_result["vulnerabilities"]) == 0
```

### 7.3 Performance Benchmarks
```python
# benchmarks/artemis_optimization_benchmark.py
import time

async def benchmark_code_optimization():
    test_cases = [
        ("small_loop", small_loop_code),
        ("nested_loops", nested_loops_code),
        ("string_concat", string_concat_code)
    ]

    for name, code in test_cases:
        start = time.perf_counter()
        result = await artemis.optimize_code(monitor, code)
        duration = time.perf_counter() - start

        print(f"{name}: {duration*1000:.2f}ms")
        assert duration < 1.0  # Max 1 second
```

---

## 8. Documentation Requirements

### 8.1 Each Skill Must Have:

1. **SKILL.md** (user-facing):
   - Purpose and use cases
   - API documentation
   - Examples with code snippets
   - Security considerations

2. **Docstrings** (developer-facing):
   ```python
   async def skill_function(
       monitor: Any,
       param1: str,
       param2: int = 10
   ) -> Dict[str, Any]:
       """
       One-line summary of the skill.

       Args:
           monitor: Execution monitor for logging
           param1: Description of param1
           param2: Description of param2 (default: 10)

       Returns:
           dict: Result with status, data, metrics

       Raises:
           SecurityError: If input validation fails

       Example:
           >>> result = await skill_function(monitor, "test", 20)
           >>> print(result["status"])
           'success'

       Security:
           - CWE-22: Path traversal prevention
           - CWE-94: Code injection prevention
       """
   ```

3. **README.md** (skill directory):
   - Overview of all skills in this persona
   - Installation instructions
   - Troubleshooting guide

---

## 9. Migration Path: Claude Code → OpenCode

### Step 1: Prepare SKILL.md (Universal Format)
```markdown
---
# Claude Code fields
skill_name: code_optimization
description: Optimize code for performance
author: Artemis
version: 1.1.0

# OpenCode-specific fields (optional)
mode: skill
runtime: bun
entry: index.ts
tools:
  - read
  - write
  - bash
---

[Rest of the documentation - same for both platforms]
```

### Step 2: Implement TypeScript Version
```typescript
// ~/.config/opencode/skill/artemis/code_optimization.ts
export interface OptimizationResult {
  status: 'success' | 'error';
  data?: {
    original_code: string;
    optimized_code: string;
  };
  metrics?: Record<string, number>;
  error?: string;
}

export async function optimizeCode(
  code: string,
  language: string = 'python'
): Promise<OptimizationResult> {
  // Same logic as Python version, translated to TypeScript
}
```

### Step 3: Create Compatibility Layer
```typescript
// ~/.config/opencode/skill/common/compat.ts
export function createMonitor() {
  return {
    log: (msg: string) => console.log(msg),
    error: (msg: string) => console.error(msg)
  };
}

// Bridge for Python-style async
export async function runSkill<T>(
  skillFn: () => Promise<T>
): Promise<T> {
  return await skillFn();
}
```

---

## 10. Success Metrics

### 10.1 Skill Quality Metrics
- ✅ **Security**: 0件のCWE脆弱性
- ✅ **Performance**: 平均実行時間 < 1秒
- ✅ **Reliability**: 95%以上の成功率
- ✅ **Documentation**: 100%のdocstring coverage

### 10.2 Integration Metrics
- ✅ **Inter-Skill Calls**: エラー率 < 5%
- ✅ **Conflict Resolution**: Eris介入率 < 20%
- ✅ **Parallel Efficiency**: 並列化によるスピードアップ > 2x

### 10.3 User Satisfaction Metrics
- ✅ **Ease of Use**: ドキュメントの明確さ
- ✅ **Accuracy**: スキル出力の精度 > 90%
- ✅ **Responsiveness**: ユーザーフィードバックへの対応速度

---

## Conclusion

この包括的なAgent Skills設計により、6つのTrinitasペルソナが調和的に連携し、ユーザーに最高の開発体験を提供できます。各スキルは専門性を持ちつつも、相互連携を通じてシステム全体の価値を最大化します。

**Next Steps**:
1. Phase 1スキルの実装開始（Artemis, Hestia, Muses）
2. SKILL.md統一フォーマットの策定
3. OpenCode版への移行計画の詳細化

---

**最終更新**: 2025-11-09
**作成者**: Athena (Harmonious Conductor)
**レビュー**: Hera (Strategic Commander), Artemis (Technical Perfectionist)
