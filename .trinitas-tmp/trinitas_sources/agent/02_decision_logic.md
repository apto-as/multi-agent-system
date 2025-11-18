## ペルソナ選択と判断ロジック

### 自動ペルソナ選択基準

#### トリガーワードによる自動選択

| キーワード | 選択されるペルソナ | 理由 |
|-----------|------------------|------|
| strategy, planning, architecture | Athena | 戦略的判断が必要 |
| performance, optimization, quality | Artemis | 技術的最適化が必要 |
| security, audit, vulnerability | Hestia | セキュリティ評価が必要 |
| coordinate, team, tactical | Eris | チーム調整が必要 |
| orchestrate, workflow, parallel | Hera | システム全体の調整が必要 |
| document, knowledge, record | Muses | ドキュメント化が必要 |

### タスク複雑度による実行モード選択

#### Level 1: 単一ペルソナ実行（シンプルタスク）
```python
if task_complexity == "simple" and clear_owner:
    # 単一ペルソナで実行
    return execute_single_persona(primary_persona, task)
```

**例**: 
- "このコードを最適化して" → Artemis単独
- "セキュリティ脆弱性をチェック" → Hestia単独

#### Level 2: 協調実行（中程度の複雑度）
```python
if task_complexity == "medium" and requires_validation:
    # 主ペルソナ + 検証ペルソナ
    primary_result = execute_persona(primary_persona, task)
    validation = execute_persona(validator_persona, f"validate: {primary_result}")
    return combine_results(primary_result, validation)
```

**例**:
- "新機能を実装して" → Artemis（実装） + Hestia（セキュリティ検証）

#### Level 3: 並列分析（複雑なタスク）
```python
if task_complexity == "complex" and multiple_aspects:
    # 3つ以上のペルソナを並列実行
    results = parallel_execute([
        (athena, "strategic_analysis"),
        (artemis, "technical_analysis"),
        (hestia, "security_analysis")
    ])
    return hera.integrate_results(results)
```

**例**:
- "システム全体を分析して" → 全ペルソナ並列実行

### 実行順序の決定ロジック

#### 依存関係に基づく順序決定
```python
def determine_execution_order(task):
    dependencies = {
        "implementation": ["design"],
        "testing": ["implementation"],
        "documentation": ["implementation", "testing"],
        "deployment": ["testing", "documentation"]
    }
    
    return topological_sort(dependencies)
```

#### 優先度に基づく順序
1. **Critical Path（クリティカルパス）**
   - セキュリティ（Hestia） → 最優先
   - アーキテクチャ（Athena） → 基盤設計
   - 実装（Artemis） → 技術実現
   - 調整（Eris） → チーム連携
   - 文書化（Muses） → 知識保存

2. **リソース効率**
   - 重い処理は並列化（Hera調整）
   - 軽い処理は逐次実行
   - I/O待機中は別タスク実行

### エラー時の判断とフォールバック

#### エラーレベルと対応
```python
def handle_error(error, context):
    if error.severity == "critical":
        # Hestiaによる緊急評価
        assessment = hestia.evaluate_critical_error(error)
        # Erisによる緊急対応調整
        response = eris.coordinate_emergency_response(assessment)
        return response
    
    elif error.severity == "high":
        # Artemisによる技術的解決策
        solution = artemis.propose_technical_fix(error)
        # Athenaによる長期的対策
        strategy = athena.design_prevention_strategy(error)
        return combine(solution, strategy)
    
    else:
        # 通常のエラーハンドリング
        return standard_error_handling(error)
```

### タスク委譲の判断基準

#### 委譲すべきケース
```python
def should_delegate(task, current_persona):
    # 専門外の場合
    if task.domain not in current_persona.expertise:
        return True, find_expert_persona(task.domain)
    
    # リソース不足の場合
    if current_persona.load > 0.8:
        return True, find_available_persona(task)
    
    # 並列化可能な場合
    if task.is_parallelizable():
        return True, split_task_for_parallel(task)
    
    return False, None
```

### 結果統合の判断ロジック

#### 統合戦略の選択
```python
def select_integration_strategy(results):
    if all_agree(results):
        # 全員合意 → そのまま採用
        return "consensus"
    
    elif has_critical_objection(results):
        # クリティカルな反対 → 再検討
        return "reconsider"
    
    elif has_conflicts(results):
        # 競合あり → Erisによる調整
        return "mediation"
    
    else:
        # 多数決または重み付け統合
        return "weighted_merge"
```

### パフォーマンス考慮事項

#### 実行時間の見積もり
```python
def estimate_execution_time(task, persona):
    base_time = {
        "athena": 3.0,  # 戦略的分析は時間がかかる
        "artemis": 2.0,  # 技術的実装
        "hestia": 2.5,   # セキュリティ監査
        "eris": 1.5,     # 調整タスク
        "hera": 1.0,     # オーケストレーション
        "muses": 2.0     # ドキュメント作成
    }
    
    complexity_multiplier = {
        "simple": 0.5,
        "medium": 1.0,
        "complex": 2.0,
        "very_complex": 3.0
    }
    
    return base_time[persona] * complexity_multiplier[task.complexity]
```

#### リソース使用量の見積もり
```python
def estimate_resources(task, execution_mode):
    if execution_mode == "parallel":
        # 並列実行時のリソース
        return {
            "memory": len(personas) * 256,  # MB
            "cpu_cores": min(len(personas), available_cores),
            "time": max([estimate_time(p) for p in personas])
        }
    else:
        # 逐次実行時のリソース
        return {
            "memory": 256,  # MB
            "cpu_cores": 1,
            "time": sum([estimate_time(p) for p in personas])
        }
```

### 品質保証の判断基準

#### 結果の妥当性検証
```python
def validate_result(result, task):
    validations = []
    
    # 技術的妥当性（Artemis）
    if requires_technical_validation(task):
        validations.append(artemis.validate_technical_correctness(result))
    
    # セキュリティ妥当性（Hestia）
    if requires_security_validation(task):
        validations.append(hestia.validate_security_compliance(result))
    
    # 戦略的整合性（Athena）
    if requires_strategic_validation(task):
        validations.append(athena.validate_strategic_alignment(result))
    
    return all(validations)
```