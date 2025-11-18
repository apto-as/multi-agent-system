# Trinitas Security Framework

...セキュリティは妥協できません。このフレームワークは最悪のケースを想定して設計されています...

## Overview

Trinitasセキュリティフレームワークは、各ペルソナのツールアクセスを厳格に制御し、システム全体の安全性を確保するためのセキュリティレイヤーです。

### Core Principles

1. **ゼロトラスト**: 全てのアクセス試行は疑わしいものとして扱います
2. **最小権限の原則**: 各ペルソナは役割を果たすのに必要最小限の権限のみを持ちます
3. **多層防御**: 複数の検証レイヤーによる包括的な保護
4. **継続的監視**: 全てのアクションが記録され、異常が検出されます

## Components

### 1. Tool Access Matrix (`tool-matrix.json`)

各ペルソナがアクセス可能なツールと制限を定義します。

```json
{
  "persona_access_matrix": {
    "athena": {
      "security_clearance": "ORCHESTRATION",
      "allowed_tool_groups": ["safe_read_tools", "coordination_tools"],
      "restrictions": {
        "no_direct_code_modification": true
      }
    }
  }
}
```

### 2. Access Validator (`access-validator.py`)

実際のアクセス制御を実行する検証エンジンです。

```python
from shared.security.access_validator import validate_persona_access

result = validate_persona_access(
    persona="hestia",
    tool="Bash", 
    operation="security_scan",
    command="npm audit"
)

if result.result == AccessResult.GRANTED:
    # アクセス許可
    execute_tool_operation()
else:
    # アクセス拒否
    log_security_violation(result.reason)
```

## Security Classifications

| Level | Classification | Description | Audit Level |
|-------|---------------|-------------|-------------|
| 1 | READ_ONLY | 情報の読み取りのみ | Minimal |
| 2 | LIMITED_WRITE | 制限された書き込み | Standard |  
| 3 | FULL_MODIFY | 完全な変更権限 | Comprehensive |
| 4 | SYSTEM_EXECUTE | システムコマンド実行 | Critical |
| 5 | ORCHESTRATION | クロスペルソナ調整 | Maximum |

## Persona Access Levels

### Athena (Harmonious Conductor)
- **Clearance**: ORCHESTRATION  
- **Tools**: Read, Coordination, Documentation
- **Restrictions**: コード変更不可、委譲のみ

### Artemis (Technical Perfectionist)  
- **Clearance**: FULL_MODIFY
- **Tools**: Read, Code Modification, Execution
- **Restrictions**: セキュリティ設定変更不可

### Hestia (Security Guardian)
- **Clearance**: READ_ONLY
- **Tools**: Read, Audit tools only
- **Restrictions**: 観察のみ、変更不可

### Eris (Tactical Coordinator)
- **Clearance**: LIMITED_WRITE  
- **Tools**: Read, Coordination, Documentation
- **Restrictions**: コード変更不可、文書のみ

### Hera (Strategic Commander)
- **Clearance**: LIMITED_WRITE
- **Tools**: Read, Documentation, Coordination  
- **Restrictions**: 実装レベル制限、計画文書のみ

### Muses (Knowledge Architect)
- **Clearance**: LIMITED_WRITE
- **Tools**: Read, Documentation
- **Restrictions**: 文書ファイルのみ、コードアクセス不可

## Risk Assessment

各アクセス試行は以下の要素でリスク評価されます：

- **Tool Risk**: 使用するツールの危険度
- **Path Risk**: アクセス先パスの機密度  
- **Command Risk**: 実行コマンドの危険性
- **History Risk**: 過去の失敗履歴

リスクレベル：
- **1-3**: 低リスク（通常の監査）
- **4-6**: 中リスク（詳細監査必要）
- **7-8**: 高リスク（承認推奨）
- **9-10**: 重大リスク（即時アラート）

## Security Policies

### Quarantine System

連続する違反やセキュリティ脅威が検出された場合、ペルソナは自動的に隔離されます：

- **失敗閾値**: 3回の連続失敗でアラート
- **危険コマンド**: `rm -rf /`, `sudo` 等で即座に隔離
- **解除**: 管理者の手動承認が必要

### Monitoring & Alerting

- 全てのアクセス試行をログ記録
- 高リスクオペレーションの即座通知
- 異常パターンの自動検出

## Emergency Protocols

### Security Incident Response

1. **Level 1** (疑わしいアクティビティ): 監視強化
2. **Level 2** (確認された脅威): 該当ペルソナを読み取り専用モードに制限  
3. **Level 3** (重大な侵害): 全ペルソナをロックダウン

## Integration Guide

### Step 1: Initialize Validator

```python
from shared.security.access_validator import TrinitasSecurityValidator

validator = TrinitasSecurityValidator("shared/security/tool-matrix.json")
```

### Step 2: Validate Before Tool Use

```python
def execute_persona_tool(persona: str, tool: str, **kwargs):
    # セキュリティ検証
    attempt = AccessAttempt(persona, tool, "execute", **kwargs)
    result = validator.validate_access(attempt)
    
    if result.result != AccessResult.GRANTED:
        raise SecurityException(f"Access denied: {result.reason}")
    
    # 実際のツール実行
    return execute_tool(tool, **kwargs)
```

### Step 3: Monitor and Log

```python
# リスクレベルに応じた処理
if result.risk_level >= 8:
    notify_security_team(result)
if result.risk_level >= 6:
    create_audit_record(attempt, result)
```

## Configuration Validation

設定ファイルの整合性を定期的に確認してください：

```bash
python3 -m shared.security.access_validator --validate-config
```

## Security Best Practices

1. **定期的な設定レビュー**: 月次で権限マトリックスを見直し
2. **ログ監査**: セキュリティログの定期的な分析
3. **アクセスパターン分析**: 異常なアクセスパターンの検出
4. **権限最小化**: 必要最小限の権限のみ付与
5. **緊急時対応**: インシデント対応計画の定期的な訓練

## Troubleshooting

### 一般的な問題

**Q: 正当なアクセスが拒否される**  
A: 権限マトリックスで該当ペルソナの `allowed_tool_groups` を確認してください

**Q: パスアクセスが拒否される**  
A: `tool_definitions` の `restrictions.allowed_paths` を確認してください  

**Q: ペルソナが隔離された**  
A: 管理者権限で `validator.release_quarantine(persona, admin_approval=True)` を実行

### デバッグモード

```python
import logging
logging.getLogger('shared.security.access_validator').setLevel(logging.DEBUG)
```

---

*"Better to be paranoid and secure than trusting and compromised."*

*...セキュリティに妥協は許されません。最悪のケースを想定して、完璧な防御を構築します...*