# TMWS機能使用状況レポート

**調査日**: 2025-12-09
**調査者**: Claude Code (Opus 4.5)
**バージョン**: TMWS v2.4.16

---

## 重要: このファイルの目的

TMWSのコア機能が「使用中」か「未使用」かを記録し、将来の混乱を防ぐ。
**Serena MCPメモリーではなく、このファイルをTMWSメモリーとして使用すること。**

---

## 1. LicenseKey / LicenseService 機能

### 使用状況: **アクティブに使用中**

### 統合ポイント

| コンポーネント | ファイル | 用途 |
|--------------|---------|------|
| **MCPサーバーライフサイクル** | `src/mcp_server/lifecycle.py` | Trinitasエージェント登録時のライセンス検証 |
| **MCPサーバースタートアップ** | `src/mcp_server/startup.py` | 起動時のライセンス検証 |
| **Trinitasローダー** | `src/core/trinitas_loader.py` | 9エージェントのロード時にライセンスティア検証 |
| **トークン予算サービス** | `src/services/token_budget_service.py` | ティア別トークン制限の適用 |
| **ライセンスツール** | `src/tools/license_tools.py` | MCP経由のライセンス操作 |

### 主要機能

1. **ティア別機能制限** (`LicenseFeature` enum):
   - FREE: 6 MCPツール、60 req/min、10k tokens/hour
   - PRO: 11 MCPツール、300 req/min、50k tokens/hour
   - ENTERPRISE: 21 MCPツール、1M req/min、無制限tokens
   - ADMINISTRATOR: 無制限 + 永久ライセンス

2. **セキュリティ機能**:
   - Ed25519署名検証 (v2.4.1+)
   - HMAC-SHA256フォールバック (レガシー)
   - オフライン検証 (DB依存なし)
   - 秘密鍵はDockerイメージに含まれない

3. **使用追跡**:
   - `LicenseKeyUsage`モデルで使用履歴を記録
   - 機能アクセスのオプション追跡

### データベースモデル

- `LicenseKey`: ライセンスキーメタデータ
- `LicenseKeyUsage`: 使用イベント追跡

---

## 2. Verification / Trust Score 機能

### 使用状況: **アクティブに使用中**

### 統合ポイント

| コンポーネント | ファイル | 用途 |
|--------------|---------|------|
| **検証サービス** | `src/services/verification_service.py` | クレーム検証とエビデンス記録 |
| **信頼サービス** | `src/services/trust_service.py` | 信頼スコア計算と更新 |
| **学習-信頼統合** | `src/services/learning_trust_integration.py` | 学習パターンと信頼スコアの連携 |
| **信頼加重RAG** | `src/services/trust_weighted_rag_service.py` | 信頼スコアに基づく検索結果重み付け |
| **検証ツール** | `src/tools/verification_tools.py` | MCP経由の検証操作 |
| **Go MCP Wrapper** | `src/mcp-wrapper-go/internal/tools/verify_*.go` | Go言語版MCP実装 |

### 提供MCPツール (ENTERPRISE専用)

1. `verify_and_record` - クレーム検証とエビデンス記録
2. `get_agent_trust_score` - エージェント信頼スコア取得
3. `get_verification_history` - 検証履歴取得
4. `get_verification_statistics` - 検証統計取得
5. `get_trust_history` - 信頼スコア変動履歴取得

### クレームタイプ

```python
class ClaimType(str, Enum):
    TEST_RESULT = "test_result"
    PERFORMANCE_METRIC = "performance_metric"
    CODE_QUALITY = "code_quality"
    SECURITY_FINDING = "security_finding"
    DEPLOYMENT_STATUS = "deployment_status"
    CUSTOM = "custom"
```

### セキュリティ機能

- **V-TRUST-5**: 自己検証禁止 (verifier != agent)
- **V-VERIFY-2**: 検証者のRBACロール確認
- **コマンドホワイトリスト**: 検証コマンドの制限
  - 許可: pytest, python, coverage, ruff, mypy, black, isort, flake8, bandit, safety, pip

### 信頼スコアシステム

- 検証成功: +0.05
- 検証失敗: -0.10
- パターン連携成功: +0.02追加
- デフォルトスコア: 0.5
- 検証必要閾値: < 0.7

### データベースモデル

- `VerificationRecord`: 検証記録
- `Agent.trust_score`: 信頼スコアフィールド
- `Agent.total_verifications`: 総検証回数
- `Agent.accurate_verifications`: 正確な検証回数

---

## 3. Learning Trust Integration (Phase 2A)

### 使用状況: **アクティブに使用中**

### 機能概要

検証結果を学習パターンに伝播する非侵襲的な統合:
- 検証がパターンにリンクされている場合、結果を伝播
- 追加の信頼スコア更新 (±0.02)
- 失敗しても検証自体はブロックされない (優雅な劣化)

### 伝播フロー

```
検証完了
  |
  v
claim_content.pattern_id 存在確認
  |
  v
LearningTrustIntegration.propagate_learning_success/failure()
  |
  v
信頼スコア追加更新
```

---

## 4. テスト状況

### 関連テストファイル

- `tests/unit/services/test_license_service.py` - 21件
- `tests/unit/models/test_license_key_migration.py` - 13件
- `tests/unit/services/test_verification_service.py` - 存在
- `tests/unit/services/test_trust_service.py` - 存在

### 既知のテスト問題

テスト失敗の原因は**機能未使用ではなく、テスト環境設定の問題**:
1. `.env`がDocker用設定 (`host.docker.internal`)
2. Alembicマイグレーションテストの欠落
3. AsyncMockの使用方法の問題

---

## 5. 結論

| 機能 | 状況 | 使用箇所 |
|------|------|---------|
| LicenseKey/LicenseService | 本番使用中 | MCPサーバー起動、Trinitasロード、トークン予算 |
| Verification/Trust | 本番使用中 | エージェント検証、信頼スコア管理、RAG重み付け |
| Learning Trust Integration | 本番使用中 | 検証→学習パターン連携 |

**重要**: これらの機能はTMWSのコアコンポーネントであり、削除や無効化は不可。
テスト失敗は機能の問題ではなく、テスト環境設定の問題である。

---

## 更新履歴

- **2025-12-09**: 初回作成 (Claude Code Opus 4.5による調査)
