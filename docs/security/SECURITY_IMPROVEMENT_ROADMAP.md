# セキュリティ改善ロードマップ

## 概要

TMWSのセキュリティ強化のための段階的改善計画です。Hestia（セキュリティ監査者）による監査結果に基づき、優先順位付けされた対応項目を定義します。

**作成日**: 2025-10-01
**監査実施**: Hestia (Security Guardian)
**承認**: 条件付き承認 - 段階的改善を前提
**次回レビュー**: 2025-10-08

## 現在のセキュリティステータス

### ✅ 実装済みのセキュリティ対策

1. **認証・認可**
   - JWT認証機能実装
   - エージェント自動検出
   - アクセスレベル管理（private, team, shared, public）

2. **データ保護**
   - PostgreSQL接続の暗号化対応
   - 環境変数による機密情報管理
   - .envファイルのgitignore設定

3. **監査ログ**
   - 非同期監査ロガー実装
   - セキュリティイベント記録

4. **入力検証**
   - Pydantic V2による型検証
   - SQLインジェクション対策（SQLAlchemy ORM使用）

5. **CI/CDセキュリティ**
   - Banditによる静的解析
   - Safetyによる依存関係チェック
   - pip-auditによる脆弱性スキャン

### ⚠️ 改善が必要な領域

1. **本番環境設定**
   - 認証の強制有効化
   - シークレットキーの強化
   - HTTPS強制

2. **レート制限**
   - Redis分散レート制限の完全実装
   - DDoS対策の強化

3. **データ暗号化**
   - 保存時の暗号化（encryption at rest）
   - センシティブデータのフィールドレベル暗号化

4. **セキュリティヘッダー**
   - HSTS, CSP, X-Frame-Optionsなどの設定

## Phase 1: Critical Fixes（24時間以内）

**目標**: システムの最重要セキュリティリスクに対処

### 1.1 本番環境認証強制

**優先度**: 🔴 Critical

```python
# src/core/config.py

class Settings(BaseSettings):
    # 環境変数検証
    def __post_init__(self):
        if self.TMWS_ENVIRONMENT == "production":
            if not self.TMWS_AUTH_ENABLED:
                raise SecurityError(
                    "Authentication MUST be enabled in production"
                )
            if len(self.TMWS_SECRET_KEY) < 32:
                raise SecurityError(
                    "SECRET_KEY must be at least 32 characters"
                )
```

**検証方法**:
```bash
pytest tests/security/test_production_config.py
```

### 1.2 デフォルト認証情報の排除

**優先度**: 🔴 Critical

**現状確認**:
```bash
# 危険なデフォルト値を検索
grep -r "postgres:postgres" . --exclude-dir=".git"
grep -r "test_secret" . --exclude-dir=".git"
```

**対応**:
- すべての設定ファイルから平文のパスワード削除
- `.env.example`にプレースホルダーのみ記載
- 本番環境では環境変数または秘密管理システム使用

### 1.3 シークレットキー生成ツール

**優先度**: 🟡 High

```python
# scripts/generate_secrets.py

import secrets
import string

def generate_secret_key(length: int = 64) -> str:
    """暗号学的に安全なシークレットキー生成"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_database_password(length: int = 32) -> str:
    """データベースパスワード生成（特殊文字制限）"""
    alphabet = string.ascii_letters + string.digits + "_-."
    return ''.join(secrets.choice(alphabet) for _ in range(length))

if __name__ == "__main__":
    print("=== TMWS Security Secrets Generator ===")
    print(f"SECRET_KEY={generate_secret_key()}")
    print(f"DB_PASSWORD={generate_database_password()}")
    print(f"REDIS_PASSWORD={generate_database_password()}")
```

**使用方法**:
```bash
python scripts/generate_secrets.py > .env.production
```

## Phase 2: High Priority Enhancements（1週間以内）

**目標**: セキュリティ基盤の強化

### 2.1 HTTPS強制化

**優先度**: 🟡 High

```python
# src/api/middleware.py

@app.middleware("http")
async def force_https(request: Request, call_next):
    """本番環境でHTTPS強制"""
    if settings.TMWS_ENVIRONMENT == "production":
        if request.url.scheme != "https":
            url = request.url.replace(scheme="https")
            return RedirectResponse(url, status_code=301)

    response = await call_next(request)
    return response
```

### 2.2 セキュリティヘッダー実装

**優先度**: 🟡 High

```python
# src/api/middleware.py

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    # Strict Transport Security
    response.headers["Strict-Transport-Security"] = \
        "max-age=31536000; includeSubDomains"

    # Content Security Policy
    response.headers["Content-Security-Policy"] = \
        "default-src 'self'; script-src 'self' 'unsafe-inline'"

    # X-Frame-Options
    response.headers["X-Frame-Options"] = "DENY"

    # X-Content-Type-Options
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Referrer-Policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    return response
```

### 2.3 レート制限強化

**優先度**: 🟡 High

```python
# src/api/rate_limiting.py

from fastapi import HTTPException
from redis import asyncio as aioredis
from typing import Optional
import time

class DistributedRateLimiter:
    def __init__(
        self,
        redis_url: str,
        default_limit: int = 100,
        window_seconds: int = 60
    ):
        self.redis = aioredis.from_url(redis_url)
        self.default_limit = default_limit
        self.window_seconds = window_seconds

    async def check_rate_limit(
        self,
        identifier: str,
        limit: Optional[int] = None
    ) -> tuple[bool, int]:
        """
        レート制限チェック

        Returns:
            (allowed, remaining): (許可されるか, 残り回数)
        """
        limit = limit or self.default_limit
        key = f"rate_limit:{identifier}"

        # Sliding window algorithm
        now = time.time()
        window_start = now - self.window_seconds

        pipe = self.redis.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zadd(key, {str(now): now})
        pipe.zcard(key)
        pipe.expire(key, self.window_seconds)

        results = await pipe.execute()
        count = results[2]

        if count > limit:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Limit: {limit}/{self.window_seconds}s"
            )

        return True, limit - count
```

### 2.4 監査ログ強化

**優先度**: 🟢 Medium

```python
# src/security/audit_logger_enhanced.py

import structlog
from datetime import datetime
from typing import Optional, Dict, Any

logger = structlog.get_logger()

class EnhancedAuditLogger:
    @staticmethod
    async def log_security_event(
        event_type: str,
        severity: str,  # "low", "medium", "high", "critical"
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """セキュリティイベントの記録"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "user_id": user_id,
            "ip_address": ip_address,
            "details": details or {}
        }

        # ログレベルに応じた処理
        if severity == "critical":
            logger.critical("security_event", **log_entry)
            # 即座にアラート送信
            await send_security_alert(log_entry)
        elif severity == "high":
            logger.error("security_event", **log_entry)
        elif severity == "medium":
            logger.warning("security_event", **log_entry)
        else:
            logger.info("security_event", **log_entry)

        # データベースに永続化
        await store_audit_log(log_entry)
```

## Phase 3: Long-term Improvements（1ヶ月以内）

**目標**: 包括的なセキュリティ態勢の確立

### 3.1 データ暗号化（Encryption at Rest）

**優先度**: 🟢 Medium

```python
# src/security/encryption.py

from cryptography.fernet import Fernet
from typing import Optional
import os

class FieldEncryption:
    def __init__(self, key: Optional[bytes] = None):
        self.key = key or os.getenv("ENCRYPTION_KEY").encode()
        self.cipher = Fernet(self.key)

    def encrypt(self, data: str) -> str:
        """データ暗号化"""
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt(self, encrypted: str) -> str:
        """データ復号化"""
        return self.cipher.decrypt(encrypted.encode()).decode()

# SQLAlchemyモデルでの使用例
from sqlalchemy import String, TypeDecorator

class EncryptedString(TypeDecorator):
    impl = String
    cache_ok = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.encryptor = FieldEncryption()

    def process_bind_param(self, value, dialect):
        if value is not None:
            return self.encryptor.encrypt(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return self.encryptor.decrypt(value)
        return value
```

### 3.2 侵入検知システム（IDS）

**優先度**: 🟢 Medium

```python
# src/security/intrusion_detection.py

from collections import defaultdict
from datetime import datetime, timedelta
import asyncio

class IntrusionDetectionSystem:
    def __init__(self):
        self.failed_attempts = defaultdict(list)
        self.suspicious_patterns = defaultdict(int)

    async def monitor_login_attempts(
        self,
        user_id: str,
        success: bool,
        ip_address: str
    ):
        """ログイン試行の監視"""
        if not success:
            self.failed_attempts[user_id].append({
                "timestamp": datetime.utcnow(),
                "ip": ip_address
            })

            # 5分以内に5回失敗でアカウントロック
            recent_failures = [
                f for f in self.failed_attempts[user_id]
                if datetime.utcnow() - f["timestamp"] < timedelta(minutes=5)
            ]

            if len(recent_failures) >= 5:
                await self.trigger_account_lock(user_id, ip_address)
        else:
            # 成功時は失敗カウントをリセット
            self.failed_attempts[user_id].clear()

    async def trigger_account_lock(self, user_id: str, ip_address: str):
        """アカウントロック処理"""
        await EnhancedAuditLogger.log_security_event(
            event_type="account_locked",
            severity="high",
            user_id=user_id,
            ip_address=ip_address,
            details={"reason": "multiple_failed_attempts"}
        )
```

### 3.3 定期セキュリティスキャン自動化

**優先度**: 🟢 Medium

```yaml
# .github/workflows/security-scan.yml

name: Weekly Security Scan

on:
  schedule:
    - cron: '0 2 * * 1'  # 毎週月曜2:00 UTC
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run comprehensive security scan
        run: |
          pip install bandit safety pip-audit semgrep

          # Static analysis
          bandit -r src/ -f json -o bandit-full.json

          # Dependency vulnerabilities
          safety check --full-report
          pip-audit --format json

          # SAST with Semgrep
          semgrep --config=auto --json -o semgrep.json

      - name: Create security report
        run: python scripts/generate_security_report.py

      - name: Upload to security dashboard
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: security-reports/
```

## 検証とテスト

### セキュリティテストスイート

```bash
# 全セキュリティテスト実行
pytest tests/security/ -v

# 特定のテスト
pytest tests/security/test_authentication.py -v
pytest tests/security/test_rate_limiting.py -v
pytest tests/security/test_encryption.py -v
```

### ペネトレーションテスト

```bash
# OWASP ZAPによるスキャン
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://localhost:8000 \
  -r zap-report.html
```

## コンプライアンス

### OWASP Top 10 対応状況

| リスク | 対策状況 | Phase |
|-------|---------|-------|
| A01:2021 - Broken Access Control | 🟡 部分実装 | Phase 2 |
| A02:2021 - Cryptographic Failures | 🔴 未実装 | Phase 3 |
| A03:2021 - Injection | ✅ 対策済み | - |
| A04:2021 - Insecure Design | 🟡 部分実装 | Phase 2 |
| A05:2021 - Security Misconfiguration | 🔴 要改善 | Phase 1 |
| A06:2021 - Vulnerable Components | ✅ 対策済み | - |
| A07:2021 - Authentication Failures | 🟡 部分実装 | Phase 1 |
| A08:2021 - Software and Data Integrity | 🟡 部分実装 | Phase 2 |
| A09:2021 - Security Logging Failures | ✅ 対策済み | - |
| A10:2021 - Server-Side Request Forgery | ✅ 対策済み | - |

## 進捗トラッキング

### Phase 1 チェックリスト

- [ ] 本番環境認証強制実装
- [ ] デフォルト認証情報排除
- [ ] シークレット生成ツール作成
- [ ] セキュリティテスト追加
- [ ] ドキュメント更新

### Phase 2 チェックリスト

- [ ] HTTPS強制化
- [ ] セキュリティヘッダー実装
- [ ] レート制限強化
- [ ] 監査ログ強化
- [ ] テストカバレッジ向上

### Phase 3 チェックリスト

- [ ] データ暗号化実装
- [ ] 侵入検知システム実装
- [ ] 自動セキュリティスキャン
- [ ] ペネトレーションテスト
- [ ] OWASP Top 10 完全対応

## 責任者とレビュー

| Phase | 担当ペルソナ | レビュアー | 期限 |
|-------|-----------|-----------|------|
| Phase 1 | Hestia + Artemis | Athena | 2025-10-02 |
| Phase 2 | Hestia + Eris | Hera | 2025-10-08 |
| Phase 3 | Hestia + Artemis | 全員 | 2025-11-01 |

## 関連ドキュメント

- [CI/CDガイド](../dev/CICD_GUIDE.md)
- [認証システム仕様](../api/AUTHENTICATION.md)
- [監査ログ設計](../architecture/AUDIT_LOGGING.md)
- [暗号化標準](ENCRYPTION_STANDARDS.md)

## 変更履歴

| 日付 | バージョン | 変更内容 | 担当 |
|-----|-----------|---------|------|
| 2025-10-01 | 1.0.0 | 初版作成、3フェーズロードマップ策定 | Hestia + Muses |
