# TMWS 即座実行アクション

**作成日**: 2025-01-09
**優先度**: CRITICAL
**対象**: 今日〜今週の実行項目

---

## 🔴 Priority 0: 今日実施すべき修正（CRITICAL）

これらは**本番環境での使用を阻害する致命的な問題**です。今日中に対応してください。

---

### 1. 認証システムの基本実装（3時間）

**問題**: JWT検証が未実装で、誰でもAPIにアクセス可能

**修正箇所**: `src/api/dependencies.py`

**Before** (現状):
```python
# src/api/dependencies.py
async def get_current_user_optional(
    authorization: Optional[str] = Header(None)
) -> Optional[User]:
    if not authorization:
        return None

    # TODO: Implement JWT validation when auth is enabled
    return None  # ❌ 常にNoneを返す
```

**After** (修正版):
```python
# src/api/dependencies.py
from src.security.jwt_service import JWTService
from src.security.exceptions import InvalidTokenError, ExpiredTokenError

jwt_service = JWTService()

async def get_current_user_optional(
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Optional authentication - returns None in dev mode"""
    if not settings.auth_enabled:
        return None  # 開発環境では認証スキップ

    if not authorization or not authorization.startswith("Bearer "):
        return None

    try:
        token = authorization.replace("Bearer ", "")
        payload = jwt_service.verify_token(token)

        if not payload:
            raise InvalidTokenError("Invalid token payload")

        user_id = payload.get("sub")
        if not user_id:
            raise InvalidTokenError("Missing user ID in token")

        # データベースからユーザー取得
        from src.services.auth_service import AuthService
        auth_service = AuthService(db)
        user = await auth_service.get_user_by_id(user_id)

        if not user:
            raise InvalidTokenError("User not found")

        return user

    except (ExpiredTokenError, InvalidTokenError) as e:
        logger.warning(f"Authentication failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected auth error: {e}")
        return None


async def get_current_user(
    user: Optional[User] = Depends(get_current_user_optional)
) -> User:
    """Required authentication - raises 401 if not authenticated"""
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user
```

**実行コマンド**:
```bash
# 1. ファイルを編集
vim src/api/dependencies.py

# 2. テスト実行
pytest tests/unit/test_auth_service.py -v

# 3. 動作確認
python -m pytest tests/integration/test_api_authentication.py -v
```

**検証方法**:
```bash
# 認証なしでアクセス（401エラーが返るべき）
curl -X GET http://localhost:8000/api/v1/memory/recall

# 正しいトークンでアクセス（成功するべき）
curl -X GET http://localhost:8000/api/v1/memory/recall \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

**チェックリスト**:
- [ ] `get_current_user_optional` を修正
- [ ] `get_current_user` を追加
- [ ] テスト実行（`test_auth_service.py`）
- [ ] 統合テスト実行
- [ ] 動作確認

---

### 2. 環境変数の安全な設定（1時間）

**問題**: 本番環境用の環境変数テンプレートが存在しない

**作成するファイル**: `.env.production.example`

**コピー&ペースト可能な内容**:

```bash
# .env.production.example
# ============================================
# TMWS Production Environment Configuration
# ============================================
# IMPORTANT: Generate secure values for all CHANGE_ME fields!

# === Core Settings ===
TMWS_ENVIRONMENT=production
TMWS_DEBUG=false

# === Security (CRITICAL - Change All Defaults!) ===
# Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
TMWS_SECRET_KEY=CHANGE_ME_TO_SECURE_32_CHAR_KEY

# Generate with: python -c "import secrets; print(secrets.token_urlsafe(64))"
TMWS_JWT_SECRET=CHANGE_ME_TO_SECURE_JWT_SECRET

# === Authentication ===
TMWS_AUTH_ENABLED=true
TMWS_JWT_EXPIRE_HOURS=24
TMWS_REFRESH_TOKEN_EXPIRE_DAYS=7

# === Database ===
# Use strong password: python -c "import secrets; print(secrets.token_urlsafe(24))"
TMWS_DATABASE_URL=postgresql://tmws_user:CHANGE_ME_SECURE_PASSWORD@localhost:5432/tmws_prod

# Connection pool settings
TMWS_DB_POOL_SIZE=10
TMWS_DB_MAX_OVERFLOW=20
TMWS_DB_POOL_RECYCLE=3600
TMWS_DB_POOL_PRE_PING=true

# === Redis ===
TMWS_REDIS_URL=redis://:CHANGE_ME_REDIS_PASSWORD@localhost:6379/0

# === API Settings ===
TMWS_API_HOST=0.0.0.0
TMWS_API_PORT=8000

# === CORS (Restrict to your domains) ===
TMWS_CORS_ORIGINS=["https://yourdomain.com"]
TMWS_CORS_CREDENTIALS=true

# === Rate Limiting ===
TMWS_RATE_LIMIT_ENABLED=true
TMWS_RATE_LIMIT_REQUESTS=100
TMWS_RATE_LIMIT_PERIOD=60

# === Security Headers ===
TMWS_FORCE_HTTPS=true
TMWS_HSTS_ENABLED=true
TMWS_HSTS_MAX_AGE=31536000

# === Logging ===
TMWS_LOG_LEVEL=INFO
TMWS_LOG_FORMAT=json

# === Embedding Model ===
TMWS_EMBEDDING_MODEL=all-MiniLM-L6-v2
TMWS_VECTOR_DIMENSION=384
```

**シークレット生成スクリプト**:

```python
# scripts/generate_secrets.py
"""Generate secure secrets for TMWS production"""
import secrets
from datetime import datetime

def generate_secret_key(length: int = 32) -> str:
    """Generate a secure random secret key"""
    return secrets.token_urlsafe(length)

def generate_all_secrets():
    """Generate all required secrets"""
    secrets_dict = {
        "TMWS_SECRET_KEY": generate_secret_key(32),
        "TMWS_JWT_SECRET": generate_secret_key(64),
        "DB_PASSWORD": generate_secret_key(24),
        "REDIS_PASSWORD": generate_secret_key(24),
    }

    print("# Generated Secrets for TMWS Production")
    print(f"# Generated on: {datetime.utcnow().isoformat()}")
    print("#")
    print("# IMPORTANT:")
    print("# 1. Store these securely (use password manager)")
    print("# 2. Never commit to version control")
    print("# 3. Use different values for each environment")
    print()

    for key, value in secrets_dict.items():
        print(f"{key}={value}")

if __name__ == "__main__":
    generate_all_secrets()
```

**実行コマンド**:
```bash
# 1. テンプレートファイル作成
cat > .env.production.example << 'EOF'
# ... 上記の内容をペースト ...
EOF

# 2. シークレット生成スクリプト作成
cat > scripts/generate_secrets.py << 'EOF'
# ... 上記のPythonコードをペースト ...
EOF

# 3. シークレット生成
python scripts/generate_secrets.py > .env.production.secrets

# 4. 生成されたシークレットを確認
cat .env.production.secrets

# 5. .env.production.secretsをgitignoreに追加
echo ".env.production.secrets" >> .gitignore
```

**チェックリスト**:
- [ ] `.env.production.example` 作成
- [ ] `scripts/generate_secrets.py` 作成
- [ ] シークレット生成実行
- [ ] `.gitignore` に追加
- [ ] ドキュメント更新

---

### 3. 基本的な入力検証の実装（2時間）

**問題**: XSS、SQLインジェクション対策が不足

**作成するファイル**: `src/security/validators.py`

**コピー&ペースト可能なコード**:

```python
# src/security/validators.py
"""Input validation and sanitization utilities"""
from typing import Optional
import re
from html import escape
from src.core.exceptions import ValidationError

class InputValidator:
    """Comprehensive input validation utility"""

    # 危険なHTMLパターン
    DANGEROUS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',  # onclick, onload, etc.
        r'<iframe',
        r'<object',
        r'<embed',
    ]

    # SQLインジェクションパターン
    SQL_INJECTION_PATTERNS = [
        r'(\bUNION\b.*\bSELECT\b)',
        r'(\bOR\b.*=.*)',
        r'(;.*DROP\b.*TABLE)',
        r'(--)',
        r'(\/\*.*\*\/)',
    ]

    def validate_string(
        self,
        value: str,
        field_name: str,
        min_length: int = 0,
        max_length: int = 1000,
        allow_html: bool = False,
        pattern: Optional[str] = None
    ) -> str:
        """文字列の検証とサニタイゼーション"""

        # 長さチェック
        if len(value) < min_length:
            raise ValidationError(
                f"{field_name} must be at least {min_length} characters"
            )

        if len(value) > max_length:
            raise ValidationError(
                f"{field_name} must not exceed {max_length} characters"
            )

        # XSS対策
        if not allow_html:
            if self._contains_dangerous_html(value):
                raise ValidationError(
                    f"{field_name} contains potentially dangerous content"
                )
            # HTMLエスケープ
            value = escape(value)

        # SQLインジェクション対策
        if self._contains_sql_injection(value):
            raise ValidationError(
                f"{field_name} contains potentially malicious SQL"
            )

        # カスタムパターンマッチング
        if pattern and not re.match(pattern, value):
            raise ValidationError(
                f"{field_name} does not match required format"
            )

        return value

    def _contains_dangerous_html(self, value: str) -> bool:
        """危険なHTMLパターンの検出"""
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False

    def _contains_sql_injection(self, value: str) -> bool:
        """SQLインジェクションパターンの検出"""
        for pattern in self.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False
```

**APIエンドポイントへの適用**:

```python
# src/api/routers/memory.py
from src.security.validators import InputValidator

validator = InputValidator()

@router.post("/store")
async def store_memory(
    request: MemoryRequest,
    current_user: User = Depends(get_current_user)
):
    # ✅ 入力検証を追加
    validated_content = validator.validate_string(
        request.content,
        field_name="content",
        min_length=1,
        max_length=10000,
        allow_html=False
    )

    # importanceの範囲チェック
    if not 0.0 <= request.importance <= 1.0:
        raise ValidationError("importance must be between 0.0 and 1.0")

    # メモリ作成
    memory = await memory_service.create_memory(
        content=validated_content,
        importance=request.importance,
        user_id=current_user.id
    )

    return memory
```

**実行コマンド**:
```bash
# 1. ファイル作成
cat > src/security/validators.py << 'EOF'
# ... 上記のPythonコードをペースト ...
EOF

# 2. memory.pyを編集
vim src/api/routers/memory.py
# 上記の修正を適用

# 3. テスト実行
pytest tests/unit/test_input_validator.py -v

# 4. 統合テスト
pytest tests/integration/test_api_memory.py -v
```

**テストコード** (コピー&ペースト可能):

```python
# tests/unit/test_input_validator.py
import pytest
from src.security.validators import InputValidator
from src.core.exceptions import ValidationError

@pytest.fixture
def validator():
    return InputValidator()

def test_xss_detection(validator):
    """XSS攻撃の検出"""
    malicious = "<script>alert('XSS')</script>"

    with pytest.raises(ValidationError, match="dangerous content"):
        validator.validate_string(malicious, "test", allow_html=False)

def test_sql_injection_detection(validator):
    """SQLインジェクション検出"""
    malicious = "'; DROP TABLE users; --"

    with pytest.raises(ValidationError, match="malicious SQL"):
        validator.validate_string(malicious, "test")

def test_valid_string(validator):
    """正常な文字列"""
    result = validator.validate_string(
        "This is a safe string",
        "test",
        min_length=5,
        max_length=100
    )

    assert "This is a safe string" in result
```

**チェックリスト**:
- [ ] `src/security/validators.py` 作成
- [ ] 全APIエンドポイントに適用
- [ ] テストコード作成
- [ ] テスト実行
- [ ] 動作確認

---

### 4. HTTPS強制設定（30分）

**問題**: HTTP通信が許可されている

**作成するファイル**: `src/api/middleware/https_redirect.py`

**コピー&ペースト可能なコード**:

```python
# src/api/middleware/https_redirect.py
"""HTTPS enforcement middleware"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse
from src.core.config import settings

class HTTPSRedirectMiddleware(BaseHTTPMiddleware):
    """Force HTTPS in production"""

    async def dispatch(self, request, call_next):
        # 開発環境ではスキップ
        if not settings.force_https:
            return await call_next(request)

        # ヘルスチェックはHTTPを許可
        if request.url.path in ["/health", "/metrics"]:
            return await call_next(request)

        # HTTPSでなければリダイレクト
        if request.url.scheme != "https":
            url = request.url.replace(scheme="https")
            return RedirectResponse(url, status_code=301)

        # HSTSヘッダーを追加
        response = await call_next(request)

        if settings.hsts_enabled:
            response.headers["Strict-Transport-Security"] = (
                f"max-age={settings.hsts_max_age}; "
                "includeSubDomains; preload"
            )

        return response
```

**main.pyへの適用**:

```python
# src/main.py
from src.api.middleware.https_redirect import HTTPSRedirectMiddleware

app = FastAPI(title="TMWS")

# ✅ HTTPS強制ミドルウェア追加
app.add_middleware(HTTPSRedirectMiddleware)
```

**設定の追加** (`src/core/config.py`):

```python
# src/core/config.py
class Settings(BaseSettings):
    # ... 既存設定 ...

    # HTTPS enforcement
    force_https: bool = Field(False, env="TMWS_FORCE_HTTPS")
    hsts_enabled: bool = Field(True, env="TMWS_HSTS_ENABLED")
    hsts_max_age: int = Field(31536000, env="TMWS_HSTS_MAX_AGE")  # 1年
```

**実行コマンド**:
```bash
# 1. ミドルウェア作成
mkdir -p src/api/middleware
cat > src/api/middleware/https_redirect.py << 'EOF'
# ... 上記のPythonコードをペースト ...
EOF

# 2. main.pyを編集
vim src/main.py
# HTTPSRedirectMiddlewareを追加

# 3. config.pyを編集
vim src/core/config.py
# HTTPS設定を追加

# 4. 環境変数設定
export TMWS_FORCE_HTTPS=true
export TMWS_HSTS_ENABLED=true

# 5. サーバー起動
python -m src.main

# 6. 動作確認
curl -I http://localhost:8000/health
# → 301 Redirect to https://localhost:8000/health
```

**チェックリスト**:
- [ ] `https_redirect.py` 作成
- [ ] `main.py` に適用
- [ ] `config.py` に設定追加
- [ ] 環境変数設定
- [ ] 動作確認

---

## 🟡 Priority 1: 今週実施すべき修正（HIGH）

これらは今週中に対応してください。

---

### 5. コード重複の解消（3日）

**問題**: `src/` と `tmws/` の完全重複

**実行手順**:

```bash
# Day 1: バックアップと準備
git checkout -b refactor/consolidate-source-tree
git tag backup-before-consolidation

# バックアップ作成
cp -r tmws tmws.backup

# Day 2: 重複削除
rm -rf tmws/

# pyproject.toml更新
# [tool.setuptools.packages.find]
# where = ["."]
# include = ["src*"]

# Day 3: テストと検証
pytest tests/ -v

# 問題なければコミット
git add -A
git commit -m "refactor: Consolidate to single source tree (src/)"
git push origin refactor/consolidate-source-tree
```

**検証コマンド**:
```bash
# tmws.*からのimportがないことを確認
grep -r "from tmws" . --include="*.py" || echo "✅ No tmws imports found"

# すべてのテストが通ることを確認
pytest tests/ -v --tb=short

# カバレッジ確認
pytest --cov=src --cov-report=term tests/
```

**チェックリスト**:
- [ ] バックアップ作成
- [ ] `tmws/` 削除
- [ ] `pyproject.toml` 更新
- [ ] import確認
- [ ] テスト実行
- [ ] コミット

---

### 6. データベースプールの最適化（1日）

**問題**: `NullPool`使用でパフォーマンス低下

**修正箇所**: `src/core/database.py`

**Before** (現状):
```python
# src/core/database.py
engine = create_async_engine(
    DATABASE_URL,
    poolclass=NullPool,  # ❌ プーリング無効
    echo=False
)
```

**After** (修正版):
```python
# src/core/database.py
from sqlalchemy.pool import QueuePool

class DatabaseManager:
    def _create_engine(self):
        """最適化されたエンジン作成"""
        if settings.environment == "production":
            pool_config = {
                "poolclass": QueuePool,
                "pool_size": 10,
                "max_overflow": 20,
                "pool_recycle": 3600,
                "pool_pre_ping": True,
                "pool_timeout": 30
            }
        else:
            pool_config = {
                "poolclass": QueuePool,
                "pool_size": 5,
                "max_overflow": 10,
                "pool_recycle": 3600,
                "pool_pre_ping": True
            }

        return create_async_engine(
            settings.database_url,
            **pool_config,
            echo=settings.debug
        )
```

**設定追加** (`src/core/config.py`):
```python
# src/core/config.py
class Settings(BaseSettings):
    # Database pool settings
    db_pool_size: int = Field(10, env="TMWS_DB_POOL_SIZE")
    db_max_overflow: int = Field(20, env="TMWS_DB_MAX_OVERFLOW")
    db_pool_recycle: int = Field(3600, env="TMWS_DB_POOL_RECYCLE")
    db_pool_pre_ping: bool = Field(True, env="TMWS_DB_POOL_PRE_PING")
```

**チェックリスト**:
- [ ] `database.py` 修正
- [ ] `config.py` に設定追加
- [ ] テスト実行
- [ ] パフォーマンステスト

---

### 7. 無効化テストの修正（2日）

**問題**: 14個のテストが無効化されている

**実行スクリプト**:

```bash
#!/bin/bash
# scripts/reactivate_tests.sh

cd tests/unit

echo "Reactivating disabled tests..."

for file in _test_*.py; do
    if [[ -f "$file" ]]; then
        new_name="${file/_test_/test_}"
        mv "$file" "$new_name"
        echo "✅ Reactivated: $new_name"
    fi
done

echo -e "\nTesting each file..."

for file in test_*.py; do
    echo "Testing $file..."
    pytest "$file" -v --tb=line || echo "  ❌ Failed: $file"
done
```

**実行コマンド**:
```bash
# 1. スクリプト実行
chmod +x scripts/reactivate_tests.sh
./scripts/reactivate_tests.sh

# 2. 失敗したテストを修正
# (各テストファイルの修正内容はROADMAP参照)

# 3. 全テスト実行
pytest tests/ -v

# 4. カバレッジ確認
pytest --cov=src --cov-report=html tests/
open htmlcov/index.html
```

**チェックリスト**:
- [ ] 再有効化スクリプト実行
- [ ] 失敗テストの修正
- [ ] テストカバレッジ80%達成
- [ ] HTMLレポート確認

---

### 8. レート制限の有効化（1日）

**問題**: DoS攻撃への耐性が不足

**実装** (既存の`UnifiedSecurityMiddleware`を活用):

```python
# src/api/middleware/security_middleware.py
# 既存のレート制限機能を有効化

# .env設定
TMWS_RATE_LIMIT_ENABLED=true
TMWS_RATE_LIMIT_REQUESTS=100
TMWS_RATE_LIMIT_PERIOD=60
```

**検証コマンド**:
```bash
# レート制限テスト
for i in {1..110}; do
  curl -X GET http://localhost:8000/health
  echo "Request $i"
done

# 101番目以降は429 Too Many Requestsが返るべき
```

**チェックリスト**:
- [ ] 環境変数設定
- [ ] レート制限有効化
- [ ] テスト実行
- [ ] 動作確認

---

## 📊 進捗確認チェックリスト

### 今日の終了時（Priority 0完了）
- [ ] 認証システムが動作する
- [ ] 環境変数テンプレートが存在する
- [ ] 入力検証が実装されている
- [ ] HTTPS強制が動作する

### 今週の終了時（Priority 1完了）
- [ ] コード重複が解消されている
- [ ] データベースプールが最適化されている
- [ ] 無効化テストが修正されている
- [ ] レート制限が有効化されている

### 成功指標
- セキュリティスコア: 2/10 → 6/10
- テストカバレッジ: 65% → 75%
- デプロイ可能性: 不可 → 開発環境で可

---

## 🆘 トラブルシューティング

### 認証テストが失敗する場合

```bash
# JWT_SECRETが設定されているか確認
echo $TMWS_JWT_SECRET

# 設定されていなければ生成
export TMWS_JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(64))")

# テスト再実行
pytest tests/unit/test_jwt_service.py -v
```

### データベース接続エラーの場合

```bash
# PostgreSQLが起動しているか確認
pg_isready

# データベースが存在するか確認
psql -U postgres -c "\l"

# データベース作成
createdb tmws_dev

# マイグレーション実行
alembic upgrade head
```

### テストが失敗する場合

```bash
# 詳細なエラーメッセージを表示
pytest tests/ -vv --tb=long

# 特定のテストのみ実行
pytest tests/unit/test_specific.py::test_function_name -vv

# デバッグモード
pytest tests/ --pdb
```

---

## 📞 サポート

問題が発生した場合:
1. エラーメッセージをコピー
2. 実行したコマンドを記録
3. 環境情報を確認（Python version, OS, etc.）
4. GitHubのIssueに報告

---

**次のステップ**: `REFACTORING_ROADMAP.md`で全体計画を確認
**ドキュメント**: `CODE_QUALITY_AUDIT_REPORT.md`で詳細な問題分析を確認
