# TMWS リファクタリング・ロードマップ

**バージョン**: v2.2.0 → v2.3.0
**期間**: 6週間（2025-01-10 〜 2025-02-20）
**目標**: エンタープライズグレードの品質達成

---

## 📋 ロードマップ概要

```
Week 1: セキュリティ緊急対応（P0問題の解決）
Week 2-3: 構造整理とテスト品質向上（P1問題の解決）
Week 4-6: 本番運用準備（P2問題とエンハンスメント）
```

**重点領域**:
1. セキュリティ強化
2. コード重複の解消
3. テストカバレッジの向上
4. 本番環境の整備

---

## Week 1: セキュリティ緊急対応

### Day 1-2: 認証システムの実装

#### 目標
JWT認証を完全に実装し、全APIエンドポイントを保護する

#### タスク

**1. JWT検証ロジックの実装**

**Before**（現状 - 未実装）:
```python
# src/api/dependencies.py
async def get_current_user_optional(
    authorization: Optional[str] = Header(None)
) -> Optional[User]:
    if not authorization:
        return None

    # TODO: Implement JWT validation when auth is enabled
    return None  # 常にNoneを返す
```

**After**（修正後）:
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

        if not user.is_active:
            raise InvalidTokenError("User is inactive")

        return user

    except ExpiredTokenError:
        logger.warning(f"Expired token attempt: {authorization[:20]}...")
        return None
    except InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
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

**2. JWT Service の強化**

```python
# src/security/jwt_service.py
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import jwt, JWTError
from src.core.config import settings

class JWTService:
    def __init__(self):
        self.secret_key = settings.jwt_secret
        self.algorithm = "HS256"
        self.access_token_expire = timedelta(hours=24)
        self.refresh_token_expire = timedelta(days=7)

    def create_access_token(
        self,
        user_id: str,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """アクセストークン生成"""
        expire = datetime.utcnow() + self.access_token_expire

        claims = {
            "sub": user_id,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        }

        if additional_claims:
            claims.update(additional_claims)

        return jwt.encode(claims, self.secret_key, algorithm=self.algorithm)

    def create_refresh_token(self, user_id: str) -> str:
        """リフレッシュトークン生成"""
        expire = datetime.utcnow() + self.refresh_token_expire

        claims = {
            "sub": user_id,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh"
        }

        return jwt.encode(claims, self.secret_key, algorithm=self.algorithm)

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """トークン検証"""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )

            # トークンタイプ確認
            token_type = payload.get("type")
            if token_type not in ["access", "refresh"]:
                raise InvalidTokenError("Invalid token type")

            # 有効期限確認
            exp = payload.get("exp")
            if not exp or datetime.fromtimestamp(exp) < datetime.utcnow():
                raise ExpiredTokenError("Token has expired")

            return payload

        except JWTError as e:
            logger.error(f"JWT verification failed: {e}")
            raise InvalidTokenError(f"Token verification failed: {e}")
```

**3. テストコード**

```python
# tests/unit/test_jwt_service.py
import pytest
from datetime import datetime, timedelta
from src.security.jwt_service import JWTService
from src.security.exceptions import InvalidTokenError, ExpiredTokenError

@pytest.fixture
def jwt_service():
    return JWTService()

class TestJWTService:
    def test_create_access_token(self, jwt_service):
        """アクセストークン生成のテスト"""
        user_id = "user_123"
        token = jwt_service.create_access_token(user_id)

        assert token is not None
        assert isinstance(token, str)

        # トークンを検証
        payload = jwt_service.verify_token(token)
        assert payload["sub"] == user_id
        assert payload["type"] == "access"

    def test_verify_valid_token(self, jwt_service):
        """有効なトークンの検証テスト"""
        user_id = "user_123"
        token = jwt_service.create_access_token(user_id)

        payload = jwt_service.verify_token(token)
        assert payload["sub"] == user_id

    def test_verify_expired_token(self, jwt_service, monkeypatch):
        """期限切れトークンの検証テスト"""
        # トークンを即座に期限切れにする
        monkeypatch.setattr(
            jwt_service,
            "access_token_expire",
            timedelta(seconds=-1)
        )

        user_id = "user_123"
        token = jwt_service.create_access_token(user_id)

        with pytest.raises(ExpiredTokenError):
            jwt_service.verify_token(token)

    def test_verify_invalid_token(self, jwt_service):
        """無効なトークンの検証テスト"""
        with pytest.raises(InvalidTokenError):
            jwt_service.verify_token("invalid.token.here")
```

#### チェックリスト

- [ ] JWT検証ロジックの実装
- [ ] アクセストークン生成機能
- [ ] リフレッシュトークン生成機能
- [ ] トークン検証の単体テスト
- [ ] エンドツーエンドのテスト
- [ ] エラーハンドリングの実装
- [ ] ドキュメント更新

---

### Day 3-4: 環境設定とシークレット管理

#### 目標
本番環境で安全に使用できる環境変数テンプレートと設定ガイドを作成

#### タスク

**1. 本番用環境変数テンプレート**

```bash
# .env.production.example
# ============================================
# TMWS Production Environment Configuration
# ============================================

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
TMWS_DATABASE_URL=postgresql://tmws_user:SECURE_PASSWORD@db-host:5432/tmws_prod

# Connection pool settings
TMWS_DB_POOL_SIZE=10
TMWS_DB_MAX_OVERFLOW=20
TMWS_DB_POOL_RECYCLE=3600
TMWS_DB_POOL_PRE_PING=true

# === Redis ===
TMWS_REDIS_URL=redis://:REDIS_PASSWORD@redis-host:6379/0
TMWS_REDIS_SSL=true

# === API Settings ===
TMWS_API_HOST=0.0.0.0
TMWS_API_PORT=8000

# === CORS (Restrict to your domains) ===
TMWS_CORS_ORIGINS=["https://yourdomain.com","https://api.yourdomain.com"]
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
TMWS_LOG_FILE=/var/log/tmws/app.log

# === Monitoring ===
TMWS_METRICS_ENABLED=true
TMWS_METRICS_PORT=9090

# === Embedding Model ===
TMWS_EMBEDDING_MODEL=all-MiniLM-L6-v2
TMWS_VECTOR_DIMENSION=384
```

**2. シークレットキー生成スクリプト**

```python
# scripts/generate_secrets.py
"""
Secure secret generation script for TMWS production environment
"""
import secrets
import string
from pathlib import Path
from typing import Dict

def generate_secret_key(length: int = 32) -> str:
    """Generate a secure random secret key"""
    return secrets.token_urlsafe(length)

def generate_password(length: int = 24) -> str:
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def generate_all_secrets() -> Dict[str, str]:
    """Generate all required secrets for production"""
    return {
        "TMWS_SECRET_KEY": generate_secret_key(32),
        "TMWS_JWT_SECRET": generate_secret_key(64),
        "DB_PASSWORD": generate_password(24),
        "REDIS_PASSWORD": generate_password(24),
    }

def save_secrets_template(secrets: Dict[str, str], output_file: str):
    """Save secrets to a template file"""
    template = f"""# Generated Secrets for TMWS Production
# Generated on: {datetime.utcnow().isoformat()}
#
# IMPORTANT:
# 1. Store these securely (use password manager or secrets vault)
# 2. Never commit this file to version control
# 3. Use environment-specific values for each deployment

"""
    for key, value in secrets.items():
        template += f"{key}={value}\n"

    Path(output_file).write_text(template)
    print(f"✅ Secrets saved to: {output_file}")
    print(f"⚠️  Keep this file secure and never commit to git!")

if __name__ == "__main__":
    secrets_dict = generate_all_secrets()
    save_secrets_template(secrets_dict, ".env.production.secrets")

    print("\n🔑 Generated Secrets:")
    for key in secrets_dict.keys():
        print(f"  - {key}")
```

**使用方法**:
```bash
# シークレット生成
python scripts/generate_secrets.py

# 生成されたファイルを確認
cat .env.production.secrets

# 本番環境に適用
cp .env.production.secrets /etc/tmws/.env
chmod 600 /etc/tmws/.env
```

**3. 設定検証スクリプト**

```python
# scripts/validate_production_config.py
"""
Validate production configuration before deployment
"""
import os
import sys
from pathlib import Path
from typing import List, Tuple

class ConfigValidator:
    def __init__(self, env_file: str = ".env"):
        self.env_file = env_file
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def load_env(self) -> Dict[str, str]:
        """Load environment variables from file"""
        env_vars = {}
        if Path(self.env_file).exists():
            with open(self.env_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        env_vars[key] = value
        return env_vars

    def validate(self) -> bool:
        """Run all validation checks"""
        env_vars = self.load_env()

        # Critical checks
        self.check_secret_keys(env_vars)
        self.check_database_url(env_vars)
        self.check_cors_origins(env_vars)

        # Warning checks
        self.check_rate_limiting(env_vars)
        self.check_https_settings(env_vars)

        # Print results
        self.print_results()

        return len(self.errors) == 0

    def check_secret_keys(self, env_vars: Dict[str, str]):
        """Validate secret keys"""
        keys_to_check = ["TMWS_SECRET_KEY", "TMWS_JWT_SECRET"]

        for key in keys_to_check:
            value = env_vars.get(key, "")

            if not value or "CHANGE_ME" in value:
                self.errors.append(
                    f"{key} is not set or using default value"
                )
            elif len(value) < 32:
                self.errors.append(
                    f"{key} is too short (minimum 32 characters)"
                )

    def check_database_url(self, env_vars: Dict[str, str]):
        """Validate database URL"""
        db_url = env_vars.get("TMWS_DATABASE_URL", "")

        if not db_url:
            self.errors.append("TMWS_DATABASE_URL is not set")
            return

        if "postgres:postgres" in db_url:
            self.errors.append(
                "Using default database credentials (postgres:postgres)"
            )

        if "localhost" in db_url:
            self.warnings.append(
                "Database URL points to localhost (may be intentional)"
            )

    def check_cors_origins(self, env_vars: Dict[str, str]):
        """Validate CORS settings"""
        cors_origins = env_vars.get("TMWS_CORS_ORIGINS", "")

        if not cors_origins or cors_origins == '["*"]':
            self.errors.append(
                "CORS origins allow all domains (security risk)"
            )

    def check_rate_limiting(self, env_vars: Dict[str, str]):
        """Check rate limiting settings"""
        enabled = env_vars.get("TMWS_RATE_LIMIT_ENABLED", "false")

        if enabled.lower() != "true":
            self.warnings.append(
                "Rate limiting is disabled (recommended for production)"
            )

    def check_https_settings(self, env_vars: Dict[str, str]):
        """Check HTTPS enforcement"""
        force_https = env_vars.get("TMWS_FORCE_HTTPS", "false")

        if force_https.lower() != "true":
            self.warnings.append(
                "HTTPS is not enforced (required for production)"
            )

    def print_results(self):
        """Print validation results"""
        print("\n" + "="*60)
        print("TMWS Production Configuration Validation")
        print("="*60 + "\n")

        if self.errors:
            print("❌ ERRORS (Must fix before deployment):")
            for error in self.errors:
                print(f"  - {error}")
            print()

        if self.warnings:
            print("⚠️  WARNINGS (Recommended fixes):")
            for warning in self.warnings:
                print(f"  - {warning}")
            print()

        if not self.errors and not self.warnings:
            print("✅ All checks passed!")
        elif not self.errors:
            print("✅ No critical errors, but review warnings")
        else:
            print("❌ Configuration validation failed")
            print("   Fix all errors before deploying to production")

if __name__ == "__main__":
    validator = ConfigValidator(".env.production")

    if not validator.validate():
        sys.exit(1)  # Exit with error code

    sys.exit(0)  # Success
```

#### チェックリスト

- [ ] 本番用環境変数テンプレート作成
- [ ] シークレット生成スクリプト作成
- [ ] 設定検証スクリプト作成
- [ ] セキュリティ設定ガイド作成
- [ ] 環境変数ドキュメント更新

---

### Day 5-7: 入力検証とHTTPS

#### 目標
全APIエンドポイントに入力検証を追加し、HTTPS通信を強制

#### タスク

**1. 入力検証ユーティリティの作成**

```python
# src/security/validators.py
from typing import Optional, List
import re
from html import escape
from src.core.exceptions import ValidationError

class InputValidator:
    """Comprehensive input validation utility"""

    # 危険なHTMLタグとスクリプト検出
    DANGEROUS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',  # onclick, onload, etc.
        r'<iframe',
        r'<object',
        r'<embed',
    ]

    # SQLインジェクション検出
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

    def validate_email(self, email: str) -> str:
        """メールアドレスの検証"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

        if not re.match(pattern, email):
            raise ValidationError("Invalid email format")

        return email.lower()

    def validate_url(self, url: str, allowed_schemes: List[str] = ["https"]) -> str:
        """URLの検証"""
        from urllib.parse import urlparse

        parsed = urlparse(url)

        if parsed.scheme not in allowed_schemes:
            raise ValidationError(
                f"URL must use one of: {', '.join(allowed_schemes)}"
            )

        if not parsed.netloc:
            raise ValidationError("Invalid URL format")

        return url

    def validate_json(self, data: dict, max_depth: int = 5) -> dict:
        """JSONデータの検証"""
        current_depth = self._get_json_depth(data)

        if current_depth > max_depth:
            raise ValidationError(
                f"JSON nesting too deep (max {max_depth} levels)"
            )

        return data

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

    def _get_json_depth(self, obj, current_depth: int = 0) -> int:
        """JSON構造の深さを取得"""
        if not isinstance(obj, (dict, list)):
            return current_depth

        if isinstance(obj, dict):
            if not obj:
                return current_depth
            return max(
                self._get_json_depth(v, current_depth + 1)
                for v in obj.values()
            )

        if isinstance(obj, list):
            if not obj:
                return current_depth
            return max(
                self._get_json_depth(item, current_depth + 1)
                for item in obj
            )
```

**2. APIエンドポイントへの適用**

**Before**:
```python
# src/api/routers/memory.py
@router.post("/store")
async def store_memory(request: MemoryRequest):
    # 入力検証なし
    memory = await memory_service.create_memory(
        content=request.content,
        importance=request.importance
    )
    return memory
```

**After**:
```python
# src/api/routers/memory.py
from src.security.validators import InputValidator

validator = InputValidator()

@router.post("/store")
async def store_memory(
    request: MemoryRequest,
    current_user: User = Depends(get_current_user)
):
    # 入力検証を追加
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

    # メタデータの検証
    if request.metadata:
        validator.validate_json(request.metadata, max_depth=5)

    memory = await memory_service.create_memory(
        content=validated_content,
        importance=request.importance,
        metadata=request.metadata,
        user_id=current_user.id
    )

    return memory
```

**3. HTTPS強制ミドルウェア**

```python
# src/api/middleware/https_redirect.py
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

**適用**:
```python
# src/main.py
from src.api.middleware.https_redirect import HTTPSRedirectMiddleware

app = FastAPI()
app.add_middleware(HTTPSRedirectMiddleware)
```

#### チェックリスト

- [ ] 入力検証ユーティリティの実装
- [ ] 全APIエンドポイントに検証を追加
- [ ] HTTPS強制ミドルウェアの実装
- [ ] HSTSヘッダーの設定
- [ ] セキュリティテストの実行
- [ ] ドキュメント更新

---

## Week 2: 構造整理 - コード重複解消

### 目標
`src/` と `tmws/` の重複を解消し、単一のソースツリーに統合

### タスク

#### 1. 統合戦略の決定

**選択肢A**: `src/` を削除、`tmws/` を使用
- メリット: パッケージ名がプロジェクト名と一致
- デメリット: 既存のimportを大幅に変更

**選択肢B**: `tmws/` を削除、`src/` を使用（推奨）
- メリット: 最小限の変更で対応可能
- デメリット: パッケージ名が`src`になる

**決定**: 選択肢Bを採用

#### 2. 実行手順

```bash
# Step 1: バックアップ作成
git checkout -b refactor/consolidate-source-tree
cp -r tmws tmws.backup

# Step 2: tmws/を削除
rm -rf tmws/

# Step 3: pyproject.tomlを更新
# [tool.setuptools.packages.find]
# where = ["."]
# include = ["src*"]

# Step 4: import文の確認（tmws.*からのimportがないことを確認）
grep -r "from tmws" . --include="*.py" || echo "No tmws imports found"

# Step 5: テスト実行
pytest tests/ -v

# Step 6: 問題なければコミット
git add -A
git commit -m "refactor: Consolidate to single source tree (src/)"
```

#### 3. データベースマネージャーの統合

**現状の3つの実装**:
- `src/core/database.py` - 基本実装（使用中）
- `src/core/database_enhanced.py` - 拡張版
- `src/core/unified_database.py` - 統合試行版

**統合手順**:

```python
# Step 1: database.pyに最適化機能を移植
# src/core/database.py

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool, QueuePool
from src.core.config import settings

class DatabaseManager:
    """統合データベースマネージャー"""

    def __init__(self):
        self.engine = self._create_engine()
        self.SessionLocal = sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

    def _create_engine(self):
        """最適化されたエンジン作成"""
        pool_config = self._get_pool_config()

        return create_async_engine(
            settings.database_url,
            **pool_config,
            echo=settings.debug,
            future=True
        )

    def _get_pool_config(self) -> dict:
        """環境に応じたプール設定"""
        if settings.environment == "production":
            return {
                "poolclass": QueuePool,
                "pool_size": settings.db_pool_size,
                "max_overflow": settings.db_max_overflow,
                "pool_recycle": settings.db_pool_recycle,
                "pool_pre_ping": settings.db_pool_pre_ping
            }
        else:
            # 開発環境では接続数を抑える
            return {
                "poolclass": QueuePool,
                "pool_size": 5,
                "max_overflow": 10,
                "pool_recycle": 3600,
                "pool_pre_ping": True
            }

    async def get_session(self) -> AsyncSession:
        """セッション取得"""
        async with self.SessionLocal() as session:
            yield session

    async def health_check(self) -> bool:
        """データベース接続確認"""
        try:
            async with self.SessionLocal() as session:
                await session.execute("SELECT 1")
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

# グローバルインスタンス
db_manager = DatabaseManager()

async def get_db() -> AsyncSession:
    """FastAPI Dependency"""
    async for session in db_manager.get_session():
        yield session
```

```bash
# Step 2: 他のマネージャーを使用しているコードを更新
# src/services/batch_service.py
# Before:
# from src.core.database_enhanced import DatabaseManager

# After:
# from src.core.database import db_manager

# Step 3: 古いファイルを削除
git rm src/core/database_enhanced.py
git rm src/core/unified_database.py

# Step 4: テスト実行
pytest tests/unit/test_database.py -v

# Step 5: コミット
git commit -m "refactor: Consolidate database managers"
```

#### チェックリスト

- [ ] バックアップ作成
- [ ] tmws/ディレクトリの削除
- [ ] pyproject.tomlの更新
- [ ] データベースマネージャーの統合
- [ ] 全サービスのimport更新
- [ ] テスト実行と検証
- [ ] コミット

---

## Week 3: テスト品質向上

### 目標
無効化されたテストを修正し、テストカバレッジ80%を達成

### タスク

#### 1. 無効化テストの再有効化

**無効化されたテストファイル**（14個）:
```
tests/unit/
├── _test_agent_memory_tools.py
├── _test_api_router_functions.py
├── _test_base_tool.py
├── _test_batch_service.py
├── _test_core_exceptions.py
├── _test_coverage_boost.py
├── _test_graceful_shutdown.py
├── _test_html_sanitizer.py
├── _test_learning_service.py
├── _test_log_cleanup_service.py
├── _test_service_manager.py
├── _test_simple_mocks.py
├── _test_statistics_service.py
└── _test_utils.py
```

**再有効化スクリプト**:
```bash
#!/bin/bash
# scripts/reactivate_tests.sh

cd tests/unit

for file in _test_*.py; do
    if [[ -f "$file" ]]; then
        new_name="${file/_test_/test_}"
        mv "$file" "$new_name"
        echo "Reactivated: $new_name"
    fi
done

# 各テストを実行して失敗を確認
for file in test_*.py; do
    echo "Testing $file..."
    pytest "$file" -v || echo "  ❌ Failed: $file"
done
```

**テスト修正の例**:

```python
# Before: tests/unit/_test_batch_service.py（無効化されていた）
# 失敗理由: database_enhanced.pyへの依存

# After: tests/unit/test_batch_service.py（修正版）
import pytest
from unittest.mock import AsyncMock, MagicMock
from src.services.batch_service import BatchService
# 修正: database.pyに変更
from src.core.database import db_manager

@pytest.fixture
async def batch_service(db_session):
    """BatchServiceのフィクスチャ"""
    service = BatchService(db_session)
    return service

@pytest.mark.asyncio
async def test_batch_create_memories(batch_service):
    """バッチメモリ作成のテスト"""
    memories_data = [
        {"content": "Test memory 1", "importance": 0.8},
        {"content": "Test memory 2", "importance": 0.7},
    ]

    results = await batch_service.batch_create_memories(memories_data)

    assert len(results) == 2
    assert all(r.content for r in results)
```

#### 2. テストカバレッジの測定と改善

```bash
# カバレッジ測定
pytest --cov=src --cov-report=html --cov-report=term tests/

# カバレッジレポート確認
open htmlcov/index.html

# 目標: 80%以上
```

**カバレッジギャップの特定と対応**:

```python
# 未テストのセキュリティ機能をテスト
# tests/unit/test_input_validator.py

import pytest
from src.security.validators import InputValidator
from src.core.exceptions import ValidationError

@pytest.fixture
def validator():
    return InputValidator()

class TestInputValidator:
    def test_validate_string_xss_detection(self, validator):
        """XSS攻撃の検出テスト"""
        malicious_input = "<script>alert('XSS')</script>"

        with pytest.raises(ValidationError, match="dangerous content"):
            validator.validate_string(
                malicious_input,
                field_name="test",
                allow_html=False
            )

    def test_validate_string_sql_injection_detection(self, validator):
        """SQLインジェクション検出テスト"""
        malicious_input = "'; DROP TABLE users; --"

        with pytest.raises(ValidationError, match="malicious SQL"):
            validator.validate_string(
                malicious_input,
                field_name="test"
            )

    def test_validate_email_valid(self, validator):
        """正常なメールアドレス検証"""
        email = "user@example.com"
        result = validator.validate_email(email)

        assert result == email

    def test_validate_email_invalid(self, validator):
        """不正なメールアドレス検証"""
        with pytest.raises(ValidationError, match="Invalid email"):
            validator.validate_email("not-an-email")

    def test_validate_url_https_only(self, validator):
        """HTTPS URLのみ許可"""
        # 正常なHTTPS URL
        https_url = "https://example.com"
        result = validator.validate_url(https_url)
        assert result == https_url

        # HTTP URLは拒否
        http_url = "http://example.com"
        with pytest.raises(ValidationError, match="must use one of"):
            validator.validate_url(http_url)
```

#### 3. CI/CDパイプライン整備

```yaml
# .github/workflows/test-suite.yml
name: Test Suite

on:
  push:
    branches: [ master, develop ]
  pull_request:
    branches: [ master, develop ]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:15-alpine
        env:
          POSTGRES_DB: tmws_test
          POSTGRES_USER: test_user
          POSTGRES_PASSWORD: test_password
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

      redis:
        image: redis:7-alpine
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'

    - name: Install dependencies
      run: |
        pip install -e ".[dev]"

    - name: Run linting
      run: |
        ruff check src/
        black --check src/

    - name: Run tests with coverage
      env:
        TMWS_DATABASE_URL: postgresql://test_user:test_password@localhost:5432/tmws_test
        TMWS_REDIS_URL: redis://localhost:6379/0
        TMWS_AUTH_ENABLED: false
      run: |
        pytest --cov=src --cov-report=xml --cov-report=term tests/

    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        files: ./coverage.xml
        fail_ci_if_error: true

    - name: Check coverage threshold
      run: |
        coverage report --fail-under=80
```

#### チェックリスト

- [ ] 無効化テストの再有効化スクリプト実行
- [ ] 各テストファイルの修正
- [ ] セキュリティ機能のテスト追加
- [ ] カバレッジ80%達成
- [ ] CI/CDパイプライン整備
- [ ] テストドキュメント更新

---

## Week 4: データベース最適化

### 目標
接続プールを適切に設定し、パフォーマンステストで検証

### タスク

#### 1. 接続プール設定の最適化

**設定追加**:
```python
# src/core/config.py
class Settings(BaseSettings):
    # ... 既存設定 ...

    # Database pool settings
    db_pool_size: int = Field(10, env="TMWS_DB_POOL_SIZE")
    db_max_overflow: int = Field(20, env="TMWS_DB_MAX_OVERFLOW")
    db_pool_recycle: int = Field(3600, env="TMWS_DB_POOL_RECYCLE")
    db_pool_pre_ping: bool = Field(True, env="TMWS_DB_POOL_PRE_PING")
    db_pool_timeout: int = Field(30, env="TMWS_DB_POOL_TIMEOUT")
```

**適用** (既にWeek 2で実装済み):
```python
# src/core/database.py
# DatabaseManager._get_pool_config() で使用
```

#### 2. パフォーマンステスト

```python
# tests/performance/test_database_pool.py
import pytest
import asyncio
from time import time
from src.core.database import db_manager

@pytest.mark.asyncio
async def test_concurrent_connections():
    """並列接続のパフォーマンステスト"""
    num_concurrent = 50

    async def execute_query(session_id: int):
        async for session in db_manager.get_session():
            result = await session.execute("SELECT 1")
            return result.scalar()

    start = time()
    tasks = [execute_query(i) for i in range(num_concurrent)]
    results = await asyncio.gather(*tasks)
    elapsed = time() - start

    # すべて成功
    assert len(results) == num_concurrent
    assert all(r == 1 for r in results)

    # 10秒以内に完了
    assert elapsed < 10.0

    print(f"\n✅ {num_concurrent} concurrent queries in {elapsed:.2f}s")
    print(f"   Average: {elapsed/num_concurrent*1000:.2f}ms per query")

@pytest.mark.asyncio
async def test_connection_pool_exhaustion():
    """プール枯渇時の挙動テスト"""
    # プールサイズを超える接続を試行
    num_requests = db_manager.engine.pool.size() + \
                   db_manager.engine.pool._max_overflow + 10

    async def slow_query(session_id: int):
        async for session in db_manager.get_session():
            # 意図的に遅いクエリ
            await session.execute("SELECT pg_sleep(0.1)")
            return session_id

    tasks = [slow_query(i) for i in range(num_requests)]

    # タイムアウトせずに完了することを確認
    results = await asyncio.wait_for(
        asyncio.gather(*tasks),
        timeout=60.0  # 60秒タイムアウト
    )

    assert len(results) == num_requests
```

#### 3. 監視メトリクスの設定

```python
# src/monitoring/database_metrics.py
from prometheus_client import Counter, Histogram, Gauge

# メトリクス定義
db_connections_active = Gauge(
    'tmws_db_connections_active',
    'Number of active database connections'
)

db_connections_total = Counter(
    'tmws_db_connections_total',
    'Total database connections created'
)

db_query_duration = Histogram(
    'tmws_db_query_duration_seconds',
    'Database query duration',
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
)

db_pool_size = Gauge(
    'tmws_db_pool_size',
    'Database connection pool size'
)

db_pool_overflow = Gauge(
    'tmws_db_pool_overflow',
    'Database connection pool overflow'
)

def update_pool_metrics():
    """プールメトリクスを更新"""
    from src.core.database import db_manager

    pool = db_manager.engine.pool
    db_pool_size.set(pool.size())
    db_pool_overflow.set(pool.overflow())
    db_connections_active.set(pool.checkedout())
```

#### チェックリスト

- [ ] 接続プール設定の追加
- [ ] パフォーマンステストの実装
- [ ] 監視メトリクスの設定
- [ ] 負荷テストの実行
- [ ] ドキュメント更新

---

## Week 5: セキュリティ強化

### 目標
包括的セキュリティ監査とペネトレーションテストの実施

### タスク

#### 1. 自動セキュリティスキャン

```bash
# 依存関係の脆弱性スキャン
pip-audit

# コード静的解析
bandit -r src/ -f json -o bandit_report.json

# Semgrepによるセキュリティチェック
semgrep --config=auto --json -o semgrep_findings.json src/
```

#### 2. ペネトレーションテスト

```python
# tests/security/test_penetration.py
import pytest
from httpx import AsyncClient
from src.main import app

@pytest.mark.asyncio
async def test_sql_injection_attempt():
    """SQLインジェクション攻撃の防御テスト"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        # 悪意のあるペイロード
        malicious_payload = {
            "content": "'; DROP TABLE memories; --",
            "importance": 0.5
        }

        response = await client.post(
            "/api/v1/memory/store",
            json=malicious_payload
        )

        # 400 Bad Request（入力検証エラー）が返るべき
        assert response.status_code == 400
        assert "malicious SQL" in response.json()["detail"].lower()

@pytest.mark.asyncio
async def test_xss_attempt():
    """XSS攻撃の防御テスト"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        xss_payload = {
            "content": "<script>alert('XSS')</script>",
            "importance": 0.5
        }

        response = await client.post(
            "/api/v1/memory/store",
            json=xss_payload
        )

        assert response.status_code == 400
        assert "dangerous content" in response.json()["detail"].lower()

@pytest.mark.asyncio
async def test_authentication_bypass_attempt():
    """認証バイパス試行の防御テスト"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        # 認証なしでアクセス
        response = await client.get("/api/v1/memory/recall")

        # 401 Unauthorized
        assert response.status_code == 401
```

#### チェックリスト

- [ ] 依存関係スキャン実行
- [ ] コード静的解析実行
- [ ] ペネトレーションテスト実行
- [ ] 発見された脆弱性の修正
- [ ] セキュリティレポート作成

---

## Week 6: 本番運用準備

### 目標
監視、ログ、ドキュメントの整備

### タスク

#### 1. 監視システム統合

```yaml
# docker-compose.monitoring.yml
version: '3.8'

services:
  tmws:
    build: .
    environment:
      - TMWS_METRICS_ENABLED=true
    ports:
      - "8000:8000"
      - "9090:9090"  # Prometheusメトリクス

  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    ports:
      - "9091:9090"

  grafana:
    image: grafana/grafana:latest
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana
    ports:
      - "3000:3000"

volumes:
  prometheus_data:
  grafana_data:
```

#### 2. ログシステムの整備

```python
# src/utils/logging_config.py
import logging
import sys
from pathlib import Path
from src.core.config import settings

def setup_logging():
    """ロギング設定"""
    log_format = (
        "%(asctime)s | %(levelname)-8s | "
        "%(name)s:%(funcName)s:%(lineno)d | "
        "%(message)s"
    )

    handlers = [logging.StreamHandler(sys.stdout)]

    if settings.log_file:
        Path(settings.log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(
            logging.FileHandler(settings.log_file)
        )

    logging.basicConfig(
        level=settings.log_level,
        format=log_format,
        handlers=handlers
    )
```

#### 3. 運用ドキュメント

ドキュメント作成（別ファイルで詳述）:
- 本番環境デプロイ手順
- トラブルシューティングガイド
- 運用監視ダッシュボード
- インシデント対応フロー

#### チェックリスト

- [ ] Prometheus統合
- [ ] Grafanaダッシュボード作成
- [ ] ログシステム整備
- [ ] 運用ドキュメント作成
- [ ] 本番デプロイリハーサル

---

## 成功指標

### Week 1終了時
- [ ] 認証システムが動作
- [ ] 環境変数が適切に設定
- [ ] 基本的入力検証が実装
- [ ] HTTPS強制が動作

### Week 3終了時
- [ ] コード重複が解消
- [ ] テストカバレッジ80%達成
- [ ] CI/CDパイプラインが動作

### Week 6終了時
- [ ] セキュリティスコア 9/10
- [ ] 本番環境デプロイ準備完了
- [ ] 監視システムが稼働
- [ ] 全ドキュメントが完成

---

**次のアクション**: `IMMEDIATE_ACTION_ITEMS.md`を確認し、今日から実行開始
