### セキュリティ監査ガイドライン

## セキュリティ監査の段階的アプローチ

### Phase 1: 静的解析（Hestia主導）

1. **依存関係の脆弱性スキャン**
```bash
# npm/yarn
npm audit
npm audit fix

# Python
pip-audit
safety check

# 依存関係の更新
npm update --save
```

2. **コードの静的解析**
```python
# Bandit (Python)
bandit -r src/ -f json -o security_report.json

# ESLint Security Plugin (JavaScript)
eslint --ext .js,.jsx,.ts,.tsx src/ --plugin security

# Semgrep
semgrep --config=auto --json -o findings.json
```

### Phase 2: 動的解析（Hestia + Artemis協調）

1. **SQLインジェクション対策**
```python
# Bad: 文字列連結
query = f"SELECT * FROM users WHERE id = {user_id}"

# Good: パラメータ化クエリ
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))

# SQLAlchemy (ORM)
user = session.query(User).filter(User.id == user_id).first()
```

2. **XSS (Cross-Site Scripting) 対策**
```javascript
// Bad: 直接HTML挿入
element.innerHTML = userInput;

// Good: テキストとして挿入
element.textContent = userInput;

// React: 自動エスケープ
return <div>{userInput}</div>

// 必要な場合のみ
return <div dangerouslySetInnerHTML={{__html: sanitizedHTML}} />
```

3. **CSRF対策**
```python
# Flask-WTF
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# Django
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',
]
```

### Phase 3: 認証・認可（Hestia + Athena設計）

1. **認証の実装**
```python
# JWT実装例
from jose import jwt
from datetime import datetime, timedelta

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    
    return jwt.encode(
        to_encode, 
        SECRET_KEY, 
        algorithm="HS256"
    )

# パスワードハッシュ
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)
```

2. **認可の実装**
```python
# Role-Based Access Control (RBAC)
def require_role(role: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = get_current_user()
            if role not in current_user.roles:
                raise HTTPException(403, "Insufficient permissions")
            return await func(*args, **kwargs)
        return wrapper
    return decorator

@require_role("admin")
async def admin_endpoint():
    return {"message": "Admin only content"}
```

### Phase 4: データ保護（Hestia専門領域）

1. **暗号化**
```python
# 保存時暗号化 (Encryption at Rest)
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)

# 暗号化
encrypted = cipher.encrypt(sensitive_data.encode())

# 復号化
decrypted = cipher.decrypt(encrypted).decode()
```

2. **個人情報保護**
```python
# PII (Personally Identifiable Information) のマスキング
def mask_email(email: str) -> str:
    parts = email.split('@')
    if len(parts) != 2:
        return "***"
    username = parts[0]
    if len(username) <= 3:
        masked = "*" * len(username)
    else:
        masked = username[:2] + "*" * (len(username) - 3) + username[-1]
    return f"{masked}@{parts[1]}"

# ログでのPII除去
logger.info(f"User login: {mask_email(email)}")
```

### Phase 5: インフラセキュリティ（Hestia + Hera協調）

1. **環境変数管理**
```python
# .env.example (コミット対象)
DATABASE_URL=postgresql://user:pass@localhost/db
SECRET_KEY=your-secret-key-here

# .env (gitignore)
DATABASE_URL=postgresql://prod_user:prod_pass@prod_host/prod_db
SECRET_KEY=actual-secret-key-never-commit

# 読み込み
from dotenv import load_dotenv
load_dotenv()
```

2. **HTTPS強制**
```python
# Flask
@app.before_request
def force_https():
    if not request.is_secure and app.env != 'development':
        return redirect(request.url.replace('http://', 'https://'))

# FastAPI with middleware
@app.middleware("http")
async def force_https(request: Request, call_next):
    if request.url.scheme != "https" and not DEBUG:
        url = request.url.replace(scheme="https")
        return RedirectResponse(url)
    return await call_next(request)
```

## セキュリティチェックリスト

### 開発時チェック
- [ ] 入力検証を実装した
- [ ] 出力エスケープを確認した
- [ ] SQLインジェクション対策を実装した
- [ ] XSS対策を実装した
- [ ] CSRF対策を有効化した
- [ ] 適切な認証機構を実装した
- [ ] 認可チェックを実装した
- [ ] センシティブデータを暗号化した
- [ ] ログにPIIが含まれていないことを確認した

### デプロイ前チェック
- [ ] 依存関係の脆弱性スキャンを実行した
- [ ] 静的コード解析を実行した
- [ ] ペネトレーションテストを実施した
- [ ] HTTPSが強制されている
- [ ] セキュリティヘッダーを設定した
- [ ] 環境変数が適切に管理されている
- [ ] エラーメッセージが情報漏洩していない
- [ ] ロギングが適切に設定されている

### 継続的監視
- [ ] セキュリティアラートの監視体制
- [ ] 定期的な脆弱性スキャン
- [ ] アクセスログの監視
- [ ] 異常検知の仕組み
- [ ] インシデント対応計画の準備

## セキュリティレベル定義

| レベル | 説明 | 対応期限 |
|-------|------|---------|
| Critical | 即座に悪用可能、システム全体に影響 | 24時間以内 |
| High | 悪用可能、重要データに影響 | 3日以内 |
| Medium | 条件付きで悪用可能、限定的影響 | 1週間以内 |
| Low | 理論的リスク、直接的影響なし | 次回リリース |

## TMWSへの記録

```python
# セキュリティ監査結果の記録
await memory_service.create_memory(
    content=f"セキュリティ監査完了: {len(findings)}件の問題発見",
    memory_type="security_audit",
    importance=0.9 if critical_findings else 0.6,
    tags=["security", "audit", audit_date],
    metadata={
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "tools_used": ["bandit", "semgrep", "npm_audit"]
    },
    persona_id=hestia_id
)