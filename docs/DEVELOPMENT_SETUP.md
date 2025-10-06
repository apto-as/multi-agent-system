# TMWS ハイブリッドクラウド 開発環境構築ガイド

## 1. 前提条件

### 1.1 必須ソフトウェア

- **Python**: 3.11以上
- **PostgreSQL**: 15以上（pgvector拡張機能付き）
- **SQLite**: 3.35以上
- **Git**: 2.x
- **Docker**: 20.x以上（オプション）
- **Redis**: 6.x以上（オプション）

### 1.2 推奨ツール

- **uv**: 超高速Pythonパッケージマネージャー
- **VSCode**: 推奨IDE
- **TablePlus**: データベースGUIクライアント

---

## 2. 開発環境セットアップ

### 2.1 リポジトリクローン

```bash
# リポジトリクローン
git clone https://github.com/apto-as/tmws.git
cd tmws

# ブランチ確認
git branch
# * master
```

### 2.2 Python環境構築

#### Option A: uv使用（推奨）

```bash
# uvインストール（macOS/Linux）
curl -LsSf https://astral.sh/uv/install.sh | sh

# 仮想環境作成と依存関係インストール
uv venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate  # Windows

# 依存関係インストール
uv pip install -e ".[dev,test]"
```

#### Option B: pip使用

```bash
# 仮想環境作成
python3.11 -m venv .venv
source .venv/bin/activate

# 依存関係インストール
pip install -e ".[dev,test]"
```

### 2.3 環境変数設定

```bash
# .env.development ファイル作成
cat > .env.development <<EOF
# Core Settings
TMWS_ENVIRONMENT=development
TMWS_SECRET_KEY=$(openssl rand -hex 32)
TMWS_DATABASE_URL=postgresql://tmws_user:tmws_password@localhost:5432/tmws_dev

# Hybrid Cloud Settings
TMWS_HYBRID_MODE_ENABLED=true
TMWS_CLOUD_DATABASE_URL=postgresql://user:pass@cloud-host:5432/tmws_global
TMWS_LOCAL_DATABASE_URL=sqlite+aiosqlite:///./data/tmws_local.db
TMWS_CLOUD_SSL_CERT_PATH=

# API Settings
TMWS_API_HOST=127.0.0.1
TMWS_API_PORT=8000

# Security Settings (development)
TMWS_AUTH_ENABLED=false
TMWS_RATE_LIMIT_ENABLED=false

# Redis (optional)
TMWS_REDIS_URL=redis://localhost:6379/0
EOF

# 環境変数読み込み
export $(cat .env.development | xargs)
```

---

## 3. データベースセットアップ

### 3.1 PostgreSQL（クラウドDB）

#### Option A: Docker使用（推奨）

```bash
# PostgreSQL + pgvector コンテナ起動
docker run -d \
  --name tmws-postgres \
  -e POSTGRES_USER=tmws_user \
  -e POSTGRES_PASSWORD=tmws_password \
  -e POSTGRES_DB=tmws_dev \
  -p 5432:5432 \
  ankane/pgvector:latest

# pgvector拡張機能有効化
docker exec tmws-postgres psql -U tmws_user -d tmws_dev -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

#### Option B: ローカルインストール

```bash
# macOS (Homebrew)
brew install postgresql@15
brew install pgvector

# PostgreSQL起動
brew services start postgresql@15

# データベース作成
createdb tmws_dev -U postgres

# pgvector有効化
psql -d tmws_dev -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

#### Option C: Supabase（クラウド）

```bash
# Supabaseプロジェクト作成
# 1. https://supabase.com でプロジェクト作成
# 2. 接続文字列を取得
# 3. pgvectorは自動で有効化済み

# 接続テスト
export TMWS_CLOUD_DATABASE_URL="postgresql://postgres:[PASSWORD]@db.[PROJECT-REF].supabase.co:5432/postgres"
psql $TMWS_CLOUD_DATABASE_URL -c "SELECT 1;"
```

### 3.2 SQLite（ローカルDB）

```bash
# ローカルディレクトリ作成
mkdir -p data

# SQLiteデータベース作成（自動生成されるので不要）
# Alembicマイグレーション実行時に自動作成
```

### 3.3 データベースマイグレーション

```bash
# Alembic初期化（既に完了している場合はスキップ）
# alembic init migrations

# マイグレーション実行
alembic upgrade head

# マイグレーション確認
alembic current
# 7e805ed (head)
```

---

## 4. クラウドプロバイダ選択ガイド

### 4.1 Supabase（推奨 - 最も簡単）

**利点**:
- PostgreSQL + pgvectorが標準装備
- 無料枠: 500MB、2週間非アクティブで一時停止
- 自動バックアップ、RLS標準対応
- WebUI でデータ確認可能

**セットアップ**:
```bash
# 1. Supabaseでプロジェクト作成
# https://supabase.com/dashboard

# 2. 接続情報取得
# Settings → Database → Connection string (Session mode)

# 3. 環境変数設定
export TMWS_CLOUD_DATABASE_URL="postgresql://postgres:[PASSWORD]@db.[PROJECT-REF].supabase.co:5432/postgres"

# 4. SSL証明書（オプション）
# Supabaseは自動でTLS 1.3対応
```

### 4.2 Neon（サーバーレス PostgreSQL）

**利点**:
- サーバーレス、使用時のみ課金
- 無料枠: 3プロジェクト、0.5GB
- pgvector対応
- 自動スケーリング

**セットアップ**:
```bash
# 1. Neon コンソールでプロジェクト作成
# https://console.neon.tech/

# 2. pgvector有効化
psql $NEON_DATABASE_URL -c "CREATE EXTENSION IF NOT EXISTS vector;"

# 3. 環境変数設定
export TMWS_CLOUD_DATABASE_URL="postgres://user:pass@ep-xxx.region.aws.neon.tech/neondb?sslmode=require"
```

### 4.3 Amazon RDS（エンタープライズ）

**利点**:
- 高可用性、マルチAZ対応
- 自動バックアップ、ポイントインタイムリカバリ
- VPC内配置でセキュア

**セットアップ**:
```bash
# 1. RDS インスタンス作成（PostgreSQL 15）

# 2. セキュリティグループ設定
# インバウンドルール: TCP 5432 from your IP

# 3. pgvector インストール
psql -h your-rds-endpoint.rds.amazonaws.com -U postgres -d tmws \
  -c "CREATE EXTENSION IF NOT EXISTS vector;"

# 4. 環境変数設定
export TMWS_CLOUD_DATABASE_URL="postgresql://user:pass@your-rds-endpoint.rds.amazonaws.com:5432/tmws"
export TMWS_CLOUD_SSL_CERT_PATH="/path/to/rds-ca-bundle.pem"
```

---

## 5. 開発サーバー起動

### 5.1 基本起動

```bash
# FastAPI開発サーバー起動
python -m src.main

# または uvicornで起動
uvicorn src.main:app --reload --host 127.0.0.1 --port 8000
```

### 5.2 ハイブリッドモード有効化

```bash
# Feature Flag有効化
export TMWS_HYBRID_MODE_ENABLED=true

# クラウドDB接続確認
python -c "
from src.core.database_router import get_database_router
import asyncio

async def test():
    router = get_database_router()
    try:
        engine = router.get_cloud_engine()
        print(f'✅ Cloud DB: {engine.url}')
    except Exception as e:
        print(f'❌ Cloud DB Error: {e}')

asyncio.run(test())
"

# サーバー起動
python -m src.main
```

### 5.3 動作確認

```bash
# Health check
curl http://localhost:8000/health

# メモリ作成テスト（GLOBAL scope）
curl -X POST http://localhost:8000/api/v1/memories \
  -H "Content-Type: application/json" \
  -d '{
    "content": "React Query caching optimization",
    "scope_hint": "GLOBAL",
    "metadata": {"tags": ["react", "performance"]}
  }'

# メモリ作成テスト（PRIVATE scope - 機密情報）
curl -X POST http://localhost:8000/api/v1/memories \
  -H "Content-Type: application/json" \
  -d '{
    "content": "API key: sk-test-123456",
    "metadata": {"tags": ["credentials"]}
  }'
```

---

## 6. テスト実行

### 6.1 単体テスト

```bash
# 全単体テスト実行
pytest tests/unit/ -v

# カバレッジ付き
pytest tests/unit/ -v --cov=src --cov-report=term-missing --cov-report=html

# 特定ファイルのみ
pytest tests/unit/test_scope_classifier.py -v
```

### 6.2 統合テスト

```bash
# 統合テスト実行（PostgreSQL必須）
export TEST_DATABASE_URL="postgresql://tmws_user:tmws_password@localhost:5432/tmws_test"

# テストDB作成
createdb tmws_test -U tmws_user

# マイグレーション実行
TMWS_DATABASE_URL=$TEST_DATABASE_URL alembic upgrade head

# テスト実行
pytest tests/integration/ -v
```

### 6.3 セキュリティテスト

```bash
# セキュリティテスト実行
pytest tests/security/ -v -m security

# 機密情報検出テスト
pytest tests/security/test_sensitive_detection.py -v
```

---

## 7. デバッグ設定

### 7.1 VSCode設定

`.vscode/launch.json`:
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "TMWS FastAPI",
      "type": "python",
      "request": "launch",
      "module": "uvicorn",
      "args": [
        "src.main:app",
        "--reload",
        "--host", "127.0.0.1",
        "--port", "8000"
      ],
      "envFile": "${workspaceFolder}/.env.development",
      "console": "integratedTerminal"
    },
    {
      "name": "Pytest: Current File",
      "type": "python",
      "request": "launch",
      "module": "pytest",
      "args": [
        "${file}",
        "-v",
        "-s"
      ],
      "console": "integratedTerminal"
    }
  ]
}
```

### 7.2 ログレベル設定

```bash
# デバッグログ有効化
export TMWS_LOG_LEVEL=DEBUG

# 特定モジュールのみデバッグ
export TMWS_LOG_CONFIG='{"loggers": {"src.services.scope_classifier": {"level": "DEBUG"}}}'
```

---

## 8. トラブルシューティング

### 8.1 よくあるエラー

#### エラー: `ModuleNotFoundError: No module named 'pgvector'`

```bash
# 解決策: pgvectorインストール
pip install pgvector
```

#### エラー: `could not connect to server: Connection refused`

```bash
# 解決策: PostgreSQL起動確認
# macOS
brew services list
brew services start postgresql@15

# Docker
docker ps -a | grep tmws-postgres
docker start tmws-postgres
```

#### エラー: `ERROR: extension "vector" does not exist`

```bash
# 解決策: pgvector拡張機能インストール
psql -d tmws_dev -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

#### エラー: `SENSITIVE_DATA_VIOLATION`

```bash
# 期待される動作: 機密情報は自動的にPRIVATEスコープへ
# 解決策: 意図的にPRIVATEスコープを指定
curl -X POST http://localhost:8000/api/v1/memories \
  -d '{"content": "password: xxx", "scope_hint": "PRIVATE"}'
```

### 8.2 デバッグコマンド

```bash
# データベース接続テスト
python -c "
from src.core.database import get_engine
import asyncio

async def test():
    engine = get_engine()
    async with engine.connect() as conn:
        result = await conn.execute(text('SELECT 1'))
        print('✅ Database connected')

asyncio.run(test())
"

# スコープ分類テスト
python -c "
from src.services.scope_classifier import ScopeClassifier

classifier = ScopeClassifier()
scope, details = classifier.classify('password: secret123')
print(f'Scope: {scope}')
print(f'Details: {details}')
"
```

---

## 9. CI/CD設定（GitHub Actions）

### 9.1 テストワークフロー

`.github/workflows/test-suite.yml`:
```yaml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: ankane/pgvector:latest
        env:
          POSTGRES_USER: tmws_test
          POSTGRES_PASSWORD: test_password
          POSTGRES_DB: tmws_test
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install uv
          uv pip install -e ".[dev,test]"

      - name: Run migrations
        env:
          TMWS_DATABASE_URL: postgresql://tmws_test:test_password@localhost:5432/tmws_test
        run: alembic upgrade head

      - name: Run unit tests
        run: pytest tests/unit/ -v --cov=src --cov-report=xml

      - name: Run integration tests
        env:
          TMWS_DATABASE_URL: postgresql://tmws_test:test_password@localhost:5432/tmws_test
        run: pytest tests/integration/ -v

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
```

---

## 10. 本番環境デプロイ準備

### 10.1 本番環境変数

```bash
# .env.production
TMWS_ENVIRONMENT=production
TMWS_SECRET_KEY=$(openssl rand -hex 32)
TMWS_DATABASE_URL=postgresql://prod_user:prod_pass@prod-host:5432/tmws_prod

# Hybrid Settings
TMWS_HYBRID_MODE_ENABLED=true
TMWS_CLOUD_DATABASE_URL=postgresql://cloud_user:cloud_pass@cloud-host:5432/tmws_global
TMWS_CLOUD_SSL_CERT_PATH=/etc/tmws/ssl/ca-cert.pem

# Security (MUST BE ENABLED)
TMWS_AUTH_ENABLED=true
TMWS_RATE_LIMIT_ENABLED=true
TMWS_SECURITY_HEADERS_ENABLED=true
TMWS_AUDIT_LOG_ENABLED=true

# CORS
TMWS_CORS_ORIGINS='["https://app.example.com"]'
```

### 10.2 デプロイチェックリスト

- [ ] `TMWS_ENVIRONMENT=production` 設定
- [ ] `TMWS_AUTH_ENABLED=true` 設定
- [ ] 強力な`TMWS_SECRET_KEY`生成（32文字以上）
- [ ] SSL/TLS証明書設定
- [ ] データベースバックアップ設定
- [ ] 監視・アラート設定
- [ ] ログローテーション設定
- [ ] セキュリティ監査実施

---

**作成者**: Artemis（技術実装）+ Muses（文書化）
**バージョン**: 1.0
**作成日**: 2025-01-06
**最終更新**: 2025-01-06
