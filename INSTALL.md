# TMWS v2.2.0 インストールガイド

## 目次
- [クイックスタート（自動セットアップ）](#クイックスタート)
- [手動セットアップ](#手動セットアップ)
- [動作確認](#step-6-動作確認)
- [トラブルシューティング](#トラブルシューティング)

## 前提条件

- **Python**: 3.10以上（推奨: 3.11+）
- **PostgreSQL**: 17.x（pgvector拡張が必要）
- **Redis**: 7.0以上（オプション、キャッシュ用）
- **OS**: macOS / Linux
- **所要時間**: 約10-15分

---

## クイックスタート

**最速セットアップ（推奨）**:

```bash
# PostgreSQL 17をインストール（未インストールの場合）
brew install postgresql@17

# 自動セットアップスクリプトを実行
chmod +x setup.sh
./setup.sh
```

セットアップが完了したら、[動作確認](#step-6-動作確認)に進んでください。

**注意**: `pip install`の実行には3-5分かかります。進捗が表示されるので、そのままお待ちください。

---

## 手動セットアップ

自動セットアップスクリプトがうまく動作しない場合、以下の手順で手動セットアップできます。

## Step 1: PostgreSQLのセットアップ

### PostgreSQLサービスの起動

```bash
# macOS (Homebrew)
brew services start postgresql@17

# Linux (systemd)
sudo systemctl start postgresql
```

### データベースとユーザーの作成

```bash
# PostgreSQLに接続
/opt/homebrew/opt/postgresql@17/bin/psql postgres

# データベースとユーザーを作成
CREATE USER tmws_user WITH PASSWORD 'tmws_password';
CREATE DATABASE tmws_db OWNER tmws_user;

# pgvector拡張を有効化
\c tmws_db
CREATE EXTENSION IF NOT EXISTS vector;

# 接続を終了
\q
```

## Step 2: Python環境のセットアップ

### 仮想環境の作成と有効化

```bash
cd /Users/apto-as/workspace/github.com/apto-as/tmws

# 仮想環境を作成
python3 -m venv .venv

# 有効化
source .venv/bin/activate  # macOS/Linux
# または
.venv\Scripts\activate  # Windows
```

### 依存パッケージのインストール

```bash
# pipのアップグレード
pip install --upgrade pip

# 依存関係をインストール（約3-5分）
pip install -e ".[dev]"
```

**注意**: 初回インストール時、以下のパッケージがダウンロードされます:
- FastAPI, SQLAlchemy, Alembic（Web/DB関連）
- ChromaDB（ベクトルストレージ）
- pytest, ruff, mypy（開発ツール）

**重要**: Ollamaは別途インストールが必要です（v2.3.0+で必須）:
1. https://ollama.ai/download からダウンロード
2. `ollama pull zylonai/multilingual-e5-large` でモデル取得
3. `ollama serve` でサーバー起動

進捗が表示されるので、そのままお待ちください。

## Step 3: 環境変数の設定

### .envファイルの作成

```bash
# SECRET_KEYを生成
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# .envファイルを作成
cat > .env << EOF
# Database Configuration
TMWS_DATABASE_URL=postgresql://tmws_user:tmws_password@localhost:5432/tmws_db

# Security
TMWS_SECRET_KEY=${SECRET_KEY}
TMWS_AUTH_ENABLED=false  # 開発時はfalse、本番ではtrue

# Environment
TMWS_ENVIRONMENT=development

# API Configuration
TMWS_API_HOST=0.0.0.0
TMWS_API_PORT=8000

# Redis (オプション)
# TMWS_REDIS_URL=redis://localhost:6379/0

# Embeddings
TMWS_EMBEDDING_MODEL=all-MiniLM-L6-v2
TMWS_VECTOR_DIMENSION=384
EOF
```

**重要**: `.env`ファイルは`.gitignore`に含まれているため、Gitにコミットされません。

## Step 4: データベースマイグレーション

```bash
# マイグレーションを実行
alembic upgrade head
```

## Step 5: TMWSサーバーの起動

### 開発モード（手動起動）

```bash
# FastAPI + MCPサーバーを起動
python -m src.main
```

サーバーが起動したら:
- **REST API**: http://localhost:8000
- **Swagger UI**: http://localhost:8000/docs
- **MCP WebSocket**: ws://localhost:8000/ws/mcp

### Claude Desktop統合

`.config/claude_desktop_config.json`を編集:

```json
{
  "mcpServers": {
    "tmws": {
      "command": "/Users/apto-as/workspace/github.com/apto-as/tmws/.venv/bin/python",
      "args": ["-m", "src.mcp_server"],
      "cwd": "/Users/apto-as/workspace/github.com/apto-as/tmws",
      "env": {
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws_db",
        "TMWS_SECRET_KEY": "your-secret-key-here",
        "TMWS_ENVIRONMENT": "development",
        "TMWS_AUTH_ENABLED": "false"
      }
    }
  }
}
```

Claude Desktopを再起動すると、TMWSのMCPツールが利用可能になります。

## Step 6: 動作確認

### 1. サーバーを起動

別ターミナルで:
```bash
cd /Users/apto-as/workspace/github.com/apto-as/tmws
source .venv/bin/activate
python -m src.main
```

起動成功時の出力例:
```
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### 2. ヘルスチェック

新しいターミナルで:
```bash
curl http://localhost:8000/health
```

期待される出力:
```json
{
  "status": "healthy",
  "version": "2.2.0",
  "database": "connected",
  "timestamp": "2025-01-09T..."
}
```

### 3. Swagger UIでテスト

ブラウザで http://localhost:8000/docs を開き、インタラクティブにAPIをテストできます。

### 4. メモリ機能のテスト

```bash
# メモリを作成
curl -X POST http://localhost:8000/api/v1/memory \
  -H "Content-Type: application/json" \
  -d '{
    "content": "TMWSインストール成功！",
    "importance": 0.9,
    "tags": ["installation", "success"]
  }'

# メモリを検索
curl -X POST http://localhost:8000/api/v1/memory/search \
  -H "Content-Type: application/json" \
  -d '{
    "query": "インストール",
    "limit": 5
  }'
```

### 5. MCPツールのテスト（Claude Desktop連携）

Claude Desktopで:
```
/tmws health
```

または:
```
/tmws store "テストメモリ" --importance 0.8
```

## トラブルシューティング

### PostgreSQL接続エラー

```bash
# PostgreSQLが起動しているか確認
/opt/homebrew/opt/postgresql@17/bin/pg_ctl status -D /opt/homebrew/var/postgresql@17

# 起動していない場合
brew services start postgresql@17
```

### pgvector拡張がない

```bash
/opt/homebrew/opt/postgresql@17/bin/psql tmws_db -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

### ポート8000が使用中

```bash
# ポートを変更
export TMWS_API_PORT=8001
python -m src.main
```

## 次のステップ

- [API認証ドキュメント](docs/API_AUTHENTICATION.md)
- [クイックスタートガイド](docs/QUICK_START_AUTH.md)
- [パターン実行ガイド](docs/PATTERN_USER_GUIDE.md)
- [セキュリティ設定](scripts/security_setup.py)

## 開発者向け

### テストの実行

```bash
# 全テスト
pytest tests/ -v

# カバレッジ付き
pytest tests/ -v --cov=src --cov-report=html
```

### コード品質チェック

```bash
# リント
ruff check .

# フォーマット
ruff format .

# 型チェック
mypy src/
```

## アンインストール

```bash
# サービス停止
brew services stop postgresql@17

# データベース削除
dropdb tmws_db
dropuser tmws_user

# 仮想環境削除
rm -rf .venv
```
