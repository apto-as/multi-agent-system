# TMWS uvx インストールガイド

## uvとは？

[uv](https://github.com/astral-sh/uv)は、Rustで書かれた超高速なPythonパッケージマネージャーです。pipの10-100倍高速で、依存関係の解決も賢くなっています。

## 前提条件

- **uv**: 0.1.0以上
- **PostgreSQL**: 17.x（pgvector拡張が必要）
- **OS**: macOS / Linux
- **所要時間**: 約5-10分（pipより2-3倍高速）

---

## Step 1: uvのインストール

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# または Homebrew
brew install uv

# Windowsの場合
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

インストール確認:
```bash
uv --version  # uv 0.x.x
```

---

## Step 2: PostgreSQLのセットアップ

```bash
# PostgreSQL 17のインストール
brew install postgresql@17

# サービス起動
brew services start postgresql@17

# データベースとユーザーの作成
/opt/homebrew/opt/postgresql@17/bin/psql postgres << EOF
CREATE USER tmws_user WITH PASSWORD 'tmws_password';
CREATE DATABASE tmws_db OWNER tmws_user;
\c tmws_db
CREATE EXTENSION IF NOT EXISTS vector;
\q
EOF
```

---

## Step 3: TMWSのインストール

### 方法A: ローカル開発用（推奨）

```bash
# プロジェクトディレクトリに移動
cd /path/to/tmws

# uv syncで依存関係をインストール（超高速）
uv sync

# または開発依存関係も含めて
uv sync --extra dev
```

### 方法B: GitHubから直接インストール

```bash
# GitHubリポジトリから直接インストール
uv pip install git+https://github.com/apto-as/tmws.git

# または特定のブランチ/タグを指定
uv pip install git+https://github.com/apto-as/tmws.git@v2.2.0
```

---

## Step 4: 環境変数の設定

```bash
# .envファイルを作成
cat > .env << EOF
# Database Configuration
TMWS_DATABASE_URL=postgresql://tmws_user:tmws_password@localhost:5432/tmws_db

# Security
TMWS_SECRET_KEY=$(uv run python -c "import secrets; print(secrets.token_urlsafe(32))")
TMWS_AUTH_ENABLED=false

# Environment
TMWS_ENVIRONMENT=development

# API Configuration
TMWS_API_HOST=0.0.0.0
TMWS_API_PORT=8000

# Embeddings
TMWS_EMBEDDING_MODEL=all-MiniLM-L6-v2
TMWS_VECTOR_DIMENSION=384
EOF
```

---

## Step 5: データベースマイグレーション

```bash
# Alembicマイグレーションを実行
uv run alembic upgrade head
```

---

## Step 6: サーバー起動

### MCPサーバーモード（Claude Desktop統合用）

```bash
# MCPサーバーとして起動
uv run tmws
```

### REST APIモード（Web API用）

```bash
# FastAPIサーバーとして起動
uv run tmws-api
```

### uvxで直接実行（インストール不要）

```bash
# 一時的に実行（依存関係を自動解決）
uvx --from git+https://github.com/apto-as/tmws.git tmws
```

---

## Claude Desktop統合

### .claude/mcp_config.json に追加

```json
{
  "mcpServers": {
    "tmws": {
      "command": "uv",
      "args": [
        "--directory",
        "/Users/apto-as/workspace/github.com/apto-as/tmws",
        "run",
        "tmws"
      ],
      "env": {
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws_db",
        "TMWS_SECRET_KEY": "your-secret-key-from-env-file",
        "TMWS_ENVIRONMENT": "development",
        "TMWS_AUTH_ENABLED": "false"
      }
    }
  }
}
```

### または uvx を使用（推奨：環境を分離）

```json
{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": [
        "--from",
        "/Users/apto-as/workspace/github.com/apto-as/tmws",
        "tmws"
      ],
      "env": {
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws_db",
        "TMWS_SECRET_KEY": "your-secret-key-from-env-file",
        "TMWS_ENVIRONMENT": "development",
        "TMWS_AUTH_ENABLED": "false"
      }
    }
  }
}
```

### GitHubから直接起動（最新版を常に使用）

```json
{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/apto-as/tmws.git",
        "tmws"
      ],
      "env": {
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws_db",
        "TMWS_SECRET_KEY": "your-secret-key-from-env-file",
        "TMWS_ENVIRONMENT": "development"
      }
    }
  }
}
```

Claude Desktopを再起動すると、TMWSのMCPツールが利用可能になります。

---

## 動作確認

### 1. ヘルスチェック

```bash
# REST APIサーバーを起動（別ターミナル）
uv run tmws-api

# ヘルスチェック
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

### 2. Claude Desktopでテスト

Claude Desktopを再起動後:
```
TMWSのヘルスチェックを実行して
```

または:
```
TMWSにメモリを保存: "uvx経由でのインストール成功"
```

---

## uvの利点

### 速度比較（依存関係インストール）

| ツール | 所要時間 | 備考 |
|-------|---------|------|
| pip | 3-5分 | 従来の方法 |
| uv sync | 30-60秒 | **5-10倍高速** |
| uvx | 初回90秒、以降30秒 | キャッシュ後は超高速 |

### その他の利点

1. **依存関係の解決が賢い**
   - 競合を事前に検出
   - ロックファイルで再現性を保証

2. **仮想環境管理が簡単**
   - 自動で.venvを作成・管理
   - 複数バージョンの共存が容易

3. **キャッシュが効率的**
   - グローバルキャッシュで再ダウンロード不要
   - ディスク使用量を削減

4. **クロスプラットフォーム**
   - macOS, Linux, Windowsで同じコマンド

---

## トラブルシューティング

### uvが見つからない

```bash
# PATHに追加
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### PostgreSQL接続エラー

```bash
# サービス状態確認
brew services list | grep postgresql

# 再起動
brew services restart postgresql@17
```

### uvx実行時の権限エラー

```bash
# スクリプトに実行権限を付与
chmod +x src/mcp_server.py
```

### キャッシュのクリア

```bash
# uvのキャッシュをクリア
uv cache clean

# 再インストール
uv sync --reinstall
```

---

## uv.lock について

`uv sync`を実行すると、`uv.lock`ファイルが生成されます。これは依存関係のロックファイルで：

- **コミット推奨**: チーム全体で同じバージョンを使用
- **再現性**: 誰が実行しても同じ環境
- **CI/CD**: GitHub Actionsでも同じ依存関係

```bash
# ロックファイルを更新
uv lock --upgrade
```

---

## 開発者向け

### テストの実行

```bash
# 全テスト
uv run pytest tests/ -v

# カバレッジ付き
uv run pytest tests/ -v --cov=src --cov-report=html
```

### コード品質チェック

```bash
# リント
uv run ruff check .

# フォーマット
uv run ruff format .

# 型チェック
uv run mypy src/
```

### スクリプト実行

```bash
# 任意のPythonスクリプトを実行
uv run python scripts/check_database.py

# インラインスクリプト
uv run python -c "from src.core.config import get_settings; print(get_settings())"
```

---

## 次のステップ

- [QUICKSTART.md](QUICKSTART.md) - 5分クイックスタート
- [INSTALL.md](INSTALL.md) - 従来のpip版インストール
- [API認証ドキュメント](docs/API_AUTHENTICATION.md)
- [Trinitas統合ガイド](docs/TRINITAS_INTEGRATION.md)

---

## 参考リンク

- [uv公式ドキュメント](https://docs.astral.sh/uv/)
- [FastMCP公式ドキュメント](https://github.com/jlowin/fastmcp)
- [Model Context Protocol仕様](https://modelcontextprotocol.io/)
