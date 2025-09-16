# 🤖 TMWS MCP Server セットアップガイド

## 概要
TMWS v2.2.0はClaude DesktopからMCPサーバーとして直接利用できます。uvxコマンドを使用した簡単なセットアップが可能です。

## 🚀 クイックスタート（uvx使用）

### 1. 前提条件
- Python 3.11以上
- PostgreSQL 15以上（pgvector拡張必須）
- uv（Pythonパッケージマネージャー）

```bash
# uvのインストール（まだの場合）
curl -LsSf https://astral.sh/uv/install.sh | sh

# PostgreSQLとpgvectorの確認
psql --version
psql -d postgres -c "SELECT * FROM pg_extension WHERE extname = 'vector';"
```

### 2. データベースセットアップ

```bash
# PostgreSQLでデータベースとユーザーを作成
sudo -u postgres psql << EOF
CREATE USER tmws_user WITH PASSWORD 'tmws_password';
CREATE DATABASE tmws OWNER tmws_user;
\c tmws
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
GRANT ALL PRIVILEGES ON DATABASE tmws TO tmws_user;
EOF
```

### 3. Claude Desktop設定

#### macOS
```bash
# Claude Desktop設定ファイルの場所
~/Library/Application Support/Claude/claude_desktop_config.json
```

#### Windows
```
%APPDATA%\Claude\claude_desktop_config.json
```

#### Linux
```bash
~/.config/Claude/claude_desktop_config.json
```

以下の設定を追加：

```json
{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/apto-as/tmws.git@v2.2.0",
        "tmws"
      ],
      "env": {
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws",
        "TMWS_ENVIRONMENT": "development",
        "TMWS_SECRET_KEY": "your_secret_key_at_least_32_characters_long",
        "TMWS_AUTH_ENABLED": "false",
        "TMWS_AGENT_ID": "athena-conductor",
        "TMWS_AGENT_NAMESPACE": "trinitas",
        "TMWS_ALLOW_DEFAULT_AGENT": "true"
      }
    }
  }
}
```

### 4. 初回起動時のマイグレーション

TMWSを初めて使用する場合、データベースマイグレーションが必要です：

```bash
# リポジトリをクローン（マイグレーション実行用）
git clone --branch v2.2.0 https://github.com/apto-as/tmws.git
cd tmws

# 環境変数設定
export TMWS_DATABASE_URL="postgresql://tmws_user:tmws_password@localhost:5432/tmws"

# マイグレーション実行
pip install alembic sqlalchemy asyncpg
python -m alembic upgrade head
```

### 5. 動作確認

1. Claude Desktopを再起動
2. 新しい会話を開始
3. 以下のコマンドで接続確認：

```
TMWSの状態を確認してください
```

期待される応答：
```
TMWSに正常に接続されています。
- バージョン: v2.2.0
- エージェント: athena-conductor
- データベース: 接続済み
```

## 🔧 カスタマイズ

### エージェント変更

異なるTrinitasエージェントを使用する場合：

```json
"env": {
  "TMWS_AGENT_ID": "artemis-optimizer",  // または他のエージェント
  "TMWS_AGENT_NAMESPACE": "custom"
}
```

利用可能なエージェント：
- `athena-conductor` - 調和的な指揮者
- `artemis-optimizer` - 技術的完璧主義者
- `hestia-auditor` - セキュリティ監査者
- `eris-coordinator` - 戦術的調整者
- `hera-strategist` - 戦略的指揮官
- `muses-documenter` - 知識アーキテクト

### 本番環境設定

本番環境で使用する場合：

```json
"env": {
  "TMWS_ENVIRONMENT": "production",
  "TMWS_AUTH_ENABLED": "true",
  "TMWS_SECRET_KEY": "production_secret_key_must_be_very_secure",
  "TMWS_JWT_SECRET": "separate_jwt_secret_key"
}
```

## 📊 利用可能なMCPツール

### メモリ管理
- `store_memory` - メモリを保存
- `recall_memory` - メモリを検索
- `search_memories` - セマンティック検索

### タスク管理
- `create_task` - タスクを作成
- `update_task` - タスクを更新
- `get_tasks` - タスク一覧取得

### ワークフロー
- `execute_workflow` - ワークフロー実行
- `get_workflow_status` - ステータス確認

### エージェント管理
- `get_current_agent` - 現在のエージェント確認
- `switch_agent` - エージェント切り替え
- `get_agent_statistics` - 統計情報取得

## 🐛 トラブルシューティング

### 問題: データベース接続エラー

```bash
# PostgreSQLサービスの確認
sudo systemctl status postgresql

# 接続テスト
psql -U tmws_user -d tmws -c "SELECT 1;"
```

### 問題: pgvector拡張が見つからない

```bash
# Ubuntu/Debian
sudo apt-get install postgresql-15-pgvector

# macOS (Homebrew)
brew install pgvector

# 拡張を有効化
psql -U postgres -d tmws -c "CREATE EXTENSION vector;"
```

### 問題: uvxコマンドが見つからない

```bash
# uvを再インストール
curl -LsSf https://astral.sh/uv/install.sh | sh

# パスを確認
echo $PATH
# ~/.cargo/bin が含まれていることを確認

# シェル設定を再読み込み
source ~/.bashrc  # または ~/.zshrc
```

### 問題: MCPサーバーが起動しない

1. Claude Desktopのログを確認：
   - macOS: `~/Library/Logs/Claude/`
   - Windows: `%APPDATA%\Claude\Logs\`

2. 手動でテスト起動：
```bash
uvx --from git+https://github.com/apto-as/tmws.git@v2.2.0 tmws
```

3. 環境変数を確認：
```bash
env | grep TMWS
```

## 📚 高度な使用方法

### 複数エージェントの並列使用

複数のTMWSインスタンスを異なるエージェントで起動：

```json
{
  "mcpServers": {
    "tmws-athena": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/apto-as/tmws.git@v2.2.0", "tmws"],
      "env": {
        "TMWS_AGENT_ID": "athena-conductor",
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws"
      }
    },
    "tmws-artemis": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/apto-as/tmws.git@v2.2.0", "tmws"],
      "env": {
        "TMWS_AGENT_ID": "artemis-optimizer",
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws"
      }
    }
  }
}
```

### ローカル開発版の使用

開発中のローカル版を使用する場合：

```json
{
  "mcpServers": {
    "tmws-local": {
      "command": "python",
      "args": ["-m", "src.mcp_server"],
      "cwd": "/path/to/tmws",
      "env": {
        "PYTHONPATH": "/path/to/tmws",
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws"
      }
    }
  }
}
```

## 🔄 アップデート方法

新しいバージョンにアップデートする場合：

1. Claude Desktop設定のバージョンタグを更新：
```json
"args": [
  "--from",
  "git+https://github.com/apto-as/tmws.git@v2.3.0",  // 新バージョン
  "tmws"
]
```

2. Claude Desktopを再起動

3. 必要に応じてデータベースマイグレーション実行：
```bash
cd tmws
git pull
git checkout v2.3.0
python -m alembic upgrade head
```

## 📞 サポート

- GitHub Issues: https://github.com/apto-as/tmws/issues
- Documentation: https://github.com/apto-as/tmws/docs
- Discord: https://discord.gg/tmws

---

*TMWS v2.2.0 - Trinitas Memory & Workflow Service*
*MCPサーバーとして、より便利に、より強力に。*