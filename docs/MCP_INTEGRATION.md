# TMWS MCP統合ガイド

## 概要

TMWSは Model Context Protocol (MCP) サーバーとして動作し、Claude Desktopから直接呼び出すことができます。

## 3つの統合方法

### 方法1: uv run（推奨：ローカル開発）

**利点**:
- ローカルのコードを直接実行
- 開発中の変更がすぐ反映
- デバッグが容易

**設定**: `.claude/mcp_config.json`

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
        "TMWS_SECRET_KEY": "your-secret-key-here",
        "TMWS_ENVIRONMENT": "development",
        "TMWS_AUTH_ENABLED": "false",
        "TMWS_AGENT_ID": "claude-desktop",
        "TMWS_AGENT_NAMESPACE": "default"
      }
    }
  }
}
```

---

### 方法2: uvx（推奨：本番・安定版使用）

**利点**:
- 環境が完全に分離
- 複数バージョンの共存が可能
- クリーンな実行環境

**設定**: `.claude/mcp_config.json`

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
        "TMWS_SECRET_KEY": "your-secret-key-here",
        "TMWS_ENVIRONMENT": "production",
        "TMWS_AUTH_ENABLED": "false"
      }
    }
  }
}
```

---

### 方法3: uvx + GitHub（最新版を常に使用）

**利点**:
- 常に最新版を使用
- インストール不要
- チーム全体で同じバージョン

**設定**: `.claude/mcp_config.json`

```json
{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/apto-as/tmws.git@master",
        "tmws"
      ],
      "env": {
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws_db",
        "TMWS_SECRET_KEY": "your-secret-key-here",
        "TMWS_ENVIRONMENT": "production"
      }
    }
  }
}
```

特定のバージョンを指定:
```json
"args": [
  "--from",
  "git+https://github.com/apto-as/tmws.git@v2.2.0",
  "tmws"
]
```

---

## 環境変数の詳細

### 必須の環境変数

| 変数名 | 説明 | 例 |
|-------|------|---|
| `TMWS_DATABASE_URL` | PostgreSQL接続URL | `postgresql://user:pass@localhost:5432/tmws_db` |
| `TMWS_SECRET_KEY` | JWT署名用の秘密鍵（32文字以上） | `your-secret-key-minimum-32-chars` |

### オプションの環境変数

| 変数名 | デフォルト | 説明 |
|-------|-----------|------|
| `TMWS_ENVIRONMENT` | `development` | 実行環境 (`development`/`staging`/`production`) |
| `TMWS_AUTH_ENABLED` | `false` | JWT認証の有効化 |
| `TMWS_AGENT_ID` | 自動生成 | エージェントID（例: `claude-desktop-1`） |
| `TMWS_AGENT_NAMESPACE` | `default` | 名前空間（メモリの分離） |
| `TMWS_API_HOST` | `0.0.0.0` | REST APIのホスト |
| `TMWS_API_PORT` | `8000` | REST APIのポート |
| `TMWS_REDIS_URL` | なし | Redisキャッシュ（オプション） |
| `TMWS_LOG_LEVEL` | `INFO` | ログレベル |

---

## マルチエージェント構成

複数のClaude Desktopインスタンスや、異なるエージェントを同時に使う場合:

### 設定例: 3つの異なるエージェント

```json
{
  "mcpServers": {
    "tmws-athena": {
      "command": "uvx",
      "args": ["--from", "/path/to/tmws", "tmws"],
      "env": {
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws_db",
        "TMWS_SECRET_KEY": "your-secret-key",
        "TMWS_AGENT_ID": "athena-conductor",
        "TMWS_AGENT_NAMESPACE": "architecture",
        "TMWS_AUTH_ENABLED": "false"
      }
    },
    "tmws-artemis": {
      "command": "uvx",
      "args": ["--from", "/path/to/tmws", "tmws"],
      "env": {
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws_db",
        "TMWS_SECRET_KEY": "your-secret-key",
        "TMWS_AGENT_ID": "artemis-optimizer",
        "TMWS_AGENT_NAMESPACE": "optimization",
        "TMWS_AUTH_ENABLED": "false"
      }
    },
    "tmws-hestia": {
      "command": "uvx",
      "args": ["--from", "/path/to/tmws", "tmws"],
      "env": {
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws_db",
        "TMWS_SECRET_KEY": "your-secret-key",
        "TMWS_AGENT_ID": "hestia-auditor",
        "TMWS_AGENT_NAMESPACE": "security",
        "TMWS_AUTH_ENABLED": "false"
      }
    }
  }
}
```

各エージェントは異なる名前空間で動作し、メモリを分離できます。

---

## 利用可能なMCPツール

TMWSは以下のMCPツールを提供します:

### メモリ管理
- `store_memory` - メモリを保存
- `recall_memory` - メモリを検索（セマンティック検索対応）
- `update_memory` - メモリを更新
- `delete_memory` - メモリを削除
- `list_memories` - メモリ一覧を取得

### タスク管理
- `create_task` - タスクを作成
- `update_task` - タスクを更新
- `complete_task` - タスクを完了
- `list_tasks` - タスク一覧を取得

### ワークフロー管理
- `create_workflow` - ワークフローを作成
- `execute_workflow` - ワークフローを実行
- `workflow_status` - ワークフロー状態を確認

### システム管理
- `health_check` - システムヘルスチェック
- `get_stats` - システム統計情報
- `register_agent` - カスタムエージェント登録
- `switch_agent` - エージェント切り替え

詳細は [MCP_TOOLS_REFERENCE.md](MCP_TOOLS_REFERENCE.md) を参照。

---

## 動作確認

### 1. Claude Desktopを再起動

設定ファイルを編集したら、Claude Desktopを完全に再起動してください。

### 2. MCPツールの確認

Claude Desktopで以下のように実行:

```
TMWSのヘルスチェックを実行してください
```

または:

```
TMWSに「テストメモリ」を保存してください
```

### 3. デバッグ方法

#### ログの確認

```bash
# Claude Desktopのログを確認（macOS）
tail -f ~/Library/Logs/Claude/mcp*.log

# TMWSサーバーのログ
# 通常、標準エラー出力に表示されます
```

#### 手動でMCPサーバーを起動

```bash
# ターミナルで直接起動してエラーを確認
cd /Users/apto-as/workspace/github.com/apto-as/tmws
uv run tmws
```

正常起動時の出力:
```
INFO:     TMWS MCP Server v2.2.0 starting...
INFO:     Agent ID: claude-desktop-xxxxx
INFO:     Database connected: postgresql://...
INFO:     MCP Server ready
```

---

## トラブルシューティング

### Claude Desktopで認識されない

**原因1**: 設定ファイルのJSON構文エラー
```bash
# JSONの構文チェック
cat ~/.claude/mcp_config.json | jq .
```

**原因2**: uvコマンドが見つからない
```bash
# PATHにuvが含まれているか確認
which uv

# なければPATHに追加
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

**原因3**: PostgreSQLが起動していない
```bash
# PostgreSQL状態確認
brew services list | grep postgresql

# 起動
brew services start postgresql@17
```

### データベース接続エラー

```bash
# 接続テスト
psql postgresql://tmws_user:tmws_password@localhost:5432/tmws_db -c "SELECT 1;"

# pgvector拡張確認
psql tmws_db -c "\dx vector"
```

### エージェントIDの競合

複数インスタンスで同じエージェントIDを使うと、メモリが混在します。

**解決策**: 各インスタンスに異なる `TMWS_AGENT_ID` を設定
```json
{
  "env": {
    "TMWS_AGENT_ID": "claude-desktop-instance-1"
  }
}
```

---

## パフォーマンス最適化

### Redisキャッシュの追加

```bash
# Redisをインストール
brew install redis

# 起動
brew services start redis
```

設定に追加:
```json
{
  "env": {
    "TMWS_REDIS_URL": "redis://localhost:6379/0"
  }
}
```

### データベース接続プールの調整

多数のメモリ操作を行う場合:

```json
{
  "env": {
    "TMWS_DB_POOL_SIZE": "20",
    "TMWS_DB_MAX_OVERFLOW": "40"
  }
}
```

---

## セキュリティベストプラクティス

### 本番環境での推奨設定

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
        "TMWS_DATABASE_URL": "postgresql://tmws_prod:STRONG_PASSWORD@localhost:5432/tmws_prod",
        "TMWS_SECRET_KEY": "GENERATE_WITH_openssl_rand_base64_32",
        "TMWS_ENVIRONMENT": "production",
        "TMWS_AUTH_ENABLED": "true",
        "TMWS_LOG_LEVEL": "WARNING"
      }
    }
  }
}
```

### SECRET_KEYの生成

```bash
# 安全な秘密鍵を生成
openssl rand -base64 32

# またはPythonで
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## 次のステップ

- [MCP_TOOLS_REFERENCE.md](MCP_TOOLS_REFERENCE.md) - ツールリファレンス
- [API_AUTHENTICATION.md](API_AUTHENTICATION.md) - 認証設定
- [PERFORMANCE_TUNING.md](PERFORMANCE_TUNING.md) - パフォーマンス調整
