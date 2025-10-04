# TMWS - Trinitas Memory & Workflow Service

[![Version](https://img.shields.io/badge/version-2.2.0-blue)](https://github.com/apto-as/tmws)
[![Python](https://img.shields.io/badge/python-3.11%2B-green)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-purple)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-orange)](https://modelcontextprotocol.io)

A unified memory and workflow service for AI agents, providing database-level sharing for multiple Claude Code instances.


## 🚀 Quick Start

### インストール方法の選択

| 方法 | 推奨用途 | 所要時間 | ドキュメント |
|-----|---------|---------|------------|
| **uvx** (推奨) | 本番・安定版 | 1-2分 | [INSTALL_UVX.md](INSTALL_UVX.md) |
| **自動セットアップ** | ローカル開発 | 5-10分 | [QUICKSTART.md](QUICKSTART.md) |
| **手動セットアップ** | カスタマイズ | 10-15分 | [INSTALL.md](INSTALL.md) |

### uvxで即座に起動（最速）

```bash
# 1. PostgreSQL準備
brew install postgresql@17
brew services start postgresql@17

# 2. データベース作成
createdb tmws_db
psql tmws_db -c "CREATE EXTENSION IF NOT EXISTS vector;"

# 3. 環境変数設定
export TMWS_DATABASE_URL="postgresql://$(whoami)@localhost:5432/tmws_db"
export TMWS_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# 4. uvxで起動（インストール不要）
uvx --from git+https://github.com/apto-as/tmws.git tmws
```

## Features

- 🧠 **Semantic Memory**: PostgreSQL + pgvector for intelligent memory storage and retrieval
- 🤖 **Multi-Agent Support**: Pre-configured with 6 Trinitas agents + custom agent registration
- 🔄 **Dynamic Agent Switching**: Runtime agent context switching via MCP tools
- 📋 **Task Management**: Workflow orchestration and task tracking
- 🔌 **MCP Protocol**: Full Model Context Protocol support via stdio
- 🔒 **Security**: JWT authentication, rate limiting, audit logging
- 💾 **Database-Level Sharing**: Multiple Claude Code instances share state via PostgreSQL
- 🔄 **Real-time Sync**: LISTEN/NOTIFY for immediate updates across instances
- ⚡ **Connection Pooling**: PgBouncer integration for efficient database access
- 🚀 **Performance**: Sub-100ms vector search with IVFFlat indexing

### 方法2: uv run（ローカル開発）

```json
{
  "mcpServers": {
    "tmws": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/tmws",
        "run",
        "tmws"
      ],
      "env": {
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws_db",
        "TMWS_SECRET_KEY": "your-secret-key-here",
        "TMWS_ENVIRONMENT": "development"
      }
    }
  }
}
```

詳細は [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) を参照。

---

## 🧠 利用可能なMCPツール

- **メモリ管理**: `store_memory`, `recall_memory`, `update_memory`, `delete_memory`
- **タスク管理**: `create_task`, `update_task`, `complete_task`, `list_tasks`
- **ワークフロー**: `create_workflow`, `execute_workflow`, `workflow_status`
- **システム**: `health_check`, `get_stats`, `register_agent`, `switch_agent`

詳細は [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) を参照。

---

## 📋 必須要件

- **Python**: 3.10以上（推奨: 3.11+）
- **PostgreSQL**: 17.x + pgvector拡張
- **uv**: 0.1.0以上（推奨インストーラー）
- **OS**: macOS / Linux / Windows

## 📖 ドキュメント

### インストール
- [INSTALL_UVX.md](INSTALL_UVX.md) - **uvx推奨インストール**（最速・最新版）
- [QUICKSTART.md](QUICKSTART.md) - 5分クイックスタート
- [INSTALL.md](INSTALL.md) - 詳細な手動インストール

### MCP統合
- [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) - **Claude Desktop統合ガイド**
- [docs/MCP_TOOLS_REFERENCE.md](docs/MCP_TOOLS_REFERENCE.md) - MCPツールリファレンス

### その他
- [docs/API_AUTHENTICATION.md](docs/API_AUTHENTICATION.md) - API認証設定
- [docs/TRINITAS_INTEGRATION.md](docs/TRINITAS_INTEGRATION.md) - Trinitas統合

---

## 🔌 Claude Desktop統合

### 方法1: uvx（推奨）

`.claude/mcp_config.json` に追加:

```json
{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/apto-as/tmws.git", "tmws"],
      "env": {
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws_db",
        "TMWS_AGENT_ID": "athena-conductor-1"  // Unique per instance
      }
    }
  }
}
```

### Multiple Instances

Each Claude Code terminal runs independently with a unique AGENT_ID. All instances automatically share memories, tasks, and workflows through the database.

### How It Works

1. **Each Claude Code instance** runs its own MCP server process (stdio requirement)
2. **All MCP servers** connect to the same PostgreSQL database
3. **Real-time synchronization** via PostgreSQL LISTEN/NOTIFY
4. **Connection pooling** minimizes database overhead
5. **Local caching** reduces database queries
6. **Vector similarity search** enables semantic memory sharing


## Default Agents

TMWS includes 6 pre-configured Trinitas agents:

- **Athena** - System orchestration and coordination
- **Artemis** - Performance optimization and technical excellence
- **Hestia** - Security analysis and audit
- **Eris** - Tactical planning and team coordination
- **Hera** - Strategic planning and architecture
- **Muses** - Documentation and knowledge management

## Custom Agents

You can register your own agents dynamically. See [CUSTOM_AGENTS_GUIDE.md](CUSTOM_AGENTS_GUIDE.md) for details.

## Environment Variables

All configuration is managed via `.env` file. Key variables:

### Required
- `TMWS_DATABASE_URL` - PostgreSQL connection string (e.g., `postgresql://tmws_user:tmws_password@localhost:5432/tmws`)
- `TMWS_SECRET_KEY` - Security key (32+ characters, auto-generated if not set)

### Agent Configuration
- `TMWS_AGENT_ID` - Agent identifier (e.g., "athena-conductor")
- `TMWS_AGENT_NAMESPACE` - Agent namespace (default: "trinitas")
- `TMWS_ALLOW_DEFAULT_AGENT` - Allow fallback agent for testing (default: "true")

### Optional
- `TMWS_LOG_LEVEL` - Logging level (default: "INFO")
- `MCP_MODE` - Set to "true" for MCP server mode

## Requirements

- Python 3.11+
- PostgreSQL with pgvector extension
- uv package manager (for uvx installation)

## Documentation

- [Custom Agents Guide](CUSTOM_AGENTS_GUIDE.md) - How to register and manage custom agents
- [Example Configuration](custom_agents_example.json) - Sample custom agent definitions

## License

Copyright (c) 2025 Apto AS