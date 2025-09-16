# TMWS - Trinitas Memory & Workflow Service

[![Version](https://img.shields.io/badge/version-2.2.0-blue)](https://github.com/apto-as/tmws)
[![Python](https://img.shields.io/badge/python-3.11%2B-green)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-purple)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-orange)](https://modelcontextprotocol.io)

A unified memory and workflow service for AI agents, providing both REST API and MCP (Model Context Protocol) interfaces.

## 🚀 Quick Start

### One-Command Setup (Recommended)

```bash
# Install and run directly with uvx
uvx --from git+https://github.com/apto-as/tmws.git@v2.2.0 tmws
```

### Database Setup

```bash
# Quick setup for development
./scripts/setup_db_quick.sh

# Or manual setup
createdb tmws
psql tmws -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

## Features

- 🧠 **Semantic Memory**: PostgreSQL + pgvector for intelligent memory storage and retrieval
- 🤖 **Multi-Agent Support**: Pre-configured with 6 Trinitas agents + custom agent registration
- 🔄 **Dynamic Agent Switching**: Runtime agent context switching via MCP tools
- 📋 **Task Management**: Workflow orchestration and task tracking
- 🔌 **MCP Protocol**: Full Model Context Protocol support
- 🔒 **Security**: JWT authentication, rate limiting, audit logging
- 🌐 **Unified Server**: Single instance handles both REST API and MCP connections
- 🚀 **Performance**: Sub-100ms vector search with IVFFlat indexing

## Prerequisites

### PostgreSQL Setup

TMWS requires PostgreSQL with pgvector extension:

```bash
# 1. Create database and user
createdb tmws
createuser tmws_user

# 2. Set password for user
psql postgres -c "ALTER USER tmws_user WITH PASSWORD 'tmws_password';"

# 3. Grant privileges
psql postgres -c "GRANT ALL PRIVILEGES ON DATABASE tmws TO tmws_user;"

# 4. Enable required extensions
PGPASSWORD=tmws_password psql -U tmws_user -d tmws -c "CREATE EXTENSION IF NOT EXISTS vector;"
PGPASSWORD=tmws_password psql -U tmws_user -d tmws -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;"

# 5. Create database tables
python setup_database.py
```

### Environment Configuration

Copy `.env.example` to `.env` and configure:

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your settings
# Key configurations:
# - TMWS_DATABASE_URL=postgresql://tmws_user:tmws_password@localhost:5432/tmws
# - TMWS_AGENT_ID=athena-conductor
# - TMWS_AGENT_NAMESPACE=trinitas
```

## Installation & Usage

### Quick Start (v2.0 - Shared Server Model)

#### Step 1: Start the TMWS Server

```bash
# Start the server (in a separate terminal)
uvx --from git+https://github.com/apto-as/tmws.git tmws-server

# Or with custom settings
tmws-server --host 0.0.0.0 --port 8000 --log-level info
```

#### Step 2: Configure Claude Code

Add to your Claude Code config:

```json
{
  "mcpServers": {
    "tmws": {
      "type": "stdio",
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/apto-as/tmws.git",
        "tmws-ws-client",
        "--server",
        "ws://localhost:8000/ws/mcp"
      ]
    }
  }
}
```

Now you can open multiple Claude Code terminals and they will all connect to the same server!

### Legacy Mode (v1.0 - Direct Connection)

For single terminal use only:

```json
{
  "mcpServers": {
    "tmws": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/apto-as/tmws.git", "tmws"]
    }
  }
}
```

Note: v1.0 mode does not support multiple concurrent connections.

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