# TMWS - Trinitas Memory & Workflow Service

[![Version](https://img.shields.io/badge/version-2.4.19-blue)](https://github.com/apto-as/tmws)
[![Python](https://img.shields.io/badge/python-3.11%2B-green)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-purple)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-orange)](https://modelcontextprotocol.io)

**Ultra-fast, multi-agent memory and workflow service with SQLite + ChromaDB architecture.**

## What's New in v2.4.19

- **Issue #73: ChromaDB Skills Extension**: Unified search across Skills, Tools, and MCP servers with 85% token reduction
- **Issue #74: Persona Linguistic Calibration**: GFL2 character-based language profiles for 11 Trinitas personas
- **Issue #75: SubAgent Conversation Logging**: Full conversation capture with pattern learning export

### Previous Releases

**v2.4.18**: Gap Integration Complete - 85% Feature Utilization Achieved
**v2.4.6

- **P3 Security Enhancements**: Enhanced credential protection and command validation
- **R-1 Env Masking**: Automatic detection and masking of API keys, secrets, tokens (13 patterns)
- **R-2 Command Whitelist**: 18 allowed commands, 14 dangerous commands blocked

### Previous Releases

**v2.4.5**: OpenCode support, multi-environment detection, security hardening
**v2.4.4**: Rate limit bypass fix, cache cleanup, thread-safety improvements
**v2.4.3**: Redis removed, Docker-only deployment, local rate limiting

---

## Quick Start (Docker)

### Prerequisites

- Docker and Docker Compose
- Ollama (for embeddings)

### 1. Prepare Ollama

```bash
# Install Ollama
brew install ollama  # macOS
# or: curl -fsSL https://ollama.ai/download.sh | sh  # Linux

# Start Ollama
ollama serve

# Pull embedding model
ollama pull zylonai/multilingual-e5-large
```

### 2. Clone and Configure

```bash
git clone https://github.com/apto-as/tmws.git
cd tmws

# Copy example environment
cp .env.example .env

# Edit .env and set your license key
# TMWS_LICENSE_KEY=TMWS-FREE-your-key-here
```

### 3. Start TMWS

```bash
docker-compose up -d
```

### 4. Verify

```bash
# Check health
curl http://localhost:8000/health

# Check logs
docker-compose logs -f tmws
```

---

## License Configuration

TMWS requires a license key to start.

### License Tiers

| Tier | Agents | Support |
|------|--------|---------|
| **FREE** | 1 agent | Community |
| **STANDARD** | 10 agents | Internal |
| **ENTERPRISE** | Unlimited | Priority |

### Setting License Key

Add to `.env` file:
```bash
TMWS_LICENSE_KEY=TMWS-FREE-your-actual-key-here
```

Or set environment variable:
```bash
export TMWS_LICENSE_KEY="TMWS-FREE-your-actual-key-here"
```

### License Validation

- **Missing License**: TMWS will not start (exit code 1)
- **Invalid License**: TMWS will not start with error message
- **Valid License**: TMWS starts and logs license tier
- **Expired License**: 7-day grace period (warning logs)

---

## Claude Desktop Integration

Add to your Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "tmws": {
      "command": "docker",
      "args": ["exec", "-it", "tmws", "tmws-mcp-server"],
      "env": {
        "TMWS_LICENSE_KEY": "TMWS-FREE-your-actual-key-here"
      }
    }
  }
}
```

---

## Architecture

### SQLite + ChromaDB

TMWS uses a dual-storage architecture:

| Component | Purpose | Performance |
|-----------|---------|-------------|
| **SQLite** | Metadata, auth, audit logs | < 20ms P95 |
| **ChromaDB** | Vector embeddings, semantic search | < 5ms P95 |
| **Ollama** | Embedding generation (1024-dim) | Required |

```
User Request
    ↓
┌─────────────────────────────────────┐
│           TMWS Service              │
├─────────────────────────────────────┤
│  SQLite (WAL mode)                  │
│  - Metadata storage                 │
│  - Authentication                   │
│  - Audit logging                    │
├─────────────────────────────────────┤
│  ChromaDB (DuckDB backend)          │
│  - Vector storage                   │
│  - Semantic search                  │
│  - HNSW indexing                    │
├─────────────────────────────────────┤
│  Ollama                             │
│  - multilingual-e5-large            │
│  - 1024-dimensional embeddings      │
└─────────────────────────────────────┘
```

### Performance

| Operation | Target | Achieved |
|-----------|--------|----------|
| Vector Search | < 20ms | 0.47ms P95 |
| Memory Store | < 5ms | 2ms P95 |
| Metadata Query | < 20ms | 2.63ms P95 |

---

## Environment Variables

### Required

```bash
# Database
TMWS_DATABASE_URL=sqlite+aiosqlite:///./data/tmws.db

# Security
TMWS_SECRET_KEY=your-secret-key-minimum-32-characters-long

# License
TMWS_LICENSE_KEY=TMWS-FREE-your-key-here

# Environment
TMWS_ENVIRONMENT=production
```

### Optional

```bash
# Agent Configuration
TMWS_AGENT_ID=athena-conductor
TMWS_AGENT_NAMESPACE=trinitas

# ChromaDB
TMWS_CHROMA_PERSIST_DIRECTORY=./data/chroma
TMWS_CHROMA_COLLECTION=tmws_memories

# Ollama
TMWS_OLLAMA_BASE_URL=http://localhost:11434
TMWS_OLLAMA_EMBEDDING_MODEL=zylonai/multilingual-e5-large

# Logging
TMWS_LOG_LEVEL=INFO
```

---

## Default Agents

TMWS includes 6 pre-configured Trinitas agents:

| Agent | ID | Specialty |
|-------|-----|-----------|
| **Athena** | athena-conductor | System orchestration |
| **Artemis** | artemis-optimizer | Performance optimization |
| **Hestia** | hestia-auditor | Security analysis |
| **Eris** | eris-coordinator | Tactical planning |
| **Hera** | hera-strategist | Strategic planning |
| **Muses** | muses-documenter | Documentation |

---

## MCP Tools

### Memory Management

```python
# Store memory
store_memory(content="...", importance=0.9, tags=["ml", "success"])

# Search memories
search_memories(query="optimization", limit=10, min_similarity=0.7)

# Update/Delete
update_memory(memory_id="uuid", content="updated")
delete_memory(memory_id="uuid")
```

### Agent Management

```python
# Register agent
register_agent(agent_id="custom", namespace="team", capabilities=["analysis"])

# List agents
list_agents(namespace="trinitas", limit=10)

# Heartbeat
heartbeat(agent_id="athena-conductor")
```

### Task Management

```python
# Create task
create_task(title="...", priority="HIGH", assigned_persona="artemis-optimizer")

# Update status
update_task_status(task_id="uuid", status="in_progress", progress=50)

# List tasks
list_tasks(status="pending", priority="HIGH")
```

---

## Security

### Production Checklist

- [ ] Set `TMWS_ENVIRONMENT=production`
- [ ] Generate secure `TMWS_SECRET_KEY` (32+ characters)
- [ ] Configure firewall rules
- [ ] Review audit logs regularly
- [ ] Set up automated backups

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Email: security@apto.as with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

---

## Documentation

- [DOCKER_QUICKSTART.md](DOCKER_QUICKSTART.md) - Docker deployment guide
- [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) - Claude Desktop integration
- [docs/MCP_TOOLS_REFERENCE.md](docs/MCP_TOOLS_REFERENCE.md) - MCP tools reference

---

## Support

- **Issues**: [GitHub Issues](https://github.com/apto-as/tmws/issues)
- **Discussions**: [GitHub Discussions](https://github.com/apto-as/tmws/discussions)

---

## License

Copyright (c) 2025 Apto AS

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

**TMWS v2.4.19** - Ultra-fast memory and workflow service for AI agents (MCP-first architecture)
