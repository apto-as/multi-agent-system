# TMWS Project Overview

## Project Purpose
TMWS (Trinitas Memory & Workflow Service) is a **multi-agent memory and workflow orchestration platform** with semantic search capabilities. It enables AI agents to store, retrieve, and share memories across projects with namespace isolation.

## Current Version
- **Version**: v2.2.6 (v2.3.0 in README)
- **Architecture**: SQLite + ChromaDB (PostgreSQL support removed in v2.2.6)
- **MCP Compatible**: Yes (Model Context Protocol for Claude Desktop)

## Tech Stack

### Core Technologies
- **Language**: Python 3.11+
- **MCP Framework**: FastMCP v0.1.0+
- **Database**: 
  - SQLite with aiosqlite (async driver) - Metadata storage
  - ChromaDB v0.4.22+ - Vector search (1024-dim Multilingual-E5-Large via Ollama)
- **ORM**: SQLAlchemy 2.0.23+ (async)
- **Migration**: Alembic 1.12.0+

### Supporting Services
- **Redis**: Optional (agent/task coordination, < 1ms P95)
- **Celery**: Background tasks
- **Ollama**: Embedding generation (REQUIRED as of v2.3.0)

### Security
- JWT authentication (python-jose, PyJWT)
- Password hashing (passlib with bcrypt)
- HTML sanitization (bleach)
- Secrets management (hvac for HashiCorp Vault)

### Monitoring
- Prometheus metrics
- Structured logging (structlog)
- OpenTelemetry support (optional)

## Architecture Highlights

### Dual Storage Architecture
```
┌──────────────────────────────────────┐
│ SQLite (Metadata)                    │
│ - Agent registry                     │
│ - Memory metadata                    │
│ - Tasks, workflows, audit logs       │
│ - Access control (namespaces)        │
└──────────────────────────────────────┘

┌──────────────────────────────────────┐
│ ChromaDB (Vectors)                   │
│ - 1024-dim Multilingual-E5-Large     │
│ - Semantic search: 5-20ms P95        │
│ - HNSW index (M=16, ef=200)          │
│ - 10K hot cache                      │
└──────────────────────────────────────┘

┌──────────────────────────────────────┐
│ Ollama (Embeddings) - REQUIRED       │
│ - zylonai/multilingual-e5-large      │
│ - 1024 dimensions                    │
│ - No fallback (fail-fast)            │
└──────────────────────────────────────┘
```

### Performance Targets (Achieved)
- **Vector search**: 5-20ms P95 ✅
- **Metadata queries**: < 20ms P95 ✅
- **Agent operations**: < 1ms P95 (with Redis) ✅
- **Cross-agent sharing**: < 15ms P95 ✅

## Key Features

1. **Namespace Isolation**: Multi-project memory separation
2. **Semantic Search**: ChromaDB-powered vector search
3. **Access Control**: 5 levels (PRIVATE, TEAM, SHARED, PUBLIC, SYSTEM)
4. **Agent Coordination**: Redis-based real-time coordination
5. **Workflow Orchestration**: Multi-step task execution
6. **MCP Integration**: Claude Desktop native support

## Default Trinitas Agents
- **Athena** (athena-conductor): System orchestration
- **Artemis** (artemis-optimizer): Performance optimization
- **Hestia** (hestia-auditor): Security analysis
- **Eris** (eris-coordinator): Tactical planning
- **Hera** (hera-strategist): Strategic planning
- **Muses** (muses-documenter): Documentation
