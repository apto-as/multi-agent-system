# TMWS v2.4.8 OpenCode Test Guide
## Docker MCP Server Verification Protocol

**Created**: 2025-11-29
**Version**: v2.4.8-test
**Status**: Claude Code Tests PASSED - Ready for OpenCode Verification

---

## Executive Summary

TMWS v2.4.8 Docker deployment has been validated through Claude Code. This document provides the test procedures for verification in OpenCode environment.

### Claude Code Test Results (Reference)

| Phase | Test | Result |
|-------|------|--------|
| 1 | MCP Connection | PASS |
| 2 | Agent Functions (9 agents) | PASS |
| 3 | Memory CRUD + Semantic Search | PASS |
| 4 | License Validation (Ed25519) | PASS |
| 5 | Data Persistence (container restart) | PASS |
| 6 | Security Isolation (namespace) | PASS |

### Bug Fixed During Testing

**AgentService.list_agents() AttributeError**
- File: `src/services/agent_service.py`
- Lines: 175, 433
- Issue: Referenced `Agent.last_activity` (non-existent)
- Fix: Changed to `Agent.last_active_at`
- Docker image rebuilt with fix

---

## Prerequisites

### Docker Environment

```bash
# Navigate to deployment directory
cd ~/tmws-docker/claude-code

# Verify container is running
docker ps --filter "name=tmws"

# Expected output:
# NAMES      STATUS
# tmws-app   Up X minutes (healthy)
```

### MCP Configuration for OpenCode

Add to your OpenCode MCP configuration:

```json
{
  "mcpServers": {
    "tmws": {
      "command": "docker",
      "args": [
        "exec", "-i", "tmws-app",
        "python", "-m", "src.mcp_server"
      ],
      "env": {}
    }
  }
}
```

---

## Test Procedures

### Phase 1: MCP Connection Test

**Objective**: Verify MCP server responds to basic queries

**MCP Tools to Test**:
```
get_agent_status
get_memory_stats
```

**Expected Results**:
- `get_agent_status`: Returns 9 agents
- `get_memory_stats`: Shows ChromaDB available

**Manual Verification** (if MCP tools unavailable):
```bash
docker exec -it tmws-app python -c "
from src.mcp_server import HybridMCPServer
print('MCP Server: OK')
"
```

---

### Phase 2: Agent Function Test

**Objective**: Verify all 9 Trinitas agents are registered and active

**Agents to Verify**:

| Agent ID | Display Name | Type |
|----------|--------------|------|
| athena-conductor | Athena - Harmonious Conductor | coordinator |
| artemis-optimizer | Artemis - Technical Perfectionist | optimizer |
| hestia-auditor | Hestia - Security Guardian | auditor |
| eris-coordinator | Eris - Tactical Coordinator | coordinator |
| hera-strategist | Hera - Strategic Commander | strategist |
| muses-documenter | Muses - Knowledge Architect | documenter |
| aphrodite-designer | Aphrodite - UI/UX Designer | designer |
| metis-developer | Metis - Development Assistant | developer |
| aurora-researcher | Aurora - Research Assistant | researcher |

**MCP Tool**:
```
list_agents (namespace: "trinitas")
```

**Manual Verification**:
```bash
docker exec -it tmws-app python -c "
import asyncio
from sqlalchemy import text
from src.core.database import get_session_maker

async def check():
    session_maker = get_session_maker()
    async with session_maker() as session:
        result = await session.execute(text('SELECT agent_id, status FROM agents'))
        for row in result.fetchall():
            print(f'{row[0]}: {row[1]}')

asyncio.run(check())
"
```

**Expected**: All 9 agents with status `active`

---

### Phase 3: Memory CRUD + Semantic Search Test

**Objective**: Verify memory creation and multilingual semantic search

#### Test 3.1: Create Memory (Japanese)

**MCP Tool**: `store_memory`
```json
{
  "content": "OpenCodeテスト: TMWSメモリシステムの日本語セマンティック検索を検証中",
  "namespace": "trinitas",
  "tags": ["opencode", "test", "japanese"],
  "importance_score": 0.8
}
```

#### Test 3.2: Create Memory (English)

**MCP Tool**: `store_memory`
```json
{
  "content": "OpenCode Test: Validating TMWS memory system with English semantic search",
  "namespace": "trinitas",
  "tags": ["opencode", "test", "english"],
  "importance_score": 0.8
}
```

#### Test 3.3: Semantic Search (Japanese)

**MCP Tool**: `search_memories`
```json
{
  "query": "日本語メモリ検索",
  "namespace": "trinitas",
  "limit": 5
}
```

**Expected**: Returns Japanese content with high relevance score

#### Test 3.4: Semantic Search (English)

**MCP Tool**: `search_memories`
```json
{
  "query": "English memory validation",
  "namespace": "trinitas",
  "limit": 5
}
```

**Expected**: Returns English content with high relevance score

**Manual Verification**:
```bash
docker exec -it tmws-app python -c "
import asyncio
from src.core.database import get_session_maker
from src.mcp_server import HybridMemoryService

async def test():
    session_maker = get_session_maker()
    async with session_maker() as session:
        svc = HybridMemoryService(session)

        # Create
        r = await svc.create_memory(
            content='OpenCode manual test',
            agent_id='athena-conductor',
            namespace='trinitas',
            tags=['manual'],
            importance_score=0.7
        )
        print(f'Created: {r.id}')

        # Search
        results = await svc.search_memories(
            query='manual test',
            namespace='trinitas',
            limit=3
        )
        print(f'Found: {len(results)} results')
        await session.commit()

asyncio.run(test())
"
```

---

### Phase 4: License Validation Test

**Objective**: Verify license tier and feature access

**Key Concepts**:
- Agents have tiers: FREE, PRO, ENTERPRISE
- Features are enabled per tier
- Ed25519 signature verification available (CLI tools)

**Manual Verification**:
```bash
docker exec -it tmws-app python -c "
import asyncio
from sqlalchemy import text
from src.core.database import get_session_maker
from src.services.license_service import LicenseService, LicenseFeature

async def test():
    session_maker = get_session_maker()
    async with session_maker() as session:
        svc = LicenseService(session)

        # Get agent UUID
        r = await session.execute(text(
            \"SELECT id FROM agents WHERE agent_id = 'athena-conductor'\"
        ))
        uuid = str(r.fetchone()[0])

        # Get tier
        tier = await svc.get_agent_tier(uuid)
        print(f'Tier: {tier}')

        # Check features
        for f in [LicenseFeature.MEMORY_STORE, LicenseFeature.MEMORY_SEARCH]:
            enabled = svc.is_feature_enabled(tier, f)
            print(f'{f.value}: {\"ENABLED\" if enabled else \"DISABLED\"}')

        # Get limits
        limits = svc.get_tier_limits(tier)
        print(f'Max memories: {limits.max_memories_per_agent}')

asyncio.run(test())
"
```

**Expected Output**:
```
Tier: TierEnum.FREE
memory_store: ENABLED
memory_search: ENABLED
Max memories: 1000
```

---

### Phase 5: Data Persistence Test

**Objective**: Verify data survives container restart

#### Step 1: Record Current State
```bash
docker exec -it tmws-app python -c "
import asyncio
from sqlalchemy import text
from src.core.database import get_session_maker

async def check():
    session_maker = get_session_maker()
    async with session_maker() as session:
        r1 = await session.execute(text('SELECT COUNT(*) FROM agents'))
        r2 = await session.execute(text('SELECT COUNT(*) FROM memories'))
        print(f'Agents: {r1.scalar()}')
        print(f'Memories: {r2.scalar()}')

asyncio.run(check())
"
```

#### Step 2: Restart Container
```bash
cd ~/tmws-docker/claude-code
docker compose restart tmws
sleep 15  # Wait for healthy status
docker ps --filter "name=tmws"
```

#### Step 3: Verify Data Persisted
```bash
# Run same check as Step 1
# Counts should match
```

**Expected**: Agent and memory counts unchanged after restart

---

### Phase 6: Security Isolation Test

**Objective**: Verify namespace isolation prevents cross-tenant access

#### Test 6.1: Create in Different Namespaces

```bash
docker exec -it tmws-app python -c "
import asyncio
from src.core.database import get_session_maker
from src.mcp_server import HybridMemoryService

async def test():
    session_maker = get_session_maker()
    async with session_maker() as session:
        svc = HybridMemoryService(session)

        # Create in namespace-x
        await svc.create_memory(
            content='Secret X data',
            agent_id='athena-conductor',
            namespace='namespace-x',
            tags=['secret'],
            importance_score=0.9
        )

        # Create in namespace-y
        await svc.create_memory(
            content='Secret Y data',
            agent_id='artemis-optimizer',
            namespace='namespace-y',
            tags=['secret'],
            importance_score=0.9
        )

        await session.commit()

        # Search in namespace-x only
        results = await svc.search_memories(
            query='Secret data',
            namespace='namespace-x',
            limit=10
        )

        print(f'Results in namespace-x: {len(results)}')
        for r in results:
            content = r.content if hasattr(r, 'content') else r.get('content', '')
            has_y = 'Y data' in content
            print(f'  - Contains namespace-y data: {has_y}')

        # Verify isolation
        y_leaked = any('Y data' in (r.content if hasattr(r, 'content') else r.get('content', '')) for r in results)
        print(f'\\nIsolation: {\"FAIL\" if y_leaked else \"PASS\"}')

asyncio.run(test())
"
```

**Expected Output**:
```
Results in namespace-x: 1
  - Contains namespace-y data: False

Isolation: PASS
```

---

## Troubleshooting

### MCP Connection Issues

**Symptom**: "Not connected" error

**Solution**:
```bash
# Check container status
docker ps --filter "name=tmws"

# Check logs
docker logs tmws-app --tail 50

# Restart if needed
cd ~/tmws-docker/claude-code
docker compose restart tmws
```

### Import Errors in Container

**Symptom**: `ImportError: cannot import name 'X'`

**Cause**: Bytecode-only image has different module structure

**Solution**: Use the correct import paths:
```python
# Correct imports for bytecode image
from src.mcp_server import HybridMemoryService, HybridMCPServer
from src.core.database import get_session_maker
from src.services.license_service import LicenseService
```

### Database Locked

**Symptom**: `sqlite3.OperationalError: database is locked`

**Solution**:
```bash
# Restart container to release locks
docker compose restart tmws
```

---

## Quick Reference

### Key Docker Commands

```bash
# Start
cd ~/tmws-docker/claude-code && docker compose up -d

# Stop
docker compose down

# Restart
docker compose restart tmws

# Logs
docker logs tmws-app -f

# Shell access
docker exec -it tmws-app /bin/bash

# Python REPL
docker exec -it tmws-app python
```

### Key Paths in Container

| Path | Description |
|------|-------------|
| `/app/.tmws/db/tmws.db` | SQLite database |
| `/app/.tmws/chroma/` | ChromaDB vector storage |
| `/app/.tmws/logs/` | Application logs |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TMWS_ENVIRONMENT` | production | Environment mode |
| `TMWS_LOG_LEVEL` | INFO | Logging level |
| `TMWS_DATABASE_URL` | sqlite:///... | Database connection |

---

## Test Completion Checklist

- [ ] Phase 1: MCP Connection verified
- [ ] Phase 2: All 9 agents active
- [ ] Phase 3: Memory CRUD works
- [ ] Phase 3: Semantic search (Japanese) works
- [ ] Phase 3: Semantic search (English) works
- [ ] Phase 4: License tier detection works
- [ ] Phase 4: Feature access check works
- [ ] Phase 5: Data persists after restart
- [ ] Phase 6: Namespace isolation verified

---

## Contact

For issues or questions:
- GitHub: apto-as/tmws
- Documentation: /docs/

---

*Document generated by Trinitas Agent System*
*Athena (coordination) + Hestia (security) + Muses (documentation)*
