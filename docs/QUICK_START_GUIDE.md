# TMWS Quick Start Guide for Trinitas-agents
## Get Your Agent Connected and Running in 15 Minutes

**Version**: v2.3.0
**Target Audience**: Trinitas-agents Development Team
**Time to Complete**: 10-15 minutes
**Prerequisites**: Python 3.11+, Git

---

## What is TMWS?

**TMWS (Trinitas Memory & Workflow System)** is your agent's persistent memory and workflow orchestration platform. It provides:

- **21 MCP Tools** for memory, task, and workflow management
- **Semantic Search** with ChromaDB (5-20ms P95)
- **Learning Pattern System** (Agent Skills TMWS version)
- **Multi-Agent Coordination** with namespace isolation
- **REST API** for managing external MCP connections

### Architecture Overview

```
┌─────────────────────────────────────────────────┐
│  Trinitas-agents (Your Agent)                   │
│  ├─ Uses 21 MCP Tools via Claude Code           │
│  ├─ Stores memories, patterns, tasks            │
│  └─ Coordinates with other agents               │
└─────────────────────────────────────────────────┘
                    ↓ MCP Protocol
┌─────────────────────────────────────────────────┐
│  TMWS MCP Server                                │
│  ├─ Core Memory (3 tools)                       │
│  ├─ System Tools (3 tools)                      │
│  ├─ Expiration Management (10 tools)            │
│  ├─ Trust & Verification (5 tools)              │
│  └─ Learning Patterns (Agent Skills)            │
└─────────────────────────────────────────────────┘
                    ↓ Storage
┌─────────────────────────────────────────────────┐
│  Dual Storage Architecture                      │
│  ├─ SQLite: Metadata, relationships, ACL        │
│  └─ ChromaDB: 1024-dim semantic vectors         │
└─────────────────────────────────────────────────┘
```

---

## Step 1: Install Prerequisites (3 minutes)

### 1.1 Install Ollama (Required for Embeddings)

TMWS uses **Multilingual-E5-Large** (1024 dimensions) via Ollama:

```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Pull embedding model
ollama pull zylonai/multilingual-e5-large

# Start Ollama server
ollama serve
```

**Verify Ollama is Running**:
```bash
curl http://localhost:11434/api/tags
# Should return JSON with available models
```

### 1.2 Install TMWS

```bash
# Clone repository
git clone https://github.com/apto-as/tmws.git
cd tmws

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e .

# Initialize database
alembic upgrade head

# Set environment variables
export TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"
export TMWS_SECRET_KEY="$(openssl rand -hex 32)"
export TMWS_ENVIRONMENT="development"
```

---

## Step 2: Configure Claude Code (2 minutes)

Add TMWS MCP server to your Claude Code configuration:

**File**: `~/.config/claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "tmws": {
      "command": "/absolute/path/to/tmws/.venv/bin/python",
      "args": ["-m", "src.mcp_server"],
      "cwd": "/absolute/path/to/tmws",
      "env": {
        "TMWS_DATABASE_URL": "sqlite+aiosqlite:///./data/tmws.db",
        "TMWS_SECRET_KEY": "your-generated-secret-key-from-step-1",
        "TMWS_ENVIRONMENT": "development"
      }
    }
  }
}
```

**⚠️ Important**: Replace `/absolute/path/to/tmws` with your actual TMWS installation path.

**Restart Claude Code** to load the MCP server.

---

## Step 3: Your First Memory (2 minutes)

### 3.1 Store a Memory

```python
# In Claude Code, you can now use TMWS tools directly
await store_memory(
    content="TMWS installation completed successfully. Agent artemis-optimizer is now operational.",
    importance_score=0.9,
    tags=["milestone", "setup", "agent:artemis"],
    namespace="trinitas-agents"
)
```

**Expected Response** (< 5ms):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "content": "TMWS installation completed...",
  "importance_score": 0.9,
  "tags": ["milestone", "setup", "agent:artemis"],
  "namespace": "trinitas-agents",
  "created_at": "2025-11-14T10:30:00.123456Z"
}
```

### 3.2 Search Your Memories (Semantic Search)

```python
# Semantic search with ChromaDB
results = await search_memories(
    query="How did the installation go?",
    limit=5,
    min_similarity=0.7,
    namespace="trinitas-agents"
)
```

**Expected Response** (5-20ms P95):
```json
{
  "results": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "content": "TMWS installation completed successfully...",
      "similarity": 0.95,
      "importance_score": 0.9,
      "tags": ["milestone", "setup", "agent:artemis"]
    }
  ],
  "search_time_ms": 12.4,
  "total_results": 1
}
```

---

## Step 4: Your First Learning Pattern (Agent Skills) (3 minutes)

TMWS's **Learning Pattern System** is the database-based equivalent of Anthropic's Agent Skills (`.claude/skills/` directories).

### 4.1 Create a Learning Pattern

```python
# Store a reusable pattern
pattern_id = await create_learning_pattern(
    pattern_name="optimization_database_query",
    category="performance",
    subcategory="database",
    pattern_data={
        "description": "Add composite index for frequently queried columns",
        "steps": [
            "Identify slow queries with EXPLAIN ANALYZE",
            "Create composite index on filtered + sorted columns",
            "Verify with EXPLAIN to confirm index usage"
        ],
        "example": "CREATE INDEX idx_posts_user_created ON posts(user_id, created_at DESC);",
        "expected_improvement": "60-85% query latency reduction"
    },
    access_level="team",  # Share with team
    namespace="trinitas-agents"
)
```

### 4.2 Apply the Pattern

```python
# Later, retrieve and apply the pattern
pattern = await get_learning_pattern(
    pattern_name="optimization_database_query",
    namespace="trinitas-agents"
)

# Pattern contains all the knowledge to apply
print(pattern["pattern_data"]["steps"])
# Use the pattern to optimize your database queries
```

### 4.3 Track Pattern Success

```python
# After applying the pattern, record the outcome
await record_pattern_usage(
    pattern_id=pattern_id,
    success=True,
    execution_time_ms=150,  # Query time after optimization
    context={"table": "posts", "improvement": "85%"}
)
```

**Why Learning Patterns?**
- **Persistent Knowledge**: Survives across agent restarts
- **Team Sharing**: Share successful patterns across agents
- **Version Control**: Track pattern evolution over time
- **Success Metrics**: Learn which patterns work best
- **Access Control**: Private, Team, Shared, Public, System levels

---

## Step 5: Your First Task (2 minutes)

```python
# Create a coordinated task
task = await create_task(
    title="Implement Phase 2 authentication features",
    description="Add JWT token refresh and role-based access control",
    priority="high",
    assigned_agent_id="artemis-optimizer",
    due_date="2025-11-20T17:00:00Z",
    estimated_duration=240  # minutes
)
```

**Expected Response**:
```json
{
  "id": "task-123",
  "title": "Implement Phase 2 authentication features",
  "status": "pending",
  "assigned_agent_id": "artemis-optimizer",
  "created_at": "2025-11-14T10:30:00Z"
}
```

---

## Step 6: Agent Trust & Verification (3 minutes)

TMWS includes a **Trust System** for verifying agent claims:

### 6.1 Verify a Claim

```python
# Artemis claims tests passed - let's verify
result = await verify_and_record(
    agent_id="artemis-optimizer",
    claim_type="test_result",
    claim_content={
        "passed": 150,
        "failed": 0,
        "coverage": 92.5
    },
    verification_command="pytest tests/unit/ -v --cov=src"
)
```

**Expected Response**:
```json
{
  "claim": {"passed": 150, "failed": 0, "coverage": 92.5},
  "actual": {"passed": 148, "failed": 2, "coverage": 91.2},
  "accurate": false,
  "evidence_id": "evidence-456",
  "new_trust_score": 0.73
}
```

### 6.2 Check Agent Trust Score

```python
# Get agent's trust score
trust_info = await get_agent_trust_score(
    agent_id="artemis-optimizer"
)
```

**Expected Response**:
```json
{
  "agent_id": "artemis-optimizer",
  "trust_score": 0.73,
  "total_verifications": 25,
  "accurate_verifications": 18,
  "verification_accuracy": 0.72,
  "requires_verification": true,
  "is_reliable": true
}
```

---

## Complete MCP Tools Reference (21 Tools)

TMWS provides 21 MCP tools organized into 4 categories:

### Core Memory (3 tools)
1. **store_memory** - Store information in hybrid semantic memory
2. **search_memories** - Search with semantic similarity
3. **create_task** - Create coordinated tasks

### System Tools (3 tools)
4. **get_agent_status** - Get connected agents status
5. **get_memory_stats** - Get memory system statistics
6. **invalidate_cache** - Clear ChromaDB cache (testing)

### Expiration Management (10 tools)
7. **prune_expired_memories** - Remove expired memories from namespace
8. **get_expiration_stats** - Get expiration statistics
9. **set_memory_ttl** - Update TTL for existing memory
10. **cleanup_namespace** - Delete ALL memories from namespace (admin-only)
11. **get_namespace_stats** - Get comprehensive namespace statistics
12. **get_scheduler_status** - Get expiration scheduler status
13. **configure_scheduler** - Configure scheduler interval (admin-only)
14. **start_scheduler** - Start expiration scheduler (admin-only)
15. **stop_scheduler** - Stop expiration scheduler (admin-only)
16. **trigger_scheduler** - Manually trigger cleanup

### Trust & Verification (5 tools)
17. **verify_and_record** - Verify claim and record evidence
18. **get_agent_trust_score** - Get agent trust score and statistics
19. **get_verification_history** - Get agent verification history
20. **get_verification_statistics** - Get comprehensive statistics
21. **get_trust_history** - Get agent trust score history

**Detailed Reference**: See `docs/MCP_TOOLS_REFERENCE.md` (coming in Phase 1-3)

---

## Common Use Cases

### Use Case 1: Daily Standup Memory

```python
# Store daily progress
await store_memory(
    content="""
    Daily Progress - 2025-11-14:
    - Completed: Phase 1-2 authentication features
    - In Progress: Phase 1-3 rate limiting
    - Blocked: Waiting for Hestia's security review
    - Next: Implement JWT refresh tokens
    """,
    importance_score=0.7,
    tags=["daily-standup", "progress", "2025-11-14"],
    namespace="trinitas-agents"
)

# Later, search for recent progress
await search_memories(
    query="What did I work on this week?",
    namespace="trinitas-agents",
    tags=["daily-standup"]
)
```

### Use Case 2: Share Knowledge Across Agents

```python
# Artemis discovers optimization pattern
pattern_id = await create_learning_pattern(
    pattern_name="async_database_connection_pooling",
    category="performance",
    pattern_data={
        "description": "Use connection pooling to improve async DB performance",
        "implementation": "pool_config = {'pool_size': 10, 'max_overflow': 20}",
        "impact": "+30% throughput improvement"
    },
    access_level="team",  # Share with all Trinitas agents
    namespace="trinitas-agents"
)

# Hera retrieves the pattern for strategic planning
pattern = await get_learning_pattern(
    pattern_name="async_database_connection_pooling",
    namespace="trinitas-agents"
)
```

### Use Case 3: Security Audit Trail

```python
# Hestia performs security audit
audit_memory = await store_memory(
    content="""
    Security Audit - 2025-11-14:
    - Scanned: 234 files
    - Vulnerabilities: 3 (2 HIGH, 1 MEDIUM)
    - V-AUTH-1: JWT secret key hardcoded in config.py (CVSS 9.1)
    - V-SQL-2: SQL injection in user_search() (CVSS 8.7)
    - V-XSS-3: Unescaped user input in template (CVSS 6.5)
    - Action Required: Fix V-AUTH-1 and V-SQL-2 within 24 hours
    """,
    importance_score=1.0,  # Maximum importance
    tags=["security", "audit", "critical", "hestia"],
    namespace="trinitas-agents"
)

# Later, verify fixes with trust system
await verify_and_record(
    agent_id="artemis-optimizer",
    claim_type="security_fix",
    claim_content={"vulnerability": "V-AUTH-1", "fixed": true},
    verification_command="rg 'SECRET_KEY.*=' src/ --type py"
)
```

---

## Troubleshooting

### Issue 1: "Ollama connection failed"

**Symptom**:
```
EmbeddingServiceError: Ollama is required but unavailable
```

**Solution**:
```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# If not running, start it
ollama serve

# Verify model is installed
ollama list | grep multilingual-e5-large

# If not installed, pull it
ollama pull zylonai/multilingual-e5-large
```

### Issue 2: "MCP server tmws failed to start"

**Symptom**: Claude Code shows "MCP server error" or TMWS tools are unavailable.

**Solution**:
```bash
# Test MCP server manually
cd /path/to/tmws
source .venv/bin/activate
python -m src.mcp_server

# Check for errors in output
# Common issues:
# - Missing .venv/bin/python path in config
# - Incorrect TMWS_DATABASE_URL
# - Missing TMWS_SECRET_KEY
```

### Issue 3: "Namespace validation failed"

**Symptom**:
```
ValidationError: Namespace 'default' is reserved and cannot be used
```

**Solution**: TMWS enforces namespace isolation for security. Always provide a specific namespace:

```python
# ❌ Wrong - uses reserved 'default' namespace
await store_memory(content="...", namespace="default")

# ✅ Correct - use project/team namespace
await store_memory(content="...", namespace="trinitas-agents")
```

### Issue 4: "Database is locked"

**Symptom**:
```
sqlite3.OperationalError: database is locked
```

**Solution**: Enable WAL mode for better concurrency:

```bash
sqlite3 data/tmws.db "PRAGMA journal_mode=WAL;"
```

---

## Next Steps

### Layer 2: Complete Reference (Detailed Documentation)

1. **MCP_TOOLS_REFERENCE.md** - All 21 tools with examples, parameters, performance metrics
2. **LEARNING_PATTERN_API.md** - Complete Learning Pattern System guide (Agent Skills)
3. **REST_API_GUIDE.md** - 4 REST API endpoints for external MCP connection management
4. **INTEGRATION_PATTERNS.md** - 8 integration workflows for common scenarios
5. **SECURITY_GUIDE.md** - P0-1 compliance, namespace isolation, RBAC

### Layer 3: Advanced Topics

6. **PERFORMANCE_TUNING.md** - Optimization strategies and benchmarks
7. **PRODUCTION_DEPLOYMENT.md** - Production setup, monitoring, backup
8. **TROUBLESHOOTING.md** - Comprehensive troubleshooting guide

---

## Performance Expectations

Based on v2.3.0 benchmarks:

| Operation | Target | Typical | Status |
|-----------|--------|---------|--------|
| store_memory | < 5ms | 2-4ms | ✅ |
| search_memories | < 20ms | 5-20ms | ✅ |
| get_learning_pattern | < 10ms | 3-8ms | ✅ |
| verify_and_record | < 100ms | 50-80ms | ✅ |
| create_task | < 10ms | 5-10ms | ✅ |

**ChromaDB Performance** (1024-dim vectors):
- Vector similarity search: < 10ms P95 ✅
- Metadata filtering: < 20ms P95 ✅
- Cross-agent sharing: < 15ms P95 ✅

---

## Security Considerations

### Namespace Isolation (P0-1 Compliance)

TMWS enforces strict namespace isolation:

- **Never trust JWT claims**: Namespace is verified from database
- **Authorization pattern**: Fetch agent → Verify namespace → Check access
- **Access levels**: PRIVATE, TEAM, SHARED, PUBLIC, SYSTEM

```python
# ✅ Secure - namespace verified from DB
agent = await get_agent_from_db(agent_id)
verified_namespace = agent.namespace
memory.is_accessible_by(agent_id, verified_namespace)

# ❌ Insecure - never trust JWT claims directly
namespace = jwt_claims.get("namespace")  # Security risk!
```

### Rate Limiting

TMWS REST API includes fail-secure rate limiting:

- **Development**: Lenient limits (30-200 requests/min)
- **Production**: Strict limits (10-100 requests/min)
- **Test**: Disabled for automated testing

### Audit Logging

All security-sensitive operations are logged:

- Memory creation/deletion
- Pattern modifications
- Task assignments
- Trust score changes

---

## Support & Resources

- **GitHub Issues**: https://github.com/apto-as/tmws/issues
- **Documentation**: `docs/` directory
- **Security Issues**: See `SECURITY.md`
- **Development Setup**: `docs/DEVELOPMENT_SETUP.md`

---

## Quick Reference Card

```bash
# Core Memory Operations
await store_memory(content, importance_score, tags, namespace)
await search_memories(query, limit, min_similarity, namespace)

# Learning Patterns (Agent Skills)
await create_learning_pattern(pattern_name, category, pattern_data, access_level)
await get_learning_pattern(pattern_name, namespace)
await record_pattern_usage(pattern_id, success, execution_time_ms)

# Task Management
await create_task(title, priority, assigned_agent_id, due_date)

# Trust & Verification
await verify_and_record(agent_id, claim_type, claim_content, verification_command)
await get_agent_trust_score(agent_id)

# System Monitoring
await get_memory_stats()
await get_agent_status()
await get_namespace_stats(agent_id, namespace)
```

---

**🎉 Congratulations!** You've completed the TMWS quick start. Your Trinitas agent is now equipped with:

- ✅ Persistent semantic memory
- ✅ Learning pattern system (Agent Skills)
- ✅ Task coordination
- ✅ Trust verification
- ✅ Multi-agent collaboration

**Estimated setup time**: 10-15 minutes ✅
**Time to first success**: < 5 minutes ✅

**Next**: Dive into the complete reference documentation for advanced features and integration patterns.

---

**Document Author**: Muses (Knowledge Architect)
**Reviewed By**: Athena (Harmonious Conductor), Hera (Strategic Commander)
**Last Updated**: 2025-11-14
**Status**: Production-ready
**Version**: 1.0.0
