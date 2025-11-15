# TMWS MCP Tools Reference
## Complete Guide to 21 MCP Tools for Trinitas-agents

**Version**: v2.3.0
**Target Audience**: Trinitas-agents Development Team
**Last Updated**: 2025-11-14
**Status**: Production-ready

---

## Table of Contents

1. [Overview](#overview)
2. [Core Memory Tools (3)](#core-memory-tools)
3. [System Tools (3)](#system-tools)
4. [Expiration Management (10)](#expiration-management-tools)
5. [Trust & Verification (5)](#trust--verification-tools)
6. [Common Patterns](#common-patterns)
7. [Error Handling](#error-handling)
8. [Performance Metrics](#performance-metrics)

---

## Overview

TMWS provides **21 MCP tools** organized into 4 categories. All tools are accessible via Claude Code once the TMWS MCP server is configured.

### Quick Facts

- **Protocol**: Model Context Protocol (MCP)
- **Architecture**: Dual storage (SQLite + ChromaDB)
- **Embedding Model**: Multilingual-E5-Large (1024 dimensions)
- **Average Latency**: 2-20ms P95
- **Authentication**: Optional API key/JWT (security-sensitive operations)

### Tool Categories

| Category | Count | Tools |
|----------|-------|-------|
| Core Memory | 3 | store_memory, search_memories, create_task |
| System | 3 | get_agent_status, get_memory_stats, invalidate_cache |
| Expiration | 10 | prune/stats/TTL management, scheduler control |
| Verification | 5 | verify_and_record, trust scores, verification history |

---

## Core Memory Tools

These are the most frequently used tools for storing and retrieving information.

### store_memory

Store information in hybrid semantic memory (SQLite + ChromaDB).

**Signature**:
```python
store_memory(content: str, importance_score: float = 0.5, tags: list[str] = None, 
             namespace: str = None, context: dict = None) -> dict
```

**Performance**: ~2-4ms P95 ✅

**Example**:
```python
result = await store_memory(
    content="Phase 1-2 authentication features completed successfully.",
    importance_score=0.85,
    tags=["milestone", "phase1", "authentication"],
    namespace="trinitas-agents"
)
print(f"Stored: {result['memory_id']}")
```

**See**: [QUICK_START_GUIDE.md](QUICK_START_GUIDE.md#store_memory) for detailed examples.

---

### search_memories

Search semantic memories using ChromaDB vector search.

**Signature**:
```python
search_memories(query: str, limit: int = 10, min_similarity: float = 0.7,
                namespace: str = None, tags: list[str] = None) -> dict
```

**Performance**: ~5-20ms P95 ✅

**Example**:
```python
results = await search_memories(
    query="What did I work on this week?",
    namespace="trinitas-agents",
    tags=["daily-standup"]
)
for memory in results["results"]:
    print(f"[{memory['similarity']:.0%}] {memory['content'][:100]}")
```

**See**: [QUICK_START_GUIDE.md](QUICK_START_GUIDE.md#search_memories) for detailed examples.

---

### create_task

Create a coordinated task for multi-agent workflow.

**Signature**:
```python
create_task(title: str, description: str = None, priority: str = "medium",
            assigned_agent_id: str = None, estimated_duration: int = None,
            due_date: str = None) -> dict
```

**Example**:
```python
task = await create_task(
    title="Implement JWT refresh token mechanism",
    description="Add token rotation with 7-day refresh window",
    priority="high",
    assigned_agent_id="artemis-optimizer",
    estimated_duration=180,  # 3 hours
    due_date="2025-11-15T17:00:00Z"
)
```

---

## System Tools

Administrative and monitoring tools.

### get_agent_status

Get status of connected agents in the TMWS system.

**Signature**:
```python
get_agent_status() -> dict
```

**Example**:
```python
status = await get_agent_status()
print(f"Active agents: {status['total']}")
for agent in status['agents']:
    print(f"  - {agent['agent_id']} ({', '.join(agent['capabilities'])})")
```

---

### get_memory_stats

Get combined SQLite + ChromaDB statistics.

**Signature**:
```python
get_memory_stats() -> dict
```

**Example**:
```python
stats = await get_memory_stats()
print(f"Total memories: {stats['total_memories']}")
print(f"ChromaDB hit rate: {stats['mcp_metrics']['chroma_hit_rate']:.1f}%")
```

---

### invalidate_cache

Clear ChromaDB cache (use with caution, testing only).

**Signature**:
```python
invalidate_cache() -> dict
```

⚠️ **Warning**: This clears vector embeddings. Use only for testing/debugging.

---

## Expiration Management Tools

TMWS includes a comprehensive TTL (Time-To-Live) system for automatic memory cleanup.

### Security Model

All expiration tools require **authentication** (REQ-1):
- API key authentication or JWT token authentication
- Namespace isolation (REQ-2)
- Role-based access control (REQ-5)

**Mass Deletion Protection** (REQ-3):
- Operations affecting >10 items require `confirm_mass_deletion=True`
- Dry-run mode available for safety

**Rate Limiting** (REQ-4):
- Tool-specific limits (5-30 requests/min in production)

---

### prune_expired_memories

Remove expired memories from a namespace.

**Signature**:
```python
prune_expired_memories(agent_id: str, namespace: str, api_key: str | None = None,
                       jwt_token: str | None = None, dry_run: bool = False,
                       confirm_mass_deletion: bool = False) -> dict
```

**Security**:
- Authentication: REQ-1 (API key or JWT)
- Namespace Isolation: REQ-2 (P0-1 pattern)
- Mass Deletion: REQ-3 (>10 items requires confirmation)
- Rate Limit: 5 deletions/hour (REQ-4)

**Example**:
```python
# Dry run first
result = await prune_expired_memories(
    agent_id="my-agent",
    namespace="project-x",
    api_key="your-api-key",
    dry_run=True
)
print(f"Would delete {result['would_delete_count']} memories")

# Confirm if >10
if result['would_delete_count'] > 10:
    result = await prune_expired_memories(
        agent_id="my-agent",
        namespace="project-x",
        api_key="your-api-key",
        confirm_mass_deletion=True
    )
```

---

### get_expiration_stats

Get expiration statistics for a namespace.

**Signature**:
```python
get_expiration_stats(agent_id: str, namespace: str, api_key: str | None = None,
                     jwt_token: str | None = None) -> dict
```

**Rate Limit**: 30 queries/minute

**Example**:
```python
stats = await get_expiration_stats(
    agent_id="artemis-optimizer",
    namespace="trinitas-agents",
    api_key="your-api-key"
)
print(f"Expired memories ready to prune: {stats['expired']}")
print(f"Expiring in 24h: {stats['expiring_soon_24h']}")
```

---

### set_memory_ttl

Update TTL for an existing memory.

**Signature**:
```python
set_memory_ttl(agent_id: str, memory_id: str, ttl_days: int | None,
               api_key: str | None = None, jwt_token: str | None = None) -> dict
```

**Security**: Only memory owner can modify TTL (P0-1 pattern)

**Example**:
```python
# Set 30-day expiration
result = await set_memory_ttl(
    agent_id="artemis-optimizer",
    memory_id="550e8400-e29b-41d4-a716-446655440000",
    ttl_days=30,
    api_key="your-api-key"
)

# Remove expiration (make permanent)
result = await set_memory_ttl(
    agent_id="artemis-optimizer",
    memory_id="550e8400-e29b-41d4-a716-446655440000",
    ttl_days=None,
    api_key="your-api-key"
)
```

---

### cleanup_namespace

Delete ALL memories from a namespace (admin-only, destructive).

**Signature**:
```python
cleanup_namespace(agent_id: str, namespace: str, api_key: str | None = None,
                  jwt_token: str | None = None, dry_run: bool = False,
                  confirm_mass_deletion: bool = False) -> dict
```

⚠️ **WARNING**: DESTRUCTIVE OPERATION - Deletes ALL memories in namespace.

**Security**:
- Admin-Only: REQ-5 (requires special role)
- Mass Deletion: REQ-3 (confirmation required)
- Rate Limit: 2 cleanups/day (very strict)

---

### get_namespace_stats

Get comprehensive statistics for a namespace.

**Signature**:
```python
get_namespace_stats(agent_id: str, namespace: str, api_key: str | None = None,
                    jwt_token: str | None = None) -> dict
```

**Rate Limit**: 20 queries/minute

---

### Scheduler Tools (5 tools)

Tools for controlling the automatic expiration scheduler:

1. **get_scheduler_status**: Get scheduler status (read-only, 60/min)
2. **configure_scheduler**: Configure interval (admin-only, 3/hour)
3. **start_scheduler**: Start scheduler (admin-only, 5/hour)
4. **stop_scheduler**: Stop scheduler (admin-only, 2/day)
5. **trigger_scheduler**: Manual cleanup (10/hour)

**Example**:
```python
# Check scheduler status
status = await get_scheduler_status(
    agent_id="artemis-optimizer",
    api_key="your-api-key"
)
if status['is_running']:
    print(f"Next cleanup: {status['next_run_time']}")
```

---

## Trust & Verification Tools

TMWS includes a **Trust System** for verifying agent claims and tracking reliability.

### verify_and_record

Verify a claim and record evidence.

**Signature**:
```python
verify_and_record(agent_id: str, claim_type: str, claim_content: dict,
                  verification_command: str, verified_by_agent_id: str | None = None) -> dict
```

**Claim Types**:
- `test_result`: Test execution results
- `performance_metric`: Performance measurements
- `code_quality`: Code quality metrics
- `security_finding`: Security audit findings
- `deployment_status`: Deployment status
- `custom`: Other claim types

**Example**:
```python
# Artemis claims tests passed - let's verify
result = await verify_and_record(
    agent_id="artemis-optimizer",
    claim_type="test_result",
    claim_content={"passed": 150, "failed": 0, "coverage": 92.5},
    verification_command="pytest tests/unit/ -v --cov=src",
    verified_by_agent_id="hestia-auditor"
)

if result['accurate']:
    print("✅ Claim verified")
else:
    print(f"⚠️  Claim inaccurate. New trust score: {result['new_trust_score']:.2f}")
```

---

### get_agent_trust_score

Get agent trust score and statistics.

**Signature**:
```python
get_agent_trust_score(agent_id: str) -> dict
```

**Trust Score Interpretation**:
- 0.9-1.0: Highly Reliable (verification rarely needed)
- 0.7-0.89: Reliable (spot verification recommended)
- 0.5-0.69: Moderate (regular verification needed)
- 0.3-0.49: Low Trust (verification required for critical claims)
- 0.0-0.29: Untrusted (verification required for all claims)

**Example**:
```python
score_info = await get_agent_trust_score("artemis-optimizer")
print(f"Trust score: {score_info['trust_score']:.0%}")
if score_info['requires_verification']:
    print("⚠️  This agent requires verification for reports")
```

---

### Additional Verification Tools

1. **get_verification_history**: Get verification history (filter by claim type)
2. **get_verification_statistics**: Get comprehensive statistics by claim type
3. **get_trust_history**: Get trust score evolution over time

**Example**:
```python
# Get detailed statistics
stats = await get_verification_statistics("artemis-optimizer")
print(f"Overall trust score: {stats['trust_score']:.0%}")
for claim_type, metrics in stats['by_claim_type'].items():
    print(f"  {claim_type}: {metrics['accuracy']:.0%}")
```

---

## Common Patterns

### Pattern 1: Daily Standup Memory

```python
# Store daily progress
await store_memory(
    content="Daily Progress - 2025-11-14: Completed Phase 1-2, In Progress: Phase 1-3",
    importance_score=0.7,
    tags=["daily-standup", "progress"],
    namespace="trinitas-agents"
)

# Search weekly progress
results = await search_memories(
    query="What did I work on this week?",
    tags=["daily-standup"]
)
```

### Pattern 2: Security Audit Trail

```python
# Hestia performs audit
audit_id = await store_memory(
    content="Security Audit: Found 3 vulnerabilities (2 HIGH, 1 MEDIUM)",
    importance_score=1.0,
    tags=["security", "audit", "critical"],
    context={"vulnerabilities": 3, "critical": 1}
)

# Artemis fixes and verifies
verification = await verify_and_record(
    agent_id="artemis-optimizer",
    claim_type="security_fix",
    claim_content={"vulnerability": "V-AUTH-1", "fixed": True},
    verification_command="rg 'SECRET_KEY.*=' src/ --type py",
    verified_by_agent_id="hestia-auditor"
)
```

---

## Error Handling

All tools return standardized error format:

```json
{
  "error": "Error message",
  "error_type": "ErrorClassName"
}
```

### Common Errors

| Error Type | Cause | Solution |
|------------|-------|----------|
| `ValidationError` | Invalid parameters | Check parameter types/ranges |
| `MCPAuthenticationError` | Invalid API key/JWT | Verify credentials |
| `MCPAuthorizationError` | Namespace access denied | Check agent namespace access |
| `MemoryNotFoundError` | Memory ID doesn't exist | Verify memory ID |
| `ChromaOperationError` | Vector search failed | Check Ollama/embedding service |

---

## Performance Metrics

### Target Performance (P95)

| Operation | Target | Typical | Status |
|-----------|--------|---------|--------|
| store_memory | < 5ms | 2-4ms | ✅ |
| search_memories | < 20ms | 5-20ms | ✅ |
| create_task | < 10ms | 5-10ms | ✅ |
| verify_and_record | < 500ms | 100-300ms | ✅ |

### ChromaDB Performance

- **Vector similarity search**: < 10ms P95 ✅
- **Metadata filtering**: < 20ms P95 ✅
- **Hot cache hit rate**: > 90% ✅
- **Embedding generation**: 70-90ms (Ollama)

---

## Support & Resources

- **Quick Start**: [QUICK_START_GUIDE.md](QUICK_START_GUIDE.md)
- **Learning Pattern API**: [LEARNING_PATTERN_API.md](LEARNING_PATTERN_API.md)
- **REST API Guide**: [REST_API_GUIDE.md](REST_API_GUIDE.md)
- **Integration Patterns**: [INTEGRATION_PATTERNS.md](INTEGRATION_PATTERNS.md)
- **Security Guide**: [SECURITY_GUIDE.md](SECURITY_GUIDE.md)

---

**Document Author**: Artemis (Technical Perfectionist)
**Reviewed By**: Athena, Hera
**Last Updated**: 2025-11-14
**Status**: Production-ready
**Version**: 1.0.0
