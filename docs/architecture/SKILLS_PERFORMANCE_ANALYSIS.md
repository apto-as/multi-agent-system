# Skills System Performance Analysis
**TMWS v2.4.0 - Phase 5A**

**Author**: Artemis (Technical Perfectionist)
**Created**: 2025-11-25
**Status**: Design Document - Pre-Implementation Analysis

---

## Executive Summary

This document analyzes the expected performance characteristics of the Skills System under various load conditions and identifies potential bottlenecks before implementation.

### Key Findings

- ✅ **Target: Metadata Query < 10ms P95** - Achievable with proper indexing
- ✅ **Target: Semantic Search < 20ms P95** - Achievable with ChromaDB HNSW
- ⚠️ **Bottleneck: Embedding Generation** - 50-100ms per skill (acceptable for write path)
- ✅ **Scalability: 10,000 skills** - No issues with current architecture
- ⚠️ **Scalability: 100,000+ skills** - May require index tuning

---

## Query Pattern Analysis

### Pattern 1: Get Skill by Name (Exact Match)

**Query**:
```sql
SELECT * FROM skills
WHERE namespace = ? AND name = ? AND is_deleted = 0
LIMIT 1;
```

**Index Used**: `ix_skills_namespace_name` (composite unique)

**Performance Estimation**:
- **Index Type**: B-tree (SQLite default)
- **Complexity**: O(log n) for lookup
- **Expected Latency**:
  - 100 skills: < 1ms
  - 1,000 skills: < 2ms
  - 10,000 skills: < 5ms
  - 100,000 skills: < 10ms

**Bottleneck**: None (B-tree is extremely efficient for exact match)

**Validation**: Run EXPLAIN QUERY PLAN in SQLite:
```sql
EXPLAIN QUERY PLAN
SELECT * FROM skills WHERE namespace = 'tmws-core' AND name = 'security-audit';
-- Expected: SEARCH TABLE skills USING INDEX ix_skills_namespace_name
```

---

### Pattern 2: Get Active Version of Skill

**Query**:
```sql
-- Step 1: Get skill metadata (5ms)
SELECT * FROM skills WHERE id = ?;

-- Step 2: Get active version content (3ms)
SELECT * FROM skill_versions
WHERE skill_id = ? AND version = ?
LIMIT 1;
```

**Indexes Used**:
- `skills.id` (primary key)
- `ix_skill_versions_skill_version` (composite unique)

**Performance Estimation**:
- **Total Latency**: 5ms + 3ms = 8ms (sequential)
- **Complexity**: O(log n) + O(log n) = O(log n)

**Optimization Opportunity**: Single JOIN query
```sql
SELECT s.*, sv.content, sv.metadata_json, sv.core_instructions
FROM skills s
JOIN skill_versions sv ON sv.skill_id = s.id AND sv.version = s.active_version
WHERE s.id = ?;
```
- **Improved Latency**: 5ms (single query)
- **Trade-off**: Slightly larger result set (acceptable)

---

### Pattern 3: List Skills by Persona

**Query**:
```sql
SELECT * FROM skills
WHERE namespace = ? AND persona = ? AND is_deleted = 0
ORDER BY created_at DESC
LIMIT 20;
```

**Index Used**: `ix_skills_persona` (single column)

**Performance Estimation**:
- **Index Scan**: O(log n) to find first match
- **Sequential Scan**: O(k) to read k=20 results
- **Expected Latency**:
  - 100 skills: < 2ms
  - 1,000 skills: < 5ms
  - 10,000 skills: < 10ms

**Bottleneck**: If persona filter is non-selective (e.g., 50% of skills have same persona)
- **Mitigation**: Add composite index `(persona, created_at)` for ORDER BY optimization

**Recommended Index**:
```sql
CREATE INDEX ix_skills_persona_created_at ON skills(persona, created_at DESC);
```

---

### Pattern 4: Semantic Search (ChromaDB)

**Query**:
```python
results = collection.query(
    query_embeddings=[embedding],  # 1024-dim vector
    n_results=10,
    where={
        "namespace": namespace,
        "is_deleted": False
    }
)
```

**Algorithm**: HNSW (Hierarchical Navigable Small World)

**Performance Estimation** (based on HNSW paper + ChromaDB benchmarks):
- **Complexity**: O(log n) average case
- **Expected Latency**:
  - 100 skills: < 5ms
  - 1,000 skills: < 10ms
  - 10,000 skills: < 20ms
  - 100,000 skills: < 50ms

**HNSW Parameters**:
```python
hnsw:M = 16              # Graph connectivity (16 links per node)
hnsw:search_ef = 100     # Search quality (higher = better recall)
hnsw:construction_ef = 200  # Build quality (one-time cost)
```

**Memory Usage**:
- **Per Skill**: ~1.6KB (1024 dim * 4 bytes/float + HNSW graph)
- **Total (10,000 skills)**: ~16MB
- **Total (100,000 skills)**: ~160MB

**Bottleneck Identification**:
- **10,000 skills**: No bottleneck (< 20ms target ✅)
- **100,000 skills**: May exceed 20ms target at P95
  - **Mitigation**: Increase `M=32` (better recall, higher memory)
  - **Trade-off**: 2x memory usage (320MB)

---

### Pattern 5: Activation Logging (Write Path)

**Query**:
```sql
INSERT INTO skill_activations (
    id, skill_id, version, agent_id, namespace,
    activation_type, layer_loaded, tokens_loaded,
    activated_at, duration_ms, success
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
```

**Performance Estimation**:
- **Complexity**: O(log n) for index update
- **Expected Latency**: < 2ms (write-heavy tables are slower than read)

**Index Overhead**:
- 4 indexes on `skill_activations` table
- Each insert updates 4 B-tree indexes
- Estimated overhead: +50% latency (2ms → 3ms)

**Bottleneck**: High activation rate (>1000/sec)
- **Mitigation**: Batch inserts (insert 100 records in single transaction)
- **Trade-off**: Latency in activation logging (acceptable, non-critical path)

**Recommended Optimization**:
```python
# Batch insert for high-throughput scenarios
async def batch_log_activations(activations: list[SkillActivation]):
    async with AsyncSession(engine) as session:
        session.add_all(activations)
        await session.commit()  # Single transaction
```

---

## Write Path Performance

### Skill Creation Flow

```
User Request
    ↓
Step 1: Validate Input (1ms)
    ↓
Step 2: Generate UUID (0.1ms)
    ↓
Step 3: Insert into SQLite (5ms)
    |
    ├─ INSERT INTO skills (...)
    └─ INSERT INTO skill_versions (...)
    ↓
Step 4: Generate Embedding (50-100ms) ← BOTTLENECK
    |
    └─ Ollama API call (zylonai/multilingual-e5-large)
    ↓
Step 5: Insert into ChromaDB (10ms)
    ↓
Total: 66-116ms
```

**Bottleneck**: Embedding generation (50-100ms)

**Mitigation Strategies**:

1. **Async Background Processing** (Recommended)
   ```python
   async def create_skill(skill_data):
       # Synchronous path (fast response)
       skill = await insert_skill_to_sqlite(skill_data)  # 5ms

       # Asynchronous path (background task)
       asyncio.create_task(embed_and_index_skill(skill))

       return skill  # Return immediately (5ms total)
   ```
   - **Latency**: 5ms (user-facing)
   - **Trade-off**: Skill not immediately searchable via semantic search (acceptable)

2. **Embedding Cache** (If applicable)
   ```python
   # Cache embeddings for common descriptions/tags
   embedding_cache = {
       "security audit": [0.123, 0.456, ...],  # Pre-computed
       "data processing": [0.789, 0.012, ...]
   }
   ```
   - **Use Case**: Template-based skill creation
   - **Cache Hit Rate**: ~20-30% (estimated)
   - **Benefit**: 50-100ms → 1ms (99% reduction)

3. **Batch Processing** (For bulk imports)
   ```python
   # Process 100 skills in parallel
   embeddings = await ollama_service.batch_embed(texts, batch_size=10)
   # Ollama may support batching (10x speedup)
   ```

**Recommendation**: Use Strategy 1 (async background) for MVP, add Strategy 2 (cache) if latency becomes issue.

---

## Read Path Performance

### Skill Discovery Flow (Semantic Search)

```
User Query: "I need to audit security"
    ↓
Step 1: Generate Query Embedding (50ms)
    ↓
Step 2: ChromaDB Semantic Search (20ms)
    |
    └─ HNSW vector search + metadata filter
    ↓
Step 3: Fetch Skill Metadata from SQLite (5ms)
    |
    └─ SELECT * FROM skills WHERE id IN (...)
    ↓
Step 4: Access Control Check (1ms per skill)
    |
    └─ skill.is_accessible_by(agent_id, namespace)
    ↓
Step 5: Join Active Version (optional) (5ms)
    |
    └─ SELECT * FROM skill_versions WHERE skill_id = ? AND version = ?
    ↓
Total: 81ms (without version content)
Total: 86ms (with Layer 1 metadata)
```

**Bottleneck**: Query embedding generation (50ms)

**Mitigation**:
- **Query Cache**: Cache embeddings for common queries
  ```python
  query_cache = {
      "security audit": [0.123, ...],  # Pre-computed
      "data processing": [0.456, ...]
  }
  ```
- **Cache Hit Rate**: ~10-20% (estimated, depends on query diversity)
- **Benefit**: 50ms → 1ms (98% reduction)

**Optimization**: Parallel execution (ChromaDB search while embedding)
```python
# NOT APPLICABLE: Embedding must complete before vector search
# No parallelization opportunity here
```

---

## Progressive Disclosure Performance

### Layer Loading Latency

| Layer | Content Size | Query | Estimated Latency |
|-------|--------------|-------|-------------------|
| Layer 1 (Metadata) | ~100 tokens | `SELECT metadata_json FROM skill_versions WHERE ...` | 2ms |
| Layer 2 (Core) | ~2,000 tokens | `SELECT core_instructions FROM skill_versions WHERE ...` | 5ms |
| Layer 3 (Full) | ~10,000 tokens | `SELECT content FROM skill_versions WHERE ...` | 15ms |
| Layer 4 (Memory) | Variable | `SELECT * FROM memories WHERE ...` (semantic search) | 20-50ms |

**Optimization**: Fetch only required layer
```python
# Layer 1 only (fast path)
version = await session.execute(
    select(SkillVersion.metadata_json)
    .where(SkillVersion.skill_id == skill_id)
)

# Layer 2 (if needed)
version = await session.execute(
    select(SkillVersion.core_instructions)
    .where(SkillVersion.skill_id == skill_id)
)
```

**Benefit**: 2ms vs 15ms (7.5x faster for metadata-only queries)

---

## Index Strategy Summary

### Existing Indexes (from Migration)

| Table | Index Name | Columns | Type | Purpose |
|-------|------------|---------|------|---------|
| `skills` | `ix_skills_namespace_name` | `namespace, name` | UNIQUE | Exact match queries |
| `skills` | `ix_skills_created_by` | `created_by` | INDEX | User's skills |
| `skills` | `ix_skills_persona` | `persona` | INDEX | Persona filtering |
| `skills` | `ix_skills_is_deleted` | `is_deleted` | INDEX | Soft delete queries |
| `skill_versions` | `ix_skill_versions_skill_version` | `skill_id, version` | UNIQUE | Version lookup |
| `skill_activations` | `ix_skill_activations_agent_time` | `agent_id, activated_at` | INDEX | Analytics queries |

### Recommended Additional Indexes

**Priority 1 (High Impact)**:
```sql
-- Optimize persona + ordering queries
CREATE INDEX ix_skills_persona_created_at ON skills(persona, created_at DESC);

-- Optimize namespace + access level queries
CREATE INDEX ix_skills_namespace_access ON skills(namespace, access_level);
```

**Priority 2 (Medium Impact)**:
```sql
-- Optimize analytics queries (activation success rate)
CREATE INDEX ix_skill_activations_skill_success ON skill_activations(skill_id, success);

-- Optimize version history queries
CREATE INDEX ix_skill_versions_created_at ON skill_versions(created_at DESC);
```

**Priority 3 (Low Impact, defer to v2.5.0)**:
```sql
-- Optimize tag-based queries (if tag search becomes common)
-- Note: JSON indexing in SQLite is limited, may require application-level filtering
```

---

## Scalability Analysis

### Skill Count vs Performance

| Metric | 100 Skills | 1,000 Skills | 10,000 Skills | 100,000 Skills |
|--------|------------|--------------|---------------|----------------|
| **Metadata Query** | < 1ms | < 2ms | < 5ms | < 10ms |
| **Semantic Search** | < 5ms | < 10ms | < 20ms ✅ | < 50ms ⚠️ |
| **Version Lookup** | < 1ms | < 2ms | < 3ms | < 5ms |
| **Activation Logging** | < 2ms | < 2ms | < 3ms | < 5ms |
| **ChromaDB Memory** | 160KB | 1.6MB | 16MB ✅ | 160MB ⚠️ |
| **SQLite Size** | 1MB | 10MB | 100MB | 1GB |

**Target Deployment Size**: 1,000-10,000 skills (MVP)

**Recommendations**:
- ✅ **Current design handles 10,000 skills** with no issues
- ⚠️ **100,000+ skills** requires ChromaDB tuning (`M=32`, `search_ef=200`)
- ⚠️ **1M+ skills** requires sharding/partitioning (defer to v3.0)

---

## Concurrent Access Patterns

### Scenario 1: 10 Concurrent Users (Low Load)

**Assumptions**:
- Each user performs 1 semantic search/sec
- 50% read, 50% write (activation logging)

**Load**:
- Reads: 5 queries/sec
- Writes: 5 inserts/sec

**Performance**:
- ChromaDB: 5 searches/sec → < 100ms total (20ms each)
- SQLite: 5 writes/sec → < 15ms total (3ms each)
- **Bottleneck**: None (well below capacity)

### Scenario 2: 100 Concurrent Users (Medium Load)

**Load**:
- Reads: 50 queries/sec
- Writes: 50 inserts/sec

**Performance**:
- ChromaDB: 50 searches/sec → < 1000ms total (20ms each, parallelizable)
- SQLite: 50 writes/sec → < 150ms total (3ms each, WAL mode allows concurrent reads)
- **Bottleneck**: Ollama embedding service (50 embeds/sec = 5 seconds total)
  - **Mitigation**: Query cache (reduce to 10 unique queries/sec = 1 second)

### Scenario 3: 1000 Concurrent Users (High Load)

**Load**:
- Reads: 500 queries/sec
- Writes: 500 inserts/sec

**Performance**:
- ChromaDB: 500 searches/sec → Potential bottleneck (20ms * 500 = 10 seconds)
- SQLite: 500 writes/sec → WAL mode supports ~10,000 writes/sec (no issue)
- **Bottleneck**: ChromaDB sequential searches (single-threaded)
  - **Mitigation**: Connection pooling + async execution (10 parallel threads → 1 second)

**Recommendation**: For 1000+ users, implement ChromaDB connection pooling:
```python
chromadb_pool = [
    chromadb.Client() for _ in range(10)  # 10 parallel clients
]

async def parallel_chromadb_search(query_embedding):
    client = random.choice(chromadb_pool)  # Simple load balancing
    return await asyncio.to_thread(client.query, ...)
```

---

## Memory Usage Analysis

### SQLite (Metadata Storage)

**Estimation**:
```
Skill record:
- id: 36 bytes (UUID string)
- name: 50 bytes (avg)
- description: 200 bytes (avg)
- tags_json: 100 bytes (avg)
- Other fields: 150 bytes
Total per skill: ~500 bytes

SkillVersion record:
- content: 10,000 bytes (avg, full SKILL.md)
- metadata_json: 500 bytes
- core_instructions: 2,000 bytes
- Other fields: 200 bytes
Total per version: ~13KB

SkillActivation record:
- All fields: ~300 bytes

Total (10,000 skills, 3 versions each, 100,000 activations):
- Skills: 10,000 * 500 bytes = 5MB
- Versions: 30,000 * 13KB = 390MB
- Activations: 100,000 * 300 bytes = 30MB
Total: ~425MB (well within acceptable range)
```

### ChromaDB (Vector Storage)

**Estimation**:
```
Vector:
- Embedding: 1024 dim * 4 bytes/float = 4KB
- HNSW graph: 16 links * 4 bytes/link = 64 bytes
- Metadata: 500 bytes
Total per skill: ~4.5KB

Total (10,000 skills):
- Vectors: 10,000 * 4.5KB = 45MB
- DuckDB backend overhead: ~10MB
Total: ~55MB
```

**Total Memory (10,000 skills)**: 425MB (SQLite) + 55MB (ChromaDB) = **480MB** ✅

---

## Bottleneck Summary

### Critical Path Bottlenecks

1. **Embedding Generation** (50-100ms)
   - **Severity**: HIGH
   - **Impact**: Write path (skill creation)
   - **Mitigation**: Async background processing ✅

2. **ChromaDB Sequential Searches** (20ms each)
   - **Severity**: MEDIUM (only at 1000+ concurrent users)
   - **Impact**: Read path (semantic search)
   - **Mitigation**: Connection pooling ✅

3. **Ollama Service Availability** (external dependency)
   - **Severity**: HIGH
   - **Impact**: Both read and write paths
   - **Mitigation**: Health checks + circuit breaker ✅

### Non-Critical Bottlenecks

4. **SQLite B-tree Rebalancing** (rare, on large inserts)
   - **Severity**: LOW
   - **Impact**: First insert after 1000 records (one-time cost)
   - **Mitigation**: Pre-allocate database file ⚠️ (defer to v2.5.0)

---

## Performance Testing Plan

### Unit Tests (Target: < 1 second per test)

```python
async def test_skill_exact_match_latency():
    """Test exact match query meets <5ms target."""
    start = time.perf_counter()
    skill = await skill_service.get_skill_by_name(namespace, "security-audit")
    latency = (time.perf_counter() - start) * 1000
    assert latency < 5, f"Latency {latency}ms exceeds 5ms target"

async def test_semantic_search_latency():
    """Test semantic search meets <20ms P95 target."""
    latencies = []
    for _ in range(100):
        start = time.perf_counter()
        results = await skill_service.search_skills("security audit", top_k=10)
        latencies.append((time.perf_counter() - start) * 1000)

    p95_latency = np.percentile(latencies, 95)
    assert p95_latency < 20, f"P95 latency {p95_latency}ms exceeds 20ms target"
```

### Load Tests (Target: 100 concurrent users)

```python
async def load_test_concurrent_searches():
    """Test 100 concurrent semantic searches."""
    async def search_task():
        return await skill_service.search_skills("data processing", top_k=10)

    start = time.perf_counter()
    results = await asyncio.gather(*[search_task() for _ in range(100)])
    total_time = time.perf_counter() - start

    # Target: 100 searches in < 5 seconds (with caching/pooling)
    assert total_time < 5, f"100 searches took {total_time}s (target: <5s)"
```

---

## Conclusion

### Performance Targets (MVP)

| Metric | Target | Confidence | Mitigation |
|--------|--------|------------|------------|
| Exact match query | < 5ms P95 | ✅ HIGH | Composite index |
| Semantic search | < 20ms P95 | ✅ HIGH | HNSW + metadata filter |
| Version lookup | < 3ms P95 | ✅ HIGH | Composite unique index |
| Activation logging | < 5ms P95 | ✅ HIGH | Batch inserts |
| Skill creation | < 10ms P95 | ✅ HIGH | Async embedding |
| Memory usage | < 1GB | ✅ HIGH | Efficient storage |

### Scale Targets

- ✅ **1,000 skills**: No performance issues
- ✅ **10,000 skills**: Well within targets
- ⚠️ **100,000 skills**: May require ChromaDB tuning
- ❌ **1M+ skills**: Requires architectural changes (sharding)

### Recommendations for Phase 5B (Implementation)

1. **Implement async background embedding** (Priority 1)
2. **Add composite index `(persona, created_at)`** (Priority 1)
3. **Implement query cache for embeddings** (Priority 2)
4. **Add ChromaDB connection pooling** (Priority 3, defer to v2.5.0 if not needed)
5. **Set up load testing infrastructure** (Priority 2)

---

**End of Document**

*Reviewed by*: Artemis (Technical Perfectionist)
*Next Step*: Phase 5B Implementation (SkillService + MCP Tools)
