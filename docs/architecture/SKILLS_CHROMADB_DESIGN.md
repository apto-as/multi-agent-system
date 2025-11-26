# Skills ChromaDB Collection Design
**TMWS v2.4.0 - Phase 5A**

**Author**: Artemis (Technical Perfectionist)
**Created**: 2025-11-25
**Status**: Design Document

---

## Overview

This document specifies the ChromaDB collection design for the TMWS Skills System, enabling semantic search and discovery of skills based on natural language queries.

### Architecture Context

- **Primary Storage**: SQLite (metadata, versions, access control)
- **Vector Storage**: ChromaDB (semantic embeddings for skill discovery)
- **Embedding Model**: Ollama Multilingual-E5-Large (1024 dimensions)
- **Query Pattern**: Hybrid (exact match on SQLite + semantic search on ChromaDB)

---

## Collection Specification

### Collection Name

```python
COLLECTION_NAME = "tmws_skills_v1"
```

**Versioning**: Appended `_v1` allows for future schema evolution without breaking existing collections.

**Migration Path**: If schema changes in v2.5.0, create `tmws_skills_v2` and migrate data.

---

## Metadata Schema

### Document Structure

Each skill is stored as a ChromaDB document with the following metadata:

```python
{
    # Core identification
    "skill_id": "550e8400-e29b-41d4-a716-446655440000",  # UUID (string)
    "skill_name": "security-audit",                      # lowercase-hyphenated
    "display_name": "Security Audit",                    # Human-readable
    "namespace": "tmws-core",                            # Namespace isolation

    # Classification
    "persona": "hestia-auditor",                         # Optional persona
    "tags": ["security", "audit", "owasp", "penetration-testing"],  # Array

    # Version tracking
    "version": 3,                                        # Active version number
    "version_count": 5,                                  # Total versions available

    # Access control
    "access_level": "TEAM",                              # PRIVATE/TEAM/SHARED/PUBLIC/SYSTEM

    # Timestamp
    "created_at": "2025-11-25T17:13:00.000000Z",        # ISO 8601 UTC
    "updated_at": "2025-11-25T18:45:00.000000Z",        # ISO 8601 UTC

    # Soft delete flag
    "is_deleted": false                                  # Filter out deleted skills
}
```

### Metadata Field Justification

| Field | Purpose | Query Pattern |
|-------|---------|---------------|
| `skill_id` | Primary key linkage to SQLite | Join with SQLite after vector search |
| `skill_name` | Exact match fallback | `WHERE metadata.skill_name = ?` |
| `namespace` | Namespace isolation (security) | `WHERE metadata.namespace = ?` |
| `persona` | Filter by persona | `WHERE metadata.persona = 'hestia-auditor'` |
| `tags` | Tag-based filtering | `WHERE 'security' IN metadata.tags` |
| `access_level` | Authorization pre-filter | `WHERE metadata.access_level IN ('PUBLIC', 'TEAM')` |
| `is_deleted` | Soft delete support | `WHERE metadata.is_deleted = false` |

---

## Embedding Strategy

### Embedded Content

**Formula**: `name + description + tags`

```python
def create_embedding_text(skill: Skill) -> str:
    """Generate text to embed for semantic search."""
    parts = [
        f"Skill: {skill.name}",
        f"Description: {skill.description or ''}",
        f"Tags: {', '.join(skill.tags)}"
    ]
    return "\n".join(parts)
```

**Example**:
```
Skill: security-audit
Description: Comprehensive security audit for web applications using OWASP Top 10
Tags: security, audit, owasp, penetration-testing, vulnerability-assessment
```

**Rationale**:
- **Name**: Primary identifier (exact match queries)
- **Description**: Semantic content (natural language queries)
- **Tags**: Keyword expansion (topic-based queries)

### Embedding Model

- **Model**: `zylonai/multilingual-e5-large`
- **Dimensions**: 1024
- **Provider**: Ollama (required)
- **Normalization**: L2 normalization (ChromaDB default)

**Performance**:
- Embedding generation: ~50ms per skill (Ollama)
- Vector similarity: <10ms P95 (ChromaDB HNSW index)

---

## Query Patterns

### Pattern 1: Semantic Search (Primary Use Case)

**User Query**: "I need to audit the security of my web application"

**ChromaDB Query**:
```python
results = collection.query(
    query_embeddings=[query_embedding],  # 1024-dim vector
    n_results=10,
    where={
        "namespace": namespace,           # Namespace isolation
        "is_deleted": False,              # Exclude deleted
        "access_level": {                 # Access control
            "$in": ["PUBLIC", "TEAM", "SYSTEM"]
        }
    },
    include=["metadatas", "distances"]
)
```

**Result**:
```json
{
    "ids": [["skill-uuid-1", "skill-uuid-2", ...]],
    "distances": [[0.23, 0.35, ...]],
    "metadatas": [[
        {"skill_name": "security-audit", "persona": "hestia-auditor", ...},
        {"skill_name": "owasp-scanner", "persona": "hestia-auditor", ...}
    ]]
}
```

**Post-processing**:
1. Filter by distance threshold (e.g., `distance < 0.5`)
2. Join with SQLite to get full skill details
3. Apply `is_accessible_by()` check (defense-in-depth)

### Pattern 2: Tag-Based Search

**User Query**: "Show me all security-related skills"

**ChromaDB Query**:
```python
results = collection.query(
    query_embeddings=[tag_embedding("security")],
    n_results=20,
    where={
        "namespace": namespace,
        "is_deleted": False,
        "tags": {"$contains": "security"}  # Exact tag match
    }
)
```

### Pattern 3: Persona-Specific Search

**User Query**: "What skills does Hestia provide?"

**ChromaDB Query**:
```python
results = collection.query(
    query_embeddings=[persona_embedding("hestia")],
    n_results=50,
    where={
        "namespace": namespace,
        "is_deleted": False,
        "persona": "hestia-auditor"  # Exact persona match
    }
)
```

### Pattern 4: Hybrid Exact + Semantic

**User Query**: "security-audit" (exact name known)

**Execution**:
1. **Fast path**: SQLite exact match
   ```sql
   SELECT * FROM skills WHERE namespace = ? AND name = 'security-audit' AND is_deleted = 0
   ```
2. **Fallback**: ChromaDB semantic search (if exact match fails)

**Rationale**: Exact match is O(log n) on indexed column, faster than vector search.

---

## CRUD Operations

### Create (Insert)

```python
async def add_skill_to_chromadb(skill: Skill, embedding: list[float]) -> None:
    """Add skill to ChromaDB collection."""
    collection.add(
        ids=[str(skill.id)],
        embeddings=[embedding],
        metadatas=[{
            "skill_id": str(skill.id),
            "skill_name": skill.name,
            "display_name": skill.display_name,
            "namespace": skill.namespace,
            "persona": skill.persona,
            "tags": skill.tags,
            "version": skill.active_version,
            "version_count": skill.version_count,
            "access_level": skill.access_level.value,
            "created_at": skill.created_at.isoformat(),
            "updated_at": skill.updated_at.isoformat(),
            "is_deleted": skill.is_deleted
        }]
    )
```

### Update

```python
async def update_skill_in_chromadb(skill: Skill, new_embedding: list[float]) -> None:
    """Update skill in ChromaDB (metadata and embedding)."""
    collection.update(
        ids=[str(skill.id)],
        embeddings=[new_embedding],
        metadatas=[{
            # ... same metadata as Create
            "updated_at": datetime.now(timezone.utc).isoformat()
        }]
    )
```

**Trigger**: When `name`, `description`, or `tags` change (re-embed required).

### Delete (Soft)

```python
async def soft_delete_skill_in_chromadb(skill_id: str) -> None:
    """Soft delete skill in ChromaDB (set is_deleted=true)."""
    collection.update(
        ids=[skill_id],
        metadatas=[{"is_deleted": True}]
    )
```

**Rationale**: Preserves vector for audit/analytics, but excludes from search results.

### Delete (Hard)

```python
async def hard_delete_skill_in_chromadb(skill_id: str) -> None:
    """Hard delete skill from ChromaDB (permanent removal)."""
    collection.delete(ids=[skill_id])
```

**Use Case**: Compliance requirements (GDPR right to erasure).

---

## Performance Analysis

### Benchmark Targets

| Operation | Target Latency (P95) | Justification |
|-----------|----------------------|---------------|
| Semantic search (10 results) | < 20ms | Same as Memory semantic search |
| Tag-based filter | < 15ms | Metadata-only query (no vector search) |
| Exact match (SQLite) | < 5ms | B-tree index lookup |
| Embedding generation | < 100ms | Ollama overhead (acceptable for write path) |
| Hybrid query (SQLite + ChromaDB) | < 30ms | Sequential execution (5ms + 20ms + 5ms join) |

### Index Configuration

**ChromaDB HNSW Parameters**:
```python
collection = client.create_collection(
    name="tmws_skills_v1",
    metadata={
        "hnsw:space": "cosine",        # Cosine similarity (best for normalized vectors)
        "hnsw:construction_ef": 200,   # Build quality (higher = better recall)
        "hnsw:search_ef": 100,         # Query quality (higher = better recall)
        "hnsw:M": 16                   # Graph connectivity (higher = better recall, more memory)
    }
)
```

**Trade-off Analysis**:
- `M=16`: 16MB memory per 10,000 skills (acceptable)
- `search_ef=100`: 95%+ recall with <20ms latency
- `construction_ef=200`: One-time cost at skill creation (~200ms)

### Scalability Estimation

| Skill Count | Memory (HNSW) | Search Latency (P95) | Storage (ChromaDB) |
|-------------|---------------|----------------------|--------------------|
| 100 | 160KB | < 5ms | 10MB |
| 1,000 | 1.6MB | < 10ms | 100MB |
| 10,000 | 16MB | < 20ms | 1GB |
| 100,000 | 160MB | < 50ms | 10GB |

**Bottleneck**: 100,000+ skills may require index tuning (`M=32`, `search_ef=200`).

---

## Security Considerations

### Namespace Isolation

**Critical**: All ChromaDB queries MUST include `where={"namespace": namespace}` filter.

**Attack Vector**: Cross-namespace skill discovery via semantic search.

**Mitigation**:
```python
# CORRECT: Namespace-filtered query
results = collection.query(
    query_embeddings=[embedding],
    where={"namespace": verified_namespace},  # ✅ Verified from DB
    n_results=10
)

# WRONG: No namespace filter (SECURITY RISK)
results = collection.query(
    query_embeddings=[embedding],  # ❌ Allows cross-namespace leakage
    n_results=10
)
```

### Access Control Pre-filtering

**Defense-in-Depth**: Filter by `access_level` in ChromaDB, then apply `is_accessible_by()` in Python.

```python
# Step 1: ChromaDB pre-filter (performance optimization)
results = collection.query(
    where={
        "namespace": namespace,
        "access_level": {"$in": ["PUBLIC", "TEAM", "SYSTEM"]}  # Exclude PRIVATE
    }
)

# Step 2: Python post-filter (security guarantee)
accessible_skills = [
    skill for skill in results
    if skill.is_accessible_by(agent_id, verified_namespace)
]
```

**Rationale**: ChromaDB metadata filtering is fast but not security-critical. Always verify in Python.

### Content Integrity

**Embedding Tampering Risk**: Attacker modifies ChromaDB embedding to inject malicious skill.

**Mitigation**: Verify `content_hash` from SQLite before using skill content.

```python
# 1. Get skill_id from ChromaDB
skill_ids = chromadb_results["ids"][0]

# 2. Load full skill from SQLite
skill = await db.get(Skill, skill_ids[0])
skill_version = skill.get_active_version()

# 3. Verify content integrity
if not skill_version.verify_content_integrity():
    raise SecurityError("Skill content hash mismatch - possible tampering")
```

---

## Migration Strategy

### Phase 1: Initial Population

```python
async def populate_chromadb_from_sqlite():
    """One-time migration: Load all skills from SQLite to ChromaDB."""
    async with AsyncSession(engine) as session:
        result = await session.execute(
            select(Skill).where(Skill.is_deleted == False)
        )
        skills = result.scalars().all()

        for skill in skills:
            embedding_text = create_embedding_text(skill)
            embedding = await ollama_service.embed(embedding_text)
            await add_skill_to_chromadb(skill, embedding)
```

### Phase 2: Incremental Updates

```python
async def sync_skill_to_chromadb(skill: Skill):
    """Keep ChromaDB in sync when skill is created/updated in SQLite."""
    embedding_text = create_embedding_text(skill)
    embedding = await ollama_service.embed(embedding_text)

    # Upsert (create or update)
    try:
        await update_skill_in_chromadb(skill, embedding)
    except NotFoundError:
        await add_skill_to_chromadb(skill, embedding)
```

**Trigger Points**:
- `SkillService.create_skill()` → `sync_skill_to_chromadb()`
- `SkillService.update_skill()` → `sync_skill_to_chromadb()`
- `SkillService.delete_skill()` → `soft_delete_skill_in_chromadb()`

---

## Testing Strategy

### Unit Tests

```python
async def test_skill_embedding_creation():
    """Test embedding text generation."""
    skill = Skill(
        name="security-audit",
        description="OWASP security audit",
        tags=["security", "owasp"]
    )
    text = create_embedding_text(skill)
    assert "security-audit" in text
    assert "OWASP security audit" in text
    assert "security, owasp" in text

async def test_chromadb_namespace_isolation():
    """Test namespace isolation in ChromaDB queries."""
    # Insert skills in different namespaces
    skill1 = create_skill(namespace="project-a")
    skill2 = create_skill(namespace="project-b")

    # Query with namespace filter
    results = collection.query(
        query_embeddings=[embedding],
        where={"namespace": "project-a"}
    )

    # Assert only project-a skill is returned
    assert skill1.id in results["ids"][0]
    assert skill2.id not in results["ids"][0]
```

### Performance Tests

```python
async def test_semantic_search_latency():
    """Test semantic search meets <20ms P95 target."""
    # Populate with 1000 skills
    await populate_test_skills(count=1000)

    # Run 100 searches
    latencies = []
    for _ in range(100):
        start = time.perf_counter()
        results = collection.query(query_embeddings=[embedding], n_results=10)
        latencies.append((time.perf_counter() - start) * 1000)

    p95_latency = np.percentile(latencies, 95)
    assert p95_latency < 20, f"P95 latency {p95_latency}ms exceeds 20ms target"
```

---

## Future Enhancements

### Phase 2: Multi-modal Embeddings

- Embed skill code examples (Layer 2 core_instructions)
- Embed skill output examples (Layer 3 auxiliary_content)
- Weighted multi-vector search (metadata=0.3, code=0.4, examples=0.3)

### Phase 3: Active Learning

- Track search queries that return no results (skill gaps)
- Cluster skills by embedding similarity (skill taxonomy)
- Suggest skill creation based on query patterns

### Phase 4: Cross-lingual Search

- Multilingual-E5 already supports 100+ languages
- Test with non-English skill names/descriptions
- Validate cross-lingual semantic search accuracy

---

## References

- ChromaDB Documentation: https://docs.trychroma.com/
- HNSW Algorithm: https://arxiv.org/abs/1603.09320
- Multilingual-E5 Model: https://huggingface.co/intfloat/multilingual-e5-large
- TMWS Memory ChromaDB Integration: `src/services/vector_search_service.py`

---

**End of Document**

*Reviewed by*: Artemis (Technical Perfectionist)
*Security Review*: Pending (Hestia)
*Performance Validation*: Pending (Load tests in Phase 5B)
