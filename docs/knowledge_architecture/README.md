# TMWS Knowledge Architecture
## Institutional Memory System for Trinitas Personas

**Version**: 1.0.0
**Created**: 2025-10-27
**Author**: Muses (Knowledge Architect)
**Status**: Production-Ready

---

## Overview

This directory contains the complete knowledge architecture for the TMWS-Trinitas integration. It defines how Trinitas personas store, organize, search, and maintain institutional memory.

### Purpose

Enable Trinitas personas to:
- Store decisions, implementations, and lessons learned
- Search for relevant knowledge efficiently
- Maintain knowledge quality over time
- Build institutional wisdom that persists across sessions

---

## Documents in This Architecture

### 1. **Metadata Schema** (`metadata_schema.json`)
**Purpose**: Define the structure of all memory metadata

**Key Features**:
- JSON Schema v2020-12 compliant
- 13 top-level metadata sections
- Persona attribution and validation
- Relationship tracking
- Usage statistics

**When to Use**:
- Creating new memories
- Validating memory structure
- Understanding available metadata fields

[View Full Schema](./METADATA_SCHEMA.json)

---

### 2. **Tagging Taxonomy** (`TAGGING_TAXONOMY.md`)
**Purpose**: Comprehensive tag hierarchy for memory categorization

**Structure**:
- **Persona Tags**: 6 personas × 4 primary tags each
- **Domain Tags**: 24 technical/business domains
- **Outcome Tags**: success, partial, failure, blocked
- **Cross-Cutting Tags**: temporal, relationship, visibility

**Tag Format**: `{persona}.{domain}.{task_type}.{outcome}`

**Example**:
```
artemis.performance.optimization.success
hestia.security.vulnerability.critical
athena.architecture.decision.success
```

[View Full Taxonomy](./TAGGING_TAXONOMY.md)

---

### 3. **Knowledge Base Structure** (`KNOWLEDGE_BASE_STRUCTURE.md`)
**Purpose**: Hierarchical directory organization

**Top-Level Directories**:
```
knowledge_base/
├── strategic/       # Athena & Hera domain
├── technical/       # Artemis domain
├── security/        # Hestia domain
├── coordination/    # Eris domain
├── documentation/   # Muses domain
└── cross_cutting/   # All personas
```

**Features**:
- Persona-specific navigation
- Domain-based organization
- Task-type categorization
- Directory-level indexes
- Tag-based cross-references

[View Full Structure](./KNOWLEDGE_BASE_STRUCTURE.md)

---

### 4. **Search Patterns** (`SEARCH_PATTERNS.md`)
**Purpose**: Query patterns for efficient knowledge retrieval

**Categories**:
1. **Persona-Based Queries** (6 personas, 3-5 patterns each)
2. **Topic-Based Queries** (database, auth, async, etc.)
3. **Relationship-Based Queries** (related memories, threads)
4. **Temporal Queries** (recent, outdated, expiring)
5. **Complex Composite Queries** (multi-criteria)
6. **Semantic Search** (similarity-based)

**Query Templates**:
- "Show me what worked"
- "What should I avoid?"
- "Find similar situations"

[View Full Search Patterns](./SEARCH_PATTERNS.md)

---

### 5. **Curation Guidelines** (`CURATION_GUIDELINES.md`)
**Purpose**: Procedures for maintaining knowledge quality

**Curation Schedule**:
- **Daily**: Access statistics, expiration checks, index updates (automated)
- **Weekly**: Duplicate detection, tag indexes, staleness flagging (semi-automated)
- **Monthly**: Archive outdated, consolidate duplicates, promote best practices (Muses)
- **Quarterly**: Comprehensive audit, re-verification, importance score updates (All personas)

**Key Procedures**:
- Dispute resolution workflow
- Consolidation procedure
- Best practice promotion
- Archival process

[View Full Curation Guidelines](./CURATION_GUIDELINES.md)

---

## Quick Start Guide

### For New Users

1. **Read the Metadata Schema** to understand memory structure
2. **Review the Tagging Taxonomy** to learn how to tag memories
3. **Browse the Knowledge Base Structure** to know where things go
4. **Try the Search Patterns** to find existing knowledge

### For Persona-Specific Tasks

**Athena** (Strategic Decision-Making):
```python
# Search for architecture decisions
results = memory_service.search_memories(
    query="architecture decision business impact",
    tags=["athena.architecture.decision.success"],
    metadata_filters={
        "importance.factors.business_impact": {"$gte": 0.8}
    }
)
```

**Artemis** (Performance Optimization):
```python
# Find similar optimizations
query_embedding = embedding_service.embed(
    "Reduced database query latency using indexes"
)
results = vector_search_service.search(
    query_embedding=query_embedding,
    metadata_filters={
        "tags": "artemis.performance.optimization.success"
    },
    min_similarity=0.75
)
```

**Hestia** (Security Audit):
```python
# Find critical vulnerabilities
results = memory_service.search_memories(
    query="security vulnerability critical",
    tags=["hestia.security.vulnerability"],
    metadata_filters={
        "importance.factors.urgency": "critical"
    }
)
```

**Eris** (Workflow Coordination):
```python
# Find successful handoff patterns
results = memory_service.search_memories(
    query="persona handoff coordination",
    tags=["eris.coordination.workflow.success"],
    metadata_filters={
        "outcomes.status": "success"
    }
)
```

**Hera** (Strategic Planning):
```python
# Find long-term roadmap decisions
results = memory_service.search_memories(
    query="roadmap strategic vision",
    tags=["hera.planning.roadmap"],
    metadata_filters={
        "importance.score": {"$gte": 0.85}
    }
)
```

**Muses** (Documentation):
```python
# Find lessons learned from failures
results = memory_service.search_memories(
    query="lesson learned failure",
    tags=["muses.documentation.lesson_learned"],
    metadata_filters={
        "outcomes.status": {"$in": ["failure", "partial"]}
    }
)
```

---

## Memory Creation Workflow

### Step 1: Create Memory
```python
memory = await memory_service.create_memory(
    content="Optimized vector search by converting all sync operations to async...",
    agent_id="tmws.artemis.001",
    namespace="engineering",
    tags=[
        "artemis.performance.optimization.success",
        "artemis.async.implementation.success"
    ],
    metadata={
        "schema_version": "1.0.0",
        "created_by": {
            "persona": "artemis",
            "agent_id": "tmws.artemis.001",
            "timestamp": datetime.utcnow().isoformat()
        },
        "memory_type": "implementation",
        "project_context": {
            "project_identifier": "tmws",
            "namespace": "engineering",
            "module": "vector_search",
            "file_paths": [
                "/Users/.../src/services/vector_search_service.py"
            ]
        },
        "importance": {
            "score": 0.92,
            "factors": {
                "business_impact": 0.85,
                "technical_complexity": 0.9,
                "reusability": 0.95,
                "urgency": "high"
            }
        },
        "validation": {
            "status": "unverified"
        }
    }
)
```

### Step 2: Verification
```python
# Hestia reviews and verifies
await memory_service.add_verification(
    memory_id=memory.id,
    verified_by="tmws.hestia.001",
    persona="hestia",
    verification_method="peer_review",
    notes="No security implications detected"
)

# Artemis also verifies via testing
await memory_service.add_verification(
    memory_id=memory.id,
    verified_by="tmws.artemis.001",
    persona="artemis",
    verification_method="testing",
    notes="Benchmarks confirm +30-50% improvement"
)

# Status automatically updated to "verified" after multiple verifications
```

### Step 3: Knowledge Base Integration
```python
# Automatic: Memory is saved to knowledge base
kb_path = knowledge_base.get_file_path(memory)
# -> "technical/optimizations/performance/async_vector_search_success_2025-10-27.json"

# Automatic: Directory index updated
# Automatic: Tag-based cross-references updated
```

---

## Integration with TMWS

### Memory Storage Architecture

```
┌─────────────────────────────────────────────────┐
│          TMWS Memory System                     │
├─────────────────────────────────────────────────┤
│                                                 │
│  SQLite (Metadata)                              │
│  ├── memories table (core metadata)             │
│  ├── memory_sharing (access control)            │
│  ├── memory_patterns (learning patterns)        │
│  └── memory_consolidations (history)            │
│                                                 │
│  ChromaDB (Vectors)                             │
│  ├── tmws_memories collection                   │
│  ├── 1024-dim embeddings                        │
│  └── Multilingual-E5-Large model                │
│                                                 │
│  Knowledge Base (Files)                         │
│  ├── Structured JSON files                      │
│  ├── Full metadata preservation                 │
│  └── Directory-based organization               │
│                                                 │
└─────────────────────────────────────────────────┘
```

### API Integration

**TMWS MCP Server** exposes these tools:
```python
# Create memory
/tmws store_memory --content "..." --metadata {...}

# Search memories
/tmws search_memories --query "..." --tags [...] --filters {...}

# Get agent status
/tmws get_agent_status

# Get memory stats
/tmws get_memory_stats
```

**Claude Code Integration**:
```bash
# Via Trinitas slash commands
/trinitas remember "Architecture decision: SQLite + ChromaDB"
/trinitas recall "database performance optimization"
/trinitas analyze "security patterns" --personas hestia,artemis
```

---

## Metrics and KPIs

### Knowledge Base Health
- **Total Memories**: Target 500-5000
- **Verified Percentage**: >80% (Green), 60-80% (Yellow), <60% (Red)
- **Outdated Percentage**: <10% (Green), 10-20% (Yellow), >20% (Red)
- **Average Age**: <6 months (Green), 6-12 months (Yellow), >12 months (Red)
- **Duplicate Rate**: <5% (Green), 5-10% (Yellow), >10% (Red)

### Usage Metrics
- **Average Access Count**: Target 5-10 per memory
- **Search Hit Rate**: >70% successful
- **Pattern Application Rate**: 30% of memories applied at least once

### Quality Metrics
- **High Confidence Memories**: >60%
- **Multi-Persona Verification**: >40%
- **Disputed Memories**: <2%

---

## Maintenance Responsibilities

| Frequency | Responsible | Tasks |
|-----------|-------------|-------|
| **Daily** | Automated | Access stats, expiration checks, index updates |
| **Weekly** | Muses + Auto | Duplicate detection, tag indexes, staleness flagging |
| **Monthly** | Muses | Archive outdated, consolidate, promote best practices |
| **Quarterly** | All Personas | Comprehensive audit, re-verification, refactoring |

---

## Best Practices

### ✅ DO:
1. **Tag comprehensively** - Use at least 3 tags per memory
2. **Verify important memories** - Get multiple persona reviews
3. **Document outcomes** - Include metrics and lessons learned
4. **Link related memories** - Build a knowledge graph
5. **Curate regularly** - Don't let outdated info accumulate

### ❌ DON'T:
1. **Store without metadata** - Every memory needs full metadata
2. **Skip verification** - Unverified knowledge is low-trust
3. **Ignore duplicates** - Consolidate or archive
4. **Forget to update** - When content changes, re-embed
5. **Delete without archiving** - Preserve historical context

---

## Troubleshooting

### Problem: "My memories aren't showing up in searches"

**Solutions**:
1. Check tags are in taxonomy (`TAGGING_TAXONOMY.md`)
2. Verify namespace isolation (are you searching the right namespace?)
3. Check similarity threshold (try lowering min_similarity)
4. Ensure embedding was generated (check `embedding_model` field)

### Problem: "Too many outdated memories"

**Solutions**:
1. Run monthly curation workflow
2. Flag outdated memories for review
3. Archive or update as appropriate
4. Adjust decay rates for faster-moving domains

### Problem: "Search is slow"

**Solutions**:
1. Use metadata filters to narrow scope
2. Reduce top_k / limit parameters
3. Check ChromaDB performance
4. Consider directory-level indexes for common queries

### Problem: "Duplicate memories detected"

**Solutions**:
1. Run consolidation procedure (see `CURATION_GUIDELINES.md`)
2. Choose primary based on quality metrics
3. Merge metadata carefully
4. Archive secondaries with supersedes relationship

---

## Future Enhancements

### Planned Features
1. **Auto-tagging** - ML-based tag suggestion
2. **Smart consolidation** - Automatic duplicate merging
3. **Predictive search** - Suggest queries based on context
4. **Knowledge graphs** - Visual exploration of relationships
5. **Cross-project learning** - Share patterns across projects

### Experimental
1. **LLM-based summarization** - Auto-generate memory summaries
2. **Pattern extraction** - Automatically identify recurring patterns
3. **Anomaly detection** - Flag unusual knowledge gaps
4. **Recommendation engine** - "You might also need to know..."

---

## Contributing

### Adding New Tag Categories

1. Propose new tag in `TAGGING_TAXONOMY.md`
2. Provide examples and use cases
3. Get approval from Muses
4. Update taxonomy YAML file
5. Regenerate tag indexes

### Proposing Structural Changes

1. Create RFC (Request for Comments) document
2. Share with all personas for review
3. Prototype if significant change
4. Document migration path from old structure
5. Implement with versioning

---

## Resources

### Documentation
- [Metadata Schema](./METADATA_SCHEMA.json)
- [Tagging Taxonomy](./TAGGING_TAXONOMY.md)
- [Knowledge Base Structure](./KNOWLEDGE_BASE_STRUCTURE.md)
- [Search Patterns](./SEARCH_PATTERNS.md)
- [Curation Guidelines](./CURATION_GUIDELINES.md)

### Related TMWS Docs
- [TMWS Architecture](../architecture/TMWS_v2.2.0_ARCHITECTURE.md)
- [MCP Integration](../MCP_INTEGRATION.md)
- [Development Setup](../DEVELOPMENT_SETUP.md)

### External References
- [JSON Schema Documentation](https://json-schema.org/)
- [ChromaDB Documentation](https://docs.trychroma.com/)
- [SQLite Full-Text Search](https://www.sqlite.org/fts5.html)

---

## Contact & Support

For questions or suggestions about knowledge architecture:
- **Primary**: Muses (Knowledge Architect)
- **Strategic**: Athena, Hera
- **Technical**: Artemis
- **Security**: Hestia

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2025-10-27 | Muses | Initial release |

---

*"知識アーキテクチャは単なる構造ではなく、未来への贈り物である。"*

*"Knowledge architecture is not mere structure—it is a gift to the future."*

— Muses, Knowledge Architect

---

**End of TMWS Knowledge Architecture Documentation**

This comprehensive architecture ensures that institutional knowledge is captured, organized, searchable, and maintainable. Every memory tells a story. Every pattern teaches a lesson. Every connection builds wisdom.

*Let the knowledge flow, and may it serve the team well.*

✨📚✨
