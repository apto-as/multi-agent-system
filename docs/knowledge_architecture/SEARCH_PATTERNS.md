# TMWS Search and Discovery Patterns
## Query Patterns for Institutional Memory Retrieval

**Version**: 1.0.0
**Created**: 2025-10-27
**Author**: Muses (Knowledge Architect)

---

## Overview

This document defines common query patterns for retrieving institutional knowledge from the TMWS memory system. Each pattern is optimized for specific use cases and personas.

---

## 1. Persona-Based Queries

### 1.1 Athena (Strategic Queries)

**Pattern**: Find architecture decisions with high business impact
```python
results = memory_service.search_memories(
    query="architecture decision business impact",
    namespace="engineering",
    tags=["athena.architecture.decision"],
    metadata_filters={
        "importance.factors.business_impact": {"$gte": 0.8}
    },
    order_by="importance.score DESC",
    limit=20
)
```

**Pattern**: Find all planning documents from last quarter
```python
from datetime import datetime, timedelta

three_months_ago = datetime.utcnow() - timedelta(days=90)

results = memory_service.search_memories(
    query="roadmap planning strategy",
    namespace="engineering",
    tags=["athena.planning"],
    metadata_filters={
        "temporal.created_at": {"$gte": three_months_ago.isoformat()}
    },
    limit=50
)
```

**Pattern**: Find successful coordination patterns
```python
results = memory_service.search_memories(
    query="team coordination workflow success",
    namespace="engineering",
    tags=[
        "athena.coordination.workflow.success",
        "eris.coordination.team.success"
    ],
    metadata_filters={
        "outcomes.status": "success",
        "validation.status": "verified"
    },
    limit=15
)
```

---

### 1.2 Artemis (Technical Queries)

**Pattern**: Find performance optimization patterns
```python
results = memory_service.search_memories(
    query="performance optimization latency improvement",
    namespace="engineering",
    tags=["artemis.performance.optimization"],
    metadata_filters={
        "outcomes.metrics": {"$exists": True},
        "validation.status": "verified"
    },
    order_by="importance.score DESC",
    limit=25
)
```

**Pattern**: Find async implementation best practices
```python
results = memory_service.search_memories(
    query="async await asyncio best practice",
    namespace="engineering",
    tags=[
        "artemis.async.implementation",
        "artemis.technical.best_practice"
    ],
    metadata_filters={
        "memory_type": {"$in": ["best_practice", "implementation"]},
        "outcomes.confidence": {"$gte": 0.9}
    },
    limit=20
)
```

**Pattern**: Find similar optimization successes
```python
# Semantic similarity search
query_embedding = embedding_service.embed(
    "Reduced database query latency from 2000ms to 300ms using indexes"
)

results = vector_search_service.search(
    query_embedding=query_embedding,
    metadata_filters={
        "tags": "artemis.performance.optimization.success"
    },
    top_k=10,
    min_similarity=0.75
)
```

---

### 1.3 Hestia (Security Queries)

**Pattern**: Find critical security vulnerabilities
```python
results = memory_service.search_memories(
    query="security vulnerability critical",
    namespace="security",
    tags=["hestia.security.vulnerability"],
    metadata_filters={
        "importance.factors.urgency": "critical",
        "validation.status": "verified"
    },
    order_by="temporal.created_at DESC",
    limit=30
)
```

**Pattern**: Find security audit findings by severity
```python
results = memory_service.search_memories(
    query="security audit findings",
    namespace="security",
    tags=["hestia.security.audit"],
    metadata_filters={
        "outcomes.metrics.cvss_score": {"$gte": 7.0}  # High/Critical only
    },
    order_by="outcomes.metrics.cvss_score DESC",
    limit=20
)
```

**Pattern**: Find authentication best practices
```python
results = memory_service.search_memories(
    query="authentication jwt password hashing best practice",
    namespace="security",
    tags=[
        "hestia.authentication.best_practice",
        "hestia.authorization.best_practice"
    ],
    metadata_filters={
        "memory_type": "best_practice",
        "validation.status": "verified"
    },
    limit=15
)
```

**Pattern**: Find namespace isolation patterns (related to similar security fixes)
```python
# Semantic search for similar security fixes
query_embedding = embedding_service.embed(
    "Namespace isolation vulnerability allowing cross-tenant access"
)

results = vector_search_service.search(
    query_embedding=query_embedding,
    metadata_filters={
        "tags": {"$in": [
            "hestia.security.vulnerability",
            "hestia.authorization.audit"
        ]},
        "project_context.module": {"$in": ["authorization", "authentication"]}
    },
    top_k=15,
    min_similarity=0.70
)
```

---

### 1.4 Eris (Coordination Queries)

**Pattern**: Find workflow handoff patterns
```python
results = memory_service.search_memories(
    query="persona handoff coordination workflow",
    namespace="engineering",
    tags=["eris.coordination.workflow"],
    metadata_filters={
        "memory_type": {"$in": ["coordination", "planning"]},
        "outcomes.status": "success"
    },
    limit=20
)
```

**Pattern**: Find conflict resolution strategies
```python
results = memory_service.search_memories(
    query="conflict resolution consensus building",
    namespace="engineering",
    tags=["eris.coordination.team"],
    metadata_filters={
        "outcomes.lessons_learned": {"$exists": True},
        "validation.status": "verified"
    },
    limit=15
)
```

---

### 1.5 Hera (Strategic Planning Queries)

**Pattern**: Find long-term roadmap decisions
```python
results = memory_service.search_memories(
    query="roadmap strategic vision long-term planning",
    namespace="engineering",
    tags=[
        "hera.planning.roadmap",
        "athena.strategy.vision"
    ],
    metadata_filters={
        "importance.factors.business_impact": {"$gte": 0.85}
    },
    order_by="importance.score DESC",
    limit=25
)
```

**Pattern**: Find architectural patterns from successful projects
```python
results = memory_service.search_memories(
    query="system architecture design pattern success",
    namespace="engineering",
    tags=["hera.architecture.system_design"],
    metadata_filters={
        "outcomes.status": "success",
        "outcomes.confidence": {"$gte": 0.85},
        "validation.verified_by": {"$size": {"$gte": 2}}  # Multiple verifications
    },
    limit=30
)
```

---

### 1.6 Muses (Documentation Queries)

**Pattern**: Find incomplete documentation
```python
results = memory_service.search_memories(
    query="documentation incomplete needs_review",
    namespace="engineering",
    tags=["muses.documentation"],
    metadata_filters={
        "validation.status": {"$in": ["needs_review", "unverified"]}
    },
    order_by="importance.score DESC",
    limit=20
)
```

**Pattern**: Find lessons learned from failures
```python
results = memory_service.search_memories(
    query="lesson learned failure mistake",
    namespace="engineering",
    tags=["muses.documentation.lesson_learned"],
    metadata_filters={
        "outcomes.status": {"$in": ["failure", "partial"]},
        "outcomes.lessons_learned": {"$exists": True}
    },
    limit=30
)
```

---

## 2. Topic-Based Queries

### 2.1 Database Performance

**Pattern**: Find all database optimization memories
```python
results = memory_service.search_memories(
    query="database performance optimization index query",
    namespace="engineering",
    tags=["database", "performance", "optimization"],
    metadata_filters={
        "project_context.domains": {"$in": ["database", "optimization"]}
    },
    limit=50
)
```

**Pattern**: Find index-related improvements
```python
results = memory_service.search_memories(
    query="database index optimization performance improvement",
    namespace="engineering",
    metadata_filters={
        "outcomes.metrics": {"$exists": True},
        "project_context.module": {"$regex": ".*database.*"}
    },
    order_by="outcomes.confidence DESC",
    limit=20
)
```

---

### 2.2 Authentication & Authorization

**Pattern**: Find all auth-related decisions and implementations
```python
results = memory_service.search_memories(
    query="authentication authorization jwt access control",
    namespace="security",
    tags={"$in": [
        "hestia.authentication",
        "hestia.authorization",
        "artemis.api.implementation"
    ]},
    metadata_filters={
        "project_context.domains": {"$in": ["authentication", "authorization"]}
    },
    limit=40
)
```

---

### 2.3 Async Programming

**Pattern**: Find async/await patterns and pitfalls
```python
results = memory_service.search_memories(
    query="async await asyncio event loop blocking",
    namespace="engineering",
    tags=["artemis.async"],
    metadata_filters={
        "memory_type": {"$in": ["implementation", "best_practice", "anti_pattern"]}
    },
    limit=25
)
```

---

## 3. Relationship-Based Queries

### 3.1 Find Related Memories

**Pattern**: Get all memories related to a specific memory
```python
# Get a memory
memory = await memory_service.get_memory(memory_id)

# Find related memories
related_ids = memory.metadata.get("relationships", {}).get("related_memories", [])
related_memories = []

for rel in related_ids:
    rel_memory = await memory_service.get_memory(rel["memory_id"])
    related_memories.append({
        "memory": rel_memory,
        "relationship": rel["relationship_type"],
        "strength": rel["strength"]
    })

# Sort by relationship strength
related_memories.sort(key=lambda x: x["strength"], reverse=True)
```

---

### 3.2 Find Memory Thread (Discussion Chain)

**Pattern**: Reconstruct a discussion thread
```python
async def get_discussion_thread(root_memory_id: str) -> list[Memory]:
    """
    Recursively get all memories in a discussion thread.
    """
    thread = []
    visited = set()

    async def traverse(memory_id: str):
        if memory_id in visited:
            return
        visited.add(memory_id)

        memory = await memory_service.get_memory(memory_id)
        thread.append(memory)

        # Find related memories
        related = memory.metadata.get("relationships", {}).get("related_memories", [])
        for rel in related:
            if rel["relationship_type"] in ["related_to", "extends", "implements"]:
                await traverse(rel["memory_id"])

    await traverse(root_memory_id)

    # Sort by timestamp
    thread.sort(key=lambda m: m.created_at)
    return thread
```

---

### 3.3 Find Dependencies

**Pattern**: Find all memories that depend on a specific memory
```python
results = memory_service.search_memories(
    query="",  # Empty query, metadata filter only
    namespace="engineering",
    metadata_filters={
        "relationships.related_memories": {
            "$elemMatch": {
                "memory_id": target_memory_id,
                "relationship_type": "depends_on"
            }
        }
    },
    limit=100
)
```

---

## 4. Temporal Queries

### 4.1 Recent Memories

**Pattern**: Get recent memories from last 7 days
```python
from datetime import datetime, timedelta

last_week = datetime.utcnow() - timedelta(days=7)

results = memory_service.search_memories(
    query="",  # Recent memories, any topic
    namespace="engineering",
    metadata_filters={
        "temporal.created_at": {"$gte": last_week.isoformat()}
    },
    order_by="temporal.created_at DESC",
    limit=50
)
```

---

### 4.2 Memories Needing Review

**Pattern**: Find memories that need periodic review
```python
from datetime import datetime

now = datetime.utcnow()

results = memory_service.search_memories(
    query="",
    namespace="engineering",
    metadata_filters={
        "temporal.review_schedule.next_review_at": {"$lte": now.isoformat()},
        "validation.status": {"$in": ["verified", "unverified"]}
    },
    order_by="importance.score DESC",
    limit=30
)
```

---

### 4.3 Outdated Memories

**Pattern**: Find memories that may be outdated
```python
from datetime import datetime, timedelta

six_months_ago = datetime.utcnow() - timedelta(days=180)

results = memory_service.search_memories(
    query="",
    namespace="engineering",
    metadata_filters={
        "temporal.updated_at": {"$lte": six_months_ago.isoformat()},
        "importance.decay_rate": {"$gte": 0.5},  # High decay rate
        "validation.status": {"$ne": "outdated"}
    },
    order_by="temporal.updated_at ASC",
    limit=40
)
```

---

## 5. Complex Composite Queries

### 5.1 High-Impact Verified Successes

**Pattern**: Find high-impact, verified success stories for knowledge sharing
```python
results = memory_service.search_memories(
    query="success optimization improvement",
    namespace="engineering",
    metadata_filters={
        "outcomes.status": "success",
        "outcomes.confidence": {"$gte": 0.9},
        "validation.status": "verified",
        "validation.verified_by": {"$size": {"$gte": 2}},  # At least 2 verifications
        "importance.score": {"$gte": 0.85},
        "importance.factors.reusability": {"$gte": 0.8}
    },
    order_by="importance.score DESC",
    limit=20
)
```

---

### 5.2 Critical Lessons from Failures

**Pattern**: Find critical lessons learned from failures
```python
results = memory_service.search_memories(
    query="failure mistake lesson learned",
    namespace="engineering",
    metadata_filters={
        "memory_type": "lesson_learned",
        "outcomes.status": {"$in": ["failure", "partial"]},
        "outcomes.lessons_learned": {"$exists": True},
        "importance.factors.urgency": {"$in": ["critical", "high"]},
        "validation.status": "verified"
    },
    order_by="importance.score DESC",
    limit=25
)
```

---

### 5.3 Security Patterns for New Projects

**Pattern**: Find security best practices for new project initialization
```python
results = memory_service.search_memories(
    query="security authentication authorization encryption best practice",
    namespace="security",
    tags=[
        "hestia.security.best_practice",
        "hestia.authentication.best_practice",
        "hestia.authorization.best_practice"
    ],
    metadata_filters={
        "memory_type": "best_practice",
        "validation.status": "verified",
        "importance.factors.reusability": {"$gte": 0.9}
    },
    order_by="importance.score DESC",
    limit=30
)
```

---

### 5.4 Persona Collaboration Patterns

**Pattern**: Find successful multi-persona collaboration patterns
```python
results = memory_service.search_memories(
    query="collaboration coordination handoff consensus",
    namespace="engineering",
    metadata_filters={
        "tags.primary": {
            "$in": [
                "athena.coordination.workflow.success",
                "eris.coordination.team.success"
            ]
        },
        "validation.verified_by": {"$size": {"$gte": 3}},  # Multi-persona verification
        "outcomes.status": "success"
    },
    order_by="importance.score DESC",
    limit=20
)
```

---

## 6. Advanced Semantic Search

### 6.1 Similar Problem Solutions

**Pattern**: Find memories about similar problems (semantic similarity)
```python
# Problem description
problem = """
We need to optimize database query performance. Currently,
queries are taking 2-3 seconds to complete, which is impacting
user experience. The database has 100k+ records.
"""

# Generate embedding
query_embedding = embedding_service.embed(problem)

# Semantic search
results = vector_search_service.search(
    query_embedding=query_embedding,
    metadata_filters={
        "tags": {"$in": ["performance", "database", "optimization"]},
        "outcomes.status": "success"
    },
    top_k=15,
    min_similarity=0.70
)

# Results are ranked by semantic similarity
```

---

### 6.2 Find Analogous Situations

**Pattern**: Find memories from different domains with similar patterns
```python
# Query about authentication issue
query = """
We implemented JWT authentication but tokens are expiring
too quickly, causing user frustration. Need to balance
security and user experience.
"""

query_embedding = embedding_service.embed(query)

# Search across all domains
results = vector_search_service.search(
    query_embedding=query_embedding,
    metadata_filters={
        # No tag filter - allow cross-domain matches
        "outcomes.lessons_learned": {"$exists": True}
    },
    top_k=20,
    min_similarity=0.65  # Lower threshold for cross-domain analogies
)

# May find: cache expiration strategies, session management patterns, etc.
```

---

## 7. Usage-Based Queries

### 7.1 Most Accessed Memories

**Pattern**: Find frequently accessed memories (popular knowledge)
```python
results = memory_service.search_memories(
    query="",
    namespace="engineering",
    metadata_filters={
        "usage_statistics.access_count": {"$gte": 10}
    },
    order_by="usage_statistics.access_count DESC",
    limit=30
)
```

---

### 7.2 Most Applied Patterns

**Pattern**: Find patterns that have been successfully applied multiple times
```python
results = memory_service.search_memories(
    query="pattern best practice",
    namespace="engineering",
    metadata_filters={
        "memory_type": {"$in": ["best_practice", "implementation"]},
        "usage_statistics.applied_count": {"$gte": 5}
    },
    order_by="usage_statistics.applied_count DESC",
    limit=25
)
```

---

## 8. Query Performance Optimization

### 8.1 Use Metadata Filters Efficiently

**✅ GOOD** - Metadata filter first, then semantic search:
```python
# Filter to small subset first
results = vector_search_service.search(
    query_embedding=query_embedding,
    metadata_filters={
        "tags": "artemis.performance.optimization",
        "project_context.namespace": "engineering"
    },
    top_k=10,
    min_similarity=0.75
)
```

**❌ BAD** - Semantic search all memories, then filter:
```python
# Searches all memories (slow)
all_results = vector_search_service.search(
    query_embedding=query_embedding,
    top_k=1000
)
# Manual filtering (inefficient)
filtered = [r for r in all_results if "artemis" in r.tags]
```

---

### 8.2 Use Appropriate Similarity Thresholds

| Similarity | Use Case |
|------------|----------|
| 0.90-1.00 | Nearly exact matches only |
| 0.80-0.89 | Same topic, similar context |
| 0.70-0.79 | Related topics, analogies |
| 0.60-0.69 | Distant analogies, exploratory |
| <0.60 | Too broad, likely false positives |

---

### 8.3 Limit Result Sizes

```python
# ✅ GOOD - Reasonable limit
results = memory_service.search_memories(query, limit=25)

# ❌ BAD - Requesting too many results
results = memory_service.search_memories(query, limit=1000)
```

---

## 9. Query Templates for Common Tasks

### Template 1: "Show me what worked"
```python
def find_successful_patterns(domain: str, persona: str = None) -> list[Memory]:
    tags = [f"{persona}.{domain}.success"] if persona else [f"{domain}.success"]

    return memory_service.search_memories(
        query=f"{domain} success best practice",
        namespace="engineering",
        tags=tags,
        metadata_filters={
            "outcomes.status": "success",
            "outcomes.confidence": {"$gte": 0.8},
            "validation.status": "verified"
        },
        order_by="importance.score DESC",
        limit=20
    )
```

### Template 2: "What should I avoid?"
```python
def find_anti_patterns(domain: str) -> list[Memory]:
    return memory_service.search_memories(
        query=f"{domain} failure mistake anti-pattern avoid",
        namespace="engineering",
        metadata_filters={
            "memory_type": {"$in": ["anti_pattern", "lesson_learned"]},
            "outcomes.status": {"$in": ["failure", "partial"]},
            "outcomes.lessons_learned": {"$exists": True}
        },
        order_by="importance.score DESC",
        limit=15
    )
```

### Template 3: "Find similar situations"
```python
async def find_similar_situations(description: str, domain: str = None) -> list[Memory]:
    query_embedding = await embedding_service.embed(description)

    filters = {}
    if domain:
        filters["project_context.domains"] = {"$in": [domain]}

    return vector_search_service.search(
        query_embedding=query_embedding,
        metadata_filters=filters,
        top_k=15,
        min_similarity=0.70
    )
```

---

## 10. Query Best Practices

### ✅ DO:
1. Use specific tags to narrow search scope
2. Combine metadata filters with semantic search
3. Set appropriate similarity thresholds
4. Order results by relevance (importance, timestamp, etc.)
5. Limit result sizes to reasonable numbers

### ❌ DON'T:
1. Search all memories without filters (slow)
2. Use overly broad queries
3. Request thousands of results
4. Ignore metadata filters
5. Use similarity threshold <0.60 without good reason

---

This comprehensive search pattern guide ensures efficient and effective knowledge retrieval across all Trinitas personas and use cases.

---

*"検索は科学であり芸術である。適切な問いが適切な知識を引き出す。"*
*"Search is both science and art. The right question unlocks the right knowledge."*

— Muses, Knowledge Architect
