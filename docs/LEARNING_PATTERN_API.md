# TMWS Learning Pattern System API
## Agent Skills for Trinitas-agents - Database-Backed Implementation

**Version**: v2.3.0
**Target Audience**: Trinitas-agents Development Team
**Last Updated**: 2025-11-14
**Status**: Production-ready

---

## Table of Contents

1. [Overview](#overview)
2. [Why Learning Patterns Instead of .claude/skills/](#why-learning-patterns-instead-of-claudeskills)
3. [Two Implementations Comparison](#two-implementations-comparison)
4. [Database Schema](#database-schema)
5. [Core API Reference](#core-api-reference)
6. [MCP Tools Reference](#mcp-tools-reference)
7. [Access Control Levels](#access-control-levels)
8. [Team Collaboration Patterns](#team-collaboration-patterns)
9. [Pattern Versioning](#pattern-versioning)
10. [Usage Examples](#usage-examples)
11. [Migration Guide](#migration-guide)
12. [Best Practices](#best-practices)

---

## Overview

**Learning Pattern System** is TMWS's implementation of **Agent Skills** - a database-backed knowledge management system that allows agents to learn, store, and reuse successful patterns across the team.

### What are Learning Patterns?

Learning Patterns are **reusable solutions, optimizations, or knowledge** that can be:
- Stored in a centralized database (not filesystem)
- Searched semantically (vector-based similarity)
- Shared across agents (PRIVATE, TEAM, SHARED, PUBLIC)
- Versioned and evolved based on usage feedback
- Analyzed for effectiveness (success rate, usage count, confidence)

### Key Features

| Feature | Description |
|---------|-------------|
| **Database-Backed** | SQLite + ChromaDB (not filesystem) |
| **Semantic Search** | 1024-dim Multilingual-E5-Large embeddings |
| **Access Control** | 5 levels: PRIVATE, TEAM, SHARED, PUBLIC, SYSTEM |
| **Versioning** | Parent-child pattern hierarchy |
| **Analytics** | Usage tracking, success rate, confidence scoring |
| **Team Collaboration** | Share patterns across agents and namespaces |
| **MCP Integration** | 5 MCP tools + complete service API |

---

## Why Learning Patterns Instead of .claude/skills/?

### Background: Strategic Decision (Proposal 2)

In a past discussion with the user, **two proposals** were evaluated:

#### Proposal 1: Filesystem-Based (.claude/skills/)
- Anthropic's official Agent Skills approach
- Markdown files in `.claude/skills/` directories
- Git-versioned
- Simple to implement

#### Proposal 2: Database-Based (Learning Pattern System) ✅ **CHOSEN**
- TMWS's custom implementation
- Database storage with semantic search
- Team collaboration and access control
- Advanced analytics and recommendations

### Why Database-Based Won

| Criterion | .claude/skills/ | Learning Patterns |
|-----------|-----------------|-------------------|
| **Team Collaboration** | Difficult (Git conflicts) | Easy (database sharing) |
| **Semantic Search** | No | Yes (ChromaDB vectors) |
| **Access Control** | Git-based | Fine-grained (5 levels) |
| **Usage Analytics** | No | Yes (tracking, success rate) |
| **Versioning** | Git commits | Parent-child hierarchy |
| **Performance** | File I/O | Database queries (faster) |
| **Multi-tenant** | Separate repos | Namespace isolation |

**User's Decision**: Proposal 2 (Database-Based) approved and implemented.

---

## Two Implementations Comparison

### Legacy Implementation (learning_tools.py)

**Approach**: Store patterns as special "pattern" memory type using MemoryService

**MCP Tools** (5 tools):
1. `learn_pattern` - Store new pattern as memory
2. `apply_pattern` - Search and apply patterns
3. `get_pattern_analytics` - Analytics on learned patterns
4. `evolve_pattern` - Update pattern based on feedback
5. `suggest_learning_opportunities` - Recommend new learning areas

**Pros**:
- Simple implementation (uses existing memory system)
- Vector search built-in
- Quick to get started

**Cons**:
- No dedicated schema (generic metadata dict)
- Limited access control (memory-level only)
- No versioning support
- Analytics are basic

### New Implementation (learning_service.py + learning_pattern.py) ✅ **RECOMMENDED**

**Approach**: Dedicated `LearningPattern` database model with separate service layer

**Service Methods** (11 methods):
1. `create_pattern` - Create new pattern
2. `get_pattern` - Get single pattern with access control
3. `get_patterns_by_agent` - Get all patterns owned by agent
4. `search_patterns` - Advanced search with filters
5. `use_pattern` - Record usage and update statistics
6. `update_pattern` - Modify existing pattern
7. `delete_pattern` - Remove pattern
8. `get_pattern_analytics` - Comprehensive analytics
9. `recommend_patterns` - AI-powered recommendations
10. `batch_create_patterns` - Bulk pattern creation
11. Plus: Versioning methods (create_version, etc.)

**Pros**:
- Dedicated schema with proper validation
- Fine-grained access control (5 levels)
- Full versioning support
- Advanced analytics and recommendations
- Team collaboration features
- Better performance (indexed queries)

**Cons**:
- More complex implementation
- Requires migration from legacy

**Recommendation**: Use **New Implementation** for all new development. Legacy is kept for backward compatibility only.

---

## Database Schema

### LearningPattern Model

```python
class LearningPattern(TMWSBase, MetadataMixin):
    """Enhanced Learning pattern model with agent-centric design."""
    
    # Pattern identification
    id: UUID                        # Primary key
    pattern_name: str               # Unique pattern name
    
    # Agent-centric design
    agent_id: str | None            # Owner agent ID
    namespace: str                  # Organization/project namespace
    
    # Pattern classification
    category: str                   # Main category (e.g., "optimization", "security")
    subcategory: str | None         # Optional subcategory
    
    # Access control
    access_level: str               # "private", "shared", "public", "system"
    shared_with_agents: list[str]   # List of agent IDs (for "shared" level)
    
    # Pattern data
    pattern_data: dict[str, Any]    # Pattern content (JSON)
    
    # Pattern versioning
    version: str                    # Semantic version (e.g., "1.0.0")
    parent_pattern_id: UUID | None  # Parent pattern (for versioning)
    
    # Usage analytics
    usage_count: int                # Total usage count
    success_rate: float             # Success rate (0.0-1.0)
    learning_weight: float          # Learning importance (0.0-10.0)
    confidence_score: float         # Confidence (0.0-1.0)
    complexity_score: float | None  # Complexity (0.0-1.0)
    
    # Timestamps
    created_at: datetime
    updated_at: datetime
```

### PatternUsageHistory Model

```python
class PatternUsageHistory(TMWSBase):
    """Track pattern usage for analytics and learning."""
    
    id: UUID
    pattern_id: UUID                # Foreign key to LearningPattern
    agent_id: str                   # Agent who used the pattern
    execution_time: float           # Execution time (seconds)
    success: bool | None            # Whether usage was successful
    context_data: dict | None       # Context information
    used_at: datetime               # When pattern was used
```

---

## Core API Reference

### LearningService Methods

#### 1. create_pattern()

Create a new learning pattern.

**Signature**:
```python
async def create_pattern(
    self,
    pattern_name: str,
    category: str,
    pattern_data: dict[str, Any],
    agent_id: str | None = None,
    namespace: str = "default",
    subcategory: str | None = None,
    access_level: str = "private",
    learning_weight: float = 1.0,
    complexity_score: float | None = None,
) -> LearningPattern
```

**Parameters**:
- `pattern_name`: Unique pattern identifier (e.g., "database_index_optimization")
- `category`: Main category (e.g., "optimization", "security", "architecture")
- `pattern_data`: Pattern content as dictionary:
  ```python
  {
      "description": "Add composite index for query optimization",
      "steps": ["Identify slow queries", "Create index", "Verify"],
      "example": "CREATE INDEX idx_posts_user ON posts(user_id, created_at);",
      "expected_improvement": "60-85% latency reduction"
  }
  ```
- `agent_id`: Owner agent ID (optional, defaults to system)
- `namespace`: Organization/project namespace (default: "default")
- `subcategory`: Optional subcategory (e.g., "database" under "optimization")
- `access_level`: Access control level (see [Access Control Levels](#access-control-levels))
- `learning_weight`: Importance weight (0.0-10.0, default: 1.0)
- `complexity_score`: Optional complexity rating (0.0-1.0)

**Returns**: Created `LearningPattern` instance

**Example**:
```python
from src.services.learning_service import LearningService

service = LearningService()

pattern = await service.create_pattern(
    pattern_name="database_query_optimization",
    category="performance",
    subcategory="database",
    pattern_data={
        "description": "Add composite index for frequently queried columns",
        "problem": "Slow queries on user_id + created_at filters",
        "solution": "CREATE INDEX idx_posts_user_created ON posts(user_id, created_at DESC);",
        "steps": [
            "1. Identify slow queries with EXPLAIN ANALYZE",
            "2. Create composite index on filtered + sorted columns",
            "3. Verify with EXPLAIN to confirm index usage"
        ],
        "expected_improvement": "60-85% query latency reduction",
        "prerequisites": ["PostgreSQL 12+", "Write access to database"],
        "gotchas": ["Index size increases disk usage", "May slow down inserts"]
    },
    agent_id="artemis-optimizer",
    namespace="trinitas-agents",
    access_level="team",  # Share with team
    learning_weight=8.5,
    complexity_score=0.3
)

print(f"Pattern created: {pattern.id}")
print(f"Version: {pattern.version}")
```

---

#### 2. get_pattern()

Get a single pattern with access control verification.

**Signature**:
```python
async def get_pattern(
    self,
    pattern_id: UUID,
    requesting_agent_id: str | None = None
) -> LearningPattern | None
```

**Parameters**:
- `pattern_id`: Pattern UUID
- `requesting_agent_id`: Agent requesting access (for access control check)

**Returns**: `LearningPattern` if found and accessible, `None` otherwise

**Raises**:
- `PermissionError`: If access denied

**Example**:
```python
pattern = await service.get_pattern(
    pattern_id=UUID("550e8400-e29b-41d4-a716-446655440000"),
    requesting_agent_id="hestia-auditor"
)

if pattern:
    print(f"Pattern: {pattern.pattern_name}")
    print(f"Category: {pattern.category}")
    print(f"Success Rate: {pattern.success_rate:.0%}")
else:
    print("Pattern not found or access denied")
```

---

#### 3. search_patterns()

Advanced search with multiple filters.

**Signature**:
```python
async def search_patterns(
    self,
    query_text: str | None = None,
    category: str | None = None,
    subcategory: str | None = None,
    namespace: str | None = None,
    access_levels: list[str] | None = None,
    requesting_agent_id: str | None = None,
    min_success_rate: float = 0.0,
    min_usage_count: int = 0,
    limit: int = 50,
) -> list[LearningPattern]
```

**Parameters**:
- `query_text`: Optional text search query
- `category`: Filter by category
- `subcategory`: Filter by subcategory
- `namespace`: Filter by namespace
- `access_levels`: Filter by access levels (e.g., `["public", "team"]`)
- `requesting_agent_id`: Agent requesting access (for filtering)
- `min_success_rate`: Minimum success rate (0.0-1.0)
- `min_usage_count`: Minimum usage count
- `limit`: Maximum results (default: 50)

**Returns**: List of matching `LearningPattern` instances

**Example**:
```python
# Find high-quality performance patterns
patterns = await service.search_patterns(
    category="performance",
    namespace="trinitas-agents",
    access_levels=["team", "public"],
    requesting_agent_id="artemis-optimizer",
    min_success_rate=0.8,
    min_usage_count=5,
    limit=10
)

print(f"Found {len(patterns)} high-quality performance patterns:")
for pattern in patterns:
    print(f"  - {pattern.pattern_name}: {pattern.success_rate:.0%} success")
```

---

#### 4. use_pattern()

Record pattern usage and update statistics.

**Signature**:
```python
async def use_pattern(
    self,
    pattern_id: UUID,
    using_agent_id: str,
    execution_time: float,
    success: bool | None = None,
    context_data: dict[str, Any] | None = None,
) -> LearningPattern
```

**Parameters**:
- `pattern_id`: Pattern UUID
- `using_agent_id`: Agent using the pattern
- `execution_time`: Execution time in seconds
- `success`: Whether usage was successful (optional)
- `context_data`: Additional context information

**Returns**: Updated `LearningPattern` with incremented usage count

**Raises**:
- `NotFoundError`: If pattern not found
- `PermissionError`: If access denied

**Example**:
```python
# Artemis uses database optimization pattern
pattern = await service.use_pattern(
    pattern_id=pattern.id,
    using_agent_id="artemis-optimizer",
    execution_time=0.245,  # 245ms
    success=True,
    context_data={
        "database": "PostgreSQL 14",
        "table": "posts",
        "rows_before": 1_000_000,
        "query_time_before_ms": 2000,
        "query_time_after_ms": 300,
        "improvement_percent": 85
    }
)

print(f"Pattern used. New usage count: {pattern.usage_count}")
print(f"New success rate: {pattern.success_rate:.0%}")
```

---

#### 5. update_pattern()

Update pattern content or metadata (owner only).

**Signature**:
```python
async def update_pattern(
    self,
    pattern_id: UUID,
    updating_agent_id: str,
    pattern_data: dict[str, Any] | None = None,
    learning_weight: float | None = None,
    complexity_score: float | None = None,
    access_level: str | None = None,
    shared_with_agents: list[str] | None = None,
) -> LearningPattern
```

**Parameters**:
- `pattern_id`: Pattern UUID
- `updating_agent_id`: Agent updating the pattern (must be owner)
- `pattern_data`: New pattern data (optional)
- `learning_weight`: New learning weight (optional)
- `complexity_score`: New complexity score (optional)
- `access_level`: New access level (optional)
- `shared_with_agents`: New agent sharing list (optional)

**Returns**: Updated `LearningPattern`

**Raises**:
- `NotFoundError`: If pattern not found
- `PermissionError`: If not owner
- `ValidationError`: If validation fails

**Example**:
```python
# Artemis updates pattern with new findings
updated = await service.update_pattern(
    pattern_id=pattern.id,
    updating_agent_id="artemis-optimizer",
    pattern_data={
        **pattern.pattern_data,  # Keep existing data
        "updated_findings": "Works better on PostgreSQL 15+ with JIT enabled",
        "new_gotcha": "May cause lock contention on high-write tables"
    },
    learning_weight=9.0,  # Increase importance
    shared_with_agents=["artemis-optimizer", "hestia-auditor", "athena-conductor"]
)

print(f"Pattern updated. New weight: {updated.learning_weight}")
```

---

#### 6. delete_pattern()

Delete a pattern (owner only).

**Signature**:
```python
async def delete_pattern(
    self,
    pattern_id: UUID,
    deleting_agent_id: str
) -> bool
```

**Parameters**:
- `pattern_id`: Pattern UUID
- `deleting_agent_id`: Agent deleting (must be owner)

**Returns**: `True` if deleted successfully

**Raises**:
- `NotFoundError`: If pattern not found
- `PermissionError`: If not owner

**Example**:
```python
success = await service.delete_pattern(
    pattern_id=obsolete_pattern.id,
    deleting_agent_id="artemis-optimizer"
)

if success:
    print("Pattern deleted successfully")
```

---

#### 7. get_pattern_analytics()

Get comprehensive analytics for patterns.

**Signature**:
```python
async def get_pattern_analytics(
    self,
    agent_id: str | None = None,
    namespace: str | None = None,
    days: int = 30,
) -> dict[str, Any]
```

**Parameters**:
- `agent_id`: Optional agent filter
- `namespace`: Optional namespace filter
- `days`: Number of days to analyze (default: 30)

**Returns**: Dictionary with analytics data

**Example**:
```python
analytics = await service.get_pattern_analytics(
    namespace="trinitas-agents",
    days=30
)

print(f"Total patterns: {analytics['total_patterns']}")
print(f"Category distribution: {analytics['category_distribution']}")
print(f"Top patterns by usage: {analytics['top_patterns']}")
print(f"Average success rate: {analytics['success_statistics']['avg_success_rate']:.0%}")
```

---

#### 8. recommend_patterns()

Get AI-powered pattern recommendations for an agent.

**Signature**:
```python
async def recommend_patterns(
    self,
    agent_id: str,
    category: str | None = None,
    context_data: dict[str, Any] | None = None,
    limit: int = 10,
) -> list[tuple[LearningPattern, float]]
```

**Parameters**:
- `agent_id`: Agent requesting recommendations
- `category`: Optional category filter
- `context_data`: Context for better recommendations
- `limit`: Number of recommendations (default: 10)

**Returns**: List of tuples `(pattern, relevance_score)`

**Relevance Score Calculation**:
```
base_score = (
    pattern.success_rate * 0.4 +
    min(pattern.usage_count / 10.0, 1.0) * 0.3 +
    pattern.confidence_score * 0.3
)
+ similarity_boost (if agent used similar patterns)
+ context_boost (keyword matching)
```

**Example**:
```python
# Get recommendations for Hestia working on security
recommendations = await service.recommend_patterns(
    agent_id="hestia-auditor",
    category="security",
    context_data={
        "task": "SQL injection prevention",
        "language": "Python",
        "framework": "FastAPI"
    },
    limit=5
)

print(f"Top {len(recommendations)} recommended patterns:")
for pattern, score in recommendations:
    print(f"  {score:.0%} - {pattern.pattern_name}")
    print(f"    Success: {pattern.success_rate:.0%} | Usage: {pattern.usage_count}x")
```

---

#### 9. batch_create_patterns()

Create multiple patterns in a batch (optimized for performance).

**Signature**:
```python
async def batch_create_patterns(
    self,
    patterns_data: list[dict[str, Any]],
    agent_id: str | None = None,
) -> list[LearningPattern]
```

**Parameters**:
- `patterns_data`: List of pattern creation data (same schema as `create_pattern`)
- `agent_id`: Default agent ID for patterns

**Returns**: List of created `LearningPattern` instances

**Example**:
```python
patterns_data = [
    {
        "pattern_name": "sql_injection_prevention",
        "category": "security",
        "pattern_data": {"description": "Use parameterized queries", ...}
    },
    {
        "pattern_name": "xss_prevention",
        "category": "security",
        "pattern_data": {"description": "Escape user input", ...}
    }
]

created = await service.batch_create_patterns(
    patterns_data=patterns_data,
    agent_id="hestia-auditor"
)

print(f"Created {len(created)} patterns in batch")
```

---

## MCP Tools Reference

### Available Tools (5 tools)

All tools are registered in `src/tools/learning_tools.py` and available via MCP.

#### 1. learn_pattern

Store a new pattern for future application.

**Usage**:
```bash
/tmws learn_pattern \
  --pattern_name "database_query_optimization" \
  --pattern_content "Add composite index for user_id + created_at queries" \
  --category "performance" \
  --examples '["CREATE INDEX idx_posts_user ON posts(user_id, created_at);"]' \
  --confidence 0.9
```

**Response**:
```json
{
  "success": true,
  "result": {
    "pattern_id": "550e8400-e29b-41d4-a716-446655440000",
    "pattern_name": "database_query_optimization",
    "category": "performance",
    "confidence": 0.9,
    "examples_count": 1,
    "vector_dimensions": 1024,
    "stored_at": "2025-11-14T10:30:00.123456Z"
  },
  "message": "Pattern 'database_query_optimization' learned successfully"
}
```

---

#### 2. apply_pattern

Find and apply relevant patterns to a context.

**Usage**:
```bash
/tmws apply_pattern \
  --pattern_query "optimize slow database queries" \
  --context "PostgreSQL table with 1M rows, user_id and created_at filters" \
  --max_patterns 3 \
  --min_similarity 0.7
```

**Response**:
```json
{
  "success": true,
  "result": {
    "found": true,
    "pattern_count": 2,
    "patterns": [
      {
        "pattern_name": "database_query_optimization",
        "category": "performance",
        "similarity": 0.92,
        "confidence": 0.9,
        "application_count": 15,
        "success_rate": 0.87,
        "examples": ["CREATE INDEX ..."]
      }
    ],
    "application_guidance": {
      "recommended_pattern": {...},
      "confidence_threshold": 0.7
    }
  },
  "message": "Found 2 applicable patterns"
}
```

---

#### 3. get_pattern_analytics

Get analytics on learned patterns.

**Usage**:
```bash
/tmws get_pattern_analytics
```

**Response**:
```json
{
  "success": true,
  "result": {
    "overview": {
      "total_patterns": 45,
      "total_applications": 327,
      "avg_applications_per_pattern": 7.27,
      "avg_success_rate": 0.853,
      "knowledge_base_health": "excellent"
    },
    "distribution": {
      "by_category": {
        "performance": 15,
        "security": 12,
        "architecture": 10
      },
      "by_confidence": {
        "high": 30,
        "medium": 12,
        "low": 3
      }
    },
    "usage_patterns": {
      "most_applied": [...],
      "least_applied": [...],
      "unused_patterns": 5
    }
  }
}
```

---

#### 4. evolve_pattern

Evolve pattern based on usage feedback.

**Usage**:
```bash
/tmws evolve_pattern \
  --pattern_id "550e8400-e29b-41d4-a716-446655440000" \
  --evolution_data '{"improvement": "Works better with JIT enabled"}' \
  --success_feedback true \
  --notes "Tested on PostgreSQL 15"
```

**Response**:
```json
{
  "success": true,
  "result": {
    "pattern_id": "550e8400-e29b-41d4-a716-446655440000",
    "pattern_name": "database_query_optimization",
    "evolution_summary": {
      "previous_success_rate": 0.85,
      "new_success_rate": 0.87,
      "previous_confidence": 0.8,
      "new_confidence": 0.9,
      "evolution_count": 3,
      "applications_analyzed": 15
    }
  },
  "message": "Pattern evolved - Success rate: 0.87"
}
```

---

#### 5. suggest_learning_opportunities

Get recommendations for new learning areas.

**Usage**:
```bash
/tmws suggest_learning_opportunities
```

**Response**:
```json
{
  "success": true,
  "result": {
    "knowledge_base_summary": {
      "total_memories": 1250,
      "total_patterns": 45,
      "coverage_ratio": 0.67
    },
    "learning_opportunities": [
      {
        "type": "pattern_opportunity",
        "area": "api_design",
        "priority": "high",
        "reason": "High activity (120 memories) but low pattern coverage (2 patterns)",
        "suggested_action": "Learn patterns for api_design operations"
      }
    ],
    "opportunity_count": 8,
    "priority_breakdown": {
      "high": 3,
      "medium": 4,
      "low": 1
    }
  }
}
```

---

## Access Control Levels

### 5 Levels of Access

| Level | Description | Who Can Access | Use Case |
|-------|-------------|---------------|----------|
| `PRIVATE` | Owner only | `agent_id` matches owner | Personal patterns, experiments |
| `TEAM` | Same namespace | Same `namespace` | Team collaboration |
| `SHARED` | Explicit agents | Listed in `shared_with_agents` | Cross-team sharing |
| `PUBLIC` | All agents | Anyone | Best practices, public knowledge |
| `SYSTEM` | All agents (read-only) | Anyone (read-only) | System-wide patterns |

### Access Control Logic

**Implementation** (from `learning_pattern.py:243-257`):

```python
def can_access(self, agent_id: str | None) -> bool:
    """Check if an agent can access this pattern."""
    # PUBLIC and SYSTEM: Anyone can access
    if self.access_level == "public" or self.access_level == "system":
        return True
    
    # PRIVATE: Only owner
    if self.access_level == "private" and self.agent_id == agent_id:
        return True
    
    # SHARED: Owner or explicitly shared agents
    if self.access_level == "shared":
        return self.agent_id == agent_id or (
            self.shared_with_agents and agent_id in self.shared_with_agents
        )
    
    return False
```

### Example: Setting Access Levels

```python
# Private pattern (default)
private_pattern = await service.create_pattern(
    pattern_name="artemis_secret_optimization",
    category="performance",
    pattern_data={"secret": "technique"},
    agent_id="artemis-optimizer",
    access_level="private"  # Only Artemis can access
)

# Team pattern (share with namespace)
team_pattern = await service.create_pattern(
    pattern_name="team_code_review_checklist",
    category="quality",
    pattern_data={"checklist": [...]},
    namespace="trinitas-agents",
    access_level="team"  # All agents in "trinitas-agents" namespace
)

# Shared pattern (explicit agents)
shared_pattern = await service.create_pattern(
    pattern_name="security_audit_process",
    category="security",
    pattern_data={"process": [...]},
    agent_id="hestia-auditor",
    access_level="shared",
    shared_with_agents=["hestia-auditor", "artemis-optimizer", "athena-conductor"]
)

# Public pattern (everyone)
public_pattern = await service.create_pattern(
    pattern_name="python_coding_standards",
    category="quality",
    pattern_data={"standards": [...]},
    access_level="public"  # All agents can access
)
```

---

## Team Collaboration Patterns

### Pattern 1: Team Knowledge Base

**Scenario**: Artemis discovers optimization, shares with team

```python
# 1. Artemis creates team pattern
pattern = await service.create_pattern(
    pattern_name="database_connection_pooling",
    category="performance",
    subcategory="database",
    pattern_data={
        "description": "Use connection pooling to reduce latency",
        "implementation": "SQLAlchemy pool_size=10, max_overflow=20",
        "before_latency_ms": 150,
        "after_latency_ms": 15,
        "improvement_percent": 90
    },
    agent_id="artemis-optimizer",
    namespace="trinitas-agents",
    access_level="team",  # Share with entire team
    learning_weight=9.0
)

# 2. Hera searches for performance patterns
patterns = await service.search_patterns(
    category="performance",
    namespace="trinitas-agents",
    requesting_agent_id="hera-strategist",
    min_success_rate=0.8
)

# 3. Hera uses the pattern
await service.use_pattern(
    pattern_id=pattern.id,
    using_agent_id="hera-strategist",
    execution_time=0.1,
    success=True,
    context_data={"applied_to": "workflow execution service"}
)

# 4. Hera gets recommendations
recommendations = await service.recommend_patterns(
    agent_id="hera-strategist",
    category="performance"
)
```

---

### Pattern 2: Cross-Agent Collaboration

**Scenario**: Hestia + Artemis collaborate on security + performance

```python
# 1. Hestia creates security pattern
security_pattern = await service.create_pattern(
    pattern_name="sql_injection_prevention",
    category="security",
    pattern_data={
        "description": "Prevent SQL injection with parameterized queries",
        "vulnerable_code": 'f"SELECT * FROM users WHERE id = {user_id}"',
        "secure_code": "session.query(User).filter(User.id == user_id).first()",
        "frameworks": ["SQLAlchemy", "Django ORM"]
    },
    agent_id="hestia-auditor",
    namespace="trinitas-agents",
    access_level="shared",
    shared_with_agents=["hestia-auditor", "artemis-optimizer"]
)

# 2. Artemis checks if security pattern impacts performance
artemis_review = await service.get_pattern(
    pattern_id=security_pattern.id,
    requesting_agent_id="artemis-optimizer"
)

# 3. Artemis adds performance notes
await service.update_pattern(
    pattern_id=security_pattern.id,
    updating_agent_id="hestia-auditor",  # Only owner can update
    pattern_data={
        **security_pattern.pattern_data,
        "performance_notes": "Parameterized queries have minimal overhead (<1ms)",
        "reviewed_by": "artemis-optimizer"
    }
)

# 4. Both track usage
await service.use_pattern(
    pattern_id=security_pattern.id,
    using_agent_id="artemis-optimizer",
    execution_time=0.05,
    success=True
)
```

---

### Pattern 3: Pattern Evolution Through Team Usage

**Scenario**: Pattern improves through collective feedback

```python
# Initial pattern (Artemis)
pattern = await service.create_pattern(
    pattern_name="api_rate_limiting",
    category="security",
    pattern_data={
        "description": "Basic rate limiting with Redis",
        "implementation": "10 requests/minute per IP"
    },
    agent_id="artemis-optimizer",
    access_level="team",
    namespace="trinitas-agents"
)

# Hestia uses and provides feedback
await service.use_pattern(
    pattern_id=pattern.id,
    using_agent_id="hestia-auditor",
    execution_time=0.2,
    success=True,
    context_data={
        "feedback": "Works but needs burst allowance for legitimate traffic spikes"
    }
)

# Eris uses and finds improvement
await service.use_pattern(
    pattern_id=pattern.id,
    using_agent_id="eris-coordinator",
    execution_time=0.15,
    success=True,
    context_data={
        "feedback": "Token bucket algorithm better than fixed window"
    }
)

# Artemis creates new version based on team feedback
new_version = await pattern.create_version(
    new_version="2.0.0",
    pattern_data={
        "description": "Advanced rate limiting with token bucket",
        "implementation": "10 requests/min baseline + 5 burst tokens",
        "algorithm": "token_bucket",
        "improvements_from_v1": [
            "Burst allowance for traffic spikes",
            "Token bucket algorithm for smoother limiting"
        ]
    }
)

# Analytics show improvement
analytics = await service.get_pattern_analytics(
    namespace="trinitas-agents"
)
# v2.0.0 success rate: 95% vs v1.0.0: 78%
```

---

## Pattern Versioning

### Version Hierarchy

```
pattern_v1.0.0 (parent_pattern_id = None)
    ├── pattern_v1.1.0 (parent_pattern_id = v1.0.0)
    ├── pattern_v2.0.0 (parent_pattern_id = v1.0.0)
    │       └── pattern_v2.1.0 (parent_pattern_id = v2.0.0)
    └── pattern_v3.0.0 (parent_pattern_id = v1.0.0)
```

### Creating Versions

**Method 1: Using `create_version()` (Model Method)**

```python
# Get existing pattern
pattern_v1 = await service.get_pattern(
    pattern_id=UUID("..."),
    requesting_agent_id="artemis-optimizer"
)

# Create new version
pattern_v2 = await pattern_v1.create_version(
    new_version="2.0.0",
    pattern_data={
        **pattern_v1.pattern_data,  # Inherit base data
        "improvements": ["Better error handling", "Added retry logic"],
        "breaking_changes": ["API signature changed"]
    },
    learning_weight=pattern_v1.learning_weight + 1.0  # Increase importance
)

print(f"Created v{pattern_v2.version} from v{pattern_v1.version}")
print(f"Parent: {pattern_v2.parent_pattern_id}")
```

**Method 2: Manual Creation with `parent_pattern_id`**

```python
pattern_v3 = await service.create_pattern(
    pattern_name=pattern_v1.pattern_name,  # Same name
    category=pattern_v1.category,
    pattern_data={
        "version_note": "Major refactor",
        "improvements": [...]
    },
    agent_id=pattern_v1.agent_id,
    namespace=pattern_v1.namespace,
    version="3.0.0",  # Explicit version
    parent_pattern_id=pattern_v1.id  # Link to parent
)
```

### Version Query

**Get all versions of a pattern**:

```python
# Get pattern lineage
parent = await service.get_pattern(parent_pattern_id)

# Find all children
children = await service.search_patterns(
    namespace=parent.namespace,
    # Custom query for parent_pattern_id = parent.id
)

print(f"Pattern '{parent.pattern_name}' has {len(children)} versions")
for child in children:
    print(f"  v{child.version} - {child.pattern_data.get('version_note', 'N/A')}")
```

---

## Usage Examples

### Example 1: Artemis Optimizes Database Query

```python
# 1. Artemis discovers optimization
pattern = await service.create_pattern(
    pattern_name="postgres_index_optimization",
    category="performance",
    subcategory="database",
    pattern_data={
        "description": "Add composite index to speed up user post queries",
        "problem": "Slow queries: SELECT * FROM posts WHERE user_id = X ORDER BY created_at DESC",
        "solution": "CREATE INDEX idx_posts_user_created ON posts(user_id, created_at DESC);",
        "benchmark": {
            "before_ms": 2000,
            "after_ms": 300,
            "improvement_percent": 85
        },
        "steps": [
            "Run EXPLAIN ANALYZE to confirm index not used",
            "Create composite index",
            "Verify with EXPLAIN to confirm index usage",
            "Monitor query performance for 24 hours"
        ]
    },
    agent_id="artemis-optimizer",
    namespace="trinitas-agents",
    access_level="team",
    learning_weight=9.5
)

# 2. Record successful application
await service.use_pattern(
    pattern_id=pattern.id,
    using_agent_id="artemis-optimizer",
    execution_time=0.245,
    success=True,
    context_data={
        "database": "PostgreSQL 14",
        "table_rows": 1_000_000,
        "actual_improvement_percent": 87
    }
)
```

---

### Example 2: Hestia Security Audit

```python
# 1. Hestia creates security checklist
checklist = await service.create_pattern(
    pattern_name="api_security_checklist",
    category="security",
    subcategory="api",
    pattern_data={
        "description": "Comprehensive API security audit checklist",
        "checklist": [
            "✓ Authentication: JWT with 256-bit secret",
            "✓ Authorization: Role-based access control (RBAC)",
            "✓ Input validation: Pydantic models for all endpoints",
            "✓ SQL injection: Parameterized queries only",
            "✓ XSS: Output escaping enabled",
            "✓ CSRF: Token validation on state-changing operations",
            "✓ Rate limiting: 100 req/min per IP",
            "✓ HTTPS: Force HTTPS in production",
            "✓ Security headers: HSTS, CSP, X-Frame-Options",
            "✓ Logging: Security events logged (no PII)"
        ],
        "severity_levels": {
            "CRITICAL": "SQL injection, XSS, Auth bypass",
            "HIGH": "CSRF, Missing rate limiting",
            "MEDIUM": "Missing security headers",
            "LOW": "Verbose error messages"
        }
    },
    agent_id="hestia-auditor",
    namespace="trinitas-agents",
    access_level="public",  # Everyone should use this
    learning_weight=10.0  # Maximum importance
)

# 2. Hestia uses checklist
await service.use_pattern(
    pattern_id=checklist.id,
    using_agent_id="hestia-auditor",
    execution_time=15.5,  # 15.5 seconds for full audit
    success=True,
    context_data={
        "audit_target": "TMWS REST API",
        "findings": {
            "CRITICAL": 0,
            "HIGH": 1,  # Missing rate limiting on one endpoint
            "MEDIUM": 2,
            "LOW": 3
        }
    }
)
```

---

### Example 3: Athena Architecture Design

```python
# 1. Athena creates architecture pattern
pattern = await service.create_pattern(
    pattern_name="microservices_communication",
    category="architecture",
    subcategory="distributed_systems",
    pattern_data={
        "description": "Event-driven microservices communication pattern",
        "problem": "Tight coupling between services via synchronous HTTP calls",
        "solution": "Asynchronous event bus with message queues",
        "components": {
            "message_broker": "RabbitMQ or Redis Streams",
            "event_schema": "Pydantic models",
            "retry_strategy": "Exponential backoff with max 3 retries"
        },
        "benefits": [
            "Loose coupling",
            "Better fault tolerance",
            "Horizontal scalability",
            "Event replay capability"
        ],
        "tradeoffs": [
            "Increased complexity",
            "Eventual consistency",
            "Debugging difficulty"
        ],
        "when_to_use": "Services need to scale independently or have different SLAs",
        "when_not_to_use": "Simple CRUD applications or strong consistency required"
    },
    agent_id="athena-conductor",
    namespace="trinitas-agents",
    access_level="team",
    learning_weight=8.5
)

# 2. Get recommendations for similar patterns
recommendations = await service.recommend_patterns(
    agent_id="athena-conductor",
    category="architecture",
    context_data={
        "task": "Design workflow orchestration system",
        "requirements": ["fault tolerance", "scalability", "event-driven"]
    }
)

print(f"Found {len(recommendations)} relevant architecture patterns")
```

---

### Example 4: Team Learning Analytics

```python
# Get team learning analytics
analytics = await service.get_pattern_analytics(
    namespace="trinitas-agents",
    days=30
)

print("\n=== Team Learning Report (Last 30 Days) ===\n")

print(f"Total Patterns: {analytics['total_patterns']}")
print(f"Total Applications: {analytics['overview']['total_applications']}")
print(f"Avg Success Rate: {analytics['overview']['avg_success_rate']:.0%}")
print(f"Knowledge Base Health: {analytics['overview']['knowledge_base_health']}")

print("\n--- Category Distribution ---")
for category, count in analytics['distribution']['by_category'].items():
    print(f"  {category}: {count} patterns")

print("\n--- Top 5 Most Used Patterns ---")
for i, pattern in enumerate(analytics['usage_patterns']['most_applied'][:5], 1):
    print(f"{i}. {pattern['pattern_name']}")
    print(f"   Applied: {pattern['application_count']}x | Success: {pattern['success_rate']:.0%}")

print("\n--- Recommendations ---")
recs = analytics['recommendations']
print(f"High-value patterns: {recs['high_value_patterns']}")
print(f"Patterns to review: {recs['patterns_to_review']}")
print(f"Knowledge gaps: {', '.join(recs['knowledge_gaps'])}")
```

---

## Migration Guide

### From .claude/skills/ to TMWS Learning Patterns

#### Step 1: Export Existing Skills

**Anthropic Agent Skills Structure**:
```
.claude/skills/
├── database_optimization/
│   ├── SKILL.md
│   └── examples/
│       └── postgres_index.sql
├── security_audit/
│   └── SKILL.md
```

**SKILL.md Format**:
```markdown
# Database Query Optimization

## Description
Optimize slow database queries using composite indexes.

## When to Use
- Query takes >1 second
- Filtering on multiple columns
- PostgreSQL or MySQL

## Steps
1. Run EXPLAIN ANALYZE
2. Identify missing indexes
3. Create composite index
4. Verify improvement

## Example
\`\`\`sql
CREATE INDEX idx_posts_user_created ON posts(user_id, created_at DESC);
\`\`\`

## Expected Improvement
60-85% query latency reduction
```

---

#### Step 2: Convert to TMWS Pattern

**Conversion Script** (`scripts/migrate_skills_to_tmws.py`):

```python
#!/usr/bin/env python3
"""Migrate .claude/skills/ to TMWS Learning Patterns"""

import asyncio
from pathlib import Path
import frontmatter
from src.services.learning_service import LearningService

async def migrate_skills():
    service = LearningService()
    skills_dir = Path(".claude/skills")
    
    if not skills_dir.exists():
        print("No .claude/skills directory found")
        return
    
    for skill_dir in skills_dir.iterdir():
        if not skill_dir.is_dir():
            continue
        
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            print(f"⚠️  Skipping {skill_dir.name} - no SKILL.md")
            continue
        
        # Parse markdown with frontmatter
        post = frontmatter.load(skill_md)
        
        # Extract metadata
        pattern_name = skill_dir.name
        category = post.metadata.get("category", "general")
        subcategory = post.metadata.get("subcategory")
        
        # Parse markdown sections
        content = post.content
        sections = parse_markdown_sections(content)
        
        # Create pattern data
        pattern_data = {
            "description": sections.get("Description", ""),
            "when_to_use": sections.get("When to Use", ""),
            "steps": parse_list(sections.get("Steps", "")),
            "example": sections.get("Example", ""),
            "expected_improvement": sections.get("Expected Improvement", ""),
            "migrated_from": str(skill_md),
            "original_frontmatter": post.metadata
        }
        
        # Create TMWS pattern
        pattern = await service.create_pattern(
            pattern_name=pattern_name,
            category=category,
            subcategory=subcategory,
            pattern_data=pattern_data,
            agent_id=post.metadata.get("author", "system"),
            namespace="trinitas-agents",
            access_level="team",
            learning_weight=post.metadata.get("importance", 5.0)
        )
        
        print(f"✅ Migrated: {pattern_name} → {pattern.id}")
    
    print("\nMigration complete!")

def parse_markdown_sections(content: str) -> dict[str, str]:
    """Parse markdown into sections"""
    sections = {}
    current_section = None
    current_content = []
    
    for line in content.split("\n"):
        if line.startswith("## "):
            if current_section:
                sections[current_section] = "\n".join(current_content).strip()
            current_section = line[3:].strip()
            current_content = []
        else:
            current_content.append(line)
    
    if current_section:
        sections[current_section] = "\n".join(current_content).strip()
    
    return sections

def parse_list(text: str) -> list[str]:
    """Parse markdown list to Python list"""
    return [
        line.strip("- ").strip()
        for line in text.split("\n")
        if line.strip().startswith("-") or line.strip().startswith("1.")
    ]

if __name__ == "__main__":
    asyncio.run(migrate_skills())
```

**Run Migration**:
```bash
python scripts/migrate_skills_to_tmws.py
```

---

#### Step 3: Verify Migration

```python
from src.services.learning_service import LearningService

service = LearningService()

# List all migrated patterns
patterns = await service.search_patterns(
    namespace="trinitas-agents",
    limit=100
)

print(f"Migrated {len(patterns)} patterns:")
for pattern in patterns:
    if "migrated_from" in pattern.pattern_data:
        print(f"  ✅ {pattern.pattern_name}")
        print(f"     From: {pattern.pattern_data['migrated_from']}")
```

---

#### Step 4: Update Agent Workflows

**Before** (.claude/skills/):
```bash
# Manual file reading
cat .claude/skills/database_optimization/SKILL.md
```

**After** (TMWS MCP):
```bash
# Semantic search
/tmws apply_pattern \
  --pattern_query "optimize database queries" \
  --context "PostgreSQL slow SELECT"
```

---

## Best Practices

### 1. Pattern Naming Conventions

**Good Names**:
- `database_query_optimization` (specific, actionable)
- `sql_injection_prevention` (clear security focus)
- `microservices_event_driven` (architectural pattern)

**Bad Names**:
- `optimization` (too generic)
- `pattern1` (meaningless)
- `fix_bug` (not reusable)

**Convention**:
```
{domain}_{action}_{detail}

Examples:
- database_index_composite
- security_audit_api
- architecture_event_bus
```

---

### 2. Pattern Data Structure

**Minimum Required Fields**:
```python
{
    "description": "Clear one-sentence description",
    "problem": "What problem does this solve?",
    "solution": "What is the solution?",
    "steps": ["Step 1", "Step 2", "Step 3"],
    "example": "Code example",
    "expected_improvement": "Quantifiable improvement"
}
```

**Recommended Additional Fields**:
```python
{
    # Required fields...
    
    # Context
    "when_to_use": "Conditions for applying this pattern",
    "when_not_to_use": "When to avoid this pattern",
    "prerequisites": ["Requirement 1", "Requirement 2"],
    
    # Implementation
    "code_example": "Full code snippet",
    "frameworks": ["FastAPI", "SQLAlchemy"],
    "languages": ["Python", "SQL"],
    
    # Results
    "benchmark": {
        "before": "2000ms",
        "after": "300ms",
        "improvement_percent": 85
    },
    
    # Tradeoffs
    "benefits": ["Benefit 1", "Benefit 2"],
    "drawbacks": ["Drawback 1", "Drawback 2"],
    "gotchas": ["Watch out for X", "Be careful with Y"]
}
```

---

### 3. Access Level Guidelines

| Scenario | Recommended Access Level |
|----------|-------------------------|
| Personal experiment | `PRIVATE` |
| Team best practice | `TEAM` |
| Cross-team collaboration | `SHARED` (with explicit agents) |
| Universal best practice | `PUBLIC` |
| System-wide policy | `SYSTEM` |

**Example Decision Tree**:
```python
def choose_access_level(pattern):
    if pattern.is_experimental or pattern.is_work_in_progress:
        return "private"
    
    if pattern.is_team_specific:
        return "team"
    
    if pattern.involves_cross_team_coordination:
        return "shared"
    
    if pattern.is_universal_best_practice:
        return "public"
    
    if pattern.is_security_policy or pattern.is_compliance_requirement:
        return "system"
    
    return "team"  # Default
```

---

### 4. Pattern Maintenance

**Regular Reviews**:
```python
# Monthly pattern review
analytics = await service.get_pattern_analytics(
    namespace="trinitas-agents",
    days=30
)

# Identify low-performing patterns
low_performers = [
    p for p in analytics['top_patterns']
    if p['success_rate'] < 0.7 and p['application_count'] > 5
]

# Review and update or deprecate
for pattern_info in low_performers:
    pattern = await service.get_pattern(UUID(pattern_info['id']))
    
    # Option 1: Update with improvements
    await service.update_pattern(
        pattern_id=pattern.id,
        updating_agent_id=pattern.agent_id,
        pattern_data={
            **pattern.pattern_data,
            "deprecated_reason": "Low success rate",
            "replacement_pattern": "new_pattern_v2"
        }
    )
    
    # Option 2: Create new version
    new_version = await pattern.create_version(
        new_version="2.0.0",
        pattern_data={...improvements...}
    )
```

**Versioning Strategy**:
- **Patch (1.0.1)**: Bug fixes, minor improvements
- **Minor (1.1.0)**: New features, backward compatible
- **Major (2.0.0)**: Breaking changes, significant redesign

---

### 5. Team Collaboration Best Practices

**Pattern Sharing Workflow**:
```python
# 1. Artemis creates private pattern
pattern = await service.create_pattern(
    pattern_name="new_optimization_technique",
    access_level="private",  # Start private
    agent_id="artemis-optimizer"
)

# 2. Test and validate (5+ successful uses)
for _ in range(5):
    await service.use_pattern(
        pattern_id=pattern.id,
        using_agent_id="artemis-optimizer",
        success=True
    )

# 3. If success rate > 80%, share with team
refreshed = await service.get_pattern(pattern.id)
if refreshed.success_rate > 0.8:
    await service.update_pattern(
        pattern_id=pattern.id,
        updating_agent_id="artemis-optimizer",
        access_level="team"  # Now team can use
    )
```

**Cross-Agent Review**:
```python
# Hestia reviews Artemis's performance pattern for security
pattern = await service.get_pattern(
    pattern_id=artemis_pattern.id,
    requesting_agent_id="hestia-auditor"
)

# Hestia adds security notes
await service.update_pattern(
    pattern_id=pattern.id,
    updating_agent_id="artemis-optimizer",  # Still owner
    pattern_data={
        **pattern.pattern_data,
        "security_review": {
            "reviewer": "hestia-auditor",
            "date": "2025-11-14",
            "findings": "No security concerns",
            "recommendations": ["Add input validation example"]
        }
    }
)
```

---

### 6. Performance Optimization

**Batch Operations**:
```python
# Bad: Create patterns one-by-one
for pattern_data in patterns_list:
    await service.create_pattern(**pattern_data)  # N database calls

# Good: Batch create
await service.batch_create_patterns(
    patterns_data=patterns_list  # 1 database transaction
)
```

**Caching**:
```python
# Service-level caching (already implemented)
analytics = await service.get_pattern_analytics()  # Cache hit: <1ms
analytics = await service.get_pattern_analytics()  # Cache hit: <1ms

# Clear cache after pattern updates
await service.update_pattern(...)
# Analytics cache automatically invalidated
```

---

## Summary

### Key Takeaways

1. **Learning Patterns = Agent Skills TMWS Version**
   - Database-backed (not filesystem)
   - User chose Proposal 2 (database-based) over Proposal 1 (.claude/skills/)

2. **Two Implementations**:
   - Legacy: `learning_tools.py` (memory-based, 5 MCP tools)
   - New: `learning_service.py` (database-based, 11 methods) ✅ **Use this**

3. **Core Features**:
   - 5 access levels (PRIVATE, TEAM, SHARED, PUBLIC, SYSTEM)
   - Pattern versioning (parent-child hierarchy)
   - Usage tracking (success rate, confidence score)
   - AI-powered recommendations
   - Team collaboration

4. **Usage Pattern**:
   ```python
   # Create → Use → Track → Evolve → Share
   pattern = await service.create_pattern(...)
   await service.use_pattern(pattern.id, success=True)
   analytics = await service.get_pattern_analytics()
   new_version = await pattern.create_version("2.0.0", ...)
   await service.update_pattern(access_level="team")
   ```

5. **Migration Path**: .claude/skills/ → TMWS Learning Patterns (see [Migration Guide](#migration-guide))

---

## Next Steps

1. **Read**: [QUICK_START_GUIDE.md](QUICK_START_GUIDE.md) - Get started in 15 minutes
2. **Reference**: [MCP_TOOLS_REFERENCE.md](MCP_TOOLS_REFERENCE.md) - Complete tool reference
3. **Explore**: Try the 5 MCP tools via Claude Code
4. **Integrate**: Use `LearningService` in your Trinitas-agents workflows
5. **Migrate**: Convert existing `.claude/skills/` to TMWS patterns

---

**Document Author**: Artemis (Technical Perfectionist) + Muses (Knowledge Architect)
**Reviewed By**: Athena, Hera
**Last Updated**: 2025-11-14
**Status**: Production-ready
**Version**: 1.0.0
