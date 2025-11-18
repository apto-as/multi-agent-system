# TMWS Integration Guide for Trinitas-agents v2.2.5
## Complete Knowledge Architecture Strategy

---
**Document Type**: Implementation Guide
**Created**: 2025-10-29
**Author**: Muses (Knowledge Architect)
**Target Version**: v2.2.5
**Purpose**: TMWS-specific documentation for public release
---

## Executive Summary

This guide details how to document TMWS (Trinitas Memory & Workflow System) integration into Trinitas-agents v2.2.5 for public consumption. It complements the existing PUBLIC_DOCUMENTATION_STRATEGY.md with TMWS-specific content.

### Key Changes in v2.2.5
- **TMWS as Core Component**: MCP server integration (was separate project)
- **Unified Memory System**: SQLite + ChromaDB for persistent knowledge
- **Enhanced Workflow Orchestration**: Multi-agent task coordination
- **Learning System**: Pattern recognition and knowledge evolution

---

## Documentation Structure for TMWS Integration

### New Sections Required

```
docs/
├── getting-started/
│   ├── tmws-quickstart.md          # NEW: 5-minute TMWS intro
│   └── tmws-concepts.md            # NEW: Memory, workflows, learning
│
├── user-guides/
│   ├── memory-management.md        # ENHANCED: TMWS memory operations
│   ├── workflow-orchestration.md   # ENHANCED: TMWS workflow system
│   ├── learning-system.md          # NEW: Pattern learning with TMWS
│   └── mcp-server-usage.md         # NEW: Using TMWS as MCP server
│
├── reference/
│   ├── tmws-api/                   # NEW: TMWS API reference
│   │   ├── memory-service.md
│   │   ├── workflow-service.md
│   │   └── learning-service.md
│   ├── tmws-tools.md               # NEW: MCP tools catalog
│   └── tmws-configuration.md       # NEW: TMWS config options
│
├── migration/
│   └── tmws-migration-guide.md     # NEW: v2.2.4 → v2.2.5 with TMWS
│
└── architecture/
    ├── tmws-architecture.md        # NEW: TMWS design & integration
    └── tmws-security.md            # NEW: TMWS security model
```

---

## TMWS Quick Start Guide Template

**File**: `docs/getting-started/tmws-quickstart.md`
**Target Audience**: New users wanting to try TMWS features
**Estimated Length**: 800 words (~10 minutes)

### Content Outline

```markdown
# TMWS Quick Start Guide

## What is TMWS?

TMWS (Trinitas Memory & Workflow System) is the intelligence core of Trinitas-agents, providing:

- **Persistent Memory**: Remember conversations, decisions, and patterns across sessions
- **Workflow Orchestration**: Coordinate multiple AI agents for complex tasks
- **Learning System**: Automatically recognize and apply successful patterns

## 5-Minute Quick Start

### Step 1: Verify TMWS Installation (1 minute)

```bash
# Check TMWS is available
python -c "from src.services.memory_service import MemoryService; print('TMWS Ready')"
```

**Expected Output**: `TMWS Ready`

### Step 2: Create Your First Memory (2 minutes)

```python
from src.services.memory_service import MemoryService

# Initialize service
memory_service = MemoryService()

# Create a memory
memory_id = await memory_service.create_memory(
    content="My project uses Python 3.11 with FastAPI",
    memory_type="project_context",
    importance=0.9,
    tags=["python", "fastapi", "project-setup"]
)

print(f"Memory created: {memory_id}")
```

### Step 3: Search Memories (1 minute)

```python
# Semantic search
results = await memory_service.search_memories(
    query="What Python version do I use?",
    limit=5
)

for memory in results:
    print(f"- {memory.content} (relevance: {memory.score:.2f})")
```

### Step 4: Execute a Workflow (2 minutes)

```python
from src.services.workflow_service import WorkflowService

workflow_service = WorkflowService()

# Create simple workflow
workflow_id = await workflow_service.create_workflow(
    name="Code Review",
    tasks=[
        {"agent": "artemis", "action": "review_code", "input": "src/api.py"},
        {"agent": "hestia", "action": "security_scan", "input": "src/api.py"},
        {"agent": "muses", "action": "document_findings"}
    ]
)

# Execute
results = await workflow_service.execute_workflow(workflow_id)
```

## Next Steps

- **Memory Management**: [Complete guide](../user-guides/memory-management.md)
- **Workflow Patterns**: [Orchestration guide](../user-guides/workflow-orchestration.md)
- **Learning System**: [Pattern recognition](../user-guides/learning-system.md)

## Troubleshooting

**Q: Memory creation fails with "Database connection error"**
A: Check that `./data/tmws.db` exists and is writable

**Q: Search returns no results**
A: Ensure ChromaDB is initialized: `python -m src.database.init_db`
```

---

## Memory Management Guide Enhancement

**File**: `docs/user-guides/memory-management.md`
**Enhancements for v2.2.5**

### New Sections to Add

#### 1. Memory Types and Use Cases

```markdown
## Memory Types in TMWS

TMWS supports 7 memory types, each optimized for specific use cases:

| Type | Purpose | Importance Range | Example |
|------|---------|-----------------|---------|
| `user_preference` | User settings, preferences | 0.7-1.0 | "User prefers TypeScript over JavaScript" |
| `project_context` | Project-specific knowledge | 0.8-1.0 | "This project uses microservices architecture" |
| `technical_decision` | Design choices, rationale | 0.7-0.9 | "Chose PostgreSQL for ACID guarantees" |
| `pattern` | Reusable solutions | 0.6-0.9 | "Use Redis for session management" |
| `conversation` | Interaction history | 0.3-0.6 | "Discussed authentication on 2025-10-28" |
| `task` | Work items, todos | 0.5-0.8 | "Implement rate limiting by Friday" |
| `system` | System state, config | 0.8-1.0 | "Database migrated to v2.2.5 on 2025-10-29" |

### Choosing the Right Memory Type

```python
# Project decision (high importance, long retention)
await memory_service.create_memory(
    content="Using SQLite for simplicity, scalability not a concern",
    memory_type="technical_decision",
    importance=0.9,
    tags=["database", "architecture"]
)

# Casual conversation (low importance, can be archived)
await memory_service.create_memory(
    content="Discussed weekend plans",
    memory_type="conversation",
    importance=0.3,
    tags=["casual"]
)
```
```

#### 2. Access Levels and Sharing

```markdown
## Memory Access Levels

TMWS supports 4 access levels for knowledge sharing:

### 1. Private (Default)
- **Visibility**: Only you
- **Use Case**: Personal notes, sensitive information
```python
memory = await memory_service.create_memory(
    content="API key: sk-...",
    memory_type="system",
    importance=1.0,
    access_level="private"  # Never shared
)
```

### 2. Team
- **Visibility**: Your team/namespace
- **Use Case**: Team conventions, shared decisions
```python
memory = await memory_service.create_memory(
    content="Team coding standard: 4 spaces, no tabs",
    memory_type="project_context",
    importance=0.8,
    access_level="team"  # Shared with team
)
```

### 3. Shared
- **Visibility**: Explicitly shared users/agents
- **Use Case**: Cross-team collaboration
```python
memory = await memory_service.create_memory(
    content="API versioning strategy: /api/v1, /api/v2",
    memory_type="technical_decision",
    importance=0.9,
    access_level="shared",
    metadata={"shared_with": ["frontend-team", "backend-team"]}
)
```

### 4. Public
- **Visibility**: All users/agents in organization
- **Use Case**: Company-wide best practices
```python
memory = await memory_service.create_memory(
    content="Security policy: All passwords must be 12+ chars",
    memory_type="system",
    importance=1.0,
    access_level="public"  # Available to all
)
```
```

#### 3. Advanced Search Techniques

```markdown
## Advanced Memory Search

### Semantic Search with Filters

```python
# Find security-related decisions from last month
results = await memory_service.search_memories(
    query="authentication security",
    memory_type="technical_decision",
    tags=["security"],
    min_importance=0.7,
    limit=10,
    start_date="2025-10-01"
)
```

### Hybrid Search (Semantic + Keyword)

```python
# Combine semantic similarity with exact keyword matching
results = await memory_service.search_memories(
    query="database performance optimization",
    keywords=["postgresql", "index"],  # Must contain these
    min_relevance=0.6,
    limit=5
)
```

### Temporal Search

```python
# Find memories from specific time period
results = await memory_service.search_memories(
    query="project decisions",
    start_date="2025-10-01",
    end_date="2025-10-31",
    order_by="created_at"
)
```
```

---

## Workflow Orchestration Guide Enhancement

**File**: `docs/user-guides/workflow-orchestration.md`

### New Content for TMWS Integration

#### 1. Workflow Patterns with TMWS

```markdown
## TMWS-Powered Workflow Patterns

### Pattern 1: Memory-Aware Workflows

Use past decisions and context automatically:

```python
# Workflow that recalls relevant project context
workflow = await workflow_service.create_workflow(
    name="Feature Implementation",
    tasks=[
        {
            "agent": "athena",
            "action": "design_feature",
            "context_query": "project architecture decisions",  # Injects memories
            "input": "Add user authentication"
        },
        {
            "agent": "artemis",
            "action": "implement",
            "context_query": "coding standards performance patterns"
        },
        {
            "agent": "hestia",
            "action": "security_review",
            "context_query": "security vulnerabilities authentication"
        }
    ]
)
```

**How it Works**:
1. Before each task, TMWS searches relevant memories
2. Top 5 memories injected into agent context
3. Agent uses historical knowledge for decisions

### Pattern 2: Learning Workflows

Workflows that improve over time:

```python
# Workflow that learns from outcomes
workflow = await workflow_service.create_workflow(
    name="Bug Fixing",
    tasks=[
        {
            "agent": "artemis",
            "action": "analyze_bug",
            "learn_from": "previous_bug_fixes"  # Apply learned patterns
        },
        {
            "agent": "hestia",
            "action": "verify_fix"
        }
    ],
    enable_learning=True  # Record successful patterns
)

# After execution, TMWS saves effective approaches
```

### Pattern 3: Parallel Workflows with Shared Memory

```python
# Multiple agents working simultaneously, sharing context
workflow = await workflow_service.create_workflow(
    name="Comprehensive Code Review",
    execution_mode="parallel",
    tasks=[
        {"agent": "artemis", "action": "performance_review"},
        {"agent": "hestia", "action": "security_review"},
        {"agent": "muses", "action": "documentation_review"}
    ],
    shared_memory_access="team"  # All agents see same context
)
```
```

#### 2. Workflow Templates

```markdown
## Pre-built Workflow Templates

### Template 1: API Development Workflow

```python
from src.templates.workflows import ApiDevelopmentWorkflow

workflow = ApiDevelopmentWorkflow(
    api_name="User Management API",
    features=["CRUD", "Authentication", "Rate Limiting"]
)

# Execute with memory context
results = await workflow.execute(
    context_query="REST API best practices authentication patterns"
)
```

**Template Steps**:
1. Athena: Architecture design
2. Artemis: Implementation + optimization
3. Hestia: Security audit
4. Muses: API documentation
5. Learning: Save successful patterns

### Template 2: Security Audit Workflow

```python
from src.templates.workflows import SecurityAuditWorkflow

workflow = SecurityAuditWorkflow(
    target="./src/",
    depth="comprehensive"  # or "quick"
)

results = await workflow.execute(
    context_query="OWASP top 10 previous vulnerabilities"
)
```
```

---

## TMWS API Reference Structure

**Directory**: `docs/reference/tmws-api/`

### Memory Service API (`memory-service.md`)

```markdown
# Memory Service API Reference

## Overview

The Memory Service provides programmatic access to TMWS memory operations.

## Initialization

```python
from src.services.memory_service import MemoryService

memory_service = MemoryService()
# Uses DATABASE_URL from environment
```

## Methods

### `create_memory()`

Create a new memory entry.

**Signature**:
```python
async def create_memory(
    content: str,
    memory_type: MemoryType,
    importance: float = 0.5,
    access_level: AccessLevel = AccessLevel.PRIVATE,
    tags: list[str] | None = None,
    metadata: dict | None = None,
    persona_id: str | None = None
) -> str
```

**Parameters**:

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `content` | `str` | Yes | - | Memory content (1-10000 chars) |
| `memory_type` | `MemoryType` | Yes | - | Type of memory (enum) |
| `importance` | `float` | No | `0.5` | Importance score (0.0-1.0) |
| `access_level` | `AccessLevel` | No | `PRIVATE` | Access control level |
| `tags` | `list[str]` | No | `[]` | Searchable tags |
| `metadata` | `dict` | No | `{}` | Additional structured data |
| `persona_id` | `str` | No | `None` | Trinitas persona that created memory |

**Returns**: `str` - Memory ID (UUID format)

**Raises**:
- `ValueError`: Invalid parameters (content empty, importance out of range)
- `DatabaseError`: Database connection or write failure

**Example**:
```python
memory_id = await memory_service.create_memory(
    content="Project uses Python 3.11 and FastAPI 0.104",
    memory_type=MemoryType.PROJECT_CONTEXT,
    importance=0.9,
    tags=["python", "fastapi", "setup"],
    metadata={"project_id": "proj-123", "created_by": "user-456"},
    persona_id="athena-conductor"
)
print(f"Created memory: {memory_id}")
```

**Best Practices**:
- Use descriptive content (complete sentences)
- Set importance based on long-term value (0.8+ for critical decisions)
- Add tags for efficient filtering (3-5 tags recommended)
- Include structured metadata for complex queries

---

### `search_memories()`

Search memories using semantic similarity and filters.

**Signature**:
```python
async def search_memories(
    query: str,
    memory_type: MemoryType | None = None,
    tags: list[str] | None = None,
    min_importance: float = 0.0,
    access_level: AccessLevel | None = None,
    limit: int = 10,
    start_date: str | None = None,
    end_date: str | None = None
) -> list[Memory]
```

**Parameters**:

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `query` | `str` | Yes | - | Search query (natural language) |
| `memory_type` | `MemoryType` | No | `None` | Filter by type |
| `tags` | `list[str]` | No | `None` | Filter by tags (OR logic) |
| `min_importance` | `float` | No | `0.0` | Minimum importance threshold |
| `access_level` | `AccessLevel` | No | `None` | Filter by access level |
| `limit` | `int` | No | `10` | Max results (1-100) |
| `start_date` | `str` | No | `None` | ISO format date (YYYY-MM-DD) |
| `end_date` | `str` | No | `None` | ISO format date (YYYY-MM-DD) |

**Returns**: `list[Memory]` - Ordered by relevance score (descending)

**Example**:
```python
# Find recent security decisions
results = await memory_service.search_memories(
    query="authentication security vulnerabilities",
    memory_type=MemoryType.TECHNICAL_DECISION,
    tags=["security"],
    min_importance=0.7,
    limit=5,
    start_date="2025-10-01"
)

for memory in results:
    print(f"[{memory.relevance_score:.2f}] {memory.content}")
```

**Performance Notes**:
- Semantic search: ~50-200ms (depends on collection size)
- Filtered search: ~20-100ms (indexes used)
- First search after startup: ~500ms (model loading)

---

[Continue with remaining API methods...]
```

---

## TMWS Tools Reference

**File**: `docs/reference/tmws-tools.md`

### MCP Tools Catalog

```markdown
# TMWS MCP Tools Reference

## Overview

TMWS provides 20+ tools via MCP (Model Context Protocol) for integration with AI assistants like Claude Code.

## Tool Categories

### 1. Memory Operations (7 tools)

#### `tmws_create_memory`

Create a new memory entry.

**Parameters**:
```json
{
  "content": "Memory content",
  "memory_type": "project_context",
  "importance": 0.9,
  "tags": ["tag1", "tag2"],
  "access_level": "private"
}
```

**Returns**:
```json
{
  "memory_id": "mem-abc123",
  "created_at": "2025-10-29T10:30:00Z"
}
```

**Example Usage** (Claude Code):
```
User: "Remember that we're using Python 3.11 for this project"
Claude: [Calls tmws_create_memory automatically]
```

---

#### `tmws_search_memories`

Search memories with semantic similarity.

**Parameters**:
```json
{
  "query": "What database are we using?",
  "limit": 5,
  "min_importance": 0.6
}
```

**Returns**:
```json
{
  "results": [
    {
      "memory_id": "mem-xyz789",
      "content": "Using PostgreSQL 15 for primary database",
      "relevance_score": 0.92,
      "created_at": "2025-10-20T14:00:00Z"
    }
  ]
}
```

---

#### `tmws_recall_context`

Inject relevant memories into conversation context.

**Parameters**:
```json
{
  "query": "implementation approach",
  "limit": 5,
  "auto_inject": true
}
```

**Behavior**:
- Searches relevant memories
- Automatically adds to conversation context
- Returns summary of injected memories

**Use Case**: Before implementing features, recall project decisions

---

[Continue with remaining 17 tools...]

### 2. Workflow Operations (6 tools)

- `tmws_create_workflow`
- `tmws_execute_workflow`
- `tmws_get_workflow_status`
- `tmws_list_workflows`
- `tmws_cancel_workflow`
- `tmws_workflow_templates`

### 3. Learning Operations (4 tools)

- `tmws_create_pattern`
- `tmws_apply_pattern`
- `tmws_list_patterns`
- `tmws_pattern_effectiveness`

### 4. System Operations (3 tools)

- `tmws_status`
- `tmws_stats`
- `tmws_health_check`
```

---

## Migration Guide for TMWS Integration

**File**: `docs/migration/tmws-migration-guide.md`

### Content Structure

```markdown
# Migration Guide: v2.2.4 → v2.2.5 (TMWS Integration)

## Overview

Version 2.2.5 integrates TMWS as a core component, replacing the previous file-based memory system.

## Breaking Changes Summary

### 1. Memory System Changed

**v2.2.4** (File-based):
```python
# Old approach
from shared.utils.file_memory import FileMemory
memory = FileMemory("~/.claude/memories/")
memory.save("key", "value")
```

**v2.2.5** (TMWS):
```python
# New approach
from src.services.memory_service import MemoryService
memory_service = MemoryService()
memory_id = await memory_service.create_memory(
    content="value",
    memory_type="project_context",
    importance=0.8
)
```

### 2. Configuration Changes

**Old** (`.env` in v2.2.4):
```bash
MEMORY_DIR=~/.claude/memories
```

**New** (`.env` in v2.2.5):
```bash
DATABASE_URL=sqlite+aiosqlite:///./data/tmws.db
CHROMA_PERSIST_DIR=./data/chroma
EMBEDDING_MODEL=intfloat/multilingual-e5-large
```

### 3. API Changes

| v2.2.4 Method | v2.2.5 Equivalent | Notes |
|---------------|-------------------|-------|
| `memory.save(key, val)` | `create_memory(content=val, ...)` | Now requires type, importance |
| `memory.load(key)` | `search_memories(query=key, limit=1)` | Semantic search instead of key-value |
| `memory.list()` | `search_memories(query="", limit=100)` | Returns all memories |
| `memory.delete(key)` | `delete_memory(memory_id)` | Now uses memory ID |

## Migration Steps

### Phase 1: Install TMWS Dependencies (5 minutes)

```bash
# Update dependencies
uv sync --all-extras

# Verify TMWS installation
python -c "from src.services.memory_service import MemoryService; print('OK')"
```

### Phase 2: Initialize TMWS Database (3 minutes)

```bash
# Create database
python -m src.database.init_db

# Verify database created
ls -lh ./data/tmws.db
ls -lh ./data/chroma/
```

### Phase 3: Migrate Existing Memories (varies)

**Automatic Migration** (recommended):
```bash
./scripts/migrate_memories_to_tmws.sh \
  --source ~/.claude/memories/ \
  --target ./data/tmws.db \
  --default-importance 0.6
```

**Manual Migration** (if automatic fails):
```python
# Read old memories
import json
from pathlib import Path

old_memories = Path("~/.claude/memories/").expanduser()
for file in old_memories.glob("*.json"):
    with open(file) as f:
        data = json.load(f)

    # Create in TMWS
    await memory_service.create_memory(
        content=data["content"],
        memory_type="conversation",  # Adjust based on context
        importance=0.6,
        tags=data.get("tags", [])
    )
```

### Phase 4: Update Custom Code (varies)

If you have custom integrations using the old memory system:

**Before** (v2.2.4):
```python
from shared.utils.file_memory import FileMemory

memory = FileMemory()
memory.save("project_db", "PostgreSQL 15")
db_type = memory.load("project_db")
```

**After** (v2.2.5):
```python
from src.services.memory_service import MemoryService

memory_service = MemoryService()

# Save
await memory_service.create_memory(
    content="Using PostgreSQL 15 for database",
    memory_type="project_context",
    importance=0.9,
    tags=["database", "postgresql"]
)

# Load
results = await memory_service.search_memories(
    query="project database",
    limit=1
)
db_info = results[0].content if results else None
```

### Phase 5: Verify Migration (10 minutes)

```bash
# Check memory count
python -c "
from src.services.memory_service import MemoryService
ms = MemoryService()
count = await ms.count_memories()
print(f'Migrated {count} memories')
"

# Test search
python -c "
from src.services.memory_service import MemoryService
ms = MemoryService()
results = await ms.search_memories('project', limit=5)
for r in results:
    print(f'- {r.content}')
"
```

### Phase 6: Cleanup (optional)

```bash
# Backup old memories
mv ~/.claude/memories/ ~/memories-backup-$(date +%Y%m%d)/

# Remove old configuration
sed -i '/MEMORY_DIR/d' .env
```

## Rollback Procedure

If migration fails or issues arise:

```bash
# 1. Restore code
git checkout v2.2.4

# 2. Restore old memories
mv ~/memories-backup-*/ ~/.claude/memories/

# 3. Remove TMWS database
rm -rf ./data/tmws.db ./data/chroma/

# 4. Reinstall dependencies
uv sync
```

## Frequently Asked Questions

**Q: Can I keep both old and new memory systems?**
A: No, v2.2.5 requires TMWS. However, you can keep a backup of old memories.

**Q: Will TMWS slow down my system?**
A: Initial startup: ~500ms (model loading). After that: 20-200ms per operation.

**Q: Can I use TMWS with multiple projects?**
A: Yes, use separate databases per project or use `access_level` and `metadata` to separate.

**Q: How do I back up TMWS data?**
A: Copy `./data/tmws.db` and `./data/chroma/` directories.
```

---

## TMWS Architecture Documentation

**File**: `docs/architecture/tmws-architecture.md`

### Content Focus

- **High-Level Design**: Component interaction, not implementation details
- **Integration Points**: How TMWS connects to Trinitas agents
- **Data Flow**: Memory creation → storage → retrieval
- **Scalability Considerations**: Performance characteristics, limits

**Exclude**:
- Source code listings
- Internal algorithms (semantic search implementation)
- Security mechanisms (protect IP)

---

## Implementation Timeline

### Week 1: TMWS Quick Start
- [ ] Write `tmws-quickstart.md` (800 words)
- [ ] Create 3 code examples (create, search, workflow)
- [ ] Test with 3 external users

### Week 2: Enhanced User Guides
- [ ] Enhance `memory-management.md` with TMWS sections
- [ ] Enhance `workflow-orchestration.md` with TMWS patterns
- [ ] Write `learning-system.md` (new guide)

### Week 3: API Reference
- [ ] Write `memory-service.md` API reference (2000 words)
- [ ] Write `workflow-service.md` API reference (1800 words)
- [ ] Write `learning-service.md` API reference (1500 words)

### Week 4: Tools & Migration
- [ ] Write `tmws-tools.md` (2500 words, 20+ tools)
- [ ] Write `tmws-migration-guide.md` (2000 words)
- [ ] Create migration scripts

### Week 5: Architecture & Polish
- [ ] Write `tmws-architecture.md` (1800 words)
- [ ] Write `tmws-security.md` (1400 words)
- [ ] Review all TMWS documentation
- [ ] Add diagrams (Mermaid.js)

**Total Effort**: ~40 hours writing + 10 hours review = **50 hours**

---

## Success Metrics for TMWS Documentation

| Metric | Target | Measurement |
|--------|--------|-------------|
| **TMWS Quick Start Success** | >85% complete in <15 min | User testing |
| **Migration Success Rate** | >90% successful migrations | User reports |
| **TMWS Tool Discovery** | >80% users find tools easily | Analytics (doc views) |
| **API Reference Completeness** | 100% public APIs documented | Code coverage |
| **User Satisfaction (TMWS docs)** | >4.3/5 stars | Feedback forms |

---

## Public vs Private: TMWS-Specific Guidelines

### Public (In multi-agent-system repo)

**Include**:
- ✅ TMWS concepts (memory, workflows, learning)
- ✅ API signatures and parameters
- ✅ Usage examples and patterns
- ✅ Configuration options
- ✅ Migration guides
- ✅ Tool catalog (MCP tools)

**High-Level Only**:
- ⚠️ Architecture diagrams (abstract components)
- ⚠️ Security best practices (user-facing advice)
- ⚠️ Performance characteristics (latency ranges, not algorithms)

### Private (Stay in trinitas-agents)

**Exclude**:
- ❌ TMWS source code (`src/services/*.py`)
- ❌ Database schema internals (migration scripts)
- ❌ Embedding model fine-tuning details
- ❌ Security vulnerability mitigations (CWE-specific code)
- ❌ Performance optimization algorithms
- ❌ Internal testing infrastructure

---

## Documentation Templates for Contributors

### Memory Service API Method Template

```markdown
### `method_name()`

Brief description (1-2 sentences).

**Signature**:
```python
async def method_name(
    param1: Type,
    param2: Type = default
) -> ReturnType
```

**Parameters**:
[Table with Name, Type, Required, Default, Description]

**Returns**: [Description of return value]

**Raises**: [List of exceptions]

**Example**:
```python
# Practical example with real use case
result = await service.method_name(param1="value")
print(result)
```

**Best Practices**:
- [Tip 1]
- [Tip 2]
- [Tip 3]

**Performance Notes**: [Latency, considerations]
```

### MCP Tool Documentation Template

```markdown
#### `tool_name`

Brief description (1 sentence).

**Parameters**:
```json
{
  "param1": "description",
  "param2": "description"
}
```

**Returns**:
```json
{
  "result": "description"
}
```

**Example Usage** (Claude Code):
```
User: "User request that triggers this tool"
Claude: [Automatic tool call]
Result: [What user sees]
```

**Use Cases**:
- Use case 1
- Use case 2

**Limitations**:
- Limitation 1
```

---

## Conclusion

This TMWS integration guide provides a comprehensive documentation strategy for v2.2.5, ensuring users can:

1. **Quickly understand TMWS** (5-minute quick start)
2. **Migrate smoothly** (90%+ success rate)
3. **Use effectively** (complete API reference, examples)
4. **Troubleshoot independently** (FAQ, common issues)

**Next Steps**:
1. Review this guide with technical team
2. Begin Week 1 implementation (quick start guide)
3. Coordinate with existing PUBLIC_DOCUMENTATION_STRATEGY.md
4. Test with alpha users (5-10 testers)

---

*"Clear, complete documentation turns complexity into capability."*
— Muses, Knowledge Architect

*明確で完全な文書は、複雑さを能力に変える*
