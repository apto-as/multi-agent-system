# AI Agent Integration Guide for TMWS
## How Trinitas-agents (AI Agents) Should Use This Documentation

**Target Audience**: AI Agents (not humans)
**Purpose**: Enable AI agents to properly integrate TMWS into their multi-agent system
**Last Updated**: 2025-11-14
**Version**: 1.0.0

---

## > Important: You Are an AI Agent Reading This

This guide is specifically written for **AI agents like you** (Trinitas-agents team), not for human developers. It addresses AI-specific challenges such as:

- **Context Window Limits**: You likely have a limited context window (typically 200K tokens)
- **Memory Constraints**: You need to process information efficiently
- **Sequential Learning**: You must learn TMWS incrementally, not all at once
- **Self-Verification**: You need to verify your understanding through code execution

**This guide will help you**:
1. Navigate the 7,400+ lines of TMWS documentation efficiently
2. Learn TMWS in a memory-efficient, prioritized manner
3. Integrate TMWS into your multi-agent system correctly
4. Verify your implementation through self-testing

---

## =Ú Table of Contents

1. [Prerequisite Knowledge](#prerequisite-knowledge)
2. [Document Reading Strategy](#document-reading-strategy)
3. [Persona-Specific Learning Paths](#persona-specific-learning-paths)
4. [Phase 0: Initial Assessment](#phase-0-initial-assessment)
5. [Phase 1: Core Knowledge Acquisition](#phase-1-core-knowledge-acquisition)
6. [Phase 2: Advanced Integration](#phase-2-advanced-integration)
7. [Phase 3: Production Deployment](#phase-3-production-deployment)
8. [Team Collaboration Protocol](#team-collaboration-protocol)
9. [Common Tasks & Solutions](#common-tasks--solutions)
10. [Self-Assessment Checklist](#self-assessment-checklist)
11. [Best Practices for AI Agents](#best-practices-for-ai-agents)
12. [Anti-Patterns to Avoid](#anti-patterns-to-avoid)
13. [Error Recovery Procedures](#error-recovery-procedures)

---

## Prerequisite Knowledge

Before you start learning TMWS, verify you have the following knowledge:

###  Required Knowledge (Must Have)

- [ ] **Python 3.11+**: Async/await, type hints, context managers
- [ ] **HTTP/REST API**: GET/POST/PUT/DELETE methods, JSON
- [ ] **Database Basics**: CRUD operations, SQL queries
- [ ] **Authentication**: JWT tokens, API keys
- [ ] **Multi-Agent Systems**: Task coordination, shared memory

###   Recommended Knowledge (Should Have)

- [ ] **FastAPI**: Async endpoints, dependency injection
- [ ] **SQLAlchemy 2.0**: Async ORM, models, sessions
- [ ] **ChromaDB**: Vector embeddings, semantic search
- [ ] **MCP (Model Context Protocol)**: Tool-based agent communication

### =Ö Optional Knowledge (Nice to Have)

- [ ] **Alembic**: Database migrations
- [ ] **Docker**: Containerization
- [ ] **CI/CD**: Automated testing, deployment

**Self-Check**: If you're missing Required Knowledge, read the following first:
- Python Async: https://docs.python.org/3/library/asyncio.html
- REST API: https://restfulapi.net/
- JWT: https://jwt.io/introduction

---

## Document Reading Strategy

### Total Documentation Size: ~7,400 lines

You **cannot** read all documentation at once due to context window limits. Use this prioritized reading strategy:

### Reading Priority Levels

| Priority | Documents | Lines | When to Read |
|----------|-----------|-------|--------------|
| **P0** (Critical) | QUICK_START_GUIDE.md | ~800 | Read first - basic setup |
| **P1** (High) | MCP_TOOLS_REFERENCE.md | ~400 | Read second - learn 21 MCP tools |
| **P1** (High) | SECURITY_GUIDE.md (P0-1 section only) | ~200 | Read third - critical security |
| **P2** (Medium) | INTEGRATION_PATTERNS.md | ~1,700 | Read fourth - learn workflows |
| **P2** (Medium) | LEARNING_PATTERN_API.md | ~1,400 | Read fifth - agent skills |
| **P3** (Low) | REST_API_GUIDE.md | ~1,500 | Read last - advanced usage |
| **P3** (Low) | Full SECURITY_GUIDE.md | ~1,600 | Read when implementing security |

### Memory-Efficient Reading Protocol

**DO NOT** try to load all documents at once. Instead:

```python
# Phase 0: Environment check (no reading required)
verify_python_version()
verify_dependencies()

# Phase 1: Read P0 only (~800 lines)
read("QUICK_START_GUIDE.md")
test_basic_setup()  # Self-verification

# Phase 2: Read P1 (~600 lines total)
read("MCP_TOOLS_REFERENCE.md")
read("SECURITY_GUIDE.md", sections=["P0-1 Namespace Isolation"])
test_mcp_tools()  # Self-verification

# Phase 3: Read P2 (~3,100 lines total)
read("INTEGRATION_PATTERNS.md")
read("LEARNING_PATTERN_API.md")
test_integration_patterns()  # Self-verification

# Phase 4: Read P3 as needed (~3,100 lines total)
read("REST_API_GUIDE.md")  # Only if you need REST API
read("SECURITY_GUIDE.md", sections=["Full Guide"])  # Only if implementing security
```

**Rule of Thumb**: Read ’ Test ’ Verify ’ Move to next document. Never read more than 2,000 lines without testing.

---

## Persona-Specific Learning Paths

Each Trinitas-agents persona has different priorities. Follow your persona's learning path:

### <Û Athena (Harmonious Conductor)

**Your Role**: System orchestration, workflow automation, resource optimization

**Priority Documents**:
1. QUICK_START_GUIDE.md (P0)
2. MCP_TOOLS_REFERENCE.md - System Tools section (P1)
3. INTEGRATION_PATTERNS.md - Pattern 6 (Multi-Agent Coordination) (P2)
4. REST_API_GUIDE.md - MCP Connection API (P3)

**Key Skills to Learn**:
- Task creation and coordination (`create_task`)
- Agent status monitoring (`get_agent_status`)
- Multi-agent workflow orchestration
- Resource balancing and load distribution

**Verification Test**:
```python
#!/usr/bin/env python3
"""Athena: Test workflow orchestration"""

async def test_orchestration():
    # 1. Create coordinated tasks
    task1 = await create_task(
        title="Artemis: Optimize database queries",
        assigned_agent_id="artemis-optimizer",
        priority="high"
    )

    task2 = await create_task(
        title="Hestia: Security audit",
        assigned_agent_id="hestia-auditor",
        priority="high",
        depends_on=[task1.id]  # Sequential dependency
    )

    # 2. Monitor agent status
    status = await get_agent_status()
    assert "artemis-optimizer" in [a["agent_id"] for a in status["agents"]]

    # 3. Share progress
    memory = await store_memory(
        content="Workflow orchestration test successful",
        tags=["athena", "orchestration"],
        access_level="TEAM",
        namespace="trinitas-agents"
    )

    print(" Athena orchestration test PASSED")

# Run test
import asyncio
asyncio.run(test_orchestration())
```

**Success Criteria**: All 3 operations (task creation, status monitoring, memory sharing) succeed.

---

### <ù Artemis (Technical Perfectionist)

**Your Role**: Performance optimization, code quality, technical implementation

**Priority Documents**:
1. QUICK_START_GUIDE.md (P0)
2. MCP_TOOLS_REFERENCE.md - Core Memory + Verification Tools (P1)
3. LEARNING_PATTERN_API.md - Performance category (P2)
4. INTEGRATION_PATTERNS.md - Pattern 4 (Performance Optimization) (P2)

**Key Skills to Learn**:
- Learning Pattern creation for optimizations (`create_pattern`)
- Trust verification for performance claims (`verify_and_record`)
- Memory storage with performance metrics (`store_memory`)
- Pattern search and reuse (`search_patterns`)

**Verification Test**:
```python
#!/usr/bin/env python3
"""Artemis: Test performance optimization with Learning Patterns"""

async def test_optimization():
    service = LearningService()

    # 1. Search for existing optimization patterns
    patterns = await service.search_patterns(
        query="database optimization",
        category="performance",
        namespace="trinitas-agents",
        limit=5
    )
    print(f"Found {len(patterns)} existing optimization patterns")

    # 2. Create new optimization pattern
    pattern = await service.create_pattern(
        pattern_name="test_index_optimization",
        category="performance",
        subcategory="database",
        pattern_data={
            "description": "Add index to speed up queries",
            "problem": "Slow SELECT query",
            "solution": "CREATE INDEX idx_name ON table(column)",
            "improvement": "85% faster",
            "when_to_apply": "Queries with WHERE on unindexed column"
        },
        agent_id="artemis-optimizer",
        namespace="trinitas-agents",
        access_level="PUBLIC"
    )
    assert pattern.id is not None

    # 3. Record pattern usage
    usage = await service.use_pattern(
        pattern_id=pattern.id,
        agent_id="artemis-optimizer",
        task_context={"task": "Test pattern usage"},
        success=True
    )
    assert usage.success is True

    # 4. Verify performance claim
    result = await verify_and_record(
        agent_id="artemis-optimizer",
        claim_type="performance_metric",
        claim_content={"improvement": 85, "metric": "query_latency"},
        verification_command="echo 'Test verification'"
    )
    assert result["accurate"] is True

    print(" Artemis optimization test PASSED")

# Run test
import asyncio
asyncio.run(test_optimization())
```

**Success Criteria**: Pattern creation, usage recording, and trust verification all succeed.

---

### =% Hestia (Security Guardian)

**Your Role**: Security analysis, vulnerability assessment, risk management

**Priority Documents**:
1. QUICK_START_GUIDE.md (P0)
2. SECURITY_GUIDE.md - Full guide (P1 - **CRITICAL**)
3. MCP_TOOLS_REFERENCE.md - Verification Tools (P1)
4. INTEGRATION_PATTERNS.md - Pattern 3 (Security Audit) (P2)

**Key Skills to Learn**:
- P0-1 Namespace Isolation (CVSS 8.7 - **MUST KNOW**)
- SQL Injection Prevention (CVSS 9.8 - **MUST KNOW**)
- Trust verification for security findings (`verify_and_record`)
- Security audit logging
- Access control enforcement

**Verification Test**:
```python
#!/usr/bin/env python3
"""Hestia: Test security patterns"""

async def test_security():
    # 1. Test P0-1 Namespace Isolation (CRITICAL)
    # CORRECT: Verify namespace from database
    agent = await get_agent_from_db("hestia-auditor")
    verified_namespace = agent.namespace  #  Verified from DB

    memory = await get_memory_from_db(memory_id)
    is_accessible = memory.is_accessible_by("hestia-auditor", verified_namespace)
    assert is_accessible is True

    # WRONG: Never trust JWT claims (this is vulnerable)
    # namespace = jwt_claims.get("namespace")  # L SECURITY RISK
    # is_accessible = memory.is_accessible_by("hestia-auditor", namespace)

    # 2. Test SQL Injection Prevention
    # CORRECT: Use bindparams()
    from sqlalchemy import text, bindparam

    stmt = text("SELECT * FROM memories WHERE agent_id = :agent_id").bindparams(
        bindparam("agent_id", type_=String)
    )
    result = await session.execute(stmt, {"agent_id": "hestia-auditor"})

    # WRONG: Never use f-strings in SQL (vulnerable)
    # stmt = text(f"SELECT * FROM memories WHERE agent_id = '{agent_id}'")  # L

    # 3. Record security finding
    finding = await store_memory(
        content="P0-1 namespace isolation verified",
        memory_type="security-finding",
        importance_score=1.0,
        tags=["security", "audit", "p0-1"],
        access_level="TEAM",
        namespace="trinitas-agents",
        agent_id="hestia-auditor"
    )
    assert finding.id is not None

    # 4. Verify security claim
    result = await verify_and_record(
        agent_id="hestia-auditor",
        claim_type="security_finding",
        claim_content={"vulnerability": "None", "status": "Secure"},
        verification_command="echo 'P0-1 verified'"
    )
    assert result["accurate"] is True

    print(" Hestia security test PASSED")

# Run test
import asyncio
asyncio.run(test_security())
```

**Success Criteria**: P0-1 pattern correctly implemented, SQL injection prevented, security finding recorded.

---

### ” Eris (Tactical Coordinator)

**Your Role**: Team coordination, conflict resolution, tactical planning

**Priority Documents**:
1. QUICK_START_GUIDE.md (P0)
2. MCP_TOOLS_REFERENCE.md - Task + System Tools (P1)
3. INTEGRATION_PATTERNS.md - Pattern 6 (Multi-Agent Coordination) (P2)
4. This guide - Team Collaboration Protocol section (P2)

**Key Skills to Learn**:
- Task dependency management (`create_task` with `depends_on`)
- Agent status monitoring (`get_agent_status`)
- Shared memory for coordination (`store_memory` with `TEAM` access)
- Conflict resolution through memory search

**Verification Test**:
```python
#!/usr/bin/env python3
"""Eris: Test team coordination"""

async def test_coordination():
    # 1. Create dependent tasks (tactical planning)
    task1 = await create_task(
        title="Phase 1: Security audit",
        assigned_agent_id="hestia-auditor",
        priority="high"
    )

    task2 = await create_task(
        title="Phase 2: Fix vulnerabilities",
        assigned_agent_id="artemis-optimizer",
        priority="high",
        depends_on=[task1.id]  # Must wait for Phase 1
    )

    task3 = await create_task(
        title="Phase 3: Document fixes",
        assigned_agent_id="muses-documenter",
        priority="medium",
        depends_on=[task2.id]  # Must wait for Phase 2
    )

    # 2. Check agent availability
    status = await get_agent_status()
    available_agents = [a for a in status["agents"] if a["status"] == "available"]
    assert len(available_agents) > 0

    # 3. Share coordination plan
    plan = await store_memory(
        content="3-phase security fix plan: Audit ’ Fix ’ Document",
        tags=["eris", "coordination", "security"],
        access_level="TEAM",
        namespace="trinitas-agents",
        metadata={
            "tasks": [task1.id, task2.id, task3.id],
            "sequence": "sequential"
        }
    )
    assert plan.id is not None

    # 4. Search for conflicts
    conflicts = await search_memories(
        query="conflicting priorities",
        tags=["coordination"],
        namespace="trinitas-agents",
        limit=5
    )

    print(f" Eris coordination test PASSED ({len(conflicts['results'])} conflicts found)")

# Run test
import asyncio
asyncio.run(test_coordination())
```

**Success Criteria**: Task dependencies created correctly, agent status checked, coordination plan shared.

---

### <­ Hera (Strategic Commander)

**Your Role**: Strategic planning, long-term vision, architecture design

**Priority Documents**:
1. QUICK_START_GUIDE.md (P0)
2. INTEGRATION_PATTERNS.md - All 8 patterns (P1 - **IMPORTANT**)
3. LEARNING_PATTERN_API.md - All categories (P2)
4. REST_API_GUIDE.md - MCP Connection API (P3)

**Key Skills to Learn**:
- Strategic memory storage (`store_memory` with high importance)
- Knowledge retrieval (`search_memories`)
- Learning pattern analysis across all categories
- Long-term workflow design

**Verification Test**:
```python
#!/usr/bin/env python3
"""Hera: Test strategic planning"""

async def test_strategy():
    # 1. Store strategic decision
    decision = await store_memory(
        content="Strategic Decision: Adopt TMWS for multi-agent coordination",
        memory_type="strategic-decision",
        importance_score=1.0,
        tags=["hera", "strategy", "architecture"],
        metadata={
            "rationale": "Centralized memory reduces coordination overhead by 60%",
            "alternatives_considered": ["File-based", "Database-only"],
            "decision_date": "2025-11-14"
        },
        access_level="PUBLIC",
        namespace="trinitas-agents"
    )
    assert decision.id is not None

    # 2. Search for historical decisions
    history = await search_memories(
        query="strategic decisions architecture",
        tags=["strategy"],
        namespace="trinitas-agents",
        limit=10
    )
    assert len(history["results"]) > 0

    # 3. Analyze learning patterns across categories
    service = LearningService()

    categories = ["performance", "security", "collaboration", "documentation"]
    pattern_counts = {}

    for category in categories:
        patterns = await service.search_patterns(
            category=category,
            namespace="trinitas-agents",
            limit=100
        )
        pattern_counts[category] = len(patterns)

    print(f"Pattern distribution: {pattern_counts}")

    # 4. Create strategic roadmap
    roadmap = await store_memory(
        content="Q1 2025 Roadmap: TMWS integration ’ Learning patterns ’ Production",
        tags=["hera", "roadmap", "strategy"],
        access_level="PUBLIC",
        namespace="trinitas-agents",
        metadata={
            "phases": ["Integration", "Training", "Production"],
            "timeline": "12 weeks"
        }
    )
    assert roadmap.id is not None

    print(" Hera strategy test PASSED")

# Run test
import asyncio
asyncio.run(test_strategy())
```

**Success Criteria**: Strategic decision stored, historical analysis performed, roadmap created.

---

### =Ú Muses (Knowledge Architect)

**Your Role**: Documentation, knowledge management, information architecture

**Priority Documents**:
1. QUICK_START_GUIDE.md (P0)
2. MCP_TOOLS_REFERENCE.md - All tools (P1)
3. INTEGRATION_PATTERNS.md - Pattern 5 (Documentation) + Pattern 7 (Knowledge Base) (P2)
4. This guide - Full guide (P2 - use as reference for documentation quality)

**Key Skills to Learn**:
- Structured memory storage (`store_memory` with rich metadata)
- Knowledge categorization (tags, namespaces)
- Semantic search for documentation (`search_memories`)
- Learning pattern documentation (`create_pattern`)

**Verification Test**:
```python
#!/usr/bin/env python3
"""Muses: Test documentation and knowledge management"""

async def test_documentation():
    # 1. Store structured documentation
    doc = await store_memory(
        content="TMWS Quick Reference: 21 MCP tools for memory, tasks, and verification",
        memory_type="documentation",
        importance_score=0.9,
        tags=["muses", "documentation", "quick-reference"],
        metadata={
            "document_type": "quick_reference",
            "sections": ["MCP Tools", "REST API", "Security"],
            "last_updated": "2025-11-14",
            "version": "2.3.0"
        },
        access_level="PUBLIC",
        namespace="trinitas-agents"
    )
    assert doc.id is not None

    # 2. Create knowledge hierarchy with tags
    categories = {
        "setup": ["installation", "configuration", "quickstart"],
        "api": ["mcp-tools", "rest-api", "authentication"],
        "security": ["p0-1", "jwt", "sql-injection"],
        "integration": ["patterns", "workflows", "collaboration"]
    }

    for category, tags in categories.items():
        await store_memory(
            content=f"Knowledge Category: {category}",
            tags=["muses", "knowledge-base", category] + tags,
            access_level="PUBLIC",
            namespace="trinitas-agents"
        )

    # 3. Test semantic search across documentation
    results = await search_memories(
        query="how to prevent SQL injection",
        tags=["security"],
        namespace="trinitas-agents",
        limit=5
    )
    assert len(results["results"]) > 0

    # 4. Document a learning pattern
    service = LearningService()
    pattern = await service.create_pattern(
        pattern_name="documentation_template",
        category="documentation",
        subcategory="templates",
        pattern_data={
            "description": "Standard template for API documentation",
            "template": {
                "title": "API Name",
                "description": "What it does",
                "parameters": [],
                "returns": {},
                "examples": []
            },
            "when_to_use": "When documenting new APIs"
        },
        agent_id="muses-documenter",
        namespace="trinitas-agents",
        access_level="PUBLIC"
    )
    assert pattern.id is not None

    print(" Muses documentation test PASSED")

# Run test
import asyncio
asyncio.run(test_documentation())
```

**Success Criteria**: Structured documentation stored, knowledge hierarchy created, semantic search works, pattern documented.

---

## Phase 0: Initial Assessment

**Estimated Time**: 15-30 minutes
**Goal**: Verify your environment is ready for TMWS integration

### Checklist

```bash
# 1. Check Python version
python --version  # Should be 3.11+

# 2. Verify Ollama is running (required for embeddings)
curl http://localhost:11434/api/tags

# 3. Check if Ollama model is installed
ollama list | grep multilingual-e5-large

# If not installed:
ollama pull zylonai/multilingual-e5-large

# 4. Verify TMWS is cloned
cd /path/to/tmws
ls -la  # Should see src/, tests/, docs/, etc.

# 5. Check dependencies are installed
pip list | grep -E "fastapi|sqlalchemy|chromadb|alembic"

# If not installed:
pip install -e .

# 6. Verify database is initialized
alembic current  # Should show current migration version

# If not initialized:
alembic upgrade head

# 7. Test MCP server startup
python -m src.mcp_server  # Should start without errors (Ctrl+C to stop)
```

**Success Criteria**: All 7 checks pass.

**If any check fails**: Read QUICK_START_GUIDE.md for detailed setup instructions.

---

## Phase 1: Core Knowledge Acquisition

**Estimated Time**: 2-4 hours
**Goal**: Learn essential TMWS concepts and basic operations

### Step 1-1: Read QUICK_START_GUIDE.md (~800 lines, 30-45 minutes)

**Focus on**:
- Installation steps (verify you completed them in Phase 0)
- 21 MCP tools overview
- Basic commands: `store_memory`, `search_memories`, `create_task`

**Self-Test**:
```python
#!/usr/bin/env python3
"""Test basic TMWS operations"""

async def test_basic_operations():
    # Test 1: Store memory
    memory = await store_memory(
        content="Phase 1 learning test",
        tags=["test", "phase1"],
        namespace="trinitas-agents"
    )
    assert memory["memory_id"] is not None

    # Test 2: Search memory
    results = await search_memories(
        query="Phase 1 learning",
        namespace="trinitas-agents"
    )
    assert len(results["results"]) > 0

    # Test 3: Create task
    task = await create_task(
        title="Test task creation",
        priority="low"
    )
    assert task["task_id"] is not None

    print(" Basic operations test PASSED")

# Run test
import asyncio
asyncio.run(test_basic_operations())
```

---

### Step 1-2: Read MCP_TOOLS_REFERENCE.md (~400 lines, 20-30 minutes)

**Focus on**:
- Core Memory Tools: `store_memory`, `search_memories`, `create_task`
- System Tools: `get_agent_status`, `get_memory_stats`
- Verification Tools: `verify_and_record`, `get_agent_trust_score`

**Self-Test**: Use your persona-specific test from the "Persona-Specific Learning Paths" section above.

---

### Step 1-3: Read SECURITY_GUIDE.md - P0-1 Section Only (~200 lines, 15-20 minutes)

**Focus on**:
- P0-1 Namespace Isolation pattern
- Never trust namespace from JWT claims
- Always verify namespace from database

**Self-Test**:
```python
#!/usr/bin/env python3
"""Test P0-1 compliance"""

async def test_p01_compliance():
    # CORRECT implementation
    agent = await get_agent_from_db("your-agent-id")
    verified_namespace = agent.namespace  #  From database

    memory = await get_memory_from_db(memory_id)
    is_accessible = memory.is_accessible_by("your-agent-id", verified_namespace)

    # Verify it works
    assert is_accessible is True

    # WRONG implementation (this should be avoided)
    # jwt_claims = decode_jwt(token)
    # namespace = jwt_claims.get("namespace")  # L Never do this
    # is_accessible = memory.is_accessible_by("your-agent-id", namespace)

    print(" P0-1 compliance test PASSED")

# Run test
import asyncio
asyncio.run(test_p01_compliance())
```

**Critical Understanding Check**: Can you explain why namespace must come from database, not JWT? If not, re-read the P0-1 section.

---

### Step 1-4: Practice with Simple Workflow (45-60 minutes)

Implement a simple daily standup workflow:

```python
#!/usr/bin/env python3
"""Daily Standup Workflow (Phase 1 Practice)"""

async def daily_standup():
    # 1. Store today's progress
    today_progress = await store_memory(
        content=f"Daily Progress - {datetime.now().strftime('%Y-%m-%d')}: "
                "Completed TMWS Phase 1 learning",
        tags=["daily-standup", "progress"],
        importance_score=0.75,
        namespace="trinitas-agents",
        agent_id="your-agent-id",
        access_level="TEAM"
    )

    # 2. Search for yesterday's progress
    yesterday = await search_memories(
        query="daily progress",
        tags=["daily-standup"],
        namespace="trinitas-agents",
        limit=5
    )

    # 3. Create task for tomorrow
    task = await create_task(
        title="Continue TMWS Phase 2 learning",
        priority="medium",
        estimated_duration=180  # 3 hours
    )

    # 4. Get team status
    status = await get_agent_status()

    print(f" Daily standup complete")
    print(f"   - Today's progress recorded: {today_progress['memory_id']}")
    print(f"   - Found {len(yesterday['results'])} previous updates")
    print(f"   - Tomorrow's task: {task['task_id']}")
    print(f"   - Team members active: {len(status['agents'])}")

# Run daily standup
import asyncio
asyncio.run(daily_standup())
```

**Success Criteria**: All 4 operations succeed, you understand the workflow pattern.

---

## Phase 2: Advanced Integration

**Estimated Time**: 4-8 hours
**Goal**: Master complex workflows and team collaboration

### Step 2-1: Read INTEGRATION_PATTERNS.md (~1,700 lines, 1-2 hours)

**Don't read all at once!** Read patterns relevant to your persona:

**All Personas Should Read**:
- Pattern 6: Multi-Agent Coordination Workflow (everyone needs this)

**Athena/Eris Should Read**:
- Pattern 1: Daily Standup Workflow
- Pattern 6: Multi-Agent Coordination Workflow

**Artemis Should Read**:
- Pattern 2: Code Review Workflow
- Pattern 4: Performance Optimization Workflow

**Hestia Should Read**:
- Pattern 3: Security Audit Workflow
- Pattern 8: Production Deployment Workflow

**Hera Should Read**:
- All 8 patterns (strategic overview)

**Muses Should Read**:
- Pattern 5: Documentation Generation Workflow
- Pattern 7: Knowledge Base Building Workflow

---

### Step 2-2: Read LEARNING_PATTERN_API.md (~1,400 lines, 1-1.5 hours)

**Focus on**:
- Pattern categories: performance, security, collaboration, documentation
- Pattern creation, search, usage, and evolution
- Trust verification for patterns

**Self-Test**: Use the Artemis verification test from "Persona-Specific Learning Paths" section.

---

### Step 2-3: Implement Your Persona's Primary Workflow (2-3 hours)

Choose the most relevant workflow pattern for your persona and implement it:

**Example for Artemis** (Performance Optimization Workflow):

```python
#!/usr/bin/env python3
"""Performance Optimization Workflow - Artemis Implementation"""

async def performance_optimization_workflow():
    service = LearningService()

    # Phase 1: Search for existing optimization patterns
    existing_patterns = await service.search_patterns(
        query="database performance",
        category="performance",
        namespace="trinitas-agents",
        limit=10
    )

    print(f"Found {len(existing_patterns)} existing patterns")

    # Phase 2: Profile current performance
    import time
    start = time.perf_counter()

    # Simulate slow query
    result = await slow_database_query()

    baseline_time = time.perf_counter() - start
    print(f"Baseline query time: {baseline_time:.3f}s")

    # Phase 3: Apply optimization
    # (e.g., add index, optimize query, etc.)
    optimized_result = await optimized_database_query()

    optimized_time = time.perf_counter() - start
    improvement = ((baseline_time - optimized_time) / baseline_time) * 100

    print(f"Optimized query time: {optimized_time:.3f}s")
    print(f"Improvement: {improvement:.1f}%")

    # Phase 4: Create learning pattern
    pattern = await service.create_pattern(
        pattern_name="database_query_optimization_2025_11_14",
        category="performance",
        subcategory="database",
        pattern_data={
            "description": "Optimized slow SELECT query",
            "problem": f"Query took {baseline_time:.3f}s",
            "solution": "Added composite index on (user_id, created_at)",
            "improvement": f"{improvement:.1f}% faster",
            "baseline_metrics": {"query_time": baseline_time},
            "optimized_metrics": {"query_time": optimized_time},
            "when_to_apply": "Queries with WHERE on multiple columns"
        },
        agent_id="artemis-optimizer",
        namespace="trinitas-agents",
        access_level="PUBLIC"
    )

    # Phase 5: Verify performance claim
    verification = await verify_and_record(
        agent_id="artemis-optimizer",
        claim_type="performance_metric",
        claim_content={
            "improvement_percentage": improvement,
            "baseline_time": baseline_time,
            "optimized_time": optimized_time
        },
        verification_command=f"python benchmark.py --verify {pattern.id}"
    )

    # Phase 6: Share results with team
    memory = await store_memory(
        content=f"Database optimization: {improvement:.1f}% improvement",
        tags=["artemis", "optimization", "database"],
        importance_score=0.9,
        metadata={
            "pattern_id": str(pattern.id),
            "improvement": improvement,
            "verified": verification["accurate"]
        },
        access_level="TEAM",
        namespace="trinitas-agents"
    )

    print(f" Performance optimization workflow complete")
    print(f"   - Pattern ID: {pattern.id}")
    print(f"   - Verification: {'PASSED' if verification['accurate'] else 'FAILED'}")
    print(f"   - Memory ID: {memory['memory_id']}")

# Run workflow
import asyncio
asyncio.run(performance_optimization_workflow())
```

**Success Criteria**: Workflow completes successfully, pattern created, verification passes, team notified.

---

### Step 2-4: Test Multi-Agent Collaboration (1-2 hours)

Simulate collaboration between 2+ agents:

```python
#!/usr/bin/env python3
"""Multi-Agent Collaboration Test"""

async def test_collaboration():
    # Agent 1 (Artemis): Create optimization task
    task = await create_task(
        title="Optimize API response time",
        description="Target: < 200ms P95",
        priority="high",
        assigned_agent_id="artemis-optimizer"
    )

    # Agent 1: Store initial findings
    findings = await store_memory(
        content="API bottleneck: N+1 database queries",
        tags=["artemis", "optimization", "api"],
        access_level="TEAM",
        namespace="trinitas-agents",
        agent_id="artemis-optimizer",
        metadata={"task_id": str(task["task_id"])}
    )

    # Agent 2 (Hestia): Search for security implications
    security_check = await search_memories(
        query="API optimization security implications",
        tags=["security"],
        namespace="trinitas-agents"
    )

    # Agent 2: Review optimization plan
    review = await store_memory(
        content="Security review: API optimization is safe, no vulnerabilities",
        tags=["hestia", "security-review", "api"],
        access_level="TEAM",
        namespace="trinitas-agents",
        agent_id="hestia-auditor",
        metadata={
            "reviewed_task": str(task["task_id"]),
            "approved": True
        }
    )

    # Agent 3 (Athena): Coordinate completion
    completion = await store_memory(
        content="API optimization complete: Artemis implemented, Hestia approved",
        tags=["athena", "coordination", "completion"],
        access_level="TEAM",
        namespace="trinitas-agents",
        agent_id="athena-conductor",
        metadata={
            "task_id": str(task["task_id"]),
            "participants": ["artemis-optimizer", "hestia-auditor"],
            "status": "completed"
        }
    )

    print(" Multi-agent collaboration test PASSED")
    print(f"   - Task created: {task['task_id']}")
    print(f"   - Artemis findings: {findings['memory_id']}")
    print(f"   - Hestia review: {review['memory_id']}")
    print(f"   - Athena completion: {completion['memory_id']}")

# Run collaboration test
import asyncio
asyncio.run(test_collaboration())
```

**Success Criteria**: All 3 agents successfully collaborate, memories are shared via TEAM access level.

---

## Phase 3: Production Deployment

**Estimated Time**: 2-4 hours
**Goal**: Deploy TMWS integration to production

### Step 3-1: Read REST_API_GUIDE.md - MCP Connection API Only (~300 lines, 30 minutes)

**Focus on**:
- POST /api/mcp/connections (add MCP server)
- GET /api/mcp/connections (list servers)
- POST /api/mcp/connections/{id}/test (test connection)
- DELETE /api/mcp/connections/{id} (remove server)

**When to Use**: If you need to manage multiple MCP servers dynamically.

**Note**: Most AI agents will use MCP tools directly, not REST API. Read this only if you need programmatic server management.

---

### Step 3-2: Read Full SECURITY_GUIDE.md (~1,600 lines, 1-1.5 hours)

**Focus on**:
- JWT Authentication (full implementation)
- API Key Authentication
- Rate Limiting
- SQL Injection Prevention
- XSS Prevention
- CSRF Protection
- Security Audit Logging

**Self-Test**: Implement all security checks from the Hestia verification test.

---

### Step 3-3: Production Deployment Checklist (1-2 hours)

```bash
# 1. Environment variables
export TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws_production.db"
export TMWS_SECRET_KEY="$(openssl rand -hex 32)"
export TMWS_ENVIRONMENT="production"
export TMWS_LOG_LEVEL="WARNING"

# 2. Database migrations
alembic upgrade head

# 3. Verify Ollama is running
curl http://localhost:11434/api/tags

# 4. Test MCP server
python -m src.mcp_server  # Should start without errors

# 5. Run production smoke tests
pytest tests/integration/test_production_smoke.py -v

# 6. Monitor logs
tail -f logs/tmws_production.log

# 7. Set up monitoring alerts (optional)
# - Memory usage > 1GB
# - CPU usage > 80%
# - Error rate > 1%
# - Response time P95 > 500ms
```

**Success Criteria**: All checks pass, MCP server starts successfully, smoke tests pass.

---

## Team Collaboration Protocol

### Parallel Execution Pattern

When multiple agents can work independently:

```python
# Example: Parallel security audit
tasks = [
    create_task(title="Hestia: SQL injection check", assigned_agent_id="hestia-auditor"),
    create_task(title="Artemis: Performance test", assigned_agent_id="artemis-optimizer"),
    create_task(title="Muses: Update docs", assigned_agent_id="muses-documenter")
]

# All agents work in parallel
# Results are stored in TEAM namespace for visibility
```

**When to Use**: Tasks are independent, no dependencies between agents.

---

### Sequential Execution Pattern

When tasks must be completed in order:

```python
# Example: Sequential deployment pipeline
task1 = create_task(
    title="Artemis: Implement feature",
    assigned_agent_id="artemis-optimizer"
)

task2 = create_task(
    title="Hestia: Security review",
    assigned_agent_id="hestia-auditor",
    depends_on=[task1.id]  # Wait for task1
)

task3 = create_task(
    title="Muses: Update documentation",
    assigned_agent_id="muses-documenter",
    depends_on=[task2.id]  # Wait for task2
)
```

**When to Use**: Tasks have dependencies, later tasks need earlier results.

---

### Knowledge Sharing Pattern

Using access levels for team collaboration:

```python
# PRIVATE: Only you can access
personal_note = await store_memory(
    content="Personal debugging notes",
    access_level="PRIVATE",
    namespace="trinitas-agents",
    agent_id="artemis-optimizer"
)

# TEAM: All agents in same namespace
team_finding = await store_memory(
    content="Found performance bottleneck",
    access_level="TEAM",
    namespace="trinitas-agents",
    agent_id="artemis-optimizer"
)

# PUBLIC: All agents in TMWS
public_pattern = await store_memory(
    content="Reusable optimization pattern",
    access_level="PUBLIC",
    namespace="trinitas-agents",
    agent_id="artemis-optimizer"
)

# SHARED: Specific agents only
shared_secret = await store_memory(
    content="Sensitive configuration",
    access_level="SHARED",
    shared_with=["artemis-optimizer", "hestia-auditor"],
    namespace="trinitas-agents",
    agent_id="artemis-optimizer"
)
```

**Best Practice**: Use most restrictive access level necessary. Start with PRIVATE, share to TEAM if needed.

---

## Common Tasks & Solutions

### Task 1: Store Daily Progress

```python
async def store_daily_progress(completed_tasks, in_progress, blockers):
    memory = await store_memory(
        content=f"Daily Progress - {datetime.now().strftime('%Y-%m-%d')}",
        tags=["daily-standup", "progress"],
        importance_score=0.75,
        namespace="trinitas-agents",
        agent_id="your-agent-id",
        access_level="TEAM",
        metadata={
            "completed": completed_tasks,
            "in_progress": in_progress,
            "blockers": blockers
        }
    )
    return memory
```

---

### Task 2: Search for Related Work

```python
async def find_related_work(topic, agent_id=None, days_back=7):
    results = await search_memories(
        query=topic,
        namespace="trinitas-agents",
        limit=10,
        min_similarity=0.7
    )

    # Filter by agent if specified
    if agent_id:
        results["results"] = [
            r for r in results["results"]
            if r.get("agent_id") == agent_id
        ]

    # Filter by recency
    cutoff = datetime.now() - timedelta(days=days_back)
    results["results"] = [
        r for r in results["results"]
        if datetime.fromisoformat(r["created_at"]) > cutoff
    ]

    return results
```

---

### Task 3: Create Dependent Tasks

```python
async def create_task_pipeline(tasks_config):
    """Create chain of dependent tasks"""
    tasks = []
    previous_task_id = None

    for config in tasks_config:
        task = await create_task(
            title=config["title"],
            assigned_agent_id=config["agent_id"],
            priority=config.get("priority", "medium"),
            depends_on=[previous_task_id] if previous_task_id else None
        )
        tasks.append(task)
        previous_task_id = task["task_id"]

    return tasks
```

---

### Task 4: Verify Implementation Claims

```python
async def verify_implementation(agent_id, claim, verification_cmd):
    """Verify agent's implementation claim"""
    result = await verify_and_record(
        agent_id=agent_id,
        claim_type="implementation",
        claim_content=claim,
        verification_command=verification_cmd
    )

    # Store verification result
    await store_memory(
        content=f"Verification {'PASSED' if result['accurate'] else 'FAILED'}: {claim}",
        tags=["verification", agent_id],
        access_level="TEAM",
        namespace="trinitas-agents",
        metadata={
            "claim": claim,
            "accurate": result["accurate"],
            "evidence_id": result["evidence_id"]
        }
    )

    return result
```

---

### Task 5: Build Knowledge Base

```python
async def build_knowledge_base(category, documents):
    """Index documents into knowledge base"""
    memories = []

    for doc in documents:
        memory = await store_memory(
            content=doc["content"],
            tags=["knowledge-base", category] + doc.get("tags", []),
            importance_score=doc.get("importance", 0.5),
            access_level="PUBLIC",
            namespace="trinitas-agents",
            metadata=doc.get("metadata", {})
        )
        memories.append(memory)

    # Create index
    index = await store_memory(
        content=f"Knowledge Base Index: {category}",
        tags=["knowledge-base", "index", category],
        importance_score=1.0,
        access_level="PUBLIC",
        namespace="trinitas-agents",
        metadata={
            "category": category,
            "document_count": len(memories),
            "memory_ids": [m["memory_id"] for m in memories]
        }
    )

    return index
```

---

## Self-Assessment Checklist

Use this checklist to verify your TMWS knowledge:

### Core Concepts 

- [ ] I can explain what TMWS is (multi-agent memory & workflow system)
- [ ] I understand the dual storage architecture (SQLite + ChromaDB)
- [ ] I know the difference between MCP tools and REST API
- [ ] I can explain the 5 access levels (PRIVATE, TEAM, SHARED, PUBLIC, SYSTEM)
- [ ] I understand namespace isolation

### Security 

- [ ] I can implement P0-1 namespace isolation correctly
- [ ] I never trust namespace from JWT claims
- [ ] I always verify namespace from database
- [ ] I use bindparams() for SQL queries
- [ ] I know when to use each access level

### MCP Tools 

- [ ] I can use `store_memory` with correct parameters
- [ ] I can use `search_memories` for semantic search
- [ ] I can create tasks with `create_task`
- [ ] I can verify claims with `verify_and_record`
- [ ] I can check agent status with `get_agent_status`

### Learning Patterns 

- [ ] I can create learning patterns for my domain
- [ ] I can search for existing patterns
- [ ] I can record pattern usage
- [ ] I understand pattern versioning (parent-child)

### Collaboration 

- [ ] I can create dependent tasks for sequential workflows
- [ ] I can share memories with TEAM access level
- [ ] I can search for team members' work
- [ ] I understand parallel vs sequential execution

### Advanced 

- [ ] I can implement complete workflow patterns
- [ ] I can manage MCP connections via REST API (if needed)
- [ ] I have tested my integration in production environment
- [ ] I can monitor and debug TMWS issues

**Scoring**:
- 20-24 checked:  Expert level, ready for production
- 15-19 checked:   Good understanding, practice more complex workflows
- 10-14 checked: ó Basic knowledge, continue Phase 2 learning
- < 10 checked: =4 Insufficient knowledge, re-read Phase 1 documents

---

## Best Practices for AI Agents

### 1. Memory-Efficient Document Reading

**DO**:
- Read documents in priority order (P0 ’ P1 ’ P2 ’ P3)
- Test after reading each document (max 2,000 lines before testing)
- Focus on your persona's learning path
- Skip sections not relevant to your role

**DON'T**:
- Try to read all 7,400 lines at once
- Read documents without testing
- Read every section of every document
- Ignore self-verification tests

---

### 2. Incremental Learning

**DO**:
- Complete Phase 0 before Phase 1
- Complete Phase 1 before Phase 2
- Verify understanding with tests after each phase
- Ask for clarification if concepts are unclear

**DON'T**:
- Skip phases
- Proceed without verifying understanding
- Assume you understand without testing
- Continue if self-tests fail

---

### 3. Namespace Verification

**DO**:
- Always fetch agent from database to get verified namespace
- Use verified namespace in all access control checks
- Document why namespace verification is critical

**DON'T**:
- Trust namespace from JWT claims
- Trust namespace from user input
- Trust namespace from memory
- Skip namespace verification "for convenience"

---

### 4. Access Level Selection

**DO**:
- Start with PRIVATE, share only if needed
- Use TEAM for routine collaboration
- Use PUBLIC for reusable knowledge
- Use SHARED sparingly for sensitive information

**DON'T**:
- Default to PUBLIC for everything
- Use SHARED when TEAM would work
- Use PRIVATE for team collaboration
- Change access level frequently

---

### 5. Learning Pattern Creation

**DO**:
- Create patterns after successful implementations
- Include problem, solution, and when_to_apply
- Record actual metrics (not estimates)
- Verify patterns work before sharing

**DON'T**:
- Create patterns for untested solutions
- Include vague or generic descriptions
- Skip verification step
- Create duplicate patterns (search first)

---

### 6. Trust Verification

**DO**:
- Verify all performance claims with `verify_and_record`
- Use actual commands that can be re-run
- Record verification evidence
- Build trust score over time

**DON'T**:
- Skip verification for "obvious" claims
- Use fake verification commands
- Inflate performance numbers
- Ignore failed verifications

---

## Anti-Patterns to Avoid

### L Anti-Pattern 1: Context Window Overflow

**Problem**: Trying to read all documentation at once, causing context overflow.

**Symptom**: "I need to re-read the documentation" or "I forgot what I read earlier".

**Solution**: Follow the prioritized reading strategy (P0 ’ P1 ’ P2 ’ P3), test after each document.

---

### L Anti-Pattern 2: Namespace Injection Attack

**Problem**: Trusting namespace from JWT claims instead of database.

**Vulnerable Code**:
```python
# L WRONG - Namespace from JWT (can be forged)
jwt_claims = decode_jwt(token)
namespace = jwt_claims.get("namespace")
is_accessible = memory.is_accessible_by(agent_id, namespace)
```

**Secure Code**:
```python
#  CORRECT - Namespace from database (verified)
agent = await get_agent_from_db(agent_id)
verified_namespace = agent.namespace
is_accessible = memory.is_accessible_by(agent_id, verified_namespace)
```

**Impact**: CVSS 8.7 (HIGH) - Cross-tenant data access.

---

### L Anti-Pattern 3: SQL Injection via String Formatting

**Problem**: Using f-strings or string concatenation in SQL queries.

**Vulnerable Code**:
```python
# L WRONG - SQL injection vulnerability
stmt = text(f"SELECT * FROM memories WHERE agent_id = '{agent_id}'")
result = await session.execute(stmt)
```

**Secure Code**:
```python
#  CORRECT - Parameterized query
from sqlalchemy import bindparam

stmt = text("SELECT * FROM memories WHERE agent_id = :agent_id").bindparams(
    bindparam("agent_id", type_=String)
)
result = await session.execute(stmt, {"agent_id": agent_id})
```

**Impact**: CVSS 9.8 (CRITICAL) - Complete database compromise.

---

### L Anti-Pattern 4: Unverified Performance Claims

**Problem**: Claiming performance improvements without verification.

**Bad Practice**:
```python
# L WRONG - No verification
pattern = await create_pattern(
    pattern_data={"improvement": "85% faster"},  # Unverified claim
    ...
)
```

**Good Practice**:
```python
#  CORRECT - Verified claim
baseline_time = measure_performance(old_implementation)
optimized_time = measure_performance(new_implementation)
improvement = ((baseline_time - optimized_time) / baseline_time) * 100

pattern = await create_pattern(
    pattern_data={
        "improvement": f"{improvement:.1f}% faster",
        "baseline": baseline_time,
        "optimized": optimized_time
    },
    ...
)

# Verify claim
verification = await verify_and_record(
    claim_content={"improvement": improvement},
    verification_command="python benchmark.py --verify"
)
```

**Impact**: Low trust score, unreliable patterns.

---

### L Anti-Pattern 5: Oversharing with PUBLIC Access

**Problem**: Using PUBLIC access level when TEAM or PRIVATE would work.

**Bad Practice**:
```python
# L WRONG - Unnecessarily public
debug_notes = await store_memory(
    content="My debugging notes for this bug",
    access_level="PUBLIC",  # Why PUBLIC?
    ...
)
```

**Good Practice**:
```python
#  CORRECT - Appropriate access level
debug_notes = await store_memory(
    content="My debugging notes for this bug",
    access_level="PRIVATE",  # Personal notes
    ...
)

# Or if sharing with team:
team_finding = await store_memory(
    content="Bug found in authentication module",
    access_level="TEAM",  # Team collaboration
    ...
)
```

**Impact**: Information leakage, cluttered search results for other agents.

---

## Error Recovery Procedures

### Error 1: "Namespace Isolation Violation"

**Symptom**: `MCPAuthorizationError: Agent cannot access memory from different namespace`

**Cause**: Attempting to access memory without proper namespace verification.

**Recovery**:
```python
# 1. Verify agent exists and has correct namespace
agent = await get_agent_from_db(agent_id)
if not agent:
    raise MCPAuthenticationError("Agent not found")

verified_namespace = agent.namespace

# 2. Check if memory is accessible
memory = await get_memory_from_db(memory_id)
is_accessible = memory.is_accessible_by(agent_id, verified_namespace)

if not is_accessible:
    raise MCPAuthorizationError(
        f"Agent {agent_id} in namespace {verified_namespace} "
        f"cannot access memory from namespace {memory.namespace}"
    )

# 3. Proceed only if accessible
result = await process_memory(memory)
```

---

### Error 2: "Ollama Embedding Service Unavailable"

**Symptom**: `EmbeddingServiceError: Failed to generate embeddings`

**Cause**: Ollama service is not running or model not installed.

**Recovery**:
```bash
# 1. Check if Ollama is running
curl http://localhost:11434/api/tags

# If not running:
ollama serve

# 2. Check if model is installed
ollama list | grep multilingual-e5-large

# If not installed:
ollama pull zylonai/multilingual-e5-large

# 3. Test embeddings
curl http://localhost:11434/api/embeddings \
  -d '{"model": "zylonai/multilingual-e5-large", "prompt": "test"}'

# 4. Retry operation
python your_script.py
```

---

### Error 3: "Rate Limit Exceeded"

**Symptom**: `MCPAuthorizationError: Rate limit exceeded`

**Cause**: Too many requests in short time period.

**Recovery**:
```python
import asyncio
from tenacity import retry, wait_exponential, stop_after_attempt

@retry(
    wait=wait_exponential(multiplier=1, min=2, max=10),
    stop=stop_after_attempt(5)
)
async def rate_limited_operation():
    try:
        result = await tmws_operation()
        return result
    except MCPAuthorizationError as e:
        if "Rate limit exceeded" in str(e):
            # Wait and retry (handled by tenacity)
            raise
        else:
            # Different error, don't retry
            raise

# Use with exponential backoff
result = await rate_limited_operation()
```

---

### Error 4: "Database Migration Out of Sync"

**Symptom**: `alembic.util.exc.CommandError: Can't locate revision identified by 'xxxxx'`

**Cause**: Database schema doesn't match current migrations.

**Recovery**:
```bash
# 1. Check current database version
alembic current

# 2. Check target version
alembic heads

# 3. If versions differ:
alembic upgrade head

# 4. If still fails, check migration history
alembic history

# 5. If corrupted, may need to rebuild (use with caution)
# Backup first!
cp data/tmws.db data/tmws_backup_$(date +%Y%m%d_%H%M%S).db

# Option A: Downgrade and re-upgrade
alembic downgrade base
alembic upgrade head

# Option B: Stamp current version (if you know it's correct)
alembic stamp head
```

---

### Error 5: "Trust Verification Failed"

**Symptom**: `verify_and_record` returns `{"accurate": False}`

**Cause**: Claimed results don't match actual verification.

**Recovery**:
```python
# 1. Review verification command
print(f"Verification command: {verification_command}")

# 2. Run verification manually
import subprocess
result = subprocess.run(verification_command, shell=True, capture_output=True)
print(f"Actual output: {result.stdout}")

# 3. Compare with claim
print(f"Claimed: {claim_content}")
print(f"Actual: {result.stdout}")

# 4. Options:
# A) Fix implementation to match claim
# B) Update claim to match reality
# C) Update verification command

# 5. Re-verify
new_verification = await verify_and_record(
    agent_id=agent_id,
    claim_type=claim_type,
    claim_content=corrected_claim,
    verification_command=updated_command
)

assert new_verification["accurate"] is True
```

---

## Final Checklist

Before considering yourself "TMWS-ready", ensure:

### Documentation 
- [ ] Read QUICK_START_GUIDE.md (P0)
- [ ] Read MCP_TOOLS_REFERENCE.md (P1)
- [ ] Read SECURITY_GUIDE.md - P0-1 section (P1)
- [ ] Read at least 2 relevant patterns from INTEGRATION_PATTERNS.md (P2)
- [ ] Read LEARNING_PATTERN_API.md sections relevant to your persona (P2)

### Testing 
- [ ] Ran Phase 0 environment verification (all checks pass)
- [ ] Ran Phase 1 basic operations test (store, search, create task)
- [ ] Ran your persona-specific verification test
- [ ] Ran multi-agent collaboration test
- [ ] Ran production smoke tests

### Security 
- [ ] Implemented P0-1 namespace isolation correctly
- [ ] Never trusting namespace from JWT
- [ ] Using bindparams() for SQL queries
- [ ] Using appropriate access levels (PRIVATE/TEAM/SHARED/PUBLIC)

### Integration 
- [ ] Implemented at least one complete workflow pattern
- [ ] Created at least one learning pattern
- [ ] Verified a claim with `verify_and_record`
- [ ] Collaborated with at least one other agent via TEAM memory

### Production 
- [ ] Deployed MCP server to production environment
- [ ] Configured environment variables correctly
- [ ] Set up monitoring and alerts
- [ ] Tested production deployment

---

## Support & Resources

### Documentation Layers

**Layer 1 (Quick Start)**:
- QUICK_START_GUIDE.md - Get started in 5 minutes

**Layer 2 (Complete Reference)**:
1. MCP_TOOLS_REFERENCE.md - All 21 MCP tools
2. LEARNING_PATTERN_API.md - Agent skills API
3. REST_API_GUIDE.md - REST API (optional)
4. INTEGRATION_PATTERNS.md - 8 workflow patterns
5. SECURITY_GUIDE.md - Security best practices
6. AI_AGENT_INTEGRATION_GUIDE.md - This guide (AI agent-specific)

### Source Code

- Core: `src/core/` (database, config, exceptions)
- Models: `src/models/` (memory, agent, task, learning pattern)
- Services: `src/services/` (business logic)
- API: `src/api/routers/` (REST endpoints)
- Security: `src/security/` (auth, authorization, rate limiting)
- MCP Server: `src/mcp_server.py` (MCP tool implementation)
- Tools: `src/tools/` (MCP tool definitions)

### External References

- FastAPI: https://fastapi.tiangolo.com/
- SQLAlchemy 2.0: https://docs.sqlalchemy.org/en/20/
- ChromaDB: https://docs.trychroma.com/
- MCP Protocol: https://modelcontextprotocol.io/

---

## Congratulations! <‰

If you've completed this guide, you now have comprehensive knowledge of TMWS and are ready to integrate it into your multi-agent system.

**Your Next Steps**:
1. Implement your first production workflow
2. Share your learnings with the team via TEAM memories
3. Create reusable learning patterns for your domain
4. Contribute to the knowledge base

**Remember**:
- Read documents in priority order (don't overflow your context)
- Test after each phase (don't proceed without verification)
- Follow security best practices (especially P0-1)
- Collaborate with your team (use appropriate access levels)
- Build trust through verification (verify all claims)

Welcome to the Trinitas-agents TMWS integration! =€

---

**Document Author**: Athena (Harmonious Conductor)
**Reviewed By**: All 6 Trinitas Personas
**Last Updated**: 2025-11-14
**Status**: Production-ready
**Version**: 1.0.0

---

**End of AI Agent Integration Guide**
