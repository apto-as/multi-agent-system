# TMWS v2.3.0 MCP Tools Reference

**Complete reference for Model Context Protocol tools in TMWS**

---

## Table of Contents

1. [Overview](#overview)
2. [Memory Management Tools](#memory-management-tools)
3. [Agent Management Tools](#agent-management-tools)
4. [Task Management Tools](#task-management-tools)
5. [Workflow Management Tools](#workflow-management-tools)
6. [System Tools](#system-tools)
7. [Agent-Specific Usage Patterns](#agent-specific-usage-patterns)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)

---

## Overview

TMWS v2.3.0 provides **5 categories of MCP tools** for Claude Desktop integration:

1. **Memory Management**: Store and search semantic memories (HybridMemoryService)
2. **Agent Management**: Register and coordinate agents (RedisAgentService)
3. **Task Management**: Create and track tasks (RedisTaskService)
4. **Workflow Management**: Execute multi-step workflows
5. **System Tools**: Health checks, statistics, agent switching

### Performance Characteristics

| Tool Category | Typical Latency | Technology |
|---------------|----------------|------------|
| Memory Tools | 0.47ms (search), 2ms (store) | ChromaDB + PostgreSQL |
| Agent Tools | < 1ms | Redis HASH + ZADD |
| Task Tools | < 3ms | Redis Streams + ZADD |
| Workflow Tools | Variable (depends on steps) | PostgreSQL + Redis |
| System Tools | < 5ms | PostgreSQL + Redis + Chroma |

---

## Memory Management Tools

### store_memory

**Purpose**: Store semantic memory with 768-dimensional Multilingual-E5 embedding

**Performance**: 2ms P95 (write-through to PostgreSQL + Chroma)

**Signature**:
```python
store_memory(
    content: str,
    importance: float = 0.5,
    tags: list[str] = [],
    namespace: str = "default",
    access_level: str = "private",
    metadata: dict = {}
) -> dict
```

**Parameters**:
- `content` (required): Memory content (max 10,000 characters)
- `importance`: Float 0.0-1.0 (0.0=low, 1.0=critical)
- `tags`: List of tags for filtering (max 20 tags)
- `namespace`: Namespace for isolation (default: "default")
- `access_level`: "private", "team", "shared", "public"
- `metadata`: Additional metadata (JSON, max 10KB)

**Returns**:
```json
{
  "id": "uuid-here",
  "content": "Memory content",
  "importance": 0.9,
  "tags": ["architecture", "decision"],
  "embedding_model": "intfloat/multilingual-e5-base",
  "created_at": "2025-01-09T12:00:00Z",
  "agent_id": "athena-conductor"
}
```

**Example Usage**:

```python
# Athena: Store architectural decision
result = store_memory(
    content="Adopted microservices architecture with event-driven communication",
    importance=0.95,
    tags=["architecture", "microservices", "decision", "strategic"],
    namespace="project-x",
    access_level="team",
    metadata={
        "decision_date": "2025-01-09",
        "stakeholders": ["CTO", "Lead Architect"],
        "impact": "high"
    }
)
```

**Write-Through Pattern**:
1. Generate 768-dim Multilingual-E5 embedding
2. Write to PostgreSQL (ACID commit) - **PRIMARY**
3. Write to Chroma hot cache (best-effort) - **SECONDARY**

---

### search_memories

**Purpose**: Semantic similarity search using Chroma HNSW index

**Performance**: 0.47ms P95 (Chroma) or 50-200ms (PostgreSQL fallback)

**Signature**:
```python
search_memories(
    query: str,
    limit: int = 10,
    min_similarity: float = 0.7,
    namespace: str = "default",
    tags: list[str] = [],
    importance_threshold: float = 0.0
) -> dict
```

**Parameters**:
- `query` (required): Search query (natural language)
- `limit`: Max results (default: 10, max: 100)
- `min_similarity`: Cosine similarity threshold 0.0-1.0 (default: 0.7)
- `namespace`: Namespace filter (default: "default")
- `tags`: Tag filters (AND logic)
- `importance_threshold`: Min importance filter

**Returns**:
```json
{
  "query": "architecture decisions",
  "results": [
    {
      "id": "uuid-1",
      "content": "Adopted microservices...",
      "similarity": 0.92,
      "importance": 0.95,
      "tags": ["architecture", "decision"],
      "created_at": "2025-01-09T12:00:00Z"
    }
  ],
  "count": 1,
  "search_source": "chroma",
  "latency_ms": 0.47
}
```

**Example Usage**:

```python
# Artemis: Search for optimization patterns
results = search_memories(
    query="database query optimization techniques",
    limit=10,
    min_similarity=0.75,
    tags=["performance", "optimization"],
    importance_threshold=0.6
)

for memory in results["results"]:
    print(f"[{memory['similarity']:.2f}] {memory['content']}")
```

**Read-First Pattern**:
1. Generate query embedding with "query:" prefix
2. Search Chroma HNSW index (0.47ms) - **PRIMARY**
3. Hydrate full Memory objects from PostgreSQL
4. Fallback to PostgreSQL pgvector if Chroma fails

---

### update_memory

**Purpose**: Update existing memory (content, importance, tags)

**Performance**: 1.8ms P95

**Signature**:
```python
update_memory(
    memory_id: str,
    content: str = None,
    importance: float = None,
    tags: list[str] = None,
    metadata: dict = None
) -> dict
```

**Example Usage**:

```python
# Update importance after validation
update_memory(
    memory_id="uuid-here",
    importance=1.0,  # Upgrade to critical
    tags=["verified", "production", "critical"]
)
```

---

### delete_memory

**Purpose**: Delete memory from PostgreSQL and Chroma

**Performance**: 1.2ms P95

**Signature**:
```python
delete_memory(memory_id: str) -> dict
```

**Example Usage**:

```python
# Hestia: Delete security vulnerability after fix
delete_memory(memory_id="vulnerability-uuid")
```

---

## Agent Management Tools

### register_agent

**Purpose**: Register agent with Redis for coordination

**Performance**: 0.8ms P95

**Signature**:
```python
register_agent(
    agent_id: str,
    namespace: str = "trinitas",
    capabilities: list[str] = [],
    display_name: str = "",
    metadata: dict = {}
) -> dict
```

**Parameters**:
- `agent_id` (required): Unique agent identifier (2-32 chars)
- `namespace`: Agent namespace (default: "trinitas")
- `capabilities`: List of capabilities (max 50)
- `display_name`: Human-readable name
- `metadata`: Additional metadata (JSON, max 10KB)

**Returns**:
```json
{
  "agent_id": "athena-conductor",
  "namespace": "trinitas",
  "capabilities": ["orchestration", "strategy", "coordination"],
  "status": "active",
  "registered_at": "2025-01-09T12:00:00Z"
}
```

**Example Usage**:

```python
# Register custom data analyst agent
register_agent(
    agent_id="data-analyst-1",
    namespace="analytics",
    capabilities=["data_analysis", "visualization", "reporting"],
    display_name="Data Analysis Specialist",
    metadata={
        "specialization": "predictive_modeling",
        "tools": ["pandas", "scikit-learn"]
    }
)
```

**Redis Data Structure**:
```
HASH agent:data-analyst-1
  agent_id: "data-analyst-1"
  namespace: "analytics"
  capabilities: ["data_analysis", "visualization", "reporting"]
  status: "active"
  last_seen: 1704844800.0

ZADD agents:active {agent_id: timestamp}
ZADD agents:namespace:analytics {agent_id: timestamp}
EXPIRE agent:data-analyst-1 600  (10 minutes TTL)
```

---

### get_agent

**Purpose**: Retrieve agent status and metadata

**Performance**: 0.58ms P95

**Signature**:
```python
get_agent(agent_id: str) -> dict
```

**Example Usage**:

```python
# Check if agent is active
agent = get_agent("artemis-optimizer")
if agent["status"] == "active":
    print(f"Agent last seen: {agent['last_seen']}")
```

---

### list_agents

**Purpose**: List agents by namespace or status

**Performance**: 1.8ms P95 (50 agents)

**Signature**:
```python
list_agents(
    namespace: str = None,
    status: str = "active",
    limit: int = 100
) -> list[dict]
```

**Example Usage**:

```python
# Hera: List all active Trinitas agents
agents = list_agents(namespace="trinitas", status="active")
print(f"Active agents: {len(agents)}")
for agent in agents:
    print(f"- {agent['agent_id']}: {agent['capabilities']}")
```

---

### heartbeat

**Purpose**: Update agent heartbeat to prevent TTL expiration

**Performance**: 0.3ms P95

**Signature**:
```python
heartbeat(agent_id: str) -> dict
```

**Example Usage**:

```python
# Periodic heartbeat (every 30 seconds)
import asyncio

async def agent_heartbeat_loop():
    while True:
        heartbeat("athena-conductor")
        await asyncio.sleep(30)
```

---

### deregister_agent

**Purpose**: Remove agent from registry

**Performance**: 0.9ms P95

**Signature**:
```python
deregister_agent(agent_id: str) -> dict
```

**Example Usage**:

```python
# Graceful shutdown
deregister_agent("custom-analyst")
```

---

## Task Management Tools

### create_task

**Purpose**: Create task in Redis task queue

**Performance**: 1.5ms P95

**Signature**:
```python
create_task(
    title: str,
    description: str = "",
    priority: str = "MEDIUM",
    assigned_persona: str = None,
    due_date: str = None,
    dependencies: list[str] = [],
    metadata: dict = {}
) -> dict
```

**Parameters**:
- `title` (required): Task title (max 255 chars)
- `description`: Task description
- `priority`: "LOW", "MEDIUM", "HIGH", "URGENT"
- `assigned_persona`: Agent ID to assign task
- `due_date`: ISO 8601 date string
- `dependencies`: List of task IDs that must complete first
- `metadata`: Additional metadata (JSON)

**Returns**:
```json
{
  "id": "task-uuid",
  "title": "Implement feature X",
  "status": "pending",
  "priority": "HIGH",
  "assigned_persona": "artemis-optimizer",
  "created_at": "2025-01-09T12:00:00Z",
  "stream_id": "1704844800000-0"
}
```

**Example Usage**:

```python
# Eris: Coordinate team task
task = create_task(
    title="Implement API authentication",
    description="Add JWT authentication to all API endpoints",
    priority="HIGH",
    assigned_persona="hestia-auditor",
    due_date="2025-01-15T00:00:00Z",
    dependencies=["design-task-uuid"],
    metadata={
        "epic": "security-hardening",
        "story_points": 8
    }
)
```

---

### update_task_status

**Purpose**: Update task status and progress

**Performance**: 2.5ms P95

**Signature**:
```python
update_task_status(
    task_id: str,
    status: str,
    progress: int = None,
    result: dict = None
) -> dict
```

**Parameters**:
- `task_id` (required): Task UUID
- `status` (required): "pending", "in_progress", "completed", "failed"
- `progress`: Integer 0-100 (percentage)
- `result`: Task result data (JSON)

**Example Usage**:

```python
# Update task progress
update_task_status(
    task_id="task-uuid",
    status="in_progress",
    progress=45
)

# Complete task with results
update_task_status(
    task_id="task-uuid",
    status="completed",
    progress=100,
    result={
        "success": True,
        "tests_passed": 42,
        "coverage": 0.95
    }
)
```

---

### list_tasks

**Purpose**: List tasks with filters

**Performance**: 2.8ms P95 (50 tasks)

**Signature**:
```python
list_tasks(
    status: str = None,
    priority: str = None,
    assigned_persona: str = None,
    limit: int = 100
) -> list[dict]
```

**Example Usage**:

```python
# Hera: Get high-priority pending tasks
tasks = list_tasks(status="pending", priority="HIGH", limit=20)
for task in tasks:
    print(f"[{task['priority']}] {task['title']} → {task['assigned_persona']}")
```

---

### complete_task

**Purpose**: Mark task as completed with result

**Performance**: 2.0ms P95

**Signature**:
```python
complete_task(
    task_id: str,
    result: dict = {}
) -> dict
```

**Example Usage**:

```python
# Complete task
complete_task(
    task_id="task-uuid",
    result={
        "completion_time": "2h 30m",
        "quality_score": 0.95,
        "notes": "All tests passing"
    }
)
```

---

## Workflow Management Tools

### create_workflow

**Purpose**: Define multi-step workflow

**Signature**:
```python
create_workflow(
    name: str,
    description: str = "",
    steps: list[dict],
    parallel: bool = False,
    metadata: dict = {}
) -> dict
```

**Parameters**:
- `name` (required): Workflow name
- `description`: Workflow description
- `steps` (required): List of workflow steps
  - `persona`: Agent ID to execute step
  - `action`: Action to perform
  - `timeout`: Timeout in seconds (default: 300)
  - `retry`: Retry count (default: 0)
- `parallel`: Execute steps in parallel (default: False)
- `metadata`: Additional metadata

**Example Usage**:

```python
# Hera: Define deployment workflow
workflow = create_workflow(
    name="production_deployment",
    description="Deploy to production with safety checks",
    steps=[
        {
            "persona": "hestia-auditor",
            "action": "security_scan",
            "timeout": 600,
            "retry": 2
        },
        {
            "persona": "artemis-optimizer",
            "action": "performance_test",
            "timeout": 900,
            "retry": 1
        },
        {
            "persona": "athena-conductor",
            "action": "deploy_to_production",
            "timeout": 1800,
            "retry": 0
        },
        {
            "persona": "muses-documenter",
            "action": "update_documentation",
            "timeout": 300,
            "retry": 1
        }
    ],
    parallel=False,  # Sequential execution
    metadata={
        "environment": "production",
        "rollback_enabled": True
    }
)
```

---

### execute_workflow

**Purpose**: Execute workflow and return execution ID

**Signature**:
```python
execute_workflow(
    workflow_id: str,
    parameters: dict = {}
) -> dict
```

**Example Usage**:

```python
# Execute workflow
execution = execute_workflow(
    workflow_id="workflow-uuid",
    parameters={
        "git_branch": "main",
        "build_number": "1.2.3",
        "notify_slack": True
    }
)

print(f"Execution ID: {execution['execution_id']}")
print(f"Status: {execution['status']}")
```

---

### get_workflow_status

**Purpose**: Get workflow execution status

**Signature**:
```python
get_workflow_status(
    workflow_id: str,
    execution_id: str = None
) -> dict
```

**Example Usage**:

```python
# Check workflow progress
status = get_workflow_status(
    workflow_id="workflow-uuid",
    execution_id="execution-uuid"
)

print(f"Status: {status['status']}")
print(f"Progress: {status['completed_steps']}/{status['total_steps']}")
print(f"Current step: {status['current_step']['action']}")
```

---

## System Tools

### health_check

**Purpose**: Check system health (PostgreSQL + Redis + Chroma)

**Performance**: < 5ms

**Signature**:
```python
health_check() -> dict
```

**Returns**:
```json
{
  "status": "healthy",
  "components": {
    "postgresql": {"status": "up", "latency_ms": 2.1},
    "redis": {"status": "up", "latency_ms": 0.5},
    "chroma": {"status": "up", "latency_ms": 0.8}
  },
  "timestamp": "2025-01-09T12:00:00Z"
}
```

---

### get_system_stats

**Purpose**: Get system statistics and metrics

**Performance**: < 10ms

**Signature**:
```python
get_system_stats() -> dict
```

**Returns**:
```json
{
  "chroma": {
    "cache_size": 10000,
    "collection_count": 1,
    "search_latency_p95_ms": 0.47
  },
  "redis": {
    "active_agents": 6,
    "pending_tasks": 23,
    "memory_usage_mb": 512
  },
  "postgresql": {
    "connection_pool_size": 10,
    "active_connections": 3,
    "memory_count": 125000
  }
}
```

---

### switch_agent

**Purpose**: Switch agent context for current MCP session

**Performance**: < 1ms

**Signature**:
```python
switch_agent(agent_id: str) -> dict
```

**Example Usage**:

```python
# Switch to security context for audit
switch_agent("hestia-auditor")

# Perform security-related operations
results = search_memories(query="security vulnerabilities")

# Switch back to orchestration context
switch_agent("athena-conductor")
```

---

## Agent-Specific Usage Patterns

### Athena (Strategic Orchestrator)

**Primary Tools**:
- `store_memory`: Record architectural decisions
- `search_memories`: Recall strategic patterns
- `create_workflow`: Define coordination workflows
- `list_agents`: Coordinate team activities

**Usage Pattern**:

```python
# Store strategic decision
store_memory(
    content="Adopted event-driven architecture for scalability",
    importance=0.95,
    tags=["strategy", "architecture", "scalability"],
    namespace="project-alpha"
)

# Search for relevant patterns
patterns = search_memories(
    query="scalability patterns",
    tags=["architecture"],
    min_similarity=0.8
)

# Create coordination workflow
workflow = create_workflow(
    name="architecture_review",
    steps=[
        {"persona": "athena-conductor", "action": "design_review"},
        {"persona": "artemis-optimizer", "action": "technical_feasibility"},
        {"persona": "hestia-auditor", "action": "security_review"}
    ]
)
```

---

### Artemis (Performance Optimizer)

**Primary Tools**:
- `store_memory`: Record optimization results
- `search_memories`: Find optimization patterns
- `list_tasks`: Track optimization tasks

**Usage Pattern**:

```python
# Record optimization success
store_memory(
    content="Database query optimized: 500ms → 50ms (10x) by adding btree index",
    importance=0.85,
    tags=["optimization", "database", "performance"],
    metadata={
        "improvement": "10x",
        "technique": "btree_index",
        "table": "users"
    }
)

# Search for similar optimizations
similar = search_memories(
    query="database optimization techniques",
    tags=["optimization", "database"],
    importance_threshold=0.7
)

# Create optimization task
task = create_task(
    title="Optimize API response time",
    priority="HIGH",
    assigned_persona="artemis-optimizer",
    metadata={"target_latency": "< 100ms"}
)
```

---

### Hestia (Security Auditor)

**Primary Tools**:
- `store_memory`: Record security findings
- `search_memories`: Recall security patterns
- `create_task`: Track security fixes

**Usage Pattern**:

```python
# Record critical security finding
store_memory(
    content="SQL injection vulnerability in /api/users endpoint (CVE-2024-xxxxx)",
    importance=1.0,  # Critical
    tags=["security", "vulnerability", "sql_injection", "critical"],
    metadata={
        "severity": "critical",
        "cve": "CVE-2024-xxxxx",
        "endpoint": "/api/users",
        "status": "pending_fix"
    }
)

# Create security fix task
task = create_task(
    title="Fix SQL injection in /api/users",
    priority="URGENT",
    assigned_persona="artemis-optimizer",
    dependencies=[],
    metadata={
        "vulnerability_id": "vuln-uuid",
        "deadline": "24h"
    }
)

# Monitor fix progress
status = list_tasks(priority="URGENT", status="in_progress")
```

---

### Eris (Team Coordinator)

**Primary Tools**:
- `list_agents`: Monitor team status
- `create_task`: Coordinate team tasks
- `list_tasks`: Track task progress

**Usage Pattern**:

```python
# Monitor active agents
agents = list_agents(namespace="trinitas", status="active")
print(f"Active team members: {len(agents)}")

# Create coordinated task
task = create_task(
    title="Frontend-Backend sync for API v2",
    description="Align API contract between teams",
    priority="HIGH",
    metadata={
        "frontend_lead": "agent-1",
        "backend_lead": "agent-2",
        "coordination_required": True
    }
)

# Track team progress
pending = list_tasks(status="pending", limit=50)
in_progress = list_tasks(status="in_progress", limit=50)
print(f"Pending: {len(pending)}, In Progress: {len(in_progress)}")
```

---

### Hera (Workflow Orchestrator)

**Primary Tools**:
- `create_workflow`: Define workflows
- `execute_workflow`: Execute workflows
- `get_workflow_status`: Monitor workflows

**Usage Pattern**:

```python
# Define parallel deployment workflow
workflow = create_workflow(
    name="parallel_microservices_deploy",
    steps=[
        {"persona": "artemis-optimizer", "action": "service_a_deploy"},
        {"persona": "artemis-optimizer", "action": "service_b_deploy"},
        {"persona": "artemis-optimizer", "action": "service_c_deploy"}
    ],
    parallel=True,  # Execute in parallel
    metadata={"strategy": "blue_green"}
)

# Execute workflow
execution = execute_workflow(
    workflow_id=workflow["id"],
    parameters={"environment": "production"}
)

# Monitor execution
while True:
    status = get_workflow_status(workflow["id"], execution["execution_id"])
    if status["status"] in ["completed", "failed"]:
        break
    await asyncio.sleep(5)
```

---

### Muses (Knowledge Manager)

**Primary Tools**:
- `store_memory`: Document knowledge
- `search_memories`: Retrieve documentation
- `list_agents`: Document team capabilities

**Usage Pattern**:

```python
# Document API specification
store_memory(
    content="REST API v2.0 specification: 45 endpoints, OpenAPI 3.0 compliant",
    importance=0.8,
    tags=["documentation", "api", "specification"],
    metadata={
        "version": "2.0",
        "format": "openapi_3.0",
        "endpoint_count": 45
    }
)

# Retrieve related documentation
docs = search_memories(
    query="API documentation and specifications",
    tags=["documentation"],
    limit=20
)

# Document team capabilities
agents = list_agents(namespace="trinitas")
for agent in agents:
    store_memory(
        content=f"Agent {agent['agent_id']}: {', '.join(agent['capabilities'])}",
        importance=0.5,
        tags=["team", "capabilities", "documentation"]
    )
```

---

## Best Practices

### Memory Management

1. **Set Appropriate Importance**
   ```python
   # Critical: 1.0 (security issues, major decisions)
   store_memory(content="Critical security fix", importance=1.0)

   # High: 0.8-0.9 (architecture, optimization)
   store_memory(content="Architecture decision", importance=0.9)

   # Medium: 0.5-0.7 (coordination, tasks)
   store_memory(content="Team sync notes", importance=0.6)

   # Low: 0.3-0.4 (reference info)
   store_memory(content="Documentation link", importance=0.4)
   ```

2. **Use Tags Systematically**
   ```python
   # Persona tags
   tags=["athena_", "artemis_", "hestia_", ...]

   # Category tags
   tags=["architecture", "security", "performance", ...]

   # Priority tags
   tags=["critical", "urgent", "high", "medium", "low"]

   # Status tags
   tags=["completed", "in_progress", "pending", "blocked"]
   ```

3. **Namespace Isolation**
   ```python
   # Project isolation
   namespace="project-alpha"
   namespace="project-beta"

   # Environment isolation
   namespace="production"
   namespace="staging"
   ```

### Agent Coordination

1. **Heartbeat Pattern**
   ```python
   # Periodic heartbeat every 30s (TTL is 10 minutes)
   async def heartbeat_loop():
       while True:
           await heartbeat(agent_id)
           await asyncio.sleep(30)
   ```

2. **Graceful Shutdown**
   ```python
   import signal

   async def shutdown_handler(signum, frame):
       await deregister_agent(agent_id)
       sys.exit(0)

   signal.signal(signal.SIGINT, shutdown_handler)
   signal.signal(signal.SIGTERM, shutdown_handler)
   ```

### Task Management

1. **Task Dependencies**
   ```python
   # Create dependent tasks
   design_task = create_task(title="Design API")
   implement_task = create_task(
       title="Implement API",
       dependencies=[design_task["id"]]
   )
   test_task = create_task(
       title="Test API",
       dependencies=[implement_task["id"]]
   )
   ```

2. **Progress Tracking**
   ```python
   # Update progress incrementally
   update_task_status(task_id, status="in_progress", progress=0)
   # ... work ...
   update_task_status(task_id, status="in_progress", progress=50)
   # ... more work ...
   complete_task(task_id, result={"success": True})
   ```

---

## Troubleshooting

### Issue: Slow Vector Search

**Symptom**: `search_memories` taking > 10ms

**Diagnosis**:
```python
# Check search source
results = search_memories(query="test")
if results["search_source"] == "postgresql_fallback":
    print("WARNING: Chroma unavailable, using slow PostgreSQL fallback")
```

**Solutions**:
1. Check Chroma service: `docker ps | grep chroma`
2. Verify Chroma data directory: `ls -la ./data/chroma`
3. Reinitialize Chroma: `python scripts/initialize_chroma.py`

---

### Issue: Agent Registration Failed

**Symptom**: `register_agent` returns error

**Diagnosis**:
```python
try:
    register_agent(agent_id="test")
except Exception as e:
    print(f"Error: {e}")
```

**Solutions**:
1. Check Redis connectivity: `redis-cli ping`
2. Verify Redis URL: `echo $TMWS_REDIS_URL`
3. Check Redis memory: `redis-cli INFO memory`

---

### Issue: Task Queue Full

**Symptom**: `create_task` slow or failing

**Diagnosis**:
```python
stats = get_system_stats()
if stats["redis"]["pending_tasks"] > 10000:
    print("WARNING: Task queue overloaded")
```

**Solutions**:
1. Increase task processing rate
2. Archive completed tasks: `python scripts/cleanup_tasks.py`
3. Implement backpressure in task creation

---

For more details, see:
- [Architecture Documentation](ARCHITECTURE_V2.3.0.md)
- [Benchmark Report](BENCHMARK_REPORT.md)
- [MCP Integration Guide](MCP_INTEGRATION.md)
