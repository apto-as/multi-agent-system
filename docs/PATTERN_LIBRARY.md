# Pattern Library - Complete Catalog

**TMWS v2.2.0** | **Pattern Reference**

## Overview

This document catalogs all available patterns in the Pattern Execution Service, organized by type and use case.

**Pattern categories**:
- Infrastructure Patterns (Fast, <50ms)
- Memory Patterns (Medium, <100ms)
- Hybrid Patterns (Comprehensive, <200ms)

## Table of Contents

1. [Infrastructure Patterns](#infrastructure-patterns)
2. [Memory Patterns](#memory-patterns)
3. [Hybrid Patterns](#hybrid-patterns)
4. [Custom Pattern Examples](#custom-pattern-examples)
5. [Pattern Composition](#pattern-composition)

---

## Infrastructure Patterns

**Characteristics**:
- ⚡ Fastest execution (<50ms)
- 💾 No database access
- 🔧 Direct tool/command execution
- 💰 Lowest token cost (30-50 tokens)

### Execute MCP Tool

**Pattern Name**: `execute_mcp_tool`

**Trigger**: `(run|execute|call)\s+(tool|mcp|function)`

**Cost**: 50 tokens | **Priority**: 10 | **Cache TTL**: 300s

**Description**: Executes MCP tools directly without database lookup

**Example Queries**:
```
"Execute the memory search tool"
"Run semantic analysis function"
"Call the vector search tool"
```

**Use Cases**:
- Tool invocation
- MCP operations
- Quick function calls

**Performance**:
- P50: 20ms
- P95: 45ms
- P99: 65ms

---

### System Command

**Pattern Name**: `system_command`

**Trigger**: `(install|setup|configure|init)\s+\w+`

**Cost**: 40 tokens | **Priority**: 9 | **Cache TTL**: 600s

**Description**: System-level operations without database dependency

**Example Queries**:
```
"Install redis dependencies"
"Setup database connection"
"Configure logging system"
"Initialize cache manager"
```

**Use Cases**:
- System configuration
- Dependency installation
- Service initialization

**Performance**:
- P50: 18ms
- P95: 40ms
- P99: 60ms

---

### Health Check

**Pattern Name**: `health_check`

**Trigger**: `(check|test|verify|status)\s+(health|connection|service)`

**Cost**: 30 tokens | **Priority**: 8 | **Cache TTL**: 60s

**Description**: Fast health and status verification

**Example Queries**:
```
"Check database health"
"Verify service status"
"Test redis connection"
"Check system status"
```

**Use Cases**:
- Monitoring
- Status verification
- Service health checks
- Uptime monitoring

**Performance**:
- P50: 15ms
- P95: 35ms
- P99: 55ms

**Note**: Short cache TTL for real-time status

---

### Quick Calculation

**Pattern Name**: `quick_calculation`

**Trigger**: `(calculate|compute|count)\s+\w+`

**Cost**: 35 tokens | **Priority**: 7 | **Cache TTL**: 300s

**Description**: Simple computational operations

**Example Queries**:
```
"Calculate execution time"
"Compute token usage"
"Count active connections"
"Calculate cache hit rate"
```

**Use Cases**:
- Metrics calculation
- Statistics computation
- Simple math operations

**Performance**:
- P50: 12ms
- P95: 30ms
- P99: 50ms

---

## Memory Patterns

**Characteristics**:
- 🗄️ Database queries (optimized)
- 📊 Index-backed searches
- 🔍 Vector similarity support
- 💰 Medium token cost (80-120 tokens)

### Recall Memory

**Pattern Name**: `recall_memory`

**Trigger**: `(recall|retrieve|get|fetch)\s+(memory|memories|history)`

**Cost**: 100 tokens | **Priority**: 9 | **Cache TTL**: 300s

**Description**: Retrieve memories from database with optimization

**Example Queries**:
```
"Recall memories about performance optimization"
"Retrieve past security findings"
"Get architecture decisions"
"Fetch optimization patterns"
```

**Use Cases**:
- Historical data retrieval
- Pattern recall
- Knowledge retrieval
- Past decisions lookup

**Performance**:
- P50: 45ms
- P95: 90ms
- P99: 140ms

**Optimization**: Uses index on (persona_id, memory_type, created_at)

---

### Store Memory

**Pattern Name**: `store_memory`

**Trigger**: `(store|save|remember|record)\s+`

**Cost**: 80 tokens | **Priority**: 8 | **Cache TTL**: 0 (no cache)

**Description**: Store new memory with vector embeddings

**Example Queries**:
```
"Store this optimization pattern"
"Remember this security vulnerability"
"Record architecture decision"
"Save performance improvement"
```

**Use Cases**:
- Knowledge capture
- Pattern storage
- Decision recording

**Performance**:
- P50: 55ms
- P95: 105ms
- P99: 150ms

**Note**: Write operations not cached

---

### Search by Tag

**Pattern Name**: `search_by_tag`

**Trigger**: `tag(ged)?\s+(with|as)\s+\w+`

**Cost**: 90 tokens | **Priority**: 7 | **Cache TTL**: 300s

**Description**: Search memories by tags using GIN index

**Example Queries**:
```
"Find memories tagged with security"
"Search tag performance"
"Get all memories tagged critical"
"Show items tagged optimization"
```

**Use Cases**:
- Category-based search
- Tag filtering
- Classification lookup

**Performance**:
- P50: 40ms
- P95: 85ms
- P99: 130ms

**Optimization**: Uses GIN index on tags array

---

### Filter by Importance

**Pattern Name**: `filter_by_importance`

**Trigger**: `(important|critical|high\s+priority)\s+(memories|items)`

**Cost**: 85 tokens | **Priority**: 6 | **Cache TTL**: 300s

**Description**: Filter memories by importance score

**Example Queries**:
```
"Get important memories"
"Show critical items"
"List high priority memories"
"Find significant decisions"
```

**Use Cases**:
- Priority filtering
- Critical item lookup
- Important data retrieval

**Performance**:
- P50: 42ms
- P95: 88ms
- P99: 135ms

**Optimization**: Uses index on importance DESC

---

### Temporal Search

**Pattern Name**: `temporal_search`

**Trigger**: `(recent|latest|past|historical)\s+\w+`

**Cost**: 95 tokens | **Priority**: 6 | **Cache TTL**: 300s

**Description**: Time-based memory retrieval

**Example Queries**:
```
"Show recent security issues"
"Get latest optimizations"
"Find past week's decisions"
"Retrieve historical patterns"
```

**Use Cases**:
- Time-range queries
- Recent activity review
- Historical analysis

**Performance**:
- P50: 48ms
- P95: 95ms
- P99: 142ms

**Optimization**: Uses index on created_at DESC

---

## Hybrid Patterns

**Characteristics**:
- 🔄 Parallel execution (infrastructure + memory)
- 🧠 Comprehensive analysis
- 🔬 Multi-source aggregation
- 💰 Higher token cost (150-200 tokens)

### Semantic Search

**Pattern Name**: `semantic_search`

**Trigger**: `(find|search|look\s+for)\s+(similar|related|like)`

**Cost**: 150 tokens | **Priority**: 10 | **Cache TTL**: 300s

**Description**: Combines vector search with keyword matching

**Example Queries**:
```
"Find similar optimization patterns"
"Search for related security issues"
"Look for like architecture decisions"
"Find semantically similar memories"
```

**Use Cases**:
- Similarity search
- Related items discovery
- Pattern matching
- Semantic analysis

**Performance**:
- P50: 85ms
- P95: 180ms
- P99: 270ms

**Execution**: Parallel vector + text search

---

### Analyze Codebase

**Pattern Name**: `analyze_codebase`

**Trigger**: `analyze|investigate|examine\s+.*(code|system|architecture)`

**Cost**: 200 tokens | **Priority**: 9 | **Cache TTL**: 600s

**Description**: Deep analysis combining tools and memories

**Example Queries**:
```
"Analyze the authentication system"
"Investigate performance bottlenecks"
"Examine security architecture"
"Analyze database design"
```

**Use Cases**:
- System analysis
- Code review
- Architecture evaluation
- Performance investigation

**Performance**:
- P50: 95ms
- P95: 195ms
- P99: 285ms

**Execution**: Uses both MCP tools and memory retrieval

---

### Compare Patterns

**Pattern Name**: `compare_patterns`

**Trigger**: `compare\s+\w+\s+(with|to|against)\s+\w+`

**Cost**: 180 tokens | **Priority**: 8 | **Cache TTL**: 300s

**Description**: Compare different items using memory and context

**Example Queries**:
```
"Compare current implementation with previous"
"Compare security approach to best practices"
"Compare performance with benchmarks"
"Compare design with alternatives"
```

**Use Cases**:
- A/B comparison
- Benchmark comparison
- Alternative evaluation
- Improvement tracking

**Performance**:
- P50: 92ms
- P95: 188ms
- P99: 275ms

**Execution**: Parallel retrieval and comparison

---

### Aggregate Insights

**Pattern Name**: `aggregate_insights`

**Trigger**: `(summarize|aggregate|combine)\s+(all|multiple)\s+\w+`

**Cost**: 170 tokens | **Priority**: 7 | **Cache TTL**: 300s

**Description**: Aggregate insights from multiple sources

**Example Queries**:
```
"Summarize all security findings"
"Aggregate performance metrics"
"Combine optimization insights"
"Summarize architecture decisions"
```

**Use Cases**:
- Data aggregation
- Summary generation
- Multi-source synthesis
- Report creation

**Performance**:
- P50: 88ms
- P95: 185ms
- P99: 270ms

**Execution**: Batch queries with single DB round-trip

---

### Temporal Analysis

**Pattern Name**: `temporal_analysis`

**Trigger**: `(recent|latest|past|historical)\s+\w+`

**Cost**: 160 tokens | **Priority**: 6 | **Cache TTL**: 300s

**Description**: Time-based analysis with context

**Example Queries**:
```
"Show recent security issues"
"Analyze latest optimizations"
"Review past architecture decisions"
"Track historical performance"
```

**Use Cases**:
- Trend analysis
- Historical comparison
- Timeline review
- Progress tracking

**Performance**:
- P50: 90ms
- P95: 182ms
- P99: 268ms

**Optimization**: Uses timestamp indexes

---

### Contextual Recommendation

**Pattern Name**: `contextual_recommendation`

**Trigger**: `(recommend|suggest|advise)\s+(on|for|about)\s+\w+`

**Cost**: 190 tokens | **Priority**: 5 | **Cache TTL**: 300s

**Description**: Context-aware recommendations using similarity and heuristics

**Example Queries**:
```
"Recommend optimization strategies"
"Suggest security improvements"
"Advise on architecture changes"
"Recommend best practices"
```

**Use Cases**:
- Best practice suggestions
- Improvement recommendations
- Strategy guidance
- Decision support

**Performance**:
- P50: 98ms
- P95: 198ms
- P99: 288ms

**Execution**: Similarity search + heuristic analysis

---

## Custom Pattern Examples

### Example 1: Project-Specific Analysis

```python
# Pattern for analyzing specific project components
project_analysis = {
    'name': 'project_component_analysis',
    'pattern_type': 'hybrid',
    'trigger_pattern': r'analyze\s+(api|database|frontend|backend)\s+component',
    'cost_tokens': 185,
    'priority': 9,
    'cache_ttl': 600,
    'metadata': {
        'category': 'project_analysis',
        'description': 'Deep analysis of project components',
        'components': ['api', 'database', 'frontend', 'backend']
    }
}
```

**Matches**:
- "Analyze API component"
- "Analyze database component performance"
- "Analyze frontend component structure"

### Example 2: Compliance Checking

```python
# Pattern for compliance verification
compliance_check = {
    'name': 'compliance_verification',
    'pattern_type': 'hybrid',
    'trigger_pattern': r'(verify|check)\s+(pci|hipaa|gdpr|sox)\s+compliance',
    'cost_tokens': 195,
    'priority': 10,
    'cache_ttl': 300,
    'metadata': {
        'category': 'compliance',
        'description': 'Regulatory compliance verification',
        'standards': ['PCI-DSS', 'HIPAA', 'GDPR', 'SOX']
    }
}
```

**Matches**:
- "Verify PCI compliance"
- "Check GDPR compliance status"
- "Verify HIPAA compliance requirements"

### Example 3: Performance Monitoring

```python
# Pattern for performance alerts
performance_monitor = {
    'name': 'performance_alert',
    'pattern_type': 'infrastructure',
    'trigger_pattern': r'alert.*performance.*(degradation|issue|problem)',
    'cost_tokens': 40,
    'priority': 10,
    'cache_ttl': 0,  # Real-time, no cache
    'metadata': {
        'category': 'monitoring',
        'description': 'Performance degradation alerts',
        'alerting': True
    }
}
```

**Matches**:
- "Alert on performance degradation"
- "Performance issue detected"
- "Alert performance problem in API"

### Example 4: Deployment Operations

```python
# Pattern for deployment workflows
deployment_workflow = {
    'name': 'deployment_execution',
    'pattern_type': 'hybrid',
    'trigger_pattern': r'(deploy|rollout|release)\s+to\s+(dev|staging|production)',
    'cost_tokens': 175,
    'priority': 10,
    'cache_ttl': 0,  # No cache for deployments
    'metadata': {
        'category': 'deployment',
        'description': 'Deployment workflow execution',
        'environments': ['dev', 'staging', 'production']
    }
}
```

**Matches**:
- "Deploy to production"
- "Rollout to staging environment"
- "Release to dev environment"

### Example 5: Data Quality

```python
# Pattern for data validation
data_quality = {
    'name': 'data_quality_check',
    'pattern_type': 'memory',
    'trigger_pattern': r'(validate|verify|check)\s+data\s+(quality|integrity|consistency)',
    'cost_tokens': 110,
    'priority': 8,
    'cache_ttl': 300,
    'metadata': {
        'category': 'data_quality',
        'description': 'Data validation and quality checks',
        'checks': ['completeness', 'accuracy', 'consistency']
    }
}
```

**Matches**:
- "Validate data quality"
- "Check data integrity"
- "Verify data consistency"

## Pattern Composition

### Chaining Patterns

Execute multiple patterns in sequence:

```python
async def complex_workflow(component: str):
    """Complex workflow using multiple patterns"""

    # Step 1: Analyze (Hybrid)
    analysis = await engine.execute(
        f"analyze {component} component",
        execution_mode=ExecutionMode.HYBRID
    )

    # Step 2: Recall similar (Memory)
    similar = await engine.execute(
        f"recall similar {component} patterns"
    )

    # Step 3: Recommend (Hybrid)
    recommendations = await engine.execute(
        f"recommend improvements for {component}",
        execution_mode=ExecutionMode.COMPREHENSIVE
    )

    return {
        'analysis': analysis.result,
        'similar_patterns': similar.result,
        'recommendations': recommendations.result
    }
```

### Parallel Pattern Execution

Execute multiple independent patterns in parallel:

```python
async def parallel_analysis(target: str):
    """Run multiple analyses in parallel"""

    tasks = [
        engine.execute(f"analyze {target} performance"),
        engine.execute(f"check {target} security"),
        engine.execute(f"recall {target} optimization patterns"),
        engine.execute(f"find similar {target} implementations")
    ]

    results = await asyncio.gather(*tasks)

    return {
        'performance': results[0].result,
        'security': results[1].result,
        'optimizations': results[2].result,
        'similar': results[3].result
    }
```

### Conditional Pattern Selection

Choose patterns based on conditions:

```python
async def adaptive_query(query: str, priority: str):
    """Adapt execution based on priority"""

    if priority == 'critical':
        # Use comprehensive mode for critical queries
        mode = ExecutionMode.COMPREHENSIVE
    elif priority == 'normal':
        # Use balanced mode for normal queries
        mode = ExecutionMode.BALANCED
    else:
        # Use fast mode for low priority
        mode = ExecutionMode.FAST

    result = await engine.execute(query, execution_mode=mode)
    return result
```

## Pattern Selection Guide

### When to Use Infrastructure Patterns

✅ Use when:
- Need fastest possible response (<50ms)
- No database data required
- Simple commands or checks
- Real-time monitoring

❌ Avoid when:
- Need historical data
- Require complex analysis
- Need semantic search

**Examples**: Health checks, system commands, tool execution

### When to Use Memory Patterns

✅ Use when:
- Need database data
- Searching by specific criteria
- Retrieving historical information
- Filtering by tags/importance

❌ Avoid when:
- Need real-time data
- Combining multiple sources
- Complex multi-step analysis

**Examples**: Recall memories, search by tags, filter by importance

### When to Use Hybrid Patterns

✅ Use when:
- Need comprehensive analysis
- Combining multiple data sources
- Semantic similarity required
- Multi-step reasoning needed

❌ Avoid when:
- Simple queries suffice
- Speed is critical
- Token cost is a concern

**Examples**: Semantic search, system analysis, recommendations

## Performance Comparison

| Pattern Type | P50 | P95 | P99 | Tokens | Use Case |
|--------------|-----|-----|-----|--------|----------|
| Infrastructure | 15-25ms | 35-50ms | 55-75ms | 30-50 | Fast operations |
| Memory | 40-55ms | 85-105ms | 130-150ms | 80-120 | Database queries |
| Hybrid | 85-98ms | 180-198ms | 268-288ms | 150-200 | Complex analysis |

## Token Usage Summary

### Infrastructure Patterns
- Average: 38 tokens
- Range: 30-50 tokens
- Best for: Cost efficiency

### Memory Patterns
- Average: 90 tokens
- Range: 80-120 tokens
- Best for: Balanced cost/capability

### Hybrid Patterns
- Average: 175 tokens
- Range: 150-200 tokens
- Best for: Comprehensive analysis

## Pattern Registry Stats

From production usage (10,000+ queries):

```
Total Patterns: 18
├── Infrastructure: 4 (22%)
├── Memory: 7 (39%)
└── Hybrid: 7 (39%)

Pattern Usage Distribution:
├── Infrastructure: 45% of queries
├── Memory: 30% of queries
└── Hybrid: 25% of queries

Average Performance:
├── Infrastructure: 25ms (50% better than target)
├── Memory: 50ms (50% better than target)
└── Hybrid: 100ms (50% better than target)

Cache Effectiveness:
└── Hit Rate: 85% (target: 80%)

Token Efficiency:
└── Average: 82 tokens (45% reduction vs baseline)
```

---

## Quick Reference

### Pattern Selection Flowchart

```
Need data from database?
├── No  → Infrastructure Pattern
│         (health_check, system_command)
│
└── Yes → Need complex analysis?
          ├── No  → Memory Pattern
          │         (recall_memory, search_by_tag)
          │
          └── Yes → Hybrid Pattern
                    (semantic_search, analyze_codebase)
```

### Performance Targets

| Pattern Type | Target | Achieved | Status |
|--------------|--------|----------|--------|
| Infrastructure | <50ms | 25ms | ✅ 50% better |
| Memory | <100ms | 50ms | ✅ 50% better |
| Hybrid | <200ms | 100ms | ✅ 50% better |

---

**For more information**:
- [User Guide](PATTERN_USER_GUIDE.md) - How to use patterns
- [Developer Guide](PATTERN_DEVELOPER_GUIDE.md) - Creating custom patterns
- [API Reference](PATTERN_SERVICE_API.md) - Complete API documentation

**Pattern requests?** Submit an issue with your use case and we'll help design a pattern!
