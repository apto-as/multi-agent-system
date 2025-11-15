# TMWS Integration Patterns Guide
## 8 Complete Workflow Patterns for Trinitas-agents

**Version**: v2.3.0
**Target Audience**: Trinitas-agents Development Team
**Last Updated**: 2025-11-14
**Status**: Production-ready

---

## Table of Contents

1. [Overview](#overview)
2. [Pattern 1: Daily Standup Workflow](#pattern-1-daily-standup-workflow)
3. [Pattern 2: Code Review Workflow](#pattern-2-code-review-workflow)
4. [Pattern 3: Security Audit Workflow](#pattern-3-security-audit-workflow)
5. [Pattern 4: Performance Optimization Workflow](#pattern-4-performance-optimization-workflow)
6. [Pattern 5: Documentation Generation Workflow](#pattern-5-documentation-generation-workflow)
7. [Pattern 6: Multi-Agent Coordination Workflow](#pattern-6-multi-agent-coordination-workflow)
8. [Pattern 7: Knowledge Base Building Workflow](#pattern-7-knowledge-base-building-workflow)
9. [Pattern 8: Production Deployment Workflow](#pattern-8-production-deployment-workflow)
10. [Best Practices](#best-practices)
11. [Common Pitfalls](#common-pitfalls)

---

## Overview

This guide demonstrates **8 complete integration patterns** showing how Trinitas-agents use TMWS in real development scenarios. Each pattern combines:

- **MCP Tools** (21 tools for memory & workflow management)
- **REST API** (4 endpoints for external MCP server connections)
- **Learning Patterns** (Agent Skills TMWS version)
- **Team Collaboration** (multi-agent coordination)

### Quick Reference: TMWS Capabilities

| Capability | Interface | Example Use Case |
|------------|-----------|------------------|
| Memory storage | MCP: `store_memory` | Store daily progress, decisions |
| Semantic search | MCP: `search_memories` | Find past solutions, context |
| Agent Skills | MCP + Learning Service | Store/apply optimization patterns |
| Task coordination | MCP: `create_task` | Delegate work to other agents |
| Trust verification | MCP: `verify_and_record` | Validate agent claims (tests, metrics) |
| External tools | REST: `/mcp/connections` | Connect to context7, serena, playwright |
| Agent status | MCP: `get_agent_status` | Monitor team activity |

---

## Pattern 1: Daily Standup Workflow

**Scenario**: Artemis (Technical Perfectionist) records daily progress and searches for past work to prepare standup report.

### Tools Used

- **MCP Tools**: `store_memory`, `search_memories`
- **REST API**: None (uses MCP directly)
- **Learning Patterns**: Optional (store recurring tasks as patterns)

### Complete Workflow

#### Step 1: Store Today's Progress

```python
#!/usr/bin/env python3
"""Artemis: Store daily progress to TMWS"""

import asyncio
from datetime import datetime
from src.services.memory_service import MemoryService

async def store_daily_progress():
    service = MemoryService()

    # Today's accomplishments
    progress = {
        "date": datetime.now().isoformat(),
        "completed": [
            "Optimized database queries (SQL injection fix - CVSS 9.8)",
            "Reduced search latency by 60-85% with new indexes",
            "Reviewed 3 pull requests from team"
        ],
        "in_progress": [
            "Phase 2D security test suite implementation"
        ],
        "blockers": [],
        "metrics": {
            "tests_passed": 370,
            "tests_failed": 0,
            "coverage": 85.2
        }
    }

    # Store as high-importance memory
    memory = await service.create_memory(
        content=f"Daily Progress - {datetime.now().strftime('%Y-%m-%d')}: "
                f"Completed {len(progress['completed'])} tasks, "
                f"In Progress: {len(progress['in_progress'])}, "
                f"Test Coverage: {progress['metrics']['coverage']}%",
        memory_type="daily-standup",
        importance_score=0.75,  # Medium-high importance
        tags=["daily-standup", "artemis", "progress", "2025-11-14"],
        metadata=progress,
        access_level="TEAM",  # Share with team
        namespace="trinitas-agents",
        agent_id="artemis-optimizer"
    )

    print(f" Stored daily progress: {memory.id}")
    print(f"   Content preview: {memory.content[:100]}...")

    return memory

# Run
asyncio.run(store_daily_progress())
```

#### Step 2: Search Past Week's Work

```python
async def search_weekly_progress():
    """Search memories from the past week for standup report"""
    service = MemoryService()

    # Semantic search for progress updates
    results = await service.search_memories(
        query="What did I work on this week? Show progress, blockers, and metrics.",
        top_k=10,
        filters={
            "tags": ["daily-standup"],
            "agent_id": "artemis-optimizer"
        },
        namespace="trinitas-agents"
    )

    # Extract weekly summary
    weekly_summary = {
        "total_tasks_completed": 0,
        "key_accomplishments": [],
        "blockers_resolved": [],
        "metrics_trend": []
    }

    for memory in results["results"][:7]:  # Last 7 days
        metadata = memory.get("metadata", {})
        weekly_summary["total_tasks_completed"] += len(metadata.get("completed", []))
        weekly_summary["key_accomplishments"].extend(metadata.get("completed", []))

        if metadata.get("metrics"):
            weekly_summary["metrics_trend"].append({
                "date": metadata.get("date"),
                "coverage": metadata["metrics"].get("coverage")
            })

    print("\n=Ê Weekly Summary:")
    print(f"   Total tasks completed: {weekly_summary['total_tasks_completed']}")
    print(f"   Key accomplishments ({len(weekly_summary['key_accomplishments'])} items):")
    for i, task in enumerate(weekly_summary['key_accomplishments'][:5], 1):
        print(f"      {i}. {task}")

    return weekly_summary

# Run
asyncio.run(search_weekly_progress())
```

#### Step 3: Generate Standup Report

```bash
#!/bin/bash
# Artemis: Quick standup report generation

# Search for this week's progress
python3 << 'EOF'
import asyncio
from src.services.memory_service import MemoryService

async def generate_standup():
    service = MemoryService()

    results = await service.search_memories(
        query="Daily progress this week",
        top_k=7,
        filters={"tags": ["daily-standup"]},
        namespace="trinitas-agents"
    )

    print("=Ë Artemis Daily Standup Report\n")
    print("Yesterday:")
    if results["results"]:
        latest = results["results"][0]
        print(f"   {latest['content']}\n")

    print("Today:")
    print("   - Continue Phase 2D security tests")
    print("   - Review Hestia's security audit findings\n")

    print("Blockers: None")

asyncio.run(generate_standup())
EOF
```

### Expected Outcome

- **Daily progress stored** with 0.75 importance score
- **Team visibility** via TEAM access level
- **Semantic search** retrieves relevant past work
- **Weekly summary** generated from 7 days of memories
- **Standup report** ready in < 30 seconds

### Team Collaboration

Other agents can search Artemis's progress:

```python
# Athena searches Artemis's progress for coordination
results = await service.search_memories(
    query="What did Artemis work on this week?",
    filters={"agent_id": "artemis-optimizer", "tags": ["daily-standup"]},
    namespace="trinitas-agents"
)
```

---

## Pattern 2: Code Review Workflow

**Scenario**: Hestia (Security Guardian) reviews code, creates tasks for fixes, verifies Artemis's claims about test results.

### Tools Used

- **MCP Tools**: `create_task`, `verify_and_record`, `store_memory`, `get_agent_trust_score`
- **REST API**: None (uses MCP directly)
- **Learning Patterns**: Store common security issues as patterns

### Complete Workflow

#### Step 1: Hestia Reviews Code & Finds Issues

```python
#!/usr/bin/env python3
"""Hestia: Security code review workflow"""

import asyncio
from src.services.memory_service import MemoryService
from src.mcp.tools.task_tools import create_task
from src.services.learning_service import LearningService

async def security_code_review():
    memory_service = MemoryService()
    learning_service = LearningService()

    # Findings from static analysis (Bandit, Semgrep)
    findings = [
        {
            "severity": "HIGH",
            "type": "SQL Injection",
            "location": "src/services/learning_service.py:704",
            "description": "Potential SQL injection via f-string in WHERE clause",
            "cvss": 9.8,
            "recommendation": "Use bindparams() for parameterized queries"
        },
        {
            "severity": "MEDIUM",
            "type": "Hardcoded Secret",
            "location": "tests/conftest.py:15",
            "description": "Secret key visible in test fixtures",
            "cvss": 5.3,
            "recommendation": "Use environment variable or test-specific secret"
        }
    ]

    # Store findings as memories
    for finding in findings:
        memory = await memory_service.create_memory(
            content=f"Security Finding ({finding['severity']}): {finding['type']} "
                    f"in {finding['location']} - CVSS {finding['cvss']}",
            memory_type="security-audit",
            importance_score=1.0 if finding['severity'] == "HIGH" else 0.8,
            tags=["security", "code-review", "hestia", finding['type'].lower()],
            metadata=finding,
            access_level="TEAM",
            namespace="trinitas-agents",
            agent_id="hestia-auditor"
        )
        print(f"=4 Stored finding: {finding['type']} (CVSS {finding['cvss']})")

    # Create learning pattern for SQL injection prevention
    pattern = await learning_service.create_pattern(
        pattern_name="sql_injection_prevention",
        category="security",
        subcategory="database",
        pattern_data={
            "description": "Prevent SQL injection by using parameterized queries",
            "problem": "F-strings and string concatenation in SQL WHERE clauses",
            "solution": "Use SQLAlchemy bindparams() or ORM filters",
            "example_bad": "f\"WHERE value = '{user_input}'\"",
            "example_good": "text('WHERE value = :input').bindparams(input=user_input)",
            "cvss_prevented": 9.8,
            "references": ["OWASP A01:2021", "CWE-89"]
        },
        agent_id="hestia-auditor",
        namespace="trinitas-agents",
        access_level="PUBLIC",  # Share with all agents
        tags=["security", "sql-injection", "prevention"]
    )
    print(f" Created learning pattern: {pattern.pattern_name}")

    return findings

asyncio.run(security_code_review())
```

#### Step 2: Create Tasks for Artemis to Fix

```python
async def create_fix_tasks(findings):
    """Create tasks for each security finding"""
    from src.mcp.tools.task_tools import create_task

    tasks = []
    for finding in findings:
        task = await create_task(
            title=f"Fix {finding['type']} (CVSS {finding['cvss']})",
            description=f"{finding['description']}\n\n"
                        f"Location: {finding['location']}\n"
                        f"Recommendation: {finding['recommendation']}",
            priority="critical" if finding['severity'] == "HIGH" else "high",
            assigned_agent_id="artemis-optimizer",
            estimated_duration=60 if finding['severity'] == "HIGH" else 30,
            metadata={
                "finding": finding,
                "reviewer": "hestia-auditor",
                "requires_verification": True
            }
        )
        tasks.append(task)
        print(f"=Ë Created task: {task['title']}")

    return tasks

# Run after code review
findings = asyncio.run(security_code_review())
asyncio.run(create_fix_tasks(findings))
```

#### Step 3: Verify Artemis's Fix Claims

```python
async def verify_fix():
    """Hestia verifies Artemis's claim that SQL injection is fixed"""
    from src.mcp.tools.trust_tools import verify_and_record

    # Artemis claims: "Fixed SQL injection, all tests pass"
    claim = {
        "vulnerability": "SQL Injection (CVSS 9.8)",
        "location": "src/services/learning_service.py:704",
        "fix_applied": "Changed to bindparams()",
        "tests_passed": 28,
        "tests_failed": 0
    }

    # Hestia verifies with actual test execution
    result = await verify_and_record(
        agent_id="artemis-optimizer",
        claim_type="security_finding",
        claim_content=claim,
        verification_command=(
            "pytest tests/unit/security/test_sql_injection.py -v && "
            "grep -n 'bindparams' src/services/learning_service.py"
        ),
        verified_by_agent_id="hestia-auditor"
    )

    if result["accurate"]:
        print(f" Verified: Artemis's fix is correct")
        print(f"   New trust score: {result['new_trust_score']:.2%}")
    else:
        print(f"   Claim inaccurate: Re-review required")
        print(f"   Actual: {result['actual']}")
        print(f"   Claimed: {result['claim']}")

    # Store verification result
    await memory_service.create_memory(
        content=f"Security Fix Verified: SQL Injection (CVSS 9.8) fixed by Artemis",
        memory_type="verification",
        importance_score=1.0,
        tags=["security", "verification", "sql-injection", "resolved"],
        metadata=result,
        access_level="TEAM",
        namespace="trinitas-agents",
        agent_id="hestia-auditor"
    )

    return result

asyncio.run(verify_fix())
```

### Expected Outcome

- **2 security findings** stored with HIGH/MEDIUM severity
- **2 tasks created** and assigned to Artemis
- **1 learning pattern** created (sql_injection_prevention) for team
- **Verification result** recorded with updated trust score
- **Audit trail** maintained for compliance

### Team Collaboration

```python
# Athena monitors fix progress
from src.mcp.tools.system_tools import get_agent_status

status = await get_agent_status()
for agent in status["agents"]:
    if agent["agent_id"] == "artemis-optimizer":
        print(f"Artemis status: {agent['active_tasks']} tasks")
```

---

## Pattern 3: Security Audit Workflow

**Scenario**: Comprehensive security audit using Learning Patterns, external tools (Playwright for dynamic testing), and team reporting.

### Tools Used

- **MCP Tools**: `store_memory`, `search_memories`, Learning Pattern Service
- **REST API**: `/mcp/connections` (connect to Playwright for dynamic testing)
- **Learning Patterns**: Apply security testing patterns

### Complete Workflow

#### Step 1: Search for Past Security Patterns

```python
#!/usr/bin/env python3
"""Hestia: Apply learned security testing patterns"""

import asyncio
from src.services.learning_service import LearningService

async def search_security_patterns():
    service = LearningService()

    # Search for security testing patterns
    patterns = await service.search_patterns(
        query="XSS vulnerability testing methodology",
        category="security",
        min_success_rate=0.8,  # Only proven patterns
        access_level=["PUBLIC", "TEAM"],
        namespace="trinitas-agents",
        limit=5
    )

    print("= Found security testing patterns:\n")
    for pattern in patterns:
        print(f"   {pattern['pattern_name']}")
        print(f"   Success rate: {pattern['success_rate']:.0%}")
        print(f"   Used {pattern['usage_count']} times\n")

    return patterns

patterns = asyncio.run(search_security_patterns())
```

#### Step 2: Connect to Playwright for Dynamic Testing

```python
async def setup_dynamic_testing():
    """Connect to Playwright MCP server for XSS testing"""
    import requests
    from jose import jwt
    import os
    from datetime import datetime, timedelta

    # Generate JWT token
    token = jwt.encode(
        {
            "sub": "hestia-auditor",
            "exp": datetime.utcnow() + timedelta(hours=1)
        },
        os.getenv("TMWS_SECRET_KEY"),
        algorithm="HS256"
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # Create connection to Playwright MCP server
    response = requests.post(
        "http://localhost:8000/api/v1/mcp/connections",
        json={
            "server_name": "playwright",
            "url": "http://localhost:3001",
            "timeout": 60,
            "namespace": "trinitas-agents",
            "agent_id": "hestia-auditor"
        },
        headers=headers
    )

    connection = response.json()
    print(f" Connected to Playwright: {connection['id']}")

    return connection["id"], headers

connection_id, headers = asyncio.run(setup_dynamic_testing())
```

#### Step 3: Execute XSS Tests via Playwright

```python
async def test_xss_vulnerability(connection_id, headers):
    """Execute XSS tests using Playwright"""
    import requests

    # Test payload: <script>alert('XSS')</script>
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')"
    ]

    results = []
    for payload in xss_payloads:
        # Navigate and inject payload
        response = requests.post(
            f"http://localhost:8000/api/v1/mcp/connections/{connection_id}/tools/browser_type/execute",
            json={
                "arguments": {
                    "action": "fill",
                    "selector": "input[name='search']",
                    "value": payload
                }
            },
            headers=headers
        )

        # Check if alert was triggered (XSS vulnerability)
        check_response = requests.post(
            f"http://localhost:8000/api/v1/mcp/connections/{connection_id}/tools/browser_evaluate/execute",
            json={
                "arguments": {
                    "function": "() => document.querySelectorAll('script').length"
                }
            },
            headers=headers
        )

        vulnerable = check_response.json()["result"]["result"] > 0
        results.append({
            "payload": payload,
            "vulnerable": vulnerable
        })

        print(f"{'=4 VULNERABLE' if vulnerable else ' SAFE'}: {payload}")

    return results

results = asyncio.run(test_xss_vulnerability(connection_id, headers))
```

#### Step 4: Store Audit Results & Create Learning Pattern

```python
async def store_audit_results(results):
    """Store XSS audit results and create learning pattern"""
    from src.services.memory_service import MemoryService
    from src.services.learning_service import LearningService

    memory_service = MemoryService()
    learning_service = LearningService()

    # Count vulnerabilities
    vulnerable_count = sum(1 for r in results if r["vulnerable"])

    # Store audit result
    memory = await memory_service.create_memory(
        content=f"XSS Security Audit: Tested {len(results)} payloads, "
                f"Found {vulnerable_count} vulnerabilities",
        memory_type="security-audit",
        importance_score=1.0,
        tags=["security", "xss", "audit", "playwright"],
        metadata={
            "results": results,
            "vulnerable_count": vulnerable_count,
            "total_tested": len(results),
            "auditor": "hestia-auditor",
            "audit_date": datetime.now().isoformat()
        },
        access_level="TEAM",
        namespace="trinitas-agents",
        agent_id="hestia-auditor"
    )

    print(f" Stored audit results: {memory.id}")

    # Create/update learning pattern
    if vulnerable_count > 0:
        pattern = await learning_service.create_pattern(
            pattern_name="xss_testing_methodology",
            category="security",
            subcategory="xss",
            pattern_data={
                "description": "Dynamic XSS testing using Playwright",
                "payloads": [r["payload"] for r in results],
                "success_indicators": ["alert triggered", "script injected"],
                "tools_required": ["playwright", "browser automation"],
                "severity": "HIGH",
                "cvss_range": "7.0-9.0"
            },
            agent_id="hestia-auditor",
            namespace="trinitas-agents",
            access_level="PUBLIC",
            tags=["security", "xss", "testing", "playwright"]
        )
        print(f" Created learning pattern: {pattern.pattern_name}")

    return memory

asyncio.run(store_audit_results(results))
```

#### Step 5: Disconnect Playwright & Generate Report

```python
async def finalize_audit(connection_id, headers):
    """Disconnect Playwright and generate audit report"""
    import requests
    from src.services.memory_service import MemoryService

    # Disconnect Playwright
    requests.delete(
        f"http://localhost:8000/api/v1/mcp/connections/{connection_id}",
        headers=headers
    )
    print(" Disconnected Playwright")

    # Search all security audit memories for report
    service = MemoryService()
    audit_memories = await service.search_memories(
        query="Security audit findings this month",
        top_k=20,
        filters={
            "memory_type": "security-audit",
            "agent_id": "hestia-auditor"
        },
        namespace="trinitas-agents"
    )

    # Generate report
    print("\n=Ê Security Audit Report")
    print("=" * 60)
    for memory in audit_memories["results"]:
        metadata = memory.get("metadata", {})
        print(f"\n{memory['content']}")
        if "vulnerable_count" in metadata:
            print(f"   Vulnerabilities: {metadata['vulnerable_count']}/{metadata['total_tested']}")

    return audit_memories

asyncio.run(finalize_audit(connection_id, headers))
```

### Expected Outcome

- **XSS vulnerabilities detected** via dynamic Playwright testing
- **Audit results stored** with 1.0 importance score
- **Learning pattern created** (xss_testing_methodology) for team reuse
- **Comprehensive report** generated from semantic search
- **External tool (Playwright) disconnected** properly

### Team Collaboration

```python
# Artemis searches for security findings to fix
results = await service.search_memories(
    query="Security vulnerabilities found by Hestia",
    filters={"memory_type": "security-audit"},
    namespace="trinitas-agents"
)
```

---

## Pattern 4: Performance Optimization Workflow

**Scenario**: Artemis discovers performance bottleneck, applies learned optimization pattern, measures improvement, stores new pattern.

### Tools Used

- **MCP Tools**: Learning Pattern Service, `store_memory`, `verify_and_record`
- **REST API**: None (uses MCP directly)
- **Learning Patterns**: Apply database optimization patterns

### Complete Workflow

#### Step 1: Search for Optimization Patterns

```python
#!/usr/bin/env python3
"""Artemis: Apply learned optimization patterns"""

import asyncio
from src.services.learning_service import LearningService

async def search_optimization_patterns():
    service = LearningService()

    # Search for database optimization patterns
    patterns = await service.search_patterns(
        query="Database query optimization with indexes",
        category="performance",
        subcategory="database",
        min_success_rate=0.85,
        namespace="trinitas-agents",
        limit=5
    )

    print("= Found optimization patterns:\n")
    for pattern in patterns:
        data = pattern["pattern_data"]
        print(f"   {pattern['pattern_name']}")
        print(f"   Success rate: {pattern['success_rate']:.0%}")
        print(f"   Avg improvement: {data.get('avg_improvement', 'N/A')}")
        print(f"   Applied {pattern['usage_count']} times\n")

    # Select best pattern
    best_pattern = max(patterns, key=lambda p: p["success_rate"])
    return best_pattern

best_pattern = asyncio.run(search_optimization_patterns())
```

#### Step 2: Apply Optimization Pattern

```python
async def apply_optimization(pattern):
    """Apply database index optimization pattern"""
    from src.services.learning_service import LearningService

    service = LearningService()

    # Pattern suggests: Add composite index on (agent_id, created_at DESC)
    optimization_steps = pattern["pattern_data"]["steps"]

    print(f"=Ý Applying pattern: {pattern['pattern_name']}\n")
    for i, step in enumerate(optimization_steps, 1):
        print(f"   Step {i}: {step}")

    # Example: Create database migration
    migration_code = f"""
# Alembic migration generated from pattern: {pattern['pattern_name']}

def upgrade():
    # Add composite index (from pattern recommendation)
    op.create_index(
        'idx_learning_patterns_agent_performance',
        'learning_patterns',
        ['agent_id', 'created_at', 'success_rate'],
        postgresql_ops={{'created_at': 'DESC'}}
    )

def downgrade():
    op.drop_index('idx_learning_patterns_agent_performance')
"""

    # Record pattern usage
    result = await service.use_pattern(
        pattern_id=pattern["id"],
        agent_id="artemis-optimizer",
        task_context={
            "task": "Optimize learning pattern queries",
            "location": "src/services/learning_service.py:search_patterns"
        },
        success=True,  # Will be updated after measurement
        outcome_notes="Applied composite index optimization"
    )

    print(f"\n Pattern applied: {result['pattern_name']}")
    print(f"   Usage count: {result['usage_count']}")

    return migration_code

migration = asyncio.run(apply_optimization(best_pattern))
```

#### Step 3: Measure Performance Improvement

```python
async def measure_improvement():
    """Benchmark before/after performance"""
    import time
    from src.services.learning_service import LearningService

    service = LearningService()

    # Benchmark: Search patterns (before optimization)
    print("=Ê Measuring performance improvement...\n")

    # Before (simulate: ~2000ms)
    before_latency = 2000  # ms

    # After (with index)
    start = time.perf_counter()
    patterns = await service.search_patterns(
        query="Database optimization",
        category="performance",
        namespace="trinitas-agents",
        limit=10
    )
    after_latency = (time.perf_counter() - start) * 1000

    # Calculate improvement
    improvement_pct = ((before_latency - after_latency) / before_latency) * 100

    print(f"   Before: {before_latency:.0f}ms")
    print(f"   After:  {after_latency:.1f}ms")
    print(f"   Improvement: -{improvement_pct:.1f}%\n")

    return {
        "before_ms": before_latency,
        "after_ms": after_latency,
        "improvement_pct": improvement_pct
    }

metrics = asyncio.run(measure_improvement())
```

#### Step 4: Verify and Store Results

```python
async def verify_optimization(metrics, pattern):
    """Verify optimization claim and store results"""
    from src.mcp.tools.trust_tools import verify_and_record
    from src.services.memory_service import MemoryService
    from src.services.learning_service import LearningService

    # Artemis claims: "Optimization improved performance by 85%"
    claim = {
        "optimization": "Composite index on learning_patterns",
        "improvement_claimed": 85.0,  # %
        "latency_before": 2000,  # ms
        "latency_after": 300  # ms
    }

    # Verify with benchmark
    result = await verify_and_record(
        agent_id="artemis-optimizer",
        claim_type="performance_metric",
        claim_content=claim,
        verification_command=(
            "pytest tests/performance/test_learning_service.py::test_search_patterns_performance -v"
        ),
        verified_by_agent_id="hestia-auditor"
    )

    print(f"{'' if result['accurate'] else '  '} Verification: {result['accurate']}")

    # Store optimization result
    memory_service = MemoryService()
    memory = await memory_service.create_memory(
        content=f"Performance Optimization: Learning pattern search improved by {metrics['improvement_pct']:.1f}% "
                f"(from {metrics['before_ms']:.0f}ms to {metrics['after_ms']:.1f}ms)",
        memory_type="optimization",
        importance_score=0.9,
        tags=["performance", "optimization", "database", "artemis"],
        metadata={
            "pattern_used": pattern["pattern_name"],
            "metrics": metrics,
            "verification": result
        },
        access_level="TEAM",
        namespace="trinitas-agents",
        agent_id="artemis-optimizer"
    )

    # Update pattern with successful outcome
    learning_service = LearningService()
    await learning_service.use_pattern(
        pattern_id=pattern["id"],
        agent_id="artemis-optimizer",
        task_context={"task": "Optimize search_patterns() latency"},
        success=True,
        outcome_notes=f"Achieved {metrics['improvement_pct']:.1f}% improvement"
    )

    print(f" Stored optimization result: {memory.id}")

    return memory

asyncio.run(verify_optimization(metrics, best_pattern))
```

#### Step 5: Create New Pattern from Success

```python
async def create_new_pattern(metrics):
    """Create new optimization pattern from this success"""
    from src.services.learning_service import LearningService

    service = LearningService()

    # Create reusable pattern
    pattern = await service.create_pattern(
        pattern_name="composite_index_for_filtered_queries",
        category="performance",
        subcategory="database",
        pattern_data={
            "description": "Add composite index for queries with multiple filters",
            "problem": "Slow queries with WHERE clause on multiple columns",
            "solution": "Create composite index covering all filter columns",
            "steps": [
                "Identify slow query with EXPLAIN ANALYZE",
                "Determine most common filter combinations",
                "Create composite index with DESC for sorting",
                "Benchmark before/after performance",
                "Monitor index usage with pg_stat_user_indexes"
            ],
            "example": {
                "before": "SELECT * FROM table WHERE col1 = ? AND col2 = ? ORDER BY created_at DESC",
                "index": "CREATE INDEX idx_name ON table(col1, col2, created_at DESC)",
                "improvement": f"{metrics['improvement_pct']:.1f}%"
            },
            "proven_improvement": metrics,
            "when_to_apply": "Queries with 2+ filters and sorting",
            "cost": "Low (index creation time)",
            "risk": "Low (can be dropped if ineffective)"
        },
        agent_id="artemis-optimizer",
        namespace="trinitas-agents",
        access_level="PUBLIC",  # Share with all agents
        tags=["performance", "database", "indexing", "proven"],
        learning_weight=0.95  # High confidence
    )

    print(f" Created new pattern: {pattern.pattern_name}")
    print(f"   This pattern is now available for all agents to apply")

    return pattern

asyncio.run(create_new_pattern(metrics))
```

### Expected Outcome

- **Existing pattern applied** (database optimization)
- **85% performance improvement** measured and verified
- **Trust score updated** for Artemis (accurate claim)
- **Optimization result stored** with 0.9 importance
- **New pattern created** for team reuse (composite_index_for_filtered_queries)

### Team Collaboration

```python
# Other agents can now search and apply Artemis's proven pattern
results = await service.search_patterns(
    query="How to optimize slow database queries with multiple filters?",
    category="performance",
    min_success_rate=0.9,  # Only proven patterns
    namespace="trinitas-agents"
)
```

---

## Pattern 5: Documentation Generation Workflow

**Scenario**: Muses (Knowledge Architect) generates comprehensive documentation using external context7 tool for library docs, TMWS memory for project context.

### Tools Used

- **MCP Tools**: `store_memory`, `search_memories`
- **REST API**: `/mcp/connections` (connect to context7 for library documentation)
- **Learning Patterns**: Documentation templates and best practices

### Complete Workflow

#### Step 1: Search Project Context

```python
#!/usr/bin/env python3
"""Muses: Gather project context for documentation"""

import asyncio
from src.services.memory_service import MemoryService

async def gather_project_context():
    service = MemoryService()

    # Search for architecture decisions
    arch_results = await service.search_memories(
        query="Architecture decisions and design rationale",
        top_k=10,
        filters={"tags": ["architecture", "design"]},
        namespace="trinitas-agents"
    )

    # Search for security requirements
    security_results = await service.search_memories(
        query="Security requirements and P0-1 patterns",
        top_k=5,
        filters={"tags": ["security"]},
        namespace="trinitas-agents"
    )

    # Search for performance benchmarks
    perf_results = await service.search_memories(
        query="Performance benchmarks and optimization results",
        top_k=5,
        filters={"tags": ["performance", "optimization"]},
        namespace="trinitas-agents"
    )

    context = {
        "architecture": arch_results["results"],
        "security": security_results["results"],
        "performance": perf_results["results"]
    }

    print("=Ú Gathered project context:")
    print(f"   Architecture: {len(context['architecture'])} items")
    print(f"   Security: {len(context['security'])} items")
    print(f"   Performance: {len(context['performance'])} items\n")

    return context

context = asyncio.run(gather_project_context())
```

#### Step 2: Connect to context7 for Library Docs

```python
async def fetch_library_docs():
    """Connect to context7 to fetch Next.js documentation"""
    import requests
    from jose import jwt
    import os
    from datetime import datetime, timedelta

    # Generate JWT token
    token = jwt.encode(
        {
            "sub": "muses-documenter",
            "exp": datetime.utcnow() + timedelta(hours=1)
        },
        os.getenv("TMWS_SECRET_KEY"),
        algorithm="HS256"
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # Create connection to context7
    response = requests.post(
        "http://localhost:8000/api/v1/mcp/connections",
        json={
            "server_name": "context7",
            "url": "http://localhost:3000",
            "timeout": 30,
            "namespace": "trinitas-agents",
            "agent_id": "muses-documenter"
        },
        headers=headers
    )

    connection_id = response.json()["id"]
    print(f" Connected to context7: {connection_id}\n")

    # Fetch Next.js routing documentation
    response = requests.post(
        f"http://localhost:8000/api/v1/mcp/connections/{connection_id}/tools/get-library-docs/execute",
        json={
            "arguments": {
                "context7CompatibleLibraryID": "/vercel/next.js",
                "topic": "routing",
                "tokens": 5000
            }
        },
        headers=headers
    )

    docs = response.json()["result"]["result"]["documentation"]
    print(f" Fetched Next.js routing docs ({len(docs)} chars)\n")

    # Disconnect
    requests.delete(
        f"http://localhost:8000/api/v1/mcp/connections/{connection_id}",
        headers=headers
    )

    return docs

library_docs = asyncio.run(fetch_library_docs())
```

#### Step 3: Generate Documentation

```python
async def generate_documentation(context, library_docs):
    """Generate comprehensive documentation combining project context and library docs"""
    from src.services.learning_service import LearningService

    # Search for documentation template pattern
    learning_service = LearningService()
    templates = await learning_service.search_patterns(
        query="API documentation template structure",
        category="documentation",
        namespace="trinitas-agents",
        limit=1
    )

    template = templates[0] if templates else None

    # Generate documentation sections
    documentation = f"""
# TMWS Next.js Integration Guide

## Overview

This guide demonstrates how to integrate TMWS (Trinitas Memory & Workflow System)
with a Next.js application for semantic memory and agent coordination.

## Architecture

{context['architecture'][0]['content'] if context['architecture'] else 'TBD'}

## Next.js Routing Integration

{library_docs[:1000]}...

## Security Requirements

{context['security'][0]['content'] if context['security'] else 'TBD'}

### P0-1 Namespace Isolation

Critical security pattern for multi-tenant applications. See full guide at
docs/SECURITY_GUIDE.md.

## Performance Benchmarks

{context['performance'][0]['content'] if context['performance'] else 'TBD'}

## API Reference

See docs/REST_API_GUIDE.md for complete API documentation.

## Quick Start

See docs/QUICK_START_GUIDE.md for setup instructions.

---

Generated by Muses (Knowledge Architect)
Date: {datetime.now().strftime('%Y-%m-%d')}
"""

    print("=Ý Generated documentation:")
    print(f"   Length: {len(documentation)} characters")
    print(f"   Sections: 7\n")

    return documentation

docs = asyncio.run(generate_documentation(context, library_docs))
```

#### Step 4: Store Documentation as Memory

```python
async def store_documentation(docs):
    """Store generated documentation for team access"""
    from src.services.memory_service import MemoryService

    service = MemoryService()

    memory = await service.create_memory(
        content=f"Documentation: TMWS Next.js Integration Guide ({len(docs)} chars)",
        memory_type="documentation",
        importance_score=0.9,
        tags=["documentation", "nextjs", "integration", "muses"],
        metadata={
            "title": "TMWS Next.js Integration Guide",
            "full_content": docs,
            "sections": ["Overview", "Architecture", "Routing", "Security", "Performance", "API", "Quick Start"],
            "generated_by": "muses-documenter",
            "generated_at": datetime.now().isoformat()
        },
        access_level="TEAM",
        namespace="trinitas-agents",
        agent_id="muses-documenter"
    )

    print(f" Stored documentation: {memory.id}")
    print(f"   Team can search: 'Next.js integration guide'\n")

    # Also save to filesystem
    with open("docs/NEXTJS_INTEGRATION.md", "w") as f:
        f.write(docs)

    print(" Saved to: docs/NEXTJS_INTEGRATION.md")

    return memory

asyncio.run(store_documentation(docs))
```

### Expected Outcome

- **Project context gathered** from semantic search (20 relevant memories)
- **External library docs fetched** from context7 (Next.js routing)
- **Documentation generated** combining context + library docs
- **Documentation stored** as memory with 0.9 importance
- **File saved** to `docs/NEXTJS_INTEGRATION.md`

### Team Collaboration

```python
# Other agents can search for documentation
results = await service.search_memories(
    query="How to integrate TMWS with Next.js?",
    filters={"memory_type": "documentation"},
    namespace="trinitas-agents"
)
```

---

## Pattern 6: Multi-Agent Coordination Workflow

**Scenario**: Athena (Harmonious Conductor) coordinates multiple agents for a complex feature implementation using tasks, status monitoring, and memory sharing.

### Tools Used

- **MCP Tools**: `create_task`, `get_agent_status`, `store_memory`, `search_memories`
- **REST API**: None (uses MCP directly)
- **Learning Patterns**: Project coordination patterns

### Complete Workflow

#### Step 1: Athena Creates Feature Implementation Plan

```python
#!/usr/bin/env python3
"""Athena: Coordinate multi-agent feature implementation"""

import asyncio
from src.services.memory_service import MemoryService
from src.mcp.tools.task_tools import create_task

async def plan_feature_implementation():
    """Plan: Implement JWT refresh token mechanism"""

    memory_service = MemoryService()

    # Store high-level plan
    plan_memory = await memory_service.create_memory(
        content="Feature Plan: JWT Refresh Token Mechanism - "
                "Implement token rotation with 7-day refresh window, "
                "coordinated by Athena, implemented by Artemis, "
                "secured by Hestia, documented by Muses",
        memory_type="project-plan",
        importance_score=0.95,
        tags=["feature", "jwt", "authentication", "coordination"],
        metadata={
            "feature": "JWT Refresh Tokens",
            "agents_involved": ["artemis-optimizer", "hestia-auditor", "muses-documenter"],
            "estimated_duration": 480,  # 8 hours total
            "phases": [
                {
                    "phase": "Design",
                    "agent": "artemis-optimizer",
                    "duration": 120
                },
                {
                    "phase": "Implementation",
                    "agent": "artemis-optimizer",
                    "duration": 180
                },
                {
                    "phase": "Security Review",
                    "agent": "hestia-auditor",
                    "duration": 120
                },
                {
                    "phase": "Documentation",
                    "agent": "muses-documenter",
                    "duration": 60
                }
            ]
        },
        access_level="TEAM",
        namespace="trinitas-agents",
        agent_id="athena-conductor"
    )

    print(f" Stored feature plan: {plan_memory.id}\n")

    return plan_memory

plan = asyncio.run(plan_feature_implementation())
```

#### Step 2: Create Tasks for Each Agent

```python
async def create_coordination_tasks(plan):
    """Create tasks for Artemis, Hestia, and Muses"""

    tasks = []

    # Task 1: Artemis - Design & Implementation
    artemis_task = await create_task(
        title="Implement JWT Refresh Token Mechanism",
        description="""Design and implement JWT refresh token rotation:

1. Add refresh_token field to User model
2. Implement /auth/refresh endpoint
3. Set access token TTL: 1 hour, refresh token TTL: 7 days
4. Add token rotation logic (invalidate old refresh token on use)
5. Write unit tests (target: 100% coverage)

See plan: {plan_id}
        """.format(plan_id=plan.id),
        priority="high",
        assigned_agent_id="artemis-optimizer",
        estimated_duration=300,  # 5 hours
        metadata={
            "feature": "JWT Refresh Tokens",
            "phase": "Design & Implementation",
            "coordinator": "athena-conductor"
        }
    )
    tasks.append(artemis_task)
    print(f"=Ë Created task for Artemis: {artemis_task['title']}")

    # Task 2: Hestia - Security Review
    hestia_task = await create_task(
        title="Security Review: JWT Refresh Token Implementation",
        description="""Review Artemis's JWT refresh token implementation:

1. Verify token rotation prevents replay attacks
2. Check refresh token storage security (encrypted at rest)
3. Test token invalidation on logout
4. Verify TTL enforcement
5. Check for timing attack vulnerabilities

See plan: {plan_id}
        """.format(plan_id=plan.id),
        priority="high",
        assigned_agent_id="hestia-auditor",
        estimated_duration=120,  # 2 hours
        metadata={
            "feature": "JWT Refresh Tokens",
            "phase": "Security Review",
            "depends_on": artemis_task["id"],
            "coordinator": "athena-conductor"
        }
    )
    tasks.append(hestia_task)
    print(f"=Ë Created task for Hestia: {hestia_task['title']}")

    # Task 3: Muses - Documentation
    muses_task = await create_task(
        title="Document JWT Refresh Token API",
        description="""Create comprehensive documentation:

1. Update API reference with /auth/refresh endpoint
2. Add sequence diagram for token rotation flow
3. Document error scenarios and responses
4. Create integration examples (Python, JavaScript)
5. Update SECURITY_GUIDE.md with token security best practices

See plan: {plan_id}
        """.format(plan_id=plan.id),
        priority="medium",
        assigned_agent_id="muses-documenter",
        estimated_duration=60,  # 1 hour
        metadata={
            "feature": "JWT Refresh Tokens",
            "phase": "Documentation",
            "depends_on": hestia_task["id"],
            "coordinator": "athena-conductor"
        }
    )
    tasks.append(muses_task)
    print(f"=Ë Created task for Muses: {muses_task['title']}\n")

    return tasks

tasks = asyncio.run(create_coordination_tasks(plan))
```

#### Step 3: Monitor Agent Status

```python
async def monitor_progress():
    """Athena monitors agent progress"""
    from src.mcp.tools.system_tools import get_agent_status
    import time

    print("=@ Athena monitoring agent status...\n")

    while True:
        status = await get_agent_status()

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Agent Status:")
        for agent in status["agents"]:
            if agent["agent_id"] in ["artemis-optimizer", "hestia-auditor", "muses-documenter"]:
                print(f"   {agent['agent_id']}: "
                      f"{agent['active_tasks']} active tasks, "
                      f"capabilities: {', '.join(agent['capabilities'][:3])}")

        print()

        # Check if all tasks completed
        all_completed = all(
            agent["active_tasks"] == 0
            for agent in status["agents"]
            if agent["agent_id"] in ["artemis-optimizer", "hestia-auditor", "muses-documenter"]
        )

        if all_completed:
            print(" All tasks completed!\n")
            break

        time.sleep(60)  # Check every minute

# Run in background
# asyncio.create_task(monitor_progress())
```

#### Step 4: Collect Results and Store Summary

```python
async def collect_results():
    """Search for work completed by agents and create summary"""
    from src.services.memory_service import MemoryService

    service = MemoryService()

    # Search for Artemis's implementation
    artemis_results = await service.search_memories(
        query="JWT refresh token implementation by Artemis",
        filters={"agent_id": "artemis-optimizer"},
        namespace="trinitas-agents",
        top_k=5
    )

    # Search for Hestia's security review
    hestia_results = await service.search_memories(
        query="JWT refresh token security review by Hestia",
        filters={"agent_id": "hestia-auditor"},
        namespace="trinitas-agents",
        top_k=5
    )

    # Search for Muses's documentation
    muses_results = await service.search_memories(
        query="JWT refresh token documentation by Muses",
        filters={"agent_id": "muses-documenter"},
        namespace="trinitas-agents",
        top_k=3
    )

    # Create summary
    summary = f"""
Feature Implementation Summary: JWT Refresh Tokens

Artemis (Implementation):
{artemis_results['results'][0]['content'] if artemis_results['results'] else 'Pending'}

Hestia (Security Review):
{hestia_results['results'][0]['content'] if hestia_results['results'] else 'Pending'}

Muses (Documentation):
{muses_results['results'][0]['content'] if muses_results['results'] else 'Pending'}

Status: Complete 
Total Duration: 8 hours (estimated)
Agents Involved: 3 (Artemis, Hestia, Muses)
"""

    # Store summary
    summary_memory = await service.create_memory(
        content="Feature Complete: JWT Refresh Token Mechanism - "
                "Successfully implemented with security review and documentation",
        memory_type="project-summary",
        importance_score=1.0,
        tags=["feature", "jwt", "complete", "coordination"],
        metadata={
            "feature": "JWT Refresh Tokens",
            "coordinator": "athena-conductor",
            "summary": summary,
            "agents": ["artemis-optimizer", "hestia-auditor", "muses-documenter"]
        },
        access_level="TEAM",
        namespace="trinitas-agents",
        agent_id="athena-conductor"
    )

    print("=Ê Feature Implementation Summary:")
    print(summary)
    print(f"\n Stored summary: {summary_memory.id}")

    return summary_memory

asyncio.run(collect_results())
```

### Expected Outcome

- **Feature plan stored** with 0.95 importance
- **3 tasks created** and assigned to Artemis, Hestia, Muses
- **Agent status monitored** every minute until completion
- **Results collected** from all 3 agents via semantic search
- **Summary stored** with 1.0 importance for future reference

### Team Collaboration

```python
# Future teams can learn from this coordination pattern
results = await service.search_memories(
    query="How did Athena coordinate the JWT refresh token feature?",
    filters={"memory_type": "project-summary"},
    namespace="trinitas-agents"
)
```

---

## Pattern 7: Knowledge Base Building Workflow

**Scenario**: Team builds shared knowledge base by storing learnings, creating patterns, and enabling semantic search across all agent contributions.

### Tools Used

- **MCP Tools**: `store_memory`, `search_memories`, Learning Pattern Service
- **REST API**: None (uses MCP directly)
- **Learning Patterns**: Knowledge organization patterns

### Complete Workflow

#### Step 1: Each Agent Contributes Knowledge

```python
#!/usr/bin/env python3
"""All agents contribute to shared knowledge base"""

import asyncio
from src.services.memory_service import MemoryService
from src.services.learning_service import LearningService

async def artemis_contributes():
    """Artemis: Share performance optimization knowledge"""
    memory_service = MemoryService()
    learning_service = LearningService()

    # Store optimization finding
    memory = await memory_service.create_memory(
        content="Performance Finding: Composite indexes reduce query latency by 60-85% "
                "for filtered searches with sorting",
        memory_type="knowledge",
        importance_score=0.85,
        tags=["performance", "database", "indexing", "artemis"],
        metadata={
            "category": "performance",
            "subcategory": "database",
            "proven": True,
            "metrics": {"improvement": "60-85%", "cost": "low"}
        },
        access_level="PUBLIC",  # Share with all agents
        namespace="trinitas-agents",
        agent_id="artemis-optimizer"
    )

    # Create learning pattern
    pattern = await learning_service.create_pattern(
        pattern_name="composite_index_optimization",
        category="performance",
        subcategory="database",
        pattern_data={
            "description": "Use composite indexes for multi-column filters",
            "when_to_apply": "Queries with 2+ WHERE clauses and ORDER BY",
            "steps": [
                "Run EXPLAIN ANALYZE on slow query",
                "Identify filter columns and sort column",
                "Create index: CREATE INDEX idx_name ON table(col1, col2, sort_col DESC)",
                "Benchmark improvement"
            ],
            "proven_improvement": "60-85%",
            "cost": "Low",
            "risk": "Low"
        },
        agent_id="artemis-optimizer",
        namespace="trinitas-agents",
        access_level="PUBLIC",
        tags=["performance", "database", "proven"]
    )

    print(f" Artemis contributed: {memory.id} + pattern {pattern.id}")

async def hestia_contributes():
    """Hestia: Share security knowledge"""
    memory_service = MemoryService()
    learning_service = LearningService()

    # Store security finding
    memory = await memory_service.create_memory(
        content="Security Best Practice: Always use bindparams() for SQL queries "
                "to prevent SQL injection (CVSS 9.8)",
        memory_type="knowledge",
        importance_score=1.0,  # Critical security knowledge
        tags=["security", "sql-injection", "prevention", "hestia"],
        metadata={
            "category": "security",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "vulnerability": "CWE-89"
        },
        access_level="PUBLIC",
        namespace="trinitas-agents",
        agent_id="hestia-auditor"
    )

    # Create learning pattern
    pattern = await learning_service.create_pattern(
        pattern_name="sql_injection_prevention",
        category="security",
        subcategory="database",
        pattern_data={
            "description": "Prevent SQL injection with parameterized queries",
            "problem": "User input in SQL WHERE clause via f-strings",
            "solution": "Use SQLAlchemy bindparams() or ORM filters",
            "bad_example": "f\"WHERE value = '{user_input}'\"",
            "good_example": "text('WHERE value = :input').bindparams(input=user_input)",
            "cvss_prevented": 9.8,
            "references": ["OWASP A03:2021", "CWE-89"]
        },
        agent_id="hestia-auditor",
        namespace="trinitas-agents",
        access_level="PUBLIC",
        tags=["security", "sql-injection", "critical"]
    )

    print(f" Hestia contributed: {memory.id} + pattern {pattern.id}")

async def athena_contributes():
    """Athena: Share coordination knowledge"""
    memory_service = MemoryService()

    memory = await memory_service.create_memory(
        content="Coordination Pattern: Multi-agent features should follow "
                "Plan ’ Implement ’ Review ’ Document workflow with clear task dependencies",
        memory_type="knowledge",
        importance_score=0.9,
        tags=["coordination", "workflow", "best-practice", "athena"],
        metadata={
            "category": "coordination",
            "phases": ["Plan", "Implement", "Review", "Document"],
            "success_rate": 0.92
        },
        access_level="PUBLIC",
        namespace="trinitas-agents",
        agent_id="athena-conductor"
    )

    print(f" Athena contributed: {memory.id}")

# All agents contribute in parallel
asyncio.run(asyncio.gather(
    artemis_contributes(),
    hestia_contributes(),
    athena_contributes()
))
```

#### Step 2: Organize Knowledge with Tags

```python
async def organize_knowledge():
    """Categorize and tag knowledge for easy retrieval"""
    from src.services.memory_service import MemoryService

    service = MemoryService()

    # Define knowledge categories
    categories = {
        "performance": ["database", "caching", "indexing", "optimization"],
        "security": ["sql-injection", "xss", "authentication", "authorization"],
        "architecture": ["design-patterns", "microservices", "api-design"],
        "coordination": ["workflow", "task-management", "team-collaboration"]
    }

    # Search and re-tag knowledge
    for category, subcategories in categories.items():
        results = await service.search_memories(
            query=f"{category} knowledge and best practices",
            filters={"memory_type": "knowledge"},
            namespace="trinitas-agents",
            top_k=20
        )

        print(f"=Â {category.title()}: {len(results['results'])} knowledge items")
        for subcategory in subcategories:
            count = sum(1 for r in results['results'] if subcategory in r.get('tags', []))
            print(f"   - {subcategory}: {count} items")
        print()

asyncio.run(organize_knowledge())
```

#### Step 3: Create Knowledge Discovery Interface

```python
async def search_knowledge_base(question: str):
    """Semantic search across all agent contributions"""
    from src.services.memory_service import MemoryService
    from src.services.learning_service import LearningService

    memory_service = MemoryService()
    learning_service = LearningService()

    print(f"= Searching knowledge base: '{question}'\n")

    # Search memories
    memory_results = await memory_service.search_memories(
        query=question,
        filters={"memory_type": "knowledge"},
        namespace="trinitas-agents",
        top_k=5
    )

    # Search learning patterns
    pattern_results = await learning_service.search_patterns(
        query=question,
        namespace="trinitas-agents",
        limit=5
    )

    print("=Ú Knowledge Memories:")
    for i, memory in enumerate(memory_results["results"], 1):
        print(f"{i}. [{memory.get('tags', [])[0]}] {memory['content'][:100]}...")
        print(f"   By: {memory.get('agent_id', 'unknown')}, Importance: {memory.get('importance_score', 0):.1f}\n")

    print("\n=Ö Learning Patterns:")
    for i, pattern in enumerate(pattern_results, 1):
        print(f"{i}. {pattern['pattern_name']}")
        print(f"   Category: {pattern['category']}/{pattern.get('subcategory', 'general')}")
        print(f"   Success rate: {pattern['success_rate']:.0%}, Used: {pattern['usage_count']} times\n")

    return {
        "memories": memory_results["results"],
        "patterns": pattern_results
    }

# Example queries
questions = [
    "How to prevent SQL injection attacks?",
    "What are the best practices for database performance optimization?",
    "How to coordinate multi-agent feature development?"
]

for question in questions:
    results = asyncio.run(search_knowledge_base(question))
    print("-" * 80 + "\n")
```

#### Step 4: Generate Knowledge Base Report

```python
async def generate_kb_report():
    """Generate comprehensive knowledge base statistics"""
    from src.services.memory_service import MemoryService
    from src.services.learning_service import LearningService
    from src.mcp.tools.system_tools import get_memory_stats

    memory_service = MemoryService()
    learning_service = LearningService()

    # Get overall stats
    stats = await get_memory_stats()

    # Search all knowledge memories
    all_knowledge = await memory_service.search_memories(
        query="*",  # All
        filters={"memory_type": "knowledge"},
        namespace="trinitas-agents",
        top_k=1000
    )

    # Count by agent
    by_agent = {}
    by_category = {}
    for memory in all_knowledge["results"]:
        agent = memory.get("agent_id", "unknown")
        by_agent[agent] = by_agent.get(agent, 0) + 1

        tags = memory.get("tags", [])
        if tags:
            category = tags[0]
            by_category[category] = by_category.get(category, 0) + 1

    # Search all patterns
    all_patterns = await learning_service.search_patterns(
        query="*",
        namespace="trinitas-agents",
        limit=1000
    )

    report = f"""
# TMWS Knowledge Base Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Overall Statistics

- Total memories: {stats['total_memories']}
- Knowledge memories: {len(all_knowledge['results'])}
- Learning patterns: {len(all_patterns)}
- Active agents: {len(by_agent)}

## Knowledge by Agent

{chr(10).join(f'- {agent}: {count} contributions' for agent, count in sorted(by_agent.items(), key=lambda x: x[1], reverse=True))}

## Knowledge by Category

{chr(10).join(f'- {category}: {count} items' for category, count in sorted(by_category.items(), key=lambda x: x[1], reverse=True))}

## Top Learning Patterns (by success rate)

{chr(10).join(f'{i}. {p["pattern_name"]} ({p["success_rate"]:.0%} success, {p["usage_count"]} uses)'
              for i, p in enumerate(sorted(all_patterns, key=lambda x: x["success_rate"], reverse=True)[:10], 1))}

## Storage Performance

- Vector search latency (P95): {stats['mcp_metrics']['vector_search_latency_p95']:.1f}ms
- Metadata query latency (P95): {stats['mcp_metrics']['metadata_query_latency_p95']:.1f}ms
- ChromaDB hit rate: {stats['mcp_metrics']['chroma_hit_rate']:.1f}%

---

Knowledge base is growing! Keep contributing for collective intelligence.
"""

    print(report)

    # Store report as memory
    report_memory = await memory_service.create_memory(
        content=f"Knowledge Base Report: {len(all_knowledge['results'])} memories, "
                f"{len(all_patterns)} patterns, {len(by_agent)} agents",
        memory_type="report",
        importance_score=0.8,
        tags=["knowledge-base", "report", "statistics"],
        metadata={
            "full_report": report,
            "stats": stats,
            "by_agent": by_agent,
            "by_category": by_category
        },
        access_level="TEAM",
        namespace="trinitas-agents",
        agent_id="system"
    )

    print(f"\n Stored report: {report_memory.id}")

    return report

asyncio.run(generate_kb_report())
```

### Expected Outcome

- **Knowledge contributions** from 3+ agents (Artemis, Hestia, Athena)
- **Learning patterns created** (2+ patterns with proven success rates)
- **Knowledge organized** by categories and tags
- **Semantic search** retrieves relevant knowledge across all agents
- **KB report generated** with statistics and top patterns

### Team Collaboration

```python
# Any agent can search the shared knowledge base
results = await service.search_memories(
    query="What security best practices should I follow?",
    filters={"memory_type": "knowledge", "tags": ["security"]},
    namespace="trinitas-agents"
)
```

---

## Pattern 8: Production Deployment Workflow

**Scenario**: Complete deployment workflow with verification, documentation handoff, and monitoring setup.

### Tools Used

- **MCP Tools**: `verify_and_record`, `store_memory`, `get_agent_trust_score`, `create_task`
- **REST API**: None (uses MCP directly)
- **Learning Patterns**: Deployment checklists and rollback procedures

### Complete Workflow

#### Step 1: Pre-Deployment Verification

```python
#!/usr/bin/env python3
"""Hestia: Pre-deployment security and quality verification"""

import asyncio
from src.mcp.tools.trust_tools import verify_and_record, get_agent_trust_score

async def pre_deployment_checks():
    """Run comprehensive pre-deployment checks"""

    checks = []

    # 1. Verify test coverage claim
    test_check = await verify_and_record(
        agent_id="artemis-optimizer",
        claim_type="test_result",
        claim_content={
            "total_tests": 644,
            "passed": 644,
            "failed": 0,
            "coverage": 90.5
        },
        verification_command="pytest tests/ -v --cov=src --cov-report=term-missing",
        verified_by_agent_id="hestia-auditor"
    )
    checks.append(("Test Coverage", test_check["accurate"]))

    # 2. Verify security scan claim
    security_check = await verify_and_record(
        agent_id="hestia-auditor",
        claim_type="security_finding",
        claim_content={
            "vulnerabilities_found": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "scan_tool": "bandit + semgrep"
        },
        verification_command="bandit -r src/ -f json && semgrep --config=auto src/",
        verified_by_agent_id="hestia-auditor"
    )
    checks.append(("Security Scan", security_check["accurate"]))

    # 3. Verify performance benchmarks
    perf_check = await verify_and_record(
        agent_id="artemis-optimizer",
        claim_type="performance_metric",
        claim_content={
            "vector_search_p95": 10,  # ms
            "metadata_query_p95": 20,  # ms
            "api_response_p95": 200  # ms
        },
        verification_command="pytest tests/performance/ -v",
        verified_by_agent_id="artemis-optimizer"
    )
    checks.append(("Performance", perf_check["accurate"]))

    # 4. Check agent trust scores
    artemis_trust = await get_agent_trust_score("artemis-optimizer")
    hestia_trust = await get_agent_trust_score("hestia-auditor")

    checks.append(("Artemis Trust", artemis_trust["trust_score"] >= 0.8))
    checks.append(("Hestia Trust", hestia_trust["trust_score"] >= 0.8))

    # Print results
    print(" Pre-Deployment Verification:\n")
    all_passed = True
    for check_name, passed in checks:
        status = " PASS" if passed else "=4 FAIL"
        print(f"   {status}: {check_name}")
        all_passed = all_passed and passed

    print(f"\n{' All checks passed - Ready to deploy' if all_passed else '=4 Deployment blocked - Fix issues'}")

    return all_passed

deployment_ready = asyncio.run(pre_deployment_checks())
```

#### Step 2: Create Deployment Task

```python
async def create_deployment_task():
    """Athena creates deployment task if all checks pass"""
    from src.mcp.tools.task_tools import create_task
    from src.services.memory_service import MemoryService

    if not deployment_ready:
        print("   Deployment blocked - skipping task creation")
        return

    # Create deployment checklist
    checklist = """
Deployment Checklist:

Pre-Deployment:
- [x] All tests passing (644/644)
- [x] Security scan clean (0 vulnerabilities)
- [x] Performance benchmarks met
- [x] Agent trust scores verified
- [ ] Database migrations reviewed
- [ ] Environment variables configured
- [ ] Backup strategy confirmed

Deployment:
- [ ] Stop application
- [ ] Run database migrations (alembic upgrade head)
- [ ] Deploy new code
- [ ] Restart application
- [ ] Verify health check endpoint

Post-Deployment:
- [ ] Smoke tests
- [ ] Monitor error rates (15 minutes)
- [ ] Verify key metrics
- [ ] Update documentation
- [ ] Notify team

Rollback Plan:
- [ ] Database rollback: alembic downgrade -1
- [ ] Code rollback: git checkout <previous-tag>
- [ ] Restore from backup (if needed)
"""

    task = await create_task(
        title="Deploy TMWS v2.3.0 to Production",
        description=checklist,
        priority="critical",
        assigned_agent_id="athena-conductor",
        estimated_duration=120,  # 2 hours
        metadata={
            "deployment": True,
            "version": "v2.3.0",
            "pre_checks_passed": True
        }
    )

    print(f" Created deployment task: {task['id']}")
    print(f"   Priority: {task['priority']}")
    print(f"   Estimated duration: {task['estimated_duration']} minutes\n")

    # Store deployment plan
    memory_service = MemoryService()
    plan_memory = await memory_service.create_memory(
        content="Deployment Plan: TMWS v2.3.0 - Pre-checks passed, "
                "deployment scheduled with rollback plan",
        memory_type="deployment-plan",
        importance_score=1.0,
        tags=["deployment", "production", "v2.3.0"],
        metadata={
            "version": "v2.3.0",
            "checklist": checklist,
            "pre_checks": "PASSED",
            "estimated_duration": 120
        },
        access_level="TEAM",
        namespace="trinitas-agents",
        agent_id="athena-conductor"
    )

    print(f" Stored deployment plan: {plan_memory.id}")

    return task

asyncio.run(create_deployment_task())
```

#### Step 3: Execute Deployment (Simulated)

```bash
#!/bin/bash
# Deployment script (executed manually or via CI/CD)

set -e  # Exit on error

echo "=€ Starting TMWS v2.3.0 Deployment"
echo "======================================"

# Stop application
echo "ø  Stopping application..."
systemctl stop tmws-api
echo " Application stopped"

# Backup database
echo "=¾ Creating database backup..."
cp data/tmws.db data/tmws.db.backup.$(date +%Y%m%d_%H%M%S)
echo " Database backed up"

# Run migrations
echo "= Running database migrations..."
alembic upgrade head
echo " Migrations applied"

# Deploy new code
echo "=æ Deploying new code..."
git pull origin main
git checkout v2.3.0
echo " Code deployed"

# Install dependencies
echo "=Ú Installing dependencies..."
pip install -e .
echo " Dependencies installed"

# Restart application
echo "= Starting application..."
systemctl start tmws-api
echo " Application started"

# Health check
echo "<å Running health check..."
sleep 5
response=$(curl -s http://localhost:8000/health)
if echo "$response" | grep -q '"status":"healthy"'; then
    echo " Health check passed"
else
    echo "=4 Health check failed - initiating rollback"
    systemctl stop tmws-api
    git checkout v2.2.7
    alembic downgrade -1
    systemctl start tmws-api
    exit 1
fi

echo ""
echo " Deployment Complete: TMWS v2.3.0"
echo "======================================"
```

#### Step 4: Post-Deployment Monitoring

```python
async def post_deployment_monitoring():
    """Monitor application health after deployment"""
    import time
    import requests
    from src.services.memory_service import MemoryService

    print("=@ Starting post-deployment monitoring (15 minutes)...\n")

    start_time = time.time()
    metrics = {
        "health_checks": [],
        "error_count": 0,
        "avg_response_time": []
    }

    while time.time() - start_time < 900:  # 15 minutes
        try:
            # Health check
            response = requests.get("http://localhost:8000/health", timeout=5)
            health = response.json()

            metrics["health_checks"].append({
                "timestamp": time.time(),
                "status": health.get("status"),
                "response_time": response.elapsed.total_seconds() * 1000
            })

            print(f"[{time.strftime('%H:%M:%S')}] Health: {health.get('status')}, "
                  f"Response: {response.elapsed.total_seconds() * 1000:.1f}ms")

        except Exception as e:
            metrics["error_count"] += 1
            print(f"[{time.strftime('%H:%M:%S')}]    Error: {e}")

        time.sleep(60)  # Check every minute

    # Calculate metrics
    successful_checks = [c for c in metrics["health_checks"] if c["status"] == "healthy"]
    success_rate = len(successful_checks) / len(metrics["health_checks"]) if metrics["health_checks"] else 0
    avg_response = sum(c["response_time"] for c in successful_checks) / len(successful_checks) if successful_checks else 0

    print(f"\n=Ê Monitoring Summary:")
    print(f"   Success rate: {success_rate:.1%}")
    print(f"   Avg response time: {avg_response:.1f}ms")
    print(f"   Error count: {metrics['error_count']}\n")

    # Store monitoring results
    memory_service = MemoryService()
    monitoring_memory = await memory_service.create_memory(
        content=f"Deployment Monitoring: TMWS v2.3.0 - Success rate {success_rate:.1%}, "
                f"Avg response {avg_response:.1f}ms, {metrics['error_count']} errors",
        memory_type="deployment-monitoring",
        importance_score=0.95,
        tags=["deployment", "monitoring", "production", "v2.3.0"],
        metadata={
            "version": "v2.3.0",
            "success_rate": success_rate,
            "avg_response_time": avg_response,
            "error_count": metrics["error_count"],
            "duration": 900
        },
        access_level="TEAM",
        namespace="trinitas-agents",
        agent_id="athena-conductor"
    )

    print(f" Stored monitoring results: {monitoring_memory.id}")

    if success_rate >= 0.99 and metrics["error_count"] == 0:
        print("\n Deployment successful - All metrics green!")
    else:
        print("\n   Deployment needs attention - Review metrics")

    return metrics

# asyncio.run(post_deployment_monitoring())
```

#### Step 5: Documentation Handoff

```python
async def documentation_handoff():
    """Muses generates deployment documentation"""
    from src.services.memory_service import MemoryService

    memory_service = MemoryService()

    # Search for deployment-related memories
    deployment_memories = await memory_service.search_memories(
        query="TMWS v2.3.0 deployment plan monitoring results",
        filters={"tags": ["deployment"]},
        namespace="trinitas-agents",
        top_k=10
    )

    # Generate deployment documentation
    docs = f"""
# TMWS v2.3.0 Deployment Report

## Deployment Summary

- **Version**: v2.3.0
- **Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Coordinator**: Athena (Harmonious Conductor)
- **Duration**: 2 hours (estimated)

## Pre-Deployment Verification

 All tests passing (644/644)
 Security scan clean (0 vulnerabilities)
 Performance benchmarks met
 Agent trust scores verified (Artemis: 0.92, Hestia: 0.95)

## Deployment Steps

1. Application stopped
2. Database backed up
3. Migrations applied (alembic upgrade head)
4. New code deployed (git checkout v2.3.0)
5. Dependencies installed
6. Application restarted
7. Health check passed 

## Post-Deployment Monitoring

- Success rate: 99.9%
- Avg response time: 12.3ms
- Error count: 0
- Monitoring duration: 15 minutes

## Rollback Plan (Not Needed)

If rollback required:
1. Stop application
2. Restore database: cp data/tmws.db.backup.<timestamp> data/tmws.db
3. Rollback code: git checkout v2.2.7
4. Rollback migrations: alembic downgrade -1
5. Restart application

## Key Learnings

{chr(10).join(f'- {m["content"]}' for m in deployment_memories["results"][:3])}

## Next Steps

- Monitor production for 24 hours
- Update team documentation
- Schedule retrospective meeting

---

Deployment executed successfully. System is stable.
"""

    # Store deployment documentation
    doc_memory = await memory_service.create_memory(
        content="Deployment Documentation: TMWS v2.3.0 - Complete deployment report "
                "with verification, monitoring, and rollback plan",
        memory_type="documentation",
        importance_score=1.0,
        tags=["deployment", "documentation", "v2.3.0", "muses"],
        metadata={
            "version": "v2.3.0",
            "full_documentation": docs,
            "status": "successful"
        },
        access_level="TEAM",
        namespace="trinitas-agents",
        agent_id="muses-documenter"
    )

    print("=Ý Deployment Documentation:\n")
    print(docs)
    print(f"\n Stored documentation: {doc_memory.id}")

    # Save to filesystem
    with open("docs/deployments/DEPLOYMENT_v2.3.0.md", "w") as f:
        f.write(docs)

    print(" Saved to: docs/deployments/DEPLOYMENT_v2.3.0.md")

    return doc_memory

asyncio.run(documentation_handoff())
```

### Expected Outcome

- **Pre-deployment checks completed** (5 verifications)
- **Deployment task created** with comprehensive checklist
- **Deployment executed** successfully with health check
- **15-minute monitoring** (99.9% success rate, 0 errors)
- **Documentation generated** with rollback plan and learnings

### Team Collaboration

```python
# Future deployments can reference this successful deployment
results = await service.search_memories(
    query="How was TMWS v2.3.0 deployed to production?",
    filters={"tags": ["deployment", "v2.3.0"]},
    namespace="trinitas-agents"
)
```

---

## Best Practices

### 1. Memory Storage

**Do's**:
-  Use meaningful `memory_type` values (daily-standup, security-audit, optimization, etc.)
-  Set appropriate `importance_score` (0.0-1.0)
  - 1.0: Critical security findings, deployment plans
  - 0.8-0.9: Important optimizations, feature implementations
  - 0.6-0.7: Daily progress, code reviews
  - 0.4-0.5: Minor findings, routine tasks
-  Use descriptive tags for categorization
-  Set correct `access_level`:
  - `PRIVATE`: Personal notes, credentials
  - `TEAM`: Team collaboration (default)
  - `PUBLIC`: Shared knowledge, patterns
  - `SYSTEM`: System announcements
-  Include rich metadata for context

**Don'ts**:
- L Don't store secrets or credentials in memories (use environment variables)
- L Don't use generic `memory_type` like "memory" or "data"
- L Don't skip `namespace` (required for multi-tenant isolation)
- L Don't set all memories to 1.0 importance (defeats ranking)

### 2. Semantic Search

**Do's**:
-  Use natural language queries ("What did I work on this week?")
-  Combine with filters for precision:
  ```python
  results = await service.search_memories(
      query="Database optimization",
      filters={"tags": ["performance"], "agent_id": "artemis-optimizer"},
      top_k=10
  )
  ```
-  Use `top_k` to limit results (default: 10)
-  Expect latency: 5-20ms P95 (semantic search)

**Don'ts**:
- L Don't use exact string matching (use semantic similarity)
- L Don't query without `namespace` (security risk)
- L Don't fetch all memories at once (`top_k=1000`)

### 3. Learning Patterns

**Do's**:
-  Create patterns from proven successes (success_rate >= 0.8)
-  Include:
  - Problem description
  - Solution steps
  - Example code (bad vs good)
  - When to apply
  - Cost and risk assessment
-  Record pattern usage with `use_pattern()`
-  Share proven patterns (`access_level="PUBLIC"`)
-  Version patterns (use `parent_pattern_id` for updates)

**Don'ts**:
- L Don't create patterns without validation
- L Don't skip `pattern_data` (critical for reuse)
- L Don't forget to update `success_rate` after usage
- L Don't create duplicate patterns (search first)

### 4. Trust Verification

**Do's**:
-  Verify agent claims with `verify_and_record()`:
  ```python
  result = await verify_and_record(
      agent_id="artemis-optimizer",
      claim_type="test_result",
      claim_content={"passed": 100, "failed": 0},
      verification_command="pytest tests/ -v"
  )
  ```
-  Update trust scores over time
-  Check `requires_verification` flag:
  ```python
  score_info = await get_agent_trust_score("artemis-optimizer")
  if score_info["requires_verification"]:
      # Verify claim before accepting
  ```

**Don'ts**:
- L Don't skip verification for critical claims (security, deployment)
- L Don't trust low-score agents (<0.5) without verification

### 5. REST API Integration

**Do's**:
-  Use REST API for external MCP server connections only
-  Generate JWT token with proper expiration:
  ```python
  token = jwt.encode(
      {"sub": agent_id, "exp": datetime.utcnow() + timedelta(hours=1)},
      settings.secret_key,
      algorithm="HS256"
  )
  ```
-  Always disconnect after use:
  ```python
  requests.delete(
      f"http://localhost:8000/api/v1/mcp/connections/{connection_id}",
      headers=headers
  )
  ```
-  Handle rate limiting (10-100 req/min)

**Don'ts**:
- L Don't use REST API for TMWS memory operations (use MCP tools)
- L Don't share JWT tokens between agents
- L Don't forget to disconnect (connection leak)

### 6. Team Coordination

**Do's**:
-  Create tasks with clear dependencies:
  ```python
  task = await create_task(
      title="Security Review",
      metadata={"depends_on": implementation_task_id}
  )
  ```
-  Use `get_agent_status()` for monitoring
-  Store coordination plans with high importance
-  Search past coordination patterns for guidance

**Don'ts**:
- L Don't create tasks without assigned agent
- L Don't skip `estimated_duration` (impacts planning)
- L Don't create circular dependencies

### 7. Performance

**Do's**:
-  Batch operations when possible:
  ```python
  patterns = await service.batch_create_patterns(pattern_list)
  ```
-  Use appropriate `top_k` for searches (10-20)
-  Monitor latency with `get_memory_stats()`
-  Set TTL for temporary memories:
  ```python
  await service.create_memory(..., ttl_days=7)
  ```

**Don'ts**:
- L Don't create thousands of memories without cleanup strategy
- L Don't fetch full memories when only metadata needed
- L Don't skip database indexes (causes slow queries)

---

## Common Pitfalls

### Pitfall 1: Namespace Confusion

**Problem**: Using wrong namespace or skipping namespace parameter

**Impact**: Cross-tenant data leakage (security vulnerability)

**Solution**:
```python
#  CORRECT - Explicit namespace
memory = await service.create_memory(
    content="...",
    namespace="trinitas-agents",  # Always specify
    agent_id="artemis-optimizer"
)

# L WRONG - Missing namespace (will use default or fail)
memory = await service.create_memory(
    content="...",
    agent_id="artemis-optimizer"
)
```

### Pitfall 2: Over-Trusting Agent Claims

**Problem**: Accepting agent claims without verification

**Impact**: Inaccurate metrics, false confidence

**Solution**:
```python
#  CORRECT - Verify before accepting
result = await verify_and_record(
    agent_id="artemis-optimizer",
    claim_type="test_result",
    claim_content=claim,
    verification_command="pytest tests/ -v"
)

if result["accurate"]:
    # Accept claim
else:
    # Reject and request re-work
```

### Pitfall 3: Memory Pollution

**Problem**: Storing too many low-value memories without cleanup

**Impact**: Degraded search quality, storage bloat

**Solution**:
```python
#  CORRECT - Set TTL for temporary memories
memory = await service.create_memory(
    content="Daily standup",
    ttl_days=30,  # Auto-delete after 30 days
    importance_score=0.5
)

#  Use prune_expired_memories() regularly
await prune_expired_memories(
    agent_id="system",
    namespace="trinitas-agents",
    dry_run=False
)
```

### Pitfall 4: Forgetting to Disconnect MCP Connections

**Problem**: Creating MCP connections without cleanup

**Impact**: Connection leak, resource exhaustion

**Solution**:
```python
#  CORRECT - Use try/finally for cleanup
connection_id = None
try:
    # Create connection
    response = requests.post(...)
    connection_id = response.json()["id"]

    # Use connection
    result = requests.post(...)

finally:
    # Always disconnect
    if connection_id:
        requests.delete(
            f"http://localhost:8000/api/v1/mcp/connections/{connection_id}",
            headers=headers
        )
```

### Pitfall 5: Ignoring Rate Limits

**Problem**: Exceeding REST API rate limits (10-100 req/min)

**Impact**: 429 errors, blocked requests

**Solution**:
```python
import time
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

#  CORRECT - Implement retry with exponential backoff
session = requests.Session()
retry = Retry(
    total=5,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504]
)
adapter = HTTPAdapter(max_retries=retry)
session.mount("http://", adapter)
session.mount("https://", adapter)
```

### Pitfall 6: Poor Learning Pattern Structure

**Problem**: Creating patterns without sufficient detail

**Impact**: Patterns are not reusable

**Solution**:
```python
#  CORRECT - Comprehensive pattern
pattern = await service.create_pattern(
    pattern_name="sql_injection_prevention",
    category="security",
    pattern_data={
        "description": "Prevent SQL injection",
        "problem": "User input in SQL WHERE clause",
        "solution": "Use bindparams()",
        "example_bad": "f\"WHERE value = '{user_input}'\"",
        "example_good": "text('WHERE value = :input').bindparams(input=user_input)",
        "when_to_apply": "Any dynamic SQL query",
        "cost": "Low",
        "risk": "Low",
        "cvss_prevented": 9.8,
        "references": ["OWASP A03:2021", "CWE-89"]
    }
)

# L WRONG - Minimal pattern (not reusable)
pattern = await service.create_pattern(
    pattern_name="security_fix",
    category="security",
    pattern_data={"description": "Fix security issue"}
)
```

### Pitfall 7: Not Monitoring Trust Scores

**Problem**: Ignoring declining agent trust scores

**Impact**: Accepting inaccurate work without verification

**Solution**:
```python
#  CORRECT - Check trust score before accepting claims
score_info = await get_agent_trust_score("artemis-optimizer")

if score_info["trust_score"] < 0.7:
    print(f"   Agent trust is low ({score_info['trust_score']:.0%})")
    print("   Verification required for all claims")

    # Require verification
    result = await verify_and_record(...)
else:
    # Can accept claims without verification
    pass
```

---

## Next Steps

After mastering these 8 integration patterns, explore:

1. **Advanced Security**: `docs/SECURITY_GUIDE.md`
   - P0-1 namespace isolation implementation
   - JWT authentication best practices
   - Rate limiting strategies

2. **Performance Tuning**: `docs/PERFORMANCE_TUNING.md` (planned)
   - Database optimization techniques
   - Vector search tuning
   - Caching strategies

3. **Production Deployment**: `docs/PRODUCTION_DEPLOYMENT.md` (planned)
   - Monitoring and alerting
   - Backup and recovery
   - Scaling strategies

4. **Custom MCP Tools**: `docs/CUSTOM_MCP_TOOLS.md` (planned)
   - Create your own MCP tools
   - Tool registration
   - Tool testing

---

## Support & Community

- **Documentation**: `docs/` directory
- **Quick Start**: `docs/QUICK_START_GUIDE.md`
- **API Reference**: `docs/REST_API_GUIDE.md` + `docs/MCP_TOOLS_REFERENCE.md`
- **Learning Patterns**: `docs/LEARNING_PATTERN_API.md`
- **GitHub Issues**: Report bugs and feature requests
- **Development Chat**: (configure team chat here)

---

**Document Author**: Athena (Harmonious Conductor)
**Contributors**: Artemis, Hestia, Hera, Eris, Muses
**Reviewed By**: Hera, Eris
**Last Updated**: 2025-11-14
**Status**: Production-ready
**Version**: 1.0.0
