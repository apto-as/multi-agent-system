# Pattern Execution Service - Integration Test Plan
**Coordinator**: Eris (Tactical Coordinator)
**Version**: TMWS v2.2.0
**Date**: 2025-01-09
**Status**: Ready for Execution

## Executive Summary

This document outlines the comprehensive integration testing strategy for the Pattern Execution Service in TMWS v2.2.0. The testing focuses on identifying integration failures that occur only under production-like conditions and validating the 40% token reduction target.

### Strategic Goals
1. **Multi-Agent Scalability**: Validate 50+ concurrent agent sessions
2. **MCP Protocol Compliance**: Ensure backward compatibility with existing tools
3. **Database Performance**: Verify pgvector query performance under load
4. **Cache Coherency**: Test Redis cluster behavior and failover
5. **End-to-End Latency**: Maintain P95 < 250ms target
6. **Throughput**: Sustain 100+ RPS with 95%+ success rate

---

## 1. Multi-Agent Concurrency Testing

### Test Scenarios

#### 1.1 50+ Simultaneous Agent Sessions
**Objective**: Validate concurrent pattern execution without deadlocks or race conditions

**Test Configuration**:
- **Agents**: 50 concurrent sessions
- **Requests per agent**: 3-7 randomized
- **Query types**: Mixed (infrastructure, memory, hybrid)
- **Duration**: ~30 seconds

**Success Criteria**:
- ✅ Success rate ≥ 95%
- ✅ No deadlocks or race conditions detected
- ✅ Average latency < 300ms under load
- ✅ Cache hit rate > 70%

**Key Metrics**:
```python
{
    "total_requests": 250-350,
    "success_rate": ">= 95%",
    "avg_latency_ms": "< 300",
    "cache_hit_rate": "> 70%",
    "deadlocks": 0,
    "race_conditions": 0
}
```

**Failure Modes to Test**:
- Agent registration conflicts
- Concurrent cache updates
- Database connection pool exhaustion
- Memory leak under sustained load

#### 1.2 Cache Coherency Under Concurrent Updates
**Objective**: Verify cache consistency across multiple agents

**Test Configuration**:
- **Agents**: 20 concurrent
- **Pattern**: Same pattern executed simultaneously
- **Cache**: Enabled with TTL

**Success Criteria**:
- ✅ All agents receive coherent results
- ✅ Cache hit rate > 70% after warm-up
- ✅ No stale data served

**Validation**:
- Pattern name consistency across all responses
- Cache invalidation propagates correctly
- No phantom reads or dirty writes

#### 1.3 Database Connection Pool Stress
**Objective**: Test connection pool behavior when requests exceed pool size

**Test Configuration**:
- **Pool size**: 10 connections
- **Max overflow**: 20 connections
- **Concurrent requests**: 50 (exceeds pool)
- **Pattern type**: Memory (requires DB access)

**Success Criteria**:
- ✅ Zero database exceptions
- ✅ Graceful queuing when pool exhausted
- ✅ Success rate ≥ 96%
- ✅ Total execution time < 60s

**Monitoring**:
- Connection acquisition time
- Pool utilization percentage
- Queue depth during peak load
- Connection leak detection

---

## 2. WebSocket MCP Integration Testing

### Test Scenarios

#### 2.1 Pattern Execution via WebSocket MCP
**Objective**: Validate MCP protocol compliance for pattern execution

**Test Flow**:
1. Establish WebSocket connection
2. Receive welcome message
3. Send pattern execution request
4. Validate MCP response structure
5. Verify result contains required fields

**MCP Message Format**:
```json
{
    "jsonrpc": "2.0",
    "id": "pattern-exec-1",
    "method": "execute_pattern",
    "params": {
        "query": "execute tool test",
        "execution_mode": "balanced",
        "use_cache": true
    }
}
```

**Expected Response**:
```json
{
    "jsonrpc": "2.0",
    "id": "pattern-exec-1",
    "result": {
        "success": true,
        "pattern_name": "execute_tool",
        "execution_time_ms": 45.2,
        "tokens_used": 30,
        "cache_hit": false
    }
}
```

**Success Criteria**:
- ✅ MCP protocol compliance (jsonrpc: 2.0)
- ✅ Request-response ID matching
- ✅ Proper error propagation
- ✅ Session isolation maintained

#### 2.2 Backward Compatibility with Existing MCP Tools
**Objective**: Ensure pattern execution doesn't break existing tools

**Test Cases**:
- Memory operations (store_memory, recall_memory)
- Task management (create_task, update_task)
- Workflow execution (execute_workflow)
- Agent operations (switch_agent, get_agent_info)

**Success Criteria**:
- ✅ All existing tools function without regression
- ✅ Pattern execution is purely additive
- ✅ No interference with existing MCP handlers

#### 2.3 Multi-Client WebSocket Pattern Execution
**Objective**: Test concurrent WebSocket clients executing patterns

**Test Configuration**:
- **Clients**: 10 simultaneous WebSocket connections
- **Same agent**: All connections from one agent (multi-terminal)
- **Pattern requests**: Each client sends unique request

**Success Criteria**:
- ✅ All clients receive responses
- ✅ Session isolation maintained
- ✅ No message crosstalk between clients
- ✅ Success rate ≥ 80% (8/10 clients)

---

## 3. Database Integration Testing

### Test Scenarios

#### 3.1 pgvector Query Performance Under Load
**Objective**: Validate vector search performance with concurrent queries

**Test Configuration**:
- **Concurrent queries**: 50 vector similarity searches
- **Pattern type**: Memory (triggers vector search)
- **Cache**: Disabled to force DB access
- **Dimensions**: 384 (MiniLM-L6-v2)

**Performance Targets**:
```python
{
    "avg_latency_ms": "< 200",
    "p95_latency_ms": "< 500",
    "success_rate": ">= 96%",
    "queries_per_second": "> 10"
}
```

**Index Validation**:
- Verify IVFFlat index usage
- Check index scan vs sequential scan ratio
- Monitor query plan execution

**SQL Query Pattern**:
```sql
SELECT
    id, content, embedding <-> %s::vector AS distance
FROM memory_embeddings
WHERE distance < 0.3
ORDER BY distance
LIMIT 10;
```

#### 3.2 Transaction Isolation During Pattern Execution
**Objective**: Test PostgreSQL serializable isolation under concurrent updates

**Test Scenarios**:
- Concurrent writes to pattern results
- Read-after-write consistency
- Deadlock detection and recovery
- Rollback handling

**Success Criteria**:
- ✅ No dirty reads
- ✅ Serializable isolation maintained
- ✅ Deadlocks handled gracefully
- ✅ Zero data corruption

#### 3.3 Migration Testing (v2.0 → v2.2)
**Objective**: Validate database migration from v2.0 to v2.2

**Migration Steps**:
1. Backup v2.0 database
2. Run migration scripts
3. Verify schema changes
4. Test pattern execution on migrated data

**Schema Changes to Validate**:
- New pattern_executions table
- Updated indexes for performance
- Backward compatibility with existing data

---

## 4. Redis Cache Integration Testing

### Test Scenarios

#### 4.1 Cache Invalidation Propagation
**Objective**: Verify cache invalidation across all consumers

**Test Flow**:
1. Execute pattern → Cache miss
2. Execute again → Cache hit
3. Invalidate cache entry
4. Execute again → Cache miss (validation)

**Success Criteria**:
- ✅ Invalidation propagates immediately
- ✅ No stale data served after invalidation
- ✅ Cache consistency maintained

#### 4.2 Redis Cluster Failover
**Objective**: Test graceful degradation when Redis unavailable

**Scenario**: Simulate Redis connection loss

**Expected Behavior**:
- Graceful fallback to local cache
- Continued pattern execution (degraded mode)
- No service interruption

**Success Criteria**:
- ✅ Execution succeeds without Redis
- ✅ Local cache used as fallback
- ✅ Automatic reconnection when Redis available

#### 4.3 Multi-Instance Cache Coherency
**Objective**: Validate cache consistency across multiple TMWS instances

**Test Configuration**:
- **Instances**: 3 TMWS servers
- **Shared Redis**: Single Redis cluster
- **Pattern**: Same pattern executed on different instances

**Success Criteria**:
- ✅ Cache updates visible across all instances
- ✅ No cache duplication
- ✅ Consistent invalidation

---

## 5. Performance Integration Testing

### Test Scenarios

#### 5.1 End-to-End Latency Target
**Objective**: Measure complete request pipeline latency

**Pipeline**: Client → WebSocket → Pattern Router → Executor → Database → Response

**Test Configuration**:
- **Requests**: 100 sequential
- **Execution mode**: Balanced
- **Cache**: Enabled

**Performance Targets**:
```python
{
    "avg_latency_ms": "< 150",
    "p50_latency_ms": "< 100",
    "p95_latency_ms": "< 250",
    "p99_latency_ms": "< 400"
}
```

**Latency Breakdown**:
- WebSocket overhead: ~5ms
- Pattern matching: ~10ms
- Execution: ~50-150ms (depending on type)
- Database query: ~30ms (if applicable)
- Response serialization: ~5ms

#### 5.2 Throughput Test - 100+ RPS
**Objective**: Validate sustained throughput at production levels

**Test Configuration**:
- **Duration**: 10 seconds
- **Target RPS**: 100
- **Total requests**: 1000
- **Execution mode**: Fast (infrastructure-only)
- **Cache**: Enabled

**Success Criteria**:
- ✅ Actual RPS ≥ 90
- ✅ Success rate ≥ 95%
- ✅ No performance degradation over time
- ✅ CPU usage < 80%

**Load Pattern**:
```
Seconds 0-2:   Ramp-up (20 → 100 RPS)
Seconds 2-8:   Sustained (100 RPS)
Seconds 8-10:  Ramp-down (100 → 20 RPS)
```

#### 5.3 Token Reduction Validation
**Objective**: Confirm 40% token reduction vs full LLM inference

**Test Cases**:
| Query Type | Pattern Tokens | LLM Baseline | Reduction |
|-----------|----------------|--------------|-----------|
| Infrastructure | 30 | 400 | 92.5% |
| Memory | 80 | 400 | 80.0% |
| Hybrid | 150 | 400 | 62.5% |

**Overall Target**: Average 40% reduction across all query types

**Success Criteria**:
- ✅ Total reduction ≥ 40%
- ✅ Pattern token usage within ±10% of targets
- ✅ Hybrid decision router accuracy > 80%

---

## 6. Error Recovery Integration Testing

### Test Scenarios

#### 6.1 Database Connection Loss Recovery
**Objective**: Test recovery when database becomes unavailable

**Scenario**:
1. Execute pattern successfully
2. Simulate database disconnect
3. Attempt pattern execution
4. Reconnect database
5. Retry pattern execution

**Expected Behavior**:
- Graceful error propagation
- Automatic retry logic
- Circuit breaker activation
- Service recovery when DB available

**Success Criteria**:
- ✅ No service crash
- ✅ Error message indicates DB unavailability
- ✅ Automatic recovery on reconnect

#### 6.2 Pattern Execution Timeout Handling
**Objective**: Validate timeout enforcement for long-running patterns

**Test Configuration**:
- **Timeout threshold**: 5 seconds
- **Slow pattern**: Simulated delay > 5s

**Expected Behavior**:
- Pattern execution cancelled after timeout
- Timeout error propagated to client
- Resources cleaned up properly

**Success Criteria**:
- ✅ Timeout detected and enforced
- ✅ No resource leaks
- ✅ Client receives timeout error

#### 6.3 Workflow Integration Error Handling
**Objective**: Test error propagation in hybrid workflow + pattern execution

**Scenario**:
1. Hybrid workflow triggers pattern execution
2. Pattern execution fails
3. Workflow should handle failure gracefully
4. Learning system records failure

**Success Criteria**:
- ✅ Workflow error handling activated
- ✅ LLM fallback triggered on pattern failure
- ✅ Failure recorded in learning system

---

## 7. Automation and CI/CD Integration

### Test Automation Script

**Location**: `scripts/run_integration_tests.sh`

**Usage**:
```bash
# Run all integration tests
./scripts/run_integration_tests.sh

# Run specific test suite
./scripts/run_integration_tests.sh --suite=concurrency

# Run with custom timeout
TEST_TIMEOUT=1200 ./scripts/run_integration_tests.sh

# Generate detailed report
./scripts/run_integration_tests.sh --report=detailed
```

### CI/CD Pipeline Integration

**GitHub Actions Workflow**:
```yaml
name: Integration Tests - Pattern Execution

on:
  pull_request:
    paths:
      - 'src/services/pattern_execution_service.py'
      - 'tests/integration/test_pattern_integration.py'

jobs:
  integration-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: pgvector/pgvector:pg15
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s

      redis:
        image: redis:7-alpine
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s

    steps:
      - uses: actions/checkout@v3
      - name: Run Integration Tests
        run: ./scripts/run_integration_tests.sh
      - name: Upload Test Reports
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: integration-test-reports
          path: test-reports/integration/
```

---

## 8. Team Coordination Checklist

### Pre-Test Coordination

**Infrastructure Team** (Hera):
- [ ] PostgreSQL 15+ with pgvector running
- [ ] Redis cluster configured and accessible
- [ ] Test database created and migrated
- [ ] Connection pool configuration validated
- [ ] Monitoring dashboards set up

**Development Team** (Artemis):
- [ ] Pattern execution service deployed to test environment
- [ ] Pattern definitions loaded in registry
- [ ] Cache configuration validated
- [ ] Performance instrumentation enabled
- [ ] Debug logging configured

**Security Team** (Hestia):
- [ ] Test environment isolated from production
- [ ] Test credentials rotated
- [ ] Audit logging enabled
- [ ] Security scanning completed

**Documentation Team** (Muses):
- [ ] Test plan reviewed and approved
- [ ] Expected results documented
- [ ] Failure remediation steps prepared
- [ ] Report templates ready

### During Test Execution

**Eris (Tactical Coordinator)**:
- [ ] Monitor test progress in real-time
- [ ] Track performance metrics against targets
- [ ] Coordinate issue triage if failures occur
- [ ] Ensure test environment stability
- [ ] Manage test data isolation

**Communication Protocol**:
- **Success**: Update team chat with green status
- **Partial failure**: Immediate notification to relevant team
- **Critical failure**: Escalate to Hera for strategic decision

### Post-Test Coordination

**Analysis Phase**:
- [ ] Review all test reports (Artemis)
- [ ] Analyze performance metrics (Hera)
- [ ] Security assessment (Hestia)
- [ ] Document findings (Muses)

**Remediation Phase**:
- [ ] Prioritize failures by severity (Eris)
- [ ] Assign fixes to appropriate team members (Athena)
- [ ] Set remediation timeline (Hera)
- [ ] Track fix implementation (Eris)

**Sign-off**:
- [ ] All critical tests passing
- [ ] Performance targets met
- [ ] Security review completed
- [ ] Documentation updated
- [ ] Ready for production deployment

---

## 9. Performance Benchmarks

### Baseline Performance Targets

| Metric | Target | Critical Threshold |
|--------|--------|-------------------|
| Pattern Matching | < 10ms | < 20ms |
| Infrastructure Execution | < 50ms | < 100ms |
| Memory Execution | < 100ms | < 200ms |
| Hybrid Execution | < 200ms | < 400ms |
| Cache Hit Rate | > 80% | > 60% |
| Success Rate | > 95% | > 90% |
| Throughput (RPS) | > 100 | > 50 |
| P95 Latency | < 250ms | < 500ms |
| Token Reduction | ≥ 40% | ≥ 30% |

### Resource Utilization Targets

| Resource | Normal | Warning | Critical |
|----------|--------|---------|----------|
| CPU Usage | < 60% | 60-80% | > 80% |
| Memory | < 1GB | 1-2GB | > 2GB |
| DB Connections | < 20 | 20-25 | > 25 |
| Redis Memory | < 500MB | 500MB-1GB | > 1GB |

---

## 10. Risk Mitigation

### Identified Risks and Mitigation Strategies

#### Risk 1: Database Connection Pool Exhaustion
**Severity**: High
**Probability**: Medium
**Mitigation**:
- Connection timeout configuration
- Pool size optimization (10 base + 20 overflow)
- Connection leak detection
- Graceful degradation to local cache

#### Risk 2: Cache Invalidation Race Condition
**Severity**: Medium
**Probability**: Low
**Mitigation**:
- Redis Lua scripts for atomic operations
- Cache versioning
- Distributed locks for critical sections
- Cache coherency tests in CI/CD

#### Risk 3: WebSocket Connection Overflow
**Severity**: Medium
**Probability**: Medium
**Mitigation**:
- Connection limit per agent (10 max)
- Automatic connection cleanup
- Health check for stale connections
- Rate limiting at WebSocket layer

#### Risk 4: Pattern Execution Timeout Cascade
**Severity**: High
**Probability**: Low
**Mitigation**:
- Timeout enforcement at multiple layers
- Circuit breaker pattern
- Fallback to LLM inference
- Timeout learning for pattern adjustment

---

## 11. Success Criteria Summary

### Phase 1: Functional Validation ✅
- [ ] All test scenarios execute without crashes
- [ ] MCP protocol compliance verified
- [ ] Backward compatibility confirmed
- [ ] Error handling validated

### Phase 2: Performance Validation ✅
- [ ] Latency targets met (P95 < 250ms)
- [ ] Throughput targets met (100+ RPS)
- [ ] Token reduction ≥ 40% achieved
- [ ] Resource utilization within limits

### Phase 3: Scalability Validation ✅
- [ ] 50+ concurrent agents supported
- [ ] Database pool handles load
- [ ] Cache coherency maintained
- [ ] No performance degradation over time

### Phase 4: Reliability Validation ✅
- [ ] Graceful error recovery
- [ ] Automatic failover working
- [ ] Circuit breakers functional
- [ ] No data loss or corruption

### Final Approval Criteria
- [ ] 100% of critical tests passing
- [ ] ≥ 90% of all tests passing
- [ ] No high-severity bugs
- [ ] Performance benchmarks met
- [ ] Security review completed
- [ ] Documentation complete
- [ ] Team sign-off obtained

---

## 12. Reporting and Metrics

### Automated Report Generation

**Report Types**:
1. **JUnit XML**: CI/CD integration
2. **HTML Dashboard**: Human-readable results
3. **JSON Metrics**: Programmatic analysis
4. **Markdown Summary**: Documentation

**Report Location**: `test-reports/integration/`

**Key Metrics Tracked**:
- Test execution time
- Success/failure rates
- Performance percentiles (P50, P95, P99)
- Resource utilization
- Error frequency and types
- Cache hit rates
- Token reduction achieved

### Dashboard Metrics

```
┌─────────────────────────────────────────┐
│   TMWS Pattern Execution Integration    │
│              Test Results               │
├─────────────────────────────────────────┤
│                                         │
│  Total Tests:     47                    │
│  ✓ Passed:        45                    │
│  ✗ Failed:        2                     │
│  ⊘ Skipped:       0                     │
│                                         │
│  Success Rate:    95.7%                 │
│  Duration:        8m 34s                │
│                                         │
├─────────────────────────────────────────┤
│  Performance Metrics                    │
├─────────────────────────────────────────┤
│                                         │
│  Avg Latency:     142ms    ✓            │
│  P95 Latency:     238ms    ✓            │
│  Throughput:      105 RPS  ✓            │
│  Token Reduction: 42.3%    ✓            │
│  Cache Hit Rate:  81.2%    ✓            │
│                                         │
└─────────────────────────────────────────┘
```

---

## Appendix A: Test Environment Setup

### Docker Compose Configuration

```yaml
version: '3.8'

services:
  postgres:
    image: pgvector/pgvector:pg15
    environment:
      POSTGRES_DB: tmws_test
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - "5432:5432"
    volumes:
      - pgdata_test:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --maxmemory 1gb --maxmemory-policy allkeys-lru
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 3

  tmws:
    build: .
    environment:
      TMWS_DATABASE_URL: postgresql://postgres:postgres@postgres:5432/tmws_test
      TMWS_REDIS_URL: redis://redis:6379/0
      TMWS_ENVIRONMENT: testing
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    ports:
      - "8000:8000"

volumes:
  pgdata_test:
```

### Quick Start Commands

```bash
# Start test environment
docker-compose up -d

# Run integration tests
./scripts/run_integration_tests.sh

# View test reports
open test-reports/integration/index.html

# Cleanup
docker-compose down -v
```

---

## Appendix B: Troubleshooting Guide

### Common Issues and Solutions

#### Issue 1: PostgreSQL Connection Failed
**Symptoms**: Tests fail with "connection refused"
**Solution**:
```bash
# Check PostgreSQL status
docker-compose ps postgres

# Restart PostgreSQL
docker-compose restart postgres

# Verify connection
psql -h localhost -U postgres -d tmws_test -c "SELECT 1"
```

#### Issue 2: Redis Connection Timeout
**Symptoms**: Cache operations timing out
**Solution**:
```bash
# Check Redis status
redis-cli ping

# Clear Redis test database
redis-cli -n 1 FLUSHDB

# Restart Redis
docker-compose restart redis
```

#### Issue 3: High Test Failure Rate
**Symptoms**: Success rate < 90%
**Investigation Steps**:
1. Check logs: `tail -f test-reports/integration/*.log`
2. Verify resource utilization: `docker stats`
3. Review error patterns in JUnit XML
4. Increase timeout if needed: `TEST_TIMEOUT=1200 ./scripts/run_integration_tests.sh`

---

**Document Owner**: Eris (Tactical Coordinator)
**Last Updated**: 2025-01-09
**Next Review**: After v2.2.0 deployment
**Approval Status**: Ready for Team Review
