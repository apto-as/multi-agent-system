# Integration Testing Coordination Checklist
**TMWS v2.2.0 - Pattern Execution Service**
**Coordinator**: Eris (Tactical Coordinator)
**Date**: 2025-01-09

## Quick Reference

### Critical Commands
```bash
# Start test environment
docker-compose up -d

# Run all integration tests
./scripts/run_integration_tests.sh

# Run performance benchmarks
python scripts/benchmark_pattern_performance.py --scenario=all

# View results
open test-reports/integration/index.html
```

### Success Criteria At-a-Glance
- ✅ Success rate ≥ 95%
- ✅ P95 latency < 250ms
- ✅ Throughput ≥ 100 RPS
- ✅ Token reduction ≥ 40%
- ✅ Cache hit rate > 80%

---

## Pre-Test Phase (T-24 hours)

### Infrastructure Setup - Hera (Strategic Commander)

**PostgreSQL Configuration**
- [ ] PostgreSQL 15+ running
- [ ] pgvector extension installed
- [ ] Test database `tmws_test` created
- [ ] Connection pool configured (10 base + 20 overflow)
- [ ] IVFFlat indexes created for vector queries
- [ ] Health check passing: `psql -h localhost -U postgres -c "SELECT version()"`

**Redis Configuration**
- [ ] Redis 7+ running
- [ ] Test database #1 configured
- [ ] Maxmemory policy: `allkeys-lru`
- [ ] Memory limit: 1GB
- [ ] Health check passing: `redis-cli ping`

**Monitoring Setup**
- [ ] Prometheus/Grafana dashboards configured
- [ ] Application metrics endpoint active
- [ ] Database metrics collected
- [ ] CPU/Memory monitoring active

### Code Preparation - Artemis (Technical Perfectionist)

**Pattern Execution Service**
- [ ] Latest code deployed to test environment
- [ ] Pattern definitions loaded in registry
- [ ] Performance instrumentation enabled
- [ ] Debug logging configured (level: DEBUG)
- [ ] Unit tests passing: `pytest tests/unit/test_pattern_execution_service.py -v`

**Dependencies**
- [ ] Python dependencies installed: `pip install -r requirements.txt`
- [ ] Test dependencies installed: `pip install -r requirements-test.txt`
- [ ] MCP tools functional
- [ ] WebSocket server operational

**Code Quality**
- [ ] Linting passed: `ruff check .`
- [ ] Type checking passed: `mypy src/`
- [ ] Security scan completed: `bandit -r src/`
- [ ] No TODO/FIXME in critical paths

### Security Review - Hestia (Security Guardian)

**Environment Isolation**
- [ ] Test environment isolated from production
- [ ] Test credentials rotated
- [ ] Firewall rules validated
- [ ] Network segmentation confirmed

**Audit Configuration**
- [ ] Audit logging enabled
- [ ] Security events tracked
- [ ] Failed login attempts monitored
- [ ] Anomaly detection active

**Vulnerability Assessment**
- [ ] Latest security patches applied
- [ ] Known vulnerabilities resolved
- [ ] Dependencies scanned: `pip-audit`
- [ ] Container images scanned

### Documentation - Muses (Knowledge Architect)

**Test Documentation**
- [ ] Test plan reviewed: `docs/INTEGRATION_TEST_PLAN.md`
- [ ] Expected results documented
- [ ] Failure remediation steps prepared
- [ ] Report templates ready

**Team Communication**
- [ ] Test schedule shared with team
- [ ] Stakeholders notified
- [ ] Emergency contacts updated
- [ ] Escalation paths defined

---

## Test Execution Phase (T-0)

### Test Environment Validation - Eris

**Pre-Flight Checks** (5 minutes)
```bash
# Run automated pre-flight
./scripts/run_integration_tests.sh --preflight-only

# Manual verification
- [ ] PostgreSQL: psql -h localhost -U postgres -c "SELECT 1"
- [ ] pgvector: psql -U postgres -d tmws_test -c "SELECT extversion FROM pg_extension WHERE extname='vector'"
- [ ] Redis: redis-cli ping
- [ ] Python env: python -c "import pytest, asyncio, sqlalchemy, redis"
```

**Environment Variables**
```bash
export TMWS_ENVIRONMENT=testing
export TMWS_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/tmws_test
export TMWS_REDIS_URL=redis://localhost:6379/1
export TMWS_AUTH_ENABLED=false
export PYTHONPATH=$(pwd)
```
- [ ] All environment variables set
- [ ] Configuration validated

### Multi-Agent Concurrency Tests (15 minutes)

**Test Execution**
```bash
pytest tests/integration/test_pattern_integration.py::TestMultiAgentConcurrency -v
```

**Real-Time Monitoring** - Eris
- [ ] Monitor test progress in terminal
- [ ] Watch system resources: `htop` / `docker stats`
- [ ] Track database connections: `psql -c "SELECT count(*) FROM pg_stat_activity"`
- [ ] Monitor Redis memory: `redis-cli info memory`

**Success Criteria Validation**
- [ ] Success rate ≥ 95%
- [ ] No deadlocks detected
- [ ] Avg latency < 300ms
- [ ] Cache hit rate > 70%

**Failure Response Protocol**
- If success rate < 90%:
  1. [ ] Pause tests immediately
  2. [ ] Capture logs: `docker logs tmws > error-logs.txt`
  3. [ ] Check database: `psql -c "SELECT * FROM pg_stat_activity WHERE state != 'idle'"`
  4. [ ] Notify Artemis for code review
  5. [ ] Escalate to Hera if infrastructure issue

### WebSocket MCP Integration Tests (10 minutes)

**Test Execution**
```bash
pytest tests/integration/test_pattern_integration.py::TestWebSocketMCPIntegration -v
```

**Validation Checklist** - Eris
- [ ] MCP protocol compliance verified
- [ ] Backward compatibility confirmed
- [ ] Multi-client sessions functional
- [ ] No message crosstalk

**WebSocket Health Check**
```bash
# Test WebSocket endpoint
wscat -c ws://localhost:8000/ws/mcp?agent_id=test-agent

# Should receive:
# {"method": "welcome", "params": {"session_id": "..."}}
```

### Database Integration Tests (20 minutes)

**Test Execution**
```bash
pytest tests/integration/test_pattern_integration.py::TestDatabaseIntegration -v
```

**Database Performance Monitoring** - Hera + Artemis
- [ ] Monitor query performance: `psql -c "SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 10"`
- [ ] Check pgvector index usage: `EXPLAIN ANALYZE SELECT ...`
- [ ] Validate connection pool: `psql -c "SELECT count(*) FROM pg_stat_activity"`
- [ ] Monitor transaction isolation

**Success Criteria**
- [ ] Avg pgvector query < 200ms
- [ ] P95 latency < 500ms
- [ ] Zero transaction isolation failures
- [ ] Connection pool stable (< 25 connections)

### Performance Benchmarks (30 minutes)

**Benchmark Execution**
```bash
python scripts/benchmark_pattern_performance.py --scenario=all --duration=10
```

**Performance Targets** - Artemis
- [ ] Latency benchmark:
  - [ ] P50 < 100ms
  - [ ] P95 < 250ms
  - [ ] P99 < 400ms

- [ ] Throughput benchmark:
  - [ ] Sustained RPS ≥ 100
  - [ ] Success rate ≥ 95%
  - [ ] CPU usage < 80%

- [ ] Stress test:
  - [ ] System stable at 100 concurrent workers
  - [ ] Graceful degradation observed
  - [ ] Memory < 2GB

**Token Reduction Validation** - Hera
- [ ] Infrastructure patterns: 90%+ reduction
- [ ] Memory patterns: 80%+ reduction
- [ ] Hybrid patterns: 60%+ reduction
- [ ] Overall average: ≥ 40% reduction

### Error Recovery Tests (15 minutes)

**Test Execution**
```bash
pytest tests/integration/test_pattern_integration.py::TestErrorRecoveryIntegration -v
```

**Failure Scenario Validation** - Hestia
- [ ] Database connection loss handled gracefully
- [ ] Redis failover to local cache works
- [ ] Pattern execution timeout enforced
- [ ] Circuit breaker functional

**Recovery Verification**
```bash
# Simulate DB failure
docker-compose stop postgres

# Run pattern execution (should fail gracefully)
# ...

# Restore DB
docker-compose start postgres

# Verify auto-recovery
```

---

## Post-Test Phase (T+2 hours)

### Results Analysis - Team Collaboration

**Test Report Review** - Eris + Artemis
- [ ] Review JUnit XML reports: `test-reports/integration/*-junit.xml`
- [ ] Analyze HTML dashboard: `test-reports/integration/index.html`
- [ ] Extract key metrics from logs
- [ ] Identify performance bottlenecks

**Performance Metrics Dashboard** - Hera
```
┌──────────────────────────────────────┐
│   Integration Test Summary          │
├──────────────────────────────────────┤
│  Concurrency:    ✓ 95.7% success    │
│  WebSocket:      ✓ 100% compatible  │
│  Database:       ✓ P95 < 200ms      │
│  Throughput:     ✓ 105 RPS          │
│  Token Reduce:   ✓ 42.3%            │
│  Cache Hit:      ✓ 81.2%            │
└──────────────────────────────────────┘
```

- [ ] All metrics meet targets
- [ ] No critical issues identified
- [ ] Performance baseline established

### Issue Triage - Eris (Coordination)

**Severity Classification**
- **Critical** (P0): System crash, data corruption, security breach
  - [ ] Immediate escalation to Hera
  - [ ] Block deployment
  - [ ] 24-hour fix timeline

- **High** (P1): Performance degradation, partial failures
  - [ ] Notify Artemis for investigation
  - [ ] 3-day fix timeline
  - [ ] Deployment decision by Hera

- **Medium** (P2): Minor issues, edge cases
  - [ ] Log for next sprint
  - [ ] 1-week fix timeline
  - [ ] Can proceed with deployment

- **Low** (P3): Cosmetic, documentation
  - [ ] Backlog for future improvement

**Issue Assignment**
- [ ] Create GitHub issues for failures
- [ ] Assign to appropriate team member
- [ ] Set priority and timeline
- [ ] Link to test reports

### Security Assessment - Hestia

**Security Test Results**
- [ ] No vulnerabilities detected in concurrency tests
- [ ] MCP protocol secure against injection
- [ ] Database queries parameterized (no SQL injection)
- [ ] Rate limiting functional
- [ ] Audit logs complete

**Security Sign-off**
- [ ] All security tests passed
- [ ] No high-severity findings
- [ ] Production deployment approved from security perspective

### Documentation Update - Muses

**Test Report Documentation**
- [ ] Executive summary created
- [ ] Key findings documented
- [ ] Performance baselines recorded
- [ ] Known issues listed with workarounds

**Knowledge Base Update**
- [ ] Test results archived
- [ ] Lessons learned documented
- [ ] Best practices updated
- [ ] Troubleshooting guide enhanced

---

## Deployment Decision (T+4 hours)

### Go/No-Go Decision Matrix - Hera (Strategic Commander)

**Deployment Criteria**
```
┌─────────────────┬──────────┬────────┬──────────┐
│ Criterion       │ Target   │ Actual │ Status   │
├─────────────────┼──────────┼────────┼──────────┤
│ Success Rate    │ ≥ 95%    │ ____%  │ ☐ ✓ ☐ ✗ │
│ P95 Latency     │ < 250ms  │ ___ms  │ ☐ ✓ ☐ ✗ │
│ Throughput      │ ≥ 100RPS │ ___RPS │ ☐ ✓ ☐ ✗ │
│ Token Reduction │ ≥ 40%    │ ___%   │ ☐ ✓ ☐ ✗ │
│ Security        │ Pass     │ ___    │ ☐ ✓ ☐ ✗ │
│ Stability       │ Pass     │ ___    │ ☐ ✓ ☐ ✗ │
└─────────────────┴──────────┴────────┴──────────┘

Decision: ☐ GO  ☐ NO-GO  ☐ CONDITIONAL

Approved by:
- [ ] Hera (Strategic)
- [ ] Artemis (Technical)
- [ ] Hestia (Security)
- [ ] Athena (Architecture)
```

**GO Criteria** (All must be ✓)
- [ ] All critical tests passing
- [ ] Performance targets met
- [ ] No high-severity security issues
- [ ] Team consensus achieved

**NO-GO Criteria** (Any trigger)
- [ ] Success rate < 90%
- [ ] Critical security vulnerability
- [ ] Data corruption risk
- [ ] System instability

**CONDITIONAL GO**
- [ ] Minor issues with known workarounds
- [ ] Performance slightly below target but acceptable
- [ ] Phased rollout recommended
- [ ] Monitoring plan in place

### Deployment Plan - Hera + Eris

**If GO:**
1. [ ] Tag release: `git tag v2.2.0-pattern-execution`
2. [ ] Deploy to staging first (blue-green)
3. [ ] Run smoke tests in staging
4. [ ] Monitor for 2 hours
5. [ ] Deploy to production with gradual rollout
6. [ ] Enable feature flag for 10% traffic
7. [ ] Monitor metrics for 24 hours
8. [ ] Gradual increase to 100%

**If NO-GO:**
1. [ ] Document blocking issues
2. [ ] Create remediation plan
3. [ ] Assign fixes to team
4. [ ] Schedule re-test
5. [ ] Update stakeholders

**If CONDITIONAL GO:**
1. [ ] Deploy with feature flag (disabled by default)
2. [ ] Enable for internal testing only
3. [ ] Monitor closely for 48 hours
4. [ ] Gradual rollout based on stability

---

## Continuous Monitoring (Post-Deployment)

### Week 1 Monitoring - Eris + Hera

**Daily Checks**
- [ ] **Day 1**: Monitor error rates, latency spikes
- [ ] **Day 2**: Check token reduction in production
- [ ] **Day 3**: Validate cache performance
- [ ] **Day 4**: Review user feedback
- [ ] **Day 5**: Performance trend analysis

**Metrics to Track**
```python
{
    "pattern_execution": {
        "success_rate": ">= 95%",
        "p95_latency_ms": "< 250",
        "throughput_rps": ">= 100",
        "token_reduction_pct": ">= 40%",
        "cache_hit_rate": "> 80%"
    },
    "system_health": {
        "cpu_usage_pct": "< 80%",
        "memory_usage_mb": "< 2048",
        "db_connections": "< 25",
        "redis_memory_mb": "< 1024"
    },
    "errors": {
        "total_errors": "< 100/day",
        "critical_errors": "0"
    }
}
```

**Alert Thresholds**
- 🟢 Green: All metrics within target
- 🟡 Yellow: Any metric within 10% of threshold
- 🔴 Red: Any metric exceeds threshold

**Escalation Protocol**
- Yellow for > 1 hour → Notify Eris
- Red for > 15 minutes → Escalate to Hera
- Critical error → Immediate rollback

### Week 2-4 Monitoring - Artemis

**Performance Optimization**
- [ ] Identify slow patterns
- [ ] Optimize database queries
- [ ] Tune cache TTL
- [ ] Adjust connection pool

**Pattern Learning**
- [ ] Analyze pattern usage distribution
- [ ] Identify new pattern opportunities
- [ ] Update pattern definitions
- [ ] Improve routing accuracy

---

## Appendix: Quick Troubleshooting

### Common Issues and Fixes

**Issue: Tests Fail to Start**
```bash
# Check services
docker-compose ps

# Restart all services
docker-compose restart

# View logs
docker-compose logs --tail=100
```

**Issue: Database Connection Errors**
```bash
# Check PostgreSQL status
psql -h localhost -U postgres -c "SELECT 1"

# Check connections
psql -c "SELECT count(*) FROM pg_stat_activity"

# Restart PostgreSQL
docker-compose restart postgres
```

**Issue: Redis Unavailable**
```bash
# Check Redis
redis-cli ping

# Clear test database
redis-cli -n 1 FLUSHDB

# Restart Redis
docker-compose restart redis
```

**Issue: Low Performance**
```bash
# Check system resources
htop
docker stats

# Check database performance
psql -c "SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 10"

# Check cache hit rate
redis-cli info stats
```

### Emergency Contacts

**Team Leads**
- Hera (Strategic): @hera-strategist
- Artemis (Technical): @artemis-optimizer
- Hestia (Security): @hestia-auditor
- Eris (Coordinator): @eris-coordinator

**Escalation Path**
1. Test failure → Eris
2. Performance issue → Artemis
3. Security concern → Hestia
4. Strategic decision → Hera

**Emergency Rollback**
```bash
# Immediate rollback if critical issue
git checkout v2.1.0
docker-compose down
docker-compose up -d
./scripts/run_smoke_tests.sh
```

---

**Checklist Owner**: Eris (Tactical Coordinator)
**Last Updated**: 2025-01-09
**Next Review**: After deployment
**Status**: ✅ Ready for Execution
