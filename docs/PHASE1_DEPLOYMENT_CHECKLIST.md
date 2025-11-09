# Phase 1 Deployment Checklist
## Learning & Trust Score System

**Target**: Production deployment for Week 1
**Status**: ⚠️ **NOT READY** (3 blockers identified)
**Est. Time to Ready**: 24 hours (3 days)

---

## Critical Blockers

### 🚨 Blocker 1: LearningService Test Coverage (0%)

**Current**: No unit tests
**Target**: 90% coverage
**Effort**: 8-12 hours

**Required Tests**:
- [ ] `test_create_pattern_validation.py` (2 hours)
  - Valid/invalid pattern names
  - Category validation
  - Access level enforcement
  - Namespace isolation

- [ ] `test_pattern_access_control.py` (2 hours)
  - PRIVATE patterns (owner-only)
  - SHARED patterns (explicit list)
  - PUBLIC patterns (all agents)
  - SYSTEM patterns (read-only)

- [ ] `test_pattern_search_filters.py` (2 hours)
  - Search by category
  - Search by success rate
  - Search by usage count
  - Semantic search validation

- [ ] `test_usage_tracking_accuracy.py` (2 hours)
  - Usage count increments
  - Success rate calculation
  - Execution time averaging (EWMA)
  - Confidence score updates

- [ ] `test_recommendation_algorithm.py` (2 hours)
  - Recommendation relevance
  - Context-based scoring
  - Usage history influence
  - Pattern ranking

- [ ] `test_batch_operations.py` (1 hour)
  - Batch create patterns
  - Transaction rollback on error
  - Performance validation

- [ ] `test_performance_benchmarks.py` (1 hour)
  - Pattern search <20ms
  - Pattern create <10ms
  - Pattern analytics <100ms

**Command**:
```bash
pytest tests/unit/services/test_learning_service.py -v --cov=src/services/learning_service --cov-report=term-missing
```

---

### 🚨 Blocker 2: VerificationService Bugs (6 failing tests)

**Current**: 13/19 tests passing (68%)
**Target**: 100% passing
**Effort**: 2 hours

**Failing Tests**:
1. ❌ `test_verify_claim_accurate`
2. ❌ `test_verify_claim_inaccurate`
3. ❌ `test_verify_claim_agent_not_found`
4. ❌ `test_compare_results_metrics`
5. ❌ `test_create_evidence_memory`
6. ❌ `test_performance_verification`

**Fixes Required**:

#### Fix 1: Mock Memory Service Signature (Tests 1-3, 5-6)
**File**: `tests/unit/services/test_verification_service.py:542-557`
**Issue**: Mock doesn't match `HybridMemoryService.create_memory()` signature
**Fix**:
```python
@pytest.fixture
def mock_memory_service():
    """Mock memory service for testing"""
    class MockMemoryService:
        async def create_memory(
            self,
            content: str,
            agent_id: str = "",
            namespace: str = "test",  # ← ADD
            importance_score: float = 0.5,
            tags: list[str] = None,
            context: dict = None,
            **kwargs
        ):
            return Memory(
                id=uuid4(),
                content=content,
                agent_id=agent_id,
                namespace=namespace,  # ← ADD
                importance=importance_score,
                metadata_json=json.dumps(context or {})
            )
    return MockMemoryService()
```

#### Fix 2: Metrics Comparison Logic (Test 4)
**File**: `src/services/verification_service.py:316-327`
**Issue**: Metrics not extracted from `verification_result`
**Fix**:
```python
def _compare_results(
    self,
    claim: dict[str, Any],
    actual: dict[str, Any]
) -> bool:
    # ... existing code ...

    # If claim specifies numeric values, check with tolerance
    if "metrics" in claim:
        # Extract metrics from actual result
        actual_metrics = actual.get("metrics")
        if actual_metrics is None:
            # Try to parse from stdout if structured
            try:
                import json
                stdout = actual.get("stdout", "")
                if stdout:
                    actual_metrics = json.loads(stdout).get("metrics")
            except (json.JSONDecodeError, AttributeError):
                return False

        if actual_metrics is None:
            return False

        for key, claimed_value in claim["metrics"].items():
            actual_value = actual_metrics.get(key)
            # ... rest of comparison logic ...
```

#### Fix 3: Update Test to Pass Namespace (Test 5)
**File**: `tests/unit/services/test_verification_service.py:246-250`
**Fix**:
```python
# Create evidence
memory = await service._create_evidence_memory(
    agent_id="test-agent",
    namespace="test",  # ← ADD
    verification_record=verification_record,
    verification_duration_ms=150.5
)
```

**Command**:
```bash
pytest tests/unit/services/test_verification_service.py -v --tb=short
```

---

### 🚨 Blocker 3: Command Injection Vulnerability

**Risk**: CRITICAL security gap
**Issue**: Verification commands executed without sanitization
**File**: `src/services/verification_service.py:223-278`
**Effort**: 4 hours

**Current**:
```python
async def _execute_verification(
    self,
    command: str,  # ← UNSAFE: Direct shell execution
    timeout_seconds: float = 30.0
) -> dict[str, Any]:
    process = await asyncio.create_subprocess_shell(
        command,  # ← VULNERABILITY
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
```

**Fix Option 1: Command Whitelist (Recommended)**
```python
ALLOWED_COMMANDS = {
    "pytest": {"args": ["-v", "--tb=short", "--maxfail=1"], "timeout": 300},
    "ruff": {"args": ["check", "--select", "ALL"], "timeout": 60},
    "mypy": {"args": ["--strict"], "timeout": 120},
    "npm": {"args": ["test", "--", "--coverage"], "timeout": 300},
}

async def _execute_verification(
    self,
    command: str,
    timeout_seconds: float | None = None
) -> dict[str, Any]:
    # Parse command
    parts = command.split()
    cmd = parts[0]

    # Validate against whitelist
    if cmd not in ALLOWED_COMMANDS:
        raise VerificationError(
            f"Command '{cmd}' not allowed. Allowed: {list(ALLOWED_COMMANDS.keys())}"
        )

    # Get allowed args and timeout
    config = ALLOWED_COMMANDS[cmd]
    timeout = timeout_seconds or config["timeout"]

    # Build safe command
    safe_command = [cmd] + config["args"] + parts[1:]

    # Execute with whitelist
    process = await asyncio.create_subprocess_exec(
        *safe_command,  # ← SAFE: No shell injection
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    # ... rest of execution ...
```

**Fix Option 2: Sandbox Execution (Advanced)**
```python
# Use Docker or firejail for complete isolation
async def _execute_verification_sandboxed(
    self,
    command: str,
    timeout_seconds: float = 30.0
) -> dict[str, Any]:
    # Run in isolated container
    docker_command = [
        "docker", "run", "--rm",
        "--network=none",  # No network
        "--memory=256m",   # Memory limit
        "--cpus=0.5",      # CPU limit
        f"--timeout={timeout_seconds}",
        "tmws-verification",  # Custom image
        "sh", "-c", command
    ]

    process = await asyncio.create_subprocess_exec(
        *docker_command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
```

**Testing**:
```bash
# Test command injection prevention
pytest tests/security/test_command_injection.py -v

# Test whitelist enforcement
pytest tests/unit/services/test_verification_service.py::test_command_whitelist -v
```

---

## Non-Blocking Improvements

### ⚠️ Missing E2E Workflow Test

**Priority**: High (but not blocking)
**Effort**: 6 hours

**Test**: `tests/integration/test_learning_trust_workflow.py`
```python
async def test_learn_verify_trust_workflow():
    """Test complete workflow: learn → apply → verify → trust update"""

    # Phase 1: Learn a pattern
    pattern = await learning_service.create_pattern(
        pattern_name="sql_optimization_index",
        category="performance",
        pattern_data={
            "technique": "Add composite index",
            "expected_improvement": "90%"
        }
    )

    # Phase 2: Apply pattern (simulate)
    claim = {
        "return_code": 0,
        "output_contains": "Query time reduced by 90%",
        "metrics": {"query_time_ms": 10}  # Claimed improvement
    }

    # Phase 3: Verify claim
    verification = await verification_service.verify_claim(
        agent_id="artemis-optimizer",
        claim_type=ClaimType.PERFORMANCE_METRIC,
        claim_content=claim,
        verification_command="python scripts/benchmark_query.py"
    )

    # Phase 4: Check trust score updated
    trust_score = await trust_service.get_trust_score("artemis-optimizer")

    # Assertions
    assert verification.accurate is True
    assert trust_score["trust_score"] > 0.5  # Increased
    assert pattern.usage_count == 1  # Pattern usage tracked
    assert pattern.success_rate == 1.0  # First use successful
```

**Command**:
```bash
pytest tests/integration/test_learning_trust_workflow.py -v --tb=short
```

---

### ⚠️ Performance Index Missing

**Priority**: Medium
**Effort**: 2 hours

**Issue**: Pattern search may be slow for large datasets (uncached)
**File**: `src/models/learning_pattern.py`
**Fix**: Add composite index

```python
# In LearningPattern.__table_args__
Index(
    "idx_learning_patterns_search_performance",
    "category",
    "access_level",
    "success_rate",
    "usage_count"
),
```

**Migration**:
```bash
alembic revision --autogenerate -m "p1_add_pattern_search_index"
alembic upgrade head
```

**Validation**:
```bash
# Before index
pytest tests/performance/test_pattern_search.py::test_search_10000_patterns -v

# After index (should be <20ms)
pytest tests/performance/test_pattern_search.py::test_search_10000_patterns -v
```

---

## Deployment Checklist

### Pre-Deployment (3 days)

**Day 1: Fix Tests**
- [ ] Fix 6 failing VerificationService tests (2 hours)
- [ ] Write LearningService unit tests (Part 1: 6 hours)

**Day 2: Complete Tests**
- [ ] Write LearningService unit tests (Part 2: 6 hours)
- [ ] Add command sanitization (4 hours)

**Day 3: Integration**
- [ ] Write E2E workflow test (6 hours)
- [ ] Add performance index (2 hours)
- [ ] Final validation (2 hours)

### Validation (4 hours)

- [ ] All unit tests passing (100% for new services)
  ```bash
  pytest tests/unit/services/ -v --cov=src/services --cov-report=term-missing
  ```

- [ ] Integration tests passing
  ```bash
  pytest tests/integration/ -v
  ```

- [ ] Performance benchmarks met
  ```bash
  pytest tests/performance/ -v --benchmark-only
  ```

- [ ] Security audit clean
  ```bash
  pytest tests/security/ -v
  ```

### Post-Deployment Monitoring

**Week 1 Metrics**:
- [ ] Trust score update latency <1ms P95
- [ ] Pattern search latency <20ms P95
- [ ] Verification completion rate >95%
- [ ] Zero command injection attempts

**Week 2 Metrics**:
- [ ] Pattern usage >100/day
- [ ] Trust score convergence <10 verifications
- [ ] Verification error rate <1%

---

## Success Criteria

### Phase 1 Complete When:

✅ **All Tests Passing**
- LearningService: 90% coverage, all passing
- TrustService: 100% coverage, all passing ✅ (already done)
- VerificationService: 100% coverage, all passing
- Integration: 80% coverage, all passing

✅ **Performance Targets Met**
- Trust score update: <1ms P95 ✅ (0.9ms achieved)
- Pattern search: <20ms P95
- Pattern analytics: <100ms P95
- Verification: <500ms P95

✅ **Security Audit Clean**
- No critical vulnerabilities
- No high-risk vulnerabilities
- Command injection prevented
- Namespace isolation enforced

✅ **Documentation Complete**
- API documentation: 100%
- User guide: Learning & Trust Score
- Architecture diagrams updated
- MCP tool reference updated

---

## Rollback Plan

**If Deployment Fails**:

1. **Disable MCP tools** (5 minutes)
   ```python
   # In mcp_server.py
   # Comment out tool registrations
   # @mcp.tool()
   # async def learn_pattern(...):
   #     ...
   ```

2. **Revert database migrations** (10 minutes)
   ```bash
   alembic downgrade -1
   ```

3. **Restore previous version** (15 minutes)
   ```bash
   git revert <commit-hash>
   git push
   ```

4. **Notify users** (immediate)
   - Learning & Trust features temporarily disabled
   - Manual verification required
   - ETA for fix

---

## Contact & Support

**Technical Lead**: Artemis (artemis-optimizer)
**Testing Lead**: Hestia (hestia-auditor)
**Deployment Lead**: Hera (hera-strategist)

**Escalation**:
- Test failures → Hestia
- Performance issues → Artemis
- Security concerns → Hestia
- Deployment issues → Hera

---

**Last Updated**: 2025-11-08
**Status**: ⚠️ **NOT READY** (3 blockers)
**Next Review**: After blocker fixes (estimated 3 days)
