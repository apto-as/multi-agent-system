# Implementation Checklist
## Learning → Trust → Verification Integration

**Status**: Ready for Implementation
**Estimated Time**: 3-4 days
**Owner**: Development Team

---

## Phase 1: Database Schema Extensions (2 hours)

### 1.1 Add Verification Fields to LearningPattern

**File**: `src/models/learning_pattern.py`

- [ ] Add `verification_command: str | None` field
- [ ] Add `verified_usage_count: int` field (default 0)
- [ ] Add `verification_success_rate: float` field (default 1.0)
- [ ] Add docstrings explaining new fields
- [ ] Update `__repr__` to include new fields (optional)

**Verification**:
```python
# Check model definition
pattern = LearningPattern(
    pattern_name="test",
    category="test",
    pattern_data={},
    verification_command="echo test"
)
assert hasattr(pattern, 'verification_command')
assert hasattr(pattern, 'verified_usage_count')
assert hasattr(pattern, 'verification_success_rate')
```

### 1.2 Create Alembic Migration

**File**: `migrations/versions/YYYYMMDD_HHMM_add_pattern_verification_fields.py`

- [ ] Create migration: `alembic revision --autogenerate -m "Add verification fields to learning_patterns"`
- [ ] Review auto-generated migration
- [ ] Add `server_default` for `verified_usage_count` (0)
- [ ] Add `server_default` for `verification_success_rate` (1.0)
- [ ] Add docstrings in migration
- [ ] Test upgrade: `alembic upgrade head`
- [ ] Test downgrade: `alembic downgrade -1`
- [ ] Test upgrade again: `alembic upgrade head`

**Verification**:
```bash
# Check migration applied
alembic current
# Should show latest revision

# Check database
sqlite3 data/tmws.db "PRAGMA table_info(learning_patterns);"
# Should show new columns
```

---

## Phase 2: Service Layer Extensions (4 hours)

### 2.1 LearningService Extended Methods

**File**: `src/services/learning_service.py`

#### Task 2.1.1: Add `use_pattern_with_verification` method

- [ ] Add method signature with full type hints
- [ ] Implement pattern execution logic
- [ ] Add automatic verification trigger (if `auto_verify=True`)
- [ ] Add success/failure update to pattern
- [ ] Add comprehensive docstring
- [ ] Add logging for debugging
- [ ] Handle errors gracefully

**Code Template**:
```python
async def use_pattern_with_verification(
    self,
    pattern_id: UUID,
    using_agent_id: str,
    context_data: dict[str, Any] | None = None,
    auto_verify: bool = True,
    verification_command: str | None = None
) -> dict[str, Any]:
    """Use pattern with automatic verification

    Args:
        pattern_id: Pattern UUID
        using_agent_id: Agent using the pattern
        context_data: Optional context data
        auto_verify: Whether to automatically verify result
        verification_command: Override pattern's verification command

    Returns:
        {
            "pattern_result": {...},
            "verification": {
                "accurate": bool,
                "evidence_id": UUID,
                "new_trust_score": float
            } | None
        }

    Raises:
        NotFoundError: If pattern not found
        PermissionError: If access denied
    """
    # Implementation...
```

- [ ] **Verification**: Write unit test
  ```python
  async def test_use_pattern_with_verification(db_session):
      # Test auto_verify=True
      # Test auto_verify=False
      # Test verification_command override
  ```

#### Task 2.1.2: Add `update_verification_stats` method

- [ ] Add method to update `verified_usage_count` and `verification_success_rate`
- [ ] Use atomic update with row-level lock
- [ ] Calculate new success rate: `(old_rate * old_count + new_result) / (old_count + 1)`
- [ ] Add logging

**Code Template**:
```python
async def update_verification_stats(
    self,
    pattern_id: UUID,
    success: bool
) -> None:
    """Update pattern verification statistics

    Args:
        pattern_id: Pattern UUID
        success: Whether verification succeeded
    """
    async with get_db_session() as session:
        result = await session.execute(
            select(LearningPattern)
            .where(LearningPattern.id == pattern_id)
            .with_for_update()  # Row-level lock
        )
        pattern = result.scalar_one_or_none()
        if not pattern:
            raise NotFoundError("LearningPattern", str(pattern_id))

        # Update statistics
        old_count = pattern.verified_usage_count
        old_rate = pattern.verification_success_rate

        pattern.verified_usage_count += 1
        pattern.verification_success_rate = (
            (old_rate * old_count + (1.0 if success else 0.0))
            / (old_count + 1)
        )

        await session.flush()
```

- [ ] **Verification**: Write unit test

### 2.2 VerificationService Extended Methods

**File**: `src/services/verification_service.py`

#### Task 2.2.1: Add `verify_pattern_usage` method

- [ ] Add method specialized for learning pattern verification
- [ ] Extract pattern details from database
- [ ] Delegate to existing `verify_claim` method
- [ ] Add pattern-specific logging

**Code Template**:
```python
async def verify_pattern_usage(
    self,
    pattern_id: UUID,
    agent_id: str,
    claimed_result: dict[str, Any],
    verification_command: str | None = None
) -> VerificationResult:
    """Specialized verification for learning patterns

    Args:
        pattern_id: Pattern UUID
        agent_id: Agent who used pattern
        claimed_result: Claimed execution result
        verification_command: Optional command override

    Returns:
        VerificationResult with evidence and trust update

    Raises:
        NotFoundError: If pattern not found
    """
    # Get pattern from learning service
    from src.services.learning_service import LearningService

    learning_service = LearningService()
    pattern = await learning_service.get_pattern(pattern_id, agent_id)

    if not pattern:
        raise NotFoundError("LearningPattern", str(pattern_id))

    # Use pattern's verification command or override
    command = verification_command or pattern.verification_command

    if not command:
        raise ValidationError("No verification command available for pattern")

    # Delegate to standard verification
    return await self.verify_claim(
        agent_id=agent_id,
        claim_type=ClaimType.CUSTOM,
        claim_content=claimed_result,
        verification_command=command
    )
```

- [ ] **Verification**: Write unit test

### 2.3 TrustService Extended Methods

**File**: `src/services/trust_service.py`

#### Task 2.3.1: Add `get_agent_reliability_status` method

- [ ] Add comprehensive reliability assessment
- [ ] Include autonomy threshold logic
- [ ] Add clear explanation of status

**Code Template**:
```python
async def get_agent_reliability_status(
    self,
    agent_id: str
) -> dict[str, Any]:
    """Get comprehensive reliability assessment

    Args:
        agent_id: Agent identifier

    Returns:
        {
            "trust_score": float,
            "is_reliable": bool,
            "total_verifications": int,
            "accuracy_rate": float,
            "can_operate_autonomously": bool,
            "requires_supervision": bool,
            "status_level": str  # "untrusted", "building", "reliable", "trusted"
        }

    Raises:
        AgentNotFoundError: If agent not found
    """
    trust_data = await self.get_trust_score(agent_id)

    trust_score = trust_data["trust_score"]
    total_verifications = trust_data["total_verifications"]

    # Determine status level
    if total_verifications < 5:
        status_level = "untrusted"
    elif trust_score < 0.7:
        status_level = "building"
    elif trust_score < 0.8:
        status_level = "reliable"
    else:
        status_level = "trusted"

    return {
        **trust_data,
        "can_operate_autonomously": (
            trust_score >= 0.7 and total_verifications >= 5
        ),
        "requires_supervision": not (
            trust_score >= 0.7 and total_verifications >= 5
        ),
        "status_level": status_level
    }
```

- [ ] **Verification**: Write unit test

---

## Phase 3: MCP Tools (3 hours)

### 3.1 Add Integration Test Tool

**File**: `src/tools/integration_tools.py` (new file)

#### Task 3.1.1: Create `IntegrationTools` class

- [ ] Create new tool class inheriting from `BaseTool`
- [ ] Import necessary services
- [ ] Add registration method

```python
from .base_tool import BaseTool
from fastmcp import FastMCP

class IntegrationTools(BaseTool):
    """Integration testing tools for Learning → Trust → Verification"""

    async def register_tools(self, mcp: FastMCP) -> None:
        """Register integration tools"""
        # Register tools here
```

#### Task 3.1.2: Add `test_learning_trust_integration` tool

- [ ] Implement tool with three scenarios: full, learning_only, verification_only
- [ ] Add comprehensive error handling
- [ ] Return detailed results
- [ ] Add usage examples in docstring

**Code Template**:
```python
@mcp.tool()
async def test_learning_trust_integration(
    agent_id: str = "test-agent",
    scenario: str = "full"
) -> dict[str, Any]:
    """Test the Learning → Trust → Verification integration

    Args:
        agent_id: Agent to test (default: test-agent)
        scenario: Test scenario (full, learning_only, verification_only)

    Returns:
        Comprehensive test results with evidence

    Scenarios:
    - full: Complete workflow (pattern → verify → trust)
    - learning_only: Test pattern learning without verification
    - verification_only: Test verification and trust update

    Example:
        /tmws test_learning_trust_integration --scenario full
    """
    # Implementation based on PHASE_1-3_INTEGRATION_PLAN.md section 5.1
```

- [ ] **Verification**: Test manually via MCP

#### Task 3.1.3: Add `get_agent_learning_stats` tool

- [ ] Implement comprehensive statistics aggregation
- [ ] Combine data from all three services
- [ ] Format for human readability

**Code Template**:
```python
@mcp.tool()
async def get_agent_learning_stats(agent_id: str) -> dict[str, Any]:
    """Get comprehensive learning and trust statistics

    Combines:
    - Learning patterns created/used
    - Verification history
    - Trust score progression
    - Reliability assessment

    Example:
        /tmws get_agent_learning_stats --agent_id artemis-optimizer
    """
    # Implementation based on PHASE_1-3_INTEGRATION_PLAN.md section 5.2
```

- [ ] **Verification**: Test manually via MCP

### 3.2 Register New Tools

**File**: `src/mcp_server.py`

- [ ] Import `IntegrationTools`
- [ ] Add to tool registration list
- [ ] Test MCP server startup

```python
from src.tools.integration_tools import IntegrationTools

# In setup_tools():
tools = [
    # ... existing tools ...
    IntegrationTools()
]
```

- [ ] **Verification**: `python -m src.mcp_server` starts without errors

---

## Phase 4: Integration Tests (4 hours)

### 4.1 Create Integration Test File

**File**: `tests/integration/test_learning_trust_verification.py`

#### Task 4.1.1: Setup test fixtures

- [ ] Create `integration_services` fixture
- [ ] Create `test_agent` fixture
- [ ] Create `test_pattern` fixture

```python
@pytest.fixture
async def integration_services(db_session):
    """Provide all three services for integration testing"""
    return {
        "learning": LearningService(),
        "verification": VerificationService(db_session),
        "trust": TrustService(db_session),
        "memory": HybridMemoryService(db_session)
    }

@pytest.fixture
async def test_agent(db_session):
    """Create test agent"""
    agent = Agent(
        agent_id="integration-test-agent",
        display_name="Integration Test Agent",
        namespace="test",
        trust_score=0.5
    )
    db_session.add(agent)
    await db_session.commit()
    return agent
```

#### Task 4.1.2: Test successful pattern workflow

- [ ] Test pattern creation
- [ ] Test pattern application
- [ ] Test verification (accurate)
- [ ] Test trust score increase
- [ ] Test evidence storage
- [ ] Verify all database records

```python
@pytest.mark.asyncio
async def test_successful_pattern_builds_trust(
    db_session,
    integration_services,
    test_agent
):
    """Test that successful pattern usage increases trust"""
    # See PHASE_1-3_INTEGRATION_PLAN.md section 7.2
```

- [ ] **Verification**: `pytest tests/integration/test_learning_trust_verification.py::test_successful_pattern_builds_trust -v`

#### Task 4.1.3: Test failed pattern workflow

- [ ] Test inaccurate verification
- [ ] Test trust score decrease
- [ ] Test evidence marked as INACCURATE
- [ ] Verify pattern success_rate decreases

```python
@pytest.mark.asyncio
async def test_failed_pattern_decreases_trust(
    db_session,
    integration_services,
    test_agent
):
    """Test that failed verification decreases trust"""
    # Implementation...
```

- [ ] **Verification**: Run test

#### Task 4.1.4: Test trust threshold logic

- [ ] Build trust through 10+ verifications
- [ ] Verify `is_reliable` becomes True
- [ ] Verify autonomy threshold crossed

```python
@pytest.mark.asyncio
async def test_trust_threshold_enables_autonomy(
    db_session,
    integration_services,
    test_agent
):
    """Test that high trust enables autonomous operation"""
    # See PHASE_1-3_INTEGRATION_PLAN.md section 7.2
```

- [ ] **Verification**: Run test

#### Task 4.1.5: Test workflow helpers

- [ ] Test `use_pattern_with_verification()` end-to-end
- [ ] Test error handling
- [ ] Test with various claim types

```python
@pytest.mark.asyncio
async def test_use_pattern_with_verification_workflow(
    db_session,
    integration_services,
    test_agent
):
    """Test complete workflow helper"""
    # Implementation...
```

- [ ] **Verification**: Run test

### 4.2 Run Full Test Suite

- [ ] Run all integration tests: `pytest tests/integration/ -v`
- [ ] Verify 100% pass rate
- [ ] Check test coverage: `pytest tests/integration/ --cov=src/services --cov-report=term-missing`
- [ ] Aim for >90% coverage of integration code paths

---

## Phase 5: Performance Testing (2 hours)

### 5.1 Create Performance Test

**File**: `tests/performance/test_integration_performance.py`

#### Task 5.1.1: Test end-to-end latency

- [ ] Measure full workflow latency (pattern → verify → trust)
- [ ] Verify P95 < 600ms
- [ ] Identify bottlenecks

```python
@pytest.mark.benchmark
async def test_full_workflow_latency(benchmark, db_session):
    """Benchmark full workflow latency"""
    # Setup
    services = {...}

    # Benchmark
    result = benchmark(
        lambda: asyncio.run(full_workflow(...))
    )

    # Assert P95 < 600ms
    assert result.stats.quantiles[0.95] < 0.6
```

- [ ] **Verification**: Run benchmark

#### Task 5.1.2: Test concurrent operations

- [ ] Test 10 concurrent verifications
- [ ] Verify no race conditions
- [ ] Verify trust scores calculated correctly

```python
@pytest.mark.asyncio
async def test_concurrent_verifications(db_session):
    """Test concurrent verification handling"""
    tasks = [
        verify_claim(...) for _ in range(10)
    ]
    results = await asyncio.gather(*tasks)

    # Verify all succeeded
    assert all(r.accurate for r in results)

    # Verify trust score updated correctly
    final_trust = await trust_service.get_trust_score(agent_id)
    assert final_trust["total_verifications"] == 10
```

- [ ] **Verification**: Run test

### 5.2 Performance Benchmarks

- [ ] Document baseline performance
- [ ] Create performance regression tests
- [ ] Add to CI/CD pipeline (future)

---

## Phase 6: Documentation (2 hours)

### 6.1 Update API Documentation

**File**: `docs/api/SERVICES_API.md`

- [ ] Document `LearningService.use_pattern_with_verification()`
- [ ] Document `VerificationService.verify_pattern_usage()`
- [ ] Document `TrustService.get_agent_reliability_status()`
- [ ] Add code examples for each
- [ ] Add error handling examples

### 6.2 Create User Guide

**File**: `docs/guides/LEARNING_TRUST_VERIFICATION_GUIDE.md`

- [ ] Write "Getting Started" section
- [ ] Add manual testing scenarios (from PHASE_1-3_INTEGRATION_PLAN.md section 3)
- [ ] Add troubleshooting section
- [ ] Add FAQ section

### 6.3 Update CHANGELOG

**File**: `CHANGELOG.md`

- [ ] Add entry for new integration features
- [ ] List breaking changes (if any)
- [ ] Document new MCP tools
- [ ] Document performance improvements

---

## Phase 7: Manual Testing (2 hours)

### 7.1 Test Scenario 1: Basic Integration

**User**: Developer testing integration

- [ ] Start MCP server: `python -m src.mcp_server`
- [ ] Run: `/tmws test_learning_trust_integration --scenario full`
- [ ] Verify output matches expected format
- [ ] Check database for created records
- [ ] Verify evidence stored in memory

**Expected Output**:
```json
{
  "status": "success",
  "pattern_id": "...",
  "verification_accurate": true,
  "trust_score": 0.55,
  "is_reliable": false,
  "evidence_id": "..."
}
```

- [ ] **Verification**: Screenshot or log output

### 7.2 Test Scenario 2: Build Trust

**User**: Developer testing trust progression

- [ ] Run 10 successful verifications:
  ```bash
  for i in {1..10}; do
    /tmws test_learning_trust_integration --scenario full
  done
  ```
- [ ] Check final trust score: `/tmws get_agent_learning_stats --agent_id test-agent`
- [ ] Verify `is_reliable: true`
- [ ] Verify `trust_score >= 0.7`

- [ ] **Verification**: Log final stats

### 7.3 Test Scenario 3: Trust Decay

**User**: Developer testing trust decrease

- [ ] Create verification with inaccurate claim
- [ ] Manually verify trust score decreased
- [ ] Check evidence marked as INACCURATE

- [ ] **Verification**: Verify trust score < previous score

---

## Phase 8: Code Review & Cleanup (1 hour)

### 8.1 Code Quality Checks

- [ ] Run Ruff: `ruff check src/`
- [ ] Fix any linting issues
- [ ] Run type checker (if enabled): `mypy src/services/`
- [ ] Verify no new warnings

### 8.2 Code Review Checklist

- [ ] All methods have comprehensive docstrings
- [ ] All error cases handled
- [ ] Logging added for debugging
- [ ] No hardcoded values
- [ ] Type hints complete
- [ ] No code duplication
- [ ] Performance considerations addressed

### 8.3 Security Review

- [ ] Verify namespace isolation (no cross-tenant access)
- [ ] Verify authorization checks in place
- [ ] Verify SQL injection prevention (parameterized queries)
- [ ] Verify no sensitive data in logs
- [ ] Review against V-TRUST-1 through V-TRUST-5 vulnerabilities

---

## Phase 9: Deployment (30 minutes)

### 9.1 Database Migration

- [ ] Backup production database (if applicable)
- [ ] Run migration: `alembic upgrade head`
- [ ] Verify migration success
- [ ] Test rollback: `alembic downgrade -1`
- [ ] Re-apply migration: `alembic upgrade head`

### 9.2 Service Deployment

- [ ] Update dependencies (if any)
- [ ] Restart MCP server
- [ ] Verify health check
- [ ] Monitor logs for errors

### 9.3 Smoke Tests

- [ ] Test MCP tools work correctly
- [ ] Test basic pattern creation
- [ ] Test verification workflow
- [ ] Test trust score update

---

## Summary Checklist

### Must-Have (P0)
- [ ] Database migration applied successfully
- [ ] All unit tests pass (100%)
- [ ] All integration tests pass (100%)
- [ ] MCP tools registered and functional
- [ ] Manual test scenarios 1-3 pass
- [ ] Documentation complete

### Should-Have (P1)
- [ ] Performance tests pass (P95 < 600ms)
- [ ] Code review complete
- [ ] Security review complete
- [ ] User guide written

### Nice-to-Have (P2)
- [ ] Performance benchmarks documented
- [ ] Advanced workflow scenarios tested
- [ ] CI/CD integration (future)

---

## Estimated Timeline

| Phase | Estimated Time | Cumulative |
|-------|---------------|------------|
| 1. Database Schema | 2 hours | 2 hours |
| 2. Service Layer | 4 hours | 6 hours |
| 3. MCP Tools | 3 hours | 9 hours |
| 4. Integration Tests | 4 hours | 13 hours |
| 5. Performance Tests | 2 hours | 15 hours |
| 6. Documentation | 2 hours | 17 hours |
| 7. Manual Testing | 2 hours | 19 hours |
| 8. Code Review | 1 hour | 20 hours |
| 9. Deployment | 30 min | 20.5 hours |

**Total Estimated Time**: 20.5 hours (~3 working days)

---

## Success Criteria

**Definition of Done**:
1. ✅ All checkboxes above marked complete
2. ✅ All tests pass (unit + integration + performance)
3. ✅ Manual testing scenarios verified
4. ✅ Documentation complete and reviewed
5. ✅ Code review approved
6. ✅ Deployed successfully to target environment

**Acceptance Criteria**:
- User can run `/tmws test_learning_trust_integration` and get results
- User can run `/tmws get_agent_learning_stats` and see comprehensive data
- Full workflow completes in <600ms P95
- Trust score increases after accurate verifications
- Trust score decreases after inaccurate verifications
- Evidence stored and retrievable

---

**End of Implementation Checklist**

*"A checklist is not a burden, it's a guarantee of excellence through systematic execution."*

— Athena, Harmonious Conductor
