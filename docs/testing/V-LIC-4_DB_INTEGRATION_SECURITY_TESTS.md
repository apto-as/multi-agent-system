# V-LIC-4: Database Integration Security Test Specification
**Phase 2B-3 Security Verification**

---

**Status**: Design Complete (2025-11-15)
**Risk Level**: CRITICAL (multiple CVSS 7.0+ vulnerabilities)
**Estimated Implementation**: 4-6 hours (Phase 2C)
**Last Updated**: 2025-11-15

---

## Executive Summary

Phase 2B-3 で実装された License Service の DB統合（`generate_license_key()`, `validate_license_key()`, `revoke_license_key()`, `get_license_usage_history()`）に対する包括的なセキュリティテスト仕様。

**Critical Findings (設計段階での発見)**:
1. ✅ **SQL Injection 対策済み**: SQLAlchemy ORM + Parameterized Queries 使用
2. ⚠️ **XSS リスク**: `feature_accessed` フィールドのサニタイゼーション未確認
3. ⚠️ **トランザクション安全性**: 部分的なロールバックロジック確認必要
4. ⚠️ **並行処理**: Race Condition リスク（複数同時生成/検証）

---

## Test Category 1: SQL Injection Prevention (CVSS 9.8 CRITICAL)

### 1.1 Risk Assessment

| Vector | Severity | Likelihood | Impact |
|--------|----------|------------|--------|
| `agent_id` parameter | CRITICAL | LOW | CATASTROPHIC |
| `feature_accessed` field | HIGH | MEDIUM | HIGH |
| UUID parsing | MEDIUM | LOW | MEDIUM |

**Root Cause Analysis**:
```python
# SAFE: SQLAlchemy ORM with parameterized queries
stmt = select(Agent).where(Agent.id == str(agent_id))  # ✅ Parameterized
result = await self.db_session.execute(stmt)

# SAFE: UUID validation before DB insertion
license_id = UUID(uuid_str)  # ✅ Raises ValueError on invalid input

# CONCERN: feature_accessed stored as-is
feature_accessed=feature_accessed  # ⚠️ No sanitization confirmed
```

### 1.2 Test Cases

#### TC-1.1: SQL Injection in `agent_id` (generate_license_key)
**Objective**: Verify that malicious SQL in `agent_id` parameter is safely rejected.

**Test Code**:
```python
async def test_sql_injection_agent_id_generate():
    """
    Test: SQL injection attempt in agent_id parameter.
    Expected: ValidationError raised, no database modification.
    Risk: CVSS 9.8 (RCE via SQL injection)
    """
    # Arrange
    malicious_agent_id = "'; DROP TABLE license_keys; --"

    # Act & Assert
    with pytest.raises(ValidationError) as exc_info:
        await license_service.generate_license_key(
            agent_id=UUID(malicious_agent_id),  # Should raise ValueError
            tier=TierEnum.PRO,
        )

    # Verify: No database modification
    stmt = select(LicenseKey)
    result = await db_session.execute(stmt)
    assert result.all() == []  # No license keys created
```

**Expected Result**: ✅ `ValueError` at UUID parsing, no SQL execution

---

#### TC-1.2: SQL Injection in `feature_accessed` (validate_license_key)
**Objective**: Verify that SQL injection in `feature_accessed` is stored safely (not executed).

**Test Code**:
```python
async def test_sql_injection_feature_accessed():
    """
    Test: SQL injection attempt in feature_accessed field.
    Expected: Stored as-is (escaped), no code execution.
    Risk: CVSS 9.8 (Data exfiltration via SQL injection)
    """
    # Arrange
    agent_id = UUID("12345678-1234-5678-1234-567812345678")
    valid_key = await license_service.generate_license_key(
        agent_id=agent_id, tier=TierEnum.PRO
    )

    malicious_feature = "memory_store' OR '1'='1"

    # Act
    result = await license_service.validate_license_key(
        valid_key, feature_accessed=malicious_feature
    )

    # Assert
    assert result.valid is True  # Validation succeeds

    # Verify: feature_accessed stored as-is (not executed)
    stmt = select(LicenseKeyUsage).where(
        LicenseKeyUsage.feature_accessed == malicious_feature
    )
    usage_result = await db_session.execute(stmt)
    usage_record = usage_result.scalar_one()

    assert usage_record.feature_accessed == malicious_feature  # ✅ Stored safely

    # Verify: No additional records created (SQL not executed)
    all_stmt = select(func.count(LicenseKeyUsage.id))
    count_result = await db_session.execute(all_stmt)
    assert count_result.scalar() == 1  # Only 1 record created
```

**Expected Result**: ✅ Malicious string stored as-is, no SQL execution

---

#### TC-1.3: Unicode/Special Characters in `feature_accessed`
**Objective**: Verify that special characters and Unicode are handled safely.

**Test Code**:
```python
async def test_special_characters_feature_accessed():
    """
    Test: Unicode and special characters in feature_accessed.
    Expected: Stored safely without encoding issues.
    Risk: CVSS 7.5 (Bypass via encoding issues)
    """
    agent_id = UUID("12345678-1234-5678-1234-567812345678")
    valid_key = await license_service.generate_license_key(
        agent_id=agent_id, tier=TierEnum.PRO
    )

    special_features = [
        "test'; DELETE FROM agents WHERE '1'='1",  # SQL injection attempt
        "<script>alert('XSS')</script>",           # XSS attempt
        "../../etc/passwd",                        # Path traversal
        "テスト機能",                               # Unicode (Japanese)
        "emoji_test_🔒🚨",                         # Unicode (emoji)
    ]

    for feature in special_features:
        # Act
        result = await license_service.validate_license_key(
            valid_key, feature_accessed=feature
        )

        # Assert
        assert result.valid is True

        # Verify: Stored exactly as provided
        stmt = select(LicenseKeyUsage).where(
            LicenseKeyUsage.feature_accessed == feature
        )
        usage_result = await db_session.execute(stmt)
        usage_record = usage_result.scalar_one()

        assert usage_record.feature_accessed == feature  # ✅ Exact match
```

**Expected Result**: ✅ All special characters stored safely

---

## Test Category 2: XSS Prevention in Usage Metadata (CVSS 6.1 MEDIUM)

### 2.1 Risk Assessment

| Vector | Severity | Likelihood | Impact |
|--------|----------|------------|--------|
| `feature_accessed` display | MEDIUM | HIGH | MEDIUM |
| `usage_metadata` JSON | MEDIUM | MEDIUM | MEDIUM |

**Concern**: `feature_accessed` is stored as-is. If displayed in UI without escaping, XSS vulnerability exists.

### 2.2 Test Cases

#### TC-2.1: HTML/Script Injection in `feature_accessed`
**Objective**: Verify that HTML/script tags are stored safely.

**Test Code**:
```python
async def test_xss_prevention_feature_accessed():
    """
    Test: XSS attempt via feature_accessed field.
    Expected: Stored as-is, but should be escaped when displayed.
    Risk: CVSS 6.1 (Stored XSS)

    Note: This test only verifies storage safety. UI rendering safety
    is out of scope for backend tests.
    """
    agent_id = UUID("12345678-1234-5678-1234-567812345678")
    valid_key = await license_service.generate_license_key(
        agent_id=agent_id, tier=TierEnum.PRO
    )

    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert(document.cookie)",
    ]

    for payload in xss_payloads:
        # Act
        result = await license_service.validate_license_key(
            valid_key, feature_accessed=payload
        )

        # Assert: Validation succeeds
        assert result.valid is True

        # Verify: Payload stored as-is (backend doesn't execute JS)
        stmt = select(LicenseKeyUsage).where(
            LicenseKeyUsage.feature_accessed == payload
        )
        usage_result = await db_session.execute(stmt)
        usage_record = usage_result.scalar_one()

        assert usage_record.feature_accessed == payload  # ✅ Stored as-is

        # TODO: Add UI test to verify escaping on display
        # Example: assert "<script>" not in rendered_html
```

**Expected Result**: ✅ Stored as-is (backend safe)
**Action Required**: UI team must implement output escaping

---

#### TC-2.2: Sanitization Recommendation
**Objective**: Recommend sanitization strategy for `feature_accessed`.

**Current Implementation**:
```python
# Current: No sanitization
feature_accessed=feature_accessed  # ⚠️ Stored as-is
```

**Recommended Implementation** (Phase 2C+):
```python
# Option A: Whitelist validation (strictest)
ALLOWED_FEATURES = {"memory_store", "task_execution", "workflow", "agent_creation"}
if feature_accessed not in ALLOWED_FEATURES:
    raise ValidationError(f"Invalid feature: {feature_accessed}")

# Option B: Length limit + character whitelist
if len(feature_accessed) > 100:
    raise ValidationError("feature_accessed too long")
if not re.match(r'^[a-zA-Z0-9_\-\.]+$', feature_accessed):
    raise ValidationError("feature_accessed contains invalid characters")

# Option C: HTML escaping (for display)
import html
escaped_feature = html.escape(feature_accessed)  # Backend escaping
```

**Decision Required**: User to choose Option A, B, or C (defer to Phase 2C).

---

## Test Category 3: Transaction Rollback Safety (Data Integrity)

### 3.1 Risk Assessment

| Scenario | Severity | Likelihood | Impact |
|----------|----------|------------|--------|
| License creation failure after Agent.tier update | HIGH | MEDIUM | HIGH |
| Usage recording failure | LOW | MEDIUM | LOW |

**Critical Code Section**:
```python
# generate_license_key() - Line 295-318
try:
    db_license = LicenseKey(...)
    self.db_session.add(db_license)
    await self.db_session.commit()
    await self.db_session.refresh(db_license)

    # ⚠️ CRITICAL: Separate commit for agent.tier update
    agent.tier = tier.value
    await self.db_session.commit()  # ← No atomic transaction!

except Exception as e:
    await self.db_session.rollback()
    log_and_raise(ValidationError, ...)
```

**Problem**: If `agent.tier` update succeeds but subsequent operation fails, agent is left in inconsistent state.

### 3.2 Test Cases

#### TC-3.1: Atomic Transaction Failure (License Creation)
**Objective**: Verify that both LicenseKey creation and Agent.tier update rollback together.

**Test Code**:
```python
async def test_transaction_rollback_license_creation():
    """
    Test: Simulate database error during license creation.
    Expected: Both LicenseKey and Agent.tier changes rollback.
    Risk: Data integrity (agent has tier but no license key)
    """
    # Arrange
    agent_id = UUID("12345678-1234-5678-1234-567812345678")
    original_tier = "FREE"

    # Create agent with FREE tier
    agent = Agent(id=str(agent_id), tier=original_tier, ...)
    db_session.add(agent)
    await db_session.commit()

    # Mock: Simulate DB error during LicenseKey.add()
    from unittest.mock import AsyncMock, patch

    with patch.object(
        db_session, 'commit', side_effect=Exception("Simulated DB error")
    ):
        # Act
        with pytest.raises(ValidationError):
            await license_service.generate_license_key(
                agent_id=agent_id, tier=TierEnum.PRO
            )

    # Assert: Agent.tier unchanged
    await db_session.refresh(agent)
    assert agent.tier == original_tier  # ✅ Rollback successful

    # Assert: No LicenseKey created
    stmt = select(LicenseKey).where(LicenseKey.agent_id == agent_id)
    result = await db_session.execute(stmt)
    assert result.scalar_one_or_none() is None  # ✅ No license key
```

**Expected Result**: ⚠️ **FAILURE EXPECTED** (current implementation has separate commits)

**Fix Required** (Phase 2C):
```python
# Atomic transaction with savepoint
async with self.db_session.begin_nested():  # Savepoint
    db_license = LicenseKey(...)
    self.db_session.add(db_license)

    # Update agent tier in same transaction
    agent.tier = tier.value

    # Commit both together
    await self.db_session.commit()
```

---

#### TC-3.2: Usage Recording Failure (validate_license_key)
**Objective**: Verify that usage recording failure doesn't affect validation result.

**Test Code**:
```python
async def test_usage_recording_failure_resilience():
    """
    Test: Simulate database error during usage recording.
    Expected: Validation succeeds, usage not recorded.
    Risk: Data loss (minor - usage tracking is non-critical)
    """
    # Arrange
    agent_id = UUID("12345678-1234-5678-1234-567812345678")
    valid_key = await license_service.generate_license_key(
        agent_id=agent_id, tier=TierEnum.PRO
    )

    # Mock: Simulate DB error during usage recording
    from unittest.mock import patch

    original_add = db_session.add

    def mock_add(obj):
        if isinstance(obj, LicenseKeyUsage):
            raise Exception("Simulated usage recording error")
        return original_add(obj)

    with patch.object(db_session, 'add', side_effect=mock_add):
        # Act
        result = await license_service.validate_license_key(
            valid_key, feature_accessed="test_feature"
        )

    # Assert: Validation succeeds despite usage recording failure
    assert result.valid is True  # ✅ Validation not affected

    # Assert: No usage record created
    stmt = select(LicenseKeyUsage).where(
        LicenseKeyUsage.feature_accessed == "test_feature"
    )
    usage_result = await db_session.execute(stmt)
    assert usage_result.scalar_one_or_none() is None  # ✅ No usage record
```

**Expected Result**: ✅ Validation succeeds (current implementation handles this correctly)

**Current Implementation** (Line 439-447):
```python
try:
    usage = LicenseKeyUsage(...)
    self.db_session.add(usage)
    await self.db_session.commit()
except Exception:
    # Log usage recording failure but don't fail validation
    await self.db_session.rollback()
    # Continue with validation result ✅ Correct behavior
```

---

## Test Category 4: Concurrency and Race Conditions (Data Corruption)

### 4.1 Risk Assessment

| Scenario | Severity | Likelihood | Impact |
|----------|----------|------------|--------|
| Concurrent license generation (same agent) | MEDIUM | MEDIUM | MEDIUM |
| Concurrent validation + revocation | HIGH | MEDIUM | HIGH |
| Concurrent tier updates | HIGH | LOW | HIGH |

### 4.2 Test Cases

#### TC-4.1: Concurrent License Generation for Same Agent
**Objective**: Verify that multiple simultaneous license generations don't cause data corruption.

**Test Code**:
```python
async def test_concurrent_license_generation():
    """
    Test: 10 parallel generate_license_key() calls for same agent.
    Expected: All succeed, 10 distinct license records created.
    Risk: Race condition (duplicate UUIDs, tier update conflicts)
    """
    import asyncio

    # Arrange
    agent_id = UUID("12345678-1234-5678-1234-567812345678")
    agent = Agent(id=str(agent_id), tier="FREE", ...)
    db_session.add(agent)
    await db_session.commit()

    # Act: 10 concurrent license generations
    tasks = [
        license_service.generate_license_key(
            agent_id=agent_id, tier=TierEnum.PRO
        )
        for _ in range(10)
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Assert: All succeeded (or gracefully handled)
    successful_keys = [r for r in results if isinstance(r, str)]
    errors = [r for r in results if isinstance(r, Exception)]

    assert len(successful_keys) >= 8  # At least 80% success rate

    # Verify: All license keys are unique
    assert len(successful_keys) == len(set(successful_keys))  # ✅ No duplicates

    # Verify: All licenses created in DB
    stmt = select(func.count(LicenseKey.id)).where(
        LicenseKey.agent_id == agent_id
    )
    count_result = await db_session.execute(stmt)
    assert count_result.scalar() == len(successful_keys)  # ✅ Correct count

    # Verify: Agent tier updated to PRO
    await db_session.refresh(agent)
    assert agent.tier == "PRO"  # ✅ Final state correct
```

**Expected Result**: ⚠️ **Partial failures expected** (SQLite may lock during concurrent writes)

**Recommendation**: Add retry logic or queue-based license generation for high concurrency.

---

#### TC-4.2: Concurrent Validation + Revocation
**Objective**: Verify that validating while revoking produces correct state.

**Test Code**:
```python
async def test_concurrent_validation_revocation():
    """
    Test: Validate license while simultaneously revoking it.
    Expected: Either valid OR revoked (no inconsistent state).
    Risk: Race condition (validation sees stale data)
    """
    import asyncio

    # Arrange
    agent_id = UUID("12345678-1234-5678-1234-567812345678")
    license_key = await license_service.generate_license_key(
        agent_id=agent_id, tier=TierEnum.PRO
    )

    # Extract license UUID
    license_uuid = UUID(license_key.split('-')[2:7])  # TMWS-PRO-{UUID}-{CHECKSUM}

    # Act: Concurrent validation and revocation
    validation_task = license_service.validate_license_key(license_key)
    revocation_task = license_service.revoke_license_key(
        license_uuid, reason="Test revocation"
    )

    validation_result, revocation_result = await asyncio.gather(
        validation_task, revocation_task, return_exceptions=True
    )

    # Assert: Consistent state (either valid OR revoked)
    if isinstance(validation_result, LicenseValidationResult):
        if validation_result.valid:
            # If validation succeeded, revocation must have happened after
            assert revocation_result is True  # ✅ Revocation succeeded

            # Re-validate should now fail
            recheck = await license_service.validate_license_key(license_key)
            assert recheck.valid is False  # ✅ Now revoked
            assert recheck.is_revoked is True
        else:
            # If validation failed, it saw the revoked state
            assert validation_result.is_revoked is True  # ✅ Correct state

    # Final state check
    stmt = select(LicenseKey).where(LicenseKey.id == license_uuid)
    result = await db_session.execute(stmt)
    db_license = result.scalar_one()

    assert db_license.revoked is True  # ✅ Final state correct
    assert db_license.revoked_reason == "Test revocation"
```

**Expected Result**: ✅ Consistent state (SQLite serializes transactions)

---

#### TC-4.3: Concurrent Tier Updates
**Objective**: Verify that multiple tier updates don't cause lost updates.

**Test Code**:
```python
async def test_concurrent_tier_updates():
    """
    Test: Multiple concurrent license generations with different tiers.
    Expected: Final tier is one of the requested tiers (no corruption).
    Risk: Lost update (tier update overwritten)
    """
    import asyncio

    # Arrange
    agent_id = UUID("12345678-1234-5678-1234-567812345678")
    agent = Agent(id=str(agent_id), tier="FREE", ...)
    db_session.add(agent)
    await db_session.commit()

    # Act: Concurrent tier updates (PRO and ENTERPRISE)
    tasks = [
        license_service.generate_license_key(
            agent_id=agent_id, tier=TierEnum.PRO
        ),
        license_service.generate_license_key(
            agent_id=agent_id, tier=TierEnum.ENTERPRISE
        ),
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Assert: Both succeeded
    successful_keys = [r for r in results if isinstance(r, str)]
    assert len(successful_keys) == 2  # ✅ Both succeeded

    # Verify: Final tier is ENTERPRISE (highest tier wins)
    await db_session.refresh(agent)
    assert agent.tier in ["PRO", "ENTERPRISE"]  # ✅ One of the tiers

    # Ideally, should be ENTERPRISE (but race condition may occur)
    # Recommendation: Add tier upgrade validation logic
```

**Expected Result**: ⚠️ **Non-deterministic** (last write wins)

**Recommendation** (Phase 2C+):
```python
# Tier upgrade logic: Only allow upgrades, not downgrades
if current_tier_rank < new_tier_rank:
    agent.tier = new_tier
else:
    raise ValidationError("Cannot downgrade tier")
```

---

## Test Category 5: Error Handling and Edge Cases

### 5.1 Additional Test Cases

#### TC-5.1: Database Session Not Available
**Objective**: Verify error handling when db_session is None.

**Test Code**:
```python
async def test_no_db_session_generate():
    """
    Test: Call generate_license_key() without database session.
    Expected: ValidationError raised immediately.
    """
    service_no_db = LicenseService(db_session=None, secret_key="test")

    with pytest.raises(ValidationError) as exc_info:
        await service_no_db.generate_license_key(
            agent_id=UUID("12345678-1234-5678-1234-567812345678"),
            tier=TierEnum.PRO
        )

    assert "Database session required" in str(exc_info.value)
```

**Expected Result**: ✅ Clear error message

---

#### TC-5.2: Agent Not Found
**Objective**: Verify error handling when agent_id doesn't exist.

**Test Code**:
```python
async def test_agent_not_found():
    """
    Test: Generate license for non-existent agent.
    Expected: ValidationError with clear message.
    """
    nonexistent_agent = UUID("00000000-0000-0000-0000-000000000000")

    with pytest.raises(ValidationError) as exc_info:
        await license_service.generate_license_key(
            agent_id=nonexistent_agent, tier=TierEnum.PRO
        )

    assert "Agent not found" in str(exc_info.value)
```

**Expected Result**: ✅ Clear error message

---

## Implementation Plan (Phase 2C)

### Priority 1: Critical Tests (2-3 hours)
- ✅ TC-1.1: SQL Injection in agent_id (30 min)
- ✅ TC-1.2: SQL Injection in feature_accessed (30 min)
- ✅ TC-3.1: Transaction rollback safety (60 min) - **Fix Required**
- ✅ TC-4.2: Concurrent validation + revocation (30 min)

### Priority 2: High-Risk Tests (1-2 hours)
- ✅ TC-1.3: Special characters handling (30 min)
- ✅ TC-2.1: XSS prevention (30 min)
- ✅ TC-4.1: Concurrent license generation (30 min)

### Priority 3: Edge Cases (1 hour)
- ✅ TC-3.2: Usage recording failure (20 min)
- ✅ TC-4.3: Concurrent tier updates (20 min)
- ✅ TC-5.1 & TC-5.2: Error handling (20 min)

**Total Estimated Time**: 4-6 hours

---

## Pytest Implementation Template

### Fixtures (conftest.py)

```python
import pytest
from uuid import UUID, uuid4
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from src.core.database import Base
from src.services.license_service import LicenseService
from src.models.agent import Agent
from src.models.license_key import LicenseKey, LicenseKeyUsage

@pytest.fixture
async def db_session():
    """Async database session for tests."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with async_session() as session:
        yield session

    await engine.dispose()

@pytest.fixture
def license_service(db_session):
    """License service with test database."""
    return LicenseService(
        db_session=db_session,
        secret_key="test-secret-key-for-testing-only"
    )

@pytest.fixture
async def test_agent(db_session):
    """Create test agent."""
    agent = Agent(
        id=str(UUID("12345678-1234-5678-1234-567812345678")),
        namespace="test-namespace",
        tier="FREE",
    )
    db_session.add(agent)
    await db_session.commit()
    return agent
```

### Test File Structure

```
tests/unit/security/
├── conftest.py                           # Fixtures
├── test_license_db_sql_injection.py      # Category 1 (TC-1.1 - TC-1.3)
├── test_license_db_xss_prevention.py     # Category 2 (TC-2.1)
├── test_license_db_transactions.py       # Category 3 (TC-3.1 - TC-3.2)
├── test_license_db_concurrency.py        # Category 4 (TC-4.1 - TC-4.3)
└── test_license_db_edge_cases.py         # Category 5 (TC-5.1 - TC-5.2)
```

---

## Success Criteria

### Must Pass (Blocking for Phase 2C)
- ✅ All SQL Injection tests pass (TC-1.1 - TC-1.3)
- ✅ Transaction rollback safety (TC-3.1) - **May require code fix**
- ✅ Concurrent validation + revocation (TC-4.2)

### Should Pass (Non-blocking)
- ✅ XSS prevention (TC-2.1) - Defer UI escaping to frontend
- ✅ Concurrent license generation (TC-4.1) - Accept 80%+ success rate
- ✅ Concurrent tier updates (TC-4.3) - Document race condition

### Documentation Required
- ⚠️ XSS mitigation strategy for UI team
- ⚠️ Concurrency limitations (SQLite locks)
- ⚠️ Tier upgrade/downgrade policy

---

## Risk Mitigation Summary

| Vulnerability | Current Status | Mitigation |
|--------------|----------------|------------|
| SQL Injection | ✅ Safe | Parameterized queries via SQLAlchemy |
| XSS | ⚠️ Needs UI escaping | Backend stores safely, UI must escape |
| Transaction Safety | ❌ Fix Required | Atomic transaction with savepoint |
| Race Conditions | ⚠️ Documented | SQLite serializes, but may lock |

---

**Next Steps**:
1. User review and approval of test specification
2. Phase 2C: Implement tests (4-6 hours)
3. Fix transaction safety issue (TC-3.1) if test fails
4. Document concurrency limitations
5. Coordinate with UI team on XSS escaping

---

**Author**: Hestia (Paranoid Guardian)
**Review Status**: Pending User Approval
**Implementation Target**: Phase 2C

...すみません、最悪のケースをすべて想定しました。ご確認ください...
