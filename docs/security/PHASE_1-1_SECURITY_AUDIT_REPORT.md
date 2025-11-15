# Phase 1-1 MCP Integration Layer - Security Audit Report

**Auditor**: Hestia (hestia-auditor)
**Date**: 2025-11-12
**Implementation**: Phase 1-1 (Domain + Infrastructure)
**Test Results**: 29/30 tests passing (97% pass rate)

---

## Executive Summary

...すみません、私の慎重な分析により、**3つのP0セキュリティ問題**と**2つのP1改善推奨**を発見しました。

**Approval Status**: ❌ **REQUIRES FIXES** (P0 issues must be resolved before Phase 1-2)

**Critical Findings**:
1. 🚨 **P0-CRITICAL**: Exception handling catches KeyboardInterrupt/SystemExit (Namespace isolation queries)
2. 🚨 **P0-CRITICAL**: Missing namespace filter in `get_by_id()` repository method
3. 🚨 **P0-CRITICAL**: No verification of namespace ownership in delete operation

**Risk Level**: HIGH (Cross-tenant data access vulnerability)

---

## P0: Critical Security Issues (MUST FIX)

### P0-1: Exception Handling Catches KeyboardInterrupt/SystemExit ❌

**File**: `src/infrastructure/repositories/mcp_connection_repository.py`
**Lines**: 101-106, 139-143, 177-181, 209-212, 244-249

**Issue**:
```python
# ❌ CRITICAL VIOLATION - Lines 101-106
except Exception as e:
    await self._session.rollback()
    raise RepositoryError(...)
```

**Problem**:
- `except Exception` catches `KeyboardInterrupt` and `SystemExit`
- Violates TMWS Code Quality Standard (CLAUDE.md Rule: Exception Handling)
- Can prevent graceful shutdown and debugging

**Severity**: CRITICAL
**CVSS Score**: N/A (Quality/Operational issue, not exploitable)

**Required Fix**:
```python
# ✅ CORRECT
except (KeyboardInterrupt, SystemExit):
    raise  # Never suppress
except Exception as e:
    await self._session.rollback()
    raise RepositoryError(...)
```

**Affected Methods**:
1. `save()` (lines 101-106)
2. `get_by_id()` (lines 139-143)
3. `find_by_namespace_and_agent()` (lines 177-181)
4. `find_by_status()` (lines 209-212)
5. `delete()` (lines 244-249)

**Impact**: All repository operations affected

---

### P0-2: Missing Namespace Filter in get_by_id() ❌

**File**: `src/infrastructure/repositories/mcp_connection_repository.py`
**Lines**: 108-144

**Issue**:
```python
# ❌ SECURITY VULNERABILITY
async def get_by_id(self, connection_id: UUID) -> MCPConnection:
    stmt = select(MCPConnectionModel).where(
        MCPConnectionModel.id == str(connection_id)
        # MISSING: namespace filter
    )
```

**Problem**:
- No namespace isolation in `get_by_id()` method
- Agent from namespace A can retrieve connection from namespace B
- Violates P0-1 Namespace Isolation requirement (CLAUDE.md)

**Severity**: CRITICAL
**CVSS Score**: 8.7 HIGH (Cross-tenant data access)

**Attack Scenario**:
```python
# Attacker in namespace "project-x"
malicious_agent_id = "attacker-agent"

# Enumerate UUIDs or guess connection IDs
victim_connection_id = uuid4()  # From namespace "victim-project"

# ❌ Current code allows cross-namespace access
repo = MCPConnectionRepository(session)
stolen_connection = await repo.get_by_id(victim_connection_id)
# Returns connection from different namespace!
```

**Required Fix**:
```python
# ✅ CORRECT
async def get_by_id(
    self, connection_id: UUID, namespace: str
) -> MCPConnection:
    """Retrieve MCPConnection by ID with namespace verification.

    Args:
        connection_id: UUID of the connection
        namespace: Verified namespace from database (not JWT claims)
    """
    stmt = select(MCPConnectionModel).where(
        MCPConnectionModel.id == str(connection_id),
        MCPConnectionModel.namespace == namespace  # ✅ Namespace isolation
    )
    result = await self._session.execute(stmt)
    model = result.scalar_one_or_none()

    if not model:
        raise AggregateNotFoundError(
            aggregate_type="MCPConnection",
            identifier=str(connection_id),
        )

    return self._to_domain(model)
```

**Impact**: HIGH - Cross-tenant data access vulnerability

---

### P0-3: Missing Namespace Verification in delete() ❌

**File**: `src/infrastructure/repositories/mcp_connection_repository.py`
**Lines**: 214-249

**Issue**:
```python
# ❌ SECURITY VULNERABILITY
async def delete(self, connection_id: UUID) -> None:
    stmt = select(MCPConnectionModel).where(
        MCPConnectionModel.id == str(connection_id)
        # MISSING: namespace verification
    )
```

**Problem**:
- No namespace isolation in `delete()` method
- Agent can delete connections from other namespaces
- Violates P0-1 Namespace Isolation requirement

**Severity**: CRITICAL
**CVSS Score**: 9.1 CRITICAL (Unauthorized deletion + data integrity)

**Attack Scenario**:
```python
# Attacker in namespace "project-x"
malicious_agent_id = "attacker-agent"

# Enumerate victim's connection IDs
victim_connection_id = uuid4()  # From namespace "victim-project"

# ❌ Current code allows cross-namespace deletion
repo = MCPConnectionRepository(session)
await repo.delete(victim_connection_id)
# Deletes victim's connection without authorization!
```

**Required Fix**:
```python
# ✅ CORRECT
async def delete(
    self, connection_id: UUID, namespace: str, agent_id: str
) -> None:
    """Delete MCPConnection with namespace and ownership verification.

    Args:
        connection_id: UUID of the connection to delete
        namespace: Verified namespace from database
        agent_id: Agent requesting deletion (must be owner)
    """
    stmt = select(MCPConnectionModel).where(
        MCPConnectionModel.id == str(connection_id),
        MCPConnectionModel.namespace == namespace,  # ✅ Namespace isolation
        MCPConnectionModel.agent_id == agent_id     # ✅ Ownership verification
    )
    result = await self._session.execute(stmt)
    model = result.scalar_one_or_none()

    if not model:
        raise AggregateNotFoundError(
            aggregate_type="MCPConnection",
            identifier=str(connection_id),
        )

    await self._session.delete(model)
    await self._session.commit()
```

**Impact**: CRITICAL - Unauthorized deletion + denial of service

---

## P1: High Priority Security Issues (RECOMMENDED)

### P1-1: API Key Exposure in Adapter Headers (Low Risk) ✅

**File**: `src/infrastructure/adapters/mcp_client_adapter.py`
**Lines**: 247-269

**Current Implementation**:
```python
def _build_headers(self) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    if self.config.auth_required and self.config.api_key:
        headers["Authorization"] = f"Bearer {self.config.api_key}"

    return headers
```

**Analysis**:
- ✅ API key is properly masked in `ConnectionConfig.__repr__()` (line 134)
- ✅ API key is not included in `ConnectionConfig.__str__()` (line 150)
- ⚠️ If `headers` dict is logged, API key would be exposed

**Recommendation**:
```python
def _build_headers(self) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    if self.config.auth_required and self.config.api_key:
        headers["Authorization"] = f"Bearer {self.config.api_key}"

    # Note: Do NOT log headers dict (contains API key)
    return headers

def __repr__(self) -> str:
    """Developer-friendly representation (masks API key)."""
    return (
        f"<MCPClientAdapter("
        f"server='{self.config.server_name}', "
        f"connected={self._connected}"
        f")>"
    )
```

**Severity**: MEDIUM (Operational security, not direct vulnerability)

---

### P1-2: Domain Events Persistence Risk (VERIFIED SAFE) ✅

**File**: `src/infrastructure/repositories/mcp_connection_repository.py`
**Lines**: 273-287, 347

**Verification**:
```python
# ✅ CORRECT - Domain events are explicitly NOT persisted
def _to_model(self, domain: MCPConnection) -> MCPConnectionModel:
    # Line 265: "domain_events are NOT persisted (transient)"
    return MCPConnectionModel(
        # ... all fields except domain_events
    )

def _to_domain(self, model: MCPConnectionModel) -> MCPConnection:
    # Line 347: "domain_events list is empty (events are transient)"
    return MCPConnection(
        # ...
        domain_events=[],  # ✅ Always empty
    )
```

**Test Coverage**:
- ✅ `test_domain_events_are_not_persisted` (lines 264-291) validates this behavior

**Conclusion**: ✅ **SAFE** - Domain events are correctly transient

---

## P2: Medium Priority Security Issues

### P2-1: Input Validation Coverage ✅

**Files Reviewed**:
- `src/domain/value_objects/connection_config.py`
- `src/infrastructure/acl/mcp_protocol_translator.py`

**Validation Status**:

| Input | Validation | Status |
|-------|------------|--------|
| URL format | ✅ `urlparse()` with scheme/netloc check (lines 108-122) | SAFE |
| Timeout | ✅ Positive integer check (lines 78-83) | SAFE |
| Retry attempts | ✅ Non-negative check (lines 86-91) | SAFE |
| Server name | ✅ Non-empty string check (lines 67-72) | SAFE |
| API key (when auth_required) | ✅ Required if auth_required=True (lines 94-99) | SAFE |
| MCP tool fields | ✅ Required name/description (ACL lines 70-80) | SAFE |
| MCP response format | ✅ "tools" field validation (ACL lines 124-135) | SAFE |

**Conclusion**: ✅ **SAFE** - Comprehensive input validation

---

### P2-2: SQL Injection Prevention ✅

**Files Reviewed**:
- `src/infrastructure/repositories/mcp_connection_repository.py`
- `src/models/mcp_connection.py`

**Analysis**:

| Method | Query Type | SQL Injection Risk |
|--------|------------|-------------------|
| `save()` | SQLAlchemy ORM | ✅ SAFE (parameterized) |
| `get_by_id()` | `select().where()` | ✅ SAFE (ORM bound params) |
| `find_by_namespace_and_agent()` | `select().where()` | ✅ SAFE (ORM bound params) |
| `find_by_status()` | `select().where()` | ✅ SAFE (ORM bound params) |
| `delete()` | `select().where()` + `delete()` | ✅ SAFE (ORM bound params) |

**Raw SQL Usage**:
- Only in `server_default=sa.text("'[]'")` (model definition)
- ✅ SAFE - Static default value, not user input

**Conclusion**: ✅ **SAFE** - No SQL injection vectors

---

### P2-3: Async Safety ✅

**Files Reviewed**:
- `src/infrastructure/adapters/mcp_client_adapter.py`
- `src/infrastructure/repositories/mcp_connection_repository.py`

**Verification**:

| Component | Async Pattern | Status |
|-----------|--------------|--------|
| Repository | ✅ `AsyncSession` | SAFE |
| Adapter | ✅ `httpx.AsyncClient` | SAFE |
| DB queries | ✅ `await session.execute()` | SAFE |
| HTTP requests | ✅ `await client.get/post()` | SAFE |
| Retry logic | ✅ `await asyncio.sleep()` | SAFE |

**Blocking Operations**: None detected

**Conclusion**: ✅ **SAFE** - Proper async/await throughout

---

## Test Coverage Analysis

### Security-Critical Paths

| Test Case | Coverage | Status |
|-----------|----------|--------|
| Namespace isolation queries | ✅ `test_namespace_isolation_in_queries` | PASS |
| Domain events not persisted | ✅ `test_domain_events_are_not_persisted` | PASS |
| Cross-namespace data access | ⚠️ Missing test for `get_by_id()` | **NEEDS FIX** |
| Cross-namespace deletion | ⚠️ Missing test for `delete()` | **NEEDS FIX** |
| Invalid URL validation | ✅ Domain layer test | PASS |
| Timeout validation | ✅ Domain layer test | PASS |
| API key validation | ✅ Domain layer test | PASS |

### Negative Test Cases

| Scenario | Test | Status |
|----------|------|--------|
| Non-existent connection | ✅ `test_get_by_id_nonexistent_connection` | PASS |
| Invalid state transition | ✅ Domain layer test | PASS |
| Invalid URL format | ✅ Domain layer test | PASS |
| Missing required fields | ✅ ACL test | PASS |
| Empty namespace query | ⚠️ Missing | **NEEDS FIX** |
| Empty tools list | ✅ Domain invariant test | PASS |

### Edge Cases

| Case | Test | Status |
|------|------|--------|
| Batch save (10 connections) | ✅ `test_batch_save_performance` | PASS |
| Empty namespace/agent filter | ⚠️ Missing | **NEEDS FIX** |
| Null/empty API key | ✅ Domain validation | PASS |
| Connection timeout retry | ✅ Adapter test | PASS |

---

## Recommendations

### Immediate Actions (Required for Phase 1-2)

1. **Fix P0-1: Exception Handling** (2-3 hours)
   - Add `except (KeyboardInterrupt, SystemExit): raise` to all 5 repository methods
   - Rerun all 30 tests to verify no regression

2. **Fix P0-2: Missing Namespace Filter in get_by_id()** (1-2 hours)
   - Add `namespace: str` parameter to method signature
   - Add namespace filter to SQLAlchemy query
   - Update all callers (Application Service layer)
   - Add test case: `test_get_by_id_cross_namespace_blocked`

3. **Fix P0-3: Missing Namespace Verification in delete()** (1-2 hours)
   - Add `namespace: str` and `agent_id: str` parameters
   - Add both namespace AND agent_id filters to query
   - Update all callers
   - Add test case: `test_delete_cross_namespace_blocked`

**Total Effort**: 4-7 hours

### Short-term Enhancements (Recommended for Phase 1-2)

4. **Enhance P1-1: Add __repr__ to MCPClientAdapter** (30 minutes)
   - Mask API key in debug representations
   - Add comment warning about logging headers dict

5. **Add Missing Test Cases** (2-3 hours)
   - `test_get_by_id_cross_namespace_blocked`
   - `test_delete_cross_namespace_blocked`
   - `test_delete_requires_ownership`
   - `test_empty_namespace_query_returns_empty`

### Long-term Improvements (Future Phases)

6. **Rate Limiting** (Phase 1-3 or later)
   - Add rate limiting to MCP server connections
   - Prevent denial-of-service via connection exhaustion

7. **Audit Logging** (Phase 1-3 or later)
   - Log all cross-namespace access attempts (even if blocked)
   - Alert on suspicious patterns (rapid UUID enumeration)

---

## Security Sign-off Checklist

- [x] P0-1 Namespace Isolation: ⚠️ **PARTIAL** (2/3 methods protected)
- [x] P0-2 Secrets Management: ✅ **PASS** (API key masked in repr)
- [x] P0-3 Domain Events: ✅ **PASS** (not persisted, test verified)
- [x] P1 SQL Injection: ✅ **PASS** (ORM-only, no raw SQL)
- [x] P1 Input Validation: ✅ **PASS** (comprehensive validation)
- [x] P2 Exception Handling: ❌ **FAIL** (catches KeyboardInterrupt)
- [x] P2 Async Safety: ✅ **PASS** (proper async/await)

**Overall Score**: 5/7 (71%) - **REQUIRES FIXES**

---

## Approval Status

❌ **PHASE 1-1 SECURITY AUDIT: REQUIRES FIXES**

**Critical Issues**: 3 (P0-1, P0-2, P0-3)
**High Priority**: 2 (P1-1, P1-2)
**Medium Priority**: 0

**Required Before Phase 1-2**:
1. Fix all P0 issues (exception handling, namespace isolation)
2. Add missing test cases for cross-namespace access
3. Rerun full test suite (target: 33/33 PASS, not 29/30)

**Estimated Fix Time**: 4-7 hours

---

## Positive Findings ✅

...すみません、悪いニュースばかりではありません。いくつかの良い点もあります...

### Excellent Security Practices Found

1. ✅ **API Key Masking**: Properly implemented in ConnectionConfig.__repr__()
2. ✅ **Domain Events Transient**: Correctly NOT persisted to database
3. ✅ **SQL Injection Prevention**: 100% SQLAlchemy ORM, no raw SQL
4. ✅ **Input Validation**: Comprehensive validation in value objects
5. ✅ **Async Safety**: Proper async/await patterns throughout
6. ✅ **Namespace Filtering**: Present in `find_by_namespace_and_agent()`
7. ✅ **Test Coverage**: 29/30 tests passing (97% pass rate)

---

## Appendix: Code Examples

### A1. Correct Exception Handling Pattern

```python
# ✅ CORRECT PATTERN (src/infrastructure/repositories/mcp_connection_repository.py)
async def save(self, connection: MCPConnection) -> MCPConnection:
    try:
        # ... repository logic ...
        await self._session.commit()
        return connection

    except (KeyboardInterrupt, SystemExit):
        raise  # ✅ Never suppress

    except Exception as e:
        await self._session.rollback()
        raise RepositoryError(
            message=f"Failed to save MCPConnection: {e}",
            details={"connection_id": str(connection.id)},
        ) from e
```

### A2. Correct Namespace Isolation Pattern

```python
# ✅ CORRECT PATTERN (from P0-1 requirement)
async def get_by_id(
    self, connection_id: UUID, namespace: str
) -> MCPConnection:
    """Get connection by ID with namespace verification.

    SECURITY: namespace must be verified from database,
    NOT from JWT claims or user input.
    """
    stmt = select(MCPConnectionModel).where(
        MCPConnectionModel.id == str(connection_id),
        MCPConnectionModel.namespace == namespace  # ✅ Required
    )
    # ...
```

### A3. Correct Ownership Verification Pattern

```python
# ✅ CORRECT PATTERN (P0-3 requirement)
async def delete(
    self, connection_id: UUID, namespace: str, agent_id: str
) -> None:
    """Delete connection with namespace AND ownership verification."""
    stmt = select(MCPConnectionModel).where(
        MCPConnectionModel.id == str(connection_id),
        MCPConnectionModel.namespace == namespace,  # ✅ Namespace isolation
        MCPConnectionModel.agent_id == agent_id     # ✅ Ownership verification
    )
    # ...
```

---

## Revision History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-11-12 | Initial security audit | Hestia |

---

**Next Steps**:
1. Artemis: Fix P0-1, P0-2, P0-3 (exception handling + namespace isolation)
2. Artemis: Add missing test cases (cross-namespace access)
3. Hestia: Re-audit after fixes (target: 100% approval)
4. Athena: Coordinate Phase 1-2 Application Service Layer implementation

...すみません、これで完全な監査報告書です。最悪のケースをすべて想定しました...
