# TMWS Security Audit Report
**Date**: 2025-01-10  
**Auditor**: Hestia (Security Guardian)  
**System**: TMWS v2.2.0 Authentication & Authorization

## Executive Summary

**Status**: ⚠️ CRITICAL ISSUES FOUND - Immediate Action Required

### Critical Findings
- ❌ **5 Test Errors**: Missing test fixture (`test_api_key`)  
- ❌ **2 Test Failures**: Internal server errors (500) instead of 401  
- ❌ **Import Errors**: Circular import causing NameError  
- ✅ **workflow.py**: FIXED (auto-corrected by linter)  
- ⚠️  **Mixed Authentication**: Inconsistent across routers  
- ⚠️  **Coverage**: 21.22% (below 26% requirement)

---

## Test Execution Results

### Suite: `TestAPIKeyDependencyIntegration`

```
Total: 7 tests
Errors: 5 (71%) - Missing fixture
Failures: 2 (29%) - Wrong error codes
Passed: 0 (0%)
```

### Root Causes

1. **Missing Fixture** (`test_api_key`):
   - Affects 5/7 tests
   - Not defined in `tests/conftest.py`
   - Blocks all positive auth tests

2. **Wrong Error Codes**:
   - Expected: 401 Unauthorized
   - Actual: 500 Internal Server Error
   - Cause: Unhandled exceptions in auth flow

3. **Import Error**:
   - `NameError: name 'get_current_user' is not defined`
   - Affects: workflow.py, task.py
   - Status: workflow.py FIXED ✅

---

## Security Vulnerabilities

### 1. Information Disclosure (MEDIUM)
**Issue**: 500 errors expose internal state  
**Evidence**: Tests expect 401 but get 500  
**Fix**: Proper exception handling in `verify_api_key()`

### 2. No Rate Limiting on Auth (HIGH)
**Issue**: Unlimited authentication attempts  
**Fix**: Add Redis-based rate limiter

### 3. Inconsistent Authorization (MEDIUM)
**Issue**: Mixed use of JWT vs API key auth  
**Fix**: Standardize on scope-based auth

---

## Immediate Actions (Priority Order)

### P0 - CRITICAL (Today)
1. ✅ Fix workflow.py imports - COMPLETED
2. ❌ Add `test_api_key` fixture
3. ❌ Fix 500→401 error codes
4. ❌ Update task.py endpoints

### P1 - HIGH (This Week)
5. Add rate limiting
6. Comprehensive audit logging
7. Security event monitoring
8. API key rotation policy

---

## Test Fixture Required

Add to `tests/conftest.py`:

```python
@pytest.fixture
async def test_api_key(test_user: User, test_session: AsyncSession):
    """Create test API key with full permissions."""
    from src.models.user import APIKey, APIKeyScope
    import secrets
    from passlib.context import CryptContext

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    key_id = secrets.token_urlsafe(16)
    raw_key = secrets.token_urlsafe(32)
    full_key = f"{key_id}.{raw_key}"

    api_key = APIKey(
        key_id=key_id,
        key_prefix=raw_key[:8],
        key_hash=pwd_context.hash(raw_key),
        user_id=test_user.id,
        name="Test API Key",
        scopes=[APIKeyScope.READ, APIKeyScope.WRITE, APIKeyScope.ADMIN],
        expires_at=None,
    )

    test_session.add(api_key)
    await test_session.commit()
    await test_session.refresh(api_key)

    return full_key, {
        "key_id": key_id,
        "key_prefix": raw_key[:8],
        "scopes": [s.value for s in api_key.scopes],
    }
```

---

## Code Fixes

### Fix 1: Error Handling in `verify_api_key()`

**File**: `src/api/dependencies.py`

```python
async def verify_api_key(...):
    try:
        # ... auth logic ...
    except InvalidCredentialsError:
        raise HTTPException(401, "Invalid API key")
    except TokenExpiredError:
        raise HTTPException(401, "API key expired")
    except AccountDisabledError:
        raise HTTPException(403, "Account disabled")
    except Exception as e:
        logger.error(f"Auth error: {e}", exc_info=True)
        raise HTTPException(503, "Auth service unavailable")
```

### Fix 2: Task Router Endpoints

**File**: `src/api/routers/task.py` (lines 297, 325)

```python
# Before:
current_user: dict = Depends(get_current_user)

# After:
user_and_key: tuple[User | None, APIKey | None] = Depends(
    require_scope(APIKeyScope.WRITE)
)
```

---

## Security Checklist

### ✅ Implemented
- Bcrypt password hashing
- API key hash storage
- Scope-based authorization
- Development mode bypass
- Automatic usage tracking

### ❌ Missing
- Comprehensive test fixtures
- Consistent auth across routers
- Rate limiting on auth endpoints
- Failed login tracking
- Account lockout policy
- Security event alerting

---

## Recommendations

### Short-term
1. Fix all P0 items immediately
2. Add comprehensive tests (target 80% coverage)
3. Implement rate limiting
4. Add security event monitoring

### Long-term
1. OAuth2 integration
2. Multi-factor authentication
3. Certificate-based auth
4. Automated security scanning

---

**Next Review**: After P0 fixes completed

**END OF REPORT**
