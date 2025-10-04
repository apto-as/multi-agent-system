# Immediate Action Items - TMWS Code Quality Fixes
## Today → This Week Priority Tasks

**Last Updated**: 2025-01-09
**Status**: 🔴 CRITICAL - Start immediately
**Estimated Total Time**: 18 hours (today) + 60 hours (this week)

---

## 🚨 Priority 0: TODAY (Must complete before end of day)

### Task 1: Implement Basic Authentication (6 hours)

**Owner**: Hestia
**File**: `src/api/dependencies.py`
**Issue**: API key validation is TODO comment only

#### Current Code (Lines 73-77)
```python
# In a real implementation, you would:
# 1. Check key against database
# 2. Validate key hasn't expired
# 3. Check rate limits for this key
# 4. Log API key usage
return agent_id
```

#### Fix Implementation

**Step 1**: Create API key validation service (2h)

```python
# src/services/api_key_service.py (NEW FILE)
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.api_keys import APIKey
from ..core.exceptions import AuthenticationError, ErrorCode

class APIKeyService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def validate_api_key(self, api_key: str) -> dict:
        """Validate API key and return agent info."""

        # 1. Check key against database
        stmt = select(APIKey).where(
            APIKey.key_hash == self._hash_key(api_key),
            APIKey.is_active == True
        )
        result = await self.session.execute(stmt)
        key_record = result.scalar_one_or_none()

        if not key_record:
            raise AuthenticationError(
                "Invalid API key",
                ErrorCode.AUTH_INVALID_CREDENTIALS
            )

        # 2. Validate key hasn't expired
        if key_record.expires_at and key_record.expires_at < datetime.utcnow():
            raise AuthenticationError(
                "API key expired",
                ErrorCode.AUTH_TOKEN_EXPIRED
            )

        # 3. Check rate limits (basic)
        if await self._is_rate_limited(key_record):
            raise AuthenticationError(
                "Rate limit exceeded",
                ErrorCode.SECURITY_QUOTA_EXCEEDED
            )

        # 4. Log API key usage
        key_record.last_used_at = datetime.utcnow()
        key_record.usage_count += 1
        await self.session.commit()

        return {
            "agent_id": key_record.agent_id,
            "permissions": key_record.permissions,
            "rate_limit": key_record.rate_limit_per_hour
        }

    def _hash_key(self, api_key: str) -> str:
        """Hash API key for storage."""
        import hashlib
        return hashlib.sha256(api_key.encode()).hexdigest()

    async def _is_rate_limited(self, key_record: APIKey) -> bool:
        """Check if key has exceeded rate limit."""
        # Simple hourly rate limit check
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)

        if key_record.last_used_at and key_record.last_used_at > one_hour_ago:
            hourly_count = key_record.usage_count  # Simplified
            if hourly_count >= key_record.rate_limit_per_hour:
                return True

        return False
```

**Step 2**: Update dependencies.py (1h)

```python
# src/api/dependencies.py
from fastapi import Depends, HTTPException, Header, Request, status
from typing import Optional

from ..services.api_key_service import APIKeyService
from ..core.exceptions import AuthenticationError

async def require_agent_access(
    x_api_key: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db_session_dependency)
) -> dict:
    """Require valid API key for agent access."""

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required in X-API-Key header"
        )

    try:
        api_key_service = APIKeyService(db)
        agent_info = await api_key_service.validate_api_key(x_api_key)
        return agent_info

    except AuthenticationError as e:
        raise HTTPException(
            status_code=e.http_status,
            detail=e.message,
            headers={"WWW-Authenticate": "ApiKey"}
        )
```

**Step 3**: Create database migration (1h)

```python
# migrations/versions/007_add_api_keys_usage.py
"""Add API key usage tracking

Revision ID: 007
Revises: 006
Create Date: 2025-01-09
"""

def upgrade():
    # Add usage tracking columns
    op.add_column('api_keys',
        sa.Column('usage_count', sa.Integer(), nullable=False, server_default='0')
    )
    op.add_column('api_keys',
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column('api_keys',
        sa.Column('rate_limit_per_hour', sa.Integer(), nullable=False, server_default='100')
    )

    # Add index for performance
    op.create_index('idx_api_keys_last_used', 'api_keys', ['last_used_at'])
```

**Step 4**: Apply migration and test (2h)

```bash
# Apply migration
alembic upgrade head

# Test authentication
pytest tests/security/test_api_key_service.py -v

# Integration test
curl -H "X-API-Key: test_key_12345" http://localhost:8000/api/v1/tasks
# Expected: 401 if invalid, 200 if valid
```

---

### Task 2: Fix Missing HTTPException Import (5 minutes)

**Owner**: Athena
**File**: `src/api/dependencies.py`
**Issue**: HTTPException used but not imported

#### Fix

```python
# Line 1-10 of src/api/dependencies.py
from fastapi import Depends, HTTPException, Header, Request, status  # ← Add HTTPException
from fastapi.security import HTTPBearer
from typing import Optional

from ..core.database import get_db_session
from ..services.auth_service import AuthService
# ... rest of imports
```

#### Verification

```bash
# Test import
python -c "from src.api.dependencies import require_agent_access"
# Should succeed without ImportError

# Run affected tests
pytest tests/api/test_dependencies.py -v
```

---

### Task 3: Fix Bare Except Statements (4 hours)

**Owner**: Hestia
**File**: `scripts/check_database.py`
**Issue**: 6 locations using `except:` without logging

#### Fix #1: Table Row Count (Line 161-165)

**Current**:
```python
try:
    count_result = await conn.execute(text(f"SELECT COUNT(*) FROM {table}"))
    count = count_result.scalar()
    if table in result['tables']:
        result['tables'][table]['row_count'] = count
except:
    pass
```

**Fixed**:
```python
try:
    # Use safer query construction
    from sqlalchemy import text, literal_column

    # Validate table name (prevent SQL injection)
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', table):
        logger.warning(f"Invalid table name: {table}")
        continue

    count_result = await conn.execute(
        text(f"SELECT COUNT(*) FROM {table}")  # Safe after validation
    )
    count = count_result.scalar()
    if table in result['tables']:
        result['tables'][table]['row_count'] = count

except OperationalError as e:
    logger.warning(f"Cannot access table {table}: {e}")
    result['tables'][table]['row_count'] = None
except ProgrammingError as e:
    logger.warning(f"Table {table} does not exist: {e}")
    result['tables'][table]['row_count'] = None
except Exception as e:
    logger.error(f"Unexpected error counting rows in {table}: {e}", exc_info=True)
    result['tables'][table]['row_count'] = None
```

#### Fix #2-6: Apply Same Pattern

```python
# General template for all 6 locations
try:
    # ... operation ...
except SpecificExpectedException as e:
    logger.warning(f"Expected issue: {e}")
    # Set default/None value
except Exception as e:
    logger.error(f"Unexpected error: {e}", exc_info=True)
    # Set default/None value or re-raise
```

#### Locations to Fix

1. ✅ Line 162: Table row count
2. ✅ Line 257: pg_stat_statements
3. ✅ Line 316: Vector dimension
4. ✅ Line 385: Orphaned records
5. ✅ Line 448: Index statistics (if exists)
6. ✅ Line 512: Connection test (if exists)

#### Verification

```bash
# Search for remaining bare excepts
grep -n "except:" scripts/check_database.py
# Expected: 0 results

# Test the script
python scripts/check_database.py
# Should show warnings instead of silent failures
```

---

### Task 4: Enable Basic Security Settings (2 hours)

**Owner**: Hestia
**File**: `.env` (or environment configuration)

#### Current Insecure Settings

```bash
# Current .env
TMWS_AUTH_ENABLED=false  # ← Dangerous!
TMWS_RATE_LIMIT_ENABLED=false  # ← No protection!
TMWS_ENVIRONMENT=development  # ← Not production
```

#### Secure Configuration

```bash
# Updated .env for production
TMWS_AUTH_ENABLED=true
TMWS_RATE_LIMIT_ENABLED=true
TMWS_RATE_LIMIT_REQUESTS=100
TMWS_RATE_LIMIT_PERIOD=60

TMWS_ENVIRONMENT=production
TMWS_SECRET_KEY=<GENERATE_NEW_32_CHAR_KEY>

# HTTPS enforcement
TMWS_HTTPS_ONLY=true
TMWS_SECURE_COOKIES=true

# CORS strict settings
TMWS_CORS_ORIGINS=["https://yourdomain.com"]

# Database connection pooling
TMWS_DB_MAX_CONNECTIONS=20
TMWS_DB_POOL_PRE_PING=true
```

#### Generate Secure Secret

```bash
# Generate cryptographically secure secret
python -c "import secrets; print(secrets.token_urlsafe(32))"
# Output example: xVQz_8kJ9mN2pR5tY7wA3bC6eD1fH4gI0

# Update .env
TMWS_SECRET_KEY=xVQz_8kJ9mN2pR5tY7wA3bC6eD1fH4gI0
```

#### Force HTTPS (30 minutes)

```python
# src/main.py - Add HTTPS middleware
from fastapi import FastAPI, Request
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware

app = create_app()

# Force HTTPS in production
if settings.environment == "production":
    app.add_middleware(HTTPSRedirectMiddleware)
```

#### Verification

```bash
# Restart server
python -m src.main

# Test authentication is required
curl http://localhost:8000/api/v1/tasks
# Expected: 401 Unauthorized

# Test with API key
curl -H "X-API-Key: valid_key" http://localhost:8000/api/v1/tasks
# Expected: 200 OK or 403 Forbidden (not 500 error)
```

---

### Task 5: Enable Rate Limiting (2 hours)

**Owner**: Hestia
**Files**: `src/api/dependencies.py`, `src/security/rate_limiter.py`

#### Current Code

```python
# src/api/dependencies.py:89-96
if settings.rate_limit_enabled:
    # Rate limit check
    # TODO: Actual implementation
    pass
```

#### Implementation

```python
# src/api/dependencies.py
from ..security.rate_limiter import RateLimiter

async def check_rate_limit(
    request: Request,
    agent_info: dict = Depends(require_agent_access),
    rate_limiter: RateLimiter = Depends(get_rate_limiter)
):
    """Check rate limit for authenticated agent."""

    agent_id = agent_info["agent_id"]
    client_ip = request.client.host

    # Check rate limit
    is_allowed, remaining = await rate_limiter.check_limit(
        key=f"agent:{agent_id}",
        limit=100,  # requests per minute
        window=60   # seconds
    )

    if not is_allowed:
        # Log rate limit event
        await audit_logger.log_rate_limit_exceeded(
            agent_id=agent_id,
            ip_address=client_ip,
            endpoint=request.url.path
        )

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {remaining}s",
            headers={"Retry-After": str(remaining)}
        )

    # Add rate limit info to response headers
    request.state.rate_limit_remaining = remaining
    return True
```

#### Add Dependency to Routes

```python
# src/api/routers/tasks.py
from ..dependencies import check_rate_limit

@router.get("/tasks", dependencies=[Depends(check_rate_limit)])
async def list_tasks(...):
    # Rate limit is enforced before this executes
    pass
```

---

## ⚡ Priority 1: THIS WEEK (Complete by Friday)

### Task 6: Consolidate Audit Loggers (16 hours)

**Owner**: Artemis
**Issue**: 3 duplicate implementations, 800+ lines of duplicate code

#### Phase 1: Create Base Class (4h)

```python
# src/security/audit_logger_base.py (NEW)
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from ..models.audit_log import AuditLog, AuditEventType, AuditSeverity

class BaseAuditLogger(ABC):
    """Unified base class for all audit loggers."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def log_event(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        agent_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Common logging implementation."""
        entry = AuditLog(
            event_type=event_type.value,
            severity=severity.value,
            agent_id=agent_id,
            metadata=details or {},
            timestamp=datetime.utcnow()
        )

        self.session.add(entry)
        await self.session.flush()

        # Log to file as well
        self._log_to_file(entry)

    def _log_to_file(self, entry: AuditLog):
        """Write to audit log file."""
        import logging
        audit_logger = logging.getLogger("audit")
        audit_logger.info(
            f"{entry.event_type}|{entry.severity}|{entry.agent_id}|{entry.metadata}"
        )

    # Convenience methods
    async def log_security_event(self, agent_id: str, event: str, details: dict):
        await self.log_event(
            AuditEventType.SECURITY_VIOLATION,
            AuditSeverity.CRITICAL,
            agent_id,
            {"event": event, **details}
        )

    async def log_authentication_success(self, agent_id: str):
        await self.log_event(
            AuditEventType.AUTHENTICATION_SUCCESS,
            AuditSeverity.INFO,
            agent_id
        )

    async def log_authentication_failure(self, agent_id: Optional[str], reason: str):
        await self.log_event(
            AuditEventType.AUTHENTICATION_FAILURE,
            AuditSeverity.WARNING,
            agent_id,
            {"reason": reason}
        )
```

#### Phase 2: Refactor Existing Loggers (6h)

```python
# src/security/audit_logger.py - SIMPLIFIED
from .audit_logger_base import BaseAuditLogger

class AuditLogger(BaseAuditLogger):
    """Synchronous-style audit logger (uses base implementation)."""
    pass  # Inherits all methods

# src/security/audit_logger_async.py - DELETE OR MERGE
# This file can be deleted - BaseAuditLogger is already async

# src/security/audit_logger_enhanced.py - DELETE OR MERGE
# This file can be deleted - features moved to BaseAuditLogger
```

#### Phase 3: Update All Imports (4h)

```bash
# Find all usages
grep -r "from.*audit_logger" --include="*.py" src/

# Update imports
# Old: from src.security.audit_logger_async import AsyncAuditLogger
# New: from src.security.audit_logger_base import BaseAuditLogger
```

#### Phase 4: Testing (2h)

```bash
# Run audit logger tests
pytest tests/security/test_audit_logger.py -v

# Integration test
pytest tests/integration/test_audit_logging.py -v

# Verify all audit events still logged
grep "AUDIT" logs/audit.log | wc -l
# Should show non-zero count
```

**Expected Results**:
- ✅ 800 lines → 200 lines (75% reduction)
- ✅ Single source of truth
- ✅ Easier to maintain
- ✅ No duplicate bugs

---

### Task 7: Unify Database Connection Pool (8 hours)

**Owner**: Artemis
**Issue**: 4 separate connection pools, 300% overhead

#### Phase 1: Identify All Pool Creations (1h)

```bash
# Find all engine creations
grep -r "create_async_engine" --include="*.py" src/

# Expected findings:
# src/core/database.py:45          ← Keep this one ✓
# src/security/audit_logger.py:52  ← Remove
# src/security/audit_logger_async.py:48  ← Remove
# src/security/audit_logger_enhanced.py:30  ← Remove
```

#### Phase 2: Remove Duplicate Engines (2h)

**Before (audit_logger.py)**:
```python
# src/security/audit_logger.py
engine = create_async_engine(
    settings.database_url_async,
    pool_size=5,
    max_overflow=10
)
async_session = sessionmaker(engine, class_=AsyncSession)
```

**After**:
```python
# src/security/audit_logger.py
from ..core.database import get_db_session

class AuditLogger(BaseAuditLogger):
    def __init__(self, session: AsyncSession):
        super().__init__(session)  # Use injected session
```

#### Phase 3: Update Service Dependencies (3h)

```python
# src/api/dependencies.py
from ..security.audit_logger_base import BaseAuditLogger

async def get_audit_logger(
    db: AsyncSession = Depends(get_db_session_dependency)
) -> BaseAuditLogger:
    """Get audit logger with shared DB session."""
    return BaseAuditLogger(db)

# Usage in routes
@router.post("/tasks")
async def create_task(
    task_data: TaskCreate,
    audit: BaseAuditLogger = Depends(get_audit_logger)
):
    # Audit logger uses same connection pool
    await audit.log_event(...)
```

#### Phase 4: Performance Testing (2h)

```bash
# Before: Check connection count
docker exec tmws-postgres-test psql -U tmws_user -d tmws_test -c \
    "SELECT count(*) FROM pg_stat_activity WHERE datname='tmws_test';"
# Expected: 60-80 connections

# After: Apply changes and restart
python -m src.main

# Check new connection count
docker exec tmws-postgres-test psql -U tmws_user -d tmws_test -c \
    "SELECT count(*) FROM pg_stat_activity WHERE datname='tmws_test';"
# Expected: 15-20 connections (75% reduction)

# Benchmark performance
pytest tests/performance/test_db_pool.py --benchmark-only
# Expected: 30-40% improvement in throughput
```

---

### Task 8: Standardize Password Hashing (3 hours)

**Owner**: Artemis
**Issue**: 3 different implementations, inconsistent security

#### Current Situation

```python
# Implementation 1: src/security/validators.py (WEAK)
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hash_obj = hashlib.sha256((password + salt).encode())
    return f"{salt}${hash_obj.hexdigest()}"

# Implementation 2: src/utils/security.py (STRONG)
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# Implementation 3: src/services/auth_service.py (DUPLICATE)
# Another bcrypt implementation
```

#### Unified Solution

**Step 1**: Delete weak implementation (30min)

```python
# src/security/validators.py
# DELETE lines 473-479 (weak SHA256 implementation)
```

**Step 2**: Standardize on utils/security.py (1h)

```python
# src/utils/security.py - Keep and enhance
from passlib.context import CryptContext

# Use argon2 (even stronger than bcrypt)
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto",
    argon2__rounds=4,
    argon2__memory_cost=65536
)

def hash_password(password: str) -> str:
    """Hash password using Argon2 (OWASP recommended)."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash."""
    return pwd_context.verify(plain_password, hashed_password)
```

**Step 3**: Update all imports (1h)

```bash
# Find all password hashing usages
grep -r "hash_password" --include="*.py" src/

# Update imports everywhere
# Old: from src.security.validators import hash_password
# New: from src.utils.security import hash_password, verify_password
```

**Step 4**: Test migration (30min)

```python
# tests/security/test_password_hashing.py
def test_password_hashing_strength():
    """Verify passwords are hashed with Argon2."""
    password = "Test123!@#"
    hashed = hash_password(password)

    # Should use Argon2
    assert hashed.startswith("$argon2")

    # Verify works
    assert verify_password(password, hashed)
    assert not verify_password("wrong", hashed)

def test_backward_compatibility():
    """Verify old bcrypt hashes still work."""
    # Old bcrypt hash
    old_hash = "$2b$12$..."

    # Should still verify
    assert verify_password("oldpassword", old_hash)
```

---

## ✅ Success Criteria

### Today (End of Day Checklist)

- [ ] Authentication system implemented and tested
- [ ] HTTPException import added
- [ ] All 6 bare excepts fixed with logging
- [ ] Security settings enabled in production
- [ ] Rate limiting functional
- [ ] All tests passing (`pytest tests/ -v`)
- [ ] No critical security warnings

### This Week (Friday EOD Checklist)

- [ ] Audit loggers consolidated (3 → 1 implementation)
- [ ] Database pools unified (4 → 1 pool)
- [ ] Password hashing standardized (Argon2 only)
- [ ] Code duplication <15% (down from 23%)
- [ ] Test coverage ≥70%
- [ ] Performance benchmarks improved 20%+
- [ ] Documentation updated

---

## 🚀 Deployment Checklist

Before deploying to production:

```bash
# 1. All tests pass
pytest tests/ -v --cov=src --cov-report=term-missing
# Expected: >70% coverage, 0 failures

# 2. Security scan clean
bandit -r src/ -f json -o security_scan.json
# Expected: 0 high/critical issues

# 3. No TODO in critical code
grep -r "TODO" src/security/ src/api/
# Expected: 0 results in security layer

# 4. Database migrations applied
alembic current
# Expected: Shows latest revision (007 or higher)

# 5. Environment variables set
env | grep TMWS_
# Must include: AUTH_ENABLED=true, RATE_LIMIT_ENABLED=true

# 6. HTTPS enforced
curl -I http://localhost:8000/health
# Expected: 308 Permanent Redirect to https://

# 7. Audit logging operational
tail -f logs/audit.log
# Should show recent events
```

---

## 📞 Support and Escalation

### Blocked on Task?

**Immediate Help**:
1. Check troubleshooting section in REFACTORING_ROADMAP.md
2. Search related tests: `grep -r "test_<feature>" tests/`
3. Review related code: `grep -r "<function_name>" src/`

**Still Blocked?**:
- Eris: Task coordination and prioritization
- Hestia: Security-related questions
- Artemis: Code quality and performance
- Athena: Architecture decisions

### Critical Issues

If you discover a **critical security vulnerability** during fixes:

1. **STOP** current work
2. Document the vulnerability
3. Assess immediate risk
4. Implement emergency fix if exploitable
5. Update this document with new priority

---

## 📊 Progress Tracking

### Daily Checklist Template

```markdown
## 2025-01-09 Progress

### Completed
- [x] Task 1: Authentication (6h actual vs 6h estimated)
- [x] Task 2: HTTPException (5min actual vs 5min estimated)

### In Progress
- [ ] Task 3: Bare except fixes (2h completed, 2h remaining)

### Blocked
- None

### Tomorrow's Plan
1. Complete Task 3 (2h)
2. Start Task 6: Audit logger consolidation (4h)
3. Code review with team (1h)
```

---

**Document Owner**: Muses (Knowledge Architecture)
**Last Updated**: 2025-01-09
**Next Review**: Daily standup, Weekly integration meeting
