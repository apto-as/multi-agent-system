# [Security] SHA256 Password Hashing Migration to Bcrypt

## Priority: P0 (Security Critical)

## Overview
Remove deprecated SHA256 password hashing functions and migrate all authentication to bcrypt.

## Background
- SHA256 is vulnerable to GPU-accelerated brute force attacks (CVSS 7.5 HIGH)
- Deprecated functions exist in `src/utils/security.py` (lines 54-107)
- Used for backward compatibility with legacy API keys
- `password_salt` column in User model is always NULL (already unused)

## Goals

- [ ] Remove `hash_password_with_salt()` function
- [ ] Remove `verify_password_with_salt()` function
- [ ] Remove `password_salt` column from User model
- [ ] Update `mcp_auth.py` to reject SHA256 API keys with migration message
- [ ] Update test fixtures (6 files)
- [ ] Create Alembic migration for column removal

## Implementation Plan

### Phase 1: Pre-Migration Safety Checks
```sql
-- Check for non-NULL password_salt values
SELECT COUNT(*) FROM users WHERE password_salt IS NOT NULL;

-- Check for SHA256 format API keys
SELECT id, agent_name FROM agents
WHERE api_key_hash NOT LIKE '$2%'
AND api_key_hash IS NOT NULL;
```

### Phase 2: Database Migration
```python
# Alembic migration: remove password_salt column
def upgrade():
    # Safety check - fail if data exists
    op.execute("SELECT COUNT(*) FROM users WHERE password_salt IS NOT NULL")
    op.drop_column('users', 'password_salt')

def downgrade():
    op.add_column('users', sa.Column('password_salt', sa.Text, nullable=True))
```

### Phase 3: Code Cleanup

**Files to modify:**
| File | Change |
|------|--------|
| `src/utils/security.py` | DELETE lines 54-107 |
| `src/security/mcp_auth.py` | Reject SHA256 with migration error |
| `src/models/user.py` | Remove password_salt column |
| `src/services/auth_service.py` | Remove password_salt assignment |

### Phase 4: Test Fixture Updates

**Files to update:**
- `tests/conftest.py` (lines 172, 175, 211, 214)
- `tests/integration/api/conftest.py`
- `tests/unit/security/conftest.py`
- `tests/e2e/conftest.py`
- `tests/unit/test_auth_service.py`
- `tests/integration/api/test_skills_api.py`

### Phase 5: Agent Migration Strategy
- SHA256 API keys will be **rejected** after migration
- Affected agents receive clear error message with regeneration instructions
- 30-day notice period for production

### Phase 6: Verification
- [ ] All tests pass
- [ ] No SHA256 functions in codebase
- [ ] Performance benchmark: auth < 200ms

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Agents locked out | Low | High | 30-day notice + clear error message |
| Data loss | Very Low | Medium | Column is always NULL |
| Test failures | Medium | Low | Update fixtures before removal |

## Rollback Plan
1. Revert Alembic migration (re-add column)
2. Git revert code changes
3. Column will be empty (acceptable - was always NULL)

## Estimated Effort
- **Duration**: 3 days (dev → staging → prod)
- **Engineering Time**: 10.5 hours

## Labels
- `priority:P0`
- `type:security`
- `complexity:medium`

---
**Prepared by**: Hestia (Security Guardian)
**Date**: 2025-12-06
