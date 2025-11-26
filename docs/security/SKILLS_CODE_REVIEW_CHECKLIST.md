# Skills System Code Review Checklist

**Status**: Phase 5A Security Analysis
**Author**: Hestia (Security Guardian)
**Date**: 2025-11-25
**TMWS Version**: v2.4.0 (Skills System)
**Purpose**: Code review checklist for Artemis's implementation

---

## Overview

This checklist is used by **Hestia** to review Artemis's implementation in Phase 5B. All items marked as **CRITICAL** must be verified before approval.

**Approval Process**:
1. Artemis completes implementation (Phase 5B)
2. Hestia reviews using this checklist (Phase 5C)
3. Hestia provides PASS/FAIL for each item
4. If all CRITICAL items PASS → Approve for deployment
5. If any CRITICAL item FAILS → Reject, require fixes

---

## 1. Database Schema Review

### CRITICAL: Namespace Isolation Schema
- [ ] `skills` table has `namespace` column (TEXT, NOT NULL, indexed)
- [ ] Unique constraint exists: `idx_skills_namespace_name ON (namespace, name)`
- [ ] `access_level` column exists (Enum: PRIVATE, TEAM, SHARED, PUBLIC, SYSTEM)
- [ ] `shared_with_agents` column exists (JSON array)
- [ ] `created_by` column exists (TEXT, NOT NULL, indexed)

**Verification**:
```sql
-- Check table schema
\d skills

-- Check unique constraint
SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'skills' AND indexdef LIKE '%UNIQUE%';
-- Expected: idx_skills_namespace_name UNIQUE (namespace, name)
```

**Risk if FAIL**: CVSS 8.7 CRITICAL (S-2 namespace isolation breach)

---

### CRITICAL: Skill Versions Schema
- [ ] `skill_versions` table exists
- [ ] `raw_content` column exists (TEXT, stores SKILL.md)
- [ ] `rendered_content` column exists (TEXT, stores sanitized HTML)
- [ ] `frontmatter` column exists (JSON, stores parsed YAML)
- [ ] Foreign key: `skill_id` → `skills.id` with `ON DELETE CASCADE`
- [ ] Unique constraint: `(skill_id, version)`

**Verification**:
```sql
\d skill_versions

SELECT conname, confdeltype FROM pg_constraint WHERE conrelid = 'skill_versions'::regclass;
-- Expected: confdeltype = 'c' (CASCADE)
```

**Risk if FAIL**: Data integrity issues, orphaned versions

---

### HIGH: Database Indexes
- [ ] Index exists: `idx_skills_namespace` on `skills(namespace)`
- [ ] Index exists: `idx_skills_access_level` on `skills(access_level, created_by)`
- [ ] Index exists: `idx_skill_versions_skill_id` on `skill_versions(skill_id)`

**Verification**:
```sql
SELECT indexname FROM pg_indexes WHERE tablename IN ('skills', 'skill_versions');
```

**Risk if FAIL**: Poor query performance (>100ms P95)

---

### CRITICAL: No Filesystem Paths
- [ ] NO column stores filesystem paths (e.g., `file_path`)
- [ ] All content stored in database (`raw_content`, `rendered_content`)
- [ ] UUID primary keys only (no filename-based IDs)

**Verification**: Manually inspect schema definition

**Risk if FAIL**: CVSS 6.5 MEDIUM (S-4 path traversal vulnerability)

---

## 2. Model Implementation Review

### CRITICAL: Skill.is_accessible_by() Method
- [ ] Method signature: `is_accessible_by(self, requesting_agent_id: str, requesting_agent_namespace: str) -> bool`
- [ ] Namespace parameter is **required** (not optional)
- [ ] Same logic as `Memory.is_accessible_by()` (proven secure)
- [ ] Owner check: `if requesting_agent_id == self.created_by: return True`
- [ ] PUBLIC check: `if self.access_level == AccessLevel.PUBLIC: return True`
- [ ] SYSTEM check: `if self.access_level == AccessLevel.SYSTEM: return True`
- [ ] SHARED check: `requesting_agent_id in shared_with_agents AND requesting_agent_namespace == self.namespace`
- [ ] TEAM check: `requesting_agent_namespace == self.namespace`
- [ ] PRIVATE default: `return False`

**Verification**:
```python
# Read implementation
cat src/models/skill.py | grep -A 30 "def is_accessible_by"

# Compare with Memory implementation
diff <(grep -A 30 "def is_accessible_by" src/models/memory.py) \
     <(grep -A 30 "def is_accessible_by" src/models/skill.py)
```

**Risk if FAIL**: CVSS 8.7 CRITICAL (S-2 cross-tenant access)

---

### CRITICAL: Docstring Security Warning
- [ ] Docstring includes "SECURITY-CRITICAL" warning
- [ ] Docstring mentions namespace must be verified from database
- [ ] Docstring includes example of correct usage

**Verification**: Read `src/models/skill.py` docstring

**Risk if FAIL**: Future developers may misuse API

---

### HIGH: Type Hints
- [ ] All parameters have type hints
- [ ] Return type is `bool`
- [ ] No `Any` types (strict typing)

**Verification**:
```python
import inspect
sig = inspect.signature(Skill.is_accessible_by)
print(sig)  # Should show: (requesting_agent_id: str, requesting_agent_namespace: str) -> bool
```

---

## 3. SkillService Implementation Review

### CRITICAL: get_skill() Namespace Verification
- [ ] Fetches agent from database to verify namespace
- [ ] Uses `select(Agent).where(Agent.agent_id == agent_id)`
- [ ] Stores verified namespace: `verified_namespace = agent.namespace`
- [ ] **NEVER trusts JWT claim or user input for namespace**
- [ ] Queries skill with namespace filter: `Skill.namespace == verified_namespace`
- [ ] Calls `skill.is_accessible_by(agent_id, verified_namespace)`
- [ ] Raises `AuthorizationError` if access denied

**Verification**:
```python
# Read implementation
cat src/services/skill_service.py | grep -A 50 "async def get_skill"

# Critical checks:
# 1. "select(Agent).where(Agent.agent_id == agent_id)" exists
# 2. "verified_namespace = agent.namespace" exists
# 3. "Skill.namespace == verified_namespace" in WHERE clause
# 4. "is_accessible_by(agent_id, verified_namespace)" called
```

**Risk if FAIL**: CVSS 8.7 CRITICAL (S-2 namespace isolation breach)

---

### CRITICAL: create_skill() Namespace Enforcement
- [ ] Fetches agent from database to verify namespace
- [ ] Forces namespace to verified value (ignores client input)
- [ ] Logs warning if client namespace differs from verified namespace
- [ ] Sanitizes SKILL.md content before storage
- [ ] Enforces content size limit (1MB)

**Verification**:
```python
cat src/services/skill_service.py | grep -A 50 "async def create_skill"

# Critical checks:
# 1. Namespace override: "data.namespace = verified_namespace"
# 2. Sanitization called: "sanitize_skill_html()"
# 3. Size limit: "len(content.encode('utf-8')) > 1024*1024"
```

**Risk if FAIL**: CVSS 8.7 CRITICAL (S-2 namespace override attack)

---

### HIGH: update_skill() Ownership Check
- [ ] Fetches skill with `get_skill()` (includes namespace verification)
- [ ] Checks ownership: `if skill.created_by != agent_id: raise AuthorizationError`
- [ ] Re-sanitizes content on update
- [ ] Increments version number

**Verification**:
```python
cat src/services/skill_service.py | grep -A 40 "async def update_skill"

# Critical checks:
# 1. Ownership: "skill.created_by != agent_id"
# 2. Re-sanitization: "sanitize_skill_html()"
```

**Risk if FAIL**: CVSS 7.5 HIGH (S-2 privilege escalation)

---

### CRITICAL: activate_skill() Permission Inheritance
- [ ] Fetches skill with `get_skill()` (namespace verified)
- [ ] Fetches activating agent from database
- [ ] Stores verified namespace: `verified_namespace = agent.namespace`
- [ ] Uses **activating agent's** permissions (NOT creator's)
- [ ] Memory queries use: `agent_id=agent_id, namespace=verified_namespace`
- [ ] Validates memory filters (namespace forced)
- [ ] Logs activation to SecurityAuditLog

**Verification**:
```python
cat src/services/skill_service.py | grep -A 80 "async def activate_skill"

# Critical checks:
# 1. Agent fetch: "agent = await session.get(Agent, agent_id)"
# 2. Namespace: "verified_namespace = agent.namespace"
# 3. Memory query: "agent_id=agent_id, namespace=verified_namespace"
# 4. NO "skill.created_by" used for memory queries
# 5. Audit log: "security_audit_facade.log_event('skill_activation')"
```

**Risk if FAIL**: CVSS 7.8 HIGH (S-3 memory permission escalation)

---

## 4. Markdown Sanitization Review

### CRITICAL: YAML Frontmatter Parsing
- [ ] Uses `yaml.safe_load()` (NOT `yaml.load()`)
- [ ] Handles YAML errors gracefully (try/except)
- [ ] Validates frontmatter type: `isinstance(frontmatter, dict)`
- [ ] Validates schema with Pydantic after parsing

**Verification**:
```python
cat src/services/skill_service.py | grep -A 30 "parse.*frontmatter"

# Critical checks:
# 1. "yaml.safe_load()" exists
# 2. "yaml.load(" does NOT exist (would be CRITICAL vulnerability)
# 3. "isinstance(frontmatter, dict)" validation
```

**Risk if FAIL**: CVSS 9.0 CRITICAL (S-1 YAML RCE via !!python/)

---

### CRITICAL: Markdown Rendering (HTML Disabled)
- [ ] Uses `markdown-it-py` library
- [ ] Option set: `MarkdownIt("commonmark", {"html": False})`
- [ ] Only safe extensions enabled: `md.enable("table")`, `md.enable("strikethrough")`
- [ ] NO custom plugins loaded

**Verification**:
```python
cat src/services/skill_service.py | grep -A 20 "MarkdownIt"

# Critical checks:
# 1. "html": False exists in options
# 2. "html": True does NOT exist
```

**Risk if FAIL**: CVSS 8.5 CRITICAL (S-1 HTML injection)

---

### CRITICAL: HTML Sanitization (Bleach)
- [ ] Uses `markdown_sanitizer` from `src/security/html_sanitizer.py`
- [ ] Preset: `markdown` (NOT `rich` or custom)
- [ ] Calls `markdown_sanitizer.sanitize(html, context="skill_content")`
- [ ] Checks for suspicious patterns after sanitization
- [ ] Raises `SecurityError` if patterns detected after sanitization

**Verification**:
```python
cat src/services/skill_service.py | grep -A 10 "markdown_sanitizer"

# Critical checks:
# 1. Import: "from src.security.html_sanitizer import markdown_sanitizer"
# 2. Sanitize call: "markdown_sanitizer.sanitize()"
# 3. Pattern check: "_contains_suspicious_patterns(sanitized)"
```

**Risk if FAIL**: CVSS 8.5 CRITICAL (S-1 XSS)

---

### HIGH: URL Validation
- [ ] Uses `HTMLSanitizer.sanitize_url()` for all URLs
- [ ] Whitelist: `http, https, mailto` protocols only
- [ ] Blocks: `javascript, data, vbscript, file` protocols
- [ ] Blocks internal URLs: `localhost, 127.0.0.1, 10.x.x.x, 192.168.x.x`

**Verification**:
```python
cat src/services/skill_service.py | grep -A 10 "sanitize_url"

# Check src/security/html_sanitizer.py:
cat src/security/html_sanitizer.py | grep -A 30 "def sanitize_url"
```

**Risk if FAIL**: CVSS 7.5 HIGH (S-1 JavaScript URL injection)

---

## 5. API Endpoint Review

### CRITICAL: POST /api/skills Validation
- [ ] Request validated with Pydantic model: `CreateSkillRequest`
- [ ] Content size limit enforced: `@validator("content")` checks size
- [ ] UUID validation for related IDs
- [ ] Namespace forced to verified value (ignores client input)
- [ ] Sanitization called before database insert

**Verification**:
```python
cat src/api/routers/skills.py | grep -A 50 "POST.*skills"

# Critical checks:
# 1. Pydantic model: "data: CreateSkillRequest"
# 2. Namespace override: "data.namespace = verified_namespace"
# 3. Sanitization: "sanitize_skill_html()"
```

**Risk if FAIL**: CVSS 8.5 CRITICAL (S-1 injection, S-2 namespace breach)

---

### CRITICAL: GET /api/skills/{skill_id} UUID Validation
- [ ] Path parameter type: `skill_id: str` (NOT `UUID` to allow validation)
- [ ] UUID validation: `UUID(skill_id)` in try/except
- [ ] Raises `HTTPException(400)` for invalid UUID
- [ ] Calls `skill_service.get_skill(skill_uuid, agent_id)`

**Verification**:
```python
cat src/api/routers/skills.py | grep -A 30 "GET.*skill_id"

# Critical checks:
# 1. "skill_id: str" parameter
# 2. "UUID(skill_id)" validation
# 3. "HTTPException(status_code=400)" on ValueError
```

**Risk if FAIL**: CVSS 6.5 MEDIUM (S-4 path traversal)

---

### CRITICAL: PUT /api/skills/{skill_id} Ownership Check
- [ ] UUID validation (same as GET)
- [ ] Calls `skill_service.update_skill()` (includes ownership check)
- [ ] Re-sanitizes content
- [ ] Returns 403 Forbidden for non-owners

**Verification**:
```python
cat src/api/routers/skills.py | grep -A 40 "PUT.*skill_id"

# Critical checks:
# 1. UUID validation exists
# 2. "update_skill()" called (which has ownership check)
```

**Risk if FAIL**: CVSS 7.5 HIGH (S-2 privilege escalation)

---

### HIGH: POST /api/skills/{skill_id}/activate CSP Header
- [ ] UUID validation
- [ ] Calls `skill_service.activate_skill()`
- [ ] Sets Content-Security-Policy header:
   ```python
   response.headers["Content-Security-Policy"] = (
       "default-src 'self'; "
       "script-src 'self'; "
       "style-src 'self' 'unsafe-inline'; "
       "img-src 'self' https:; "
       "connect-src 'self'; "
       "frame-ancestors 'none';"
   )
   ```

**Verification**:
```python
cat src/api/routers/skills.py | grep -A 50 "activate"

# Critical checks:
# 1. CSP header set on Response object
```

**Risk if FAIL**: Defense-in-depth weakened (S-1 XSS mitigation)

---

## 6. Memory Filter Validation Review

### CRITICAL: validate_memory_filters() Implementation
- [ ] Function exists in `SkillService` or helper module
- [ ] Forces namespace to agent's verified namespace
- [ ] Logs warning if client namespace differs
- [ ] Validates semantic query (max 1000 chars, no SQL injection)
- [ ] Removes disallowed filters: `access_level`, `agent_id`

**Verification**:
```python
cat src/services/skill_service.py | grep -A 40 "validate_memory_filters"

# Critical checks:
# 1. Namespace override: "filters['namespace'] = agent_namespace"
# 2. Query validation: "len(query) > 1000"
# 3. Disallowed removal: "filters.pop('access_level')"
```

**Risk if FAIL**: CVSS 7.8 HIGH (S-3 memory escalation)

---

## 7. Audit Logging Review

### HIGH: Skill Activation Logging
- [ ] Calls `security_audit_facade.log_event()` on every activation
- [ ] Event type: `"skill_activation"`
- [ ] Event data includes: `skill_id`, `agent_id`, `namespace`, `memory_count`, `timestamp`

**Verification**:
```python
cat src/services/skill_service.py | grep -A 20 "security_audit_facade"

# Check event data structure matches spec
```

**Risk if FAIL**: Compliance violation, forensics impaired

---

### MEDIUM: Security Event Logging
- [ ] Logs suspicious patterns detected
- [ ] Logs access denied events
- [ ] Logs sanitization failures

**Verification**: Grep for `security_audit_facade.log_event` calls

---

## 8. Test Implementation Review

### CRITICAL: Unit Tests Exist
- [ ] `tests/unit/security/test_skill_markdown_injection.py` exists (20 tests)
- [ ] `tests/unit/security/test_skill_namespace_isolation.py` exists (14 tests)
- [ ] `tests/unit/security/test_skill_memory_escalation.py` exists (10 tests)
- [ ] `tests/unit/security/test_skill_path_traversal.py` exists (5 tests)
- [ ] Total: 49 security tests (35 minimum required)

**Verification**:
```bash
ls -lh tests/unit/security/test_skill_*.py

# Count tests
pytest tests/unit/security/test_skill_*.py --collect-only | grep "test_" | wc -l
# Expected: ≥35 tests
```

**Risk if FAIL**: Untested code = vulnerable code

---

### CRITICAL: All Tests PASS
- [ ] All 49 skill security tests PASS
- [ ] Zero regressions in existing tests (Memory, Agent, etc.)
- [ ] Code coverage >90% for security-critical paths

**Verification**:
```bash
pytest tests/unit/security/test_skill_*.py -v
# Expected: ALL PASS, 0 FAIL

pytest tests/ -v --cov=src --cov-report=term-missing
# Expected: Coverage ≥90% for src/services/skill_service.py
```

**Risk if FAIL**: CRITICAL (cannot deploy)

---

### HIGH: Integration Tests
- [ ] `tests/integration/test_skill_security_integration.py` exists (5 tests)
- [ ] All integration tests PASS

**Verification**:
```bash
pytest tests/integration/test_skill_security_integration.py -v
```

---

## 9. Migration Review

### CRITICAL: Alembic Migration Exists
- [ ] Migration file exists in `migrations/versions/`
- [ ] Migration creates `skills` table
- [ ] Migration creates `skill_versions` table
- [ ] Migration creates unique constraint: `idx_skills_namespace_name`
- [ ] Migration creates indexes
- [ ] Migration is idempotent (can run multiple times safely)

**Verification**:
```bash
ls -lh migrations/versions/*skills*.py

# Apply migration
alembic upgrade head

# Check tables exist
psql -c "\d skills"
psql -c "\d skill_versions"
```

**Risk if FAIL**: Database schema mismatch, deployment failure

---

## 10. Documentation Review

### HIGH: Docstrings Present
- [ ] All public methods have docstrings
- [ ] Security-critical methods have "SECURITY-CRITICAL" warnings
- [ ] Type hints are complete
- [ ] Examples provided for complex methods

**Verification**: Manually inspect `src/services/skill_service.py`

---

### MEDIUM: README/CHANGELOG Updated
- [ ] `README.md` mentions Skills system
- [ ] `CHANGELOG.md` has v2.4.0 entry
- [ ] Security considerations documented

**Verification**: Read files

---

## Final Approval Checklist

### CRITICAL Items (Must ALL PASS)
- [ ] Database schema: Namespace isolation (REQ-NS-001, REQ-NS-002)
- [ ] Model: `is_accessible_by()` method (REQ-NS-003)
- [ ] Service: Namespace verification (REQ-NS-001)
- [ ] Service: Permission inheritance (REQ-MEM-001)
- [ ] YAML: `safe_load()` only (REQ-YAML-001)
- [ ] Markdown: HTML disabled (REQ-MD-001)
- [ ] HTML: Bleach sanitization (REQ-HTML-001)
- [ ] API: UUID validation (REQ-IV-003)
- [ ] Tests: All PASS (REQ-TEST-001, REQ-TEST-002)

**Total CRITICAL Items**: 9

### HIGH Items (Should ALL PASS)
- [ ] Ownership checks (REQ-NS-004)
- [ ] URL validation (REQ-HTML-003)
- [ ] Content size limits (REQ-IV-001)
- [ ] Memory filter validation (REQ-MEM-002)
- [ ] Audit logging (REQ-AUDIT-001)
- [ ] Indexes created (performance)
- [ ] Integration tests PASS

**Total HIGH Items**: 7

### MEDIUM Items (Nice to Have)
- [ ] Skill name validation (REQ-IV-002)
- [ ] Suspicious pattern detection (REQ-HTML-004)
- [ ] CSP headers (REQ-CSP-001)
- [ ] Security event logging (REQ-AUDIT-002)
- [ ] Documentation complete

**Total MEDIUM Items**: 5

---

## Approval Decision Matrix

| CRITICAL Pass | HIGH Pass | MEDIUM Pass | Decision |
|---------------|-----------|-------------|----------|
| 9/9 (100%) | 7/7 (100%) | 5/5 (100%) | ✅ **APPROVE** - Production ready |
| 9/9 (100%) | 7/7 (100%) | 3-4/5 (60-80%) | ✅ **APPROVE** - Minor docs fix recommended |
| 9/9 (100%) | 5-6/7 (71-86%) | Any | ⚠️ **CONDITIONAL APPROVE** - Fix HIGH items in hotfix |
| 8/9 (89%) | Any | Any | ❌ **REJECT** - Fix CRITICAL item immediately |
| <8/9 (<89%) | Any | Any | ❌ **REJECT** - Major security issues, cannot deploy |

---

## Review Process

### Step 1: Code Review (Hestia)
1. Clone Artemis's branch
2. Review each file against this checklist
3. Mark PASS/FAIL for each item
4. Document all FAIL items with details

### Step 2: Test Execution (Hestia)
```bash
# Run all security tests
pytest tests/unit/security/test_skill_*.py -v

# Run integration tests
pytest tests/integration/test_skill_security_integration.py -v

# Check coverage
pytest tests/ -v --cov=src --cov-report=html
```

### Step 3: Manual Verification (Hestia)
1. Test XSS vectors manually (A1-A9)
2. Test namespace isolation (A18-A23)
3. Test permission escalation (A24-A26)
4. Test path traversal (A27)

### Step 4: Approval Decision (Hestia)
- Count PASS/FAIL for CRITICAL, HIGH, MEDIUM
- Apply decision matrix
- If APPROVE: Sign off and merge to master
- If REJECT: Document all issues, send back to Artemis

---

## Issue Template (for FAIL items)

```markdown
### Issue: [CRITICAL/HIGH/MEDIUM] - [Brief Description]

**Checklist Item**: [Item number and name]
**Risk**: CVSS [score] [severity] ([Risk ID from threat model])
**File**: [path to file]
**Line**: [line number]

**Issue Description**:
[Detailed description of what's wrong]

**Expected Behavior**:
[What should happen]

**Actual Behavior**:
[What currently happens]

**Fix Required**:
[Step-by-step fix instructions]

**Test to Verify Fix**:
[Test name that should PASS after fix]

**Deadline**:
- CRITICAL: 24 hours
- HIGH: 3 days
- MEDIUM: 1 week
```

---

**End of Code Review Checklist**

*"...すべてのCRITICAL項目が完璧でなければ、承認しません。セキュリティに妥協はありません..."*

**Hestia (Security Guardian)**
**Status**: Checklist Complete ✅
**Next**: Artemis implementation (Phase 5B) → Hestia review (Phase 5C)
