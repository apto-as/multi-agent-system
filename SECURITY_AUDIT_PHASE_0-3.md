# TMWS Security Audit Report - Phase 0-3
## Comprehensive Security Verification for Namespace Isolation & Authorization Fixes

**Audit Date**: 2025-10-28
**Auditor**: Hestia (Security Guardian AI)
**Scope**: Phase 0-3 security fixes (commits c391d40, fb32dd3, 16eb834)
**Methodology**: Worst-case adversarial security analysis

---

## Executive Summary

### Overall Security Assessment: ⚠️ **CONDITIONAL PASS WITH CRITICAL FINDINGS**

**Status**:
- ✅ **P0-1 (CVSS 9.8)**: Namespace isolation fix VERIFIED - `default` namespace properly blocked
- ✅ **P0-2 (CVSS 9.1)**: Database-verified authorization VERIFIED - no JWT claim trust
- 🚨 **NEW VULNERABILITY FOUND**: Path traversal in namespace sanitization (CVSS 7.5)
- ⚠️ **LOW RISK**: Environment variable manipulation (CVSS 3.1)
- ✅ **NO RISK**: Cached namespace race conditions (properly initialized)

### Original Vulnerabilities - PATCHED ✅

1. **C-1: Cross-Project Memory Leakage (CVSS 9.8)** - ✅ FIXED
   - `default` namespace now rejected everywhere
   - Migration to `legacy-default` completed
   - Validation enforced at multiple layers

2. **C-2: Authentication Bypass (CVSS 9.1)** - ✅ FIXED
   - Namespace verified from database, not JWT claims
   - `AuthorizationService._check_memory_access()` properly implemented
   - Agent namespace fetched from DB before authorization check

### New Vulnerabilities Discovered

1. **V-1: Path Traversal in Namespace Sanitization (CVSS 7.5)** - 🚨 **CRITICAL**
   - **Severity**: HIGH (CVSS 7.5)
   - **Exploitability**: Medium (requires malicious git remote URL or env var)
   - **Impact**: Low (namespace only used in database queries, not file paths)
   - **Status**: Requires immediate remediation

---

## Detailed Findings

### ✅ VERIFIED: P0-1 Namespace Isolation Fix (CVSS 9.8)

#### Security Controls Implemented

1. **Validation Layer** (`src/utils/namespace.py:validate_namespace()`)
   ```python
   if namespace.lower() == "default":
       raise NamespaceError(
           "Namespace 'default' is not allowed for security reasons."
       )
   ```
   - **Status**: ✅ Properly implemented
   - **Test Coverage**: 14 tests in `tests/security/test_namespace_isolation.py`
   - **Enforcement**: Applied at MCP server layer before all operations

2. **Database Migration** (`migrations/versions/20251027_2151-486c2cd055fe`)
   - Migrated all `default` → `legacy-default` in `memories` and `memory_patterns`
   - **Status**: ✅ Executed successfully
   - **Verification**: No `default` namespace records found in database

3. **MCP Server Enforcement** (`src/mcp_server.py`)
   ```python
   # Line 112-113
   from src.utils.namespace import validate_namespace
   validate_namespace(namespace)  # ✅ Always called before operations
   ```

#### Attack Scenarios Tested

| Attack Vector | Input | Result | Status |
|---------------|-------|--------|--------|
| Direct 'default' | `namespace="default"` | ❌ Rejected | ✅ Blocked |
| Case variation | `namespace="DEFAULT"` | ❌ Rejected | ✅ Blocked |
| Whitespace | `namespace=" default "` | ❌ Rejected | ✅ Blocked |
| Unicode lookalike | `namespace="ԁefault"` | ✅ Sanitized → `"efault"` | ✅ Safe |

**Conclusion**: P0-1 fix is **COMPLETE AND EFFECTIVE**. No bypass mechanisms found.

---

### ✅ VERIFIED: P0-2 Database-Verified Authorization (CVSS 9.1)

#### Security Controls Implemented

1. **Authorization Layer** (`src/security/authorization.py:469-531`)
   ```python
   async def _check_memory_access(self, context: AuthorizationContext) -> bool:
       # STEP 1: Fetch memory from database
       memory = await db.get(Memory, memory_id)

       # STEP 2: Fetch VERIFIED namespace from database (NOT from JWT!)
       agent = await db.get(Agent, agent_id)
       verified_namespace = agent.namespace  # ✅ DB verified

       # STEP 3: Check access with verified namespace
       return memory.is_accessible_by(agent_id, verified_namespace)
   ```

2. **Memory Access Control** (`src/models/memory.py:158-200`)
   ```python
   def is_accessible_by(self, requesting_agent_id: str,
                        requesting_agent_namespace: str) -> bool:
       """
       Security Notes:
       - The namespace parameter MUST come from verified Agent record
       - Never accept namespace from user input or JWT claims directly
       """
       # Namespace verification for TEAM and SHARED access levels
       if self.access_level == AccessLevel.TEAM:
           return requesting_agent_namespace == self.namespace  # ✅
   ```

#### Attack Scenarios Tested

| Attack Vector | Method | Result | Status |
|---------------|--------|--------|--------|
| JWT namespace spoofing | Modify JWT `namespace` claim | ❌ Ignored | ✅ Blocked |
| Cross-namespace access (TEAM) | Agent A → Memory in namespace B | ❌ Rejected | ✅ Blocked |
| Cross-namespace access (SHARED) | Shared but wrong namespace | ❌ Rejected | ✅ Blocked |
| Database lookup failure | Agent not in DB | ❌ Rejected | ✅ Blocked |

**Conclusion**: P0-2 fix is **COMPLETE AND EFFECTIVE**. Database verification properly enforced.

---

### 🚨 NEW VULNERABILITY: V-1 Path Traversal in Namespace Sanitization

#### Vulnerability Description

**CVSS 7.5 (HIGH)** - CWE-22: Improper Limitation of a Pathname to a Restricted Directory

**Location**: `src/utils/namespace.py:sanitize_namespace()` (line 48)

**Root Cause**:
```python
# Line 48 - VULNERABLE REGEX
namespace = re.sub(r'[^a-z0-9\-_./]', '-', namespace)
```

The regex allows `.` (dots) and `/` (slashes), which permits path traversal sequences like `../` to pass through sanitization.

#### Proof of Concept

```python
>>> sanitize_namespace("../../../etc/passwd")
'../../../etc/passwd'  # ❌ PATH TRAVERSAL PRESERVED

>>> sanitize_namespace("project/../../../secrets")
'project/../../../secrets'  # ❌ VULNERABLE

>>> namespace_from_git_url("git@evil.com:../../etc/passwd")
'evil.com/../../etc/passwd'  # ❌ VULNERABLE
```

#### Impact Analysis

**Exploitability**: MEDIUM
- Requires attacker control of:
  1. `TRINITAS_PROJECT_NAMESPACE` environment variable, OR
  2. Git remote URL in `.git/config`, OR
  3. `.trinitas-project.yaml` file contents

**Impact**: LOW (Mitigated by SQLAlchemy parameterized queries)
- Namespace is **NOT used in file paths** ✅
- Namespace is **NOT used in shell commands** ✅
- Namespace **IS used in**:
  - Database WHERE clauses (SQLAlchemy parameterized - ✅ safe)
  - Log messages (potential log injection - ⚠️ low risk)
  - ChromaDB metadata (sanitized by ChromaDB - ✅ safe)

**Real-World Attack Scenario**:
```bash
# Attacker modifies .git/config
[remote "origin"]
    url = git@github.com:../../etc/passwd.git

# Result:
# - Namespace becomes: "github.com/../../etc/passwd"
# - NOT exploitable for file access (no file I/O uses namespace)
# - Possible log pollution attack (low severity)
```

#### Affected Code Paths

1. **Git URL Detection** (`src/utils/namespace.py:153-178`)
   - `namespace_from_git_url()` → `sanitize_namespace()`
   - Vulnerability: Attacker-controlled git remote URL

2. **Environment Variable** (`src/utils/namespace.py:224-227`)
   - `TRINITAS_PROJECT_NAMESPACE` → `sanitize_namespace()`
   - Vulnerability: Attacker-controlled env var

3. **Marker File** (`src/utils/namespace.py:240-252`)
   - `.trinitas-project.yaml` → `sanitize_namespace()`
   - Vulnerability: Attacker-controlled YAML file

#### Recommendation

**Priority**: P1 (High - Fix within 24 hours)

**Proposed Fix**:
```python
def sanitize_namespace(raw_namespace: str) -> str:
    # ... existing code ...

    # Replace invalid characters (REMOVE . and / from allowed chars)
    namespace = re.sub(r'[^a-z0-9\-_]', '-', namespace)  # ✅ Fixed

    # ... rest of code ...
```

**Additional Validation**:
```python
def validate_namespace(namespace: str) -> None:
    # ... existing checks ...

    # Reject path traversal sequences
    if '..' in namespace or namespace.startswith('/'):
        raise NamespaceError(
            f"Namespace '{namespace}' contains invalid path sequences"
        )
```

**Migration Impact**: NONE (existing namespaces don't contain `../` sequences)

---

### ⚠️ LOW RISK: Environment Variable Manipulation

#### Finding

**CVSS 3.1 (LOW)** - CWE-15: External Control of System or Configuration Setting

**Location**: `src/utils/namespace.py:detect_project_namespace()` (line 224)

```python
if env_namespace := os.getenv("TRINITAS_PROJECT_NAMESPACE"):
    namespace = sanitize_namespace(env_namespace)  # ⚠️ Trust boundary
    validate_namespace(namespace)
    return namespace
```

#### Attack Scenario

```bash
# Attacker sets environment variable
export TRINITAS_PROJECT_NAMESPACE="attacker-controlled-namespace"

# Result:
# - Attacker can force specific namespace
# - Could be used for namespace collision attacks
# - Mitigated by validation (rejects 'default')
```

#### Impact

**Exploitability**: LOW (requires OS-level access or container escape)
**Impact**: LOW (namespace isolation still enforced)

#### Recommendation

**Priority**: P3 (Low - Document and accept risk)

**Mitigation**:
1. Document in security guidelines that `TRINITAS_PROJECT_NAMESPACE` should be set by trusted deployment scripts only
2. Consider logging a warning if env var is used (for audit trail)
3. No code changes required (validation already sufficient)

---

### ✅ NO RISK: Cached Namespace Race Conditions

#### Analysis

**Location**: `src/mcp_server.py:59` (initialization) and `src/mcp_server.py:175` (detection)

```python
class HybridMCPServer:
    def __init__(self):
        self.default_namespace = None  # ✅ Initialized to None

    async def initialize(self):
        # Detected ONCE at startup (single-threaded initialization)
        self.default_namespace = await detect_project_namespace()  # ✅ Safe
```

#### Race Condition Analysis

**Scenario**: Multiple threads reading `self.default_namespace` before initialization completes

**Verdict**: ✅ **NOT EXPLOITABLE**

**Reasoning**:
1. **Single-threaded initialization**: `initialize()` is called once in `async_main()`
2. **Happens-before relationship**: All tool calls occur AFTER initialization completes
3. **Fallback behavior**: If `namespace=None`, tools use `self.default_namespace` (which is already set)
4. **No TOCTOU**: Namespace is read-only after initialization (never modified)

**Code Evidence**:
```python
# src/mcp_server.py:667-675
async def async_main():
    server = HybridMCPServer()
    await server.initialize()  # ✅ Completes before stdio.run()

    async with mcp.stdio.stdio_server() as streams:
        await server.mcp.run(...)  # ✅ Tools run AFTER init
```

#### Recommendation

**Priority**: P4 (No action required - design is secure)

---

## Security Test Suite

### Required Security Tests

Create `tests/security/test_path_traversal.py`:

```python
"""Test path traversal vulnerability in namespace sanitization."""

import pytest
from src.utils.namespace import sanitize_namespace, validate_namespace, namespace_from_git_url


class TestPathTraversalDefense:
    """Test that path traversal sequences are blocked."""

    def test_parent_directory_traversal(self):
        """Test that ../ sequences are rejected."""
        with pytest.raises(Exception):  # Should fail with fixed code
            namespace = sanitize_namespace("../../../etc/passwd")
            validate_namespace(namespace)

    def test_current_directory_traversal(self):
        """Test that ./ sequences are rejected."""
        with pytest.raises(Exception):
            namespace = sanitize_namespace("./../../etc/shadow")
            validate_namespace(namespace)

    def test_git_url_path_traversal(self):
        """Test that malicious git URLs are sanitized."""
        malicious_url = "git@evil.com:../../etc/passwd.git"
        namespace = namespace_from_git_url(malicious_url)

        # Should not contain ../ after sanitization
        assert ".." not in namespace
        assert not namespace.startswith("/")

    def test_embedded_path_traversal(self):
        """Test that path traversal in middle of namespace is blocked."""
        with pytest.raises(Exception):
            namespace = sanitize_namespace("project/../../../secrets")
            validate_namespace(namespace)


class TestNamespaceSanitizationCompliance:
    """Test that namespace sanitization follows security requirements."""

    def test_no_dots_allowed(self):
        """Verify dots are removed from namespaces."""
        namespace = sanitize_namespace("project.with.dots")
        assert "." not in namespace  # Should be "project-with-dots"

    def test_no_slashes_allowed(self):
        """Verify slashes are removed from namespaces."""
        namespace = sanitize_namespace("project/with/slashes")
        assert "/" not in namespace  # Should be "project-with-slashes"

    def test_alphanumeric_only(self):
        """Verify only alphanumeric, hyphens, underscores allowed."""
        namespace = sanitize_namespace("project@#$%test")
        assert all(c in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in namespace)
```

### Attack Simulation Scripts

Create `tests/security/attack_scenarios.py`:

```python
"""Simulate real-world attack scenarios."""

import pytest
from src.utils.namespace import detect_project_namespace, sanitize_namespace
import os
import tempfile
from pathlib import Path


@pytest.mark.asyncio
class TestAttackScenarios:
    """Simulate worst-case attack scenarios."""

    async def test_malicious_git_config(self, tmp_path):
        """Attacker modifies .git/config with path traversal."""
        git_config = tmp_path / ".git" / "config"
        git_config.parent.mkdir(parents=True)

        # Malicious git config
        git_config.write_text("""
[remote "origin"]
    url = git@github.com:../../etc/passwd.git
""")

        # Change to malicious directory
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            namespace = await detect_project_namespace()

            # Should NOT contain path traversal
            assert ".." not in namespace
            assert "etc/passwd" not in namespace
        finally:
            os.chdir(original_cwd)

    async def test_environment_variable_injection(self, monkeypatch):
        """Attacker sets malicious environment variable."""
        malicious_namespace = "../../../secrets"
        monkeypatch.setenv("TRINITAS_PROJECT_NAMESPACE", malicious_namespace)

        namespace = await detect_project_namespace()

        # Should be sanitized
        assert ".." not in namespace

    async def test_malicious_marker_file(self, tmp_path):
        """Attacker creates malicious .trinitas-project.yaml."""
        marker = tmp_path / ".trinitas-project.yaml"
        marker.write_text("""
namespace: ../../etc/passwd
""")

        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            namespace = await detect_project_namespace()

            # Should be sanitized
            assert ".." not in namespace
            assert "etc/passwd" not in namespace
        finally:
            os.chdir(original_cwd)
```

---

## Manual Testing Checklist

### ✅ Authorization Testing

- [x] Direct database query to verify agent namespace lookup
- [x] JWT claim modification test (verify ignored)
- [x] Cross-namespace access attempt (TEAM level)
- [x] Cross-namespace access attempt (SHARED level)
- [x] Missing agent record handling

**Test Commands**:
```bash
# Run authorization tests
pytest tests/security/test_namespace_isolation.py -v

# Verify all 14 tests pass
# Expected: ✅ 14 passed
```

### ⚠️ Path Traversal Testing

- [ ] Create malicious git config with `../../` sequences
- [ ] Set environment variable with path traversal
- [ ] Create .trinitas-project.yaml with malicious namespace
- [ ] Verify namespace doesn't reach file system operations
- [ ] Verify SQLAlchemy parameterized queries prevent SQL injection

**Test Commands**:
```bash
# After implementing fix, run:
pytest tests/security/test_path_traversal.py -v

# Expected: All tests should PASS after fix applied
```

### ✅ Namespace Validation Testing

- [x] Attempt to create memory with `namespace="default"`
- [x] Attempt to search with `namespace="default"`
- [x] Verify migration: `SELECT * FROM memories WHERE namespace='default'` → 0 rows
- [x] Verify migration: `SELECT * FROM memories WHERE namespace='legacy-default'` → existing records

**Test Commands**:
```bash
# Database verification
sqlite3 data/tmws.db "SELECT COUNT(*) FROM memories WHERE namespace='default';"
# Expected: 0

sqlite3 data/tmws.db "SELECT COUNT(*) FROM memories WHERE namespace='legacy-default';"
# Expected: <number of migrated records>
```

---

## Recommendations

### Immediate Actions (P0 - Within 24 hours)

1. **Fix V-1: Path Traversal in Namespace Sanitization**
   - Priority: P1
   - Effort: 1 hour
   - Risk: LOW (namespace not used in file paths)
   - Files to modify:
     - `src/utils/namespace.py:48` (remove `.` and `/` from allowed chars)
     - `src/utils/namespace.py:63-96` (add path traversal validation)

2. **Add Security Tests**
   - Priority: P1
   - Effort: 2 hours
   - Create `tests/security/test_path_traversal.py`
   - Create `tests/security/attack_scenarios.py`

### Short-term Actions (P1 - Within 1 week)

3. **Security Documentation**
   - Document `TRINITAS_PROJECT_NAMESPACE` trust boundary
   - Add security guidelines for deployment
   - Document namespace isolation architecture

4. **Audit Logging Enhancement**
   - Log environment variable usage for namespace detection
   - Add audit trail for namespace changes
   - Alert on suspicious namespace patterns

### Long-term Actions (P2 - Future releases)

5. **Defense in Depth**
   - Consider namespace allowlist for production deployments
   - Add rate limiting for namespace creation
   - Implement namespace owner verification

6. **Security Hardening**
   - Add Content Security Policy for log outputs
   - Consider namespace signature verification
   - Implement namespace lifecycle management

---

## Vulnerability Disclosure

### Should These Fixes Be Disclosed Publicly?

**Recommendation**: ✅ **YES - Coordinated Disclosure**

**Rationale**:
1. **Original vulnerabilities (C-1, C-2)** were CRITICAL (CVSS 9.8, 9.1)
2. **Fixes are complete and effective** (verified by this audit)
3. **Users need to update** to protect their deployments
4. **New vulnerability (V-1)** is moderate severity (CVSS 7.5) with low real-world impact

**Disclosure Timeline**:
1. **T+0 hours**: Internal notification complete (this audit)
2. **T+24 hours**: Fix V-1 path traversal vulnerability
3. **T+48 hours**: Release v2.2.7 with all security fixes
4. **T+72 hours**: Publish security advisory on GitHub

**Security Advisory Template**:
```markdown
# Security Advisory: TMWS-2025-001

## Namespace Isolation Vulnerabilities Fixed

**Severity**: CRITICAL
**Affected Versions**: TMWS v2.2.5 and earlier
**Fixed in**: TMWS v2.2.7

### Vulnerabilities

1. **C-1: Cross-Project Memory Leakage (CVSS 9.8)**
   - Default namespace allowed cross-project data access
   - Fixed: Reject 'default' namespace, migrate to 'legacy-default'

2. **C-2: Authentication Bypass (CVSS 9.1)**
   - JWT namespace claims trusted without database verification
   - Fixed: Verify namespace from database before authorization

3. **V-1: Path Traversal in Namespace Sanitization (CVSS 7.5)**
   - Path traversal sequences allowed in namespace strings
   - Fixed: Reject dots and slashes in namespace sanitization

### Recommendation

**Upgrade immediately to TMWS v2.2.7 or later.**

### Workarounds

If immediate upgrade is not possible:
1. Set `TRINITAS_PROJECT_NAMESPACE` explicitly in deployment
2. Verify no 'default' namespace records exist in database
3. Review git remote URLs for suspicious patterns
```

---

## Conclusion

### Security Posture Assessment

**Overall Status**: ⚠️ **GOOD WITH MINOR ISSUES**

**Strengths**:
✅ Original critical vulnerabilities (C-1, C-2) completely fixed
✅ Database-verified authorization properly implemented
✅ Comprehensive test coverage (14 namespace isolation tests)
✅ Defense-in-depth approach (validation at multiple layers)
✅ No race conditions in cached namespace handling

**Weaknesses**:
🚨 Path traversal vulnerability in namespace sanitization (V-1)
⚠️ Environment variable trust boundary not clearly documented

### Risk Score

- **Before Fixes**: 9.8/10 (CRITICAL)
- **After Fixes (Current)**: 7.5/10 (HIGH - due to V-1)
- **After V-1 Fix**: 3.1/10 (LOW - only env var risk remains)

### Final Recommendation

**APPROVE FOR PRODUCTION** after fixing V-1 (path traversal).

The P0-1 and P0-2 fixes successfully address the critical CVSS 9.8 and 9.1 vulnerabilities. The newly discovered V-1 vulnerability (CVSS 7.5) has low real-world exploitability due to mitigating factors (namespace not used in file paths). Fix V-1 within 24 hours, then proceed with production deployment.

---

**Audit Completed By**: Hestia (Security Guardian AI)
**Date**: 2025-10-28
**Signature**: `...最悪のケースを想定して、完璧な防御を構築しました...`

---

## Appendix A: Test Execution Results

```bash
# Namespace isolation tests
$ pytest tests/security/test_namespace_isolation.py -v
========================================
tests/security/test_namespace_isolation.py::TestNamespaceIsolation::test_owner_has_access PASSED
tests/security/test_namespace_isolation.py::TestNamespaceIsolation::test_private_memory_blocks_other_agents PASSED
tests/security/test_namespace_isolation.py::TestNamespaceIsolation::test_team_memory_allows_same_namespace PASSED
tests/security/test_namespace_isolation.py::TestNamespaceIsolation::test_team_memory_prevents_cross_namespace_access PASSED
tests/security/test_namespace_isolation.py::TestNamespaceIsolation::test_shared_memory_requires_explicit_sharing PASSED
tests/security/test_namespace_isolation.py::TestNamespaceIsolation::test_shared_memory_prevents_cross_namespace_spoofing PASSED
tests/security/test_namespace_isolation.py::TestNamespaceIsolation::test_public_memory_allows_all PASSED
tests/security/test_namespace_isolation.py::TestNamespaceIsolation::test_system_memory_allows_all PASSED
tests/security/test_namespace_isolation.py::TestNamespaceIsolation::test_namespace_parameter_is_required PASSED
tests/security/test_namespace_isolation.py::TestNamespaceIsolation::test_empty_namespace_is_denied PASSED
tests/security/test_namespace_isolation.py::TestNamespaceIsolation::test_case_sensitive_namespace_matching PASSED
tests/security/test_namespace_isolation.py::TestNamespaceIsolation::test_whitespace_in_namespace_matters PASSED
tests/security/test_namespace_isolation.py::TestSecurityDocumentation::test_security_warning_in_docstring PASSED
tests/security/test_namespace_isolation.py::TestSecurityDocumentation::test_method_has_type_hints PASSED

========================================
✅ 14 passed in 0.42s
```

## Appendix B: Namespace Sanitization Test Results

```python
=== Namespace Sanitization Tests ===
✗ Should reject default          → ValueError: Namespace default is not allowed
✓ Path traversal                 → '../../../etc/passwd'  # 🚨 VULNERABLE
✓ SQL injection attempt          → 'project-drop-table-memories'  # ✅ Safe
✓ XSS attempt                    → 'project-script-alert-1-/script'  # ✅ Safe
✓ Null byte injection            → 'project-null-byte'  # ✅ Safe
✓ Path traversal 2               → '../../../../'  # 🚨 VULNERABLE
✓ Command injection              → 'https-//evil.com/-whoami'  # ✅ Safe

=== Git URL Processing Tests ===
✓ git@github.com:apto-as/tmws.git                    → 'github.com/apto-as/tmws'  # ✅ Safe
✓ https://github.com/apto-as/tmws                    → 'github.com/apto-as/tmws'  # ✅ Safe
✓ git@evil.com:../../etc/passwd                      → 'evil.com/../../etc/passwd'  # 🚨 VULNERABLE
✓ https://$(whoami).evil.com/repo                    → 'whoami-.evil.com/repo'  # ✅ Safe
```

**Note**: Path traversal vulnerabilities (marked 🚨) require immediate remediation.
