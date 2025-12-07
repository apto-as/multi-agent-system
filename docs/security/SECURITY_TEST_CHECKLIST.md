# SECURITY TEST IMPLEMENTATION CHECKLIST
**Hestia (Security Guardian) - Quick Reference for Test Implementation**

---

## WEEK 1: P0 CRITICAL TESTS (24 tests)

### Day 1: Bcrypt Migration Security (5 tests)
**File**: `tests/integration/security/test_password_security.py`

- [ ] `test_new_passwords_use_bcrypt_format()`
  - Verify new passwords use $2b$ format (not SHA256)
  - **BLOCKS**: GPU brute force attack (CVSS 7.5)

- [ ] `test_legacy_sha256_passwords_still_authenticate()`
  - Verify existing SHA256 passwords still work
  - **PREVENTS**: User lockout

- [ ] `test_hash_format_detection_security()`
  - Verify hash format detection is secure
  - **BLOCKS**: Hash confusion attack

- [ ] `test_password_verification_constant_time()`
  - Verify password verification is constant-time
  - **BLOCKS**: Timing attack to enumerate users

- [ ] `test_bcrypt_rejects_sha256_hash()`
  - Verify bcrypt verification rejects SHA256 format
  - **BLOCKS**: Algorithm confusion attack

**Completion Criteria**:
- [ ] All 5 tests passing
- [ ] Coverage report shows bcrypt migration code covered
- [ ] CI/CD integration working

---

### Day 2: JWT Attack Vectors (4 tests)
**File**: `tests/integration/security/test_jwt_security_vectors.py`

- [ ] `test_jwt_algorithm_confusion_attack()`
  - Verify 'none' algorithm is rejected
  - **BLOCKS**: CVE-2015-9235 (CVSS 9.1 CRITICAL)

- [ ] `test_jwt_signature_stripping_attack()`
  - Verify signature-stripped tokens are rejected
  - **BLOCKS**: JWT forgery

- [ ] `test_jwt_kid_injection_attack()`
  - Verify 'kid' header path traversal is blocked
  - **BLOCKS**: CVE-2018-0114

- [ ] `test_jwt_replay_attack_after_logout()`
  - Verify tokens are blacklisted after logout
  - **BLOCKS**: Replay attack

**Completion Criteria**:
- [ ] All 4 tests passing
- [ ] JWT verification code fully covered
- [ ] Attack vectors documented

---

### Day 3: Session/Cookie Security (4 tests)
**File**: `tests/integration/security/test_session_security.py`

- [ ] `test_session_cookie_secure_flag_production()`
  - Verify Secure flag in production
  - **BLOCKS**: Cookie interception over HTTP

- [ ] `test_session_cookie_httponly_flag()`
  - Verify HttpOnly flag is set
  - **BLOCKS**: XSS cookie theft

- [ ] `test_session_cookie_samesite_strict()`
  - Verify SameSite=Strict is set
  - **BLOCKS**: CSRF attack

- [ ] `test_session_timeout_enforcement()`
  - Verify session timeout works
  - **BLOCKS**: Session hijacking

**Completion Criteria**:
- [ ] All 4 tests passing
- [ ] Cookie configuration validated
- [ ] Production vs dev differences tested

---

### Day 4: CORS Security (6 tests)
**File**: `tests/integration/security/test_cors_security.py`

- [ ] `test_cors_wildcard_rejected_in_production()`
  - Verify wildcard '*' is rejected in production
  - **BLOCKS**: Cross-origin data theft

- [ ] `test_cors_null_origin_rejected()`
  - Verify 'null' origin is rejected
  - **BLOCKS**: Sandbox escape attack

- [ ] `test_cors_subdomain_takeover_attack()`
  - Verify non-whitelisted subdomains rejected
  - **BLOCKS**: Subdomain takeover

- [ ] `test_cors_http_downgrade_attack()`
  - Verify HTTP origins rejected in production
  - **BLOCKS**: HTTPS downgrade

- [ ] `test_cors_credential_leak_via_wildcard()`
  - Verify wildcard + credentials blocked
  - **BLOCKS**: Cookie leak to any origin

- [ ] `test_cors_preflight_cache_poisoning()`
  - Verify reasonable max-age
  - **BLOCKS**: Cache poisoning

**Completion Criteria**:
- [ ] All 6 tests passing
- [ ] CORS validator code covered
- [ ] Production config validated

---

### Day 5: Production Configuration (5 tests)
**File**: `tests/integration/security/test_production_security.py`

- [ ] `test_production_requires_https()`
  - Verify HTTPS enforcement in production
  - **BLOCKS**: MITM attack

- [ ] `test_production_requires_secret_key()`
  - Verify strong secret key required
  - **BLOCKS**: JWT forgery

- [ ] `test_production_requires_cors_whitelist()`
  - Verify explicit CORS origins required
  - **BLOCKS**: Any-origin access

- [ ] `test_production_disables_debug_mode()`
  - Verify debug features disabled
  - **BLOCKS**: Information disclosure

- [ ] `test_production_rate_limiting_enabled()`
  - Verify rate limiting enabled
  - **BLOCKS**: DoS attack

**Completion Criteria**:
- [ ] All 5 tests passing
- [ ] Config validators covered
- [ ] Production hardening verified

---

## WEEK 2: P1 HIGH TESTS (9 tests)

### Day 6: RBAC Boundary Tests (2 tests)
**File**: `tests/integration/security/test_rbac_security.py`

- [ ] `test_namespace_isolation_agent_spoofing()`
  - Verify namespace verified from DB (not JWT)
  - **BLOCKS**: Cross-namespace data access

- [ ] `test_privilege_escalation_via_role_claim()`
  - Verify role verified from DB (not JWT)
  - **BLOCKS**: Privilege escalation

**Completion Criteria**:
- [ ] Both tests passing
- [ ] RBAC code covered
- [ ] Namespace isolation verified

---

### Day 7: SQL Injection (3 tests)
**File**: `tests/integration/security/test_injection_attacks.py`

- [ ] `test_sql_injection_via_username()`
  - Verify SQL injection blocked in username
  - **BLOCKS**: Auth bypass

- [ ] `test_sql_injection_via_memory_search()`
  - Verify SQL injection blocked in search
  - **BLOCKS**: Data exfiltration

- [ ] `test_nosql_injection_via_namespace()`
  - Verify NoSQL injection blocked
  - **BLOCKS**: Filter bypass

**Completion Criteria**:
- [ ] All 3 tests passing
- [ ] All user inputs covered
- [ ] Parameterized queries verified

---

### Day 8: XSS Prevention (2 tests)
**File**: `tests/integration/security/test_injection_attacks.py`

- [ ] `test_stored_xss_via_memory_content()`
  - Verify HTML sanitization in stored content
  - **BLOCKS**: Stored XSS

- [ ] `test_reflected_xss_via_error_message()`
  - Verify user input escaped in errors
  - **BLOCKS**: Reflected XSS

**Completion Criteria**:
- [ ] Both tests passing
- [ ] Content sanitization verified
- [ ] Error messages safe

---

### Day 9: Rate Limiting (2 tests)
**File**: `tests/integration/security/test_rate_limiting_security.py`

- [ ] `test_rate_limit_ip_rotation_attack()`
  - Verify rate limit by user ID (not IP)
  - **BLOCKS**: IP rotation bypass

- [ ] `test_rate_limit_header_spoofing()`
  - Verify trusted headers only
  - **BLOCKS**: Header spoofing bypass

**Completion Criteria**:
- [ ] Both tests passing
- [ ] Rate limiter covered
- [ ] Bypass attacks blocked

---

### Day 10: Review & Fix
- [ ] Fix any failing tests
- [ ] Review code coverage reports
- [ ] Update documentation
- [ ] Submit PR for review

---

## WEEK 3: P2 MEDIUM TESTS (4 tests)

### Day 11: API Key Security (2 tests)
**File**: `tests/integration/security/test_api_key_security.py`

- [ ] `test_api_key_brute_force_protection()`
  - Verify API key attempts rate limited
  - **BLOCKS**: Brute force enumeration

- [ ] `test_api_key_timing_attack_prevention()`
  - Verify constant-time verification
  - **BLOCKS**: Timing attack

**Completion Criteria**:
- [ ] Both tests passing
- [ ] API key verification covered
- [ ] Timing analysis completed

---

### Day 12: Documentation
- [ ] Update README with security test info
- [ ] Document test coverage gaps
- [ ] Create security runbook
- [ ] Update deployment checklist

---

### Day 13: CI/CD Integration
- [ ] Add security tests to GitHub Actions
- [ ] Configure test result reporting
- [ ] Set up quality gates
- [ ] Test PR workflow

---

### Day 14: Final Review
- [ ] Run full test suite
- [ ] Generate coverage report
- [ ] Review security compliance
- [ ] Prepare deployment approval

---

## VALIDATION CHECKLIST

### Test Quality Requirements
Each test MUST have:
- [ ] Clear docstring explaining attack vector
- [ ] SEVERITY and ATTACK annotations
- [ ] Proper pytest markers (`@pytest.mark.security`)
- [ ] Descriptive assertion messages
- [ ] Edge case coverage

### Code Quality Requirements
- [ ] Type hints on all test functions
- [ ] Fixtures properly scoped
- [ ] Test isolation (no shared state)
- [ ] Clear test names (what is tested)
- [ ] Comments for complex logic

### CI/CD Requirements
- [ ] Tests run on every PR
- [ ] P0 tests MUST pass to merge
- [ ] P1 tests report failures
- [ ] Coverage report generated
- [ ] Security dashboard updated

---

## QUICK COMMANDS

### Run Tests by Priority
```bash
# P0 CRITICAL only (must pass)
pytest tests/integration/security/ -v -m "security and p0"

# P1 HIGH only
pytest tests/integration/security/ -v -m "security and p1"

# P2 MEDIUM only
pytest tests/integration/security/ -v -m "security and p2"

# All security tests
pytest tests/integration/security/ -v -m security
```

### Coverage Analysis
```bash
# Generate coverage report
pytest tests/integration/security/ \
  --cov=src \
  --cov-report=html \
  --cov-report=term-missing

# View coverage report
open htmlcov/index.html
```

### CI/CD Commands
```bash
# What CI/CD runs on PR
pytest tests/integration/security/ -v -m "security and p0" --tb=short

# What CI/CD runs before merge
pytest tests/integration/security/ -v -m security --tb=short
```

---

## COMPLETION TRACKING

### Week 1 Progress
- [ ] Day 1: 5/5 bcrypt tests passing
- [ ] Day 2: 4/4 JWT tests passing
- [ ] Day 3: 4/4 session tests passing
- [ ] Day 4: 6/6 CORS tests passing
- [ ] Day 5: 5/5 production tests passing
- [ ] **Week 1 Total: 24/24 P0 tests passing**

### Week 2 Progress
- [ ] Day 6: 2/2 RBAC tests passing
- [ ] Day 7: 3/3 SQL injection tests passing
- [ ] Day 8: 2/2 XSS tests passing
- [ ] Day 9: 2/2 rate limit tests passing
- [ ] Day 10: All fixes completed
- [ ] **Week 2 Total: 9/9 P1 tests passing**

### Week 3 Progress
- [ ] Day 11: 2/2 API key tests passing
- [ ] Day 12: Documentation updated
- [ ] Day 13: CI/CD integrated
- [ ] Day 14: Final review completed
- [ ] **Week 3 Total: 4/4 P2 tests passing**

### Overall Progress
- [ ] **Total Tests Implemented: 49/49**
- [ ] **P0 Pass Rate: 100%**
- [ ] **P1 Pass Rate: ≥95%**
- [ ] **P2 Pass Rate: ≥80%**
- [ ] **Code Coverage: ≥90%**
- [ ] **Security Coverage: 100%**

---

## DEPLOYMENT APPROVAL

### Pre-Deployment Checklist
- [ ] All P0 CRITICAL tests passing (100%)
- [ ] All P1 HIGH tests passing (≥95%)
- [ ] All P2 MEDIUM tests passing (≥80%)
- [ ] Code coverage ≥90%
- [ ] Security audit report approved
- [ ] Production config validated
- [ ] CI/CD security stage passing

### Sign-Off Required
- [ ] Security Engineer: _______________
- [ ] Lead Developer: _______________
- [ ] DevOps Engineer: _______________
- [ ] Product Owner: _______________

### Deployment Approval
- [ ] ✅ **APPROVED for production deployment**
- [ ] ❌ **BLOCKED - security tests failing**

**Date**: _______________
**Approved By**: Hestia (Security Guardian)

---

**END OF CHECKLIST**
