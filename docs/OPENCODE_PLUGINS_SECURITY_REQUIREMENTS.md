# OpenCode Plugins - Security Requirements & Verification Report

**Report Date**: 2025-10-19
**Auditor**: Hestia (Security Guardian)
**Project**: Trinitas Agents OpenCode Plugins
**Scope**: Rate Limiting, Symlink Protection, Path Traversal Prevention

---

## Executive Summary

**Overall Risk Level**: 🔴 **HIGH**

This report defines mandatory security requirements for OpenCode plugins and audits existing implementations. Current plugins lack critical protections against DoS attacks (no rate limiting), TOCTOU vulnerabilities (CWE-61), and path traversal exploits.

### Critical Findings
1. ❌ **No Rate Limiting** - DoS attack vector (Priority: CRITICAL)
2. ❌ **No Symlink Protection** - CWE-61 TOCTOU vulnerability (Priority: HIGH)
3. ⚠️ **Incomplete Path Traversal Prevention** - Directory escapes possible (Priority: HIGH)

---

## 1. Rate Limiting Requirements

### 1.1 Threat Model
**Attack Vector**: Denial of Service (DoS)
**CWE Reference**: CWE-400 (Uncontrolled Resource Consumption)

**Attack Scenario**:
```javascript
// Malicious script floods plugin API
for (let i = 0; i < 100000; i++) {
  await plugin.executeHook('tool.execute.before', {/* payload */});
}
```

### 1.2 Mandatory Requirements

#### REQ-RL-001: Call Rate Limits
**Severity**: CRITICAL
**Implementation Deadline**: Before production deployment

**Requirements**:
- Maximum 100 calls per 60-second window per hook
- Sliding window algorithm (NOT fixed window to prevent burst attacks)
- Per-hook independent rate limiting
- Graceful degradation (return error, do not crash)

**Reference Implementation**:
```javascript
class RateLimiter {
  constructor(maxCalls = 100, windowMs = 60000) {
    this.maxCalls = maxCalls;
    this.windowMs = windowMs;
    this.callHistory = []; // Array of timestamps
  }

  checkLimit(hookName) {
    const now = Date.now();

    // Remove calls outside sliding window
    this.callHistory = this.callHistory.filter(
      timestamp => now - timestamp < this.windowMs
    );

    // Check if limit exceeded
    if (this.callHistory.length >= this.maxCalls) {
      const oldestCall = this.callHistory[0];
      const retryAfter = Math.ceil((this.windowMs - (now - oldestCall)) / 1000);

      throw new RateLimitError(
        `Rate limit exceeded for ${hookName}. Retry after ${retryAfter}s`,
        { retryAfter, limit: this.maxCalls, window: this.windowMs }
      );
    }

    // Record this call
    this.callHistory.push(now);
    return true;
  }
}
```

#### REQ-RL-002: Memory Management
**Severity**: HIGH
**Issue**: Array-based rate limiter can grow unbounded

**Requirements**:
- Maximum 10,000 entries in `callHistory` (fail-safe)
- Automatic cleanup of stale entries
- Memory usage monitoring

**Security Guard**:
```javascript
// Fail-safe to prevent memory exhaustion
if (this.callHistory.length > 10000) {
  console.error('🚨 Rate limiter memory overflow detected');
  this.callHistory = this.callHistory.slice(-1000); // Keep only recent 1000
}
```

#### REQ-RL-003: Error Response
**Severity**: MEDIUM
**Requirement**: Proper error messages with actionable information

**Error Format**:
```javascript
{
  error: "RateLimitExceeded",
  message: "Too many requests to hook 'tool.execute.before'",
  retryAfter: 45,  // seconds
  limit: 100,
  window: 60000,
  timestamp: "2025-10-19T15:30:45Z"
}
```

#### REQ-RL-004: Bypass Protection
**Severity**: CRITICAL
**Threat**: Attacker bypasses rate limiting by manipulating timestamps

**Requirements**:
- Use `Date.now()` (server-side) - NEVER trust client timestamps
- Rate limiter state must be immutable from external code
- No exposed methods to reset/clear rate limiting state

**Anti-Pattern (FORBIDDEN)**:
```javascript
// ❌ NEVER DO THIS
plugin.rateLimiter.reset(); // Allows bypass
plugin.rateLimiter.callHistory = []; // Direct manipulation
```

### 1.3 Testing Requirements

**Test Case RL-T001**: Normal Usage
```javascript
test('should allow 100 calls within 60s', async () => {
  const limiter = new RateLimiter(100, 60000);

  for (let i = 0; i < 100; i++) {
    expect(() => limiter.checkLimit('test')).not.toThrow();
  }
});
```

**Test Case RL-T002**: Rate Limit Exceeded
```javascript
test('should reject 101st call', async () => {
  const limiter = new RateLimiter(100, 60000);

  for (let i = 0; i < 100; i++) {
    limiter.checkLimit('test');
  }

  expect(() => limiter.checkLimit('test')).toThrow(RateLimitError);
});
```

**Test Case RL-T003**: Sliding Window Recovery
```javascript
test('should allow calls after window expires', async () => {
  const limiter = new RateLimiter(2, 100); // 2 calls per 100ms

  limiter.checkLimit('test');
  limiter.checkLimit('test');

  expect(() => limiter.checkLimit('test')).toThrow();

  await new Promise(resolve => setTimeout(resolve, 150));

  expect(() => limiter.checkLimit('test')).not.toThrow();
});
```

---

## 2. Symlink Protection Requirements

### 2.1 Threat Model
**Attack Vector**: TOCTOU (Time-of-Check Time-of-Use)
**CWE Reference**: CWE-61, CWE-367

**Attack Scenario**:
```bash
# Attacker creates symlink to sensitive file
ln -s /etc/passwd ./allowed-dir/innocent-file.txt

# Plugin checks path (appears safe)
# Plugin resolves symlink → reads /etc/passwd
```

### 2.2 Mandatory Requirements

#### REQ-SYM-001: Symlink Detection BEFORE Resolution
**Severity**: CRITICAL
**Implementation**: Check symlink status BEFORE resolving paths

**Correct Order**:
```javascript
import { lstatSync } from 'fs';
import { resolve } from 'path';

function safeReadFile(filePath, allowedRoots) {
  // Step 1: Check if path is symlink (BEFORE resolution)
  try {
    const stats = lstatSync(filePath); // lstat does NOT follow symlinks

    if (stats.isSymbolicLink()) {
      throw new SecurityError(
        `Symlink detected: ${filePath}`,
        { code: 'SYMLINK_FORBIDDEN', cwe: 'CWE-61' }
      );
    }
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new Error(`File not found: ${filePath}`);
    }
    throw error;
  }

  // Step 2: Resolve path (safe because not a symlink)
  const resolvedPath = resolve(filePath);

  // Step 3: Verify within allowed roots
  const isAllowed = allowedRoots.some(root =>
    resolvedPath.startsWith(resolve(root))
  );

  if (!isAllowed) {
    throw new SecurityError(
      `Path outside allowed roots: ${resolvedPath}`,
      { code: 'PATH_FORBIDDEN', allowedRoots }
    );
  }

  // Step 4: Safe to read
  return readFileSync(resolvedPath, 'utf-8');
}
```

#### REQ-SYM-002: Recursive Symlink Check
**Severity**: HIGH
**Threat**: Symlink in parent directories

**Requirements**:
- Check EVERY component of the path for symlinks
- Example: `/allowed/dir/subdir/file.txt` → check `/allowed`, `/allowed/dir`, `/allowed/dir/subdir`

**Implementation**:
```javascript
function checkPathForSymlinks(filePath) {
  const parts = filePath.split('/').filter(Boolean);
  let currentPath = '/';

  for (const part of parts) {
    currentPath = join(currentPath, part);

    try {
      const stats = lstatSync(currentPath);
      if (stats.isSymbolicLink()) {
        throw new SecurityError(
          `Symlink detected in path: ${currentPath}`,
          { fullPath: filePath, symlinkAt: currentPath }
        );
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
}
```

#### REQ-SYM-003: Security Logging
**Severity**: MEDIUM
**Requirement**: Log all symlink detection attempts

**Log Format**:
```javascript
{
  timestamp: "2025-10-19T15:30:45Z",
  event: "SYMLINK_BLOCKED",
  path: "/path/to/symlink",
  target: "/etc/passwd", // where symlink points
  plugin: "dynamic-context-loader",
  severity: "HIGH"
}
```

### 2.3 Current Implementation Status

#### dynamic-context-loader.js
**Status**: ❌ **VULNERABLE**

**Vulnerable Code (Line 24)**:
```javascript
const configData = readFileSync(configPath, 'utf-8');
```

**Issue**: No symlink check before `readFileSync`

**Fix Required**:
```javascript
// Before reading
checkPathForSymlinks(configPath);
const configData = readFileSync(configPath, 'utf-8');
```

#### narrative-engine.js
**Status**: ❌ **VULNERABLE**

**Vulnerable Code (Line 24)**:
```javascript
const configData = readFileSync(configPath, 'utf-8');
```

**Same vulnerability** as dynamic-context-loader.js

---

## 3. Path Traversal Prevention Requirements

### 3.1 Threat Model
**Attack Vector**: Directory Traversal
**CWE Reference**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

**Attack Scenario**:
```javascript
// Attacker provides malicious path
const maliciousPath = "../../../../../../etc/passwd";
plugin.readConfig(maliciousPath);
// → Reads /etc/passwd instead of allowed config
```

### 3.2 Mandatory Requirements

#### REQ-PT-001: Path Canonicalization
**Severity**: CRITICAL
**Requirement**: Always resolve paths to absolute canonical form

**Implementation**:
```javascript
import { resolve, normalize } from 'path';

function validatePath(userPath, allowedRoots) {
  // Step 1: Normalize (removes .., ., redundant slashes)
  const normalized = normalize(userPath);

  // Step 2: Resolve to absolute path
  const absolute = resolve(normalized);

  // Step 3: Verify starts with allowed root
  const isAllowed = allowedRoots.some(root => {
    const absoluteRoot = resolve(root);
    return absolute.startsWith(absoluteRoot) &&
           absolute !== absoluteRoot; // Prevent reading root itself
  });

  if (!isAllowed) {
    throw new SecurityError(
      `Path outside allowed directories: ${absolute}`,
      {
        provided: userPath,
        resolved: absolute,
        allowedRoots: allowedRoots
      }
    );
  }

  return absolute;
}
```

#### REQ-PT-002: Allowed Roots Whitelist
**Severity**: CRITICAL
**Requirement**: Strict whitelist of allowed directories

**Default Allowed Roots**:
```javascript
const ALLOWED_ROOTS = [
  '.opencode/',           // OpenCode config
  'trinitas_sources/',    // Trinitas sources
  'docs/',                // Documentation
  'agents/',              // Agent definitions
  // NO access to:
  // - /etc/
  // - /home/
  // - /Users/
  // - ../../ (parent directories)
];
```

#### REQ-PT-003: Unicode Normalization
**Severity**: MEDIUM
**Threat**: Unicode normalization attacks (e.g., `..` as Unicode)

**Requirements**:
- Apply Unicode normalization (NFC) before path checks
- Reject paths with unusual Unicode characters

**Implementation**:
```javascript
function normalizeUnicode(path) {
  // Normalize to NFC (Canonical Composition)
  const normalized = path.normalize('NFC');

  // Reject if contains unusual Unicode
  if (/[\u0000-\u001F\u007F-\u009F]/.test(normalized)) {
    throw new SecurityError('Path contains control characters');
  }

  return normalized;
}
```

#### REQ-PT-004: Null Byte Injection Prevention
**Severity**: HIGH
**Threat**: Null byte injection (e.g., `file.txt\0malicious`)

**Requirements**:
```javascript
function checkNullBytes(path) {
  if (path.includes('\0')) {
    throw new SecurityError(
      'Null byte detected in path',
      { code: 'NULL_BYTE_INJECTION' }
    );
  }
}
```

### 3.3 Current Implementation Status

#### dynamic-context-loader.js
**Status**: ⚠️ **PARTIAL PROTECTION**

**Current Code (Lines 20-23)**:
```javascript
contextFiles: [
  'docs/tmws-integration.md',
  'trinitas_sources/tmws/01_tmws_commands.md'
]
```

**Analysis**:
- ✅ Uses relative paths (safer than absolute)
- ❌ No explicit validation before `readFileSync`
- ❌ No whitelist enforcement
- ❌ Could be exploited if `contextFiles` is user-controlled

**Fix Required**:
```javascript
contextFiles: config.contextFiles.map(file =>
  validatePath(file, ALLOWED_ROOTS)
)
```

---

## 4. Comprehensive Security Checklist

### 4.1 Pre-Implementation Checklist

- [ ] **Rate Limiting**
  - [ ] Sliding window algorithm implemented
  - [ ] Per-hook rate limiting (100 calls/60s)
  - [ ] Memory-safe (max 10,000 entries)
  - [ ] Proper error messages with `retryAfter`
  - [ ] Unit tests for normal/exceeded/recovery scenarios

- [ ] **Symlink Protection**
  - [ ] `lstatSync()` check BEFORE path resolution
  - [ ] Recursive parent directory checks
  - [ ] Security logging for all blocked attempts
  - [ ] Unit tests for symlink detection

- [ ] **Path Traversal Prevention**
  - [ ] Path canonicalization (normalize → resolve)
  - [ ] Whitelist validation against `ALLOWED_ROOTS`
  - [ ] Unicode normalization (NFC)
  - [ ] Null byte injection checks
  - [ ] Unit tests for `..` attacks, Unicode tricks

### 4.2 Code Review Checklist

**File System Operations**:
- [ ] Every `readFileSync()` preceded by security checks
- [ ] Every `writeFileSync()` validates target path
- [ ] No direct use of user input in file paths
- [ ] No `eval()` or `exec()` of user data

**Input Validation**:
- [ ] All user inputs sanitized
- [ ] Type checking for all parameters
- [ ] Bounds checking for numeric inputs
- [ ] Regex patterns tested against ReDoS attacks

**Error Handling**:
- [ ] No sensitive data in error messages
- [ ] Proper error codes (not stack traces)
- [ ] Rate limiting on error responses
- [ ] Security events logged to separate file

---

## 5. Risk Assessment Summary

### 5.1 Risk Matrix

| Vulnerability | CWE | Severity | Exploitability | Impact | Current Status |
|---------------|-----|----------|----------------|--------|----------------|
| No Rate Limiting | CWE-400 | CRITICAL | Easy | High | ❌ Not Implemented |
| Symlink TOCTOU | CWE-61 | HIGH | Medium | High | ❌ Vulnerable |
| Path Traversal | CWE-22 | HIGH | Easy | High | ⚠️ Partial |
| Null Byte Injection | CWE-158 | MEDIUM | Hard | Medium | ❌ Not Checked |
| Unicode Tricks | CWE-176 | MEDIUM | Medium | Medium | ❌ Not Checked |

### 5.2 Recommended Remediation Priority

**Phase 1 (Immediate - Block Production Deployment)**:
1. Implement Rate Limiting (REQ-RL-001, REQ-RL-002)
2. Add Symlink Detection (REQ-SYM-001)
3. Path Traversal Prevention (REQ-PT-001, REQ-PT-002)

**Phase 2 (Before Public Release)**:
4. Recursive Symlink Checks (REQ-SYM-002)
5. Unicode Normalization (REQ-PT-003)
6. Security Logging (REQ-SYM-003)

**Phase 3 (Hardening)**:
7. Null Byte Protection (REQ-PT-004)
8. Comprehensive Audit Logging
9. Intrusion Detection Integration

---

## 6. Security Testing Requirements

### 6.1 Unit Tests (Mandatory)

**Test Suite: Rate Limiting**
```javascript
describe('RateLimiter', () => {
  test('allows normal usage', () => { /* ... */ });
  test('blocks excessive calls', () => { /* ... */ });
  test('resets after window expires', () => { /* ... */ });
  test('handles memory overflow', () => { /* ... */ });
});
```

**Test Suite: Symlink Protection**
```javascript
describe('SymlinkProtection', () => {
  test('detects direct symlinks', () => { /* ... */ });
  test('detects symlinks in parent path', () => { /* ... */ });
  test('allows regular files', () => { /* ... */ });
  test('logs security events', () => { /* ... */ });
});
```

**Test Suite: Path Traversal**
```javascript
describe('PathValidation', () => {
  test('blocks ../ attacks', () => { /* ... */ });
  test('blocks absolute paths outside roots', () => { /* ... */ });
  test('allows whitelisted paths', () => { /* ... */ });
  test('handles Unicode normalization', () => { /* ... */ });
});
```

### 6.2 Integration Tests

**Test: End-to-End Security**
```javascript
test('complete security chain for file read', async () => {
  // Attempt to read file with:
  // - Rate limiting active
  // - Symlink in path
  // - Path traversal attempt

  const result = await plugin.readConfig('../../../etc/passwd');
  expect(result).toThrow(SecurityError);
  expect(securityLog).toContain('PATH_TRAVERSAL_BLOCKED');
});
```

---

## 7. Artemis Implementation Guidance

### 7.1 Suggested Implementation Order

**Step 1: Security Module (New File)**
Create `/plugins/security-guard.js`:
```javascript
export class SecurityGuard {
  constructor(config) {
    this.rateLimiter = new RateLimiter(config.rateLimit);
    this.allowedRoots = config.allowedRoots;
  }

  validateFileAccess(filePath) {
    // Symlink check
    checkPathForSymlinks(filePath);

    // Path traversal check
    const safePath = validatePath(filePath, this.allowedRoots);

    return safePath;
  }

  checkRateLimit(hookName) {
    return this.rateLimiter.checkLimit(hookName);
  }
}
```

**Step 2: Integrate into Existing Plugins**
```javascript
// dynamic-context-loader.js
import { SecurityGuard } from './security-guard.js';

export const DynamicContextLoader = async ({ project, client, $, directory, worktree }) => {
  const security = new SecurityGuard({
    rateLimit: { maxCalls: 100, windowMs: 60000 },
    allowedRoots: ['.opencode/', 'trinitas_sources/', 'docs/']
  });

  return {
    "tool.execute.before": async (input, output) => {
      // Rate limit check
      security.checkRateLimit('tool.execute.before');

      // File access validation
      if (input.filePath) {
        const safePath = security.validateFileAccess(input.filePath);
        input.filePath = safePath; // Use validated path
      }

      // ... rest of logic
    }
  };
};
```

### 7.2 Performance Considerations

**Latency Budget**:
- Rate limiting: < 0.1ms per check
- Symlink detection: < 1ms per path
- Path validation: < 0.5ms per path
- **Total overhead: < 2ms per hook invocation**

**Memory Budget**:
- Rate limiter: < 1MB (10,000 entries × ~100 bytes)
- Security logs: < 5MB (rotate after 1000 events)
- **Total overhead: < 10MB**

---

## 8. Security Logging Requirements

### 8.1 Log Format

**Security Event Log**:
```json
{
  "timestamp": "2025-10-19T15:30:45.123Z",
  "severity": "HIGH",
  "event": "SYMLINK_BLOCKED",
  "plugin": "dynamic-context-loader",
  "details": {
    "path": "/path/to/symlink",
    "target": "/etc/passwd",
    "user": "plugin-system",
    "ip": "127.0.0.1"
  },
  "cwe": "CWE-61",
  "action": "BLOCKED"
}
```

### 8.2 Alerting Thresholds

**Immediate Alerts**:
- 10+ security events in 60 seconds (potential attack)
- Any CRITICAL severity event
- Rate limiting triggered 3+ times in 5 minutes

**Daily Digest**:
- All HIGH severity events
- Aggregated statistics (blocked attempts by type)
- Trend analysis (increasing attack patterns)

---

## 9. Conclusion

### 9.1 Current Risk Assessment

**Overall Security Posture**: 🔴 **INADEQUATE FOR PRODUCTION**

**Critical Gaps**:
1. No DoS protection (rate limiting)
2. TOCTOU vulnerabilities (symlinks)
3. Incomplete path validation

**Recommendation**: 🚫 **BLOCK production deployment until Phase 1 requirements are met.**

### 9.2 Action Items for Artemis

**Immediate (Before Production)**:
- [ ] Implement `RateLimiter` class with sliding window
- [ ] Add `checkPathForSymlinks()` to all file operations
- [ ] Create `validatePath()` with whitelist enforcement
- [ ] Write unit tests for all security functions

**Short-term (Within 1 Week)**:
- [ ] Integrate `SecurityGuard` into all 4 existing plugins
- [ ] Add security logging infrastructure
- [ ] Create integration tests for attack scenarios
- [ ] Document security architecture for future developers

**Long-term (Ongoing)**:
- [ ] Regular security audits (quarterly)
- [ ] Penetration testing before major releases
- [ ] Security training for plugin developers
- [ ] Bug bounty program for external security researchers

---

## 10. References

**Security Standards**:
- OWASP Top 10 (2021)
- CWE Top 25 Most Dangerous Software Weaknesses
- NIST SP 800-53 (Security Controls)

**CWE References**:
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-61: UNIX Symbolic Link (Symlink) Following
- CWE-367: Time-of-Check Time-of-Use (TOCTOU) Race Condition
- CWE-400: Uncontrolled Resource Consumption

**Plugin Security Best Practices**:
- Node.js Security Best Practices (nodejs.org)
- OWASP Secure Coding Practices
- OpenCode Plugin Security Guidelines (opencode-ecosystem.org)

---

**Report Prepared By**: Hestia (Security Guardian)
**Review Status**: Ready for Artemis Implementation
**Next Review Date**: After implementation completion

---

*"Security is not a feature. It is a foundation."*
*— Hestia, Security Guardian*
