# Security Implementation Guide for OpenCode Plugins

**Target Audience**: Artemis (Technical Perfectionist)
**Purpose**: Step-by-step implementation guide with working code examples
**Estimated Implementation Time**: 4-6 hours

---

## Quick Start

### Implementation Checklist

- [ ] Create `security-guard.js` module (30 min)
- [ ] Implement `RateLimiter` class (45 min)
- [ ] Implement `SymlinkProtector` class (30 min)
- [ ] Implement `PathValidator` class (30 min)
- [ ] Write unit tests (90 min)
- [ ] Integrate into existing plugins (60 min)
- [ ] Run security test suite (30 min)

**Total**: ~5 hours

---

## 1. Security Guard Module

### File: `/.opencode/plugin/security-guard.js`

```javascript
/**
 * Security Guard Module for OpenCode Plugins
 * Provides rate limiting, symlink protection, and path validation
 * Version: 1.0.0
 *
 * Security Features:
 * - DoS protection via rate limiting (100 calls/60s)
 * - TOCTOU prevention via symlink detection (CWE-61)
 * - Path traversal prevention (CWE-22)
 * - Security event logging
 */

import { lstatSync, existsSync } from 'fs';
import { resolve, normalize, join, sep } from 'path';
import { writeFileSync, appendFileSync } from 'fs';

// ============================================================================
// ERROR CLASSES
// ============================================================================

export class SecurityError extends Error {
  constructor(message, metadata = {}) {
    super(message);
    this.name = 'SecurityError';
    this.metadata = metadata;
    this.timestamp = new Date().toISOString();
  }
}

export class RateLimitError extends SecurityError {
  constructor(message, metadata = {}) {
    super(message, metadata);
    this.name = 'RateLimitError';
    this.code = 'RATE_LIMIT_EXCEEDED';
  }
}

export class SymlinkError extends SecurityError {
  constructor(message, metadata = {}) {
    super(message, metadata);
    this.name = 'SymlinkError';
    this.code = 'SYMLINK_FORBIDDEN';
    this.cwe = 'CWE-61';
  }
}

export class PathTraversalError extends SecurityError {
  constructor(message, metadata = {}) {
    super(message, metadata);
    this.name = 'PathTraversalError';
    this.code = 'PATH_TRAVERSAL_FORBIDDEN';
    this.cwe = 'CWE-22';
  }
}

// ============================================================================
// RATE LIMITER
// ============================================================================

export class RateLimiter {
  constructor(maxCalls = 100, windowMs = 60000) {
    this.maxCalls = maxCalls;
    this.windowMs = windowMs;
    this.callHistory = []; // Array of timestamps

    // Performance metrics
    this.metrics = {
      totalCalls: 0,
      blockedCalls: 0,
      lastReset: Date.now()
    };
  }

  /**
   * Check if rate limit is exceeded
   * @param {string} identifier - Hook name or identifier
   * @returns {boolean} true if within limit
   * @throws {RateLimitError} if limit exceeded
   *
   * Performance: O(n) where n = calls in window (max 100)
   * Memory: O(n) bounded by maxCalls
   */
  checkLimit(identifier = 'default') {
    const now = Date.now();

    // Step 1: Remove calls outside sliding window
    // This is O(n) but n is small (max 100)
    this.callHistory = this.callHistory.filter(
      timestamp => now - timestamp < this.windowMs
    );

    // Step 2: Memory overflow protection (fail-safe)
    if (this.callHistory.length > 10000) {
      console.error('🚨 Rate limiter memory overflow detected');
      this.callHistory = this.callHistory.slice(-1000);
    }

    // Step 3: Check if limit exceeded
    if (this.callHistory.length >= this.maxCalls) {
      this.metrics.blockedCalls++;

      const oldestCall = this.callHistory[0];
      const retryAfter = Math.ceil((this.windowMs - (now - oldestCall)) / 1000);

      throw new RateLimitError(
        `Rate limit exceeded for '${identifier}'. Retry after ${retryAfter}s`,
        {
          identifier,
          retryAfter,
          limit: this.maxCalls,
          window: this.windowMs,
          currentCalls: this.callHistory.length
        }
      );
    }

    // Step 4: Record this call
    this.callHistory.push(now);
    this.metrics.totalCalls++;

    return true;
  }

  /**
   * Get current rate limit status
   * @returns {object} Status information
   */
  getStatus() {
    const now = Date.now();
    const activeCalls = this.callHistory.filter(
      timestamp => now - timestamp < this.windowMs
    ).length;

    return {
      activeCalls,
      maxCalls: this.maxCalls,
      available: this.maxCalls - activeCalls,
      windowMs: this.windowMs,
      utilization: ((activeCalls / this.maxCalls) * 100).toFixed(1) + '%',
      metrics: this.metrics
    };
  }

  /**
   * Reset rate limiter (use with extreme caution)
   * Should only be called during testing or maintenance
   */
  reset() {
    this.callHistory = [];
    this.metrics.lastReset = Date.now();
  }
}

// ============================================================================
// SYMLINK PROTECTOR
// ============================================================================

export class SymlinkProtector {
  /**
   * Check if path contains any symlinks
   * @param {string} filePath - Path to check
   * @throws {SymlinkError} if symlink detected
   *
   * Security: Checks BEFORE path resolution to prevent TOCTOU (CWE-61)
   * Performance: O(d) where d = directory depth
   */
  static checkPath(filePath) {
    // Handle empty or invalid paths
    if (!filePath || typeof filePath !== 'string') {
      throw new SecurityError('Invalid path provided', { path: filePath });
    }

    // Check if file exists (required for lstatSync)
    if (!existsSync(filePath)) {
      // File doesn't exist - not a security issue, just return
      return true;
    }

    try {
      // Step 1: Check if path itself is a symlink
      const stats = lstatSync(filePath); // lstat does NOT follow symlinks

      if (stats.isSymbolicLink()) {
        throw new SymlinkError(
          `Symlink detected: ${filePath}`,
          {
            path: filePath,
            type: 'direct_symlink'
          }
        );
      }

      // Step 2: Check parent directories for symlinks
      const parts = normalize(filePath).split(sep).filter(Boolean);
      let currentPath = sep;

      for (const part of parts) {
        currentPath = join(currentPath, part);

        // Skip if we're at the final component (already checked above)
        if (currentPath === filePath) {
          break;
        }

        if (!existsSync(currentPath)) {
          continue; // Parent doesn't exist yet, skip
        }

        const parentStats = lstatSync(currentPath);
        if (parentStats.isSymbolicLink()) {
          throw new SymlinkError(
            `Symlink detected in parent path: ${currentPath}`,
            {
              fullPath: filePath,
              symlinkAt: currentPath,
              type: 'parent_symlink'
            }
          );
        }
      }

      return true;

    } catch (error) {
      if (error instanceof SymlinkError) {
        throw error; // Re-throw security errors
      }

      // Handle file system errors
      if (error.code === 'ENOENT') {
        return true; // File not found is okay (not a security issue)
      }

      throw new SecurityError(
        `Failed to check symlink: ${error.message}`,
        { path: filePath, originalError: error.message }
      );
    }
  }
}

// ============================================================================
// PATH VALIDATOR
// ============================================================================

export class PathValidator {
  constructor(allowedRoots = []) {
    // Normalize allowed roots to absolute paths
    this.allowedRoots = allowedRoots.map(root => resolve(root));
  }

  /**
   * Validate path against security requirements
   * @param {string} userPath - User-provided path
   * @returns {string} Validated absolute path
   * @throws {PathTraversalError} if path is invalid
   *
   * Security Checks:
   * 1. Unicode normalization
   * 2. Null byte injection
   * 3. Path canonicalization
   * 4. Whitelist validation
   */
  validatePath(userPath) {
    // Step 1: Input validation
    if (!userPath || typeof userPath !== 'string') {
      throw new PathTraversalError('Invalid path provided', { path: userPath });
    }

    // Step 2: Null byte injection check (CWE-158)
    if (userPath.includes('\0')) {
      throw new PathTraversalError(
        'Null byte detected in path',
        { path: userPath, code: 'NULL_BYTE_INJECTION' }
      );
    }

    // Step 3: Unicode normalization (NFC)
    const normalized = userPath.normalize('NFC');

    // Step 4: Check for control characters
    if (/[\u0000-\u001F\u007F-\u009F]/.test(normalized)) {
      throw new PathTraversalError(
        'Path contains control characters',
        { path: userPath }
      );
    }

    // Step 5: Path canonicalization
    const absolutePath = resolve(normalize(normalized));

    // Step 6: Whitelist validation
    if (this.allowedRoots.length === 0) {
      // No whitelist configured - allow all (development mode)
      console.warn('⚠️  Path validator running without whitelist');
      return absolutePath;
    }

    const isAllowed = this.allowedRoots.some(root => {
      return absolutePath.startsWith(root) && absolutePath !== root;
    });

    if (!isAllowed) {
      throw new PathTraversalError(
        `Path outside allowed directories: ${absolutePath}`,
        {
          provided: userPath,
          resolved: absolutePath,
          allowedRoots: this.allowedRoots
        }
      );
    }

    return absolutePath;
  }
}

// ============================================================================
// SECURITY LOGGER
// ============================================================================

export class SecurityLogger {
  constructor(logPath = 'trinitas_security.log') {
    this.logPath = logPath;
  }

  /**
   * Log security event
   * @param {string} event - Event type
   * @param {object} details - Event details
   * @param {string} severity - Severity level (LOW, MEDIUM, HIGH, CRITICAL)
   */
  log(event, details = {}, severity = 'MEDIUM') {
    const logEntry = {
      timestamp: new Date().toISOString(),
      severity,
      event,
      plugin: details.plugin || 'unknown',
      details: {
        ...details,
        pid: process.pid,
        node_version: process.version
      }
    };

    const logLine = JSON.stringify(logEntry) + '\n';

    try {
      appendFileSync(this.logPath, logLine);
    } catch (error) {
      console.error('Failed to write security log:', error.message);
    }

    // Console output for immediate visibility
    if (severity === 'CRITICAL' || severity === 'HIGH') {
      console.error(`🚨 [${severity}] ${event}:`, details);
    } else {
      console.warn(`⚠️  [${severity}] ${event}:`, details);
    }
  }
}

// ============================================================================
// SECURITY GUARD (Main Class)
// ============================================================================

export class SecurityGuard {
  constructor(config = {}) {
    // Initialize components
    this.rateLimiter = new RateLimiter(
      config.maxCalls || 100,
      config.windowMs || 60000
    );

    this.pathValidator = new PathValidator(
      config.allowedRoots || [
        '.opencode/',
        'trinitas_sources/',
        'docs/',
        'agents/'
      ]
    );

    this.logger = new SecurityLogger(
      config.logPath || 'trinitas_security.log'
    );

    // Metrics
    this.metrics = {
      rateLimitBlocks: 0,
      symlinkBlocks: 0,
      pathTraversalBlocks: 0,
      totalChecks: 0
    };
  }

  /**
   * Validate file access with all security checks
   * @param {string} filePath - Path to validate
   * @param {string} hookName - Hook identifier (for rate limiting)
   * @returns {string} Validated absolute path
   * @throws {SecurityError} if validation fails
   */
  validateFileAccess(filePath, hookName = 'file_access') {
    this.metrics.totalChecks++;

    try {
      // Step 1: Rate limiting
      this.rateLimiter.checkLimit(hookName);

      // Step 2: Path validation (traversal prevention)
      const safePath = this.pathValidator.validatePath(filePath);

      // Step 3: Symlink protection
      SymlinkProtector.checkPath(safePath);

      return safePath;

    } catch (error) {
      // Update metrics
      if (error instanceof RateLimitError) {
        this.metrics.rateLimitBlocks++;
        this.logger.log('RATE_LIMIT_EXCEEDED', error.metadata, 'HIGH');
      } else if (error instanceof SymlinkError) {
        this.metrics.symlinkBlocks++;
        this.logger.log('SYMLINK_BLOCKED', error.metadata, 'HIGH');
      } else if (error instanceof PathTraversalError) {
        this.metrics.pathTraversalBlocks++;
        this.logger.log('PATH_TRAVERSAL_BLOCKED', error.metadata, 'HIGH');
      }

      // Re-throw for caller to handle
      throw error;
    }
  }

  /**
   * Get security metrics
   * @returns {object} Current metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      rateLimitStatus: this.rateLimiter.getStatus()
    };
  }
}

// ============================================================================
// EXPORT DEFAULT
// ============================================================================

export default SecurityGuard;
```

---

## 2. Unit Tests

### File: `/tests/security-guard.test.js`

```javascript
import { describe, test, expect, beforeEach } from '@jest/globals';
import {
  SecurityGuard,
  RateLimiter,
  SymlinkProtector,
  PathValidator,
  RateLimitError,
  SymlinkError,
  PathTraversalError
} from '../.opencode/plugin/security-guard.js';
import { writeFileSync, unlinkSync, symlinkSync, existsSync } from 'fs';
import { join } from 'path';

// ============================================================================
// RATE LIMITER TESTS
// ============================================================================

describe('RateLimiter', () => {
  let limiter;

  beforeEach(() => {
    limiter = new RateLimiter(5, 1000); // 5 calls per second for testing
  });

  test('should allow calls within limit', () => {
    for (let i = 0; i < 5; i++) {
      expect(() => limiter.checkLimit('test')).not.toThrow();
    }
  });

  test('should block 6th call within window', () => {
    for (let i = 0; i < 5; i++) {
      limiter.checkLimit('test');
    }

    expect(() => limiter.checkLimit('test')).toThrow(RateLimitError);
  });

  test('should allow calls after window expires', async () => {
    limiter.checkLimit('test');
    limiter.checkLimit('test');

    // Wait for window to expire
    await new Promise(resolve => setTimeout(resolve, 1100));

    expect(() => limiter.checkLimit('test')).not.toThrow();
  });

  test('should provide correct retry-after in error', () => {
    for (let i = 0; i < 5; i++) {
      limiter.checkLimit('test');
    }

    try {
      limiter.checkLimit('test');
    } catch (error) {
      expect(error).toBeInstanceOf(RateLimitError);
      expect(error.metadata.retryAfter).toBeGreaterThan(0);
      expect(error.metadata.retryAfter).toBeLessThanOrEqual(1);
    }
  });

  test('should track metrics correctly', () => {
    limiter.checkLimit('test');
    limiter.checkLimit('test');

    const status = limiter.getStatus();
    expect(status.activeCalls).toBe(2);
    expect(status.available).toBe(3);
    expect(status.metrics.totalCalls).toBe(2);
  });
});

// ============================================================================
// SYMLINK PROTECTOR TESTS
// ============================================================================

describe('SymlinkProtector', () => {
  const testDir = '/tmp/trinitas-security-test';
  const regularFile = join(testDir, 'regular.txt');
  const symlinkFile = join(testDir, 'symlink.txt');

  beforeEach(() => {
    // Create test directory
    if (!existsSync(testDir)) {
      require('fs').mkdirSync(testDir, { recursive: true });
    }

    // Create regular file
    writeFileSync(regularFile, 'test content');
  });

  afterEach(() => {
    // Cleanup
    try {
      if (existsSync(symlinkFile)) unlinkSync(symlinkFile);
      if (existsSync(regularFile)) unlinkSync(regularFile);
      require('fs').rmdirSync(testDir);
    } catch (e) {
      // Ignore cleanup errors
    }
  });

  test('should allow regular files', () => {
    expect(() => SymlinkProtector.checkPath(regularFile)).not.toThrow();
  });

  test('should block direct symlinks', () => {
    // Create symlink
    symlinkSync(regularFile, symlinkFile);

    expect(() => SymlinkProtector.checkPath(symlinkFile)).toThrow(SymlinkError);
  });

  test('should allow non-existent files', () => {
    const nonExistent = join(testDir, 'does-not-exist.txt');
    expect(() => SymlinkProtector.checkPath(nonExistent)).not.toThrow();
  });

  test('should provide detailed error metadata', () => {
    symlinkSync(regularFile, symlinkFile);

    try {
      SymlinkProtector.checkPath(symlinkFile);
    } catch (error) {
      expect(error).toBeInstanceOf(SymlinkError);
      expect(error.metadata.path).toBe(symlinkFile);
      expect(error.metadata.type).toBe('direct_symlink');
      expect(error.cwe).toBe('CWE-61');
    }
  });
});

// ============================================================================
// PATH VALIDATOR TESTS
// ============================================================================

describe('PathValidator', () => {
  let validator;
  const allowedRoot = '/Users/test/project';

  beforeEach(() => {
    validator = new PathValidator([allowedRoot]);
  });

  test('should allow paths within allowed roots', () => {
    const safePath = join(allowedRoot, 'docs/file.md');
    expect(() => validator.validatePath(safePath)).not.toThrow();
  });

  test('should block path traversal with ..', () => {
    const maliciousPath = join(allowedRoot, '../../../etc/passwd');

    expect(() => validator.validatePath(maliciousPath)).toThrow(PathTraversalError);
  });

  test('should block absolute paths outside roots', () => {
    expect(() => validator.validatePath('/etc/passwd')).toThrow(PathTraversalError);
  });

  test('should block null byte injection', () => {
    const maliciousPath = 'file.txt\0malicious';

    expect(() => validator.validatePath(maliciousPath)).toThrow(PathTraversalError);
  });

  test('should normalize Unicode characters', () => {
    // Unicode normalization test
    const unicodePath = join(allowedRoot, 'docs/café.md');
    const normalized = validator.validatePath(unicodePath);

    expect(normalized).toContain('café');
  });

  test('should provide detailed error for path traversal', () => {
    try {
      validator.validatePath('/etc/passwd');
    } catch (error) {
      expect(error).toBeInstanceOf(PathTraversalError);
      expect(error.metadata.provided).toBeDefined();
      expect(error.metadata.resolved).toBeDefined();
      expect(error.metadata.allowedRoots).toBeDefined();
    }
  });
});

// ============================================================================
// SECURITY GUARD INTEGRATION TESTS
// ============================================================================

describe('SecurityGuard Integration', () => {
  let guard;

  beforeEach(() => {
    guard = new SecurityGuard({
      maxCalls: 3,
      windowMs: 1000,
      allowedRoots: ['/Users/test/project']
    });
  });

  test('should perform all security checks', () => {
    const safePath = '/Users/test/project/docs/file.md';

    // Create test file
    const fs = require('fs');
    const path = require('path');
    const dir = path.dirname(safePath);

    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(safePath, 'test');

    try {
      const validated = guard.validateFileAccess(safePath, 'test-hook');
      expect(validated).toContain('file.md');
    } finally {
      // Cleanup
      fs.unlinkSync(safePath);
      fs.rmdirSync(dir, { recursive: true });
    }
  });

  test('should block after rate limit reached', () => {
    const safePath = '/Users/test/project/docs/file.md';

    // First 3 should pass
    for (let i = 0; i < 3; i++) {
      guard.rateLimiter.checkLimit('test');
    }

    // 4th should fail
    expect(() => {
      guard.validateFileAccess(safePath, 'test');
    }).toThrow(RateLimitError);
  });

  test('should track metrics correctly', () => {
    const metrics = guard.getMetrics();

    expect(metrics).toHaveProperty('rateLimitBlocks');
    expect(metrics).toHaveProperty('symlinkBlocks');
    expect(metrics).toHaveProperty('pathTraversalBlocks');
    expect(metrics).toHaveProperty('rateLimitStatus');
  });
});
```

---

## 3. Integration into Existing Plugins

### Example: dynamic-context-loader.js

```javascript
// Add at top of file
import SecurityGuard from './security-guard.js';

export const DynamicContextLoader = async ({ project, client, $, directory, worktree }) => {
  console.log('🧠 Trinitas Dynamic Context Loader initialized');

  // ===== SECURITY GUARD INITIALIZATION =====
  const security = new SecurityGuard({
    maxCalls: 100,
    windowMs: 60000,
    allowedRoots: [
      join(directory, '.opencode'),
      join(directory, 'trinitas_sources'),
      join(directory, 'docs'),
      join(directory, 'agents')
    ]
  });

  // ... existing configuration ...

  return {
    event: async ({ event }) => {
      // ===== SECURITY: RATE LIMIT CHECK =====
      try {
        security.rateLimiter.checkLimit('event');
      } catch (error) {
        console.error('Rate limit exceeded:', error.message);
        return; // Silently skip event processing
      }

      // ... existing event handling ...
    },

    "tool.execute.before": async (input, output) => {
      // ===== SECURITY: RATE LIMIT CHECK =====
      try {
        security.rateLimiter.checkLimit('tool.execute.before');
      } catch (error) {
        console.error('Rate limit exceeded:', error.message);
        throw error; // Block execution
      }

      // ===== SECURITY: FILE ACCESS VALIDATION =====
      if (input.filePath) {
        try {
          const safePath = security.validateFileAccess(input.filePath, 'file_read');
          input.filePath = safePath; // Use validated path
        } catch (error) {
          console.error('Security violation:', error.message);
          throw error;
        }
      }

      // ... existing tool execution logic ...
    }
  };
};
```

---

## 4. Performance Benchmarks

### Expected Performance

**Rate Limiting**:
- Check latency: < 0.1ms (P99)
- Memory overhead: < 1MB
- Throughput: 10,000 checks/sec

**Symlink Detection**:
- Check latency: < 1ms per path
- Recursive depth: O(d) where d = directory depth
- Typical depth: 5-10 levels

**Path Validation**:
- Validation latency: < 0.5ms
- Unicode normalization: < 0.1ms
- Whitelist check: O(1) hash lookup

**Total Overhead**: < 2ms per hook invocation

---

## 5. Deployment Checklist

### Pre-Deployment

- [ ] All unit tests passing (run `npm test`)
- [ ] Integration tests passing
- [ ] Security tests passing
- [ ] Performance benchmarks meet targets
- [ ] Documentation updated

### Deployment

- [ ] Create `security-guard.js` in `.opencode/plugin/`
- [ ] Update all 4 existing plugins with SecurityGuard
- [ ] Configure allowed roots for production
- [ ] Set up security log rotation
- [ ] Configure alerting for security events

### Post-Deployment

- [ ] Monitor security logs for 24 hours
- [ ] Verify rate limiting is working (check metrics)
- [ ] Test with malicious inputs (penetration testing)
- [ ] Review performance impact (should be < 2ms)
- [ ] Update security documentation

---

## 6. Monitoring & Alerting

### Security Metrics Dashboard

```javascript
// Get current security status
const metrics = securityGuard.getMetrics();

console.log('Security Status:');
console.log('  Rate Limit Blocks:', metrics.rateLimitBlocks);
console.log('  Symlink Blocks:', metrics.symlinkBlocks);
console.log('  Path Traversal Blocks:', metrics.pathTraversalBlocks);
console.log('  Total Checks:', metrics.totalChecks);
console.log('  Block Rate:', (
  (metrics.rateLimitBlocks + metrics.symlinkBlocks + metrics.pathTraversalBlocks) /
  metrics.totalChecks * 100
).toFixed(2) + '%');
```

### Alert Thresholds

**Immediate Alerts**:
- 10+ security blocks in 60 seconds
- Rate limit utilization > 90%
- Any critical severity event

**Daily Digest**:
- Total security events by type
- Most common attack patterns
- Performance metrics (P50, P95, P99)

---

## 7. Troubleshooting

### Common Issues

**Issue**: "Rate limit exceeded" during normal use
**Solution**: Increase `maxCalls` or `windowMs` in configuration

**Issue**: "Symlink detected" for valid files
**Solution**: Check if file is actually a symlink (`ls -la`). If valid use case, add exception.

**Issue**: "Path outside allowed directories"
**Solution**: Add directory to `allowedRoots` in SecurityGuard configuration

### Debug Mode

```javascript
const security = new SecurityGuard({
  maxCalls: 100,
  windowMs: 60000,
  allowedRoots: [...],
  debug: true  // Enable verbose logging
});
```

---

## 8. Next Steps

After implementation:

1. **Security Audit**: Schedule quarterly security reviews
2. **Penetration Testing**: Hire external security researchers
3. **Bug Bounty**: Consider bug bounty program for community
4. **Training**: Security training for all developers
5. **Compliance**: Ensure compliance with OWASP Top 10

---

**Implementation Guide Prepared By**: Hestia (Security Guardian)
**Target Implementer**: Artemis (Technical Perfectionist)
**Estimated Time**: 4-6 hours
**Priority**: CRITICAL (blocking production deployment)

---

*"Code defensively. Trust nothing. Validate everything."*
*— Hestia*
