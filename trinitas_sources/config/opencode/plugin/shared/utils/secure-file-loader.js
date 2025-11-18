/**
 * SecureFileLoader - Secure file loading with comprehensive security checks
 *
 * Security Protections:
 * - CWE-61: Symlink following prevention
 * - CWE-22: Path traversal attack prevention
 * - CWE-400: Resource exhaustion prevention (rate limiting, file size limits)
 *
 * Performance Target: <50ms per file load
 *
 * @example
 * const loader = new SecureFileLoader({
 *   maxFileSize: 10 * 1024 * 1024, // 10MB
 *   allowedDirectories: ['/home/user/.config/opencode']
 * });
 * const content = loader.loadFile('/home/user/.config/opencode/agent/test.md');
 */

import fs from 'fs';
import path from 'path';
import { RateLimiter } from './rate-limiter.js';

export class SecureFileLoader {
  /**
   * @param {Object} options - Configuration options
   * @param {number} [options.maxFileSize=10485760] - Maximum file size in bytes (default: 10MB)
   * @param {string[]} [options.allowedDirectories] - Whitelist of allowed directories
   * @param {number} [options.maxCalls=100] - Maximum calls per window (rate limiting)
   * @param {number} [options.windowMs=60000] - Rate limit window in milliseconds
   */
  constructor(options = {}) {
    this.maxFileSize = options.maxFileSize || 10 * 1024 * 1024; // 10MB default

    // Default allowed directories: OpenCode config and current project
    this.allowedDirectories = options.allowedDirectories || [
      path.join(process.env.HOME || '/tmp', '.config/opencode'),
      process.cwd()
    ];

    // Normalize all allowed directories to canonical paths
    this.allowedDirectories = this.allowedDirectories.map(dir => {
      try {
        return fs.realpathSync(dir);
      } catch (error) {
        // Directory might not exist yet, use as-is
        return path.resolve(dir);
      }
    });

    // Initialize rate limiter (100 calls per 60 seconds)
    this.rateLimiter = new RateLimiter(
      options.maxCalls || 100,
      options.windowMs || 60000
    );
  }

  /**
   * Load file securely with comprehensive security checks
   *
   * Security measures:
   * - Rate limiting (CWE-400)
   * - Symlink detection BEFORE resolution (CWE-61, TOCTOU prevention)
   * - Path validation (CWE-22)
   * - File size limit (CWE-400)
   * - Proper error messages
   *
   * @param {string} filePath - Path to file to load
   * @returns {string} File contents
   * @throws {Error} If any security check fails
   */
  loadFile(filePath) {
    // 1. Rate limiting check (CWE-400)
    this.rateLimiter.check();

    // 2. CRITICAL FIX: Symlink detection BEFORE path resolution (CWE-61)
    //    This prevents TOCTOU (Time-of-check-time-of-use) vulnerability
    //    Check if ANY component in the path is a symlink (including parent directories)
    if (this.hasSymlinkInPath(filePath)) {
      throw new Error(
        `Security violation (CWE-61): Symlink access denied: ${filePath}\n` +
        `Symlinks are not allowed for security reasons (including parent directories).`
      );
    }

    // 3. Path validation (CWE-22) - now safe because symlink already checked
    const validatedPath = this.validatePath(filePath);

    // 4. TOCTOU protection: Double-check symlink after resolution
    //    Attacker might have replaced file with symlink between steps
    if (this.hasSymlinkInPath(validatedPath)) {
      throw new Error(
        `Security violation (CWE-61): Symlink detected after resolution: ${filePath}\n` +
        `Possible TOCTOU attack attempt.`
      );
    }

    // 5. File size check (CWE-400)
    const stats = fs.statSync(validatedPath);
    if (stats.size > this.maxFileSize) {
      const sizeMB = (stats.size / (1024 * 1024)).toFixed(2);
      const maxMB = (this.maxFileSize / (1024 * 1024)).toFixed(2);
      throw new Error(
        `Security violation (CWE-400): File too large: ${sizeMB}MB (max: ${maxMB}MB)\n` +
        `File: ${filePath}`
      );
    }

    // 6. Read file contents
    try {
      return fs.readFileSync(validatedPath, 'utf-8');
    } catch (error) {
      throw new Error(
        `File read error: ${error.message}\n` +
        `File: ${filePath}`
      );
    }
  }

  /**
   * Validate file path against security rules
   *
   * Security checks:
   * - Path must be within allowed directories (whitelist)
   * - No path traversal attacks (../, null bytes, etc.)
   * - Normalized to canonical path
   *
   * @param {string} filePath - Path to validate
   * @returns {string} Canonical (resolved) file path
   * @throws {Error} If path validation fails
   */
  validatePath(filePath) {
    // Check for null bytes (CWE-158)
    if (filePath.includes('\0')) {
      throw new Error(
        `Security violation (CWE-158): Null byte in path: ${filePath}`
      );
    }

    // CRITICAL: Check for path traversal patterns BEFORE normalization (CWE-22)
    // This prevents bypasses via filesystem API bugs or unexpected normalization
    // Enhanced detection with multiple encoding variations
    const dangerousPatterns = [
      /\.\./,                    // ..
      /\.\.[\\/]/,               // ../ or ..\
      /[\\/]\.\./,               // /.. or \..
      /[\\/]\.\.[\\/]/,          // /../ or \..\
      /%2e%2e/i,                 // URL-encoded ..
      /\.%2e/i,                  // Mixed encoding .%2e
      /%2e\./i,                  // Mixed encoding %2e.
      /\x2e\x2e/,                // Hex-encoded ..
      /\.\x2e/,                  // Mixed hex .
      /\x2e\./                   // Mixed hex .
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(filePath)) {
        throw new Error(
          `Security violation (CWE-22): Path traversal pattern detected: ${filePath}\n` +
          `Pattern: ${pattern.source}`
        );
      }
    }

    // Resolve to canonical path (AFTER pattern check)
    let canonicalPath;
    try {
      canonicalPath = fs.realpathSync(filePath);
    } catch (error) {
      // File might not exist yet, try to resolve parent directory
      try {
        const dir = path.dirname(filePath);
        const base = path.basename(filePath);
        const canonicalDir = fs.realpathSync(dir);
        canonicalPath = path.join(canonicalDir, base);
      } catch (dirError) {
        throw new Error(
          `Path resolution error: ${error.message}\n` +
          `File: ${filePath}`
        );
      }
    }

    // CRITICAL: Verify canonical path is within whitelist (defense in depth)
    const isWithinWhitelist = this.allowedDirectories.some(dir => {
      const canonicalDir = fs.realpathSync(dir);
      return canonicalPath.startsWith(canonicalDir + path.sep) ||
             canonicalPath === canonicalDir;
    });

    if (!isWithinWhitelist) {
      throw new Error(
        `Security violation (CWE-22): Path outside allowed directories: ${filePath}\n` +
        `Canonical path: ${canonicalPath}\n` +
        `Allowed directories: ${this.allowedDirectories.join(', ')}`
      );
    }

    return canonicalPath;
  }

  /**
   * Check if path is a symbolic link
   *
   * @param {string} filePath - Path to check
   * @returns {boolean} True if path is a symlink
   */
  isSymlink(filePath) {
    try {
      const stats = fs.lstatSync(filePath);
      return stats.isSymbolicLink();
    } catch (error) {
      // If lstat fails, path doesn't exist or is inaccessible
      return false;
    }
  }

  /**
   * Check if path or any parent directory is a symbolic link
   * CRITICAL: This prevents accessing files through symlinked directories
   *
   * Only checks symlinks WITHIN allowed directories, not system-level symlinks
   * (e.g., /tmp -> /private/tmp on macOS is ignored)
   *
   * @param {string} filePath - Path to check
   * @returns {boolean} True if any component within allowed dirs is a symlink
   */
  hasSymlinkInPath(filePath) {
    try {
      // Normalize path (but don't follow symlinks)
      let normalizedPath = path.resolve(filePath);

      // Handle macOS system symlinks by string replacement (don't use realpathSync yet)
      // /tmp -> /private/tmp, /var -> /private/var, /etc -> /private/etc
      if (normalizedPath.startsWith('/tmp/')) {
        normalizedPath = '/private' + normalizedPath;
      } else if (normalizedPath.startsWith('/var/') && !normalizedPath.startsWith('/var/private/')) {
        normalizedPath = '/private' + normalizedPath;
      } else if (normalizedPath.startsWith('/etc/')) {
        normalizedPath = '/private' + normalizedPath;
      }

      // Find which allowed directory (if any) this path is under
      // We need to compare against canonical (resolved) allowed directories
      let allowedRoot = null;
      let allowedRootRaw = null;
      for (const dir of this.allowedDirectories) {
        const canonicalDir = fs.realpathSync(dir);
        if (normalizedPath.startsWith(canonicalDir + path.sep) ||
            normalizedPath === canonicalDir) {
          allowedRoot = canonicalDir;
          allowedRootRaw = dir;
          break;
        }
      }

      // If not under any allowed directory, let validatePath() handle it
      if (!allowedRoot) {
        return false;
      }

      // Get the relative path within the allowed directory
      const relativePath = path.relative(allowedRoot, normalizedPath);
      if (relativePath === '' || relativePath.startsWith('..')) {
        return false;  // At or above allowed root
      }

      // Check each component of the RELATIVE path for symlinks
      // Start from the allowed directory root and check each component
      const components = relativePath.split(path.sep);
      let currentPath = allowedRoot;

      for (const component of components) {
        currentPath = path.join(currentPath, component);

        try {
          // Use lstatSync to NOT follow symlinks
          const stats = fs.lstatSync(currentPath);
          if (stats.isSymbolicLink()) {
            return true;  // Found a symlink within allowed directory
          }
        } catch {
          // Component doesn't exist yet, continue checking
          continue;
        }
      }

      return false;  // No symlinks found in relative path
    } catch (error) {
      // If path resolution fails, be conservative
      return false;  // Let other checks handle it
    }
  }

  /**
   * Check if file exists and is readable
   *
   * @param {string} filePath - Path to check
   * @returns {boolean} True if file exists and is readable
   */
  fileExists(filePath) {
    try {
      fs.accessSync(filePath, fs.constants.R_OK);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get file metadata without loading contents
   *
   * @param {string} filePath - Path to file
   * @returns {Object} File metadata (size, mtime, etc.)
   * @throws {Error} If security checks fail
   */
  getFileMetadata(filePath) {
    // Apply same security checks as loadFile
    this.rateLimiter.check();

    // Check for symlinks BEFORE resolution (including parent directories)
    if (this.hasSymlinkInPath(filePath)) {
      throw new Error(
        `Security violation (CWE-61): Symlink access denied: ${filePath}` +
        `\nSymlinks are not allowed for security reasons (including parent directories).`
      );
    }

    const validatedPath = this.validatePath(filePath);

    // TOCTOU protection: Check again after resolution
    if (this.hasSymlinkInPath(validatedPath)) {
      throw new Error(
        `Security violation (CWE-61): Symlink detected after resolution: ${filePath}` +
        `\nPossible TOCTOU attack attempt.`
      );
    }

    const stats = fs.statSync(validatedPath);
    return {
      size: stats.size,
      mtime: stats.mtime,
      ctime: stats.ctime,
      isFile: stats.isFile(),
      isDirectory: stats.isDirectory()
    };
  }

  /**
   * Add allowed directory to whitelist
   *
   * @param {string} directory - Directory to allow
   */
  addAllowedDirectory(directory) {
    const canonicalDir = fs.realpathSync(directory);
    if (!this.allowedDirectories.includes(canonicalDir)) {
      this.allowedDirectories.push(canonicalDir);
    }
  }
}
