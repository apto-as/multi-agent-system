/**
 * Skill Helpers Plugin - Secure script execution for OpenCode agents
 *
 * Security: CWE-78 (Command Injection) prevention through Bun shell API
 * Performance: <100ms overhead (excluding script execution time)
 *
 * Features:
 * - Execute Python scripts with arguments
 * - Execute Bash scripts with arguments
 * - Timeout enforcement (30s default)
 * - Output sanitization (ANSI codes removal, size limits)
 * - Comprehensive error handling
 *
 * @example
 * // In OpenCode plugin
 * import skillHelpers from './skill-helpers.js';
 *
 * const result = await skillHelpers.executePythonScript('analyze.py', ['--input', 'data.json']);
 * console.log(result.stdout);
 */

import { $ } from 'bun';
import path from 'path';
import { SecureFileLoader } from './shared/utils/secure-file-loader.js';

/**
 * Strip ANSI escape codes from text
 * @param {string} text - Text with ANSI codes
 * @returns {string} Clean text
 */
function stripAnsi(text) {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '');
}

/**
 * Limit output size to prevent memory exhaustion
 * @param {string} text - Output text
 * @param {number} maxBytes - Maximum bytes (default: 1MB)
 * @returns {string} Truncated text if needed
 */
function limitOutputSize(text, maxBytes = 1024 * 1024) {
  if (Buffer.byteLength(text, 'utf-8') <= maxBytes) {
    return text;
  }

  const truncated = text.substring(0, maxBytes);
  const sizeMB = (Buffer.byteLength(text, 'utf-8') / (1024 * 1024)).toFixed(2);
  return truncated + `\n\n[Output truncated: original size ${sizeMB}MB]`;
}

/**
 * Sanitize script output for safe display
 * @param {string} output - Raw script output
 * @returns {string} Sanitized output
 */
function sanitizeOutput(output) {
  let clean = stripAnsi(output);
  clean = limitOutputSize(clean);
  return clean;
}

export default {
  name: 'skill-helpers',
  version: '1.0.0',
  description: 'Secure script execution helpers for OpenCode agents',

  /**
   * Execute Python script with security checks
   *
   * Security measures:
   * - Script path validation (must be in allowed directory)
   * - No string concatenation (prevents CWE-78)
   * - Timeout enforcement (prevents DoS)
   * - Output sanitization (prevents log injection)
   *
   * @param {string} scriptName - Name of Python script (e.g., 'analyze.py')
   * @param {string[]} args - Script arguments (each element is a separate argument)
   * @param {Object} options - Execution options
   * @param {number} [options.timeout=30000] - Timeout in milliseconds
   * @param {string} [options.cwd] - Working directory
   * @returns {Promise<{stdout: string, stderr: string, exitCode: number}>}
   * @throws {Error} If script path is invalid or execution fails
   */
  async executePythonScript(scriptName, args = [], options = {}) {
    const timeout = options.timeout || 30000; // 30 seconds default
    const scriptsDir = path.join(
      process.env.HOME || '/tmp',
      '.config/opencode/agent/scripts'
    );
    const scriptPath = path.join(scriptsDir, scriptName);

    // Validate script path using SecureFileLoader
    const loader = new SecureFileLoader({
      allowedDirectories: [scriptsDir]
    });

    try {
      // Check if script exists and is within allowed directory
      await loader.validatePath(scriptPath);

      if (!loader.fileExists(scriptPath)) {
        throw new Error(`Script not found: ${scriptName}\nExpected location: ${scriptPath}`);
      }
    } catch (error) {
      throw new Error(
        `Script validation failed: ${error.message}\n` +
        `Script: ${scriptName}\n` +
        `Allowed directory: ${scriptsDir}`
      );
    }

    // Execute script using Bun shell API (prevents CWE-78)
    // CRITICAL: Use tagged template literal with array spread for safety
    try {
      const cmd = $`python3 ${scriptPath} ${args}`.quiet().nothrow();

      if (options.cwd) {
        cmd.cwd(options.cwd);
      }

      // Implement timeout using Promise.race (Bun doesn't support .timeout())
      const result = await Promise.race([
        cmd,
        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error('TimeoutError')),
            timeout
          )
        )
      ]);

      return {
        stdout: sanitizeOutput(result.stdout.toString()),
        stderr: sanitizeOutput(result.stderr.toString()),
        exitCode: result.exitCode
      };
    } catch (error) {
      if (error.message === 'TimeoutError') {
        throw new Error(
          `Script execution timeout (${timeout}ms)\n` +
          `Script: ${scriptName}\n` +
          `Consider increasing timeout or optimizing script.`
        );
      }

      throw new Error(
        `Script execution failed: ${error.message}\n` +
        `Script: ${scriptName}`
      );
    }
  },

  /**
   * Execute Bash script with security checks
   *
   * Same security measures as executePythonScript
   *
   * @param {string} scriptName - Name of Bash script (e.g., 'deploy.sh')
   * @param {string[]} args - Script arguments
   * @param {Object} options - Execution options
   * @param {number} [options.timeout=30000] - Timeout in milliseconds
   * @param {string} [options.cwd] - Working directory
   * @returns {Promise<{stdout: string, stderr: string, exitCode: number}>}
   * @throws {Error} If script path is invalid or execution fails
   */
  async executeBashScript(scriptName, args = [], options = {}) {
    const timeout = options.timeout || 30000;
    const scriptsDir = path.join(
      process.env.HOME || '/tmp',
      '.config/opencode/agent/scripts'
    );
    const scriptPath = path.join(scriptsDir, scriptName);

    // Validate script path
    const loader = new SecureFileLoader({
      allowedDirectories: [scriptsDir]
    });

    try {
      await loader.validatePath(scriptPath);

      if (!loader.fileExists(scriptPath)) {
        throw new Error(`Script not found: ${scriptName}\nExpected location: ${scriptPath}`);
      }
    } catch (error) {
      throw new Error(
        `Script validation failed: ${error.message}\n` +
        `Script: ${scriptName}\n` +
        `Allowed directory: ${scriptsDir}`
      );
    }

    // Execute script (CWE-78 prevention via Bun shell API)
    try {
      const cmd = $`bash ${scriptPath} ${args}`.quiet().nothrow();

      if (options.cwd) {
        cmd.cwd(options.cwd);
      }

      // Implement timeout using Promise.race
      const result = await Promise.race([
        cmd,
        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error('TimeoutError')),
            timeout
          )
        )
      ]);

      return {
        stdout: sanitizeOutput(result.stdout.toString()),
        stderr: sanitizeOutput(result.stderr.toString()),
        exitCode: result.exitCode
      };
    } catch (error) {
      if (error.message === 'TimeoutError') {
        throw new Error(
          `Script execution timeout (${timeout}ms)\n` +
          `Script: ${scriptName}`
        );
      }

      throw new Error(
        `Script execution failed: ${error.message}\n` +
        `Script: ${scriptName}`
      );
    }
  },

  /**
   * Execute arbitrary command with strict security (use sparingly)
   *
   * WARNING: Only use this for trusted commands. Never pass user input directly.
   *
   * @param {string[]} command - Command and arguments as array
   * @param {Object} options - Execution options
   * @param {number} [options.timeout=30000] - Timeout in milliseconds
   * @param {string} [options.cwd] - Working directory
   * @returns {Promise<{stdout: string, stderr: string, exitCode: number}>}
   * @throws {Error} If execution fails
   */
  async executeCommand(command, options = {}) {
    if (!Array.isArray(command) || command.length === 0) {
      throw new Error('Command must be a non-empty array');
    }

    const timeout = options.timeout || 30000;

    try {
      const cmd = $`${command}`.quiet().nothrow();

      if (options.cwd) {
        cmd.cwd(options.cwd);
      }

      // Implement timeout using Promise.race (Bun doesn't support .timeout())
      const result = await Promise.race([
        cmd,
        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error('TimeoutError')),
            timeout
          )
        )
      ]);

      return {
        stdout: sanitizeOutput(result.stdout.toString()),
        stderr: sanitizeOutput(result.stderr.toString()),
        exitCode: result.exitCode
      };
    } catch (error) {
      if (error.message === 'TimeoutError') {
        throw new Error(`Command execution timeout (${timeout}ms)`);
      }

      throw new Error(`Command execution failed: ${error.message}`);
    }
  },

  /**
   * Check if script exists in scripts directory
   *
   * @param {string} scriptName - Name of script to check
   * @returns {Promise<boolean>} True if script exists
   */
  async scriptExists(scriptName) {
    const scriptsDir = path.join(
      process.env.HOME || '/tmp',
      '.config/opencode/agent/scripts'
    );
    const scriptPath = path.join(scriptsDir, scriptName);

    const loader = new SecureFileLoader({
      allowedDirectories: [scriptsDir]
    });

    try {
      await loader.validatePath(scriptPath);
      return loader.fileExists(scriptPath);
    } catch {
      return false;
    }
  }
};
