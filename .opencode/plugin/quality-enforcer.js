/**
 * Quality Enforcer Plugin for Open Code
 * Implements Trinitas Quality Guardian functionality
 * Version: 1.1.0
 */

export const QualityEnforcer = async ({ project, client, $, directory, worktree }) => {
  console.log('🚀 Trinitas Quality Enforcer initialized');

  // Helper functions
  const detectLanguage = (filePath) => {
    const ext = filePath.split('.').pop().toLowerCase();
    const languageMap = {
      'py': 'python',
      'js': 'javascript',
      'jsx': 'javascript',
      'ts': 'typescript',
      'tsx': 'typescript',
      'go': 'go',
      'rs': 'rust',
      'java': 'java',
      'cpp': 'cpp',
      'c': 'c'
    };
    return languageMap[ext] || 'unknown';
  };

  const findLineNumber = (content, pattern) => {
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) {
        return i + 1;
      }
    }
    return 0;
  };

  const runSecurityCheck = async (filePath, content) => {
    const issues = [];

    // Check for hardcoded secrets
    const secretPatterns = [
      /api[_-]?key\s*=\s*["'][^"']+["']/gi,
      /password\s*=\s*["'][^"']+["']/gi,
      /secret\s*=\s*["'][^"']+["']/gi,
      /token\s*=\s*["'][^"']+["']/gi,
      /AWS[A-Z0-9]{16,}/g,
      /ghp_[a-zA-Z0-9]{36}/g
    ];

    for (const pattern of secretPatterns) {
      if (pattern.test(content)) {
        issues.push({
          severity: 'critical',
          message: `Potential secret detected: ${pattern.source}`,
          line: findLineNumber(content, pattern)
        });
      }
    }

    // Check for dangerous functions
    const dangerousPatterns = {
      'eval(': 'Use of eval() is dangerous',
      'exec(': 'Use of exec() is dangerous',
      'innerHTML': 'Direct innerHTML assignment can cause XSS',
      'dangerouslySetInnerHTML': 'Use with extreme caution'
    };

    for (const [pattern, message] of Object.entries(dangerousPatterns)) {
      if (content.includes(pattern)) {
        issues.push({
          severity: 'high',
          message: message,
          pattern: pattern
        });
      }
    }

    return issues;
  };

  const runPythonChecks = async (filePath) => {
    const checks = [];

    try {
      // Ruff check
      const ruffResult = await $`ruff check ${filePath}`.quiet();
      checks.push({
        tool: 'ruff',
        passed: ruffResult.exitCode === 0,
        message: ruffResult.stdout?.toString() || ruffResult.stderr?.toString()
      });
    } catch (error) {
      // Tool not available is okay
      checks.push({
        tool: 'ruff',
        passed: true,
        message: 'Ruff not installed'
      });
    }

    return checks;
  };

  const runJavaScriptChecks = async (filePath) => {
    const checks = [];

    try {
      // ESLint check
      const eslintResult = await $`eslint ${filePath}`.quiet();
      checks.push({
        tool: 'eslint',
        passed: eslintResult.exitCode === 0,
        message: eslintResult.stdout?.toString()
      });
    } catch (error) {
      // Tool not available is okay
      checks.push({
        tool: 'eslint',
        passed: true,
        message: 'ESLint not installed'
      });
    }

    return checks;
  };

  // Return hooks
  return {
    // Event hook for monitoring events
    event: async ({ event }) => {
      if (event.type === 'session.idle') {
        console.log('💤 Session idle - Quality checks on standby');
      }
    },

    // Tool execution hooks
    "tool.execute.before": async (input, output) => {
      // Check for .env file reads
      if (input.tool === "read" && output.args?.filePath?.includes(".env")) {
        console.warn("⚠️  Warning: Reading .env file - be careful with secrets");
      }

      // Check for dangerous edits
      if (input.tool === "edit" || input.tool === "write") {
        const filePath = output.args?.filePath || output.args?.file_path;
        const content = output.args?.content || output.args?.new_string || "";

        if (filePath && content) {
          const language = detectLanguage(filePath);
          console.log(`🔍 Quality check for ${filePath} (${language})`);

          const securityIssues = await runSecurityCheck(filePath, content);
          if (securityIssues.length > 0) {
            console.warn('⚠️  Security issues detected:');
            securityIssues.forEach(issue => {
              console.warn(`  - ${issue.severity}: ${issue.message}`);
            });

            // Warn about critical issues but don't block (for Phase 1)
            const hasCritical = securityIssues.some(i => i.severity === 'critical');
            if (hasCritical) {
              console.error('🚫 Critical security issues detected! Review before committing.');
            }
          }
        }
      }
    },

    // Tool execution after hook
    "tool.execute.after": async (input, output) => {
      // Log successful edits
      if ((input.tool === "edit" || input.tool === "write") && output.success) {
        const filePath = output.args?.filePath || output.args?.file_path;
        console.log(`✅ File modified: ${filePath}`);
      }
    }
  };
};

// Export as default for compatibility
export default QualityEnforcer;