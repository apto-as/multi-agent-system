/**
 * Pre-Compact Plugin for Trinitas Agents (OpenCode)
 *
 * Implements Level 3 Hierarchical Summarization for context-limited situations.
 * Equivalent to Claude Code's protocol_injector.py (inject_pre_compact method).
 *
 * Provides minimal summary of the Trinitas system with only core coordination
 * patterns and active personas. Used when full context injection exceeds token limits.
 *
 * Performance Characteristics:
 *   - Summary generation: <0.5ms (static template)
 *   - Total latency: <1ms typical
 *
 * Integration:
 *   - Hook: session.compact.before (before context compaction)
 *   - Output: Minimal Level 3 summary
 *
 * Version: 2.0.0 (OpenCode Edition)
 * Refactored: 2025-10-19 - Based on Claude Code v2.2.4
 */

import { existsSync, readFileSync } from 'fs';
import { join } from 'path';

export const PreCompactPlugin = async ({ project, client, $, directory, worktree }) => {
  console.log('📦 Trinitas Pre-Compact Plugin v2.0.0 initialized');

  const VERSION = '2.2.4';
  const MEMORY_BASE = join(directory, '.opencode/memory');

  /**
   * Get context profile from environment variable
   * @returns {string} Profile name (minimal|coding|security|full)
   */
  const getContextProfile = () => {
    const profile = process.env.TRINITAS_CONTEXT_PROFILE || 'coding';
    const validProfiles = ['minimal', 'coding', 'security', 'full'];

    return validProfiles.includes(profile) ? profile : 'coding';
  };

  /**
   * Load previous session summary for continuity
   * @returns {string} Previous session summary or empty string
   */
  const loadPreviousSessionSummary = () => {
    try {
      // Calculate yesterday's date (YYYY-MM-DD format)
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      const yesterdayStr = yesterday.toISOString().split('T')[0];

      const summaryPath = join(MEMORY_BASE, 'sessions', `${yesterdayStr}_summary.md`);

      if (existsSync(summaryPath)) {
        const content = readFileSync(summaryPath, 'utf-8');
        return `
## Previous Session Summary (${yesterdayStr})

${content}

---
`;
      }

      return '';

    } catch (error) {
      console.error('Error loading previous session summary:', error.message);
      return '';
    }
  };

  /**
   * Generate Level 3 Hierarchical Summary
   *
   * Provides minimal context with:
   *   - Active coordinators (Athena + Hera)
   *   - Specialist agents (Artemis, Hestia, Eris, Muses)
   *   - Context profile name
   *   - Key coordination patterns
   *
   * @returns {string} Markdown-formatted Level 3 summary
   */
  const generateLevel3Summary = () => {
    const profile = getContextProfile();

    const summary = `
## Trinitas Core (Level 3 Summary)

**Active Coordinators**: Athena + Hera
**Specialists**: Artemis, Hestia, Eris, Muses

**Context Profile**: \`${profile}\`

**Key Patterns**:
- Parallel analysis coordinated by Athena
- Security-first approach via Hestia
- Strategic execution by Hera
- Knowledge preservation by Muses

---

**Trinitas v${VERSION}** | Compact Mode
`;

    return summary.trim();
  };

  /**
   * Generate compact context with session continuity
   *
   * Combines:
   *   1. Previous session summary (if exists)
   *   2. Level 3 Hierarchical Summary
   *
   * @returns {string} Full compact context
   */
  const generateCompactContext = () => {
    const previousSession = loadPreviousSessionSummary();
    const level3Summary = generateLevel3Summary();

    const parts = [];

    if (previousSession) {
      parts.push(previousSession);
    }

    parts.push(level3Summary);

    return parts.join('\n\n');
  };

  /**
   * Inject compact context and log metrics
   */
  const injectPreCompact = () => {
    try {
      const compactContext = generateCompactContext();
      const verbose = process.env.TRINITAS_VERBOSE === '1';

      if (verbose) {
        const tokenEstimate = Math.ceil(compactContext.length / 4);
        console.log(`✓ Trinitas v${VERSION} | Compact Mode | ~${(tokenEstimate / 1000).toFixed(1)}k tokens`);
      }

      return compactContext;

    } catch (error) {
      console.error('Error injecting pre-compact context:', error.message);
      return '';
    }
  };

  // === PLUGIN HOOKS ===
  return {
    /**
     * Event hook: Monitor session lifecycle
     */
    event: async ({ event }) => {
      if (event.type === 'session.start') {
        console.log('📦 Pre-Compact ready');
        console.log(`   Context profile: ${getContextProfile()}`);
        console.log(`   Version: ${VERSION}`);
      }

      if (event.type === 'session.idle') {
        // Log summary on session end
        const verbose = process.env.TRINITAS_VERBOSE === '1';
        if (verbose) {
          console.log('📦 Pre-Compact session completed');
        }
      }
    },

    /**
     * Session compact hook: Inject minimal context before compaction
     *
     * Note: OpenCode's event system may not have a direct "session.compact.before" event.
     * This is conceptual - actual integration may require custom event handling or a
     * different hook point (e.g., before context window limit is reached).
     *
     * Equivalent to Claude Code's SessionStart hook with TRINITAS_MINIMAL_OUTPUT=1.
     */
    'session.compact.before': async () => {
      const compactContext = injectPreCompact();

      return {
        systemMessage: compactContext
      };
    },

    /**
     * Alternative: Provide compact context on demand
     * Can be triggered by other plugins or custom events
     */
    'context.compact': async () => {
      return {
        context: injectPreCompact(),
        type: 'level3_summary',
        version: VERSION,
        profile: getContextProfile()
      };
    },

    /**
     * Tool hook: Inject compact context before heavy operations
     * This serves as a fallback if session.compact.before is not available
     */
    'tool.execute.before': async (input, output) => {
      // Inject compact context for potentially heavy operations
      const heavyTools = ['grep', 'glob', 'bash', 'write'];

      if (heavyTools.includes(input.tool)) {
        // Check if context pressure is high (heuristic)
        const shouldCompact = shouldInjectCompactContext();

        if (shouldCompact && output) {
          const compactContext = injectPreCompact();
          output.compactContext = compactContext;
        }
      }
    },

    /**
     * Custom API: Direct compact context generation
     */
    'compact.generate': async () => {
      const startTime = performance.now();
      const compactContext = injectPreCompact();
      const elapsed = performance.now() - startTime;

      return {
        context: compactContext,
        version: VERSION,
        profile: getContextProfile(),
        generationTime: `${elapsed.toFixed(2)}ms`,
        tokenEstimate: Math.ceil(compactContext.length / 4),
        type: 'level3_summary'
      };
    }
  };
};

/**
 * Heuristic to determine if compact context should be injected
 * @returns {boolean} True if context pressure is high
 */
function shouldInjectCompactContext() {
  // Simple heuristic: Inject compact context every N operations
  // In production, this would check actual context window usage
  const INJECT_FREQUENCY = 10;

  if (!global._trinitasCompactCounter) {
    global._trinitasCompactCounter = 0;
  }

  global._trinitasCompactCounter++;

  if (global._trinitasCompactCounter >= INJECT_FREQUENCY) {
    global._trinitasCompactCounter = 0;
    return true;
  }

  return false;
}

// Export as default for compatibility
export default PreCompactPlugin;
