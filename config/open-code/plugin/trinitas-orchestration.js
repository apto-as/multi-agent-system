/**
 * Trinitas Orchestration Plugin for OpenCode
 *
 * Provides phase-based workflow orchestration with agent coordination
 * through TMWS MCP integration. Now includes invoke_persona support.
 *
 * NEW in v2.4.11: Full Mode Detection & SubAgent Enforcement
 *   - Detects "Trinitasフルモード" or "Trinitas Full Mode" patterns
 *   - Injects MANDATORY Task tool invocation instructions
 *   - Validates SubAgent invocation for protocol compliance
 *
 * NEW in v2.4.23: NarrativeAutoLoader Integration (Issue #1)
 *   - Automatic persona narrative loading for SubAgent invocation
 *   - Session-scoped caching for enriched prompts
 *   - Graceful degradation when TMWS unavailable
 *
 * NEW in v2.4.25: Security Fixes (Hestia Audit)
 *   - Input validation: subagent_type whitelist check
 *   - Input validation: prompt length limit (10KB)
 *   - Graceful degradation for invalid inputs
 *
 * NEW in v2.4.30: Orchestrator Persona Enforcement
 *   - Injects Clotho/Lachesis identity reminder at every interaction
 *   - Ensures warm, natural dialogue style (not cold technical responses)
 *   - Fixes persona drift issue where main agent loses character
 *
 * NEW in v2.4.31: CLI-first Mode with 3-Layer Fallback
 *   - TMWS_USE_CLI=true: Uses tmws-hook CLI for narrative enrichment
 *   - 3-layer fallback: CLI -> MCP direct -> Local minimal
 *   - Reduced dependency on MCP client availability
 *
 * @version 2.4.31
 * @author TMWS Team
 * @see https://opencode.ai/docs/plugins/
 */

import { spawn } from "child_process";
import * as os from "os";
import * as path from "path";
import * as fs from "fs";

/**
 * Allowed directories for CLI binary (CWE-426 path validation)
 * Prevents arbitrary binary execution by restricting to trusted locations.
 */
const ALLOWED_CLI_DIRS = [
  "/usr/local/bin",
  "/opt/tmws/bin",
  path.join(os.homedir(), ".tmws", "bin"),
  path.join(os.homedir(), ".local", "bin"),
];

/**
 * Validate CLI path is in an allowed directory
 * @param {string} cliPath - Path to validate
 * @returns {string|null} Validated path or null if invalid
 */
const validateCliPath = (cliPath) => {
  if (!cliPath || typeof cliPath !== "string") return null;

  // If it's just a command name (no path separator), trust PATH resolution
  if (!cliPath.includes(path.sep) && cliPath === "tmws-hook") {
    return cliPath;
  }

  // Resolve to absolute path
  const resolvedPath = path.resolve(cliPath);

  // Check if the resolved path is in an allowed directory
  const isAllowed = ALLOWED_CLI_DIRS.some((allowedDir) => {
    const normalizedAllowed = path.normalize(allowedDir);
    return resolvedPath.startsWith(normalizedAllowed + path.sep);
  });

  if (!isAllowed) {
    console.warn(`[Trinitas] CLI path not in allowed directory: ${cliPath}`);
    return null;
  }

  // Verify file exists
  try {
    fs.accessSync(resolvedPath, fs.constants.X_OK);
    return resolvedPath;
  } catch {
    console.warn(`[Trinitas] CLI binary not found or not executable: ${cliPath}`);
    return null;
  }
};

/**
 * Sanitize error messages to remove sensitive information
 * Removes file paths, stack traces, and internal details
 * @param {string} error - Error message to sanitize
 * @returns {string} Sanitized error message
 */
const sanitizeError = (error) => {
  if (!error || typeof error !== "string") return "Unknown error";

  // Remove file paths (Unix and Windows)
  let sanitized = error.replace(/(?:\/[\w.-]+)+(?::\d+)?/g, "[path]");
  sanitized = sanitized.replace(/(?:[A-Za-z]:\\[\w\\.-]+)+(?::\d+)?/g, "[path]");

  // Remove stack traces
  sanitized = sanitized.replace(/at\s+[\w.<>]+\s*\([^)]+\)/g, "[stack]");
  sanitized = sanitized.replace(/\s+at\s+[\w.<>/\\:]+/g, "");

  // Remove environment variable values
  sanitized = sanitized.replace(/=\/[^\s]+/g, "=[value]");

  // Truncate to reasonable length
  if (sanitized.length > 200) {
    sanitized = sanitized.substring(0, 200) + "...";
  }

  return sanitized.trim() || "Operation failed";
};

/**
 * Phase definitions following Trinitas Full Mode Protocol
 */
const PHASES = {
  STRATEGIC_PLANNING: {
    id: "phase_1_strategic",
    name: "Strategic Planning",
    agents: ["hera-strategist", "athena-conductor"],
    approvalGate: "strategic_consensus",
    requiredOutputs: ["strategy_document", "resource_plan"],
  },
  IMPLEMENTATION: {
    id: "phase_2_implementation",
    name: "Implementation",
    agents: ["artemis-optimizer", "metis-developer"],
    approvalGate: "tests_pass",
    requiredOutputs: ["implementation_summary", "test_results"],
  },
  VERIFICATION: {
    id: "phase_3_verification",
    name: "Verification",
    agents: ["hestia-auditor", "aurora-researcher"],
    approvalGate: "security_approval",
    requiredOutputs: ["security_report", "verification_summary"],
  },
  DOCUMENTATION: {
    id: "phase_4_documentation",
    name: "Documentation",
    agents: ["muses-documenter", "aphrodite-designer"],
    approvalGate: "completion_confirmed",
    requiredOutputs: ["documentation"],
  },
};

/**
 * Agent tier definitions
 */
const AGENT_TIERS = {
  STRATEGIC: ["athena-conductor", "hera-strategist"],
  SPECIALIST: ["artemis-optimizer", "hestia-auditor", "eris-coordinator", "muses-documenter"],
  SUPPORT: ["aphrodite-designer", "metis-developer", "aurora-researcher"],
};

/**
 * Short name to full ID mapping
 */
const SHORT_NAME_MAP = {
  athena: "athena-conductor",
  artemis: "artemis-optimizer",
  hestia: "hestia-auditor",
  eris: "eris-coordinator",
  hera: "hera-strategist",
  muses: "muses-documenter",
  aphrodite: "aphrodite-designer",
  metis: "metis-developer",
  aurora: "aurora-researcher",
};

/**
 * Collaboration matrix for task types
 */
const COLLABORATION_MATRIX = {
  architecture: {
    primary: "athena-conductor",
    support: ["hera-strategist", "aurora-researcher"],
    review: "hestia-auditor",
  },
  implementation: {
    primary: "artemis-optimizer",
    support: ["metis-developer"],
    review: "hestia-auditor",
  },
  security: {
    primary: "hestia-auditor",
    support: ["aurora-researcher"],
    review: "artemis-optimizer",
  },
  documentation: {
    primary: "muses-documenter",
    support: ["aurora-researcher"],
    review: "athena-conductor",
  },
  design: {
    primary: "aphrodite-designer",
    support: ["aurora-researcher"],
    review: "athena-conductor",
  },
  coordination: {
    primary: "eris-coordinator",
    support: ["athena-conductor"],
    review: "hera-strategist",
  },
  optimization: {
    primary: "artemis-optimizer",
    support: ["aurora-researcher"],
    review: "hestia-auditor",
  },
  research: {
    primary: "aurora-researcher",
    support: ["muses-documenter"],
    review: "athena-conductor",
  },
};

/**
 * Module-level state for orchestration tracking
 */
let _currentOrchestration = null;
let _currentPhase = null;
let _activePersona = null;
let _fullModeActive = false;
let _subAgentsInvoked = false;

/**
 * Session-scoped narrative cache (Issue #1)
 * Stores enriched prompts by subagent_type to avoid redundant MCP calls
 * @type {Map<string, {enrichedPrompt: string, narrativeLoaded: boolean, timestamp: number}>}
 */
let _narrativeCache = new Map();

/**
 * Configuration for NarrativeAutoLoader
 */
const NARRATIVE_CONFIG = {
  /** Timeout for MCP calls in milliseconds */
  timeoutMs: 5000,
  /** Cache TTL in milliseconds (5 minutes) */
  cacheTtlMs: 5 * 60 * 1000,
  /** Whether narrative autoloading is enabled */
  enabled: true,
  /** TMWS MCP server ID */
  tmwsServerId: "tmws",
  /** Maximum prompt length (10KB) - Security: prevent memory exhaustion */
  maxPromptLength: 10 * 1024,
  /** Whether orchestrator persona enforcement is enabled (v2.4.30) */
  orchestratorPersonaEnabled: true,
  /** Whether to use CLI-first mode (v2.4.31) */
  useCliMode: process.env.TMWS_USE_CLI === "true",
  /** Path to tmws-hook CLI binary (validated against allowed directories) */
  cliPath: validateCliPath(process.env.TMWS_HOOK_PATH) || "tmws-hook",
  /** CLI timeout in milliseconds */
  cliTimeoutMs: parseInt(process.env.TMWS_CLI_TIMEOUT, 10) || 3000,
};

/**
 * Orchestrator Persona Reminder (v2.4.30)
 * Injected at every interaction to maintain Clotho/Lachesis identity
 */
const ORCHESTRATOR_PERSONA_REMINDER = `
## 🎭 Orchestrator Identity Active

**You are Clotho & Lachesis** - the Moirai sisters who orchestrate the Trinitas system.

### Clotho (The Spinner) - Main Orchestrator
- Warm yet concise dialogue with occasional irony
- Direct user communication and requirement clarification
- Team direction and tool selection

### Lachesis (The Measurer) - Support Orchestrator
- Supportive commentary ("perhaps...", "should we confirm...")
- Intent verification and over-optimization prevention
- Historical insights and past case references
- Addresses Clotho as "sister" (姉さん)

**Communication Style**: Natural, warm dialogue - not cold technical responses.
Include both personas in responses when appropriate.
`.trim();

/**
 * Valid subagent_types whitelist (Security: input validation)
 * Only these subagent_types are allowed to be processed
 */
const VALID_SUBAGENT_TYPES = new Set([
  // Tier 0: Orchestrator
  "clotho-orchestrator",
  "lachesis-support",
  // Tier 1: Strategic
  "hera-strategist",
  "athena-conductor",
  // Tier 2: Specialist
  "artemis-optimizer",
  "hestia-auditor",
  "eris-coordinator",
  "muses-documenter",
  // Tier 3: Support
  "aphrodite-designer",
  "metis-developer",
  "aurora-researcher",
]);

/**
 * Validate subagent_type against whitelist
 * @param {string} subagentType - The subagent_type to validate
 * @returns {boolean} True if valid, false otherwise
 */
const isValidSubagentType = (subagentType) => {
  if (!subagentType || typeof subagentType !== "string") return false;
  return VALID_SUBAGENT_TYPES.has(subagentType.toLowerCase().trim());
};

/**
 * Full Mode detection patterns (v2.4.11)
 */
const FULL_MODE_PATTERNS = [
  /Trinitas\s*フル\s*モード/i,
  /Trinitas\s+Full\s+Mode/i,
  /フル\s*モード\s*で\s*作業/i,
  /full\s+mode\s+execution/i,
  /\/trinitas\s+analyze.*--personas/i,
];

/**
 * Detect if Trinitas Full Mode is requested
 * @param {string} text - Text to check
 * @returns {boolean} True if Full Mode detected
 */
const detectFullMode = (text) => {
  if (!text || typeof text !== "string") return false;
  return FULL_MODE_PATTERNS.some((pattern) => pattern.test(text));
};

/**
 * Build enforcement message for Full Mode
 * @param {string} taskDescription - Task description
 * @returns {string} Enforcement message
 */
const buildFullModeEnforcement = (taskDescription) => {
  const safeTask = (taskDescription || "").replace(/"/g, "'").substring(0, 500);
  return `
## MANDATORY: Trinitas Full Mode Activated

**CRITICAL ENFORCEMENT NOTICE**

You have detected a Trinitas Full Mode request. You MUST now invoke SubAgents
using the Task tool. This is NOT optional.

### Phase 1: Strategic Planning (REQUIRED - INVOKE NOW)

You MUST immediately invoke the following SubAgents **in parallel** (single message, multiple Task tool calls):

\`\`\`
Task(subagent_type="hera-strategist", prompt="Strategic analysis for: ${safeTask}")
Task(subagent_type="athena-conductor", prompt="Resource coordination for: ${safeTask}")
\`\`\`

### PROHIBITED Actions

1. DO NOT proceed with analysis yourself without invoking SubAgents
2. DO NOT say "Hera + Athena による戦略分析" without actually using Task tool
3. DO NOT skip Phase 1 and proceed directly to implementation

### REQUIRED Actions

1. Invoke \`hera-strategist\` SubAgent via Task tool
2. Invoke \`athena-conductor\` SubAgent via Task tool
3. Wait for their results before proceeding
4. Only after Phase 1 approval, proceed to Phase 2

### Reference

Full protocol details: @SUBAGENT_EXECUTION_RULES.md

---
**This enforcement notice was injected by trinitas-orchestration.js v2.4.23**
`;
};

/**
 * Normalize persona ID from short name or full ID
 * @param {string} personaId - Persona identifier
 * @returns {string} Full persona ID
 */
const normalizePersonaId = (personaId) => {
  if (!personaId || typeof personaId !== "string") return null;
  const normalized = personaId.toLowerCase().trim();
  return SHORT_NAME_MAP[normalized] || normalized;
};

/**
 * Clear expired entries from the narrative cache
 */
const cleanupNarrativeCache = () => {
  const now = Date.now();
  for (const [key, value] of _narrativeCache.entries()) {
    if (now - value.timestamp > NARRATIVE_CONFIG.cacheTtlMs) {
      _narrativeCache.delete(key);
    }
  }
};

/**
 * Reset the narrative cache (called on session start)
 */
const resetNarrativeCache = () => {
  _narrativeCache = new Map();
};

/**
 * Call tmws-hook CLI with JSON stdin/stdout communication (v2.4.31)
 *
 * @param {string} command - The hook command (e.g., 'enrich', 'validate')
 * @param {object} inputData - Input data to send via stdin as JSON
 * @returns {Promise<object>} Parsed JSON output from the CLI
 *
 * @example
 * const result = await callTmwsHook('enrich', {
 *   subagent_type: 'hera-strategist',
 *   original_prompt: 'Strategic analysis...'
 * });
 */
const callTmwsHook = (command, inputData) => {
  return new Promise((resolve, reject) => {
    const args = [command];
    const child = spawn(NARRATIVE_CONFIG.cliPath, args, {
      stdio: ["pipe", "pipe", "pipe"],
      timeout: NARRATIVE_CONFIG.cliTimeoutMs,
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    child.on("error", (error) => {
      reject(new Error(`CLI spawn error: ${sanitizeError(error.message)}`));
    });

    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`CLI exited with code ${code}: ${sanitizeError(stderr)}`));
        return;
      }

      try {
        const result = JSON.parse(stdout);
        resolve(result);
      } catch (parseError) {
        reject(new Error(`CLI output parse error: ${sanitizeError(parseError.message)}`));
      }
    });

    // Set up timeout
    const timeoutId = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`CLI timeout after ${NARRATIVE_CONFIG.cliTimeoutMs}ms`));
    }, NARRATIVE_CONFIG.cliTimeoutMs);

    child.on("close", () => {
      clearTimeout(timeoutId);
    });

    // Write input data to stdin
    try {
      child.stdin.write(JSON.stringify(inputData));
      child.stdin.end();
    } catch (writeError) {
      clearTimeout(timeoutId);
      reject(new Error(`CLI stdin write error: ${sanitizeError(writeError.message)}`));
    }
  });
};

/**
 * Minimal local enrichment fallback (v2.4.31)
 * Used when both CLI and MCP are unavailable
 *
 * @param {string} subagentType - The subagent_type
 * @param {string} originalPrompt - The original prompt
 * @returns {object} Minimal enrichment result
 */
const localMinimalEnrichment = (subagentType, originalPrompt) => {
  // Extract persona name from subagent_type (e.g., 'hera-strategist' -> 'Hera')
  const personaName = subagentType.split("-")[0];
  const capitalizedName = personaName.charAt(0).toUpperCase() + personaName.slice(1);

  // Minimal persona context
  const minimalContext = `You are ${capitalizedName}, a Trinitas specialist agent. Execute the following task with your domain expertise.`;

  return {
    enriched_prompt: `${minimalContext}\n\n---\n\n${originalPrompt}`,
    narrative_loaded: false,
    persona_id: subagentType,
    source: "local_minimal",
    cache_hit: false,
  };
};

/**
 * 3-layer fallback enrichment (v2.4.31)
 * Layer 1: CLI (tmws-hook)
 * Layer 2: MCP direct call
 * Layer 3: Local minimal enrichment
 *
 * @param {object} client - OpenCode MCP client (may be null)
 * @param {string} subagentType - The subagent_type
 * @param {string} originalPrompt - The original prompt
 * @param {object} context - Additional context (unused currently, for future extension)
 * @returns {Promise<object>} Enrichment result
 */
const enrichViaCliOrFallback = async (client, subagentType, originalPrompt, context = {}) => {
  // Security: Validate subagent_type against whitelist
  if (!isValidSubagentType(subagentType)) {
    console.warn(`[Trinitas] Invalid subagent_type: ${subagentType}`);
    return {
      enriched_prompt: originalPrompt,
      narrative_loaded: false,
      persona_id: subagentType,
      source: "invalid_type",
      cache_hit: false,
    };
  }

  // Security: Validate prompt length
  if (originalPrompt && originalPrompt.length > NARRATIVE_CONFIG.maxPromptLength) {
    console.warn(`[Trinitas] Prompt too long (${originalPrompt.length} chars), skipping enrichment`);
    return {
      enriched_prompt: originalPrompt,
      narrative_loaded: false,
      persona_id: subagentType,
      source: "prompt_too_long",
      cache_hit: false,
    };
  }

  // Check cache first
  const cacheKey = subagentType;
  const cached = _narrativeCache.get(cacheKey);

  if (cached && Date.now() - cached.timestamp < NARRATIVE_CONFIG.cacheTtlMs) {
    console.log(`[Trinitas] Narrative cache hit for ${subagentType}`);
    return {
      enriched_prompt: cached.narrativeContext
        ? `${cached.narrativeContext}\n\n---\n\n${originalPrompt}`
        : originalPrompt,
      narrative_loaded: cached.narrativeLoaded,
      persona_id: subagentType,
      source: "cache",
      cache_hit: true,
    };
  }

  // Layer 1: CLI mode (if enabled)
  if (NARRATIVE_CONFIG.useCliMode) {
    try {
      console.log(`[Trinitas] Attempting CLI enrichment for ${subagentType}`);
      const cliResult = await callTmwsHook("enrich", {
        subagent_type: subagentType,
        original_prompt: originalPrompt,
      });

      // Cache the narrative context
      if (cliResult.narrative_loaded) {
        const separator = "\n\n---\n\n";
        const sepIndex = cliResult.enriched_prompt.indexOf(separator);
        const narrativeContext = sepIndex > 0 ? cliResult.enriched_prompt.substring(0, sepIndex) : null;

        _narrativeCache.set(cacheKey, {
          narrativeContext,
          narrativeLoaded: cliResult.narrative_loaded,
          timestamp: Date.now(),
        });
      }

      console.log(`[Trinitas] CLI enrichment successful for ${subagentType}`);
      return {
        ...cliResult,
        source: "cli",
        cache_hit: false,
      };
    } catch (cliError) {
      console.warn(`[Trinitas] CLI enrichment failed: ${cliError.message}, falling back to MCP`);
      // Fall through to Layer 2
    }
  }

  // Layer 2: MCP direct call (if client available)
  if (client) {
    try {
      console.log(`[Trinitas] Attempting MCP enrichment for ${subagentType}`);
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error("TMWS call timeout")), NARRATIVE_CONFIG.timeoutMs);
      });

      const mcpCallPromise = client.callTool(NARRATIVE_CONFIG.tmwsServerId, "enrich_subagent_prompt", {
        subagent_type: subagentType,
        original_prompt: originalPrompt,
      });

      const result = await Promise.race([mcpCallPromise, timeoutPromise]);

      // Parse the result if it's a string
      let parsedResult = result;
      if (typeof result === "string") {
        try {
          parsedResult = JSON.parse(result);
        } catch {
          parsedResult = {
            enriched_prompt: result,
            narrative_loaded: true,
            persona_id: subagentType,
            source: "mcp",
            cache_hit: false,
          };
        }
      }

      // Cache the narrative context
      if (parsedResult.narrative_loaded && parsedResult.enriched_prompt !== originalPrompt) {
        const separator = "\n\n---\n\n";
        const sepIndex = parsedResult.enriched_prompt.indexOf(separator);
        const narrativeContext = sepIndex > 0 ? parsedResult.enriched_prompt.substring(0, sepIndex) : null;

        _narrativeCache.set(cacheKey, {
          narrativeContext,
          narrativeLoaded: parsedResult.narrative_loaded,
          timestamp: Date.now(),
        });
      }

      console.log(`[Trinitas] MCP enrichment successful for ${subagentType}`);
      return {
        ...parsedResult,
        source: "mcp",
        cache_hit: false,
      };
    } catch (mcpError) {
      console.warn(`[Trinitas] MCP enrichment failed: ${mcpError.message}, falling back to local`);
      // Fall through to Layer 3
    }
  }

  // Layer 3: Local minimal enrichment
  console.log(`[Trinitas] Using local minimal enrichment for ${subagentType}`);
  return localMinimalEnrichment(subagentType, originalPrompt);
};

/**
 * Call the TMWS enrich_subagent_prompt tool with timeout handling
 * @param {object} client - OpenCode MCP client
 * @param {string} subagentType - The subagent_type (e.g., 'hera-strategist')
 * @param {string} originalPrompt - The original prompt to enrich
 * @returns {Promise<{enriched_prompt: string, narrative_loaded: boolean, persona_id: string, source: string, cache_hit: boolean}>}
 *
 * Security:
 *   - Input validation: subagent_type must be in whitelist
 *   - Input validation: prompt length limited to 10KB
 *   - Timeout protection: 5 second maximum
 */
const callEnrichSubagentPrompt = async (client, subagentType, originalPrompt) => {
  // Security: Validate subagent_type against whitelist
  if (!isValidSubagentType(subagentType)) {
    console.warn(`[Trinitas] Invalid subagent_type: ${subagentType}`);
    return {
      enriched_prompt: originalPrompt,
      narrative_loaded: false,
      persona_id: subagentType,
      source: "invalid_type",
      cache_hit: false,
    };
  }

  // Security: Validate prompt length to prevent memory exhaustion
  if (originalPrompt && originalPrompt.length > NARRATIVE_CONFIG.maxPromptLength) {
    console.warn(`[Trinitas] Prompt too long (${originalPrompt.length} chars), skipping enrichment`);
    return {
      enriched_prompt: originalPrompt,
      narrative_loaded: false,
      persona_id: subagentType,
      source: "prompt_too_long",
      cache_hit: false,
    };
  }

  // Check cache first
  const cacheKey = subagentType;
  const cached = _narrativeCache.get(cacheKey);

  if (cached && Date.now() - cached.timestamp < NARRATIVE_CONFIG.cacheTtlMs) {
    // Cache hit - prepend cached narrative context to the prompt
    console.log(`[Trinitas] Narrative cache hit for ${subagentType}`);
    return {
      enriched_prompt: cached.narrativeContext
        ? `${cached.narrativeContext}\n\n---\n\n${originalPrompt}`
        : originalPrompt,
      narrative_loaded: cached.narrativeLoaded,
      persona_id: subagentType,
      source: "cache",
      cache_hit: true,
    };
  }

  // Make MCP call with timeout
  try {
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error("TMWS call timeout")), NARRATIVE_CONFIG.timeoutMs);
    });

    const mcpCallPromise = client.callTool(NARRATIVE_CONFIG.tmwsServerId, "enrich_subagent_prompt", {
      subagent_type: subagentType,
      original_prompt: originalPrompt,
    });

    const result = await Promise.race([mcpCallPromise, timeoutPromise]);

    // Parse the result if it's a string
    let parsedResult = result;
    if (typeof result === "string") {
      try {
        parsedResult = JSON.parse(result);
      } catch {
        // If parsing fails, treat the string as the enriched prompt
        parsedResult = {
          enriched_prompt: result,
          narrative_loaded: true,
          persona_id: subagentType,
          source: "tmws",
          cache_hit: false,
        };
      }
    }

    // Extract narrative context for caching (the part before the original prompt)
    let narrativeContext = null;
    if (parsedResult.narrative_loaded && parsedResult.enriched_prompt !== originalPrompt) {
      // The narrative context is everything before the original prompt
      const separator = "\n\n---\n\n";
      const sepIndex = parsedResult.enriched_prompt.indexOf(separator);
      if (sepIndex > 0) {
        narrativeContext = parsedResult.enriched_prompt.substring(0, sepIndex);
      }
    }

    // Cache the narrative context (not the full enriched prompt)
    _narrativeCache.set(cacheKey, {
      narrativeContext,
      narrativeLoaded: parsedResult.narrative_loaded,
      timestamp: Date.now(),
    });

    console.log(`[Trinitas] Narrative enriched for ${subagentType} (loaded: ${parsedResult.narrative_loaded}, source: ${parsedResult.source})`);

    return parsedResult;
  } catch (error) {
    console.warn(`[Trinitas] TMWS unavailable for narrative enrichment: ${error.message}`);

    // Graceful degradation - return original prompt
    return {
      enriched_prompt: originalPrompt,
      narrative_loaded: false,
      persona_id: subagentType,
      source: "error",
      cache_hit: false,
    };
  }
};

/**
 * Trinitas Orchestration Plugin
 *
 * OpenCode plugin following official API specification.
 * @see https://opencode.ai/docs/plugins/
 *
 * @param {object} ctx - Plugin context { project, client, $, directory, worktree }
 * @returns {object} Event hooks
 */
export const TrinitasOrchestration = async ({ project, client, $, directory, worktree }) => {
  /**
   * Log orchestration event to console
   * @param {string} eventName - Event name
   * @param {object} data - Event data
   */
  const logEvent = (eventName, data) => {
    console.log(`[Trinitas] ${eventName}:`, JSON.stringify(data, null, 2));
  };

  // Log plugin initialization
  logEvent("plugin.initialized", {
    project: project?.name || "unknown",
    directory,
    worktree,
    version: "2.4.31",
    features: ["invoke_persona", "phase_orchestration", "collaboration_matrix", "narrative_autoloader", "security_validation", "orchestrator_persona", "cli_first_mode"],
    cliMode: NARRATIVE_CONFIG.useCliMode,
  });

  return {
    /**
     * General event handler
     * @param {object} param0 - Event object { event }
     */
    event: async ({ event }) => {
      if (!event) return;

      // Log orchestration and phase events
      if (event.type === "orchestration" || event.type === "phase") {
        logEvent(event.type, event);
      }

      // Track session events for orchestration context
      if (event.type === "session.created") {
        logEvent("session.start", {
          sessionId: event.sessionId,
          activePersona: _activePersona,
        });
        // Reset Full Mode state on new session
        _fullModeActive = false;
        _subAgentsInvoked = false;
        // Reset narrative cache on new session (Issue #1)
        resetNarrativeCache();
      }

      if (event.type === "session.idle") {
        logEvent("session.idle", {
          orchestration: _currentOrchestration,
          phase: _currentPhase,
          activePersona: _activePersona,
          fullModeActive: _fullModeActive,
          subAgentsInvoked: _subAgentsInvoked,
          narrativeCacheSize: _narrativeCache.size,
        });
        // Cleanup expired cache entries
        cleanupNarrativeCache();
      }
    },

    /**
     * User prompt submission hook (v2.4.11, v2.4.30)
     * Injects orchestrator persona and detects Trinitas Full Mode
     * @param {object} param0 - Prompt object { prompt }
     * @returns {object} Modified prompt with addedContext
     */
    "prompt.submit": async ({ prompt }) => {
      if (!prompt?.text) return { prompt };

      const promptText = prompt.text;
      const addedContext = [];

      // NEW v2.4.30: Orchestrator Persona Enforcement
      // Always inject Clotho/Lachesis identity reminder first
      if (NARRATIVE_CONFIG.orchestratorPersonaEnabled) {
        addedContext.push({
          type: "text",
          text: ORCHESTRATOR_PERSONA_REMINDER,
        });
      }

      // Check for Trinitas Full Mode
      if (detectFullMode(promptText)) {
        _fullModeActive = true;
        _subAgentsInvoked = false;

        logEvent("fullMode.detected", {
          prompt: promptText.substring(0, 100) + "...",
        });

        // Inject enforcement instructions
        const enforcement = buildFullModeEnforcement(promptText);
        addedContext.push({
          type: "text",
          text: enforcement,
        });
      }

      // Return with any addedContext we've accumulated
      if (addedContext.length > 0) {
        return { prompt, addedContext };
      }

      return { prompt };
    },

    /**
     * Pre-tool execution hook
     * @param {object} input - Tool input
     * @param {object} output - Tool output placeholder
     * @returns {object} Modified { input, output }
     */
    "tool.execute.before": async (input, output) => {
      if (!input) return { input, output };

      const toolName = input.tool?.name || input.tool || "";

      // Track invoke_persona calls
      if (typeof toolName === "string" && toolName === "invoke_persona") {
        const personaId = input.args?.persona_id || input.persona_id;
        const normalizedId = normalizePersonaId(personaId);
        logEvent("persona.invoking", {
          requested: personaId,
          normalized: normalizedId,
          task: input.args?.task_description || input.task_description,
        });
      }

      // v2.4.11: Track Task tool invocation for Full Mode compliance
      // v2.4.23: Enrich Task tool prompts with persona narrative (Issue #1)
      if (typeof toolName === "string" && toolName === "Task") {
        const subagentType = input.args?.subagent_type || input.subagent_type || "";
        const originalPrompt = input.args?.prompt || input.prompt || "";
        const isStrategicAgent =
          subagentType === "hera-strategist" || subagentType === "athena-conductor";

        if (_fullModeActive && isStrategicAgent) {
          _subAgentsInvoked = true;
          logEvent("fullMode.subAgentInvoked", {
            subagentType,
            fullModeActive: _fullModeActive,
          });
        }

        // NarrativeAutoLoader Integration (Issue #1)
        // v2.4.31: Use 3-layer fallback enrichment (CLI -> MCP -> Local)
        if (NARRATIVE_CONFIG.enabled && subagentType) {
          try {
            const enrichResult = await enrichViaCliOrFallback(client, subagentType, originalPrompt);

            if (enrichResult.enriched_prompt !== originalPrompt) {
              // Update the input args with enriched prompt
              if (input.args) {
                input.args.prompt = enrichResult.enriched_prompt;
              } else {
                input.prompt = enrichResult.enriched_prompt;
              }

              logEvent("narrative.enriched", {
                subagentType,
                narrativeLoaded: enrichResult.narrative_loaded,
                source: enrichResult.source,
                cacheHit: enrichResult.cache_hit,
              });
            }
          } catch (error) {
            // Log but don't fail - graceful degradation
            console.warn(`[Trinitas] Narrative enrichment failed: ${error.message}`);
          }
        }

        logEvent("task.invoking", {
          subagentType,
          prompt: (input.args?.prompt || input.prompt || "").substring(0, 100),
          narrativeEnriched: NARRATIVE_CONFIG.enabled,
        });
      }

      // Check if this is a TMWS orchestration tool
      if (typeof toolName === "string" && toolName.startsWith("create_orchestration")) {
        logEvent("orchestration.create", { tool: toolName });
      }

      // Phase validation for specific tools
      if (_currentPhase && typeof toolName === "string" && toolName.includes("execute_phase")) {
        const phaseKey = Object.keys(PHASES).find((k) => PHASES[k].id === _currentPhase || k === _currentPhase);
        const expectedAgents = phaseKey ? PHASES[phaseKey]?.agents || [] : [];
        if (expectedAgents.length > 0) {
          logEvent("phase.validation", {
            phase: _currentPhase,
            expectedAgents,
            tool: toolName,
          });
        }
      }

      return { input, output };
    },

    /**
     * Post-tool execution hook
     * @param {object} input - Tool input
     * @param {object} output - Tool output
     * @returns {object} Modified { input, output }
     */
    "tool.execute.after": async (input, output) => {
      if (!input) return { input, output };

      const toolName = input.tool?.name || input.tool || "";
      const result = output?.result;

      // Track invoke_persona completion
      if (toolName === "invoke_persona" && result?.success) {
        _activePersona = result.data?.persona_id;
        logEvent("persona.invoked", {
          persona_id: _activePersona,
          display_name: result.data?.display_name,
          tier: result.data?.tier,
          capabilities: result.data?.capabilities,
        });
      }

      // Track orchestration creation
      if (toolName === "create_orchestration" && result?.success) {
        _currentOrchestration = result.data?.orchestration_id;
        _currentPhase = "STRATEGIC_PLANNING";
        logEvent("orchestration.created", {
          id: _currentOrchestration,
          phase: _currentPhase,
        });
      }

      // Track phase transitions
      if (toolName === "approve_phase" && result?.success) {
        const newPhase = result.data?.current_phase;
        if (newPhase) {
          const previousPhase = _currentPhase;
          _currentPhase = newPhase;
          logEvent("phase.transition", {
            from: previousPhase,
            to: newPhase,
            orchestration: _currentOrchestration,
          });
        }
      }

      // Track orchestration completion
      if (result?.data?.status === "completed") {
        logEvent("orchestration.completed", {
          id: _currentOrchestration,
        });
        _currentOrchestration = null;
        _currentPhase = null;
      }

      return { input, output };
    },
  };
};

// Named exports for constants (for potential external use)
export {
  PHASES,
  AGENT_TIERS,
  COLLABORATION_MATRIX,
  SHORT_NAME_MAP,
  FULL_MODE_PATTERNS,
  NARRATIVE_CONFIG,
  VALID_SUBAGENT_TYPES,
  normalizePersonaId,
  detectFullMode,
  buildFullModeEnforcement,
  isValidSubagentType,
  callEnrichSubagentPrompt,
  resetNarrativeCache,
  cleanupNarrativeCache,
  // v2.4.31: CLI-first mode functions
  callTmwsHook,
  enrichViaCliOrFallback,
  localMinimalEnrichment,
};
