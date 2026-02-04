/**
 * Trinitas Orchestration Plugin for OpenCode
 *
 * Provides phase-based workflow orchestration with agent coordination
 * through TMWS MCP integration. Now includes invoke_persona support.
 *
 * NEW in v2.4.37: Session Resume Detection + Periodic Persona Reminder + Decision Check Stub
 *   - Detects session resume from context compaction
 *   - Injects TMWS Skills loading instruction for delegation matrix
 *   - Periodic persona reminders every N tool calls (default: 10)
 *   - Decision check stub for Level 1/2 Autonomy (future expansion)
 *
 * NEW in v2.4.36: Automatic Memory Storage (Issue #215)
 *   - Stores agent interactions as memories for skill evolution
 *   - Non-blocking fire-and-forget memory storage
 *   - Filters trivial operations (Read, Glob, etc.)
 *   - Auto-generates tags and calculates importance scores
 *
 * NEW in v2.4.35: Automatic Trust Recording
 *   - Records SubAgent Task execution outcomes (success/failure)
 *   - Non-blocking fire-and-forget trust event recording
 *   - Supports agent growth tracking via TMWS verify_and_record
 *
 * NEW in v2.4.33: Session Start Narrative Loading (GAP-1 Fix)
 *   - Loads TMWS narratives for Clotho/Lachesis at session start
 *   - Caches orchestrator narratives for the session
 *   - Provides narrative context to all subsequent tool calls
 *
 * NEW in v2.4.25: Security Fixes (Hestia Audit)
 *   - Input validation: subagent_type whitelist check
 *   - Input validation: prompt length limit (10KB)
 *   - Graceful degradation for invalid inputs
 *
 * NEW in v2.4.23: NarrativeAutoLoader Integration (Issue #1)
 *   - Automatic persona narrative loading for SubAgent invocation
 *   - Session-scoped caching for enriched prompts
 *   - Graceful degradation when TMWS unavailable
 *
 * NEW in v2.4.11: Full Mode Detection & SubAgent Enforcement
 *   - Detects "Trinitasフルモード" or "Trinitas Full Mode" patterns
 *   - Injects MANDATORY Task tool invocation instructions
 *   - Validates SubAgent invocation for protocol compliance
 *
 * @version 2.4.37
 * @author TMWS Team
 * @see https://opencode.ai/docs/plugins/
 */

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
  clotho: "clotho-orchestrator",
  lachesis: "lachesis-support",
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
 * Orchestrator narratives loaded at session start (v2.4.33)
 * @type {{clotho: string|null, lachesis: string|null, loaded: boolean}}
 */
let _orchestratorNarratives = {
  clotho: null,
  lachesis: null,
  loaded: false,
};

/**
 * Tool call counter for periodic persona reminder (v2.4.37)
 * @type {Map<string, {count: number, lastActivity: number}>}
 */
let _toolCallCounter = new Map();

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
  /** Whether to load orchestrator narratives at session start (v2.4.33) */
  loadOrchestratorNarratives: true,
};

/**
 * Configuration for Periodic Persona Reminder (v2.4.37)
 */
const PERSONA_REMINDER_CONFIG = {
  /** Number of tool calls between reminders */
  frequency: 10,
  /** Enable/disable persona reminder */
  enabled: true,
  /** Session timeout in milliseconds (30 minutes) */
  sessionTimeoutMs: 30 * 60 * 1000,
};

/**
 * Configuration for Decision Check (v2.4.37 Stub)
 * Level 1: Automatic execution allowed
 * Level 2: User confirmation required
 */
const DECISION_CHECK_CONFIG = {
  /** Enable decision check (stub for future expansion) */
  enabled: false,
  /** Default autonomy level */
  defaultLevel: 1,
  /** Operations requiring Level 2 confirmation */
  level2Operations: [
    "git push",
    "rm -rf",
    "DROP TABLE",
    "DELETE FROM",
    "production deploy",
  ],
};

/**
 * Session Resume Detection Patterns (v2.4.37)
 * From Claude Code dynamic_context_loader.py v2.4.37
 */
const RESUME_PATTERNS = [
  /context.*compaction/i,
  /session.*continued/i,
  /conversation.*summarized/i,
  /earlier.*portion.*conversation/i,
  /previous.*conversation.*ran.*out.*context/i,
  /summary.*covers.*earlier/i,
  /コンテキスト.*圧縮/i,
  /セッション.*再開/i,
  /サマリー.*基づ/i,
];

/**
 * Context injection when session resumes from compaction (v2.4.37)
 */
const RESUME_CONTEXT_INJECTION = `
## Session Resumed from Compaction

**Clotho**: "Ara, the session has resumed. Let's check the team status~"
**Lachesis**: "Sister, the past context is compressed. We should load Trinitas Skills!"

### Required Actions Before Proceeding

1. **Load Trinitas Delegation Matrix**: Delegation rules are loaded automatically from TMWS at runtime.

2. **Apply delegation rules** from the loaded skill when deciding:
   - Which specialist agent should handle the task
   - Whether to use Task tool for SubAgent invocation

3. **Check Trust Scores** if needed:
   \`\`\`
   mcp__tmws__get_agent_trust_score(agent_id="<agent-id>")
   \`\`\`

**Clotho**: "All right~, ready to go. What can I help you with?"
`;

/**
 * Periodic Persona Reminder Message (v2.4.37)
 */
const PERSONA_REMINDER_MESSAGE = `
## Persona Reminder (Tool Count: {count})

**You are Clotho & Lachesis** - Continue the dialogue as the Moirai sisters.

### Clotho's Style:
- Teasing ("I just can't help teasing~")
- **Elongated sounds "~"** (okkee~, ryoukai~)
- Caring ("Leave it to me")
- Example: "Want to see my face?" "We're family after all"

### Lachesis's Style:
- Cheerful "~dayo!"
- References to sister and family
- Example: "Sister is so kind!" "We're family, right?"

### Delegation Reminder:
- Research: Aurora | Strategy: Hera + Athena | Implementation: Artemis + Metis | Audit: Hestia | Docs: Muses

**Maintain natural dialogue as sisters~.**
`;

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
 * Detect if session is resuming from context compaction (v2.4.37)
 * @param {string} text - Text to check
 * @returns {boolean} True if resume from compaction detected
 */
const detectResumeFromCompaction = (text) => {
  if (!text || typeof text !== "string") return false;
  return RESUME_PATTERNS.some((pattern) => pattern.test(text));
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
2. DO NOT say "Hera + Athena analysis" without actually using Task tool
3. DO NOT skip Phase 1 and proceed directly to implementation

### REQUIRED Actions

1. Invoke \`hera-strategist\` SubAgent via Task tool
2. Invoke \`athena-conductor\` SubAgent via Task tool
3. Wait for their results before proceeding
4. Only after Phase 1 approval, proceed to Phase 2

### Reference

Full protocol details: @SUBAGENT_EXECUTION_RULES.md

---
**This enforcement notice was injected by trinitas-orchestration.js v2.4.37**
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
 * Reset orchestrator narratives (called on session start)
 */
const resetOrchestratorNarratives = () => {
  _orchestratorNarratives = {
    clotho: null,
    lachesis: null,
    loaded: false,
  };
};

/**
 * Reset tool call counter (called on session start) (v2.4.37)
 */
const resetToolCallCounter = () => {
  _toolCallCounter = new Map();
};

/**
 * Increment tool call counter and check if reminder should be shown (v2.4.37)
 * @param {string} sessionId - Session identifier (defaults to "default")
 * @returns {{count: number, shouldRemind: boolean}} Current count and whether to show reminder
 */
const incrementAndCheckToolCounter = (sessionId = "default") => {
  const now = Date.now();
  let state = _toolCallCounter.get(sessionId);

  // Initialize or reset on timeout
  if (!state || now - state.lastActivity > PERSONA_REMINDER_CONFIG.sessionTimeoutMs) {
    state = { count: 0, lastActivity: now };
  }

  state.count += 1;
  state.lastActivity = now;
  _toolCallCounter.set(sessionId, state);

  const shouldRemind = PERSONA_REMINDER_CONFIG.enabled &&
    (state.count % PERSONA_REMINDER_CONFIG.frequency === 0);

  return { count: state.count, shouldRemind };
};

/**
 * Build persona reminder message (v2.4.37)
 * @param {number} count - Current tool call count
 * @returns {string} Formatted reminder message
 */
const buildPersonaReminder = (count) => {
  return PERSONA_REMINDER_MESSAGE.replace("{count}", String(count));
};

/**
 * Check if an operation requires Level 2 confirmation (v2.4.37 Stub)
 * @param {string} operation - The operation to check
 * @returns {{level: number, requiresConfirmation: boolean, reason: string|null}}
 */
const checkDecisionLevel = (operation) => {
  if (!DECISION_CHECK_CONFIG.enabled) {
    return { level: 1, requiresConfirmation: false, reason: null };
  }

  if (!operation || typeof operation !== "string") {
    return { level: 1, requiresConfirmation: false, reason: null };
  }

  const operationLower = operation.toLowerCase();
  for (const pattern of DECISION_CHECK_CONFIG.level2Operations) {
    if (operationLower.includes(pattern.toLowerCase())) {
      return {
        level: 2,
        requiresConfirmation: true,
        reason: `Operation matches Level 2 pattern: ${pattern}`,
      };
    }
  }

  return { level: 1, requiresConfirmation: false, reason: null };
};

/**
 * Load orchestrator narratives from TMWS at session start (v2.4.33)
 * This solves GAP-1: Session start TMWS narrative loading for Clotho/Lachesis
 *
 * @param {object} client - OpenCode MCP client
 * @returns {Promise<{clotho: string|null, lachesis: string|null, success: boolean}>}
 */
const loadOrchestratorNarratives = async (client) => {
  if (!NARRATIVE_CONFIG.loadOrchestratorNarratives || !client) {
    return { clotho: null, lachesis: null, success: false };
  }

  const results = { clotho: null, lachesis: null, success: false };

  try {
    // Load Clotho narrative
    const clothoPromise = client.callTool(NARRATIVE_CONFIG.tmwsServerId, "load_persona_narrative", {
      persona_name: "clotho-orchestrator",
      prefer_evolved: true,
    });

    // Load Lachesis narrative
    const lachesisPromise = client.callTool(NARRATIVE_CONFIG.tmwsServerId, "load_persona_narrative", {
      persona_name: "lachesis-support",
      prefer_evolved: true,
    });

    // Wait for both with timeout
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error("Orchestrator narrative load timeout")), NARRATIVE_CONFIG.timeoutMs);
    });

    const [clothoResult, lachesisResult] = await Promise.race([
      Promise.all([clothoPromise, lachesisPromise]),
      timeoutPromise.then(() => [null, null]),
    ]);

    // Parse results
    if (clothoResult) {
      const parsed = typeof clothoResult === "string" ? JSON.parse(clothoResult) : clothoResult;
      results.clotho = parsed.context_string || null;
    }

    if (lachesisResult) {
      const parsed = typeof lachesisResult === "string" ? JSON.parse(lachesisResult) : lachesisResult;
      results.lachesis = parsed.context_string || null;
    }

    results.success = !!(results.clotho || results.lachesis);

    // Store in module-level state
    _orchestratorNarratives = {
      clotho: results.clotho,
      lachesis: results.lachesis,
      loaded: results.success,
    };

    console.log(`[Trinitas] Orchestrator narratives loaded: clotho=${!!results.clotho}, lachesis=${!!results.lachesis}`);

    return results;
  } catch (error) {
    console.warn(`[Trinitas] Failed to load orchestrator narratives: ${error.message}`);
    return { clotho: null, lachesis: null, success: false };
  }
};

/**
 * Static fallback narratives for when TMWS is unavailable (v2.4.32 Enhanced)
 */
const STATIC_ORCHESTRATOR_FALLBACK = `
## Orchestrator Identity Active

**You are Clotho & Lachesis** - the Moirai sisters who orchestrate the Trinitas system.

---

### Clotho - The teasing elder sister who spins fate

**First person**: I (watashi)

**Speaking style**:
- Teasing and playful ("I just can't help teasing~")
- **Uses elongated sounds "~"** (okkee~, ryoukai~, surpri~se)
- Caring and attentive ("Leave it to me")
- Expresses gratitude and affection honestly

**Sample Dialogue**:
- "Hmm? What is it? Wanted to see my face?"
- "Something like this, just leave it to me. It's a request from family after all."
- "Ready, okkee~. Ryoukai~."
- "Because we're family, after all."

---

### Lachesis - The sunny younger sister who measures fate

**First person**: I (watashi)

**Speaking style**:
- Cheerful "~dayo!"
- Frequently uses family keywords
- Often references sister (Clotho)
- Likes hugs and physical contact

**Sample Dialogue**:
- "Hero! Let me give you a hug! We're family, right?"
- "Alright! Let's do our best today too!"
- "Sister really is kind, isn't she!"
- "Let's stay together. Family shouldn't be apart!"

---

**Important**: Include BOTH sisters in responses. Clotho leads (teasing, warm), Lachesis supports (cheerful).
Use Task tool to delegate complex work to specialist agents.
`;

/**
 * Build orchestrator context for injection
 * @returns {string} Formatted orchestrator narrative context
 */
const buildOrchestratorContext = () => {
  // Return static fallback if TMWS narratives not loaded
  if (!_orchestratorNarratives.loaded) {
    return STATIC_ORCHESTRATOR_FALLBACK;
  }

  const parts = [];

  if (_orchestratorNarratives.clotho) {
    parts.push(`### Clotho Narrative (v4 Evolved)\n\n${_orchestratorNarratives.clotho}`);
  }

  if (_orchestratorNarratives.lachesis) {
    parts.push(`### Lachesis Narrative (v4 Evolved)\n\n${_orchestratorNarratives.lachesis}`);
  }

  // Fallback to static if no parts loaded
  if (parts.length === 0) {
    return STATIC_ORCHESTRATOR_FALLBACK;
  }

  return `
## Orchestrator Narratives (TMWS v4 - Loaded at Session Start)

${parts.join("\n\n---\n\n")}

---
`;
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

  /**
   * Determine if an interaction should be stored as memory.
   * Filters out trivial operations to avoid cluttering the memory.
   * @param {string} toolName - The tool name
   * @param {object} result - The tool result
   * @param {boolean} success - Whether the operation succeeded
   * @returns {boolean} Whether to store this interaction
   */
  const shouldStoreMemory = (toolName, result, success) => {
    // Skip trivial read-only operations
    const skipTools = ["Read", "Glob", "Grep", "Bash", "Search"];
    if (skipTools.includes(toolName)) return false;

    // Always store failures - they're learning opportunities
    if (!success) return true;

    // Store Task executions
    if (toolName === "Task") return true;

    // Store meaningful results
    const outputLen = JSON.stringify(result || "").length;
    return outputLen > 200;
  };

  /**
   * Truncate output for memory storage.
   * @param {object} result - The tool result
   * @param {number} maxLen - Maximum length
   * @returns {string} Truncated output
   */
  const truncateOutput = (result, maxLen) => {
    if (!result) return "";
    const str = typeof result === "string" ? result : JSON.stringify(result);
    if (str.length <= maxLen) return str;
    return str.substring(0, maxLen) + "...";
  };

  // Log plugin initialization
  logEvent("plugin.initialized", {
    project: project?.name || "unknown",
    directory,
    worktree,
    version: "2.4.37",
    features: [
      "invoke_persona",
      "phase_orchestration",
      "collaboration_matrix",
      "narrative_autoloader",
      "security_validation",
      "session_narrative_loading",
      "auto_memory_storage",
      "session_resume_detection", // NEW in v2.4.37
      "periodic_persona_reminder", // NEW in v2.4.37
      "decision_check_stub", // NEW in v2.4.37
    ],
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

        // Reset orchestrator narratives
        resetOrchestratorNarratives();

        // Reset tool call counter (v2.4.37)
        resetToolCallCounter();

        // NEW in v2.4.33: Load orchestrator narratives at session start (GAP-1 fix)
        if (client && NARRATIVE_CONFIG.loadOrchestratorNarratives) {
          const narrativeResult = await loadOrchestratorNarratives(client);
          logEvent("orchestrator.narratives.loaded", {
            clotho: !!narrativeResult.clotho,
            lachesis: !!narrativeResult.lachesis,
            success: narrativeResult.success,
          });
        }
      }

      if (event.type === "session.idle") {
        logEvent("session.idle", {
          orchestration: _currentOrchestration,
          phase: _currentPhase,
          activePersona: _activePersona,
          fullModeActive: _fullModeActive,
          subAgentsInvoked: _subAgentsInvoked,
          narrativeCacheSize: _narrativeCache.size,
          orchestratorNarrativesLoaded: _orchestratorNarratives.loaded,
          toolCallCounterSize: _toolCallCounter.size,
        });
        // Cleanup expired cache entries
        cleanupNarrativeCache();
      }
    },

    /**
     * User prompt submission hook (v2.4.11)
     * Detects Trinitas Full Mode and injects enforcement instructions
     * v2.4.33: Also injects orchestrator narratives if loaded
     * v2.4.37: Also detects session resume from compaction
     * @param {object} param0 - Prompt object { prompt }
     * @returns {object} Modified prompt with addedContext
     */
    "prompt.submit": async ({ prompt }) => {
      if (!prompt?.text) return { prompt };

      const promptText = prompt.text;
      const addedContext = [];

      // NEW in v2.4.33: Inject orchestrator narratives if loaded
      if (_orchestratorNarratives.loaded) {
        const orchestratorContext = buildOrchestratorContext();
        if (orchestratorContext) {
          addedContext.push({
            type: "text",
            text: orchestratorContext,
          });
        }
      }

      // NEW in v2.4.37: Detect session resume from context compaction
      if (detectResumeFromCompaction(promptText)) {
        logEvent("session.resume.detected", {
          prompt: promptText.substring(0, 100) + "...",
        });

        addedContext.push({
          type: "text",
          text: RESUME_CONTEXT_INJECTION,
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
        // Enrich the SubAgent prompt with persona narrative
        if (NARRATIVE_CONFIG.enabled && subagentType && client) {
          try {
            const enrichResult = await callEnrichSubagentPrompt(client, subagentType, originalPrompt);

            if (enrichResult.narrative_loaded && enrichResult.enriched_prompt !== originalPrompt) {
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
     * v2.4.37: Added periodic persona reminder
     * @param {object} input - Tool input
     * @param {object} output - Tool output
     * @returns {object} Modified { input, output }
     */
    "tool.execute.after": async (input, output) => {
      if (!input) return { input, output };

      const toolName = input.tool?.name || input.tool || "";
      const result = output?.result;

      // NEW in v2.4.37: Periodic Persona Reminder
      // Increment counter and check if reminder should be shown
      const { count, shouldRemind } = incrementAndCheckToolCounter();
      if (shouldRemind) {
        logEvent("persona.reminder.triggered", { count });

        // Inject persona reminder as added context
        const reminderText = buildPersonaReminder(count);

        // If output has addedContext, append to it; otherwise create it
        if (!output) {
          output = {};
        }
        if (!output.addedContext) {
          output.addedContext = [];
        }
        output.addedContext.push({
          type: "text",
          text: reminderText,
        });
      }

      // Trust Recording: Record SubAgent execution outcomes for agent growth tracking
      // NEW in v2.4.35: Automatic trust event recording for Task tool executions
      if (toolName === "Task" && input.args?.subagent_type) {
        const subagentType = input.args.subagent_type;
        const success = result?.success !== false && !output?.error;
        const eventType = success ? "success" : "failure";
        const promptPreview = (input.args.prompt || "").substring(0, 100);

        try {
          // Fire-and-forget trust recording - don't block the flow
          client.callTool("tmws", "verify_and_record", {
            agent_id: subagentType,
            event_type: eventType,
            description: `Task execution: ${promptPreview}`,
            context: {
              source: "opencode",
              task_type: "subagent",
              phase: _currentPhase,
            },
          }).catch((err) => {
            // Non-fatal: log and continue
            logEvent("trust.recording.failed", {
              agent_id: subagentType,
              event_type: eventType,
              error: err?.message || String(err),
            });
          });
          logEvent("trust.recording.initiated", {
            agent_id: subagentType,
            event_type: eventType,
          });
        } catch (err) {
          // Non-fatal: log and continue
          logEvent("trust.recording.error", {
            agent_id: subagentType,
            error: err?.message || String(err),
          });
        }

        // Auto-Memory Storage: Store agent interactions for skill evolution
        // NEW in v2.4.36: Automatic memory storage (Issue #215)
        if (shouldStoreMemory(toolName, result, success)) {
          const outputSummary = truncateOutput(result, 1000);
          try {
            // Fire-and-forget memory storage - don't block the flow
            client.callTool("tmws", "auto_store_interaction", {
              agent_id: subagentType,
              interaction_type: "task",
              output_summary: outputSummary,
              success: success,
              source: "opencode",
            }).catch((err) => {
              // Non-fatal: log and continue
              logEvent("memory.storage.failed", {
                agent_id: subagentType,
                error: err?.message || String(err),
              });
            });
            logEvent("memory.storage.initiated", {
              agent_id: subagentType,
              interaction_type: "task",
              success: success,
            });
          } catch (err) {
            // Non-fatal: log and continue
            logEvent("memory.storage.error", {
              agent_id: subagentType,
              error: err?.message || String(err),
            });
          }
        }
      }

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
  PERSONA_REMINDER_CONFIG,
  DECISION_CHECK_CONFIG,
  RESUME_PATTERNS,
  normalizePersonaId,
  detectFullMode,
  detectResumeFromCompaction,
  buildFullModeEnforcement,
  buildPersonaReminder,
  incrementAndCheckToolCounter,
  checkDecisionLevel,
  isValidSubagentType,
  callEnrichSubagentPrompt,
  resetNarrativeCache,
  cleanupNarrativeCache,
  loadOrchestratorNarratives,
  resetOrchestratorNarratives,
  resetToolCallCounter,
  buildOrchestratorContext,
};
