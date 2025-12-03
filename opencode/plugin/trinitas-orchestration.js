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
 * @version 2.4.11
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
## ⚠️ MANDATORY: Trinitas Full Mode Activated

**CRITICAL ENFORCEMENT NOTICE**

You have detected a Trinitas Full Mode request. You MUST now invoke SubAgents
using the Task tool. This is NOT optional.

### Phase 1: Strategic Planning (REQUIRED - INVOKE NOW)

You MUST immediately invoke the following SubAgents **in parallel** (single message, multiple Task tool calls):

\`\`\`
Task(subagent_type="hera-strategist", prompt="Strategic analysis for: ${safeTask}")
Task(subagent_type="athena-conductor", prompt="Resource coordination for: ${safeTask}")
\`\`\`

### ❌ PROHIBITED Actions

1. DO NOT proceed with analysis yourself without invoking SubAgents
2. DO NOT say "Hera + Athena による戦略分析" without actually using Task tool
3. DO NOT skip Phase 1 and proceed directly to implementation

### ✅ REQUIRED Actions

1. Invoke \`hera-strategist\` SubAgent via Task tool
2. Invoke \`athena-conductor\` SubAgent via Task tool
3. Wait for their results before proceeding
4. Only after Phase 1 approval, proceed to Phase 2

### Reference

Full protocol details: @SUBAGENT_EXECUTION_RULES.md

---
**This enforcement notice was injected by trinitas-orchestration.js v2.4.11**
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
    version: "2.4.11",
    features: ["invoke_persona", "phase_orchestration", "collaboration_matrix"],
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
      }

      if (event.type === "session.idle") {
        logEvent("session.idle", {
          orchestration: _currentOrchestration,
          phase: _currentPhase,
          activePersona: _activePersona,
          fullModeActive: _fullModeActive,
          subAgentsInvoked: _subAgentsInvoked,
        });
      }
    },

    /**
     * User prompt submission hook (v2.4.11)
     * Detects Trinitas Full Mode and injects enforcement instructions
     * @param {object} param0 - Prompt object { prompt }
     * @returns {object} Modified prompt with addedContext
     */
    "prompt.submit": async ({ prompt }) => {
      if (!prompt?.text) return { prompt };

      const promptText = prompt.text;

      // Check for Trinitas Full Mode
      if (detectFullMode(promptText)) {
        _fullModeActive = true;
        _subAgentsInvoked = false;

        logEvent("fullMode.detected", {
          prompt: promptText.substring(0, 100) + "...",
        });

        // Inject enforcement instructions
        const enforcement = buildFullModeEnforcement(promptText);

        return {
          prompt,
          addedContext: [
            {
              type: "text",
              text: enforcement,
            },
          ],
        };
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
      if (typeof toolName === "string" && toolName === "Task") {
        const subagentType = input.args?.subagent_type || input.subagent_type || "";
        const isStrategicAgent =
          subagentType === "hera-strategist" || subagentType === "athena-conductor";

        if (_fullModeActive && isStrategicAgent) {
          _subAgentsInvoked = true;
          logEvent("fullMode.subAgentInvoked", {
            subagentType,
            fullModeActive: _fullModeActive,
          });
        }

        logEvent("task.invoking", {
          subagentType,
          prompt: (input.args?.prompt || input.prompt || "").substring(0, 100),
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
  normalizePersonaId,
  detectFullMode,
  buildFullModeEnforcement,
};
