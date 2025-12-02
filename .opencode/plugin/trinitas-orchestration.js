/**
 * Trinitas Orchestration Plugin for OpenCode
 *
 * Provides phase-based workflow orchestration with agent coordination
 * through TMWS MCP integration.
 *
 * Features:
 * - Automatic phase tracking
 * - Agent coordination notifications
 * - Quality checkpoints
 * - Progress monitoring
 *
 * @version 2.4.8
 * @author TMWS Team
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
    agents: [], // Dynamically assigned
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
};

/**
 * Pattern matchers for task type detection
 */
const TASK_PATTERNS = {
  architecture: /\b(architect|design|structure|system|component)\b/i,
  implementation: /\b(implement|develop|build|code|fix|create)\b/i,
  security: /\b(security|audit|vulnerab|threat|risk|compliance)\b/i,
  documentation: /\b(document|guide|manual|readme|spec|api doc)\b/i,
  design: /\b(ui|ux|interface|visual|layout|style)\b/i,
  optimization: /\b(optimi|perform|speed|effici|cache)\b/i,
  testing: /\b(test|coverage|quality|assert)\b/i,
};

/**
 * Detect task type from content
 * @param {string} content - Task description
 * @returns {string} Detected task type
 */
function detectTaskType(content) {
  for (const [type, pattern] of Object.entries(TASK_PATTERNS)) {
    if (pattern.test(content)) {
      return type;
    }
  }
  return "implementation"; // Default
}

/**
 * Get recommended agents for a task
 * @param {string} taskType - Type of task
 * @returns {object} Agent recommendations
 */
function getRecommendedAgents(taskType) {
  return COLLABORATION_MATRIX[taskType] || COLLABORATION_MATRIX.implementation;
}

/**
 * Format phase status for display
 * @param {object} phase - Phase configuration
 * @param {string} status - Current status
 * @returns {string} Formatted status string
 */
function formatPhaseStatus(phase, status) {
  const statusEmoji = {
    pending: "⏳",
    in_progress: "🔄",
    completed: "✅",
    approved: "✅",
    rejected: "❌",
    failed: "❌",
  };
  const emoji = statusEmoji[status] || "⏳";
  return `${emoji} ${phase.name}: ${status}`;
}

/**
 * Trinitas Orchestration Plugin
 *
 * Integrates phase-based execution with OpenCode's event system.
 *
 * @param {object} context - OpenCode plugin context
 * @returns {object} Event handlers
 */
export const TrinitasOrchestration = async (context) => {
  // Plugin state
  let currentOrchestration = null;
  let currentPhase = null;

  /**
   * Log orchestration event
   * @param {string} event - Event name
   * @param {object} data - Event data
   */
  const logEvent = (event, data) => {
    console.log(`[Trinitas] ${event}:`, JSON.stringify(data, null, 2));
  };

  return {
    /**
     * Handle general events
     */
    event: async (data) => {
      // Log significant events
      if (data.type === "orchestration" || data.type === "phase") {
        logEvent(data.type, data);
      }
    },

    /**
     * Pre-tool execution hook
     * Validates tool calls against current phase constraints
     */
    "tool.execute.before": async (input, output) => {
      const toolName = input.tool?.name || "";

      // Check if this is a TMWS orchestration tool
      if (toolName.startsWith("create_orchestration")) {
        logEvent("orchestration.create", { input });
      }

      // Phase validation for specific tools
      if (currentPhase && toolName.includes("execute_phase")) {
        const expectedAgents = PHASES[currentPhase]?.agents || [];
        if (expectedAgents.length > 0) {
          logEvent("phase.validation", {
            phase: currentPhase,
            expectedAgents,
            tool: toolName,
          });
        }
      }

      return { input, output };
    },

    /**
     * Post-tool execution hook
     * Updates orchestration state based on tool results
     */
    "tool.execute.after": async (input, output) => {
      const toolName = input.tool?.name || "";
      const result = output?.result;

      // Track orchestration creation
      if (toolName === "create_orchestration" && result?.success) {
        currentOrchestration = result.data?.orchestration_id;
        currentPhase = "STRATEGIC_PLANNING";
        logEvent("orchestration.created", {
          id: currentOrchestration,
          phase: currentPhase,
        });
      }

      // Track phase transitions
      if (toolName === "approve_phase" && result?.success) {
        const newPhase = result.data?.current_phase;
        if (newPhase) {
          const previousPhase = currentPhase;
          currentPhase = newPhase;
          logEvent("phase.transition", {
            from: previousPhase,
            to: newPhase,
            orchestration: currentOrchestration,
          });
        }
      }

      // Track orchestration completion
      if (result?.data?.status === "completed") {
        logEvent("orchestration.completed", {
          id: currentOrchestration,
        });
        currentOrchestration = null;
        currentPhase = null;
      }

      return { input, output };
    },

    /**
     * Message hook for agent coordination
     * Monitors inter-agent communication
     */
    "message.send": async (data) => {
      // Detect if message mentions agent coordination
      const content = data.content || "";
      const agentMentions = [];

      for (const tier of Object.values(AGENT_TIERS)) {
        for (const agent of tier) {
          if (content.toLowerCase().includes(agent.toLowerCase())) {
            agentMentions.push(agent);
          }
        }
      }

      if (agentMentions.length > 0) {
        logEvent("agent.coordination", {
          mentioned: agentMentions,
          inPhase: currentPhase,
        });
      }

      return data;
    },
  };
};

/**
 * Helper: Get current phase info
 * @returns {object|null} Current phase information
 */
export const getCurrentPhase = () => {
  return currentPhase ? PHASES[currentPhase] : null;
};

/**
 * Helper: Get phase by ID
 * @param {string} phaseId - Phase identifier
 * @returns {object|null} Phase configuration
 */
export const getPhaseById = (phaseId) => {
  for (const [key, phase] of Object.entries(PHASES)) {
    if (phase.id === phaseId) {
      return { key, ...phase };
    }
  }
  return null;
};

/**
 * Helper: Get agents by tier
 * @param {string} tier - Tier name (STRATEGIC, SPECIALIST, SUPPORT)
 * @returns {string[]} Agent list
 */
export const getAgentsByTier = (tier) => {
  return AGENT_TIERS[tier.toUpperCase()] || [];
};

/**
 * Helper: Detect optimal agent for task
 * @param {string} taskContent - Task description
 * @returns {object} Recommended agents
 */
export const detectOptimalAgent = (taskContent) => {
  const taskType = detectTaskType(taskContent);
  return {
    taskType,
    recommendation: getRecommendedAgents(taskType),
  };
};

// Export default plugin
export default TrinitasOrchestration;
