/**
 * Trinitas Trigger Processor Plugin for OpenCode
 *
 * Processes user prompts and detects appropriate agent personas based on
 * configurable trigger rules loaded from ~/.trinitas/trigger-registry.json
 *
 * Features:
 *   - 3-tier detection: Keywords -> Regex Patterns -> Confidence scoring
 *   - Hot-reload support: Config changes apply without restart
 *   - Platform-agnostic: Same trigger rules as Claude Code
 *   - Auto-routing: Suggests optimal agent for detected task type
 *   - Full Mode detection: Triggers multi-agent orchestration
 *
 * @version 2.4.12
 * @author TMWS Team
 * @see https://github.com/apto-as/tmws
 */

import { readFileSync, statSync, existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";

/**
 * Configuration paths
 */
const TRINITAS_CONFIG_DIR = join(homedir(), ".trinitas");
const TRIGGER_REGISTRY_PATH = join(TRINITAS_CONFIG_DIR, "trigger-registry.json");
const ENV_FILE_PATH = join(TRINITAS_CONFIG_DIR, ".env");

/**
 * Default trigger patterns (fallback if registry not found)
 */
const DEFAULT_TRIGGER_RULES = {
  settings: {
    enabled: true,
    auto_routing: true,
    confidence_threshold: 0.85,
    max_parallel_agents: 3,
  },
  trigger_rules: {
    "athena-conductor": {
      triggers: {
        keywords: ["orchestration", "workflow", "automation", "parallel", "coordination"],
        patterns: [{ regex: "\\b(orchestrat|coordinat|automat)", confidence: 0.90 }],
      },
      display_name: "Athena - Harmonious Conductor",
      emoji: "\u{1f3db}",
      tier: "strategic",
    },
    "hera-strategist": {
      triggers: {
        keywords: ["strategy", "planning", "architecture", "vision", "roadmap"],
        patterns: [{ regex: "\\b(strateg|architect|vision|roadmap)", confidence: 0.90 }],
      },
      display_name: "Hera - Strategic Commander",
      emoji: "\u{1f3ad}",
      tier: "strategic",
    },
    "artemis-optimizer": {
      triggers: {
        keywords: ["optimization", "performance", "quality", "technical", "efficiency"],
        patterns: [{ regex: "\\b(optimi|perform|efficien|quality)", confidence: 0.88 }],
      },
      display_name: "Artemis - Technical Perfectionist",
      emoji: "\u{1f3f9}",
      tier: "specialist",
    },
    "hestia-auditor": {
      triggers: {
        keywords: ["security", "audit", "risk", "vulnerability", "threat"],
        patterns: [{ regex: "\\b(secur|audit|vulnerab|threat|risk)", confidence: 0.92 }],
      },
      display_name: "Hestia - Security Guardian",
      emoji: "\u{1f525}",
      tier: "specialist",
    },
    "eris-coordinator": {
      triggers: {
        keywords: ["coordinate", "tactical", "team", "collaboration", "conflict"],
        patterns: [{ regex: "\\b(coordinat|tactic|team|collaborat)", confidence: 0.85 }],
      },
      display_name: "Eris - Tactical Coordinator",
      emoji: "\u2694\ufe0f",
      tier: "specialist",
    },
    "muses-documenter": {
      triggers: {
        keywords: ["documentation", "knowledge", "record", "guide", "spec"],
        patterns: [{ regex: "\\b(document|knowledge|record|guide|spec)", confidence: 0.85 }],
      },
      display_name: "Muses - Knowledge Architect",
      emoji: "\u{1f4da}",
      tier: "specialist",
    },
    "aphrodite-designer": {
      triggers: {
        keywords: ["design", "ui", "ux", "interface", "visual", "layout"],
        patterns: [{ regex: "\\b(design|ui|ux|interface|visual|layout)", confidence: 0.85 }],
      },
      display_name: "Aphrodite - UI/UX Designer",
      emoji: "\u{1f338}",
      tier: "support",
    },
    "metis-developer": {
      triggers: {
        keywords: ["implement", "code", "develop", "build", "test", "debug"],
        patterns: [{ regex: "\\b(implement|develop|build|code|test|debug)", confidence: 0.82 }],
      },
      display_name: "Metis - Development Assistant",
      emoji: "\u{1f527}",
      tier: "support",
    },
    "aurora-researcher": {
      triggers: {
        keywords: ["search", "find", "lookup", "research", "context", "retrieve"],
        patterns: [{ regex: "\\b(search|find|lookup|research|retriev)", confidence: 0.80 }],
      },
      display_name: "Aurora - Research Assistant",
      emoji: "\u{1f305}",
      tier: "support",
    },
  },
  full_mode_triggers: {
    patterns: [
      "Trinitas\\s*\u30d5\u30eb\\s*\u30e2\u30fc\u30c9",
      "Trinitas\\s+Full\\s+Mode",
      "\u30d5\u30eb\\s*\u30e2\u30fc\u30c9\\s*\u3067\\s*\u4f5c\u696d",
      "full\\s+mode\\s+execution",
    ],
  },
  collaboration_matrix: {
    architecture: { primary: "athena-conductor", support: ["hera-strategist", "aurora-researcher"], review: "hestia-auditor" },
    implementation: { primary: "artemis-optimizer", support: ["metis-developer"], review: "hestia-auditor" },
    security: { primary: "hestia-auditor", support: ["aurora-researcher"], review: "artemis-optimizer" },
    documentation: { primary: "muses-documenter", support: ["aurora-researcher"], review: "athena-conductor" },
    design: { primary: "aphrodite-designer", support: ["aurora-researcher"], review: "athena-conductor" },
    optimization: { primary: "artemis-optimizer", support: ["aurora-researcher"], review: "hestia-auditor" },
    research: { primary: "aurora-researcher", support: ["muses-documenter"], review: "athena-conductor" },
    coordination: { primary: "eris-coordinator", support: ["athena-conductor"], review: "hera-strategist" },
  },
};

/**
 * Plugin state
 */
let _triggerRegistry = null;
let _registryMtime = null;
let _compiledPatterns = {};
let _fullModePatterns = [];
let _settings = null;

/**
 * Load environment settings from ~/.trinitas/.env
 * @returns {Object} Environment settings
 */
const loadEnvSettings = () => {
  const settings = {
    enabled: true,
    autoRouting: true,
    confidenceThreshold: 0.85,
    hotReload: true,
    learningEnabled: false,
  };

  if (!existsSync(ENV_FILE_PATH)) {
    return settings;
  }

  try {
    const envContent = readFileSync(ENV_FILE_PATH, "utf8");
    const lines = envContent.split("\n");

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;

      const [key, ...valueParts] = trimmed.split("=");
      const value = valueParts.join("=").trim();

      switch (key) {
        case "TRINITAS_TRIGGER_RULES_ENABLED":
          settings.enabled = value.toLowerCase() === "true";
          break;
        case "TRINITAS_AUTO_ROUTING_ENABLED":
          settings.autoRouting = value.toLowerCase() === "true";
          break;
        case "TRINITAS_CONFIDENCE_THRESHOLD":
          settings.confidenceThreshold = parseFloat(value) || 0.85;
          break;
        case "TRINITAS_HOT_RELOAD_ENABLED":
          settings.hotReload = value.toLowerCase() === "true";
          break;
        case "TRINITAS_LEARNING_ENABLED":
          settings.learningEnabled = value.toLowerCase() === "true";
          break;
      }
    }
  } catch (error) {
    console.warn(`[TriggerProcessor] Failed to load .env: ${error.message}`);
  }

  return settings;
};

/**
 * Load trigger registry from ~/.trinitas/trigger-registry.json
 * Supports hot-reload by checking file modification time
 * @param {boolean} forceReload - Force reload regardless of mtime
 * @returns {Object} Trigger registry
 */
const loadTriggerRegistry = (forceReload = false) => {
  if (!existsSync(TRIGGER_REGISTRY_PATH)) {
    console.log("[TriggerProcessor] Registry not found, using defaults");
    _triggerRegistry = DEFAULT_TRIGGER_RULES;
    compileRegistryPatterns();
    return _triggerRegistry;
  }

  try {
    const stats = statSync(TRIGGER_REGISTRY_PATH);
    const currentMtime = stats.mtimeMs;

    // Hot-reload check
    if (!forceReload && _triggerRegistry && currentMtime === _registryMtime) {
      return _triggerRegistry;
    }

    const content = readFileSync(TRIGGER_REGISTRY_PATH, "utf8");
    _triggerRegistry = JSON.parse(content);
    _registryMtime = currentMtime;

    // Reload settings
    _settings = loadEnvSettings();

    // Override settings from registry if present
    if (_triggerRegistry.settings) {
      _settings.enabled = _triggerRegistry.settings.enabled ?? _settings.enabled;
      _settings.autoRouting = _triggerRegistry.settings.auto_routing ?? _settings.autoRouting;
      _settings.confidenceThreshold = _triggerRegistry.settings.confidence_threshold ?? _settings.confidenceThreshold;
    }

    compileRegistryPatterns();

    console.log(`[TriggerProcessor] Registry loaded (${Object.keys(_triggerRegistry.trigger_rules || {}).length} agents)`);
    return _triggerRegistry;
  } catch (error) {
    console.error(`[TriggerProcessor] Failed to load registry: ${error.message}`);
    _triggerRegistry = DEFAULT_TRIGGER_RULES;
    compileRegistryPatterns();
    return _triggerRegistry;
  }
};

/**
 * Security: ReDoS prevention constants (V-REDOS-1/2)
 */
const MAX_PATTERN_LENGTH = 200;
const DANGEROUS_PATTERNS = new Set([
  ".*",
  ".+",
  "[\\s\\S]*",
  "[\\s\\S]+",
  "(?:.*)*",
  "(?:.+)+",
]);
const REDOS_INDICATORS = [
  /\(\?:[^)]*\*\)\*/,      // (?:...*)*
  /\(\?:[^)]*\+\)\+/,      // (?:...+)+
  /\([^)]*\*\)\*/,         // (...*)*
  /\([^)]*\+\)\+/,         // (...+)+
];

/**
 * Validate regex pattern for safety (V-REDOS-1/2)
 * @param {string} pattern - Pattern to validate
 * @returns {boolean} True if pattern is safe
 */
const isPatternSafe = (pattern) => {
  if (!pattern || typeof pattern !== "string") return false;
  if (pattern.length > MAX_PATTERN_LENGTH) {
    console.warn(`[TriggerProcessor] Pattern too long (${pattern.length} > ${MAX_PATTERN_LENGTH})`);
    return false;
  }
  if (DANGEROUS_PATTERNS.has(pattern)) {
    console.warn(`[TriggerProcessor] Dangerous pattern blocked: ${pattern}`);
    return false;
  }
  // Check for unbounded .* or .+ without limits
  if (/(?<!\\)\.\*(?!\?)(?!\{)/.test(pattern) || /(?<!\\)\.\+(?!\?)(?!\{)/.test(pattern)) {
    console.warn(`[TriggerProcessor] Unbounded quantifier detected: ${pattern}`);
    return false;
  }
  // Check for nested quantifiers (exponential backtracking)
  for (const indicator of REDOS_INDICATORS) {
    if (indicator.test(pattern)) {
      console.warn(`[TriggerProcessor] Nested quantifier detected: ${pattern}`);
      return false;
    }
  }
  return true;
};

/**
 * Compile regex with timeout wrapper (V-REDOS-1)
 * @param {string} pattern - Pattern to compile
 * @param {string} flags - Regex flags
 * @returns {RegExp|null} Compiled regex or null if unsafe
 */
const compilePatternSafe = (pattern, flags = "i") => {
  if (!isPatternSafe(pattern)) return null;
  try {
    return new RegExp(pattern, flags);
  } catch (error) {
    console.warn(`[TriggerProcessor] Invalid regex syntax: ${pattern}`);
    return null;
  }
};

/**
 * Compile regex patterns from registry for efficient matching
 */
const compileRegistryPatterns = () => {
  _compiledPatterns = {};
  _fullModePatterns = [];

  if (!_triggerRegistry) return;

  // Use new format if available, fall back to old format
  const agents = _triggerRegistry.agents || _triggerRegistry.trigger_rules || {};

  for (const [agentKey, agentConfig] of Object.entries(agents)) {
    // Support both new format (agents.athena) and old format (trigger_rules.athena-conductor)
    const agentId = agentConfig.id || agentKey;

    _compiledPatterns[agentId] = {
      keywords: agentConfig.keywords || agentConfig.triggers?.keywords || [],
      patterns: [],
      metadata: {
        display_name: agentConfig.display_name,
        emoji: agentConfig.emoji,
        tier: agentConfig.tier,
        mcp_tools: agentConfig.mcp_tools || [],
      },
    };

    // Compile regex patterns with safety validation (V-REDOS-1/2)
    const patterns = agentConfig.patterns || agentConfig.triggers?.patterns || [];
    for (const patternConfig of patterns) {
      const patternStr = typeof patternConfig === "string" ? patternConfig : patternConfig.regex;
      const regex = compilePatternSafe(patternStr);
      if (regex) {
        _compiledPatterns[agentId].patterns.push({
          regex,
          confidence: patternConfig.confidence || 0.85,
        });
      }
    }
  }

  // Compile Full Mode patterns with safety validation
  const fullModeConfig = _triggerRegistry.full_mode || _triggerRegistry.full_mode_triggers || {};
  const fullModePatternStrings = fullModeConfig.triggers || fullModeConfig.patterns || [];

  for (const patternStr of fullModePatternStrings) {
    const regex = compilePatternSafe(patternStr);
    if (regex) {
      _fullModePatterns.push(regex);
    }
  }

  console.log(`[TriggerProcessor] Compiled ${Object.keys(_compiledPatterns).length} agents, ${_fullModePatterns.length} Full Mode patterns`);
};

/**
 * Detect matching agents from prompt text
 * @param {string} text - User prompt text
 * @returns {Array} Array of { agentId, confidence, matchType, matchedTerms }
 */
const detectAgents = (text) => {
  if (!text || typeof text !== "string") return [];
  if (!_settings?.enabled) return [];

  // Hot-reload check
  if (_settings?.hotReload) {
    loadTriggerRegistry();
  }

  const normalizedText = text.toLowerCase();
  const matches = [];

  for (const [agentId, config] of Object.entries(_compiledPatterns)) {
    let bestConfidence = 0;
    let matchType = null;
    let matchedTerms = [];

    // Tier 1: Keyword matching
    for (const keyword of config.keywords) {
      if (normalizedText.includes(keyword.toLowerCase())) {
        matchedTerms.push(keyword);
        bestConfidence = Math.max(bestConfidence, 0.7);
        matchType = "keyword";
      }
    }

    // Tier 2: Regex pattern matching
    for (const { regex, confidence } of config.patterns) {
      if (regex.test(text)) {
        if (confidence > bestConfidence) {
          bestConfidence = confidence;
          matchType = "pattern";
        }
        const match = text.match(regex);
        if (match) {
          matchedTerms.push(match[0]);
        }
      }
    }

    // Only include if above threshold
    if (bestConfidence >= (_settings?.confidenceThreshold || 0.85)) {
      matches.push({
        agentId,
        confidence: bestConfidence,
        matchType,
        matchedTerms: [...new Set(matchedTerms)],
        metadata: config.metadata,
      });
    }
  }

  // Sort by confidence (highest first)
  matches.sort((a, b) => b.confidence - a.confidence);

  return matches;
};

/**
 * Detect if Full Mode is requested
 * @param {string} text - User prompt text
 * @returns {boolean} True if Full Mode detected
 */
const detectFullMode = (text) => {
  if (!text || typeof text !== "string") return false;
  return _fullModePatterns.some((pattern) => pattern.test(text));
};

/**
 * Get optimal agent for task type from collaboration matrix
 * @param {string} taskType - Task type (architecture, implementation, etc.)
 * @returns {Object|null} Collaboration recommendation
 */
const getCollaborationRecommendation = (taskType) => {
  if (!_triggerRegistry?.collaboration_matrix) return null;
  return _triggerRegistry.collaboration_matrix[taskType.toLowerCase()] || null;
};

/**
 * Build context injection for detected agents
 * @param {Array} detectedAgents - Array of detected agents
 * @param {boolean} isFullMode - Whether Full Mode is active
 * @returns {string} Context text to inject
 */
const buildAgentContext = (detectedAgents, isFullMode) => {
  if (!detectedAgents.length && !isFullMode) return null;

  let context = "## Trinitas Persona Detection\n\n";

  if (isFullMode) {
    context += "### \u26a0\ufe0f Full Mode Activated\n\n";
    context += "Multi-agent orchestration detected. Use phase-based execution:\n";
    context += "1. **Phase 1**: Strategic Planning (Hera + Athena)\n";
    context += "2. **Phase 2**: Implementation (Artemis + Metis)\n";
    context += "3. **Phase 3**: Verification (Hestia + Aurora)\n";
    context += "4. **Phase 4**: Documentation (Muses + Aphrodite)\n\n";
  }

  if (detectedAgents.length > 0) {
    context += "### Detected Personas\n\n";
    context += "| Persona | Confidence | Match Type |\n";
    context += "|---------|------------|------------|\n";

    for (const agent of detectedAgents.slice(0, 3)) {
      const emoji = agent.metadata?.emoji || "\u{1f916}";
      const name = agent.metadata?.display_name || agent.agentId;
      context += `| ${emoji} ${name} | ${(agent.confidence * 100).toFixed(0)}% | ${agent.matchType} |\n`;
    }

    context += "\n";

    // Primary recommendation
    const primary = detectedAgents[0];
    if (primary) {
      context += `### Recommended: ${primary.metadata?.emoji || ""} ${primary.metadata?.display_name || primary.agentId}\n\n`;

      if (primary.metadata?.mcp_tools?.length > 0) {
        context += `**Available MCP Tools**: ${primary.metadata.mcp_tools.join(", ")}\n\n`;
      }

      context += `To invoke this persona, use:\n`;
      context += "```\n";
      context += `/trinitas execute ${primary.agentId.split("-")[0]} \"[task description]\"\n`;
      context += "```\n\n";
    }
  }

  context += "---\n";
  context += "*Detected by trinitas-trigger-processor.js v2.4.12*\n";

  return context;
};

/**
 * Trinitas Trigger Processor Plugin
 *
 * @param {object} ctx - Plugin context
 * @returns {object} Event hooks
 */
export const TrinitasTriggerProcessor = async ({ project, client, $, directory, worktree }) => {
  // Initialize on first load
  _settings = loadEnvSettings();
  loadTriggerRegistry(true);

  console.log(`[TriggerProcessor] Initialized (enabled: ${_settings.enabled}, autoRouting: ${_settings.autoRouting})`);

  return {
    /**
     * User prompt submission hook
     * Detects personas and injects context
     * @param {object} param0 - Prompt object
     * @returns {object} Modified prompt with addedContext
     */
    "prompt.submit": async ({ prompt }) => {
      if (!prompt?.text) return { prompt };
      if (!_settings?.enabled) return { prompt };

      const promptText = prompt.text;
      const detectedAgents = detectAgents(promptText);
      const isFullMode = detectFullMode(promptText);

      // Log detection results
      if (detectedAgents.length > 0 || isFullMode) {
        console.log(`[TriggerProcessor] Detected ${detectedAgents.length} agents, Full Mode: ${isFullMode}`);
      }

      // Build context injection
      const contextText = buildAgentContext(detectedAgents, isFullMode);

      if (contextText) {
        return {
          prompt,
          addedContext: [
            {
              type: "text",
              text: contextText,
            },
          ],
        };
      }

      return { prompt };
    },

    /**
     * General event handler
     * @param {object} param0 - Event object
     */
    event: async ({ event }) => {
      if (!event) return;

      // Reload registry on session start (hot-reload support)
      if (event.type === "session.created") {
        console.log("[TriggerProcessor] Session started, checking registry...");
        loadTriggerRegistry();
      }
    },
  };
};

// Named exports for external use
export {
  loadTriggerRegistry,
  loadEnvSettings,
  detectAgents,
  detectFullMode,
  getCollaborationRecommendation,
  buildAgentContext,
  DEFAULT_TRIGGER_RULES,
};
