/**
 * Dynamic Context Loader Plugin for Open Code
 * Complements Claude Code Hooks functionality
 * Version: 1.0.0
 *
 * Responsibilities:
 * - Monitors tool execution patterns
 * - Provides context suggestions based on usage patterns
 * - Integrates with existing quality-enforcer and performance-monitor plugins
 */

export const DynamicContextLoader = async ({ project, client, $, directory, worktree }) => {
  console.log('🧠 Trinitas Dynamic Context Loader initialized');

  // Trigger patterns for context detection
  const TRIGGER_PATTERNS = {
    tmws: {
      keywords: ['tmws', 'memory', 'workflow', 'task', 'recall', 'remember'],
      threshold: 2,
      contextFiles: [
        'docs/tmws-integration.md',
        'trinitas_sources/tmws/01_tmws_commands.md'
      ]
    },
    security: {
      keywords: ['security', 'audit', 'vulnerability', 'exploit', 'xss', 'injection'],
      threshold: 1,
      contextFiles: [
        'docs/security-standards.md',
        'trinitas_sources/common/03_security_audit.md'
      ]
    },
    performance: {
      keywords: ['optimization', 'performance', 'bottleneck', 'profiling', 'slow', 'latency'],
      threshold: 2,
      contextFiles: [
        'docs/performance-guidelines.md',
        'trinitas_sources/common/02_performance_optimization.md'
      ]
    },
    coordination: {
      keywords: ['coordinate', 'team', 'parallel', 'workflow', 'orchestrat'],
      threshold: 1,
      contextFiles: [
        'docs/coordination-patterns.md',
        'AGENTS.md'
      ]
    }
  };

  // Persona detection patterns
  const PERSONA_PATTERNS = {
    athena: /\b(orchestr|workflow|automat|parallel|coordin|harmoniz)\w*/gi,
    artemis: /\b(optim|perform|quality|technical|efficien|refactor)\w*/gi,
    hestia: /\b(secur|audit|risk|vulnerab|threat|validat)\w*/gi,
    eris: /\b(coordinat|tactical|team|collaborat|mediat|priorit)\w*/gi,
    hera: /\b(strateg|planning|architect|vision|roadmap|command)\w*/gi,
    muses: /\b(document|knowledge|record|guide|archive|structur)\w*/gi
  };

  // Tracking state
  const state = {
    promptHistory: [],
    detectedContexts: new Set(),
    sessionStart: Date.now()
  };

  // Helper: Detect required contexts from prompt text
  const detectContexts = (text) => {
    const contexts = [];
    const lowerText = text.toLowerCase();

    for (const [category, config] of Object.entries(TRIGGER_PATTERNS)) {
      const matches = config.keywords.filter(kw => lowerText.includes(kw)).length;

      if (matches >= config.threshold) {
        contexts.push({
          category,
          files: config.contextFiles,
          relevance: matches / config.keywords.length,
          matchCount: matches
        });
      }
    }

    return contexts.sort((a, b) => b.relevance - a.relevance);
  };

  // Helper: Detect active personas
  const detectPersonas = (text) => {
    const personas = [];

    for (const [persona, pattern] of Object.entries(PERSONA_PATTERNS)) {
      const matches = text.match(pattern);
      if (matches && matches.length > 0) {
        personas.push({
          persona,
          matchCount: matches.length,
          keywords: matches.slice(0, 3) // Top 3 matched keywords
        });
      }
    }

    return personas.sort((a, b) => b.matchCount - a.matchCount);
  };

  // Helper: Generate context suggestion
  const generateContextSuggestion = (contexts, personas) => {
    if (contexts.length === 0 && personas.length === 0) {
      return null;
    }

    let suggestion = '## 🎯 Context Recommendations\n\n';

    if (personas.length > 0) {
      suggestion += '### Active Personas Detected\n';
      personas.slice(0, 2).forEach(p => {
        suggestion += `- **${p.persona.charAt(0).toUpperCase() + p.persona.slice(1)}**: ` +
                      `${p.matchCount} relevant keywords detected\n`;
      });
      suggestion += '\n';
    }

    if (contexts.length > 0) {
      suggestion += '### Recommended Documentation\n';
      contexts.slice(0, 2).forEach(ctx => {
        suggestion += `- **${ctx.category}** (relevance: ${(ctx.relevance * 100).toFixed(0)}%)\n`;
        ctx.files.forEach(file => {
          suggestion += `  - @${file}\n`;
        });
      });
    }

    return suggestion;
  };

  return {
    // Event monitoring
    event: async ({ event }) => {
      if (event.type === 'session.start') {
        state.sessionStart = Date.now();
        state.promptHistory = [];
        state.detectedContexts.clear();
        console.log('🧠 Dynamic context tracking initialized');
      }

      if (event.type === 'session.idle') {
        if (state.detectedContexts.size > 0) {
          console.log(`📊 Session context summary: ${Array.from(state.detectedContexts).join(', ')}`);
        }
      }
    },

    // Pre-tool execution: Analyze user prompts
    "tool.execute.before": async (input, output) => {
      // Extract prompt text from various tool inputs
      let promptText = '';

      if (input.tool === 'ask' && output.args?.prompt) {
        promptText = output.args.prompt;
      } else if (input.tool === 'task' && output.args?.prompt) {
        promptText = output.args.prompt;
      }

      if (promptText) {
        // Detect contexts and personas
        const contexts = detectContexts(promptText);
        const personas = detectPersonas(promptText);

        // Track detected contexts
        contexts.forEach(ctx => state.detectedContexts.add(ctx.category));

        // Log detected patterns
        if (contexts.length > 0) {
          console.log('🎯 Context triggers detected:', contexts.map(c => c.category).join(', '));
        }

        if (personas.length > 0) {
          console.log('👥 Active personas:', personas.map(p => p.persona).join(', '));
        }

        // Generate suggestion (informational only - does not modify flow)
        const suggestion = generateContextSuggestion(contexts, personas);
        if (suggestion) {
          console.log('\n' + suggestion);
        }

        // Store in history
        state.promptHistory.push({
          timestamp: Date.now(),
          text: promptText,
          contexts: contexts.map(c => c.category),
          personas: personas.map(p => p.persona)
        });

        // Keep history bounded
        if (state.promptHistory.length > 10) {
          state.promptHistory.shift();
        }
      }
    },

    // Custom command: Get context analysis
    "context.analyze": async () => {
      const recentContexts = state.promptHistory.slice(-5);

      if (recentContexts.length === 0) {
        return {
          message: "No prompts analyzed yet in this session"
        };
      }

      // Aggregate context usage
      const contextCounts = {};
      const personaCounts = {};

      recentContexts.forEach(entry => {
        entry.contexts.forEach(ctx => {
          contextCounts[ctx] = (contextCounts[ctx] || 0) + 1;
        });
        entry.personas.forEach(p => {
          personaCounts[p] = (personaCounts[p] || 0) + 1;
        });
      });

      return {
        summary: {
          totalPrompts: state.promptHistory.length,
          recentPrompts: recentContexts.length,
          uniqueContexts: new Set(Object.keys(contextCounts)).size,
          activePersonas: Object.keys(personaCounts)
        },
        contextFrequency: contextCounts,
        personaFrequency: personaCounts,
        sessionDuration: `${((Date.now() - state.sessionStart) / 1000 / 60).toFixed(1)}m`
      };
    }
  };
};

// Export as default for compatibility
export default DynamicContextLoader;
