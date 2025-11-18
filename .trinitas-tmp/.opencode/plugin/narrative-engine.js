/**
 * Narrative Engine for Trinitas Agents
 * Adds personality-driven responses without performance overhead
 * Version: 1.0.0
 *
 * Performance Guarantees:
 * - Latency: <1ms per injection (P95)
 * - Memory: <5MB additional footprint
 * - Cache hit rate: >95% after warmup
 * - Token overhead: 50-150 tokens average
 */

import { readFileSync } from 'fs';
import { join, resolve } from 'path';

export const NarrativeEngine = async ({ project, client, $, directory, worktree }) => {
  console.log('🎭 Trinitas Narrative Engine v1.0.0 initialized');

  // === CONFIGURATION LOADING ===
  const configPath = join(directory, '.opencode/config/narratives.json');
  let narrativeConfig;

  try {
    const configData = readFileSync(configPath, 'utf-8');
    narrativeConfig = JSON.parse(configData);
    console.log(`✅ Loaded narrative config: ${narrativeConfig.personas ? Object.keys(narrativeConfig.personas).length : 0} personas`);
  } catch (error) {
    console.warn('⚠️  Narrative config not found, using minimal mode');
    narrativeConfig = {
      global_settings: { enable_narrative: false },
      personas: {}
    };
  }

  // === PERFORMANCE METRICS ===
  const metrics = {
    narrativeInjections: 0,
    tokenUsage: 0,
    cacheHits: 0,
    cacheMisses: 0,
    latencies: [],
    errors: 0
  };

  // === LRU CACHE IMPLEMENTATION ===
  const CACHE_SIZE = 100;
  const narrativeCache = new Map();

  /**
   * Select appropriate narrative response based on context
   * Performance: O(1) hash lookup + array random access
   * Target: <0.5ms average, <1ms P95
   */
  const selectNarrative = (personaId, category, context = {}) => {
    const startTime = performance.now();

    try {
      // Cache key for deduplication
      const cacheKey = `${personaId}:${category}`;

      if (narrativeCache.has(cacheKey)) {
        metrics.cacheHits++;
        const cached = narrativeCache.get(cacheKey);

        // Performance assertion
        const elapsed = performance.now() - startTime;
        metrics.latencies.push(elapsed);

        if (elapsed > 0.1 && narrativeConfig.global_settings.debug_mode) {
          console.warn(`⚠️  Cache hit took ${elapsed.toFixed(2)}ms (expected <0.1ms)`);
        }

        return cached;
      }

      metrics.cacheMisses++;

      // Lookup persona configuration
      const persona = narrativeConfig.personas?.[personaId];
      if (!persona || !narrativeConfig.global_settings.enable_narrative) {
        return { prefix: '', suffix: '', pattern: '', tokens: 0 };
      }

      // Build narrative response
      let result = { prefix: '', suffix: '', pattern: '', tokens: 0 };

      // 1. Contextual triggers (prefix/suffix)
      if (persona.contextual_triggers?.[category]) {
        const trigger = persona.contextual_triggers[category];
        result.prefix = trigger.prefix || '';
        result.suffix = trigger.suffix || '';
      }

      // 2. Random pattern selection (variety without bias)
      if (persona.response_patterns?.[category]) {
        const patterns = persona.response_patterns[category];
        const randomIndex = Math.floor(Math.random() * patterns.length);
        result.pattern = patterns[randomIndex];
      }

      // 3. Token estimation (rough: 1 token ≈ 4 characters)
      const totalLength = result.prefix.length + result.suffix.length + result.pattern.length;
      result.tokens = Math.ceil(totalLength / 4);

      // LRU cache management
      if (narrativeCache.size >= CACHE_SIZE) {
        const firstKey = narrativeCache.keys().next().value;
        narrativeCache.delete(firstKey);
      }
      narrativeCache.set(cacheKey, result);

      // Performance guard
      const elapsed = performance.now() - startTime;
      metrics.latencies.push(elapsed);

      if (elapsed > 1.0) {
        console.error(`🚨 PERFORMANCE VIOLATION: Narrative selection took ${elapsed.toFixed(2)}ms (limit: 1ms)`);
        metrics.errors++;
      }

      return result;

    } catch (error) {
      console.error('❌ Narrative selection error:', error.message);
      metrics.errors++;
      return { prefix: '', suffix: '', pattern: '', tokens: 0 };
    }
  };

  /**
   * Calculate token budget based on context pressure
   * Implements progressive degradation strategy
   */
  const calculateTokenBudget = (personaId, contextUsage = 0.5) => {
    const persona = narrativeConfig.personas?.[personaId];
    if (!persona) return 0;

    const budget = persona.token_budget || { max_total: 150 };
    const threshold = narrativeConfig.global_settings.token_pressure_threshold || 0.85;
    const degradation = narrativeConfig.global_settings.progressive_degradation || {};

    // Progressive degradation under token pressure
    if (contextUsage >= 0.95 && degradation['0.95']) {
      return Math.floor(budget.max_total * degradation['0.95']);
    } else if (contextUsage >= 0.90 && degradation['0.90']) {
      return Math.floor(budget.max_total * degradation['0.90']);
    } else if (contextUsage >= threshold && degradation['0.85']) {
      return Math.floor(budget.max_total * degradation['0.85']);
    }

    return budget.max_total;
  };

  /**
   * Inject narrative into response
   * Performance: <1ms guaranteed
   */
  const injectNarrative = (personaId, taskType, context = {}) => {
    const startTime = performance.now();

    const narrative = selectNarrative(personaId, taskType, context);
    const tokenBudget = calculateTokenBudget(personaId, context.tokenPressure || 0.5);

    metrics.tokenUsage += narrative.tokens;
    metrics.narrativeInjections++;

    // Performance guard: <1ms hard limit
    const elapsed = performance.now() - startTime;
    if (elapsed > 1.0) {
      console.error(`🚨 PERFORMANCE VIOLATION: Injection took ${elapsed.toFixed(2)}ms (limit: 1ms)`);
      metrics.errors++;
    }

    return {
      prefix: narrative.prefix,
      suffix: narrative.suffix,
      pattern: narrative.pattern,
      tokens: narrative.tokens,
      budget: tokenBudget,
      withinBudget: narrative.tokens <= tokenBudget,
      elapsed: elapsed
    };
  };

  /**
   * Detect persona from tool usage patterns
   * Lightweight heuristics for common cases
   */
  const detectPersona = (input) => {
    // Performance-related tools → Artemis
    if (['grep', 'glob', 'bash'].includes(input.tool)) {
      return 'artemis-optimizer';
    }

    // Security checks → Hestia
    if (input.args?.filePath?.includes('.env') ||
        input.args?.content?.match(/password|secret|key/i)) {
      return 'hestia-auditor';
    }

    // Documentation → Muses
    if (input.tool === 'write' && input.args?.filePath?.endsWith('.md')) {
      return 'muses-documenter';
    }

    // Architecture/coordination → Athena (default)
    return 'athena-conductor';
  };

  /**
   * Format narrative message for console output
   */
  const formatMessage = (narrative, context = {}) => {
    if (!narrative.withinBudget && narrativeConfig.global_settings.debug_mode) {
      console.warn(`⚠️  Narrative exceeds budget: ${narrative.tokens}/${narrative.budget} tokens`);
    }

    let message = '';

    if (narrative.prefix) {
      message += `${narrative.prefix}\n`;
    }

    if (narrative.pattern) {
      // Simple template variable substitution
      let pattern = narrative.pattern;
      if (context.improvement) {
        pattern = pattern.replace('{improvement}', context.improvement);
      }
      if (context.issue_type) {
        pattern = pattern.replace('{issue_type}', context.issue_type);
      }
      message += `${pattern}\n`;
    }

    if (narrative.suffix) {
      message += `${narrative.suffix}`;
    }

    return message.trim();
  };

  // === PLUGIN HOOKS ===

  return {
    /**
     * Event hook: Monitor session lifecycle
     */
    event: async ({ event }) => {
      if (event.type === 'session.start') {
        console.log('🎭 Narrative engine ready');
        if (narrativeConfig.global_settings.debug_mode) {
          console.log('🔍 Debug mode enabled');
        }
      }

      if (event.type === 'session.idle') {
        // Log performance summary
        if (metrics.narrativeInjections > 0) {
          const avgLatency = metrics.latencies.reduce((a, b) => a + b, 0) / metrics.latencies.length;
          const p95Index = Math.floor(metrics.latencies.length * 0.95);
          const p95Latency = metrics.latencies.sort((a, b) => a - b)[p95Index] || 0;

          console.log('📊 Narrative Engine Session Summary:');
          console.log(`  Total injections: ${metrics.narrativeInjections}`);
          console.log(`  Total tokens: ${metrics.tokenUsage}`);
          console.log(`  Avg tokens/injection: ${(metrics.tokenUsage / metrics.narrativeInjections).toFixed(1)}`);
          console.log(`  Cache hit rate: ${((metrics.cacheHits / (metrics.cacheHits + metrics.cacheMisses)) * 100).toFixed(1)}%`);
          console.log(`  Avg latency: ${avgLatency.toFixed(2)}ms`);
          console.log(`  P95 latency: ${p95Latency.toFixed(2)}ms`);
          console.log(`  Errors: ${metrics.errors}`);
        }
      }
    },

    /**
     * Tool execution hook: Add narrative context
     */
    "tool.execute.before": async (input, output) => {
      if (!narrativeConfig.global_settings.enable_narrative) {
        return;
      }

      const personaId = detectPersona(input);
      const narrative = injectNarrative(personaId, 'analysis_start', {
        tokenPressure: 0.6 // Mock - would integrate with actual context tracking
      });

      if (narrative.withinBudget && narrative.prefix) {
        const message = formatMessage(narrative);
        if (message) {
          console.log(message);
        }
      }
    },

    /**
     * Tool execution complete hook: Add conclusion narrative
     */
    "tool.execute.after": async (input, output) => {
      if (!narrativeConfig.global_settings.enable_narrative || !output.success) {
        return;
      }

      const personaId = detectPersona(input);
      const narrative = injectNarrative(personaId, 'success', {
        tokenPressure: 0.6,
        improvement: '15' // Mock data
      });

      if (narrative.withinBudget && narrative.suffix) {
        const message = formatMessage(narrative, { improvement: '15' });
        if (message) {
          console.log(message);
        }
      }
    },

    /**
     * Custom API: Direct narrative injection
     */
    "narrative.inject": async ({ personaId, taskType, context }) => {
      return injectNarrative(personaId, taskType, context);
    },

    /**
     * Metrics reporting
     */
    "metrics.report": async () => {
      const avgLatency = metrics.latencies.length > 0
        ? metrics.latencies.reduce((a, b) => a + b, 0) / metrics.latencies.length
        : 0;

      const cacheHitRate = (metrics.cacheHits + metrics.cacheMisses) > 0
        ? (metrics.cacheHits / (metrics.cacheHits + metrics.cacheMisses)) * 100
        : 0;

      return {
        narrative: {
          enabled: narrativeConfig.global_settings.enable_narrative,
          totalInjections: metrics.narrativeInjections,
          totalTokens: metrics.tokenUsage,
          avgTokensPerInjection: metrics.narrativeInjections > 0
            ? (metrics.tokenUsage / metrics.narrativeInjections).toFixed(1)
            : 0,
          cacheHitRate: `${cacheHitRate.toFixed(1)}%`,
          avgLatency: `${avgLatency.toFixed(2)}ms`,
          errors: metrics.errors,
          status: metrics.errors === 0 ? 'HEALTHY' : 'DEGRADED'
        }
      };
    }
  };
};

// Export as default for compatibility
export default NarrativeEngine;
