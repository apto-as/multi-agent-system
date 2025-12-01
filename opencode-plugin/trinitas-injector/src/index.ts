/**
 * Trinitas OpenCode Plugin - Main Entry Point
 *
 * Implements defer_loading pattern for efficient token usage.
 * Reference: https://www.anthropic.com/engineering/advanced-tool-use
 *
 * Events handled:
 * - onSessionCreated: Inject Level 1-2 context + MCP tools summary
 * - onSessionUpdated: Inject Level 3 compressed context when token threshold exceeded
 * - onMessageCreated: Detect and suggest appropriate Trinitas persona
 */

import { TMWSApiClient, TMWSApiConfig } from './api-client.js';
import { TrinitasInjector } from './injector.js';
import { PersonaDetector } from './persona-detector.js';

/**
 * Token threshold for triggering context compression (90%)
 */
const TOKEN_THRESHOLD = 0.9;

/**
 * Plugin configuration interface
 */
export interface TrinitasPluginConfig {
  tmws: TMWSApiConfig;
  tokenThreshold?: number;
  contextDir?: string;
}

/**
 * Session event interfaces (OpenCode plugin API)
 */
export interface SessionCreatedEvent {
  sessionId: string;
  timestamp: Date;
}

export interface SessionUpdatedEvent {
  sessionId: string;
  tokenUsage: number;
  maxTokens: number;
  timestamp: Date;
}

export interface MessageCreatedEvent {
  sessionId: string;
  messageId: string;
  content: string;
  role: 'user' | 'assistant';
  timestamp: Date;
}

/**
 * Plugin interface (OpenCode plugin API)
 */
export interface Plugin {
  name: string;
  version: string;
  onSessionCreated?(event: SessionCreatedEvent): Promise<string | null>;
  onSessionUpdated?(event: SessionUpdatedEvent): Promise<string | null>;
  onMessageCreated?(event: MessageCreatedEvent): Promise<string | null>;
}

/**
 * Trinitas OpenCode Plugin
 *
 * Provides context injection and persona detection for OpenCode sessions.
 */
export default class TrinitasPlugin implements Plugin {
  public readonly name = '@trinitas/opencode-injector';
  public readonly version = '1.0.0';

  private apiClient: TMWSApiClient;
  private injector: TrinitasInjector;
  private personaDetector: PersonaDetector;
  private tokenThreshold: number;

  constructor(config: TrinitasPluginConfig) {
    this.apiClient = new TMWSApiClient(config.tmws);
    this.injector = new TrinitasInjector(this.apiClient, config.contextDir);
    this.personaDetector = new PersonaDetector();
    this.tokenThreshold = config.tokenThreshold ?? TOKEN_THRESHOLD;
  }

  /**
   * Handle session creation event
   *
   * Injects Level 1-2 context + MCP tools summary at session start.
   * Token reduction: ~17,000 -> ~2,000 tokens (88% reduction)
   *
   * @param event - Session created event
   * @returns Injected context string
   */
  async onSessionCreated(event: SessionCreatedEvent): Promise<string> {
    console.log(
      `[TrinitasPlugin] Session created: ${event.sessionId} at ${event.timestamp.toISOString()}`
    );

    try {
      const context = await this.injector.injectSessionStart();
      console.log(
        `[TrinitasPlugin] Injected Level 1-2 context (~${this.estimateTokens(context)} tokens)`
      );
      return context;
    } catch (error) {
      console.error('[TrinitasPlugin] Failed to inject session start context:', error);
      // Fail-safe: Return minimal context
      return this.getMinimalContext();
    }
  }

  /**
   * Handle session update event
   *
   * Monitors token usage and injects Level 3 compressed context
   * when threshold is exceeded.
   *
   * @param event - Session updated event
   * @returns Compressed context string or null if threshold not exceeded
   */
  async onSessionUpdated(event: SessionUpdatedEvent): Promise<string | null> {
    const usageRatio = event.tokenUsage / event.maxTokens;

    if (usageRatio < this.tokenThreshold) {
      return null;
    }

    console.log(
      `[TrinitasPlugin] Token threshold exceeded: ${(usageRatio * 100).toFixed(1)}% ` +
        `(${event.tokenUsage}/${event.maxTokens})`
    );

    try {
      const context = await this.injector.injectPreCompact();
      console.log(
        `[TrinitasPlugin] Injected Level 3 compressed context (~${this.estimateTokens(context)} tokens)`
      );
      return context;
    } catch (error) {
      console.error('[TrinitasPlugin] Failed to inject pre-compact context:', error);
      return null;
    }
  }

  /**
   * Handle message creation event
   *
   * Detects appropriate Trinitas persona based on user message content.
   *
   * @param event - Message created event
   * @returns Persona suggestion string or null
   */
  async onMessageCreated(event: MessageCreatedEvent): Promise<string | null> {
    // Only analyze user messages
    if (event.role !== 'user') {
      return null;
    }

    const detectedPersona = this.personaDetector.detect(event.content);

    if (!detectedPersona) {
      // No specific persona detected, use default (Athena + Hera)
      return null;
    }

    const allMatches = this.personaDetector.detectAll(event.content);
    const matchDetails = Array.from(allMatches.entries())
      .map(([persona, score]) => `${persona}(${score})`)
      .join(', ');

    console.log(
      `[TrinitasPlugin] Persona detected: ${detectedPersona} (matches: ${matchDetails})`
    );

    return this.formatPersonaSuggestion(detectedPersona, allMatches);
  }

  /**
   * Format persona suggestion as context injection
   */
  private formatPersonaSuggestion(
    primaryPersona: string,
    allMatches: Map<string, number>
  ): string {
    const lines: string[] = [
      '',
      '---',
      '### Trinitas Persona Suggestion',
      '',
      `**Primary**: \`${primaryPersona}\``,
    ];

    if (allMatches.size > 1) {
      const others = Array.from(allMatches.entries())
        .filter(([p]) => p !== primaryPersona)
        .map(([p, score]) => `\`${p}\`(${score})`)
        .join(', ');
      lines.push(`**Also relevant**: ${others}`);
    }

    lines.push('', '*Auto-detected based on prompt keywords*', '---', '');

    return lines.join('\n');
  }

  /**
   * Estimate token count (rough approximation: 1 token ~= 4 chars)
   */
  private estimateTokens(text: string): number {
    return Math.ceil(text.length / 4);
  }

  /**
   * Get minimal context for fail-safe scenarios
   */
  private getMinimalContext(): string {
    return `# Trinitas System

You are operating within the Trinitas multi-agent system.

## Quick Commands
- \`/trinitas status\` - Check system status
- \`/trinitas execute <persona> "<task>"\` - Execute with specific persona
- \`/trinitas analyze "<task>" --personas all\` - Multi-agent analysis

## Available Personas
- athena-conductor: Orchestration
- artemis-optimizer: Technical excellence
- hestia-auditor: Security
- eris-coordinator: Tactical coordination
- hera-strategist: Strategic planning
- muses-documenter: Documentation

*Note: Full context unavailable. Use commands above for guidance.*
`;
  }
}

/**
 * Factory function for creating plugin instance
 */
export function createPlugin(config: TrinitasPluginConfig): TrinitasPlugin {
  return new TrinitasPlugin(config);
}

// Export types for consumers
export { TMWSApiClient, TMWSApiConfig, ToolsSummaryResponse } from './api-client.js';
export { TrinitasInjector } from './injector.js';
export { PersonaDetector, PersonaTriggers } from './persona-detector.js';
