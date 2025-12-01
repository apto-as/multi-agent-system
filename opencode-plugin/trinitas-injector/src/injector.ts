/**
 * Trinitas Context Injector for OpenCode
 *
 * Manages context injection using the defer_loading pattern.
 *
 * Events:
 * - Session created: Level 1-2 + MCP tools summary
 * - Token threshold exceeded: Level 3 compressed summary
 *
 * Reference: https://www.anthropic.com/engineering/advanced-tool-use
 */

import * as fs from 'fs';
import * as path from 'path';
import { TMWSApiClient, ToolsSummaryResponse } from './api-client.js';

export class TrinitasInjector {
  private apiClient: TMWSApiClient;
  private contextDir: string;

  constructor(apiClient: TMWSApiClient, contextDir?: string) {
    this.apiClient = apiClient;
    this.contextDir =
      contextDir ?? path.join(__dirname, '..', 'src', 'context');
  }

  /**
   * Load context template from file
   */
  private loadContextTemplate(level: number): string {
    const templatePath = path.join(this.contextDir, `level-${level}.md`);

    try {
      if (fs.existsSync(templatePath)) {
        return fs.readFileSync(templatePath, 'utf-8');
      }
    } catch (error) {
      console.warn(`[TrinitasInjector] Failed to load level-${level}:`, error);
    }

    // Fallback
    return `# Level ${level} Context\n\n[Template not found]`;
  }

  /**
   * Sanitize Markdown content (SEC-PUSH-1)
   */
  private sanitizeMdContent(content: string): string {
    // Remove script tags
    content = content.replace(/<script[^>]*>.*?<\/script>/gis, '');

    // Remove HTML tags
    content = content.replace(/<[^>]+>/g, '');

    // Remove javascript: protocol
    content = content.replace(/javascript:/gi, '');

    // Remove event handlers
    content = content.replace(/on\w+\s*=/gi, '');

    return content;
  }

  /**
   * Format MCP tools summary as Markdown
   */
  private formatToolsSummary(summary: ToolsSummaryResponse): string {
    if (summary.error) {
      return `\n### MCP Tools (unavailable)\n*Error: ${summary.error}*\n`;
    }

    if (summary.total_count === 0) {
      return '\n### MCP Tools\n*No tools available*\n';
    }

    const lines: string[] = [
      `\n### Available MCP Tools (${summary.total_count} total)`,
      '',
      `**Servers**: ${summary.servers.join(', ') || 'none'}`,
      '',
      '**Frequently Used**:',
    ];

    for (const tool of summary.frequently_used) {
      lines.push(
        `- \`${tool.server}.${tool.tool}\`: ${tool.description}`
      );
    }

    lines.push(
      '',
      `*Token estimate: ~${summary.token_estimate} tokens*`,
      '*Use `list_mcp_tools` for full list (defer_loading pattern)*'
    );

    return lines.join('\n');
  }

  /**
   * Inject context for session start (Level 1-2 + MCP tools)
   */
  async injectSessionStart(): Promise<string> {
    // Level 1: Core Identity
    const level1 = this.sanitizeMdContent(this.loadContextTemplate(1));

    // Level 2: Session Context
    const level2 = this.sanitizeMdContent(this.loadContextTemplate(2));

    // MCP Tools Summary (defer_loading)
    const toolsSummary = await this.apiClient.getToolsSummary(5);
    const mcpSection = this.formatToolsSummary(toolsSummary);

    return `${level1}\n\n${level2}\n${mcpSection}`;
  }

  /**
   * Inject context for pre-compact (Level 3 compressed)
   */
  async injectPreCompact(): Promise<string> {
    // Level 3: Compressed Summary
    const level3 = this.sanitizeMdContent(this.loadContextTemplate(3));

    return level3;
  }
}
