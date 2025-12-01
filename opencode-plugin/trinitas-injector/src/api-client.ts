/**
 * TMWS API Client for OpenCode Plugin
 *
 * Implements defer_loading pattern for efficient token usage.
 *
 * Reference: https://www.anthropic.com/engineering/advanced-tool-use
 */

export interface TMWSApiConfig {
  baseUrl: string;
  namespace: string;
  token: string;
  timeout?: number;
}

export interface ToolSummary {
  server: string;
  tool: string;
  description: string;
  usage_count: number;
}

export interface ToolsSummaryResponse {
  total_count: number;
  frequently_used: ToolSummary[];
  servers: string[];
  token_estimate: number;
  error?: string | null;
}

export class TMWSApiClient {
  private config: TMWSApiConfig;

  constructor(config: TMWSApiConfig) {
    this.config = {
      ...config,
      timeout: config.timeout ?? 5000,
    };
  }

  /**
   * Fetch MCP tools summary (defer_loading pattern)
   *
   * Returns a compact summary of available tools instead of full definitions.
   * Token reduction: ~17,000 -> ~2,000 tokens (88% reduction)
   */
  async getToolsSummary(limit: number = 5): Promise<ToolsSummaryResponse> {
    try {
      const url = new URL('/api/v1/mcp/tools/summary', this.config.baseUrl);
      url.searchParams.set('limit', limit.toString());

      const controller = new AbortController();
      const timeoutId = setTimeout(
        () => controller.abort(),
        this.config.timeout
      );

      const response = await fetch(url.toString(), {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${this.config.token}`,
          'Content-Type': 'application/json',
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`API error: ${response.status} ${response.statusText}`);
      }

      return (await response.json()) as ToolsSummaryResponse;
    } catch (error) {
      // Fail-safe: Return empty response instead of failing
      console.warn('[TMWSApiClient] Failed to fetch tools summary:', error);

      return {
        total_count: 0,
        frequently_used: [],
        servers: [],
        token_estimate: 0,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }
}
