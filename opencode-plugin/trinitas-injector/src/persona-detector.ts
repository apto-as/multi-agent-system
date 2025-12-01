/**
 * Trinitas Persona Detector
 *
 * Automatically detects which Trinitas agent is most suitable for a given prompt
 * based on trigger keywords.
 */

export interface PersonaTriggers {
  [personaId: string]: string[];
}

/**
 * Trigger keywords for each Trinitas persona
 *
 * Core Agents (6):
 * - Athena: Orchestration and workflow coordination
 * - Artemis: Technical excellence and optimization
 * - Hestia: Security and risk assessment
 * - Eris: Team coordination and conflict resolution
 * - Hera: Strategic planning and architecture
 * - Muses: Documentation and knowledge management
 *
 * Support Agents (3):
 * - Aphrodite: UI/UX design
 * - Metis: Code implementation and testing
 * - Aurora: Research and information retrieval
 */
const PERSONA_TRIGGERS: PersonaTriggers = {
  // Core Agents
  'athena-conductor': [
    'orchestration',
    'workflow',
    'coordination',
    'parallel',
    'オーケストレーション',
    '調整',
    'ワークフロー',
    'harmony',
    'harmonize',
  ],
  'artemis-optimizer': [
    'optimization',
    'performance',
    'quality',
    'technical',
    'efficiency',
    '最適化',
    'パフォーマンス',
    '品質',
    'optimize',
    'benchmark',
    'profiling',
  ],
  'hestia-auditor': [
    'security',
    'audit',
    'risk',
    'vulnerability',
    'threat',
    'セキュリティ',
    '監査',
    '脆弱性',
    'secure',
    'penetration',
    'hardening',
  ],
  'eris-coordinator': [
    'coordinate',
    'tactical',
    'team',
    'collaboration',
    'チーム調整',
    '戦術',
    '協調',
    'resolve',
    'conflict',
    'mediate',
  ],
  'hera-strategist': [
    'strategy',
    'planning',
    'architecture',
    'vision',
    'roadmap',
    '戦略',
    '計画',
    'アーキテクチャ',
    'strategic',
    'long-term',
  ],
  'muses-documenter': [
    'documentation',
    'knowledge',
    'record',
    'guide',
    'ドキュメント',
    '文書化',
    '知識',
    'document',
    'wiki',
    'readme',
  ],

  // Support Agents (v2.4.7+)
  'aphrodite-designer': [
    'design',
    'ui',
    'ux',
    'interface',
    'visual',
    'layout',
    'usability',
    'デザイン',
    'UI',
    'インターフェース',
    'mockup',
    'prototype',
  ],
  'metis-developer': [
    'implement',
    'code',
    'develop',
    'build',
    'test',
    'debug',
    'fix',
    '実装',
    'コード',
    'テスト',
    'デバッグ',
    'refactor',
  ],
  'aurora-researcher': [
    'search',
    'find',
    'lookup',
    'research',
    'context',
    'retrieve',
    '検索',
    '調査',
    'リサーチ',
    'investigate',
    'explore',
  ],
};

export class PersonaDetector {
  private triggers: PersonaTriggers;

  constructor(customTriggers?: PersonaTriggers) {
    this.triggers = customTriggers ?? PERSONA_TRIGGERS;
  }

  /**
   * Detect the most suitable persona based on prompt content
   *
   * @param prompt - User prompt to analyze
   * @returns Detected persona ID or null if no match (defaults to Athena + Hera)
   */
  detect(prompt: string): string | null {
    const promptLower = prompt.toLowerCase();
    const scores: { [key: string]: number } = {};

    for (const [persona, triggers] of Object.entries(this.triggers)) {
      const score = triggers.filter((t) =>
        promptLower.includes(t.toLowerCase())
      ).length;

      if (score > 0) {
        scores[persona] = score;
      }
    }

    if (Object.keys(scores).length === 0) {
      return null; // Default: Athena + Hera coordination
    }

    // Return persona with highest score
    return Object.entries(scores).sort(([, a], [, b]) => b - a)[0][0];
  }

  /**
   * Get all matching personas with their scores
   *
   * @param prompt - User prompt to analyze
   * @returns Map of persona IDs to match scores
   */
  detectAll(prompt: string): Map<string, number> {
    const promptLower = prompt.toLowerCase();
    const scores = new Map<string, number>();

    for (const [persona, triggers] of Object.entries(this.triggers)) {
      const score = triggers.filter((t) =>
        promptLower.includes(t.toLowerCase())
      ).length;

      if (score > 0) {
        scores.set(persona, score);
      }
    }

    return scores;
  }
}
