/**
 * Persona Pattern Loader - JavaScript version
 * Unified persona detection for OpenCode plugins
 *
 * Replaces hardcoded patterns in multiple JavaScript plugins with single JSON source.
 * Provides dynamic loading of persona detection patterns from centralized JSON config.
 *
 * This module eliminates code duplication across:
 * - .opencode/plugin/dynamic-context-loader.js
 * - trinitas_sources/config/opencode/plugin/dynamic-context.js
 *
 * Version: 2.2.4
 * Created: 2025-10-19 (Phase 2 cleanup)
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * PersonaPatternLoader - Load and compile persona detection patterns from JSON
 *
 * Provides centralized management of persona detection patterns for all
 * OpenCode plugins. Patterns are loaded from JSON and compiled into
 * RegExp objects for efficient matching.
 *
 * @example
 * const loader = new PersonaPatternLoader();
 * const detected = loader.detectPersona("optimize performance");
 * console.log(detected); // 'artemis'
 *
 * const metadata = loader.getMetadata('artemis');
 * console.log(metadata.title); // 'Technical Perfectionist'
 */
export class PersonaPatternLoader {
  /**
   * Initialize loader with persona patterns from JSON config
   *
   * @param {string|null} configPath - Optional path to persona_patterns.json
   * @throws {Error} If persona_patterns.json cannot be found or is malformed
   */
  constructor(configPath = null) {
    this.configPath = configPath || this._findConfigFile();
    this.patterns = new Map();
    this.metadata = new Map();
    this._loadConfig();
  }

  /**
   * Auto-detect persona_patterns.json location
   *
   * Searches upward from current file location for:
   * trinitas_sources/config/shared/persona_patterns.json
   *
   * @returns {string} Path to persona_patterns.json
   * @throws {Error} If config file cannot be found
   * @private
   */
  _findConfigFile() {
    let current = path.dirname(__dirname);

    while (current !== path.dirname(current)) {
      const candidate = path.join(
        current,
        'trinitas_sources',
        'config',
        'shared',
        'persona_patterns.json'
      );

      if (fs.existsSync(candidate)) {
        console.debug(`Found persona patterns config: ${candidate}`);
        return candidate;
      }
      current = path.dirname(current);
    }

    throw new Error(
      'persona_patterns.json not found. Expected at: ' +
      'trinitas_sources/config/shared/persona_patterns.json'
    );
  }

  /**
   * Load and compile patterns from JSON config
   *
   * Reads persona_patterns.json and compiles all regex patterns.
   * Stores both compiled patterns and full metadata for each persona.
   *
   * @throws {Error} If JSON is malformed or required fields are missing
   * @private
   */
  _loadConfig() {
    console.debug(`Loading persona patterns from: ${this.configPath}`);

    const configData = fs.readFileSync(this.configPath, 'utf-8');
    const config = JSON.parse(configData);

    for (const [personaId, personaData] of Object.entries(config.personas)) {
      // Compile regex pattern
      const pattern = personaData.pattern;
      const flags = personaData.flags || '';

      this.patterns.set(personaId, new RegExp(pattern, flags));
      this.metadata.set(personaId, personaData);
    }

    console.info(`Loaded ${this.patterns.size} persona patterns`);
  }

  /**
   * Detect persona from text using pattern matching
   *
   * Uses compiled regex patterns to identify which persona is most
   * relevant to the given text. Returns highest priority match.
   *
   * @param {string} text - Input text to analyze (e.g., user prompt)
   * @returns {string|null} Persona ID (e.g., 'athena', 'artemis') or null if no match
   *
   * @example
   * const loader = new PersonaPatternLoader();
   *
   * loader.detectPersona("optimize database queries");
   * // Returns: 'artemis'
   *
   * loader.detectPersona("security audit needed");
   * // Returns: 'hestia'
   *
   * loader.detectPersona("hello world");
   * // Returns: null
   */
  detectPersona(text) {
    const matches = [];

    for (const [personaId, pattern] of this.patterns) {
      if (pattern.test(text)) {
        const priority = this.metadata.get(personaId).priority;
        matches.push({ priority, personaId });
      }
    }

    if (matches.length === 0) {
      return null;
    }

    // Return highest priority match (lowest priority number)
    matches.sort((a, b) => a.priority - b.priority);
    const detectedPersona = matches[0].personaId;

    console.debug(`Detected persona: ${detectedPersona} from text: ${text.substring(0, 50)}...`);
    return detectedPersona;
  }

  /**
   * Detect all matching personas from text
   *
   * Similar to detectPersona() but returns all matches, not just
   * the highest priority one.
   *
   * @param {string} text - Input text to analyze
   * @returns {string[]} Array of persona IDs sorted by priority (highest first)
   *
   * @example
   * const loader = new PersonaPatternLoader();
   * loader.detectAllPersonas("optimize security performance");
   * // Returns: ['hestia', 'artemis']
   */
  detectAllPersonas(text) {
    const matches = [];

    for (const [personaId, pattern] of this.patterns) {
      if (pattern.test(text)) {
        const priority = this.metadata.get(personaId).priority;
        matches.push({ priority, personaId });
      }
    }

    // Sort by priority (ascending) and return persona IDs
    matches.sort((a, b) => a.priority - b.priority);
    return matches.map(m => m.personaId);
  }

  /**
   * Get full metadata for a persona
   *
   * Returns all configuration data for the specified persona,
   * including display_name, title, emoji, contexts, etc.
   *
   * @param {string} personaId - Persona identifier (e.g., 'athena')
   * @returns {Object} Dictionary with all persona metadata
   *
   * @example
   * const loader = new PersonaPatternLoader();
   * const metadata = loader.getMetadata('artemis');
   * console.log(metadata.title); // 'Technical Perfectionist'
   * console.log(metadata.emoji); // '🏹'
   */
  getMetadata(personaId) {
    return this.metadata.get(personaId) || {};
  }

  /**
   * Get compiled regex pattern for a persona
   *
   * @param {string} personaId - Persona identifier
   * @returns {RegExp|null} Compiled RegExp object or null if not found
   */
  getPattern(personaId) {
    return this.patterns.get(personaId) || null;
  }

  /**
   * Get list of all available persona IDs
   *
   * @returns {string[]} Array of persona identifiers (e.g., ['athena', 'artemis', ...])
   */
  listPersonas() {
    return Array.from(this.patterns.keys());
  }
}

/**
 * Convenience function for quick persona detection
 *
 * @param {string} text - Text to analyze
 * @param {string|null} configPath - Optional path to persona_patterns.json
 * @returns {string|null} Detected persona ID or null
 *
 * @example
 * import { detectPersona } from './persona_pattern_loader.js';
 * detectPersona("optimize this code"); // Returns: 'artemis'
 */
export function detectPersona(text, configPath = null) {
  const loader = new PersonaPatternLoader(configPath);
  return loader.detectPersona(text);
}

// CLI testing (if run directly with Node.js)
if (import.meta.url === `file://${process.argv[1]}`) {
  const text = process.argv.slice(2).join(' ');

  if (!text) {
    console.log("Usage: node persona_pattern_loader.js 'text to analyze'");
    process.exit(1);
  }

  const loader = new PersonaPatternLoader();
  const detected = loader.detectPersona(text);

  if (detected) {
    const metadata = loader.getMetadata(detected);
    console.log(`✅ Detected: ${metadata.display_name} (${metadata.emoji} ${metadata.title})`);
    console.log(`   Pattern: ${metadata.pattern}`);
    console.log(`   Priority: ${metadata.priority}`);
  } else {
    console.log("❌ No persona detected");
  }
}
