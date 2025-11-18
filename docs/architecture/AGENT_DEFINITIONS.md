# Agent Definition Systems Architecture

**Created**: 2025-10-15
**Status**: Documented - Intentional Dual System
**Version**: v2.2.4

## Overview

Trinitas maintains two sets of agent definition files that serve different purposes. This is an **intentional architectural decision**, not a duplication issue.

## The Two Systems

### 1. Main Agent Definitions (`agents/` directory)

**Purpose**: Comprehensive reference documentation for the Trinitas agent system

**Location**: `/agents/*.md`

**Characteristics**:
- **Size**: 9-19KB per file
- **Format**: Markdown documentation with code examples
- **Content**:
  - DF2 Behavioral Modifiers
  - Narrative templates
  - Detailed collaboration patterns
  - Performance metrics and best practices
  - Troubleshooting guides
  - Token budget management
  - Related documentation references

**Use Cases**:
- Understanding agent coordination patterns
- Reference for implementing new features
- Learning how agents collaborate
- Documentation for developers

**Examples**:
- `athena-conductor.md` (9.2KB) - Comprehensive orchestration patterns
- `artemis-optimizer.md` (14.7KB) - Technical excellence patterns
- `hestia-auditor.md` (18.5KB) - Security audit patterns

### 2. Open Code Agent Definitions (`.opencode/agent/` directory)

**Purpose**: Runtime configuration for Open Code CLI integration

**Location**: `/.opencode/agent/*.md`

**Characteristics**:
- **Size**: 2-6KB per file
- **Format**: YAML frontmatter + simplified markdown
- **Content**:
  - Tool permissions (write, edit, bash, read, grep, glob, MCP tools)
  - Model configuration (model, temperature, mode)
  - Behavioral principles (simplified DF2)
  - Decision style
  - Activation triggers (keywords)
  - Core responsibilities
  - Integration summaries

**Use Cases**:
- Open Code runtime configuration
- Tool permission management
- Agent behavior tuning
- Keyword-based activation

**Examples**:
- `athena.md` (5.9KB) - Open Code configuration for Athena
- `artemis.md` (2.1KB) - Open Code configuration for Artemis
- `hestia.md` (2.1KB) - Open Code configuration for Hestia

## Key Differences

| Aspect | `agents/` | `.opencode/agent/` |
|--------|-----------|-------------------|
| **Primary Purpose** | Documentation & Reference | Runtime Configuration |
| **Audience** | Developers & Users | Open Code CLI |
| **Format** | Pure Markdown | YAML + Markdown |
| **Size** | 9-19KB | 2-6KB |
| **Code Examples** | Extensive Python examples | Minimal |
| **Tool Config** | No | Yes (permissions, model, etc.) |
| **Behavioral Modifiers** | DF2 detailed | Simplified principles |
| **Update Frequency** | Less frequent (major versions) | More frequent (tuning) |

## Maintenance Guidelines

### When to Update `agents/`
- Adding new collaboration patterns
- Updating coordination logic
- Adding troubleshooting guides
- Documenting new features
- Major version updates

### When to Update `.opencode/agent/`
- Changing tool permissions
- Adjusting behavioral parameters
- Updating activation triggers
- Modifying model configuration
- Performance tuning

### Synchronization Requirements

**Must Stay in Sync**:
- Agent names and IDs
- Core responsibilities
- Integration partnerships
- Memory management approach (e.g., TMWS → Mem0 MCP migration)

**Can Differ**:
- Level of detail
- Code examples
- Tool permissions
- Model configuration
- Narrative templates

## Migration Notes (v2.2.4)

Both systems were updated during the TMWS → Mem0 MCP migration:

**agents/ updates**:
- `@contexts/tmws.md` → `@contexts/mcp-tools.md` (hera, muses)
- "TMWS Integration" → "MCP Tools Integration"

**.opencode/agent/ updates**:
- `mcp_tmws_*` → `mcp_openmemory_*` (all 6 agents)
- "TMWS Memory Management" → "Mem0 MCP Memory Management"

## Rationale

This dual system provides:

1. **Separation of Concerns**: Documentation vs. Configuration
2. **Flexibility**: Update runtime config without changing documentation
3. **Performance**: Lightweight Open Code configs don't load heavy documentation
4. **Clarity**: Developers get comprehensive docs, CLI gets focused config
5. **Evolution**: Each system can evolve independently

## Related Documentation

- [Open Code Plugin Architecture](/.opencode/README.md)
- [Agent Coordination Patterns](/AGENTS.md)
- [Trinitas System Overview](/README.md)

---

**Decision**: Maintain both systems as intentional architecture
**Review Date**: Next major version (v3.0.0)
