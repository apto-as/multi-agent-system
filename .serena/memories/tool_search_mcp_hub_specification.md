# Tool Search + MCP Hub Specification Summary
## Quick Reference for Implementation

---
version: "1.0.0"
created: "2025-12-04"
full_spec_location: "docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md"
checklist_location: "docs/specifications/tool-search-mcp-hub/IMPLEMENTATION_CHECKLIST.md"
---

## Core Architecture

### 2-Container Hybrid Architecture
```
┌─────────────────────────────────────────┐
│ TMWS Core Container                      │
│ ├─ Tool Discovery Engine (ChromaDB)     │
│ ├─ Internal Tools (42 MCP tools)        │
│ └─ Skills System                        │
└─────────────────┬───────────────────────┘
                  │ Unix Socket + HMAC
┌─────────────────┴───────────────────────┐
│ MCP Hub Container                        │
│ ├─ External MCP Connections             │
│ ├─ Tool Forwarding                      │
│ └─ Connection Pool (max 10)             │
└─────────────────────────────────────────┘
```

## TMWS 4 Core Features (MUST PRESERVE)

1. **記憶 (Memory)**: ChromaDB `tmws_memories` collection - DO NOT MODIFY
2. **ナラティブ (Narrative)**: Platform-specific response formatting
3. **スキル (Skills)**: Priority ranking (2.0x weight) in search results
4. **学習 (Learning)**: Usage pattern recording for adaptive ranking

## Key Implementation Points

### Tool Search
- New collection: `tmws_tools` (separate from `tmws_memories`)
- Hybrid search: BM25 + Vector similarity
- Skills appear first with 2.0x weight boost
- Latency target: < 100ms P95

### MCP Hub
- Connection pool: max 10 servers
- Lazy initialization for memory efficiency
- Tool namespace: `mcp__{server}__{tool}`
- Preset-only server allowlist (no arbitrary connections)

### Security (P0 - MANDATORY)
- S-P0-1: Unix Socket HMAC authentication
- S-P0-2: Container capability drop
- S-P0-3: JSON Schema input validation
- S-P0-4: Skill sandboxing (AST + resource limits)
- S-P0-5: External MCP allowlist
- S-P0-6: Response size limit (10MB)
- S-P0-7: Timeout enforcement (30s)
- S-P0-8: Audit logging

### Platform Compatibility
- Claude Code: ~/.claude/.mcp.json
- OpenCode: ~/.config/opencode/
- Same backend, platform-specific adapters

## Implementation Phases

| Phase | Focus | Duration | Gate |
|-------|-------|----------|------|
| 1 | Foundation (Tool Discovery + Hub Base) | Week 1-2 | Artemis review |
| 2 | MCP Hub + Security (P0) | Week 3-4 | Hestia audit |
| 3 | Platform Adapters | Week 5-6 | Aphrodite UX |
| 4 | Learning Integration + Polish | Week 7-8 | Athena approval |

## Critical Regression Test

Every commit must run:
```bash
pytest tests/integration/test_four_features_regression.py
```

This test verifies:
- Memory operations unchanged
- Skills priority maintained
- Narrative formatting intact
- Learning patterns recorded

## Quick Links

- Full Specification: `docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md`
- Implementation Checklist: `docs/specifications/tool-search-mcp-hub/IMPLEMENTATION_CHECKLIST.md`
- TMWS 4 Features: `.serena/memories/tmws_four_core_features.md`

---
*Stored for cross-session persistence via Serena memory*
