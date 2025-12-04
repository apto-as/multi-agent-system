# Tool Search + MCP Hub Implementation Checklist

---
specification_version: "1.0.0"
checklist_version: "1.0.0"
created: "2025-12-04"
---

## Pre-Implementation Requirements

### Specification Review
- [ ] Read SPECIFICATION_v1.0.0.md completely
- [ ] Understand 4 core features preservation requirements
- [ ] Review security requirements (P0 mandatory)
- [ ] Check TMWS Memory for latest updates:
  ```
  namespace: tmws-core
  tags: ["tool-search", "mcp-hub", "specification"]
  ```

### Environment Setup
- [ ] TMWS v2.4.12+ running
- [ ] Docker and docker-compose installed
- [ ] Ollama with multilingual-e5-large model
- [ ] Development environment configured

---

## Phase 1: Foundation (Week 1-2)

### 1.1 Tool Discovery Engine

#### Files to Create
- [ ] `src/tools/tool_search.py`
- [ ] `src/services/tool_search_service.py`
- [ ] `src/models/tool_metadata.py`

#### Implementation Tasks
- [ ] Define `ToolSearchResult` dataclass
- [ ] Define `MCPServerMetadata` dataclass
- [ ] Create ChromaDB collection `tmws_tools`
- [ ] Implement `search_tools()` MCP tool
- [ ] Implement Skills priority ranking (weight: 2.0)
- [ ] Implement internal tools ranking (weight: 1.5)
- [ ] Add hybrid BM25 + vector search

#### Tests
- [ ] `tests/unit/test_tool_search.py`
- [ ] `tests/unit/test_tool_metadata.py`
- [ ] Test Skills ranking priority
- [ ] Test search latency < 100ms

#### 4 Features Check
- [ ] **記憶**: ChromaDB `tmws_memories` unchanged
- [ ] **スキル**: Skills appear first in search results

### 1.2 MCP Hub Manager Base

#### Files to Create
- [ ] `src/infrastructure/mcp/hub_manager.py`
- [ ] `src/infrastructure/mcp/hub_connection.py`

#### Implementation Tasks
- [ ] Create `MCPHubManager` class
- [ ] Implement connection pool (max 10)
- [ ] Implement lazy initialization
- [ ] Add Unix socket communication stub

#### Tests
- [ ] `tests/unit/test_mcp_hub_manager.py`
- [ ] Test connection pool limits
- [ ] Test lazy initialization

### 1.3 Gate 1 Verification

Before proceeding to Phase 2:
- [ ] All Phase 1 unit tests pass
- [ ] `search_tools` returns skills + internal tools
- [ ] No regression in existing TMWS tests
- [ ] 4 features regression test passes
- [ ] Code review by Artemis

---

## Phase 2: MCP Hub + Security (Week 3-4)

### 2.1 External MCP Connections

#### Files to Modify/Create
- [ ] `src/infrastructure/mcp/hub_manager.py` (extend)
- [ ] `src/infrastructure/mcp/external_connection.py`
- [ ] `src/infrastructure/mcp/tool_proxy.py`

#### Implementation Tasks
- [ ] Implement `connect_server()` for external MCPs
- [ ] Implement `proxy_tool_call()`
- [ ] Implement `expose_external_tools()`
- [ ] Add tool namespace prefixing (`mcp__{server}__{tool}`)
- [ ] Implement dynamic tool registration

#### Tests
- [ ] `tests/integration/test_external_mcp_connection.py`
- [ ] `tests/integration/test_tool_forwarding.py`
- [ ] Test with context7 MCP server
- [ ] Test with serena MCP server

### 2.2 Security Implementation (P0)

#### Files to Create
- [ ] `src/infrastructure/security/socket_auth.py`
- [ ] `src/infrastructure/security/input_validator.py`
- [ ] `src/infrastructure/security/sandbox.py`
- [ ] `src/infrastructure/security/audit_logger.py`

#### P0 Security Tasks (MANDATORY)
- [ ] **S-P0-1**: Unix Socket HMAC authentication
- [ ] **S-P0-2**: Container capability drop (docker-compose.yml)
- [ ] **S-P0-3**: JSON Schema input validation
- [ ] **S-P0-4**: Skill sandboxing (AST analysis + resource limits)
- [ ] **S-P0-5**: External MCP allowlist (preset-only)
- [ ] **S-P0-6**: Response size limit (10MB)
- [ ] **S-P0-7**: Timeout enforcement (30s)
- [ ] **S-P0-8**: Audit logging

#### Security Tests
- [ ] `tests/security/test_socket_auth.py`
- [ ] `tests/security/test_input_validation.py`
- [ ] `tests/security/test_sandbox.py`
- [ ] `tests/security/test_injection_prevention.py`
- [ ] `tests/security/test_audit_logging.py`

#### 4 Features Check
- [ ] **記憶**: Tool usage stored in Memory
- [ ] **学習**: Usage patterns recorded

### 2.3 Gate 2 Verification

Before proceeding to Phase 3:
- [ ] All Phase 2 tests pass
- [ ] External tools callable via TMWS
- [ ] **ALL P0 security tests pass** (BLOCKER)
- [ ] Hestia security audit approval
- [ ] 4 features regression test passes

---

## Phase 3: Platform Adapters (Week 5-6)

### 3.1 Claude Code Adapter

#### Files to Create
- [ ] `src/infrastructure/platform/claude_adapter.py`
- [ ] `src/infrastructure/platform/base_adapter.py`

#### Implementation Tasks
- [ ] Implement platform detection
- [ ] Implement config loading from `~/.claude/.mcp.json`
- [ ] Implement response formatting

### 3.2 OpenCode Adapter

#### Files to Create
- [ ] `src/infrastructure/platform/opencode_adapter.py`

#### Implementation Tasks
- [ ] Implement config loading from `~/.config/opencode/`
- [ ] Implement response formatting for OpenCode
- [ ] Add plugin-compatible output

### 3.3 Platform Synchronization

#### Implementation Tasks
- [ ] Implement config sync mechanism
- [ ] Add platform-specific error handling
- [ ] Document platform differences

#### Tests
- [ ] `tests/integration/test_claude_adapter.py`
- [ ] `tests/integration/test_opencode_adapter.py`
- [ ] `tests/e2e/test_platform_parity.py`

#### 4 Features Check
- [ ] **ナラティブ**: Platform-specific narrative formatting

### 3.3 Gate 3 Verification

Before proceeding to Phase 4:
- [ ] Both platforms work identically
- [ ] Configuration sync verified
- [ ] E2E tests pass on both platforms
- [ ] UX review by Aphrodite
- [ ] 4 features regression test passes

---

## Phase 4: Learning Integration + Polish (Week 7-8)

### 4.1 Adaptive Ranking

#### Files to Create
- [ ] `src/services/adaptive_ranker.py`

#### Implementation Tasks
- [ ] Implement `record_outcome()`
- [ ] Implement `get_personalized_ranking()`
- [ ] Integrate with Learning system
- [ ] Add A/B test framework

### 4.2 Tool → Skill Promotion

#### Implementation Tasks
- [ ] Implement promotion criteria (usage > 100, success > 95%)
- [ ] Create promotion workflow
- [ ] Add user notification

### 4.3 Performance Optimization

#### Tasks
- [ ] Implement intelligent caching
- [ ] Optimize vector search
- [ ] Add parallel tool discovery
- [ ] Profile and optimize hot paths

#### Performance Targets
- [ ] search_tools: < 100ms P95
- [ ] tool_execution (warm): < 75ms P95
- [ ] cache_hit_rate: > 95%

### 4.4 Documentation

#### Documents to Create (Muses)
- [ ] User guide
- [ ] API reference
- [ ] Migration guide
- [ ] Troubleshooting guide

### 4.5 Final Gate Verification

Before production deployment:
- [ ] All tests pass (unit, integration, security, e2e)
- [ ] Performance targets met
- [ ] **4 core features verified intact**
- [ ] Final Hestia security audit
- [ ] Documentation complete
- [ ] Athena coordination approval

---

## Continuous Verification

### Every Commit
- [ ] Run `pytest tests/unit/`
- [ ] Run `pytest tests/integration/test_four_features_regression.py`
- [ ] Run `ruff check src/`

### Every Phase Completion
- [ ] Update TMWS Memory with progress:
  ```python
  await store_memory(
      namespace="tmws-core",
      content={"phase": N, "status": "completed", ...},
      tags=["tool-search", "implementation-progress"]
  )
  ```
- [ ] Update Serena memory
- [ ] Review specification for any needed updates

### Weekly
- [ ] Check specification for updates
- [ ] Review security posture
- [ ] Performance regression check

---

## Emergency Rollback Plan

If critical issues discovered:

1. **Immediate**: Disable MCP Hub features via config flag
2. **Short-term**: Revert to previous TMWS version
3. **Communication**: Notify via Eris coordination

Rollback command:
```bash
# Disable MCP Hub
export TMWS_MCP_HUB_ENABLED=false
docker-compose restart tmws

# Full revert if needed
git checkout v2.4.12
docker-compose down && docker-compose up -d
```

---

## Sign-off Requirements

| Phase | Reviewer | Required |
|-------|----------|----------|
| Phase 1 | Artemis | Code review |
| Phase 2 | Hestia | Security audit |
| Phase 3 | Aphrodite | UX review |
| Phase 4 | Athena | Final coordination |
| All Phases | Automated | 4 features regression |

---

**Checklist Version:** 1.0.0
**Last Updated:** 2025-12-04
**Reference:** SPECIFICATION_v1.0.0.md
