# TMWS v3.0 Migration Plan
**From v2.3 (FastAPI + FastMCP Hybrid) to v3.0 (MCP Complete)**

---

**Date**: 2025-01-10
**Status**: Planning
**Completion**: 0%

---

## Current State Analysis (v2.3.0)

### Architecture Overview
- **Hybrid Model**: FastAPI (HTTP REST) + FastMCP (stdio MCP)
- **Entry Points**: 2 (src/main.py for HTTP, src/mcp_server.py for stdio)
- **Port Exposure**: 8000 (HTTP)
- **MCP Tools**: 6 basic tools
- **Dependencies**: 38 FastAPI import statements

### File Structure
```
src/
├── api/                    # FastAPI related (TO BE REMOVED)
│   ├── routers/           # 10 REST route files
│   ├── middleware/        # HTTP middleware
│   ├── dependencies.py    # FastAPI dependencies
│   ├── app.py             # FastAPI application factory
│   └── ...
├── mcp_server.py          # MCP entry point (KEEP & REFACTOR)
├── main.py                # HTTP entry point (TO BE REMOVED)
├── core/                  # Core services (KEEP)
├── models/                # Data models (KEEP)
├── services/              # Business logic (KEEP)
├── security/              # Security modules (REFACTOR)
├── tools/                 # MCP tools (EXPAND)
└── integration/           # External integrations (REVIEW)
```

### FastAPI Dependencies (38 imports)
**Critical Files**:
- src/api/app.py (FastAPI factory)
- src/api/routers/*.py (10 route files)
- src/api/middleware_unified.py (HTTP middleware)
- src/api/dependencies.py (dependency injection)
- src/security/*_middleware.py (HTTP security)
- src/integration/fastapi_mcp_bridge*.py (bridge code)

---

## Target State (v3.0)

### Architecture
- **MCP Only**: FastMCP (stdio transport)
- **Entry Point**: 1 (src/mcp_server.py)
- **Port Exposure**: None (stdio only)
- **MCP Tools**: 30 comprehensive tools
- **Dependencies**: 0 FastAPI imports

### File Structure (After Migration)
```
src/
├── mcp_server.py          # Single entry point
├── core/                  # Core services
├── models/                # Data models
├── services/              # Business logic
├── security/              # MCP security (refactored)
├── mcp_tools/             # 30 MCP tools (renamed from tools/)
│   ├── memory_tools.py
│   ├── graph_tools.py     # NEW
│   ├── agent_tools.py
│   ├── workflow_tools.py
│   └── system_tools.py
└── integration/           # External integrations (MCP compatible)
```

---

## Migration Strategy

### Phase 1: Preparation (Week 1, Day 1-2)
**Goal**: Understand dependencies and plan removal

#### Step 1.1: Dependency Analysis
- [x] Identify all FastAPI import statements (38 found)
- [ ] Map dependencies between FastAPI and core services
- [ ] Identify shared code between FastAPI and MCP
- [ ] Document business logic in FastAPI routers to preserve

#### Step 1.2: Backup and Branch
```bash
# Create migration branch
git checkout -b feature/v3.0-mcp-complete

# Tag current state
git tag v2.3.0-pre-migration

# Backup important files
mkdir -p archive/v2.3-fastapi-backup
cp -r src/api archive/v2.3-fastapi-backup/
cp src/main.py archive/v2.3-fastapi-backup/
```

#### Step 1.3: Test Suite Analysis
- [ ] Identify tests dependent on FastAPI
- [ ] Plan test refactoring (HTTP tests → MCP tests)
- [ ] Ensure core business logic tests are independent

### Phase 2: FastAPI Removal (Week 1, Day 2-3)
**Goal**: Remove all FastAPI code and dependencies

#### Step 2.1: Remove Entry Points
```bash
# Remove main.py (FastAPI entry point)
git rm src/main.py

# Remove uvicorn from pyproject.toml
# Remove fastapi from pyproject.toml
```

#### Step 2.2: Remove API Directory
```bash
# Archive first (already done in Step 1.2)
git rm -r src/api/
```

#### Step 2.3: Clean Dependencies
**Files to remove/refactor**:
- src/integration/fastapi_mcp_bridge.py (DELETE)
- src/integration/fastapi_mcp_bridge_enhanced.py (DELETE)
- src/security/security_middleware.py (REFACTOR for MCP)
- src/security/rate_limiter.py (KEEP, MCP compatible)
- src/security/audit_logger*.py (KEEP, MCP compatible)

#### Step 2.4: Update pyproject.toml
```toml
# REMOVE
fastapi>=0.110.0
uvicorn[standard]>=0.27.0
gunicorn>=21.0.0

# KEEP
fastmcp>=0.1.0
mcp>=0.9.0
```

### Phase 3: MCP Server Refactoring (Week 1, Day 3-5)
**Goal**: Refactor mcp_server.py to be the single entry point

#### Step 3.1: Rename tools/ to mcp_tools/
```bash
git mv src/tools src/mcp_tools
```

#### Step 3.2: Update MCP Server Structure
**Current**: HybridMCPServer with 6 tools
**Target**: TMWSMCPServer with 30 tools

```python
# src/mcp_server.py (refactored)
class TMWSMCPServer:
    """
    TMWS v3.0 MCP Server - Pure stdio implementation

    Features:
    - 30 MCP tools (Memory, Graph, Agent, Workflow, System)
    - stdio transport only
    - Long-running daemon process
    - Smart defaults (~/.tmws auto-initialization)
    """

    def __init__(self):
        self.agent_id = os.getenv("TMWS_AGENT_ID", self._auto_detect_agent())
        self.mcp = FastMCP(name="tmws", version="3.0.0")
        self._register_all_tools()

    def _register_all_tools(self):
        # Memory tools (10)
        register_memory_tools(self.mcp)
        # Graph tools (5) - NEW
        register_graph_tools(self.mcp)
        # Agent tools (5)
        register_agent_tools(self.mcp)
        # Workflow tools (5)
        register_workflow_tools(self.mcp)
        # System tools (5)
        register_system_tools(self.mcp)
```

#### Step 3.3: Expand MCP Tools
**Memory Tools** (10 tools):
- [x] store_memory (existing)
- [x] search_memories (existing)
- [ ] update_memory
- [ ] delete_memory
- [ ] get_memory
- [ ] batch_store_memories
- [ ] search_similar
- [ ] get_memory_stats
- [ ] export_memories
- [ ] import_memories

**Graph Tools** (5 tools) - NEW:
- [ ] add_graph_node
- [ ] add_graph_edge
- [ ] find_path
- [ ] get_neighbors
- [ ] query_subgraph

**Agent Tools** (5 tools):
- [ ] register_agent
- [x] get_agent_status (existing)
- [ ] switch_agent
- [ ] list_agents
- [ ] delete_agent

**Workflow Tools** (5 tools):
- [x] create_task (existing, rename to create_workflow)
- [ ] execute_workflow
- [ ] get_workflow_status
- [ ] cancel_workflow
- [ ] list_workflows

**System Tools** (5 tools):
- [x] get_memory_stats (existing, rename to system_stats)
- [ ] system_health
- [ ] clear_cache
- [ ] backup
- [ ] optimize

### Phase 4: Security Hardening (Week 3, Day 1-2)
**Goal**: Implement Hestia security recommendations

#### Step 4.1: Path Validation
```python
# src/security/path_validator.py (NEW)
class PathValidator:
    def validate_file_path(self, user_path: str) -> str:
        """Prevent directory traversal attacks."""
        canonical_path = Path(user_path).resolve()

        for allowed_base in self.allowed_base_dirs:
            if str(canonical_path).startswith(str(allowed_base)):
                return str(canonical_path)

        raise ValidationError("Path outside allowed directories")
```

#### Step 4.2: User-Memory Isolation
```sql
-- migrations/versions/008_user_memory_isolation.py
ALTER TABLE memories ADD COLUMN owner_user_id UUID NOT NULL;
ALTER TABLE memories ADD COLUMN namespace_owner_id UUID;
ALTER TABLE memories ADD CONSTRAINT fk_owner FOREIGN KEY (owner_user_id) REFERENCES users(id);
```

#### Step 4.3: Content Sanitization
```python
# src/security/input_validator.py (ENHANCED)
def sanitize_jsonb_recursively(self, data: dict, max_depth: int = 10) -> dict:
    """Sanitize all string values in nested JSON."""
    # Recursive sanitization implementation
    pass
```

#### Step 4.4: Audit Logging
```python
# Enhance src/security/audit_logger_async.py
await audit_logger.log_event(
    event_type="mcp_tool_called",
    user_id=str(user_id),
    resource=f"mcp_tool/{tool_name}",
    action="CALL",
    metadata={
        "tool_name": tool_name,
        "arguments": sanitize_for_logging(arguments)
    }
)
```

### Phase 5: Testing (Week 2-3)
**Goal**: Ensure 95% test coverage

#### Step 5.1: Unit Tests
- [ ] Test all 30 MCP tools
- [ ] Test security validators
- [ ] Test business logic services

#### Step 5.2: Integration Tests
- [ ] Test MCP server initialization
- [ ] Test stdio communication
- [ ] Test database operations
- [ ] Test Redis caching

#### Step 5.3: Performance Tests
- [ ] Benchmark stdio overhead (<0.6ms target)
- [ ] Benchmark P95 latencies (<10ms for simple ops)
- [ ] Load testing (100 req/s target)

### Phase 6: Documentation (Week 3, Day 3-5)
**Goal**: Complete documentation for v3.0

#### Step 6.1: API Documentation
- [ ] Document all 30 MCP tools
- [ ] Update README.md
- [ ] Create usage examples

#### Step 6.2: Migration Guide
- [ ] v2.3 → v3.0 migration steps
- [ ] Breaking changes documentation
- [ ] Rollback procedures

#### Step 6.3: Security Documentation
- [ ] Security architecture
- [ ] Threat model
- [ ] Incident response

---

## Execution Timeline

### Week 1: Core Migration
**Day 1**: Preparation
- Dependency analysis
- Backup and branch creation
- Test suite analysis

**Day 2**: FastAPI Removal
- Remove src/main.py
- Remove src/api/
- Clean dependencies

**Day 3**: MCP Server Refactoring
- Rename tools/ to mcp_tools/
- Update MCP server structure

**Day 4-5**: Memory Tools Expansion
- Implement 10 memory tools
- Unit tests for memory tools

### Week 2: Advanced Features
**Day 1-3**: Graph Tools (NEW)
- Implement graph data model
- Implement 5 graph tools
- Integration tests

**Day 4**: Workflow Tools
- Implement 5 workflow tools

**Day 5**: System Tools
- Implement 5 system tools

### Week 3: Security & Polish
**Day 1-2**: Security Hardening
- Path validation
- User-memory isolation
- Content sanitization
- Enhanced audit logging

**Day 3**: CLI Integration
- Claude Code configuration
- opencode integration
- Claude Desktop setup

**Day 4**: Performance Optimization
- Connection pooling tuning
- Redis caching optimization
- Vector index optimization

**Day 5**: Documentation & Release
- API documentation
- Migration guide
- Security documentation
- v3.0.0 release

---

## Risk Assessment

### High Risk
1. **Database migrations**: User-memory isolation schema changes
   - Mitigation: Backward compatible migrations, rollback plan
   - Contingency: Delay release, keep v2.3 running

2. **Breaking changes**: External integrations may break
   - Mitigation: Provide v2.3 compatibility layer (optional HTTP proxy)
   - Contingency: Document migration path, support v2.3 for 3 months

### Medium Risk
3. **Performance regression**: stdio may be slower than expected
   - Mitigation: Continuous benchmarking, optimize hot paths
   - Contingency: Reintroduce connection pooling from v2.3

4. **Test coverage**: May miss edge cases
   - Mitigation: 95% coverage target, integration tests
   - Contingency: Extend testing phase by 1 week

### Low Risk
5. **Documentation gaps**: Users may struggle with migration
   - Mitigation: Comprehensive migration guide, examples
   - Contingency: Create video tutorials, community support

---

## Success Criteria

### Functional
- ✅ All 30 MCP tools implemented and working
- ✅ stdio transport functional with <0.6ms overhead
- ✅ No FastAPI dependencies remaining
- ✅ All v2.3 core features preserved in MCP

### Performance
- ✅ P95 latency <10ms for simple operations
- ✅ P95 latency <40ms for semantic search
- ✅ 100 req/s throughput

### Security
- ✅ All Hestia critical gaps resolved
- ✅ Security score 9/10
- ✅ Zero network exposure (stdio only)

### Quality
- ✅ 95% test coverage
- ✅ All tests passing
- ✅ Zero regressions in core functionality

### Documentation
- ✅ Complete API documentation
- ✅ Migration guide
- ✅ Security documentation
- ✅ Claude Code integration examples

---

## Rollback Plan

If v3.0 fails to meet criteria:

```bash
# Revert to v2.3
git checkout v2.3.0-pre-migration
pip install -r requirements-v2.3.txt
uvicorn src.main:app --host 0.0.0.0 --port 8000
```

**Data Safety**: v3.0 database schema is backward compatible with v2.3.

---

## Next Steps

1. **Review this plan** with project stakeholders
2. **Start Phase 1** (Dependency Analysis)
3. **Daily standups** during Week 1-3
4. **Go/No-Go decision** at end of Week 2

---

**Document Status**: Draft
**Approval Required**: Project Owner
**Contact**: Trinitas Agent System
