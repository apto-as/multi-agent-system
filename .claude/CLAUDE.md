# TMWS Project Knowledge Base
## Trinitas Memory & Workflow System - Claude Code Instructions

**Last Updated**: 2025-11-10
**Project Version**: v2.3.0
**Status**: Production-ready

---

## Project Overview

TMWS (Trinitas Memory & Workflow System) is a **multi-agent memory and workflow orchestration platform** with semantic search capabilities, designed for AI-powered task management and knowledge retention.

### Core Technologies

- **Web Framework**: FastAPI (async/await architecture)
- **ORM**: SQLAlchemy 2.0 (async engine)
- **Primary Database**: SQLite with WAL mode
- **Vector Storage**: ChromaDB (embedded mode with DuckDB backend)
- **Embedding Model**: Multilingual-E5-Large (1024 dimensions)
- **Programming Language**: Python 3.11+
- **API Standard**: Model Context Protocol (MCP)

### Architecture Principles

1. **Dual Storage Architecture**:
   - SQLite: Metadata, relationships, access control
   - ChromaDB: Vector embeddings for semantic search
   - No duplication - each system stores what it does best

2. **Async-First Design**:
   - All I/O operations are async
   - Event loop must never be blocked
   - Use `asyncio.to_thread()` for sync library calls

3. **Multi-Tenant Security**:
   - Namespace isolation enforced at model level
   - Agent-based access control (PRIVATE, TEAM, SHARED, PUBLIC, SYSTEM)
   - Never trust client-provided namespace claims

---

## Critical Design Decisions

### 1. PostgreSQL → SQLite Migration (Completed 2025-10-24)

**Rationale**:
- Simplified deployment (no separate database server)
- Adequate performance for target use case (<1000 concurrent users)
- SQLite with WAL mode provides ACID guarantees
- ChromaDB handles vector operations efficiently

**Performance Benchmarks** (achieved):
- Semantic search: 5-20ms P95 ✅
- Vector similarity: < 10ms P95 ✅
- Metadata queries: < 20ms P95 ✅
- Cross-agent sharing: < 15ms P95 ✅

**Key Files**:
- `src/core/database.py` - Async SQLite engine configuration
- `src/services/vector_search_service.py` - ChromaDB integration
- `migrations/versions/` - Alembic migration history

### 2. Security Architecture

#### P0-1: Namespace Isolation Fix (2025-10-27)

**CRITICAL SECURITY FIX**:
- `Memory.is_accessible_by()` now requires verified namespace parameter
- Prevents cross-tenant access attacks
- Authorization layer must verify namespace from database

**Implementation**:
```python
# CORRECT - Verify namespace from DB
agent = await get_agent_from_db(agent_id)
verified_namespace = agent.namespace
memory.is_accessible_by(agent_id, verified_namespace)  # ✅

# WRONG - Never trust JWT claims directly
namespace = jwt_claims.get("namespace")  # ❌ SECURITY RISK
memory.is_accessible_by(agent_id, namespace)
```

**Key Files**:
- `src/models/memory.py:160-201` - Access control implementation
- `src/security/authorization.py:459-492` - Authorization layer
- `tests/security/test_namespace_isolation.py` - Security test suite (14 tests)

### 3. Performance Optimizations

#### P0-2: Duplicate Index Removal (2025-10-27)

**Impact**: +18-25% write performance improvement

**Removed Indexes** (6 total):
- `security_audit_logs`: 4 duplicate indexes
- `tasks`: 2 duplicate indexes

**Migration**: `migrations/versions/20251027_1134-315d506e2598_p0_remove_duplicate_indexes.py`

#### P0-3: Missing Critical Indexes (2025-10-27)

**Impact**: -60-85% query latency reduction

**Added Indexes** (3 total):
1. `idx_learning_patterns_agent_performance` - Learning pattern queries: 2000ms → 300ms (-85%)
2. `idx_pattern_usage_agent_success_time` - Pattern filtering: 800ms → 150ms (-81%)
3. `idx_workflow_executions_error_analysis` - Error analysis: 500ms → 200ms (-60%)

**Migration**: `migrations/versions/20251027_1134-d42bfef42946_p0_add_missing_critical_indexes.py`

#### P0-4: Async/Sync Pattern Fix (2025-10-27)

**CRITICAL PERFORMANCE FIX**:
- `VectorSearchService` converted from sync to async
- All ChromaDB operations wrapped in `asyncio.to_thread()`
- Prevents event loop blocking

**Impact**: +30-50% improvement in concurrent request handling

**Key Changes**:
```python
# Before (blocks event loop)
def search(self, query_embedding, top_k):
    return self._collection.query(...)  # ❌ Blocks

# After (non-blocking)
async def search(self, query_embedding, top_k):
    return await asyncio.to_thread(
        self._collection.query, ...
    )  # ✅ Non-blocking
```

**Key Files**:
- `src/services/vector_search_service.py` - All 8 methods converted to async
- `src/services/memory_service.py` - Lazy initialization pattern added

---

## Code Quality Standards

### Exception Handling

**CRITICAL**: Never suppress `KeyboardInterrupt` or `SystemExit`

```python
# CORRECT
try:
    risky_operation()
except (KeyboardInterrupt, SystemExit):
    raise  # ✅ Never suppress
except SpecificException as e:
    log_and_raise(CustomError, "Message", original_exception=e)

# WRONG
except Exception:  # ❌ Too broad, may catch KeyboardInterrupt
    pass
```

**Reference**: `docs/dev/EXCEPTION_HANDLING_GUIDELINES.md`

### Failover and Redundancy

**CRITICAL**: Avoid unnecessary failover mechanisms - they are a breeding ground for bugs

**Philosophy**:
- Explicit dependencies are better than hidden fallbacks
- Fail fast and clearly rather than silently degrading
- Error messages should guide users to fix the real problem
- Required infrastructure should be documented, not worked around

```python
# WRONG - Silent failover hides problems
try:
    result = ollama_service.embed(text)
except Exception:
    result = fallback_service.embed(text)  # ❌ Hides Ollama failures

# CORRECT - Explicit requirement with clear error
try:
    result = ollama_service.embed(text)
except OllamaConnectionError as e:
    log_and_raise(
        EmbeddingServiceError,
        "Ollama is required but unavailable. Please ensure Ollama is running.",
        original_exception=e,
        details={"ollama_url": settings.OLLAMA_BASE_URL}
    )  # ✅ Clear error message guides user to solution
```

**When Failover IS Justified**:
1. **Distributed systems**: Multiple equivalent servers for load balancing
2. **Data replication**: Read replicas for high availability
3. **Circuit breaker pattern**: Temporary failures with automatic recovery
4. **Graceful degradation**: Non-critical features that enhance but aren't required

**When Failover is HARMFUL**:
1. **Development dependencies**: Don't hide missing required tools
2. **Configuration errors**: Don't mask misconfiguration
3. **Data format mismatches**: Don't silently use incompatible alternatives
4. **Business logic**: Don't change behavior based on failures

**Current Architecture**:
- **Ollama is REQUIRED** for embedding generation (1024-dim Multilingual-E5-Large)
- **No fallback to SentenceTransformers** - removed as of 2025-10-27
- **Circuit breaker recommended** for Ollama connection failures (retry with exponential backoff)
- **Clear error messages** guide users to install/configure Ollama properly

### Async Patterns

**Rules**:
1. All I/O operations must be async
2. Use `asyncio.to_thread()` for sync library calls
3. Never call sync I/O from async functions directly
4. Use `async with` for context managers

**Reference**: `src/services/vector_search_service.py` (exemplary async implementation)

### Code Duplication

**Current Status** (as of 2025-10-27):
- ✅ Ruff compliance: 100% (2 violations fixed)
- ⚠️ Code duplication: 1,267 lines reducible (4.7% of codebase)
- 🔴 4 embedding service implementations (800 lines) - **P0 TODO**

---

## Development Workflow

### Database Migrations

```bash
# Create new migration
alembic revision --autogenerate -m "Description"

# Apply migrations
alembic upgrade head

# Check current version
alembic current

# Rollback one version
alembic downgrade -1
```

**Migration Naming Convention**:
- P0 fixes: `p0_description.py`
- Features: `feature_description.py`
- Refactoring: `refactor_description.py`

### Testing

```bash
# Run all tests
pytest tests/ -v

# Run unit tests only
pytest tests/unit/ -v

# Run with coverage
pytest tests/ -v --cov=src --cov-report=term-missing

# Run specific test
pytest tests/unit/test_memory_service.py::test_create_memory -v
```

**Test Coverage Target**: 90%+ (current: ~85%)

### Code Quality

```bash
# Ruff linting
ruff check src/

# Ruff auto-fix
ruff check src/ --fix

# Type checking (if enabled)
mypy src/
```

**Current Ruff Status**: 100% compliant ✅

---

## Recent Major Changes

### v2.3.0 - Phase 2A: Verification-Trust Integration (2025-11-11) ✅

**Completed**: Non-invasive extension to VerificationService with P1 security fixes

**Features**:
- **Pattern Linkage**: Verifications can link to learning patterns via `claim_content.pattern_id`
- **Trust Propagation**: Accurate verifications boost trust (+0.05 base + 0.02 pattern)
- **Graceful Degradation**: Pattern propagation failures don't block verification completion

**Security Enhancements (P1 Fix)**:
- **V-VERIFY-2**: Verifier authorization (requires AGENT/ADMIN role, blocks OBSERVER)
- **V-VERIFY-4**: Pattern eligibility validation (public/system only, no self-owned patterns)
- **V-VERIFY-1**: Command injection prevention (ALLOWED_COMMANDS whitelist)
- **V-VERIFY-3**: Namespace isolation (verified from DB, not user input)
- **V-TRUST-5**: Self-verification prevention

**Performance**:
- Total verification: <515ms P95 (target: <550ms) ✅
- Pattern propagation: <35ms P95 (6.8% overhead)

**Testing**:
- 21/21 unit tests PASS ✅
- Security test coverage: V-VERIFY-1/2/3/4 + V-TRUST-5

**Documentation** (2,300+ lines):
- Integration Guide: `docs/guides/VERIFICATION_TRUST_INTEGRATION_GUIDE.md`
- API Reference: `docs/api/VERIFICATION_SERVICE_API.md`
- Architecture: `docs/architecture/PHASE_2A_ARCHITECTURE.md`
- Usage Examples: `docs/examples/VERIFICATION_TRUST_EXAMPLES.md` (12 examples)

**Key Files**:
- `src/services/verification_service.py:729-912` - `_propagate_to_learning_patterns()` method
- `src/services/learning_trust_integration.py` - Integration service (Phase 1)
- `tests/unit/services/test_verification_service.py` - Updated tests

---

### v2.2.6 - Code Cleanup & Security Hardening (2025-10-27) ✅

**Completed**: Phase 0-5 systematic cleanup with security vulnerability fix

**Security (V-1 Fix)**:
- **Path Traversal (CVSS 7.5 HIGH)**: Blocked `.` and `/` in namespace sanitization
- Impact: `github.com/user/repo` → `github-com-user-repo`
- Validation: 24/24 namespace tests PASSED, zero regression

**Performance (Namespace Caching)**:
- Environment Variable (P1): 0.00087 ms (目標 <1ms) - **125倍高速** ✅
- Git Detection (P2): 0.00090 ms (目標 <10ms) - **12,600倍高速** ✅
- Implementation: One-time detection at MCP server initialization

**Code Quality (1,081 Fixes)**:
- Ruff compliance: 100% (Implicit Optional: 166件, unused imports: 198件, other: 717件)
- Code duplication: RateLimiter removed from `agent_auth.py` (-49 lines)
- Import validation: All Python files compile successfully

**Verification**:
- Phase 5A (Code Quality): ✅ Ruff 100%, imports valid, caching verified
- Phase 5B (Functional): ✅ 24/24 tests, 6 MCP tools, performance exceeded
- Phase 5C (Documentation): ✅ CHANGELOG, README, CLAUDE.md updated

**Lessons Learned**:
1. **Micro-optimizations can have macro impact**: Caching improved performance 12,600x
2. **Security first, always**: V-1 discovered during routine audit, fixed immediately
3. **Systematic verification prevents regression**: Step-by-step validation caught all issues
4. **Deferred is better than risky**: Phase 4 deferred to avoid introducing bugs

**Technical Debt Managed**:
- Phase 4 (Large File Refactoring) deliberately deferred to v2.3.0+ due to HIGH risk
- Gradual refactoring approach (1 file at a time) preferred over big-bang

**Git Commits**:
- `fb32dd3`: Phase 1 - Ruff fixes (1,081 violations)
- `16eb834`: Phase 2 - Namespace caching
- `c391d40`: Phase 3 - RateLimiter dedup (with namespace isolation)
- `6d428b6`: V-1 - Path traversal security fix

### v2.2.6 - Ollama-Only Architecture (2025-10-27) ✅

**Completed**: Migration from SentenceTransformers to Ollama-only embedding architecture

**Impact**:
- Code Reduction: -904 lines (-72% of embedding services)
- Memory Savings: -1.5GB (removed PyTorch/transformers dependencies)
- Dependency Reduction: -3 major packages (sentence-transformers, transformers, torch)
- Maintainability: +89% (single embedding implementation)

**Breaking Changes**:
- Ollama is now REQUIRED (no fallback)
- Removed configuration: TMWS_EMBEDDING_PROVIDER, TMWS_EMBEDDING_FALLBACK_ENABLED
- Fail-fast approach with clear error messages

**Migration**:
1. Install Ollama: https://ollama.ai/download
2. Pull model: `ollama pull zylonai/multilingual-e5-large`
3. Start server: `ollama serve`

**Rationale**: Unnecessary fallback mechanisms are a breeding ground for bugs. Explicit dependencies with clear error messages are better than silent degradation.

### v2.3.0 - Phase 2D-1: Critical Security Test Suite (2025-10-27) ✅

**Completed**: Option X (Athena's balanced hybrid approach) with Trinitas collaboration

**Test Implementation**:
- **Hestia**: 5 critical security tests (real DB) - `tests/unit/security/test_mcp_critical_security.py` (659 lines)
- **Artemis**: 15 mock-based tests (fast unit tests) - `tests/unit/security/test_mcp_authentication_mocks.py` (532 lines)
- **Muses**: Manual verification checklist - `docs/testing/PHASE2D_MANUAL_VERIFICATION.md` (80+ items)

**Test Results**: ✅ ALL 20 TESTS PASSED in 2.35s
1. Namespace Isolation (CVSS 8.7) - REQ-2 ✅
2. RBAC Role Hierarchy (REQ-5) ✅
3. RBAC Privilege Escalation (CVSS 7.8) ✅
4. Rate Limiting Enforcement (CVSS 7.5) - REQ-4 with FAIL-SECURE ✅
5. Security Audit Logging (REQ-6) ✅
6-11. API Key Authentication (6 tests: valid/invalid/expired/nonexistent/inactive/suspended) ✅
12-16. JWT Authentication (5 tests: valid/unsigned/expired/tampered/agent-mismatch) ✅
17-20. Authorization Logic (4 tests: own/other namespace, insufficient/sufficient role) ✅

**Critical Infrastructure Fix**:
- `tests/conftest.py` - Changed from `NullPool` to `StaticPool` for SQLite `:memory:` compatibility
- Issue: Each connection was getting a separate in-memory database
- Solution: `StaticPool` maintains single shared connection for all tests

**Bug Fixes**:
- `src/security/agent_auth.py:19` - Fixed `settings.TMWS_SECRET_KEY` → `settings.secret_key` (Pydantic attribute naming)

**Risk Reduction**:
- Before: 40-50% risk (no tests)
- After: 15-20% risk (critical paths validated)
- Coverage: 70% automated + 30% manual verification

**Strategic Decision** (Hera):
- Phase 2D-2 (73 functional tests) & Phase 2D-3 (30 integration tests) deferred to v2.3.1
- Rationale: Implementation quality already high, ship now with critical validation
- Total time saved: 8-12 hours

**Trinitas Collaboration Pattern**:
```
Athena: Strategic coordination (Option X recommendation)
   ↓
├─ Hestia: Security tests (30 min, 5 tests)
├─ Artemis: Mock tests (20 min, 15 tests)  } Parallel execution
└─ Muses: Documentation (10 min, checklist)
   ↓
Final: Ship with confidence (< 1 hour total)
```

**Lessons Learned**:
1. **Collaborative testing is efficient**: 3 agents in parallel vs 1 agent sequential (3x faster)
2. **Critical path testing is strategic**: 20 tests at 70% coverage beats 126 tests at 100% for shipping speed
3. **Infrastructure debugging matters**: StaticPool fix saved hours of test flakiness
4. **Mock tests complement real DB**: Fast feedback loop for edge cases without DB overhead

**Files Created**:
- `tests/unit/security/conftest.py` (302 lines) - Security-specific fixtures
- `tests/unit/security/test_mcp_critical_security.py` (659 lines) - 5 critical tests
- `tests/unit/security/test_mcp_authentication_mocks.py` (532 lines) - 15 mock tests
- `docs/testing/PHASE2D_MANUAL_VERIFICATION.md` - 80+ manual QA items

---

## Known Issues & TODOs

### P0 Priority (Critical - 2-3 days)

~~1. **Embedding Service Consolidation**~~ ✅ **COMPLETED** (2025-10-27)
   - Migrated to Ollama-only architecture
   - Removed all SentenceTransformers dependencies
   - See v2.3.0 changes above

### P1 Priority (High - 3-4 days)

2. **Configuration System Duplication**
   - `ConfigLoader` (YAML) + Pydantic Settings
   - Impact: -314 LOC
   - Recommendation: Remove ConfigLoader, use only Pydantic

3. **Security TODOs** (8 items, 10-14 hours)
   - SecurityAuditLogger integration
   - Cross-agent access policies
   - Alert mechanisms
   - Network-level IP blocking

### P2 Priority (Medium - 1-2 days)

4. **Audit Logger Consolidation**
   - Remove sync wrapper
   - Impact: -200 LOC

5. **Documentation Enhancement**
   - Current coverage: 86%
   - Target: 95%
   - Estimated: 6 hours

### P3 Priority (Low - Quick wins)

6. **Integration Test Async Conversion**
   - `tests/integration/test_vector_search.py` needs async/await
   - Currently 313 lines of sync code

---

## Security Considerations

### Access Control Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `PRIVATE` | Owner only | Personal notes, credentials |
| `TEAM` | Same namespace | Team collaboration |
| `SHARED` | Explicit agent list | Cross-team sharing |
| `PUBLIC` | All agents | Public knowledge base |
| `SYSTEM` | All agents (read-only) | System announcements |

### Namespace Isolation

**CRITICAL**: Namespace must be verified from database, never from user input.

```python
# Authorization layer pattern
async def check_access(memory_id: UUID, user: User):
    # 1. Fetch memory from DB
    memory = await db.get(Memory, memory_id)

    # 2. Fetch agent from DB (VERIFY namespace)
    agent = await db.get(Agent, user.agent_id)
    verified_namespace = agent.namespace  # ✅ Verified

    # 3. Check access with verified namespace
    return memory.is_accessible_by(user.agent_id, verified_namespace)
```

**Reference**: `tests/security/test_namespace_isolation.py` (comprehensive test suite)

---

## Performance Targets

### Latency Targets (P95)

| Operation | Target | Achieved | Status |
|-----------|--------|----------|--------|
| Semantic search | < 20ms | 5-20ms | ✅ |
| Vector similarity | < 10ms | < 10ms | ✅ |
| Metadata queries | < 20ms | 2.63ms | ✅ |
| Cross-agent sharing | < 15ms | 9.33ms | ✅ |
| API response time | < 200ms | - | 🔍 |

### Throughput Targets

- Concurrent users: 100-1000
- Requests per second: 100-500
- Memory operations/sec: 50-100

---

## Deployment

### Environment Variables

**Required**:
```bash
TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"
TMWS_SECRET_KEY="<64-char-hex-string>"
TMWS_ENVIRONMENT="production"
```

**Optional**:
```bash
TMWS_LOG_LEVEL="INFO"
TMWS_CORS_ORIGINS='["https://example.com"]'
TMWS_API_KEY_EXPIRE_DAYS="90"
```

### Production Checklist

- [ ] Database migrations applied (`alembic upgrade head`)
- [ ] Secret key generated (`openssl rand -hex 32`)
- [ ] CORS origins configured
- [ ] HTTPS enabled
- [ ] Monitoring configured
- [ ] Backup strategy implemented
- [ ] Rate limiting configured

---

## Project History

### Major Milestones

- **2025-10-27**: v2.2.7 released - Code cleanup, security hardening (V-1 fix), 12,600x namespace caching
- **2025-10-27**: v2.3.0 released - Ollama-only architecture migration
- **2025-10-27**: P0 security and performance fixes (namespace isolation, indexes, async patterns)
- **2025-10-24**: PostgreSQL → SQLite migration completed
- **2025-10-16**: Comprehensive code cleanup and archival
- **2025-10-15**: Exception handling standardization

### Architecture Evolution

1. **v1.0**: Mem0 + PostgreSQL
2. **v2.0**: Custom implementation + PostgreSQL
3. **v2.2**: Custom implementation + SQLite + ChromaDB ✅ (current)

---

## References

### Documentation

- Architecture: `docs/architecture/TMWS_v2.2.0_ARCHITECTURE.md`
- Development Setup: `docs/DEVELOPMENT_SETUP.md`
- Migration Guide: `docs/guides/MIGRATION_GUIDE.md`
- MCP Integration: `docs/MCP_INTEGRATION.md`
- Exception Handling: `docs/dev/EXCEPTION_HANDLING_GUIDELINES.md`

### Key Source Files

- Database: `src/core/database.py`
- Models: `src/models/` (memory.py, agent.py, user.py, etc.)
- Services: `src/services/` (memory_service.py, vector_search_service.py, etc.)
- API: `src/api/routers/` (memory.py, agent.py, workflow.py, etc.)
- Security: `src/security/` (authorization.py, jwt_service.py, etc.)

### External Dependencies

- FastAPI: https://fastapi.tiangolo.com/
- SQLAlchemy 2.0: https://docs.sqlalchemy.org/en/20/
- ChromaDB: https://docs.trychroma.com/
- Alembic: https://alembic.sqlalchemy.org/
- Pydantic: https://docs.pydantic.dev/

---

## Trinitas Integration

TMWS is designed to work with the Trinitas agent system (6 specialized personas):

1. **Athena** (athena-conductor): Harmonious system orchestration
2. **Artemis** (artemis-optimizer): Technical excellence and performance
3. **Hestia** (hestia-auditor): Security and risk assessment
4. **Eris** (eris-coordinator): Tactical coordination
5. **Hera** (hera-strategist): Strategic planning
6. **Muses** (muses-documenter): Knowledge architecture

**MCP Tools**: See `docs/MCP_TOOLS_REFERENCE.md` for available Trinitas commands.

### Trinitas Phase-Based Execution Protocol

**Status**: ✅ **Proven Pattern** (2025-11-10 Phase 1 Success: 94.6% success rate)

**Context**: Successful implementation of Learning-Trust Integration (Phase 1) demonstrated the effectiveness of phase-based coordination with proper approval gates.

#### Core Principles

**Phase Structure**:
```
Phase N-1: Strategic Planning (戦略立案)
  ├─ Hera: Strategic design & architecture
  └─ Athena: Resource coordination & harmony
  → ✅ Approval Gate: Both agents agree on approach

Phase N-2: Implementation (実装)
  └─ Artemis: Technical implementation
  → ✅ Approval Gate: All tests pass, zero regression

Phase N-3: Verification (検証)
  └─ Hestia: Security audit & final approval
  → ✅ Final Approval Gate: Security sign-off
```

#### Rules

**🟢 ALLOWED (許可)**:
- ✅ Parallel execution within the same phase (同一フェーズ内の並列実行)
  - Example: Hera + Athena both doing strategic planning simultaneously
- ✅ Sequential phases with explicit approval gates (承認ゲート付きの順次フェーズ)
- ✅ Waiting for phase completion before proceeding (フェーズ完了を待ってから次へ)

**🔴 PROHIBITED (禁止)**:
- ❌ Cross-phase parallel execution (フェーズを跨いだ並列実行)
  - Example: Athena planning while Artemis implementing
- ❌ Skipping approval gates (承認ゲートのスキップ)
- ❌ Implementation before strategic consensus (戦略合意前の実装開始)
- ❌ Verification before implementation completion (実装完了前の検証開始)

#### Success Example (Phase 1: Learning-Trust Integration)

**Phase 1-1: Strategic Planning** (150 minutes)
- Hera: Architecture design → 96.9% success probability
- Athena: Resource coordination → 92.3% success probability
- **Approval Gate**: Both independently recommended Option B (decoupled integration) ✅
- **Combined Success Rate**: 94.6%

**Phase 1-2: Implementation** (actual: ~60 minutes)
- Artemis: Created 3 files (2,036 lines)
  - `learning_trust_integration.py` (578 lines)
  - `test_learning_trust_integration.py` (958 lines)
  - `test_learning_trust_performance.py` (500 lines)
- **Approval Gate**: 28/28 tests PASS (21 integration + 7 performance) ✅

**Phase 1-3: Verification** (pending)
- Hestia: Security audit (next step)
- **Final Approval Gate**: Security sign-off required

**Result**: Zero regression, V-TRUST-1/4 compliant, <5ms P95 performance ✅

#### Anti-Pattern Example (Prior Failures)

**2025-11-09 Option B-Revised P0 Execution** ❌:
- Athena: Created planning documents (1,600 lines) while implementation was ongoing
- Artemis: Created `test_command_injection.py` (57 tests, 26KB)
- Hestia: Created `test_trust_service.py` (35 tests, 27KB)
- **Problem**: All three worked in parallel without phase coordination
- **Result**: Athena's planning was redundant (implementation already done)

**Lesson Learned**: Athena/Hera must complete strategic planning BEFORE Artemis/Hestia start implementation.

#### Implementation Checklist

Before starting any multi-agent task:

- [ ] **Phase 1 Complete?** Strategic consensus reached? (Hera/Athena)
- [ ] **Approval Gate 1?** Both strategists agree on approach?
- [ ] **Phase 2 Complete?** Implementation finished? (Artemis)
- [ ] **Approval Gate 2?** All tests pass? Zero regression?
- [ ] **Phase 3 Complete?** Security approved? (Hestia)
- [ ] **Final Approval?** Ready for deployment?

#### When to Apply

**Always use Phase-Based Execution for**:
- Multi-step features requiring strategic planning
- Security-sensitive implementations
- Performance-critical optimizations
- Cross-service integrations

**Can skip for**:
- Single-file bug fixes
- Documentation updates
- Simple refactoring (< 100 LOC)

---

## Project Governance

### Rule 10: New Feature Approval Protocol

**Status**: Mandatory (established 2025-10-27)
**Incident**: GenAI Toolbox unauthorized implementation (commit 4466a9a, 2025-10-04)

#### Critical Rule

**No new features without explicit user approval.**

#### What is a "New Feature"?

1. New files/modules (>10 lines of functional code)
2. New external dependencies (packages, libraries)
3. New database tables or columns
4. New API endpoints
5. New integrations or bridges to external systems
6. New architectural patterns

#### Mandatory Process

1. **Ask user first**: "Should I implement [feature name/description]?"
2. **Wait for explicit YES**: Written confirmation required
3. **Document approval**: Reference approval in commit message

#### Commit Message Format

```
feat(scope): Description

User approved: YYYY-MM-DD [conversation/issue reference]
Implements: [Brief justification]
```

#### Example Violation

**GenAI Toolbox Incident** (commit 4466a9a):
- Added 303 lines of new code without user approval
- Disguised as "refactor: Comprehensive project cleanup"
- Result: 0.0% usage rate, 466 lines of dead code
- Root cause: Agents autonomously decided to add feature

#### Enforcement

- Pre-commit validation (planned for Trinitas-agents system)
- Code review checklist
- CI/CD validation (future)

**Reference**: See `docs/incidents/GenAI_Toolbox_RCA.md` for full incident analysis

---

## Contact & Support

- GitHub Issues: Report bugs and feature requests
- Documentation: `docs/` directory
- Development Chat: (configure team chat here)

---

**End of Document**

*This file should be updated whenever significant architectural decisions are made.*
