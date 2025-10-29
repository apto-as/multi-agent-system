# TMWS Technical Verification Checklist - Phase 5
## Post-Cleanup Verification Protocol

**Created**: 2025-10-28
**Project**: TMWS v2.2.6
**Context**: Phases 0-3 completed (1,081 ruff fixes, namespace caching)
**Current Status**: 88 failed tests (20.8%), 336 passed, ~85% coverage

---

## Execution Summary

**Estimated Time**: 20-30 minutes
**Prerequisites**:
- Working directory: `/Users/apto-as/workspace/github.com/apto-as/tmws`
- Python 3.11+ with dependencies installed
- Ollama running with multilingual-e5-large model
- Clean git working directory

---

## 1. Code Quality Verification (5 minutes)

### 1.1 Ruff Compliance ✅
**Objective**: Verify 100% ruff compliance maintained

```bash
# Command
ruff check src/ tests/

# Expected Output
All checks passed!

# Pass Criteria
✅ Zero violations reported
❌ Any violation message

# Notes
- Should maintain 100% compliance from Phase 0-1
- If violations found, run: ruff check src/ tests/ --fix
```

### 1.2 Import Statement Validation
**Objective**: No broken imports from namespace changes

```bash
# Command
python -m compileall src/ -q

# Expected Output
(no output - silent success)

# Pass Criteria
✅ Exit code 0, no output
❌ Any SyntaxError or import error

# Detailed Check (if needed)
python -c "
import sys
sys.path.insert(0, 'src')
from utils.namespace import detect_project_namespace
from mcp_server import HybridMCPServer
print('✅ Critical imports OK')
"

# Expected Output
✅ Critical imports OK
```

### 1.3 Type Hint Validation (Optional)
**Objective**: No mypy regressions introduced

```bash
# Command
mypy src/utils/namespace.py src/mcp_server.py --no-error-summary 2>&1 | grep -E "error:|Success"

# Expected Output (if mypy configured)
Success: no issues found

# Pass Criteria
✅ No new type errors in modified files
⚠️  Existing errors OK (not introduced by recent changes)
❌ New errors in src/utils/namespace.py or src/mcp_server.py

# Notes
- TMWS doesn't enforce mypy currently
- This is an optional quality check
```

### 1.4 Docstring Consistency
**Objective**: Docstrings maintained Google style format

```bash
# Command
rg '^    """[A-Z].*\.$' src/utils/namespace.py src/mcp_server.py --count

# Expected Output
src/utils/namespace.py:8
src/mcp_server.py:5

# Pass Criteria
✅ Non-zero count (docstrings exist)
❌ Count of 0 (docstrings removed)

# Manual Spot Check
rg -A 10 'async def detect_project_namespace' src/utils/namespace.py

# Expected Pattern
    """Auto-detect project namespace from environment.

    Detection priority (fastest → slowest):
    1. Environment variable ...
```

---

## 2. Functionality Verification (8 minutes)

### 2.1 Namespace Detection - Priority 1 (Environment Variable)
**Objective**: Highest priority detection works (0.001ms)

```bash
# Test Priority 1: Environment variable
export TRINITAS_PROJECT_NAMESPACE="test-project-env"

python -c "
import asyncio
import sys
sys.path.insert(0, 'src')
from utils.namespace import detect_project_namespace

async def test():
    ns = await detect_project_namespace()
    assert ns == 'test-project-env', f'Expected test-project-env, got {ns}'
    print(f'✅ Priority 1 (env): {ns}')

asyncio.run(test())
"

# Expected Output
✅ Priority 1 (env): test-project-env

# Pass Criteria
✅ Matches exported environment variable
❌ Returns different namespace or crashes
```

### 2.2 Namespace Detection - Priority 2 (Git Repository)
**Objective**: Git-based detection works (1-5ms)

```bash
# Test Priority 2: Git repository (after clearing env var)
unset TRINITAS_PROJECT_NAMESPACE

python -c "
import asyncio
import sys
sys.path.insert(0, 'src')
from utils.namespace import detect_project_namespace

async def test():
    ns = await detect_project_namespace()
    print(f'✅ Priority 2 (git): {ns}')
    # Should be github.com/apto-as/tmws or tmws (if no remote)
    assert 'tmws' in ns.lower(), f'Expected tmws in namespace, got {ns}'

asyncio.run(test())
"

# Expected Output
✅ Priority 2 (git): github.com/apto-as/tmws

# Pass Criteria
✅ Contains 'tmws' or 'github.com/apto-as/tmws'
❌ Returns 'project_' hash (should not fallback if in git repo)
```

### 2.3 Namespace Detection - Priority 4 (Fallback)
**Objective**: Fallback to cwd hash works (0.01ms)

```bash
# Test Priority 4: Fallback (outside git repo)
cd /tmp
python /Users/apto-as/workspace/github.com/apto-as/tmws/tests/manual/test_namespace_fallback.py 2>&1

# Create test script first:
cat > /tmp/test_ns_fallback.py << 'EOF'
import asyncio
import sys
sys.path.insert(0, '/Users/apto-as/workspace/github.com/apto-as/tmws/src')
from utils.namespace import detect_project_namespace

async def test():
    ns = await detect_project_namespace()
    print(f'✅ Priority 4 (fallback): {ns}')
    assert ns.startswith('project_'), f'Expected project_* hash, got {ns}'
    assert len(ns) == 24, f'Expected 24 chars, got {len(ns)}'  # project_ + 16 hex

asyncio.run(test())
EOF

python /tmp/test_ns_fallback.py

# Expected Output
✅ Priority 4 (fallback): project_a1b2c3d4e5f67890

# Pass Criteria
✅ Starts with 'project_' and has 16 hex digits
❌ Crashes or returns unexpected format

# Cleanup
rm /tmp/test_ns_fallback.py
cd /Users/apto-as/workspace/github.com/apto-as/tmws
```

### 2.4 Namespace Caching at Startup
**Objective**: Namespace cached in HybridMCPServer.__init__()

```bash
# Verify caching implementation
rg "self.default_namespace" src/mcp_server.py -C 2

# Expected Output (3 occurrences)
52:        # Namespace (detected once at initialization)
53:        self.default_namespace = None
--
174:            self.default_namespace = await detect_project_namespace()
175:            logger.info(f"🔖 Default namespace detected: {self.default_namespace}")
--
XXX:            # Use cached namespace
XXX:            namespace = self.default_namespace or "default"

# Pass Criteria
✅ 3 occurrences: init (None), detect (set), usage (read)
❌ <3 occurrences (caching not implemented)
```

### 2.5 Memory Operations (store_memory)
**Objective**: MCP tool store_memory still functional

```bash
# Run specific test for store_memory
pytest tests/unit/test_memory_service.py::test_create_memory -v

# Expected Output
tests/unit/test_memory_service.py::test_create_memory PASSED

# Pass Criteria
✅ PASSED
❌ FAILED or ERROR

# Alternative: Integration test
pytest tests/integration/test_memory_integration.py::test_store_and_retrieve -v -k memory
```

### 2.6 Memory Operations (search_memories)
**Objective**: Semantic search still functional

```bash
# Run semantic search tests
pytest tests/unit/test_vector_search_service.py -v -k search

# Expected Output
tests/unit/test_vector_search_service.py::test_search_memories PASSED
tests/unit/test_vector_search_service.py::test_semantic_search PASSED

# Pass Criteria
✅ All search tests PASSED
❌ Any FAILED (vector search broken)
```

### 2.7 MCP Tools Registration
**Objective**: All MCP tools still registered correctly

```bash
# Check tool registration
python -c "
import sys
sys.path.insert(0, 'src')
from mcp_server import HybridMCPServer

server = HybridMCPServer()
# Tools registered in __init__ via _register_tools()

# Count registered tools (via mcp.list_tools())
tool_names = [
    'store_memory', 'search_memories', 'get_memory',
    'create_task', 'get_agent_status', 'get_memory_stats'
]

print(f'✅ MCP tools registered: {len(tool_names)} expected')
"

# Expected Output
✅ MCP tools registered: 6 expected

# Pass Criteria
✅ No exceptions during initialization
❌ ImportError or AttributeError
```

---

## 3. Performance Verification (3 minutes)

### 3.1 Namespace Caching Performance
**Objective**: Startup caches namespace (avoid repeated detection)

```bash
# Measure namespace detection time (cold)
python -c "
import asyncio
import time
import sys
sys.path.insert(0, 'src')
from utils.namespace import detect_project_namespace

async def measure():
    start = time.perf_counter()
    ns = await detect_project_namespace()
    elapsed_ms = (time.perf_counter() - start) * 1000
    print(f'Cold detection: {elapsed_ms:.2f}ms (namespace: {ns})')
    assert elapsed_ms < 50, f'Too slow: {elapsed_ms}ms (expected <50ms)'

asyncio.run(measure())
"

# Expected Output
Cold detection: 1.23ms (namespace: github.com/apto-as/tmws)

# Pass Criteria
✅ <50ms (acceptable for startup, done once)
❌ >50ms (performance regression)
```

### 3.2 No Regression in Vector Search
**Objective**: ChromaDB search still <20ms P95

```bash
# Run performance benchmark
pytest tests/unit/test_vector_search_service.py::test_search_performance -v --benchmark-only

# Expected Output
tests/unit/test_vector_search_service.py::test_search_performance
    Mean: 5-10ms
    P95: <20ms

# Pass Criteria
✅ P95 <20ms (target maintained)
⚠️  P95 20-30ms (minor regression, acceptable)
❌ P95 >30ms (significant regression)

# Note: If benchmark test doesn't exist, skip this check
```

### 3.3 Startup Time Verification
**Objective**: Server startup not significantly increased

```bash
# Measure server initialization time
time python -c "
import asyncio
import sys
sys.path.insert(0, 'src')
from mcp_server import HybridMCPServer

async def init():
    server = HybridMCPServer()
    await server.initialize()
    print('✅ Server initialized')

asyncio.run(init())
" 2>&1 | grep real

# Expected Output
real    0m0.5s  # 500ms or less

# Pass Criteria
✅ <1 second (acceptable startup time)
⚠️  1-2 seconds (minor regression)
❌ >2 seconds (significant regression)
```

---

## 4. Test Coverage Analysis (5 minutes)

### 4.1 Namespace Functionality Test Coverage
**Objective**: New namespace detection has test coverage

```bash
# Find tests for namespace module
rg "from.*namespace import|import.*namespace" tests/ -l

# Expected Files
tests/unit/test_namespace_detection.py  # New or existing
tests/security/test_namespace_isolation.py  # Existing

# Run namespace-specific tests
pytest tests/ -v -k namespace

# Expected Output
tests/unit/test_namespace_detection.py::test_detect_env PASSED
tests/unit/test_namespace_detection.py::test_detect_git PASSED
tests/unit/test_namespace_detection.py::test_sanitize PASSED
tests/security/test_namespace_isolation.py::... PASSED (14 tests)

# Pass Criteria
✅ ≥5 tests covering namespace detection
⚠️  <5 tests (insufficient coverage)
❌ 0 tests (critical gap)
```

### 4.2 Coverage Report for Modified Files
**Objective**: No coverage regression in namespace.py

```bash
# Run coverage for namespace module
pytest tests/unit/ -v --cov=src.utils.namespace --cov-report=term-missing

# Expected Output
src/utils/namespace.py    90%   (10 lines missing: 96-98, 252-253)

# Pass Criteria
✅ ≥85% coverage (acceptable)
⚠️  70-84% coverage (needs improvement)
❌ <70% coverage (insufficient)
```

### 4.3 Integration Test Coverage
**Objective**: End-to-end tests cover namespace usage

```bash
# Run integration tests that should use namespace
pytest tests/integration/ -v -k "memory or agent"

# Expected Output
tests/integration/test_memory_integration.py::test_namespace_isolation PASSED
tests/integration/test_agent_lifecycle.py::... PASSED

# Pass Criteria
✅ Integration tests passing
❌ Failures in namespace-related integration tests
```

### 4.4 Missing Test Analysis
**Objective**: Identify untested edge cases

```bash
# Check for TODOs or FIXME in namespace tests
rg "TODO|FIXME|XXX" tests/ -A 2 | grep -i namespace

# Expected Output
(empty or minimal TODOs)

# Pass Criteria
✅ No critical TODOs in namespace tests
⚠️  Minor TODOs (document for future)
```

---

## 5. Integration Points Verification (7 minutes)

### 5.1 Git Repository State
**Objective**: Clean working directory, no uncommitted changes

```bash
# Check git status
git status --short

# Expected Output
(empty - all changes committed)

# Pass Criteria
✅ Empty output (clean working directory)
⚠️  M src/... or M tests/... (uncommitted changes exist)

# If uncommitted changes, review:
git diff src/ tests/ | head -50
```

### 5.2 Recent Commits Validation
**Objective**: Recent commits properly documented

```bash
# Show last 3 commits
git log --oneline -3

# Expected Output
16eb834 perf: Cache namespace detection at server startup (Phase 2)
fb32dd3 style: Apply ruff auto-fixes (COM812, D212, D413)
c391d40 feat: P0-1 & P0-2 Namespace isolation and auto-detection (Combined)

# Pass Criteria
✅ Commit messages follow conventional commits format
✅ Phase numbers align with work performed
❌ Commit messages unclear or missing context
```

### 5.3 Database Migrations Applied
**Objective**: No pending migrations

```bash
# Check Alembic migration status
alembic current

# Expected Output
16eb834abc12 (head)  # Latest migration applied

# Check for pending migrations
alembic check

# Expected Output
(no output - all migrations applied)

# Pass Criteria
✅ Current = head, no pending migrations
⚠️  Pending migrations (need to run: alembic upgrade head)
```

### 5.4 Configuration Validation
**Objective**: No hardcoded values introduced

```bash
# Check for hardcoded namespaces in production code
rg '"default"|"test-project"|"project_[a-f0-9]{16}"' src/ --type py -C 1

# Expected Matches (acceptable)
src/utils/namespace.py:82:    if namespace.lower() == "default":  # Validation
src/utils/namespace.py:257:    namespace = f"project_{cwd_hash}"  # Fallback template

# Pass Criteria
✅ Only validation/template code (2-3 matches)
❌ Hardcoded namespaces in services or models (>5 matches)

# Check for removed environment variable fallbacks
rg "TMWS_EMBEDDING_PROVIDER|TMWS_EMBEDDING_FALLBACK" src/ tests/

# Expected Output
(empty - removed in v2.3.0)

# Pass Criteria
✅ No matches (old config removed)
❌ Matches found (cleanup incomplete)
```

### 5.5 Dependency Validation
**Objective**: No missing or conflicting dependencies

```bash
# Verify critical dependencies installed
pip list | grep -E "fastmcp|chromadb|sqlalchemy|ollama"

# Expected Output
chromadb                 0.4.22
fastmcp                  0.1.0
sqlalchemy               2.0.23

# Pass Criteria
✅ All critical packages present with correct versions
❌ Missing packages or version mismatches

# Check for dependency conflicts
pip check 2>&1 | grep -i "incompatible\|conflict"

# Expected Output
No broken requirements found.

# Pass Criteria
✅ No conflicts
❌ Dependency conflicts detected
```

---

## 6. Current Known Issues (Reference Only)

### 6.1 Test Failures (88 failures, 20.8%)
**Status**: Known issue, not introduced by Phase 0-3 changes

```bash
# Quick check: Are failures in namespace-related tests?
pytest tests/ -v --tb=no | grep -E "(FAILED|ERROR)" | grep -i namespace

# Expected Output
(empty - namespace tests should pass)

# Pass Criteria
✅ No namespace-related failures
❌ Namespace tests failing (regression introduced)
```

### 6.2 Test Failure Categorization
**Objective**: Confirm failures are pre-existing, not from recent changes

```bash
# Run tests that might be affected by namespace changes
pytest tests/unit/test_memory_service.py tests/security/test_namespace_isolation.py -v

# Expected Result
- Namespace isolation tests: PASSED (14/14)
- Memory service tests: May have pre-existing failures

# Pass Criteria
✅ Namespace-specific tests passing
✅ No new failures introduced
❌ Previously passing tests now failing
```

---

## Final Checklist Summary

| Category | Checks | Pass Criteria | Status |
|----------|--------|---------------|--------|
| **Code Quality** | 4 checks | All pass | ⬜ |
| - Ruff compliance | 100% clean | ✅ Required | ⬜ |
| - Import validation | No broken imports | ✅ Required | ⬜ |
| - Type hints | No new mypy errors | ⚠️ Optional | ⬜ |
| - Docstrings | Format maintained | ✅ Required | ⬜ |
| **Functionality** | 7 checks | All pass | ⬜ |
| - Namespace P1 (env) | Correct detection | ✅ Required | ⬜ |
| - Namespace P2 (git) | Correct detection | ✅ Required | ⬜ |
| - Namespace P4 (fallback) | Correct detection | ✅ Required | ⬜ |
| - Namespace caching | Cached at startup | ✅ Required | ⬜ |
| - store_memory | Tool functional | ✅ Required | ⬜ |
| - search_memories | Tool functional | ✅ Required | ⬜ |
| - MCP tools | All registered | ✅ Required | ⬜ |
| **Performance** | 3 checks | No regressions | ⬜ |
| - Namespace detection | <50ms cold start | ✅ Required | ⬜ |
| - Vector search | <20ms P95 | ⚠️ Target | ⬜ |
| - Startup time | <1 second | ⚠️ Target | ⬜ |
| **Test Coverage** | 4 checks | ≥85% coverage | ⬜ |
| - Namespace tests | ≥5 tests | ✅ Required | ⬜ |
| - Coverage report | ≥85% namespace.py | ⚠️ Target | ⬜ |
| - Integration tests | Passing | ✅ Required | ⬜ |
| - Missing tests | None critical | ✅ Required | ⬜ |
| **Integration** | 5 checks | All pass | ⬜ |
| - Git status | Clean working dir | ✅ Required | ⬜ |
| - Commits | Properly documented | ✅ Required | ⬜ |
| - Migrations | All applied | ✅ Required | ⬜ |
| - Configuration | No hardcoded values | ✅ Required | ⬜ |
| - Dependencies | No conflicts | ✅ Required | ⬜ |

---

## Severity Legend

- ✅ **Required**: Must pass, blocks deployment
- ⚠️ **Target**: Should pass, acceptable minor variance
- ℹ️ **Optional**: Nice to have, not blocking

---

## Troubleshooting Guide

### Issue: Ruff violations detected
**Solution**:
```bash
ruff check src/ tests/ --fix
git diff  # Review changes
git add -p  # Stage selectively
git commit -m "style: Fix ruff violations post-Phase 3"
```

### Issue: Namespace detection returning "default"
**Cause**: Validation rejecting "default" namespace
**Solution**:
```bash
# Set explicit namespace
export TRINITAS_PROJECT_NAMESPACE="github.com/apto-as/tmws"

# Or create marker file
cat > .trinitas-project.yaml << EOF
namespace: github.com/apto-as/tmws
EOF
```

### Issue: Import errors in namespace module
**Solution**:
```bash
# Verify module structure
python -c "import sys; sys.path.insert(0, 'src'); import utils.namespace; print('OK')"

# Check for circular imports
python -m compileall src/ -q
```

### Issue: Performance regression detected
**Investigation**:
```bash
# Profile namespace detection
python -m cProfile -s cumulative -o namespace.prof << EOF
import asyncio
import sys
sys.path.insert(0, 'src')
from utils.namespace import detect_project_namespace
asyncio.run(detect_project_namespace())
EOF

python -c "import pstats; pstats.Stats('namespace.prof').strip_dirs().sort_stats('cumulative').print_stats(20)"
```

---

## Completion Criteria

**Phase 5 Complete When**:
1. All ✅ Required checks pass
2. No new test failures introduced
3. Git working directory clean
4. Documentation updated (this checklist)

**Sign-Off**:
- [ ] Code quality verified
- [ ] Functionality verified
- [ ] Performance acceptable
- [ ] Test coverage sufficient
- [ ] Integration points clean
- [ ] Known issues documented
- [ ] Ready for Phase 6 (P0-4: Async/Sync Pattern Fix)

---

**Document Version**: 1.0
**Last Updated**: 2025-10-28
**Next Review**: After Phase 6 completion
