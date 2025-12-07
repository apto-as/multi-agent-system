# ISSUE #2: Implementation Checklist

## Pre-Flight Checks
- [ ] Backup original file: `cp src/mcp_server.py src/mcp_server_backup.py`
- [ ] Create package directory: `mkdir -p src/mcp_server`
- [ ] Verify git status is clean: `git status`
- [ ] Create feature branch: `git checkout -b refactor/mcp-server-split-issue-02`

---

## Phase 1: Extract Zero-Dependency Modules (15 min)

### Step 1.1: Extract constants.py
- [ ] Create `src/mcp_server/constants.py`
- [ ] Copy lines 1-18 (version detection)
- [ ] Copy lines 50-107 (TRINITAS_AGENTS)
- [ ] Verify: `python -c "from src.mcp_server.constants import TRINITAS_AGENTS; print(len(TRINITAS_AGENTS))"`
  - Expected output: `9`

### Step 1.2: Extract validation.py
- [ ] Create `src/mcp_server/validation.py`
- [ ] Copy lines 1518-1568 (`validate_license_at_startup` function)
- [ ] Add imports: `from datetime import datetime`, `from src.core.database import get_db_session`, `from src.services.license_service import LicenseService`
- [ ] Verify: `python -c "from src.mcp_server.validation import validate_license_at_startup"`

---

## Phase 2: Extract Server Core (20 min)

### Step 2.1: Extract server.py
- [ ] Create `src/mcp_server/server.py`
- [ ] Add header docstring (lines 1-11)
- [ ] Add imports (lines 13-47)
- [ ] Copy `HybridMCPServer` class definition (lines 110-122)
- [ ] Copy `__init__` method (lines 123-157) **BUT**:
  - [ ] Remove `self._register_tools()` call (line 155)
  - [ ] Add placeholder: `# Tool registration deferred to __init__ completion`
- [ ] Copy memory operation methods (lines 950-1086):
  - [ ] `store_memory_hybrid`
  - [ ] `search_memories_hybrid`
- [ ] Copy agent/task operation methods (lines 1088-1196):
  - [ ] `_create_task`
  - [ ] `_get_agent_status`
- [ ] Copy stats/cleanup methods (lines 1198-1306):
  - [ ] `get_hybrid_memory_stats`
  - [ ] `clear_chroma_cache`
  - [ ] `_update_avg_latency`
  - [ ] `cleanup` (MOVE to lifecycle.py in Phase 3)
- [ ] Fix imports: `from .constants import __version__`
- [ ] Verify: `python -c "from src.mcp_server.server import HybridMCPServer; s = HybridMCPServer()"`

### Step 2.2: Extract tool_registry.py
- [ ] Create `src/mcp_server/tool_registry.py`
- [ ] Add imports: `from typing import TYPE_CHECKING`, `if TYPE_CHECKING: from .server import HybridMCPServer`
- [ ] Create function signature:
  ```python
  def register_core_tools(mcp_server: 'HybridMCPServer') -> None:
      """Register all MCP tools with the server."""
      mcp = mcp_server.mcp
  ```
- [ ] Copy tool decorator definitions (lines 162-467):
  - [ ] Replace `@self.mcp.tool` with `@mcp.tool`
  - [ ] Replace `await self.store_memory_hybrid` with `await mcp_server.store_memory_hybrid`
  - [ ] Replace `self.agent_id` with `mcp_server.agent_id`
  - [ ] Replace `self.default_namespace` with `mcp_server.default_namespace`
  - [ ] Replace `self.external_mcp_manager` with `mcp_server.external_mcp_manager`
- [ ] Tools to migrate:
  - [ ] `store_memory` (lines 162-191)
  - [ ] `search_memories` (lines 193-220)
  - [ ] `create_task` (lines 222-234)
  - [ ] `get_agent_status` (lines 236-239)
  - [ ] `get_memory_stats` (lines 241-244)
  - [ ] `invalidate_cache` (lines 246-249)
  - [ ] `list_mcp_servers` (lines 256-308)
  - [ ] `connect_mcp_server` (lines 310-387)
  - [ ] `disconnect_mcp_server` (lines 389-427)
  - [ ] `get_mcp_status` (lines 429-463)
- [ ] Update `server.py` `__init__` to call `register_core_tools(self)` after `self.mcp` creation
- [ ] Verify: `python -c "from src.mcp_server.tool_registry import register_core_tools"`

---

## Phase 3: Extract Lifecycle (25 min)

### Step 3.1: Extract lifecycle.py
- [ ] Create `src/mcp_server/lifecycle.py`
- [ ] Add imports:
  ```python
  import logging
  import os
  from typing import TYPE_CHECKING
  if TYPE_CHECKING:
      from .server import HybridMCPServer
  from .constants import TRINITAS_AGENTS
  ```
- [ ] Copy `initialize` function (lines 469-933):
  - [ ] Change signature: `async def initialize(server: 'HybridMCPServer') -> None:`
  - [ ] Replace `self.` with `server.`
  - [ ] **Remove** expiration tools registration (lines 482-493) - keep in initialize but as comment for now
  - [ ] Keep all other tool registrations (verification, skill, agent, routing, communication, orchestration, learning, pattern-skill, tool search, MCP hub)
  - [ ] Ensure `tool_registry.register_core_tools(server)` is NOT called here (already in server.__init__)
- [ ] Copy `cleanup` function (lines 1271-1306):
  - [ ] Change signature: `async def cleanup(server: 'HybridMCPServer') -> None:`
  - [ ] Replace `self.` with `server.`
- [ ] Verify: `python -c "from src.mcp_server.lifecycle import initialize, cleanup"`

**Critical**: Verify tool registration happens exactly once:
- [ ] Core tools (store_memory, search_memories, etc.) → `server.__init__` via `tool_registry.register_core_tools(self)`
- [ ] All other tools (expiration, verification, skill, etc.) → `lifecycle.initialize(server)`

---

## Phase 4: Extract Startup (20 min)

### Step 4.1: Extract startup.py
- [ ] Create `src/mcp_server/startup.py`
- [ ] Add imports:
  ```python
  import asyncio
  import logging
  import os
  import sys
  from pathlib import Path
  from .server import HybridMCPServer
  from .lifecycle import initialize, cleanup
  from .validation import validate_license_at_startup
  from .constants import __version__
  from src.core.config import get_settings
  from src.core.database import get_engine
  from src.models import TMWSBase
  ```
- [ ] Copy `first_run_setup` function (lines 1308-1474)
- [ ] Copy `async_main` function (lines 1476-1516):
  - [ ] Replace `server = HybridMCPServer()` (keep as-is)
  - [ ] Replace `await server.initialize()` with `await initialize(server)`
  - [ ] Replace `await server.cleanup()` with `await cleanup(server)` (already in finally block)
- [ ] Copy `main` function (lines 1571-1644):
  - [ ] Ensure license validation uses `validate_license_at_startup` from `.validation`
- [ ] Verify: `python -c "from src.mcp_server.startup import main, async_main, first_run_setup"`

---

## Phase 5: Create Public API (10 min)

### Step 5.1: Create __init__.py
- [ ] Create `src/mcp_server/__init__.py` with content:
  ```python
  """TMWS MCP Server - Hybrid SQLite + Chroma Implementation

  MCP Server providing Trinitas agents with:
  - Ultra-fast vector search via Chroma (P95: 0.47ms)
  - Multilingual-E5 embeddings (1024-dimensional, cross-lingual)
  - SQLite as relational data store
  - Agent coordination and task management

  Architecture: SQLite + ChromaDB
  """

  from .constants import __version__, TRINITAS_AGENTS
  from .server import HybridMCPServer
  from .startup import main, async_main, first_run_setup

  __all__ = [
      "__version__",
      "TRINITAS_AGENTS",
      "HybridMCPServer",
      "main",
      "async_main",
      "first_run_setup",
  ]
  ```
- [ ] Verify: `python -c "from src.mcp_server import HybridMCPServer, main, __version__; print(__version__)"`

### Step 5.2: Create __main__.py
- [ ] Create `src/mcp_server/__main__.py` with content:
  ```python
  """Entry point for python -m src.mcp_server."""
  from .startup import main

  if __name__ == "__main__":
      main()
  ```
- [ ] Verify: `python -m src.mcp_server --help` (will fail on license, but module loads)

---

## Phase 6: Validation & Cleanup (15 min)

### Step 6.1: Verify Entry Points
- [ ] Test module execution: `python -m src.mcp_server`
  - Expected: License validation error (TMWS_LICENSE_KEY not set)
  - If error is different, rollback and debug
- [ ] Test direct import: `python -c "from src.mcp_server import HybridMCPServer; print(HybridMCPServer)"`
  - Expected: `<class 'src.mcp_server.server.HybridMCPServer'>`
- [ ] Test version import: `python -c "from src.mcp_server import __version__; print(__version__)"`
  - Expected: `2.4.16` (or current version)

### Step 6.2: Run Existing Tests
- [ ] Run namespace detection tests:
  ```bash
  pytest tests/integration/test_namespace_detection.py::test_hybrid_server_namespace_detection -v
  ```
  - Expected: PASS (or SKIP if license not set)
- [ ] Run MCP tool tests:
  ```bash
  pytest tests/integration/test_mcp_tools_summary.py -v -k "not license" || true
  ```
  - Expected: Most tests PASS or SKIP (license-gated)

### Step 6.3: Update Deprecated Scripts
- [ ] Fix `scripts/start_mcp_server.py`:
  - [ ] Replace `from src.mcp_server import TMWSFastMCPServer, create_server` with `from src.mcp_server import HybridMCPServer, main`
- [ ] Fix `scripts/run_mcp.py`:
  - [ ] Replace `from src.mcp_server import run_server` with `from src.mcp_server import main`

### Step 6.4: Delete Original File
- [ ] Verify all tests pass
- [ ] Delete: `rm src/mcp_server.py`
- [ ] Delete backup: `rm src/mcp_server_backup.py` (after confirmation)
- [ ] Git status check: `git status`
  - Expected: `deleted: src/mcp_server.py`, `new file: src/mcp_server/*.py`

---

## Phase 7: Documentation & Commit (10 min)

### Step 7.1: Update Documentation
- [ ] Update `docs/issues/ISSUE_02_MCP_SERVER_SPLIT.md`:
  - [ ] Mark all tasks as completed
  - [ ] Add "Completed: 2025-12-07" timestamp
- [ ] Update `CHANGELOG.md`:
  ```markdown
  ## [Unreleased]
  ### Refactored
  - Split monolithic `src/mcp_server.py` (1,645 lines) into modular package with 8 focused modules (ISSUE-02)
    - Improved maintainability and testability
    - Zero backward compatibility breakage
    - All entry points preserved (`python -m src.mcp_server`, `uvx tmws-mcp-server`)
  ```

### Step 7.2: Commit Changes
- [ ] Stage all changes: `git add src/mcp_server/ scripts/ docs/ CHANGELOG.md`
- [ ] Commit with detailed message:
  ```bash
  git commit -m "refactor(mcp): Split mcp_server.py into modular package (ISSUE-02)

  BREAKING CHANGES: None (backward compatible via __init__.py re-exports)

  Architecture:
  - constants.py: TRINITAS_AGENTS, __version__ (70 lines)
  - validation.py: License validation (80 lines)
  - server.py: HybridMCPServer core logic (220 lines)
  - tool_registry.py: MCP tool decorators (320 lines)
  - lifecycle.py: initialize(), cleanup() (520 lines)
  - startup.py: main(), async_main(), first_run_setup() (280 lines)
  - __init__.py: Public API exports (30 lines)
  - __main__.py: Entry point preservation (8 lines)

  Total: 1,528 lines (117 lines reduction from original 1,645)

  Verified:
  - All entry points work (python -m, uvx, direct import)
  - Zero circular dependencies (DAG confirmed)
  - All tests pass (namespace detection, MCP tools)
  - Scripts updated (start_mcp_server.py, run_mcp.py)

  Risk: LOW
  Effort: 3 hours
  Reviewed-by: Hera (Strategic Commander)
  "
  ```
- [ ] Push to remote: `git push -u origin refactor/mcp-server-split-issue-02`

---

## Phase 8: Post-Merge Validation (5 min)

### After PR Merge to Main
- [ ] Pull latest main: `git checkout main && git pull`
- [ ] Run full test suite: `pytest tests/ -v --tb=short`
- [ ] Verify production deployment (if applicable)
- [ ] Close ISSUE-02 in issue tracker

---

## Rollback Plan (If Needed)

### Immediate Rollback (Before Commit)
```bash
rm -rf src/mcp_server/
mv src/mcp_server_backup.py src/mcp_server.py
git restore scripts/
```

### Post-Commit Rollback
```bash
git revert <commit-hash>
git push origin refactor/mcp-server-split-issue-02
```

### Post-Merge Rollback
```bash
git checkout main
git revert <merge-commit-hash>
git push origin main
```

---

## Completion Criteria

### Definition of Done
- [ ] All 8 modules created and functional
- [ ] Original `mcp_server.py` deleted
- [ ] All entry points verified (`python -m`, `uvx`, import)
- [ ] All existing tests pass (or skip due to license)
- [ ] No circular dependencies detected
- [ ] Documentation updated (CHANGELOG, ISSUE-02)
- [ ] Code committed and pushed to feature branch
- [ ] PR created and ready for review

### Success Metrics
- [ ] Line count reduction: 1,645 → 1,528 (7% reduction)
- [ ] Module count: 1 → 8 (focused modules)
- [ ] Test failures: 0 (regression-free)
- [ ] Import breakage: 0 (backward compatible)
- [ ] Performance degradation: < 1% (negligible)

---

**Prepared by**: Hera (Strategic Commander)
**Checklist Date**: 2025-12-07
**Estimated Duration**: 3 hours
**Risk Level**: LOW
