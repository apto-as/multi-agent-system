# [Refactor] Split mcp_server.py into Modular Package

## Priority: P1 (High)

## Overview
Split the monolithic `src/mcp_server.py` (1,644 lines) into a modular package structure for improved maintainability.

## Background
- Single file contains server class, tool registration, startup logic, and constants
- Difficult to test individual components
- High cognitive load for new developers

## Goals

- [ ] Create `src/mcp_server/` package directory
- [ ] Extract `constants.py` (TRINITAS_AGENTS)
- [ ] Extract `server.py` (HybridMCPServer class)
- [ ] Extract `tool_registry.py` (_register_tools function)
- [ ] Extract `lifecycle.py` (initialize, cleanup)
- [ ] Extract `startup.py` (main, async_main, first_run_setup)
- [ ] Create `__init__.py` with public API
- [ ] Create `__main__.py` for entry point preservation
- [ ] Verify `python -m src.mcp_server` still works
- [ ] Delete original mcp_server.py

## Target Structure

```
src/mcp_server/
├── __init__.py          # Public API exports
├── __main__.py          # Entry point (python -m src.mcp_server)
├── server.py            # HybridMCPServer class (400 lines)
├── tool_registry.py     # register_core_tools() (600 lines)
├── lifecycle.py         # initialize(), cleanup() (500 lines)
├── startup.py           # main(), async_main(), first_run_setup() (400 lines)
└── constants.py         # TRINITAS_AGENTS (100 lines)
```

## Implementation Order

1. **Create directory structure**
2. **Extract constants.py** (zero dependencies)
3. **Extract startup.py** (minimal dependencies)
4. **Extract lifecycle.py** (depends on server state)
5. **Extract tool_registry.py** (depends on server.mcp)
6. **Create server.py** (core class)
7. **Create __init__.py** (public API)
8. **Create __main__.py** (entry point)
9. **Verify all entry points work**
10. **Delete original file**

## Entry Point Preservation

```python
# __main__.py
from .startup import main
if __name__ == "__main__":
    main()
```

**Verification:**
```bash
python -m src.mcp_server  # Must work
uvx tmws-mcp-server       # Must work
```

## Test Impact

- No import changes needed (backward compatible via __init__.py)
- All existing tests should pass without modification
- New tests can target individual modules

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Entry point breakage | Low | High | __main__.py pattern |
| Import breakage | Low | High | Re-export in __init__.py |
| Tool registration order | Low | Medium | No reordering |

## Rollback Plan
1. Keep backup: `mv mcp_server.py mcp_server_backup.py`
2. If fails: `rm -rf mcp_server/ && mv mcp_server_backup.py mcp_server.py`

## Estimated Effort
- **Duration**: 1-2 days
- **Risk Level**: Low

## Labels
- `priority:P1`
- `type:refactor`
- `complexity:low`

---
**Prepared by**: Eris (Tactical Coordinator)
**Date**: 2025-12-06
