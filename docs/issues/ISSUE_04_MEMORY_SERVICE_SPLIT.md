# [Refactor] Split memory_service.py into Modular Package

## Priority: P2 (Medium)

## Overview
Split `src/services/memory_service.py` (1,982 lines) into a modular package for the core memory management system.

## Background
- Largest service file in codebase
- 27 methods handling CRUD, search, expiration, statistics
- Mixed responsibilities
- Core business logic - requires careful migration

## Goals

- [ ] Create `src/services/memory_service/` package
- [ ] Extract `validation.py` (TTL validation)
- [ ] Extract `crud_operations.py` (CRUD)
- [ ] Extract `search_operations.py` (vector search)
- [ ] Extract `expiration_manager.py` (TTL cleanup)
- [ ] Extract `namespace_operations.py` (namespace cleanup)
- [ ] Extract `statistics.py` (stats & TTL management)
- [ ] Create `core.py` (HybridMemoryService coordinator)
- [ ] Create `__init__.py` with backward-compatible API
- [ ] Verify all tests pass
- [ ] Delete original memory_service.py

## Target Structure

```
src/services/memory_service/
├── __init__.py              # Public API (backward compatible)
├── core.py                  # HybridMemoryService coordinator
├── validation.py            # TTL & access level validation (122 lines)
├── crud_operations.py       # CRUD operations (410 lines)
├── search_operations.py     # Vector search (169 lines)
├── expiration_manager.py    # TTL cleanup (196 lines)
├── namespace_operations.py  # Namespace cleanup (589 lines)
└── statistics.py            # Stats & TTL management (251 lines)
```

## Method Distribution

### validation.py (122 lines)
- `_validate_ttl_days` (L46-99)
- `_validate_access_level_ttl_limit` (L101-167)

### crud_operations.py (410 lines)
- `create_memory` (L253-430)
- `get_memory` (L456-571)
- `update_memory` (L573-633)
- `delete_memory` (L635-662)
- `batch_create_memories` (L834-945)

### search_operations.py (169 lines)
- `search_memories` (L664-772)
- `_search_chroma` (L774-802)
- `_fetch_memories_by_ids` (L804-832)

### expiration_manager.py (196 lines)
- `cleanup_old_memories` (L1001-1053)
- `find_expired_memories` (L1055-1076)
- `cleanup_expired_memories` (L1078-1164)
- `run_expiration_cleanup` (L1166-1196)

### namespace_operations.py (589 lines)
- `cleanup_namespace` (L1198-1520)
- `prune_expired_memories` (L1522-1786)

### statistics.py (251 lines)
- `count_memories` (L947-965)
- `get_memory_stats` (L967-999)
- `set_memory_ttl` (L1788-1975)

## Dependency Graph

```
Core (core.py)
├── _ensure_initialized() ← ALL async methods
├── _sync_to_chroma() ← create, update, batch_create
└── Properties: embedding_service, vector_service, agent_service

CRUD → validation, core._sync_to_chroma
Search → core._ensure_initialized
Expiration → core._ensure_initialized
Namespace → core._ensure_initialized, core._ensure_audit_initialized
Statistics → core._ensure_initialized
```

## Implementation Order

1. **Phase 1**: Extract `validation.py` (no dependencies)
2. **Phase 2**: Extract `statistics.py`, `expiration_manager.py` (minimal deps)
3. **Phase 3**: Extract `search_operations.py` (depends on core)
4. **Phase 4**: Extract `crud_operations.py` (depends on validation)
5. **Phase 5**: Extract `namespace_operations.py` (complex, depends on core)
6. **Phase 6**: Create `core.py` (coordinator)
7. **Phase 7**: Create `__init__.py`, verify tests

## Backward Compatibility

```python
# All existing imports continue to work
from src.services.memory_service import HybridMemoryService, get_memory_service
```

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Breaking imports | Low | High | __init__.py re-exports all |
| Internal method calls fail | Medium | High | Careful dependency mapping |
| ChromaDB sync issues | Low | High | Test vector operations extensively |
| Performance regression | Very Low | Medium | Benchmark before/after |

## Test Files to Verify

- `tests/integration/test_memory_service.py`
- `tests/security/test_memory_expiration.py`
- `tests/unit/services/test_memory_service_audit.py`
- `tests/integration/test_memory_service_audit_integration.py`
- `tests/unit/services/test_memory_security_phase1.py`
- `tests/integration/test_memory_rate_limiting.py`
- `tests/integration/test_memory_crud_workflow.py`

## Estimated Effort
- **Duration**: 2-3 days
- **Risk Level**: Medium (core business logic)

## Labels
- `priority:P2`
- `type:refactor`
- `complexity:medium`

---
**Prepared by**: Athena (Harmonious Conductor)
**Date**: 2025-12-06
