# [Refactor] Split skill_service.py into Modular Package

## Priority: P1 (High)

## Overview
Split `src/services/skill_service.py` (1,851 lines) into a modular package using the composition pattern.

## Background
- Single file with 8 major methods
- Handles CRUD, sharing, activation, versioning
- Difficult to test individual concerns

## Goals

- [ ] Create `src/services/skill_service/` package
- [ ] Extract `skill_crud.py` (CRUD operations)
- [ ] Extract `skill_sharing.py` (share/unshare logic)
- [ ] Extract `skill_activation.py` (activate/deactivate)
- [ ] Create `core.py` (coordinator with composition pattern)
- [ ] Create `__init__.py` with backward-compatible API
- [ ] Verify all tests pass
- [ ] Delete original skill_service.py

## Target Structure

```
src/services/skill_service/
├── __init__.py           # Public API (backward compatible)
├── core.py               # SkillService coordinator (250 lines)
├── skill_crud.py         # CRUD operations (1,100 lines)
├── skill_sharing.py      # Sharing logic (300 lines)
└── skill_activation.py   # Activation/deactivation (500 lines)
```

## Method Distribution

| Method | Target File | Lines |
|--------|-------------|-------|
| `__init__` | core.py | 8 |
| `create_skill` | skill_crud.py | 222 |
| `get_skill` | skill_crud.py | 149 |
| `update_skill` | skill_crud.py | 252 |
| `list_skills` | skill_crud.py | 241 |
| `delete_skill` | skill_crud.py | 159 |
| `share_skill` | skill_sharing.py | 295 |
| `activate_skill` | skill_activation.py | 251 |
| `deactivate_skill` | skill_activation.py | 196 |

## Composition Pattern

```python
# core.py
class SkillService:
    def __init__(self, session: AsyncSession):
        self._crud = SkillCRUDService(session)
        self._sharing = SkillSharingService(session)
        self._activation = SkillActivationService(session)

    async def create_skill(self, **kwargs):
        return await self._crud.create_skill(**kwargs)

    # ... delegate all methods
```

## Backward Compatibility

```python
# Before and after splitting
from src.services.skill_service import SkillService  # WORKS
```

## Implementation Order

1. Extract `skill_sharing.py` (independent)
2. Extract `skill_activation.py` (independent)
3. Extract `skill_crud.py` (bulk of code)
4. Create `core.py` (coordinator)
5. Create `__init__.py` (API surface)
6. Verify tests pass
7. Delete original file

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Import breakage | Low | High | __init__.py re-export |
| Session sharing issues | Low | Medium | Pass session to all sub-services |
| Circular imports | Very Low | High | One-way dependency only |

## Estimated Effort
- **Duration**: 2 days
- **Risk Level**: Low

## Labels
- `priority:P1`
- `type:refactor`
- `complexity:low`

---
**Prepared by**: Artemis (Technical Perfectionist)
**Date**: 2025-12-06
