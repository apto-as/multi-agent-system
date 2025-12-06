# [Refactor] Extract config.py Validators to Reduce C901 Complexity

## Priority: P2 (Medium)

## Overview
Extract complex validators from `src/core/config.py` to resolve C901 cyclomatic complexity violations.

## Background
- 3 methods exceed complexity threshold of 10
- `validate_required_env_vars`: complexity 14
- `validate_cors_security`: complexity 13
- `_validate_production_settings`: complexity 13
- Security-critical code requires careful refactoring

## Goals

- [ ] Create `src/core/config_validators/` package
- [ ] Extract `env_resolver.py` (environment resolution)
- [ ] Extract `cors_validator.py` (CORS validation)
- [ ] Extract `production_validator.py` (production checks)
- [ ] Extract `secret_manager.py` (secret key handling)
- [ ] Update config.py to use extracted validators
- [ ] Achieve complexity ≤10 for all methods
- [ ] Maintain all security guarantees
- [ ] All existing tests pass

## Target Structure

```
src/core/
├── config.py                      # Simplified Settings class
├── config_validators/
│   ├── __init__.py               # Public API exports
│   ├── env_resolver.py           # Environment variable resolution
│   ├── cors_validator.py         # CORS security validation
│   ├── production_validator.py   # Production security checks
│   └── secret_manager.py         # Secret key generation/loading
└── exceptions.py                  # Existing exceptions
```

## Complexity Targets

| Method | Current | Target |
|--------|---------|--------|
| `validate_required_env_vars` | 14 | ≤7 |
| `validate_cors_security` | 13 | ≤5 |
| `_validate_production_settings` | 13 | ≤3 |

## Extraction Strategy

### env_resolver.py
```python
def resolve_environment_variables(values: dict) -> dict:
    """Main entry point (complexity ~3)."""
    ...

def _resolve_smtp_fields(values: dict) -> None:
    """SMTP resolution (complexity ~3)."""
    ...

def _resolve_database_url(values: dict, environment: str) -> str:
    """Database URL resolution (complexity ~2)."""
    ...
```

### cors_validator.py
```python
def validate_cors_origins(origins: list[str], environment: str) -> list[str]:
    """Main entry (complexity ~2)."""
    ...

def _validate_single_origin(origin: str, environment: str, has_wildcard: bool) -> None:
    """Per-origin validation (complexity ~5)."""
    ...
```

### production_validator.py
```python
@dataclass
class SecurityRule:
    name: str
    condition: Callable[[Settings], bool]
    error_message: str

def validate_production_security_settings(settings: Settings) -> None:
    """Rule-based validation (complexity ~2)."""
    for rule in _get_security_rules():
        if not rule.condition(settings):
            raise ConfigurationError(rule.error_message)
```

## Updated config.py Pattern

```python
@model_validator(mode="before")
@classmethod
def validate_required_env_vars(cls, values):
    from .config_validators import resolve_environment_variables
    return resolve_environment_variables(values)

@field_validator("cors_origins")
@classmethod
def validate_cors_security(cls, v, info):
    from .config_validators import validate_cors_origins
    environment = info.data.get("environment", "development")
    return validate_cors_origins(v, environment)
```

## Security Considerations

- All 404 security standards maintained
- Pydantic validator signatures unchanged
- Error messages preserved exactly
- No changes to Settings public API

## Test Requirements

### New Test Files
- `tests/unit/config_validators/test_env_resolver.py`
- `tests/unit/config_validators/test_cors_validator.py`
- `tests/unit/config_validators/test_production_validator.py`
- `tests/unit/config_validators/test_secret_manager.py`

### Coverage Targets
- All new modules: >95% coverage
- Integration tests: Settings initialization unchanged

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Breaking Settings init | Medium | Critical | Comprehensive integration tests |
| Changing error messages | Low | Medium | Preserve exact messages |
| Import cycle | Low | High | Validators import only stdlib |
| Security weakness | Very Low | Critical | Security audit post-extraction |

## Rollback Strategy

If issues detected:
1. Revert to single-file config.py
2. Add `# noqa: C901` temporarily
3. Schedule for next sprint

## Implementation Order

| Day | Phase | Deliverable |
|-----|-------|-------------|
| 1 | Setup | Package structure + __init__.py |
| 2 | Phase 1 | env_resolver.py + secret_manager.py + tests |
| 3 | Phase 2 | cors_validator.py + tests |
| 4 | Phase 3 | production_validator.py + tests |
| 5 | Integration | Update config.py, full test suite |

## Estimated Effort
- **Duration**: 5 days
- **Risk Level**: Medium (Pydantic integration complexity)

## Labels
- `priority:P2`
- `type:refactor`
- `complexity:medium`

---
**Prepared by**: Hera (Strategic Commander)
**Date**: 2025-12-06
