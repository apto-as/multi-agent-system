# TMWS Exception Handling Guidelines - Knowledge Archive

**Created**: 2025-10-20
**Type**: Development Guidelines
**Status**: Stable

## Summary

Comprehensive exception handling guidelines document created at `/Users/apto-as/workspace/github.com/apto-as/tmws/docs/dev/EXCEPTION_HANDLING_GUIDELINES.md` to address the systematic problem of 300+ silent exception handlers in the TMWS codebase.

## Problem Solved

The codebase had **300+ locations** with `except Exception: pass` anti-pattern that:
- Hid critical errors without logging
- Prevented debugging in production
- Suppressed user interrupts (Ctrl+C)
- Caused database corruption without rollback
- Created resource leaks

## Solution Established

Based on Tier 1 critical path fixes (31 locations across 5 files):

### Core Principles

1. **100% Logging Coverage**: All exceptions must be logged
2. **Specific Exception Types**: Use granular exception classes
3. **User Interrupt Protection**: `KeyboardInterrupt`/`SystemExit` always propagate
4. **Exception Chaining**: Preserve root causes with `from e`
5. **Rich Context**: Include debugging details in all errors

### Exception Hierarchy

```
TMWSException (base - auto-logs)
├── DatabaseException
│   ├── DatabaseConnectionError
│   ├── DatabaseOperationError
│   └── DatabaseInitializationError
├── MemoryException
│   ├── MemoryCreationError
│   ├── MemorySearchError
│   ├── MemoryUpdateError
│   └── MemoryDeletionError
├── ServiceError
│   ├── VectorSearchError
│   │   ├── ChromaInitializationError
│   │   ├── ChromaOperationError
│   │   └── EmbeddingGenerationError
│   └── ServiceInitializationError
├── MCPServerError
│   ├── MCPInitializationError
│   └── MCPToolExecutionError
├── IntegrationError
│   ├── OllamaError
│   └── GenAIToolboxError
└── ConfigurationError
    └── EnvironmentVariableError
```

### Key Patterns

#### Pattern 1: Database Transactions
```python
try:
    await session.commit()
except (KeyboardInterrupt, SystemExit):
    await session.rollback()
    raise
except SQLAlchemyError as e:
    await session.rollback()
    log_and_raise(DatabaseOperationError, "Commit failed", original_exception=e)
```

#### Pattern 2: Service Initialization (Fail-Fast)
```python
try:
    self.service = Service()
except (KeyboardInterrupt, SystemExit):
    raise
except Exception as e:
    log_and_raise(ServiceInitializationError, "Init failed", original_exception=e)
```

#### Pattern 3: Atomic Multi-Step Operations
```python
# Write to SQLite
await session.commit()
# Write to ChromaDB (required)
try:
    await sync_to_chroma()
except Exception as e:
    await session.rollback()  # Rollback SQLite on Chroma failure
    raise
```

### Helper Function

`log_and_raise()` simplifies exception handling:

```python
def log_and_raise(
    exception_class: type[TMWSException],
    message: str,
    original_exception: Exception | None = None,
    details: dict[str, Any] | None = None,
    log_level: int = logging.ERROR,
) -> None:
    """Auto-logs and raises exception with proper chaining."""
```

**Usage**:
```python
try:
    await risky_operation()
except SpecificError as e:
    log_and_raise(
        ServiceExecutionError,
        "Operation failed",
        original_exception=e,
        details={"context": "value"}
    )
```

## Real-World Examples

### Example 1: Database Session (src/core/database.py:131-144)
- Rollback on all errors before propagating
- User interrupts handled first
- Unexpected errors logged as CRITICAL

### Example 2: Memory Creation (src/services/memory_service.py:128-147)
- Atomic rollback if ChromaDB write fails after SQLite commit
- Prevents inconsistent state between databases

### Example 3: ChromaDB Init (src/services/vector_search_service.py:113-126)
- Fail-fast on initialization (don't create broken service)
- Rich error details for debugging

### Example 4: Config Loading (src/core/config.py:499-509)
- Actionable error messages (lists required env vars)
- Differentiates expected vs unexpected errors

### Example 5: MCP Server (src/mcp_server.py:164-178)
- Re-raises expected errors without duplicate logging
- Wraps unexpected errors in MCPInitializationError

## Developer Checklist

Before committing:
- [ ] KeyboardInterrupt/SystemExit handled first
- [ ] Specific exception types (not bare Exception)
- [ ] All exceptions logged (logger or TMWSException)
- [ ] Exception chains preserved (raise ... from e)
- [ ] Stack traces included (exc_info=True)
- [ ] Rich context in details dict
- [ ] Atomic rollback for multi-step operations

## Log Level Guidelines

| Level | Usage |
|-------|-------|
| CRITICAL | Unexpected errors, system crash risk |
| ERROR | Expected errors preventing operation |
| WARNING | Non-critical failures (best-effort) |
| INFO | Successful operations |

## Next Steps

### Tier 2: High-Impact (116 locations)
- memory_service.py (20 remaining)
- vector_search_service.py (15 remaining)
- agent_service.py (12)
- workflow_service.py (18)
- genai_bridge.py (25)
- ollama_client.py (26)

### Tier 3: Moderate-Impact (153 locations)
- Test files (79)
- Scripts (38)
- Utilities (36)

### Validation Metrics
```
Pre-migration:  300 locations, 15% with logging
Post-Tier-1:     31 locations, 100% fixed
Target:         147 locations (Tier 1+2), 95% coverage
```

## Document Location

`/Users/apto-as/workspace/github.com/apto-as/tmws/docs/dev/EXCEPTION_HANDLING_GUIDELINES.md`

## Related Files

- `src/core/exceptions.py` - Exception class definitions
- `VERIFICATION_REPORT.md` - Tier 1 fix analysis
- `.pre-commit-config.yaml` - Future linting integration

## Impact

This guideline enables:
1. **Reliable Production Debugging**: All errors logged with context
2. **Data Integrity**: Atomic rollback prevents corruption
3. **User Control**: Interrupts always work (Ctrl+C)
4. **Code Quality**: Consistent exception handling patterns
5. **Developer Velocity**: Clear examples and helper functions

---

**Status**: ✅ Complete and ready for team adoption
**Next Action**: Begin Tier 2 migration using these guidelines
