# Exception Handling Quick Reference

**Quick guide for common exception handling patterns in TMWS**

---

## 🚨 Golden Rules

1. **ALWAYS handle user interrupts first**: `except (KeyboardInterrupt, SystemExit): raise`
2. **ALWAYS log exceptions**: Use `logger.error()` or `log_and_raise()`
3. **ALWAYS use specific exception types**: Avoid bare `except Exception`
4. **ALWAYS preserve exception chains**: Use `raise ... from e`
5. **ALWAYS rollback on database errors**: `await session.rollback()`

---

## 🔧 Common Patterns

### Database Operations

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

### Service Initialization

```python
try:
    self.service = Service()
except (KeyboardInterrupt, SystemExit):
    raise
except Exception as e:
    log_and_raise(
        ServiceInitializationError,
        "Failed to initialize service",
        original_exception=e,
        details={"service_name": "MyService"}
    )
```

### Multi-Step Atomic Operations

```python
# Step 1: SQLite
await session.commit()

# Step 2: ChromaDB (must rollback SQLite if this fails)
try:
    await sync_to_chroma()
except (KeyboardInterrupt, SystemExit):
    await session.rollback()
    raise
except Exception as e:
    await session.rollback()  # Keep databases consistent!
    log_and_raise(MemoryCreationError, "Chroma sync failed", original_exception=e)
```

### Best-Effort Operations (Cleanup)

```python
try:
    await cleanup_temp_files()
except (KeyboardInterrupt, SystemExit):
    raise
except OSError as e:
    logger.warning(f"Cleanup failed (non-critical): {e}")
    # No re-raise - cleanup is optional
```

---

## 📦 Exception Types Reference

| Operation | Exception Type |
|-----------|---------------|
| Database connection | `DatabaseConnectionError` |
| Database query/commit | `DatabaseOperationError` |
| Database schema/migration | `DatabaseInitializationError` |
| Memory creation | `MemoryCreationError` |
| Memory search | `MemorySearchError` |
| Memory update | `MemoryUpdateError` |
| Memory deletion | `MemoryDeletionError` |
| ChromaDB initialization | `ChromaInitializationError` |
| ChromaDB operations | `ChromaOperationError` |
| Embedding generation | `EmbeddingGenerationError` |
| Service initialization | `ServiceInitializationError` |
| Service execution | `ServiceExecutionError` |
| MCP initialization | `MCPInitializationError` |
| MCP tool execution | `MCPToolExecutionError` |
| Ollama API | `OllamaError` |
| GenAI Toolbox | `GenAIToolboxError` |
| Configuration | `ConfigurationError` |
| Environment variables | `EnvironmentVariableError` |

---

## 🛠️ Helper Function

```python
from src.core.exceptions import log_and_raise, DatabaseOperationError

try:
    await risky_operation()
except SpecificError as e:
    log_and_raise(
        DatabaseOperationError,        # Exception class
        "Operation failed",             # Message
        original_exception=e,           # Chain the original error
        details={"context": "value"}    # Extra debugging info
    )
```

**Benefits**:
- Auto-logs with proper level
- Auto-chains exceptions (`from e`)
- Auto-includes stack trace
- Consistent error format

---

## 📊 Log Levels

| Level | When to Use | Example |
|-------|-------------|---------|
| `CRITICAL` | Unexpected errors, system crash risk | `logger.critical(f"Unexpected: {e}", exc_info=True)` |
| `ERROR` | Expected errors preventing operation | `logger.error(f"Failed: {e}", exc_info=True)` |
| `WARNING` | Non-critical failures (best-effort) | `logger.warning(f"Cleanup failed: {e}")` |
| `INFO` | Successful operations | `logger.info("✅ Memory created")` |

**Always use `exc_info=True`** for ERROR and CRITICAL!

---

## ✅ Pre-Commit Checklist

Before committing code with `try-except`:

- [ ] `except (KeyboardInterrupt, SystemExit): raise` is FIRST
- [ ] Specific exception types (not bare `except Exception`)
- [ ] All exceptions logged or auto-logged
- [ ] Exception chains preserved (`from e`)
- [ ] Stack traces included (`exc_info=True`)
- [ ] Context details provided
- [ ] Database rollback on errors

---

## ❌ Anti-Patterns (DO NOT USE)

```python
# ❌ WRONG: Silent failure
try:
    await critical_operation()
except Exception:
    pass  # Error hidden!

# ❌ WRONG: No user interrupt handling
try:
    await operation()
except Exception as e:
    logger.error(f"Error: {e}")
    # Ctrl+C won't work!

# ❌ WRONG: Lost exception chain
try:
    await operation()
except SpecificError as e:
    raise CustomError("Failed")  # Original error lost!

# ❌ WRONG: No stack trace
try:
    await operation()
except Exception as e:
    logger.error(f"Error: {e}")  # Missing exc_info=True

# ❌ WRONG: No rollback
try:
    await session.commit()
except Exception as e:
    logger.error(f"Error: {e}")
    raise  # Session left in bad state!
```

---

## 🔍 Quick Decision Tree

```
Exception caught?
│
├─ Is it KeyboardInterrupt/SystemExit?
│  └─ YES → Rollback (if needed) + raise immediately
│
├─ Is it an expected error (SQLAlchemyError, etc)?
│  ├─ Database operation? → Rollback first
│  └─ log_and_raise(SpecificError, ..., original_exception=e)
│
└─ Is it unexpected (bare Exception)?
   ├─ Database operation? → Rollback first
   ├─ Log as CRITICAL with exc_info=True
   └─ Re-raise
```

---

## 📚 Full Documentation

See `/Users/apto-as/workspace/github.com/apto-as/tmws/docs/dev/EXCEPTION_HANDLING_GUIDELINES.md` for:
- Detailed principles
- Complete exception hierarchy
- Real-world examples with code references
- Helper function documentation
- Migration plan

---

**Quick Start**: Copy the relevant pattern, replace exception type and message, add context details.
