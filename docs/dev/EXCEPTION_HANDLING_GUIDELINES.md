# TMWS Exception Handling Guidelines

**Version**: 1.0
**Last Updated**: 2025-10-20
**Status**: Stable

## Table of Contents

1. [Overview](#overview)
2. [Design Principles](#design-principles)
3. [Exception Class Hierarchy](#exception-class-hierarchy)
4. [Common Patterns](#common-patterns)
5. [Logging Guidelines](#logging-guidelines)
6. [Developer Checklist](#developer-checklist)
7. [Real-World Examples](#real-world-examples)
8. [Helper Functions](#helper-functions)
9. [Next Steps](#next-steps)

---

## Overview

This document establishes best practices for exception handling in TMWS. It addresses the systematic problem of **300+ silent exception handlers** (`except Exception: pass`) that were hiding critical errors and making debugging impossible.

### The Problem

```python
# ❌ CRITICAL ANTI-PATTERN
try:
    await critical_operation()
except Exception:
    pass  # Error silently swallowed - NO LOGGING, NO VISIBILITY
```

**Impact**:
- Production failures with no diagnostic information
- Database corruption without rollback
- Resource leaks (connections, files, memory)
- User interrupts (Ctrl+C) being suppressed
- Development velocity reduced by blind debugging

### The Solution

Following Tier 1 critical path fixes (31 locations across 5 files), we established:
- **100% logging coverage** for all exceptions
- **Specific exception types** for granular error handling
- **Proper exception chaining** to preserve root causes
- **KeyboardInterrupt/SystemExit protection** for user control
- **Rich context** in all error messages

---

## Design Principles

### 1. All Exceptions Must Be Logged

**Rule**: Every `except` block must produce a log entry or raise a custom exception that auto-logs.

```python
# ✅ CORRECT: Explicit logging
try:
    result = await operation()
except SpecificError as e:
    logger.error(f"Operation failed: {e}", exc_info=True)
    raise

# ✅ CORRECT: Auto-logging via TMWSException
try:
    result = await operation()
except SpecificError as e:
    log_and_raise(
        DatabaseOperationError,
        "Failed to execute query",
        original_exception=e,
        details={"query": query_name}
    )
```

### 2. Use Specific Exception Types

**Rule**: Always catch the most specific exception type possible.

```python
# ❌ WRONG: Too broad
try:
    await db.commit()
except Exception as e:
    logger.error(f"Error: {e}")

# ✅ CORRECT: Specific types
try:
    await db.commit()
except (KeyboardInterrupt, SystemExit):
    raise
except SQLAlchemyError as e:
    log_and_raise(DatabaseOperationError, "Commit failed", original_exception=e)
except Exception as e:
    logger.critical(f"Unexpected error: {e}", exc_info=True)
    raise
```

### 3. Never Suppress User Interrupts

**Rule**: `KeyboardInterrupt` and `SystemExit` must always be caught first and re-raised immediately.

```python
# ✅ CORRECT: User interrupts always propagate
try:
    await long_running_operation()
except (KeyboardInterrupt, SystemExit):
    # Never suppress - user wants to stop execution
    raise
except OperationError as e:
    logger.error(f"Operation failed: {e}")
    raise
```

**Why**: Suppressing these exceptions prevents users from stopping runaway processes (Ctrl+C becomes ineffective).

### 4. Preserve Exception Chains

**Rule**: Always use `raise ... from e` to maintain the original exception context.

```python
# ❌ WRONG: Lost root cause
try:
    await db.query()
except SQLAlchemyError as e:
    raise DatabaseError("Query failed")  # Original exception lost!

# ✅ CORRECT: Preserved chain
try:
    await db.query()
except SQLAlchemyError as e:
    raise DatabaseError("Query failed") from e  # Root cause preserved
```

### 5. Include Rich Context

**Rule**: Exception messages and details must contain enough information for debugging.

```python
# ❌ WRONG: Generic message
raise DatabaseError("Database error")

# ✅ CORRECT: Rich context
log_and_raise(
    DatabaseOperationError,
    "Failed to commit transaction",
    original_exception=e,
    details={
        "operation": "commit",
        "table": table_name,
        "session_id": id(session),
        "transaction_depth": session.transaction.nested
    }
)
```

---

## Exception Class Hierarchy

All TMWS custom exceptions inherit from `TMWSException`, which provides **auto-logging**.

### Base Exception

```python
class TMWSException(Exception):
    """
    Base exception for TMWS.

    Features:
    - Auto-logs at specified level when raised
    - Stores structured details dict
    - Includes full stack trace
    """
    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        log_level: int = logging.ERROR,
    ):
        # Auto-logging happens here
        logger.log(log_level, f"{self.__class__.__name__}: {message}",
                   extra={"details": details}, exc_info=True)
```

### Database Exceptions

```python
DatabaseException          # Base for all database errors
├── DatabaseConnectionError    # Connection failures
├── DatabaseOperationError     # Query/commit failures
└── DatabaseInitializationError # Schema/migration failures
```

**Usage**:
```python
try:
    await session.execute(stmt)
except SQLAlchemyError as e:
    log_and_raise(DatabaseOperationError, "Query failed", original_exception=e)
```

### Service Exceptions

```python
ServiceError               # Base for service errors
├── ServiceInitializationError # Service startup failures
└── ServiceExecutionError      # Runtime operation failures
```

**Usage**:
```python
try:
    await service.initialize()
except Exception as e:
    log_and_raise(ServiceInitializationError, "Failed to start service",
                  original_exception=e)
```

### Memory Exceptions

```python
MemoryException           # Base for memory operations
├── MemoryCreationError      # create_memory() failures
├── MemorySearchError        # search() failures
├── MemoryUpdateError        # update() failures
├── MemoryDeletionError      # delete() failures
└── MemoryNotFoundError      # Specific memory not found
```

**Usage**:
```python
try:
    memory = await memory_service.create_memory(content)
except SQLAlchemyError as e:
    log_and_raise(MemoryCreationError, "Failed to create memory",
                  original_exception=e)
```

### Vector Search Exceptions

```python
VectorSearchError         # Base for vector operations
├── ChromaInitializationError # ChromaDB startup failures
├── ChromaOperationError      # ChromaDB operation failures
└── EmbeddingGenerationError  # Embedding generation failures
```

**Usage**:
```python
try:
    collection = chroma_client.get_or_create_collection(name)
except Exception as e:
    log_and_raise(ChromaInitializationError, "Failed to init collection",
                  original_exception=e,
                  details={"collection_name": name})
```

### Integration Exceptions

```python
IntegrationError          # Base for external services
├── OllamaError              # Ollama API failures
└── GenAIToolboxError        # GenAI Toolbox failures
```

### MCP Exceptions

```python
MCPServerError            # Base for MCP server
├── MCPInitializationError   # Server startup failures
└── MCPToolExecutionError    # Tool execution failures
```

### Configuration Exceptions

```python
ConfigurationError        # Base for config errors
└── EnvironmentVariableError # Missing/invalid env vars
```

### Complete Hierarchy

```
TMWSException (base - auto-logs all errors)
├── DatabaseException
│   ├── DatabaseConnectionError
│   ├── DatabaseOperationError
│   └── DatabaseInitializationError
├── MemoryException
│   ├── MemoryCreationError
│   ├── MemorySearchError
│   ├── MemoryUpdateError
│   ├── MemoryDeletionError
│   └── MemoryNotFoundError
├── WorkflowException
├── ValidationException
├── AuthenticationException
├── AuthorizationException
├── RateLimitException
├── VectorizationException
├── ConfigurationError
│   └── EnvironmentVariableError
├── SecurityError
├── ServiceError
│   ├── ServiceInitializationError
│   ├── ServiceExecutionError
│   ├── VectorSearchError
│   │   ├── ChromaInitializationError
│   │   ├── ChromaOperationError
│   │   └── EmbeddingGenerationError
│   └── AgentError
│       ├── AgentRegistrationError
│       └── AgentNotFoundError
├── IntegrationError
│   ├── OllamaError
│   └── GenAIToolboxError
├── MCPServerError
│   ├── MCPInitializationError
│   └── MCPToolExecutionError
└── NotFoundError
```

---

## Common Patterns

### Pattern 1: Database Transactions

#### ❌ BEFORE: Silent Failure

```python
try:
    await db.commit()
except Exception:
    pass  # Transaction may have failed - NO ROLLBACK, NO LOG
```

**Problems**:
- No rollback on failure
- Partial commits corrupt database state
- No diagnostic information

#### ✅ AFTER: Proper Handling

```python
try:
    await session.commit()
except (KeyboardInterrupt, SystemExit):
    # User interrupt - rollback and propagate
    await session.rollback()
    raise
except SQLAlchemyError as e:
    # Database error - rollback and raise with context
    await session.rollback()
    log_and_raise(
        DatabaseOperationError,
        "Failed to commit transaction",
        original_exception=e,
        details={
            "operation": "commit",
            "table": table_name,
            "session_id": id(session)
        }
    )
except Exception as e:
    # Unexpected error - log as critical and propagate
    await session.rollback()
    logger.critical(f"Unexpected error during commit: {e}", exc_info=True)
    raise
```

**Source**: `src/core/database.py:131-144`

### Pattern 2: Service Initialization

#### ❌ BEFORE: Silent Degradation

```python
try:
    self.chroma_client = chromadb.Client()
except Exception:
    self.chroma_client = None  # Service silently disabled
```

**Problems**:
- Service appears healthy but is broken
- Errors deferred until first use
- No indication of what went wrong

#### ✅ AFTER: Fail-Fast with Context

```python
try:
    self._collection = self._client.get_or_create_collection(
        name=self.COLLECTION_NAME,
        metadata={
            "hnsw:space": "cosine",
            "hnsw:M": 16,
            "hnsw:construction_ef": 200,
        },
    )
    count = self._collection.count()
    logger.info(f"✅ Collection '{self.COLLECTION_NAME}' ready ({count} memories)")

except (KeyboardInterrupt, SystemExit):
    # Never suppress user interrupts
    raise
except Exception as e:
    # ChromaDB initialization errors - fail fast
    log_and_raise(
        ChromaInitializationError,
        f"Failed to initialize ChromaDB collection '{self.COLLECTION_NAME}'",
        original_exception=e,
        details={
            "collection_name": self.COLLECTION_NAME,
            "persist_directory": str(self.persist_directory),
        },
    )
```

**Benefits**:
- Immediate failure on startup (better than runtime surprise)
- Clear error message with configuration details
- Full stack trace for debugging

**Source**: `src/services/vector_search_service.py:113-126`

### Pattern 3: Best-Effort Cleanup

Some operations are **non-critical** and can fail without stopping execution.

#### ✅ ACCEPTABLE: Logged Warning for Non-Critical Operations

```python
# Example: Cleanup old temporary files
try:
    await cleanup_temp_files()
except (KeyboardInterrupt, SystemExit):
    # User interrupt always propagates
    raise
except OSError as e:
    # Cleanup failure is non-critical - log warning and continue
    logger.warning(f"Failed to cleanup temp files (non-critical): {e}")
    # No re-raise - we continue execution
except Exception as e:
    # Unexpected errors should still be logged at ERROR level
    logger.error(f"Unexpected error during cleanup: {e}", exc_info=True)
    # Still no re-raise if cleanup is truly optional
```

**When is this acceptable?**
- ✅ Cleanup operations (temp files, caches)
- ✅ Optional notifications/metrics
- ✅ Graceful degradation features

**When is this NOT acceptable?**
- ❌ Data persistence operations
- ❌ Security checks
- ❌ User-requested operations
- ❌ Critical path logic

### Pattern 4: Multi-Step Atomic Operations

#### ❌ BEFORE: Inconsistent State on Failure

```python
try:
    # Step 1: Write to SQLite
    self.session.add(memory)
    await self.session.commit()

    # Step 2: Write to Chroma (might fail silently)
    try:
        await self._sync_to_chroma(memory, embedding)
    except Exception:
        pass  # ChromaDB write failed but SQLite committed = inconsistent state!

except Exception:
    pass
```

**Problem**: SQLite has the memory but ChromaDB doesn't - vector search broken!

#### ✅ AFTER: Atomic Rollback on Partial Failure

```python
try:
    # Step 1: Write to SQLite
    self.session.add(memory)
    await self.session.commit()
    await self.session.refresh(memory)

    # Step 2: Write to Chroma (REQUIRED for vector storage)
    try:
        await self._sync_to_chroma(memory, embedding_vector.tolist())
    except (KeyboardInterrupt, SystemExit):
        # User interrupt - rollback SQLite and propagate
        await self.session.rollback()
        raise
    except ChromaOperationError:
        # ChromaDB specific errors - rollback SQLite and re-raise
        await self.session.rollback()
        raise
    except Exception as e:
        # Chroma is REQUIRED - rollback SQLite and raise error
        await self.session.rollback()
        log_and_raise(
            MemoryCreationError,
            "Failed to sync memory to ChromaDB (vector storage required)",
            original_exception=e,
            details={
                "memory_id": memory.id,
                "embedding_size": len(embedding_vector)
            }
        )

    logger.info(f"✅ Memory created: {memory.id}")
    return memory

except (KeyboardInterrupt, SystemExit):
    raise
except (MemoryCreationError, ChromaOperationError):
    # Expected errors - already logged
    raise
except SQLAlchemyError as e:
    # Database errors during memory creation
    await self.session.rollback()
    log_and_raise(
        MemoryCreationError,
        "Failed to create memory in database",
        original_exception=e,
        details={"content_length": len(content)}
    )
```

**Source**: `src/services/memory_service.py:128-147`

### Pattern 5: Configuration Loading

#### ❌ BEFORE: Unclear Failure

```python
try:
    settings = Settings()
except Exception as e:
    logger.error("Config failed")
    raise
```

#### ✅ AFTER: Actionable Error Messages

```python
try:
    # Load and validate settings
    settings = _load_settings_from_env()

    # Validate critical security settings
    if settings.is_production:
        _validate_production_settings(settings)
    elif settings.is_staging:
        _validate_staging_settings(settings)

    return settings

except (KeyboardInterrupt, SystemExit):
    # Never suppress user interrupts
    raise
except ValueError as e:
    # Configuration validation errors (expected)
    logger.error(f"Configuration validation failed: {e}")
    logger.error("Ensure all required environment variables are set:")
    logger.error("- TMWS_DATABASE_URL")
    logger.error("- TMWS_SECRET_KEY")
    logger.error("- TMWS_ENVIRONMENT")
    raise ConfigurationError(
        "Settings validation failed",
        details={"error": str(e)}
    ) from e
except Exception as e:
    # Unexpected configuration errors
    logger.critical(f"Unexpected error loading configuration: {e}", exc_info=True)
    raise
```

**Benefits**:
- Clear guidance on which env vars are missing
- Differentiate between expected (ValueError) and unexpected errors
- Specific ConfigurationError for targeted handling upstream

**Source**: `src/core/config.py:499-509`

### Pattern 6: MCP Server Initialization

#### ✅ CORRECT: Layered Error Handling

```python
async def initialize_resources(self):
    """Initialize MCP server with database session and services."""
    try:
        # Initialize Chroma vector service
        self.vector_service.initialize()
        logger.info("Chroma vector service initialized")

        # Start GenAI Toolbox sidecar services
        await self.genai_bridge.start_sidecar_services()

        logger.info(
            f"HybridMCPServer initialized: {self.instance_id} "
            f"(Chroma: {self.vector_service.HOT_CACHE_SIZE} hot cache)"
        )

    except (KeyboardInterrupt, SystemExit):
        # Never suppress user interrupts
        raise
    except (ChromaOperationError, ServiceInitializationError):
        # Expected initialization errors - already logged by lower layers
        raise
    except Exception as e:
        # Unexpected initialization errors
        log_and_raise(
            MCPInitializationError,
            "Failed to initialize HybridMCPServer",
            original_exception=e,
            details={
                "instance_id": self.instance_id,
                "chroma_ready": hasattr(self.vector_service, '_collection')
            }
        )
```

**Source**: `src/mcp_server.py:164-178`

---

## Logging Guidelines

### Log Levels

| Level | Usage | Example |
|-------|-------|---------|
| `CRITICAL` | Unexpected errors that may crash the system | `logger.critical(f"Unexpected error: {e}", exc_info=True)` |
| `ERROR` | Expected errors that prevent operation success | `logger.error(f"Failed to create memory: {e}")` |
| `WARNING` | Non-critical failures (best-effort operations) | `logger.warning(f"Cleanup failed (non-critical): {e}")` |
| `INFO` | Successful operations, state changes | `logger.info(f"✅ Memory created: {memory_id}")` |
| `DEBUG` | Detailed diagnostic information | `logger.debug(f"Query: {query}")` |

### Always Include Stack Traces

```python
# ✅ CORRECT: Full stack trace
logger.error(f"Operation failed: {e}", exc_info=True)

# ✅ CORRECT: TMWSException auto-includes stack trace
log_and_raise(DatabaseError, "Query failed", original_exception=e)

# ❌ WRONG: No stack trace
logger.error(f"Operation failed: {e}")  # Missing exc_info=True
```

### Structured Logging with Context

```python
# ✅ CORRECT: Rich context in details dict
log_and_raise(
    MemoryCreationError,
    "Failed to create memory",
    original_exception=e,
    details={
        "content_length": len(content),
        "content_preview": content[:100],
        "memory_type": memory_type,
        "importance": importance,
        "tags": tags,
        "embedding_model": model_name
    }
)
```

---

## Developer Checklist

Before committing code with `try-except` blocks, verify:

### Must-Have (Required)

- [ ] **User interrupts handled first**: `except (KeyboardInterrupt, SystemExit): raise`
- [ ] **Specific exception types caught**: Not bare `except Exception` without reason
- [ ] **All exceptions logged**: Either explicit `logger.error()` or `TMWSException` auto-log
- [ ] **Exception chains preserved**: Use `raise ... from e` for root cause
- [ ] **Stack traces included**: `exc_info=True` or auto-included by `TMWSException`

### Should-Have (Recommended)

- [ ] **Rich context provided**: `details` dict with debugging information
- [ ] **Appropriate log level**: CRITICAL for unexpected, ERROR for expected, WARNING for non-critical
- [ ] **Atomic rollback**: Database rollback on multi-step operation failure
- [ ] **Custom exception type**: Use specific `TMWSException` subclass when appropriate
- [ ] **Actionable error messages**: Include what failed and how to fix it

### Code Review Questions

1. **What happens if this fails in production?** Can you diagnose it from logs?
2. **What happens if user presses Ctrl+C?** Does it stop immediately?
3. **What is the system state after exception?** Consistent or corrupt?
4. **Is the error expected or unexpected?** Logged at correct level?
5. **Can downstream code handle this exception?** Is it specific enough?

---

## Real-World Examples

### Example 1: Database Session Context Manager

**File**: `src/core/database.py` (lines 125-147)

**Scenario**: Database session errors during transactions

```python
@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager for database sessions.

    Ensures proper rollback on errors and user interrupts.
    """
    session_maker = get_session_maker()
    async with session_maker() as session:
        try:
            yield session
        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            await session.rollback()
            raise
        except SQLAlchemyError as e:
            # Database errors - rollback and raise with context
            await session.rollback()
            log_and_raise(
                DatabaseOperationError,
                "Database session error during operation",
                original_exception=e,
                details={"session_id": id(session)},
            )
        except Exception as e:
            # Unexpected errors - rollback and log critical
            await session.rollback()
            logger.critical(
                f"Unexpected error in database session: {e}", exc_info=True
            )
            raise
```

**Key Points**:
- User interrupts handled first with rollback
- Specific `SQLAlchemyError` caught for database issues
- Unexpected errors logged as CRITICAL with full trace
- Always rollback before propagating

### Example 2: Memory Service Creation

**File**: `src/services/memory_service.py` (lines 120-147)

**Scenario**: Multi-step atomic operation (SQLite + ChromaDB)

```python
async def create_memory(self, content: str, ...) -> Memory:
    """Create memory with atomic rollback on partial failure."""

    # Generate embedding
    embedding_vector = await self._generate_embedding(content, metadata_str)

    # Step 1: Write to SQLite
    memory = Memory(
        content=content,
        memory_type=memory_type,
        # ... other fields
    )
    self.session.add(memory)
    await self.session.commit()
    await self.session.refresh(memory)

    # Step 2: Write to Chroma (REQUIRED)
    try:
        await self._sync_to_chroma(memory, embedding_vector.tolist())
    except (KeyboardInterrupt, SystemExit):
        await self.session.rollback()
        raise
    except ChromaOperationError:
        await self.session.rollback()
        raise
    except Exception as e:
        await self.session.rollback()
        log_and_raise(
            MemoryCreationError,
            "Failed to sync memory to ChromaDB",
            original_exception=e,
            details={"memory_id": memory.id}
        )

    logger.info(f"✅ Memory created: {memory.id}")
    return memory
```

**Key Points**:
- ChromaDB write failure triggers SQLite rollback (atomic)
- Specific `ChromaOperationError` caught and re-raised
- User interrupts cause rollback before propagation
- Unexpected errors rollback and raise `MemoryCreationError`

### Example 3: ChromaDB Initialization

**File**: `src/services/vector_search_service.py` (lines 113-126)

**Scenario**: Service initialization with fail-fast behavior

```python
def initialize(self) -> None:
    """Initialize ChromaDB collection with HNSW index."""
    try:
        self._collection = self._client.get_or_create_collection(
            name=self.COLLECTION_NAME,
            metadata={
                "hnsw:space": "cosine",
                "hnsw:M": 16,
                "hnsw:construction_ef": 200,
                "hnsw:search_ef": 100,
            },
        )
        count = self._collection.count()
        logger.info(f"✅ Collection '{self.COLLECTION_NAME}' ready ({count} memories)")

    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        log_and_raise(
            ChromaInitializationError,
            f"Failed to initialize ChromaDB collection '{self.COLLECTION_NAME}'",
            original_exception=e,
            details={
                "collection_name": self.COLLECTION_NAME,
                "persist_directory": str(self.persist_directory),
            },
        )
```

**Key Points**:
- Fail-fast on initialization (don't create broken service)
- Rich details include collection name and persist directory
- Clear error type (`ChromaInitializationError`) for upstream handling

### Example 4: Configuration Validation

**File**: `src/core/config.py` (lines 499-509)

**Scenario**: Configuration loading with actionable error messages

```python
def get_settings() -> Settings:
    """Load and validate application settings."""
    try:
        settings = _load_settings_from_env()

        if settings.is_production:
            _validate_production_settings(settings)
        elif settings.is_staging:
            _validate_staging_settings(settings)

        return settings

    except (KeyboardInterrupt, SystemExit):
        raise
    except ValueError as e:
        # Expected validation errors - provide actionable guidance
        logger.error(f"Configuration validation failed: {e}")
        logger.error("Ensure all required environment variables are set:")
        logger.error("- TMWS_DATABASE_URL")
        logger.error("- TMWS_SECRET_KEY")
        logger.error("- TMWS_ENVIRONMENT")
        raise ConfigurationError(
            "Settings validation failed",
            details={"error": str(e)}
        ) from e
    except Exception as e:
        logger.critical(f"Unexpected error loading configuration: {e}", exc_info=True)
        raise
```

**Key Points**:
- Differentiate expected (`ValueError`) from unexpected errors
- Provide actionable guidance (list required env vars)
- Use specific `ConfigurationError` for targeted handling

### Example 5: MCP Server Initialization

**File**: `src/mcp_server.py` (lines 164-178)

**Scenario**: Layered initialization with specific error types

```python
async def initialize_resources(self):
    """Initialize MCP server with database session and services."""
    try:
        self.vector_service.initialize()
        logger.info("Chroma vector service initialized")

        await self.genai_bridge.start_sidecar_services()

        logger.info(
            f"HybridMCPServer initialized: {self.instance_id} "
            f"(Chroma: {self.vector_service.HOT_CACHE_SIZE} hot cache)"
        )

    except (KeyboardInterrupt, SystemExit):
        raise
    except (ChromaOperationError, ServiceInitializationError):
        # Expected initialization errors - already logged by lower layers
        raise
    except Exception as e:
        log_and_raise(
            MCPInitializationError,
            "Failed to initialize HybridMCPServer",
            original_exception=e,
            details={
                "instance_id": self.instance_id,
                "chroma_ready": hasattr(self.vector_service, '_collection')
            }
        )
```

**Key Points**:
- Re-raise expected errors without duplicate logging
- Catch unexpected errors and wrap in `MCPInitializationError`
- Include diagnostic details (instance_id, chroma_ready status)

---

## Helper Functions

### `log_and_raise()`

**Location**: `src/core/exceptions.py:297-333`

**Purpose**: Simplify exception handling with automatic logging and chaining.

```python
def log_and_raise(
    exception_class: type[TMWSException],
    message: str,
    original_exception: Exception | None = None,
    details: dict[str, Any] | None = None,
    log_level: int = logging.ERROR,
) -> None:
    """
    Helper function to log and raise custom exceptions.

    Args:
        exception_class: The exception class to raise
        message: Error message
        original_exception: Original exception (if any) to chain
        details: Additional context details
        log_level: Logging level (default: ERROR)

    Raises:
        exception_class: The specified exception type
    """
    exc = exception_class(message, details=details, log_level=log_level)
    if original_exception:
        raise exc from original_exception
    else:
        raise exc
```

### Usage Examples

#### Basic Usage

```python
try:
    result = await risky_operation()
except SpecificError as e:
    log_and_raise(
        ServiceExecutionError,
        "Operation failed",
        original_exception=e
    )
```

#### With Context Details

```python
try:
    await db.execute(query)
except SQLAlchemyError as e:
    log_and_raise(
        DatabaseOperationError,
        "Query execution failed",
        original_exception=e,
        details={
            "query": query_name,
            "table": table_name,
            "params": query_params
        }
    )
```

#### Custom Log Level

```python
try:
    await initialize_critical_service()
except Exception as e:
    log_and_raise(
        ServiceInitializationError,
        "Critical service failed to start",
        original_exception=e,
        log_level=logging.CRITICAL  # Override default ERROR
    )
```

### Benefits

1. **Consistency**: Same logging pattern across codebase
2. **Automatic chaining**: Preserves root cause with `from e`
3. **Auto-logging**: No need to manually call `logger.error()`
4. **Stack traces**: Always includes `exc_info=True`
5. **Structured data**: Details dict for structured logging backends

---

## Next Steps

### Tier 2: High-Impact Areas (116 locations)

**Target Files**:
- `src/services/memory_service.py` (remaining 20 locations)
- `src/services/vector_search_service.py` (remaining 15 locations)
- `src/services/agent_service.py` (12 locations)
- `src/services/workflow_service.py` (18 locations)
- `src/integrations/genai_bridge.py` (25 locations)
- `src/integrations/ollama_client.py` (26 locations)

**Priority**: High (moderate frequency, high impact on core services)

### Tier 3: Moderate-Impact Areas (153 locations)

**Target Files**:
- Test files (79 locations)
- Scripts (38 locations)
- Utilities (36 locations)

**Priority**: Medium (lower frequency, but still important for reliability)

### Automated Migration Plan

1. **Pattern Detection**: Identify all `except Exception: pass` locations
2. **Context Analysis**: Determine appropriate exception type based on surrounding code
3. **Automated Refactoring**: Apply patterns from this guideline
4. **Manual Review**: Review high-risk areas (data persistence, security)
5. **Testing**: Verify error handling with integration tests

### Validation Metrics

Track improvement over time:

```python
# Pre-migration baseline (v2.2.6)
total_bare_exceptions = 300
with_logging = 45  # 15%
proper_user_interrupt_handling = 12  # 4%

# Post-Tier-1 (current)
tier1_fixed = 31
tier1_locations = 31
tier1_coverage = 100%  # All Tier 1 locations fixed

# Target (Post-Tier-2)
tier2_target = 147  # 31 + 116
coverage_target = 95%  # Allow 5% for legitimate best-effort cases
```

### Linting Integration

**Add to `.pre-commit-config.yaml`**:

```yaml
- repo: local
  hooks:
    - id: check-bare-except
      name: Check for bare except clauses
      entry: python scripts/check_exception_handling.py
      language: python
      types: [python]
      pass_filenames: true
```

**Create `scripts/check_exception_handling.py`**:

```python
#!/usr/bin/env python3
"""
Check for anti-patterns in exception handling.

Flags:
- except Exception: pass
- except: pass
- Missing KeyboardInterrupt handling
"""
import ast
import sys
from pathlib import Path

def check_file(filepath: Path) -> list[str]:
    """Check a single file for exception handling anti-patterns."""
    issues = []

    try:
        tree = ast.parse(filepath.read_text())
    except SyntaxError as e:
        return [f"{filepath}:{e.lineno}: Syntax error"]

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            # Check for bare except
            if node.type is None:
                issues.append(
                    f"{filepath}:{node.lineno}: Bare except clause (use specific exception types)"
                )

            # Check for except Exception: pass
            if (isinstance(node.type, ast.Name) and
                node.type.id == "Exception" and
                len(node.body) == 1 and
                isinstance(node.body[0], ast.Pass)):
                issues.append(
                    f"{filepath}:{node.lineno}: Silent exception handler (except Exception: pass)"
                )

    return issues

if __name__ == "__main__":
    all_issues = []
    for filepath in sys.argv[1:]:
        all_issues.extend(check_file(Path(filepath)))

    for issue in all_issues:
        print(issue)

    sys.exit(1 if all_issues else 0)
```

---

## References

- **Tier 1 Fixes**: See `VERIFICATION_REPORT.md` for detailed analysis
- **Exception Classes**: `src/core/exceptions.py`
- **Design Principles**: Aligned with [Python Error Handling Best Practices](https://docs.python.org/3/tutorial/errors.html)
- **TMWSException Auto-Logging**: Inspired by structured logging standards

---

**Document Status**: ✅ **Stable** - Ready for developer use

**Feedback**: Report issues or suggestions to the TMWS development team.
