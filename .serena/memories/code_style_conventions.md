# Code Style and Conventions

## Code Style Tools

### Black (Formatter)
- Line length: 100
- Target versions: Python 3.10, 3.11
- Auto-format Python files

### Ruff (Linter)
- Line length: 100
- Target version: Python 3.10
- Selected rules:
  - E (pycodestyle errors)
  - W (pycodestyle warnings)
  - F (pyflakes)
  - I (isort - import sorting)
  - B (flake8-bugbear)
  - C4 (flake8-comprehensions)
  - UP (pyupgrade)
  - ARG (unused arguments)
  - SIM (simplify)
- Ignores: E501 (line length - handled by black), B008, B904

### isort (Import Sorting)
- Profile: black
- Line length: 100
- Multi-line output mode: 3
- Trailing comma: true

### Mypy (Type Checking)
- Python version: 3.10
- Strict typing enabled
- Disallow untyped definitions
- Warn on redundant casts, unused ignores, no return

## Naming Conventions

### General Principles
- **Variables/Functions**: `snake_case`
- **Classes**: `PascalCase`
- **Constants**: `UPPER_SNAKE_CASE`
- **Private members**: `_leading_underscore`
- **Protected members**: `__double_underscore` (rare, use sparingly)

### Project-Specific Conventions

#### Agent IDs
- Format: `{role}-{function}` (kebab-case)
- Examples: `athena-conductor`, `artemis-optimizer`, `hestia-auditor`

#### Namespaces
- Format: lowercase, no spaces
- Examples: `trinitas`, `architecture`, `optimization`, `security`

#### Memory IDs
- Format: UUID (auto-generated)
- Never use version numbers in identifiers (see CLAUDE.md Rule 8)

#### Database Tables
- Format: `snake_case`, plural nouns
- Examples: `memories`, `agents`, `tasks`, `workflows`, `learning_patterns`
- **Never append version numbers** (e.g., `memories_v2` ❌)

## Code Organization

### Directory Structure
```
src/
├── core/          # Database, config, exceptions
├── models/        # SQLAlchemy models
├── services/      # Business logic
├── security/      # Authentication, authorization
├── tools/         # MCP tools
├── utils/         # Utilities
└── mcp_server.py  # Entry point
```

### Service Layer Pattern
- All business logic in `services/`
- Models contain only data structure
- Controllers (MCP tools) call services
- Services handle transactions and coordination

## Async/Await Patterns

### Rules
1. **All I/O operations must be async**
2. Use `asyncio.to_thread()` for sync library calls (e.g., ChromaDB)
3. Never call sync I/O from async functions directly
4. Use `async with` for context managers

### Example
```python
# ✅ CORRECT - Non-blocking
async def search(self, query_embedding, top_k):
    return await asyncio.to_thread(
        self._collection.query, 
        query_embeddings=[query_embedding],
        n_results=top_k
    )

# ❌ WRONG - Blocks event loop
def search(self, query_embedding, top_k):
    return self._collection.query(...)
```

## Exception Handling

### Guidelines (CRITICAL)
1. **Never suppress `KeyboardInterrupt` or `SystemExit`**
2. Use specific exception types, not `Exception`
3. Always include original exception context
4. Log with structured logging

### Pattern
```python
# ✅ CORRECT
try:
    risky_operation()
except (KeyboardInterrupt, SystemExit):
    raise  # Never suppress
except SpecificException as e:
    log_and_raise(CustomError, "Message", original_exception=e)

# ❌ WRONG
except Exception:  # Too broad
    pass  # Silent failure
```

Reference: `docs/dev/EXCEPTION_HANDLING_GUIDELINES.md`

## Testing

### Structure
```
tests/
├── unit/          # Isolated unit tests
├── integration/   # Service integration tests
├── e2e/           # End-to-end tests
└── security/      # Security-focused tests
```

### Pytest Configuration
- Asyncio mode: auto
- Coverage target: 90%+ (current: ~85%)
- Test markers: `benchmark` for performance tests

### Test Naming
- Format: `test_{feature}_{scenario}_{expected_result}`
- Example: `test_memory_create_success`, `test_namespace_isolation_unauthorized_access`

## Documentation

### Docstrings
- Format: Google-style docstrings
- Required for: public functions, classes, modules
- Include: Args, Returns, Raises, Examples (if complex)

### Comments
- Explain **why**, not **what**
- Use `# TODO:` for temporary workarounds
- Use `# NOTE:` for important design decisions
- Use `# FIXME:` for known issues

## Performance Guidelines

### Database Queries
- Always use indexes for WHERE clauses
- Avoid N+1 queries (use eager loading)
- Use `.scalars()` for single-column results
- Use `.unique()` for joined eager loads

### ChromaDB
- Batch operations when possible
- Use filters to reduce search space
- Limit results to minimum needed

### Caching Strategy
- Redis for hot data (agents, tasks)
- ChromaDB in-memory cache (10K memories)
- SQLite WAL mode for concurrent reads
