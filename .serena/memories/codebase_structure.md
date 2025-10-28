# TMWS Codebase Structure

## High-Level Overview
```
tmws/
├── src/                  # Source code
├── tests/                # Test suite
├── docs/                 # Documentation
├── migrations/           # Database migrations (Alembic)
├── scripts/              # Utility scripts
├── config/               # Configuration files
├── data/                 # Runtime data (SQLite, ChromaDB)
├── examples/             # Usage examples
├── .claude/              # Claude Code instructions
└── [config files]        # pyproject.toml, alembic.ini, etc.
```

## Source Code Structure (`src/`)

### Entry Point
- **`mcp_server.py`**: Main MCP server entry point (FastMCP-based)

### Core Modules (`src/core/`)
- **`database.py`**: SQLite async engine, session factory
- **`config.py`**: Pydantic settings (environment variables)
- **`exceptions.py`**: Custom exception classes

### Data Models (`src/models/`)
- **`memory.py`**: Memory model with access control logic
- **`agent.py`**: Agent registry model
- **`user.py`**: User authentication model
- **`task.py`**: Task management model
- **`workflow.py`**: Workflow orchestration model
- **`learning_pattern.py`**: Learning pattern model
- **`audit_log.py`**: Audit logging models

### Business Logic (`src/services/`)
- **`memory_service.py`**: Memory CRUD operations
- **`vector_search_service.py`**: ChromaDB integration (async)
- **`embedding_service.py`**: Ollama embedding generation
- **`agent_service.py`**: Agent registration and lifecycle
- **`task_service.py`**: Task management
- **`workflow_service.py`**: Workflow execution
- **`learning_service.py`**: Pattern learning and application
- **`audit_service.py`**: Security audit logging

### Security (`src/security/`)
- **`authorization.py`**: Access control enforcement
- **`jwt_service.py`**: JWT token generation and validation
- **`rate_limiter.py`**: Rate limiting (Redis-based)
- **`agent_auth.py`**: Agent authentication
- **`validators.py`**: Input validation

### MCP Tools (`src/tools/`)
- **`memory_tools.py`**: Memory management MCP tools
- **`agent_tools.py`**: Agent management MCP tools
- **`task_tools.py`**: Task management MCP tools
- **`workflow_tools.py`**: Workflow management MCP tools
- **`system_tools.py`**: System utilities MCP tools

### Utilities (`src/utils/`)
- **`logging.py`**: Structured logging setup
- **`security.py`**: Security utilities
- **`validation.py`**: Validation helpers

## Tests Structure (`tests/`)

### Unit Tests (`tests/unit/`)
- **`test_memory_service.py`**: Memory service tests
- **`test_vector_search_service.py`**: ChromaDB integration tests
- **`test_agent_service.py`**: Agent service tests
- **`test_embedding_service.py`**: Ollama embedding tests
- **`test_models.py`**: Model tests (SQLAlchemy)

### Integration Tests (`tests/integration/`)
- **`test_memory_integration.py`**: End-to-end memory operations
- **`test_vector_search.py`**: Vector search integration
- **`test_agent_lifecycle.py`**: Agent registration and coordination

### Security Tests (`tests/security/`)
- **`test_namespace_isolation.py`**: Namespace isolation security tests (14 tests)
- **`test_access_control.py`**: Access control tests

### Performance Tests (`tests/unit/` with `@pytest.mark.benchmark`)
- Performance benchmarks for critical operations

## Documentation (`docs/`)

### Architecture
- **`TMWS_v2.2.0_ARCHITECTURE.md`**: Overall architecture
- **`PHASE_4_HYBRID_MEMORY.md`**: Hybrid memory design
- **`PHASE_6_REDIS_AGENTS.md`**: Redis agent service
- **`PHASE_9_POSTGRESQL_MINIMIZATION.md`**: PostgreSQL minimization (archived)

### Integration
- **`MCP_INTEGRATION.md`**: Claude Desktop integration guide
- **`MCP_TOOLS_REFERENCE.md`**: MCP tools reference
- **`TRINITAS_INTEGRATION.md`**: Trinitas agent integration

### Development
- **`DEVELOPMENT_SETUP.md`**: Development environment setup
- **`dev/EXCEPTION_HANDLING_GUIDELINES.md`**: Exception handling best practices

### User Guides
- **`QUICKSTART.md`**: 5-minute quickstart
- **`CUSTOM_AGENTS_GUIDE.md`**: Custom agent registration
- **`API_AUTHENTICATION.md`**: API authentication

## Database Migrations (`migrations/`)

### Alembic Structure
```
migrations/
├── versions/              # Migration files
│   ├── 001_initial.py
│   ├── 002_add_agents.py
│   ├── ...
│   ├── 20251027_1134_p0_...py  # P0 performance fixes
│   └── 20251027_1134_p0_...py  # P0 security fixes
├── env.py                 # Alembic environment config
└── script.py.mako         # Migration template
```

### Migration Naming Convention
- **P0 fixes**: `p0_description.py`
- **Features**: `feature_description.py`
- **Refactoring**: `refactor_description.py`

## Scripts (`scripts/`)

- **`initialize_db.py`**: Initialize database schema
- **`initialize_chroma.py`**: Initialize ChromaDB cache
- **`benchmark_phase8.py`**: Performance benchmarks
- **`phase9_archive.py`**: Archive PostgreSQL data (v2.3.0 migration)

## Configuration Files

### Project Configuration
- **`pyproject.toml`**: Project metadata, dependencies, tool configs
- **`alembic.ini`**: Alembic migration configuration
- **`pytest.ini`**: Pytest configuration (if separate from pyproject.toml)

### Environment
- **`.env.example`**: Example environment variables
- **`.env`**: Local environment variables (gitignored)
- **`.env.cloud`**: Cloud deployment environment (gitignored)

### Development Tools
- **`.pre-commit-config.yaml`**: Pre-commit hooks
- **`.gitignore`**: Git ignore rules
- **`.ruff_cache/`**: Ruff cache (gitignored)

## Runtime Data (`data/`)

### SQLite Database
- **`tmws.db`**: Main SQLite database (gitignored)
- **`tmws.db-shm`, `tmws.db-wal`**: SQLite WAL mode files

### ChromaDB
- **`chroma/`**: ChromaDB persistence directory (gitignored)
  - DuckDB backend
  - HNSW index

## Key Design Patterns

### Service Layer Pattern
```
MCP Tool (tools/) 
  → Service (services/) 
    → Model (models/) 
      → Database (core/database.py)
```

### Async/Await Pattern
- All I/O operations are async
- Use `asyncio.to_thread()` for sync library calls (e.g., ChromaDB)

### Dependency Injection
- Services receive dependencies via constructor
- Testable with mock objects

### Repository Pattern
- Models contain data structure only
- Services handle business logic

### Access Control Pattern
- Namespace isolation at model level
- Authorization layer verifies namespace from database
- Never trust client-provided namespace claims

## Critical Files for Namespace Strategy

### Current Implementation
- **`src/models/memory.py`**: `Memory.is_accessible_by()` method (lines 160-201)
- **`src/security/authorization.py`**: Authorization layer (lines 459-492)
- **`tests/security/test_namespace_isolation.py`**: Security test suite

### Future Enhancement Areas
- **`src/models/agent.py`**: Agent namespace registry
- **`src/services/memory_service.py`**: Cross-namespace search logic
- **`src/services/agent_service.py`**: Multi-project agent coordination

## Performance-Critical Components

### Hot Paths (< 20ms P95)
- `VectorSearchService.search()` - ChromaDB vector search
- `MemoryService.search_memories()` - Semantic search
- `AgentService.get_agent()` - Agent lookup (Redis)

### Database Indexes
- `idx_memories_namespace_created` - Memory queries
- `idx_learning_patterns_agent_performance` - Learning pattern queries (P0-3)
- `idx_pattern_usage_agent_success_time` - Pattern filtering (P0-3)
- `idx_workflow_executions_error_analysis` - Error analysis (P0-3)
