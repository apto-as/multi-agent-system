# Suggested Commands for TMWS Development

## Development Environment

### Virtual Environment (uv)
```bash
# Create virtual environment
uv venv

# Install dependencies
uv sync

# Install dev dependencies
uv sync --all-extras
```

## Testing

### Run Tests
```bash
# All tests
pytest tests/ -v

# Unit tests only
pytest tests/unit/ -v

# With coverage
pytest tests/ -v --cov=src --cov-report=term-missing --cov-report=html

# Specific test file
pytest tests/unit/test_memory_service.py -v

# Specific test function
pytest tests/unit/test_memory_service.py::test_create_memory -v

# Security tests (namespace isolation)
pytest tests/security/test_namespace_isolation.py -v

# Performance benchmarks
pytest tests/unit/ -v -m benchmark
```

## Code Quality

### Linting
```bash
# Run ruff linter
ruff check src/

# Auto-fix issues
ruff check src/ --fix

# Check specific files
ruff check src/services/memory_service.py
```

### Formatting
```bash
# Format with black
black src/

# Check without modifying
black src/ --check
```

### Import Sorting
```bash
# Sort imports with isort
isort src/

# Check without modifying
isort src/ --check
```

### Type Checking
```bash
# Run mypy (if type checking is enforced)
mypy src/
```

### All-in-One Quality Check
```bash
# Comprehensive check (run before committing)
ruff check src/ --fix && black src/ && isort src/ && pytest tests/ -v
```

## Database Management

### Migrations
```bash
# Create new migration (auto-detect changes)
alembic revision --autogenerate -m "Description"

# Apply migrations
alembic upgrade head

# Check current version
alembic current

# Rollback one version
alembic downgrade -1

# Show migration history
alembic history

# Generate SQL without applying
alembic upgrade head --sql
```

### Database Initialization
```bash
# Initialize database (first time)
python scripts/initialize_db.py

# Initialize ChromaDB cache
python scripts/initialize_chroma.py
```

## Running the Server

### MCP Server (for Claude Desktop)
```bash
# Start MCP server (stdio mode)
uv run tmws

# Or with explicit command
uv run python -m src.mcp_server

# With environment variables
TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db" \
TMWS_SECRET_KEY="dev-secret" \
TMWS_ENVIRONMENT="development" \
uv run tmws
```

### Ollama Setup (REQUIRED)
```bash
# Install Ollama (if not already installed)
# Visit: https://ollama.ai/download

# Pull the embedding model
ollama pull zylonai/multilingual-e5-large

# Start Ollama server
ollama serve

# Test embedding generation
curl http://localhost:11434/api/embeddings -d '{
  "model": "zylonai/multilingual-e5-large",
  "prompt": "test"
}'
```

## Debugging

### Python Debugger
```bash
# Run with Python debugger
python -m pdb -m src.mcp_server

# Or use breakpoint() in code
# breakpoint()  # Python 3.7+
```

### Logging
```bash
# Enable debug logging
TMWS_LOG_LEVEL=DEBUG uv run tmws

# Structured JSON logging
TMWS_LOG_FORMAT=json uv run tmws
```

## Performance Analysis

### Benchmarking
```bash
# Run Phase 8 benchmarks
python scripts/benchmark_phase8.py

# Generate performance report
pytest tests/unit/ -v -m benchmark --benchmark-only
```

### Profiling
```bash
# Profile with cProfile
python -m cProfile -o output.prof -m src.mcp_server

# Analyze profile
python -m pstats output.prof
# >>> sort cumtime
# >>> stats 20
```

## Git Workflow

### Pre-commit Hooks
```bash
# Install pre-commit hooks
pre-commit install

# Run manually
pre-commit run --all-files

# Update hooks
pre-commit autoupdate
```

### Commit Standards
```bash
# Recommended commit format
git commit -m "feat: Add namespace isolation for memories"
git commit -m "fix: Resolve ChromaDB async pattern blocking"
git commit -m "perf: Remove duplicate indexes (+18% write performance)"
git commit -m "docs: Update MCP integration guide"
git commit -m "test: Add security tests for namespace isolation"
```

## macOS-Specific Utilities

### PostgreSQL (if using PostgreSQL instead of SQLite)
```bash
# Install PostgreSQL 17
brew install postgresql@17

# Start service
brew services start postgresql@17

# Create database
createdb tmws_db

# Install pgvector extension
psql tmws_db -c "CREATE EXTENSION IF NOT EXISTS vector;"

# Check status
brew services list | grep postgresql
```

### Redis
```bash
# Install Redis
brew install redis

# Start service
brew services start redis

# Check status
redis-cli ping  # Should return "PONG"

# Monitor commands
redis-cli monitor

# Get server info
redis-cli INFO
```

### System Monitoring
```bash
# Check disk usage
du -sh data/chroma data/tmws.db

# Monitor memory usage
ps aux | grep tmws

# Check open files
lsof | grep tmws

# Network connections
netstat -an | grep 11434  # Ollama
```

## Documentation

### Generate API docs (if sphinx is set up)
```bash
# Build docs
cd docs && make html

# Clean build
cd docs && make clean && make html

# View docs
open docs/_build/html/index.html
```

## Cleanup

### Remove Generated Files
```bash
# Remove Python cache
find . -type d -name __pycache__ -exec rm -rf {} +
find . -type f -name "*.pyc" -delete

# Remove pytest cache
rm -rf .pytest_cache htmlcov .coverage

# Remove build artifacts
rm -rf build/ dist/ *.egg-info

# Remove Ruff cache
rm -rf .ruff_cache

# Remove ChromaDB persistence (WARNING: deletes vector data)
rm -rf data/chroma

# Remove SQLite database (WARNING: deletes all data)
rm -f data/tmws.db
```

## Task Completion Checklist

When you complete a development task:

1. ✅ Run linting: `ruff check src/ --fix`
2. ✅ Run formatter: `black src/`
3. ✅ Sort imports: `isort src/`
4. ✅ Run tests: `pytest tests/ -v --cov=src`
5. ✅ Check coverage: Ensure coverage ≥90% for modified files
6. ✅ Update CHANGELOG.md (if user-facing change)
7. ✅ Update documentation (if API change)
8. ✅ Create migration (if database change): `alembic revision --autogenerate -m "..."`
9. ✅ Commit with clear message: `git commit -m "type: description"`
