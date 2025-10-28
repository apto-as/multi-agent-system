# Task Completion Checklist for TMWS

When you finish implementing a task, always complete this checklist:

## Code Quality

### 1. Linting and Formatting
```bash
# Run ruff linter with auto-fix
ruff check src/ --fix

# Format code with black
black src/

# Sort imports
isort src/
```

**Expected**: No errors or warnings from ruff, all files formatted consistently.

### 2. Type Checking (Optional but Recommended)
```bash
# Run mypy for type checking
mypy src/
```

**Expected**: No type errors.

## Testing

### 3. Run Unit Tests
```bash
# Run all tests with coverage
pytest tests/ -v --cov=src --cov-report=term-missing --cov-report=html
```

**Expected**: 
- All tests pass
- Coverage ≥90% for modified files
- No new warnings

### 4. Run Security Tests (if security-related)
```bash
# Namespace isolation tests
pytest tests/security/test_namespace_isolation.py -v

# All security tests
pytest tests/security/ -v
```

**Expected**: All security tests pass.

### 5. Run Integration Tests (if applicable)
```bash
# Integration tests
pytest tests/integration/ -v
```

**Expected**: Integration tests pass.

## Database

### 6. Create Migration (if database schema changed)
```bash
# Generate migration
alembic revision --autogenerate -m "Descriptive message"

# Review migration file
cat migrations/versions/{latest_file}.py

# Apply migration
alembic upgrade head

# Verify current version
alembic current
```

**Expected**: Migration file accurately reflects changes, no errors during upgrade.

## Documentation

### 7. Update Documentation
- [ ] Update docstrings for modified functions/classes
- [ ] Update `CHANGELOG.md` (if user-facing change)
- [ ] Update relevant docs in `docs/` (if API or architecture change)
- [ ] Update `.claude/CLAUDE.md` (if critical design decision)

## Performance

### 8. Performance Considerations
- [ ] Added/removed indexes? Run benchmark:
  ```bash
  python scripts/benchmark_phase8.py
  ```
- [ ] Changed async patterns? Verify event loop not blocked
- [ ] New ChromaDB queries? Check P95 latency < 20ms

## Security

### 9. Security Review (CRITICAL for all changes)
- [ ] No hardcoded credentials or secrets
- [ ] Namespace isolation preserved (if touching access control)
- [ ] Input validation for user-provided data
- [ ] SQL injection prevention (use SQLAlchemy ORM)
- [ ] XSS prevention (use bleach for HTML)

## Git Workflow

### 10. Commit
```bash
# Stage changes
git add <modified files>

# Commit with clear message
git commit -m "type: description"
```

**Commit message types**:
- `feat:` - New feature
- `fix:` - Bug fix
- `perf:` - Performance improvement
- `docs:` - Documentation only
- `test:` - Test-related changes
- `refactor:` - Code refactoring
- `chore:` - Maintenance tasks

### 11. Pre-Commit Hooks (if set up)
```bash
# Manually run pre-commit checks
pre-commit run --all-files
```

**Expected**: All pre-commit hooks pass.

## Final Verification

### 12. Clean Environment Test
```bash
# Remove virtual environment
rm -rf .venv

# Recreate and test
uv venv
uv sync
pytest tests/unit/ -v
```

**Expected**: Fresh install works, tests pass.

### 13. Ollama Dependency (REQUIRED)
- [ ] Verify Ollama is running: `curl http://localhost:11434/api/tags`
- [ ] Verify model is available: `ollama list | grep multilingual-e5-large`
- [ ] If adding embedding-related code, test with Ollama

## Summary Report

Create a brief summary:
```
## Changes
- [List of changes]

## Testing
- ✅ All tests pass (X/Y passed)
- ✅ Coverage: Z% (+/- Δ%)

## Performance
- [Any performance metrics]

## Breaking Changes
- [None / List of breaking changes]
```

---

## Quick Reference: One-Line Checklist

For quick tasks:
```bash
ruff check src/ --fix && black src/ && isort src/ && pytest tests/ -v --cov=src
```

**If all pass**: Ready to commit! ✅
