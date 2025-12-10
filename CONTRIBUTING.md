# Contributing to TMWS

Thank you for your interest in contributing to **TMWS (Trinitas Memory & Workflow System)**! This document provides guidelines for contributing to the project using our **GitHub-independent, local-first development workflow**.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Docker Builds](#docker-builds)
- [Issue Tracking](#issue-tracking)
- [Questions](#questions)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors.

### Expected Behavior

- Be respectful and considerate
- Welcome newcomers and help them get started
- Focus on constructive feedback
- Accept criticism gracefully

### Unacceptable Behavior

- Harassment, discrimination, or trolling
- Personal attacks or insults
- Publishing others' private information
- Unethical or unprofessional conduct

**Enforcement**: Violations may result in temporary or permanent ban from the project.

---

## Getting Started

### Prerequisites

```bash
# Required tools
brew install gh          # GitHub CLI
brew install docker      # Docker Desktop
brew install git         # Git 2.30+
brew install python@3.11 # Python 3.11+
brew install poetry      # Poetry 1.7+

# Verify installations
gh --version            # 2.40+
docker --version        # 24.0+
git --version           # 2.30+
python --version        # 3.11+
poetry --version        # 1.7+
```

### Fork and Clone

```bash
# 1. Fork repository on GitHub
# (Click "Fork" button on https://github.com/apto-as/tmws)

# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/tmws.git
cd tmws

# 3. Add upstream remote
git remote add upstream https://github.com/apto-as/tmws.git

# 4. Verify remotes
git remote -v
# origin    https://github.com/YOUR_USERNAME/tmws.git (fetch)
# origin    https://github.com/YOUR_USERNAME/tmws.git (push)
# upstream  https://github.com/apto-as/tmws.git (fetch)
# upstream  https://github.com/apto-as/tmws.git (push)
```

### Install Dependencies

```bash
# Install Python dependencies
poetry install

# Activate virtual environment
poetry shell

# Install git hooks (IMPORTANT!)
bash scripts/git-hooks/install-hooks.sh

# Verify hook installation
ls -la .git/hooks/pre-push
# Expected: -rwxr-xr-x ... .git/hooks/pre-push

# Authenticate GitHub CLI
gh auth login
```

---

## Development Workflow

TMWS uses a **local-first, Issue-centric workflow**. All development follows the TDD (Test-Driven Development) cycle with automated validation via git hooks.

### Complete Workflow

```
┌─────────────────────────────────────────────────────────┐
│  1️⃣  CREATE ISSUE (GitHub)                              │
│      gh issue create --title "feat: Add X" --body "..." │
│      → Issue #123 created                               │
└─────────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────┐
│  2️⃣  CREATE BRANCH (Local)                              │
│      git checkout -b feature/description-123            │
└─────────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────┐
│  3️⃣  TDD CYCLE (Red → Green → Refactor)                 │
│      🔴 Write failing test                              │
│         pytest tests/test_feature.py                    │
│      🟢 Implement minimal code                          │
│         vim src/feature.py                              │
│      🔵 Refactor & cleanup                              │
│         make format lint typecheck                      │
└─────────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────┐
│  4️⃣  COMMIT (Reference Issue)                           │
│      git commit -m "feat: Add X (fixes #123)"           │
└─────────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────┐
│  5️⃣  PUSH (Pre-push hook validates automatically)       │
│      git push origin feature/description-123            │
│      → Tests run, results posted to Issue #123          │
└─────────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────┐
│  6️⃣  CREATE PULL REQUEST                                │
│      gh pr create --fill                                │
└─────────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────┐
│  7️⃣  CODE REVIEW & MERGE                                │
│      (Maintainer reviews and merges)                    │
└─────────────────────────────────────────────────────────┘
```

### Step-by-Step Example

```bash
# 1. Create Issue
gh issue create \
  --title "feat: Add semantic deduplication" \
  --body "Implement semantic deduplication using cosine similarity" \
  --label "enhancement,priority-P1"
# → Created issue #130

# 2. Create branch
git checkout main
git pull upstream main
git checkout -b feature/semantic-deduplication-130

# 3. TDD Cycle
# RED: Write failing test
cat > tests/unit/test_deduplication.py <<EOF
def test_semantic_deduplication():
    result = deduplicate_memories([...])
    assert len(result) < len(original)
EOF

pytest tests/unit/test_deduplication.py
# FAILED ❌ (expected)

# GREEN: Implement feature
vim src/memory/deduplication.py
# ... (implement logic)

pytest tests/unit/test_deduplication.py
# PASSED ✅

# REFACTOR: Clean up
make format lint typecheck

# 4. Commit (reference Issue)
git add .
git commit -m "feat: Add semantic deduplication (fixes #130)"

# 5. Push (pre-push hook runs automatically)
git push origin feature/semantic-deduplication-130

# Output:
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TMWS Pre-Push Validation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Issue: #130
#  Tests: ✅ PASSED (24 tests, 0.5s)
#  Type Check: ✅ PASSED
#  Security: ✅ PASSED (0 issues)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Posted summary to Issue #130
#  Push allowed ✅

# 6. Create Pull Request
gh pr create \
  --title "feat: Add semantic deduplication" \
  --body "Closes #130" \
  --label "enhancement"

# 7. Wait for review and merge
```

---

## Coding Standards

### Python Style Guide

TMWS follows **PEP 8** with enforcements via Ruff.

```bash
# Format code (automatic)
make format

# Lint code (check for issues)
make lint

# Type check (mypy)
make typecheck

# All-in-one quality check
make format lint typecheck
```

### Code Quality Rules

1. **Type Hints**: Required for all function signatures
   ```python
   # ✅ GOOD
   def search_memories(query: str, limit: int = 10) -> list[Memory]:
       ...

   # ❌ BAD
   def search_memories(query, limit=10):
       ...
   ```

2. **Docstrings**: Required for public APIs
   ```python
   def store_memory(content: str, importance: float) -> str:
       """Store a new memory in the system.

       Args:
           content: Memory content text
           importance: Importance score (0.0-1.0)

       Returns:
           Memory UUID

       Raises:
           ValueError: If importance is out of range
       """
       ...
   ```

3. **Imports**: Organized by stdlib → third-party → local
   ```python
   # Standard library
   import json
   from typing import Optional

   # Third-party
   import httpx
   from sqlalchemy import select

   # Local
   from tmws.models import Memory
   from tmws.config import settings
   ```

4. **Line Length**: 100 characters (Ruff configured)

5. **Naming Conventions**:
   - Functions/variables: `snake_case`
   - Classes: `PascalCase`
   - Constants: `UPPER_SNAKE_CASE`
   - Private members: `_leading_underscore`

---

## Testing Requirements

### Test Coverage

**Minimum**: 80% code coverage

```bash
# Run tests with coverage
make test-cov

# View coverage report
open htmlcov/index.html
```

### Test Organization

```
tests/
├── unit/              # Unit tests (fast, isolated)
│   ├── test_memory.py
│   ├── test_auth.py
│   └── test_utils.py
├── integration/       # Integration tests (slower, real DB)
│   ├── test_api.py
│   ├── test_mcp.py
│   └── test_workflow.py
└── conftest.py        # Shared fixtures
```

### Writing Tests

```python
# Unit test example (fast, mocked dependencies)
def test_memory_store(mock_db):
    """Test memory storage with mocked database."""
    memory_id = store_memory("Test content", importance=0.8)
    assert isinstance(memory_id, str)
    assert mock_db.insert.called

# Integration test example (real dependencies)
@pytest.mark.integration
def test_api_health(client):
    """Test /health endpoint with real HTTP client."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
```

### Running Tests

```bash
# All tests
make test

# Unit tests only (fast, runs in pre-push hook)
make test-unit

# Integration tests only (slower)
make test-integration

# Specific test file
pytest tests/unit/test_memory.py -v

# Specific test function
pytest tests/unit/test_memory.py::test_store_memory -v

# With coverage
make test-cov
```

### Pre-Push Validation

The pre-push hook runs **unit tests only** for speed:

```bash
# What the hook runs:
pytest tests/unit/ -v --tb=short
mypy src/
bandit -r src/
```

Always run full tests locally before pushing:

```bash
make test
```

---

## Commit Guidelines

### Commit Message Format

Follow **Conventional Commits** specification:

```
<type>(<scope>): <subject>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring (no functional change)
- `perf`: Performance improvements
- `test`: Adding/updating tests
- `chore`: Maintenance tasks (deps, build, etc.)

**Scope** (optional): Component affected (`memory`, `auth`, `mcp`, `api`)

**Subject**: Short description (imperative mood, lowercase, no period)

**Footer**: Reference Issues with `fixes`, `closes`, or `resolves`

### Examples

```bash
# ✅ GOOD: Feature with Issue reference
git commit -m "feat(memory): add semantic deduplication (fixes #130)"

# ✅ GOOD: Bug fix with scope
git commit -m "fix(auth): handle expired tokens correctly (fixes #135)"

# ✅ GOOD: Docs update
git commit -m "docs: update Docker build guide"

# ✅ GOOD: Refactoring
git commit -m "refactor(api): simplify health check endpoint"

# ❌ BAD: No type
git commit -m "Added new feature"

# ❌ BAD: No Issue reference (for bugs/features)
git commit -m "fix: bug in memory search"

# ❌ BAD: Vague description
git commit -m "feat: improvements"
```

### Issue References

**Always** reference the Issue number in commits:

```bash
# Preferred formats:
git commit -m "feat: description (fixes #123)"
git commit -m "feat: description (closes #123)"
git commit -m "feat: description (resolves #123)"

# Also accepted:
git commit -m "feat: description (#123)"
git commit -m "feat: description - Issue #123"
```

The pre-push hook extracts Issue numbers to post test results.

---

## Pull Request Process

### Before Creating PR

```bash
# 1. Sync with upstream
git checkout main
git pull upstream main

# 2. Rebase feature branch
git checkout feature/your-branch
git rebase main

# 3. Run all tests
make test

# 4. Check code quality
make format lint typecheck

# 5. Ensure pre-push hook passes
git push origin feature/your-branch
```

### Creating Pull Request

```bash
# Create PR via GitHub CLI
gh pr create \
  --title "feat: Your feature description" \
  --body "Closes #123

## Summary
Brief description of changes

## Changes
- Added X
- Fixed Y
- Updated Z

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed" \
  --label "enhancement"

# Or use --fill to auto-populate from commits
gh pr create --fill
```

### PR Checklist

Before submitting, ensure:

- [ ] Tests pass (`make test`)
- [ ] Code is formatted (`make format`)
- [ ] Linting passes (`make lint`)
- [ ] Type checking passes (`make typecheck`)
- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG updated (for significant changes)
- [ ] Issue referenced in commit message
- [ ] PR description is clear and complete

### PR Review Process

1. **Automated Checks**: Pre-push hook posts test results to Issue
2. **Code Review**: Maintainer reviews code, suggests changes
3. **Address Feedback**: Make changes, push updates
4. **Approval**: Maintainer approves PR
5. **Merge**: Maintainer merges (squash or rebase)

### After Merge

```bash
# 1. Switch to main
git checkout main

# 2. Pull latest changes
git pull upstream main

# 3. Delete feature branch
git branch -d feature/your-branch
git push origin --delete feature/your-branch

# 4. Close Issue (if not auto-closed)
gh issue close 123 --comment "Completed in #PR_NUMBER"
```

---

## Docker Builds

### Local Docker Build

Contributors should **not** build Docker images for PRs—this is handled by maintainers during releases.

If you need to test Docker locally:

```bash
# Build local image
docker build -t tmws:dev .

# Run locally
docker run -p 8000:8000 -e TMWS_LICENSE_KEY=TMWS-FREE-test tmws:dev

# Test health endpoint
curl http://localhost:8000/health
```

For detailed Docker build documentation, see:
- [docs/development/DOCKER_BUILD_GUIDE.md](docs/development/DOCKER_BUILD_GUIDE.md)

### Release Process (Maintainers Only)

```bash
# 1. Update version
vim pyproject.toml  # version = "2.5.0"

# 2. Commit version bump
git commit -am "chore: bump to v2.5.0"

# 3. Build and release Docker image
make docker-release ISSUE=XX

# 4. Verify release
gh release view v2.5.0
docker pull ghcr.io/apto-as/tmws:2.5.0
```

---

## Issue Tracking

### Creating Issues

Use GitHub Issues for:
- Bug reports
- Feature requests
- Documentation improvements
- Questions

```bash
# Create issue via CLI
gh issue create \
  --title "fix: Memory search returns duplicates" \
  --body "Description of bug..." \
  --label "bug,priority-P1"

# Or via web UI:
# https://github.com/apto-as/tmws/issues/new
```

### Issue Labels

| Label | Meaning |
|-------|---------|
| `bug` | Something isn't working |
| `enhancement` | New feature or request |
| `documentation` | Improvements to docs |
| `good first issue` | Good for newcomers |
| `help wanted` | Extra attention needed |
| `priority-P0` | Critical priority |
| `priority-P1` | High priority |
| `priority-P2` | Medium priority |
| `priority-P3` | Low priority |

### Issue Templates

When creating issues, include:

**Bug Reports:**
- **Description**: What's wrong?
- **Steps to Reproduce**: How to trigger the bug
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Environment**: OS, Python version, TMWS version

**Feature Requests:**
- **Problem**: What problem does this solve?
- **Proposed Solution**: How should it work?
- **Alternatives**: Other solutions considered
- **Additional Context**: Mockups, examples, etc.

---

## Questions

### Where to Ask

- **GitHub Discussions**: General questions, ideas
  - https://github.com/apto-as/tmws/discussions

- **GitHub Issues**: Bug reports, feature requests
  - https://github.com/apto-as/tmws/issues

- **Email**: Private inquiries, security issues
  - security@apto.as (security vulnerabilities)
  - support@apto.as (general support)

### Getting Help

```bash
# Search existing issues
gh issue list --search "memory search"

# Search discussions
gh search issues "semantic search" --discussions

# Create discussion
gh discussion create \
  --title "How to optimize vector search?" \
  --body "..." \
  --category "Q&A"
```

---

## Local Workflow Reference

For comprehensive details on the local-first development workflow, see:
- [docs/development/LOCAL_WORKFLOW.md](docs/development/LOCAL_WORKFLOW.md)

Key features:
- **Pre-push hook**: Automated test validation
- **Issue-centric**: All work tracked via GitHub Issues
- **TDD-friendly**: RED → GREEN → REFACTOR cycle
- **Git Worktree support**: Parallel task isolation

---

## Additional Resources

- [README.md](README.md) - Project overview
- [docs/development/LOCAL_WORKFLOW.md](docs/development/LOCAL_WORKFLOW.md) - Local workflow guide
- [docs/development/DOCKER_BUILD_GUIDE.md](docs/development/DOCKER_BUILD_GUIDE.md) - Docker build guide
- [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) - MCP integration
- [docs/TMWS_USAGE_GUIDE.md](docs/TMWS_USAGE_GUIDE.md) - Usage guide

---

## License

By contributing to TMWS, you agree that your contributions will be licensed under the MIT License.

---

## Acknowledgments

Thank you to all contributors who help make TMWS better! 🙏

---

**Last Updated**: 2025-12-10
**Issue**: [#55](https://github.com/apto-as/tmws/issues/55)
