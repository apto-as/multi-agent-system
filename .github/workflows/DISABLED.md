# GitHub Actions Workflows - DISABLED

**Status**: ⚠️ **Workflows Disabled** (Issue #55 Phase 2)
**Date**: 2025-12-10
**Reason**: GitHub-Independent Development Workflow

---

## Why Are Workflows Disabled?

As part of Issue #55 Phase 2, all automatic GitHub Actions triggers have been **disabled** to support a GitHub-independent development workflow. This allows:

1. **Local-first development** without GitHub dependency
2. **Git hook-based validation** via `pre-push` hooks
3. **Manual control** over CI/CD pipelines
4. **Reduced GitHub Actions minutes** consumption

---

## Disabled Workflows

### 1. `test-suite.yml` (CI/CD Pipeline)
**Disabled Triggers**:
- ❌ `push` (branches: master, main, develop)
- ❌ `pull_request` (branches: master, main, develop)
- ✅ `workflow_dispatch` (manual trigger **ONLY**)

**Replacement**: Local pre-push git hook
**See**: `scripts/git-hooks/pre-push-validator.py`

---

### 2. `docker-publish.yml` (Docker Image CI/CD)
**Disabled Triggers**:
- ❌ `push` (branches: master, tags: v*.*.*)
- ✅ `workflow_dispatch` (manual trigger **ONLY**)

**Replacement**: Local Docker build workflow
**See**: `make docker-build`, `make docker-push`, `make docker-release`

---

### 3. `docker-prebuild-scan.yml` (Security Scan)
**Disabled Triggers**:
- ❌ `pull_request` (paths: Dockerfile, workflows)
- ❌ `push` (branches: main, master, feature/**)
- ✅ `workflow_dispatch` (manual trigger **ONLY**)

**Replacement**: Security checks in pre-push hook
**See**: `scripts/git-hooks/pre-push-validator.py` (bandit integration)

---

## How to Run Workflows Manually

If you need to trigger a workflow manually (e.g., for official releases):

```bash
# Via GitHub CLI
gh workflow run test-suite.yml
gh workflow run docker-publish.yml

# Via GitHub Web UI
# 1. Go to Actions tab
# 2. Select workflow
# 3. Click "Run workflow" button
# 4. Choose branch and click "Run workflow"
```

---

## Local Development Workflow

### Pre-Push Validation (Replaces CI/CD)

```bash
# Install git hooks (one-time setup)
bash scripts/git-hooks/install-hooks.sh

# Hooks run automatically on push
git push origin feature/my-branch

# Hook runs:
# 1. pytest (unit + integration tests)
# 2. mypy (type checking)
# 3. bandit (security scan)
# 4. Generate test summary
# 5. Post to GitHub Issue (if Issue # in commit)
```

### Docker Build (Replaces docker-publish.yml)

```bash
# Build Docker image locally
make docker-build

# Push to GitHub Container Registry
make docker-push

# Build + Push + Tag release
make docker-release TAG=v2.4.17
```

---

## Re-Enabling Workflows

To re-enable automatic triggers (if GitHub workflow is needed):

1. Edit workflow YAML files
2. Uncomment `push` and `pull_request` triggers
3. Remove `# DISABLED:` comments
4. Commit changes

Example:
```yaml
# Before (disabled)
on:
  # push:
  #   branches: [ master ]
  workflow_dispatch:

# After (enabled)
on:
  push:
    branches: [ master ]
  workflow_dispatch:
```

---

## Trade-offs

### Advantages ✅
- No GitHub dependency for local development
- Faster feedback via local hooks
- No Actions minutes consumption
- Full control over validation timing

### Disadvantages ⚠️
- No automatic PR checks (must run locally)
- No public test badges (unless manually triggered)
- Requires developer discipline to run hooks
- No matrix testing across Python versions (local only)

---

## Monitoring

**Q**: How do I know if tests are passing?
**A**: Pre-push hook blocks push on test failures. See `.git/hooks/pre-push` for details.

**Q**: Can I skip the hook?
**A**: Yes, but **NOT recommended**:
```bash
git push --no-verify  # Skip hooks (use with caution!)
```

**Q**: Where are test results posted?
**A**: If commit message contains `Fixes #123`, results are posted to Issue #123 automatically.

---

## Related Documentation

- **Issue #55**: GitHub-independent workflow implementation
- **Pre-Push Hook**: `scripts/git-hooks/pre-push-validator.py`
- **Install Script**: `scripts/git-hooks/install-hooks.sh`
- **Makefile Targets**: `make docker-build`, `make docker-push`

---

**Last Updated**: 2025-12-10
**Maintained By**: Artemis (Technical Perfectionist)
**Status**: Active - Workflows disabled, local hooks enabled
