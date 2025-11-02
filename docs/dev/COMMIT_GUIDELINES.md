# Commit Message Guidelines
## TMWS Project - Essential Standards

**Version**: 1.0.0 (Simplified)
**Last Updated**: 2025-10-27
**Status**: Mandatory
**Related**: `.claude/CLAUDE.md` Rule 10

---

## Purpose

Prevent misleading commit classifications like the GenAI Toolbox incident (commit 4466a9a: "refactor" that added 303 lines of new features).

**Key Principle**: **Commit messages must accurately describe what the commit does.**

---

## Commit Message Format

```
<type>(<scope>): <subject>

<body (optional)>

<footer (optional)>
```

### Type (Required)

| Type | Description | Example |
|------|-------------|---------|
| **feat** | New feature (requires user approval) | `feat(api): Add task priority filtering` |
| **fix** | Bug fix | `fix(auth): Correct JWT expiration validation` |
| **refactor** | Code refactoring (no functionality change) | `refactor(memory): Simplify query logic` |
| **perf** | Performance improvement | `perf(search): Add index to created_at column` |
| **docs** | Documentation only | `docs(api): Update authentication guide` |
| **test** | Test additions/modifications | `test(memory): Add edge case tests` |
| **chore** | Build/tooling changes | `chore: Update dependencies` |

### Subject (Required)

- **Maximum 72 characters**
- **Imperative mood** ("Add feature" not "Added feature")
- **No period at end**

---

## Critical Rules

### 1. Never Mislead with Type Classification

**GenAI Toolbox Violation** (commit 4466a9a):

```bash
# ❌ WRONG
refactor: Comprehensive project cleanup and code consolidation

# What it actually did:
# - Added 303 lines of new code (genai_toolbox_bridge.py)
# - Added 163 lines of migration
# - Added 4 new database tables
```

**Correct Approach**:

```bash
# ✅ CORRECT - Separate commits

# Commit 1: Actual cleanup
refactor: Remove duplicate code and unused files
- Delete unused audit_logger_enhanced.py
- Consolidate sanitize_input() to security/validators.py

# Commit 2: New feature (requires user approval FIRST)
feat(integration): Add GenAI Toolbox bridge

User approved: 2025-10-04 discussion
Implements: External toolbox integration for enhanced AI capabilities
```

### 2. New Features Require Approval Reference

**Mandatory for `feat` commits**:

```bash
feat(mcp): Add namespace auto-detection at server startup

User approved: 2025-10-27 conversation
Implements: Phase 2 namespace caching optimization

Performance:
- Environment variable: 0.00087 ms (125x faster)
- Git detection: 0.00090 ms (12,600x faster)
```

### 3. Avoid Vague Messages

```bash
# ❌ WRONG
fix: various fixes
refactor: improvements
feat: add stuff

# ✅ CORRECT
fix(auth): Prevent token reuse after logout
refactor(memory): Extract duplicate query logic to helper
feat(api): Add task filtering by assignee and status
```

---

## Body Guidelines (Optional but Recommended)

### When to Include

- Security fixes (vulnerability details)
- Breaking changes (migration guide)
- New features (rationale, user approval)
- Complex refactoring (before/after comparison)

### Format

```markdown
## What changed
[Brief description]

## Why
[Rationale or problem being solved]

## Impact
[Performance, breaking changes, dependencies]
```

---

## Footer Guidelines

### References

```bash
Closes: #123
Fixes: #456
Related: #789
```

### Breaking Changes

```bash
BREAKING CHANGE: Ollama is now required for all embedding operations.

Migration:
1. Install Ollama: https://ollama.ai/download
2. Pull model: ollama pull zylonai/multilingual-e5-large
```

---

## Pre-Commit Checklist

- [ ] **Type** accurately describes the change
- [ ] **Subject** is concise (<72 chars) and descriptive
- [ ] **New features** have user approval reference
- [ ] **No misleading classification** (cleanup ≠ new features)

---

## Good Examples

### Feature with Approval

```bash
feat(security): Fix path traversal in namespace sanitization (V-1)

User approved: 2025-10-27 security audit
CVSS 7.5 HIGH - Path traversal vulnerability

Fixed by:
- Block '.' and '/' characters in namespace_from_url()
- Add comprehensive validation tests (24 test cases)

Verification:
- ✅ 24/24 namespace tests PASSED
- ✅ Zero regression in functionality
```

### Refactoring (No Functionality Change)

```bash
refactor: Remove SentenceTransformers dependency

Migration to Ollama-only embedding architecture (v2.3.0)
User approved: 2025-10-27

Impact:
- Code reduction: -904 lines (-72% of embedding services)
- Memory savings: -1.5GB (removed PyTorch/transformers)

BREAKING CHANGE: Ollama is now REQUIRED (no fallback)
```

---

## Bad Examples

### Misleading Type

```bash
# ❌ WRONG - GenAI Toolbox incident
refactor: Comprehensive project cleanup and code consolidation
# ^ Actually added 466 lines of new feature code
```

### Vague Message

```bash
# ❌ WRONG
fix: various fixes
# ^ What was fixed? Why? How?
```

### Missing Approval

```bash
# ❌ WRONG
feat(integration): Add new external service integration
# ^ No user approval reference for new feature
```

---

## Related Documents

- `.claude/CLAUDE.md` - Rule 10: New Feature Approval Protocol
- `docs/incidents/GenAI_Toolbox_RCA.md` - Root cause analysis

---

**Last Updated**: 2025-10-27
**Incident Reference**: GenAI Toolbox (commit 4466a9a) - 466 lines of unauthorized code
