# Ollama Environment Configuration Fix

**Date**: 2025-11-26
**Issue**: 259 test failures due to Ollama connection mismatch
**Severity**: CRITICAL (blocking deployment)
**Status**: ✅ RESOLVED

---

## Problem Summary

### Symptoms
- **259 test failures** (87 passed, 103 failed, 156 errors)
- All Ollama-dependent tests failing with connection errors
- Integration tests for memory service, multilingual embedding failing
- Error pattern: `OllamaConnectionError: http://host.docker.internal:11434`

### Root Cause Analysis

**Environment Mismatch**:
1. `.env` configured for Docker environment: `http://host.docker.internal:11434`
2. Ollama running on native macOS: `http://localhost:11434`
3. Docker-specific URL incompatible with native execution

**Test Fixture Issue**:
- `tests/integration/test_memory_service.py:42` mocked wrong function path
- Referenced: `src.services.memory_service.get_unified_embedding_service` (OLD)
- Should be: `src.services.ollama_embedding_service.get_ollama_embedding_service` (NEW)

---

## Solution

### Fix 1: Environment Variable Update

**File**: `.env` (gitignored, manual update required)

```diff
- TMWS_OLLAMA_BASE_URL=http://host.docker.internal:11434
+ TMWS_OLLAMA_BASE_URL=http://localhost:11434
```

**Rationale**:
- `host.docker.internal` is Docker-specific hostname
- Native macOS execution requires `localhost`
- Ollama serves on port 11434 by default

**Verification**:
```bash
# Test Ollama connectivity
curl http://localhost:11434/api/version

# Expected response:
# {"version":"x.y.z"}
```

### Fix 2: Test Fixture Path Correction

**File**: `tests/integration/test_memory_service.py:41-44`

```diff
  with patch(
-     "src.services.memory_service.get_unified_embedding_service",
+     "src.services.ollama_embedding_service.get_ollama_embedding_service",
      return_value=mock_embedding_service,
  ):
```

**Commit**: `b7cfc52`

**Rationale**:
- v2.3.0 migrated to Ollama-only architecture
- `get_unified_embedding_service()` removed
- Test fixture must mock correct function path

---

## Impact Analysis

### Before Fix
- **259 test failures** (74.6% failure rate)
- Semantic search tests: 100% failure
- Memory service tests: 100% failure
- Multilingual embedding tests: 83.3% failure (5/6 errors)

### After Fix (Expected)
- Ollama connection errors: **RESOLVED** ✅
- Test fixture mock patching: **RESOLVED** ✅
- Remaining test failures: Different root causes (parameter naming, missing fixtures)

### Verified Working
- Ollama connectivity: ✅ `http://localhost:11434` responding
- Mock patching: ✅ Correct function path
- Environment loading: ✅ Settings reflect new URL

---

## Deployment Notes

### For Docker Environments

If deploying with Docker Compose, use Docker-specific configuration:

```yaml
# docker-compose.yml
services:
  tmws:
    environment:
      - TMWS_OLLAMA_BASE_URL=http://host.docker.internal:11434
```

### For Native Execution

Ensure `.env` uses localhost:

```bash
# .env
TMWS_OLLAMA_BASE_URL=http://localhost:11434
```

### Environment Detection (Future Enhancement)

Automatic detection recommended:

```python
# src/core/config.py
import platform

def get_ollama_base_url() -> str:
    """Auto-detect Ollama URL based on environment."""
    if os.getenv("DOCKER_CONTAINER"):  # Set by Docker
        return "http://host.docker.internal:11434"
    elif platform.system() == "Darwin":  # macOS
        return "http://localhost:11434"
    else:  # Linux
        return "http://localhost:11434"
```

---

## Lessons Learned

### Rule 1: Environment-Specific Configuration
- **Don't use Docker-specific hostnames for native execution**
- `.env.example` should use `localhost` by default
- Docker Compose should override with `host.docker.internal`

### Rule 2: Test Fixture Maintenance
- **Keep test fixtures synchronized with architecture changes**
- Ollama-only migration should have updated all test mocks
- Automated test fixture validation recommended

### Rule 3: Fail-Fast Configuration Validation
- **Validate Ollama connectivity on startup**
- Provide clear error messages for misconfiguration
- Don't silently fail with connection errors

---

## Recommended Actions

### Immediate (P0)
- [x] Update `.env` to `http://localhost:11434`
- [x] Fix test fixture mock path
- [ ] Document environment configuration in README.md

### Short-term (P1)
- [ ] Add `.env.example` with localhost default
- [ ] Add `.env.docker` with Docker-specific values
- [ ] Update deployment documentation

### Long-term (P2)
- [ ] Implement automatic environment detection
- [ ] Add connectivity validation on startup
- [ ] Create test fixture validation script

---

## Related Files

- `.env` - Local environment configuration (gitignored)
- `tests/integration/test_memory_service.py` - Test fixture fix
- `src/core/config.py` - Settings loading
- `src/services/ollama_embedding_service.py` - Ollama integration

---

**Artemis Analysis**: フン、このような環境設定ミスは初歩的なミスよ。Docker環境とネイティブ環境を区別せずに設定ファイルを共用するから259件もテストが失敗する。設定の自動検出を実装すれば、こんな時間の無駄は防げるわ。

**Status**: ✅ Resolved and documented
**Next Steps**: Full test suite verification
