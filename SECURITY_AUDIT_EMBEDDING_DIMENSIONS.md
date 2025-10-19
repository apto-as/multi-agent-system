# Security Audit: Embedding Dimension Inconsistencies in TMWS v2.2.6

**Audit Date**: 2025-01-17
**Auditor**: Hestia (Security Guardian)
**Severity**: **MEDIUM** (Data Integrity Risk)
**Status**: Active Investigation

---

## Executive Summary

TMWS v2.2.6 exhibits **dimension configuration inconsistencies** across three critical components. While the system is **currently functional** using 1024-dimensional embeddings via Ollama, residual configuration artifacts from previous versions (768-dim and 384-dim) pose **data integrity and operational risks**.

### Key Findings

| Component | Configured Dimension | Status | Risk Level |
|-----------|---------------------|--------|------------|
| **Runtime (Actual)** | 1024-dim (Ollama) | ✅ Active | None |
| **Config Default** | 768-dim | ⚠️ Stale | Medium |
| **Legacy Fallback** | 384-dim | ⚠️ Unused | Low |
| **MCP Server** | 768-dim (hardcoded) | ⚠️ Stale | Medium |

---

## Detailed Analysis

### 1. Actual Runtime Behavior (1024-dim) ✅

**Current State**: System is **correctly** using 1024-dimensional embeddings.

**Evidence**:
```python
# src/services/memory_service.py (Lines 51-53)
model_info = self.embedding_service.get_model_info()
self.embedding_model_name = model_info.get("model_name", "zylonai/multilingual-e5-large")
self.embedding_dimension = model_info.get("dimension", 1024)  # ✅ DYNAMIC DETECTION
```

**Provider Chain**:
1. **UnifiedEmbeddingService** (unified_embedding_service.py)
   - Initializes based on `TMWS_EMBEDDING_PROVIDER` config
   - Default: "auto" (Ollama → SentenceTransformers fallback)

2. **OllamaEmbeddingService** (ollama_embedding_service.py)
   - Model: `zylonai/multilingual-e5-large`
   - Expected Dimension: **1024** (Line 61)
   - Auto-detects actual dimension on first encoding (Lines 289-292)

3. **Dynamic Dimension Detection**:
   ```python
   # Chroma is REQUIRED for vector storage (SQLite stores metadata only)
   if self._model_dimension is None:
       self._model_dimension = embeddings_array.shape[1]
       logger.info(f"✅ Model dimension detected: {self._model_dimension}")
   ```

**✅ Verdict**: Runtime behavior is **CORRECT** and uses dynamic detection.

---

### 2. Configuration Default Inconsistency (768-dim) ⚠️

**Issue**: Default configuration in `src/core/config.py` specifies 768 dimensions.

**Location**: `src/core/config.py` (Line 146)
```python
# ==== VECTORIZATION & CHROMADB (v2.3.0) ====
embedding_model: str = Field(default="intfloat/multilingual-e5-base")
vector_dimension: int = Field(default=768, ge=1, le=4096)  # ⚠️ STALE
```

**Actual Ollama Model Configuration** (Lines 171-174):
```python
# Ollama embedding model (zylonai/multilingual-e5-large for cross-lingual support)
ollama_embedding_model: str = Field(
    default="zylonai/multilingual-e5-large",  # ✅ 1024-dim model
    description="Ollama embedding model name (default: multilingual-e5-large for Japanese-English)",
)
```

**Impact Analysis**:
- **Runtime**: ✅ No impact (dynamic detection overrides config)
- **New Deployments**: ⚠️ Misleading documentation
- **Monitoring**: ⚠️ Incorrect dimension in logs/metrics
- **Future Refactoring**: ⚠️ May cause bugs if dynamic detection is removed

**Risk Level**: **MEDIUM** (Documentation/Configuration drift)

---

### 3. Legacy Fallback Code (384-dim) ⚠️

**Issue**: `src/utils/embeddings.py` contains hardcoded 384-dimensional fallback.

**Location**: `src/utils/embeddings.py` (Lines 56, 64, 77-84, 111, etc.)

**Critical Code**:
```python
def get_embedding(text: str) -> list[float]:
    """
    Generate embedding vector for text.

    Returns:
        List[float]: 384-dimensional embedding vector  # ⚠️ HARDCODED
    """
    if not text or not text.strip():
        # Return zero vector for empty text
        return [0.0] * 384  # ⚠️ HARDCODED
```

**Usage Analysis**:
```bash
$ grep -r "from.*utils.embeddings|import.*embeddings" src/
# Result: No matches found
```

**✅ Verdict**: This module is **NOT CURRENTLY USED** in production code.

**Risk Assessment**:
- **Immediate Risk**: **LOW** (unused code)
- **Future Risk**: **MEDIUM** if accidentally imported
- **Code Maintenance**: **HIGH** (technical debt)

---

### 4. MCP Server Documentation Drift (768-dim) ⚠️

**Issue**: MCP server documentation claims 768-dimensional embeddings.

**Location**: `src/mcp_server.py`

**Hardcoded References**:
```python
# Line 7
- Multilingual-E5 embeddings (768-dimensional, cross-lingual)

# Line 39
- MultilingualEmbeddingService: 768-dimensional embeddings

# Line 207
"embedding_dimension": 768,

# Line 457
print("   • Multilingual-E5 embeddings (768-dim)")

# Line 493
"   Embeddings: Multilingual-E5 (768-dim)\n"
```

**Actual Runtime**: 1024-dimensional (Ollama)

**Impact**:
- **MCP Clients**: May receive incorrect metadata
- **Monitoring**: Misleading metrics
- **Documentation**: User confusion

**Risk Level**: **MEDIUM** (Operational confusion)

---

## Security Risk Assessment

### Risk Matrix

| Vulnerability | Likelihood | Impact | Risk Score |
|--------------|------------|--------|------------|
| **Dimension Mismatch on Failover** | Medium | High | **HIGH** |
| **Data Corruption from Wrong Dimension** | Low | Critical | **MEDIUM** |
| **Vector Search Degradation** | Medium | Medium | **MEDIUM** |
| **Legacy Code Accidental Use** | Low | High | **MEDIUM** |
| **Monitoring/Observability Gaps** | High | Low | **MEDIUM** |

### Detailed Threat Scenarios

#### Threat 1: Dimension Mismatch During Ollama Failover
**Scenario**: Ollama server becomes unavailable → System falls back to SentenceTransformers

**Current Failback Behavior**:
```python
# src/services/ollama_embedding_service.py (Lines 142-146)
if self._fallback_service is None:
    from .embedding_service import get_embedding_service
    self._fallback_service = get_embedding_service()
    # ⚠️ Returns MultilingualEmbeddingService (768-dim)
```

**Consequence**:
- Ollama: 1024-dim embeddings
- Fallback: **768-dim embeddings** (intfloat/multilingual-e5-base)
- Chroma collection: Expects **1024-dim** vectors
- **Result**: Vector dimension mismatch → Search failures

**Severity**: **HIGH** (System malfunction)

**Likelihood**: **MEDIUM** (Ollama server downtime is plausible)

**Overall Risk**: **CRITICAL**

---

#### Threat 2: Data Integrity Violation from Mixed Dimensions
**Scenario**: Production database contains embeddings of different dimensions

**Attack Vector**:
1. System starts with Ollama (1024-dim)
2. Ollama fails → Fallback to SentenceTransformers (768-dim)
3. New memories created with 768-dim embeddings
4. Ollama returns → System expects 1024-dim
5. **Result**: Inconsistent embedding dimensions in database

**Evidence of Vulnerability**:
```python
# src/services/memory_service.py (Lines 51-53)
# Dynamic dimension detection PER REQUEST
self.embedding_dimension = model_info.get("dimension", 1024)
```

**Why This is Dangerous**:
- SQLite stores metadata (dimension stored per memory)
- Chroma stores vectors (expects uniform dimension)
- **No validation** that all vectors match expected dimension

**Severity**: **CRITICAL** (Data corruption)

**Likelihood**: **LOW** (requires Ollama failover during write operations)

**Overall Risk**: **MEDIUM**

---

#### Threat 3: Legacy Code Accidental Activation
**Scenario**: Refactoring accidentally imports `utils/embeddings.py`

**Attack Vector**:
```python
# Hypothetical accident during refactoring
from src.utils.embeddings import get_embedding  # ⚠️ 384-dim!

# Instead of:
from src.services import get_embedding_service  # ✅ Correct
```

**Consequence**:
- 384-dim embeddings written to 1024-dim Chroma collection
- **Immediate search failure** (dimension mismatch)
- **Silent data corruption** if padding/truncation occurs

**Severity**: **HIGH** (Operational failure)

**Likelihood**: **LOW** (requires developer error)

**Overall Risk**: **MEDIUM**

---

## Recommended Remediation

### Priority 1: CRITICAL (Immediate Action Required)

#### 1.1 Fix Dimension Mismatch in Ollama Failover
**Issue**: Fallback to 768-dim SentenceTransformers breaks 1024-dim Chroma collection

**Solution**: Ensure fallback uses same dimension as primary

**Implementation**:
```python
# src/services/ollama_embedding_service.py
async def _get_fallback_service(self):
    """
    Lazy-load fallback embedding service with DIMENSION MATCHING.
    """
    if self._fallback_service is None:
        if self.model_name == "zylonai/multilingual-e5-large":
            # ✅ Use matching 1024-dim fallback
            from sentence_transformers import SentenceTransformer
            self._fallback_service = SentenceTransformer("intfloat/multilingual-e5-large")
            logger.warning("⚠️ Using Multilingual-E5 Large fallback (1024-dim)")
        else:
            # Use existing 768-dim fallback for base model
            from .embedding_service import get_embedding_service
            self._fallback_service = get_embedding_service()

    return self._fallback_service
```

**Alternative**: Raise error instead of falling back
```python
if not self._is_ollama_available and not self.fallback_enabled:
    raise RuntimeError(
        f"Ollama unavailable and fallback disabled. "
        f"Cannot maintain 1024-dim embedding consistency."
    )
```

---

#### 1.2 Add Dimension Validation in Vector Service
**Issue**: No validation that embedding dimension matches Chroma collection

**Solution**: Add runtime dimension check before inserting vectors

**Implementation**:
```python
# src/services/vector_search_service.py
async def add_memory(
    self,
    memory_id: str,
    embedding: list[float],
    metadata: dict[str, Any],
    content: str | None = None,
) -> None:
    """Add memory with dimension validation."""

    # ✅ SECURITY: Validate embedding dimension
    expected_dim = 1024  # Configuration-driven
    actual_dim = len(embedding)

    if actual_dim != expected_dim:
        raise ValueError(
            f"Embedding dimension mismatch: expected {expected_dim}, got {actual_dim}. "
            f"This indicates a configuration error or provider failover issue."
        )

    # Proceed with insertion
    await self.collection.add(...)
```

---

### Priority 2: HIGH (Within 7 Days)

#### 2.1 Update Configuration Defaults
**Issue**: `vector_dimension: int = Field(default=768)` is incorrect

**Solution**:
```python
# src/core/config.py (Line 146)
# ==== VECTORIZATION & CHROMADB (v2.3.0) ====
embedding_model: str = Field(default="intfloat/multilingual-e5-large")  # ✅ Large variant
vector_dimension: int = Field(default=1024, ge=1, le=4096)  # ✅ CORRECTED
max_embedding_batch_size: int = Field(default=32, ge=1, le=1000)
```

---

#### 2.2 Fix MCP Server Hardcoded Dimensions
**Issue**: `mcp_server.py` has multiple hardcoded "768" references

**Solution**: Use dynamic dimension from service

**Implementation**:
```python
# src/mcp_server.py
# Replace all hardcoded dimension references with:
embedding_service = get_unified_embedding_service()
actual_dimension = embedding_service.get_model_info().get("dimension", 1024)

# Example:
server_info = {
    "embedding_model": model_info.get("model_name"),
    "embedding_dimension": actual_dimension,  # ✅ DYNAMIC
}
```

---

### Priority 3: MEDIUM (Within 30 Days)

#### 3.1 Remove or Deprecate Legacy Fallback Code
**Issue**: `src/utils/embeddings.py` contains unused 384-dim code

**Options**:

**Option A: Complete Removal**
```bash
git rm src/utils/embeddings.py
```

**Option B: Add Deprecation Warning**
```python
# src/utils/embeddings.py (Top of file)
import warnings

warnings.warn(
    "utils/embeddings.py is DEPRECATED and will be removed in v2.3.0. "
    "Use services/unified_embedding_service.py instead.",
    DeprecationWarning,
    stacklevel=2
)
```

**Recommendation**: **Option A** (complete removal) if no external dependencies.

---

#### 3.2 Add Dimension Migration Tool
**Issue**: No tool to detect/fix dimension inconsistencies in existing data

**Solution**: Create migration script

**Implementation**:
```python
# scripts/validate_embedding_dimensions.py
async def validate_embedding_dimensions():
    """
    Audit all memories for embedding dimension consistency.

    Returns:
        - Total memories checked
        - Dimension distribution
        - Inconsistencies found
        - Recommended actions
    """
    memory_service = HybridMemoryService()

    # Check Chroma collection
    chroma_stats = await memory_service.vector_service.get_collection_stats()
    expected_dim = 1024

    # Scan for inconsistencies
    inconsistencies = []

    # ... validation logic ...

    return {
        "expected_dimension": expected_dim,
        "inconsistencies": inconsistencies,
        "action_required": len(inconsistencies) > 0
    }
```

---

## Compliance Impact

### OWASP Top 10 (2021)

- **A04: Insecure Design**: Medium severity
  - Lack of dimension validation allows data integrity violations
  - Recommendation: Implement strict dimension checks

### ISO 27001

- **A.12.6.1 Management of technical vulnerabilities**: Medium risk
  - Configuration drift poses operational risk
  - Recommendation: Automated configuration validation

---

## Monitoring Recommendations

### Metrics to Track

```python
# Add to monitoring dashboard
embedding_dimension_gauge = Gauge(
    "tmws_embedding_dimension",
    "Current embedding dimension in use",
    ["provider"]
)

dimension_mismatch_counter = Counter(
    "tmws_dimension_mismatch_total",
    "Total dimension mismatch errors",
    ["expected", "actual"]
)
```

### Alerts to Configure

1. **Critical**: Dimension mismatch detected during vector insertion
2. **Warning**: Ollama failover to SentenceTransformers
3. **Info**: Configuration dimension differs from runtime dimension

---

## Testing Recommendations

### Unit Tests

```python
# tests/unit/test_dimension_consistency.py
async def test_ollama_failover_dimension_match():
    """Test that failover maintains dimension consistency."""
    service = OllamaEmbeddingService(fallback_enabled=True)

    # Simulate Ollama unavailable
    service._is_ollama_available = False

    # Get fallback embedding
    embedding = await service.encode_document("test")

    # ✅ Assert dimension matches primary provider
    assert embedding.shape[0] == 1024, "Failover must maintain 1024-dim"
```

### Integration Tests

```python
# tests/integration/test_embedding_pipeline.py
async def test_end_to_end_dimension_consistency():
    """Test entire pipeline maintains dimension consistency."""
    memory_service = HybridMemoryService()

    # Create memory
    memory = await memory_service.create_memory(
        content="Test content",
        agent_id="test-agent"
    )

    # Search memory
    results = await memory_service.search_memories(
        query="Test query",
        agent_id="test-agent"
    )

    # ✅ Assert dimension consistency throughout
    assert memory.embedding_dimension == 1024
    assert all(r.embedding_dimension == 1024 for r in results)
```

---

## Conclusion

### Overall Risk Rating: **MEDIUM** (Trending to HIGH)

While TMWS v2.2.6 **currently functions correctly** with 1024-dimensional embeddings, the presence of **stale configuration values** (768-dim) and **unused legacy code** (384-dim) creates significant **operational and data integrity risks**, particularly during failover scenarios.

### Critical Action Items

1. ✅ **Immediate**: Fix Ollama failover dimension mismatch
2. ✅ **Immediate**: Add dimension validation to vector service
3. ⚠️ **7 Days**: Update configuration defaults to 1024-dim
4. ⚠️ **7 Days**: Fix MCP server hardcoded dimensions
5. 📝 **30 Days**: Remove/deprecate legacy embeddings.py
6. 📝 **30 Days**: Create dimension validation migration tool

### Success Criteria

- ✅ All configuration values match runtime dimension (1024)
- ✅ Ollama failover maintains dimension consistency
- ✅ Dimension validation prevents data corruption
- ✅ Monitoring alerts on dimension mismatches
- ✅ Legacy 384-dim code removed or clearly deprecated

---

**Audit Completed**: 2025-01-17
**Next Review**: 2025-02-17 (30 days)
**Auditor**: Hestia (Security Guardian)

*Paranoia is not negativity—it's preparedness.* 🔥
