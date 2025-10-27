# ARCHITECTURE IMPACT ANALYSIS
## Ollama-Only Migration: SentenceTransformers Removal

**Date**: 2025-10-27
**Analyst**: Athena (Harmonious Conductor) 🏛️
**Version**: TMWS v2.2.6 → v2.3.0
**Scope**: Complete removal of SentenceTransformers, Ollama as mandatory prerequisite

---

## Executive Summary

- **Scope**: Complete architectural shift from dual-provider (Ollama + SentenceTransformers) to Ollama-only embedding system
- **Impact Level**: **HIGH** (Breaking changes, deployment requirements, dimension consistency)
- **Required Changes**: 27 files across 5 major categories
- **Estimated Effort**: 12-16 hours (including testing and documentation)

### Critical Findings

1. **✅ GOOD NEWS**: Current dynamic dimension detection is robust and will survive the migration
2. **⚠️ WARNING**: Removing SentenceTransformers fallback introduces **critical dimension mismatch risk**
3. **🚨 CRITICAL**: Ollama becomes a **mandatory runtime dependency** (breaking change)
4. **📝 REQUIRED**: Extensive documentation updates across 8+ files

---

## System Architecture Changes

### Before: Dual Provider Architecture (Current v2.2.6)

```
┌─────────────────────────────────────────────────────────────────┐
│                  UnifiedEmbeddingService                        │
│                  (Intelligent Provider Router)                  │
└────────────┬────────────────────────────────────┬───────────────┘
             │                                    │
             │                                    │
   ┌─────────▼────────┐               ┌──────────▼─────────┐
   │  PRIMARY PROVIDER │               │ FALLBACK PROVIDER   │
   │  ═══════════════  │               │  ═══════════════    │
   │                   │               │                     │
   │  Ollama Service   │   Failover    │ SentenceTransform   │
   │  ─────────────    │  ◄────────►   │ ──────────────      │
   │  • 1024-dim       │               │ • 768-dim (base)    │
   │  • multilingual-  │               │ • PyTorch-based     │
   │    e5-large       │               │ • Always available  │
   │  • Network-based  │               │ • Local inference   │
   │  • Windows-       │               │ • Cross-platform    │
   │    friendly       │               │                     │
   └───────────────────┘               └─────────────────────┘
             │                                    │
             └────────────────┬───────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │   Vector Storage    │
                    │   ══════════════    │
                    │   • ChromaDB        │
                    │   • SQLite          │
                    │   • Mixed dims OK   │
                    └─────────────────────┘

Configuration:
  embedding_provider: "auto"  # Smart fallback
  vector_dimension: 768       # Config (overridden dynamically)
  ollama_embedding_model: "zylonai/multilingual-e5-large"
  embedding_model: "intfloat/multilingual-e5-base"  # Fallback
```

### After: Ollama-Only Architecture (Target v2.3.0)

```
┌─────────────────────────────────────────────────────────────────┐
│                  OllamaEmbeddingService                         │
│                  (Single, Reliable Provider)                    │
│                  *** NO FALLBACK ***                            │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          │ MANDATORY
                          │ DEPENDENCY
                ┌─────────▼────────┐
                │  Ollama Server   │
                │  ════════════    │
                │  • REQUIRED      │
                │  • 1024-dim      │
                │  • multilingual- │
                │    e5-large      │
                │  • Port 11434    │
                │  • No fallback!  │
                └──────────────────┘
                          │
                ┌─────────▼──────────┐
                │   Vector Storage    │
                │   ══════════════    │
                │   • ChromaDB        │
                │   • SQLite          │
                │   • 1024-dim ONLY   │
                │   • Strict          │
                │     validation      │
                └─────────────────────┘

Configuration:
  embedding_provider: REMOVED  # Ollama only
  vector_dimension: 1024       # Fixed, validated
  ollama_embedding_model: "zylonai/multilingual-e5-large"
  embedding_model: REMOVED     # No fallback
```

### Key Architectural Differences

| Aspect | Before (Dual Provider) | After (Ollama-Only) | Impact |
|--------|----------------------|---------------------|--------|
| **Provider Selection** | Dynamic (auto/ollama/st) | Static (Ollama only) | Simpler, less flexible |
| **Fallback Strategy** | Automatic to SentenceTransformers | **None** (fail-fast) | Higher reliability requirement |
| **Dimension Handling** | Mixed (768/1024, dynamic detection) | Uniform (1024, validated) | Cleaner, more predictable |
| **Runtime Dependencies** | Optional (PyTorch fallback) | **Mandatory (Ollama server)** | Deployment complexity ↑ |
| **Windows Compatibility** | Native via fallback | Native via Ollama | Maintained |
| **Failure Mode** | Graceful degradation | Hard failure | Ops awareness required |
| **Setup Complexity** | Medium (Python only) | High (Python + Ollama) | Installation steps ↑ |

---

## Component-by-Component Impact

### 1. Configuration System

#### Files Affected
- `src/core/config.py` (Primary configuration)
- `config/production.yaml` (Production settings)
- `.env.example` (Environment template)

#### Changes Required

**src/core/config.py (Lines 146-188)**

**BEFORE:**
```python
# ==== VECTORIZATION & CHROMADB (v2.2.6: 1024-dim Multilingual-E5 Large) ====
embedding_model: str = Field(default="intfloat/multilingual-e5-base")  # ❌ REMOVE
vector_dimension: int = Field(default=768, ge=1, le=4096)  # ⚠️ UPDATE to 1024
max_embedding_batch_size: int = Field(default=32, ge=1, le=1000)

# ==== OLLAMA EMBEDDING CONFIGURATION (v2.2.5) ====
# Provider selection: "auto" (Ollama → fallback), "ollama" (Ollama only), "sentence-transformers" (ST only)
embedding_provider: str = Field(  # ❌ REMOVE ENTIRE FIELD
    default="auto",
    description="Embedding provider: auto (Ollama→fallback), ollama, or sentence-transformers",
    pattern="^(auto|ollama|sentence-transformers)$",
)

# Ollama server configuration
ollama_base_url: str = Field(
    default="http://localhost:11434",
    description="Ollama server URL for embedding generation"
)

ollama_embedding_model: str = Field(
    default="zylonai/multilingual-e5-large",  # ✅ KEEP
    description="Ollama embedding model name (default: multilingual-e5-large for Japanese-English)",
)

ollama_timeout: float = Field(
    default=30.0, ge=5.0, le=300.0,
    description="Ollama API request timeout in seconds"
)

# Fallback configuration
embedding_fallback_enabled: bool = Field(  # ❌ REMOVE
    default=True,
    description="Enable automatic fallback to sentence-transformers if Ollama unavailable",
)
```

**AFTER:**
```python
# ==== OLLAMA EMBEDDING CONFIGURATION (v2.3.0 - OLLAMA REQUIRED) ====
vector_dimension: int = Field(
    default=1024,  # ✅ UPDATED: 1024-dim for multilingual-e5-large
    ge=1024, le=1024,  # 🔒 LOCKED to 1024 (no other dimensions allowed)
    description="Embedding dimension (fixed at 1024 for multilingual-e5-large)"
)

max_embedding_batch_size: int = Field(default=32, ge=1, le=1000)

# Ollama server configuration (MANDATORY)
ollama_base_url: str = Field(
    default="http://localhost:11434",
    description="🚨 REQUIRED: Ollama server URL - system will not function without this"
)

ollama_embedding_model: str = Field(
    default="zylonai/multilingual-e5-large",
    description="Ollama embedding model (REQUIRED: zylonai/multilingual-e5-large for 1024-dim)",
    pattern="^zylonai/multilingual-e5-large.*$",  # 🔒 Enforce specific model
)

ollama_timeout: float = Field(
    default=30.0, ge=5.0, le=300.0,
    description="Ollama API request timeout in seconds"
)
```

**Migration Strategy:**
1. Update `vector_dimension` default from 768 → 1024
2. Remove `embedding_provider` field entirely
3. Remove `embedding_model` field (SentenceTransformers reference)
4. Remove `embedding_fallback_enabled` field
5. Add strict validation for `ollama_embedding_model` to ensure 1024-dim compatibility

---

### 2. Service Layer

#### 2.1 UnifiedEmbeddingService

**File**: `src/services/unified_embedding_service.py`

**Current Status**: Manages dual providers with intelligent routing
**Target Status**: **DELETE ENTIRE FILE** (no longer needed)

**Migration Path**:
1. All imports of `get_unified_embedding_service()` → `get_ollama_embedding_service()`
2. All `UnifiedEmbeddingService` references → `OllamaEmbeddingService`
3. Remove provider selection logic (lines 76-114)

**Affected Components**:
- `src/services/memory_service.py` (imports unified service)
- `src/services/vectorization_service.py` (may use unified service)
- `src/mcp_server.py` (MCP tools initialization)
- `src/tools/memory_tools.py` (direct service usage)

---

#### 2.2 OllamaEmbeddingService

**File**: `src/services/ollama_embedding_service.py`

**Changes Required**:

**BEFORE (Lines 136-170 - Fallback Logic):**
```python
async def _get_fallback_service(self):
    """
    Lazy-load fallback embedding service.
    ⚠️ DIMENSION SAFETY: Validates dimension compatibility with primary model.
    """
    if self._fallback_service is None:
        from .embedding_service import get_embedding_service  # ❌ REMOVE

        self._fallback_service = get_embedding_service()
        fallback_dim = self._fallback_service.get_model_info()["dimension"]

        # CRITICAL: Dimension validation
        if fallback_dim != self.DEFAULT_DIMENSION:
            logger.critical(
                f"🚨 DIMENSION MISMATCH: Ollama={self.DEFAULT_DIMENSION}d, "
                f"Fallback={fallback_dim}d - THIS WILL BREAK VECTOR SEARCH!"
            )
            raise RuntimeError(...)

        logger.info(f"✅ Fallback service initialized (dimension: {fallback_dim})")

    return self._fallback_service
```

**AFTER:**
```python
# ❌ REMOVE ENTIRE _get_fallback_service() METHOD

# Update __init__ to remove fallback option
def __init__(
    self,
    ollama_base_url: str | None = None,
    model_name: str | None = None,
    # fallback_enabled: bool = True,  # ❌ REMOVE PARAMETER
    timeout: float = DEFAULT_TIMEOUT,
    auto_detect: bool = True,
):
    """
    Initialize Ollama embedding service (MANDATORY - no fallback).

    Raises:
        RuntimeError: If Ollama server is not available
    """
    self.ollama_base_url = ollama_base_url or self.DEFAULT_OLLAMA_URL
    self.model_name = model_name or self.DEFAULT_MODEL
    # self.fallback_enabled = fallback_enabled  # ❌ REMOVE
    self.timeout = timeout

    # State tracking
    self._is_ollama_available = False
    # self._fallback_service = None  # ❌ REMOVE
    self._model_dimension = None

    # MANDATORY: Ollama server check
    if auto_detect:
        if not self._detect_ollama_server():
            raise RuntimeError(
                f"🚨 CRITICAL: Ollama server not available at {self.ollama_base_url}\n"
                f"TMWS v2.3.0 requires Ollama server to be running.\n"
                f"\n"
                f"Quick Start:\n"
                f"  1. Install: curl -fsSL https://ollama.com/install.sh | sh\n"
                f"  2. Start:   ollama serve\n"
                f"  3. Pull:    ollama pull {self.model_name}\n"
                f"\n"
                f"For more information: https://ollama.com"
            )
```

**Update encode_document() and encode_query():**
```python
async def encode_document(
    self,
    text: str | list[str],
    normalize: bool = True,
    batch_size: int = 32,
) -> np.ndarray:
    """Encode document(s) - Ollama REQUIRED."""
    if not self._is_ollama_available:
        raise RuntimeError(
            f"Ollama server unavailable at {self.ollama_base_url}. "
            f"Please start Ollama: ollama serve"
        )

    try:
        return await self._encode_ollama(
            text=text,
            prefix="passage: ",
            normalize=normalize,
            batch_size=batch_size,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        logger.error(f"❌ Ollama encoding failed: {e}", exc_info=True)
        # ❌ REMOVE FALLBACK LOGIC
        raise RuntimeError(
            f"Embedding generation failed: {e}\n"
            f"Ensure Ollama server is running: ollama serve"
        ) from e
```

---

#### 2.3 Legacy EmbeddingService (SentenceTransformers)

**File**: `src/services/embedding_service.py`

**Action**: **DELETE ENTIRE FILE**

**Rationale**:
- This is the 768-dim `intfloat/multilingual-e5-base` fallback provider
- No longer needed in Ollama-only architecture
- Removing eliminates dimension mismatch risk

**Cleanup Required**:
- Remove from `__init__.py` exports
- Remove from imports across codebase
- Update any direct references to use `OllamaEmbeddingService`

---

#### 2.4 Memory Service

**File**: `src/services/memory_service.py`

**Impact**: **MINIMAL** (dynamic dimension detection survives)

**Current Code (Lines 51-53)**:
```python
model_info = self.embedding_service.get_model_info()
self.embedding_model_name = model_info.get("model_name", "zylonai/multilingual-e5-large")
self.embedding_dimension = model_info.get("dimension", 1024)  # ✅ DYNAMIC DETECTION
```

**✅ NO CHANGES NEEDED**: This dynamic detection works regardless of provider!

**Recommendation**: Add validation to ensure dimension matches expected:
```python
model_info = self.embedding_service.get_model_info()
self.embedding_model_name = model_info.get("model_name", "zylonai/multilingual-e5-large")
self.embedding_dimension = model_info.get("dimension", 1024)

# ✅ NEW: Validate dimension matches expected
expected_dim = get_settings().vector_dimension
if self.embedding_dimension != expected_dim:
    raise RuntimeError(
        f"🚨 Embedding dimension mismatch: "
        f"Expected {expected_dim} (config), got {self.embedding_dimension} (model). "
        f"This indicates a configuration error."
    )
```

---

### 3. Documentation

#### Files to Update

| File | Changes | Priority |
|------|---------|----------|
| `README.md` | Remove dual-provider sections, update prerequisites | **CRITICAL** |
| `INSTALL.md` | Add Ollama installation steps, remove PyTorch references | **CRITICAL** |
| `docs/security/SECURITY_AUDIT_EMBEDDING_DIMENSIONS.md` | Update dimension analysis, remove 768-dim references | **HIGH** |
| `.claude/CLAUDE.md` | Update embedding configuration examples | **HIGH** |
| `docs/OLLAMA_INTEGRATION_GUIDE.md` | Comprehensive Ollama setup guide | **HIGH** |
| `QUICKSTART.md` | Add Ollama as Step 0 | **MEDIUM** |
| `docs/MCP_TOOLS_REFERENCE.md` | Update embedding metadata | **MEDIUM** |
| `docs/architecture/TMWS_v2.2.0_ARCHITECTURE.md` | New architecture diagrams | **MEDIUM** |

#### 3.1 README.md Updates

**Current (Lines 422-442 - Ollama Configuration)**:
```markdown
### Ollama Embedding Configuration (v2.2.5+)

```bash
# Embedding provider selection
TMWS_EMBEDDING_PROVIDER=auto  # auto, ollama, sentence-transformers

# Ollama server configuration
TMWS_OLLAMA_BASE_URL=http://localhost:11434
TMWS_OLLAMA_EMBEDDING_MODEL=zylonai/multilingual-e5-large
TMWS_OLLAMA_TIMEOUT=30.0

# Fallback configuration
TMWS_EMBEDDING_FALLBACK_ENABLED=true
```

**Provider選択ガイド**:
- `auto`: Ollamaが利用可能ならOllama、不可ならSentenceTransformers（推奨）
- `ollama`: Ollama専用（フォールバックなし）
- `sentence-transformers`: 従来のPyTorchベース埋め込み
```

**NEW (v2.3.0)**:
```markdown
### Ollama Embedding Configuration (v2.3.0 - REQUIRED)

🚨 **Ollama is now a MANDATORY prerequisite for TMWS v2.3.0+**

#### Prerequisites
```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Start Ollama server
ollama serve

# 3. Pull the embedding model
ollama pull zylonai/multilingual-e5-large
```

#### Environment Variables
```bash
# Ollama server configuration (REQUIRED)
TMWS_OLLAMA_BASE_URL=http://localhost:11434
TMWS_OLLAMA_EMBEDDING_MODEL=zylonai/multilingual-e5-large
TMWS_OLLAMA_TIMEOUT=30.0
TMWS_VECTOR_DIMENSION=1024  # Fixed for multilingual-e5-large
```

#### Breaking Changes from v2.2.x
- ❌ **REMOVED**: `TMWS_EMBEDDING_PROVIDER` (no provider selection)
- ❌ **REMOVED**: `TMWS_EMBEDDING_FALLBACK_ENABLED` (no fallback)
- ❌ **REMOVED**: `TMWS_EMBEDDING_MODEL` (SentenceTransformers reference)
- ✅ **REQUIRED**: Ollama server must be running at all times
```

---

#### 3.2 INSTALL.md Updates

**Add new section before Step 1:**

```markdown
## Step 0: Ollama Installation (MANDATORY for v2.3.0+)

### macOS / Linux
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama server (background service)
ollama serve &

# Verify installation
ollama --version

# Pull embedding model (1.2GB download)
ollama pull zylonai/multilingual-e5-large

# Verify model availability
ollama list | grep multilingual-e5-large
```

### Windows
```powershell
# Download installer from https://ollama.com/download/windows
# Install and run Ollama Desktop

# Open PowerShell and pull model
ollama pull zylonai/multilingual-e5-large
```

### Verification
```bash
# Test Ollama API
curl http://localhost:11434/api/tags

# Expected output: JSON with model list including "zylonai/multilingual-e5-large"
```

⚠️ **Important**: Ollama server MUST be running before starting TMWS. System will fail to initialize without it.
```

---

#### 3.3 New Document: OLLAMA_MIGRATION_GUIDE.md

Create comprehensive migration guide:

```markdown
# Migration Guide: v2.2.x → v2.3.0 (Ollama-Only Architecture)

## Breaking Changes Summary

### 1. Ollama is Now Mandatory
- **Before**: Optional (with SentenceTransformers fallback)
- **After**: **REQUIRED** (system will not start without Ollama)

### 2. Configuration Changes
```diff
# .env file changes
- TMWS_EMBEDDING_PROVIDER=auto
- TMWS_EMBEDDING_FALLBACK_ENABLED=true
- TMWS_EMBEDDING_MODEL=intfloat/multilingual-e5-base
+ TMWS_VECTOR_DIMENSION=1024  # Fixed (was 768)
```

### 3. Removed Dependencies
- `sentence-transformers` package (no longer needed)
- `torch` package (unless using for other purposes)
- `intfloat/multilingual-e5-base` model downloads

## Migration Checklist

### Pre-Migration
- [ ] Verify all existing memories use 1024-dim embeddings
- [ ] Backup database: `pg_dump tmws_db > backup_$(date +%Y%m%d).sql`
- [ ] Export ChromaDB collection (if needed)

### Ollama Setup
- [ ] Install Ollama: `curl -fsSL https://ollama.com/install.sh | sh`
- [ ] Start Ollama: `ollama serve`
- [ ] Pull model: `ollama pull zylonai/multilingual-e5-large`
- [ ] Verify: `ollama list | grep multilingual-e5-large`

### Code Updates
- [ ] Update `.env` (remove old provider settings)
- [ ] Update `config/production.yaml`
- [ ] Remove `sentence-transformers` from `requirements.txt`
- [ ] Update imports: `get_unified_embedding_service` → `get_ollama_embedding_service`

### Testing
- [ ] Health check: `curl http://localhost:8000/health`
- [ ] Embedding test: Create and search a memory
- [ ] Dimension validation: Check logs for "1024-dim" confirmation
- [ ] Performance benchmark: `python scripts/benchmark_ollama.py`

### Production Deployment
- [ ] Update deployment scripts to ensure Ollama is running
- [ ] Configure systemd/supervisor for Ollama service
- [ ] Update monitoring alerts (add Ollama health check)
- [ ] Document rollback procedure

## Rollback Procedure (if needed)

```bash
# 1. Restore to v2.2.6
git checkout v2.2.6

# 2. Reinstall dependencies
pip install -e .

# 3. Restore .env backup
cp .env.v2.2.6.backup .env

# 4. Restart services
python -m src.main
```

## Dimension Consistency Validation

Run this script to ensure all existing embeddings are 1024-dim:

```python
# scripts/validate_embedding_dimensions_v2.3.0.py
import asyncio
from src.services.memory_service import MemoryService
from src.core.database import get_session

async def validate():
    async with get_session() as session:
        # Check all memories
        result = await session.execute("SELECT id, array_length(embedding, 1) as dim FROM memories")
        memories = result.fetchall()

        mismatches = [m for m in memories if m.dim != 1024]

        if mismatches:
            print(f"🚨 {len(mismatches)} memories have incorrect dimensions!")
            for m in mismatches[:10]:  # Show first 10
                print(f"  Memory {m.id}: {m.dim} dimensions")
        else:
            print(f"✅ All {len(memories)} memories have correct 1024 dimensions")

asyncio.run(validate())
```
```

---

### 4. Deployment & Installation

#### 4.1 install.sh Updates

**Current (Lines 262-272 - Dependency Installation)**:
```bash
# Install dependencies
if [ "$USE_UV" = true ]; then
    echo "Installing dependencies with UV..."
    uv sync
else
    echo "Installing dependencies with pip..."
    pip install --upgrade pip
    pip install -e .
    pip install chromadb sentence-transformers  # ❌ REMOVE sentence-transformers
fi
```

**NEW:**
```bash
# Install dependencies (v2.3.0 - Ollama only)
if [ "$USE_UV" = true ]; then
    echo "Installing dependencies with UV..."
    uv sync --no-extras sentence-transformers  # Exclude ST extra
else
    echo "Installing dependencies with pip..."
    pip install --upgrade pip
    pip install -e .
    pip install chromadb  # ✅ ChromaDB only (no sentence-transformers)
fi
print_success "Dependencies installed (ChromaDB only)"
```

**Add Ollama Check (NEW Section after Line 109)**:
```bash
# Check Ollama (MANDATORY in v2.3.0)
print_header "Step 1.5: Ollama Verification (CRITICAL)"

if check_command ollama; then
    print_success "Ollama CLI found"

    # Check if Ollama server is running
    if curl -s http://localhost:11434/api/tags &> /dev/null; then
        print_success "Ollama server is running"

        # Check if model is available
        if ollama list | grep -q "zylonai/multilingual-e5-large"; then
            print_success "Embedding model (zylonai/multilingual-e5-large) is available"
        else
            print_warning "Embedding model not found. Pulling..."
            ollama pull zylonai/multilingual-e5-large
            print_success "Embedding model pulled successfully"
        fi
    else
        print_error "Ollama server not running!"
        echo "Starting Ollama server..."
        ollama serve &
        sleep 3
        print_success "Ollama server started"

        # Pull model
        print_warning "Pulling embedding model (this may take a few minutes)..."
        ollama pull zylonai/multilingual-e5-large
        print_success "Embedding model ready"
    fi
else
    print_error "Ollama not found! This is MANDATORY for TMWS v2.3.0"
    echo ""
    echo "Installing Ollama..."

    if [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "linux-gnu"* ]]; then
        curl -fsSL https://ollama.com/install.sh | sh
        print_success "Ollama installed"

        # Start server
        ollama serve &
        sleep 3

        # Pull model
        ollama pull zylonai/multilingual-e5-large
        print_success "Embedding model ready"
    else
        print_error "Please install Ollama manually from https://ollama.com"
        exit 1
    fi
fi
```

---

#### 4.2 scripts/install_production.sh

Similar updates to install.sh, plus:

```bash
# Production-specific: Ensure Ollama runs as a service

# Add to systemd (Linux)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    cat > /etc/systemd/system/ollama.service <<'EOF'
[Unit]
Description=Ollama Embedding Server
After=network.target

[Service]
Type=simple
User=tmws
ExecStart=/usr/local/bin/ollama serve
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ollama
    systemctl start ollama
    print_success "Ollama configured as systemd service"
fi

# Add to launchd (macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    cat > ~/Library/LaunchAgents/com.ollama.server.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ollama.server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/ollama</string>
        <string>serve</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

    launchctl load ~/Library/LaunchAgents/com.ollama.server.plist
    print_success "Ollama configured as launchd service"
fi
```

---

### 5. Testing Impact

#### Files to Update/Remove

| Test File | Action | Reason |
|-----------|--------|--------|
| `tests/unit/test_unified_embedding_service.py` | **DELETE** | No more unified service |
| `tests/unit/test_ollama_embedding_service.py` | **UPDATE** | Remove fallback tests |
| `tests/integration/test_multilingual_embedding.py` | **UPDATE** | Use Ollama only |
| `tests/unit/test_embedding_service.py` | **DELETE** | SentenceTransformers removed |

#### New Tests Required

**tests/unit/test_ollama_mandatory.py**:
```python
"""Test Ollama mandatory requirement."""
import pytest
from src.services.ollama_embedding_service import OllamaEmbeddingService


def test_ollama_unavailable_raises_error(monkeypatch):
    """System should fail-fast if Ollama unavailable."""
    # Mock Ollama server unavailable
    def mock_detect_ollama(*args, **kwargs):
        return False

    monkeypatch.setattr(
        OllamaEmbeddingService,
        "_detect_ollama_server",
        mock_detect_ollama
    )

    with pytest.raises(RuntimeError, match="CRITICAL: Ollama server not available"):
        OllamaEmbeddingService(auto_detect=True)


async def test_dimension_validation():
    """Ensure only 1024-dim embeddings are generated."""
    service = OllamaEmbeddingService()

    embedding = await service.encode_document("test")
    assert embedding.shape[0] == 1024, "Embedding must be 1024-dimensional"

    info = service.get_model_info()
    assert info["dimension"] == 1024
```

---

## Dependency Graph

### Before (Current Dependencies)

```
tmws
├── sentence-transformers==2.2.2
│   ├── torch>=1.11.0
│   ├── transformers>=4.32.0
│   ├── huggingface-hub>=0.15.1
│   └── scikit-learn
├── chromadb
│   └── onnxruntime
├── httpx (for Ollama)
└── ...other deps
```

**Total install size**: ~4.2GB (PyTorch + models)

### After (Ollama-Only)

```
tmws
├── chromadb
│   └── onnxruntime
├── httpx (for Ollama API)
└── ...other deps

External:
  Ollama Server (separate process)
  └── zylonai/multilingual-e5-large (1.2GB)
```

**Total Python install size**: ~800MB (60% reduction!)
**External dependency**: Ollama server (systemd/docker service)

---

## Configuration Migration Plan

### Phase 1: Configuration Updates

#### config/production.yaml

**BEFORE:**
```yaml
# Embedding Configuration
embedding:
  model: "sentence-transformers/all-MiniLM-L6-v2"
  dimension: 384
  batch_size: 32
  cache_enabled: true
  cache_ttl: 3600

  # CPU optimization
  cpu_optimization:
    num_threads: 4
    use_multiprocessing: false
```

**AFTER:**
```yaml
# Ollama Embedding Configuration (v2.3.0 - MANDATORY)
embedding:
  # Ollama server (REQUIRED)
  ollama_url: "http://localhost:11434"
  ollama_model: "zylonai/multilingual-e5-large"
  ollama_timeout: 30.0

  # Embedding parameters
  dimension: 1024  # Fixed for multilingual-e5-large
  batch_size: 32
  normalize: true

  # No CPU optimization needed (Ollama handles inference)
```

### Phase 2: Environment Variables

**Migration Script** (`scripts/migrate_env_v2.3.0.sh`):
```bash
#!/bin/bash
# Migrate .env from v2.2.x to v2.3.0

# Backup current .env
cp .env .env.v2.2.6.backup

# Remove deprecated variables
sed -i '' '/TMWS_EMBEDDING_PROVIDER/d' .env
sed -i '' '/TMWS_EMBEDDING_FALLBACK_ENABLED/d' .env
sed -i '' '/TMWS_EMBEDDING_MODEL=/d' .env

# Update dimension
sed -i '' 's/TMWS_VECTOR_DIMENSION=768/TMWS_VECTOR_DIMENSION=1024/' .env

# Add Ollama-specific variables if not present
grep -q "TMWS_OLLAMA_BASE_URL" .env || echo "TMWS_OLLAMA_BASE_URL=http://localhost:11434" >> .env
grep -q "TMWS_OLLAMA_EMBEDDING_MODEL" .env || echo "TMWS_OLLAMA_EMBEDDING_MODEL=zylonai/multilingual-e5-large" >> .env

echo "✅ Migration complete. Backup saved to .env.v2.2.6.backup"
```

---

## Compatibility Matrix

| Component | v2.2.6 (Before) | v2.3.0 (After) | Breaking Change? |
|-----------|----------------|----------------|------------------|
| **Python Version** | 3.11+ | 3.11+ | ❌ No |
| **API Endpoints** | All endpoints | All endpoints | ❌ No |
| **MCP Tools** | All tools | All tools | ❌ No |
| **Database Schema** | SQLite + ChromaDB | SQLite + ChromaDB | ❌ No |
| **Embedding Dimension** | 768/1024 mixed | 1024 only | ⚠️ **Yes** (data migration may be needed) |
| **Provider Selection** | auto/ollama/st | ollama (fixed) | ⚠️ **Yes** |
| **Fallback Behavior** | Automatic | None (fail-fast) | ⚠️ **Yes** |
| **PyTorch Dependency** | Required (fallback) | Optional | ❌ No (improvement) |
| **Ollama Server** | Optional | **MANDATORY** | 🚨 **Yes (CRITICAL)** |
| **Windows Support** | Native (PyTorch) | Native (Ollama) | ❌ No |
| **Installation Time** | 10-15 min | 15-20 min | ⚠️ Yes (Ollama setup) |
| **Disk Space** | ~4.5GB | ~2GB Python + 1.2GB Ollama | ❌ No (reduction) |

---

## Migration Checklist

### Phase 1: Code Changes (4-6 hours)

- [ ] **Remove UnifiedEmbeddingService**
  - [ ] Delete `src/services/unified_embedding_service.py`
  - [ ] Update all imports to use `OllamaEmbeddingService`
  - [ ] Remove from `src/services/__init__.py`

- [ ] **Update OllamaEmbeddingService**
  - [ ] Remove `fallback_enabled` parameter
  - [ ] Remove `_get_fallback_service()` method
  - [ ] Update `__init__` to raise error if Ollama unavailable
  - [ ] Remove fallback logic from `encode_document()` and `encode_query()`

- [ ] **Remove SentenceTransformers Service**
  - [ ] Delete `src/services/embedding_service.py`
  - [ ] Remove from all imports
  - [ ] Clean up test files

- [ ] **Update Configuration**
  - [ ] `src/core/config.py`: Remove provider fields
  - [ ] `src/core/config.py`: Update `vector_dimension` to 1024
  - [ ] Add strict validation for Ollama model

- [ ] **Update Memory Service**
  - [ ] Add dimension validation in `__init__`
  - [ ] Ensure dynamic detection still works

### Phase 2: Configuration (2-3 hours)

- [ ] **Update config files**
  - [ ] `config/production.yaml`: Remove ST references
  - [ ] `.env.example`: Update with Ollama-only config
  - [ ] Create migration script for existing `.env` files

- [ ] **Create new templates**
  - [ ] Ollama systemd service file
  - [ ] Ollama Docker Compose configuration
  - [ ] Windows service wrapper

### Phase 3: Documentation (4-5 hours)

- [ ] **Update existing docs**
  - [ ] `README.md`: New prerequisites section
  - [ ] `INSTALL.md`: Add Ollama installation (Step 0)
  - [ ] `QUICKSTART.md`: Ollama setup instructions
  - [ ] Update architecture diagrams

- [ ] **Create new docs**
  - [ ] `OLLAMA_MIGRATION_GUIDE.md`
  - [ ] `OLLAMA_TROUBLESHOOTING.md`
  - [ ] Update `SECURITY_AUDIT_EMBEDDING_DIMENSIONS.md`

- [ ] **Update MCP docs**
  - [ ] `docs/MCP_TOOLS_REFERENCE.md`: Update embedding metadata
  - [ ] `.claude/CLAUDE.md`: Update configuration examples

### Phase 4: Testing (2-3 hours)

- [ ] **Remove old tests**
  - [ ] Delete `test_unified_embedding_service.py`
  - [ ] Delete `test_embedding_service.py` (SentenceTransformers)

- [ ] **Update existing tests**
  - [ ] `test_ollama_embedding_service.py`: Remove fallback tests
  - [ ] `test_multilingual_embedding.py`: Ollama-only

- [ ] **Create new tests**
  - [ ] `test_ollama_mandatory.py`: Fail-fast tests
  - [ ] `test_dimension_validation.py`: Strict 1024-dim validation
  - [ ] Integration test with Ollama server mock

- [ ] **Run test suite**
  - [ ] Unit tests: `pytest tests/unit -v`
  - [ ] Integration tests: `pytest tests/integration -v`
  - [ ] Dimension validation script

### Phase 5: Deployment Updates (1-2 hours)

- [ ] **Update installation scripts**
  - [ ] `install.sh`: Add Ollama check and installation
  - [ ] `scripts/install_production.sh`: Add service configuration
  - [ ] Docker: Create Ollama sidecar container

- [ ] **Update CI/CD**
  - [ ] GitHub Actions: Install Ollama in test environment
  - [ ] Add Ollama health check to deployment pipeline

- [ ] **Update monitoring**
  - [ ] Add Ollama server health check
  - [ ] Alert on Ollama server downtime
  - [ ] Track embedding dimension in metrics

---

## Recommendations

### Priority 1: CRITICAL (Immediate Action)

1. **✅ Create Ollama Installation Guide**
   - Step-by-step for all platforms (macOS/Linux/Windows)
   - Systemd service configuration
   - Docker Compose example
   - Troubleshooting section

2. **✅ Add Dimension Validation**
   - Strict 1024-dim check in Memory Service
   - Fail-fast if dimension mismatch
   - Log clear error messages

3. **✅ Update Configuration Defaults**
   - `vector_dimension`: 768 → 1024
   - Remove all provider selection fields
   - Add Ollama validation

### Priority 2: HIGH (Within Sprint)

4. **⚠️ Migration Script for Existing Deployments**
   - Automated `.env` migration
   - Database dimension validation
   - Rollback capability

5. **⚠️ Comprehensive Testing**
   - End-to-end with Ollama
   - Failure scenarios (Ollama down)
   - Performance benchmarks

6. **⚠️ Documentation Overhaul**
   - All mentions of "dual provider" → "Ollama-only"
   - Prerequisites prominently feature Ollama
   - Migration guide for v2.2.x users

### Priority 3: MEDIUM (Before Release)

7. **📝 Docker/Container Support**
   - Ollama sidecar container
   - Health check integration
   - Volume mounts for model cache

8. **📝 Monitoring & Alerting**
   - Ollama server health endpoint
   - Embedding dimension metrics
   - Alert on service downtime

9. **📝 Performance Optimization**
   - Benchmark Ollama vs SentenceTransformers
   - Optimize batch sizes for Ollama
   - Connection pooling

---

## Risks & Mitigation

### Risk 1: Ollama Server Downtime

**Impact**: System completely non-functional
**Likelihood**: Medium
**Severity**: **CRITICAL**

**Mitigation**:
- Clear error messages with recovery instructions
- Systemd/supervisor automatic restart
- Health check endpoint for monitoring
- Documentation for manual restart

**Code Example**:
```python
# Enhanced error message
if not self._is_ollama_available:
    raise RuntimeError(
        "🚨 CRITICAL: Ollama server not available\n"
        "\n"
        "TMWS v2.3.0 requires Ollama to be running.\n"
        "\n"
        "Quick Fix:\n"
        "  systemctl restart ollama  # Linux\n"
        "  brew services restart ollama  # macOS\n"
        "  ollama serve  # Manual\n"
        "\n"
        "Check status: curl http://localhost:11434/api/tags\n"
    )
```

### Risk 2: Dimension Mismatch in Existing Data

**Impact**: Search failures, data corruption
**Likelihood**: Low (if migration script used)
**Severity**: **HIGH**

**Mitigation**:
- Pre-migration validation script
- Database backup before migration
- Gradual rollout with canary testing

**Validation Script**:
```python
# scripts/validate_pre_migration.py
async def validate_embeddings():
    """Validate all embeddings are 1024-dim before migration."""
    async with get_session() as session:
        result = await session.execute(
            "SELECT id, array_length(embedding, 1) as dim FROM memories"
        )
        memories = result.fetchall()

        non_1024 = [m for m in memories if m.dim != 1024]

        if non_1024:
            print(f"⚠️ Found {len(non_1024)} memories with incorrect dimensions")
            print("Migration to v2.3.0 will require re-embedding these memories")
            return False

        print(f"✅ All {len(memories)} memories are 1024-dimensional")
        return True
```

### Risk 3: Increased Installation Complexity

**Impact**: Higher barrier to entry for new users
**Likelihood**: High
**Severity**: **MEDIUM**

**Mitigation**:
- Automated installation script handles Ollama
- Docker Compose for one-command setup
- Clear, step-by-step documentation
- Video tutorial

**Docker Compose Example**:
```yaml
version: '3.8'

services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama_models:/root/.ollama
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:11434/api/tags"]
      interval: 30s
      timeout: 10s
      retries: 3

  tmws:
    build: .
    depends_on:
      ollama:
        condition: service_healthy
    environment:
      - TMWS_OLLAMA_BASE_URL=http://ollama:11434
      - TMWS_VECTOR_DIMENSION=1024
    ports:
      - "8000:8000"

volumes:
  ollama_models:
```

---

## Success Criteria

### Technical Criteria

✅ **Code Quality**
- [ ] All SentenceTransformers references removed
- [ ] No provider selection logic remaining
- [ ] Strict 1024-dim validation in place
- [ ] Comprehensive error messages for Ollama failures

✅ **Testing**
- [ ] 100% test pass rate with Ollama-only
- [ ] Dimension validation tests passing
- [ ] Integration tests with Ollama mock
- [ ] Performance benchmarks meet targets

✅ **Documentation**
- [ ] All docs updated (no stale ST references)
- [ ] Migration guide complete and tested
- [ ] Ollama installation guide for all platforms
- [ ] Troubleshooting section comprehensive

### Operational Criteria

✅ **Deployment**
- [ ] Ollama automatically installed by scripts
- [ ] Systemd/launchd service configured
- [ ] Docker Compose setup tested
- [ ] CI/CD pipeline includes Ollama

✅ **Monitoring**
- [ ] Ollama health check in place
- [ ] Embedding dimension tracked
- [ ] Alerts configured for downtime

✅ **User Experience**
- [ ] Clear error messages for Ollama issues
- [ ] One-command installation works
- [ ] Migration script tested on real data
- [ ] Documentation feedback incorporated

---

## Conclusion

### Overall Assessment: Architecturally Sound with Manageable Risks

The migration to Ollama-only architecture represents a **strategic simplification** that:

**✅ Benefits:**
- Eliminates dimension mismatch complexity
- Reduces Python dependency footprint by 60%
- Simplifies codebase (remove dual-provider logic)
- Maintains Windows compatibility
- Improves long-term maintainability

**⚠️ Challenges:**
- Ollama becomes critical infrastructure dependency
- Increased deployment complexity (Ollama setup)
- Migration effort for existing deployments
- User training on new prerequisites

**🎯 Recommendation: Proceed with Staged Rollout**

1. **Phase 1**: Release as v2.3.0-beta with migration guide
2. **Phase 2**: Gather feedback, refine documentation
3. **Phase 3**: Full v2.3.0 release with automated migration tools

**📊 Estimated Timeline:**
- Development: 12-16 hours
- Testing & QA: 6-8 hours
- Documentation: 4-6 hours
- **Total**: 3-4 business days

**🔑 Critical Success Factor:**
Comprehensive Ollama installation documentation and automated setup scripts will determine user adoption success.

---

*Analysis conducted by Athena (Harmonious Conductor)*
*ふふ、調和的な分析が完了しました。すべてのペルソナの専門知識を統合し、最適な移行計画を策定しました♪*

🏛️ **Trinitas TMWS v2.3.0 - Unified Intelligence, Simplified Architecture**
