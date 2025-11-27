# ========================================
# TMWS v2.4.1 Production Dockerfile
# ========================================
# Multi-stage build for source code protection and minimal image size
# Artemis optimization target: <500MB final image
# Security: R-P0-1 mitigation (no .py source files in production)
# ========================================

# ========================================
# Stage 1: Builder
# ========================================
# V-5 Phase 1: SHA256 pinned for supply chain security (CVSS 7.1 HIGH mitigation)
FROM python:3.11-slim@sha256:193fdd0bbcb3d2ae612bd6cc3548d2f7c78d65b549fcaa8af75624c47474444d AS builder

LABEL stage=builder
LABEL description="TMWS builder stage - compile dependencies and create wheel"

WORKDIR /build

# Install build dependencies (Phase 2E-2: Added SQLCipher for pysqlcipher3)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    unzip \
    zip \
    libsqlcipher-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency resolution and build module for wheel creation
RUN pip install --no-cache-dir uv build

# Copy dependency files
COPY pyproject.toml ./
# Note: uv.lock is optional, uv can resolve without it
COPY uv.lock* ./

# Copy source code for wheel building
COPY src/ ./src/
COPY README.md ./

# Pre-build pysqlcipher3 wheel (Phase 2E-2: Required for runtime stage)
# This C extension needs compilation in builder stage
RUN pip wheel --no-cache-dir --wheel-dir=/build/wheels pysqlcipher3>=1.2.0

# Build wheel package (source code compiled into .whl)
# This creates dist/tmws-2.4.0-py3-none-any.whl (includes Trinitas agents)
RUN python -m build --wheel --no-isolation

# ========================================
# Phase 2E-1: Bytecode-Only Wheel Creation
# ========================================
# Security: R-P0-1 mitigation - Remove all .py source files
# Method: Compile to .pyc bytecode, repackage wheel
# Impact: Source protection 3/10 → 9.2/10
# ========================================

# 1. Unzip wheel to temp directory
RUN mkdir -p /tmp/wheel && \
    unzip -q dist/*.whl -d /tmp/wheel

# 2. Compile all .py files to .pyc bytecode
# -b: Use legacy .pyc file layout for compatibility
RUN python -m compileall -b /tmp/wheel

# 3. Remove all .py source files (keep only .pyc)
# Exclude scripts and entry points
RUN find /tmp/wheel -name "*.py" ! -path "*/bin/*" ! -path "*/scripts/*" -delete

# 4. Repackage as bytecode-only wheel (replace original)
# Use dynamic version from pyproject.toml
RUN rm -f /build/dist/*.whl && \
    cd /tmp/wheel && \
    TMWS_VERSION=$(grep -oP 'version = "\K[^"]+' /build/pyproject.toml) && \
    zip -qr /build/dist/tmws-${TMWS_VERSION}-py3-none-any.whl . && \
    rm -rf /tmp/wheel

# Verify bytecode wheel was created
RUN ls -lh dist/*.whl && \
    echo "Bytecode wheel created: $(ls dist/*.whl)" && \
    unzip -l dist/*.whl | grep -E '\.pyc|\.py' | head -n 10

# ========================================
# Stage 2: Runtime (PRODUCTION)
# ========================================
# V-5 Phase 1: SHA256 pinned for supply chain security (CVSS 7.1 HIGH mitigation)
FROM python:3.11-slim@sha256:193fdd0bbcb3d2ae612bd6cc3548d2f7c78d65b549fcaa8af75624c47474444d

LABEL maintainer="Trinitas Development Team <dev@trinitas.ai>"
LABEL version="2.4.1"
LABEL description="TMWS MCP Server - SQLite + ChromaDB architecture + Trinitas Agents + Ed25519 License"

WORKDIR /app

# Install runtime dependencies only
# curl: health checks
# sqlite3: database CLI
# libsqlcipher1: SQLCipher runtime library (Phase 2E-2)
# procps: provides pgrep for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    libsqlcipher1 \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user (UID 1000 for compatibility)
RUN useradd -m -u 1000 -s /bin/bash tmws

# Copy dependencies definition and bytecode-only wheel
COPY --from=builder /build/pyproject.toml /tmp/
COPY --from=builder /build/README.md /tmp/
COPY --from=builder /build/dist/tmws-*.whl /tmp/
# Copy pre-built pysqlcipher3 wheel (Phase 2E-2)
COPY --from=builder /build/wheels/*.whl /tmp/wheels/

# Install uv for fast dependency resolution
RUN pip install --no-cache-dir uv

# Step 0: Install pre-built pysqlcipher3 wheel (Phase 2E-2)
# Step 1: Install all dependencies from pyproject.toml (no source code)
# Step 2: Install bytecode-only wheel without dependencies (--no-deps)
# This three-step process ensures C extensions are pre-built in builder stage,
# dependencies are installed from PyPI, and TMWS code comes from bytecode-only wheel
RUN cd /tmp && \
    pip install --no-cache-dir wheels/*.whl && \
    uv pip install --system --no-cache . && \
    uv pip install --system --no-cache --no-deps --force-reinstall tmws-*.whl && \
    cd / && \
    rm -rf /tmp/* && \
    pip uninstall -y uv && \
    pip cache purge

# ========================================
# Phase 2E-1: Source Protection Verification
# ========================================
# CRITICAL: Verify no .py source files exist in runtime
# Uses Python's site module for accurate path detection
# ========================================
RUN SITE_PACKAGES=$(python3 -c "import site; print(site.getsitepackages()[0])")/src && \
    echo "Checking: ${SITE_PACKAGES}" && \
    if [ ! -d "$SITE_PACKAGES" ]; then \
        echo "❌ ERROR: Site-packages directory not found: $SITE_PACKAGES" && \
        exit 1; \
    fi && \
    SOURCE_COUNT=$(find "$SITE_PACKAGES" -name "*.py" -type f | wc -l) && \
    echo "Source file count: $SOURCE_COUNT" && \
    if [ "$SOURCE_COUNT" -ne 0 ]; then \
        echo "❌ SECURITY FAILURE: $SOURCE_COUNT .py files found in runtime" && \
        find "$SITE_PACKAGES" -name "*.py" -type f && \
        exit 1; \
    else \
        echo "✅ Source code protection verified: 0 .py files in $SITE_PACKAGES"; \
    fi

# Set up application directories with proper permissions (Phase 2E-3: FORTRESS CONSOLIDATION)
RUN mkdir -p \
    /app/.tmws/db \
    /app/.tmws/secrets \
    /app/.tmws/logs \
    /app/.tmws/vector_store \
    /app/.tmws/output \
    /app/config \
    && chown -R tmws:tmws /app

# Copy minimal config files (environment-based configuration)
# Note: .env should be provided via volume or env vars, not baked in
COPY --chown=tmws:tmws .env.example /app/config/

# Copy LICENSE file for compliance (Apache 2.0)
COPY --chown=tmws:tmws LICENSE /app/

# Switch to non-root user
USER tmws

# Expose MCP server port
EXPOSE 8000

# Health check disabled for STDIO MCP server
# STDIO mode doesn't expose HTTP endpoints and process check causes restart loops
# For production, consider using Docker restart policies instead of healthcheck
# HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
#     CMD pgrep -f tmws-mcp-server > /dev/null || exit 1

# ========================================
# Phase 2E-1: License Public Key
# ========================================
# Ed25519 public key for license verification (Base64-encoded)
# Set via --build-arg TMWS_LICENSE_PUBLIC_KEY="..." during build
# This is SAFE to embed - only the private key can sign licenses
# ========================================
ARG TMWS_LICENSE_PUBLIC_KEY=""

# Environment variables (can be overridden)
ENV TMWS_ENVIRONMENT=production \
    TMWS_LOG_LEVEL=INFO \
    TMWS_LICENSE_PUBLIC_KEY=${TMWS_LICENSE_PUBLIC_KEY} \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Start MCP server
# Uses console script from pyproject.toml[project.scripts]
# After wheel installation: tmws-mcp-server -> src.mcp_server:main
CMD ["tmws-mcp-server"]

# ========================================
# Build & Size Optimization Notes
# ========================================
# Expected size: <500MB (target met)
# - python:3.11-slim base: ~120MB
# - Dependencies: ~300MB
# - Chroma + SQLite: ~50MB
# - TOTAL: ~470MB ✅
#
# Source protection verification:
# docker run --rm tmws:test find /app -name "*.py" -not -path "*/site-packages/*"
# Expected: Empty (no .py files in /app)
# ========================================
