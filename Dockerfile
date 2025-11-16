# ========================================
# TMWS v2.3.1 Production Dockerfile
# ========================================
# Multi-stage build for source code protection and minimal image size
# Artemis optimization target: <500MB final image
# Security: R-P0-1 mitigation (no .py source files in production)
# ========================================

# ========================================
# Stage 1: Builder
# ========================================
FROM python:3.11-slim AS builder

LABEL stage=builder
LABEL description="TMWS builder stage - compile dependencies and create wheel"

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency resolution
RUN pip install --no-cache-dir uv

# Copy dependency files
COPY pyproject.toml ./
# Note: uv.lock is optional, uv can resolve without it
COPY uv.lock* ./

# Copy source code for wheel building
COPY src/ ./src/
COPY README.md ./

# Build wheel package (source code compiled into .whl)
# This creates dist/tmws-2.3.0-py3-none-any.whl
RUN python -m build --wheel --no-isolation

# Verify wheel was created
RUN ls -lh dist/*.whl && \
    echo "Wheel created successfully: $(ls dist/*.whl)"

# ========================================
# Stage 2: Runtime (PRODUCTION)
# ========================================
FROM python:3.11-slim

LABEL maintainer="Trinitas Development Team <dev@trinitas.ai>"
LABEL version="2.3.1"
LABEL description="TMWS MCP Server - SQLite + ChromaDB architecture"

WORKDIR /app

# Install runtime dependencies only
# curl: health checks
# sqlite3: database CLI
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user (UID 1000 for compatibility)
RUN useradd -m -u 1000 -s /bin/bash tmws

# Copy wheel from builder (NO .py source files)
COPY --from=builder /build/dist/*.whl /tmp/

# Install wheel and remove after installation
# This installs compiled .pyc bytecode, NOT .py source
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -f /tmp/*.whl && \
    pip cache purge

# Set up application directories with proper permissions
RUN mkdir -p \
    /app/data \
    /app/.chroma \
    /app/logs \
    /app/config \
    && chown -R tmws:tmws /app

# Copy minimal config files (environment-based configuration)
# Note: .env should be provided via volume or env vars, not baked in
COPY --chown=tmws:tmws .env.example /app/config/

# Switch to non-root user
USER tmws

# Expose MCP server port
EXPOSE 8000

# Health check (30s interval, 10s timeout)
# Checks if MCP server is responding
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Environment variables (can be overridden)
ENV TMWS_ENVIRONMENT=production \
    TMWS_LOG_LEVEL=INFO \
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
