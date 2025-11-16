# Wave 3 Content Implementation Plan
## Phase 2D Docker Deployment Documentation - Content Writing

**Created**: 2025-11-16
**Status**: Ready for Wave 3 Execution
**Estimated Time**: 90-120 minutes (Artemis + Hestia collaboration)
**Wave 1 Completion**: 100% (Structure design complete)

---

## Overview

Wave 1 (Muses) created comprehensive **documentation structure outlines**.
Wave 3 (Artemis + Hestia) will **fill in detailed content** for placeholder sections.

**What's Already Complete** (Wave 1):
- ✅ Full document structure with all sections and subsections
- ✅ Table of contents for all documents
- ✅ Navigation strategy and cross-references
- ✅ Platform-specific section frameworks
- ✅ Troubleshooting section outlines
- ✅ Example command templates
- ✅ Verification checklist structures

**What Needs Content** (Wave 3):
- 📝 Docker configuration files (docker-compose.yml, Dockerfile.prod)
- 📝 Complete .env.example with all variables
- 📝 Platform-specific wrapper scripts (full implementations)
- 📝 Detailed troubleshooting diagnostics
- 📝 Performance benchmarking scripts
- 📝 Security hardening configurations

---

## Document Status Matrix

| Document | Structure | Placeholder Content | Production-Ready Content | Status |
|----------|-----------|---------------------|--------------------------|--------|
| **DOCKER_DEPLOYMENT.md** | ✅ 100% | ✅ 80% | 📝 20% | Wave 3 needed |
| **MCP_CONNECTION_DOCKER.md** | ✅ 100% | ✅ 85% | 📝 15% | Wave 3 needed |
| **README.md** | ✅ 100% | ✅ 100% | ✅ 100% | **Complete** ✅ |
| **DOCUMENTATION_STRATEGY.md** | ✅ 100% | ✅ 100% | ✅ 100% | **Complete** ✅ |

---

## Wave 3 Task Breakdown

### Task 1: Docker Configuration Files (Artemis - 30 min)

**Files to Create**:

#### 1.1 docker-compose.yml (Mac Hybrid)
**Location**: Project root (`/Users/apto-as/workspace/github.com/apto-as/tmws/docker-compose.yml`)

**Content Requirements**:
```yaml
# TMWS v2.3.1 Docker Compose Configuration
# Deployment Mode: Mac Hybrid (Ollama native + TMWS Docker)

version: '3.9'

services:
  tmws-app:
    # [Artemis to specify:]
    # - image: tmws:v2.3.1 (or build context)
    # - platform: linux/arm64 (Mac M-series)
    # - container_name: tmws-app
    # - environment variables (reference .env)
    # - volumes: ./data:/app/data (persistence)
    # - ports: 8000:8000 (MCP server)
    # - healthcheck: curl http://localhost:8000/health
    # - restart: unless-stopped
    # - depends_on: (if applicable)

# [Artemis to add:]
# - networks: (if needed)
# - volumes: (if named volumes)
```

**Deliverables**:
- Complete `docker-compose.yml` (Mac Hybrid mode)
- Complete `docker-compose.linux.yml` (Linux-specific, bridge network)
- Complete `docker-compose.full.yml` (Full Docker mode with Ollama container)

**Testing Required**:
- [ ] Verify on Mac M1/M2/M3/M4 (Metal GPU access)
- [ ] Verify health check passes within 30 seconds
- [ ] Verify Ollama connection (host.docker.internal:11434)

---

#### 1.2 Dockerfile.prod
**Location**: Project root

**Content Requirements**:
```dockerfile
# TMWS v2.3.1 Production Dockerfile
# Multi-stage build for optimized image size

# [Artemis to specify:]
# - Base image: python:3.11-slim (or alpine)
# - Build stage: Install uv, build .whl package
# - Runtime stage: Copy .whl, install dependencies
# - Security: Non-root user, minimal attack surface
# - Metadata: LABEL with version, maintainer
# - Entrypoint: tmws command
```

**Deliverables**:
- Complete `Dockerfile.prod` (production-optimized)
- Optional: `Dockerfile.dev` (development mode with hot reload)

**Testing Required**:
- [ ] Build succeeds: `docker build -t tmws:v2.3.1-prod -f Dockerfile.prod .`
- [ ] Image size < 500MB (target: 300-400MB)
- [ ] Container runs as non-root user
- [ ] Health check endpoint accessible

---

#### 1.3 .env.example
**Location**: Project root

**Content Requirements**:
```bash
# TMWS v2.3.1 Environment Configuration
# Copy to .env and customize

# [Artemis to document ALL variables:]

# ============================================
# CRITICAL VARIABLES (MUST be set)
# ============================================
TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"
TMWS_SECRET_KEY="<GENERATE_WITH_openssl_rand_hex_32>"
TMWS_ENVIRONMENT="production"  # Options: development, staging, production

# ============================================
# OLLAMA CONFIGURATION
# ============================================
OLLAMA_BASE_URL="http://host.docker.internal:11434"  # Mac/Windows Hybrid
# OLLAMA_BASE_URL="http://172.17.0.1:11434"  # Linux Hybrid (Docker bridge)
# OLLAMA_BASE_URL="http://ollama:11434"  # Full Docker mode

# ============================================
# MCP SERVER
# ============================================
TMWS_MCP_HOST="0.0.0.0"
TMWS_MCP_PORT="8000"

# ============================================
# AGENT CONFIGURATION
# ============================================
TMWS_AGENT_ID="docker-instance-1"  # Auto-generated if not set
TMWS_AGENT_NAMESPACE="default"

# ============================================
# SECURITY
# ============================================
TMWS_AUTH_ENABLED="false"  # Set "true" for production
TMWS_CORS_ORIGINS='["*"]'  # Production: '["https://app.example.com"]'

# [Artemis to add ALL remaining variables with descriptions]
```

**Deliverables**:
- Complete `.env.example` with 30-40 variables documented
- Inline comments explaining each variable
- Platform-specific alternatives (Mac/Win/Linux)
- Security warnings for sensitive variables

---

### Task 2: Wrapper Scripts (Artemis - 20 min)

**Files to Create**:

#### 2.1 tmws-mcp-docker.sh (Mac/Linux)
**Location**: `scripts/mcp/tmws-mcp-docker.sh`

**Content Requirements**:
```bash
#!/bin/bash
# TMWS MCP Docker Wrapper Script
# Version: 2.3.1
# Platform: Mac/Linux
# Purpose: Bridge Claude Desktop stdio to Docker container

# [Artemis to implement:]
# - Strict error handling (set -euo pipefail)
# - Container existence check
# - Container running check (docker ps)
# - Health check before exec (optional: curl health endpoint)
# - Graceful error messages
# - Logging to syslog or file (optional)
# - Exit codes (0=success, 1=container not running, 2=health check failed)
```

**Deliverables**:
- Complete `tmws-mcp-docker.sh` with robust error handling
- Optional: `tmws-mcp-docker-debug.sh` (verbose logging for troubleshooting)

**Testing Required**:
- [ ] Container not running → Clear error message
- [ ] Container running → Successfully launches MCP server
- [ ] Stdin/stdout forwarding works (test with echo command)

---

#### 2.2 tmws-mcp-docker.bat (Windows)
**Location**: `scripts/mcp/tmws-mcp-docker.bat`

**Content Requirements**:
```batch
@echo off
REM TMWS MCP Docker Wrapper Script
REM Version: 2.3.1
REM Platform: Windows 10/11
REM Purpose: Bridge Claude Desktop stdio to Docker container

REM [Artemis to implement:]
REM - Container existence check
REM - Container running check (docker ps)
REM - Error level handling
REM - Graceful error messages
REM - Exit codes
```

**Deliverables**:
- Complete `tmws-mcp-docker.bat`
- Optional: `tmws-mcp-docker-debug.bat`

**Testing Required**:
- [ ] WSL2 compatibility verified
- [ ] Error messages display correctly in PowerShell
- [ ] Paths with spaces handled correctly

---

### Task 3: Security Configurations (Hestia - 20 min)

**Files to Create**:

#### 3.1 Nginx Reverse Proxy Configuration
**Location**: `docs/deployment/examples/nginx-tmws.conf`

**Content Requirements**:
```nginx
# TMWS Nginx Reverse Proxy Configuration
# Version: 2.3.1
# Purpose: HTTPS termination for TMWS Docker deployment

# [Hestia to specify:]
# - SSL certificate paths (Let's Encrypt)
# - HTTPS-only redirect (HTTP → HTTPS)
# - Security headers (HSTS, CSP, X-Frame-Options)
# - Rate limiting (limit_req_zone)
# - Proxy settings (proxy_pass, timeout, buffering)
# - Logging (access_log, error_log)
```

**Deliverables**:
- Complete `nginx-tmws.conf` with security best practices
- Comments explaining each security header

**Testing Required**:
- [ ] SSL Labs grade A+ (if deployed with real certificate)
- [ ] Security headers verified (securityheaders.com)

---

#### 3.2 Traefik Configuration (Docker-native HTTPS)
**Location**: `docs/deployment/examples/traefik-tmws.yml`

**Content Requirements**:
```yaml
# TMWS Traefik Configuration
# Version: 2.3.1
# Purpose: HTTPS with automatic Let's Encrypt certificate

# [Hestia to specify:]
# - Traefik v2+ configuration
# - Let's Encrypt integration (HTTP-01 or DNS-01 challenge)
# - Middleware: HTTPS redirect, security headers
# - Docker provider configuration
# - Dashboard security (if enabled)
```

**Deliverables**:
- Complete `traefik-tmws.yml`
- Integration with `docker-compose.yml` (labels)

---

#### 3.3 Security Hardening Checklist
**Location**: `docs/deployment/SECURITY_HARDENING_CHECKLIST.md`

**Content Requirements** (Hestia to write):
- [ ] Network security (firewall rules, port restrictions)
- [ ] Container security (non-root user, read-only filesystem)
- [ ] Secrets management (Docker secrets, Vault integration)
- [ ] HTTPS enforcement (certificate management, renewal)
- [ ] Audit logging (security events, access logs)
- [ ] Vulnerability scanning (Trivy, Clair)
- [ ] Compliance (SOC2, GDPR considerations)

**Format**: Checkbox-based checklist with verification commands

---

### Task 4: Performance & Monitoring (Artemis - 20 min)

**Files to Create**:

#### 4.1 Performance Benchmarking Script
**Location**: `scripts/benchmark/docker_performance_test.py`

**Content Requirements**:
```python
#!/usr/bin/env python3
# TMWS Docker Performance Benchmark
# Version: 2.3.1

# [Artemis to implement:]
# - Memory creation benchmark (1000 operations)
# - Semantic search benchmark (100 queries)
# - Vector embedding benchmark (Ollama latency)
# - P50, P95, P99 latency calculations
# - Comparison: Docker vs Native (if native installation exists)
# - Output: JSON report with metrics
```

**Deliverables**:
- Complete `docker_performance_test.py`
- Example output JSON

**Testing Required**:
- [ ] Benchmark runs successfully on Mac Hybrid
- [ ] Benchmark runs successfully on Linux Hybrid
- [ ] Results match expected latency targets (see DOCKER_DEPLOYMENT.md Section "Performance Benchmarks")

---

#### 4.2 Health Check Script
**Location**: `scripts/health/docker_health_check.sh`

**Content Requirements**:
```bash
#!/bin/bash
# TMWS Docker Health Check
# Version: 2.3.1

# [Artemis to implement:]
# - Container status check (running? healthy?)
# - API health endpoint check (HTTP 200?)
# - Ollama connection check (embeddings working?)
# - Database accessible (SQLite file exists and writable?)
# - ChromaDB accessible (collection exists?)
# - Exit codes: 0=healthy, 1=unhealthy, 2=degraded
```

**Deliverables**:
- Complete `docker_health_check.sh`
- Cron job example for periodic monitoring

**Testing Required**:
- [ ] Reports healthy when all services running
- [ ] Reports unhealthy when container stopped
- [ ] Reports degraded when Ollama unreachable

---

### Task 5: Migration & Upgrade Scripts (Artemis - 15 min)

**Files to Create**:

#### 5.1 Native → Docker Migration Script
**Location**: `scripts/migration/native_to_docker.sh`

**Content Requirements**:
```bash
#!/bin/bash
# Migrate TMWS from Native Installation to Docker
# Version: 2.3.1

# [Artemis to implement:]
# - Backup existing data (SQLite, ChromaDB)
# - Export .env variables
# - Copy data to Docker volume mount (./data/)
# - Validate data integrity (checksum)
# - Start Docker container
# - Verify migration success
```

**Deliverables**:
- Complete `native_to_docker.sh`
- Rollback instructions (if migration fails)

---

#### 5.2 Docker Image Update Script
**Location**: `scripts/upgrade/update_docker_image.sh`

**Content Requirements**:
```bash
#!/bin/bash
# Update TMWS Docker Image to Latest Version
# Version: 2.3.1

# [Artemis to implement:]
# - Backup current data
# - Pull new Docker image
# - Stop current container
# - Start new container with new image
# - Verify health check
# - Rollback on failure (restore previous image)
```

**Deliverables**:
- Complete `update_docker_image.sh`
- Safety features (data backup, rollback)

---

### Task 6: Troubleshooting Diagnostics (Hestia - 15 min)

**Files to Create**:

#### 6.1 Diagnostic Collection Script
**Location**: `scripts/troubleshooting/collect_diagnostics.sh`

**Content Requirements**:
```bash
#!/bin/bash
# TMWS Docker Troubleshooting Diagnostic Collection
# Version: 2.3.1

# [Hestia to implement:]
# - System information (OS, Docker version, resources)
# - Container status (docker ps, docker inspect)
# - Container logs (last 500 lines)
# - Ollama connectivity test
# - Database integrity check
# - ChromaDB status
# - .env validation (check for common misconfigurations)
# - Output: timestamped tarball (diagnostics_YYYYMMDD_HHMMSS.tar.gz)
```

**Deliverables**:
- Complete `collect_diagnostics.sh`
- Example output (sanitized, no secrets)

**Use Case**: "Run this script and attach output to GitHub issue"

---

## Content Placeholders to Fill

### DOCKER_DEPLOYMENT.md Sections Needing Content

**Section 4.1-4.3: Deployment Modes**
- [ ] Complete `docker-compose.yml` examples for each mode
- [ ] Platform-specific configuration notes
- [ ] Network configuration details (bridge IP, host.docker.internal)

**Section 5.1: Environment Variables Reference**
- [ ] Complete `.env.example` content (copied from Task 1.3)
- [ ] Inline in documentation with descriptions

**Section 6.2: Production Deployment Steps**
- [ ] Step 4 details (Docker Image Build)
- [ ] Step 7 details (Initial Data Setup - agent registration script)

**Section 7.2: HTTPS Configuration**
- [ ] Complete Nginx configuration (from Task 3.1)
- [ ] Complete Traefik configuration (from Task 3.2)

**Section 8: Troubleshooting**
- [ ] Diagnostic commands for each issue
- [ ] Expected vs actual output examples
- [ ] Logs interpretation guide

---

### MCP_CONNECTION_DOCKER.md Sections Needing Content

**Section 3.3: Step 2: Create Wrapper Script**
- [ ] Complete Mac/Linux wrapper script (from Task 2.1)
- [ ] Complete Windows wrapper script (from Task 2.2)

**Section 5: Verification**
- [ ] Step 3 exact test commands and expected responses

**Section 7: Troubleshooting**
- [ ] Diagnostic script output examples
- [ ] Platform-specific quirks (M4 Mac, WSL2 Windows, SELinux Linux)

---

## Trinitas Collaboration Pattern for Wave 3

### Recommended Execution Order

**Phase 1: Artemis Solo** (60 min)
1. Docker configuration files (Task 1: 30 min)
2. Wrapper scripts (Task 2: 20 min)
3. Performance benchmarking (Task 4: 10 min)

**Phase 2: Hestia Solo** (30 min)
1. Security configurations (Task 3: 20 min)
2. Troubleshooting diagnostics (Task 6: 10 min)

**Phase 3: Artemis + Hestia Collaboration** (30 min)
1. Artemis: Migration scripts (Task 5: 15 min)
2. Hestia: Security review of all scripts (10 min)
3. Both: Fill documentation placeholders (5 min)

**Total Estimated Time**: 120 minutes (2 hours)

**Parallel Optimization**: If Artemis and Hestia work simultaneously, total time reduces to **90 minutes**.

---

## Testing & Validation Checklist

### Before Declaring Wave 3 Complete

**Functionality Tests**:
- [ ] Mac Hybrid deployment works end-to-end (30-second Quick Start)
- [ ] Windows Hybrid deployment works (5-minute setup)
- [ ] Linux Hybrid deployment works
- [ ] Full Docker deployment works
- [ ] MCP connection works on all platforms
- [ ] Wrapper scripts execute without errors
- [ ] Health checks pass
- [ ] Performance benchmarks meet targets

**Documentation Tests**:
- [ ] All placeholder content filled (no `[Wave 3: ...]` markers)
- [ ] All code blocks tested and verified
- [ ] All cross-references valid (no broken links)
- [ ] Platform-specific sections complete
- [ ] Troubleshooting covers all common issues

**Security Tests**:
- [ ] Nginx/Traefik configurations reviewed by Hestia
- [ ] No secrets in example files
- [ ] Container runs as non-root user
- [ ] Security headers validated

---

## Success Criteria

**Wave 3 is complete when**:

1. ✅ **All 6 tasks completed**
   - Docker configs, wrapper scripts, security, performance, migration, diagnostics

2. ✅ **All placeholders filled**
   - No `[Wave 3: Artemis will provide...]` markers in DOCKER_DEPLOYMENT.md or MCP_CONNECTION_DOCKER.md

3. ✅ **End-to-end deployment verified**
   - At least one platform (Mac Hybrid) tested from scratch to working MCP connection

4. ✅ **Documentation quality standard met**
   - All code blocks executable
   - All verification steps have expected outputs
   - All troubleshooting sections have diagnostic commands

5. ✅ **Hestia security sign-off**
   - Security configurations reviewed
   - No vulnerabilities introduced by example configurations

---

## Post-Wave 3: Wave 4 (Optional - Muses)

**If additional refinement needed** (estimated 30 min):

- [ ] Add missing diagrams (architecture diagrams for each deployment mode)
- [ ] Create video walkthrough scripts
- [ ] Polish language (consistency, tone)
- [ ] Add FAQ section (frequently asked questions from testing)

**Wave 4 is optional** - Wave 3 completion means documentation is production-ready.

---

## Appendix: File Inventory

### New Files to Create (Wave 3)

**Docker Configurations**:
1. `docker-compose.yml` (Mac Hybrid)
2. `docker-compose.linux.yml` (Linux-specific)
3. `docker-compose.full.yml` (Full Docker mode)
4. `Dockerfile.prod` (production-optimized)
5. `.env.example` (complete with 30-40 variables)

**Scripts**:
6. `scripts/mcp/tmws-mcp-docker.sh` (Mac/Linux wrapper)
7. `scripts/mcp/tmws-mcp-docker.bat` (Windows wrapper)
8. `scripts/benchmark/docker_performance_test.py` (performance benchmarking)
9. `scripts/health/docker_health_check.sh` (health monitoring)
10. `scripts/migration/native_to_docker.sh` (migration script)
11. `scripts/upgrade/update_docker_image.sh` (upgrade script)
12. `scripts/troubleshooting/collect_diagnostics.sh` (diagnostic collection)

**Documentation Examples**:
13. `docs/deployment/examples/nginx-tmws.conf` (Nginx config)
14. `docs/deployment/examples/traefik-tmws.yml` (Traefik config)

**Total**: 14 new files

---

## Conclusion

Wave 1 (Muses) has established a **comprehensive documentation structure** with clear navigation, progressive disclosure, and user-centric organization.

Wave 3 (Artemis + Hestia) will **execute the technical implementation**, filling in Docker configurations, security hardening, performance benchmarking, and troubleshooting diagnostics.

**Estimated Wave 3 Duration**: 90-120 minutes
**Expected Outcome**: Production-ready Docker deployment documentation enabling users to deploy TMWS in 30 seconds (Quick Start) or 2 hours (full production deployment).

---

**Document**: WAVE_3_CONTENT_PLAN.md
**Created**: 2025-11-16
**Purpose**: Guide Artemis + Hestia through Wave 3 content implementation
**Status**: Ready for Execution ✅
