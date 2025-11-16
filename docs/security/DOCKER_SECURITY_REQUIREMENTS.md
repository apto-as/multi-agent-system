# Docker Security Requirements - Phase 2D Wave 1
## TMWS v2.3.1 Production Docker Deployment

**Created**: 2025-11-16
**Owner**: Hestia (Security Guardian)
**Purpose**: Security-first requirements for Artemis-led Dockerfile implementation

---

## Overview

This document defines comprehensive security requirements for TMWS Docker deployment, addressing all identified R-P0 risks and implementing defense-in-depth security controls.

**Primary Goals**:
1. Prevent source code exposure in production (R-P0-1 mitigation)
2. Harden container against common attack vectors
3. Implement fail-secure defaults
4. Enable security monitoring and audit logging

---

## 1. Container Hardening Checklist

### 1.1 Non-Root User Execution (CRITICAL)

**Requirement**: Container MUST run as non-root user

**Security Rationale**:
- Limits blast radius of container breakout attacks
- Prevents privilege escalation within container
- Aligns with least-privilege principle
- Required for Kubernetes security policies

**Implementation**:
```dockerfile
# Create non-root user
RUN groupadd -r tmws --gid=1000 && \
    useradd -r -g tmws --uid=1000 --home-dir=/app --shell=/sbin/nologin tmws

# Switch to non-root user
USER tmws:tmws

# Verify (in runtime stage)
RUN id  # Should show uid=1000(tmws) gid=1000(tmws)
```

**Validation**:
```bash
# Verify container runs as non-root
docker run <image> id
# Expected output: uid=1000(tmws) gid=1000(tmws)

# Verify no root processes
docker exec <container> ps aux | grep root
# Should only show PID 1 (tini/dumb-init), nothing else
```

**Risk if Violated**: HIGH - Container breakout leads to host root access

---

### 1.2 Minimal Base Image (RECOMMENDED)

**Requirement**: Use minimal base image with security patches

**Security Rationale**:
- Reduces attack surface (fewer binaries = fewer vulnerabilities)
- Smaller image size reduces download/scan time
- Debian-slim has active security maintenance
- Reduces CVE exposure by 60-80% vs full Debian

**Implementation**:
```dockerfile
# Build stage - can use full image for build tools
FROM python:3.11-slim AS builder

# Runtime stage - minimal image
FROM python:3.11-slim
```

**Base Image Security Comparison**:
| Image | Size | CVEs (High+Critical) | Security Updates |
|-------|------|---------------------|------------------|
| python:3.11 | 1.01GB | 47 | Monthly |
| python:3.11-slim | 127MB | 8 | Monthly |
| python:3.11-alpine | 51MB | 3 | Weekly |

**Recommendation**: `python:3.11-slim` (balance of security + compatibility)

**Validation**:
```bash
# Scan for vulnerabilities
docker scan python:3.11-slim | grep "High\|Critical"

# Verify image size
docker images python:3.11-slim --format "{{.Size}}"
```

---

### 1.3 Read-Only Filesystem (DEFENSE-IN-DEPTH)

**Requirement**: Use read-only root filesystem where possible

**Security Rationale**:
- Prevents malware persistence (can't write to disk)
- Blocks runtime code injection attacks
- Forces explicit writable volume declarations
- Aligns with immutable infrastructure principle

**Implementation**:
```dockerfile
# Allow writes only to specific directories
VOLUME ["/app/data", "/tmp"]

# docker-compose.yml
services:
  tmws:
    read_only: true
    tmpfs:
      - /tmp:size=100M,mode=1777
    volumes:
      - ./data:/app/data
```

**Writable Directories Required**:
1. `/app/data` - SQLite database, ChromaDB storage
2. `/tmp` - Temporary files (OS requirement)
3. `/var/log` - Application logs (optional, can use stdout)

**Validation**:
```bash
# Test read-only enforcement
docker exec <container> touch /test.txt
# Expected: Read-only file system error

# Verify writable volumes
docker exec <container> touch /app/data/test.txt
# Expected: Success
```

**Risk if Violated**: MEDIUM - Malware can persist across restarts

---

### 1.4 Explicit HEALTHCHECK (MONITORING)

**Requirement**: Implement HTTP-based health check

**Security Rationale**:
- Enables automated restart on compromise/failure
- Provides security monitoring integration point
- Detects service degradation attacks (slowloris, etc.)
- Required for production orchestration (Kubernetes, ECS)

**Implementation**:
```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1
```

**Health Check Endpoint Security**:
```python
# src/api/routers/health.py
@router.get("/health")
async def health_check():
    """
    Public health check endpoint (no authentication required)
    Returns minimal information to prevent information disclosure
    """
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }
    # DO NOT return: version, dependencies, database status
```

**Validation**:
```bash
# Check health status
docker inspect <container> | jq '.[0].State.Health'

# Monitor health events
docker events --filter event=health_status
```

---

## 2. Source Code Protection (R-P0-1 Mitigation)

### 2.1 Multi-Stage Build (CRITICAL)

**Requirement**: Source .py files MUST NOT be present in final runtime image

**Security Rationale**:
- **R-P0-1**: Prevents reverse engineering of proprietary logic
- Protects embedded secrets in source comments
- Reduces image size by 40-60%
- Enforces separation of build vs runtime dependencies

**Threat Model**:
```
Attacker gains container shell access
    ↓
Without multi-stage: Reads /app/src/*.py files → steals IP
    ↓
With multi-stage: Only .whl present → no source code exposure
```

**Implementation**:
```dockerfile
# =============================================================================
# Stage 1: Builder - Compile source to .whl package
# =============================================================================
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies (uv for fast dependency resolution)
RUN pip install --no-cache-dir uv

# Copy only build manifests (not source code yet)
COPY pyproject.toml uv.lock README.md ./

# Create virtual environment with all dependencies
RUN uv venv /venv
ENV PATH="/venv/bin:$PATH"
RUN uv sync --frozen --no-dev

# Copy source code ONLY in builder stage
COPY src/ src/
COPY migrations/ migrations/

# Build wheel package (compiled code, no source .py files)
RUN uv build --wheel

# Verify wheel contains only compiled code
RUN unzip -l dist/*.whl | grep "\.py$" && exit 1 || echo "No source .py files in wheel ✓"

# =============================================================================
# Stage 2: Runtime - Install wheel, NO source code
# =============================================================================
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies ONLY (curl for healthcheck, sqlite3 for database)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        sqlite3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r tmws --gid=1000 && \
    useradd -r -g tmws --uid=1000 --home-dir=/app --shell=/sbin/nologin tmws

# Copy virtual environment from builder
COPY --from=builder /venv /venv
ENV PATH="/venv/bin:$PATH"

# Copy ONLY the compiled wheel, NOT source
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Copy migrations (needed for alembic upgrade)
COPY --from=builder /build/migrations migrations/

# Create data directory
RUN mkdir -p /app/data && chown -R tmws:tmws /app

USER tmws:tmws

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["uvicorn", "tmws.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Validation** (CRITICAL):
```bash
# 1. Verify NO source .py files in image
docker run <image> find /app -name "*.py" -type f
# Expected output: EMPTY (only .pyc or .so files allowed)

# 2. Verify wheel installed correctly
docker run <image> python -c "import tmws; print(tmws.__version__)"
# Expected: v2.3.1

# 3. Verify migrations present (needed for alembic)
docker run <image> ls -la /app/migrations/versions/
# Expected: List of migration files

# 4. Verify user is non-root
docker run <image> id
# Expected: uid=1000(tmws) gid=1000(tmws)
```

**Risk if Violated**: CRITICAL - Source code IP exposure, embedded secrets leak

---

### 2.2 .dockerignore Configuration (DEFENSE-IN-DEPTH)

**Requirement**: Comprehensive .dockerignore to prevent accidental inclusion

**Security Rationale**:
- Prevents accidental .env, .git, or secret files from being copied
- Reduces build context size (faster builds)
- Explicit allow-list approach (fail-secure)

**Implementation**:
```dockerignore
# =============================================================================
# TMWS .dockerignore - Security-First Configuration
# =============================================================================
# Strategy: Deny-all, then explicitly allow required files
# =============================================================================

# Deny everything by default
*

# Allow ONLY required build files
!pyproject.toml
!uv.lock
!README.md
!src/
!migrations/

# Explicitly deny sensitive files (belt-and-suspenders)
.env
.env.*
*.key
*.pem
*.p12
*.pfx
secrets/
credentials/

# Explicitly deny version control
.git/
.gitignore
.github/

# Explicitly deny Python artifacts
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.so
*.egg
*.egg-info/
dist/
build/
.pytest_cache/
.mypy_cache/
.ruff_cache/

# Explicitly deny local development
.venv/
venv/
env/
.vscode/
.idea/
*.swp
*.swo
.DS_Store

# Explicitly deny documentation (not needed at runtime)
docs/
*.md
!README.md

# Explicitly deny test files (not needed at runtime)
tests/
*.test.py
test_*.py
```

**Validation**:
```bash
# Verify build context excludes sensitive files
docker build --no-cache --progress=plain . 2>&1 | grep "\.env"
# Expected: No output (files excluded)

# Check build context size
docker build --no-cache . 2>&1 | grep "Sending build context"
# Expected: < 5MB (only source code, no dependencies)
```

---

## 3. Dependency Management Security

### 3.1 Deterministic Dependency Resolution (CRITICAL)

**Requirement**: Use `uv.lock` for reproducible builds

**Security Rationale**:
- Prevents dependency confusion attacks
- Ensures production = development = CI dependencies
- Enables vulnerability tracking per exact version
- Blocks transitive dependency injection

**Implementation**:
```dockerfile
# Builder stage
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
```

**Lock File Security**:
```bash
# Regenerate lock file with security updates
uv lock --upgrade-package <vulnerable-package>

# Audit dependencies for known vulnerabilities
pip-audit --requirement uv.lock
```

---

### 3.2 Package Manager Cache Removal (DEFENSE-IN-DEPTH)

**Requirement**: Remove all package manager caches

**Security Rationale**:
- Reduces image size by 20-40%
- Prevents cache poisoning attacks
- Eliminates stale metadata

**Implementation**:
```dockerfile
# Remove apt cache
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Remove pip cache
RUN pip install --no-cache-dir <package>
```

---

### 3.3 Minimal Runtime Dependencies (RECOMMENDED)

**Requirement**: Only install runtime-required packages

**Security Rationale**:
- Smaller attack surface (fewer binaries)
- Reduces CVE count by 40-60%
- Faster security patching

**Runtime Dependencies**:
```dockerfile
RUN apt-get install -y --no-install-recommends \
    curl \        # For healthcheck
    sqlite3 \     # For database CLI debugging
    && apt-get clean
```

**NOT Required at Runtime**:
- gcc, g++, make (build tools)
- git (version control)
- vim, nano (editors)
- wget, netcat (network tools)

---

## 4. Network Security

### 4.1 Port Exposure (RECOMMENDED)

**Requirement**: Expose only necessary port (8000)

**Security Rationale**:
- Limits attack surface
- Enforces principle of least exposure
- Prevents accidental service exposure

**Implementation**:
```dockerfile
# Expose ONLY the API port
EXPOSE 8000

# DO NOT expose:
# - Database ports (SQLite is embedded, no network port)
# - Admin ports (no admin interface)
# - Debug ports (no remote debugging in production)
```

---

### 4.2 No Privileged Mode (CRITICAL)

**Requirement**: Never use `--privileged` flag

**Security Rationale**:
- Privileged mode disables ALL container isolation
- Allows direct host kernel access
- Enables easy container breakout

**Implementation**:
```yaml
# docker-compose.yml
services:
  tmws:
    # privileged: true  ❌ NEVER DO THIS
    cap_drop:
      - ALL  # Drop all capabilities
    cap_add:
      - NET_BIND_SERVICE  # Only if binding port < 1024
```

---

### 4.3 No Host Network Mode (CRITICAL)

**Requirement**: Use bridge network, never host network

**Security Rationale**:
- Host network bypasses network isolation
- Exposes all host network interfaces
- Prevents port remapping (security flexibility)

**Implementation**:
```yaml
# docker-compose.yml
services:
  tmws:
    # network_mode: host  ❌ NEVER DO THIS
    networks:
      - tmws-network

networks:
  tmws-network:
    driver: bridge
    internal: false  # Allow external access
```

---

## 5. Secrets Management

### 5.1 Environment Variable Secret Injection (CRITICAL)

**Requirement**: ALL secrets via environment variables, NEVER hardcoded

**Security Rationale**:
- Secrets rotation without image rebuild
- Prevents accidental commit to registry
- Enables secret management integration (AWS Secrets Manager, Vault)
- Auditable secret access

**Implementation**:
```dockerfile
# ❌ WRONG - Hardcoded secret
ENV TMWS_SECRET_KEY="a3f8b9c2..."

# ✅ CORRECT - Injected at runtime
# (no ENV declaration in Dockerfile)
```

```yaml
# docker-compose.yml
services:
  tmws:
    environment:
      TMWS_SECRET_KEY: ${TMWS_SECRET_KEY}  # From .env file
```

---

### 5.2 No Secrets in Image Layers (CRITICAL)

**Requirement**: Verify no secrets in image history

**Security Rationale**:
- Docker layers are immutable and public (if pushed to registry)
- Secrets in intermediate layers remain even if deleted in final layer
- Multi-stage build prevents this by design

**Validation**:
```bash
# Inspect image history for secrets
docker history <image> --no-trunc | grep -i "secret\|password\|key"
# Expected: No matches

# Extract all layers and search
docker save <image> | tar -xOf - | grep -a "TMWS_SECRET_KEY"
# Expected: No matches
```

---

### 5.3 .dockerignore Secret Protection (DEFENSE-IN-DEPTH)

**Requirement**: Explicitly exclude secret files

**Implementation**:
```dockerignore
.env
.env.*
*.key
*.pem
*.p12
secrets/
credentials/
~/.aws/
~/.ssh/
```

---

## 6. Vulnerability Scanning

### 6.1 Base Image CVE Scanning (RECOMMENDED)

**Requirement**: Scan base image for HIGH+ CVEs

**Security Rationale**:
- Proactive vulnerability detection
- Compliance requirement (PCI-DSS, SOC2)
- Prevents known exploit deployment

**Implementation**:
```bash
# Scan with Docker Desktop (built-in)
docker scan python:3.11-slim

# Scan with Trivy (more comprehensive)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --severity HIGH,CRITICAL python:3.11-slim
```

**Acceptable Thresholds**:
| Severity | Max Count | Action |
|----------|-----------|--------|
| Critical | 0 | BLOCK deployment |
| High | 5 | Investigate, document exception |
| Medium | 20 | Monitor, patch in next release |

---

### 6.2 Dependency CVE Scanning (RECOMMENDED)

**Requirement**: Scan Python dependencies with pip-audit

**Implementation**:
```bash
# In CI/CD pipeline
pip-audit --requirement uv.lock --format json

# Fail build on HIGH+ vulnerabilities
pip-audit --requirement uv.lock --severity HIGH,CRITICAL || exit 1
```

---

### 6.3 Regular Image Updates (OPERATIONAL)

**Requirement**: Monthly security patch updates

**Security Rationale**:
- Zero-day vulnerability mitigation
- Cumulative security improvements
- Compliance requirement

**Implementation**:
```yaml
# .github/workflows/security-scan.yml
name: Monthly Security Scan
on:
  schedule:
    - cron: '0 0 1 * *'  # 1st of each month

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: docker build -t tmws:latest .
      - run: docker scan tmws:latest --severity high,critical
```

---

## 7. Docker Compose Security

### 7.1 Restart Policy (AVAILABILITY)

**Requirement**: `unless-stopped` restart policy

**Security Rationale**:
- Automatic recovery from crashes (DoS mitigation)
- Respects manual stops (operational control)
- Prevents restart loop on persistent failures

**Implementation**:
```yaml
# docker-compose.yml
services:
  tmws:
    restart: unless-stopped  # NOT "always"
```

**Restart Policy Comparison**:
| Policy | Manual Stop | System Reboot | Crash Recovery |
|--------|-------------|---------------|----------------|
| no | Stays stopped | Stays stopped | Stays stopped |
| always | Restarts | Restarts | Restarts |
| unless-stopped | Stays stopped | Stays stopped | Restarts ✓ |
| on-failure | Stays stopped | Stays stopped | Restarts (limited) |

---

### 7.2 Health Check Configuration (MONITORING)

**Requirement**: Health check with reasonable intervals

**Implementation**:
```yaml
services:
  tmws:
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

---

### 7.3 Named Volumes (DATA PERSISTENCE)

**Requirement**: Use named volumes for data persistence

**Security Rationale**:
- Explicit permission control
- Backup-friendly (docker volume backup)
- Prevents accidental data loss

**Implementation**:
```yaml
services:
  tmws:
    volumes:
      - tmws-data:/app/data

volumes:
  tmws-data:
    driver: local
```

---

### 7.4 Network Isolation (DEFENSE-IN-DEPTH)

**Requirement**: Internal bridge network

**Implementation**:
```yaml
services:
  tmws:
    networks:
      - tmws-network

networks:
  tmws-network:
    driver: bridge
    internal: false  # Allow external API access
```

---

## 8. Production Deployment Security

### 8.1 Pre-Deployment Checklist

**Before deploying to production**:

- [ ] **Secret Key**: `openssl rand -hex 32` generated unique value
- [ ] **CORS Origins**: Restricted to production domains (no `*`)
- [ ] **Log Level**: Set to `INFO` or `WARNING` (not `DEBUG`)
- [ ] **Authentication**: `TMWS_AUTH_ENABLED=true`
- [ ] **Rate Limiting**: `TMWS_RATE_LIMIT_ENABLED=true`
- [ ] **Security Headers**: `TMWS_SECURITY_HEADERS_ENABLED=true`
- [ ] **Audit Logging**: `TMWS_AUDIT_LOG_ENABLED=true`
- [ ] **Namespace Isolation**: `TMWS_NAMESPACE_ISOLATION_ENABLED=true`
- [ ] **No Debug Mode**: `TMWS_DEBUG_MODE` not set (or `false`)
- [ ] **No Source Code**: `docker run <image> find /app -name "*.py"` returns empty
- [ ] **Vulnerability Scan**: `docker scan <image>` passes with 0 HIGH+ CVEs

---

### 8.2 Runtime Security Monitoring

**Requirement**: Enable runtime security monitoring

**Implementation**:
```yaml
# docker-compose.yml
services:
  tmws:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    security_opt:
      - no-new-privileges:true  # Prevent privilege escalation
```

---

### 8.3 Resource Limits (DoS MITIGATION)

**Requirement**: CPU and memory limits

**Security Rationale**:
- Prevents resource exhaustion attacks
- Limits blast radius of compromised container
- Enables fair resource sharing

**Implementation**:
```yaml
services:
  tmws:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 256M
```

---

### 8.4 Log Rotation (OPERATIONAL SECURITY)

**Requirement**: Automated log rotation

**Security Rationale**:
- Prevents disk exhaustion (DoS)
- Maintains audit trail within retention policy
- Compliance requirement (log preservation)

**Implementation**:
```yaml
services:
  tmws:
    logging:
      options:
        max-size: "10m"
        max-file: "5"  # 50MB total (10m × 5)
```

---

### 8.5 Backup Strategy (DATA PROTECTION)

**Requirement**: Automated volume backups

**Implementation**:
```bash
# Daily backup script
docker run --rm -v tmws-data:/source -v ./backups:/backup \
  alpine tar czf /backup/tmws-data-$(date +%Y%m%d).tar.gz -C /source .

# Retention: Keep 30 days
find ./backups -name "tmws-data-*.tar.gz" -mtime +30 -delete
```

---

## 9. Coordination with Artemis (Wave 2)

### 9.1 Checkpoint α Agenda

**Topics to discuss at Checkpoint α**:

1. **Multi-stage build verification**:
   - Review wheel compilation step
   - Confirm NO source .py files in runtime stage
   - Validate migrations are copied (needed for alembic)

2. **User creation timing**:
   - Confirm user created AFTER package installation
   - Verify ownership of /app/data directory

3. **Health check endpoint**:
   - Confirm /health endpoint exists (or create it)
   - Minimal information disclosure (no version/dependencies)

4. **Performance implications**:
   - Multi-stage build: +30% build time, acceptable?
   - Read-only filesystem: Any compatibility issues?

5. **Platform-specific issues**:
   - Mac: `host.docker.internal` for Ollama ✓
   - Windows/Linux: Docker Compose Ollama service required?

---

### 9.2 Security Review Points

**Artemis MUST verify**:

- [ ] `.dockerignore` excludes all sensitive files
- [ ] Multi-stage build has NO source code in runtime image
- [ ] Non-root user runs all processes (uid=1000)
- [ ] Health check uses curl (installed in runtime stage)
- [ ] Migrations directory copied (alembic requirement)
- [ ] Environment variables for ALL secrets (no hardcoded)

---

## 10. Testing & Validation

### 10.1 Security Test Suite

**Required tests before Wave 1 completion**:

```bash
# Test 1: No source code in image
docker run tmws:latest find /app -name "*.py" -type f | wc -l
# Expected: 0

# Test 2: Non-root user
docker run tmws:latest id
# Expected: uid=1000(tmws) gid=1000(tmws)

# Test 3: Health check works
docker run -d --name tmws-test tmws:latest
sleep 10
docker inspect tmws-test | jq '.[0].State.Health.Status'
# Expected: "healthy"

# Test 4: Read-only filesystem (if enabled)
docker run --read-only -v ./data:/app/data tmws:latest touch /test
# Expected: Error (read-only filesystem)

# Test 5: No secrets in layers
docker history tmws:latest --no-trunc | grep -i "secret\|password"
# Expected: No matches

# Cleanup
docker rm -f tmws-test
```

---

### 10.2 Compliance Checklist

**Final security sign-off checklist**:

- [ ] **Container Hardening**:
  - [ ] Non-root user (uid=1000)
  - [ ] Minimal base image (python:3.11-slim)
  - [ ] Read-only filesystem (optional)
  - [ ] Health check implemented

- [ ] **Source Code Protection (R-P0-1)**:
  - [ ] Multi-stage build configured
  - [ ] NO .py files in runtime image
  - [ ] .dockerignore comprehensive
  - [ ] Wheel packaging verified

- [ ] **Dependency Security**:
  - [ ] uv.lock for deterministic builds
  - [ ] Package manager caches removed
  - [ ] Minimal runtime dependencies
  - [ ] pip-audit passing

- [ ] **Network Security**:
  - [ ] Only port 8000 exposed
  - [ ] No privileged mode
  - [ ] Bridge network configured
  - [ ] No host network mode

- [ ] **Secrets Management**:
  - [ ] Environment variable injection only
  - [ ] No secrets in image layers
  - [ ] .dockerignore excludes secrets
  - [ ] Secret validation in .env.example

- [ ] **Production Readiness**:
  - [ ] Fail-secure defaults (.env.example)
  - [ ] Security headers enabled
  - [ ] Audit logging enabled
  - [ ] Namespace isolation enabled

---

## 11. Risk Assessment Summary

### High-Risk Areas (Require Extra Attention)

| Risk Area | Severity | Mitigation | Verification |
|-----------|----------|------------|--------------|
| Source code exposure (R-P0-1) | CRITICAL | Multi-stage build | `find /app -name "*.py"` |
| Hardcoded secrets | CRITICAL | Environment variables | `docker history` grep |
| Container breakout | HIGH | Non-root user | `docker run ... id` |
| Dependency vulnerabilities | HIGH | pip-audit + trivy | CI/CD scans |
| Network exposure | MEDIUM | Minimal port exposure | docker-compose review |

---

## 12. References

**OWASP Docker Security**:
- https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

**CIS Docker Benchmark**:
- https://www.cisecurity.org/benchmark/docker

**Docker Official Security Best Practices**:
- https://docs.docker.com/engine/security/

**NIST Container Security Guide**:
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf

---

**End of Document**

**Next Steps**:
1. Hestia → Artemis: Share this requirements document
2. Checkpoint α: Review multi-stage build approach
3. Artemis: Implement Dockerfile + docker-compose.yml (Wave 2)
4. Hestia: Security review of implementation (Wave 3)
