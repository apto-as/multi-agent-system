# TMWS Docker Deployment Guide
## v2.3.1 Production-Ready Docker Deployment

**Last Updated**: 2025-11-16
**Version**: v2.3.1
**Target Audience**: DevOps engineers, system administrators, developers
**Deployment Modes**: Mac (Hybrid), Windows/Linux (Hybrid or Full Docker)

---

## 📋 Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Quick Start](#3-quick-start)
4. [Deployment Modes](#4-deployment-modes)
5. [Configuration](#5-configuration)
6. [Production Deployment](#6-production-deployment)
7. [Security Hardening](#7-security-hardening)
8. [Troubleshooting](#8-troubleshooting)
9. [Maintenance](#9-maintenance)
10. [Migration Guide](#10-migration-guide)

---

## 1. Overview

### 1.1 Why Docker for TMWS?

**Strategic Benefits**:
- ✅ **Source Code Protection**: Compiled `.whl` package obfuscates Python source code
- ✅ **License Operation Security**: Control distribution and usage without code exposure
- ✅ **Consistent Deployment**: Same environment across Mac, Windows, Linux
- ✅ **Easy Updates**: `docker-compose pull && docker-compose up -d`
- ✅ **Dependency Isolation**: No conflicts with host system packages
- ✅ **Rollback Safety**: Previous image versions retained for instant rollback

**What's Included in This Guide**:
- Complete Docker setup for all platforms (Mac, Windows, Linux)
- Hybrid architecture (Ollama native + TMWS Docker) - RECOMMENDED
- Full Docker architecture (Ollama + TMWS both in containers)
- Production-ready security configuration (HTTPS, secrets management)
- Performance optimization (GPU access, volume mounts)
- Cross-platform deployment instructions

**What's NOT in This Guide**:
- Kubernetes deployment → See `docs/deployment/KUBERNETES_DEPLOYMENT.md` (future)
- Cloud provider specifics (AWS/GCP/Azure) → See provider-specific guides (future)
- Development setup → See `docs/DEVELOPMENT_SETUP.md`

---

### 1.2 Architecture Options

**Option A: Mac Hybrid** (Recommended for Mac M1/M2/M3/M4)
```
macOS Host (ARM64)
├─ Ollama (Native, Metal GPU acceleration)
│  └─ multilingual-e5-large (1024-dim embeddings)
└─ TMWS (Docker Container, ARM64)
   ├─ FastAPI MCP Server
   ├─ SQLite with WAL mode
   └─ ChromaDB (DuckDB backend)
```
**Performance**: Metal GPU → 3-5x faster embeddings vs CPU

---

**Option B: Windows/Linux Hybrid** (Recommended for production)
```
Host OS (x86_64 or ARM64)
├─ Ollama (Native, CUDA GPU or CPU)
│  └─ multilingual-e5-large
└─ TMWS (Docker Container)
   ├─ FastAPI MCP Server
   ├─ SQLite with WAL mode
   └─ ChromaDB (DuckDB backend)
```
**Performance**: CUDA GPU → 2-4x faster embeddings vs CPU

---

**Option C: Full Docker** (Maximum isolation)
```
Docker Environment
├─ Ollama Container (ollama/ollama:latest)
│  └─ GPU passthrough (--gpus all)
└─ TMWS Container
   └─ Network: docker-compose internal
```
**Use Case**: Complete environment isolation, CI/CD testing

---

### 1.3 Deployment Decision Matrix

| Criterion | Mac Hybrid | Windows/Linux Hybrid | Full Docker |
|-----------|-----------|---------------------|-------------|
| **Performance** | ⭐⭐⭐⭐⭐ (Metal) | ⭐⭐⭐⭐ (CUDA) | ⭐⭐⭐ (overhead) |
| **Setup Complexity** | ⭐⭐⭐⭐ (Easy) | ⭐⭐⭐⭐ (Easy) | ⭐⭐ (Complex) |
| **Isolation** | ⭐⭐⭐ (Partial) | ⭐⭐⭐ (Partial) | ⭐⭐⭐⭐⭐ (Full) |
| **GPU Support** | ⭐⭐⭐⭐⭐ (Native Metal) | ⭐⭐⭐⭐⭐ (Native CUDA) | ⭐⭐⭐ (Passthrough) |
| **Update Speed** | ⭐⭐⭐⭐⭐ (Fast) | ⭐⭐⭐⭐⭐ (Fast) | ⭐⭐⭐ (2 containers) |
| **Recommended For** | Mac Dev | Production | CI/CD, Testing |

---

## 2. Prerequisites

### 2.1 System Requirements

**Minimum Production Setup**:
- **CPU**: 4 cores (8 cores recommended)
- **RAM**: 8GB (16GB recommended for 10K+ memories)
- **Disk**: 20GB free space (50GB for large deployments)
- **Network**: Stable internet for initial setup
- **OS**:
  - macOS 11+ (Big Sur or later)
  - Windows 10/11 with WSL2
  - Linux with kernel 5.10+ (Ubuntu 20.04+, RHEL 9+)

**GPU Requirements (Optional but Recommended)**:
- **Mac**: M1/M2/M3/M4 chip (Metal automatic)
- **Windows/Linux**: NVIDIA GPU with CUDA 11.8+ (for Ollama GPU acceleration)
- **VRAM**: Minimum 4GB (8GB+ recommended)

---

### 2.2 Required Software

#### Docker Desktop

**Mac**:
```bash
# Download from https://www.docker.com/products/docker-desktop
# Or via Homebrew
brew install --cask docker

# Verify installation
docker --version  # Should show 24.0+
docker-compose --version  # Should show 2.20+
```

**Windows**:
1. Download Docker Desktop from https://www.docker.com/products/docker-desktop
2. Enable WSL2 backend during installation
3. Verify installation:
```powershell
docker --version
docker-compose --version
```

**Linux (Ubuntu)**:
```bash
# Install Docker Engine
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group (avoid sudo)
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose plugin
sudo apt-get install docker-compose-plugin

# Verify
docker --version
docker compose version
```

---

#### Ollama Installation

**Mac (Hybrid Mode)**:
```bash
# Download from https://ollama.ai/download
# Or via Homebrew
brew install ollama

# Start Ollama service
ollama serve &

# Pull required model
ollama pull zylonai/multilingual-e5-large

# Verify
curl http://localhost:11434/api/tags
```

**Windows (Hybrid Mode)**:
1. Download installer from https://ollama.ai/download
2. Install and start Ollama service
3. Pull model:
```powershell
ollama pull zylonai/multilingual-e5-large
```

**Linux (Hybrid Mode)**:
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Start service
sudo systemctl start ollama
sudo systemctl enable ollama

# Pull model
ollama pull zylonai/multilingual-e5-large
```

**Full Docker Mode** (Skip native Ollama installation):
```yaml
# Ollama will run in Docker (see section 4.3)
```

---

### 2.3 Pre-Installation Checklist

**Before proceeding, ensure**:
- [ ] Docker Desktop installed and running (`docker ps` works)
- [ ] Ollama installed (Hybrid mode) or Docker Compose ready (Full Docker mode)
- [ ] Model downloaded: `ollama pull zylonai/multilingual-e5-large` (Hybrid mode)
- [ ] Ports available:
  - [ ] 8000 (TMWS FastAPI)
  - [ ] 11434 (Ollama API) - Hybrid mode only
- [ ] Minimum 8GB RAM available for Docker
- [ ] 20GB disk space free
- [ ] Internet connection stable

**Verification Commands**:
```bash
# Docker status
docker info | grep "Server Version"

# Ollama status (Hybrid mode)
curl -s http://localhost:11434/api/tags | grep multilingual-e5-large

# Disk space
df -h | grep -E "Filesystem|/$"

# RAM
free -h  # Linux
vm_stat  # Mac
```

---

## 3. Quick Start

### 3.1 Mac Hybrid - 30-Second Setup

```bash
# 1. Clone repository (if not already)
git clone https://github.com/apto-as/tmws.git
cd tmws

# 2. Start Ollama (if not running)
ollama serve &

# 3. Verify Ollama model
ollama pull zylonai/multilingual-e5-large

# 4. Create .env file
cp .env.example .env
# Edit .env - set OLLAMA_BASE_URL=http://host.docker.internal:11434

# 5. Start TMWS Docker container
docker-compose up -d

# 6. Verify deployment
docker-compose logs -f tmws-app

# Expected output:
# INFO:     TMWS MCP Server v2.3.1 starting...
# INFO:     Database: SQLite at ./data/tmws.db
# INFO:     ChromaDB: Embedded mode
# INFO:     Ollama: http://host.docker.internal:11434
# INFO:     MCP Server ready
```

**Success Indicators**:
- ✅ Container status: `docker ps` shows `tmws-app` running
- ✅ Health check: `docker-compose exec tmws-app curl -s http://localhost:8000/health` returns `{"status":"healthy"}`
- ✅ Ollama connection: Logs show "Ollama connection: OK"

---

### 3.2 Windows/Linux Hybrid - 5-Minute Setup

**Windows (PowerShell)**:
```powershell
# 1. Clone repository
git clone https://github.com/apto-as/tmws.git
cd tmws

# 2. Start Ollama service (installed separately)
# Verify: http://localhost:11434/api/tags

# 3. Create .env file
copy .env.example .env
# Edit .env - set OLLAMA_BASE_URL=http://host.docker.internal:11434

# 4. Start TMWS
docker-compose up -d

# 5. Verify
docker-compose logs -f tmws-app
```

**Linux (Bash)**:
```bash
# 1. Clone repository
git clone https://github.com/apto-as/tmws.git
cd tmws

# 2. Ensure Ollama is running
sudo systemctl status ollama

# 3. Create .env file
cp .env.example .env
# Edit .env - set OLLAMA_BASE_URL=http://host.docker.internal:11434
# Note: On Linux, use http://172.17.0.1:11434 if host.docker.internal doesn't resolve

# 4. Start TMWS
docker-compose up -d

# 5. Verify
docker-compose logs -f tmws-app
```

---

### 3.3 Full Docker - 10-Minute Setup

```bash
# 1. Clone repository
git clone https://github.com/apto-as/tmws.git
cd tmws

# 2. Use full Docker Compose configuration
cp docker-compose.full.yml docker-compose.yml

# 3. Create .env file
cp .env.example .env
# Edit .env - set OLLAMA_BASE_URL=http://ollama:11434

# 4. Start both containers
docker-compose up -d

# 5. Pull Ollama model (inside container)
docker-compose exec ollama ollama pull zylonai/multilingual-e5-large

# 6. Verify
docker-compose logs -f tmws-app
docker-compose logs -f ollama
```

---

### 3.4 Post-Setup Verification

**Step 1: Health Check**
```bash
# Direct API check
curl http://localhost:8000/health

# Expected response:
{
  "status": "healthy",
  "database": "connected",
  "chromadb": "ready",
  "ollama": "connected",
  "model": "multilingual-e5-large"
}
```

**Step 2: MCP Connection Test**
```bash
# Test memory creation via MCP
# (This requires Claude Desktop configuration - see MCP_CONNECTION_DOCKER.md)

# Or direct API test:
curl -X POST http://localhost:8000/api/v1/memories \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Test memory from Docker deployment",
    "agent_id": "test-agent",
    "namespace": "default"
  }'

# Expected: 201 Created with memory_id
```

**Step 3: Container Status**
```bash
# Check container health
docker ps | grep tmws

# Expected output:
# CONTAINER ID   IMAGE          COMMAND       CREATED         STATUS                    PORTS                    NAMES
# abc123def456   tmws:v2.3.1    "tmws"        2 minutes ago   Up 2 minutes (healthy)    0.0.0.0:8000->8000/tcp   tmws-app
```

---

## 4. Deployment Modes

### 4.1 Mac Hybrid Mode (RECOMMENDED for Mac)

**Architecture**:
```
┌────────────────────────────────────────────────────┐
│ macOS Host (ARM64)                                 │
│                                                    │
│ ┌────────────────┐      ┌─────────────────────┐   │
│ │ Ollama         │      │ TMWS Docker         │   │
│ │ (Native)       │◄─────┤ Container           │   │
│ │                │      │                     │   │
│ │ • Metal GPU    │      │ • FastAPI MCP       │   │
│ │ • Port 11434   │      │ • SQLite + ChromaDB │   │
│ │ • E5-Large     │      │ • Port 8000         │   │
│ └────────────────┘      └─────────────────────┘   │
└────────────────────────────────────────────────────┘
```

**docker-compose.yml** (Mac-specific):
```yaml
# [Wave 3: Artemis will provide complete docker-compose.yml]
# Key configuration points:
# - platform: linux/arm64
# - OLLAMA_BASE_URL: http://host.docker.internal:11434
# - volumes: ./data:/app/data
# - network_mode: bridge
```

**Performance Characteristics**:
- Embedding generation: 50-100 vectors/sec (Metal GPU)
- Semantic search: <10ms P95 (ChromaDB + ARM64 optimization)
- Memory operations: <5ms P95 (SQLite WAL mode)

**Pros**:
- ✅ Maximum GPU performance (Metal acceleration)
- ✅ Simple network configuration (host.docker.internal)
- ✅ Fast model loading (native Ollama)
- ✅ Easy debugging (Ollama logs separate)

**Cons**:
- ⚠️ Ollama must be managed separately (not in Docker)
- ⚠️ Mac-specific setup (not portable to Windows/Linux)

---

### 4.2 Windows/Linux Hybrid Mode

**Architecture**:
```
┌────────────────────────────────────────────────────┐
│ Host OS (x86_64 or ARM64)                          │
│                                                    │
│ ┌────────────────┐      ┌─────────────────────┐   │
│ │ Ollama         │      │ TMWS Docker         │   │
│ │ (Native)       │◄─────┤ Container           │   │
│ │                │      │                     │   │
│ │ • CUDA GPU     │      │ • FastAPI MCP       │   │
│ │   or CPU       │      │ • SQLite + ChromaDB │   │
│ │ • Port 11434   │      │ • Port 8000         │   │
│ └────────────────┘      └─────────────────────┘   │
└────────────────────────────────────────────────────┘
```

**docker-compose.yml** (Linux/Windows-specific):
```yaml
# [Wave 3: Artemis will provide platform-specific configs]
# Windows: OLLAMA_BASE_URL: http://host.docker.internal:11434
# Linux: OLLAMA_BASE_URL: http://172.17.0.1:11434 (Docker bridge IP)
```

**Network Configuration Notes**:

**Windows (WSL2)**:
- `host.docker.internal` resolves to Windows host IP
- Ollama runs as Windows service, accessible from WSL2 containers

**Linux**:
- `host.docker.internal` may not work on all distributions
- Alternative: Use Docker bridge IP (typically `172.17.0.1`)
- Or: Use host network mode (`network_mode: host`)

**Verification**:
```bash
# Test Ollama connectivity from container
docker run --rm curlimages/curl:latest curl http://host.docker.internal:11434/api/tags

# If fails on Linux, try Docker bridge IP
docker run --rm curlimages/curl:latest curl http://172.17.0.1:11434/api/tags
```

---

### 4.3 Full Docker Mode

**Architecture**:
```
┌─────────────────────────────────────────────┐
│ Docker Environment                          │
│                                             │
│ ┌─────────────┐        ┌─────────────────┐ │
│ │ Ollama      │        │ TMWS            │ │
│ │ Container   │◄───────┤ Container       │ │
│ │             │  8080  │                 │ │
│ │ • GPU       │        │ • MCP Server    │ │
│ │   Passthrough        │ • SQLite        │ │
│ │ • Internal  │        │ • ChromaDB      │ │
│ │   Network   │        │                 │ │
│ └─────────────┘        └─────────────────┘ │
│                                             │
│ Shared Network: tmws-network                │
└─────────────────────────────────────────────┘
```

**docker-compose.full.yml**:
```yaml
# [Wave 3: Artemis will provide complete Full Docker configuration]
# Key features:
# - GPU passthrough for Ollama (--gpus all)
# - Internal Docker network (tmws-network)
# - Volume persistence for both containers
# - Health checks for both services
```

**GPU Passthrough (NVIDIA)**:
```yaml
services:
  ollama:
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
```

**Use Cases**:
- ✅ Complete environment isolation (no host dependencies)
- ✅ CI/CD testing (reproducible environments)
- ✅ Multi-tenant deployments (namespace per container)
- ✅ Air-gapped environments (offline after initial setup)

**Cons**:
- ⚠️ Complex GPU passthrough setup
- ⚠️ Higher resource overhead (2 containers)
- ⚠️ Slower updates (2 images to pull)

---

## 5. Configuration

### 5.1 Environment Variables Reference

**Critical Variables** (MUST be set):
```bash
# Database configuration
TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"  # Default: local SQLite

# Security
TMWS_SECRET_KEY="<64-character-hex-string>"  # GENERATE NEW: openssl rand -hex 32
TMWS_ENVIRONMENT="production"  # Options: development, staging, production

# Ollama connection
OLLAMA_BASE_URL="http://host.docker.internal:11434"  # Mac/Windows Hybrid
# Or: "http://172.17.0.1:11434"  # Linux Hybrid
# Or: "http://ollama:11434"  # Full Docker
```

**Optional Variables** (defaults provided):
```bash
# MCP Server
TMWS_MCP_HOST="0.0.0.0"  # Default: all interfaces
TMWS_MCP_PORT="8000"  # Default: 8000

# Agent configuration
TMWS_AGENT_ID="docker-instance-1"  # Auto-generated if not set
TMWS_AGENT_NAMESPACE="default"  # Default namespace

# Performance tuning
TMWS_DB_POOL_SIZE="10"  # Default: 10 connections
TMWS_DB_MAX_OVERFLOW="20"  # Default: 20 overflow connections

# Security
TMWS_AUTH_ENABLED="false"  # Default: false (set "true" for production)
TMWS_CORS_ORIGINS='["https://example.com"]'  # Default: ["*"]

# Logging
TMWS_LOG_LEVEL="INFO"  # Options: DEBUG, INFO, WARNING, ERROR
TMWS_LOG_FORMAT="json"  # Options: json, text

# ChromaDB
CHROMA_PERSIST_DIRECTORY="./data/chromadb"  # Default: ./data/chromadb
```

**Full .env.example**:
```bash
# [Wave 3: Artemis will provide complete .env.example with all variables documented]
```

---

### 5.2 Security Configuration

**SECRET_KEY Generation**:
```bash
# Option 1: OpenSSL (Recommended)
openssl rand -hex 32

# Option 2: Python
python3 -c "import secrets; print(secrets.token_hex(32))"

# Option 3: uv (if installed)
uv run python -c "import secrets; print(secrets.token_hex(32))"
```

**NEVER commit secrets to version control**:
```bash
# .gitignore should include:
.env
.env.local
.env.*.local
*.key
secrets/
```

**CORS Configuration** (Production):
```bash
# Restrict to specific domains
TMWS_CORS_ORIGINS='["https://app.example.com","https://admin.example.com"]'

# For development only
TMWS_CORS_ORIGINS='["*"]'  # WARNING: Do not use in production
```

---

### 5.3 Platform-Specific Configuration

**Mac-Specific (.env.mac)**:
```bash
# Ollama connection (host.docker.internal always works on Mac)
OLLAMA_BASE_URL="http://host.docker.internal:11434"

# Database path (Mac default)
TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"

# ChromaDB persistence
CHROMA_PERSIST_DIRECTORY="./data/chromadb"
```

**Windows-Specific (.env.windows)**:
```bash
# Ollama connection (WSL2 host)
OLLAMA_BASE_URL="http://host.docker.internal:11434"

# Database path (Windows path format)
TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"

# Note: Volume mounts use WSL paths
# Example: /mnt/c/Users/YourName/tmws/data
```

**Linux-Specific (.env.linux)**:
```bash
# Ollama connection (Docker bridge IP)
OLLAMA_BASE_URL="http://172.17.0.1:11434"
# Or use host network mode in docker-compose.yml

# Database path
TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"

# ChromaDB persistence
CHROMA_PERSIST_DIRECTORY="./data/chromadb"
```

---

## 6. Production Deployment

### 6.1 Pre-Deployment Checklist

**Infrastructure Validation**:
- [ ] Docker version ≥ 24.0 (`docker --version`)
- [ ] Ollama installed and running (Hybrid) or GPU accessible (Full Docker)
- [ ] Minimum 8GB RAM available (`free -h` / `vm_stat`)
- [ ] Minimum 20GB disk space (`df -h`)
- [ ] Ports 8000, 11434 not in use (`lsof -i :8000`, `lsof -i :11434`)

**Security Checklist**:
- [ ] SECRET_KEY generated (64 characters, unique per environment)
- [ ] .env file created and populated (never commit to git)
- [ ] CORS_ORIGINS restricted to production domains
- [ ] AUTH_ENABLED set to "true" for production
- [ ] HTTPS configured (if exposing to internet) - See section 7.2

**Configuration Validation**:
- [ ] .env file syntax correct (`docker-compose config` validates)
- [ ] DATABASE_URL points to persistent volume
- [ ] OLLAMA_BASE_URL accessible from container
- [ ] All required environment variables set

**Data Persistence**:
- [ ] Volume mount configured for `./data` directory
- [ ] Backup strategy in place (see section 9.4)
- [ ] Database migrations applied (`alembic upgrade head` - if applicable)

---

### 6.2 Production Deployment Steps

**Step 1: Environment Preparation**
```bash
# Create production directory
mkdir -p ~/tmws-production
cd ~/tmws-production

# Clone repository (production branch)
git clone -b main https://github.com/apto-as/tmws.git .

# Create production .env
cp .env.example .env
nano .env  # Edit with production values
```

**Step 2: Security Setup**
```bash
# Generate production SECRET_KEY
export TMWS_SECRET_KEY=$(openssl rand -hex 32)
echo "TMWS_SECRET_KEY=$TMWS_SECRET_KEY" >> .env

# Set production environment
echo "TMWS_ENVIRONMENT=production" >> .env
echo "TMWS_AUTH_ENABLED=true" >> .env

# Configure CORS (replace with your domains)
echo 'TMWS_CORS_ORIGINS=["https://app.example.com"]' >> .env
```

**Step 3: Ollama Setup** (Hybrid mode)
```bash
# Mac/Linux
ollama serve &
ollama pull zylonai/multilingual-e5-large

# Verify
curl http://localhost:11434/api/tags | grep multilingual-e5-large
```

**Step 4: Docker Image Build** (Optional - for custom builds)
```bash
# Build production image
docker build -t tmws:v2.3.1-prod -f Dockerfile.prod .

# Or pull pre-built image
docker pull ghcr.io/apto-as/tmws:v2.3.1
```

**Step 5: Start Services**
```bash
# Start in detached mode
docker-compose up -d

# Monitor startup logs
docker-compose logs -f tmws-app

# Expected: "MCP Server ready" within 30 seconds
```

**Step 6: Health Check**
```bash
# Wait for healthy status
timeout 60 bash -c 'until docker-compose ps | grep healthy; do sleep 2; done'

# Verify API
curl -f http://localhost:8000/health || echo "Health check failed"

# Verify Ollama connection
docker-compose exec tmws-app curl -s http://ollama:11434/api/tags
```

**Step 7: Initial Data Setup**
```bash
# Create initial agent (if needed)
# [Wave 3: Artemis will provide agent registration script]

# Test memory creation
# [Wave 3: Provide test script]
```

---

### 6.3 Post-Deployment Verification

**Functional Tests**:
```bash
# Test 1: Health endpoint
curl http://localhost:8000/health

# Test 2: MCP tools available
# [Wave 3: Provide MCP tool listing command]

# Test 3: Memory CRUD operations
# [Wave 3: Provide test script]

# Test 4: Semantic search performance
# [Wave 3: Provide benchmark script]
```

**Performance Benchmarks** (Expected P95 latency):
- Memory creation: <10ms
- Semantic search: <20ms
- Vector embedding: <50ms (GPU), <200ms (CPU)

---

## 7. Security Hardening

### 7.1 Network Security

**Firewall Configuration**:
```bash
# Linux (ufw)
sudo ufw allow 8000/tcp  # TMWS API
sudo ufw allow 11434/tcp  # Ollama (if exposing to network)
sudo ufw enable

# macOS (pf)
# Edit /etc/pf.conf and add rules
```

**Restrict Container Network Access**:
```yaml
# docker-compose.yml
networks:
  tmws-internal:
    driver: bridge
    internal: true  # No external internet access
```

---

### 7.2 HTTPS Configuration

**Option A: Nginx Reverse Proxy**
```nginx
# /etc/nginx/sites-available/tmws
server {
    listen 443 ssl http2;
    server_name tmws.example.com;

    ssl_certificate /etc/letsencrypt/live/tmws.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tmws.example.com/privkey.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Option B: Traefik** (Docker-native):
```yaml
# [Wave 3: Hestia will provide Traefik configuration for Docker HTTPS]
```

---

### 7.3 Access Control

**Enable JWT Authentication**:
```bash
# .env
TMWS_AUTH_ENABLED=true
TMWS_SECRET_KEY=<64-char-hex>

# Generate API key for agents
# [Wave 3: Provide API key generation script]
```

**RBAC Configuration**:
```yaml
# [Wave 3: Hestia will document RBAC setup for multi-agent environments]
```

---

## 8. Troubleshooting

### 8.1 Container Won't Start

**Symptom**: `docker-compose up` fails or container exits immediately

**Diagnostic Steps**:
```bash
# Check logs
docker-compose logs tmws-app

# Check container status
docker ps -a | grep tmws

# Inspect exit code
docker inspect tmws-app | grep ExitCode
```

**Common Causes**:

**Issue 1: Ollama Unreachable**
```
Error: "Failed to connect to Ollama at http://host.docker.internal:11434"
```
**Solution**:
```bash
# Verify Ollama is running
curl http://localhost:11434/api/tags

# If not running:
ollama serve &

# Check Docker host networking
docker run --rm curlimages/curl:latest curl http://host.docker.internal:11434/api/tags
```

**Issue 2: Port Already in Use**
```
Error: "Bind for 0.0.0.0:8000 failed: port is already allocated"
```
**Solution**:
```bash
# Find process using port 8000
lsof -i :8000  # Mac/Linux
netstat -ano | findstr :8000  # Windows

# Kill process or change TMWS_MCP_PORT in .env
```

**Issue 3: Volume Mount Permission Denied**
```
Error: "PermissionError: [Errno 13] Permission denied: './data/tmws.db'"
```
**Solution**:
```bash
# Fix data directory permissions
sudo chown -R $(id -u):$(id -g) ./data

# Or run container as current user
# Add to docker-compose.yml:
user: "${UID}:${GID}"
```

---

### 8.2 Ollama Connection Issues

**Symptom**: "Ollama connection: FAILED" in logs

**Diagnostic Steps**:
```bash
# Test 1: Ollama accessible from host
curl http://localhost:11434/api/tags

# Test 2: Ollama accessible from container
docker-compose exec tmws-app curl http://host.docker.internal:11434/api/tags

# Test 3: Check Ollama logs
# Mac: ollama logs (if running via launchd)
# Linux: sudo journalctl -u ollama -f
```

**Solutions**:

**Linux-Specific: host.docker.internal doesn't work**
```bash
# Option 1: Use Docker bridge IP
OLLAMA_BASE_URL=http://172.17.0.1:11434

# Option 2: Use host network mode
# docker-compose.yml:
network_mode: host
```

**Windows WSL2: Ollama not accessible**
```bash
# Ensure Ollama is listening on all interfaces
# Windows: Run Ollama with OLLAMA_HOST=0.0.0.0
```

**Full Docker: Ollama container not ready**
```bash
# Check Ollama container status
docker-compose logs ollama

# Pull model manually
docker-compose exec ollama ollama pull zylonai/multilingual-e5-large
```

---

### 8.3 Performance Issues

**Symptom**: Slow embedding generation (>500ms per request)

**Diagnostic Steps**:
```bash
# Check GPU usage
nvidia-smi  # Linux/Windows NVIDIA
# Or: ioreg -l | grep -A10 "Metal"  # Mac Metal GPU

# Check Ollama model loaded
curl http://localhost:11434/api/tags | jq '.models'

# Monitor container resources
docker stats tmws-app
```

**Solutions**:

**GPU Not Utilized**:
```bash
# Mac: Ensure Ollama using Metal (should be automatic)
# Linux/Windows: Enable GPU passthrough in docker-compose.yml

# Full Docker mode:
deploy:
  resources:
    reservations:
      devices:
        - driver: nvidia
          capabilities: [gpu]
```

**Memory Pressure**:
```bash
# Increase container memory limit
# docker-compose.yml:
deploy:
  resources:
    limits:
      memory: 8G  # Increase from default
```

---

### 8.4 Data Persistence Issues

**Symptom**: Data lost after container restart

**Diagnostic Steps**:
```bash
# Check volume mount
docker inspect tmws-app | grep -A10 Mounts

# Verify data directory exists
ls -la ./data
```

**Solution**:
```bash
# Ensure volume mount in docker-compose.yml
volumes:
  - ./data:/app/data:rw  # :rw = read-write

# Check directory ownership
sudo chown -R $(id -u):$(id -g) ./data
```

---

## 9. Maintenance

### 9.1 Daily Operations

**Start/Stop Services**:
```bash
# Start
docker-compose up -d

# Stop
docker-compose down

# Restart (apply config changes)
docker-compose restart

# Stop and remove volumes (DANGEROUS - DATA LOSS)
docker-compose down -v  # ⚠️ Deletes all data!
```

**Log Monitoring**:
```bash
# Follow real-time logs
docker-compose logs -f tmws-app

# Last 100 lines
docker-compose logs --tail=100 tmws-app

# Search logs for errors
docker-compose logs tmws-app | grep ERROR
```

---

### 9.2 Updates and Upgrades

**Update TMWS Docker Image**:
```bash
# Pull latest image
docker-compose pull tmws-app

# Stop current container
docker-compose down

# Start with new image
docker-compose up -d

# Verify version
docker-compose exec tmws-app tmws --version
```

**Rollback to Previous Version**:
```bash
# Stop current version
docker-compose down

# Edit docker-compose.yml to use previous image tag
# image: tmws:v2.3.0  # Changed from v2.3.1

# Start previous version
docker-compose up -d
```

**Database Migration** (if schema changed):
```bash
# Check migration status
docker-compose exec tmws-app alembic current

# Apply migrations
docker-compose exec tmws-app alembic upgrade head
```

---

### 9.3 Monitoring

**Health Check Script**:
```bash
#!/bin/bash
# healthcheck.sh

# Check container status
if ! docker ps | grep -q tmws-app; then
    echo "ERROR: TMWS container not running"
    exit 1
fi

# Check API health
if ! curl -sf http://localhost:8000/health > /dev/null; then
    echo "ERROR: TMWS API health check failed"
    exit 1
fi

# Check Ollama connection
if ! docker-compose exec -T tmws-app curl -sf http://ollama:11434/api/tags > /dev/null; then
    echo "WARNING: Ollama connection failed"
    exit 2
fi

echo "OK: All services healthy"
exit 0
```

**Cron Job** (Run health check every 5 minutes):
```bash
# crontab -e
*/5 * * * * /path/to/tmws/healthcheck.sh >> /var/log/tmws-health.log 2>&1
```

---

### 9.4 Backup Strategy

**Automated Backup Script**:
```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backup/tmws/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup SQLite database
docker-compose exec -T tmws-app sqlite3 /app/data/tmws.db ".backup /tmp/tmws_backup.db"
docker cp tmws-app:/tmp/tmws_backup.db "$BACKUP_DIR/tmws.db"

# Backup ChromaDB
docker cp tmws-app:/app/data/chromadb "$BACKUP_DIR/chromadb"

# Backup .env (secrets)
cp .env "$BACKUP_DIR/.env"

# Create tarball
tar -czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR"
rm -rf "$BACKUP_DIR"

echo "Backup created: $BACKUP_DIR.tar.gz"
```

**Restore from Backup**:
```bash
# Stop container
docker-compose down

# Extract backup
tar -xzf /backup/tmws/20251116_120000.tar.gz

# Restore data
cp -r 20251116_120000/* ./data/

# Restart container
docker-compose up -d
```

---

### 9.5 Log Rotation

**Docker Log Configuration**:
```yaml
# docker-compose.yml
services:
  tmws-app:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"  # Keep 3 rotated logs
```

---

## 10. Migration Guide

### 10.1 Migrating from Native Installation to Docker

**Step 1: Export Existing Data**
```bash
# Backup current database
cp ~/.tmws/tmws.db ./tmws_backup.db

# Backup ChromaDB
cp -r ~/.tmws/chromadb ./chromadb_backup
```

**Step 2: Prepare Docker Environment**
```bash
# Create data directory
mkdir -p ./data

# Copy databases
cp tmws_backup.db ./data/tmws.db
cp -r chromadb_backup ./data/chromadb
```

**Step 3: Configure .env**
```bash
# Use same SECRET_KEY as native installation
# (Find in ~/.tmws/config.yaml or previous .env)
```

**Step 4: Start Docker**
```bash
docker-compose up -d
```

**Step 5: Verify Migration**
```bash
# Check memory count matches
# [Wave 3: Provide verification script]
```

---

### 10.2 Migrating Between Deployment Modes

**Hybrid → Full Docker**:
1. Stop TMWS container
2. Change OLLAMA_BASE_URL in .env
3. Start Full Docker compose configuration
4. Pull model in Ollama container

**Full Docker → Hybrid**:
1. Install Ollama natively
2. Pull model: `ollama pull zylonai/multilingual-e5-large`
3. Stop Full Docker setup
4. Update .env with host.docker.internal URL
5. Start Hybrid configuration

---

### 10.3 Platform Migration (Mac → Linux, etc.)

**Export from Mac**:
```bash
# Backup data
tar -czf tmws-data-export.tar.gz ./data

# Export .env (REMOVE SECRET_KEY FIRST!)
grep -v SECRET_KEY .env > .env.export
```

**Import to Linux**:
```bash
# Extract data
tar -xzf tmws-data-export.tar.gz

# Create new .env
cp .env.export .env
echo "TMWS_SECRET_KEY=$(openssl rand -hex 32)" >> .env

# Update OLLAMA_BASE_URL for Linux
sed -i 's/host.docker.internal/172.17.0.1/g' .env

# Start on Linux
docker-compose up -d
```

---

## Related Documentation

- **MCP Connection Setup**: [MCP_CONNECTION_DOCKER.md](MCP_CONNECTION_DOCKER.md)
- **RBAC Rollback**: [RBAC_ROLLBACK_PROCEDURE.md](RBAC_ROLLBACK_PROCEDURE.md)
- **Monitoring Checklist**: [MONITORING_CHECKLIST.md](MONITORING_CHECKLIST.md)
- **General MCP Guide**: [../MCP_INTEGRATION.md](../MCP_INTEGRATION.md)
- **Architecture Overview**: [../architecture/TMWS_v2.2.0_ARCHITECTURE.md](../architecture/TMWS_v2.2.0_ARCHITECTURE.md)

---

## Support and Contributing

**Issues**: https://github.com/apto-as/tmws/issues
**Discussions**: https://github.com/apto-as/tmws/discussions
**Security**: security@apto-as.com

---

**Last Reviewed**: 2025-11-16
**Next Review**: 2025-12-16
**Version**: v2.3.1
**Status**: Production-Ready ✅
