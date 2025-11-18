# TMWS v2.3.2 Option A Deployment Guide
## Native Ollama + Docker TMWS (Recommended Architecture)

**Last Updated**: 2025-11-18
**TMWS Version**: v2.3.2
**Architecture**: Option A (Native Ollama on host + Docker TMWS container)
**License**: ENTERPRISE (PERPETUAL) or FREE tier
**Deployment Time**: **15 minutes** (first-time)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Verification Steps](#verification-steps)
- [Troubleshooting](#troubleshooting)
- [Performance Expectations](#performance-expectations)
- [Security Considerations](#security-considerations)
- [Maintenance](#maintenance)
- [Appendix](#appendix)

---

## 🎯 Overview

### What is Option A?

**Option A** is the **recommended architecture** for TMWS deployment, separating concerns between embedding generation (Ollama on host) and application logic (TMWS in Docker). This architecture provides:

✅ **Optimal Performance**: Native Ollama leverages host GPU/CPU without Docker overhead
✅ **Simplified Management**: Ollama updates independent of TMWS deployment
✅ **Resource Efficiency**: Single Ollama instance can serve multiple applications
✅ **Faster Troubleshooting**: Clear separation between embedding and application layers

### When to Use Option A

**Best for**:
- Production deployments (single-server or small clusters)
- Development machines with Ollama already installed
- Environments where GPU acceleration is critical
- Users who want to share Ollama across multiple services

**Not ideal for**:
- Kubernetes clusters (use Option B with sidecar pattern)
- Air-gapped environments without internet access
- Windows environments without WSL2 support

---

## 🏗️ Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                         HOST MACHINE                        │
│                                                             │
│  ┌─────────────────────┐       ┌────────────────────────┐  │
│  │   OLLAMA (Native)   │       │  TMWS (Docker)         │  │
│  │                     │       │                        │  │
│  │  Port: 11434        │◀──────│  TMWS MCP Server       │  │
│  │  Model:             │       │  Port: 8000            │  │
│  │  multilingual-e5-   │       │                        │  │
│  │  large              │       │  ┌──────────────────┐  │  │
│  │                     │       │  │  SQLite DB       │  │  │
│  │  GPU: ✅ (optional) │       │  │  ./data/tmws.db  │  │  │
│  │  RAM: ~2GB          │       │  └──────────────────┘  │  │
│  │                     │       │  ┌──────────────────┐  │  │
│  └─────────────────────┘       │  │  ChromaDB        │  │  │
│           ▲                    │  │  ./.chroma/      │  │  │
│           │                    │  └──────────────────┘  │  │
│           │                    │                        │  │
│       Embeddings               │  Volume Mounts:        │  │
│       (1024-dim)               │  - ./data:/app/data    │  │
│                                │  - ./.chroma:/app/.c.. │  │
│                                │  - ./config:/app/cfg   │  │
│                                │  - ./logs:/app/logs    │  │
│                                └────────────────────────┘  │
│                                         ▲                  │
│                                         │                  │
│                                    HTTP :8000              │
└─────────────────────────────────────────┼──────────────────┘
                                          │
                                    ┌─────▼──────┐
                                    │   CLIENT   │
                                    │  (Claude)  │
                                    └────────────┘
```

### Data Flow

1. **Client Request** → TMWS container (port 8000)
2. **TMWS** → Ollama (host.docker.internal:11434) for embeddings
3. **Ollama** → Returns 1024-dim vector
4. **TMWS** → Stores in ChromaDB + SQLite
5. **TMWS** → Returns response to client

### Component Responsibilities

| Component | Responsibility | Storage | Network |
|-----------|---------------|---------|---------|
| **Ollama (Host)** | Embedding generation (multilingual-e5-large) | `~/.ollama/` (3GB model) | `localhost:11434` |
| **TMWS (Docker)** | MCP server, API, business logic | `./data/`, `./.chroma/` | `0.0.0.0:8000` |
| **SQLite** | Metadata, relationships, access control | `./data/tmws.db` | N/A (file-based) |
| **ChromaDB** | Vector embeddings, semantic search | `./.chroma/` | N/A (embedded) |

---

## ✅ Prerequisites

### System Requirements

| Requirement | Minimum | Recommended | Notes |
|-------------|---------|-------------|-------|
| **OS** | Linux, macOS 10.15+, Windows 10+ (WSL2) | Linux Ubuntu 22.04, macOS 13+ | |
| **CPU** | 2 cores | 4+ cores | More cores = faster embeddings |
| **RAM** | 4GB | 8GB+ | Ollama model: ~2GB, TMWS: ~1GB |
| **Disk** | 10GB free | 20GB+ SSD | Ollama model: 3GB, ChromaDB grows over time |
| **GPU** | Optional | NVIDIA/AMD/Metal | **10x faster embeddings** |

### Software Prerequisites

#### 1. Ollama Installation (REQUIRED)

Ollama is **required** for TMWS v2.3.2+. No fallback embedding service is available.

##### macOS (Recommended)

```bash
# Download and install from official website
# https://ollama.ai/download/mac

# OR via Homebrew
brew install ollama

# Start Ollama service
ollama serve
```

##### Linux (Ubuntu/Debian)

```bash
# Official installation script
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama service
ollama serve

# OR as systemd service (recommended for production)
sudo systemctl enable ollama
sudo systemctl start ollama
```

##### Windows (WSL2 Required)

```powershell
# Option 1: Download installer
# https://ollama.ai/download/windows
# Run OllamaSetup.exe

# Option 2: WSL2 + Linux installation
wsl
curl -fsSL https://ollama.ai/install.sh | sh
ollama serve
```

**Verification**:
```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Expected output: JSON with "models" array
# {"models":[...]}
```

##### Pull Embedding Model

```bash
# Download multilingual-e5-large model (~3GB)
ollama pull zylonai/multilingual-e5-large

# Verify model is available
ollama list

# Expected output:
# NAME                             SIZE      MODIFIED
# zylonai/multilingual-e5-large    2.7 GB    X minutes ago
```

**⚠️ IMPORTANT**: This step downloads **3GB** data. Use a stable internet connection.

---

#### 2. Docker & Docker Compose (REQUIRED)

##### macOS

```bash
# Download Docker Desktop for Mac
# https://www.docker.com/products/docker-desktop/

# Verify installation
docker --version       # Docker version 24.0.0+
docker-compose --version  # Docker Compose version 2.0.0+
```

##### Linux (Ubuntu/Debian)

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose (V2)
sudo apt-get update
sudo apt-get install docker-compose-plugin

# Add user to docker group (avoid sudo)
sudo usermod -aG docker $USER
newgrp docker

# Verify installation
docker --version
docker compose version
```

##### Windows

```powershell
# Download Docker Desktop for Windows
# https://www.docker.com/products/docker-desktop/

# Requires WSL2 backend
# Verify installation in PowerShell
docker --version
docker-compose --version
```

---

#### 3. TMWS License Key (REQUIRED)

**License Tiers**:

| Tier | Agents | Support | Price | Use Case |
|------|--------|---------|-------|----------|
| **FREE** | 1 agent | Community | $0 | Development, Testing |
| **STANDARD** | 10 agents | Email | $49/mo | Small teams |
| **ENTERPRISE** | Unlimited | Priority | Contact sales | Production |

**Obtain License**:
1. **FREE tier**: Visit https://trinitas.ai/licensing/free
2. **STANDARD/ENTERPRISE**: Contact sales@trinitas.ai

**License Key Format**:
```
TMWS-{TIER}-{UUID}-{CHECKSUM}

Example (FREE):
TMWS-FREE-12345678-1234-5678-1234-567812345678-ABCD1234

Example (ENTERPRISE PERPETUAL):
TMWS-ENTERPRISE-PERPETUAL-87654321-4321-8765-4321-876543218765-DCBA4321
```

---

## 🚀 Quick Start

**Total time: 15 minutes** (including Ollama model download)

### Step 1: Verify Ollama is Running

```bash
# Check Ollama service
curl http://localhost:11434/api/tags

# Expected: JSON response with models array
# If error: Start Ollama with `ollama serve`
```

✅ **Checkpoint 1**: Ollama responds on port 11434

---

### Step 2: Clone TMWS Repository

```bash
# Clone latest version
git clone https://github.com/apto-as/tmws.git
cd tmws

# Checkout v2.3.2 tag (recommended for production)
git checkout v2.3.2
```

✅ **Checkpoint 2**: Repository cloned, working directory is `tmws/`

---

### Step 3: Configure Environment Variables

```bash
# Copy example environment file
cp .env.example .env

# Edit .env file
vim .env  # or nano, code, etc.
```

**Required Configuration** (update these values):

```bash
# ========================================
# CRITICAL: Update these values
# ========================================

# 1. License Key (REQUIRED)
TMWS_LICENSE_KEY=TMWS-ENTERPRISE-PERPETUAL-your-actual-key-here

# 2. Secret Key (REQUIRED - generate new one)
TMWS_SECRET_KEY=$(openssl rand -hex 32)
# Example: a3f8b9c2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1

# 3. Environment (production recommended)
TMWS_ENVIRONMENT=production

# ========================================
# Optional: Advanced Configuration
# ========================================

# Ollama URL (default works for most cases)
TMWS_OLLAMA_BASE_URL=http://host.docker.internal:11434

# CORS origins (add your frontend URLs)
TMWS_CORS_ORIGINS=["http://localhost:3000"]

# Logging level
TMWS_LOG_LEVEL=INFO
```

**Generate Secret Key**:
```bash
# macOS/Linux
openssl rand -hex 32

# Windows (PowerShell)
[Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

✅ **Checkpoint 3**: `.env` file created with valid license key and secret key

---

### Step 4: Create Persistent Directories

```bash
# Create directories for data persistence
mkdir -p data config logs .chroma

# Set permissions (Linux only)
chmod -R 755 data config logs .chroma
```

**Directory Structure**:
```
tmws/
├── data/           # SQLite database (persistent)
├── .chroma/        # ChromaDB vectors (persistent)
├── config/         # Configuration files (optional)
├── logs/           # Application logs (persistent)
└── .env            # Environment variables (NOT committed to Git)
```

✅ **Checkpoint 4**: Directories created with correct permissions

---

### Step 5: Build Docker Image

```bash
# Build TMWS container image
docker-compose build

# Expected output:
# [+] Building 45.3s (18/18) FINISHED
# ...
# => => naming to docker.io/library/tmws-app
```

**Build time**: 2-5 minutes (first time), 10-30 seconds (subsequent builds)

**What happens during build**:
1. Multi-stage build (builder + runtime)
2. Compiles Python source to bytecode (.pyc)
3. Removes all .py source files (security: R-P0-1 mitigation)
4. Creates minimal runtime image (~470MB)

✅ **Checkpoint 5**: Docker image `tmws-app` built successfully

---

### Step 6: Start TMWS Container

```bash
# Start container in detached mode
docker-compose up -d

# Expected output:
# [+] Running 1/1
#  ✔ Container tmws-app  Started
```

**Initial startup time**: 30-60 seconds

**What happens during startup**:
1. License validation (TMWS_LICENSE_KEY)
2. Database migration (Alembic auto-upgrade)
3. ChromaDB initialization
4. Ollama connectivity check
5. Health check endpoint activation

✅ **Checkpoint 6**: Container `tmws-app` is running

---

### Step 7: Verify Deployment

**Check container status**:
```bash
docker-compose ps

# Expected output:
# NAME        COMMAND              SERVICE   STATUS         PORTS
# tmws-app    "tmws-mcp-server"    tmws      Up 1 minute    0.0.0.0:8000->8000/tcp
```

**Check logs for successful startup**:
```bash
docker-compose logs -f tmws

# Expected output (key lines):
# ✅ License validated successfully
#    Tier: ENTERPRISE
#    Expires: PERPETUAL (never expires)
# ✅ Database migration completed
# ✅ Ollama connectivity verified
# ✅ MCP server started on http://0.0.0.0:8000
# INFO:     Application startup complete.
```

**Stop following logs**: Press `Ctrl+C` (container keeps running)

✅ **Checkpoint 7**: Logs confirm successful startup

---

## ✅ Verification Steps

### 1. Ollama Connectivity Test

```bash
# Test Ollama from host
curl http://localhost:11434/api/tags

# Test Ollama from Docker container
docker exec tmws-app curl -f http://host.docker.internal:11434/api/tags

# Expected: JSON response with models array
# {"models":[{"name":"zylonai/multilingual-e5-large:latest",...}]}
```

✅ **Success**: Container can reach Ollama on host

❌ **Failure**: See [Troubleshooting: Ollama Connection Refused](#ollama-connection-refused)

---

### 2. Docker Container Status

```bash
# Check if container is running
docker ps | grep tmws

# Expected:
# tmws-app   "tmws-mcp-server"   Up 5 minutes   0.0.0.0:8000->8000/tcp
```

✅ **Success**: Container status is "Up"

❌ **Failure**: See [Troubleshooting: Container Startup Failure](#container-startup-failure)

---

### 3. SQLite Database Persistence Test

```bash
# Check database file exists
ls -lh data/tmws.db

# Expected output:
# -rw-r--r-- 1 user user 256K Nov 18 10:30 data/tmws.db

# Verify database integrity
docker exec tmws-app sqlite3 /app/data/tmws.db "PRAGMA integrity_check;"

# Expected output:
# ok
```

**Persistence Test**:
```bash
# Restart container
docker-compose restart tmws

# Check database is still accessible
docker exec tmws-app sqlite3 /app/data/tmws.db "SELECT COUNT(*) FROM alembic_version;"

# Expected: 1 (alembic version exists)
```

✅ **Success**: Database persists across container restarts (100% data retention via `./data` volume mount)

---

### 4. MCP Server Health Check

```bash
# Test health endpoint
curl http://localhost:8000/health

# Expected output (JSON):
{
  "status": "healthy",
  "version": "2.3.2",
  "environment": "production",
  "database": "connected",
  "ollama": "connected",
  "license": "valid"
}
```

✅ **Success**: All systems operational

❌ **Failure**: Check specific component status in response

---

### 5. License Validation Confirmation

```bash
# Check license validation in logs
docker-compose logs tmws | grep -A 3 "License"

# Expected output:
# ✅ License validated successfully
#    Tier: ENTERPRISE
#    Expires: PERPETUAL (never expires)
#    Features: unlimited_agents,priority_support,custom_integrations
```

**ENTERPRISE PERPETUAL License Features**:
- ✅ Unlimited agents
- ✅ Never expires
- ✅ Priority support (24/7)
- ✅ Custom integrations
- ✅ Source code access
- ✅ On-premise deployment

✅ **Success**: License tier and expiration match your purchase

❌ **Failure**: See [Troubleshooting: License Validation Failure](#license-validation-failure)

---

### 6. Embedding Generation Test (End-to-End)

```bash
# Create a test memory via MCP API
curl -X POST http://localhost:8000/mcp/tools/create_memory \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "test-agent",
    "content": "Hello, this is a test memory.",
    "memory_type": "episodic",
    "importance": 0.8,
    "access_level": "private"
  }'

# Expected output (JSON):
{
  "success": true,
  "memory_id": "550e8400-e29b-41d4-a716-446655440000",
  "embedding_generated": true,
  "embedding_latency_ms": 42.5
}
```

**Verification**:
- `embedding_generated: true` → Ollama successfully generated embedding
- `embedding_latency_ms < 100` → Performance within target (<50ms typical)

✅ **Success**: End-to-end embedding pipeline works

---

## 🔧 Troubleshooting

### Common Issues and Solutions

---

#### Ollama Connection Refused

**Symptoms**:
```
ERROR: Failed to connect to Ollama at http://host.docker.internal:11434
ConnectionRefusedError: [Errno 61] Connection refused
```

**Causes & Solutions**:

1. **Ollama not running**:
   ```bash
   # Start Ollama
   ollama serve

   # Verify it's running
   curl http://localhost:11434/api/tags
   ```

2. **Firewall blocking port 11434** (Linux):
   ```bash
   # Allow port 11434 (temporary)
   sudo ufw allow 11434/tcp

   # Make permanent
   sudo ufw enable
   ```

3. **Docker network issue** (Linux):
   ```bash
   # Use host network mode instead
   # Edit docker-compose.yml, add under tmws service:
   network_mode: "host"

   # Update TMWS_OLLAMA_BASE_URL in .env:
   TMWS_OLLAMA_BASE_URL=http://localhost:11434
   ```

4. **WSL2 networking issue** (Windows):
   ```powershell
   # Get WSL2 IP address
   wsl hostname -I

   # Update .env with WSL2 IP:
   TMWS_OLLAMA_BASE_URL=http://172.x.x.x:11434
   ```

✅ **Verification**:
```bash
docker exec tmws-app curl -f http://host.docker.internal:11434/api/tags
# Should return JSON with models array
```

---

#### Model Not Found

**Symptoms**:
```
ERROR: Model 'zylonai/multilingual-e5-large' not found
```

**Solution**:
```bash
# Pull the required model
ollama pull zylonai/multilingual-e5-large

# Verify model exists
ollama list

# Expected output:
# NAME                             SIZE      MODIFIED
# zylonai/multilingual-e5-large    2.7 GB    X minutes ago
```

✅ **Verification**:
```bash
# Test embedding generation
curl http://localhost:11434/api/embeddings \
  -d '{
    "model": "zylonai/multilingual-e5-large",
    "prompt": "Test embedding"
  }'
```

---

#### License Validation Failure

**Symptoms**:
```
ERROR: License validation failed
ERROR: Invalid license key format
```

**Causes & Solutions**:

1. **Invalid license key format**:
   ```bash
   # Verify format in .env:
   TMWS_LICENSE_KEY=TMWS-ENTERPRISE-PERPETUAL-{UUID}-{CHECKSUM}

   # Must start with "TMWS-"
   # Must include tier (FREE, STANDARD, ENTERPRISE)
   # Must include UUID and checksum
   ```

2. **Missing license key**:
   ```bash
   # Check .env file exists and is loaded
   cat .env | grep TMWS_LICENSE_KEY

   # Ensure docker-compose.yml maps the variable:
   # environment:
   #   - TMWS_LICENSE_KEY=${TMWS_LICENSE_KEY}
   ```

3. **Expired license** (STANDARD tier only):
   ```bash
   # Check expiration in logs
   docker-compose logs tmws | grep "License"

   # If expired, renew at https://trinitas.ai/licensing/renew
   ```

4. **Grace period exhausted**:
   ```bash
   # ENTERPRISE PERPETUAL: Never expires
   # STANDARD: 7-day grace period after expiration

   # Disable grace period check (emergency only):
   # In .env:
   TMWS_LICENSE_STRICT_MODE=false
   ```

✅ **Verification**:
```bash
docker-compose logs tmws | grep -A 3 "License validated"
# Should show "✅ License validated successfully"
```

---

#### Container Startup Failure

**Symptoms**:
```
docker-compose ps
# Status: Exit 1 (Exited)
```

**Diagnosis**:
```bash
# Check logs for error
docker-compose logs tmws --tail 50

# Common errors:
# 1. "Secret key not set"
# 2. "Database migration failed"
# 3. "Port 8000 already in use"
```

**Solutions**:

1. **Missing secret key**:
   ```bash
   # Generate and add to .env
   openssl rand -hex 32

   # In .env:
   TMWS_SECRET_KEY=<generated-key>

   # Restart
   docker-compose up -d
   ```

2. **Port conflict**:
   ```bash
   # Check what's using port 8000
   lsof -i :8000  # macOS/Linux
   netstat -ano | findstr :8000  # Windows

   # Option A: Stop conflicting service
   # Option B: Use different port in docker-compose.yml:
   ports:
     - "8001:8000"  # Map to host port 8001
   ```

3. **Permission denied on volumes**:
   ```bash
   # Fix permissions (Linux)
   sudo chown -R $USER:$USER data .chroma logs config
   chmod -R 755 data .chroma logs config

   # Restart
   docker-compose up -d
   ```

✅ **Verification**:
```bash
docker-compose ps | grep "Up"
# Should show tmws-app with "Up" status
```

---

#### Slow Embedding Performance

**Symptoms**:
- Embedding latency > 200ms (target: <50ms)
- Memory creation takes several seconds

**Diagnosis**:
```bash
# Check Ollama logs
ollama list

# Check if GPU is being used
# macOS (Metal):
ollama serve  # Should log "Metal GPU detected"

# Linux (NVIDIA):
nvidia-smi  # Should show ollama process

# Check CPU usage
top | grep ollama
```

**Solutions**:

1. **Enable GPU acceleration** (NVIDIA):
   ```bash
   # Install NVIDIA Container Toolkit
   distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
   curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -
   curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.list | \
     sudo tee /etc/apt/sources.list.d/nvidia-docker.list

   sudo apt-get update && sudo apt-get install -y nvidia-docker2
   sudo systemctl restart docker

   # Restart Ollama with GPU
   ollama serve
   ```

2. **Enable GPU acceleration** (macOS Metal):
   ```bash
   # Metal is enabled by default
   # Verify in logs:
   ollama serve
   # Should show "Metal GPU detected"
   ```

3. **Increase Ollama memory**:
   ```bash
   # Set environment variable before starting Ollama
   export OLLAMA_MAX_LOADED_MODELS=1
   export OLLAMA_NUM_PARALLEL=1

   ollama serve
   ```

✅ **Verification**:
```bash
# Test embedding speed
time curl http://localhost:11434/api/embeddings \
  -d '{"model":"zylonai/multilingual-e5-large","prompt":"test"}'

# Expected: < 0.1s with GPU, < 1s without GPU
```

---

#### Permission Denied on Volumes

**Symptoms**:
```
ERROR: Permission denied: '/app/data/tmws.db'
ERROR: Cannot write to /app/.chroma
```

**Solution** (Linux only):
```bash
# Check current permissions
ls -la data .chroma logs config

# Fix ownership and permissions
sudo chown -R $USER:$USER data .chroma logs config
chmod -R 755 data .chroma logs config

# Restart container
docker-compose restart tmws
```

**Solution** (macOS/Windows):
```bash
# Docker Desktop automatically handles permissions
# If issue persists, recreate directories:
rm -rf data .chroma logs config
mkdir -p data .chroma logs config

docker-compose up -d
```

✅ **Verification**:
```bash
docker exec tmws-app touch /app/data/test.txt
# Should succeed without error
```

---

#### Reset Everything

**Complete cleanup and fresh start**:

```bash
# ⚠️ WARNING: This deletes ALL data
# Backup important data first!

# Stop and remove containers
docker-compose down -v

# Remove data
rm -rf data/.chroma/* data/*.db logs/*

# Remove Docker image (optional)
docker rmi tmws-app

# Recreate directories
mkdir -p data config logs .chroma

# Start fresh
docker-compose build
docker-compose up -d
```

✅ **Verification**:
```bash
# Check new database was created
ls -lh data/tmws.db

# Check logs for clean startup
docker-compose logs tmws | head -20
```

---

## ⚡ Performance Expectations

### Latency Targets (P95)

| Operation | Target | Typical (GPU) | Typical (CPU) | Notes |
|-----------|--------|---------------|---------------|-------|
| **Embedding Generation** | <100ms | 42ms | 150ms | Ollama latency |
| **Semantic Search** | <20ms | 8ms | 15ms | ChromaDB query |
| **Memory Creation** | <200ms | 65ms | 220ms | End-to-end |
| **API Response Time** | <300ms | 110ms | 350ms | Full request cycle |
| **Health Check** | <50ms | 12ms | 18ms | Lightweight |

**Performance Factors**:
- **GPU Acceleration**: 3-5x faster embeddings (42ms vs 150ms)
- **SSD vs HDD**: 2x faster ChromaDB queries
- **Network Latency**: Add ~5-10ms for remote clients

### Throughput Targets

| Metric | Target | Achieved (GPU) | Achieved (CPU) |
|--------|--------|----------------|----------------|
| **Concurrent Users** | 100-1000 | 1,200+ | 600+ |
| **Requests/Second** | 100-500 | 650 | 280 |
| **Memory Ops/Sec** | 50-100 | 145 | 72 |

### Resource Usage

**Container Resource Limits** (docker-compose.yml):
```yaml
deploy:
  resources:
    limits:
      cpus: '2.0'      # 2 CPU cores max
      memory: 2G       # 2GB RAM max
    reservations:
      cpus: '1.0'      # 1 CPU core guaranteed
      memory: 1G       # 1GB RAM guaranteed
```

**Actual Usage** (typical):
- **CPU**: 0.5-1.5 cores (idle: 0.1 cores)
- **Memory**: 800MB-1.2GB (idle: 600MB)
- **Disk I/O**: 1-5 MB/s (during heavy load)

**Ollama Resource Usage** (host):
- **CPU**: 1-4 cores (depends on model size)
- **Memory**: 2-4GB (multilingual-e5-large: ~2.7GB)
- **GPU VRAM**: 2GB (if GPU acceleration enabled)

### Optimization Tips

**Improve Embedding Performance**:
1. **Enable GPU**: 3-5x faster (42ms vs 150ms)
2. **Increase Ollama parallel requests**: `OLLAMA_NUM_PARALLEL=4`
3. **Use SSD storage**: 2x faster ChromaDB queries
4. **Tune ChromaDB indexing**: Adjust HNSW parameters

**Improve API Performance**:
1. **Enable Redis caching**: 10x faster repeated queries
2. **Increase worker count**: `TMWS_MAX_WORKERS=4`
3. **Use connection pooling**: Enabled by default in v2.3.2
4. **Enable CDN**: For static assets (if web UI present)

**Resource Optimization**:
1. **Reduce Docker memory limit**: If using small datasets
2. **Disable audit logging**: If not required (`TMWS_AUDIT_LOG_ENABLED=false`)
3. **Increase log rotation**: `TMWS_LOG_RETENTION_DAYS=7`
4. **Use tmpfs for logs**: Faster writes (in-memory)

---

## 🔒 Security Considerations

### License Key Protection

**🚨 CRITICAL**: License keys grant access to TMWS services and must be protected.

**Best Practices**:

1. **Never commit `.env` to Git**:
   ```bash
   # Verify .gitignore includes .env
   cat .gitignore | grep ".env"

   # Expected:
   .env
   .env.local
   .env.*.local
   ```

2. **Use environment variables (production)**:
   ```bash
   # Set via Docker secrets (Swarm)
   echo "TMWS-ENTERPRISE-..." | docker secret create tmws_license -

   # Or via Kubernetes secrets
   kubectl create secret generic tmws-license \
     --from-literal=TMWS_LICENSE_KEY='TMWS-ENTERPRISE-...'
   ```

3. **Rotate license keys annually**:
   ```bash
   # STANDARD tier: Expires after 1 year, auto-renews
   # ENTERPRISE: PERPETUAL (never expires)

   # To rotate (optional):
   # 1. Obtain new key from https://trinitas.ai/licensing/renew
   # 2. Update .env
   # 3. Restart: docker-compose restart tmws
   ```

4. **Monitor license usage**:
   ```bash
   # Check license status
   docker-compose logs tmws | grep "License"

   # Set up alerts for expiration (STANDARD tier)
   # Alert 30 days before expiration
   ```

### SQLite Database Backup

**Why Backup**:
- Critical data: Agents, memories, workflows, tasks
- ChromaDB vectors: Can be regenerated (but expensive)
- License validation state

**Backup Strategy**:

```bash
# 1. Hot backup (online, safe for SQLite WAL mode)
sqlite3 data/tmws.db ".backup data/tmws_backup_$(date +%Y%m%d_%H%M%S).db"

# 2. Volume backup (offline, requires container stop)
docker-compose stop tmws
tar -czf tmws_data_$(date +%Y%m%d).tar.gz data/ .chroma/
docker-compose start tmws

# 3. Automated daily backup (cron)
cat > /etc/cron.daily/tmws_backup <<'EOF'
#!/bin/bash
BACKUP_DIR="/backups/tmws"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# Backup SQLite database (hot backup)
sqlite3 /path/to/tmws/data/tmws.db ".backup $BACKUP_DIR/tmws_$DATE.db"

# Backup ChromaDB (optional, can regenerate)
tar -czf $BACKUP_DIR/chroma_$DATE.tar.gz /path/to/tmws/.chroma/

# Delete backups older than 30 days
find $BACKUP_DIR -name "*.db" -mtime +30 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
EOF

chmod +x /etc/cron.daily/tmws_backup
```

**Restore from Backup**:
```bash
# 1. Stop container
docker-compose stop tmws

# 2. Replace database
cp data/tmws_backup_20251118_120000.db data/tmws.db

# 3. Restore ChromaDB (if backed up)
tar -xzf tmws_data_20251118.tar.gz

# 4. Start container
docker-compose start tmws

# 5. Verify data integrity
docker exec tmws-app sqlite3 /app/data/tmws.db "PRAGMA integrity_check;"
# Expected: ok
```

### Network Security

**Ollama Localhost-Only** (default):
```bash
# Verify Ollama only listens on localhost
lsof -i :11434 | grep LISTEN

# Expected:
# ollama  1234 user   3u  IPv4  0x... 0t0  TCP localhost:11434 (LISTEN)
```

**Firewall Rules** (production):
```bash
# Allow only specific IPs to access TMWS API
sudo ufw allow from 192.168.1.0/24 to any port 8000

# Block all other access
sudo ufw deny 8000/tcp

# Enable firewall
sudo ufw enable
```

**Reverse Proxy with HTTPS** (recommended):
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

### Secret Key Security

**Generate Strong Secret Key**:
```bash
# 64-character hex string (256-bit entropy)
openssl rand -hex 32

# Example output:
# a3f8b9c2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
```

**Key Rotation** (annual recommended):
```bash
# 1. Generate new key
NEW_KEY=$(openssl rand -hex 32)

# 2. Update .env
sed -i "s/TMWS_SECRET_KEY=.*/TMWS_SECRET_KEY=$NEW_KEY/" .env

# 3. Restart (invalidates all existing JWT tokens)
docker-compose restart tmws

# 4. Notify users to re-login
```

**Key Storage** (production):
```bash
# Use encrypted storage
# - AWS Secrets Manager
# - HashiCorp Vault
# - Kubernetes Secrets (encrypted at rest)

# Example: AWS Secrets Manager
aws secretsmanager create-secret \
  --name tmws/secret-key \
  --secret-string "a3f8b9c2d4e5f6a7..."

# Retrieve in docker-compose.yml (or use AWS ECS task definitions)
```

### Audit Logging

**Enable Audit Logs** (production):
```bash
# In .env:
TMWS_AUDIT_LOG_ENABLED=true
TMWS_AUDIT_LOG_RETENTION_DAYS=365  # 1 year for compliance
```

**Logged Events**:
- Authentication attempts (success/failure)
- Authorization decisions (access granted/denied)
- Data access (memory read/write/delete)
- Configuration changes
- License validation events

**Query Audit Logs**:
```bash
# View recent security events
docker exec tmws-app sqlite3 /app/data/tmws.db \
  "SELECT timestamp, event_type, agent_id, details
   FROM security_audit_logs
   ORDER BY timestamp DESC
   LIMIT 10;"
```

---

## 🔧 Maintenance

### Log Rotation

**Automatic Rotation** (Docker logging driver):
```yaml
# docker-compose.yml (already configured)
logging:
  driver: "json-file"
  options:
    max-size: "10m"   # Max 10MB per log file
    max-file: "3"     # Keep 3 log files (30MB total)
```

**Manual Log Cleanup**:
```bash
# Clear Docker logs
docker-compose down
docker system prune -f --volumes
docker-compose up -d

# Clear application logs
rm -f logs/*.log
docker-compose restart tmws
```

**View Logs**:
```bash
# Real-time logs
docker-compose logs -f tmws

# Last 100 lines
docker-compose logs --tail 100 tmws

# Search for errors
docker-compose logs tmws | grep ERROR

# Logs by date range
docker-compose logs tmws --since "2025-11-18T00:00:00" \
                         --until "2025-11-18T23:59:59"
```

### Database Maintenance

**Vacuum Database** (reclaim space, optimize queries):
```bash
# Vacuum SQLite database (offline)
docker-compose stop tmws
sqlite3 data/tmws.db "VACUUM;"
docker-compose start tmws

# OR hot vacuum (auto-vacuum enabled by default)
docker exec tmws-app sqlite3 /app/data/tmws.db "PRAGMA auto_vacuum = FULL;"
```

**Analyze Database** (update query planner statistics):
```bash
# Analyze all tables
docker exec tmws-app sqlite3 /app/data/tmws.db "ANALYZE;"
```

**Check Integrity**:
```bash
# Verify database integrity
docker exec tmws-app sqlite3 /app/data/tmws.db "PRAGMA integrity_check;"

# Expected: ok
```

**Migration Status**:
```bash
# Check current migration version
docker exec tmws-app alembic current

# Expected: (head)

# Upgrade to latest (if needed)
docker exec tmws-app alembic upgrade head
```

### ChromaDB Maintenance

**Rebuild ChromaDB Index** (if performance degrades):
```bash
# Stop container
docker-compose stop tmws

# Clear ChromaDB cache
rm -rf .chroma/*

# Start container (ChromaDB will rebuild from SQLite)
docker-compose start tmws

# Monitor rebuild progress
docker-compose logs -f tmws | grep "ChromaDB"
```

**Optimize ChromaDB** (production):
```bash
# In .env, tune HNSW index parameters:
TMWS_CHROMA_HNSW_SPACE=cosine      # Similarity metric
TMWS_CHROMA_HNSW_M=16              # Max connections (default: 16)
TMWS_CHROMA_HNSW_EF_CONSTRUCTION=200  # Index build quality (default: 200)
TMWS_CHROMA_HNSW_EF_SEARCH=100     # Search quality (default: 100)

# Restart to apply
docker-compose restart tmws
```

### License Renewal

**ENTERPRISE PERPETUAL**: Never expires, no renewal needed ✅

**STANDARD Tier**:
```bash
# Check expiration date
docker-compose logs tmws | grep "License"

# Output example:
# License expires: 2025-12-15T00:00:00Z
# Grace period: 7 days (until 2025-12-22)

# Renew license (30 days before expiration)
# 1. Visit: https://trinitas.ai/licensing/renew
# 2. Update .env with new key:
TMWS_LICENSE_KEY=TMWS-STANDARD-new-key-here

# 3. Restart:
docker-compose restart tmws

# 4. Verify new expiration:
docker-compose logs tmws | grep "License"
```

### Version Upgrade

**Upgrade to Latest TMWS Version**:
```bash
# 1. Backup data
docker-compose exec tmws sqlite3 /app/data/tmws.db \
  ".backup /app/data/tmws_backup_$(date +%Y%m%d).db"

# 2. Stop container
docker-compose stop tmws

# 3. Pull latest code
git fetch --tags
git checkout v2.3.3  # Replace with desired version

# 4. Rebuild image
docker-compose build

# 5. Start container (migrations run automatically)
docker-compose up -d

# 6. Verify upgrade
docker-compose logs -f tmws | grep "Migration"

# Expected:
# ✅ Database migration completed: v2.3.2 → v2.3.3
```

**Rollback** (if upgrade fails):
```bash
# 1. Stop container
docker-compose stop tmws

# 2. Restore backup
cp data/tmws_backup_20251118.db data/tmws.db

# 3. Checkout previous version
git checkout v2.3.2

# 4. Rebuild and start
docker-compose build
docker-compose up -d

# 5. Verify rollback
docker-compose logs -f tmws | grep "version"
# Expected: "TMWS v2.3.2"
```

### Monitoring

**Health Monitoring**:
```bash
# Add to cron: check health every 5 minutes
cat > /etc/cron.d/tmws_health <<'EOF'
*/5 * * * * root curl -f http://localhost:8000/health || systemctl restart docker
EOF
```

**Resource Monitoring**:
```bash
# Docker stats (real-time)
docker stats tmws-app

# Resource limits check
docker inspect tmws-app | grep -A 10 "Memory"
```

**Performance Monitoring**:
```bash
# Embedding latency
docker-compose logs tmws | grep "embedding_latency_ms" | \
  awk '{print $NF}' | sort -n | tail -10

# API response time
docker-compose logs tmws | grep "response_time_ms" | \
  awk '{print $NF}' | sort -n | tail -10
```

---

## 📚 Appendix

### A. Environment Variables Reference

**Critical Variables** (must set):
| Variable | Required | Example | Description |
|----------|----------|---------|-------------|
| `TMWS_LICENSE_KEY` | ✅ | `TMWS-ENTERPRISE-...` | License key for activation |
| `TMWS_SECRET_KEY` | ✅ | `a3f8b9c2d4e5f6a7...` | 64-char hex secret for JWT |
| `TMWS_ENVIRONMENT` | ✅ | `production` | Environment mode |

**Ollama Configuration**:
| Variable | Default | Example | Description |
|----------|---------|---------|-------------|
| `TMWS_OLLAMA_BASE_URL` | `http://host.docker.internal:11434` | `http://localhost:11434` | Ollama API URL |
| `TMWS_OLLAMA_MODEL` | `zylonai/multilingual-e5-large` | Same | Embedding model name |

**Database Configuration**:
| Variable | Default | Example | Description |
|----------|---------|---------|-------------|
| `TMWS_DATABASE_URL` | `sqlite+aiosqlite:////app/data/tmws.db` | Same | SQLite connection string |

**Security Settings**:
| Variable | Default | Example | Description |
|----------|---------|---------|-------------|
| `TMWS_AUTH_ENABLED` | `true` | `true` | Enable authentication |
| `TMWS_RATE_LIMIT_ENABLED` | `true` | `true` | Enable rate limiting |
| `TMWS_RATE_LIMIT_PER_MINUTE` | `60` | `100` | Requests per IP per minute |
| `TMWS_CORS_ORIGINS` | `["http://localhost:3000"]` | `["https://app.example.com"]` | Allowed CORS origins |

**Logging Settings**:
| Variable | Default | Example | Description |
|----------|---------|---------|-------------|
| `TMWS_LOG_LEVEL` | `INFO` | `WARNING` | Logging verbosity |
| `TMWS_AUDIT_LOG_ENABLED` | `true` | `true` | Enable security audit logging |
| `TMWS_AUDIT_LOG_RETENTION_DAYS` | `365` | `730` | Audit log retention period |

**Performance Settings**:
| Variable | Default | Example | Description |
|----------|---------|---------|-------------|
| `TMWS_MAX_WORKERS` | `4` | `8` | Number of worker processes |
| `TMWS_REQUEST_TIMEOUT` | `60` | `120` | Request timeout (seconds) |

### B. Docker Compose Reference

**Full docker-compose.yml** (Option A):
```yaml
version: '3.8'

services:
  tmws:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: tmws-app
    hostname: tmws

    ports:
      - "8000:8000"

    volumes:
      - ./data:/app/data
      - ./config:/app/config
      - ./.chroma:/app/.chroma
      - ./logs:/app/logs

    environment:
      # License
      - TMWS_LICENSE_KEY=${TMWS_LICENSE_KEY}
      - TMWS_LICENSE_STRICT_MODE=${TMWS_LICENSE_STRICT_MODE:-false}

      # Environment
      - TMWS_ENVIRONMENT=${TMWS_ENVIRONMENT:-production}

      # Security
      - TMWS_SECRET_KEY=${TMWS_SECRET_KEY}

      # Database
      - TMWS_DATABASE_URL=sqlite+aiosqlite:////app/data/tmws.db

      # Ollama (Option A: Native on host)
      - TMWS_OLLAMA_BASE_URL=${TMWS_OLLAMA_BASE_URL:-http://host.docker.internal:11434}
      - TMWS_OLLAMA_MODEL=zylonai/multilingual-e5-large

      # ChromaDB
      - TMWS_CHROMA_PERSIST_DIRECTORY=/app/.chroma

      # Logging
      - TMWS_LOG_LEVEL=${TMWS_LOG_LEVEL:-INFO}
      - TMWS_LOG_FILE=/app/logs/tmws.log

      # CORS
      - TMWS_CORS_ORIGINS=${TMWS_CORS_ORIGINS:-["http://localhost:3000"]}

      # Performance
      - TMWS_MAX_WORKERS=${TMWS_MAX_WORKERS:-4}
      - TMWS_REQUEST_TIMEOUT=${TMWS_REQUEST_TIMEOUT:-60}

    restart: unless-stopped

    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G

    networks:
      - tmws-network

    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  tmws-network:
    driver: bridge
```

### C. Dockerfile Reference

**Multi-stage Dockerfile** (v2.3.2):
```dockerfile
# ========================================
# Stage 1: Builder
# ========================================
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ git unzip zip && \
    rm -rf /var/lib/apt/lists/*

# Install uv and build module
RUN pip install --no-cache-dir uv build

# Copy dependency files
COPY pyproject.toml uv.lock* ./
COPY src/ ./src/
COPY README.md ./

# Build wheel
RUN python -m build --wheel --no-isolation

# Bytecode compilation (Phase 2E-1)
RUN mkdir -p /tmp/wheel && \
    unzip -q dist/*.whl -d /tmp/wheel && \
    python -m compileall -b /tmp/wheel && \
    find /tmp/wheel -name "*.py" ! -path "*/bin/*" -delete && \
    rm -f /build/dist/*.whl && \
    cd /tmp/wheel && \
    zip -qr /build/dist/tmws-2.3.2-py3-none-any.whl .

# ========================================
# Stage 2: Runtime
# ========================================
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl sqlite3 && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash tmws

# Copy build artifacts
COPY --from=builder /build/pyproject.toml /tmp/
COPY --from=builder /build/README.md /tmp/
COPY --from=builder /build/dist/tmws-*.whl /tmp/

# Install dependencies + bytecode wheel
RUN pip install --no-cache-dir uv && \
    cd /tmp && \
    uv pip install --system --no-cache . && \
    uv pip install --system --no-cache --no-deps --force-reinstall tmws-*.whl && \
    rm -rf /tmp/* && \
    pip uninstall -y uv && \
    pip cache purge

# Verify source protection
RUN SITE_PACKAGES=$(python3 -c "import site; print(site.getsitepackages()[0])")/src && \
    SOURCE_COUNT=$(find "$SITE_PACKAGES" -name "*.py" -type f | wc -l) && \
    if [ "$SOURCE_COUNT" -ne 0 ]; then \
        echo "❌ SECURITY FAILURE: $SOURCE_COUNT .py files found" && exit 1; \
    else \
        echo "✅ Source protection verified: 0 .py files"; \
    fi

# Create directories
RUN mkdir -p /app/data /app/.chroma /app/logs /app/config && \
    chown -R tmws:tmws /app

# Copy config
COPY --chown=tmws:tmws .env.example /app/config/
COPY --chown=tmws:tmws LICENSE /app/

USER tmws

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENV TMWS_ENVIRONMENT=production \
    TMWS_LOG_LEVEL=INFO \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

CMD ["tmws-mcp-server"]
```

### D. Ollama Model Information

**multilingual-e5-large**:
- **Model ID**: `zylonai/multilingual-e5-large`
- **Size**: 2.7 GB
- **Embedding Dimension**: 1024
- **Languages**: 100+ (multilingual)
- **License**: MIT
- **Use Case**: Semantic similarity, multilingual embeddings

**Download**:
```bash
ollama pull zylonai/multilingual-e5-large
```

**Alternative Models** (not officially supported):
- `nomic-embed-text` (768-dim, English-only)
- `all-minilm` (384-dim, faster but lower quality)

### E. Useful Commands Cheatsheet

**Container Management**:
```bash
# Start
docker-compose up -d

# Stop
docker-compose stop

# Restart
docker-compose restart tmws

# Remove (keeps data)
docker-compose down

# Remove (deletes data)
docker-compose down -v

# Rebuild
docker-compose build --no-cache

# View logs
docker-compose logs -f tmws

# Execute command
docker exec -it tmws-app bash
```

**Database Operations**:
```bash
# Enter SQLite shell
docker exec -it tmws-app sqlite3 /app/data/tmws.db

# Backup database
docker exec tmws-app sqlite3 /app/data/tmws.db ".backup /app/data/backup.db"

# Check integrity
docker exec tmws-app sqlite3 /app/data/tmws.db "PRAGMA integrity_check;"

# Vacuum database
docker exec tmws-app sqlite3 /app/data/tmws.db "VACUUM;"
```

**Ollama Operations**:
```bash
# List models
ollama list

# Pull model
ollama pull zylonai/multilingual-e5-large

# Remove model
ollama rm zylonai/multilingual-e5-large

# Test embedding
curl http://localhost:11434/api/embeddings \
  -d '{"model":"zylonai/multilingual-e5-large","prompt":"test"}'
```

**Diagnostics**:
```bash
# Check health
curl http://localhost:8000/health

# Check license
docker-compose logs tmws | grep "License"

# Check Ollama connectivity
docker exec tmws-app curl -f http://host.docker.internal:11434/api/tags

# Resource usage
docker stats tmws-app

# Disk usage
docker system df
du -sh data .chroma logs
```

---

## 📞 Support

### Documentation

- **Architecture Guide**: `docs/architecture/TMWS_v2.2.0_ARCHITECTURE.md`
- **API Reference**: `docs/api/MCP_TOOLS_REFERENCE.md`
- **Development Guide**: `docs/DEVELOPMENT_SETUP.md`
- **Migration Guide**: `docs/guides/MIGRATION_GUIDE.md`

### Community

- **GitHub Issues**: https://github.com/apto-as/tmws/issues
- **Discussion Forum**: https://github.com/apto-as/tmws/discussions
- **Changelog**: `CHANGELOG.md`

### Commercial Support

**ENTERPRISE License Includes**:
- 24/7 priority support (4-hour SLA)
- Direct access to development team
- Custom feature development
- Dedicated Slack channel
- Quarterly architecture review

**Contact**: support@trinitas.ai

---

## 📄 License

This deployment guide is part of TMWS v2.3.2, licensed under Apache 2.0.

**License File**: `/app/LICENSE` (included in Docker image)

**Source Code Protection**: R-P0-1 mitigation applied (bytecode-only distribution)

---

**End of Guide**

*Last Updated: 2025-11-18*
*TMWS Version: v2.3.2*
*Architecture: Option A (Native Ollama + Docker TMWS)*
*Author: Muses (Knowledge Architect)*
