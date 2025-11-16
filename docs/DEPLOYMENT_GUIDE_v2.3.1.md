# TMWS v2.3.1 Production Deployment Guide
**Docker-First Deployment with SQLite + ChromaDB Architecture**

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Quick Start (Docker)](#quick-start-docker)
5. [Production Deployment](#production-deployment)
6. [Security Configuration](#security-configuration)
7. [Monitoring & Observability](#monitoring--observability)
8. [Backup & Recovery](#backup--recovery)
9. [Scaling](#scaling)
10. [Troubleshooting](#troubleshooting)

---

## Overview

TMWS v2.3.1 uses a **simplified architecture**:
- **Database**: SQLite with WAL mode (concurrent reads)
- **Vector Store**: ChromaDB (embedded DuckDB backend)
- **Embedding Service**: Ollama (multilingual-e5-large model)

This eliminates the need for PostgreSQL and Redis, simplifying deployment while maintaining production-grade performance for <1000 concurrent users.

---

## Architecture

### v2.3.1 Deployment Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Production Deployment                       │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │      TMWS Docker Container (tmws-app)            │  │
│  │                                                   │  │
│  │  ┌────────────────────────────────────────────┐  │  │
│  │  │  MCP Server (FastAPI)                      │  │  │
│  │  │  - Port 8000 (HTTP/REST API)               │  │  │
│  │  │  - Health endpoint: /health                │  │  │
│  │  └────────────────────────────────────────────┘  │  │
│  │                       │                          │  │
│  │  ┌──────────────┬────▼───────────────┐          │  │
│  │  │   SQLite DB  │  ChromaDB Vectors  │          │  │
│  │  │  (ACID, WAL) │  (1024-dim E5)     │          │  │
│  │  │  /app/data/  │  /app/.chroma/     │          │  │
│  │  └──────────────┴────────────────────┘          │  │
│  │                                                   │  │
│  └──────────────────────────────────────────────────┘  │
│                       │                                 │
│                       ▼                                 │
│  ┌─────────────────────────────────────┐               │
│  │  Ollama Embedding Service            │               │
│  │  (host.docker.internal:11434)        │               │
│  │  - Model: zylonai/multilingual-e5    │               │
│  │  - 1024 dimensions                   │               │
│  └─────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────┘
```

### Key Differences from v2.2.x

| Component | v2.2.x | v2.3.1 |
|-----------|--------|--------|
| **Primary Database** | PostgreSQL + pgvector | SQLite (WAL mode) |
| **Cache Layer** | Redis | ChromaDB in-memory cache |
| **Vector Search** | pgvector | ChromaDB (DuckDB) |
| **Embedding Service** | SentenceTransformers (fallback) | Ollama (required) |
| **Deployment Complexity** | High (3 services) | Low (1 service + Ollama) |

**Migration**: See [MIGRATION_GUIDE_v2.3.md](./MIGRATION_GUIDE_v2.3.md) if upgrading from v2.2.x

---

## Prerequisites

### System Requirements

**Minimum** (development/testing):
- CPU: 2 cores
- RAM: 2GB
- Disk: 10GB SSD
- OS: Docker Desktop (Windows/Mac/Linux)

**Recommended** (production <100 users):
- CPU: 4 cores
- RAM: 8GB
- Disk: 50GB SSD
- OS: Ubuntu 22.04 LTS / macOS 14+ / Windows Server 2022

**Large Deployments** (100-1000 users):
- CPU: 8 cores
- RAM: 16GB
- Disk: 100GB SSD
- Network: 1Gbps

### Software Dependencies

| Component | Minimum Version | Installation |
|-----------|----------------|--------------|
| **Docker** | 24.0 | [Get Docker](https://docs.docker.com/get-docker/) |
| **Docker Compose** | 2.20 | Included with Docker Desktop |
| **Ollama** | 0.1.0 | [Get Ollama](https://ollama.ai/download) |

**Ollama Setup**:
```bash
# 1. Install Ollama (see https://ollama.ai/download)
# Mac: brew install ollama
# Linux: curl -fsSL https://ollama.ai/install.sh | sh
# Windows: Download installer

# 2. Start Ollama server
ollama serve  # Default port: 11434

# 3. Pull embedding model (1.1GB download)
ollama pull zylonai/multilingual-e5-large
```

---

## Quick Start (Docker)

**5-Minute Setup** (using Docker Compose):

### Step 1: Clone Repository
```bash
git clone https://github.com/apto-as/tmws.git
cd tmws
```

### Step 2: Configure Environment
```bash
# Copy example environment file
cp .env.example .env

# Generate secret key
openssl rand -hex 32

# Edit .env and set TMWS_SECRET_KEY
nano .env  # or your preferred editor
```

**Required `.env` changes**:
```bash
# Set your unique secret key (from openssl above)
TMWS_SECRET_KEY=your_generated_64_character_hex_string

# Set allowed CORS origins (replace with your domain)
TMWS_CORS_ORIGINS=["http://localhost:3000","https://yourdomain.com"]
```

### Step 3: Start Services
```bash
# Build and start TMWS container
docker-compose up -d

# Verify container is running
docker-compose ps

# Check logs
docker-compose logs -f tmws
```

Expected output:
```
tmws-app  | INFO: Started TMWS MCP Server on http://0.0.0.0:8000
tmws-app  | INFO: Listening for MCP protocol on stdio
```

### Step 4: Verify Installation
```bash
# Test health endpoint
curl http://localhost:8000/health

# Expected response:
# {"status":"ok","version":"2.3.1"}
```

**Success!** TMWS is now running on `http://localhost:8000`

---

## Production Deployment

### Option A: Native Ollama + TMWS Docker (RECOMMENDED)

**Best for**: Single-server deployments, development, testing

**Advantages**:
- ✅ Simple setup (no GPU passthrough)
- ✅ Better performance (native Ollama)
- ✅ Easier troubleshooting

**Steps**:

1. **Install Ollama on host** (see Prerequisites)

2. **Configure docker-compose.yml**:
   ```yaml
   services:
     tmws:
       environment:
         # Use host Ollama
         - TMWS_OLLAMA_BASE_URL=http://host.docker.internal:11434
   ```

3. **Start Ollama** (in separate terminal):
   ```bash
   ollama serve
   ```

4. **Pull model**:
   ```bash
   ollama pull zylonai/multilingual-e5-large
   ```

5. **Start TMWS**:
   ```bash
   docker-compose up -d
   ```

### Option B: Both in Docker (Advanced)

**Best for**: Kubernetes, Docker Swarm, complete containerization

**Requirements**:
- GPU passthrough (NVIDIA Docker or WSL2 CUDA)
- More complex networking

**Steps**:

1. **Uncomment Ollama service** in `docker-compose.yml`:
   ```yaml
   services:
     ollama:
       image: ollama/ollama:latest
       # ... (see docker-compose.yml for full config)
   ```

2. **Update TMWS environment**:
   ```yaml
   services:
     tmws:
       environment:
         - TMWS_OLLAMA_BASE_URL=http://ollama:11434
       depends_on:
         - ollama
   ```

3. **Start both services**:
   ```bash
   docker-compose up -d
   ```

4. **Pull model inside container**:
   ```bash
   docker exec -it tmws-ollama ollama pull zylonai/multilingual-e5-large
   ```

---

## Security Configuration

### Essential Security Checklist

Before deploying to production, **verify all items**:

#### Environment Variables (.env)
- [x] **TMWS_SECRET_KEY**: Unique 64-character hex string (never reuse)
- [x] **TMWS_ENVIRONMENT**: Set to `production` (not `development`)
- [x] **TMWS_CORS_ORIGINS**: Restricted to your domain(s) (no `"*"`)
- [x] **TMWS_LOG_LEVEL**: Set to `INFO` or `WARNING` (not `DEBUG`)

#### Authentication & Authorization
- [x] **TMWS_AUTH_ENABLED**: Must be `true` in production
- [x] **TMWS_RATE_LIMIT_ENABLED**: Must be `true` (DDoS protection)
- [x] **TMWS_SECURITY_HEADERS_ENABLED**: Must be `true` (OWASP headers)
- [x] **TMWS_AUDIT_LOG_ENABLED**: Must be `true` (compliance)
- [x] **TMWS_NAMESPACE_ISOLATION_ENABLED**: Must be `true` (multi-tenant)

#### Container Security
- [x] **Non-root user**: Dockerfile uses `USER tmws` (UID 1000)
- [x] **Resource limits**: Set in `docker-compose.yml` (CPU/memory)
- [x] **No secrets in image**: Environment-based configuration
- [x] **Health checks**: Enabled for monitoring

### Fail-Secure Defaults

TMWS uses **fail-secure defaults** in `.env.example`:
- All security features **enabled** by default
- Production mode **enforced** unless explicitly changed
- Debug mode **disabled** (prevents information leakage)

**Security Score**: **100/100** (certified by Hestia, 2025-11-16)

See [WAVE3_SECURITY_AUDIT.md](../WAVE3_SECURITY_AUDIT.md) for full security assessment.

### HTTPS Configuration

**Production deployments MUST use HTTPS**. Options:

#### Option 1: Reverse Proxy (RECOMMENDED)
```
┌─────────────────┐
│   nginx/Traefik │  ← HTTPS termination (443)
│   (Reverse Proxy)│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   TMWS Container │  ← HTTP (8000, internal only)
└─────────────────┘
```

**nginx example**:
```nginx
server {
    listen 443 ssl http2;
    server_name tmws.yourdomain.com;

    ssl_certificate /etc/ssl/certs/tmws.crt;
    ssl_certificate_key /etc/ssl/private/tmws.key;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Option 2: Let's Encrypt (Certbot)
```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d tmws.yourdomain.com

# Auto-renewal (crontab)
0 12 * * * /usr/bin/certbot renew --quiet
```

### Firewall Configuration

**Recommended firewall rules**:
```bash
# Allow HTTPS only (block direct HTTP access)
sudo ufw allow 443/tcp
sudo ufw deny 8000/tcp  # Block direct access to TMWS

# Allow SSH (for management)
sudo ufw allow 22/tcp

# Enable firewall
sudo ufw enable
```

---

## Monitoring & Observability

### Health Checks

**Endpoint**: `GET /health`

**Response** (healthy):
```json
{
  "status": "ok",
  "version": "2.3.1",
  "database": "connected",
  "vector_store": "ready",
  "ollama": "available"
}
```

**Docker Compose built-in health check**:
```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 30s
```

### Logging

**Log Levels** (TMWS_LOG_LEVEL):
- `DEBUG`: Detailed debugging (development only)
- `INFO`: General information (recommended for production)
- `WARNING`: Warnings and errors only
- `ERROR`: Errors only
- `CRITICAL`: Critical failures only

**Access logs**:
```bash
# View real-time logs
docker-compose logs -f tmws

# Last 100 lines
docker-compose logs --tail=100 tmws

# Filter for errors
docker-compose logs tmws | grep ERROR
```

**Log persistence** (configure in docker-compose.yml):
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

**Centralized Logging** (optional):

- **ELK Stack** (Elasticsearch, Logstash, Kibana)
- **Splunk**
- **Datadog**
- **CloudWatch Logs** (AWS)

### Performance Metrics

**Key Metrics to Track**:

| Metric | Target | Warning | Critical |
|--------|--------|---------|----------|
| **API Response Time** (P95) | <200ms | >500ms | >1000ms |
| **Semantic Search** (P95) | <20ms | >50ms | >100ms |
| **Memory Usage** | <1.5GB | >2GB | >3GB |
| **CPU Usage** | <60% | >80% | >95% |
| **Error Rate** | <0.1% | >1% | >5% |

**Prometheus Integration** (future):
```yaml
# docker-compose.yml (TODO: v2.4.0)
services:
  tmws:
    environment:
      - TMWS_METRICS_ENABLED=true
      - TMWS_METRICS_PORT=9090
```

---

## Backup & Recovery

### What to Backup

**Essential**:
- [ ] SQLite database: `./data/tmws.db`
- [ ] ChromaDB vectors: `./.chroma/`
- [ ] Environment config: `.env` (store securely, contains secrets)

**Optional**:
- Logs: `./logs/` (if retention required for compliance)
- Application config: `docker-compose.yml` (if customized)

### Backup Strategy

#### Daily Automated Backup

**SQLite Backup Script**:
```bash
#!/bin/bash
# backup-tmws.sh

BACKUP_DIR="/backup/tmws"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup SQLite database (online backup)
sqlite3 ./data/tmws.db ".backup '$BACKUP_DIR/tmws_$DATE.db'"

# Backup ChromaDB (copy directory)
tar -czf "$BACKUP_DIR/chroma_$DATE.tar.gz" .chroma/

# Cleanup old backups (keep last 30 days)
find "$BACKUP_DIR" -name "tmws_*.db" -mtime +30 -delete
find "$BACKUP_DIR" -name "chroma_*.tar.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

**Schedule with cron**:
```bash
# Run daily at 2 AM
0 2 * * * /path/to/backup-tmws.sh >> /var/log/tmws-backup.log 2>&1
```

#### Cloud Backup (AWS S3 Example)

```bash
#!/bin/bash
# backup-to-s3.sh

# Run local backup first
/path/to/backup-tmws.sh

# Upload to S3
aws s3 sync /backup/tmws/ s3://your-bucket/tmws-backups/ \
  --storage-class STANDARD_IA \
  --exclude "*" \
  --include "tmws_*.db" \
  --include "chroma_*.tar.gz"
```

### Recovery Procedure

**Restore from backup**:
```bash
# 1. Stop TMWS
docker-compose down

# 2. Restore SQLite database
cp /backup/tmws/tmws_20250116_020000.db ./data/tmws.db

# 3. Restore ChromaDB
rm -rf .chroma/
tar -xzf /backup/tmws/chroma_20250116_020000.tar.gz

# 4. Verify permissions
chmod -R 755 data/ .chroma/

# 5. Restart TMWS
docker-compose up -d

# 6. Verify health
curl http://localhost:8000/health
```

**Disaster Recovery Time Objective (RTO)**: <15 minutes
**Recovery Point Objective (RPO)**: <24 hours (with daily backups)

---

## Scaling

### When to Scale

**Signs you need to scale**:
- ❌ API response time P95 >500ms consistently
- ❌ Memory usage >80% of container limit
- ❌ CPU usage >80% sustained for >5 minutes
- ❌ >100 concurrent users

### Vertical Scaling (Easier)

**Increase Docker container resources**:

```yaml
# docker-compose.yml
services:
  tmws:
    deploy:
      resources:
        limits:
          cpus: '4.0'      # Increased from 2.0
          memory: 4G       # Increased from 2G
        reservations:
          cpus: '2.0'
          memory: 2G
```

**Increase SQLite performance**:
```bash
# .env
TMWS_DB_POOL_SIZE=10       # Increased from 5
TMWS_DB_MAX_OVERFLOW=20    # Increased from 10
```

### Horizontal Scaling (Advanced)

**IMPORTANT**: SQLite is **not designed for horizontal scaling** (multiple writers).

**If you need horizontal scaling** (>1000 users):
1. Migrate to PostgreSQL backend (see [POSTGRESQL_MIGRATION_GUIDE.md](./dev/POSTGRESQL_MIGRATION_GUIDE.md))
2. Deploy multiple TMWS instances behind load balancer
3. Use shared PostgreSQL database + Redis cache

**Current Architecture Limits**:
- **Max concurrent users**: ~1000 (with vertical scaling)
- **Max memory storage**: Depends on disk space (100GB = ~10M memories)
- **Max vector search speed**: 5-20ms P95 (achieved in benchmarks)

---

## Troubleshooting

### Common Issues

#### 1. "Docker is not running"

**Symptoms**:
```
Cannot connect to Docker daemon
```

**Solution**:
```bash
# Mac/Windows: Start Docker Desktop
# Linux: Start Docker service
sudo systemctl start docker
```

#### 2. "Ollama connection refused"

**Symptoms**:
```
ERROR: Failed to connect to Ollama at http://host.docker.internal:11434
```

**Solutions**:
```bash
# Option A: Start Ollama on host
ollama serve

# Option B: Verify Ollama is reachable from container
docker run --rm curlimages/curl curl http://host.docker.internal:11434/api/tags

# Option C: Use Docker Ollama (see Option B deployment)
```

#### 3. "Model not found: zylonai/multilingual-e5-large"

**Symptoms**:
```
ERROR: Embedding model not loaded
```

**Solution**:
```bash
# Pull model (1.1GB download)
ollama pull zylonai/multilingual-e5-large

# Verify model is loaded
ollama list
```

#### 4. "Permission denied" on volumes

**Symptoms**:
```
ERROR: Cannot write to /app/data/tmws.db
```

**Solution**:
```bash
# Fix directory permissions
chmod -R 755 data/ config/ logs/ .chroma/

# Recreate container
docker-compose down
docker-compose up -d
```

#### 5. "Health check failing"

**Symptoms**:
```
docker-compose ps
# tmws-app  unhealthy
```

**Diagnosis**:
```bash
# Check health endpoint manually
docker exec -it tmws-app curl http://localhost:8000/health

# Check logs for errors
docker-compose logs tmws
```

**Common Causes**:
- Ollama not reachable (see #2)
- Database migration pending (run `alembic upgrade head` inside container)
- Insufficient memory (increase container limits)

### Debug Mode

**Enable debug logging** (temporary):
```bash
# Edit .env
TMWS_LOG_LEVEL=DEBUG

# Restart container
docker-compose restart tmws

# View detailed logs
docker-compose logs -f tmws
```

**⚠️ WARNING**: Debug mode may leak sensitive information. **Never use in production.**

### Performance Diagnostics

**Slow API responses**:
```bash
# 1. Check resource usage
docker stats tmws-app

# 2. Profile SQLite queries (inside container)
docker exec -it tmws-app python -c "
from src.core.database import get_db
import asyncio
async def profile():
    async with get_db() as db:
        # Enable query logging
        db.echo = True
asyncio.run(profile())
"

# 3. Check ChromaDB collection size
docker exec -it tmws-app python -c "
from src.services.vector_search_service import VectorSearchService
service = VectorSearchService()
print(f'Vectors: {service.count()}')
"
```

### Container Won't Start

**Check Docker logs**:
```bash
# Full logs
docker-compose logs tmws

# Last 50 lines
docker logs --tail 50 tmws-app

# Follow logs in real-time
docker logs -f tmws-app
```

**Common Errors**:
- `ModuleNotFoundError`: Rebuild image (`docker-compose build --no-cache`)
- `Address already in use`: Port 8000 occupied (change in docker-compose.yml)
- `OOMKilled`: Out of memory (increase container limits)

---

## Support & Documentation

**Documentation**:
- [MCP Integration Guide](./DOCKER_MCP_SETUP.md) - Connect Claude Desktop
- [Security Guidelines](../WAVE3_SECURITY_AUDIT.md) - Security best practices
- [API Reference](./api/API_REFERENCE.md) - REST API documentation
- [Architecture Deep Dive](./architecture/TMWS_v2.2.0_ARCHITECTURE.md) - System design

**Community**:
- GitHub Issues: https://github.com/apto-as/tmws/issues
- Discussions: https://github.com/apto-as/tmws/discussions

**Professional Support**:
- Email: support@tmws.ai
- Enterprise plans: contact sales@tmws.ai

---

**Last Updated**: 2025-11-16 (Wave 3 - Phase 2D-5)
**Version**: TMWS v2.3.1
**Architecture**: SQLite + ChromaDB + Ollama
