# MCP API Deployment Guide

**Version**: v2.3.0
**Last Updated**: 2025-11-13

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Environment Variables](#environment-variables)
4. [Security Configuration](#security-configuration)
5. [Database Migration](#database-migration)
6. [Testing the Deployment](#testing-the-deployment)
7. [Production Readiness Checklist](#production-readiness-checklist)
8. [Monitoring and Alerting](#monitoring-and-alerting)
9. [Troubleshooting](#troubleshooting)

---

## Overview

This guide covers deploying the MCP Connection Management API (Phase 1) to production. The API enables agents to connect to external MCP servers, discover tools, and execute tools with full security enforcement.

### Deployment Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Load Balancer                         │
│                  (HTTPS Termination)                     │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│              TMWS API Server (FastAPI)                  │
│  ┌────────────────────────────────────────────────┐     │
│  │  MCP Connection API (Port 8000)                │     │
│  │  - JWT Authentication                          │     │
│  │  - Rate Limiting (Fail-secure)                 │     │
│  │  - P0-1 Namespace Isolation                    │     │
│  └────────────────────────────────────────────────┘     │
└───────┬──────────────────────────┬──────────────────────┘
        │                          │
        ▼                          ▼
┌───────────────┐          ┌──────────────────┐
│  SQLite DB    │          │  Redis (Optional)│
│  (Metadata)   │          │  (Rate Limiting) │
└───────────────┘          └──────────────────┘
        │
        ▼
┌───────────────┐
│  ChromaDB     │
│  (Vectors)    │
└───────────────┘
```

---

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | Ubuntu 20.04+ | Ubuntu 22.04 LTS |
| **Python** | 3.11+ | 3.11+ |
| **Memory** | 2GB RAM | 4GB RAM |
| **Disk** | 10GB | 20GB SSD |
| **CPU** | 2 cores | 4 cores |

### Software Dependencies

```bash
# Install Python 3.11+
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip

# Install Redis (optional but recommended)
sudo apt install redis-server
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Verify Redis
redis-cli ping
# Expected: PONG
```

### Network Requirements

| Port | Service | Access |
|------|---------|--------|
| 8000 | TMWS API | Internal (via load balancer) |
| 6379 | Redis | Internal only |

---

## Environment Variables

### Required Variables

Create `/etc/tmws/environment` or `.env` file:

```bash
# ============================================================
# CRITICAL SECURITY SETTINGS (REQUIRED)
# ============================================================

# Database URL (SQLite for Phase 1)
TMWS_DATABASE_URL="sqlite+aiosqlite:////var/lib/tmws/data/tmws.db"

# Secret key for JWT signing (MUST be 32+ characters)
TMWS_SECRET_KEY="YOUR-SECURE-64-CHAR-HEX-KEY-HERE"

# Environment (determines rate limits and security settings)
TMWS_ENVIRONMENT="production"

# ============================================================
# API CONFIGURATION
# ============================================================

# API server
TMWS_API_HOST="0.0.0.0"  # Listen on all interfaces
TMWS_API_PORT="8000"

# CORS (restrict to your frontend domains)
TMWS_CORS_ORIGINS='["https://your-frontend-domain.com"]'

# ============================================================
# AUTHENTICATION
# ============================================================

# Enable production authentication
TMWS_AUTH_ENABLED="true"

# ============================================================
# LOGGING
# ============================================================

# Log level
TMWS_LOG_LEVEL="INFO"  # Use DEBUG only for troubleshooting

# SQL logging (disable in production for performance)
TMWS_DB_ECHO_SQL="false"
```

### Generating Secret Key

```bash
# Generate secure 64-character hex key (32 bytes)
openssl rand -hex 32

# Example output (DO NOT USE THIS):
# 8f3e7a2b9c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0
```

### Setting Environment Variables

#### Option 1: System Environment File

```bash
# Create environment file
sudo mkdir -p /etc/tmws
sudo nano /etc/tmws/environment

# Add variables (see above)

# Load in systemd service
# See systemd section below
```

#### Option 2: .env File (Development)

```bash
# Create .env in project root
cat > .env <<EOF
TMWS_SECRET_KEY=$(openssl rand -hex 32)
TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"
TMWS_ENVIRONMENT="production"
TMWS_API_HOST="0.0.0.0"
TMWS_API_PORT="8000"
EOF

# IMPORTANT: Add to .gitignore
echo ".env" >> .gitignore
```

---

## Security Configuration

### 1. Secret Key Security

**CRITICAL**: Never commit secret key to version control

```bash
# ❌ WRONG: Hardcoded in code
SECRET_KEY = "my-secret-key"

# ✅ CORRECT: Load from environment
import os
SECRET_KEY = os.getenv('TMWS_SECRET_KEY')
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise ValueError("TMWS_SECRET_KEY must be set and >= 32 characters")
```

### 2. File Permissions

```bash
# Set restrictive permissions on environment file
sudo chmod 600 /etc/tmws/environment
sudo chown tmws:tmws /etc/tmws/environment

# Set restrictive permissions on database directory
sudo mkdir -p /var/lib/tmws/data
sudo chmod 700 /var/lib/tmws/data
sudo chown tmws:tmws /var/lib/tmws/data
```

### 3. HTTPS Configuration

**Load Balancer Configuration (Nginx):**

```nginx
# /etc/nginx/sites-available/tmws-api
upstream tmws_backend {
    server 127.0.0.1:8000;
    keepalive 64;
}

server {
    listen 443 ssl http2;
    server_name api.your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/api.your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Rate Limiting (nginx level)
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/m;
    limit_req zone=api_limit burst=20 nodelay;

    # Proxy Configuration
    location / {
        proxy_pass http://tmws_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Health Check Endpoint
    location /health {
        proxy_pass http://tmws_backend;
        access_log off;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name api.your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

Enable configuration:

```bash
sudo ln -s /etc/nginx/sites-available/tmws-api /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 4. CORS Configuration

```bash
# Restrict to specific origins (NEVER use "*" in production)
TMWS_CORS_ORIGINS='["https://app.your-domain.com", "https://admin.your-domain.com"]'
```

### 5. Database Security

```bash
# SQLite file permissions
chmod 600 /var/lib/tmws/data/tmws.db

# Backup encryption
gpg --symmetric --cipher-algo AES256 /var/lib/tmws/data/tmws.db
```

---

## Database Migration

### 1. Install Application

```bash
# Create application user
sudo useradd -r -s /bin/bash -m -d /opt/tmws tmws

# Clone repository
sudo -u tmws git clone https://github.com/apto-as/tmws.git /opt/tmws/app
cd /opt/tmws/app

# Create virtual environment
sudo -u tmws python3.11 -m venv /opt/tmws/venv
source /opt/tmws/venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -e .

# Verify installation
python -c "import src; print('TMWS installed successfully')"
```

### 2. Initialize Database

```bash
# Create data directory
sudo -u tmws mkdir -p /var/lib/tmws/data
sudo -u tmws mkdir -p /var/lib/tmws/chroma

# Set database path
export TMWS_DATABASE_URL="sqlite+aiosqlite:////var/lib/tmws/data/tmws.db"

# Run migrations
cd /opt/tmws/app
alembic upgrade head

# Verify migration
sqlite3 /var/lib/tmws/data/tmws.db ".tables"
# Expected: agents, mcp_connections, memories, tasks, etc.
```

### 3. Create Initial Data

```bash
# Create admin agent (for testing)
python scripts/create_admin_agent.py \
  --agent-id "admin-agent-uuid" \
  --namespace "admin" \
  --name "Admin Agent"

# Verify agent created
sqlite3 /var/lib/tmws/data/tmws.db \
  "SELECT agent_id, namespace FROM agents WHERE agent_id = 'admin-agent-uuid';"
```

---

## Testing the Deployment

### 1. Health Check

```bash
curl http://localhost:8000/health
# Expected: {"status": "healthy"}
```

### 2. Authentication Test

Generate test JWT token:

```python
# generate_test_token.py
from datetime import datetime, timedelta
from jose import jwt
import os

SECRET_KEY = os.getenv('TMWS_SECRET_KEY')
agent_id = "admin-agent-uuid"

payload = {
    "sub": agent_id,
    "exp": datetime.utcnow() + timedelta(hours=24)
}

token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
print(f"Token: {token}")
```

Run:

```bash
export TMWS_SECRET_KEY="your-secret-key"
python generate_test_token.py
```

### 3. API Endpoint Tests

#### Create Connection

```bash
curl -X POST http://localhost:8000/api/v1/mcp/connections \
  -H "Authorization: Bearer YOUR-JWT-TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "server_name": "test_server",
    "url": "http://localhost:3000",
    "timeout": 30,
    "namespace": "admin",
    "agent_id": "admin-agent-uuid"
  }'
# Expected: 201 Created
```

#### Discover Tools

```bash
curl http://localhost:8000/api/v1/mcp/connections/CONNECTION-ID/tools \
  -H "Authorization: Bearer YOUR-JWT-TOKEN"
# Expected: 200 OK with tools list
```

#### Execute Tool

```bash
curl -X POST http://localhost:8000/api/v1/mcp/connections/CONNECTION-ID/tools/TOOL-NAME/execute \
  -H "Authorization: Bearer YOUR-JWT-TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"arguments": {"param": "value"}}'
# Expected: 200 OK with execution result
```

#### Disconnect

```bash
curl -X DELETE http://localhost:8000/api/v1/mcp/connections/CONNECTION-ID \
  -H "Authorization: Bearer YOUR-JWT-TOKEN"
# Expected: 204 No Content
```

### 4. Security Tests

#### Namespace Isolation

```bash
# Create connection as Agent A
TOKEN_A="agent-a-token"
curl -X POST http://localhost:8000/api/v1/mcp/connections \
  -H "Authorization: Bearer $TOKEN_A" \
  -d '{"server_name": "server_a", "namespace": "namespace-a", ...}'

# Try to access as Agent B (should fail)
TOKEN_B="agent-b-token"
curl http://localhost:8000/api/v1/mcp/connections/CONNECTION-ID-FROM-AGENT-A/tools \
  -H "Authorization: Bearer $TOKEN_B"
# Expected: 403 Forbidden
```

#### Rate Limiting

```bash
# Test rate limit enforcement
for i in {1..15}; do
  echo "Request $i"
  curl -X POST http://localhost:8000/api/v1/mcp/connections \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"server_name": "test_'$i'", ...}' \
    -w "\nStatus: %{http_code}\n"
  sleep 1
done
# Expected: 201 for first 12 requests, 429 for remaining
```

---

## Production Readiness Checklist

### Pre-Deployment

- [ ] **Secret key generated** (64-char hex, stored securely)
- [ ] **Environment variables set** (all required variables configured)
- [ ] **Database initialized** (migrations applied, verified)
- [ ] **HTTPS configured** (SSL certificates valid)
- [ ] **CORS restricted** (only trusted origins)
- [ ] **File permissions set** (600 for sensitive files, 700 for directories)
- [ ] **Redis installed** (optional but recommended for rate limiting)
- [ ] **Monitoring configured** (see Monitoring section)

### Deployment

- [ ] **Systemd service created** (see below)
- [ ] **Service enabled** (`systemctl enable tmws`)
- [ ] **Service started** (`systemctl start tmws`)
- [ ] **Service status verified** (`systemctl status tmws`)
- [ ] **Logs checked** (`journalctl -u tmws -f`)

### Post-Deployment

- [ ] **Health check passes** (`/health` endpoint returns 200)
- [ ] **Authentication works** (JWT tokens accepted)
- [ ] **API endpoints tested** (create, discover, execute, disconnect)
- [ ] **Rate limiting enforced** (429 returned after exceeding limits)
- [ ] **Security tests passed** (namespace isolation verified)
- [ ] **Load test completed** (handles expected traffic)
- [ ] **Backup configured** (database backed up regularly)
- [ ] **Alerts configured** (degraded mode, errors, high traffic)

### Systemd Service Configuration

Create `/etc/systemd/system/tmws.service`:

```ini
[Unit]
Description=TMWS API Server
After=network.target redis.service
Requires=redis.service

[Service]
Type=simple
User=tmws
Group=tmws
WorkingDirectory=/opt/tmws/app
EnvironmentFile=/etc/tmws/environment

# Virtual environment
ExecStart=/opt/tmws/venv/bin/uvicorn src.api.main:app \
    --host ${TMWS_API_HOST} \
    --port ${TMWS_API_PORT} \
    --workers 4 \
    --log-level ${TMWS_LOG_LEVEL}

# Restart policy
Restart=always
RestartSec=10
StartLimitInterval=200
StartLimitBurst=5

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/tmws

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable tmws
sudo systemctl start tmws
sudo systemctl status tmws
```

---

## Monitoring and Alerting

### 1. Health Check Monitoring

```bash
# Add to cron or monitoring system
*/5 * * * * curl -f http://localhost:8000/health || echo "TMWS health check failed" | mail -s "TMWS Alert" admin@your-domain.com
```

### 2. Log Monitoring

```bash
# Monitor critical errors
sudo journalctl -u tmws -f | grep -i "error\|critical\|degraded"

# Monitor rate limit violations
sudo journalctl -u tmws -f | grep -i "rate.*limit\|429\|503"
```

### 3. Prometheus Metrics (Future)

**Planned for v2.4.0:**

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'tmws'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### 4. Alerting Rules

**Example Prometheus alerts:**

```yaml
# alerts.yml
groups:
  - name: tmws_alerts
    rules:
      - alert: TMWSDegradedMode
        expr: rate_limiter_degraded_mode == 1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "TMWS rate limiter in degraded mode"

      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"

      - alert: HighRateLimitViolations
        expr: rate(rate_limit_requests_total{status="blocked"}[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High rate limit violation rate"
```

---

## Troubleshooting

### Issue: Service Won't Start

**Check logs:**

```bash
sudo journalctl -u tmws -n 50 --no-pager
```

**Common causes:**

1. **Missing environment variables**
```bash
# Check environment file
cat /etc/tmws/environment

# Verify TMWS_SECRET_KEY is set
sudo systemctl show tmws | grep TMWS_SECRET_KEY
```

2. **Port already in use**
```bash
sudo lsof -i :8000
# Kill conflicting process or change port
```

3. **Database permission issues**
```bash
ls -la /var/lib/tmws/data/tmws.db
# Should be owned by tmws:tmws with 600 permissions
sudo chown tmws:tmws /var/lib/tmws/data/tmws.db
sudo chmod 600 /var/lib/tmws/data/tmws.db
```

### Issue: Authentication Failing

**Verify secret key:**

```bash
# Check secret key length
echo $TMWS_SECRET_KEY | wc -c
# Must be >= 32 characters
```

**Test token generation:**

```python
from jose import jwt
import os

SECRET_KEY = os.getenv('TMWS_SECRET_KEY')
token = jwt.encode({"sub": "test"}, SECRET_KEY, algorithm="HS256")
decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
print(f"Token works: {decoded}")
```

### Issue: Rate Limiting Not Working

**Check Redis connection:**

```bash
redis-cli ping
# Expected: PONG

# Check TMWS can connect to Redis
python -c "import redis; r = redis.Redis(); print(r.ping())"
```

**Check environment:**

```bash
echo $TMWS_ENVIRONMENT
# Should be: production (not test)
```

### Issue: Database Errors

**Check database file:**

```bash
sqlite3 /var/lib/tmws/data/tmws.db "PRAGMA integrity_check;"
# Expected: ok
```

**Verify migrations:**

```bash
cd /opt/tmws/app
alembic current
# Should show current migration version
```

---

## Backup and Recovery

### Database Backup

```bash
#!/bin/bash
# /opt/tmws/scripts/backup.sh

BACKUP_DIR="/var/backups/tmws"
DATE=$(date +%Y%m%d_%H%M%S)
DB_FILE="/var/lib/tmws/data/tmws.db"

# Create backup
mkdir -p $BACKUP_DIR
sqlite3 $DB_FILE ".backup ${BACKUP_DIR}/tmws_${DATE}.db"

# Compress and encrypt
gzip ${BACKUP_DIR}/tmws_${DATE}.db
gpg --symmetric --cipher-algo AES256 ${BACKUP_DIR}/tmws_${DATE}.db.gz

# Clean old backups (keep 30 days)
find $BACKUP_DIR -name "tmws_*.db.gz.gpg" -mtime +30 -delete

echo "Backup completed: ${BACKUP_DIR}/tmws_${DATE}.db.gz.gpg"
```

Schedule with cron:

```bash
# Daily at 2 AM
0 2 * * * /opt/tmws/scripts/backup.sh
```

### Recovery

```bash
# Decrypt and decompress
gpg --decrypt tmws_20251113_020000.db.gz.gpg | gunzip > tmws_restored.db

# Stop service
sudo systemctl stop tmws

# Restore database
sudo cp /var/lib/tmws/data/tmws.db /var/lib/tmws/data/tmws.db.backup
sudo cp tmws_restored.db /var/lib/tmws/data/tmws.db
sudo chown tmws:tmws /var/lib/tmws/data/tmws.db
sudo chmod 600 /var/lib/tmws/data/tmws.db

# Start service
sudo systemctl start tmws
```

---

## Scaling Considerations

### Horizontal Scaling

**Load Balancer Configuration:**

```nginx
upstream tmws_cluster {
    server 10.0.1.10:8000;
    server 10.0.1.11:8000;
    server 10.0.1.12:8000;
    keepalive 64;
}
```

**Shared State (Redis):**

All instances must share Redis for rate limiting:

```bash
# Centralized Redis
REDIS_HOST="redis.internal.domain"
REDIS_PORT="6379"
```

### Vertical Scaling

**Increase workers:**

```ini
# /etc/systemd/system/tmws.service
ExecStart=/opt/tmws/venv/bin/uvicorn src.api.main:app \
    --workers 8  # Increase from 4 to 8
```

**Increase resource limits:**

```ini
# /etc/systemd/system/tmws.service
LimitNOFILE=131072  # Increase from 65536
```

---

## Reference

### Related Documentation

- [MCP Connection API](../api/MCP_CONNECTION_API.md)
- [Authentication Guide](../guides/AUTHENTICATION_GUIDE.md)
- [Rate Limiting Guide](../guides/RATE_LIMITING_GUIDE.md)

### External Resources

- [FastAPI Deployment](https://fastapi.tiangolo.com/deployment/)
- [Uvicorn Production](https://www.uvicorn.org/deployment/)
- [Nginx Configuration](https://nginx.org/en/docs/)

---

**Document Author**: Muses (Knowledge Architect)
**Last Reviewed**: 2025-11-13
**Status**: Production-ready
