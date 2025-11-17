# Docker Deployment with License Key
## Production Deployment Guide for TMWS v2.3.2+

**Last Updated**: 2025-11-16
**TMWS Version**: v2.3.2+
**Prerequisites**: Docker 20.10+, Docker Compose 1.29+

---

## Overview

This guide covers deploying TMWS v2.3.2+ using Docker with license key authentication.

**Deployment Time**: 10-15 minutes (first-time), 2-5 minutes (renewal)

---

## Prerequisites Checklist

- [ ] Docker installed and running (`docker --version`)
- [ ] Docker Compose installed (`docker-compose --version`)
- [ ] TMWS license key obtained (see [Licensing Guide](../licensing/LICENSING_GUIDE.md))
- [ ] `.env` file created (see below)

---

## Quick Start (5 minutes)

### 1. Clone Repository

```bash
git clone https://github.com/apto-as/tmws.git
cd tmws
```

### 2. Create `.env` File

```bash
cp .env.example .env
vim .env
```

**Add your license key**:
```bash
TMWS_LICENSE_KEY=TMWS-FREE-your-actual-key-here
```

### 3. Start TMWS

```bash
docker-compose up -d
```

### 4. Verify License Validation

```bash
docker logs tmws | grep "License validated"
```

**Expected output**:
```
✅ License validated successfully
   Tier: FREE
   Expires: 2026-11-16T00:00:00Z
```

**Success**: TMWS is running with valid license ✅

---

## Detailed Setup

### Step 1: Environment Configuration

**Create `.env` file** (if not exists):
```bash
touch .env
```

**Add required variables**:
```bash
# ========================================
# TMWS License Configuration
# ========================================
TMWS_LICENSE_KEY=TMWS-FREE-12345678-1234-5678-1234-567812345678-ABCD1234

# Optional: Strict mode (disable 7-day grace period)
TMWS_LICENSE_STRICT_MODE=false

# ========================================
# TMWS Configuration
# ========================================
TMWS_ENVIRONMENT=production
TMWS_LOG_LEVEL=INFO
TMWS_SECRET_KEY=<generate-with-openssl-rand-hex-32>
```

**Generate secret key**:
```bash
openssl rand -hex 32
```

---

### Step 2: Docker Compose Configuration

**Verify `docker-compose.yml`** includes license key mapping:

```yaml
services:
  tmws:
    image: ghcr.io/apto-as/tmws:latest
    environment:
      - TMWS_LICENSE_KEY=${TMWS_LICENSE_KEY}  # ✅ Required
      - TMWS_LICENSE_STRICT_MODE=${TMWS_LICENSE_STRICT_MODE:-false}
      - TMWS_ENVIRONMENT=${TMWS_ENVIRONMENT:-production}
      # ... other env vars ...
    volumes:
      - ./data:/app/data
      - ./.chroma:/app/.chroma
    ports:
      - "8000:8000"
```

---

### Step 3: Build and Start

**Option A: Pre-built Image** (recommended):
```bash
docker-compose pull
docker-compose up -d
```

**Option B: Build from Source**:
```bash
docker-compose build
docker-compose up -d
```

---

### Step 4: Verification

#### 4.1 Check Container Status
```bash
docker ps | grep tmws
```
**Expected**: `Up X minutes`

#### 4.2 Check License Validation
```bash
docker logs tmws --tail 50 | grep -A 3 "License"
```
**Expected output**:
```
✅ License validated successfully
   Tier: FREE
   Expires: 2026-11-16T00:00:00Z
```

#### 4.3 Check Health Endpoint
```bash
curl http://localhost:8000/health
```
**Expected**: `{"status": "healthy"}`

#### 4.4 Check MCP Tools Available
```bash
docker exec tmws tmws-mcp-server --help
```
**Expected**: MCP server help text

---

## Production Deployment

### Security Checklist

- [ ] Use HTTPS (reverse proxy with Let's Encrypt)
- [ ] Strong `TMWS_SECRET_KEY` (64-char hex)
- [ ] License key in environment (not `.env` file committed to Git)
- [ ] Firewall rules (port 8000 internal only)
- [ ] Regular backups (data/ and .chroma/ directories)
- [ ] Monitoring configured (Docker health checks)

### Recommended docker-compose.yml (Production)

```yaml
version: "3.8"

services:
  tmws:
    image: ghcr.io/apto-as/tmws:v2.3.2
    container_name: tmws
    restart: unless-stopped

    environment:
      - TMWS_LICENSE_KEY=${TMWS_LICENSE_KEY}
      - TMWS_LICENSE_STRICT_MODE=true  # No grace period in production
      - TMWS_ENVIRONMENT=production
      - TMWS_LOG_LEVEL=WARNING  # Reduce log verbosity
      - TMWS_SECRET_KEY=${TMWS_SECRET_KEY}

    volumes:
      - /var/tmws/data:/app/data
      - /var/tmws/chroma:/app/.chroma
      - /var/tmws/logs:/app/logs

    ports:
      - "127.0.0.1:8000:8000"  # Internal only

    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  # Reverse proxy (optional)
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
    depends_on:
      - tmws
```

---

## License Renewal

### STANDARD/ENTERPRISE (Automatic)

**No action required**: License renews automatically with subscription.

**Verify renewal**:
```bash
docker logs tmws --tail 10 | grep "Expires"
# Check expiration date has extended
```

---

### FREE Tier (Manual)

1. **Check expiration** (90 days before):
   ```bash
   docker logs tmws | grep "Expires"
   ```

2. **Renew license**:
   - Contact your system administrator
   - Request FREE license renewal
   - Receive new license key from administrator

3. **Update `.env` file**:
   ```bash
   vim .env
   # Update TMWS_LICENSE_KEY=TMWS-FREE-new-key-here
   ```

4. **Restart TMWS**:
   ```bash
   docker-compose restart
   ```

5. **Verify new license**:
   ```bash
   docker logs tmws | grep "License validated"
   # Should show new expiration date
   ```

---

## Troubleshooting

### Container Exits Immediately

**Check logs**:
```bash
docker logs tmws
```

**Common errors**:

**"TMWS requires a valid license key to start"**
- Check `.env` file exists
- Verify `TMWS_LICENSE_KEY` is set
- Ensure no extra spaces or newlines

**"Invalid license key: Invalid format"**
- Verify key format: `TMWS-{TIER}-{UUID}-{CHECKSUM}`
- Check for copy-paste errors
- Request new key if corrupted

**"Invalid license key: License has been revoked"**
- Check subscription status
- Renew subscription if expired
- Contact support if unexpected

---

### Health Check Failing

```bash
docker exec tmws curl -f http://localhost:8000/health
```

**Possible causes**:
- License validation failed (check logs)
- Database initialization error
- Port 8000 already in use

**Solution**:
```bash
# Stop conflicting containers
docker ps | grep 8000
docker stop <conflicting-container>

# Restart TMWS
docker-compose restart
```

---

### License Key Not Recognized

**Verify environment variable is set**:
```bash
docker exec tmws printenv TMWS_LICENSE_KEY
```

**If empty**:
```bash
# Check .env file
cat .env | grep TMWS_LICENSE_KEY

# Recreate container to pick up new env var
docker-compose down
docker-compose up -d
```

---

## Upgrading TMWS

### From v2.3.1 → v2.3.2+ (License Gate)

**⚠️  BREAKING CHANGE**: v2.3.2+ requires license key

**Upgrade steps**:

1. **Obtain license key** (see [Licensing Guide](../licensing/LICENSING_GUIDE.md))

2. **Update `.env` file**:
   ```bash
   echo "TMWS_LICENSE_KEY=TMWS-FREE-your-key-here" >> .env
   ```

3. **Pull new image**:
   ```bash
   docker-compose pull
   ```

4. **Restart**:
   ```bash
   docker-compose down
   docker-compose up -d
   ```

5. **Verify**:
   ```bash
   docker logs tmws | grep "License validated"
   ```

---

## Backup and Restore

### Backup

```bash
# Stop TMWS
docker-compose down

# Backup data
tar -czf tmws-backup-$(date +%Y%m%d).tar.gz data/ .chroma/

# Restart TMWS
docker-compose up -d
```

### Restore

```bash
# Stop TMWS
docker-compose down

# Restore data
tar -xzf tmws-backup-YYYYMMDD.tar.gz

# Restart TMWS
docker-compose up -d
```

---

## Monitoring

### Docker Health Checks

```bash
docker ps --filter "name=tmws" --format "{{.Status}}"
```
**Expected**: `Up X minutes (healthy)`

### Log Monitoring

```bash
# Follow logs
docker logs -f tmws

# Check for errors
docker logs tmws | grep ERROR

# Check license validation
docker logs tmws | grep "License"
```

### Prometheus Metrics (Optional)

TMWS exposes Prometheus metrics at `/metrics`:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'tmws'
    static_configs:
      - targets: ['localhost:8000']
```

---

## Support

- **Community**: https://github.com/apto-as/tmws/discussions
- **Internal Support**: Contact your system administrator
- **Security Issues**: Report to your system administrator

---

**End of Docker Deployment Guide**
