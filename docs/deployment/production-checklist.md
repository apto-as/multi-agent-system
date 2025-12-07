# Production Deployment Checklist

**Version**: 1.0.0
**Last Updated**: 2025-12-06

---

## Pre-Deployment Requirements

### 1. Infrastructure Security

- [ ] **DDoS Protection** configured (see [ddos-protection.md](./ddos-protection.md))
  - Cloud provider protection enabled (AWS Shield / Cloudflare)
  - Reverse proxy rate limiting configured (nginx/Caddy)
  - fail2ban installed and configured

- [ ] **TLS/HTTPS** enabled
  - Valid SSL certificate installed
  - HTTP redirected to HTTPS
  - TLS 1.2+ enforced

- [ ] **Firewall** configured
  - Only ports 443 (HTTPS) and 22 (SSH) open
  - SSH access restricted to known IPs

### 2. Application Configuration

- [ ] **Environment Variables** set
  ```bash
  SECRET_KEY=<256-bit random key>
  DATABASE_URL=postgresql://...
  ENVIRONMENT=production
  ```

- [ ] **Database** configured
  - PostgreSQL (not SQLite)
  - Connection pooling enabled
  - Backups automated

- [ ] **Logging** configured
  - Structured JSON logging
  - Log rotation enabled
  - Audit logs to separate file

### 3. Security Validation

- [ ] **Config validation** passes
  ```bash
  python -c "from src.core.config import settings; print(settings.environment)"
  ```

- [ ] **Rate limiting** enabled
  - Per-IP limits configured
  - Per-agent limits configured

- [ ] **CORS** properly configured
  - No wildcard (*) in production
  - Only trusted origins listed

### 4. Monitoring & Alerting

- [ ] **Health check** endpoint accessible
  - `/health` returns 200

- [ ] **Metrics** exposed
  - Prometheus metrics endpoint
  - Key metrics: request rate, latency, error rate

- [ ] **Alerts** configured
  - High error rate alert
  - High latency alert
  - DDoS detection alert

### 5. Authentication

- [ ] **JWT secret** is unique and secure
- [ ] **Agent secrets** are properly generated
- [ ] **Admin account** created with strong password

---

## Deployment Steps

```bash
# 1. Pull latest code
git pull origin master

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run migrations
alembic upgrade head

# 4. Validate configuration
python -c "from src.core.config import settings"

# 5. Start application
gunicorn -w 4 -k uvicorn.workers.UvicornWorker src.main:app
```

---

## Post-Deployment Verification

- [ ] Health check returns 200
- [ ] Can authenticate with admin account
- [ ] MCP tools respond correctly
- [ ] Rate limiting is active
- [ ] Logs are being written

---

**Document Owner**: DevOps Team
**Next Review**: 2026-01-06
