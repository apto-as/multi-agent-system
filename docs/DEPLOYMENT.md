# TMWS Deployment Guide

## Overview

This guide provides instructions for deploying TMWS in production environments without Docker, using native system services for simplicity and efficiency.

## Quick Start

```bash
# Clone repository
git clone https://github.com/apto-as/tmws.git
cd tmws

# Run installation script
./scripts/install_production.sh

# Start service
./scripts/start_production.sh

# Verify health
curl http://localhost:8000/health
```

## System Requirements

### Minimum Requirements
- **OS**: Ubuntu 20.04+, Debian 11+, or macOS 12+
- **CPU**: 2 cores (4+ recommended)
- **RAM**: 2GB (4GB+ recommended)
- **Storage**: 10GB free space
- **Python**: 3.11+
- **PostgreSQL**: 14+ with pgvector extension
- **Redis**: 6.0+

### Network Ports
- `8000`: TMWS API server
- `5432`: PostgreSQL (localhost only)
- `6379`: Redis (localhost only)
- `80/443`: Nginx reverse proxy (optional)

## Installation Steps

### 1. Prerequisites

#### Ubuntu/Debian
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y \
    python3.11 python3.11-venv python3.11-dev \
    postgresql-14 postgresql-contrib-14 \
    redis-server \
    nginx \
    git curl wget
```

#### macOS
```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python@3.11 postgresql@15 redis nginx
```

### 2. Database Setup

```bash
# Create PostgreSQL user and database
sudo -u postgres psql <<EOF
CREATE USER tmws_user WITH PASSWORD 'secure_password_here';
CREATE DATABASE tmws OWNER tmws_user;
\c tmws
CREATE EXTENSION IF NOT EXISTS vector;
GRANT ALL PRIVILEGES ON DATABASE tmws TO tmws_user;
EOF
```

### 3. Redis Configuration

```bash
# Set Redis password
echo "requirepass your_redis_password_here" | sudo tee -a /etc/redis/redis.conf

# Restart Redis
sudo systemctl restart redis-server
```

### 4. TMWS Installation

```bash
# Clone repository
git clone https://github.com/apto-as/tmws.git
cd tmws

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e .

# Create configuration
cp .env.example .env.production
# Edit .env.production with your settings
```

### 5. Database Migration

```bash
# Run migrations
source venv/bin/activate
alembic upgrade head
```

### 6. Service Configuration

#### systemd (Linux)
```bash
# Copy service file
sudo cp scripts/tmws.service /etc/systemd/system/

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable tmws
sudo systemctl start tmws
```

#### launchd (macOS)
```bash
# Use the provided start script
./scripts/start_production.sh
```

## Configuration

### Environment Variables

Create `.env.production` with:

```bash
# Database
TMWS_DATABASE_URL=postgresql://tmws_user:password@localhost:5432/tmws

# Redis
TMWS_REDIS_URL=redis://:password@localhost:6379/0

# Security
TMWS_SECRET_KEY=<generate-with-openssl-rand-base64-64>
TMWS_JWT_SECRET_KEY=<generate-with-openssl-rand-base64-32>
TMWS_AUTH_ENABLED=true

# API
TMWS_HOST=127.0.0.1
TMWS_PORT=8000
TMWS_WORKERS=4

# Environment
TMWS_ENVIRONMENT=production
```

### Production Configuration

Edit `config/production.yaml` for detailed settings:

```yaml
database:
  pool_size: 20
  max_overflow: 40

redis:
  max_connections: 50

security:
  rate_limit:
    enabled: true
    default_limit: "100/minute"

embedding:
  model: "sentence-transformers/all-MiniLM-L6-v2"
  cpu_optimization:
    num_threads: 4
```

## Security Hardening

### 1. Run Security Script

```bash
./scripts/security_hardening.sh
```

This script will:
- Configure PostgreSQL security settings
- Harden Redis configuration
- Set proper file permissions
- Generate SSL certificates
- Create audit scripts

### 2. Firewall Configuration

```bash
# Ubuntu/Debian with UFW
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### 3. SSL/TLS Setup

For production, use Let's Encrypt:

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d yourdomain.com
```

## Nginx Configuration

```nginx
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Monitoring

### Health Checks

```bash
# Basic health check
curl http://localhost:8000/health

# Detailed status
curl http://localhost:8000/health?details=true
```

### Logs

```bash
# Application logs
tail -f /var/log/tmws/tmws.log

# Audit logs
tail -f /var/log/tmws/audit.log

# Service logs (systemd)
sudo journalctl -u tmws -f
```

### Metrics

Access metrics at `http://localhost:8000/metrics` for Prometheus integration.

## Backup and Recovery

### Automated Backups

```bash
# Add to crontab
crontab -e

# Daily database backup at 2 AM
0 2 * * * /path/to/tmws/scripts/backup.sh
```

### Manual Backup

```bash
# Run backup script
./scripts/backup.sh

# Backups stored in /var/backups/tmws/
```

### Recovery

```bash
# Restore database
gunzip < /var/backups/tmws/tmws_db_20240101_020000.sql.gz | psql -U tmws_user -d tmws

# Restore Redis
redis-cli --rdb /var/backups/tmws/tmws_redis_20240101_020000.rdb
```

## Maintenance

### Updates

```bash
# Stop service
sudo systemctl stop tmws

# Pull updates
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -e . --upgrade

# Run migrations
alembic upgrade head

# Restart service
sudo systemctl start tmws
```

### Security Audit

```bash
# Run security audit
./scripts/security_audit.sh

# Check for outdated packages
pip list --outdated
```

## Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Find process using port 8000
lsof -i :8000

# Kill process if needed
kill -9 <PID>
```

#### Database Connection Failed
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Test connection
psql -U tmws_user -d tmws -h localhost
```

#### Redis Connection Failed
```bash
# Check Redis status
sudo systemctl status redis

# Test connection
redis-cli ping
```

### Performance Tuning

#### CPU-Only Embeddings
```yaml
# In config/production.yaml
embedding:
  cpu_optimization:
    num_threads: 4  # Match CPU cores
    use_multiprocessing: false
```

#### Database Optimization
```sql
-- Add indexes for common queries
CREATE INDEX idx_memories_created_at ON memories(created_at DESC);
CREATE INDEX idx_memories_embedding ON memories USING ivfflat (embedding vector_cosine_ops);
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/apto-as/tmws/issues
- Documentation: https://github.com/apto-as/tmws/wiki

## License

MIT License - see LICENSE file for details.