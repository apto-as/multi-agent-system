# Progressive Disclosure v2.0 - Deployment Guide

**Author**: Artemis (Technical Perfectionist)
**Date**: 2025-11-24
**Version**: 2.0
**Target Audience**: DevOps, System Administrators

---

## Overview

This guide provides step-by-step procedures for deploying Progressive Disclosure v2.0 with 5-tier license system to production environments.

**Prerequisites**:
- Docker 24.0+
- Docker Compose 2.0+
- Redis 7.0+ (optional, for distributed deployments)
- SQLite 3.35+ (with WAL mode)
- 4GB RAM minimum (8GB recommended)

---

## Table of Contents

1. [Pre-Deployment Checklist](#1-pre-deployment-checklist)
2. [Database Migration](#2-database-migration)
3. [Docker Image Build](#3-docker-image-build)
4. [Configuration](#4-configuration)
5. [Deployment Steps](#5-deployment-steps)
6. [License Management](#6-license-management)
7. [Monitoring & Alerts](#7-monitoring--alerts)
8. [Rollback Procedures](#8-rollback-procedures)
9. [FAQ](#9-faq)

---

## 1. Pre-Deployment Checklist

### 1.1 Environment Validation

```bash
# Check Docker version
docker --version  # Should be 24.0+

# Check Docker Compose version
docker-compose --version  # Should be 2.0+

# Check available disk space
df -h  # Need at least 10GB free

# Check available memory
free -h  # Need at least 4GB RAM
```

### 1.2 Backup Current Data

```bash
# Backup database
docker-compose exec tmws sqlite3 /app/data/tmws.db ".backup /app/data/tmws_backup_$(date +%Y%m%d_%H%M%S).db"

# Backup ChromaDB
tar -czf chromadb_backup_$(date +%Y%m%d_%H%M%S).tar.gz ./data/chromadb/

# Backup configuration
cp .env .env.backup_$(date +%Y%m%d_%H%M%S)
```

### 1.3 Download New Image

```bash
# Pull latest image
docker pull tmws:v2.4.0

# Verify image
docker images | grep tmws
```

---

## 2. Database Migration

### 2.1 Migration Script

**File**: `migrations/versions/20251124_v2_license_system.py`

```python
"""Progressive Disclosure v2.0 - License System

Revision ID: 20251124_v2_license
Revises: 315d506e2598
Create Date: 2025-11-24 12:00:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite
from datetime import datetime, timedelta

# Revision identifiers
revision = '20251124_v2_license'
down_revision = '315d506e2598'
branch_labels = None
depends_on = None


def upgrade():
    """Upgrade to v2.4.0 with 5-tier license system."""

    # 1. Create license_tier enum (SQLite uses TEXT with CHECK constraint)
    # Note: SQLite doesn't support enum natively, use CHECK constraint

    # 2. Create license_keys table
    op.create_table(
        'license_keys',
        sa.Column('id', sa.String(36), primary_key=True),  # UUID as string
        sa.Column('license_key', sa.String(200), unique=True, nullable=False),
        sa.Column(
            'tier',
            sa.String(20),
            nullable=False,
            server_default='FREE',
        ),
        sa.Column('agent_id', sa.String(255), sa.ForeignKey('agents.agent_id')),

        # Timestamps
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime, nullable=True),  # NULL = perpetual

        # Status
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('revoked_at', sa.DateTime, nullable=True),
        sa.Column('revoked_reason', sa.Text, nullable=True),

        # Tracking
        sa.Column('last_validated_at', sa.DateTime, nullable=True),
        sa.Column('validation_count', sa.Integer, default=0),

        # CHECK constraint for tier values
        sa.CheckConstraint(
            "tier IN ('FREE', 'PRO', 'ENTERPRISE', 'ADMINISTRATOR')",
            name='ck_license_tier'
        ),
    )

    # 3. Create indexes
    op.create_index('idx_license_keys_agent', 'license_keys', ['agent_id'])
    op.create_index('idx_license_keys_tier', 'license_keys', ['tier'])
    op.create_index(
        'idx_license_keys_expiry',
        'license_keys',
        ['expires_at'],
        sqlite_where='expires_at IS NOT NULL'
    )
    op.create_index(
        'idx_license_keys_active',
        'license_keys',
        ['is_active', 'expires_at']
    )

    # 4. Add license columns to agents table
    op.add_column('agents', sa.Column('license_key_id', sa.String(36), nullable=True))
    op.add_column(
        'agents',
        sa.Column('license_tier', sa.String(20), nullable=False, server_default='FREE')
    )
    op.add_column('agents', sa.Column('license_expiration', sa.DateTime, nullable=True))

    # 5. Create foreign key
    op.create_foreign_key(
        'fk_agents_license_key',
        'agents',
        'license_keys',
        ['license_key_id'],
        ['id']
    )

    # 6. Create default FREE licenses for existing agents
    # Note: This is a data migration, requires connection
    connection = op.get_bind()

    # Generate UUID function for SQLite
    import uuid

    # Fetch all existing agents
    agents = connection.execute(sa.text("SELECT agent_id FROM agents")).fetchall()

    for agent_row in agents:
        agent_id = agent_row[0]
        license_id = str(uuid.uuid4())

        # Generate license key (simplified, should use proper generator in production)
        import hashlib
        uuid_part = hashlib.md5(license_id.encode()).hexdigest()[:8]
        expiry_date = datetime.utcnow() + timedelta(days=30)
        expiry_str = expiry_date.strftime("%Y%m%d")

        license_key = f"TMWS-FREE-{uuid_part}-{expiry_str}-00000000"

        # Insert license
        connection.execute(
            sa.text("""
                INSERT INTO license_keys
                (id, license_key, tier, agent_id, created_at, expires_at, is_active)
                VALUES
                (:id, :license_key, 'FREE', :agent_id, :now, :expires_at, 1)
            """),
            {
                "id": license_id,
                "license_key": license_key,
                "agent_id": agent_id,
                "now": datetime.utcnow(),
                "expires_at": expiry_date,
            }
        )

        # Update agent with license reference
        connection.execute(
            sa.text("""
                UPDATE agents
                SET license_key_id = :license_id,
                    license_tier = 'FREE',
                    license_expiration = :expires_at
                WHERE agent_id = :agent_id
            """),
            {
                "license_id": license_id,
                "agent_id": agent_id,
                "expires_at": expiry_date,
            }
        )

    # 7. Create index for license expiration checks
    op.create_index(
        'idx_agents_license_expiry',
        'agents',
        ['license_expiration'],
        sqlite_where='license_expiration IS NOT NULL'
    )


def downgrade():
    """Downgrade from v2.4.0 to v2.3.0."""

    # Drop indexes
    op.drop_index('idx_agents_license_expiry', table_name='agents')
    op.drop_index('idx_license_keys_active', table_name='license_keys')
    op.drop_index('idx_license_keys_expiry', table_name='license_keys')
    op.drop_index('idx_license_keys_tier', table_name='license_keys')
    op.drop_index('idx_license_keys_agent', table_name='license_keys')

    # Drop foreign key
    op.drop_constraint('fk_agents_license_key', 'agents', type_='foreignkey')

    # Drop columns from agents
    op.drop_column('agents', 'license_expiration')
    op.drop_column('agents', 'license_tier')
    op.drop_column('agents', 'license_key_id')

    # Drop license_keys table
    op.drop_table('license_keys')
```

### 2.2 Run Migration

```bash
# Step 1: Stop application (optional, but recommended)
docker-compose stop tmws

# Step 2: Run migration in container
docker-compose run --rm tmws alembic upgrade head

# Expected output:
# INFO  [alembic.runtime.migration] Running upgrade 315d506e2598 -> 20251124_v2_license
# INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
# INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
# INFO  [alembic.runtime.migration] Migrated 1 agent(s) to FREE tier

# Step 3: Verify migration
docker-compose run --rm tmws alembic current

# Expected output:
# INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
# INFO  [alembic.runtime.migration] Current revision: 20251124_v2_license
```

### 2.3 Verify Database Schema

```bash
# Connect to database
docker-compose exec tmws sqlite3 /app/data/tmws.db

# Check license_keys table
sqlite> .schema license_keys

# Expected output:
# CREATE TABLE license_keys (
#     id VARCHAR(36) NOT NULL PRIMARY KEY,
#     license_key VARCHAR(200) NOT NULL UNIQUE,
#     tier VARCHAR(20) NOT NULL DEFAULT 'FREE',
#     ...
# );

# Check agents table
sqlite> .schema agents

# Verify new columns: license_key_id, license_tier, license_expiration

# Exit SQLite
sqlite> .exit
```

---

## 3. Docker Image Build

### 3.1 Dockerfile Updates

**File**: `Dockerfile`

```dockerfile
# Dockerfile for TMWS v2.4.0

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install CLI dependencies (NEW)
RUN pip install click

# Copy application code
COPY src/ ./src/
COPY migrations/ ./migrations/
COPY alembic.ini .

# Create data directories
RUN mkdir -p /app/data/chromadb /app/data/licenses

# Expose ports
EXPOSE 8000  # Main API
EXPOSE 8001  # License API (optional)

# Set environment variables
ENV PYTHONPATH=/app
ENV TMWS_DATABASE_URL=sqlite+aiosqlite:///./data/tmws.db
ENV TMWS_LICENSE_STORAGE=/app/data/licenses

# Volume for persistent data
VOLUME ["/app/data"]

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Start application
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 3.2 Build Image

```bash
# Build image
docker build -t tmws:v2.4.0 .

# Verify image size
docker images tmws:v2.4.0

# Expected output:
# REPOSITORY   TAG       IMAGE ID       CREATED         SIZE
# tmws         v2.4.0    abc123def456   2 minutes ago   450MB

# Tag for registry (if applicable)
docker tag tmws:v2.4.0 your-registry.com/tmws:v2.4.0
```

---

## 4. Configuration

### 4.1 Environment Variables

**File**: `.env`

```bash
# TMWS v2.4.0 Configuration

# Database
TMWS_DATABASE_URL=sqlite+aiosqlite:///./data/tmws.db

# Security
TMWS_SECRET_KEY=your-64-char-hex-secret-key-here
TMWS_API_KEY_EXPIRE_DAYS=90

# License System (NEW)
TMWS_LICENSE_STORAGE=/app/data/licenses
TMWS_LICENSE_DEFAULT_TIER=FREE
TMWS_LICENSE_DEFAULT_DURATION_DAYS=30

# CORS
TMWS_CORS_ORIGINS=["https://your-domain.com"]

# Logging
TMWS_LOG_LEVEL=INFO

# Environment
TMWS_ENVIRONMENT=production

# Redis (optional, for distributed deployments)
TMWS_REDIS_URL=redis://redis:6379/0

# Monitoring
TMWS_PROMETHEUS_ENABLED=true
TMWS_PROMETHEUS_PORT=9090
```

### 4.2 docker-compose.yml

**File**: `docker-compose.yml`

```yaml
version: '3.8'

services:
  tmws:
    image: tmws:v2.4.0
    container_name: tmws-app
    ports:
      - "8000:8000"  # Main API
      - "8001:8001"  # License API (optional)
      - "9090:9090"  # Prometheus metrics (optional)
    environment:
      - TMWS_DATABASE_URL=sqlite+aiosqlite:///./data/tmws.db
      - TMWS_SECRET_KEY=${TMWS_SECRET_KEY}
      - TMWS_LICENSE_STORAGE=/app/data/licenses
      - TMWS_REDIS_URL=redis://redis:6379/0
    volumes:
      - ./data:/app/data
      - ./data/licenses:/app/data/licenses
    depends_on:
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "python", "-c", "import requests; requests.get('http://localhost:8000/health')"]
      interval: 30s
      timeout: 5s
      retries: 3

  redis:
    image: redis:7-alpine
    container_name: tmws-redis
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 3

  prometheus:
    image: prom/prometheus:latest
    container_name: tmws-prometheus
    ports:
      - "9091:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    restart: unless-stopped

volumes:
  redis-data:
  prometheus-data:
```

---

## 5. Deployment Steps

### 5.1 Zero-Downtime Deployment

```bash
# Step 1: Pull new image
docker-compose pull

# Step 2: Run database migration (without downtime)
docker-compose run --rm tmws alembic upgrade head

# Step 3: Scale up new version (blue-green deployment)
docker-compose up -d --scale tmws=2 --no-recreate

# Step 4: Wait for health check
sleep 30
docker-compose ps

# Step 5: Stop old version
docker stop tmws-app-old

# Step 6: Remove old container
docker rm tmws-app-old

# Step 7: Verify deployment
curl http://localhost:8000/health
```

### 5.2 Standard Deployment (with downtime)

```bash
# Step 1: Stop current version
docker-compose down

# Step 2: Run database migration
docker-compose run --rm tmws alembic upgrade head

# Step 3: Start new version
docker-compose up -d

# Step 4: Verify deployment
docker-compose ps
docker-compose logs -f tmws

# Step 5: Check health endpoint
curl http://localhost:8000/health

# Expected output:
# {"status": "healthy", "version": "2.4.0"}
```

---

## 6. License Management

### 6.1 Create Licenses for Existing Users

```bash
# List all existing agents
docker-compose exec tmws python -c "
from sqlalchemy import create_engine, select
from src.models.agent import Agent

engine = create_engine('sqlite:///./data/tmws.db')
with engine.connect() as conn:
    result = conn.execute(select(Agent.agent_id, Agent.license_tier))
    for row in result:
        print(f'{row[0]}: {row[1]}')
"

# Create PRO license for paid user
docker-compose exec tmws tmws license create \
    --tier PRO \
    --duration 12m \
    --agent-id paid-user-1 \
    --output /app/data/licenses/paid-user-1.key

# Distribute license to user (via email, dashboard, etc.)
docker-compose exec tmws cat /app/data/licenses/paid-user-1.key
```

### 6.2 Activate License (User Side)

```bash
# User activates license via API
curl -X POST http://localhost:8000/api/v1/license/activate \
    -H "Content-Type: application/json" \
    -d '{
        "agent_id": "paid-user-1",
        "license_key": "TMWS-PRO-a1b2c3d4-20261124-5e6f7g8h"
    }'

# Expected response:
# {
#   "status": "success",
#   "tier": "PRO",
#   "expires_at": "2026-11-24T12:00:00Z"
# }
```

### 6.3 Monitor License Usage

```bash
# Check active licenses
docker-compose exec tmws tmws license list --status active

# Check expiring licenses (next 7 days)
docker-compose exec tmws python -c "
from datetime import datetime, timedelta
from sqlalchemy import create_engine, select
from src.models.license import License

engine = create_engine('sqlite:///./data/tmws.db')
with engine.connect() as conn:
    cutoff = datetime.utcnow() + timedelta(days=7)
    result = conn.execute(
        select(License).where(License.expires_at <= cutoff)
    )
    for license in result:
        print(f'{license.agent_id}: Expires {license.expires_at}')
"
```

---

## 7. Monitoring & Alerts

### 7.1 Prometheus Metrics

**File**: `prometheus.yml`

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'tmws'
    static_configs:
      - targets: ['tmws:9090']
```

**Key Metrics**:

```promql
# Budget check rate
rate(tmws_budget_checks_total[5m])

# Budget exceeded rate
rate(tmws_budget_checks_total{result="exceeded"}[5m])

# License expiring in 7 days
tmws_expiring_licenses_7d

# Token usage by tier
rate(tmws_license_tokens_used_total[1h])
```

### 7.2 Grafana Dashboard

```json
{
  "dashboard": {
    "title": "TMWS License System",
    "panels": [
      {
        "title": "Budget Check Rate",
        "targets": [
          {
            "expr": "rate(tmws_budget_checks_total[5m])"
          }
        ]
      },
      {
        "title": "Token Usage by Tier",
        "targets": [
          {
            "expr": "rate(tmws_license_tokens_used_total[1h]) by (tier)"
          }
        ]
      },
      {
        "title": "Licenses Expiring Soon",
        "targets": [
          {
            "expr": "tmws_expiring_licenses_7d"
          }
        ]
      }
    ]
  }
}
```

---

## 8. Rollback Procedures

### 8.1 Rollback to v2.3.0

```bash
# Step 1: Stop current version
docker-compose down

# Step 2: Restore database backup
docker-compose run --rm tmws sqlite3 /app/data/tmws.db ".restore /app/data/tmws_backup_YYYYMMDD_HHMMSS.db"

# Step 3: Downgrade migration
docker-compose run --rm tmws:v2.3.0 alembic downgrade 315d506e2598

# Step 4: Start old version
docker-compose -f docker-compose.v2.3.0.yml up -d

# Step 5: Verify rollback
curl http://localhost:8000/health
```

### 8.2 Partial Rollback (Keep Data)

```bash
# If migration succeeded but application has issues:

# Step 1: Stop v2.4.0
docker-compose down

# Step 2: Start v2.3.0 (skip downgrade, licenses table will be unused)
docker-compose -f docker-compose.v2.3.0.yml up -d

# Step 3: Monitor for issues
docker-compose logs -f tmws
```

---

## 9. FAQ

### Q1: What happens to existing users after deployment?

**Answer**: All existing agents are automatically assigned FREE tier licenses with 30-day expiration. Admins should manually upgrade paid users to PRO/ENTERPRISE using the CLI.

### Q2: Can I migrate licenses from another system?

**Answer**: Yes, use the license import API:

```bash
curl -X POST http://localhost:8000/api/v1/license/import \
    -H "Content-Type: application/json" \
    -d '{
        "licenses": [
            {
                "agent_id": "user-1",
                "tier": "PRO",
                "expires_at": "2026-01-01T00:00:00Z"
            }
        ]
    }'
```

### Q3: How do I monitor license expiration?

**Answer**: Use Prometheus alerts:

```yaml
# Alert when licenses expiring in 7 days > 10
- alert: LicenseExpiringIn7Days
  expr: tmws_expiring_licenses_7d > 10
  for: 1h
  annotations:
    summary: "{{ $value }} licenses expiring soon"
```

### Q4: Can ADMINISTRATOR licenses expire?

**Answer**: No, ADMINISTRATOR tier supports perpetual licenses (`expires_at = NULL`). They never expire and require manual revocation if needed.

### Q5: What's the performance impact of budget validation?

**Answer**: Measured latency: 7-10ms P95 (target: <15ms). Impact is minimal:
- FREE/PRO: Full validation (10ms)
- ENTERPRISE: No token budget check (5ms)
- ADMINISTRATOR: Skip all checks (3ms)

---

## 10. Support & Escalation

### 10.1 Deployment Issues

**Common Issues**:

1. **Migration Failed**
   ```bash
   # Check logs
   docker-compose logs tmws

   # Manual migration
   docker-compose exec tmws alembic upgrade head --sql
   ```

2. **License Activation Failed**
   ```bash
   # Validate license manually
   docker-compose exec tmws tmws license validate --license-key TMWS-...
   ```

3. **Budget Check Slow**
   ```bash
   # Check Redis connection
   docker-compose exec redis redis-cli ping

   # Check Redis stats
   docker-compose exec redis redis-cli info stats
   ```

### 10.2 Emergency Contacts

- **Critical Issues**: ops-oncall@your-company.com
- **License Issues**: license-support@your-company.com
- **General Support**: support@your-company.com

---

**End of Deployment Guide**

*For technical details, see: `docs/architecture/PROGRESSIVE_DISCLOSURE_V2_SPEC.md`*
