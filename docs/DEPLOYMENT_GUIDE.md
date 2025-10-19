# TMWS v2.3.0 Production Deployment Guide

**Complete guide for deploying TMWS to production environments**

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Infrastructure Setup](#infrastructure-setup)
3. [PostgreSQL Configuration](#postgresql-configuration)
4. [Redis Configuration](#redis-configuration)
5. [ChromaDB Configuration](#chromadb-configuration)
6. [Application Deployment](#application-deployment)
7. [Security Hardening](#security-hardening)
8. [Monitoring & Alerting](#monitoring--alerting)
9. [Backup & Recovery](#backup--recovery)
10. [Scaling & Performance](#scaling--performance)
11. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

**Minimum Production Setup**:
- **CPU**: 4 cores (8 cores recommended)
- **RAM**: 16GB (32GB recommended for 100K+ memories)
- **Disk**: 100GB SSD (500GB for large deployments)
- **Network**: 1Gbps connection
- **OS**: Ubuntu 22.04 LTS, macOS 14+, or RHEL 9+

### Software Dependencies

| Component | Minimum Version | Recommended Version |
|-----------|----------------|---------------------|
| **Python** | 3.11 | 3.11.7 |
| **PostgreSQL** | 17.0 | 17.2 |
| **pgvector** | 0.5.0 | 0.5.1 |
| **Redis** | 7.0 | 7.2.3 |
| **ChromaDB** | 0.4.20 | 0.4.22 |
| **Docker** (optional) | 24.0 | 25.0 |

### Required Tools

```bash
# Install uv (Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install PostgreSQL client tools
sudo apt install postgresql-client-17  # Ubuntu
brew install postgresql@17             # macOS

# Install Redis client tools
sudo apt install redis-tools  # Ubuntu
brew install redis            # macOS
```

---

## Infrastructure Setup

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   Load Balancer (Optional)                   │
│                     (nginx / traefik)                        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  Claude Code Instances                       │
│         (Multiple terminals, unique AGENT_ID each)          │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Terminal │  │ Terminal │  │ Terminal │  │ Terminal │   │
│  │    1     │  │    2     │  │    3     │  │    4     │   │
│  │ (athena) │  │(artemis) │  │ (hestia) │  │  (eris)  │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
└───────┼─────────────┼─────────────┼─────────────┼─────────┘
        │             │             │             │
        └─────────────┴─────────────┴─────────────┘
                         │
                         ▼
        ┌────────────────────────────────────┐
        │     Shared Database Layer          │
        │                                    │
        │  ┌──────────┐  ┌──────────┐       │
        │  │PostgreSQL│  │  Redis   │       │
        │  │  (ACID)  │  │ (Cache)  │       │
        │  └──────────┘  └──────────┘       │
        │                                    │
        │  ┌──────────┐                     │
        │  │ ChromaDB │                     │
        │  │ (Vector) │                     │
        │  └──────────┘                     │
        └────────────────────────────────────┘
```

### Deployment Options

#### Option 1: Single Server (Development/Small Scale)

```
Single Server (16GB RAM, 4 cores)
├── PostgreSQL (8GB RAM)
├── Redis (2GB RAM)
├── ChromaDB (4GB RAM)
└── TMWS (2GB RAM)
```

**Capacity**: 10 agents, 10K memories, 1K tasks/day

#### Option 2: Distributed (Production)

```
Database Server 1 (32GB RAM, 8 cores)
├── PostgreSQL Primary (24GB RAM)
└── pgvector extension

Database Server 2 (32GB RAM, 8 cores)
└── PostgreSQL Standby (24GB RAM)

Cache Server (16GB RAM, 4 cores)
├── Redis Primary (12GB RAM)
└── Redis Sentinel

Vector Server (32GB RAM, 8 cores)
└── ChromaDB (28GB RAM)

Application Servers (8GB RAM, 4 cores each)
├── TMWS Instance 1
├── TMWS Instance 2
└── TMWS Instance 3 (N instances)
```

**Capacity**: 100K agents, 1M+ memories, 100K tasks/day

---

## PostgreSQL Configuration

### Installation

#### Ubuntu

```bash
# Add PostgreSQL repository
sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -

# Install PostgreSQL 17
sudo apt update
sudo apt install postgresql-17 postgresql-client-17

# Install pgvector
sudo apt install postgresql-17-pgvector
```

#### macOS

```bash
brew install postgresql@17
brew install pgvector

# Start PostgreSQL
brew services start postgresql@17
```

### Database Setup

```bash
# Create database
sudo -u postgres createdb tmws_production

# Create user
sudo -u postgres psql <<EOF
CREATE USER tmws_user WITH PASSWORD 'CHANGE_THIS_SECURE_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE tmws_production TO tmws_user;
ALTER DATABASE tmws_production OWNER TO tmws_user;
EOF

# Enable pgvector extension
sudo -u postgres psql tmws_production <<EOF
CREATE EXTENSION IF NOT EXISTS vector;
GRANT ALL ON SCHEMA public TO tmws_user;
EOF
```

### Production postgresql.conf

```ini
# /etc/postgresql/17/main/postgresql.conf

# Connection Settings
max_connections = 200
shared_buffers = 8GB                # 25% of RAM
effective_cache_size = 24GB         # 75% of RAM
work_mem = 64MB
maintenance_work_mem = 2GB

# WAL Settings
wal_level = replica
max_wal_size = 4GB
min_wal_size = 1GB
checkpoint_completion_target = 0.9

# Performance
random_page_cost = 1.1              # SSD
effective_io_concurrency = 200      # SSD
default_statistics_target = 100

# Logging
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_rotation_age = 1d
log_rotation_size = 100MB
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
log_checkpoints = on
log_connections = on
log_disconnections = on
log_duration = off
log_min_duration_statement = 1000   # Log queries > 1s

# SSL (Production)
ssl = on
ssl_cert_file = '/etc/postgresql/ssl/server.crt'
ssl_key_file = '/etc/postgresql/ssl/server.key'
```

### pg_hba.conf (Authentication)

```ini
# /etc/postgresql/17/main/pg_hba.conf

# TYPE  DATABASE        USER            ADDRESS                 METHOD

# Local connections
local   all             postgres                                peer
local   all             tmws_user                               scram-sha-256

# Remote connections (SSL required)
hostssl tmws_production tmws_user       10.0.0.0/8              scram-sha-256
hostssl tmws_production tmws_user       172.16.0.0/12           scram-sha-256

# Replication connections
hostssl replication     replicator      10.0.0.0/8              scram-sha-256
```

### Database Migrations

```bash
# Set environment variables
export TMWS_DATABASE_URL="postgresql://tmws_user:PASSWORD@localhost:5432/tmws_production"

# Run migrations
cd /path/to/tmws
python -m alembic upgrade head

# Verify migrations
python -m alembic current
```

### PostgreSQL Replication (Optional)

**Primary Server**:

```bash
# Create replication user
sudo -u postgres psql <<EOF
CREATE USER replicator WITH REPLICATION ENCRYPTED PASSWORD 'REPLICATION_PASSWORD';
EOF

# Configure postgresql.conf
# wal_level = replica  (already set above)
# max_wal_senders = 10
```

**Standby Server**:

```bash
# Initial replication from primary
pg_basebackup -h primary_host -D /var/lib/postgresql/17/main -U replicator -P -v -R

# Start standby
sudo systemctl start postgresql@17-main
```

---

## Redis Configuration

### Installation

#### Ubuntu

```bash
# Add Redis repository
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list

# Install Redis 7.2
sudo apt update
sudo apt install redis-server
```

#### macOS

```bash
brew install redis
brew services start redis
```

### Production redis.conf

```conf
# /etc/redis/redis.conf

# Network
bind 0.0.0.0
port 6379
protected-mode yes
requirepass YOUR_SECURE_REDIS_PASSWORD

# TLS (Production)
tls-port 6380
tls-cert-file /etc/redis/ssl/redis.crt
tls-key-file /etc/redis/ssl/redis.key
tls-ca-cert-file /etc/redis/ssl/ca.crt

# Memory Management
maxmemory 2gb
maxmemory-policy allkeys-lru

# Persistence
save 900 1       # Save after 900 sec if at least 1 key changed
save 300 10      # Save after 300 sec if at least 10 keys changed
save 60 10000    # Save after 60 sec if at least 10000 keys changed
appendonly yes
appendfsync everysec

# Performance
tcp-backlog 511
timeout 0
tcp-keepalive 300

# Logging
loglevel notice
logfile /var/log/redis/redis-server.log

# Security
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command CONFIG "CONFIG_SECURE_COMMAND_NAME"
```

### Redis Sentinel (High Availability)

**Sentinel Configuration** (`/etc/redis/sentinel.conf`):

```conf
sentinel monitor tmws-redis 10.0.0.1 6379 2
sentinel down-after-milliseconds tmws-redis 5000
sentinel parallel-syncs tmws-redis 1
sentinel failover-timeout tmws-redis 10000
sentinel auth-pass tmws-redis YOUR_REDIS_PASSWORD
```

**Start Sentinel**:

```bash
redis-sentinel /etc/redis/sentinel.conf
```

---

## ChromaDB Configuration

### Installation

ChromaDB is installed automatically via Python dependencies:

```bash
cd /path/to/tmws
uv sync
```

### Production Configuration

**Environment Variables**:

```bash
# Chroma persistence directory
export TMWS_CHROMA_PERSIST_DIRECTORY="/var/lib/tmws/chroma"

# Chroma collection name
export TMWS_CHROMA_COLLECTION="tmws_memories_production"

# Chroma cache size (number of vectors to keep in memory)
export TMWS_CHROMA_CACHE_SIZE=10000
```

**Directory Setup**:

```bash
# Create Chroma data directory
sudo mkdir -p /var/lib/tmws/chroma
sudo chown tmws:tmws /var/lib/tmws/chroma
sudo chmod 700 /var/lib/tmws/chroma
```

### Initialize Chroma Collection

```bash
# Initialize with Multilingual-E5 embeddings (768-dim)
cd /path/to/tmws
python scripts/initialize_chroma.py
```

**Expected Output**:
```
Initializing Chroma collection...
✅ Collection created: tmws_memories_production
✅ HNSW index configured: M=16, ef_construction=200
✅ Distance metric: cosine
✅ Embedding dimension: 768
```

---

## Application Deployment

### Environment Configuration

Create production environment file:

```bash
# /opt/tmws/.env.production

# === Core Settings ===
TMWS_ENVIRONMENT=production
TMWS_LOG_LEVEL=INFO

# === Database Configuration ===
TMWS_DATABASE_URL=postgresql://tmws_user:PASSWORD@db-primary.example.com:5432/tmws_production?sslmode=require

# === Redis Configuration ===
TMWS_REDIS_URL=rediss://default:PASSWORD@redis.example.com:6380/0

# === Security Keys ===
TMWS_SECRET_KEY=YOUR_SECURE_SECRET_KEY_MINIMUM_32_CHARACTERS_LONG

# === ChromaDB Configuration ===
TMWS_CHROMA_PERSIST_DIRECTORY=/var/lib/tmws/chroma
TMWS_CHROMA_COLLECTION=tmws_memories_production
TMWS_CHROMA_CACHE_SIZE=10000

# === Agent Configuration ===
TMWS_AGENT_ID=production-instance-1
TMWS_AGENT_NAMESPACE=production

# === Performance Tuning ===
TMWS_DB_POOL_SIZE=20
TMWS_DB_MAX_OVERFLOW=40
TMWS_REDIS_POOL_SIZE=10

# === Monitoring ===
TMWS_ENABLE_METRICS=true
TMWS_METRICS_PORT=9090
```

### Systemd Service (Linux)

Create systemd service file:

```ini
# /etc/systemd/system/tmws.service

[Unit]
Description=TMWS (Trinitas Memory & Workflow Service)
After=network.target postgresql.service redis.service
Requires=postgresql.service redis.service

[Service]
Type=simple
User=tmws
Group=tmws
WorkingDirectory=/opt/tmws
EnvironmentFile=/opt/tmws/.env.production

ExecStart=/usr/local/bin/uvx --from /opt/tmws tmws

Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/tmws /var/log/tmws

[Install]
WantedBy=multi-user.target
```

**Enable and Start**:

```bash
# Create tmws user
sudo useradd -r -s /bin/false tmws

# Set permissions
sudo chown -R tmws:tmws /opt/tmws
sudo chown -R tmws:tmws /var/lib/tmws

# Enable service
sudo systemctl daemon-reload
sudo systemctl enable tmws.service
sudo systemctl start tmws.service

# Check status
sudo systemctl status tmws.service
sudo journalctl -u tmws.service -f
```

### Docker Deployment (Alternative)

**docker-compose.yml**:

```yaml
version: '3.8'

services:
  postgresql:
    image: pgvector/pgvector:pg17
    environment:
      POSTGRES_USER: tmws_user
      POSTGRES_PASSWORD: CHANGE_THIS
      POSTGRES_DB: tmws_production
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    restart: unless-stopped

  redis:
    image: redis:7.2-alpine
    command: redis-server --requirepass CHANGE_THIS
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    restart: unless-stopped

  tmws:
    image: tmws:v2.3.0
    environment:
      TMWS_DATABASE_URL: postgresql://tmws_user:CHANGE_THIS@postgresql:5432/tmws_production
      TMWS_REDIS_URL: redis://:CHANGE_THIS@redis:6379/0
      TMWS_SECRET_KEY: YOUR_SECRET_KEY
      TMWS_ENVIRONMENT: production
    volumes:
      - chroma_data:/var/lib/tmws/chroma
    depends_on:
      - postgresql
      - redis
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  chroma_data:
```

**Deploy**:

```bash
docker-compose up -d
docker-compose logs -f tmws
```

---

## Security Hardening

### SSL/TLS Configuration

#### PostgreSQL SSL

```bash
# Generate certificates (or use Let's Encrypt)
openssl req -new -x509 -days 365 -nodes -text \
  -out /etc/postgresql/ssl/server.crt \
  -keyout /etc/postgresql/ssl/server.key \
  -subj "/CN=db.example.com"

# Set permissions
chmod 600 /etc/postgresql/ssl/server.key
chown postgres:postgres /etc/postgresql/ssl/*

# Update postgresql.conf
ssl = on
ssl_cert_file = '/etc/postgresql/ssl/server.crt'
ssl_key_file = '/etc/postgresql/ssl/server.key'

# Restart PostgreSQL
sudo systemctl restart postgresql@17-main
```

#### Redis TLS

```bash
# Generate certificates
openssl req -new -x509 -days 365 -nodes \
  -out /etc/redis/ssl/redis.crt \
  -keyout /etc/redis/ssl/redis.key \
  -subj "/CN=redis.example.com"

# Set permissions
chmod 600 /etc/redis/ssl/redis.key
chown redis:redis /etc/redis/ssl/*

# Update redis.conf
tls-port 6380
tls-cert-file /etc/redis/ssl/redis.crt
tls-key-file /etc/redis/ssl/redis.key
```

### Firewall Configuration

```bash
# Allow only necessary ports
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 5432/tcp    # PostgreSQL (from app servers only)
sudo ufw allow 6379/tcp    # Redis (from app servers only)
sudo ufw deny 9090/tcp     # Metrics (internal only)

# Enable firewall
sudo ufw enable
```

### Secrets Management

**Option 1: Environment Variables** (Simple):

```bash
export TMWS_SECRET_KEY=$(openssl rand -base64 32)
export TMWS_DATABASE_URL="postgresql://user:$(vault read -field=password secret/db)@host/db"
```

**Option 2: HashiCorp Vault** (Enterprise):

```bash
# Store secrets in Vault
vault kv put secret/tmws \
  secret_key="..." \
  db_password="..." \
  redis_password="..."

# Retrieve at runtime
export TMWS_SECRET_KEY=$(vault kv get -field=secret_key secret/tmws)
```

### Rate Limiting

Already implemented in TMWS v2.3.0 via Redis:

```python
# Configured in .env
TMWS_RATE_LIMIT_REQUESTS=100
TMWS_RATE_LIMIT_PERIOD=60

# Or via API
from src.middleware.rate_limiter import RateLimiter
limiter = RateLimiter(requests_per_minute=100)
```

---

## Monitoring & Alerting

### Health Checks

**Basic Health Check**:

```bash
# HTTP endpoint (if REST API enabled)
curl http://localhost:8000/health

# MCP tool
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"health_check"}}' | \
  uvx --from /opt/tmws tmws
```

**Expected Response**:
```json
{
  "status": "healthy",
  "components": {
    "postgresql": {"status": "up", "latency_ms": 2.1},
    "redis": {"status": "up", "latency_ms": 0.5},
    "chroma": {"status": "up", "latency_ms": 0.8}
  },
  "timestamp": "2025-01-09T12:00:00Z"
}
```

### Metrics Collection

**Prometheus Integration** (Optional):

```python
# Add to src/main.py
from prometheus_client import Counter, Histogram, Gauge
from prometheus_client import start_http_server

# Metrics
memory_operations = Counter('tmws_memory_operations_total', 'Total memory operations', ['operation', 'status'])
operation_duration = Histogram('tmws_operation_duration_seconds', 'Operation duration', ['operation'])
active_agents = Gauge('tmws_active_agents', 'Number of active agents')

# Start metrics server
start_http_server(9090)
```

**Prometheus Configuration** (`prometheus.yml`):

```yaml
scrape_configs:
  - job_name: 'tmws'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### Grafana Dashboard

**Key Metrics to Monitor**:

1. **Performance Metrics**:
   - Vector search latency (P50, P95, P99)
   - Memory store latency
   - Agent operation latency
   - Task queue latency

2. **Resource Metrics**:
   - PostgreSQL connection pool utilization
   - Redis memory usage
   - Chroma memory usage
   - CPU and RAM usage

3. **Application Metrics**:
   - Active agents count
   - Pending tasks count
   - Memory count
   - Cache hit rate (Chroma)

4. **Error Metrics**:
   - Failed operations count
   - Database connection errors
   - Redis connection errors
   - Chroma sync failures

### Alerting Rules

**Example Prometheus Alerts** (`alerts.yml`):

```yaml
groups:
  - name: tmws
    rules:
      - alert: HighVectorSearchLatency
        expr: tmws_operation_duration_seconds{operation="vector_search", quantile="0.95"} > 0.002
        for: 5m
        annotations:
          summary: "Vector search P95 latency > 2ms"
          description: "Chroma may be overloaded or unavailable"

      - alert: RedisMemoryHigh
        expr: redis_memory_used_bytes / redis_memory_max_bytes > 0.85
        for: 5m
        annotations:
          summary: "Redis memory usage > 85%"
          description: "Consider increasing maxmemory or enabling eviction"

      - alert: PostgreSQLConnectionPoolExhausted
        expr: pg_stat_database_numbackends > 80
        for: 5m
        annotations:
          summary: "PostgreSQL active connections > 80"
          description: "Connection pool may be exhausted"

      - alert: ChromaSyncFailures
        expr: rate(tmws_chroma_sync_failures_total[5m]) > 0.1
        for: 5m
        annotations:
          summary: "Chroma sync failure rate > 10%"
          description: "Check Chroma service health"
```

---

## Backup & Recovery

### PostgreSQL Backup

**Daily Backup Script** (`/opt/tmws/scripts/backup_postgresql.sh`):

```bash
#!/bin/bash
BACKUP_DIR="/var/backups/tmws/postgresql"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="tmws_production"
DB_USER="tmws_user"

# Create backup directory
mkdir -p $BACKUP_DIR

# Full database backup
pg_dump -U $DB_USER -Fc $DB_NAME > $BACKUP_DIR/tmws_${DATE}.dump

# Compress
gzip $BACKUP_DIR/tmws_${DATE}.dump

# Delete backups older than 30 days
find $BACKUP_DIR -name "tmws_*.dump.gz" -mtime +30 -delete

# Upload to S3 (optional)
aws s3 cp $BACKUP_DIR/tmws_${DATE}.dump.gz s3://tmws-backups/postgresql/
```

**Cron Job**:

```bash
# Daily backup at 2 AM
0 2 * * * /opt/tmws/scripts/backup_postgresql.sh
```

**Restore**:

```bash
# Restore from backup
pg_restore -U tmws_user -d tmws_production /var/backups/tmws/postgresql/tmws_20250109_020000.dump.gz
```

### Redis Backup

**RDB Snapshots** (Automatic):

Redis automatically saves RDB snapshots based on `redis.conf`:

```conf
save 900 1
save 300 10
save 60 10000
```

**Manual Backup**:

```bash
# Trigger manual save
redis-cli -a PASSWORD BGSAVE

# Copy RDB file
cp /var/lib/redis/dump.rdb /var/backups/tmws/redis/dump_$(date +%Y%m%d).rdb
```

**AOF Backup**:

```bash
# Enable AOF
redis-cli -a PASSWORD CONFIG SET appendonly yes

# Copy AOF file
cp /var/lib/redis/appendonly.aof /var/backups/tmws/redis/aof_$(date +%Y%m%d).aof
```

### ChromaDB Backup

**Backup Script** (`/opt/tmws/scripts/backup_chroma.sh`):

```bash
#!/bin/bash
BACKUP_DIR="/var/backups/tmws/chroma"
DATE=$(date +%Y%m%d_%H%M%S)
CHROMA_DIR="/var/lib/tmws/chroma"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup Chroma data directory
tar -czf $BACKUP_DIR/chroma_${DATE}.tar.gz -C /var/lib/tmws chroma

# Delete backups older than 7 days (weekly rotation)
find $BACKUP_DIR -name "chroma_*.tar.gz" -mtime +7 -delete
```

**Cron Job**:

```bash
# Weekly backup on Sundays at 3 AM
0 3 * * 0 /opt/tmws/scripts/backup_chroma.sh
```

**Restore**:

```bash
# Stop TMWS
sudo systemctl stop tmws

# Restore Chroma data
tar -xzf /var/backups/tmws/chroma/chroma_20250109_030000.tar.gz -C /var/lib/tmws

# Restart TMWS
sudo systemctl start tmws
```

### Disaster Recovery Plan

1. **Backup Strategy**:
   - PostgreSQL: Daily full backups (30-day retention)
   - Redis: RDB snapshots + AOF (7-day retention)
   - Chroma: Weekly snapshots (30-day retention)

2. **Recovery Time Objective (RTO)**: < 1 hour
3. **Recovery Point Objective (RPO)**: < 24 hours

**Recovery Steps**:

```bash
# 1. Stop TMWS
sudo systemctl stop tmws

# 2. Restore PostgreSQL (most critical)
pg_restore -U tmws_user -d tmws_production /var/backups/tmws/postgresql/latest.dump.gz

# 3. Restore Redis (optional, can rebuild from PostgreSQL)
redis-cli -a PASSWORD FLUSHALL
redis-cli -a PASSWORD --rdb /var/backups/tmws/redis/latest.rdb

# 4. Restore Chroma (optional, can rebuild from PostgreSQL)
tar -xzf /var/backups/tmws/chroma/latest.tar.gz -C /var/lib/tmws

# 5. Rebuild Chroma hot cache from PostgreSQL (if needed)
python /opt/tmws/scripts/rebuild_chroma_cache.py

# 6. Start TMWS
sudo systemctl start tmws

# 7. Verify health
curl http://localhost:8000/health
```

---

## Scaling & Performance

### Horizontal Scaling

**Application Layer**:

```bash
# Run multiple TMWS instances with unique AGENT_ID
TMWS_AGENT_ID=instance-1 uvx --from /opt/tmws tmws &
TMWS_AGENT_ID=instance-2 uvx --from /opt/tmws tmws &
TMWS_AGENT_ID=instance-3 uvx --from /opt/tmws tmws &

# All instances share PostgreSQL/Redis/Chroma
```

**Load Balancer** (nginx example):

```nginx
upstream tmws_backend {
    server localhost:8001;
    server localhost:8002;
    server localhost:8003;
}

server {
    listen 80;
    server_name tmws.example.com;

    location / {
        proxy_pass http://tmws_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Database Scaling

**PostgreSQL**:

1. **Read Replicas**: Distribute read queries
   ```python
   # Configure read replica
   TMWS_DATABASE_URL_READ=postgresql://...@replica:5432/tmws_production
   ```

2. **Partitioning**: Partition large tables
   ```sql
   -- Partition memories_v2 by created_at
   CREATE TABLE memories_v2_2025_01 PARTITION OF memories_v2
   FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
   ```

**Redis**:

1. **Redis Cluster**: Horizontal sharding
   ```bash
   # Create 6-node cluster (3 masters + 3 replicas)
   redis-cli --cluster create \
     10.0.0.1:6379 10.0.0.2:6379 10.0.0.3:6379 \
     10.0.0.4:6379 10.0.0.5:6379 10.0.0.6:6379 \
     --cluster-replicas 1
   ```

**ChromaDB**:

1. **Sharding**: Split collection by namespace
   ```python
   # Create separate collections per project
   project_a_collection = client.get_or_create_collection("project_a_memories")
   project_b_collection = client.get_or_create_collection("project_b_memories")
   ```

### Performance Tuning

**PostgreSQL**:

```sql
-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM memories_v2 WHERE importance > 0.9;

-- Vacuum and analyze
VACUUM ANALYZE memories_v2;

-- Reindex
REINDEX INDEX memories_embedding_v2_idx;
```

**Redis**:

```bash
# Monitor slow queries
redis-cli -a PASSWORD SLOWLOG GET 10

# Optimize memory usage
redis-cli -a PASSWORD MEMORY DOCTOR
```

**Chroma**:

```python
# Tune HNSW index parameters for larger datasets
collection = client.get_or_create_collection(
    name="memories",
    metadata={"hnsw:M": 32, "hnsw:ef_construction": 400}
)
```

---

## Troubleshooting

### Issue: PostgreSQL Connection Errors

**Symptoms**:
```
OperationalError: could not connect to server: Connection refused
```

**Diagnosis**:
```bash
# Check PostgreSQL status
sudo systemctl status postgresql@17-main

# Check logs
sudo journalctl -u postgresql@17-main -f

# Test connection
psql -U tmws_user -h localhost -d tmws_production
```

**Solutions**:
1. Verify PostgreSQL is running: `sudo systemctl start postgresql@17-main`
2. Check pg_hba.conf authentication rules
3. Verify firewall allows port 5432
4. Check connection pool exhaustion: `SELECT count(*) FROM pg_stat_activity;`

---

### Issue: Redis Connection Errors

**Symptoms**:
```
redis.exceptions.ConnectionError: Error connecting to Redis
```

**Diagnosis**:
```bash
# Check Redis status
sudo systemctl status redis

# Test connection
redis-cli -a PASSWORD ping

# Check logs
sudo journalctl -u redis -f
```

**Solutions**:
1. Verify Redis is running: `sudo systemctl start redis`
2. Check password: `redis-cli -a YOUR_PASSWORD ping`
3. Verify firewall allows port 6379
4. Check memory usage: `redis-cli -a PASSWORD INFO memory`

---

### Issue: Slow Vector Search

**Symptoms**:
```json
{
  "search_source": "postgresql_fallback",
  "latency_ms": 250
}
```

**Diagnosis**:
```python
# Check Chroma availability
stats = get_system_stats()
print(stats["chroma"])

# Check collection size
python <<EOF
from src.services.vector_search_service import get_vector_search_service
service = get_vector_search_service()
stats = service.collection.count()
print(f"Chroma collection count: {stats}")
EOF
```

**Solutions**:
1. Verify Chroma directory exists: `ls -la /var/lib/tmws/chroma`
2. Rebuild Chroma cache: `python scripts/rebuild_chroma_cache.py`
3. Check memory availability (Chroma needs ~5GB for 10K vectors)
4. Tune HNSW parameters for your dataset size

---

### Issue: High Memory Usage

**Diagnosis**:
```bash
# Check overall memory
free -h

# Check PostgreSQL memory
ps aux | grep postgres

# Check Redis memory
redis-cli -a PASSWORD INFO memory

# Check Chroma memory
ps aux | grep chroma
```

**Solutions**:

**PostgreSQL**:
```ini
# Reduce shared_buffers
shared_buffers = 4GB  # Instead of 8GB
```

**Redis**:
```conf
# Enable eviction
maxmemory 1gb
maxmemory-policy allkeys-lru
```

**Chroma**:
```bash
# Reduce cache size
export TMWS_CHROMA_CACHE_SIZE=5000  # Instead of 10000
```

---

For additional support:
- **Issues**: [GitHub Issues](https://github.com/apto-as/tmws/issues)
- **Discussions**: [GitHub Discussions](https://github.com/apto-as/tmws/discussions)
- **Documentation**: [docs/](.)
