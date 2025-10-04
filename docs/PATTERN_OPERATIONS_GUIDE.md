# Pattern Execution Service - Operations Guide

**TMWS v2.2.0** | **For System Administrators**

## Table of Contents

1. [Deployment Guide](#deployment-guide)
2. [Configuration Reference](#configuration-reference)
3. [Monitoring and Alerts](#monitoring-and-alerts)
4. [Performance Tuning](#performance-tuning)
5. [Backup and Recovery](#backup-and-recovery)
6. [Troubleshooting](#troubleshooting)

## Deployment Guide

### Prerequisites

#### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Python | 3.11+ | 3.12+ |
| PostgreSQL | 14+ | 15+ |
| Redis | 6+ | 7+ |
| RAM | 2GB | 4GB+ |
| CPU | 2 cores | 4+ cores |
| Storage | 10GB | 50GB+ SSD |

#### Required Services

```bash
# PostgreSQL with pgvector
sudo apt-get install postgresql-15 postgresql-15-pgvector

# Redis
sudo apt-get install redis-server

# Python dependencies
pip install -r requirements.txt
```

### Installation Steps

#### Step 1: Database Setup

```bash
# Create database
sudo -u postgres createdb tmws_production

# Install pgvector extension
sudo -u postgres psql tmws_production -c "CREATE EXTENSION IF NOT EXISTS vector;"

# Create user
sudo -u postgres psql tmws_production <<EOF
CREATE USER tmws_user WITH PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE tmws_production TO tmws_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO tmws_user;
EOF
```

#### Step 2: Redis Setup

```bash
# Configure Redis
sudo nano /etc/redis/redis.conf

# Recommended settings:
# maxmemory 1gb
# maxmemory-policy allkeys-lru
# save 900 1
# save 300 10
# save 60 10000

# Start Redis
sudo systemctl enable redis-server
sudo systemctl start redis-server
```

#### Step 3: TMWS Configuration

```bash
# Create environment file
cat > /opt/tmws/.env <<EOF
# Database
TMWS_DATABASE_URL=postgresql://tmws_user:secure_password_here@localhost:5432/tmws_production

# Redis
TMWS_REDIS_URL=redis://localhost:6379/0

# Environment
TMWS_ENVIRONMENT=production

# Security
TMWS_SECRET_KEY=$(openssl rand -hex 32)
TMWS_AUTH_ENABLED=true

# Performance
TMWS_DB_MAX_CONNECTIONS=20
TMWS_DB_POOL_PRE_PING=true
TMWS_CACHE_TTL=300
TMWS_CACHE_MAX_SIZE=1000

# Logging
TMWS_LOG_LEVEL=INFO
TMWS_LOG_FILE=/var/log/tmws/app.log
EOF
```

#### Step 4: Database Migration

```bash
# Run migrations
cd /opt/tmws
python -m alembic upgrade head

# Verify
python -c "
from src.core.database import get_db_session
import asyncio

async def verify():
    async with get_db_session() as session:
        from sqlalchemy import text
        result = await session.execute(text('SELECT version()'))
        print(result.scalar())

asyncio.run(verify())
"
```

#### Step 5: Pattern Service Initialization

```bash
# Initialize pattern service
python scripts/initialize_patterns.py

# Verify
python -c "
from src.services.pattern_execution_service import create_pattern_execution_engine
import asyncio

async def verify():
    engine = await create_pattern_execution_engine()
    result = await engine.execute('check health')
    print(f'Pattern service operational: {result.success}')

asyncio.run(verify())
"
```

### Systemd Service Setup

```ini
# /etc/systemd/system/tmws.service
[Unit]
Description=TMWS Pattern Execution Service
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=tmws
Group=tmws
WorkingDirectory=/opt/tmws
Environment="PATH=/opt/tmws/venv/bin"
EnvironmentFile=/opt/tmws/.env

ExecStart=/opt/tmws/venv/bin/python -m src.main

Restart=always
RestartSec=10

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/tmws

# Resource limits
LimitNOFILE=65536
MemoryMax=4G
CPUQuota=400%

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable tmws
sudo systemctl start tmws

# Check status
sudo systemctl status tmws
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.12-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    redis-tools \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1000 tmws

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=tmws:tmws . .

# Switch to app user
USER tmws

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import asyncio; from src.services.pattern_execution_service import create_pattern_execution_engine; asyncio.run(create_pattern_execution_engine())" || exit 1

# Start application
CMD ["python", "-m", "src.main"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: pgvector/pgvector:pg15
    environment:
      POSTGRES_DB: tmws
      POSTGRES_USER: tmws_user
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U tmws_user"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    command: redis-server --maxmemory 1gb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  tmws:
    build: .
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    environment:
      TMWS_DATABASE_URL: postgresql://tmws_user:${DB_PASSWORD}@postgres:5432/tmws
      TMWS_REDIS_URL: redis://redis:6379/0
      TMWS_ENVIRONMENT: production
      TMWS_SECRET_KEY: ${SECRET_KEY}
    ports:
      - "8000:8000"
    volumes:
      - ./config:/app/config:ro
      - logs:/var/log/tmws
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  logs:
```

```bash
# Deploy with Docker Compose
docker-compose up -d

# Check logs
docker-compose logs -f tmws

# Scale horizontally
docker-compose up -d --scale tmws=3
```

## Configuration Reference

### Environment Variables

#### Core Configuration

```bash
# Application
TMWS_ENVIRONMENT=production          # Environment: development, staging, production
TMWS_DEBUG=false                     # Debug mode (never true in production)
TMWS_LOG_LEVEL=INFO                  # Logging level: DEBUG, INFO, WARNING, ERROR

# Server
TMWS_API_HOST=0.0.0.0               # Bind address
TMWS_API_PORT=8000                  # Bind port
TMWS_WORKERS=4                       # Number of worker processes
```

#### Database Configuration

```bash
# Connection
TMWS_DATABASE_URL=postgresql://user:pass@host:5432/tmws  # Connection string
TMWS_DB_MAX_CONNECTIONS=20          # Connection pool size
TMWS_DB_MAX_OVERFLOW=10             # Additional connections
TMWS_DB_POOL_TIMEOUT=30             # Connection timeout (seconds)
TMWS_DB_POOL_RECYCLE=3600          # Connection recycle time (seconds)
TMWS_DB_POOL_PRE_PING=true         # Test connections before use

# Performance
TMWS_DB_ECHO=false                  # Log SQL queries
TMWS_DB_STATEMENT_TIMEOUT=30000    # Query timeout (milliseconds)
```

#### Redis Configuration

```bash
# Connection
TMWS_REDIS_URL=redis://localhost:6379/0  # Connection string
TMWS_REDIS_MAX_CONNECTIONS=50            # Connection pool size
TMWS_REDIS_TIMEOUT=5                      # Operation timeout (seconds)

# Cache
TMWS_CACHE_TTL=300                   # Default TTL (seconds)
TMWS_CACHE_MAX_SIZE=1000             # Local cache size
TMWS_CACHE_ENABLED=true              # Enable caching
```

#### Security Configuration

```bash
# Authentication
TMWS_SECRET_KEY=your-secret-key-here     # 32+ character secret
TMWS_AUTH_ENABLED=true                    # Enable authentication
TMWS_TOKEN_EXPIRE_MINUTES=60             # JWT expiration

# Rate Limiting
TMWS_RATE_LIMIT_ENABLED=true             # Enable rate limiting
TMWS_RATE_LIMIT_REQUESTS=100             # Requests per minute
TMWS_RATE_LIMIT_PERIOD=60                # Rate limit period (seconds)
```

#### Pattern Service Configuration

```bash
# Execution
TMWS_PATTERN_DEFAULT_MODE=balanced       # Default execution mode
TMWS_PATTERN_CACHE_ENABLED=true          # Enable pattern caching
TMWS_PATTERN_CONFIG=/app/config/patterns.yaml  # Pattern definitions

# Performance
TMWS_PATTERN_INFRA_TIMEOUT=50           # Infrastructure timeout (ms)
TMWS_PATTERN_MEMORY_TIMEOUT=100         # Memory timeout (ms)
TMWS_PATTERN_HYBRID_TIMEOUT=200         # Hybrid timeout (ms)
```

### Pattern Configuration File

```yaml
# config/patterns.yaml

# Global settings
performance_targets:
  infrastructure:
    p50: 25
    p95: 50
    p99: 75
  memory:
    p50: 50
    p95: 100
    p99: 150
  hybrid:
    p50: 100
    p95: 200
    p99: 300

cache_config:
  infrastructure:
    ttl: 300
    max_size: 500
  memory:
    ttl: 300
    max_size: 1000
  hybrid:
    ttl: 600
    max_size: 200

# Pattern definitions
infrastructure_patterns:
  - name: health_check
    pattern_type: infrastructure
    trigger_pattern: '(check|test|verify)\s+(health|status)'
    cost_tokens: 30
    priority: 10
    cache_ttl: 60

# ... more patterns
```

## Monitoring and Alerts

### Health Checks

#### Application Health

```python
# health_check.py
from src.services.pattern_execution_service import create_pattern_execution_engine

async def health_check():
    """Comprehensive health check"""
    checks = {}

    # 1. Pattern engine
    try:
        engine = await create_pattern_execution_engine()
        result = await engine.execute("check health")
        checks['pattern_engine'] = result.success
    except Exception as e:
        checks['pattern_engine'] = False
        checks['pattern_engine_error'] = str(e)

    # 2. Database
    try:
        async with get_db_session() as session:
            await session.execute(text("SELECT 1"))
        checks['database'] = True
    except Exception as e:
        checks['database'] = False
        checks['database_error'] = str(e)

    # 3. Redis
    try:
        redis = await aioredis.from_url(settings.redis_url)
        await redis.ping()
        checks['redis'] = True
    except Exception as e:
        checks['redis'] = False
        checks['redis_error'] = str(e)

    # Overall status
    checks['healthy'] = all([
        checks.get('pattern_engine', False),
        checks.get('database', False),
        checks.get('redis', False)
    ])

    return checks
```

### Prometheus Metrics

```python
# metrics.py
from prometheus_client import Counter, Histogram, Gauge, Info

# Pattern execution metrics
pattern_executions_total = Counter(
    'tmws_pattern_executions_total',
    'Total pattern executions',
    ['pattern_type', 'pattern_name', 'success']
)

pattern_execution_duration_seconds = Histogram(
    'tmws_pattern_execution_duration_seconds',
    'Pattern execution duration',
    ['pattern_type'],
    buckets=[0.01, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0]
)

pattern_cache_hit_rate = Gauge(
    'tmws_pattern_cache_hit_rate',
    'Pattern cache hit rate',
    ['cache_type']
)

pattern_tokens_used_total = Counter(
    'tmws_pattern_tokens_used_total',
    'Total tokens used',
    ['pattern_type']
)

# Database metrics
database_connections_active = Gauge(
    'tmws_database_connections_active',
    'Active database connections'
)

database_query_duration_seconds = Histogram(
    'tmws_database_query_duration_seconds',
    'Database query duration',
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0]
)

# System info
tmws_info = Info('tmws', 'TMWS version and configuration')
tmws_info.info({
    'version': '2.2.0',
    'pattern_service': 'enabled'
})
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "TMWS Pattern Execution Service",
    "panels": [
      {
        "title": "Execution Time (P50, P95, P99)",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(tmws_pattern_execution_duration_seconds_bucket[5m]))",
            "legendFormat": "P50"
          },
          {
            "expr": "histogram_quantile(0.95, rate(tmws_pattern_execution_duration_seconds_bucket[5m]))",
            "legendFormat": "P95"
          },
          {
            "expr": "histogram_quantile(0.99, rate(tmws_pattern_execution_duration_seconds_bucket[5m]))",
            "legendFormat": "P99"
          }
        ]
      },
      {
        "title": "Throughput (Requests/sec)",
        "targets": [
          {
            "expr": "rate(tmws_pattern_executions_total[1m])",
            "legendFormat": "{{pattern_type}}"
          }
        ]
      },
      {
        "title": "Cache Hit Rate",
        "targets": [
          {
            "expr": "tmws_pattern_cache_hit_rate",
            "legendFormat": "{{cache_type}}"
          }
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "rate(tmws_pattern_executions_total{success='false'}[5m])",
            "legendFormat": "{{pattern_type}}"
          }
        ]
      }
    ]
  }
}
```

### Alert Rules

```yaml
# alerts.yml
groups:
  - name: tmws_pattern_service
    interval: 30s
    rules:
      # Performance alerts
      - alert: HighExecutionTime
        expr: histogram_quantile(0.95, rate(tmws_pattern_execution_duration_seconds_bucket[5m])) > 0.2
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Pattern execution P95 exceeds 200ms"
          description: "P95 execution time is {{ $value }}s"

      - alert: CriticalExecutionTime
        expr: histogram_quantile(0.99, rate(tmws_pattern_execution_duration_seconds_bucket[5m])) > 0.5
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Pattern execution P99 exceeds 500ms"
          description: "P99 execution time is {{ $value }}s"

      # Cache alerts
      - alert: LowCacheHitRate
        expr: tmws_pattern_cache_hit_rate < 0.7
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Cache hit rate below 70%"
          description: "Cache hit rate is {{ $value }}%"

      # Error alerts
      - alert: HighErrorRate
        expr: rate(tmws_pattern_executions_total{success='false'}[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Error rate above 5%"
          description: "Error rate is {{ $value }}"

      # Resource alerts
      - alert: HighDatabaseConnections
        expr: tmws_database_connections_active > 18
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Database connections approaching limit"
          description: "Active connections: {{ $value }}/20"
```

### Log Aggregation

```python
# logging_config.py
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'json': {
            'class': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(asctime)s %(name)s %(levelname)s %(message)s'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'json',
            'stream': 'ext://sys.stdout'
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'json',
            'filename': '/var/log/tmws/app.log',
            'maxBytes': 100_000_000,  # 100MB
            'backupCount': 10
        }
    },
    'root': {
        'level': 'INFO',
        'handlers': ['console', 'file']
    },
    'loggers': {
        'src.services.pattern_execution_service': {
            'level': 'INFO'
        }
    }
}
```

## Performance Tuning

### Database Optimization

#### Index Creation

```sql
-- Pattern-specific indexes
CREATE INDEX CONCURRENTLY idx_memory_content_pattern
ON memories USING gin(to_tsvector('english', content));

CREATE INDEX CONCURRENTLY idx_memory_importance_created
ON memories(importance DESC, created_at DESC);

CREATE INDEX CONCURRENTLY idx_memory_tags
ON memories USING gin(tags);

-- Vector index
CREATE INDEX CONCURRENTLY idx_memory_embedding
ON memories USING ivfflat (embedding vector_cosine_ops)
WITH (lists = 100);

-- Statistics update
ANALYZE memories;
```

#### Connection Pooling

```python
# Optimal pool settings
settings.database_pool_size = min(20, cpu_count * 5)
settings.database_max_overflow = settings.database_pool_size // 2
settings.database_pool_pre_ping = True
settings.database_pool_recycle = 3600
```

### Redis Optimization

```conf
# /etc/redis/redis.conf

# Memory
maxmemory 2gb
maxmemory-policy allkeys-lru

# Persistence (balanced)
save 900 1
save 300 10
save 60 10000
appendonly yes
appendfsync everysec

# Performance
tcp-backlog 511
timeout 0
tcp-keepalive 300
```

### Application Tuning

#### Worker Configuration

```bash
# For CPU-bound workloads
TMWS_WORKERS=$(nproc)

# For I/O-bound workloads
TMWS_WORKERS=$(($(nproc) * 2 + 1))
```

#### Cache Tuning

```python
# Aggressive caching
cache_manager = CacheManager(
    redis_url=settings.redis_url,
    local_ttl=120,       # 2 minute local cache
    redis_ttl=600,       # 10 minute Redis cache
    max_local_size=2000  # Larger local cache
)
```

## Backup and Recovery

### Database Backup

```bash
#!/bin/bash
# backup.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR=/backups/tmws
BACKUP_FILE="$BACKUP_DIR/tmws_$DATE.sql.gz"

# Create backup
pg_dump -h localhost -U tmws_user tmws_production | gzip > "$BACKUP_FILE"

# Verify backup
if [ $? -eq 0 ]; then
    echo "Backup successful: $BACKUP_FILE"

    # Cleanup old backups (keep 30 days)
    find "$BACKUP_DIR" -name "tmws_*.sql.gz" -mtime +30 -delete
else
    echo "Backup failed!"
    exit 1
fi
```

### Redis Backup

```bash
#!/bin/bash
# redis_backup.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR=/backups/redis

# Trigger Redis save
redis-cli BGSAVE

# Wait for save to complete
while [ $(redis-cli LASTSAVE) -eq $(redis-cli LASTSAVE) ]; do
    sleep 1
done

# Copy RDB file
cp /var/lib/redis/dump.rdb "$BACKUP_DIR/dump_$DATE.rdb"
```

### Disaster Recovery

```bash
#!/bin/bash
# restore.sh

BACKUP_FILE=$1

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

# Stop services
systemctl stop tmws
systemctl stop redis

# Restore database
gunzip -c "$BACKUP_FILE" | psql -h localhost -U tmws_user tmws_production

# Restore Redis
cp "$REDIS_BACKUP" /var/lib/redis/dump.rdb
chown redis:redis /var/lib/redis/dump.rdb

# Start services
systemctl start redis
systemctl start tmws

# Verify
python3 scripts/verify_installation.py
```

## Troubleshooting

### Common Issues

#### Issue: High Latency

**Symptoms**:
- P95 > 200ms
- Slow query responses

**Diagnosis**:
```bash
# Check database performance
psql tmws_production -c "
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;
"

# Check connection pool
python3 -c "
from src.core.database import get_pool_stats
print(get_pool_stats())
"
```

**Solutions**:
1. Add missing indexes
2. Increase connection pool
3. Enable query caching
4. Scale horizontally

#### Issue: Memory Leaks

**Symptoms**:
- Increasing RAM usage
- OOM kills

**Diagnosis**:
```python
import tracemalloc

tracemalloc.start()

# Run operations
result = await engine.execute(query)

# Get top memory consumers
snapshot = tracemalloc.take_snapshot()
for stat in snapshot.statistics('lineno')[:10]:
    print(stat)
```

**Solutions**:
1. Clear cache periodically
2. Limit result set sizes
3. Use generators for large datasets
4. Increase available memory

#### Issue: Cache Misses

**Symptoms**:
- Cache hit rate < 70%
- Repeated slow queries

**Diagnosis**:
```python
stats = engine.get_stats()
print(f"Cache hit rate: {stats['cache_hit_rate']:.1f}%")

# Check Redis
redis-cli INFO stats | grep keyspace
```

**Solutions**:
1. Increase cache TTL
2. Check Redis connectivity
3. Verify query consistency
4. Increase cache size

### Debug Mode

```bash
# Enable debug logging
export TMWS_LOG_LEVEL=DEBUG
export TMWS_DB_ECHO=true

# Run with profiling
python -m cProfile -o profile.stats -m src.main

# Analyze profile
python -m pstats profile.stats
```

---

**Production Checklist**:

- [ ] Database optimized with indexes
- [ ] Redis configured and running
- [ ] Environment variables set
- [ ] Systemd service configured
- [ ] Monitoring enabled
- [ ] Alerts configured
- [ ] Backups automated
- [ ] Disaster recovery tested
- [ ] Load testing completed
- [ ] Documentation updated

For deployment questions, see [Developer Guide](PATTERN_DEVELOPER_GUIDE.md) or contact the operations team.
