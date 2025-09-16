# TMWS Docker Deployment Guide

## 🔒 Security-First Containerization by Artemis & Hestia

This guide provides comprehensive instructions for deploying TMWS in production-ready containers with enterprise-grade security.

## 📋 Quick Start

### Development Environment

```bash
# Clone and setup
git clone <repo>
cd tmws

# Start development environment
./scripts/deploy.sh development up --build

# Access the application
curl http://localhost:8000/health
```

### Production Environment

```bash
# 1. Setup environment variables
cp .env.production .env
# Edit .env with your actual secrets (CRITICAL!)

# 2. Build and deploy
./scripts/build.sh production
./scripts/deploy.sh production up --build

# 3. Verify deployment
curl https://your-domain.com/health
```

## 🏗️ Architecture Overview

### Multi-Stage Docker Build

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Dependencies   │───▶│   Builder       │───▶│   Production    │
│  python:3.11    │    │  python:3.11    │    │  distroless     │
│  - Build tools  │    │  - App code     │    │  - Runtime only │
│  - Compile deps │    │  - Final prep   │    │  - <100MB       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Container Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Docker Network                   │
│                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐│
│  │    Nginx     │  │     TMWS     │  │ PostgreSQL  ││
│  │   (Proxy)    │◄─┤  (FastAPI)   │◄─┤ + pgvector  ││
│  │     :80      │  │    :8000     │  │    :5432    ││
│  └──────────────┘  └──────────────┘  └─────────────┘│
│                            │                        │
│                    ┌──────────────┐                 │
│                    │    Redis     │                 │
│                    │   (Cache)    │                 │
│                    │    :6379     │                 │
│                    └──────────────┘                 │
└─────────────────────────────────────────────────────┘
```

## 🔐 Security Features (Hestia Approved)

### Container Security
- **Distroless base image**: Minimal attack surface (<100MB)
- **Non-root user**: Runs as user 65532:65532
- **Read-only root filesystem**: Prevents runtime modifications
- **Security scanning**: Automated vulnerability detection
- **Multi-stage build**: Eliminates build tools from final image

### Network Security
- **Isolated networks**: Separate frontend/backend/monitoring
- **TLS encryption**: HTTPS with modern cipher suites
- **Rate limiting**: API and authentication endpoint protection
- **Security headers**: HSTS, CSP, XSS protection
- **Network policies**: Kubernetes-level traffic control

### Data Security
- **Encrypted secrets**: Base64-encoded environment variables
- **Database encryption**: TLS connections, encrypted storage
- **Redis authentication**: Password-protected cache access
- **Volume encryption**: Persistent data protection

## 📦 Images & Tags

| Environment | Image Tag | Size | Description |
|------------|-----------|------|-------------|
| Development | `tmws:dev` | ~200MB | Full dev tools, debugging |
| Production | `tmws:prod` | ~95MB | Optimized, distroless |
| Latest | `tmws:latest` | ~95MB | Latest stable release |

## 🚀 Deployment Options

### Option 1: Docker Compose (Recommended for Single-Node)

```bash
# Development
docker-compose up -d

# Production
docker-compose -f docker-compose.prod.yml up -d
```

### Option 2: Kubernetes (Recommended for Production)

```bash
# Apply all manifests
kubectl apply -f k8s/

# Or step by step
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secrets.yaml      # Edit secrets first!
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/postgresql.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/tmws-app.yaml
kubectl apply -f k8s/ingress.yaml
```

### Option 3: Docker Swarm

```bash
# Initialize swarm (if not already)
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.prod.yml tmws
```

## ⚙️ Configuration

### Environment Variables

#### Required (Production)
- `POSTGRES_PASSWORD`: Database password
- `REDIS_PASSWORD`: Redis password
- `TMWS_SECRET_KEY`: Application secret key

#### Optional
- `TMWS_ENVIRONMENT`: deployment environment (default: production)
- `TMWS_LOG_LEVEL`: logging level (default: INFO)
- `WORKERS`: number of worker processes (default: 4)

### Volumes and Persistence

```yaml
volumes:
  postgres_data: /var/lib/tmws/postgres  # Database storage
  redis_data: /var/lib/tmws/redis        # Cache storage
  tmws_logs: /var/log/tmws               # Application logs
  nginx_logs: /var/log/nginx             # Proxy logs
```

## 🏥 Health Checks & Monitoring

### Health Endpoints
- `GET /health`: Application health check
- `GET /metrics`: Prometheus metrics (restricted access)

### Monitoring Stack (Optional)
```bash
# Start with monitoring
docker-compose -f docker-compose.prod.yml --profile monitoring up -d

# Access dashboards
open http://localhost:3000  # Grafana (admin/password from env)
open http://localhost:9090  # Prometheus
```

### Key Metrics
- **Response Time**: <200ms (95th percentile)
- **Error Rate**: <0.1%
- **Memory Usage**: <2GB per instance
- **CPU Usage**: <70% average

## 🔧 Operations

### Build Commands

```bash
# Build specific environment
./scripts/build.sh development
./scripts/build.sh production

# Build and push to registry
REGISTRY=your-registry.com ./scripts/build.sh production true

# Multi-architecture build (ARM64 + AMD64)
./scripts/build.sh production true true
```

### Deployment Commands

```bash
# Start services
./scripts/deploy.sh production up

# Stop services
./scripts/deploy.sh production down

# Restart services
./scripts/deploy.sh production restart

# View logs
./scripts/deploy.sh production logs

# Check status
./scripts/deploy.sh production status
```

### Database Operations

```bash
# Run migrations
docker-compose exec tmws python -m alembic upgrade head

# Create backup
docker-compose exec postgres pg_dump -U tmws_user tmws > backup.sql

# Restore backup
docker-compose exec -T postgres psql -U tmws_user -d tmws < backup.sql
```

## 🚨 Troubleshooting

### Common Issues

1. **Container fails to start**
   ```bash
   # Check logs
   docker-compose logs tmws
   
   # Check health
   docker-compose exec tmws curl http://localhost:8000/health
   ```

2. **Database connection issues**
   ```bash
   # Test database connectivity
   docker-compose exec tmws python -c "
   from src.core.config import get_settings
   from src.core.database import Database
   db = Database(get_settings().database_url)
   print('Database connected!' if db.test_connection() else 'Failed!')
   "
   ```

3. **Permission issues**
   ```bash
   # Check user permissions
   docker-compose exec tmws id
   
   # Fix volume permissions (if needed)
   sudo chown -R 65532:65532 /var/lib/tmws
   ```

### Performance Tuning

1. **Database optimization**
   ```sql
   -- PostgreSQL performance settings
   ALTER SYSTEM SET shared_buffers = '512MB';
   ALTER SYSTEM SET effective_cache_size = '2GB';
   ALTER SYSTEM SET maintenance_work_mem = '128MB';
   ```

2. **Redis optimization**
   ```
   # Redis memory optimization
   maxmemory 512mb
   maxmemory-policy allkeys-lru
   ```

3. **Application optimization**
   ```bash
   # Increase worker processes
   export WORKERS=8
   docker-compose up -d
   ```

## 🔒 Security Checklist

### Pre-Production Security Review

- [ ] All default passwords changed
- [ ] Secrets properly configured (not in images)
- [ ] TLS certificates configured
- [ ] Network policies applied
- [ ] Security scanning completed
- [ ] Backup procedures tested
- [ ] Monitoring configured
- [ ] Log aggregation setup
- [ ] Incident response plan ready

### Regular Security Tasks

- [ ] Update base images monthly
- [ ] Rotate secrets quarterly
- [ ] Review access logs weekly
- [ ] Security scan before each release
- [ ] Test backup/restore monthly

## 📊 Resource Requirements

### Minimum Requirements
- **CPU**: 2 cores
- **Memory**: 4GB RAM
- **Storage**: 20GB SSD
- **Network**: 100Mbps

### Recommended Production
- **CPU**: 4-8 cores
- **Memory**: 8-16GB RAM  
- **Storage**: 100GB+ SSD
- **Network**: 1Gbps+
- **Load Balancer**: Yes
- **Monitoring**: Required

## 🔄 CI/CD Integration

### GitHub Actions Example

```yaml
name: Build and Deploy TMWS
on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Build Images
      run: ./scripts/build.sh production true true
```

### GitLab CI Example

```yaml
build-tmws:
  stage: build
  script:
    - ./scripts/build.sh production true
  only:
    - main
```

## 📞 Support

For issues or questions:
1. Check logs: `docker-compose logs tmws`
2. Review health: `curl http://localhost:8000/health`
3. Verify configuration: Check `.env` file
4. Test connectivity: Database and Redis connections

---

*"Perfection is not negotiable. Excellence is the only acceptable standard."*

**Built with security-first principles by Artemis & Hestia**