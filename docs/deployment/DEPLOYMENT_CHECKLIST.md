# TMWS v2.3.0-rc1 Deployment Checklist

**Version**: 2.3.0-rc1
**Last Updated**: 2025-11-23
**Status**: Production Release Candidate

---

## Critical Pre-Deployment Checks

### 1. Database Configuration ✅

**Task**: Apply database migrations

```bash
# Verify current database version
alembic current

# Apply all pending migrations
alembic upgrade head

# Verify migration success
alembic current
```

**Success Criteria**:
- [ ] All migrations applied successfully
- [ ] No migration errors in logs
- [ ] Database version matches latest migration ID

---

### 2. Security Configuration ✅

**Task**: Generate and configure secret key

```bash
# Generate new secret key
openssl rand -hex 32

# Add to .env file
echo "TMWS_SECRET_KEY=<generated-key>" >> .env
```

**Success Criteria**:
- [ ] Secret key is 64 characters (32 bytes hex-encoded)
- [ ] Secret key stored in `.env` file (never in git)
- [ ] `.env` file added to `.gitignore`

---

### 3. Environment Variables ✅

**Task**: Configure all required environment variables

Create `.env` file with:

```bash
# Required
TMWS_DATABASE_URL=sqlite+aiosqlite:///./data/tmws.db
TMWS_SECRET_KEY=<64-char-hex-string>
TMWS_ENVIRONMENT=production

# Optional but recommended
TMWS_LOG_LEVEL=INFO
TMWS_CORS_ORIGINS='["https://yourdomain.com"]'
TMWS_API_KEY_EXPIRE_DAYS=90
TMWS_OLLAMA_BASE_URL=http://localhost:11434
```

**Success Criteria**:
- [ ] All required variables set
- [ ] CORS origins configured for production domains
- [ ] Database URL points to production database
- [ ] Environment set to "production"

---

### 4. CORS Configuration ✅

**Task**: Configure Cross-Origin Resource Sharing

```python
# Verify in src/main.py or configuration
TMWS_CORS_ORIGINS='["https://app.yourdomain.com","https://admin.yourdomain.com"]'
```

**Success Criteria**:
- [ ] Only authorized domains in CORS allow list
- [ ] Wildcard (*) NOT used in production
- [ ] HTTPS-only domains configured

---

### 5. HTTPS Configuration ✅

**Task**: Enable HTTPS/TLS encryption

**Success Criteria**:
- [ ] Valid SSL/TLS certificate installed
- [ ] HTTP-to-HTTPS redirect enabled
- [ ] HSTS header configured (Strict-Transport-Security)
- [ ] Certificate auto-renewal configured (Let's Encrypt)

---

### 6. Monitoring Setup ✅

**Task**: Configure application monitoring

**Success Criteria**:
- [ ] Prometheus metrics endpoint configured (`/metrics`)
- [ ] Log aggregation configured (e.g., ELK, CloudWatch)
- [ ] Error tracking configured (e.g., Sentry)
- [ ] Health check endpoint verified (`/health`)
- [ ] Resource usage dashboards created

---

### 7. Backup Strategy ✅

**Task**: Implement database backup strategy

```bash
# SQLite backup script example
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
sqlite3 data/tmws.db ".backup data/backups/tmws_backup_$DATE.db"

# Retention: Keep last 30 days
find data/backups/ -name "tmws_backup_*.db" -mtime +30 -delete
```

**Success Criteria**:
- [ ] Automated daily backups configured
- [ ] Backup retention policy defined (e.g., 30 days)
- [ ] Backup restoration tested
- [ ] Off-site backup storage configured

---

### 8. Rate Limiting ✅

**Task**: Configure API rate limiting

**Success Criteria**:
- [ ] Rate limits configured per endpoint
- [ ] Authentication-based rate limits active
- [ ] IP-based rate limits configured
- [ ] Rate limit exceeded responses verified (429 status)

---

### 9. Ollama Service ✅

**Task**: Ensure Ollama service is running

```bash
# Verify Ollama installation
ollama --version

# Pull required model
ollama pull zylonai/multilingual-e5-large

# Start Ollama service
ollama serve

# Verify service
curl http://localhost:11434/api/tags
```

**Success Criteria**:
- [ ] Ollama service running and accessible
- [ ] `zylonai/multilingual-e5-large` model downloaded
- [ ] TMWS can connect to Ollama (check logs)
- [ ] Embedding generation works (test via API)

---

### 10. ChromaDB Initialization ✅

**Task**: Initialize ChromaDB vector database

```bash
# ChromaDB data directory
mkdir -p data/chroma

# Verify permissions
chmod 755 data/chroma
```

**Success Criteria**:
- [ ] ChromaDB data directory created
- [ ] Correct file permissions set
- [ ] Initial collection created successfully
- [ ] Vector search working (test via API)

---

### 11. SQLite WAL Mode ✅

**Task**: Enable Write-Ahead Logging for SQLite

```bash
# Verify WAL mode enabled
sqlite3 data/tmws.db "PRAGMA journal_mode;"
# Should return: wal

# If not, enable it
sqlite3 data/tmws.db "PRAGMA journal_mode=WAL;"
```

**Success Criteria**:
- [ ] WAL mode enabled (verified with PRAGMA)
- [ ] SQLite checkpoint interval configured
- [ ] Write performance tested under load

---

### 12. Security Audit ✅

**Task**: Complete pre-deployment security audit

**Success Criteria**:
- [ ] Dependency vulnerability scan completed (`pip-audit` or `safety`)
- [ ] No CRITICAL or HIGH vulnerabilities present
- [ ] Authentication mechanisms tested
- [ ] Authorization policies verified
- [ ] Namespace isolation tested (V-1 path traversal fix verified)
- [ ] Rate limiting enforcement tested

---

### 13. Performance Benchmarks ✅

**Task**: Verify performance targets met

**Benchmarks** (P95 latency):
- [ ] Semantic search: < 20ms
- [ ] Vector similarity: < 10ms
- [ ] Metadata queries: < 20ms
- [ ] Cross-agent sharing: < 15ms
- [ ] API response time: < 200ms

**Load Testing**:
```bash
# Example using Apache Bench
ab -n 1000 -c 10 http://localhost:8000/api/v1/health
```

**Success Criteria**:
- [ ] All performance targets met
- [ ] No memory leaks detected under sustained load
- [ ] Database connection pool stable under load

---

### 14. Integration Tests ✅

**Task**: Run full integration test suite

```bash
# Run all integration tests
pytest tests/integration/ -v

# Run security tests
pytest tests/unit/security/ -v

# Run performance tests
pytest tests/unit/services/test_learning_trust_performance.py -v
```

**Success Criteria**:
- [ ] All integration tests PASS
- [ ] All security tests PASS (20/20 as of Phase 2D-1)
- [ ] All performance tests PASS (7/7 as of Phase 1)
- [ ] Zero test regressions

---

### 15. Documentation Review ✅

**Task**: Verify all deployment documentation is up-to-date

**Success Criteria**:
- [ ] `README.md` updated with v2.3.0-rc1 information
- [ ] `CHANGELOG.md` includes all changes since last release
- [ ] API documentation up-to-date
- [ ] Security documentation reviewed
- [ ] Deployment guides accurate for current version

---

## Additional Production Readiness Checks

### 16. Service Startup ✅

**Task**: Verify clean service startup

```bash
# Start TMWS MCP server
uv run tmws-mcp-server

# Check logs for errors
tail -f logs/tmws.log
```

**Success Criteria**:
- [ ] Service starts without errors
- [ ] All required connections established (DB, Ollama, ChromaDB)
- [ ] MCP server listening on correct port
- [ ] Health check endpoint returns 200 OK

---

### 17. User Acceptance Testing (UAT) ✅

**Task**: Complete UAT scenarios

**Test Scenarios**:
1. Memory creation and retrieval
2. Semantic search across namespaces
3. Agent verification workflow
4. Pattern learning and propagation
5. Trust score updates

**Success Criteria**:
- [ ] All UAT scenarios PASS
- [ ] No unexpected errors in logs
- [ ] User experience meets expectations

---

### 18. Rollback Plan ✅

**Task**: Document rollback procedures

**Success Criteria**:
- [ ] Previous version backup created
- [ ] Database rollback script prepared
- [ ] Rollback procedure documented
- [ ] Rollback tested in staging environment

---

### 19. Capacity Planning ✅

**Task**: Verify resource capacity

**Success Criteria**:
- [ ] Disk space sufficient (minimum 10GB free)
- [ ] Memory allocation adequate (minimum 2GB)
- [ ] CPU capacity verified (load testing results)
- [ ] Network bandwidth confirmed

---

### 20. Compliance & Legal ✅

**Task**: Verify compliance requirements

**Success Criteria**:
- [ ] Data privacy policies documented
- [ ] Terms of service updated
- [ ] User consent mechanisms in place
- [ ] Data retention policies defined

---

## Deployment Sign-Off

### Pre-Deployment Team Sign-Off

- [ ] **Technical Lead**: Infrastructure verified
- [ ] **Security Lead**: Security audit passed (Hestia)
- [ ] **QA Lead**: All tests passing
- [ ] **Product Owner**: Features approved

### Deployment Execution

- [ ] **Date/Time**: _______________
- [ ] **Deployed By**: _______________
- [ ] **Deployment Method**: _______________
- [ ] **Rollback Plan Ready**: Yes / No

### Post-Deployment Verification

- [ ] **Service Health**: OK / DEGRADED / DOWN
- [ ] **Error Rate**: < 0.1%
- [ ] **Latency**: Within targets
- [ ] **User Reports**: No critical issues

---

## Emergency Contact Information

| Role | Name | Contact |
|------|------|---------|
| On-Call Engineer | ___________ | ___________ |
| Security Lead | ___________ | ___________ |
| Technical Lead | ___________ | ___________ |

---

## Notes

### Known Issues (v2.3.0-rc1)

- **pysqlcipher3 Build Issue**: The `pysqlcipher3` package has been moved to optional dependencies (`[encryption]` extra) as it is not actively used in v2.3.0-rc1. If database encryption is required, install SQLCipher C library first (`brew install sqlcipher` on macOS) then install with `uv sync --extra encryption`.

### Deferred to v2.3.1+

- Phase 4 Large File Refactoring (LOW risk, non-blocking)

---

**End of Deployment Checklist**

*Last validated: 2025-11-23*
*Next review: Before v2.3.0 GA release*
