# TMWS Phase 4 Rollback Procedures

**Backup Location**: `backups/pre-phase4/`
**Created**: 2025-11-22
**Purpose**: Emergency rollback procedures for Phase 4 deployment

---

## Table of Contents
1. [Backup Verification](#backup-verification)
2. [Rollback Steps](#rollback-steps)
3. [Database Rollback](#database-rollback)
4. [Git Rollback](#git-rollback)
5. [Verification Tests](#verification-tests)

---

## Backup Verification

### Pre-Rollback Checklist
Before initiating rollback, verify backup integrity:

```bash
# 1. Verify backup directory exists
ls -la backups/pre-phase4/

# 2. Check database backup size (should be ~844KB)
ls -lh backups/pre-phase4/database/tmws.db.backup

# 3. Verify critical files count
find backups/pre-phase4/ -type f | wc -l
# Expected: 20+ files (1 DB + 3 config + 12 migrations + 5 critical files)

# 4. Check backup manifest
cat backups/pre-phase4/BACKUP_MANIFEST.txt
```

### Backup Integrity Validation

```bash
# Verify database backup is readable
sqlite3 backups/pre-phase4/database/tmws.db.backup "SELECT COUNT(*) FROM alembic_version;"
# Expected: Should return a number without errors

# Verify Python files are valid
python -m py_compile backups/pre-phase4/critical_files/*.py
# Expected: No syntax errors
```

---

## Rollback Steps

### Emergency Rollback (Full Restore)

**Estimated Time**: 5 minutes
**Risk Level**: LOW (backup tested)

#### Step 1: Stop Services
```bash
# Stop any running TMWS instances
pkill -f "python.*tmws"
pkill -f "uvicorn.*tmws"

# Verify no processes remain
ps aux | grep tmws
```

#### Step 2: Database Rollback
```bash
# Backup current state (optional, for forensics)
cp data/tmws.db data/tmws.db.failed-phase4

# Restore database from backup
cp backups/pre-phase4/database/tmws.db.backup data/tmws.db

# Verify database integrity
sqlite3 data/tmws.db "PRAGMA integrity_check;"
# Expected: "ok"
```

#### Step 3: Configuration Rollback
```bash
# Restore configuration files
cp backups/pre-phase4/config/pyproject.toml ./
cp backups/pre-phase4/config/.env.example ./
cp backups/pre-phase4/config/alembic.ini ./

# Verify files restored
diff pyproject.toml backups/pre-phase4/config/pyproject.toml
```

#### Step 4: Migration Rollback
```bash
# Restore migration files
rm -rf migrations/versions/*
cp -r backups/pre-phase4/migrations/alembic_versions/* migrations/versions/

# Verify Alembic state
alembic current
# Expected: Should show pre-Phase4 revision
```

#### Step 5: Critical Files Rollback
```bash
# Restore domain files
cp backups/pre-phase4/critical_files/tool_category.py src/domain/value_objects/

# Restore service files
cp backups/pre-phase4/critical_files/verification_service.py src/services/
cp backups/pre-phase4/critical_files/learning_trust_integration.py src/services/

# Restore test files
cp backups/pre-phase4/critical_files/test_go_python_category_sync.py tests/integration/
cp backups/pre-phase4/critical_files/test_verification_learning_integration.py tests/unit/services/

# Verify files restored
ls -lh src/domain/value_objects/tool_category.py
ls -lh src/services/verification_service.py
```

---

## Database Rollback

### Alembic Migration Rollback

If only database schema needs to be rolled back:

```bash
# Check current revision
alembic current

# View migration history
alembic history

# Downgrade to specific revision (replace REVISION_ID)
alembic downgrade <REVISION_ID>

# Or downgrade one step
alembic downgrade -1

# Or downgrade to base (DANGER: loses all data)
# alembic downgrade base
```

### Manual Database Rollback

```bash
# 1. Export current data (optional)
sqlite3 data/tmws.db .dump > data/failed-phase4-dump.sql

# 2. Restore backup database
cp backups/pre-phase4/database/tmws.db.backup data/tmws.db

# 3. Verify schema version
sqlite3 data/tmws.db "SELECT version_num FROM alembic_version;"
```

---

## Git Rollback

### Tag-Based Rollback

If Phase 4 deployment was tagged:

```bash
# View tags
git tag -l

# Rollback to pre-phase4 tag
git checkout tags/pre-phase4

# Or create new branch from tag
git checkout -b rollback-phase4 tags/pre-phase4
```

### Commit-Based Rollback

```bash
# Find last good commit
git log --oneline --graph --decorate

# Reset to specific commit (SOFT: keeps changes)
git reset --soft <COMMIT_HASH>

# Or HARD reset (DANGER: loses all changes)
# git reset --hard <COMMIT_HASH>

# Force push if already deployed
# git push origin feature/phase4 --force
```

### File-Specific Rollback

```bash
# Restore specific file from last commit
git checkout HEAD~1 -- src/domain/value_objects/tool_category.py

# Restore all Python files from specific commit
git checkout <COMMIT_HASH> -- "*.py"
```

---

## Verification Tests

### Post-Rollback Validation

Run these tests after rollback to ensure system integrity:

#### 1. Database Integrity
```bash
# Check database file
ls -lh data/tmws.db

# Verify schema
sqlite3 data/tmws.db "SELECT name FROM sqlite_master WHERE type='table';"

# Check Alembic version
sqlite3 data/tmws.db "SELECT version_num FROM alembic_version;"

# Integrity check
sqlite3 data/tmws.db "PRAGMA integrity_check;"
```

#### 2. Migration Consistency
```bash
# Verify Alembic state
alembic current

# Check migration history
alembic history

# Verify migrations directory
ls -1 migrations/versions/ | wc -l
# Expected: 12 files
```

#### 3. Import Validation
```bash
# Verify all Python files compile
python -c "import src.domain.value_objects.tool_category"
python -c "import src.services.verification_service"
python -c "import src.services.learning_trust_integration"

# Run syntax check
python -m py_compile src/domain/value_objects/tool_category.py
python -m py_compile src/services/verification_service.py
```

#### 4. Unit Tests
```bash
# Run critical unit tests
pytest tests/unit/services/test_verification_service.py -v
pytest tests/unit/services/test_verification_learning_integration.py -v

# Run integration tests
pytest tests/integration/test_go_python_category_sync.py -v

# Expected: All tests PASS
```

#### 5. Functional Validation
```bash
# Start server in test mode
TMWS_ENVIRONMENT=development uvicorn src.main:app --reload --port 8001 &

# Wait for startup
sleep 3

# Test health endpoint
curl -s http://localhost:8001/health | jq .

# Stop server
pkill -f "uvicorn.*8001"
```

---

## Rollback Decision Matrix

| Scenario | Recommended Action | Estimated Time |
|----------|-------------------|----------------|
| Database corruption | Database rollback only | 2 minutes |
| Migration failure | Alembic downgrade | 3 minutes |
| Critical file issue | File-specific rollback | 1 minute |
| Complete failure | Full rollback (all steps) | 5 minutes |
| Git issues | Git tag/commit rollback | 2 minutes |

---

## Emergency Contacts

If rollback fails:

1. **Database Issues**: Check SQLite error logs, consider manual schema repair
2. **Migration Issues**: Review Alembic logs, check `migrations/versions/`
3. **Git Issues**: Use `git reflog` to recover lost commits
4. **Backup Corruption**: Escalate to senior engineer

---

## Post-Rollback Checklist

After rollback completion:

- [ ] Database integrity verified (`PRAGMA integrity_check`)
- [ ] Alembic revision matches pre-Phase4
- [ ] All critical files restored
- [ ] Unit tests pass (100%)
- [ ] Integration tests pass
- [ ] Server starts without errors
- [ ] Health endpoint responds
- [ ] Git state is clean (`git status`)
- [ ] Backup forensics performed (analyze failure)
- [ ] Post-mortem document created

---

## Forensics & Analysis

After successful rollback:

```bash
# 1. Preserve failed state for analysis
mkdir -p forensics/phase4-failure/
cp data/tmws.db.failed-phase4 forensics/phase4-failure/
cp -r migrations/versions/ forensics/phase4-failure/migrations/

# 2. Create failure report
cat > forensics/phase4-failure/FAILURE_REPORT.md << EOF
# Phase 4 Deployment Failure Report

**Date**: $(date '+%Y-%m-%d %H:%M:%S')
**Rollback Initiated**: $(date '+%Y-%m-%d %H:%M:%S')
**Rollback Completed**: TBD

## Failure Symptoms
- [Describe what went wrong]

## Rollback Actions Taken
- [List all rollback steps performed]

## Root Cause Analysis
- [Detailed analysis of failure]

## Prevention Measures
- [How to prevent this in future]
EOF

# 3. Review logs
tail -100 /var/log/tmws.log > forensics/phase4-failure/tmws.log
```

---

## Appendix A: Backup File List

```
backups/pre-phase4/
├── database/
│   └── tmws.db.backup (844KB)
├── migrations/
│   └── alembic_versions/ (12 files)
├── config/
│   ├── pyproject.toml (4.5KB)
│   ├── .env.example
│   └── alembic.ini (3.2KB)
├── critical_files/
│   ├── tool_category.py (6.3KB)
│   ├── verification_service.py (32KB)
│   ├── learning_trust_integration.py (21KB)
│   ├── test_go_python_category_sync.py (11KB)
│   └── test_verification_learning_integration.py (26KB)
└── BACKUP_MANIFEST.txt
```

---

## Appendix B: Alembic Commands Reference

```bash
# Show current revision
alembic current

# Show migration history
alembic history --verbose

# Downgrade one step
alembic downgrade -1

# Downgrade to specific revision
alembic downgrade <revision_id>

# Upgrade to head (after rollback fix)
alembic upgrade head

# Check database stamp
alembic stamp head
```

---

**Last Updated**: 2025-11-22
**Document Version**: 1.0
**Author**: Artemis (TMWS Technical Perfectionist)
