# RBAC Rollback Procedure
## Emergency Recovery for Phase 2C Deployment

**Last Updated**: 2025-11-15
**Migration Version**: 571948cc671b (Add Agent.role field for RBAC)
**Status**: TESTED ✅

---

## 🚨 When to Use This Procedure

Use this rollback procedure if you encounter:

- **Critical Permission Issues**: RBAC denying legitimate operations
- **Data Corruption**: `agents.role` column contains invalid data
- **Performance Degradation**: RBAC checks causing unacceptable latency
- **Migration Failures**: Database in inconsistent state after upgrade

**DO NOT** use for:
- Minor permission configuration issues (use UPDATE statements instead)
- Known xfail test failures (documented in WAVE3_KNOWN_ISSUES.md)
- Deprecation warnings (not production-blocking)

---

## ⚡ Quick Rollback (Option A - Migration Only)

**Use when**: RBAC is causing issues but database is otherwise healthy
**Time**: 2-5 minutes
**Risk**: LOW

### Step 1: Verify Current State

```bash
# Check current migration version
alembic current
# Should show: 571948cc671b

# Verify role column exists
sqlite3 ~/.tmws/data/tmws.db "PRAGMA table_info(agents);" | grep role
# Should show: 24|role|TEXT|1|'viewer'|0
```

### Step 2: Stop TMWS Services

```bash
# If running as systemd service
sudo systemctl stop tmws

# If running as MCP server
ps aux | grep mcp_server.py
kill <PID>

# Verify no TMWS processes are running
ps aux | grep -i tmws
```

### Step 3: Rollback Migration

```bash
# Set database URL (if not using default)
export TMWS_DATABASE_URL="sqlite+aiosqlite:///$HOME/.tmws/data/tmws.db"

# Rollback to previous migration
alembic downgrade 096325207c82

# Expected output:
# INFO [alembic.runtime.migration] Running downgrade 571948cc671b -> 096325207c82
```

### Step 4: Verify Rollback

```bash
# Check migration version
alembic current
# Should show: 096325207c82

# Verify role column removed
sqlite3 ~/.tmws/data/tmws.db "PRAGMA table_info(agents);" | grep role
# Should return nothing

# Verify index removed
sqlite3 ~/.tmws/data/tmws.db ".schema agents" | grep ix_agents_role
# Should return nothing
```

### Step 5: Restart Services

```bash
# Restart TMWS
sudo systemctl start tmws

# Verify health
curl http://localhost:8000/health
# Should return: {"status": "healthy"}
```

### Step 6: Verify Functionality

```bash
# Test basic operations (no RBAC enforcement)
# All agents should now have unrestricted access to license tools

# Run integration tests (without RBAC)
TMWS_DATABASE_URL="sqlite+aiosqlite:///:memory:" \
  pytest tests/integration/test_license_mcp_integration.py::TestLicenseGeneration -v
# Should PASS without permission errors
```

**Result**: RBAC removed, license tools functional without role restrictions

---

## 🔄 Full Rollback (Option B - Database Restore)

**Use when**: Database is corrupted or migration rollback failed
**Time**: 5-10 minutes
**Risk**: MEDIUM (data loss if backup is stale)

### Step 1: Verify Backup Exists

```bash
# List available backups
ls -lh ~/.tmws/data/tmws_backup_*.db

# Choose most recent backup BEFORE v2.3.0 deployment
# Should be timestamped: tmws_backup_YYYYMMDD_HHMMSS.db
```

### Step 2: Stop All TMWS Services

```bash
# Stop systemd service (if applicable)
sudo systemctl stop tmws

# Kill any lingering processes
pkill -f mcp_server.py
pkill -f tmws

# Verify all stopped
ps aux | grep -E "(mcp_server|tmws)" | grep -v grep
# Should return nothing
```

### Step 3: Backup Current Database (Precaution)

```bash
# Even if corrupted, backup current state
CORRUPTED_BACKUP="tmws_corrupted_$(date +%Y%m%d_%H%M%S).db"
cp ~/.tmws/data/tmws.db ~/.tmws/data/$CORRUPTED_BACKUP

echo "Corrupted database backed up to: $CORRUPTED_BACKUP"
```

### Step 4: Restore from Backup

```bash
# Replace current database with backup
cp ~/.tmws/data/tmws_backup_YYYYMMDD_HHMMSS.db ~/.tmws/data/tmws.db

# Verify file size (should match backup)
ls -lh ~/.tmws/data/tmws.db
```

### Step 5: Verify Database Integrity

```bash
# SQLite integrity check
sqlite3 ~/.tmws/data/tmws.db "PRAGMA integrity_check;"
# Should output: ok

# Verify migration version (should be pre-RBAC)
sqlite3 ~/.tmws/data/tmws.db "SELECT version_num FROM alembic_version;"
# Should show: e674ec434eeb or earlier

# Verify no role column
sqlite3 ~/.tmws/data/tmws.db "PRAGMA table_info(agents);" | grep role
# Should return nothing
```

### Step 6: Restart Services

```bash
# Restart TMWS
sudo systemctl start tmws

# Verify health
curl http://localhost:8000/health
```

### Step 7: Data Loss Assessment

```bash
# Check how much data was lost
sqlite3 ~/.tmws/data/tmws.db <<EOF
SELECT
  'Agents' as table_name, COUNT(*) as count FROM agents
UNION ALL
SELECT 'Memories', COUNT(*) FROM memories
UNION ALL
SELECT 'License Keys', COUNT(*) FROM license_keys
UNION ALL
SELECT 'Tasks', COUNT(*) FROM tasks;
EOF

# Compare with corrupted backup to assess loss
```

**Result**: Database restored to pre-RBAC state, data loss quantified

---

## 🔙 Code Rollback (Option C - Full Revert)

**Use when**: Code-level issues beyond database
**Time**: 10-15 minutes
**Risk**: LOW (using git tags)

### Step 1: Stop Services

```bash
sudo systemctl stop tmws
```

### Step 2: Rollback Codebase

```bash
cd /path/to/tmws

# Stash any local changes
git stash

# Checkout previous stable version
git checkout v2.2.7

# Verify tag
git describe --tags
# Should show: v2.2.7
```

### Step 3: Rollback Database (Choose Option A or B)

Follow either "Quick Rollback" or "Full Rollback" procedure above.

### Step 4: Reinstall Dependencies (if needed)

```bash
# Update to v2.2.7 dependencies
pip install -r requirements.txt
```

### Step 5: Restart Services

```bash
sudo systemctl start tmws
```

**Result**: Both code and database reverted to v2.2.7

---

## 📊 Rollback Verification Checklist

After any rollback, verify the following:

### Database Verification
- [ ] `alembic current` shows expected version (096325207c82 or earlier)
- [ ] `agents.role` column does NOT exist
- [ ] `ix_agents_role` index does NOT exist
- [ ] `license_keys` table exists (if using Option A/C)
- [ ] `PRAGMA integrity_check` returns "ok"

### Service Verification
- [ ] TMWS service is running (`systemctl status tmws`)
- [ ] Health endpoint returns 200 (`curl http://localhost:8000/health`)
- [ ] No RBAC-related errors in logs (`journalctl -u tmws -n 50`)

### Functional Verification
- [ ] Can create agent without role field
- [ ] Can generate license key (no permission checks)
- [ ] Can validate license key
- [ ] Can retrieve usage history

### Test Suite Verification
```bash
# Run integration tests (should PASS without RBAC)
TMWS_DATABASE_URL="sqlite+aiosqlite:///:memory:" \
  pytest tests/integration/test_license_mcp_integration.py::TestLicenseGeneration -v

# Should PASS all 3 tests without PermissionError
```

---

## 🐛 Troubleshooting

### Issue: Migration Rollback Fails

**Error**: `alembic.util.exc.CommandError: Can't locate revision identified by '096325207c82'`

**Solution**:
```bash
# List all migrations
alembic history

# Rollback to specific revision
alembic downgrade 096325207c82

# If still fails, use database restore (Option B)
```

### Issue: Database Locked During Rollback

**Error**: `sqlite3.OperationalError: database is locked`

**Solution**:
```bash
# Ensure all processes are stopped
pkill -f mcp_server.py
pkill -f tmws
sleep 2

# Check for lingering connections
lsof ~/.tmws/data/tmws.db

# Kill lingering processes
kill -9 <PID>

# Retry rollback
alembic downgrade 096325207c82
```

### Issue: Role Column Still Exists After Rollback

**Error**: `PRAGMA table_info(agents)` shows `role` column even after downgrade

**Solution**:
```bash
# Manual column removal (use with caution)
sqlite3 ~/.tmws/data/tmws.db <<EOF
ALTER TABLE agents DROP COLUMN role;
DROP INDEX IF EXISTS ix_agents_role;
EOF

# Or use database restore (Option B) for clean state
```

### Issue: Service Won't Start After Rollback

**Error**: `ImportError: cannot import name 'Role' from 'src.security.rbac'`

**Solution**:
```bash
# Code is still at v2.3.0, rollback code too
git checkout v2.2.7

# Restart services
sudo systemctl restart tmws
```

---

## 📞 Escalation Procedure

If rollback fails or issues persist:

1. **Stop all TMWS services immediately**
2. **Preserve evidence**:
   ```bash
   # Backup corrupted database
   cp ~/.tmws/data/tmws.db /tmp/tmws_issue_$(date +%Y%m%d_%H%M%S).db

   # Collect logs
   journalctl -u tmws -n 1000 > /tmp/tmws_rollback_logs.txt

   # Save alembic state
   alembic current > /tmp/alembic_state.txt
   alembic history > /tmp/alembic_history.txt
   ```

3. **Contact TMWS Engineering**:
   - Create GitHub issue with evidence
   - Tag: `deployment`, `rollback`, `urgent`
   - Attach: database backup, logs, alembic state

4. **Emergency Recovery**:
   ```bash
   # Use Option B (Database Restore) with oldest backup
   cp ~/.tmws/data/tmws_backup_OLDEST.db ~/.tmws/data/tmws.db

   # Reset code to stable tag
   git checkout v2.2.6  # Last known good version

   # Restart services
   sudo systemctl restart tmws
   ```

---

## 🔍 Post-Rollback Analysis

After successful rollback, document:

1. **Root Cause**: What caused the rollback need?
2. **Impact**: How many operations failed? Data loss?
3. **Time to Recovery**: How long did rollback take?
4. **Lessons Learned**: What could prevent this in future?

**Template**:
```markdown
# Rollback Report - Phase 2C

**Date**: YYYY-MM-DD HH:MM UTC
**Executed By**: [Name]
**Rollback Method**: [Option A/B/C]

## Root Cause
[Description]

## Impact
- Failed operations: [count]
- Data loss: [yes/no, details]
- Downtime: [minutes]

## Recovery Timeline
- 00:00 - Issue detected
- 00:05 - Rollback initiated
- 00:10 - Services restored
- 00:15 - Verification complete

## Lessons Learned
1. [Lesson 1]
2. [Lesson 2]

## Follow-up Actions
- [ ] Fix root cause in v2.3.1
- [ ] Update rollback procedure
- [ ] Add monitoring for this issue
```

---

## ✅ Rollback Success Criteria

Rollback is successful when:

- ✅ Migration version is < 571948cc671b
- ✅ `agents.role` column does NOT exist
- ✅ Services restart without errors
- ✅ Basic license operations work (generation, validation)
- ✅ No RBAC-related errors in logs
- ✅ Integration tests PASS without permission errors

**Estimated Rollback Time**:
- Option A (Quick): 2-5 minutes
- Option B (Full): 5-10 minutes
- Option C (Code + DB): 10-15 minutes

---

**Related Documents**:
- **Deployment Guide**: `PHASE_2C_PRODUCTION_DEPLOYMENT.md`
- **Monitoring Checklist**: `MONITORING_CHECKLIST.md`
- **Known Issues**: `docs/testing/WAVE3_KNOWN_ISSUES.md`

---

*This rollback procedure has been tested and verified as part of Phase 2C deployment validation.*
