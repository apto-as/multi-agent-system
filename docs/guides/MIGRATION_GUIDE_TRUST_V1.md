# Agent Trust & Verification System - Migration Guide v1

**Version**: v2.2.7+
**Migration Path**: No Trust System → Trust System v1
**Target Audience**: System administrators, DevOps engineers
**Last Updated**: 2025-11-07

---

## Table of Contents

1. [Overview](#overview)
2. [Pre-Migration Checklist](#pre-migration-checklist)
3. [Migration Steps](#migration-steps)
4. [Backward Compatibility](#backward-compatibility)
5. [Rollback Procedures](#rollback-procedures)
6. [Post-Migration Verification](#post-migration-verification)
7. [Breaking Changes](#breaking-changes)
8. [FAQ](#faq)

---

## Overview

This guide helps you migrate from TMWS v2.2.6 (no trust tracking) to v2.2.7+ (with Agent Trust & Verification System).

### What's New in v2.2.7

**Trust System Features**:
- 📊 **Trust Score Tracking**: Agents have trust scores (0.0-1.0) based on verification accuracy
- ✅ **Automatic Verification**: Claims can be verified against actual system state
- 🚨 **Status-Based Access Control**: Agent status determines allowed operations
- 📈 **Trust History**: Comprehensive audit trail of trust score changes
- 🔍 **MCP Tools**: New tools for trust management via Model Context Protocol

**Database Changes**:
- 3 new tables: `agent_verifications`, `verification_results`, `agent_trust_history`
- 5 new columns in `agents` table
- 3 new indexes for performance

### Migration Timeline

| Phase | Duration | Description |
|-------|----------|-------------|
| **Preparation** | 30-60 min | Backup, review requirements |
| **Database Migration** | 5-10 min | Schema updates, indexes |
| **Service Deployment** | 10-20 min | Deploy new code, restart services |
| **Verification** | 30-60 min | Smoke tests, monitoring |
| **Total** | 1.5-2.5 hours | End-to-end migration |

### Risk Assessment

| Risk Level | Impact Area | Mitigation |
|------------|-------------|------------|
| **LOW** | Database schema | Backward compatible, rollback available |
| **LOW** | Existing agents | Trust scores default to 1.0 (fully trusted) |
| **MEDIUM** | API compatibility | New fields optional, old endpoints unchanged |
| **LOW** | Performance | Indexes optimize trust queries, minimal overhead |

---

## Pre-Migration Checklist

### 1. System Requirements

**Minimum Versions**:
- TMWS: v2.2.6
- Python: 3.11+
- SQLite: 3.35+
- Alembic: 1.12+

**Check Current Version**:
```bash
# Check TMWS version
python -c "import src; print(src.__version__)"

# Check Python version
python --version

# Check SQLite version
sqlite3 --version

# Check Alembic version
alembic --version
```

### 2. Backup Current System

```bash
#!/bin/bash
# scripts/backup_before_trust_migration.sh

BACKUP_DIR="/backups/tmws-pre-trust-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "Creating backup in $BACKUP_DIR"

# 1. Backup database
echo "Backing up database..."
cp data/tmws.db "$BACKUP_DIR/tmws.db"
sqlite3 data/tmws.db ".backup '$BACKUP_DIR/tmws.db.backup'"

# 2. Backup configuration
echo "Backing up configuration..."
cp -r config/ "$BACKUP_DIR/config/"
cp .env "$BACKUP_DIR/.env" 2>/dev/null || true

# 3. Backup agent data
echo "Exporting agent data..."
sqlite3 data/tmws.db -header -csv "SELECT * FROM agents;" > "$BACKUP_DIR/agents_export.csv"

# 4. Create system snapshot
echo "Creating system snapshot..."
cat > "$BACKUP_DIR/system_snapshot.txt" <<EOF
Backup Date: $(date)
TMWS Version: $(python -c "import src; print(src.__version__)")
Python Version: $(python --version)
SQLite Version: $(sqlite3 --version)
Database Size: $(du -h data/tmws.db | cut -f1)
Agent Count: $(sqlite3 data/tmws.db "SELECT COUNT(*) FROM agents;")
Memory Count: $(sqlite3 data/tmws.db "SELECT COUNT(*) FROM memories;")
Task Count: $(sqlite3 data/tmws.db "SELECT COUNT(*) FROM tasks;")
EOF

echo "Backup complete: $BACKUP_DIR"
```

### 3. Review Existing Agents

```sql
-- Check current agent statuses
SELECT
    agent_id,
    display_name,
    status,
    is_active,
    total_tasks,
    successful_tasks,
    health_score
FROM agents
ORDER BY agent_id;

-- Check agents without status (will be migrated)
SELECT COUNT(*) as agents_without_status
FROM agents
WHERE status IS NULL OR status = '';
```

### 4. Disk Space Check

```bash
# Estimate additional space needed
# Trust system tables: ~10% of current database size

CURRENT_SIZE=$(du -k data/tmws.db | cut -f1)
ADDITIONAL_SPACE=$((CURRENT_SIZE / 10))
AVAILABLE_SPACE=$(df -k data/ | tail -1 | awk '{print $4}')

echo "Current database size: $((CURRENT_SIZE / 1024)) MB"
echo "Additional space needed: $((ADDITIONAL_SPACE / 1024)) MB"
echo "Available space: $((AVAILABLE_SPACE / 1024)) MB"

if [ $AVAILABLE_SPACE -lt $((ADDITIONAL_SPACE * 2)) ]; then
    echo "⚠️ WARNING: Low disk space. Consider cleanup before migration."
fi
```

---

## Migration Steps

### Step 1: Stop Services (Downtime Starts)

```bash
# Stop TMWS services
systemctl stop tmws-api
systemctl stop tmws-mcp
systemctl stop tmws-worker

# Verify services stopped
systemctl status tmws-api
systemctl status tmws-mcp
systemctl status tmws-worker

# Verify no database connections
lsof data/tmws.db  # Should return nothing
```

**Downtime**: 0-2 minutes

### Step 2: Update Code

```bash
# Pull latest code
git fetch origin
git checkout v2.2.7

# Or download release
# wget https://github.com/apto-as/tmws/releases/download/v2.2.7/tmws-v2.2.7.tar.gz
# tar -xzf tmws-v2.2.7.tar.gz

# Verify version
git describe --tags  # Should show v2.2.7
```

**Downtime**: 2-5 minutes (total: 2-7 minutes)

### Step 3: Install Dependencies

```bash
# Update dependencies
uv sync --all-extras

# Verify new packages installed
python -c "from src.services.verification_service import VerificationService; print('✅ Trust system installed')"
```

**Downtime**: 5-10 minutes (total: 7-17 minutes)

### Step 4: Database Migration

```bash
# Run Alembic migration
alembic upgrade head

# Expected output:
# INFO  [alembic.runtime.migration] Running upgrade 1a2b3c4d5e6f -> 7g8h9i0j1k2l, add_trust_tracking_tables
# INFO  [alembic.runtime.migration] Running upgrade 7g8h9i0j1k2l -> 3m4n5o6p7q8r, add_trust_score_columns_to_agents
# INFO  [alembic.runtime.migration] Running upgrade 3m4n5o6p7q8r -> 9s0t1u2v3w4x, add_trust_indexes

# Verify migration
alembic current
# Expected: 9s0t1u2v3w4x (head)
```

**Migration SQL** (executed by Alembic):

```sql
-- Migration 1: Create verification tables
CREATE TABLE agent_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    claim TEXT NOT NULL,
    verification_type TEXT NOT NULL,
    verification_command TEXT,
    expected_result TEXT,  -- JSON
    status TEXT NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
);

CREATE TABLE verification_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    verification_id INTEGER NOT NULL UNIQUE,
    claim_verified INTEGER NOT NULL,  -- Boolean (0/1)
    actual_result TEXT,  -- JSON
    verification_output TEXT,
    verification_error TEXT,
    execution_time_ms REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (verification_id) REFERENCES agent_verifications (id)
);

CREATE TABLE agent_trust_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    verification_id INTEGER,
    old_trust_score REAL NOT NULL,
    new_trust_score REAL NOT NULL,
    score_change REAL NOT NULL,
    claim TEXT,
    verified INTEGER,  -- Boolean (0/1)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agents (agent_id),
    FOREIGN KEY (verification_id) REFERENCES agent_verifications (id)
);

-- Migration 2: Add trust columns to agents
ALTER TABLE agents ADD COLUMN trust_score REAL DEFAULT 1.0;
ALTER TABLE agents ADD COLUMN total_verifications INTEGER DEFAULT 0;
ALTER TABLE agents ADD COLUMN successful_verifications INTEGER DEFAULT 0;
ALTER TABLE agents ADD COLUMN failed_verifications INTEGER DEFAULT 0;
ALTER TABLE agents ADD COLUMN last_verification_at TIMESTAMP;

-- Update existing agents (set default values)
UPDATE agents SET trust_score = 1.0 WHERE trust_score IS NULL;
UPDATE agents SET total_verifications = 0 WHERE total_verifications IS NULL;
UPDATE agents SET successful_verifications = 0 WHERE successful_verifications IS NULL;
UPDATE agents SET failed_verifications = 0 WHERE failed_verifications IS NULL;

-- Migration 3: Add indexes
CREATE INDEX idx_verifications_agent_status ON agent_verifications(agent_id, status);
CREATE INDEX idx_verifications_agent_type ON agent_verifications(agent_id, verification_type);
CREATE INDEX idx_verification_results_verified ON verification_results(claim_verified);
CREATE INDEX idx_trust_history_agent_created ON agent_trust_history(agent_id, created_at);
CREATE INDEX idx_trust_history_score_change ON agent_trust_history(score_change);
CREATE INDEX idx_agents_trust_score ON agents(trust_score, status);
```

**Downtime**: 10-15 minutes (total: 17-32 minutes)

### Step 5: Verify Database Schema

```bash
# Check new tables exist
sqlite3 data/tmws.db "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;" | grep -E "(agent_verifications|verification_results|agent_trust_history)"

# Expected output:
# agent_trust_history
# agent_verifications
# verification_results

# Check new columns in agents table
sqlite3 data/tmws.db "PRAGMA table_info(agents);" | grep -E "(trust_score|total_verifications|successful_verifications|failed_verifications|last_verification_at)"

# Expected output:
# trust_score|REAL|0|1.0|0
# total_verifications|INTEGER|0|0|0
# successful_verifications|INTEGER|0|0|0
# failed_verifications|INTEGER|0|0|0
# last_verification_at|TIMESTAMP|1||0

# Verify indexes
sqlite3 data/tmws.db "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%trust%' ORDER BY name;"

# Expected output:
# idx_agents_trust_score
# idx_trust_history_agent_created
# idx_trust_history_score_change
```

**Downtime**: 15-20 minutes (total: 32-52 minutes)

### Step 6: Restart Services (Downtime Ends)

```bash
# Start services
systemctl start tmws-api
systemctl start tmws-mcp
systemctl start tmws-worker

# Verify services started
systemctl status tmws-api
systemctl status tmws-mcp
systemctl status tmws-worker

# Check API health
curl -f http://localhost:8000/health || echo "API not ready"

# Check trust system endpoint
curl -s http://localhost:8000/api/v1/agents/hera-strategist/trust | jq .
# Expected:
# {
#   "agent_id": "hera-strategist",
#   "trust_score": 1.0,
#   "status": "TRUSTED",
#   "total_verifications": 0,
#   ...
# }
```

**Total Downtime**: 32-52 minutes

---

## Backward Compatibility

### API Compatibility

**Existing Endpoints**: ✅ Unchanged

All existing API endpoints continue to work without modification:
- `GET /api/v1/agents` - Lists agents (new trust fields included)
- `GET /api/v1/agents/{agent_id}` - Get agent details (new trust fields included)
- `POST /api/v1/memories` - Create memory (no changes)
- `GET /api/v1/memories/search` - Search memories (no changes)

**New Endpoints**: Added without breaking existing ones

- `GET /api/v1/agents/{agent_id}/trust` - Get trust score
- `POST /api/v1/verifications` - Verify claim
- `GET /api/v1/verifications/{verification_id}` - Get verification result
- `POST /api/v1/agents/{agent_id}/trust/reset` - Reset trust score (admin only)

### Agent Model Compatibility

**Existing Fields**: ✅ Unchanged
**New Fields**: Added with safe defaults

```python
# Before v2.2.7 (still works)
agent = Agent(
    agent_id="custom-agent",
    display_name="Custom Agent",
    agent_type="custom",
    namespace="my-namespace",
)

# After v2.2.7 (new fields auto-populated)
agent = Agent(
    agent_id="custom-agent",
    display_name="Custom Agent",
    agent_type="custom",
    namespace="my-namespace",
    # New fields (auto-populated with defaults)
    trust_score=1.0,
    total_verifications=0,
    successful_verifications=0,
    failed_verifications=0,
    last_verification_at=None,
)
```

### MCP Tools Compatibility

**Existing MCP Tools**: ✅ Unchanged

All existing MCP tools work without modification:
- `store_memory`
- `search_memories`
- `create_task`
- `get_agent_status`

**New MCP Tools**: Added

- `get_agent_trust_score`
- `verify_and_record`
- `bulk_verify_claims`
- `reset_agent_trust`

### Configuration Compatibility

**Existing Config**: ✅ Works without changes

**New Config (Optional)**:

```json
// config/trust_tracking.json (optional)
{
    "enabled": true,
    "default_trust_score": 1.0,
    "trust_thresholds": {
        "trusted": 0.90,
        "active": 0.75,
        "monitored": 0.50,
        "untrusted": 0.25
    },
    "decay_rate": 0.70,
    "growth_rate": 0.05,
    "verification_defaults": {
        "timeout": 60,
        "retry_attempts": 0
    }
}
```

If this file doesn't exist, system uses built-in defaults.

---

## Rollback Procedures

### When to Rollback

Roll back if you encounter:
- Critical bugs in trust system
- Performance degradation
- Data corruption
- Unable to complete migration

### Rollback Steps

#### Option 1: Quick Rollback (< 15 minutes)

```bash
# 1. Stop services
systemctl stop tmws-api tmws-mcp tmws-worker

# 2. Restore database backup
cp /backups/tmws-pre-trust-YYYYMMDD-HHMMSS/tmws.db data/tmws.db

# 3. Checkout previous version
git checkout v2.2.6

# 4. Downgrade dependencies
uv sync --all-extras

# 5. Restart services
systemctl start tmws-api tmws-mcp tmws-worker

# 6. Verify rollback
curl -s http://localhost:8000/health | jq .
```

#### Option 2: Database-Only Rollback (< 10 minutes)

If database is corrupted but code is fine:

```bash
# 1. Stop services
systemctl stop tmws-api tmws-mcp tmws-worker

# 2. Downgrade database schema
alembic downgrade -1  # Rollback one migration
alembic downgrade -1  # Rollback second migration
alembic downgrade -1  # Rollback third migration

# Alternative: Restore backup
cp /backups/tmws-pre-trust-YYYYMMDD-HHMMSS/tmws.db data/tmws.db

# 3. Restart services
systemctl start tmws-api tmws-mcp tmws-worker

# 4. Verify
sqlite3 data/tmws.db "SELECT name FROM sqlite_master WHERE type='table';" | grep -v trust
```

#### Option 3: Selective Disable (No Downtime)

Disable trust tracking without full rollback:

```python
# src/core/config.py
TRUST_TRACKING_ENABLED = False  # Disable trust tracking

# Restart services
systemctl restart tmws-api tmws-mcp tmws-worker
```

This keeps the database schema but stops trust score updates.

---

## Post-Migration Verification

### 1. Smoke Tests

```bash
#!/bin/bash
# scripts/verify_trust_migration.sh

echo "=== TMWS Trust System Migration Verification ==="

# Test 1: API Health
echo "Test 1: API Health"
curl -f http://localhost:8000/health || { echo "❌ FAILED: API not healthy"; exit 1; }
echo "✅ PASSED"

# Test 2: Database Schema
echo "Test 2: Database Schema"
TRUST_TABLES=$(sqlite3 data/tmws.db "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE '%trust%' OR name LIKE '%verification%';")
if [ "$TRUST_TABLES" -ne 3 ]; then
    echo "❌ FAILED: Expected 3 trust tables, found $TRUST_TABLES"
    exit 1
fi
echo "✅ PASSED: Found $TRUST_TABLES trust tables"

# Test 3: Agent Trust Score
echo "Test 3: Agent Trust Score"
TRUST_SCORE=$(sqlite3 data/tmws.db "SELECT trust_score FROM agents WHERE agent_id='hera-strategist' LIMIT 1;")
if [ "$TRUST_SCORE" != "1.0" ]; then
    echo "❌ FAILED: Expected trust score 1.0, found $TRUST_SCORE"
    exit 1
fi
echo "✅ PASSED: Default trust score is 1.0"

# Test 4: MCP Tools Available
echo "Test 4: MCP Tools Available"
MCP_RESPONSE=$(curl -s http://localhost:8000/mcp/tools)
if ! echo "$MCP_RESPONSE" | grep -q "get_agent_trust_score"; then
    echo "❌ FAILED: MCP trust tools not available"
    exit 1
fi
echo "✅ PASSED: MCP trust tools available"

# Test 5: Trust Score Update
echo "Test 5: Trust Score Update (end-to-end)"
python3 <<EOF
import asyncio
from src.core.database import get_async_session
from src.services.agent_service import AgentService
from src.services.verification_service import VerificationService
from src.models.agent_verification import VerificationResult

async def test():
    async for session in get_async_session():
        agent_service = AgentService(session)
        verification_service = VerificationService(session)

        # Create test verification
        result = await verification_service.verify_claim(
            agent_id="hera-strategist",
            claim="Test migration verification",
            verification_type="file_existence",
            verification_command="ls README.md",
            expected_result={"file_exists": True},
        )

        # Update trust score
        agent = await agent_service.update_agent_trust_score(
            agent_id="hera-strategist",
            verification_result=result,
        )

        assert agent.trust_score == 1.0, f"Trust score should remain 1.0, got {agent.trust_score}"
        assert agent.total_verifications == 1, f"Total verifications should be 1, got {agent.total_verifications}"

        print("✅ PASSED: Trust score update works")

asyncio.run(test())
EOF

echo ""
echo "=== All Tests Passed ✅ ==="
```

### 2. Monitoring Setup

```bash
# Enable trust metrics endpoint
curl -s http://localhost:8000/metrics/trust | grep tmws_agent_trust_score

# Expected output:
# tmws_agent_trust_score{agent_id="hera-strategist",agent_type="strategist"} 1.0
# tmws_agent_trust_score{agent_id="artemis-optimizer",agent_type="optimizer"} 1.0
# ...
```

### 3. Agent Status Check

```sql
-- Verify all agents have default trust values
SELECT
    agent_id,
    trust_score,
    total_verifications,
    successful_verifications,
    failed_verifications
FROM agents
WHERE trust_score IS NULL
   OR total_verifications IS NULL;

-- Should return 0 rows
```

### 4. Performance Baseline

```bash
# Measure query performance with new indexes
sqlite3 data/tmws.db <<EOF
.timer on
SELECT * FROM agents WHERE trust_score < 0.50;
SELECT * FROM agent_verifications WHERE agent_id='hera-strategist' ORDER BY created_at DESC LIMIT 10;
SELECT * FROM agent_trust_history WHERE agent_id='artemis-optimizer' ORDER BY created_at DESC LIMIT 10;
EOF

# Expected: All queries < 10ms
```

---

## Breaking Changes

### None! 🎉

TMWS v2.2.7 is **fully backward compatible** with v2.2.6.

**What This Means**:
- ✅ Existing code continues to work without modification
- ✅ API endpoints are unchanged
- ✅ Database schema is extended, not modified
- ✅ MCP tools are added, not changed
- ✅ Configuration is optional, defaults work

**Deprecation Warnings**:
- None in v2.2.7
- Future versions may require trust tracking for certain operations

---

## FAQ

### Q1: Do I need to update my agents' code?

**A**: No. Trust tracking is automatic. Agents don't need code changes.

Existing agents:
```python
# v2.2.6 code (still works in v2.2.7)
agent = await agent_service.create_agent(
    agent_id="my-agent",
    display_name="My Agent",
    agent_type="custom",
    namespace="my-namespace",
)
```

### Q2: What happens to agents created before migration?

**A**: They receive default trust values:
- `trust_score`: 1.0 (fully trusted)
- `total_verifications`: 0
- `successful_verifications`: 0
- `failed_verifications`: 0
- `status`: `ACTIVE` (or existing status if already set)

### Q3: Can I disable trust tracking after migration?

**A**: Yes, set `TRUST_TRACKING_ENABLED = False` in configuration.

```python
# src/core/config.py
TRUST_TRACKING_ENABLED = False
```

This disables:
- Trust score updates
- Automatic verification triggers
- Trust-based access control

But keeps:
- Database schema intact
- Manual verification API available
- Trust history preserved

### Q4: How do I migrate from v2.2.5 or earlier?

**A**: Upgrade to v2.2.6 first, then to v2.2.7.

```bash
# Step 1: Upgrade to v2.2.6
git checkout v2.2.6
alembic upgrade head

# Step 2: Verify v2.2.6 works
curl -f http://localhost:8000/health

# Step 3: Upgrade to v2.2.7 (follow this guide)
git checkout v2.2.7
alembic upgrade head
```

### Q5: What if verification commands fail during migration?

**A**: Migration doesn't run verifications. Verifications are triggered:
- Manually via MCP tools
- Automatically if configured (post-migration)

Migration only creates database schema.

### Q6: Can I customize trust score thresholds?

**A**: Yes, via configuration:

```json
// config/trust_tracking.json
{
    "trust_thresholds": {
        "trusted": 0.95,     // Default: 0.90
        "active": 0.80,      // Default: 0.75
        "monitored": 0.60,   // Default: 0.50
        "untrusted": 0.30    // Default: 0.25
    }
}
```

### Q7: How long does the migration take?

**A**: 1.5-2.5 hours total (30-50 minutes downtime).

| Phase | Duration | Downtime |
|-------|----------|----------|
| Preparation | 30-60 min | No |
| Database Migration | 10-15 min | Yes |
| Service Restart | 5-10 min | Yes |
| Verification | 30-60 min | No |

### Q8: What if I encounter errors during migration?

**A**: Follow this decision tree:

```
Migration Error
├─ Database Schema Error
│  └─ Rollback to v2.2.6 (Option 1)
├─ Service Start Error
│  └─ Check logs: journalctl -u tmws-api -n 100
├─ Trust System Not Working
│  └─ Disable trust tracking temporarily
└─ Data Corruption
   └─ Restore from backup (Option 1)
```

### Q9: Can I run v2.2.6 and v2.2.7 side-by-side?

**A**: Not recommended. Database schema is shared.

If you need parallel testing:
1. Create separate database file
2. Use different configuration
3. Run on different port

```bash
# Test instance
export TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws_test.db"
export TMWS_API_PORT=8001
python -m uvicorn src.main:app --port 8001
```

### Q10: How do I monitor trust scores after migration?

**A**: See [Operations Guide: Monitoring](./OPERATIONS_GUIDE_MONITORING.md)

Quick check:
```bash
# Get all agent trust scores
sqlite3 data/tmws.db "SELECT agent_id, trust_score, status FROM agents ORDER BY trust_score ASC;"

# Get agents with low trust
sqlite3 data/tmws.db "SELECT agent_id, trust_score, status FROM agents WHERE trust_score < 0.75;"
```

---

## Next Steps

### Immediate (Post-Migration)

1. ✅ **Verify Migration**: Run smoke tests (above)
2. ✅ **Enable Monitoring**: Configure Prometheus/Grafana
3. ✅ **Set Alerts**: Configure alerting rules
4. ✅ **Document Baseline**: Record current trust scores

### Short-Term (Week 1)

1. 📚 **Team Training**: Educate team on trust system
2. 🔍 **Configure Verifications**: Set up automatic verification triggers
3. 📊 **Review Dashboards**: Monitor trust score trends
4. 🚨 **Test Alerts**: Verify alerting works

### Long-Term (Month 1+)

1. 🎯 **Optimize Thresholds**: Adjust trust score thresholds based on data
2. 🔧 **Custom Verifications**: Create project-specific verification types
3. 📈 **Performance Tuning**: Optimize verification commands
4. 📝 **Runbooks**: Create incident response runbooks

---

## Additional Resources

- **User Guide**: [USER_GUIDE_AGENT_TRUST.md](./USER_GUIDE_AGENT_TRUST.md)
- **Developer Guide**: [DEVELOPER_GUIDE_VERIFICATION.md](./DEVELOPER_GUIDE_VERIFICATION.md)
- **Operations Guide**: [OPERATIONS_GUIDE_MONITORING.md](./OPERATIONS_GUIDE_MONITORING.md)
- **API Reference**: [API_REFERENCE_TRUST_SYSTEM.md](./API_REFERENCE_TRUST_SYSTEM.md)

---

## Support

**Need Help?**
- GitHub Issues: [github.com/apto-as/tmws/issues](https://github.com/apto-as/tmws/issues)
- Migration Support: `#tmws-migration` on Slack
- Emergency Rollback: [Emergency Rollback Runbook](../runbooks/emergency_rollback.md)

**Post-Migration Report Template**:
```markdown
# TMWS v2.2.7 Migration Report

**Date**: YYYY-MM-DD
**Duration**: X hours Y minutes
**Downtime**: X minutes
**Status**: ✅ Success / ❌ Rolled Back

## Pre-Migration
- Database Size: X MB
- Agent Count: X
- Backup Location: /backups/...

## Migration
- Database Migration: ✅
- Service Restart: ✅
- Smoke Tests: ✅

## Post-Migration
- Trust System Functional: ✅
- API Health: ✅
- Monitoring Enabled: ✅

## Issues Encountered
- None / [List issues]

## Rollback Performed
- No / Yes (reason: ...)

## Next Steps
- [Action items]

**Reported By**: [Your Name]
**Reviewed By**: [Team Lead]
```

---

*This migration guide is part of TMWS v2.2.7+ Agent Trust & Verification System.*
