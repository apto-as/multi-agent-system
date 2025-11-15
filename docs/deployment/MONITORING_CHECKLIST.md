# TMWS Monitoring Checklist
## Post-Deployment Monitoring for Phase 2C (RBAC + License MCP)

**Last Updated**: 2025-11-15
**Version**: v2.3.0
**Frequency**: First 24 hours after deployment, then weekly

---

## 🎯 Overview

This checklist provides a structured approach to monitoring TMWS after Phase 2C deployment (RBAC + License MCP Tools). Focus areas include:

1. **RBAC Permission Enforcement** (Security)
2. **License Operations** (Functionality)
3. **Performance Metrics** (Efficiency)
4. **Database Health** (Stability)

---

## 📋 Daily Monitoring (First 24 Hours)

### Hour 1-4: Critical Monitoring

#### 1. Service Health
```bash
# Check service status
sudo systemctl status tmws

# Verify health endpoint
curl http://localhost:8000/health
# Expected: {"status": "healthy"}

# Check for errors in logs
journalctl -u tmws -n 100 --no-pager | grep -iE "(error|exception|failed)"
# Expected: No RBAC-related errors
```

**✅ Success Criteria**:
- Service is active (running)
- Health endpoint returns 200
- No P0/P1 errors in logs

---

#### 2. RBAC Permission Checks
```bash
# Count permission check events
sqlite3 ~/.tmws/data/tmws.db <<EOF
SELECT
  COUNT(*) as total_checks,
  SUM(CASE WHEN details->>'result' = 'ALLOW' THEN 1 ELSE 0 END) as allow_count,
  SUM(CASE WHEN details->>'result' = 'DENY' THEN 1 ELSE 0 END) as deny_count,
  ROUND(100.0 * SUM(CASE WHEN details->>'result' = 'DENY' THEN 1 ELSE 0 END) / COUNT(*), 2) as deny_percentage
FROM security_audit_logs
WHERE event_type = 'permission_check'
  AND created_at > datetime('now', '-1 hour');
EOF
```

**✅ Success Criteria**:
- `total_checks` > 0 (RBAC is active)
- `deny_percentage` < 20% (legitimate denials only)
- No unexpected permission denials

**🚨 Alert Conditions**:
- `deny_percentage` > 50% → Investigate role assignments
- `total_checks` = 0 → RBAC may not be active

---

#### 3. License Operations
```bash
# Check license generation activity
sqlite3 ~/.tmws/data/tmws.db <<EOF
SELECT
  COUNT(*) as total_generated,
  tier,
  COUNT(CASE WHEN revoked_at IS NULL THEN 1 END) as active,
  COUNT(CASE WHEN revoked_at IS NOT NULL THEN 1 END) as revoked
FROM license_keys
WHERE created_at > datetime('now', '-1 hour')
GROUP BY tier;
EOF
```

**✅ Success Criteria**:
- License generation is working (if expected)
- No unexpected mass revocations
- Tier distribution matches expected usage

**🚨 Alert Conditions**:
- `total_generated` > 1000 in 1 hour → Potential abuse
- All licenses revoked → System malfunction

---

#### 4. License Validation
```bash
# Check validation activity and success rate
sqlite3 ~/.tmws/data/tmws.db <<EOF
SELECT
  COUNT(*) as total_validations,
  SUM(CASE WHEN valid = 1 THEN 1 ELSE 0 END) as successful,
  SUM(CASE WHEN valid = 0 THEN 1 ELSE 0 END) as failed,
  ROUND(100.0 * SUM(CASE WHEN valid = 0 THEN 1 ELSE 0 END) / COUNT(*), 2) as failure_rate
FROM license_usage_history
WHERE validated_at > datetime('now', '-1 hour');
EOF
```

**✅ Success Criteria**:
- `total_validations` > 0 (if expected)
- `failure_rate` < 10% (normal rate)

**🚨 Alert Conditions**:
- `failure_rate` > 50% → Signature issues or mass expiration
- `total_validations` = 0 but expected → Validation broken

---

### Hour 4-24: Standard Monitoring

#### 5. Database Migration Status
```bash
# Verify migration is at expected version
alembic current
# Expected: 571948cc671b (RBAC head)

# Check for migration table corruption
sqlite3 ~/.tmws/data/tmws.db "SELECT COUNT(*) FROM alembic_version;"
# Expected: 1 (exactly one version)
```

**✅ Success Criteria**:
- Migration version is `571948cc671b`
- `alembic_version` table has exactly 1 row

**🚨 Alert Conditions**:
- Different version → Unauthorized rollback or migration failure
- 0 rows or >1 row → Database corruption

---

#### 6. Role Distribution
```bash
# Check agent role distribution
sqlite3 ~/.tmws/data/tmws.db <<EOF
SELECT
  role,
  COUNT(*) as agent_count,
  ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM agents), 2) as percentage
FROM agents
GROUP BY role
ORDER BY agent_count DESC;
EOF
```

**✅ Success Criteria**:
- Viewer: Majority of agents (70-90%)
- Editor: Moderate count (10-25%)
- Admin: Minimal count (<5%)

**🚨 Alert Conditions**:
- Admin > 20% → Review admin assignments
- All agents are viewers → Role assignments may be broken

---

#### 7. Audit Log Volume
```bash
# Check audit log growth rate
sqlite3 ~/.tmws/data/tmws.db <<EOF
SELECT
  DATE(created_at) as date,
  event_type,
  COUNT(*) as event_count
FROM security_audit_logs
WHERE created_at > datetime('now', '-24 hours')
GROUP BY DATE(created_at), event_type
ORDER BY date DESC, event_count DESC;
EOF
```

**✅ Success Criteria**:
- `permission_check` events are being logged
- Log volume is consistent with traffic

**🚨 Alert Conditions**:
- No `permission_check` events → RBAC audit logging broken
- Sudden 10x increase → Potential attack or misconfiguration

---

#### 8. License Expiration Monitoring
```bash
# Check licenses expiring soon
sqlite3 ~/.tmws/data/tmws.db <<EOF
SELECT
  COUNT(*) as expiring_soon,
  tier
FROM license_keys
WHERE revoked_at IS NULL
  AND expires_at BETWEEN datetime('now') AND datetime('now', '+7 days')
GROUP BY tier;
EOF
```

**✅ Success Criteria**:
- Reasonable number of expiring licenses
- Users have been notified (manual check)

**🚨 Alert Conditions**:
- >100 licenses expiring in 7 days → Notify users proactively

---

## 📊 Weekly Monitoring (After First 24 Hours)

### Run Every Monday Morning

#### 9. Permission Denial Analysis
```bash
# Analyze permission denials by operation
sqlite3 ~/.tmws/data/tmws.db <<EOF
SELECT
  details->>'operation' as operation,
  details->>'role' as role,
  COUNT(*) as deny_count
FROM security_audit_logs
WHERE event_type = 'permission_check'
  AND details->>'result' = 'DENY'
  AND created_at > datetime('now', '-7 days')
GROUP BY operation, role
ORDER BY deny_count DESC
LIMIT 20;
EOF
```

**Action Items**:
- Review top 5 denied operations
- Determine if legitimate (expected denials) or misconfigured
- Update role assignments if needed

---

#### 10. License Usage Trends
```bash
# Weekly license usage report
sqlite3 ~/.tmws/data/tmws.db <<EOF
SELECT
  DATE(validated_at) as date,
  COUNT(*) as total_validations,
  COUNT(DISTINCT agent_id) as unique_agents,
  SUM(CASE WHEN valid = 1 THEN 1 ELSE 0 END) as successful,
  ROUND(100.0 * SUM(CASE WHEN valid = 1 THEN 1 ELSE 0 END) / COUNT(*), 2) as success_rate
FROM license_usage_history
WHERE validated_at > datetime('now', '-7 days')
GROUP BY DATE(validated_at)
ORDER BY date DESC;
EOF
```

**Action Items**:
- Identify usage patterns (peak hours, days)
- Plan capacity based on trends
- Investigate anomalies

---

#### 11. Database Health Check
```bash
# SQLite integrity and optimization
sqlite3 ~/.tmws/data/tmws.db <<EOF
-- Integrity check
PRAGMA integrity_check;

-- Check database size
SELECT
  page_count * page_size / 1024 / 1024 as size_mb
FROM pragma_page_count(), pragma_page_size();

-- Fragmentation check (freelist pages)
PRAGMA freelist_count;

-- Optimize (vacuum if needed)
-- VACUUM;  # Uncomment if freelist_count > 1000
EOF
```

**Action Items**:
- If `integrity_check` != "ok" → URGENT: Investigate database corruption
- If `size_mb` > 1000 → Review data retention policies
- If `freelist_count` > 1000 → Run VACUUM during maintenance window

---

#### 12. Performance Metrics
```bash
# Average query performance (if instrumented)
# Note: Requires application-level metrics logging

# License generation time
sqlite3 ~/.tmws/data/tmws.db <<EOF
SELECT
  'license_generation' as operation,
  COUNT(*) as operations,
  ROUND(AVG(CAST((julianday(created_at) - julianday(issued_at)) * 86400000 AS INTEGER)), 2) as avg_time_ms
FROM license_keys
WHERE created_at > datetime('now', '-7 days');
EOF
```

**Action Items**:
- If `avg_time_ms` > 500ms → Investigate database indexes
- Compare with baseline (Phase 2C target: < 200ms)

---

## 🔍 Investigation Playbooks

### Playbook A: High Permission Denial Rate (>20%)

**Symptoms**:
- `deny_percentage` > 20% in Hour 1-4 monitoring

**Investigation Steps**:
1. Check role distribution (Step 6)
   ```bash
   sqlite3 ~/.tmws/data/tmws.db "SELECT role, COUNT(*) FROM agents GROUP BY role;"
   ```

2. Identify most denied operations (Step 9)
   ```bash
   sqlite3 ~/.tmws/data/tmws.db <<EOF
   SELECT details->>'operation', COUNT(*) as count
   FROM security_audit_logs
   WHERE event_type = 'permission_check' AND details->>'result' = 'DENY'
   GROUP BY details->>'operation'
   ORDER BY count DESC LIMIT 5;
   EOF
   ```

3. Review recent role changes
   ```bash
   sqlite3 ~/.tmws/data/tmws.db <<EOF
   SELECT agent_id, role, updated_at
   FROM agents
   WHERE updated_at > datetime('now', '-1 day')
   ORDER BY updated_at DESC;
   EOF
   ```

4. **Fix**:
   - If agents have wrong roles → Update with SQL
   - If operations require different permissions → Review RBAC policy

---

### Playbook B: License Validation Failures (>10%)

**Symptoms**:
- `failure_rate` > 10% in Step 4

**Investigation Steps**:
1. Check failure reasons
   ```bash
   sqlite3 ~/.tmws/data/tmws.db <<EOF
   SELECT
     CASE
       WHEN license_key_id IS NULL THEN 'License not found'
       WHEN valid = 0 THEN 'Invalid signature or expired'
       ELSE 'Unknown'
     END as reason,
     COUNT(*) as count
   FROM license_usage_history
   WHERE validated_at > datetime('now', '-1 hour') AND valid = 0
   GROUP BY reason;
   EOF
   ```

2. Check for mass expiration
   ```bash
   sqlite3 ~/.tmws/data/tmws.db <<EOF
   SELECT COUNT(*) as expired_licenses
   FROM license_keys
   WHERE revoked_at IS NULL AND expires_at < datetime('now');
   EOF
   ```

3. **Fix**:
   - If "License not found" → Users using invalid keys, expected
   - If "Invalid signature" → Check SECRET_KEY consistency
   - If mass expiration → Notify users to renew

---

### Playbook C: No Audit Logs

**Symptoms**:
- `total_checks` = 0 in Step 2

**Investigation Steps**:
1. Verify RBAC is enabled
   ```bash
   grep -r "check_permission" src/tools/license_tools.py
   # Should find @require_permission decorators
   ```

2. Check if audit logging is configured
   ```bash
   grep "SecurityAuditLog" src/security/rbac.py
   # Should find audit log creation code
   ```

3. Test RBAC directly
   ```bash
   TMWS_DATABASE_URL="sqlite+aiosqlite:///:memory:" \
     pytest tests/unit/security/test_rbac_permissions.py::TestSecurityBoundaries::test_permission_check_audited_allow -v
   # Should PASS
   ```

4. **Fix**:
   - If decorators missing → CRITICAL: Deployment issue, rollback
   - If audit logging broken → Check database permissions
   - If tests fail → CRITICAL: Code regression, rollback

---

## 📈 Success Metrics (KPIs)

### Week 1 Targets

| Metric | Target | Acceptable Range |
|--------|--------|------------------|
| **Uptime** | 99.9% | 99% - 100% |
| **Permission Denial Rate** | 5-15% | 0% - 20% |
| **License Validation Success** | 90%+ | 85% - 100% |
| **License Generation Time** | <200ms | 50ms - 500ms |
| **RBAC Audit Coverage** | 100% | 95% - 100% |
| **Database Integrity** | "ok" | "ok" only |

### Month 1 Trends

- **User Adoption**: 80% of agents have appropriate roles assigned
- **License Usage**: Steady growth in validations (no sudden drops)
- **Performance**: No degradation vs pre-RBAC baseline
- **Incidents**: Zero P0/P1 security incidents

---

## 🚨 Escalation Matrix

| Severity | Condition | Response Time | Action |
|----------|-----------|---------------|--------|
| **P0 - Critical** | Service down, database corrupted, all validations failing | 5 minutes | Immediate rollback (Option B) |
| **P1 - High** | >50% permission denials, >50% validation failures | 30 minutes | Investigate + hotfix or rollback |
| **P2 - Medium** | 20-50% denials, 10-50% failures | 2 hours | Investigate + schedule fix |
| **P3 - Low** | <20% denials, <10% failures | 1 day | Log for weekly review |

**On-Call Contact**: (Configure your team's contact info)

---

## ✅ Monitoring Checklist Summary

### First 24 Hours
- [ ] Hour 1: Service health, RBAC checks, license operations (Steps 1-4)
- [ ] Hour 4: Migration status, role distribution (Steps 5-6)
- [ ] Hour 8: Audit logs, expiration monitoring (Steps 7-8)
- [ ] Hour 24: Full weekly check (Steps 9-12)

### Weekly (Ongoing)
- [ ] Monday: Permission analysis (Step 9)
- [ ] Monday: Usage trends (Step 10)
- [ ] Monday: Database health (Step 11)
- [ ] Monday: Performance review (Step 12)

### Monthly (Ongoing)
- [ ] Review KPIs vs targets
- [ ] Update monitoring thresholds if needed
- [ ] Document incidents and resolutions
- [ ] Plan improvements for next release

---

**Related Documents**:
- **Deployment Guide**: `PHASE_2C_PRODUCTION_DEPLOYMENT.md`
- **Rollback Procedure**: `RBAC_ROLLBACK_PROCEDURE.md`
- **Known Issues**: `docs/testing/WAVE3_KNOWN_ISSUES.md`

---

*This monitoring checklist is part of TMWS v2.3.0 (Phase 2C: RBAC + License MCP Tools)*
