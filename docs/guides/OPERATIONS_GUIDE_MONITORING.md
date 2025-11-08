# Agent Trust & Verification System - Operations Guide

**Version**: v2.2.7+
**Target Audience**: System administrators, DevOps engineers, SREs
**Last Updated**: 2025-11-07

---

## Table of Contents

1. [Overview](#overview)
2. [Monitoring Strategy](#monitoring-strategy)
3. [Trust Score Metrics](#trust-score-metrics)
4. [Alerting Configuration](#alerting-configuration)
5. [Incident Response](#incident-response)
6. [Common Issues](#common-issues)
7. [Performance Tuning](#performance-tuning)
8. [Maintenance Procedures](#maintenance-procedures)

---

## Overview

This guide provides operational procedures for monitoring, troubleshooting, and maintaining the Agent Trust & Verification System in production environments.

### Key Responsibilities

As an operator, you are responsible for:

1. **Monitoring**: Track trust score trends across all agents
2. **Alerting**: Configure notifications for trust score degradation
3. **Incident Response**: Handle verification failures and trust issues
4. **Maintenance**: Perform routine cleanup and optimization
5. **Reporting**: Generate trust score reports for stakeholders

### Service Level Objectives (SLOs)

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Trust Score Accuracy** | ≥ 95% | Verification accuracy rate |
| **Verification Latency** | < 60s P95 | Command execution time |
| **System Availability** | ≥ 99.9% | Verification service uptime |
| **Alert Response Time** | < 15min | Time to acknowledge alerts |
| **Incident Resolution** | < 4h | Time to resolve trust issues |

---

## Monitoring Strategy

### 1. Trust Score Dashboard

**Purpose**: Real-time visibility into agent trust levels

**Metrics to Track**:
- Current trust score per agent
- Trust score trends (7-day, 30-day)
- Verification success rate
- Status distribution (TRUSTED, MONITORED, BLOCKED, etc.)

**Implementation (Prometheus + Grafana)**:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'tmws-trust'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics/trust'
    scrape_interval: 30s
```

```python
# src/api/routers/metrics.py
from prometheus_client import Gauge, Counter, Histogram

# Trust score metrics
trust_score_gauge = Gauge(
    'tmws_agent_trust_score',
    'Current trust score for agent',
    ['agent_id', 'agent_type']
)

verification_success_counter = Counter(
    'tmws_verification_success_total',
    'Total successful verifications',
    ['agent_id', 'verification_type']
)

verification_failure_counter = Counter(
    'tmws_verification_failure_total',
    'Total failed verifications',
    ['agent_id', 'verification_type']
)

verification_latency_histogram = Histogram(
    'tmws_verification_duration_seconds',
    'Verification execution time',
    ['agent_id', 'verification_type']
)


@router.get("/metrics/trust")
async def trust_metrics(session: AsyncSession = Depends(get_session)):
    """Expose trust metrics for Prometheus."""
    agent_service = AgentService(session)
    agents = await agent_service.list_agents(limit=1000)

    for agent in agents:
        trust_score_gauge.labels(
            agent_id=agent.agent_id,
            agent_type=agent.agent_type,
        ).set(agent.trust_score)

        verification_success_counter.labels(
            agent_id=agent.agent_id,
            verification_type="all",
        ).inc(agent.successful_verifications or 0)

        verification_failure_counter.labels(
            agent_id=agent.agent_id,
            verification_type="all",
        ).inc(agent.failed_verifications or 0)

    from prometheus_client import generate_latest
    return Response(content=generate_latest(), media_type="text/plain")
```

**Grafana Dashboard Configuration**:

```json
{
    "dashboard": {
        "title": "TMWS Agent Trust Monitoring",
        "panels": [
            {
                "title": "Trust Score Overview",
                "type": "stat",
                "targets": [
                    {
                        "expr": "tmws_agent_trust_score",
                        "legendFormat": "{{agent_id}}"
                    }
                ],
                "thresholds": {
                    "steps": [
                        {"value": 0.0, "color": "red"},
                        {"value": 0.5, "color": "yellow"},
                        {"value": 0.75, "color": "green"},
                        {"value": 0.90, "color": "blue"}
                    ]
                }
            },
            {
                "title": "Verification Success Rate",
                "type": "graph",
                "targets": [
                    {
                        "expr": "rate(tmws_verification_success_total[5m]) / (rate(tmws_verification_success_total[5m]) + rate(tmws_verification_failure_total[5m]))",
                        "legendFormat": "{{agent_id}}"
                    }
                ]
            },
            {
                "title": "Status Distribution",
                "type": "piechart",
                "targets": [
                    {
                        "expr": "count by (status) (tmws_agent_trust_score)",
                        "legendFormat": "{{status}}"
                    }
                ]
            }
        ]
    }
}
```

### 2. Database Monitoring

**Purpose**: Track trust-related database growth and performance

**SQL Queries for Monitoring**:

```sql
-- Total verifications per agent (last 24h)
SELECT
    agent_id,
    COUNT(*) as total_verifications,
    SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) as successful,
    SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed,
    AVG(CAST(julianday(completed_at) - julianday(created_at) AS REAL) * 86400) as avg_duration_sec
FROM agent_verifications
WHERE created_at >= datetime('now', '-1 day')
GROUP BY agent_id
ORDER BY total_verifications DESC;

-- Trust score degradation (agents with declining scores)
SELECT
    ath.agent_id,
    MIN(ath.new_trust_score) as lowest_score,
    MAX(ath.new_trust_score) as highest_score,
    COUNT(*) as score_changes,
    SUM(ath.score_change) as total_change
FROM agent_trust_history ath
WHERE ath.created_at >= datetime('now', '-7 days')
GROUP BY ath.agent_id
HAVING SUM(ath.score_change) < -0.10  -- More than 10% decrease
ORDER BY total_change ASC;

-- Database table sizes
SELECT
    name as table_name,
    (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=m.name) as row_count
FROM sqlite_master m
WHERE type='table' AND name LIKE 'agent%'
ORDER BY name;
```

**Automated Monitoring Script**:

```bash
#!/bin/bash
# scripts/monitor_trust_database.sh

# Check database size
DB_SIZE=$(du -h data/tmws.db | cut -f1)
echo "Database Size: $DB_SIZE"

# Check verification table growth
VERIFICATION_COUNT=$(sqlite3 data/tmws.db "SELECT COUNT(*) FROM agent_verifications;")
echo "Total Verifications: $VERIFICATION_COUNT"

# Check agents with low trust scores
LOW_TRUST=$(sqlite3 data/tmws.db "
    SELECT COUNT(*) FROM agents
    WHERE trust_score < 0.50 AND is_active = 1;
")
echo "Low Trust Agents (< 0.50): $LOW_TRUST"

# Alert if thresholds exceeded
if [ "$LOW_TRUST" -gt 3 ]; then
    echo "⚠️ ALERT: $LOW_TRUST agents have low trust scores"
    # Send notification (Slack, PagerDuty, etc.)
fi
```

### 3. Log Aggregation

**Purpose**: Centralize trust-related logs for analysis

**Log Levels for Trust Events**:
- `INFO`: Trust score updates, successful verifications
- `WARNING`: Failed verifications, status changes to MONITORED
- `ERROR`: Verification errors, status changes to BLOCKED
- `CRITICAL`: System-wide trust issues

**ELK Stack Configuration**:

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/tmws/trust_*.log
    fields:
      service: tmws-trust
      environment: production
    multiline.pattern: '^\d{4}-\d{2}-\d{2}'
    multiline.negate: true
    multiline.match: after

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "tmws-trust-%{+yyyy.MM.dd}"

processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
```

**Kibana Visualization Queries**:

```
# Failed verifications (last 1h)
service:tmws-trust AND log.level:ERROR AND message:*verification*failed* AND @timestamp:[now-1h TO now]

# Trust score drops (> 0.10 decrease)
service:tmws-trust AND message:*trust_score_change* AND score_change:[-1.0 TO -0.10]

# Blocked agents
service:tmws-trust AND message:*status_change* AND new_status:BLOCKED
```

---

## Trust Score Metrics

### Key Metrics to Monitor

#### 1. **Trust Score Distribution**

**Metric**: Distribution of agents across trust levels

**Query (Prometheus)**:
```promql
histogram_quantile(0.50, sum(rate(tmws_agent_trust_score_bucket[5m])) by (le))
histogram_quantile(0.90, sum(rate(tmws_agent_trust_score_bucket[5m])) by (le))
histogram_quantile(0.99, sum(rate(tmws_agent_trust_score_bucket[5m])) by (le))
```

**Targets**:
- P50 ≥ 0.85 (median agent should be ACTIVE or better)
- P90 ≥ 0.75 (90% of agents should be ACTIVE)
- P99 ≥ 0.50 (even low performers should be MONITORED)

#### 2. **Verification Success Rate**

**Metric**: Percentage of verifications that pass

**Query**:
```promql
sum(rate(tmws_verification_success_total[5m])) /
(sum(rate(tmws_verification_success_total[5m])) + sum(rate(tmws_verification_failure_total[5m])))
```

**Target**: ≥ 95% overall success rate

**Alert Threshold**: < 90% for 15 minutes

#### 3. **Trust Score Volatility**

**Metric**: Standard deviation of trust score changes

**SQL Query**:
```sql
SELECT
    agent_id,
    AVG(score_change) as avg_change,
    STDEV(score_change) as std_dev_change,
    COUNT(*) as changes_count
FROM agent_trust_history
WHERE created_at >= datetime('now', '-7 days')
GROUP BY agent_id
HAVING STDEV(score_change) > 0.15  -- High volatility
ORDER BY std_dev_change DESC;
```

**Interpretation**:
- Low volatility (σ < 0.05): Stable, predictable agent
- Medium volatility (0.05 ≤ σ ≤ 0.15): Normal fluctuation
- High volatility (σ > 0.15): Inconsistent performance, investigate

#### 4. **Time to Recovery**

**Metric**: Time for agent to recover from BLOCKED/UNTRUSTED status

**SQL Query**:
```sql
WITH status_changes AS (
    SELECT
        agent_id,
        old_status,
        new_status,
        created_at,
        LAG(created_at) OVER (PARTITION BY agent_id ORDER BY created_at) as prev_time
    FROM (
        SELECT
            agent_id,
            'BLOCKED' as old_status,
            'ACTIVE' as new_status,
            created_at
        FROM agent_trust_history
        WHERE new_trust_score >= 0.75 AND old_trust_score < 0.25
    )
)
SELECT
    agent_id,
    AVG(julianday(created_at) - julianday(prev_time)) as avg_recovery_days
FROM status_changes
WHERE prev_time IS NOT NULL
GROUP BY agent_id;
```

**Target**: < 7 days average recovery time

---

## Alerting Configuration

### Alert Rules

#### 1. **Low Trust Score Alert**

**Condition**: Agent trust score drops below 0.50

**Severity**: WARNING

**Prometheus AlertManager Rule**:
```yaml
groups:
  - name: tmws_trust
    interval: 30s
    rules:
      - alert: LowAgentTrustScore
        expr: tmws_agent_trust_score < 0.50
        for: 5m
        labels:
          severity: warning
          service: tmws-trust
        annotations:
          summary: "Agent {{ $labels.agent_id }} has low trust score"
          description: "Agent {{ $labels.agent_id }} trust score is {{ $value | humanize }}, below threshold of 0.50"
          runbook_url: "https://docs.tmws.local/runbooks/low-trust-score"
```

**Notification Channels**:
- Slack: `#tmws-alerts`
- Email: `devops@example.com`
- PagerDuty: Low-priority

#### 2. **Critical Trust Score Alert**

**Condition**: Agent trust score drops below 0.25 (BLOCKED status)

**Severity**: CRITICAL

**Prometheus Rule**:
```yaml
- alert: CriticalAgentTrustScore
  expr: tmws_agent_trust_score < 0.25
  for: 1m
  labels:
    severity: critical
    service: tmws-trust
  annotations:
    summary: "Agent {{ $labels.agent_id }} is BLOCKED"
    description: "Agent {{ $labels.agent_id }} trust score is {{ $value | humanize }}, agent is BLOCKED from autonomous actions"
    runbook_url: "https://docs.tmws.local/runbooks/blocked-agent"
```

**Notification Channels**:
- Slack: `#tmws-critical`
- Email: `devops@example.com`, `team-leads@example.com`
- PagerDuty: High-priority
- Phone: On-call engineer

#### 3. **High Verification Failure Rate**

**Condition**: More than 20% of verifications fail in 15 minutes

**Severity**: WARNING

**Prometheus Rule**:
```yaml
- alert: HighVerificationFailureRate
  expr: |
    (sum by (agent_id) (rate(tmws_verification_failure_total[15m])) /
    (sum by (agent_id) (rate(tmws_verification_success_total[15m])) +
    sum by (agent_id) (rate(tmws_verification_failure_total[15m])))) > 0.20
  for: 15m
  labels:
    severity: warning
    service: tmws-trust
  annotations:
    summary: "High verification failure rate for {{ $labels.agent_id }}"
    description: "Agent {{ $labels.agent_id }} has {{ $value | humanizePercentage }} verification failures in last 15 minutes"
```

#### 4. **Verification System Unavailable**

**Condition**: Verification service is down

**Severity**: CRITICAL

**Prometheus Rule**:
```yaml
- alert: VerificationServiceDown
  expr: up{job="tmws-verification"} == 0
  for: 5m
  labels:
    severity: critical
    service: tmws-trust
  annotations:
    summary: "Verification service is down"
    description: "TMWS verification service has been unavailable for 5 minutes"
```

### Alert Routing

**AlertManager Configuration**:
```yaml
route:
  receiver: 'team-slack'
  group_by: ['alertname', 'agent_id']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  routes:
    - match:
        severity: critical
      receiver: 'pagerduty-high'
      continue: true
    - match:
        severity: warning
      receiver: 'team-slack'
    - match:
        alertname: CriticalAgentTrustScore
      receiver: 'team-leads-email'
      continue: true

receivers:
  - name: 'team-slack'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#tmws-alerts'
        title: '{{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'

  - name: 'pagerduty-high'
    pagerduty_configs:
      - service_key: 'YOUR_PAGERDUTY_SERVICE_KEY'
        severity: 'critical'

  - name: 'team-leads-email'
    email_configs:
      - to: 'team-leads@example.com'
        from: 'alerts@example.com'
        smarthost: 'smtp.example.com:587'
        auth_username: 'alerts@example.com'
        auth_password: 'YOUR_SMTP_PASSWORD'
```

---

## Incident Response

### Incident Classification

| Severity | Impact | Response Time | Escalation |
|----------|--------|---------------|------------|
| **P0 - CRITICAL** | System-wide trust failure | Immediate (< 5min) | On-call + Team Lead |
| **P1 - HIGH** | Multiple agents BLOCKED | < 15min | On-call engineer |
| **P2 - MEDIUM** | Single agent BLOCKED | < 1h | Assigned engineer |
| **P3 - LOW** | Agent MONITORED status | < 4h | Team triage |

### Incident Response Playbook

#### P0: System-Wide Trust Failure

**Symptoms**:
- Multiple agents (> 5) suddenly BLOCKED
- Verification service unavailable
- Database corruption detected

**Response Steps**:

1. **Immediate Assessment** (< 2 minutes):
   ```bash
   # Check verification service health
   curl -f http://localhost:8000/health/verification || echo "Service DOWN"

   # Check database integrity
   sqlite3 data/tmws.db "PRAGMA integrity_check;"

   # Count BLOCKED agents
   sqlite3 data/tmws.db "SELECT COUNT(*) FROM agents WHERE status='BLOCKED';"
   ```

2. **Isolate Issue** (< 5 minutes):
   ```bash
   # Stop verification service to prevent further damage
   systemctl stop tmws-verification

   # Backup current database state
   cp data/tmws.db data/tmws.db.incident-$(date +%Y%m%d-%H%M%S)
   ```

3. **Identify Root Cause** (< 15 minutes):
   - Check logs: `journalctl -u tmws-verification -n 1000`
   - Review recent deployments
   - Check database query performance
   - Verify external dependencies (Ollama, disk space, etc.)

4. **Mitigation** (< 30 minutes):
   - Restore from known good backup if corruption detected
   - Apply hotfix if bug identified
   - Temporarily disable trust tracking if necessary

5. **Recovery** (< 1 hour):
   ```python
   # Reset trust scores for affected agents
   async def emergency_trust_reset(session):
       agent_service = AgentService(session)
       agents = await agent_service.list_agents(status="BLOCKED")

       for agent in agents:
           await agent_service.reset_agent_trust(
               agent_id=agent.agent_id,
               new_score=0.75,  # Reset to ACTIVE
               reason=f"Emergency reset after P0 incident {incident_id}",
           )

       logger.info(f"Reset trust scores for {len(agents)} agents")
   ```

6. **Post-Incident** (< 4 hours):
   - Write incident report
   - Update runbooks
   - Schedule post-mortem meeting

#### P1: Multiple Agents BLOCKED

**Symptoms**:
- 2-5 agents suddenly BLOCKED
- Verification failures spike
- Trust scores dropping rapidly

**Response Steps**:

1. **Assess Scope** (< 5 minutes):
   ```sql
   SELECT agent_id, trust_score, status, last_verification_at
   FROM agents
   WHERE status IN ('BLOCKED', 'UNTRUSTED')
   ORDER BY trust_score ASC;
   ```

2. **Review Recent Verifications** (< 10 minutes):
   ```sql
   SELECT
       av.agent_id,
       av.claim,
       av.verification_type,
       av.status,
       vr.claim_verified,
       vr.actual_result
   FROM agent_verifications av
   JOIN verification_results vr ON av.id = vr.verification_id
   WHERE av.created_at >= datetime('now', '-1 hour')
       AND vr.claim_verified = 0
   ORDER BY av.created_at DESC
   LIMIT 50;
   ```

3. **Identify Pattern** (< 15 minutes):
   - Common verification type failing?
   - Specific agent types affected?
   - Recent code changes?
   - External dependency issues?

4. **Apply Fix** (< 30 minutes):
   - Fix verification commands if broken
   - Update expected results if requirements changed
   - Revert deployment if buggy code deployed

5. **Selective Trust Reset** (< 45 minutes):
   ```python
   # Reset only if justified
   affected_agents = ["hera-strategist", "artemis-optimizer"]

   for agent_id in affected_agents:
       # Review history first
       history = await agent_service.get_agent_trust_history(
           agent_id=agent_id,
           limit=20,
       )

       # Reset if false negatives detected
       if all(h.verified == False for h in history[-5:]):  # Last 5 all failed
           await agent_service.reset_agent_trust(
               agent_id=agent_id,
               new_score=0.80,
               reason="Reset after false negatives detected in verification system",
           )
   ```

#### P2: Single Agent BLOCKED

**Symptoms**:
- One agent's trust score below 0.25
- Agent status is BLOCKED
- Verification failures for specific agent

**Response Steps**:

1. **Review Agent History** (< 15 minutes):
   ```python
   agent = await agent_service.get_agent_by_id("hera-strategist")
   history = await agent_service.get_agent_trust_history(
       agent_id="hera-strategist",
       limit=20,
   )

   print(f"Agent: {agent.agent_id}")
   print(f"Trust Score: {agent.trust_score:.2f}")
   print(f"Status: {agent.status}")
   print(f"\nRecent History:")
   for record in history:
       print(f"  {record.created_at}: {record.old_trust_score:.2f} → {record.new_trust_score:.2f}")
       print(f"    Claim: {record.claim}")
       print(f"    Verified: {record.verified}")
   ```

2. **Determine Legitimacy** (< 30 minutes):
   - Were claims genuinely false?
   - Were verification commands incorrect?
   - Was there a temporary system issue?

3. **Take Action**:
   - **If claims were false**: Keep BLOCKED, notify agent maintainers
   - **If verifications were faulty**: Reset trust score
   - **If temporary issue**: Wait for natural recovery

4. **Document Decision**:
   ```python
   # Record decision in system
   await agent_service.add_agent_note(
       agent_id="hera-strategist",
       note=f"Investigated BLOCKED status. Root cause: [description]. Action: [action taken]. By: [operator name]",
   )
   ```

#### P3: Agent MONITORED Status

**Symptoms**:
- Agent trust score 0.50-0.74
- Status is MONITORED
- Some verification failures

**Response Steps**:

1. **Monitor** (passive):
   - No immediate action required
   - Trust score will self-correct with accurate claims
   - Verification failures are within acceptable range

2. **Investigate if Persistent** (after 7 days):
   - Review claims and verifications
   - Check if agent logic needs update
   - Consider reaching out to agent maintainers

3. **Escalate if Degrading**:
   - If trust score continues to drop → P2 incident
   - If multiple agents affected → P1 incident

---

## Common Issues

### Issue 1: Trust Score Stuck at 1.0

**Symptoms**:
- Agent trust score remains at 1.0 despite verifications
- No trust history records created

**Diagnosis**:
```sql
-- Check if verifications are running
SELECT COUNT(*) FROM agent_verifications
WHERE agent_id = 'hera-strategist' AND created_at >= datetime('now', '-1 day');

-- Check if trust tracking is enabled
SELECT trust_tracking_enabled FROM agents WHERE agent_id = 'hera-strategist';
```

**Root Causes**:
1. Trust tracking disabled in agent configuration
2. Verification results not being recorded
3. Trust score update logic not triggering

**Solution**:
```python
# Enable trust tracking
agent = await agent_service.get_agent_by_id("hera-strategist")
agent.trust_tracking_enabled = True
await session.commit()

# Manually trigger trust score update
for verification in recent_verifications:
    result = await session.get(VerificationResult, verification.result_id)
    await agent_service.update_agent_trust_score(
        agent_id="hera-strategist",
        verification_result=result,
    )
```

### Issue 2: Verification Commands Timing Out

**Symptoms**:
- Verification status is `ERROR`
- Logs show timeout errors
- Trust scores decreasing unexpectedly

**Diagnosis**:
```sql
SELECT
    verification_type,
    COUNT(*) as timeout_count,
    AVG(execution_time_ms) as avg_time_ms
FROM verification_results
WHERE verification_error LIKE '%timeout%'
GROUP BY verification_type;
```

**Root Causes**:
1. Commands genuinely slow (need optimization)
2. Timeout threshold too aggressive
3. System resource constraints

**Solution**:
```python
# Increase timeout for specific verification types
verification_service.timeout_defaults["security"] = 300  # 5 minutes
verification_service.timeout_defaults["performance"] = 240  # 4 minutes

# Or adjust per-verification
result = await verification_service.verify_claim(
    agent_id="hestia-auditor",
    claim="No security vulnerabilities found",
    verification_type="security",
    verification_command="bandit -r src/ -f json",
    timeout=300,  # Override default
)
```

### Issue 3: Database Growth Concern

**Symptoms**:
- `agent_verifications` table growing rapidly
- Database file size increasing significantly
- Query performance degrading

**Diagnosis**:
```sql
-- Check table sizes
SELECT
    COUNT(*) as verification_count,
    (COUNT(*) * 1024) / (1024 * 1024) as approx_size_mb
FROM agent_verifications;

SELECT
    COUNT(*) as history_count,
    (COUNT(*) * 512) / (1024 * 1024) as approx_size_mb
FROM agent_trust_history;
```

**Solution**:
```bash
# Archive old verifications (> 90 days)
python scripts/archive_old_verifications.py --days 90 --output /backups/verifications_archive.sql

# Vacuum database
sqlite3 data/tmws.db "VACUUM;"
```

```python
# scripts/archive_old_verifications.py
async def archive_old_verifications(days: int, output_path: str):
    """Archive verifications older than specified days."""
    from datetime import datetime, timedelta

    cutoff_date = datetime.utcnow() - timedelta(days=days)

    # Export to SQL file
    async with aiosqlite.connect("data/tmws.db") as db:
        async with aiofiles.open(output_path, "w") as f:
            cursor = await db.execute(
                """
                SELECT * FROM agent_verifications
                WHERE created_at < ?
                """,
                (cutoff_date,),
            )

            await f.write("-- Archived verifications\n")
            async for row in cursor:
                await f.write(f"INSERT INTO agent_verifications VALUES {row};\n")

        # Delete old records
        await db.execute(
            "DELETE FROM agent_verifications WHERE created_at < ?",
            (cutoff_date,),
        )
        await db.commit()

    logger.info(f"Archived verifications older than {days} days to {output_path}")
```

---

## Performance Tuning

### Database Optimization

```sql
-- Add indexes for common queries
CREATE INDEX IF NOT EXISTS idx_verifications_agent_created
    ON agent_verifications(agent_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_trust_history_agent_created
    ON agent_trust_history(agent_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_agents_trust_score
    ON agents(trust_score, status);

-- Analyze tables for query optimization
ANALYZE agent_verifications;
ANALYZE agent_trust_history;
ANALYZE agents;
```

### Verification Caching

```python
# Cache verification results for identical claims
from functools import lru_cache
import hashlib


class CachedVerificationService(VerificationService):
    """Verification service with result caching."""

    @lru_cache(maxsize=1000)
    async def verify_claim_cached(
        self,
        agent_id: str,
        claim: str,
        verification_type: str,
        verification_command: str,
    ) -> VerificationResult:
        """Verify claim with caching."""
        # Generate cache key
        cache_key = hashlib.sha256(
            f"{claim}:{verification_type}:{verification_command}".encode()
        ).hexdigest()

        # Check cache (Redis)
        cached = await redis_client.get(f"verification:{cache_key}")
        if cached:
            logger.info(f"Cache hit for verification: {claim}")
            return VerificationResult.from_json(cached)

        # Execute verification
        result = await super().verify_claim(
            agent_id=agent_id,
            claim=claim,
            verification_type=verification_type,
            verification_command=verification_command,
        )

        # Cache result (5 minutes TTL)
        await redis_client.setex(
            f"verification:{cache_key}",
            300,
            result.to_json(),
        )

        return result
```

---

## Maintenance Procedures

### Weekly Maintenance Checklist

```bash
#!/bin/bash
# scripts/weekly_trust_maintenance.sh

echo "=== TMWS Trust System Weekly Maintenance ==="
echo "Date: $(date)"

# 1. Database vacuum
echo "1. Vacuuming database..."
sqlite3 data/tmws.db "VACUUM;"

# 2. Archive old verifications (> 90 days)
echo "2. Archiving old verifications..."
python scripts/archive_old_verifications.py --days 90

# 3. Regenerate trust score statistics
echo "3. Regenerating statistics..."
python scripts/regenerate_trust_stats.py

# 4. Check for anomalies
echo "4. Checking for anomalies..."
python scripts/detect_trust_anomalies.py

# 5. Generate weekly report
echo "5. Generating weekly report..."
python scripts/generate_weekly_trust_report.py --output reports/trust_$(date +%Y%m%d).md

echo "=== Maintenance Complete ==="
```

### Monthly Audit

```python
# scripts/monthly_trust_audit.py
async def monthly_trust_audit(session):
    """Perform comprehensive monthly audit."""
    agent_service = AgentService(session)

    report = {
        "audit_date": datetime.utcnow().isoformat(),
        "agents_audited": 0,
        "issues_found": [],
        "recommendations": [],
    }

    # Audit all agents
    agents = await agent_service.list_agents(limit=1000)
    report["agents_audited"] = len(agents)

    for agent in agents:
        # Check for stale agents (no activity in 30 days)
        if agent.last_activity and (datetime.utcnow() - agent.last_activity).days > 30:
            report["issues_found"].append({
                "agent_id": agent.agent_id,
                "issue": "stale_agent",
                "details": f"No activity for {(datetime.utcnow() - agent.last_activity).days} days",
            })

        # Check for low trust with no verification attempts
        if agent.trust_score < 0.50 and (agent.total_verifications or 0) == 0:
            report["issues_found"].append({
                "agent_id": agent.agent_id,
                "issue": "low_trust_no_verification",
                "details": "Trust score low but no verifications attempted",
            })

        # Check for high volatility
        history = await agent_service.get_agent_trust_history(
            agent_id=agent.agent_id,
            limit=50,
        )

        if len(history) >= 10:
            changes = [h.score_change for h in history]
            std_dev = np.std(changes)

            if std_dev > 0.15:
                report["issues_found"].append({
                    "agent_id": agent.agent_id,
                    "issue": "high_volatility",
                    "details": f"Trust score volatility: {std_dev:.2f}",
                })

    # Generate recommendations
    if len(report["issues_found"]) > 0:
        report["recommendations"].append(
            "Review agents with issues and determine corrective actions"
        )

    # Save report
    with open(f"reports/audit_{datetime.utcnow().strftime('%Y%m')}.json", "w") as f:
        json.dump(report, f, indent=2)

    return report
```

---

## Next Steps

- **Users**: [User Guide: Agent Trust](./USER_GUIDE_AGENT_TRUST.md)
- **Developers**: [Developer Guide: Integration](./DEVELOPER_GUIDE_VERIFICATION.md)
- **API Reference**: [API Reference: Trust System](./API_REFERENCE_TRUST_SYSTEM.md)
- **Migration**: [Migration Guide: Trust System v1](./MIGRATION_GUIDE_TRUST_V1.md)

---

**Need Help?**
- Incident Response: [PagerDuty](https://tmws.pagerduty.com)
- Runbooks: [docs/runbooks/](../runbooks/)
- Team Chat: `#tmws-ops` on Slack

---

*This operations guide is part of TMWS v2.2.7+ Agent Trust & Verification System.*
