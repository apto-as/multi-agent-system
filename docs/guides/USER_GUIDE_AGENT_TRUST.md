# Agent Trust & Verification System - User Guide

**Version**: v2.2.7+
**Status**: Production Ready
**Last Updated**: 2025-11-07

---

## Table of Contents

1. [Overview](#overview)
2. [What is Trust Tracking?](#what-is-trust-tracking)
3. [Why Trust Matters](#why-trust-matters)
4. [Getting Started](#getting-started)
5. [Using Trust Tools](#using-trust-tools)
6. [Understanding Trust Scores](#understanding-trust-scores)
7. [Real-World Examples](#real-world-examples)
8. [Troubleshooting](#troubleshooting)
9. [FAQ](#faq)

---

## Overview

The **Agent Trust & Verification System** helps you track and verify the accuracy of agent claims and recommendations. When agents (like Hera or Artemis) make statements about your codebase, TMWS can automatically verify these claims and adjust trust scores accordingly.

**Key Benefits**:
- 🎯 **Accuracy Tracking**: Know which agents provide reliable information
- 🔍 **Automatic Verification**: Claims are verified against actual system state
- 📊 **Trust Scores**: Visual indicators of agent reliability (0.0 to 1.0)
- 🚨 **Status-Based Actions**: Agents with low trust are automatically flagged

---

## What is Trust Tracking?

Trust tracking monitors agent performance by:

1. **Recording Claims**: When an agent makes a statement (e.g., "5 tests fail")
2. **Verifying Claims**: Running actual checks (e.g., `pytest tests/unit/`)
3. **Scoring Accuracy**: Updating trust scores based on verification results
4. **Adjusting Access**: Changing agent status if trust falls too low

### Trust Score Scale

| Score Range | Status | Meaning | Actions Available |
|-------------|--------|---------|-------------------|
| 0.90 - 1.00 | **TRUSTED** | Highly reliable | Full access to all operations |
| 0.75 - 0.89 | **ACTIVE** | Generally reliable | Normal operations, monitoring enabled |
| 0.50 - 0.74 | **MONITORED** | Questionable accuracy | Additional verification required |
| 0.25 - 0.49 | **UNTRUSTED** | Frequent errors | Peer review required for actions |
| 0.00 - 0.24 | **BLOCKED** | Severely unreliable | No autonomous actions allowed |

---

## Why Trust Matters

### Real Incident: Hera False Report (2025-10-24)

**What Happened**:
```
Hera: "Found 216 fake tests in test_coverage_boost.py"
User: "Please verify"
Verification: ls tests/unit/test_coverage_boost.py → File not found
Result: 100% error rate (1 correct claim, 1 false claim)
Trust Score: 1.0 → 0.0 (TRUSTED → BLOCKED)
```

**Impact**:
- User wasted time investigating non-existent files
- Development workflow disrupted
- Required manual verification of all Hera's claims

**Solution with Trust Tracking**:
- Automatic verification detected the false claim
- Trust score dropped immediately
- Future claims from Hera flagged for verification
- User notified of reliability issue

### Real Incident: Artemis False Claims (2025-10-27)

**What Happened**:
```
Artemis: "RC-7 causes 5 tests to fail with RuntimeError"
Verification: pytest tests/unit/test_rc7.py → 5 passed, 0 failed
Result: 75% error rate (3 correct claims, 1 false claim)
Trust Score: 0.0 → 0.25 (BLOCKED → UNTRUSTED)
```

**Impact**:
- User delayed fixing actual issues
- False positive created confusion
- Development priorities misaligned

**Solution with Trust Tracking**:
- Verification caught the discrepancy
- Trust score adjusted appropriately
- Artemis flagged for peer review on future claims

---

## Getting Started

### Prerequisites

- TMWS v2.2.7 or later
- MCP connection configured (see [MCP Setup Guide](../MCP_SETUP_GUIDE.md))
- Agent registered in TMWS (see [Custom Agents Guide](./CUSTOM_AGENTS_GUIDE.md))

### Enable Trust Tracking (5 minutes)

#### Step 1: Check Current Trust Score

```python
# Via MCP tool (Claude Desktop)
await mcp.call_tool("get_agent_trust_score", {
    "agent_id": "hera-strategist"
})

# Returns:
{
    "agent_id": "hera-strategist",
    "trust_score": 1.0,
    "status": "TRUSTED",
    "total_verifications": 0,
    "successful_verifications": 0,
    "failed_verifications": 0,
    "last_verification": null
}
```

#### Step 2: Enable Automatic Verification

Edit your agent configuration:

```json
// ~/.tmws/agent_config.json
{
    "agent_id": "hera-strategist",
    "trust_tracking": {
        "enabled": true,
        "auto_verify": true,
        "verification_threshold": 0.75,
        "require_peer_review_below": 0.5
    }
}
```

#### Step 3: Test Verification

Make a verifiable claim:

```python
# Agent makes claim
claim = "Project has 450 total tests"

# System verifies
verification_result = await mcp.call_tool("verify_and_record", {
    "agent_id": "hera-strategist",
    "claim": "Project has 450 total tests",
    "verification_type": "test_count",
    "verification_command": "pytest tests/ --collect-only -q"
})

# Returns:
{
    "claim_verified": true,
    "expected": "450 tests",
    "actual": "447 tests",
    "match": false,
    "trust_score_before": 1.0,
    "trust_score_after": 0.95,
    "status": "TRUSTED"
}
```

---

## Using Trust Tools

### 1. Get Agent Trust Score

**Purpose**: Check current trust level and verification history

```python
await mcp.call_tool("get_agent_trust_score", {
    "agent_id": "artemis-optimizer"
})
```

**Returns**:
```json
{
    "agent_id": "artemis-optimizer",
    "trust_score": 0.87,
    "status": "ACTIVE",
    "total_verifications": 23,
    "successful_verifications": 20,
    "failed_verifications": 3,
    "accuracy_rate": 0.8695652173913043,
    "last_verification": "2025-11-07T10:30:00Z",
    "verification_history": [
        {
            "timestamp": "2025-11-07T10:30:00Z",
            "claim": "Database queries average 15ms",
            "verified": true,
            "score_change": 0.0
        },
        {
            "timestamp": "2025-11-07T09:15:00Z",
            "claim": "5 tests failing with RuntimeError",
            "verified": false,
            "score_change": -0.13
        }
    ]
}
```

### 2. Verify and Record Claim

**Purpose**: Manually verify an agent's claim and update trust score

```python
await mcp.call_tool("verify_and_record", {
    "agent_id": "hera-strategist",
    "claim": "Found 15 unused imports",
    "verification_type": "code_quality",
    "verification_command": "ruff check src/ --select F401"
})
```

**Verification Types**:

| Type | Purpose | Example Command |
|------|---------|-----------------|
| `test_count` | Verify test quantities | `pytest --collect-only -q` |
| `test_results` | Verify test pass/fail | `pytest tests/unit/ -v` |
| `code_quality` | Verify linting issues | `ruff check src/` |
| `performance` | Verify performance metrics | Custom benchmark script |
| `security` | Verify security findings | `bandit -r src/` |
| `coverage` | Verify code coverage | `pytest --cov=src --cov-report=term` |
| `file_existence` | Verify file/directory exists | `ls <path>` |
| `custom` | Custom verification | Any shell command |

### 3. Bulk Verification

**Purpose**: Verify multiple claims at once (useful for comprehensive audits)

```python
await mcp.call_tool("bulk_verify_claims", {
    "agent_id": "artemis-optimizer",
    "claims": [
        {
            "claim": "Test coverage is 85%",
            "verification_type": "coverage",
            "command": "pytest --cov=src --cov-report=term"
        },
        {
            "claim": "15 unused imports detected",
            "verification_type": "code_quality",
            "command": "ruff check src/ --select F401"
        },
        {
            "claim": "Database queries average 12ms",
            "verification_type": "performance",
            "command": "python scripts/benchmark_db.py"
        }
    ]
})
```

### 4. Reset Trust Score

**Purpose**: Reset an agent's trust score (use cautiously)

```python
# Requires admin privileges
await mcp.call_tool("reset_agent_trust", {
    "agent_id": "hera-strategist",
    "new_score": 1.0,
    "reason": "Agent logic updated, performance improved"
})
```

---

## Understanding Trust Scores

### How Scores are Calculated

Trust scores use an **Exponential Moving Average (EMA)** with decay:

```python
# Initial score: 1.0 (fully trusted)
# After verification:
if claim_verified:
    # Gradual increase (slower)
    new_score = current_score * 0.95 + 1.0 * 0.05
else:
    # Rapid decrease (faster)
    new_score = current_score * 0.70 + 0.0 * 0.30
```

**Why EMA?**
- Recent failures have more impact than old ones
- Gradual recovery prevents instant trust restoration
- Weighted toward caution (faster drop, slower rise)

### Trust Score Thresholds

| Threshold | Configuration Key | Default | Description |
|-----------|-------------------|---------|-------------|
| Trusted | `trusted_threshold` | 0.90 | Full autonomy granted |
| Active | `active_threshold` | 0.75 | Normal operations |
| Monitored | `monitored_threshold` | 0.50 | Extra verification |
| Untrusted | `untrusted_threshold` | 0.25 | Peer review required |
| Blocked | Below untrusted | < 0.25 | No autonomous actions |

### Status-Based Actions

| Status | Automatic Actions | Manual Override? |
|--------|-------------------|------------------|
| **TRUSTED** | • Full access to all tools<br>• No additional verification<br>• Can modify critical files | Yes (admin only) |
| **ACTIVE** | • Normal tool access<br>• Occasional verification<br>• Can suggest changes | Yes (admin only) |
| **MONITORED** | • Tool access restricted<br>• Mandatory verification<br>• Suggestions require approval | Yes (team lead) |
| **UNTRUSTED** | • Minimal tool access<br>• Peer review required<br>• Read-only access to code | Yes (admin only) |
| **BLOCKED** | • No autonomous actions<br>• Information gathering only<br>• Cannot modify files | Admin approval required |

---

## Real-World Examples

### Example 1: Development Workflow with Hera

**Scenario**: Hera claims there are duplicate functions in the codebase

**Without Trust Tracking**:
```
User: "Hera, analyze code duplication"
Hera: "Found 50 duplicate functions across 10 files"
User: *Spends 2 hours investigating*
User: *Finds only 5 actual duplicates*
User: "Hera's analysis was 90% wrong..."
```

**With Trust Tracking**:
```
User: "Hera, analyze code duplication"
Hera: "Found 50 duplicate functions across 10 files"
System: *Auto-verifies with PMD CPD*
System: *Detects only 5 duplicates*
System: Trust Score: 1.0 → 0.70 (TRUSTED → MONITORED)
User: *Notified immediately of discrepancy*
User: "I'll verify Hera's claims manually before acting"
```

**Trust Score Impact**:
- Initial: 1.0 (TRUSTED)
- After false claim: 0.70 (MONITORED)
- After 3 accurate claims: 0.78 (ACTIVE)
- After 10 accurate claims: 0.89 (approaching TRUSTED)

### Example 2: Security Audit with Hestia

**Scenario**: Hestia reports critical security vulnerabilities

**Trust-Aware Workflow**:
```python
# Step 1: Hestia makes security claim
hestia_claim = "Found 3 SQL injection vulnerabilities in user_auth.py"

# Step 2: Automatic verification
verification = await verify_and_record(
    agent_id="hestia-auditor",
    claim=hestia_claim,
    verification_type="security",
    command="bandit -r src/security/ -f json"
)

# Step 3: Check trust score
if verification["trust_score_after"] >= 0.90:
    # High confidence - immediate action
    priority = "P0-CRITICAL"
    action = "Fix immediately"
elif verification["trust_score_after"] >= 0.75:
    # Medium confidence - verify manually
    priority = "P1-HIGH"
    action = "Manual review required"
else:
    # Low confidence - extensive verification
    priority = "P2-MEDIUM"
    action = "Comprehensive audit before action"

print(f"Hestia Trust Score: {verification['trust_score_after']}")
print(f"Priority: {priority}")
print(f"Recommended Action: {action}")
```

### Example 3: Performance Optimization with Artemis

**Scenario**: Artemis claims to have optimized database queries

**Verification Workflow**:
```python
# Artemis makes claim
artemis_claim = "Optimized user queries: 50ms → 15ms (70% improvement)"

# Before accepting optimization
baseline = await benchmark_database_queries()
# baseline = {"avg_query_time_ms": 48.3, "p95_ms": 67.2}

# Apply Artemis's optimization
apply_optimization(artemis_suggestion)

# Verify results
actual = await benchmark_database_queries()
# actual = {"avg_query_time_ms": 16.2, "p95_ms": 21.4}

# Record verification
verification = await verify_and_record(
    agent_id="artemis-optimizer",
    claim=artemis_claim,
    verification_type="performance",
    actual_result=actual,
    expected_result={"avg_query_time_ms": 15.0}
)

if verification["claim_verified"]:
    print("✅ Optimization verified! Trust score increased.")
    # Trust Score: 0.87 → 0.89
else:
    print("⚠️ Results don't match claim. Trust score decreased.")
    # Trust Score: 0.87 → 0.77
```

### Example 4: Code Review with Multiple Agents

**Scenario**: Trinitas agents collaborate on code review

```python
# Multiple agents provide input
agents_input = {
    "artemis-optimizer": {
        "claim": "Performance improved by 40%",
        "trust_score": 0.92
    },
    "hestia-auditor": {
        "claim": "No new security risks introduced",
        "trust_score": 0.88
    },
    "hera-strategist": {
        "claim": "Aligns with system architecture",
        "trust_score": 0.65  # MONITORED status
    }
}

# Decision logic based on trust
def should_approve_merge(agents_input):
    # Require all high-trust agents to agree
    high_trust = [a for a in agents_input.values() if a["trust_score"] >= 0.85]

    # Flag low-trust agents for manual review
    low_trust = [a for a in agents_input.values() if a["trust_score"] < 0.75]

    if len(low_trust) > 0:
        return "MANUAL_REVIEW_REQUIRED", low_trust
    elif all(a["trust_score"] >= 0.85 for a in agents_input.values()):
        return "AUTO_APPROVE", []
    else:
        return "CAUTIOUS_APPROVAL", []

decision, flagged = should_approve_merge(agents_input)
# Returns: ("MANUAL_REVIEW_REQUIRED", [hera-strategist])
```

---

## Troubleshooting

### Issue: Trust Score Not Updating

**Symptoms**:
- Verifications run successfully
- Trust score remains at 1.0 or doesn't change

**Diagnosis**:
```python
# Check verification history
result = await get_agent_trust_score("hera-strategist")
print(result["verification_history"])

# Check configuration
print(result["trust_tracking_enabled"])
```

**Solutions**:
1. **Enable trust tracking in agent config**:
   ```json
   {
       "trust_tracking": {
           "enabled": true
       }
   }
   ```

2. **Verify database permissions**:
   ```bash
   # Check if verification table exists
   sqlite3 data/tmws.db "SELECT * FROM agent_verifications LIMIT 1;"
   ```

3. **Check MCP connection**:
   ```python
   # Test MCP tool availability
   tools = await mcp.list_tools()
   assert "get_agent_trust_score" in [t["name"] for t in tools]
   ```

### Issue: Verification Command Fails

**Symptoms**:
- Verification returns error
- Trust score drops unexpectedly

**Diagnosis**:
```python
result = await verify_and_record(
    agent_id="artemis-optimizer",
    claim="Test coverage is 85%",
    verification_type="coverage",
    command="pytest --cov=src --cov-report=term"
)

if "error" in result:
    print(result["error"])
    print(result["stderr"])
```

**Solutions**:
1. **Check command syntax**:
   ```bash
   # Test command manually
   pytest --cov=src --cov-report=term
   ```

2. **Verify tool installation**:
   ```bash
   # Check if pytest is installed
   which pytest
   pytest --version
   ```

3. **Check working directory**:
   ```python
   # Verification runs from project root
   # Ensure paths are relative to project root
   command = "pytest tests/unit/ --cov=src"  # ✅ Correct
   command = "pytest ../tests/unit/ --cov=../src"  # ❌ Wrong
   ```

### Issue: Trust Score Decreases Too Quickly

**Symptoms**:
- One failed verification drops score significantly
- Agent status changes from TRUSTED to UNTRUSTED

**Diagnosis**:
```python
# Check decay rate configuration
config = await get_agent_config("hera-strategist")
print(config["trust_tracking"]["decay_rate"])
```

**Solutions**:
1. **Adjust decay rate** (reduce penalty for failures):
   ```json
   {
       "trust_tracking": {
           "decay_rate": 0.85,  // Default: 0.70 (increase for gentler decay)
           "growth_rate": 0.05   // Default: 0.05
       }
   }
   ```

2. **Increase verification grace period**:
   ```json
   {
       "trust_tracking": {
           "min_verifications_before_penalty": 5  // Wait for 5 verifications
       }
   }
   ```

3. **Manual trust score adjustment** (temporary fix):
   ```python
   await reset_agent_trust(
       agent_id="hera-strategist",
       new_score=0.85,
       reason="Adjusted decay rate was too aggressive"
   )
   ```

### Issue: BLOCKED Status Prevents All Actions

**Symptoms**:
- Agent status is BLOCKED
- Cannot perform any operations
- Trust score below 0.25

**Diagnosis**:
```python
result = await get_agent_trust_score("hera-strategist")
print(f"Status: {result['status']}")
print(f"Trust Score: {result['trust_score']}")
print(f"Failed Verifications: {result['failed_verifications']}")
```

**Solutions**:
1. **Review failed verifications**:
   ```python
   for verification in result["verification_history"]:
       if not verification["verified"]:
           print(f"Failed: {verification['claim']}")
           print(f"Reason: {verification['failure_reason']}")
   ```

2. **Reset trust score with justification**:
   ```python
   await reset_agent_trust(
       agent_id="hera-strategist",
       new_score=0.75,  # Reset to ACTIVE
       reason="Agent logic updated in v2.2.8, previous failures addressed"
   )
   ```

3. **Temporarily override status** (use cautiously):
   ```python
   # Requires admin privileges
   await override_agent_status(
       agent_id="hera-strategist",
       new_status="ACTIVE",
       duration_minutes=60,  # Temporary override
       reason="Critical debugging session"
   )
   ```

---

## FAQ

### Q1: How often should I check trust scores?

**A**: Depends on your workflow:
- **High-stakes projects**: Check before every major decision
- **Normal development**: Weekly review of all agents
- **Automated monitoring**: Set up alerts for scores below 0.75

```python
# Automated monitoring (recommended)
async def monitor_trust_scores():
    agents = ["hera-strategist", "artemis-optimizer", "hestia-auditor"]
    for agent_id in agents:
        score = await get_agent_trust_score(agent_id)
        if score["trust_score"] < 0.75:
            notify_user(f"⚠️ {agent_id} trust score low: {score['trust_score']}")
```

### Q2: Can I disable trust tracking for specific agents?

**A**: Yes, configure per-agent:

```json
{
    "agent_id": "muses-documenter",
    "trust_tracking": {
        "enabled": false,  // Disable for this agent
        "reason": "Documentation agent doesn't make verifiable claims"
    }
}
```

### Q3: What happens if verification commands take too long?

**A**: Timeouts are enforced:
- Default timeout: 60 seconds
- Configurable per verification type
- Timeout = verification failure (trust score decreases)

```json
{
    "verification_timeouts": {
        "test_count": 30,      // Fast operations
        "test_results": 120,   // Slower operations
        "security": 180,       // Comprehensive scans
        "custom": 300          // User-defined operations
    }
}
```

### Q4: How do I audit agent trust history?

**A**: Use the audit API:

```python
# Get comprehensive trust history
audit = await get_agent_trust_audit(
    agent_id="hera-strategist",
    start_date="2025-10-01",
    end_date="2025-11-07"
)

print(f"Total Verifications: {audit['total_verifications']}")
print(f"Accuracy Trend: {audit['accuracy_trend']}")
print(f"Trust Score Trend: {audit['trust_score_trend']}")

# Export to CSV for analysis
await export_trust_audit(
    agent_id="hera-strategist",
    format="csv",
    output_path="./audit_hera_2025.csv"
)
```

### Q5: Can multiple users have different trust scores for the same agent?

**A**: No, trust scores are **system-wide** by default. However, you can enable per-user trust tracking:

```json
{
    "trust_tracking": {
        "per_user_scores": true,  // Enable user-specific trust
        "inherit_system_score": true  // Start with system score
    }
}
```

### Q6: What's the best practice for trust score maintenance?

**A**: Follow the 4-phase approach:

1. **Baseline Phase** (Week 1):
   - Enable trust tracking
   - Monitor without penalties
   - Collect verification data

2. **Calibration Phase** (Week 2-3):
   - Adjust decay/growth rates
   - Set appropriate thresholds
   - Fine-tune verification commands

3. **Active Phase** (Week 4+):
   - Trust scores actively enforced
   - Regular audits (weekly)
   - Address low-trust agents promptly

4. **Maintenance Phase** (Ongoing):
   - Monthly trust score reviews
   - Quarterly threshold adjustments
   - Continuous improvement

---

## Next Steps

- **Developers**: See [Developer Guide: Integration](./DEVELOPER_GUIDE_VERIFICATION.md)
- **Operators**: See [Operations Guide: Monitoring](./OPERATIONS_GUIDE_MONITORING.md)
- **API Reference**: See [API Reference: Trust System](./API_REFERENCE_TRUST_SYSTEM.md)

---

**Need Help?**
- GitHub Issues: [github.com/apto-as/tmws/issues](https://github.com/apto-as/tmws/issues)
- Documentation: [docs/](../)
- MCP Setup: [MCP_SETUP_GUIDE.md](../MCP_SETUP_GUIDE.md)

---

*This documentation is part of TMWS v2.2.7+ Agent Trust & Verification System.*
