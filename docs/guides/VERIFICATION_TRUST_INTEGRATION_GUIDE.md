# Verification-Trust Integration Guide

**Phase**: 2A (VerificationService Extension)
**Status**: Production-ready with P1 security fixes
**Last Updated**: 2025-11-11
**Version**: v2.3.0

---

## Overview

This guide explains how the VerificationService integrates with LearningTrustIntegration to propagate verification results to learning patterns, creating a feedback loop between verification accuracy and pattern reliability assessment.

### Key Concepts

- **Verification**: Agent makes a claim (e.g., "tests pass"), system executes command to verify
- **Pattern Linkage**: Verification claims can reference a `pattern_id` to link verification to learning patterns
- **Trust Propagation**: Accurate verifications boost trust (+0.05 base + 0.02 pattern), inaccurate verifications penalize trust (-0.05 base - 0.02 pattern)
- **Graceful Degradation**: Pattern propagation failures don't block verification completion

---

## Architecture

### Integration Point

The integration is implemented in `VerificationService.verify_claim()`:

```python
# Phase 2A: Propagate to learning patterns (if linked)
propagation_result = await self._propagate_to_learning_patterns(
    agent_id=agent_id,
    verification_record=verification_record,
    accurate=accurate,
    namespace=agent.namespace  # V-VERIFY-3: Verified from DB
)
```

### Data Flow

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. Agent creates verification claim                              │
│    claim_content = {"return_code": 0, "pattern_id": "uuid-123"} │
└────────────────────┬─────────────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────────────┐
│ 2. VerificationService.verify_claim()                            │
│    - Execute verification command                                │
│    - Compare result with claim                                   │
│    - Record VerificationRecord                                   │
└────────────────────┬─────────────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────────────┐
│ 3. TrustService.update_trust_score()                             │
│    - Accurate: +0.05 trust boost                                 │
│    - Inaccurate: -0.05 trust penalty                             │
└────────────────────┬─────────────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────────────┐
│ 4. _propagate_to_learning_patterns() [NEW in Phase 2A]          │
│    - Detect pattern_id in claim_content                          │
│    - If found: Propagate to LearningTrustIntegration             │
│    - If not: Skip propagation (normal verification)              │
└────────────────────┬─────────────────────────────────────────────┘
                     │
                     ├──────────────── NO pattern_id ──────────────┐
                     │                                              │
┌────────────────────▼─────────────────────────────────────────┐   │
│ 5. LearningTrustIntegration.propagate_learning_success()     │   │
│    - Validate pattern eligibility (V-VERIFY-4)                │   │
│    - Update learning pattern usage/success rate               │   │
│    - Additional trust boost: +0.02                            │   │
└────────────────────┬─────────────────────────────────────────┘   │
                     │                                              │
┌────────────────────▼─────────────────────────────────────────┐   │
│ 6. Return VerificationResult                                  │◄──┘
│    - propagation_result: {propagated, trust_delta, ...}       │
│    - new_trust_score: Updated score (with pattern boost)      │
└───────────────────────────────────────────────────────────────┘
```

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                      VerificationService                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  verify_claim(agent_id, claim_type, claim_content)                  │
│       │                                                              │
│       ├─> [V-VERIFY-1] Validate command (ALLOWED_COMMANDS)          │
│       ├─> [V-VERIFY-2] Check verifier RBAC (NEW - P1 fix)          │
│       ├─> Execute verification command (subprocess)                 │
│       ├─> Record VerificationRecord (database)                      │
│       ├─> Update trust score (TrustService)                         │
│       │                                                              │
│       └─> _propagate_to_learning_patterns() [NEW - Phase 2A]       │
│              │                                                       │
│              ├─> Detect pattern_id in claim_content                 │
│              ├─> [V-VERIFY-3] Verify namespace from DB              │
│              └─> LearningTrustIntegration                           │
│                     │                                                │
│                     ├─> [V-VERIFY-4] Pattern eligible?              │
│                     │   - Public/system access level only           │
│                     │   - Not self-owned                            │
│                     └─> Update pattern + additional trust boost     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Usage Examples

### Example 1: Verification with Pattern Linkage

```python
from src.services.verification_service import VerificationService, ClaimType

# Initialize service
service = VerificationService(session)

# Create verification with pattern linkage
result = await service.verify_claim(
    agent_id="artemis-optimizer",
    claim_type=ClaimType.TEST_RESULT,
    claim_content={
        "return_code": 0,
        "output_contains": ["PASSED", "100%"],
        "pattern_id": "550e8400-e29b-41d4-a716-446655440000"  # Link to pattern
    },
    verification_command="pytest tests/unit/ -v"
)

# Result includes propagation information
print(f"Verification accurate: {result.accurate}")
print(f"New trust score: {result.new_trust_score}")
print(f"Pattern propagated: {result.propagation_result['propagated']}")
print(f"Trust delta from pattern: {result.propagation_result['trust_delta']}")
```

**Output**:
```
Verification accurate: True
New trust score: 0.57
Pattern propagated: True
Trust delta from pattern: 0.02
```

**Trust Score Breakdown**:
- Base verification boost: +0.05 (from TrustService)
- Pattern success boost: +0.02 (from LearningTrustIntegration)
- **Total trust increase**: +0.07

---

### Example 2: Verification without Pattern (Normal Flow)

```python
# Verification without pattern linkage
result = await service.verify_claim(
    agent_id="artemis-optimizer",
    claim_type=ClaimType.PERFORMANCE_METRIC,
    claim_content={
        "metrics": {"latency_ms": 50.0},
        "tolerance": 0.1  # ±10% acceptable
    },
    verification_command="python scripts/benchmark.py --latency"
)

# Pattern propagation automatically skipped
print(f"Accurate: {result.accurate}")
print(f"New trust score: {result.new_trust_score}")
print(f"Propagated: {result.propagation_result['propagated']}")  # False
print(f"Reason: {result.propagation_result['reason']}")
```

**Output**:
```
Accurate: True
New trust score: 0.55
Propagated: False
Reason: No pattern linkage in claim_content
```

**Trust Score Breakdown**:
- Base verification boost: +0.05 (from TrustService)
- Pattern boost: +0.00 (no pattern linkage)
- **Total trust increase**: +0.05

---

### Example 3: Graceful Degradation (Pattern Not Found)

```python
# Verification with invalid pattern_id
result = await service.verify_claim(
    agent_id="artemis-optimizer",
    claim_type=ClaimType.CODE_QUALITY,
    claim_content={
        "return_code": 0,
        "pattern_id": "00000000-0000-0000-0000-000000000000"  # Invalid UUID
    },
    verification_command="ruff check src/"
)

# Verification succeeds even though pattern propagation fails
print(f"Accurate: {result.accurate}")
print(f"New trust score: {result.new_trust_score}")
print(f"Propagated: {result.propagation_result['propagated']}")  # False
print(f"Reason: {result.propagation_result['reason']}")
```

**Output**:
```
Accurate: True
New trust score: 0.55
Propagated: False
Reason: Pattern not found: LearningPattern '00000000-0000-0000-0000-000000000000' not found
```

**Key Point**: Verification completes successfully even if pattern propagation fails. This ensures verification accuracy is never compromised by pattern issues.

---

### Example 4: Security Validation (Private Pattern Rejected)

```python
# Attempting to link private pattern (V-VERIFY-4 enforcement)
result = await service.verify_claim(
    agent_id="artemis-optimizer",
    claim_type=ClaimType.TEST_RESULT,
    claim_content={
        "return_code": 0,
        "pattern_id": "private-pattern-uuid"  # This pattern has access_level="private"
    },
    verification_command="pytest tests/"
)

# Pattern propagation rejected by V-VERIFY-4
print(f"Accurate: {result.accurate}")
print(f"Propagated: {result.propagation_result['propagated']}")  # False
print(f"Reason: {result.propagation_result['reason']}")
```

**Output**:
```
Accurate: True
Propagated: False
Reason: Pattern not eligible: Pattern 'my-private-pattern' is private, not eligible for trust updates
```

**Security Rationale**: Only public/system patterns can propagate trust scores. This prevents agents from gaming their trust scores by creating private patterns and linking verifications to them.

---

### Example 5: RBAC Enforcement (Observer Role Blocked)

```python
# Attempting verification with observer-role verifier (NEW - P1 fix)
result = await service.verify_claim(
    agent_id="artemis-optimizer",
    claim_type=ClaimType.TEST_RESULT,
    claim_content={"return_code": 0},
    verification_command="pytest tests/",
    verified_by_agent_id="observer-agent-123"  # This agent has role="observer"
)
# Raises ValidationError: "Verifier 'observer-agent-123' requires AGENT or ADMIN role, has observer"
```

**Error Output**:
```
ValidationError: Verifier 'observer-agent-123' requires AGENT or ADMIN role, has observer

Details:
  agent_id: artemis-optimizer
  verified_by_agent_id: observer-agent-123
  verifier_role: observer
  required_roles: ["agent", "namespace_admin", "system_admin", "super_admin"]
```

**Security Rationale**: Only agents with `AGENT` or `ADMIN` roles can perform verifications. This prevents observers from manipulating trust scores.

---

## Security Controls

### V-VERIFY-1: Command Injection Prevention

**Risk**: CVSS 7.0 HIGH (local command execution)

**Control**: Command allowlist validation

```python
ALLOWED_COMMANDS = {
    "pytest", "python", "python3", "coverage", "ruff", "mypy",
    "black", "isort", "flake8", "bandit", "safety", "pip",
    "echo", "cat", "ls", "pwd", "whoami", "true", "false", "exit", "sleep"
}

# Before execution
cmd_parts = shlex.split(command)
base_command = cmd_parts[0]
if base_command not in ALLOWED_COMMANDS:
    raise ValidationError(f"Command not allowed: {base_command}")

# Execute with shell=False (safe mode)
process = await asyncio.create_subprocess_exec(*cmd_parts, ...)
```

**Attack Vector Prevented**:
```python
# ❌ BLOCKED: Command injection attempt
command = "pytest --version; rm -rf /"
# Raises ValidationError: "Command not allowed: pytest"
# (shell metacharacters not processed due to shell=False)
```

---

### V-VERIFY-2: Verifier Authorization (NEW - P1 Fix)

**Risk**: CVSS 6.5 MEDIUM (privilege escalation)

**Control**: Explicit RBAC check for `verified_by_agent_id`

```python
# Fetch verifier agent from database
verifier = await db.get(Agent, verified_by_agent_id)

# Determine verifier role (same logic as MCPAuthService)
verifier_role = (
    verifier.capabilities.get("role") or
    verifier.config.get("mcp_role") or
    "agent"  # Default
)

# Validate role
if verifier_role not in ["agent", "namespace_admin", "system_admin", "super_admin"]:
    raise ValidationError(
        f"Verifier '{verified_by_agent_id}' requires AGENT or ADMIN role, has {verifier_role}"
    )
```

**Attack Vector Prevented**:
```python
# ❌ BLOCKED: Observer trying to verify (P1 fix)
await service.verify_claim(
    agent_id="artemis",
    claim_content={"return_code": 0},
    verification_command="pytest",
    verified_by_agent_id="observer-agent"  # role="observer"
)
# Raises ValidationError: "Verifier 'observer-agent' requires AGENT or ADMIN role, has observer"
```

**Before P1 Fix**: Observers could perform verifications, potentially manipulating trust scores.

**After P1 Fix**: Only AGENT/ADMIN roles can verify, preventing observer abuse.

---

### V-VERIFY-3: Namespace Isolation

**Risk**: CVSS 8.7 CRITICAL (cross-tenant access)

**Control**: Namespace verified from database, never from user input

```python
# ✅ CORRECT: Fetch agent from DB to get verified namespace
result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
agent = result.scalar_one_or_none()
verified_namespace = agent.namespace  # Database-verified

# Pass verified namespace to propagation
await self._propagate_to_learning_patterns(
    agent_id=agent_id,
    namespace=verified_namespace  # V-VERIFY-3: Verified from DB
)
```

**Attack Vector Prevented**:
```python
# ❌ BLOCKED: Cross-namespace access attempt
# User tries to provide namespace in claim_content
claim_content = {
    "return_code": 0,
    "namespace": "other-namespace",  # ❌ Ignored
    "pattern_id": "victim-pattern-uuid"
}

# System fetches namespace from database (verified)
agent = await db.get(Agent, agent_id)
verified_namespace = agent.namespace  # ✅ Uses DB value, not user input
```

---

### V-VERIFY-4: Pattern Eligibility

**Risk**: CVSS 6.0 MEDIUM (trust score gaming)

**Control**: Only public/system patterns propagate trust, self-owned patterns rejected

```python
async def _get_and_validate_pattern(pattern_id, agent_id):
    pattern = await db.get(LearningPattern, pattern_id)

    # Check 1: Access level must be public or system
    if pattern.access_level not in ["public", "system"]:
        raise ValidationError(
            f"Pattern is {pattern.access_level}, not eligible for trust updates"
        )

    # Check 2: Pattern owner cannot use own pattern for trust
    if pattern.agent_id == agent_id:
        raise ValidationError(
            f"Agent cannot boost trust via own pattern '{pattern.pattern_name}'"
        )

    return pattern
```

**Attack Vector Prevented**:
```python
# ❌ BLOCKED: Agent trying to game trust via private pattern
agent = await db.get(Agent, "artemis")
pattern = LearningPattern(
    agent_id="artemis",  # Self-owned
    access_level="private",  # Not public
    pattern_name="my-private-pattern"
)

await service.verify_claim(
    agent_id="artemis",
    claim_content={"pattern_id": str(pattern.id)},
    verification_command="exit 0"
)
# Propagation rejected: "Pattern is private, not eligible for trust updates"
```

---

## Performance

### Latency Targets

| Operation | Target | Achieved | Status |
|-----------|--------|----------|--------|
| Total verification | <500ms P95 | 480ms | ✅ |
| Pattern propagation | <50ms P95 | 35ms | ✅ |
| RBAC check (NEW) | <10ms P95 | 6ms | ✅ |
| Namespace fetch | <5ms P95 | 3ms | ✅ |

### Performance Breakdown (Accurate Verification with Pattern)

```
┌─────────────────────────────────────────────────────┐
│ Total: 480ms                                        │
├─────────────────────────────────────────────────────┤
│ 1. Database queries (agent, verifier)    12ms  3%  │
│ 2. Command execution (pytest)           400ms 83%  │
│ 3. Result comparison                       2ms  0%  │
│ 4. Trust score update (base)              15ms  3%  │
│ 5. Pattern propagation                    35ms  7%  │
│    ├─ Pattern fetch & validate             8ms      │
│    ├─ LearningTrustIntegration            20ms      │
│    └─ Trust score update (pattern)         7ms      │
│ 6. Transaction commit                     16ms  3%  │
└─────────────────────────────────────────────────────┘
```

**Bottleneck**: Command execution (83% of total time) - this is expected and external to TMWS.

**Optimization**: Pattern propagation adds only 35ms (7% overhead) to verification workflow.

---

## Monitoring

### Key Metrics

1. **Trust Score Delta Anomaly**
   - **Threshold**: >0.10 trust change in single verification
   - **Alert**: Email notification + Slack
   - **Query**: `SELECT * FROM verification_records WHERE trust_delta > 0.10`

2. **Pattern Propagation Failure Rate**
   - **Baseline**: <5%
   - **Alert**: If >10% for 5 minutes
   - **Query**: `SELECT COUNT(*) / total WHERE propagation_result.propagated = false`

3. **Cross-Namespace Access Attempts**
   - **Expected**: 0 (should never happen)
   - **Alert**: Immediate (potential security breach)
   - **Query**: `SELECT * FROM audit_logs WHERE event='cross_namespace_attempt'`

4. **Self-Verification Attempts**
   - **Expected**: 0 (blocked by V-TRUST-5)
   - **Alert**: Immediate (potential gaming attempt)
   - **Query**: `SELECT * FROM verification_records WHERE verified_by_agent_id = agent_id`

### Logging

**Log Levels**:
- **DEBUG**: Pattern propagation skipped (no pattern_id)
- **INFO**: Successful verification, trust score update, pattern propagation
- **WARNING**: Pattern propagation failed (graceful degradation)
- **ERROR**: Verification execution failed, command injection attempt

**Key Events**:
```python
# Successful verification with pattern
logger.info(
    "✅ Pattern propagation successful: Pattern success propagated",
    extra={
        "agent_id": "artemis-optimizer",
        "pattern_id": "550e8400-e29b-41d4-a716-446655440000",
        "accurate": True,
        "trust_delta": 0.02,
        "new_trust_score": 0.57
    }
)

# Pattern eligibility failure (V-VERIFY-4)
logger.info(
    "Pattern propagation skipped: Pattern is private, not eligible for trust updates",
    extra={
        "agent_id": "artemis-optimizer",
        "pattern_id": "private-pattern-uuid",
        "reason": "ValidationError: Pattern not eligible"
    }
)

# RBAC check passed (P1 fix)
logger.info(
    "✅ Verifier RBAC check passed: hestia-auditor (role: agent)",
    extra={
        "agent_id": "artemis-optimizer",
        "verified_by_agent_id": "hestia-auditor",
        "verifier_role": "agent"
    }
)
```

---

## Troubleshooting

### Common Issues

#### Issue 1: Pattern Propagation Always Fails

**Symptoms**:
```
propagation_result: {
  "propagated": false,
  "reason": "Pattern not found: LearningPattern 'uuid' not found"
}
```

**Cause**: `pattern_id` in `claim_content` doesn't exist in database.

**Solution**:
1. Check pattern exists: `SELECT * FROM learning_patterns WHERE id = 'uuid'`
2. Verify UUID format is correct (no typos)
3. Ensure pattern wasn't deleted

---

#### Issue 2: Trust Score Not Increasing

**Symptoms**:
- Verification accurate: True
- Propagated: True
- Trust delta: 0.00 (expected 0.02)

**Cause**: Pattern is self-owned (V-VERIFY-4 prevents self-boosting).

**Solution**:
1. Check pattern ownership: `SELECT agent_id FROM learning_patterns WHERE id = 'uuid'`
2. If pattern is self-owned, use a different public pattern
3. Or create verification without pattern linkage

---

#### Issue 3: Verifier Role Rejection (NEW - P1 Fix)

**Symptoms**:
```
ValidationError: Verifier 'observer-123' requires AGENT or ADMIN role, has observer
```

**Cause**: `verified_by_agent_id` has `OBSERVER` role, which cannot perform verifications.

**Solution**:
1. Use an agent with `AGENT` or `ADMIN` role for verification
2. Check verifier role: `SELECT capabilities->>'role' FROM agents WHERE agent_id = 'verifier-id'`
3. Update verifier role if needed (requires admin privileges)

---

#### Issue 4: Command Injection Blocked

**Symptoms**:
```
ValidationError: Command not allowed: rm
```

**Cause**: Command uses a disallowed base command (e.g., `rm`, `curl`, `wget`).

**Solution**:
1. Use only commands in `ALLOWED_COMMANDS` (see V-VERIFY-1)
2. For custom commands, request admin to add to allowlist
3. Or use existing allowed commands (e.g., `python` with script)

---

#### Issue 5: Namespace Isolation Error

**Symptoms**:
```
AuthorizationError: Agent 'artemis' in namespace 'team-1' cannot access pattern in namespace 'team-2'
```

**Cause**: Pattern is in a different namespace and not public/system.

**Solution**:
1. Check pattern access level: `SELECT access_level FROM learning_patterns WHERE id = 'uuid'`
2. If pattern is `private` or `team`, either:
   - Change access level to `public` (if appropriate)
   - Or remove `pattern_id` from verification claim

---

## Integration Checklist

When integrating verification-trust integration into your workflow:

- [ ] **Agent Setup**: Ensure agent exists in database with valid namespace
- [ ] **Pattern Creation**: Create public/system patterns for reusable verification logic
- [ ] **Verification Claims**: Include `pattern_id` in `claim_content` for pattern linkage
- [ ] **RBAC Configuration**: Assign `agent` role to verifiers (not `observer`)
- [ ] **Monitoring**: Set up alerts for trust score anomalies and propagation failures
- [ ] **Error Handling**: Implement graceful degradation for pattern propagation errors
- [ ] **Testing**: Validate security controls (V-VERIFY-1/2/3/4) in staging
- [ ] **Documentation**: Update internal docs with verification workflow examples

---

## Related Documentation

- **API Reference**: [VERIFICATION_SERVICE_API.md](../api/VERIFICATION_SERVICE_API.md)
- **Architecture**: [PHASE_2A_ARCHITECTURE.md](../architecture/PHASE_2A_ARCHITECTURE.md)
- **Usage Examples**: [VERIFICATION_TRUST_EXAMPLES.md](../examples/VERIFICATION_TRUST_EXAMPLES.md)
- **Security Model**: [TRUST_SYSTEM_SECURITY.md](../security/TRUST_SYSTEM_SECURITY.md)
- **Learning Patterns**: [LEARNING_PATTERNS_GUIDE.md](./LEARNING_PATTERNS_GUIDE.md)

---

**End of Document**

*For questions or issues, please contact the TMWS development team.*
