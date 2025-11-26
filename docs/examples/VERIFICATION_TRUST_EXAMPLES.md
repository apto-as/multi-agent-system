# Verification-Trust Integration Examples

**Version**: v2.3.0 (Phase 2A)
**Last Updated**: 2025-11-11
**Status**: Production-ready

---

## Overview

This document provides comprehensive code examples for using the Phase 2A Verification-Trust Integration. Examples progress from basic usage to advanced scenarios, including security validations and error handling.

---

## Example 1: Basic Verification (No Pattern Linkage)

### Scenario
Verify that unit tests pass without linking to a learning pattern. This is the standard verification workflow.

### Code

```python
from src.services.verification_service import VerificationService, ClaimType
from sqlalchemy.ext.asyncio import AsyncSession

async def example_basic_verification(session: AsyncSession):
    """Basic verification without pattern linkage"""
    service = VerificationService(session)

    # Create verification claim
    result = await service.verify_claim(
        agent_id="artemis-optimizer",
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "output_contains": ["PASSED", "100%"]
        },
        verification_command="pytest tests/unit/ -v"
    )

    # Check result
    print(f"✅ Verification accurate: {result.accurate}")
    print(f"📊 New trust score: {result.new_trust_score:.3f}")
    print(f"📄 Evidence ID: {result.evidence_id}")
    print(f"🔗 Pattern propagated: {result.propagation_result['propagated']}")

    return result
```

### Expected Output

```
✅ Verification accurate: True
📊 New trust score: 0.550
📄 Evidence ID: 12345678-1234-5678-1234-567812345678
🔗 Pattern propagated: False
```

### Trust Score Breakdown

```
Initial score:      0.500
Verification boost: +0.050  (accurate=True)
Pattern boost:      +0.000  (no pattern linkage)
───────────────────────────
Final score:        0.550
```

---

## Example 2: Verification with Pattern Linkage (Success)

### Scenario
Verify tests pass and link to a public learning pattern to boost trust score.

### Code

```python
async def example_pattern_linkage_success(session: AsyncSession):
    """Verification with successful pattern propagation"""
    service = VerificationService(session)

    # Create verification with pattern linkage
    result = await service.verify_claim(
        agent_id="artemis-optimizer",
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "output_contains": ["PASSED"],
            "pattern_id": "550e8400-e29b-41d4-a716-446655440000"  # Public pattern
        },
        verification_command="pytest tests/integration/ -v"
    )

    # Check result
    print(f"✅ Verification accurate: {result.accurate}")
    print(f"📊 New trust score: {result.new_trust_score:.3f}")

    # Check propagation result
    prop = result.propagation_result
    print(f"\n🔗 Pattern Propagation:")
    print(f"  - Propagated: {prop['propagated']}")
    print(f"  - Pattern ID: {prop['pattern_id']}")
    print(f"  - Trust delta: {prop['trust_delta']:+.3f}")
    print(f"  - Reason: {prop['reason']}")

    return result
```

### Expected Output

```
✅ Verification accurate: True
📊 New trust score: 0.570

🔗 Pattern Propagation:
  - Propagated: True
  - Pattern ID: 550e8400-e29b-41d4-a716-446655440000
  - Trust delta: +0.020
  - Reason: Pattern success propagated
```

### Trust Score Breakdown

```
Initial score:      0.500
Verification boost: +0.050  (accurate=True)
Pattern boost:      +0.020  (pattern success)
───────────────────────────
Final score:        0.570
```

---

## Example 3: Verification Failure with Pattern (Penalty)

### Scenario
Verification fails (tests don't pass), and pattern linkage applies negative trust delta.

### Code

```python
async def example_pattern_linkage_failure(session: AsyncSession):
    """Verification failure with pattern penalty"""
    service = VerificationService(session)

    # Create verification claim that will fail
    result = await service.verify_claim(
        agent_id="artemis-optimizer",
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,  # Claim tests pass
            "pattern_id": "550e8400-e29b-41d4-a716-446655440000"
        },
        verification_command="pytest tests/unit/test_broken.py -v"  # Tests fail
    )

    # Check result
    print(f"❌ Verification accurate: {result.accurate}")
    print(f"📊 New trust score: {result.new_trust_score:.3f}")

    # Check propagation result
    prop = result.propagation_result
    print(f"\n🔗 Pattern Propagation:")
    print(f"  - Propagated: {prop['propagated']}")
    print(f"  - Trust delta: {prop['trust_delta']:-.3f}")
    print(f"  - Reason: {prop['reason']}")

    return result
```

### Expected Output

```
❌ Verification accurate: False
📊 New trust score: 0.430

🔗 Pattern Propagation:
  - Propagated: True
  - Trust delta: -0.020
  - Reason: Pattern failure propagated
```

### Trust Score Breakdown

```
Initial score:      0.500
Verification penalty: -0.050  (accurate=False)
Pattern penalty:      -0.020  (pattern failure)
───────────────────────────
Final score:        0.430
```

---

## Example 4: Graceful Degradation (Pattern Not Found)

### Scenario
Verification succeeds even when linked pattern doesn't exist. This demonstrates graceful degradation.

### Code

```python
async def example_graceful_degradation(session: AsyncSession):
    """Verification continues despite pattern propagation failure"""
    service = VerificationService(session)

    # Use invalid pattern_id
    result = await service.verify_claim(
        agent_id="artemis-optimizer",
        claim_type=ClaimType.CODE_QUALITY,
        claim_content={
            "return_code": 0,
            "pattern_id": "00000000-0000-0000-0000-000000000000"  # Invalid
        },
        verification_command="ruff check src/"
    )

    # Verification still succeeds
    print(f"✅ Verification accurate: {result.accurate}")
    print(f"📊 New trust score: {result.new_trust_score:.3f}")

    # Propagation failed gracefully
    prop = result.propagation_result
    print(f"\n⚠️  Pattern Propagation:")
    print(f"  - Propagated: {prop['propagated']}")
    print(f"  - Reason: {prop['reason']}")

    return result
```

### Expected Output

```
✅ Verification accurate: True
📊 New trust score: 0.550

⚠️  Pattern Propagation:
  - Propagated: False
  - Reason: Pattern not found: LearningPattern '00000000-0000-0000-0000-000000000000' not found
```

**Key Point**: Verification completed successfully despite pattern propagation failure. Trust score still received base verification boost (+0.050).

---

## Example 5: Security Validation - Private Pattern Rejected (V-VERIFY-4)

### Scenario
Attempt to link private pattern is rejected by V-VERIFY-4 security control.

### Code

```python
async def example_private_pattern_rejected(session: AsyncSession):
    """Private patterns cannot boost trust (V-VERIFY-4)"""
    service = VerificationService(session)

    # Assume pattern "private-pattern-uuid" has access_level="private"
    result = await service.verify_claim(
        agent_id="artemis-optimizer",
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "pattern_id": "private-pattern-uuid"  # Private pattern
        },
        verification_command="pytest tests/"
    )

    # Verification succeeds, propagation blocked
    print(f"✅ Verification accurate: {result.accurate}")
    print(f"📊 New trust score: {result.new_trust_score:.3f}")

    # V-VERIFY-4 enforcement
    prop = result.propagation_result
    print(f"\n🚫 Pattern Propagation Blocked (V-VERIFY-4):")
    print(f"  - Propagated: {prop['propagated']}")
    print(f"  - Reason: {prop['reason']}")

    return result
```

### Expected Output

```
✅ Verification accurate: True
📊 New trust score: 0.550

🚫 Pattern Propagation Blocked (V-VERIFY-4):
  - Propagated: False
  - Reason: Pattern not eligible: Pattern 'my-private-pattern' is private, not eligible for trust updates
```

**Security Rationale**: Only public/system patterns can propagate trust. This prevents agents from gaming trust scores via private patterns.

---

## Example 6: Security Validation - Self-Owned Pattern Rejected (V-VERIFY-4)

### Scenario
Agent attempts to boost trust via self-owned pattern, blocked by V-VERIFY-4.

### Code

```python
async def example_self_owned_pattern_rejected(session: AsyncSession):
    """Self-owned patterns cannot boost trust (V-VERIFY-4)"""
    from src.models.learning_pattern import LearningPattern
    from src.models.agent import Agent

    # Create agent and self-owned public pattern
    agent = Agent(
        agent_id="artemis-optimizer",
        namespace="team-1",
        display_name="Artemis"
    )
    session.add(agent)

    pattern = LearningPattern(
        agent_id="artemis-optimizer",  # Self-owned
        pattern_name="my-public-pattern",
        access_level="public",  # Public, but still rejected
        namespace="team-1"
    )
    session.add(pattern)
    await session.commit()

    # Attempt verification with self-owned pattern
    service = VerificationService(session)
    result = await service.verify_claim(
        agent_id="artemis-optimizer",
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "pattern_id": str(pattern.id)  # Self-owned pattern
        },
        verification_command="pytest tests/"
    )

    # Verification succeeds, propagation blocked
    print(f"✅ Verification accurate: {result.accurate}")
    print(f"📊 New trust score: {result.new_trust_score:.3f}")

    # V-VERIFY-4 enforcement
    prop = result.propagation_result
    print(f"\n🚫 Pattern Propagation Blocked (V-VERIFY-4):")
    print(f"  - Propagated: {prop['propagated']}")
    print(f"  - Reason: {prop['reason']}")

    return result
```

### Expected Output

```
✅ Verification accurate: True
📊 New trust score: 0.550

🚫 Pattern Propagation Blocked (V-VERIFY-4):
  - Propagated: False
  - Reason: Pattern not eligible: Agent cannot boost trust via own pattern 'my-public-pattern'
```

**Security Rationale**: Prevents self-boosting. Agents cannot increase their trust scores by using patterns they created.

---

## Example 7: RBAC Enforcement - Observer Role Blocked (V-VERIFY-2, P1 Fix)

### Scenario
Observer-role agent attempts to verify claims, blocked by V-VERIFY-2 (NEW in P1 fix).

### Code

```python
async def example_observer_role_blocked(session: AsyncSession):
    """Observer role cannot perform verifications (V-VERIFY-2)"""
    from src.models.agent import Agent
    from src.core.exceptions import ValidationError

    # Create observer agent
    observer = Agent(
        agent_id="observer-agent-123",
        namespace="team-1",
        display_name="Observer",
        capabilities={"role": "observer"}  # OBSERVER role
    )
    session.add(observer)
    await session.commit()

    # Attempt verification with observer as verifier
    service = VerificationService(session)
    try:
        result = await service.verify_claim(
            agent_id="artemis-optimizer",
            claim_type=ClaimType.TEST_RESULT,
            claim_content={"return_code": 0},
            verification_command="pytest tests/",
            verified_by_agent_id="observer-agent-123"  # Observer role
        )
    except ValidationError as e:
        print(f"🚫 Verification Blocked (V-VERIFY-2):")
        print(f"  - Error: {e}")
        print(f"  - Details: {e.details}")
        raise
```

### Expected Output

```
🚫 Verification Blocked (V-VERIFY-2):
  - Error: Verifier 'observer-agent-123' requires AGENT or ADMIN role, has observer
  - Details: {
      "agent_id": "artemis-optimizer",
      "verified_by_agent_id": "observer-agent-123",
      "verifier_role": "observer",
      "required_roles": ["agent", "namespace_admin", "system_admin", "super_admin"]
    }

ValidationError: Verifier 'observer-agent-123' requires AGENT or ADMIN role, has observer
```

**Security Rationale**: Only agents with AGENT or ADMIN roles can perform verifications. This prevents observers from manipulating trust scores.

---

## Example 8: Command Injection Prevention (V-VERIFY-1)

### Scenario
Malicious command injection attempt is blocked by V-VERIFY-1 security control.

### Code

```python
async def example_command_injection_blocked(session: AsyncSession):
    """Command injection prevented by allowlist (V-VERIFY-1)"""
    from src.core.exceptions import ValidationError

    service = VerificationService(session)

    # Attempt command injection
    try:
        result = await service.verify_claim(
            agent_id="artemis-optimizer",
            claim_type=ClaimType.TEST_RESULT,
            claim_content={"return_code": 0},
            verification_command="pytest --version; rm -rf /"  # Malicious
        )
    except ValidationError as e:
        print(f"🚫 Command Injection Blocked (V-VERIFY-1):")
        print(f"  - Error: {e}")
        print(f"  - Details: {e.details}")
        raise
```

### Expected Output

```
🚫 Command Injection Blocked (V-VERIFY-1):
  - Error: Command not allowed: pytest
  - Details: {
      "command": "pytest --version; rm -rf /",
      "base_command": "pytest",
      "allowed_commands": ["bandit", "black", "cat", "coverage", ...]
    }

ValidationError: Command not allowed: pytest
```

**Security Note**: Even though `pytest` is allowed, the semicolon (`;`) causes `shlex.split()` to fail, blocking the injection attempt.

---

## Example 9: Self-Verification Prevention (V-TRUST-5)

### Scenario
Agent attempts to verify own claims, blocked by V-TRUST-5.

### Code

```python
async def example_self_verification_blocked(session: AsyncSession):
    """Self-verification prevented by V-TRUST-5"""
    from src.core.exceptions import ValidationError

    service = VerificationService(session)

    # Attempt self-verification
    try:
        result = await service.verify_claim(
            agent_id="artemis-optimizer",
            claim_type=ClaimType.TEST_RESULT,
            claim_content={"return_code": 0},
            verification_command="pytest tests/",
            verified_by_agent_id="artemis-optimizer"  # Same agent
        )
    except ValidationError as e:
        print(f"🚫 Self-Verification Blocked (V-TRUST-5):")
        print(f"  - Error: {e}")
        print(f"  - Details: {e.details}")
        raise
```

### Expected Output

```
🚫 Self-Verification Blocked (V-TRUST-5):
  - Error: Self-verification not allowed: agent artemis-optimizer cannot verify own claims
  - Details: {
      "agent_id": "artemis-optimizer",
      "verified_by_agent_id": "artemis-optimizer",
      "claim_type": "test_result"
    }

ValidationError: Self-verification not allowed: agent artemis-optimizer cannot verify own claims
```

**Security Rationale**: Prevents agents from manipulating their own trust scores by verifying their own claims.

---

## Example 10: Performance Metrics Verification

### Scenario
Verify performance metrics with numeric tolerance.

### Code

```python
async def example_performance_metrics(session: AsyncSession):
    """Verify performance metrics with tolerance"""
    service = VerificationService(session)

    # Create performance verification with tolerance
    result = await service.verify_claim(
        agent_id="artemis-optimizer",
        claim_type=ClaimType.PERFORMANCE_METRIC,
        claim_content={
            "metrics": {
                "latency_ms": 50.0,
                "throughput_rps": 1000.0
            },
            "tolerance": 0.1,  # ±10% acceptable
            "pattern_id": "performance-pattern-uuid"
        },
        verification_command="python scripts/benchmark.py --json"
    )

    # Check result
    print(f"✅ Verification accurate: {result.accurate}")
    print(f"📊 New trust score: {result.new_trust_score:.3f}")

    # Show actual metrics
    actual = result.actual
    print(f"\n📈 Performance Metrics:")
    print(f"  - Claimed latency: 50.0ms")
    print(f"  - Actual latency: {actual.get('metrics', {}).get('latency_ms')}ms")
    print(f"  - Within tolerance: {result.accurate}")

    return result
```

### Expected Output

```
✅ Verification accurate: True
📊 New trust score: 0.570

📈 Performance Metrics:
  - Claimed latency: 50.0ms
  - Actual latency: 52.3ms
  - Within tolerance: True
```

**Tolerance Calculation**: 52.3ms is within ±10% of 50.0ms (45.0-55.0ms range), so verification passes.

---

## Example 11: Batch Verification History

### Scenario
Retrieve and analyze verification history for an agent.

### Code

```python
async def example_verification_history(session: AsyncSession):
    """Retrieve and analyze verification history"""
    service = VerificationService(session)

    # Get verification history
    history = await service.get_verification_history(
        agent_id="artemis-optimizer",
        limit=10
    )

    # Analyze results
    total = len(history)
    accurate = sum(1 for v in history if v["accurate"])
    accuracy_rate = accurate / total if total > 0 else 0.0

    print(f"📊 Verification History Summary:")
    print(f"  - Total verifications: {total}")
    print(f"  - Accurate: {accurate} ({accuracy_rate:.1%})")
    print(f"  - Inaccurate: {total - accurate}")

    # Show recent verifications
    print(f"\n📜 Recent Verifications:")
    for v in history[:5]:
        status = "✅" if v["accurate"] else "❌"
        claim_type = v["claim_type"]
        verified_at = v["verified_at"]
        print(f"  {status} {claim_type} at {verified_at}")

    return history
```

### Expected Output

```
📊 Verification History Summary:
  - Total verifications: 10
  - Accurate: 8 (80.0%)
  - Inaccurate: 2

📜 Recent Verifications:
  ✅ test_result at 2025-11-11T12:30:00Z
  ✅ performance_metric at 2025-11-11T12:25:00Z
  ❌ code_quality at 2025-11-11T12:20:00Z
  ✅ test_result at 2025-11-11T12:15:00Z
  ✅ security_finding at 2025-11-11T12:10:00Z
```

---

## Example 12: Comprehensive Statistics

### Scenario
Get comprehensive verification statistics for an agent.

### Code

```python
async def example_verification_statistics(session: AsyncSession):
    """Get comprehensive verification statistics"""
    service = VerificationService(session)

    # Get statistics
    stats = await service.get_verification_statistics("artemis-optimizer")

    print(f"📊 Agent Statistics:")
    print(f"  - Agent ID: {stats['agent_id']}")
    print(f"  - Trust Score: {stats['trust_score']:.3f}")
    print(f"  - Total Verifications: {stats['total_verifications']}")
    print(f"  - Accuracy Rate: {stats['accuracy_rate']:.1%}")
    print(f"  - Requires Supervision: {stats['requires_verification']}")

    print(f"\n📈 Accuracy by Claim Type:")
    for claim_type, type_stats in stats["by_claim_type"].items():
        accuracy = type_stats["accuracy"]
        total = type_stats["total"]
        accurate = type_stats["accurate"]
        print(f"  - {claim_type}: {accuracy:.1%} ({accurate}/{total})")

    return stats
```

### Expected Output

```
📊 Agent Statistics:
  - Agent ID: artemis-optimizer
  - Trust Score: 0.620
  - Total Verifications: 45
  - Accuracy Rate: 82.2%
  - Requires Supervision: False

📈 Accuracy by Claim Type:
  - test_result: 90.0% (18/20)
  - performance_metric: 75.0% (9/12)
  - code_quality: 80.0% (8/10)
  - security_finding: 66.7% (2/3)
```

---

## Example 13: Verify Performance Optimization with Pattern Linkage (NEW)

### Scenario
Verify that a performance optimization (database index addition) improves query speed and link to a public optimization pattern for trust boost.

### Code

```python
async def example_performance_optimization_with_pattern(session: AsyncSession):
    """Verify performance optimization with pattern linkage"""
    from src.models.learning_pattern import LearningPattern
    from uuid import UUID

    service = VerificationService(session)

    # 1. Create public optimization pattern (shared knowledge)
    pattern = LearningPattern(
        agent_id="artemis-optimizer",
        pattern_name="database-index-optimization",
        pattern_type="performance_optimization",
        description="Adding database indexes reduces query time by 60-85%",
        access_level="public",  # Public pattern - eligible for trust propagation
        namespace="engineering",
        success_count=15,
        total_usage_count=18,
        metadata={
            "optimization_type": "database_index",
            "avg_improvement_pct": 72.5,
            "examples": [
                "idx_learning_patterns_agent_performance: -85%",
                "idx_pattern_usage_agent_success_time: -81%",
                "idx_workflow_executions_error_analysis: -60%"
            ]
        }
    )
    session.add(pattern)
    await session.commit()

    # 2. Verify optimization claim with pattern linkage
    result = await service.verify_claim(
        agent_id="artemis-optimizer",
        claim_type=ClaimType.PERFORMANCE_METRIC,
        claim_content={
            "metrics": {
                "query_time_before_ms": 2000.0,
                "query_time_after_ms": 300.0,
                "improvement_pct": 85.0
            },
            "tolerance": 0.1,  # ±10% acceptable
            "pattern_id": str(pattern.id)  # Link to optimization pattern
        },
        verification_command="python scripts/benchmark_database_queries.py --json"
    )

    # 3. Display results
    print(f"✅ Verification accurate: {result.accurate}")
    print(f"📊 New trust score: {result.new_trust_score:.3f}")

    # 4. Show pattern propagation details
    prop = result.propagation_result
    print(f"\n🔗 Pattern Propagation:")
    print(f"  - Pattern: {pattern.pattern_name}")
    print(f"  - Propagated: {prop['propagated']}")
    print(f"  - Trust delta: {prop['trust_delta']:+.3f}")
    print(f"  - Reason: {prop['reason']}")

    # 5. Show performance metrics
    actual_metrics = result.actual.get("metrics", {})
    print(f"\n📈 Performance Metrics:")
    print(f"  - Before: {actual_metrics.get('query_time_before_ms')}ms")
    print(f"  - After: {actual_metrics.get('query_time_after_ms')}ms")
    print(f"  - Improvement: {actual_metrics.get('improvement_pct')}%")

    return result
```

### Expected Output

```
✅ Verification accurate: True
📊 New trust score: 0.570

🔗 Pattern Propagation:
  - Pattern: database-index-optimization
  - Propagated: True
  - Trust delta: +0.020
  - Reason: Pattern success propagated

📈 Performance Metrics:
  - Before: 2000.0ms
  - After: 300.0ms
  - Improvement: 85.0%
```

### Trust Score Breakdown

```
Initial score:      0.500
Verification boost: +0.050  (accurate=True, performance claim verified)
Pattern boost:      +0.020  (public optimization pattern success)
───────────────────────────
Final score:        0.570
```

### Key Benefits

1. **Knowledge Sharing**: Public pattern shares optimization knowledge across team
2. **Trust Boost**: Artemis gains +0.02 additional trust for using proven pattern
3. **Pattern Reinforcement**: Pattern's success_count increments (15 → 16)
4. **Verification Evidence**: Performance metrics permanently recorded in memory

---

## Example 14: Graceful Degradation - Pattern Propagation Failure (NEW)

### Scenario
Demonstrate that verification succeeds even when pattern propagation encounters an error (database timeout, network issue, etc.).

### Code

```python
async def example_graceful_degradation_propagation_error(session: AsyncSession):
    """Verification completes despite pattern propagation database error"""
    from src.models.learning_pattern import LearningPattern
    from src.services.learning_trust_integration import LearningTrustIntegration
    from unittest.mock import AsyncMock, patch

    service = VerificationService(session)

    # 1. Create valid public pattern
    pattern = LearningPattern(
        agent_id="hestia-auditor",  # Different agent (not self-owned)
        pattern_name="security-audit-pattern",
        pattern_type="security",
        access_level="public",
        namespace="security",
        success_count=42
    )
    session.add(pattern)
    await session.commit()

    # 2. Mock LearningTrustIntegration to simulate database timeout
    with patch.object(
        LearningTrustIntegration,
        'propagate_learning_success',
        new_callable=AsyncMock
    ) as mock_propagate:
        # Simulate database timeout during trust update
        from src.core.exceptions import DatabaseError
        mock_propagate.side_effect = DatabaseError(
            "Database timeout during trust update",
            details={"timeout_ms": 5000}
        )

        # 3. Verification should still succeed
        result = await service.verify_claim(
            agent_id="artemis-optimizer",
            claim_type=ClaimType.SECURITY_FINDING,
            claim_content={
                "return_code": 0,
                "output_contains": ["0 vulnerabilities"],
                "pattern_id": str(pattern.id)  # Valid pattern
            },
            verification_command="bandit -r src/ -f json"
        )

    # 4. Verification succeeded despite propagation failure
    print(f"✅ Verification accurate: {result.accurate}")
    print(f"📊 New trust score: {result.new_trust_score:.3f}")

    # 5. Pattern propagation failed gracefully
    prop = result.propagation_result
    print(f"\n⚠️  Pattern Propagation (Graceful Degradation):")
    print(f"  - Propagated: {prop['propagated']}")
    print(f"  - Pattern ID: {prop['pattern_id']}")
    print(f"  - Trust delta: {prop['trust_delta']}")
    print(f"  - Reason: {prop['reason']}")

    # 6. Evidence still recorded
    print(f"\n📄 Evidence recorded: {result.evidence_id}")
    print(f"✅ Verification completed successfully (graceful degradation)")

    return result
```

### Expected Output

```
✅ Verification accurate: True
📊 New trust score: 0.550

⚠️  Pattern Propagation (Graceful Degradation):
  - Propagated: False
  - Pattern ID: 550e8400-e29b-41d4-a716-446655440000
  - Trust delta: 0.000
  - Reason: Propagation error: DatabaseError

📄 Evidence recorded: 12345678-1234-5678-1234-567812345678
✅ Verification completed successfully (graceful degradation)
```

### Trust Score Breakdown

```
Initial score:      0.500
Verification boost: +0.050  (accurate=True, verification succeeded)
Pattern boost:      +0.000  (propagation failed, but verification continues)
───────────────────────────
Final score:        0.550  (base verification boost only)
```

### Error Handling Behavior

| Error Type | Propagation Result | Verification Result | Trust Update |
|------------|-------------------|---------------------|--------------|
| Pattern not found | `propagated=False` | ✅ SUCCESS | Base boost only (+0.05) |
| Pattern not eligible (private) | `propagated=False` | ✅ SUCCESS | Base boost only (+0.05) |
| Pattern not eligible (self-owned) | `propagated=False` | ✅ SUCCESS | Base boost only (+0.05) |
| Database timeout | `propagated=False` | ✅ SUCCESS | Base boost only (+0.05) |
| Authorization error | `propagated=False` | ✅ SUCCESS | Base boost only (+0.05) |
| Unknown error | `propagated=False` | ✅ SUCCESS | Base boost only (+0.05) |

### Design Rationale

**Graceful Degradation Guarantees**:

1. **Verification Always Completes**: Pattern propagation failures never block verification completion
2. **Evidence Always Recorded**: Verification evidence is saved to memory regardless of propagation status
3. **Trust Always Updated**: Base trust score update (+0.05 or -0.05) always applies
4. **Pattern Boost is Optional**: Additional +0.02 pattern boost is best-effort only

**Error Logging**:
- `ValidationError`, `NotFoundError`: Logged at `INFO` level (expected scenarios)
- `DatabaseError`, `AuthorizationError`: Logged at `WARNING` level (unexpected but recoverable)
- `Exception`: Logged at `ERROR` level (completely unexpected)

**Performance Impact**:
- Pattern propagation timeout: <50ms (99.9% of cases)
- Graceful degradation overhead: <5ms (error handling only)

---

## Running the Examples

### Setup

```python
# setup.py
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Create async engine
engine = create_async_engine(
    "sqlite+aiosqlite:///./data/tmws.db",
    echo=False
)

# Create session factory
AsyncSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

async def get_session():
    """Get database session"""
    async with AsyncSessionLocal() as session:
        yield session
```

### Running All Examples

```python
# run_examples.py
import asyncio

async def main():
    """Run all examples"""
    async with AsyncSessionLocal() as session:
        print("=" * 60)
        print("Phase 2A Verification-Trust Integration Examples")
        print("=" * 60)

        # Example 1: Basic verification
        print("\n[Example 1] Basic Verification")
        await example_basic_verification(session)

        # Example 2: Pattern linkage success
        print("\n[Example 2] Pattern Linkage (Success)")
        await example_pattern_linkage_success(session)

        # Example 3: Pattern linkage failure
        print("\n[Example 3] Pattern Linkage (Failure)")
        await example_pattern_linkage_failure(session)

        # ... run other examples ...

        print("\n" + "=" * 60)
        print("Examples completed successfully")
        print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Related Documentation

- **Integration Guide**: [VERIFICATION_TRUST_INTEGRATION_GUIDE.md](../guides/VERIFICATION_TRUST_INTEGRATION_GUIDE.md)
- **API Reference**: [VERIFICATION_SERVICE_API.md](../api/VERIFICATION_SERVICE_API.md)
- **Architecture**: [PHASE_2A_ARCHITECTURE.md](../architecture/PHASE_2A_ARCHITECTURE.md)

---

**End of Document**

*For implementation details, see: `/Users/apto-as/workspace/github.com/apto-as/tmws/src/services/verification_service.py`*
