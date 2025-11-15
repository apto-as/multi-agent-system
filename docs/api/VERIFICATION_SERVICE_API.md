# VerificationService API Reference

**Version**: v2.3.0 (Phase 2A)
**Last Updated**: 2025-11-11
**Status**: Production-ready

---

## Overview

The `VerificationService` provides claim verification capabilities with automatic trust score updates and optional learning pattern integration. This API enables agents to verify claims through command execution, record evidence, and propagate results to learning patterns.

---

## Class: VerificationService

### Constructor

```python
class VerificationService:
    def __init__(
        self,
        session: AsyncSession,
        memory_service: HybridMemoryService | None = None,
        trust_service: TrustService | None = None,
        learning_trust_integration: LearningTrustIntegration | None = None
    )
```

**Parameters**:
- `session` (AsyncSession): Database session
- `memory_service` (HybridMemoryService, optional): Memory service for evidence recording
- `trust_service` (TrustService, optional): Trust service for score updates
- `learning_trust_integration` (LearningTrustIntegration, optional): Learning-Trust integration service (Phase 2A)

**Example**:
```python
from sqlalchemy.ext.asyncio import AsyncSession
from src.services.verification_service import VerificationService

async def create_service(session: AsyncSession):
    service = VerificationService(session)
    return service
```

---

## Public Methods

### verify_claim()

Verify a claim by executing verification command and comparing result with claimed values.

**Signature**:
```python
async def verify_claim(
    self,
    agent_id: str,
    claim_type: ClaimType | str,
    claim_content: dict[str, Any],
    verification_command: str,
    verified_by_agent_id: str | None = None
) -> VerificationResult
```

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_id` | str | Yes | Agent making the claim |
| `claim_type` | ClaimType \| str | Yes | Type of claim (e.g., "test_result", "performance_metric") |
| `claim_content` | dict[str, Any] | Yes | Claim data (see structure below) |
| `verification_command` | str | Yes | Shell command to execute (must be in ALLOWED_COMMANDS) |
| `verified_by_agent_id` | str \| None | No | Agent performing verification (must have AGENT/ADMIN role) |

**claim_content Structure**:

```python
# Basic claim (return code only)
claim_content = {
    "return_code": 0
}

# Output pattern matching
claim_content = {
    "return_code": 0,
    "output_contains": ["PASSED", "100%"]  # Can be str or list[str]
}

# Numeric metrics with tolerance
claim_content = {
    "metrics": {"coverage": 90.0, "latency_ms": 50.0},
    "tolerance": 0.05  # ±5% acceptable (default: 0.05)
}

# With pattern linkage (Phase 2A)
claim_content = {
    "return_code": 0,
    "output_contains": ["PASSED"],
    "pattern_id": "550e8400-e29b-41d4-a716-446655440000"  # UUID of learning pattern
}

# Exact match
claim_content = {
    "exact_match": {"status": "success", "count": 42}
}
```

**Returns**:
```python
VerificationResult(
    claim: dict[str, Any],              # Original claim
    actual: dict[str, Any],             # Actual result from command execution
    accurate: bool,                     # Whether claim matched actual result
    evidence_id: UUID,                  # Memory ID of evidence record
    verification_id: UUID,              # Verification record ID
    new_trust_score: float,             # Updated trust score (0.0-1.0)
    propagation_result: dict[str, Any]  # NEW in Phase 2A (see below)
)
```

**propagation_result Structure** (NEW in Phase 2A):
```python
{
    "propagated": bool,                 # True if pattern linkage found and propagated
    "pattern_id": str | None,           # Linked pattern UUID (if any)
    "trust_delta": float,               # Trust score change from pattern (±0.02)
    "new_trust_score": float | None,    # Updated trust score (if propagated)
    "reason": str                       # Explanation (e.g., "Pattern success propagated")
}
```

**Raises**:
- `AgentNotFoundError`: If agent doesn't exist
- `ValidationError`: Invalid command, self-verification, pattern not eligible, or verifier role insufficient
- `AuthorizationError`: Verifier lacks required RBAC role (NEW - P1 fix)
- `VerificationError`: If command execution fails or times out
- `DatabaseError`: If database operations fail

**Performance**: <500ms P95 (target), <550ms P95 (with pattern propagation)

**Security Controls**:
- **V-VERIFY-1**: Command validated against ALLOWED_COMMANDS (prevents command injection)
- **V-VERIFY-2**: Verifier RBAC check (requires AGENT/ADMIN role) (NEW - P1 fix)
- **V-VERIFY-3**: Namespace verified from database (prevents cross-tenant access)
- **V-VERIFY-4**: Pattern eligibility validated (public/system only, not self-owned)
- **V-TRUST-5**: Self-verification prevented (verified_by_agent_id != agent_id)

**Example 1**: Basic verification
```python
result = await service.verify_claim(
    agent_id="artemis-optimizer",
    claim_type="test_result",
    claim_content={"return_code": 0, "output_contains": "PASSED"},
    verification_command="pytest tests/unit/ -v"
)

print(f"Accurate: {result.accurate}")           # True
print(f"New trust score: {result.new_trust_score}")  # 0.55 (0.50 + 0.05)
print(f"Evidence ID: {result.evidence_id}")     # UUID
```

**Example 2**: Verification with pattern linkage (Phase 2A)
```python
result = await service.verify_claim(
    agent_id="artemis-optimizer",
    claim_type="test_result",
    claim_content={
        "return_code": 0,
        "pattern_id": "550e8400-e29b-41d4-a716-446655440000"
    },
    verification_command="pytest tests/integration/ -v"
)

print(f"Accurate: {result.accurate}")           # True
print(f"New trust score: {result.new_trust_score}")  # 0.57 (0.50 + 0.05 + 0.02)
print(f"Pattern propagated: {result.propagation_result['propagated']}")  # True
print(f"Trust delta: {result.propagation_result['trust_delta']}")  # 0.02
```

**Example 3**: Verification with verifier (P1 fix)
```python
result = await service.verify_claim(
    agent_id="artemis-optimizer",
    claim_type="security_finding",
    claim_content={"return_code": 0},
    verification_command="bandit -r src/",
    verified_by_agent_id="hestia-auditor"  # Must have AGENT/ADMIN role
)

# V-VERIFY-2: RBAC check performed
# If hestia-auditor has role="observer", raises ValidationError
```

---

### get_verification_history()

Get verification history for an agent, optionally filtered by claim type.

**Signature**:
```python
async def get_verification_history(
    self,
    agent_id: str,
    claim_type: ClaimType | str | None = None,
    limit: int = 100
) -> list[dict[str, Any]]
```

**Parameters**:
- `agent_id` (str): Agent identifier
- `claim_type` (ClaimType | str, optional): Filter by claim type
- `limit` (int): Maximum records to return (default: 100)

**Returns**:
```python
[
    {
        "id": str,                      # Verification record UUID
        "claim_type": str,              # Type of claim
        "claim_content": dict,          # Original claim
        "verification_result": dict,    # Actual result
        "accurate": bool,               # Whether claim was accurate
        "evidence_memory_id": str | None,  # Memory UUID of evidence
        "verified_at": str,             # ISO timestamp
        "verified_by": str | None       # Verifier agent ID
    },
    ...
]
```

**Raises**:
- `AgentNotFoundError`: If agent doesn't exist
- `DatabaseError`: If database query fails

**Performance**: <50ms P95 for 100 records

**Example**:
```python
# Get all verification history
history = await service.get_verification_history("artemis-optimizer")

# Filter by claim type
test_history = await service.get_verification_history(
    "artemis-optimizer",
    claim_type="test_result",
    limit=50
)

# Process results
for record in test_history:
    print(f"Verified at: {record['verified_at']}")
    print(f"Accurate: {record['accurate']}")
```

---

### get_verification_statistics()

Get comprehensive verification statistics for an agent, including accuracy rates by claim type.

**Signature**:
```python
async def get_verification_statistics(
    self,
    agent_id: str
) -> dict[str, Any]
```

**Parameters**:
- `agent_id` (str): Agent identifier

**Returns**:
```python
{
    "agent_id": str,
    "trust_score": float,                   # Current trust score (0.0-1.0)
    "total_verifications": int,             # Total verification count
    "accurate_verifications": int,          # Accurate verification count
    "accuracy_rate": float,                 # Accuracy percentage (0.0-1.0)
    "requires_verification": bool,          # Whether agent requires supervision
    "by_claim_type": {
        "test_result": {
            "total": int,                   # Total test result verifications
            "accurate": int,                # Accurate test result verifications
            "accuracy": float               # Accuracy rate for test results
        },
        "performance_metric": { ... },
        ...
    },
    "recent_verifications": [
        {
            "claim_type": str,
            "accurate": bool,
            "verified_at": str              # ISO timestamp
        },
        ...
    ]  # Last 10 verifications
}
```

**Raises**:
- `AgentNotFoundError`: If agent doesn't exist
- `DatabaseError`: If database query fails

**Performance**: <100ms P95 (includes statistics calculation)

**Example**:
```python
stats = await service.get_verification_statistics("artemis-optimizer")

print(f"Trust score: {stats['trust_score']:.2%}")
print(f"Overall accuracy: {stats['accuracy_rate']:.2%}")
print(f"Total verifications: {stats['total_verifications']}")

# Analyze by claim type
for claim_type, type_stats in stats["by_claim_type"].items():
    print(f"{claim_type}: {type_stats['accuracy']:.2%} accuracy "
          f"({type_stats['accurate']}/{type_stats['total']})")

# Recent verifications
print(f"\nRecent verifications:")
for v in stats["recent_verifications"][:5]:
    status = "✅" if v["accurate"] else "❌"
    print(f"  {status} {v['claim_type']} at {v['verified_at']}")
```

---

## Private Methods (Internal)

### _propagate_to_learning_patterns()

**NEW in Phase 2A**: Propagate verification result to learning patterns.

**Signature**:
```python
async def _propagate_to_learning_patterns(
    self,
    agent_id: str,
    verification_record: VerificationRecord,
    accurate: bool,
    namespace: str
) -> dict[str, Any]
```

**Parameters**:
- `agent_id` (str): Agent identifier
- `verification_record` (VerificationRecord): Completed verification record (with id)
- `accurate` (bool): Whether verification was accurate
- `namespace` (str): Agent namespace (verified from DB, V-VERIFY-3)

**Returns**:
```python
{
    "propagated": bool,                     # True if pattern linkage found
    "pattern_id": str | None,               # Linked pattern UUID
    "trust_delta": float,                   # Trust score change from pattern (±0.02)
    "new_trust_score": float | None,        # Updated trust score (if propagated)
    "reason": str                           # Explanation
}
```

**Behavior**:
1. Detects `pattern_id` in `verification_record.claim_content`
2. If found: Validates pattern eligibility (V-VERIFY-4)
3. Propagates to `LearningTrustIntegration.propagate_learning_success/failure()`
4. Updates trust score with additional ±0.02 delta
5. Returns propagation result

**Graceful Degradation**:
- Pattern not found: Returns `propagated=False`, verification continues
- Pattern not eligible: Returns `propagated=False`, verification continues
- Trust update fails: Returns `propagated=False`, verification continues

**Performance**: <50ms P95

**Security**:
- **V-VERIFY-3**: Namespace verified from database (not user input)
- **V-VERIFY-4**: Pattern eligibility validated (public/system, not self-owned)
- **V-TRUST-1**: pattern_id serves as verification_id for automated updates

**Example** (internal usage):
```python
# Called from verify_claim() after trust score update
propagation_result = await self._propagate_to_learning_patterns(
    agent_id="artemis-optimizer",
    verification_record=verification_record,  # Has id and claim_content
    accurate=True,
    namespace="team-1"  # Verified from DB
)

if propagation_result["propagated"]:
    new_trust_score = propagation_result["new_trust_score"]  # Updated with pattern boost
    logger.info(f"Pattern propagation successful: +{propagation_result['trust_delta']}")
else:
    logger.debug(f"Pattern propagation skipped: {propagation_result['reason']}")
```

---

### _execute_verification()

Execute verification command and capture result (with command injection prevention).

**Signature**:
```python
async def _execute_verification(
    self,
    command: str,
    timeout_seconds: float = 30.0
) -> dict[str, Any]
```

**Parameters**:
- `command` (str): Shell command to execute
- `timeout_seconds` (float): Maximum execution time (default: 30.0)

**Returns**:
```python
{
    "stdout": str,              # Standard output
    "stderr": str,              # Standard error
    "return_code": int,         # Exit code
    "command": str,             # Original command
    "timestamp": str            # ISO timestamp
}
```

**Raises**:
- `ValidationError`: If command not in ALLOWED_COMMANDS
- `VerificationError`: If command fails or times out

**Security**: V-VERIFY-1 (command allowlist validation)

**Performance**: Variable (depends on command execution time)

---

### _compare_results()

Compare claimed result with actual result from verification.

**Signature**:
```python
def _compare_results(
    self,
    claim: dict[str, Any],
    actual: dict[str, Any]
) -> bool
```

**Parameters**:
- `claim` (dict): Claimed result
- `actual` (dict): Actual result from verification

**Returns**: `True` if claim is accurate, `False` otherwise

**Comparison Strategy**:
1. **Return Code**: If `claim["return_code"]` specified, must match `actual["return_code"]`
2. **Output Patterns**: If `claim["output_contains"]` specified, all patterns must be in stdout/stderr
3. **Numeric Metrics**: If `claim["metrics"]` specified, values must be within tolerance (default ±5%)
4. **Exact Match**: If `claim["exact_match"]` specified, must match actual result exactly
5. **Default**: `actual["return_code"] == 0` means success

**Performance**: <2ms (in-memory comparison)

---

### _create_evidence_memory()

Create memory record with verification evidence.

**Signature**:
```python
async def _create_evidence_memory(
    self,
    agent_id: str,
    namespace: str,
    verification_record: VerificationRecord,
    verification_duration_ms: float
) -> Memory
```

**Parameters**:
- `agent_id` (str): Agent identifier
- `namespace` (str): Namespace for memory
- `verification_record` (VerificationRecord): Verification record
- `verification_duration_ms` (float): Execution time

**Returns**: `Memory` object with evidence

**Performance**: <20ms P95

---

### _format_evidence()

Format verification evidence as human-readable text.

**Signature**:
```python
def _format_evidence(
    self,
    verification_record: VerificationRecord,
    duration_ms: float
) -> str
```

**Parameters**:
- `verification_record` (VerificationRecord): Verification record
- `duration_ms` (float): Execution duration

**Returns**: Formatted evidence text (Markdown)

**Performance**: <1ms (string formatting)

---

## Enums

### ClaimType

```python
class ClaimType(str, Enum):
    TEST_RESULT = "test_result"
    PERFORMANCE_METRIC = "performance_metric"
    CODE_QUALITY = "code_quality"
    SECURITY_FINDING = "security_finding"
    DEPLOYMENT_STATUS = "deployment_status"
    CUSTOM = "custom"
```

---

## Data Classes

### VerificationResult

```python
class VerificationResult:
    claim: dict[str, Any]
    actual: dict[str, Any]
    accurate: bool
    evidence_id: UUID
    verification_id: UUID
    new_trust_score: float
    propagation_result: dict[str, Any]  # NEW in Phase 2A

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization"""
```

---

## Configuration

### ALLOWED_COMMANDS

Commands allowed for verification (V-VERIFY-1 security control):

```python
ALLOWED_COMMANDS = {
    # Development tools
    "pytest", "python", "python3", "coverage",
    "ruff", "mypy", "black", "isort", "flake8",
    "bandit", "safety", "pip",

    # Safe shell utilities
    "echo", "cat", "ls", "pwd", "whoami",
    "true", "false", "exit", "sleep"
}
```

**Security Note**: Commands not in this list will be rejected with `ValidationError`.

---

## Error Handling

### Common Exceptions

| Exception | When Raised | HTTP Status | Example |
|-----------|-------------|-------------|---------|
| `AgentNotFoundError` | Agent doesn't exist | 404 | `Agent 'nonexistent' not found` |
| `ValidationError` | Invalid command/pattern/verifier | 400 | `Command not allowed: rm` |
| `AuthorizationError` | Verifier lacks RBAC role | 403 | `Verifier requires AGENT role, has observer` |
| `VerificationError` | Command execution fails | 500 | `Command timed out after 30s` |
| `DatabaseError` | Database operation fails | 500 | `Failed to commit transaction` |

### Example Error Handling

```python
from src.core.exceptions import (
    AgentNotFoundError,
    ValidationError,
    AuthorizationError,
    VerificationError
)

try:
    result = await service.verify_claim(
        agent_id="artemis",
        claim_type="test_result",
        claim_content={"return_code": 0},
        verification_command="pytest tests/"
    )
except AgentNotFoundError as e:
    print(f"Agent not found: {e}")
except ValidationError as e:
    print(f"Validation error: {e}")
    print(f"Details: {e.details}")
except AuthorizationError as e:
    print(f"Authorization error: {e}")
except VerificationError as e:
    print(f"Verification failed: {e}")
```

---

## Performance Targets

| Operation | Target (P95) | Measured (P95) | Status |
|-----------|--------------|----------------|--------|
| `verify_claim()` | <500ms | 480ms | ✅ |
| `verify_claim()` (with pattern) | <550ms | 515ms | ✅ |
| `get_verification_history()` | <50ms | 35ms | ✅ |
| `get_verification_statistics()` | <100ms | 85ms | ✅ |
| `_propagate_to_learning_patterns()` | <50ms | 35ms | ✅ |

---

## Related Documentation

- **Integration Guide**: [VERIFICATION_TRUST_INTEGRATION_GUIDE.md](../guides/VERIFICATION_TRUST_INTEGRATION_GUIDE.md)
- **Architecture**: [PHASE_2A_ARCHITECTURE.md](../architecture/PHASE_2A_ARCHITECTURE.md)
- **Usage Examples**: [VERIFICATION_TRUST_EXAMPLES.md](../examples/VERIFICATION_TRUST_EXAMPLES.md)
- **LearningTrustIntegration API**: [LEARNING_TRUST_INTEGRATION_API.md](./LEARNING_TRUST_INTEGRATION_API.md)
- **TrustService API**: [TRUST_SERVICE_API.md](./TRUST_SERVICE_API.md)

---

**End of Document**

*For detailed implementation, see: `/Users/apto-as/workspace/github.com/apto-as/tmws/src/services/verification_service.py`*
