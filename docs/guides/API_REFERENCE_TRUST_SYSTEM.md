# Agent Trust & Verification System - API Reference

**Version**: v2.2.7+
**Target Audience**: All developers integrating with TMWS
**Last Updated**: 2025-11-07

---

## Table of Contents

1. [AgentService API](#agentservice-api)
2. [VerificationService API](#verificationservice-api)
3. [MCP Tools API](#mcp-tools-api)
4. [Data Structures](#data-structures)
5. [Error Codes](#error-codes)
6. [Type Definitions](#type-definitions)

---

## AgentService API

### update_agent_trust_score()

Update an agent's trust score based on verification results.

**Signature**:
```python
async def update_agent_trust_score(
    self,
    agent_id: str,
    verification_result: VerificationResult,
) -> Agent
```

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_id` | `str` | Yes | Agent identifier |
| `verification_result` | `VerificationResult` | Yes | Verification outcome |

**Returns**: `Agent` - Updated agent object with new trust score

**Raises**:
- `NotFoundError` - Agent not found
- `ValidationError` - Invalid verification result
- `DatabaseError` - Database operation failed

**Example**:
```python
from src.services.agent_service import AgentService
from src.models.agent_verification import VerificationResult

async def example(session):
    agent_service = AgentService(session)

    # Create verification result (from verification)
    verification_result = VerificationResult(
        verification_id=123,
        claim_verified=False,
        actual_result={"test_count": 100},
        verification_output="Found 100 tests, expected 450",
    )

    # Update trust score
    updated_agent = await agent_service.update_agent_trust_score(
        agent_id="hera-strategist",
        verification_result=verification_result,
    )

    print(f"New Trust Score: {updated_agent.trust_score}")
    print(f"Status: {updated_agent.status}")

    # Output:
    # New Trust Score: 0.70
    # Status: MONITORED
```

**Trust Score Calculation**:
```python
# On verification failure
new_score = current_score * 0.70 + 0.0 * 0.30

# On verification success
new_score = current_score * 0.95 + 1.0 * 0.05
```

**Status Determination**:
| Trust Score | Status | Access Level |
|-------------|--------|--------------|
| ≥ 0.90 | TRUSTED | Full access |
| 0.75-0.89 | ACTIVE | Normal access |
| 0.50-0.74 | MONITORED | Restricted access |
| 0.25-0.49 | UNTRUSTED | Minimal access |
| < 0.25 | BLOCKED | No autonomous actions |

---

### get_agent_trust_history()

Retrieve historical trust score changes for an agent.

**Signature**:
```python
async def get_agent_trust_history(
    self,
    agent_id: str,
    limit: int = 100,
    offset: int = 0,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> list[AgentTrustHistory]
```

**Parameters**:
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `agent_id` | `str` | Yes | - | Agent identifier |
| `limit` | `int` | No | 100 | Maximum records to return |
| `offset` | `int` | No | 0 | Pagination offset |
| `start_date` | `datetime` | No | None | Filter start date |
| `end_date` | `datetime` | No | None | Filter end date |

**Returns**: `list[AgentTrustHistory]` - List of trust score changes

**Example**:
```python
from datetime import datetime, timedelta

# Get last 30 days of trust history
thirty_days_ago = datetime.utcnow() - timedelta(days=30)
history = await agent_service.get_agent_trust_history(
    agent_id="artemis-optimizer",
    start_date=thirty_days_ago,
    limit=50,
)

for record in history:
    print(f"{record.created_at}: {record.old_trust_score:.2f} → {record.new_trust_score:.2f}")
    print(f"  Claim: {record.claim}")
    print(f"  Verified: {record.verified}")
    print(f"  Change: {record.score_change:+.2f}")
```

---

### reset_agent_trust()

Reset an agent's trust score (requires admin privileges).

**Signature**:
```python
async def reset_agent_trust(
    self,
    agent_id: str,
    new_score: float,
    reason: str,
    reset_history: bool = False,
) -> Agent
```

**Parameters**:
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `agent_id` | `str` | Yes | - | Agent identifier |
| `new_score` | `float` | Yes | - | New trust score (0.0-1.0) |
| `reason` | `str` | Yes | - | Justification for reset |
| `reset_history` | `bool` | No | False | Clear trust history |

**Returns**: `Agent` - Agent with reset trust score

**Raises**:
- `NotFoundError` - Agent not found
- `ValidationError` - Invalid score (not 0.0-1.0)
- `PermissionError` - Insufficient privileges

**Example**:
```python
# Reset after agent logic update
agent = await agent_service.reset_agent_trust(
    agent_id="hera-strategist",
    new_score=0.85,
    reason="Agent logic updated in v2.2.8, previous failures addressed",
    reset_history=False,  # Keep history for audit
)

print(f"Trust Score Reset: {agent.trust_score}")
print(f"Status: {agent.status}")
```

**⚠️ Warning**: Use sparingly. Trust resets should be justified and documented.

---

## VerificationService API

### verify_claim()

Verify an agent's claim by executing verification command.

**Signature**:
```python
async def verify_claim(
    self,
    agent_id: str,
    claim: str,
    verification_type: str,
    verification_command: str | None = None,
    expected_result: Any = None,
    timeout: int | None = None,
) -> VerificationResult
```

**Parameters**:
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `agent_id` | `str` | Yes | - | Agent making the claim |
| `claim` | `str` | Yes | - | The claim to verify |
| `verification_type` | `str` | Yes | - | Verification category |
| `verification_command` | `str` | No | None | Shell command to execute |
| `expected_result` | `Any` | No | None | Expected outcome |
| `timeout` | `int` | No | Auto | Timeout in seconds |

**Verification Types**:
| Type | Default Timeout | Purpose |
|------|----------------|---------|
| `test_count` | 30s | Count tests in suite |
| `test_results` | 120s | Verify test pass/fail |
| `code_quality` | 60s | Check linting violations |
| `performance` | 180s | Benchmark performance |
| `security` | 180s | Security scans |
| `coverage` | 120s | Code coverage checks |
| `file_existence` | 5s | Verify file exists |
| `custom` | 300s | User-defined verification |

**Returns**: `VerificationResult` - Verification outcome

**Raises**:
- `ValidationError` - Invalid parameters
- `VerificationError` - Execution failed
- `TimeoutError` - Command exceeded timeout

**Example 1: Test Count Verification**:
```python
result = await verification_service.verify_claim(
    agent_id="hera-strategist",
    claim="Project has 450 tests",
    verification_type="test_count",
    verification_command="pytest tests/ --collect-only -q | grep -c '::'",
    expected_result={"test_count": 450},
)

print(f"Claim Verified: {result.claim_verified}")
print(f"Expected: 450 tests")
print(f"Actual: {result.actual_result['test_count']} tests")
print(f"Match: {result.claim_verified}")
```

**Example 2: Code Quality Verification**:
```python
result = await verification_service.verify_claim(
    agent_id="artemis-optimizer",
    claim="Found 15 unused imports",
    verification_type="code_quality",
    verification_command="ruff check src/ --select F401 | wc -l",
    expected_result={"violation_count": 15},
)

if result.claim_verified:
    print("✅ Code quality claim verified")
else:
    print("❌ Code quality claim failed")
    print(f"Expected: 15 violations")
    print(f"Actual: {result.actual_result['violation_count']} violations")
```

**Example 3: Performance Verification**:
```python
result = await verification_service.verify_claim(
    agent_id="artemis-optimizer",
    claim="Database queries average 12ms",
    verification_type="performance",
    verification_command="python scripts/benchmark_db.py --format json",
    expected_result={"avg_query_time_ms": 12.0},
    timeout=180,  # 3 minutes for benchmark
)

print(f"Performance: {result.actual_result['avg_query_time_ms']:.2f}ms")
print(f"Target: 12.0ms")
print(f"Within Tolerance: {result.claim_verified}")
```

---

### batch_verify_claims()

Verify multiple claims in parallel.

**Signature**:
```python
async def batch_verify_claims(
    self,
    verifications: list[dict[str, Any]],
) -> list[VerificationResult]
```

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `verifications` | `list[dict]` | Yes | List of verification requests |

**Verification Request Structure**:
```python
{
    "agent_id": str,
    "claim": str,
    "verification_type": str,
    "verification_command": str,
    "expected_result": Any,
    "timeout": int | None,
}
```

**Returns**: `list[VerificationResult]` - Results in same order as input

**Example**:
```python
verifications = [
    {
        "agent_id": "artemis-optimizer",
        "claim": "Test coverage is 85%",
        "verification_type": "coverage",
        "verification_command": "pytest --cov=src --cov-report=term",
        "expected_result": {"coverage_percent": 85},
    },
    {
        "agent_id": "artemis-optimizer",
        "claim": "15 unused imports detected",
        "verification_type": "code_quality",
        "verification_command": "ruff check src/ --select F401",
        "expected_result": {"violation_count": 15},
    },
    {
        "agent_id": "artemis-optimizer",
        "claim": "Database queries average 12ms",
        "verification_type": "performance",
        "verification_command": "python scripts/benchmark_db.py",
        "expected_result": {"avg_query_time_ms": 12.0},
    },
]

results = await verification_service.batch_verify_claims(verifications)

# Process results
for i, result in enumerate(results):
    claim = verifications[i]["claim"]
    status = "✅ VERIFIED" if result.claim_verified else "❌ FAILED"
    print(f"{status}: {claim}")
```

---

## MCP Tools API

### get_agent_trust_score

Retrieve current trust score and verification history.

**MCP Tool Signature**:
```json
{
    "name": "get_agent_trust_score",
    "description": "Get agent trust score and verification history",
    "parameters": {
        "agent_id": {
            "type": "string",
            "description": "Agent identifier",
            "required": true
        },
        "include_history": {
            "type": "boolean",
            "description": "Include verification history",
            "required": false,
            "default": true
        },
        "history_limit": {
            "type": "integer",
            "description": "Maximum history records",
            "required": false,
            "default": 10
        }
    }
}
```

**Returns**:
```json
{
    "agent_id": "hera-strategist",
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
            "score_change": 0.01,
            "old_score": 0.86,
            "new_score": 0.87
        }
    ]
}
```

**Usage (Claude Desktop)**:
```python
await mcp.call_tool("get_agent_trust_score", {
    "agent_id": "artemis-optimizer",
    "include_history": True,
    "history_limit": 5
})
```

**Example Output**:
```
Agent: artemis-optimizer
Trust Score: 0.92 (TRUSTED)
Accuracy: 95.6% (44/46 verifications)

Recent History:
  ✅ 2025-11-07 10:30: "Database queries optimized to 12ms" (+0.01)
  ✅ 2025-11-07 09:15: "Test coverage improved to 87%" (+0.01)
  ❌ 2025-11-06 15:20: "5 tests failing with RuntimeError" (-0.13)
  ✅ 2025-11-06 14:00: "Reduced memory usage by 25%" (+0.01)
  ✅ 2025-11-06 10:45: "Fixed 10 code quality issues" (+0.01)
```

---

### verify_and_record

Verify a claim and automatically update trust score.

**MCP Tool Signature**:
```json
{
    "name": "verify_and_record",
    "description": "Verify agent claim and update trust score",
    "parameters": {
        "agent_id": {
            "type": "string",
            "description": "Agent identifier",
            "required": true
        },
        "claim": {
            "type": "string",
            "description": "The claim to verify",
            "required": true
        },
        "verification_type": {
            "type": "string",
            "description": "Type of verification",
            "required": true,
            "enum": [
                "test_count",
                "test_results",
                "code_quality",
                "performance",
                "security",
                "coverage",
                "file_existence",
                "custom"
            ]
        },
        "verification_command": {
            "type": "string",
            "description": "Shell command to execute",
            "required": true
        },
        "expected_result": {
            "type": "object",
            "description": "Expected outcome (optional)",
            "required": false
        },
        "timeout": {
            "type": "integer",
            "description": "Timeout in seconds",
            "required": false
        }
    }
}
```

**Returns**:
```json
{
    "claim_verified": false,
    "expected": {"test_count": 450},
    "actual": {"test_count": 447},
    "match": false,
    "tolerance_applied": "5%",
    "trust_score_before": 1.0,
    "trust_score_after": 0.95,
    "score_change": -0.05,
    "status_before": "TRUSTED",
    "status_after": "TRUSTED",
    "verification_id": 123,
    "execution_time_ms": 2847.3
}
```

**Usage Example 1: Test Count**:
```python
result = await mcp.call_tool("verify_and_record", {
    "agent_id": "hera-strategist",
    "claim": "Project has 450 tests",
    "verification_type": "test_count",
    "verification_command": "pytest tests/ --collect-only -q | grep -c '::'",
    "expected_result": {"test_count": 450}
})

if result["claim_verified"]:
    print(f"✅ Claim verified! Trust score: {result['trust_score_after']:.2f}")
else:
    print(f"❌ Claim failed. Expected {result['expected']}, got {result['actual']}")
    print(f"Trust score decreased: {result['trust_score_before']:.2f} → {result['trust_score_after']:.2f}")
```

**Usage Example 2: File Existence**:
```python
result = await mcp.call_tool("verify_and_record", {
    "agent_id": "hera-strategist",
    "claim": "Found 216 fake tests in test_coverage_boost.py",
    "verification_type": "file_existence",
    "verification_command": "ls tests/unit/test_coverage_boost.py",
    "expected_result": {"file_exists": True}
})

# Real incident: File not found
# Result:
# {
#     "claim_verified": False,
#     "expected": {"file_exists": True},
#     "actual": {"file_exists": False},
#     "trust_score_before": 1.0,
#     "trust_score_after": 0.70,
#     "status_after": "MONITORED"
# }
```

---

### bulk_verify_claims

Verify multiple claims in a single MCP call.

**MCP Tool Signature**:
```json
{
    "name": "bulk_verify_claims",
    "description": "Verify multiple claims in batch",
    "parameters": {
        "agent_id": {
            "type": "string",
            "description": "Agent identifier",
            "required": true
        },
        "claims": {
            "type": "array",
            "description": "List of claims to verify",
            "required": true,
            "items": {
                "type": "object",
                "properties": {
                    "claim": {"type": "string"},
                    "verification_type": {"type": "string"},
                    "command": {"type": "string"},
                    "expected": {"type": "object"}
                }
            }
        }
    }
}
```

**Returns**:
```json
{
    "agent_id": "artemis-optimizer",
    "total_claims": 3,
    "verified_count": 2,
    "failed_count": 1,
    "trust_score_before": 0.87,
    "trust_score_after": 0.83,
    "status": "ACTIVE",
    "results": [
        {
            "claim": "Test coverage is 85%",
            "verified": true,
            "execution_time_ms": 2341.5
        },
        {
            "claim": "15 unused imports detected",
            "verified": true,
            "execution_time_ms": 1234.2
        },
        {
            "claim": "Database queries average 12ms",
            "verified": false,
            "execution_time_ms": 5678.9,
            "expected": {"avg_query_time_ms": 12.0},
            "actual": {"avg_query_time_ms": 16.3}
        }
    ]
}
```

**Usage**:
```python
result = await mcp.call_tool("bulk_verify_claims", {
    "agent_id": "artemis-optimizer",
    "claims": [
        {
            "claim": "Test coverage is 85%",
            "verification_type": "coverage",
            "command": "pytest --cov=src --cov-report=term",
            "expected": {"coverage_percent": 85}
        },
        {
            "claim": "15 unused imports detected",
            "verification_type": "code_quality",
            "command": "ruff check src/ --select F401",
            "expected": {"violation_count": 15}
        },
        {
            "claim": "Database queries average 12ms",
            "verification_type": "performance",
            "command": "python scripts/benchmark_db.py",
            "expected": {"avg_query_time_ms": 12.0}
        }
    ]
})

print(f"Verified: {result['verified_count']}/{result['total_claims']}")
print(f"Trust Score: {result['trust_score_before']:.2f} → {result['trust_score_after']:.2f}")
```

---

### reset_agent_trust

Reset an agent's trust score (admin only).

**MCP Tool Signature**:
```json
{
    "name": "reset_agent_trust",
    "description": "Reset agent trust score (admin only)",
    "parameters": {
        "agent_id": {
            "type": "string",
            "description": "Agent identifier",
            "required": true
        },
        "new_score": {
            "type": "number",
            "description": "New trust score (0.0-1.0)",
            "required": true,
            "minimum": 0.0,
            "maximum": 1.0
        },
        "reason": {
            "type": "string",
            "description": "Justification for reset",
            "required": true
        },
        "reset_history": {
            "type": "boolean",
            "description": "Clear trust history",
            "required": false,
            "default": false
        }
    }
}
```

**Returns**:
```json
{
    "success": true,
    "agent_id": "hera-strategist",
    "old_trust_score": 0.45,
    "new_trust_score": 0.85,
    "old_status": "UNTRUSTED",
    "new_status": "ACTIVE",
    "reason": "Agent logic updated in v2.2.8",
    "reset_by": "admin_user",
    "timestamp": "2025-11-07T12:00:00Z"
}
```

**Usage**:
```python
result = await mcp.call_tool("reset_agent_trust", {
    "agent_id": "hera-strategist",
    "new_score": 0.85,
    "reason": "Agent logic updated in v2.2.8, previous failures addressed",
    "reset_history": False
})

if result["success"]:
    print(f"✅ Trust score reset: {result['old_trust_score']:.2f} → {result['new_trust_score']:.2f}")
    print(f"Status: {result['old_status']} → {result['new_status']}")
```

---

## Data Structures

### Agent (Extended)

```python
class Agent(TMWSBase):
    """Agent model with trust tracking."""

    # Existing fields
    agent_id: str
    display_name: str
    namespace: str
    status: str  # ACTIVE, TRUSTED, MONITORED, UNTRUSTED, BLOCKED

    # Trust tracking fields (new)
    trust_score: float = 1.0  # 0.0 to 1.0
    total_verifications: int = 0
    successful_verifications: int = 0
    failed_verifications: int = 0
    last_verification_at: datetime | None = None

    # Relationships
    verifications: list[AgentVerification]
    trust_history: list[AgentTrustHistory]
```

**Trust Score Properties**:
- Default: `1.0` (fully trusted)
- Range: `0.0` (blocked) to `1.0` (fully trusted)
- Updated: After each verification
- Calculation: Exponential Moving Average (EMA)

**Status Values**:
| Status | Trust Score Range | Description |
|--------|-------------------|-------------|
| `TRUSTED` | 0.90 - 1.00 | Fully trusted agent |
| `ACTIVE` | 0.75 - 0.89 | Normally trusted agent |
| `MONITORED` | 0.50 - 0.74 | Requires additional verification |
| `UNTRUSTED` | 0.25 - 0.49 | Peer review required |
| `BLOCKED` | 0.00 - 0.24 | No autonomous actions |

---

### AgentVerification

```python
class AgentVerification(TMWSBase):
    """Record of agent claim verification."""

    id: int  # Primary key
    agent_id: str  # Foreign key to Agent
    claim: str  # The claim being verified
    verification_type: str  # Type of verification
    verification_command: str | None  # Shell command executed
    expected_result: dict[str, Any] | None  # Expected outcome
    status: str  # PENDING, COMPLETED, FAILED, ERROR
    completed_at: datetime | None  # Verification completion time

    # Relationships
    agent: Agent
    result: VerificationResult | None
```

**Verification Types**:
- `test_count`: Count tests in suite
- `test_results`: Verify test pass/fail status
- `code_quality`: Check linting/style violations
- `performance`: Benchmark performance metrics
- `security`: Security vulnerability scans
- `coverage`: Code coverage checks
- `file_existence`: File/directory existence
- `custom`: User-defined verification

**Status Values**:
- `PENDING`: Verification not yet started
- `COMPLETED`: Verification successful
- `FAILED`: Verification failed (claim incorrect)
- `ERROR`: Verification error (command failed)

---

### VerificationResult

```python
class VerificationResult(TMWSBase):
    """Result of verification execution."""

    id: int  # Primary key
    verification_id: int  # Foreign key to AgentVerification
    claim_verified: bool  # True if claim matches reality
    actual_result: dict[str, Any] | None  # Actual outcome
    verification_output: str | None  # Command stdout
    verification_error: str | None  # Command stderr
    execution_time_ms: float | None  # Execution duration

    # Relationships
    verification: AgentVerification
```

**claim_verified Logic**:
```python
# Exact match
claim_verified = (expected == actual)

# With tolerance (for numeric values)
claim_verified = abs(expected - actual) <= tolerance

# Type-specific comparison
claim_verified = compare_function(expected, actual)
```

---

### AgentTrustHistory

```python
class AgentTrustHistory(TMWSBase):
    """Historical record of trust score changes."""

    id: int  # Primary key
    agent_id: str  # Foreign key to Agent
    verification_id: int | None  # Foreign key to AgentVerification
    old_trust_score: float  # Score before change
    new_trust_score: float  # Score after change
    score_change: float  # Difference (new - old)
    claim: str | None  # Associated claim
    verified: bool | None  # Verification outcome
    created_at: datetime  # Timestamp of change
```

**Usage**: Audit trail of all trust score changes

**Querying**:
```python
# Get trust history for agent
from sqlalchemy import select
from src.models.agent_trust import AgentTrustHistory

history = await session.execute(
    select(AgentTrustHistory)
    .where(AgentTrustHistory.agent_id == "hera-strategist")
    .order_by(AgentTrustHistory.created_at.desc())
    .limit(10)
)

for record in history.scalars():
    print(f"{record.created_at}: {record.old_trust_score:.2f} → {record.new_trust_score:.2f}")
    print(f"  Change: {record.score_change:+.2f}")
    print(f"  Verified: {record.verified}")
```

---

## Error Codes

### ValidationError

**Code**: `TMWS_VAL_001` to `TMWS_VAL_999`

**Common Errors**:
| Code | Description | Solution |
|------|-------------|----------|
| `TMWS_VAL_001` | Invalid agent_id | Check agent exists |
| `TMWS_VAL_002` | Invalid trust score (not 0.0-1.0) | Use valid range |
| `TMWS_VAL_003` | Empty claim | Provide non-empty claim |
| `TMWS_VAL_004` | Invalid verification_type | Use supported type |
| `TMWS_VAL_005` | Missing verification_command | Provide command |

**Example**:
```python
try:
    await agent_service.reset_agent_trust(
        agent_id="invalid-agent",
        new_score=1.5,  # ❌ Invalid
        reason="Test",
    )
except ValidationError as e:
    print(f"Error Code: {e.code}")  # TMWS_VAL_002
    print(f"Message: {e.message}")  # Invalid trust score: 1.5 (must be 0.0-1.0)
```

---

### VerificationError

**Code**: `TMWS_VER_001` to `TMWS_VER_999`

**Common Errors**:
| Code | Description | Solution |
|------|-------------|----------|
| `TMWS_VER_001` | Command execution failed | Check command syntax |
| `TMWS_VER_002` | Verification timeout | Increase timeout |
| `TMWS_VER_003` | Output parsing failed | Check output format |
| `TMWS_VER_004` | Comparison failed | Check expected format |

**Example**:
```python
try:
    await verification_service.verify_claim(
        agent_id="hera-strategist",
        claim="Project has 450 tests",
        verification_type="test_count",
        verification_command="invalid_command",  # ❌ Invalid
    )
except VerificationError as e:
    print(f"Error Code: {e.code}")  # TMWS_VER_001
    print(f"Message: {e.message}")  # Command execution failed: invalid_command: not found
    print(f"Details: {e.details}")  # {"stderr": "...", "returncode": 127}
```

---

### NotFoundError

**Code**: `TMWS_NF_001` to `TMWS_NF_999`

**Common Errors**:
| Code | Description | Solution |
|------|-------------|----------|
| `TMWS_NF_001` | Agent not found | Verify agent_id |
| `TMWS_NF_002` | Verification not found | Check verification_id |
| `TMWS_NF_003` | Trust history not found | Agent has no history |

---

### PermissionError

**Code**: `TMWS_PERM_001` to `TMWS_PERM_999`

**Common Errors**:
| Code | Description | Solution |
|------|-------------|----------|
| `TMWS_PERM_001` | Insufficient privileges | Requires admin |
| `TMWS_PERM_002` | Agent status blocks operation | Trust score too low |

**Example**:
```python
try:
    await agent_service.reset_agent_trust(
        agent_id="hera-strategist",
        new_score=1.0,
        reason="Reset",
    )
except PermissionError as e:
    print(f"Error: {e.message}")  # Insufficient privileges for trust reset
    print("Solution: Request admin to perform reset")
```

---

## Type Definitions

### TypeScript Definitions (for MCP clients)

```typescript
// Agent Trust Types
export interface AgentTrustScore {
    agent_id: string;
    trust_score: number;  // 0.0 to 1.0
    status: AgentStatus;
    total_verifications: number;
    successful_verifications: number;
    failed_verifications: number;
    accuracy_rate: number;
    last_verification: string | null;  // ISO 8601
    verification_history?: TrustHistoryRecord[];
}

export type AgentStatus =
    | "TRUSTED"
    | "ACTIVE"
    | "MONITORED"
    | "UNTRUSTED"
    | "BLOCKED";

export interface TrustHistoryRecord {
    timestamp: string;  // ISO 8601
    claim: string;
    verified: boolean;
    score_change: number;
    old_score: number;
    new_score: number;
}

export interface VerificationRequest {
    agent_id: string;
    claim: string;
    verification_type: VerificationType;
    verification_command: string;
    expected_result?: any;
    timeout?: number;
}

export type VerificationType =
    | "test_count"
    | "test_results"
    | "code_quality"
    | "performance"
    | "security"
    | "coverage"
    | "file_existence"
    | "custom";

export interface VerificationResult {
    claim_verified: boolean;
    expected?: any;
    actual?: any;
    match: boolean;
    tolerance_applied?: string;
    trust_score_before: number;
    trust_score_after: number;
    score_change: number;
    status_before: AgentStatus;
    status_after: AgentStatus;
    verification_id: number;
    execution_time_ms: number;
}

export interface BulkVerificationResult {
    agent_id: string;
    total_claims: number;
    verified_count: number;
    failed_count: number;
    trust_score_before: number;
    trust_score_after: number;
    status: AgentStatus;
    results: Array<{
        claim: string;
        verified: boolean;
        execution_time_ms: number;
        expected?: any;
        actual?: any;
    }>;
}

export interface TrustResetResult {
    success: boolean;
    agent_id: string;
    old_trust_score: number;
    new_trust_score: number;
    old_status: AgentStatus;
    new_status: AgentStatus;
    reason: string;
    reset_by: string;
    timestamp: string;  // ISO 8601
}
```

### Python Type Hints

```python
"""Type hints for agent trust system."""

from typing import Any, Literal, TypedDict

# Agent Status Type
AgentStatus = Literal["TRUSTED", "ACTIVE", "MONITORED", "UNTRUSTED", "BLOCKED"]

# Verification Type
VerificationType = Literal[
    "test_count",
    "test_results",
    "code_quality",
    "performance",
    "security",
    "coverage",
    "file_existence",
    "custom",
]


class TrustScoreResponse(TypedDict):
    """Trust score API response."""

    agent_id: str
    trust_score: float
    status: AgentStatus
    total_verifications: int
    successful_verifications: int
    failed_verifications: int
    accuracy_rate: float
    last_verification: str | None
    verification_history: list[dict[str, Any]]


class VerificationRequest(TypedDict):
    """Verification request structure."""

    agent_id: str
    claim: str
    verification_type: VerificationType
    verification_command: str
    expected_result: Any | None
    timeout: int | None


class VerificationResponse(TypedDict):
    """Verification result response."""

    claim_verified: bool
    expected: Any | None
    actual: Any | None
    match: bool
    tolerance_applied: str | None
    trust_score_before: float
    trust_score_after: float
    score_change: float
    status_before: AgentStatus
    status_after: AgentStatus
    verification_id: int
    execution_time_ms: float
```

---

## Next Steps

- **Users**: [User Guide: Agent Trust](./USER_GUIDE_AGENT_TRUST.md)
- **Developers**: [Developer Guide: Integration](./DEVELOPER_GUIDE_VERIFICATION.md)
- **Operators**: [Operations Guide: Monitoring](./OPERATIONS_GUIDE_MONITORING.md)
- **Migration**: [Migration Guide: Trust System v1](./MIGRATION_GUIDE_TRUST_V1.md)

---

**Need Help?**
- GitHub Issues: [github.com/apto-as/tmws/issues](https://github.com/apto-as/tmws/issues)
- API Documentation: [docs/](../)
- MCP Integration: [MCP_INTEGRATION.md](../MCP_INTEGRATION.md)

---

*This API reference is part of TMWS v2.2.7+ Agent Trust & Verification System.*
