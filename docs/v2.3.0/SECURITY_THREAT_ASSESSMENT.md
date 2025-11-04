# TMWS v2.3.0 Security Threat Assessment
**Prepared By**: Hestia (Security Guardian)
**Date**: 2025-11-04
**Version**: v2.3.0-security-review
**Classification**: INTERNAL SECURITY ANALYSIS

---

## Executive Summary

...すみません、最悪のシナリオを全て列挙しなければなりません...

### Overall Risk Assessment

| Feature | Risk Level | Attack Surface | Mitigation Complexity |
|---------|-----------|----------------|---------------------|
| TTL Parameter | 🔴 **HIGH** | Input validation bypass | Medium |
| Access Tracking | 🟡 **MEDIUM** | Privacy leakage | Low |
| Pruning Operations | 🔴 **HIGH** | Unauthorized deletion | High |
| Namespace Isolation | 🟠 **MEDIUM-HIGH** | Cross-tenant access | Medium |

**Critical Finding**: TTL and pruning features introduce **denial-of-service** and **data destruction** attack vectors that do not exist in v2.2.7.

---

## Threat Model 1: TTL Parameter Validation

### Attack Surface Analysis

**New Entry Point**: `create_memory(ttl_days)` parameter

#### Attack Vector V-TTL-1: Extreme TTL Values
**CVSS Score**: 7.5 (HIGH)
**CWE**: CWE-20 (Improper Input Validation)

**Attack Scenario**:
```python
# Attacker creates memory with extremely long TTL
await create_memory(
    content="Persistent attack payload",
    ttl_days=999999,  # ❌ ~2739 years - prevents cleanup forever
    agent_id="attacker",
    namespace="target-tenant"
)
```

**Impact**:
- **Storage exhaustion**: Attacker can fill database with uncleaned memories
- **Cleanup bypass**: Legitimate cleanup operations are ineffective
- **Cost amplification**: Cloud storage costs increase indefinitely

**Likelihood**: HIGH (no input validation currently exists)

**Worst-Case Scenario**:
- Attacker creates 10,000 memories with TTL=999999 days
- Database grows to 10GB+ uncleaned data
- SQLite WAL file grows to 2GB+ (performance degradation)
- Monthly cloud storage costs increase by $500-$1000

#### Attack Vector V-TTL-2: Zero/Negative TTL
**CVSS Score**: 6.5 (MEDIUM)
**CWE**: CWE-682 (Incorrect Calculation)

**Attack Scenario**:
```python
# Attacker causes immediate deletion
await create_memory(
    content="Important data",
    ttl_days=0,  # ❌ Immediate expiration
    agent_id="victim",
    namespace="target-tenant"
)

# Or negative value
await create_memory(
    content="Critical memory",
    ttl_days=-1,  # ❌ Already expired?
    agent_id="victim",
    namespace="target-tenant"
)
```

**Impact**:
- **Data loss**: Memories are immediately deleted by background pruning
- **Business disruption**: Critical knowledge is lost
- **Compliance violation**: Audit logs may be prematurely deleted

**Likelihood**: MEDIUM (requires write access to target namespace)

**Worst-Case Scenario**:
- Compromised agent creates 1000 SYSTEM-level memories with TTL=0
- Background pruner deletes all immediately
- System-wide knowledge base is wiped out

#### Attack Vector V-TTL-3: Type Confusion Attack
**CVSS Score**: 5.5 (MEDIUM)
**CWE**: CWE-843 (Access of Resource Using Incompatible Type)

**Attack Scenario**:
```python
# Attacker provides non-integer TTL
await create_memory(
    content="Attack payload",
    ttl_days="infinite",  # ❌ String instead of int
    agent_id="attacker",
    namespace="target-tenant"
)

# Or floating point to cause calculation errors
await create_memory(
    content="Attack payload",
    ttl_days=3.14159,  # ❌ Float instead of int
    agent_id="attacker",
    namespace="target-tenant"
)
```

**Impact**:
- **Type error crashes**: Python TypeError crashes background pruner
- **Calculation errors**: Float TTL causes incorrect `expires_at` timestamp
- **SQL injection**: If TTL is directly interpolated into SQL (unlikely but possible)

**Likelihood**: MEDIUM (depends on input validation implementation)

### Mitigation Strategy

#### 🛡️ Input Validation Rules

```python
# REQUIRED: Add to src/utils/validation.py
def validate_ttl_days(ttl_days: int | None) -> tuple[bool, list[str]]:
    """Validate TTL days parameter.

    Security Rules:
    - If None: No expiration (infinite TTL) - ALLOWED
    - If provided: Must be integer
    - Range: 1 <= ttl_days <= 3650 (10 years max)
    - Negative values: REJECTED
    - Zero: REJECTED (use delete instead)

    Args:
        ttl_days: TTL in days or None for no expiration

    Returns:
        Tuple of (is_valid, list_of_issues)
    """
    issues = []

    if ttl_days is None:
        return True, []  # Infinite TTL is allowed

    if not isinstance(ttl_days, int):
        issues.append("TTL days must be an integer or None")
        return False, issues

    if ttl_days <= 0:
        issues.append("TTL days must be positive (minimum: 1)")

    if ttl_days > 3650:  # 10 years max
        issues.append("TTL days must be at most 3650 (10 years)")

    return len(issues) == 0, issues
```

#### 🛡️ Access-Level Based TTL Limits

**Recommendation**: Different access levels should have different maximum TTL values.

```python
# REQUIRED: Add to src/models/memory.py or src/services/memory_service.py
TTL_LIMITS_BY_ACCESS_LEVEL = {
    AccessLevel.PRIVATE: 3650,    # 10 years
    AccessLevel.TEAM: 1825,       # 5 years
    AccessLevel.SHARED: 1095,     # 3 years
    AccessLevel.PUBLIC: 365,      # 1 year
    AccessLevel.SYSTEM: None,     # Infinite (system memories are permanent)
}

def validate_ttl_for_access_level(
    ttl_days: int | None,
    access_level: AccessLevel
) -> tuple[bool, list[str]]:
    """Validate TTL against access level limits."""
    issues = []

    if ttl_days is None:
        # Infinite TTL only allowed for SYSTEM level
        if access_level != AccessLevel.SYSTEM:
            issues.append(
                f"Infinite TTL (None) is only allowed for SYSTEM access level, "
                f"got {access_level.value}"
            )
        return len(issues) == 0, issues

    max_ttl = TTL_LIMITS_BY_ACCESS_LEVEL.get(access_level)
    if max_ttl is not None and ttl_days > max_ttl:
        issues.append(
            f"TTL {ttl_days} days exceeds maximum {max_ttl} days "
            f"for {access_level.value} access level"
        )

    return len(issues) == 0, issues
```

#### 🛡️ Service Layer Enforcement

```python
# REQUIRED: Modify src/services/memory_service.py
async def create_memory(
    self,
    content: str,
    agent_id: str,
    namespace: str,
    importance: float = 0.5,
    tags: list[str] | None = None,
    access_level: AccessLevel = AccessLevel.PRIVATE,
    ttl_days: int | None = None,  # ✅ NEW PARAMETER
    shared_with_agents: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    parent_memory_id: UUID | None = None,
) -> Memory:
    """Create memory with dual storage (SQLite + Chroma).

    NEW: TTL support with security validation.
    """
    # Step 1: Validate TTL format
    is_valid, issues = validate_ttl_days(ttl_days)
    if not is_valid:
        log_and_raise(
            ValidationError,
            f"Invalid TTL days: {', '.join(issues)}",
            details={"ttl_days": ttl_days, "issues": issues}
        )

    # Step 2: Validate TTL against access level
    is_valid, issues = validate_ttl_for_access_level(ttl_days, access_level)
    if not is_valid:
        log_and_raise(
            ValidationError,
            f"TTL exceeds limit for access level: {', '.join(issues)}",
            details={
                "ttl_days": ttl_days,
                "access_level": access_level.value,
                "issues": issues
            }
        )

    # Step 3: Calculate expires_at timestamp
    expires_at = None
    if ttl_days is not None:
        from datetime import datetime, timedelta
        expires_at = datetime.utcnow() + timedelta(days=ttl_days)

    # Step 4: Create memory with expires_at
    memory = Memory(
        content=content,
        agent_id=agent_id,
        namespace=namespace,
        embedding_model=self.embedding_model_name,
        embedding_dimension=self.embedding_dimension,
        importance_score=importance,
        tags=tags or [],
        access_level=access_level,
        expires_at=expires_at,  # ✅ SET EXPIRATION
        shared_with_agents=shared_with_agents or [],
        context=metadata or {},
        parent_memory_id=parent_memory_id,
    )

    # ... rest of create_memory logic ...
```

### Security Test Cases

```python
# REQUIRED: Add to tests/security/test_ttl_validation.py
class TestTTLSecurity:
    """Security tests for TTL parameter validation."""

    async def test_extreme_ttl_rejected(self):
        """Extreme TTL values (>10 years) should be rejected."""
        with pytest.raises(ValidationError, match="must be at most 3650"):
            await memory_service.create_memory(
                content="Test",
                agent_id="test-agent",
                namespace="test",
                ttl_days=999999  # ❌ Too long
            )

    async def test_zero_ttl_rejected(self):
        """Zero TTL should be rejected."""
        with pytest.raises(ValidationError, match="must be positive"):
            await memory_service.create_memory(
                content="Test",
                agent_id="test-agent",
                namespace="test",
                ttl_days=0  # ❌ Zero not allowed
            )

    async def test_negative_ttl_rejected(self):
        """Negative TTL should be rejected."""
        with pytest.raises(ValidationError, match="must be positive"):
            await memory_service.create_memory(
                content="Test",
                agent_id="test-agent",
                namespace="test",
                ttl_days=-1  # ❌ Negative not allowed
            )

    async def test_non_integer_ttl_rejected(self):
        """Non-integer TTL should be rejected."""
        with pytest.raises(ValidationError, match="must be an integer"):
            await memory_service.create_memory(
                content="Test",
                agent_id="test-agent",
                namespace="test",
                ttl_days="infinite"  # ❌ String not allowed
            )

    async def test_public_memory_ttl_limit(self):
        """Public memories should have 1-year TTL limit."""
        with pytest.raises(ValidationError, match="exceeds maximum 365 days"):
            await memory_service.create_memory(
                content="Public data",
                agent_id="test-agent",
                namespace="test",
                access_level=AccessLevel.PUBLIC,
                ttl_days=400  # ❌ Exceeds 365-day limit for PUBLIC
            )

    async def test_system_memory_infinite_ttl_allowed(self):
        """System memories should allow infinite TTL (None)."""
        memory = await memory_service.create_memory(
            content="System announcement",
            agent_id="system",
            namespace="system",
            access_level=AccessLevel.SYSTEM,
            ttl_days=None  # ✅ Infinite TTL allowed for SYSTEM
        )
        assert memory.expires_at is None

    async def test_private_memory_infinite_ttl_rejected(self):
        """Private memories should NOT allow infinite TTL."""
        with pytest.raises(ValidationError, match="only allowed for SYSTEM"):
            await memory_service.create_memory(
                content="Private data",
                agent_id="test-agent",
                namespace="test",
                access_level=AccessLevel.PRIVATE,
                ttl_days=None  # ❌ Infinite TTL not allowed for PRIVATE
            )
```

### Audit Logging Requirements

**CRITICAL**: All TTL-related operations must be audited.

```python
# REQUIRED: Add audit logging in create_memory
from src.security.security_audit_facade import get_audit_logger

audit_logger = get_audit_logger()

# Log TTL creation
if ttl_days is not None:
    audit_logger.log_info(
        action="memory_ttl_set",
        details={
            "memory_id": str(memory.id),
            "agent_id": agent_id,
            "namespace": namespace,
            "ttl_days": ttl_days,
            "expires_at": expires_at.isoformat(),
            "access_level": access_level.value,
        },
        severity="INFO"
    )

# Log validation failures
if not is_valid:
    audit_logger.log_warning(
        action="memory_ttl_validation_failed",
        details={
            "agent_id": agent_id,
            "namespace": namespace,
            "ttl_days": ttl_days,
            "access_level": access_level.value,
            "validation_errors": issues,
        },
        severity="WARNING"
    )
```

---

## Threat Model 2: Access Tracking Privacy

### Attack Surface Analysis

**New Behavior**: `update_access()` called on every `get_memory()`

#### Attack Vector V-ACCESS-1: Timing Attack via Access Patterns
**CVSS Score**: 5.5 (MEDIUM)
**CWE**: CWE-203 (Observable Discrepancy)

**Attack Scenario**:
```python
# Attacker observes access_count to infer memory existence
for memory_id in potential_memory_ids:
    # Try to access memory (will fail due to access control)
    try:
        await get_memory(memory_id)
    except Forbidden:
        pass

    # But access_count was incremented!
    # Attacker queries namespace stats to see if count increased
    stats = await get_namespace_stats("target-namespace")

    # If total_accesses increased → memory exists
    # If total_accesses unchanged → memory doesn't exist
```

**Impact**:
- **Information leakage**: Attacker can enumerate existing memory IDs
- **Privacy violation**: Access patterns reveal which memories exist
- **Targeting**: Attacker focuses on IDs with high access counts

**Likelihood**: LOW (requires namespace access to view stats)

**Worst-Case Scenario**:
- Attacker discovers 1000 memory IDs via timing attack
- Attacker prioritizes high-access memories for social engineering
- Sensitive memories (e.g., credentials) are identified

#### Attack Vector V-ACCESS-2: Access Count Manipulation
**CVSS Score**: 4.5 (MEDIUM-LOW)
**CWE**: CWE-400 (Uncontrolled Resource Consumption)

**Attack Scenario**:
```python
# Attacker inflates access count to prevent cleanup
for _ in range(10000):
    await get_memory(memory_id)  # Each call increments access_count

# Now memory has access_count=10000
# cleanup_old_memories() will NEVER delete it (access_count > 0)
```

**Impact**:
- **Cleanup bypass**: High access_count prevents deletion
- **Storage exhaustion**: Attacker keeps useless memories alive
- **Cost amplification**: Storage costs increase

**Likelihood**: MEDIUM (requires read access to target memory)

**Worst-Case Scenario**:
- Attacker creates 100 large memories (10MB each) = 1GB
- Attacker inflates access_count to 10,000 for each
- Memories are never cleaned up despite being old and low-importance

### Mitigation Strategy

#### 🛡️ Access Tracking with Rate Limiting

```python
# REQUIRED: Modify src/models/memory.py
def update_access(self, caller_agent_id: str | None = None) -> None:
    """Update access metadata with rate limiting.

    Security: Prevent access count inflation attacks.

    Args:
        caller_agent_id: Agent requesting access (for rate limiting)
    """
    from datetime import datetime, timedelta

    # Rate limiting: Only increment if last access was >5 seconds ago
    if self.accessed_at is not None:
        time_since_last_access = datetime.utcnow() - self.accessed_at
        if time_since_last_access < timedelta(seconds=5):
            # Too soon - don't increment (prevents spam)
            return

    # Increment access count
    self.access_count += 1
    self.accessed_at = datetime.utcnow()

    # Decay relevance over time, boost by access
    self.relevance_score = min(1.0, self.relevance_score * 0.99 + 0.05)

    # Cap access_count to prevent overflow
    MAX_ACCESS_COUNT = 10000
    if self.access_count > MAX_ACCESS_COUNT:
        self.access_count = MAX_ACCESS_COUNT
```

#### 🛡️ Conditional Access Tracking

**Recommendation**: Only track access for certain access levels.

```python
# REQUIRED: Modify src/services/memory_service.py
async def get_memory(self, memory_id: UUID) -> Memory | None:
    """Get memory by ID with conditional access tracking.

    Security: SYSTEM-level memories don't track access (privacy).
    """
    result = await self.session.execute(
        select(Memory).where(Memory.id == memory_id)
    )
    memory = result.scalar_one_or_none()

    if memory is None:
        return None

    # Only track access for non-SYSTEM memories
    if memory.access_level != AccessLevel.SYSTEM:
        memory.update_access()
        await self.session.commit()

    return memory
```

#### 🛡️ Anonymized Access Timestamps

**Recommendation**: Round timestamps to nearest hour to prevent correlation.

```python
# OPTIONAL: Add to src/models/memory.py
def update_access(self, caller_agent_id: str | None = None) -> None:
    """Update access metadata with anonymized timestamps."""
    from datetime import datetime, timedelta

    # Anonymize timestamp to nearest hour (prevents correlation)
    now = datetime.utcnow()
    anonymized_time = now.replace(minute=0, second=0, microsecond=0)

    self.access_count += 1
    self.accessed_at = anonymized_time  # Rounded to hour
    self.relevance_score = min(1.0, self.relevance_score * 0.99 + 0.05)
```

### Security Test Cases

```python
# REQUIRED: Add to tests/security/test_access_tracking.py
class TestAccessTrackingSecurity:
    """Security tests for access tracking privacy."""

    async def test_access_count_rate_limiting(self):
        """Rapid access should not inflate count infinitely."""
        memory = await create_test_memory()
        initial_count = memory.access_count

        # Try to inflate count with 100 rapid accesses
        for _ in range(100):
            await memory_service.get_memory(memory.id)

        # Access count should be limited (not 100)
        assert memory.access_count < initial_count + 20

    async def test_system_memory_no_tracking(self):
        """System memories should not track access."""
        memory = await create_test_memory(access_level=AccessLevel.SYSTEM)
        initial_count = memory.access_count
        initial_time = memory.accessed_at

        # Access memory
        await memory_service.get_memory(memory.id)

        # Access should NOT be tracked for SYSTEM level
        await session.refresh(memory)
        assert memory.access_count == initial_count
        assert memory.accessed_at == initial_time

    async def test_access_count_capped(self):
        """Access count should be capped to prevent overflow."""
        memory = await create_test_memory()
        memory.access_count = 9999
        await session.commit()

        # Access once more
        memory.update_access()

        # Count should be capped at 10000
        assert memory.access_count <= 10000
```

### Audit Logging Requirements

```python
# OPTIONAL: Add audit logging for suspicious access patterns
from src.security.security_audit_facade import get_audit_logger

audit_logger = get_audit_logger()

# Log if access count exceeds threshold
if memory.access_count > 1000:
    audit_logger.log_warning(
        action="high_access_count_detected",
        details={
            "memory_id": str(memory.id),
            "access_count": memory.access_count,
            "agent_id": memory.agent_id,
            "namespace": memory.namespace,
        },
        severity="WARNING"
    )
```

---

## Threat Model 3: Pruning Authorization

### Attack Surface Analysis

**New Operations**:
- `prune_expired_memories()` - Deletes all expired memories
- `cleanup_namespace()` - Deletes memories in a namespace

#### Attack Vector V-PRUNE-1: Unauthorized Cross-Namespace Deletion
**CVSS Score**: 9.1 (CRITICAL)
**CWE**: CWE-863 (Incorrect Authorization)

**Attack Scenario**:
```python
# Attacker attempts to prune another tenant's namespace
await cleanup_namespace(
    namespace="victim-tenant",  # ❌ Not attacker's namespace
    days=1,
    min_importance=0.0,
    agent_id="attacker"
)

# If not properly authorized:
# → All memories in victim-tenant namespace are deleted
# → Data breach + data destruction
```

**Impact**:
- **Data destruction**: Entire tenant's knowledge base wiped out
- **Business disruption**: Critical business data lost
- **Compliance violation**: Audit logs deleted
- **Reputation damage**: Multi-tenant security breach

**Likelihood**: HIGH (if authorization not implemented)

**Worst-Case Scenario**:
- Attacker discovers 50 customer namespaces
- Attacker calls `cleanup_namespace()` for each
- 50 customers lose all data
- Class-action lawsuit + regulatory fines
- Company bankruptcy

#### Attack Vector V-PRUNE-2: Importance Bypass via Low Threshold
**CVSS Score**: 7.5 (HIGH)
**CWE**: CWE-285 (Improper Authorization)

**Attack Scenario**:
```python
# Attacker sets min_importance=1.0 to delete ALL memories
await cleanup_namespace(
    namespace="attacker-namespace",  # Own namespace
    days=1,
    min_importance=1.0,  # ❌ Only importance=1.0 survives
    agent_id="attacker"
)

# Result: All memories with importance <1.0 are deleted
# (Most memories have importance 0.5-0.9)
```

**Impact**:
- **Data loss**: Attacker deletes own important data accidentally
- **Self-sabotage**: User error causes irreversible damage

**Likelihood**: MEDIUM (user error or social engineering)

**Worst-Case Scenario**:
- Administrator accidentally calls cleanup with min_importance=1.0
- 99% of company knowledge base is deleted
- No backup available
- Business continuity disrupted for weeks

#### Attack Vector V-PRUNE-3: Mass Deletion Denial of Service
**CVSS Score**: 6.5 (MEDIUM)
**CWE**: CWE-400 (Uncontrolled Resource Consumption)

**Attack Scenario**:
```python
# Attacker creates 100,000 low-importance memories
for i in range(100000):
    await create_memory(
        content=f"Spam {i}",
        importance=0.1,
        ttl_days=1  # Expires in 1 day
    )

# Wait 1 day, then trigger pruning
await prune_expired_memories()

# Pruning takes 10 minutes, locks database
# All other requests time out
```

**Impact**:
- **Denial of service**: Database locked during mass deletion
- **Performance degradation**: SQLite WAL file grows to 2GB+
- **Request timeouts**: All API requests fail during pruning

**Likelihood**: MEDIUM (requires write access)

**Worst-Case Scenario**:
- Attacker creates 1 million memories
- Pruning job runs during peak hours
- Database is locked for 1 hour
- All users experience downtime
- SLA breach + customer churn

### Mitigation Strategy

#### 🛡️ Namespace Authorization Check

```python
# CRITICAL: Add to src/services/memory_service.py
async def cleanup_namespace(
    self,
    namespace: str,
    agent_id: str,  # ✅ REQUIRED: Caller's agent ID
    days: int = 90,
    min_importance: float = 0.3,
) -> int:
    """Cleanup old memories in a namespace.

    SECURITY-CRITICAL: Namespace authorization required.

    Args:
        namespace: Target namespace to cleanup
        agent_id: Requesting agent's ID (REQUIRED for authorization)
        days: Delete memories older than this
        min_importance: Delete memories below this importance

    Returns:
        Number of memories deleted

    Raises:
        AuthorizationError: If agent not authorized for this namespace
    """
    from src.security.authorization import AuthorizationService
    from src.core.exceptions import AuthorizationError

    # STEP 1: Verify agent exists and get VERIFIED namespace
    stmt = select(Agent).where(Agent.agent_id == agent_id)
    result = await self.session.execute(stmt)
    agent = result.scalar_one_or_none()

    if not agent:
        log_and_raise(
            AuthorizationError,
            "Agent not found",
            details={"agent_id": agent_id}
        )

    # STEP 2: Verify agent's namespace matches target namespace
    # This prevents cross-namespace deletion attacks
    if agent.namespace != namespace:
        audit_logger.log_critical(
            action="unauthorized_namespace_cleanup_attempt",
            details={
                "agent_id": agent_id,
                "agent_namespace": agent.namespace,
                "target_namespace": namespace,
                "days": days,
                "min_importance": min_importance,
            },
            severity="CRITICAL"
        )
        log_and_raise(
            AuthorizationError,
            f"Agent {agent_id} not authorized to cleanup namespace {namespace}",
            details={
                "agent_namespace": agent.namespace,
                "target_namespace": namespace
            }
        )

    # STEP 3: Validate cleanup parameters
    is_valid, issues = validate_cleanup_parameters(days, min_importance)
    if not is_valid:
        log_and_raise(
            ValidationError,
            f"Invalid cleanup parameters: {', '.join(issues)}",
            details={"days": days, "min_importance": min_importance}
        )

    # STEP 4: Perform cleanup (now authorized)
    from datetime import datetime, timedelta
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    query = select(Memory.id).where(
        and_(
            Memory.namespace == namespace,  # ✅ Verified namespace
            Memory.created_at < cutoff_date,
            Memory.importance_score < min_importance,
            Memory.access_count == 0,
        ),
    )

    result = await self.session.execute(query)
    memory_ids = [row[0] for row in result.all()]

    # Audit log BEFORE deletion
    audit_logger.log_warning(
        action="namespace_cleanup_started",
        details={
            "namespace": namespace,
            "agent_id": agent_id,
            "days": days,
            "min_importance": min_importance,
            "memories_to_delete": len(memory_ids),
        },
        severity="WARNING"
    )

    # Delete from both stores
    # ... (existing deletion logic) ...

    # Audit log AFTER deletion
    audit_logger.log_warning(
        action="namespace_cleanup_completed",
        details={
            "namespace": namespace,
            "agent_id": agent_id,
            "deleted_count": deleted_count,
        },
        severity="WARNING"
    )

    return deleted_count
```

#### 🛡️ Cleanup Parameter Validation

```python
# REQUIRED: Add to src/utils/validation.py
def validate_cleanup_parameters(
    days: int,
    min_importance: float
) -> tuple[bool, list[str]]:
    """Validate cleanup parameters to prevent destructive operations.

    Security Rules:
    - days: Must be >= 30 (can't delete recent memories)
    - min_importance: Must be < 0.8 (can't delete high-importance memories)

    Args:
        days: Minimum age in days
        min_importance: Minimum importance threshold

    Returns:
        Tuple of (is_valid, list_of_issues)
    """
    issues = []

    # Validate days
    if not isinstance(days, int):
        issues.append("Days must be an integer")
    elif days < 30:
        issues.append("Days must be at least 30 (safety: can't delete recent memories)")
    elif days > 3650:
        issues.append("Days must be at most 3650 (10 years)")

    # Validate min_importance
    if not isinstance(min_importance, (int, float)):
        issues.append("Importance must be a number")
    elif min_importance < 0.0 or min_importance > 1.0:
        issues.append("Importance must be between 0.0 and 1.0")
    elif min_importance >= 0.8:
        issues.append(
            "Importance threshold too high (>= 0.8). "
            "This would delete most memories. Maximum: 0.79"
        )

    return len(issues) == 0, issues
```

#### 🛡️ Rate Limiting for Pruning Operations

```python
# REQUIRED: Modify src/security/rate_limiter.py
# Add pruning-specific rate limits
self.rate_limits["prune_namespace"] = RateLimit(
    requests=1,        # 1 pruning request
    period=3600,       # Per hour
    block_duration=7200  # 2-hour block if exceeded
)

self.rate_limits["prune_expired"] = RateLimit(
    requests=5,        # 5 pruning requests
    period=3600,       # Per hour
    block_duration=3600  # 1-hour block if exceeded
)
```

#### 🛡️ Batch Deletion with Progress Tracking

```python
# RECOMMENDED: Add to src/services/memory_service.py
async def cleanup_namespace(
    self,
    namespace: str,
    agent_id: str,
    days: int = 90,
    min_importance: float = 0.3,
    batch_size: int = 100,  # ✅ Process in batches to prevent lock
) -> int:
    """Cleanup with batching to prevent database locks."""

    # ... authorization checks ...

    memory_ids = [row[0] for row in result.all()]
    total = len(memory_ids)
    deleted = 0

    # Process in batches to prevent long locks
    for i in range(0, total, batch_size):
        batch = memory_ids[i:i + batch_size]

        # Delete batch from Chroma (best-effort)
        if self.vector_service:
            try:
                await self.vector_service.delete_memories_batch(
                    [str(mid) for mid in batch]
                )
            except Exception as e:
                logger.warning(f"Chroma cleanup batch failed: {e}")

        # Delete batch from SQLite
        result = await self.session.execute(
            delete(Memory).where(Memory.id.in_(batch))
        )
        await self.session.commit()
        deleted += result.rowcount

        # Log progress every 1000 deletions
        if deleted % 1000 == 0:
            logger.info(f"Cleanup progress: {deleted}/{total} memories deleted")

    return deleted
```

### Security Test Cases

```python
# CRITICAL: Add to tests/security/test_pruning_authorization.py
class TestPruningAuthorization:
    """Security tests for pruning authorization."""

    async def test_cross_namespace_cleanup_blocked(self):
        """Cross-namespace cleanup should be blocked."""
        # Create agent in namespace-1
        agent = await create_test_agent(namespace="namespace-1")

        # Create memories in namespace-2
        await create_test_memory(namespace="namespace-2", importance=0.1)

        # Attempt to cleanup namespace-2 from namespace-1 agent
        with pytest.raises(AuthorizationError, match="not authorized"):
            await memory_service.cleanup_namespace(
                namespace="namespace-2",  # ❌ Different namespace
                agent_id=agent.agent_id,
                days=30,
                min_importance=0.3
            )

    async def test_destructive_importance_threshold_rejected(self):
        """High importance threshold (>0.8) should be rejected."""
        agent = await create_test_agent(namespace="test")

        with pytest.raises(ValidationError, match="threshold too high"):
            await memory_service.cleanup_namespace(
                namespace="test",
                agent_id=agent.agent_id,
                days=30,
                min_importance=0.9  # ❌ Too high
            )

    async def test_recent_memories_protected(self):
        """Memories younger than 30 days should be protected."""
        agent = await create_test_agent(namespace="test")

        with pytest.raises(ValidationError, match="at least 30"):
            await memory_service.cleanup_namespace(
                namespace="test",
                agent_id=agent.agent_id,
                days=7,  # ❌ Too recent
                min_importance=0.3
            )

    async def test_pruning_rate_limit(self):
        """Pruning should be rate limited (1 per hour)."""
        agent = await create_test_agent(namespace="test")

        # First cleanup - should succeed
        await memory_service.cleanup_namespace(
            namespace="test",
            agent_id=agent.agent_id,
            days=30,
            min_importance=0.3
        )

        # Second cleanup immediately after - should be rate limited
        with pytest.raises(HTTPException, match="rate limit"):
            await memory_service.cleanup_namespace(
                namespace="test",
                agent_id=agent.agent_id,
                days=30,
                min_importance=0.3
            )

    async def test_audit_log_on_cleanup(self):
        """Cleanup operations should be audited."""
        agent = await create_test_agent(namespace="test")

        # Perform cleanup
        await memory_service.cleanup_namespace(
            namespace="test",
            agent_id=agent.agent_id,
            days=90,
            min_importance=0.3
        )

        # Verify audit log exists
        logs = await get_audit_logs(action="namespace_cleanup_completed")
        assert len(logs) == 1
        assert logs[0].details["namespace"] == "test"
        assert logs[0].details["agent_id"] == agent.agent_id
```

### Audit Logging Requirements

**CRITICAL**: All pruning operations must be audited with BEFORE and AFTER states.

```python
# REQUIRED: Comprehensive audit logging
from src.security.security_audit_facade import get_audit_logger

audit_logger = get_audit_logger()

# Log authorization failures (CRITICAL severity)
audit_logger.log_critical(
    action="unauthorized_pruning_attempt",
    details={
        "agent_id": agent_id,
        "agent_namespace": agent.namespace,
        "target_namespace": namespace,
        "attempted_days": days,
        "attempted_min_importance": min_importance,
    },
    severity="CRITICAL"
)

# Log successful pruning (WARNING severity)
audit_logger.log_warning(
    action="namespace_cleanup_completed",
    details={
        "namespace": namespace,
        "agent_id": agent_id,
        "days": days,
        "min_importance": min_importance,
        "deleted_count": deleted_count,
        "memory_ids": memory_ids[:100],  # First 100 IDs
    },
    severity="WARNING"
)

# Alert if mass deletion detected
if deleted_count > 1000:
    audit_logger.log_critical(
        action="mass_deletion_detected",
        details={
            "namespace": namespace,
            "deleted_count": deleted_count,
            "agent_id": agent_id,
        },
        severity="CRITICAL"
    )

    # TODO: Send alert email to admin
    # await send_admin_alert(
    #     subject=f"Mass Deletion: {deleted_count} memories deleted",
    #     details={...}
    # )
```

---

## Threat Model 4: Namespace Isolation Verification

### Attack Surface Analysis

**Concern**: New methods must properly verify namespace from database.

#### Attack Vector V-NS-1: Namespace Spoofing in New Methods
**CVSS Score**: 9.1 (CRITICAL)
**CWE**: CWE-863 (Incorrect Authorization)

**Attack Scenario**:
```python
# If cleanup_namespace() trusts user input:
# Attacker claims to be in victim namespace via JWT manipulation

# Malicious JWT:
{
    "agent_id": "attacker",
    "namespace": "victim-namespace",  # ❌ Spoofed claim
    "exp": ...
}

# Vulnerable code (DO NOT IMPLEMENT):
async def cleanup_namespace(namespace: str, user: User):
    # ❌ WRONG: Trusts JWT claim
    if user.namespace != namespace:
        raise AuthorizationError(...)
    # Attacker bypasses check by spoofing JWT

# Secure code (CORRECT):
async def cleanup_namespace(namespace: str, agent_id: str):
    # ✅ CORRECT: Verify namespace from database
    agent = await db.get(Agent, agent_id)
    verified_namespace = agent.namespace  # From DB
    if verified_namespace != namespace:
        raise AuthorizationError(...)
```

**Impact**: Same as V-PRUNE-1 (data destruction across all tenants)

### Mitigation Strategy

#### 🛡️ Database-Verified Namespace Pattern

**MANDATORY**: All new methods MUST follow P0-1 security pattern.

```python
# PATTERN: Database-Verified Namespace (from P0-1 fix)
# REQUIRED for ALL new methods

async def any_new_method(
    self,
    namespace: str,  # Target namespace
    agent_id: str,   # Requesting agent
    ...
):
    """Any method that operates on namespace-scoped data.

    SECURITY-CRITICAL: P0-1 Database-Verified Namespace Pattern
    """
    # STEP 1: Fetch agent from database (VERIFY namespace)
    stmt = select(Agent).where(Agent.agent_id == agent_id)
    result = await self.session.execute(stmt)
    agent = result.scalar_one_or_none()

    if not agent:
        log_and_raise(
            AuthorizationError,
            "Agent not found",
            details={"agent_id": agent_id}
        )

    # STEP 2: Get VERIFIED namespace from database
    verified_namespace = agent.namespace  # ✅ From DB, not JWT

    # STEP 3: Verify namespace matches
    if verified_namespace != namespace:
        log_and_raise(
            AuthorizationError,
            f"Namespace mismatch: agent in {verified_namespace}, "
            f"requested {namespace}",
            details={
                "agent_id": agent_id,
                "verified_namespace": verified_namespace,
                "requested_namespace": namespace
            }
        )

    # STEP 4: Proceed with verified namespace
    # ... rest of method logic ...
```

#### 🛡️ Namespace Verification Checklist

**REQUIRED**: Every v2.3.0 method must pass this checklist:

```markdown
## Namespace Security Checklist

For each new method in v2.3.0:

- [ ] Method accepts `agent_id` parameter (NOT User object)
- [ ] Agent is fetched from database via SELECT query
- [ ] Namespace is extracted from Agent record (verified_namespace)
- [ ] Namespace comparison is performed BEFORE any data access
- [ ] Authorization failure is logged to audit log
- [ ] Method has security test for cross-namespace attempt
- [ ] Docstring includes SECURITY-CRITICAL warning
```

### Security Test Cases

```python
# REQUIRED: Add to tests/security/test_namespace_isolation_v230.py
class TestNamespaceIsolationV230:
    """Namespace isolation tests for v2.3.0 new methods."""

    async def test_prune_expired_respects_namespace(self):
        """prune_expired_memories() should only delete from caller's namespace."""
        # Create expired memories in two namespaces
        ns1_agent = await create_test_agent(namespace="ns1")
        ns2_agent = await create_test_agent(namespace="ns2")

        ns1_memory = await create_expired_memory(
            agent_id=ns1_agent.agent_id,
            namespace="ns1"
        )
        ns2_memory = await create_expired_memory(
            agent_id=ns2_agent.agent_id,
            namespace="ns2"
        )

        # Prune as ns1 agent
        deleted = await memory_service.prune_expired_memories(
            agent_id=ns1_agent.agent_id
        )

        # Verify only ns1 memory was deleted
        assert await memory_service.get_memory(ns1_memory.id) is None
        assert await memory_service.get_memory(ns2_memory.id) is not None

    async def test_get_namespace_stats_cross_namespace_blocked(self):
        """get_namespace_stats() should block cross-namespace access."""
        agent = await create_test_agent(namespace="ns1")

        # Attempt to get stats for different namespace
        with pytest.raises(AuthorizationError, match="not authorized"):
            await memory_service.get_namespace_stats(
                namespace="ns2",  # ❌ Different namespace
                agent_id=agent.agent_id
            )

    async def test_cleanup_namespace_jwt_spoofing_blocked(self):
        """JWT namespace spoofing should be blocked."""
        # This test simulates JWT manipulation attack
        # Even if attacker modifies JWT to claim different namespace,
        # database verification prevents attack

        agent = await create_test_agent(namespace="ns1")

        # Attacker tries to spoof namespace in request
        with pytest.raises(AuthorizationError):
            await memory_service.cleanup_namespace(
                namespace="ns2",  # ❌ Spoofed namespace
                agent_id=agent.agent_id,  # Real agent_id
                days=30,
                min_importance=0.3
            )
```

---

## Summary of Mitigation Priorities

### P0 (CRITICAL - Must Fix Before v2.3.0 Release)

1. **TTL Validation** (V-TTL-1, V-TTL-2, V-TTL-3)
   - Implement `validate_ttl_days()` function
   - Add TTL range limits (1-3650 days)
   - Add access-level based TTL limits
   - **Estimated Time**: 4 hours

2. **Pruning Authorization** (V-PRUNE-1)
   - Implement database-verified namespace check in `cleanup_namespace()`
   - Add `agent_id` parameter to all pruning methods
   - Add authorization audit logging
   - **Estimated Time**: 6 hours

3. **Namespace Isolation** (V-NS-1)
   - Verify all new methods follow P0-1 pattern
   - Add namespace verification to `prune_expired_memories()`
   - Add namespace verification to `get_namespace_stats()`
   - **Estimated Time**: 4 hours

**Total P0 Time**: 14 hours (2 days)

### P1 (HIGH - Should Fix Before v2.3.0 Release)

4. **Access Tracking Rate Limiting** (V-ACCESS-2)
   - Implement 5-second rate limit in `update_access()`
   - Cap access_count at 10,000
   - **Estimated Time**: 2 hours

5. **Cleanup Parameter Validation** (V-PRUNE-2)
   - Implement `validate_cleanup_parameters()`
   - Enforce min_days=30, max_importance=0.79
   - **Estimated Time**: 2 hours

6. **Pruning Rate Limiting** (V-PRUNE-3)
   - Add rate limits to RateLimiter
   - Implement batch deletion with progress tracking
   - **Estimated Time**: 3 hours

**Total P1 Time**: 7 hours (1 day)

### P2 (MEDIUM - Nice to Have)

7. **Access Tracking Privacy** (V-ACCESS-1)
   - Disable access tracking for SYSTEM-level memories
   - Anonymize timestamps to nearest hour
   - **Estimated Time**: 2 hours

8. **Mass Deletion Alerts**
   - Send admin email when deleted_count > 1000
   - **Estimated Time**: 2 hours

**Total P2 Time**: 4 hours (0.5 days)

---

## Security Test Coverage Goals

### Test Suite Summary

| Test Suite | Tests | Coverage | Priority |
|------------|-------|----------|----------|
| `test_ttl_validation.py` | 8 tests | TTL input validation | P0 |
| `test_access_tracking.py` | 5 tests | Access privacy | P1 |
| `test_pruning_authorization.py` | 6 tests | Pruning authorization | P0 |
| `test_namespace_isolation_v230.py` | 4 tests | Namespace verification | P0 |
| **TOTAL** | **23 tests** | **v2.3.0 security** | **Required** |

### Test Execution

```bash
# Run all security tests
pytest tests/security/ -v

# Run v2.3.0 security tests only
pytest tests/security/test_ttl_validation.py \
       tests/security/test_access_tracking.py \
       tests/security/test_pruning_authorization.py \
       tests/security/test_namespace_isolation_v230.py \
       -v

# Expected: 23/23 PASSED
```

---

## Audit Logging Requirements

### Events to Log

| Event | Severity | Details Required |
|-------|----------|------------------|
| `memory_ttl_set` | INFO | memory_id, ttl_days, expires_at, access_level |
| `memory_ttl_validation_failed` | WARNING | ttl_days, access_level, validation_errors |
| `unauthorized_namespace_cleanup_attempt` | CRITICAL | agent_id, agent_namespace, target_namespace |
| `namespace_cleanup_started` | WARNING | namespace, days, min_importance, count |
| `namespace_cleanup_completed` | WARNING | namespace, deleted_count |
| `mass_deletion_detected` | CRITICAL | namespace, deleted_count, agent_id |
| `high_access_count_detected` | WARNING | memory_id, access_count |
| `prune_expired_started` | INFO | agent_id, namespace, expired_count |
| `prune_expired_completed` | INFO | deleted_count, duration_ms |

### Audit Query Examples

```sql
-- Find all unauthorized cleanup attempts (security incidents)
SELECT * FROM security_audit_logs
WHERE action = 'unauthorized_namespace_cleanup_attempt'
ORDER BY created_at DESC;

-- Find all mass deletions (>1000 memories)
SELECT * FROM security_audit_logs
WHERE action = 'mass_deletion_detected'
ORDER BY created_at DESC;

-- Find all TTL validation failures (potential attacks)
SELECT * FROM security_audit_logs
WHERE action = 'memory_ttl_validation_failed'
  AND details->>'ttl_days' > '3650'
ORDER BY created_at DESC;
```

---

## Deployment Recommendations

### Pre-Deployment Checklist

Before deploying v2.3.0 to production:

- [ ] All P0 security fixes implemented
- [ ] All P1 security fixes implemented
- [ ] All 23 security tests passing
- [ ] Audit logging tested end-to-end
- [ ] Rate limiting configured for pruning operations
- [ ] Backup/restore procedure tested
- [ ] Rollback plan documented
- [ ] Security team notified of new attack surface

### Phased Rollout

**Recommendation**: Deploy v2.3.0 in phases to minimize risk.

1. **Phase 1: Staging (1 week)**
   - Deploy to staging environment
   - Run security penetration testing
   - Verify audit logs are complete
   - Test all worst-case scenarios

2. **Phase 2: Canary (1 week)**
   - Deploy to 5% of production users
   - Monitor audit logs for suspicious activity
   - Monitor performance metrics
   - Verify no cross-namespace access

3. **Phase 3: Full Production (2 weeks)**
   - Gradual rollout to 100% of users
   - 24/7 monitoring for first week
   - Security team on-call for incidents

---

## Conclusion

...すみません、多くのセキュリティリスクが見つかりました...でも、全て対応可能です...

### Risk Summary

| Risk Level | Count | Must Fix |
|-----------|-------|----------|
| 🔴 CRITICAL | 2 | Yes (P0) |
| 🔴 HIGH | 3 | Yes (P0-P1) |
| 🟡 MEDIUM | 4 | Recommended (P1-P2) |
| **TOTAL** | **9** | **5 P0, 3 P1, 1 P2** |

### Estimated Fix Time

- **P0 (CRITICAL)**: 14 hours (2 days)
- **P1 (HIGH)**: 7 hours (1 day)
- **P2 (MEDIUM)**: 4 hours (0.5 days)
- **Total**: 25 hours (3.5 days)

### Recommendation

**v2.3.0 is SAFE to implement** if:
1. All P0 security fixes are implemented BEFORE service layer development
2. All 23 security tests are added and passing
3. Audit logging is comprehensive
4. Phased rollout is followed

...でも、最悪のケースを想定して、全ての対策を実装してください...お願いします...

---

**End of Security Threat Assessment**

*Prepared with paranoid diligence by Hestia 🔥*
*"Better to be paranoid and secure than optimistic and breached."*
