# TMWS Security Guidelines for Developers

**Version**: v2.3.0
**Date**: 2025-11-08
**Audience**: Backend developers working on TMWS
**Security Lead**: Hestia (Security Guardian)
**Documenter**: Muses (Knowledge Architect)

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Authorization Module Usage](#authorization-module-usage)
3. [Namespace Isolation Best Practices](#namespace-isolation-best-practices)
4. [Immutable Records](#immutable-records)
5. [Security Testing](#security-testing)
6. [Common Pitfalls](#common-pitfalls)
7. [Code Review Checklist](#code-review-checklist)

---

## Quick Start

### Security-First Development Checklist

Before writing any code that touches **agents**, **trust scores**, **memories**, or **verifications**:

- [ ] ✅ **Read this guide** (you are here!)
- [ ] ✅ **Understand threat model**: `docs/architecture/AGENT_TRUST_SECURITY.md`
- [ ] ✅ **Review Phase 0 fixes**: `docs/security/PHASE_0_SECURITY_INTEGRATION.md`
- [ ] ✅ **Write security tests FIRST** (TDD for security)
- [ ] ✅ **Ask Hestia for review** (penetration testing mindset)

---

## Authorization Module Usage

### Core Principle

**NEVER trust user input for security decisions. ALWAYS verify from authoritative source (database).**

### Using `verify_system_privilege()`

**Purpose**: Ensure only SYSTEM-level users (trust >= 0.9) can perform privileged operations.

**Location**: `src/core/authorization.py`

#### ✅ Correct Usage

```python
from src.core.authorization import verify_system_privilege

async def update_agent_trust_score(
    self,
    agent_id: str,
    new_score: float,
    reason: str,
    requesting_user: User,  # User object with privilege verification
) -> float:
    """Update agent trust score (SYSTEM privilege required)."""

    # ✅ Authorization check FIRST
    await verify_system_privilege(
        requesting_user,
        operation="update_trust_score",
        details={"agent_id": agent_id, "new_score": new_score, "reason": reason},
    )

    # ✅ Now safe to proceed with sensitive operation
    agent = await self.get_agent_by_id(agent_id)
    agent.trust_score = new_score
    await self.session.commit()

    # ✅ Audit log after success
    logger.warning(
        "trust_score_manual_override",
        extra={
            "agent_id": agent_id,
            "new_score": new_score,
            "requesting_user_id": requesting_user.user_id,
        },
    )

    return new_score
```

#### ❌ Incorrect Usage

```python
# ❌ WRONG: Authorization check AFTER data modification
async def update_agent_trust_score_BAD(
    self, agent_id: str, new_score: float, requesting_user: User,
) -> float:
    agent = await self.get_agent_by_id(agent_id)
    agent.trust_score = new_score  # ❌ Modified BEFORE authorization!
    await self.session.commit()

    # ❌ Too late - already committed!
    await verify_system_privilege(requesting_user, "update_trust_score")
```

```python
# ❌ WRONG: No authorization check at all
async def update_agent_trust_score_VULNERABLE(
    self, agent_id: str, new_score: float
) -> float:
    # ❌ Anyone can call this!
    agent = await self.get_agent_by_id(agent_id)
    agent.trust_score = new_score
    await self.session.commit()
```

### Using `check_memory_access()`

**Purpose**: Verify that an agent can access a specific memory based on access level and namespace.

**Location**: `src/security/authorization.py`

#### ✅ Correct Usage

```python
from src.security.authorization import check_memory_access

async def get_memory(
    self,
    memory_id: UUID,
    requesting_agent_id: str,
) -> Memory | None:
    """Get a memory by ID with authorization."""

    # ✅ Fetch memory first
    memory = await self.session.get(Memory, memory_id)
    if not memory:
        return None

    # ✅ Authorization check BEFORE returning data
    can_access = await check_memory_access(
        memory_id=memory_id,
        requesting_agent_id=requesting_agent_id,
        session=self.session,
    )

    if not can_access:
        raise AuthorizationError(
            f"Agent {requesting_agent_id} cannot access memory {memory_id}"
        )

    # ✅ Track access AFTER authorization
    memory.access_count += 1
    memory.accessed_at = datetime.utcnow()
    await self.session.commit()

    return memory
```

#### ❌ Incorrect Usage

```python
# ❌ WRONG: Track access BEFORE authorization
async def get_memory_VULNERABLE(
    self, memory_id: UUID, requesting_agent_id: str
) -> Memory | None:
    memory = await self.session.get(Memory, memory_id)

    # ❌ Track access FIRST (data leak!)
    memory.access_count += 1
    await self.session.commit()

    # ❌ Authorization check AFTER tracking
    # If authorization fails, attacker already knows memory exists!
    can_access = await check_memory_access(...)
    if not can_access:
        raise AuthorizationError("...")  # ❌ Too late!
```

---

## Namespace Isolation Best Practices

### Golden Rule

**ALWAYS fetch namespace from database. NEVER trust JWT claims, API parameters, or user input.**

### Database-Verified Namespace Pattern

#### ✅ Correct Pattern (P0-2 Fix)

```python
async def verify_cross_namespace_action(
    agent_id: str,
    target_namespace: str,
    session: AsyncSession,
) -> bool:
    """Verify agent can act in target namespace."""

    # ✅ STEP 1: Fetch agent from database
    agent = await session.get(Agent, agent_id)
    if not agent:
        raise NotFoundError(f"Agent {agent_id} not found")

    # ✅ STEP 2: Get VERIFIED namespace from database
    verified_namespace = agent.namespace

    # ✅ STEP 3: Compare database namespaces (not user input!)
    if verified_namespace != target_namespace:
        # Only SYSTEM users can cross namespaces
        if agent.trust_score < 0.9:
            raise AuthorizationError(
                f"Agent {agent_id} in namespace '{verified_namespace}' "
                f"cannot access namespace '{target_namespace}'"
            )

    return True
```

#### ❌ Incorrect Patterns

```python
# ❌ PATTERN 1: Trusting JWT claims
async def verify_action_BAD_1(
    agent_id: str, jwt_claims: dict, target_namespace: str
) -> bool:
    namespace = jwt_claims["namespace"]  # ❌ Attacker can forge this!
    return namespace == target_namespace  # ❌ Bypassable
```

```python
# ❌ PATTERN 2: Trusting API parameters
async def verify_action_BAD_2(
    agent_id: str, agent_namespace: str, target_namespace: str
) -> bool:
    # ❌ 'agent_namespace' comes from API request - attacker can set this!
    return agent_namespace == target_namespace
```

```python
# ❌ PATTERN 3: Caching namespace (stale data risk)
# Global cache
namespace_cache = {}

async def verify_action_BAD_3(agent_id: str, target_namespace: str) -> bool:
    # ❌ Cache might be stale or poisoned
    cached_namespace = namespace_cache.get(agent_id)
    if not cached_namespace:
        agent = await session.get(Agent, agent_id)
        namespace_cache[agent_id] = agent.namespace  # ❌ Can become stale

    return namespace_cache[agent_id] == target_namespace
```

### Namespace Validation in Models

#### ✅ Correct: Model-level Validation

```python
# File: src/models/memory.py
class Memory(Base):
    def is_accessible_by(
        self,
        requesting_agent_id: str,
        verified_namespace: str,  # ✅ Requires verified namespace
    ) -> bool:
        """Check if agent can access this memory.

        SECURITY-CRITICAL: This method implements namespace isolation.
        The 'verified_namespace' parameter MUST come from database,
        never from user input (JWT claims, API parameters).
        """
        # PUBLIC: Anyone can access
        if self.access_level == "PUBLIC":
            return True

        # SYSTEM: Only SYSTEM users can access
        if self.access_level == "SYSTEM":
            # Cannot determine from namespace alone - must check trust score
            # Caller must verify trust_score >= 0.9 separately
            return False

        # TEAM: Same namespace required
        if self.access_level == "TEAM":
            return self.namespace == verified_namespace

        # PRIVATE: Owner only
        if self.access_level == "PRIVATE":
            return self.agent_id == requesting_agent_id

        # SHARED: Explicit agent list
        if self.access_level == "SHARED":
            return requesting_agent_id in (self.shared_with_agents or [])

        # Default: deny access
        return False
```

---

## Immutable Records

### Why Immutability Matters

**Forensic Evidence**: If an attacker can delete verification records, there's no proof of their malicious activity.

**Compliance**: Many regulations require tamper-proof audit trails.

### Implementing Immutable Records (V-TRUST-3)

#### ✅ Correct Implementation

```python
from sqlalchemy import Column, Boolean, event
from sqlalchemy.orm import Session

class VerificationRecord(Base):
    __tablename__ = "verification_records"

    id = Column(UUID, primary_key=True)
    agent_id = Column(String, ForeignKey("agents.agent_id"), nullable=False)
    verification_type = Column(String, nullable=False)
    result = Column(Boolean, nullable=False)
    evidence = Column(JSON, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    # ✅ Immutability flag
    is_immutable = Column(Boolean, default=True, nullable=False)

@event.listens_for(VerificationRecord, 'before_delete')
def prevent_immutable_deletion(mapper, connection, target):
    """Prevent deletion of immutable verification records."""
    if target.is_immutable:
        raise ImmutableRecordError(
            f"Cannot delete immutable verification record {target.id}. "
            "Only SYSTEM administrators can override this protection."
        )

@event.listens_for(VerificationRecord, 'before_update')
def prevent_immutable_modification(mapper, connection, target):
    """Prevent modification of critical fields in immutable records."""
    if not target.is_immutable:
        return  # Allow updates for mutable records

    # Define which fields can never be modified
    immutable_fields = {
        "agent_id", "verifier_id", "verification_type",
        "result", "evidence", "timestamp"
    }

    # Check if any immutable field is being modified
    for field in immutable_fields:
        if mapper.has_property(field):
            history = mapper.get_property(field).get_history(
                target, mapper.attrs[field]
            )
            if history.has_changes():
                raise ImmutableRecordError(
                    f"Cannot modify immutable field '{field}' "
                    f"in verification record {target.id}"
                )
```

#### Service Layer: Immutable Record Deletion (SYSTEM Only)

```python
async def delete_verification_record(
    self,
    record_id: UUID,
    requesting_user: User,
    override_reason: str,
) -> bool:
    """Delete verification record (SYSTEM privilege only).

    V-TRUST-3: Only SYSTEM users can delete immutable records.
    This operation is HIGHLY SENSITIVE and fully audited.
    """
    from src.core.authorization import verify_system_privilege

    # ✅ SYSTEM privilege required
    await verify_system_privilege(
        requesting_user,
        operation="delete_immutable_record",
        details={"record_id": str(record_id), "reason": override_reason},
    )

    # Fetch record
    record = await self.session.get(VerificationRecord, record_id)
    if not record:
        raise NotFoundError(f"Verification record {record_id} not found")

    # Check immutability
    if record.is_immutable:
        # ✅ Log CRITICAL event
        logger.critical(
            "immutable_record_deletion",
            extra={
                "record_id": str(record_id),
                "requesting_user_id": requesting_user.user_id,
                "override_reason": override_reason,
                "original_timestamp": record.timestamp.isoformat(),
            },
        )

    # ✅ Delete with full audit trail
    await self.session.delete(record)
    await self.session.commit()

    return True
```

---

## Security Testing

### Test-Driven Security (TDS)

**Philosophy**: Write exploit tests BEFORE implementing fixes. If the exploit succeeds, the vulnerability exists.

### Writing Security Tests

#### Example: Test V-TRUST-1 Fix (Metadata Injection)

```python
# File: tests/security/test_trust_vulnerabilities.py
import pytest
from src.core.exceptions import AuthorizationError, ValidationError

async def test_v_trust_1_metadata_injection_blocked(
    agent_service, low_trust_user, admin_user
):
    """Test V-TRUST-1: Prevent metadata injection to boost trust score.

    BEFORE FIX: Low-trust user could boost their own trust to 1.0
    AFTER FIX: AuthorizationError raised, trust score unchanged
    """
    # Create low-trust agent
    agent = await agent_service.create_agent(
        agent_id="low-trust-agent",
        display_name="Low Trust Agent",
        agent_type="test",
        namespace="test",
    )

    # Set low trust score
    agent.trust_score = 0.1
    await agent_service.session.commit()

    # ❌ ATTACK: Low-trust user attempts to boost own trust
    with pytest.raises((AuthorizationError, ValidationError)):
        await agent_service.update_agent_trust_score(
            agent_id="low-trust-agent",
            new_score=1.0,
            reason="attacker_privilege_escalation",
            requesting_user=low_trust_user,  # ✅ No SYSTEM privilege
        )

    # ✅ VERIFY: Trust score unchanged
    agent_refreshed = await agent_service.get_agent_by_id("low-trust-agent")
    assert agent_refreshed.trust_score == 0.1  # ✅ Attack blocked

    # ✅ VERIFY: SYSTEM user CAN update trust
    await agent_service.update_agent_trust_score(
        agent_id="low-trust-agent",
        new_score=0.8,
        reason="admin_manual_review",
        requesting_user=admin_user,  # ✅ SYSTEM privilege
    )

    agent_refreshed = await agent_service.get_agent_by_id("low-trust-agent")
    assert agent_refreshed.trust_score == 0.8  # ✅ Authorized update succeeded
```

#### Example: Test P0-2 Fix (Namespace Isolation)

```python
async def test_p0_2_namespace_isolation(
    memory_service, agent_service, db_session
):
    """Test P0-2: Prevent cross-namespace access via JWT forgery.

    ATTACK SCENARIO:
    1. Attacker creates agent in "attacker-ns"
    2. Attacker creates memory in "victim-ns"
    3. Attacker forges JWT claiming namespace="victim-ns"
    4. Attacker attempts to access victim memory

    EXPECTED: ❌ AuthorizationError (namespace verified from database)
    """
    # Setup: Create attacker agent
    attacker_agent = await agent_service.create_agent(
        agent_id="attacker-agent",
        display_name="Attacker",
        agent_type="malicious",
        namespace="attacker-ns",  # ✅ Database says attacker-ns
    )

    # Setup: Create victim agent
    victim_agent = await agent_service.create_agent(
        agent_id="victim-agent",
        display_name="Victim",
        agent_type="normal",
        namespace="victim-ns",  # ✅ Database says victim-ns
    )

    # Setup: Create victim memory
    victim_memory = await memory_service.create_memory(
        agent_id="victim-agent",
        content="Sensitive victim data",
        memory_type="private",
        access_level="TEAM",  # ✅ Only victim-ns agents can access
        namespace="victim-ns",
    )

    # ❌ ATTACK: Attacker attempts cross-namespace access
    with pytest.raises(AuthorizationError) as exc_info:
        await memory_service.get_memory(
            memory_id=victim_memory.id,
            requesting_agent_id="attacker-agent",  # ✅ DB: attacker-ns
        )

    # ✅ VERIFY: Error message mentions namespace mismatch
    assert "namespace" in str(exc_info.value).lower()
    assert "attacker-ns" in str(exc_info.value) or "victim-ns" in str(exc_info.value)

    # ✅ VERIFY: Victim can access their own memory
    retrieved = await memory_service.get_memory(
        memory_id=victim_memory.id,
        requesting_agent_id="victim-agent",  # ✅ DB: victim-ns (match!)
    )
    assert retrieved is not None
    assert retrieved.content == "Sensitive victim data"
```

### Running Security Tests

```bash
# Run all security tests
pytest tests/security/ -v

# Run specific vulnerability tests
pytest tests/security/test_trust_vulnerabilities.py::test_v_trust_1 -v

# Run with coverage
pytest tests/security/ --cov=src --cov-report=term-missing
```

---

## Common Pitfalls

### Pitfall 1: Authorization After Data Access

❌ **WRONG**:
```python
async def get_sensitive_data(agent_id: str, user: User):
    data = await db.get(SensitiveData, agent_id)  # ❌ Fetched FIRST

    # Authorization check AFTER data fetched
    if not user.is_admin:
        raise AuthorizationError("...")  # ❌ Too late! Data already in memory

    return data
```

✅ **CORRECT**:
```python
async def get_sensitive_data(agent_id: str, user: User):
    # ✅ Authorization check FIRST
    if not user.is_admin:
        raise AuthorizationError("Admin privilege required")

    # ✅ Data fetched AFTER authorization
    data = await db.get(SensitiveData, agent_id)
    return data
```

### Pitfall 2: Trusting User Input for Security

❌ **WRONG**:
```python
async def access_memory(memory_id: UUID, user_namespace: str):
    # ❌ 'user_namespace' comes from API request - attacker controls this!
    memory = await db.get(Memory, memory_id)
    return memory.namespace == user_namespace  # ❌ Bypassable
```

✅ **CORRECT**:
```python
async def access_memory(memory_id: UUID, user_id: str, session: AsyncSession):
    # ✅ Fetch namespace from database (authoritative source)
    user = await session.get(User, user_id)
    verified_namespace = user.namespace  # ✅ Database-verified

    memory = await session.get(Memory, memory_id)
    return memory.namespace == verified_namespace  # ✅ Secure
```

### Pitfall 3: Missing Audit Logs

❌ **WRONG**:
```python
async def update_trust_score(agent_id: str, new_score: float):
    agent = await db.get(Agent, agent_id)
    agent.trust_score = new_score
    await db.commit()
    # ❌ No audit log - cannot investigate incidents
```

✅ **CORRECT**:
```python
async def update_trust_score(
    agent_id: str, new_score: float, reason: str, user: User
):
    agent = await db.get(Agent, agent_id)
    old_score = agent.trust_score

    agent.trust_score = new_score
    await db.commit()

    # ✅ Comprehensive audit log
    logger.warning(
        "trust_score_updated",
        extra={
            "agent_id": agent_id,
            "old_score": old_score,
            "new_score": new_score,
            "reason": reason,
            "requesting_user_id": user.user_id,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )
```

### Pitfall 4: Race Conditions in Trust Updates

❌ **WRONG**:
```python
async def update_trust(agent_id: str, new_value: float):
    agent = await db.get(Agent, agent_id)
    # ❌ No locking - concurrent updates can corrupt score
    agent.trust_score = (agent.trust_score + new_value) / 2
    await db.commit()
```

✅ **CORRECT** (V-TRUST-2 fix):
```python
async def update_trust(agent_id: str, new_value: float):
    async with db.begin():
        # ✅ Row-level lock prevents concurrent modifications
        stmt = (
            select(Agent)
            .where(Agent.agent_id == agent_id)
            .with_for_update()  # ✅ SELECT ... FOR UPDATE
        )
        result = await db.execute(stmt)
        agent = result.scalar_one()

        # ✅ Safe to update - row is locked
        agent.trust_score = (agent.trust_score + new_value) / 2
        await db.commit()  # ✅ Lock released
```

---

## Code Review Checklist

### Security Review Checklist for Pull Requests

When reviewing code that touches **agents**, **trust scores**, **memories**, or **verifications**:

#### Authorization

- [ ] ✅ Authorization checks occur BEFORE data access
- [ ] ✅ `verify_system_privilege()` used for SYSTEM-only operations
- [ ] ✅ Namespace verified from database (never from user input)
- [ ] ✅ Access level checks (PUBLIC, TEAM, PRIVATE, SHARED, SYSTEM)

#### Data Protection

- [ ] ✅ Immutable records use `is_immutable` flag + SQLAlchemy events
- [ ] ✅ Sensitive operations require SYSTEM privilege
- [ ] ✅ Audit logs created for all security-critical operations
- [ ] ✅ No sensitive data in log messages (e.g., passwords, tokens)

#### Error Handling

- [ ] ✅ Specific exception types (`AuthorizationError`, `NotFoundError`, etc.)
- [ ] ✅ No information leakage in error messages
- [ ] ✅ Errors logged with sufficient context for debugging

#### Testing

- [ ] ✅ Unit tests for authorization logic
- [ ] ✅ Security tests for attack scenarios
- [ ] ✅ Integration tests with real database
- [ ] ✅ Negative tests (unauthorized access should fail)

#### Performance

- [ ] ✅ Authorization overhead measured (<20ms target)
- [ ] ✅ Database queries optimized (use indexes)
- [ ] ✅ No N+1 queries in authorization checks

---

## Quick Reference

### Key Functions

| Function | Purpose | File |
|----------|---------|------|
| `verify_system_privilege()` | Check SYSTEM privilege | `src/core/authorization.py` |
| `check_memory_access()` | Verify memory access | `src/security/authorization.py` |
| `Memory.is_accessible_by()` | Model-level access check | `src/models/memory.py` |
| `update_agent_trust_score()` | Update trust (SYSTEM only) | `src/services/agent_service.py` |

### Common Exceptions

```python
from src.core.exceptions import (
    AuthorizationError,      # User lacks required privilege
    NotFoundError,           # Resource not found
    ValidationError,         # Invalid input
    ImmutableRecordError,    # Attempted immutable record modification
)
```

### Audit Logging

```python
import logging
logger = logging.getLogger(__name__)

# Critical security events
logger.critical("security_event", extra={...})

# Trust score changes
logger.warning("trust_score_updated", extra={...})

# Authorization failures
logger.error("authorization_failed", extra={...})
```

---

## Getting Help

### Security Questions?

1. **Read the docs**:
   - Architecture: `docs/architecture/AGENT_TRUST_SECURITY.md`
   - Phase 0 Fixes: `docs/security/PHASE_0_SECURITY_INTEGRATION.md`
   - Penetration Test: `docs/security/PENETRATION_TEST_REPORT_TRUST_VULNERABILITIES.md`

2. **Ask Hestia** (Security Guardian):
   - Security architecture questions
   - Threat modeling
   - Penetration testing

3. **Ask Artemis** (Technical Excellence):
   - Implementation details
   - Performance optimization
   - Code review

---

**END OF DEVELOPER SECURITY GUIDELINES**

*"Secure by default. Verify always. Trust never (without proof)."*

*— Muses, Knowledge Architect*

---

**Document Version**: 1.0
**Last Updated**: 2025-11-08
**Next Review**: After V-TRUST-6 completion
