# RBAC Implementation Guide

## Overview

This guide describes the Role-Based Access Control (RBAC) system implemented in TMWS for the license management MCP tools. The RBAC system enforces the principle of least privilege, ensuring agents can only perform operations appropriate to their assigned role.

## Architecture

The RBAC system uses a hierarchical role model with fail-secure defaults:

- **Roles**: Assigned to agents, define broad access categories
- **Permissions**: Granular capabilities (e.g., `license:generate`, `license:revoke`)
- **Namespace Isolation**: Cross-namespace access is prohibited by default

## Roles

### viewer (Read-only)

**Permissions**:

- `license:read` - Validate license keys and view usage data
- [To be filled from Hestia's permission matrix]

**Use Case**:

Auditors, monitoring systems, and read-only dashboards that need to check license status without modifying data.

**Prohibited Operations**:

- Generate new license keys
- Revoke license keys
- Modify license configurations

---

### editor (Read-write)

**Permissions**:

- `license:read` - All viewer permissions
- `license:generate` - Create new license keys
- [To be filled from Hestia's permission matrix]

**Use Case**:

Service accounts, automation systems, and trusted agents that provision licenses for new agents or services.

**Prohibited Operations**:

- Revoke license keys (requires admin role)
- Modify RBAC role assignments

---

### admin (Full control)

**Permissions**:

- `license:read` - All viewer permissions
- `license:generate` - All editor permissions
- `license:revoke` - Revoke license keys
- `license:admin` - Administrative operations
- [To be filled from Hestia's permission matrix]

**Use Case**:

System administrators, security teams, and compliance officers who need full control over license lifecycle.

**Additional Capabilities**:

- Emergency license revocation
- Cross-namespace audit (within same organization)
- RBAC role management

---

## Permission Check Flow

```mermaid
[To be filled in Wave 3 with Artemis's implementation]
```

## Security Boundaries

### Namespace Isolation

**Principle**: Agents can only manage licenses within their own namespace.

**Implementation**:

[To be filled from Hestia's security design]

**Example**:

- Agent A (namespace: `project-alpha`) attempts to validate a license for Agent B (namespace: `project-beta`)
- **Result**: Permission denied, even if Agent A has `license:read` permission
- **Rationale**: Namespace boundary enforces tenant isolation

**Exceptions**:

- System-level admin agents with `SYSTEM` access level may perform cross-namespace audits
- Requires explicit audit logging and justification

---

### Fail-Secure Defaults

**Principle**: When in doubt, deny access.

**Implementation**:

[To be filled from Hestia's security design]

**Examples**:

1. **Missing Role Assignment**: Agent has no role → All operations denied
2. **Ambiguous Permission**: Unclear if operation requires `license:read` or `license:generate` → Deny and log
3. **Database Connection Failure**: Cannot verify permissions → Deny operation, do not proceed

**Rationale**: Security failures must never grant unintended access.

---

### Audit Logging

**Principle**: All permission checks and license operations are logged.

**Logged Events**:

[To be filled from Hestia's security design]

**Log Fields**:

- Timestamp (ISO 8601)
- Agent ID (UUID)
- Operation attempted (e.g., `license:generate`)
- Result (success/failure)
- Reason for failure (if applicable)
- IP address (if available)
- Request ID (for correlation)

**Retention**:

- Security audit logs: 90 days minimum
- Compliance logs: Per regulatory requirements

---

## Common Scenarios

### Scenario 1: Generate License Key

**Actor**: Agent with `editor` role

**Steps**:

1. Agent calls `generate_license_key` MCP tool with tier="PRO", expires_days=365
2. `@require_permission("license:generate")` decorator intercepts the call
3. Decorator fetches agent from database (verified namespace)
4. Decorator checks `license:generate` permission → ALLOWED (editor has this permission)
5. LicenseService generates key with HMAC checksum
6. License record persisted to `license_keys` table
7. Security audit log records: "ALLOW" for `license:generate`
8. License key returned to caller

**Permission Check**:

1. Verify agent has `license:generate` permission ✅
2. Verify target agent_id exists in database ✅
3. Verify rate limits not exceeded ✅ (handled by MCP layer)
4. Log operation attempt ✅ (audit log in security_audit_logs table)

**Result**:

- **Success**: License key generated and returned (e.g., `TMWS-PRO-a1b2c3d4-e5f6-7890-abcd-ef1234567890-A3F9`)
- **Failure**: PermissionError with specific reason (e.g., "Role viewer lacks permission for operation license:generate")

---

### Scenario 2: Validate License Key

**Actor**: Agent with `viewer` role

**Steps**:

1. Agent calls `validate_license_key` MCP tool with key="TMWS-PRO-..."
2. `@require_permission("license:validate")` decorator intercepts
3. Decorator checks `license:validate` permission → ALLOWED (viewer has this permission)
4. LicenseService validates checksum (HMAC-SHA256)
5. LicenseService checks expiration and revocation status
6. Validation result returned with tier, expiration, and validity status

**Permission Check**:

1. Verify agent has `license:validate` permission ✅ (viewer, editor, admin all have this)
2. Verify license key format (TMWS-{TIER}-{UUID}-{CHECKSUM}) ✅
3. Log validation attempt ✅

**Result**:

- **Success**: Validation result returned (valid/invalid/expired/revoked)
- **Failure**: ValidationError if format is invalid

---

### Scenario 3: Cross-Namespace Access Attempt (Blocked)

**Actor**: Agent in namespace `alpha` attempting to read license in namespace `beta`

**Steps**:

1. Agent A (namespace: alpha) calls `get_license_usage` for license owned by Agent B (namespace: beta)
2. `@require_permission("license:usage:read")` decorator intercepts
3. Decorator fetches Agent A from database → verified namespace = "alpha"
4. Decorator fetches license record → license.namespace = "beta"
5. Namespace isolation check FAILS (alpha ≠ beta)
6. PermissionError raised with message: "Cannot access resources in namespace beta from namespace alpha"
7. Security audit log records: "DENY" with severity: HIGH

**Permission Check**:

1. Verify agent has `license:usage:read` permission ✅ (passes)
2. Verify namespace isolation → FAILS (alpha ≠ beta)
3. Log security boundary violation ✅ (severity: HIGH)
4. Return PermissionError ✅

**Expected Behavior**:

- Operation denied immediately (no data leaked)
- Audit log entry created with severity: HIGH
- No information leaked about existence of target namespace
- Error message does not confirm or deny namespace existence

---

## Implementation Details

### Permission Checking in Services

Services check permissions using the `check_permission()` function from `src/security/rbac.py`:

```python
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from src.security.rbac import check_permission
from src.core.exceptions import PermissionError, log_and_raise

async def check_license_generation_permission(
    db_session: AsyncSession,
    agent_id: UUID
) -> None:
    """Check if agent can generate licenses (editor/admin role)."""
    allowed = await check_permission(
        db_session=db_session,
        agent_id=agent_id,
        operation="license:generate"
    )

    if not allowed:
        log_and_raise(
            PermissionError,
            f"Agent {agent_id} lacks permission for license:generate",
            details={
                "agent_id": str(agent_id),
                "operation": "license:generate",
                "required_role": "editor or admin"
            }
        )

async def check_license_read_permission_with_ownership(
    db_session: AsyncSession,
    agent_id: UUID,
    license_owner_id: UUID
) -> None:
    """Check if agent can read a specific license (ownership check)."""
    allowed = await check_permission(
        db_session=db_session,
        agent_id=agent_id,
        operation="license:read",
        resource_owner_id=license_owner_id  # Ownership verification
    )

    if not allowed:
        log_and_raise(
            PermissionError,
            f"Agent {agent_id} cannot read license owned by {license_owner_id}",
            details={
                "agent_id": str(agent_id),
                "license_owner_id": str(license_owner_id),
                "operation": "license:read",
                "reason": "Ownership check failed (non-admin cannot read other's licenses)"
            }
        )
```

**Why explicit checks matter**: These examples show how services can enforce permissions before executing business logic, providing clear error messages when access is denied.

---

### Applying @require_permission Decorator

MCP tools use the `@require_permission` decorator to enforce permissions automatically:

```python
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from src.security.rbac import require_permission
from typing import Any

@require_permission("license:generate")
async def generate_license_key_tool(
    db_session: AsyncSession,
    agent_id: UUID,  # Required by decorator for RBAC
    tier: str,
    expires_days: int | None = None
) -> dict[str, Any]:
    """MCP tool for generating license keys (editor/admin only).

    The @require_permission decorator:
    1. Fetches agent from database (verified namespace)
    2. Checks if agent has "license:generate" permission
    3. Logs permission check to security_audit_logs
    4. Raises PermissionError if denied
    5. Executes function if allowed

    Args:
        db_session: Required by decorator for DB access
        agent_id: Required by decorator for permission check
        tier: License tier (FREE/PRO/ENTERPRISE)
        expires_days: Days until expiration (None = perpetual)

    Returns:
        License key generation result

    Raises:
        PermissionError: If agent lacks editor/admin role
    """
    # Permission check happens automatically before this code runs
    # Implementation code here...
    return {"license_key": "TMWS-PRO-..."}

@require_permission("license:revoke")
async def revoke_license_key_tool(
    db_session: AsyncSession,
    agent_id: UUID,  # Required by decorator
    license_id: UUID,
    reason: str | None = None
) -> dict[str, Any]:
    """MCP tool for revoking license keys (admin only)."""
    # Admin-only code here...
    return {"success": True}
```

**Decorator Best Practices**:
1. Always include `db_session` and `agent_id` as keyword arguments
2. Add `resource_owner_id` for operations requiring ownership checks
3. Use type hints (`UUID`, `AsyncSession`) for clarity
4. Document permission requirements in docstring

---

### Testing RBAC Components

Unit tests from `tests/unit/security/test_rbac_permissions.py`:

```python
import pytest
from uuid import UUID, uuid4
from src.security.rbac import check_permission
from src.models.agent import Agent

class TestPermissionChecks:
    """Test permission checking with different roles."""

    async def test_viewer_can_validate_license(
        self,
        test_session,
        viewer_agent: Agent
    ):
        """Viewer role can validate licenses (READ operation)."""
        allowed = await check_permission(
            test_session,
            UUID(viewer_agent.id),
            "license:validate",
        )
        assert allowed is True

    async def test_viewer_cannot_generate_license(
        self,
        test_session,
        viewer_agent: Agent
    ):
        """Viewer role CANNOT generate licenses."""
        allowed = await check_permission(
            test_session,
            UUID(viewer_agent.id),
            "license:generate",
        )
        assert allowed is False

    async def test_ownership_check_viewer(
        self,
        test_session,
        viewer_agent: Agent,
        editor_agent: Agent
    ):
        """Viewer can read own licenses, not others'."""
        # Can read own license
        allowed_own = await check_permission(
            test_session,
            UUID(viewer_agent.id),
            "license:read",
            resource_owner_id=UUID(viewer_agent.id)
        )
        assert allowed_own is True

        # Cannot read other's license
        allowed_other = await check_permission(
            test_session,
            UUID(viewer_agent.id),
            "license:read",
            resource_owner_id=UUID(editor_agent.id)
        )
        assert allowed_other is False
```

**Pytest Fixtures** (from `tests/unit/security/conftest.py`):

```python
import pytest
from uuid import uuid4
from src.models.agent import Agent
from sqlalchemy.ext.asyncio import AsyncSession

@pytest.fixture
async def viewer_agent(test_session: AsyncSession) -> Agent:
    """Create viewer role agent for testing."""
    agent = Agent(
        id=str(uuid4()),
        agent_id="test-viewer",
        display_name="Test Viewer",
        namespace="test",
        status="active",
        role="viewer",
        health_score=1.0
    )
    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)
    return agent

@pytest.fixture
async def editor_agent(test_session: AsyncSession) -> Agent:
    """Create editor role agent for testing."""
    agent = Agent(
        id=str(uuid4()),
        agent_id="test-editor",
        display_name="Test Editor",
        namespace="test",
        status="active",
        role="editor",
        health_score=1.0
    )
    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)
    return agent
```

---

##

### Permission Matrix

Complete permission mapping from `src/security/rbac.py`:

| Operation | Viewer | Editor | Admin | Ownership Check Required |
|-----------|--------|--------|-------|-------------------------|
| `license:validate` | ✅ | ✅ | ✅ | No |
| `license:read` | ✅ (own only) | ✅ (own only) | ✅ (all) | Yes (non-admin) |
| `license:usage:read` | ✅ (own only) | ✅ (own only) | ✅ (all) | Yes (non-admin) |
| `license:generate` | ❌ | ✅ | ✅ | No |
| `license:revoke` | ❌ | ❌ | ✅ | No |
| `license:admin` | ❌ | ❌ | ✅ | No |
| `agent:update:tier` | ❌ | ❌ | ✅ | No |
| `system:audit` | ❌ | ❌ | ✅ | No |

**Ownership Rules**:
- Operations marked "Yes" in the "Ownership Check Required" column require the agent to own the resource (except for admin role)
- Admin role bypasses ownership checks for all operations
- Ownership is verified by comparing `agent_id` to `resource_owner_id`

### Code Location

- RBAC authorization logic: `src/security/authorization.py`
- Permission decorators: `src/security/decorators.py`
- Audit logging: `src/services/security_audit_service.py`

### Testing

- Unit tests: `tests/unit/security/test_rbac.py`
- Integration tests: `tests/integration/test_license_rbac.py`
- Security tests: `tests/security/test_namespace_isolation.py`

---

## Configuration

### Environment Variables

```bash
# RBAC enforcement mode
TMWS_RBAC_ENABLED=true  # Set to false only for testing

# Default role for new agents
TMWS_DEFAULT_AGENT_ROLE=viewer

# Audit log retention (days)
TMWS_AUDIT_LOG_RETENTION_DAYS=90
```

### Role Assignment

Roles are assigned during agent creation using the `role` field in the `Agent` model:

```python
from src.models.agent import Agent
from sqlalchemy.ext.asyncio import AsyncSession

async def create_viewer_agent(db_session: AsyncSession, agent_id: str) -> Agent:
    """Create a new agent with viewer role (read-only access)."""
    agent = Agent(
        agent_id=agent_id,
        display_name="Viewer User",
        namespace="production",
        status="active",
        role="viewer",  # RBAC role: read-only permissions
        tier="FREE",
    )

    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)

    return agent

async def create_editor_agent(db_session: AsyncSession, agent_id: str) -> Agent:
    """Create a new agent with editor role (can generate licenses)."""
    agent = Agent(
        agent_id=agent_id,
        display_name="Editor User",
        namespace="production",
        status="active",
        role="editor",  # RBAC role: read + generate permissions
        tier="PRO",
    )

    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)

    return agent

async def create_admin_agent(db_session: AsyncSession, agent_id: str) -> Agent:
    """Create a new agent with admin role (full control)."""
    agent = Agent(
        agent_id=agent_id,
        display_name="Admin User",
        namespace="production",
        status="active",
        role="admin",  # RBAC role: full permissions
        tier="ENTERPRISE",
    )

    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)

    return agent
```

**Why role assignment matters**: The role determines which MCP tools the agent can access. Assigning incorrect roles can lead to permission errors or security vulnerabilities.

---

## Troubleshooting

### Common Issues

#### Issue: "Permission denied" despite correct role

**Symptoms**: Agent has `editor` role but cannot generate license keys

**Possible Causes**:

1. **Role not properly saved to database**: Agent.role field is null or has invalid value
2. **Decorator not applied**: MCP tool missing `@require_permission` decorator
3. **Database session not passed**: `db_session` kwarg missing from tool call
4. **Agent not found**: agent_id does not exist in `agents` table

**Resolution**:

```python
# 1. Verify agent role in database
from sqlalchemy import select
from src.models.agent import Agent

stmt = select(Agent).where(Agent.agent_id == "test-editor")
result = await db_session.execute(stmt)
agent = result.scalar_one_or_none()

if agent:
    print(f"Agent role: {agent.role}")  # Should print "editor"
else:
    print("Agent not found in database")

# 2. Verify decorator is applied
# Check that MCP tool has @require_permission("license:generate")

# 3. Verify db_session is passed
result = await generate_license_key(
    db_session=session,  # ✅ Required
    agent_id=UUID("..."),  # ✅ Required
    tier="PRO"
)
```

---

#### Issue: Cross-namespace access blocked unexpectedly

**Symptoms**: Agent cannot access resources in expected namespace

**Possible Causes**:

1. **Namespace mismatch**: Agent.namespace ≠ Resource.namespace
2. **Typo in namespace**: "production" vs "Production" (case-sensitive)
3. **Agent fetched from JWT instead of DB**: V-RBAC-1 violation (namespace not verified)

**Resolution**:

```python
# 1. Verify agent namespace
stmt = select(Agent).where(Agent.id == agent_id)
result = await db_session.execute(stmt)
agent = result.scalar_one()
print(f"Agent namespace: {agent.namespace}")  # Should match resource namespace

# 2. Verify resource namespace
stmt = select(LicenseKey).where(LicenseKey.id == license_id)
result = await db_session.execute(stmt)
license_key = result.scalar_one()
print(f"License namespace: {license_key.namespace}")  # Should match agent namespace

# 3. Ensure namespace is verified from DB (V-RBAC-1)
# CORRECT: Fetch agent from DB
stmt = select(Agent).where(Agent.id == agent_id)
agent = (await db_session.execute(stmt)).scalar_one()
verified_namespace = agent.namespace  # ✅ Verified

# WRONG: Trust JWT claims
namespace = jwt_claims.get("namespace")  # ❌ Security risk
```

---

## Security Best Practices

1. **Principle of Least Privilege**: Assign the minimum role necessary
2. **Regular Audits**: Review permission grants quarterly
3. **Role Rotation**: Periodically review and revoke unused editor/admin roles
4. **Audit Log Monitoring**: Set up alerts for permission denials
5. **Namespace Verification**: Always verify namespace in custom code

---

## Compliance

### GDPR Considerations

- Audit logs may contain personal data (agent IDs)
- Implement data retention policies
- Provide data export for subject access requests

### SOC 2 Compliance

- RBAC system supports access control requirements
- Audit logs provide evidence of security monitoring
- Fail-secure defaults align with security best practices

---

## See Also

- [License MCP Tools API Reference](../api/MCP_TOOLS_LICENSE.md)
- [Usage Examples](../examples/LICENSE_MCP_EXAMPLES.md)
- [Security Audit Report](PHASE_1_SECURITY_AUDIT_REPORT.md)
- [Namespace Isolation Tests](../../tests/security/test_namespace_isolation.py)
