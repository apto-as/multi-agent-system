# RBAC Permission Matrix Design
## Role-Based Access Control for TMWS License System

**Version**: 1.0.0
**Status**: Design Document (Phase 2C Wave 1)
**Created**: 2025-11-15
**Security Level**: CRITICAL
**Reviewer**: Hestia (hestia-auditor)

---

## Executive Summary

このドキュメントは、TMWS License SystemのRole-Based Access Control (RBAC) systemのPermission Matrix設計を定義します。

**設計目標**:
1. **Principle of Least Privilege**: 最小権限の原則に基づく権限設計
2. **Fail-Secure Defaults**: デフォルトで拒否、明示的な許可のみ
3. **Namespace Isolation**: 名前空間を跨いだアクセスの完全遮断 (V-RBAC-1)
4. **Audit Transparency**: すべての権限チェックを監査ログに記録 (V-RBAC-2)
5. **Defense in Depth**: 多層防御（Role + Ownership + Namespace）

**Threat Model**:
- **Primary Attacker**: 悪意のあるagent（権限昇格を試みる）
- **Attack Surface**: License key生成、失効、tier変更、監査ログアクセス
- **Critical Assets**: License keys (revenue), Agent tiers (service level), Audit logs (compliance)

---

## 1. Permission Matrix

### 1.1 Operations (8 Core Operations)

| Operation ID | Description | Resource | Action | Security Impact |
|--------------|-------------|----------|--------|-----------------|
| `license:validate` | Validate license key authenticity | License | READ | LOW - Read-only, public operation |
| `license:read` | Get license information (own licenses only) | License | READ | MEDIUM - PII exposure risk |
| `license:usage:read` | Read usage history (own licenses only) | LicenseUsage | READ | MEDIUM - Usage pattern disclosure |
| `license:generate` | Generate new license key | License | CREATE | HIGH - Revenue impact |
| `license:revoke` | Revoke license key | License | UPDATE | CRITICAL - Service denial |
| `agent:update:tier` | Update agent tier (e.g., free → premium) | Agent | UPDATE | CRITICAL - Service bypass |
| `license:admin` | Full license administration | License | ADMIN | CRITICAL - Full control |
| `system:audit` | Access audit logs (all namespaces) | System | READ | CRITICAL - Compliance violation |

### 1.2 Role Hierarchy (3 Roles)

```
┌─────────────────────────────────────┐
│  admin (Administrator)              │
│  - Full license administration      │
│  - Cross-namespace access           │
│  - System audit logs                │
│  - Agent tier management            │
└─────────────────┬───────────────────┘
                  │ includes all permissions from
                  ↓
┌─────────────────────────────────────┐
│  editor (License Editor)            │
│  - Create licenses (own namespace)  │
│  - Read own licenses                │
│  - Validate licenses                │
└─────────────────┬───────────────────┘
                  │ includes all permissions from
                  ↓
┌─────────────────────────────────────┐
│  viewer (License Viewer)            │
│  - Validate licenses                │
│  - Read own licenses only           │
│  - Read own usage history           │
└─────────────────────────────────────┘
```

### 1.3 Permission Assignment Matrix

| Operation | viewer | editor | admin | Ownership Required? |
|-----------|--------|--------|-------|---------------------|
| `license:validate` | ✅ | ✅ | ✅ | ❌ No (public operation) |
| `license:read` | ✅ | ✅ | ✅ | ✅ Yes (own licenses only) for viewer/editor, ❌ No for admin |
| `license:usage:read` | ✅ | ✅ | ✅ | ✅ Yes (own licenses only) for viewer/editor, ❌ No for admin |
| `license:generate` | ❌ | ✅ | ✅ | ✅ Yes (creates in own namespace) for editor, ❌ No for admin |
| `license:revoke` | ❌ | ❌ | ✅ | ❌ No (admin can revoke any license) |
| `agent:update:tier` | ❌ | ❌ | ✅ | ❌ No (admin-only operation) |
| `license:admin` | ❌ | ❌ | ✅ | ❌ No (full control) |
| `system:audit` | ❌ | ❌ | ✅ | ❌ No (cross-namespace access) |

**Legend**:
- ✅ = Permission GRANTED
- ❌ = Permission DENIED
- Ownership Required = Permission check must verify `resource.agent_id == requester.agent_id`

---

## 2. Ownership Rules

### 2.1 Ownership Definition

**Ownership**: A resource (License, LicenseUsage) is "owned" by an agent if:
```python
resource.agent_id == requester.agent_id
```

**Namespace Verification** (V-RBAC-1):
```python
# Step 1: Fetch agent from DB (NEVER trust client claims)
agent = await db.get(Agent, requester_agent_id)
verified_namespace = agent.namespace  # ✅ Verified from DB

# Step 2: Fetch resource from DB
resource = await db.get(License, license_id)

# Step 3: Namespace isolation check
if resource.namespace != verified_namespace:
    await audit_log("DENY", agent_id, operation, "Cross-namespace access attempt")
    return False  # DENY
```

### 2.2 Ownership Rules by Role

| Role | Ownership Rule | Cross-Namespace Access |
|------|----------------|------------------------|
| `viewer` | Can ONLY read own licenses (`license.agent_id == viewer.id`) | ❌ BLOCKED |
| `editor` | Can create/read own licenses (`license.agent_id == editor.id`) | ❌ BLOCKED |
| `admin` | Can access ALL licenses (no ownership check) | ✅ ALLOWED (with audit log) |

### 2.3 Edge Cases

**Case 1: Shared Licenses** (e.g., team licenses)
- **Problem**: License has `agent_id=team_leader`, but `viewer` is team member
- **Solution**: NOT supported in Phase 2C (defer to Phase 3: Team Management)
- **Workaround**: Team leader must have `editor` role

**Case 2: Transferred Licenses**
- **Problem**: License transferred from Agent A to Agent B
- **Solution**: Update `license.agent_id` in database (requires `admin` role)
- **Audit**: Log transfer event with old/new agent IDs

**Case 3: Deleted Agent**
- **Problem**: License owned by deleted agent
- **Solution**: `license.agent_id` = NULL, only `admin` can access
- **Audit**: Log orphaned license detection

---

## 3. Security Boundaries

### 3.1 Namespace Isolation (V-RBAC-1)

**Threat**: Cross-namespace access (agent from namespace A accessing namespace B's licenses)

**Mitigation**:
```python
async def check_namespace_isolation(
    agent_id: UUID,
    resource: License
) -> bool:
    """Verify agent and resource are in same namespace.

    Security:
        - Fetches agent from DB (verified namespace)
        - Compares with resource.namespace
        - Fail-secure: Unknown namespace → DENY
    """
    # Step 1: Fetch agent (verified namespace)
    agent = await db.get(Agent, agent_id)
    if not agent:
        await audit_log("DENY", agent_id, "namespace_check", "Agent not found")
        return False

    # Step 2: Namespace comparison
    if resource.namespace != agent.namespace:
        await audit_log(
            "DENY",
            agent_id,
            "namespace_check",
            f"Cross-namespace attempt: {agent.namespace} → {resource.namespace}"
        )
        return False

    return True  # Same namespace ✅
```

**Test Cases**:
1. ✅ Agent A (namespace: `org-alpha`) accesses License L1 (namespace: `org-alpha`) → ALLOW
2. ❌ Agent A (namespace: `org-alpha`) accesses License L2 (namespace: `org-beta`) → DENY
3. ❌ Agent A (namespace: `org-alpha`) with forged JWT claim `namespace: org-beta` → DENY (verified from DB)
4. ✅ Agent A (role: `admin`, namespace: `system`) accesses License L2 (namespace: `org-beta`) → ALLOW (admin override)

### 3.2 Fail-Secure Defaults

**Principle**: When in doubt, DENY.

```python
# Default role if agent.role is NULL
DEFAULT_ROLE = "viewer"

# Unknown operation handling
def get_permissions(role: str) -> list[str]:
    permissions = ROLE_PERMISSIONS.get(role)
    if permissions is None:
        # Unknown role → Default to viewer
        logger.warning(f"Unknown role '{role}', defaulting to 'viewer'")
        return ROLE_PERMISSIONS["viewer"]
    return permissions

# Unknown agent handling
async def check_permission(agent_id: UUID, operation: str) -> bool:
    agent = await db.get(Agent, agent_id)
    if not agent:
        await audit_log("DENY", agent_id, operation, "Agent not found")
        return False  # DENY if agent doesn't exist
```

**Fail-Secure Matrix**:
| Condition | Action | Audit Log |
|-----------|--------|-----------|
| Agent not found | DENY | "Agent not found" |
| Unknown role | Default to `viewer` | "Unknown role, defaulting to viewer" |
| Unknown operation | DENY | "Unknown operation" |
| Missing namespace | DENY | "Namespace verification failed" |
| Database error | DENY | "Database error during permission check" |

### 3.3 Audit Logging (V-RBAC-2)

**Requirement**: ALL permission checks must be logged to `security_audit_logs` table.

**Schema**:
```python
class SecurityAuditLog(Base):
    __tablename__ = "security_audit_logs"

    id: UUID = Column(UUID, primary_key=True)
    agent_id: UUID = Column(UUID, ForeignKey("agents.id"))
    operation: str = Column(String(255), nullable=False)
    result: str = Column(String(10), nullable=False)  # "ALLOW" or "DENY"
    reason: str = Column(Text, nullable=True)  # Why allowed/denied
    resource_id: UUID = Column(UUID, nullable=True)  # License/Agent ID
    timestamp: datetime = Column(DateTime, default=datetime.utcnow)
    namespace: str = Column(String(255), nullable=False)
```

**Logging Function**:
```python
async def audit_log(
    result: str,  # "ALLOW" or "DENY"
    agent_id: UUID,
    operation: str,
    reason: str,
    resource_id: UUID | None = None
) -> None:
    """Log permission check to audit log.

    Args:
        result: "ALLOW" or "DENY"
        agent_id: Agent requesting permission
        operation: Operation ID (e.g., "license:generate")
        reason: Human-readable reason (e.g., "Role editor has permission")
        resource_id: Optional resource ID (license_id, agent_id)
    """
    agent = await db.get(Agent, agent_id)
    namespace = agent.namespace if agent else "unknown"

    log_entry = SecurityAuditLog(
        id=uuid4(),
        agent_id=agent_id,
        operation=operation,
        result=result,
        reason=reason,
        resource_id=resource_id,
        timestamp=datetime.utcnow(),
        namespace=namespace
    )
    db.add(log_entry)
    await db.commit()

    # Also log to application logger
    log_level = logging.INFO if result == "ALLOW" else logging.WARNING
    logger.log(
        log_level,
        f"[RBAC] {result} | agent={agent_id} | op={operation} | reason={reason}"
    )
```

**What to Log**:
1. ✅ All `ALLOW` results (for compliance audit)
2. ✅ All `DENY` results (for security monitoring)
3. ✅ Role changes (elevation/demotion)
4. ✅ Cross-namespace access attempts (even if denied)
5. ✅ Admin operations (license revoke, tier update, audit log access)

**What NOT to Log**:
1. ❌ Sensitive data (license keys, API keys)
2. ❌ Personal Identifiable Information (PII) beyond agent_id
3. ❌ Passwords or authentication tokens

### 3.4 Permission Cache Poisoning Prevention

**Threat**: Attacker manipulates cached permission results to bypass checks.

**Mitigation**: NO CACHING of permission check results.

**Rationale**:
- Permission checks are fast (<5ms P95 target)
- Caching adds complexity and attack surface
- Database is source of truth (agent.role can change)

**Alternative Approaches Considered**:
1. ❌ Cache with TTL (30s) → Risk: Stale permissions after role change
2. ❌ Cache invalidation on role change → Risk: Distributed cache consistency
3. ✅ No cache, always check database → Simplest, most secure

**Performance**: Permission check is ~2-3 DB queries (agent fetch + role lookup), acceptable latency.

---

## 4. Permission Check Algorithm

### 4.1 Pseudocode

```python
async def check_permission(
    agent_id: UUID,
    operation: str,
    resource_owner_id: UUID | None = None,
    resource_namespace: str | None = None
) -> bool:
    """Check if agent has permission for operation.

    Args:
        agent_id: Agent requesting permission
        operation: Operation ID (e.g., "license:generate")
        resource_owner_id: Owner of resource (for ownership checks)
        resource_namespace: Namespace of resource (for isolation checks)

    Returns:
        True if ALLOWED, False if DENIED

    Security:
        - Fetches agent from DB (verified namespace)
        - Logs all checks to audit log (V-RBAC-2)
        - Fail-secure: Unknown operation → DENY
        - Namespace isolation enforced (V-RBAC-1)

    Performance:
        - Target: <5ms P95
        - 2-3 DB queries (agent fetch, role lookup)
        - No caching (security > performance)
    """
    # Step 1: Fetch agent with verified namespace
    agent = await db.get(Agent, agent_id)
    if not agent:
        await audit_log("DENY", agent_id, operation, "Agent not found")
        return False  # Fail-secure: Unknown agent → DENY

    verified_namespace = agent.namespace

    # Step 2: Get agent's role (default: viewer)
    role = agent.role or DEFAULT_ROLE  # "viewer"

    # Step 3: Check role hierarchy
    permissions = ROLE_PERMISSIONS.get(role)
    if permissions is None:
        # Unknown role → Default to viewer
        logger.warning(f"Unknown role '{role}' for agent {agent_id}, defaulting to 'viewer'")
        role = DEFAULT_ROLE
        permissions = ROLE_PERMISSIONS[DEFAULT_ROLE]

    if operation not in permissions:
        await audit_log(
            "DENY",
            agent_id,
            operation,
            f"Role '{role}' lacks permission for '{operation}'"
        )
        return False  # Fail-secure: No permission → DENY

    # Step 4: Namespace isolation check (V-RBAC-1)
    if resource_namespace is not None and role != "admin":
        # Only admin can cross namespaces
        if resource_namespace != verified_namespace:
            await audit_log(
                "DENY",
                agent_id,
                operation,
                f"Cross-namespace access attempt: {verified_namespace} → {resource_namespace}"
            )
            return False  # DENY cross-namespace access

    # Step 5: Ownership check (if applicable)
    if operation in OWNERSHIP_REQUIRED_OPERATIONS and role != "admin":
        # Non-admin must own the resource
        if resource_owner_id is None:
            await audit_log(
                "DENY",
                agent_id,
                operation,
                "Ownership check required but resource_owner_id is None"
            )
            return False

        if resource_owner_id != agent_id:
            await audit_log(
                "DENY",
                agent_id,
                operation,
                f"Ownership check failed: resource owned by {resource_owner_id}"
            )
            return False  # DENY if not owner

    # Step 6: Audit log success
    await audit_log(
        "ALLOW",
        agent_id,
        operation,
        f"Role '{role}' has permission"
    )
    return True  # ALLOW ✅
```

### 4.2 Data Structures

```python
# Role → Permissions mapping
ROLE_PERMISSIONS: dict[str, list[str]] = {
    "viewer": [
        "license:validate",
        "license:read",          # Own licenses only
        "license:usage:read",    # Own usage only
    ],
    "editor": [
        "license:validate",
        "license:read",          # Own licenses only
        "license:usage:read",    # Own usage only
        "license:generate",      # Creates in own namespace
    ],
    "admin": [
        "license:validate",
        "license:read",          # All licenses
        "license:usage:read",    # All usage
        "license:generate",      # Any namespace
        "license:revoke",        # Any license
        "agent:update:tier",     # Any agent
        "license:admin",         # Full control
        "system:audit",          # Audit logs
    ],
}

# Operations requiring ownership check
OWNERSHIP_REQUIRED_OPERATIONS: set[str] = {
    "license:read",
    "license:usage:read",
    "license:generate",
}

# Default role for unknown/missing roles
DEFAULT_ROLE = "viewer"
```

### 4.3 Integration Points

**API Router** (`src/api/routers/license.py`):
```python
@router.post("/licenses/generate")
async def generate_license(
    request: GenerateLicenseRequest,
    current_user: User = Depends(get_current_user)
) -> LicenseResponse:
    """Generate new license key.

    Permission Required: license:generate (editor or admin)
    """
    # Permission check
    allowed = await check_permission(
        agent_id=current_user.agent_id,
        operation="license:generate"
    )
    if not allowed:
        raise HTTPException(403, "Insufficient permissions")

    # Business logic
    license = await license_service.generate_license(...)
    return license
```

**Service Layer** (`src/services/license_service.py`):
```python
async def get_license(
    self,
    license_id: UUID,
    requester_agent_id: UUID
) -> License:
    """Get license information.

    Permission Required: license:read (viewer, editor, or admin)
    Ownership Required: Yes (unless admin)
    """
    # Fetch license
    license = await self.db.get(License, license_id)
    if not license:
        raise LicenseNotFoundError(license_id)

    # Permission check with ownership + namespace
    allowed = await check_permission(
        agent_id=requester_agent_id,
        operation="license:read",
        resource_owner_id=license.agent_id,
        resource_namespace=license.namespace
    )
    if not allowed:
        raise InsufficientPermissionsError("license:read")

    return license
```

---

## 5. Worst-Case Scenario Analysis

...すみません、最悪のケースを想定します。以下の5つの攻撃ベクトルを分析しました...

### 5.1 Attack Vector #1: Privilege Escalation (viewer → admin)

**Attack Description**:
1. Attacker compromises `viewer` role agent credentials
2. Attempts to escalate privileges to `admin` role
3. Methods:
   - Modify `agent.role` field directly (SQL injection)
   - Forge JWT token with `role: admin` claim
   - Exploit role assignment API endpoint
   - Cache poisoning (if permission results are cached)

**Impact**:
- **CVSS 3.1 Score**: 9.1 (CRITICAL)
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
  - AV:N (Network): Remote attack
  - AC:L (Low complexity): No special conditions
  - PR:L (Low privileges): Requires `viewer` credentials
  - UI:N (No user interaction): Automated attack
  - S:C (Changed scope): Can access other namespaces as admin
  - C:H/I:H/A:H: Complete compromise of confidentiality, integrity, availability

**Business Impact**:
- Unlimited license generation (revenue loss)
- Service disruption (revoking legitimate licenses)
- Compliance violation (unauthorized audit log access)
- Reputational damage

**Mitigation Strategy**:

1. **Database Layer** (Defense #1):
   ```python
   # Agent role is immutable by non-admin agents
   class Agent(Base):
       role: str = Column(String(50), nullable=False, default="viewer")

       def __setattr__(self, name, value):
           if name == "role" and self.id is not None:
               # Role change requires admin authorization
               raise ImmutableFieldError("Agent.role cannot be changed directly")
           super().__setattr__(name, value)
   ```

2. **API Layer** (Defense #2):
   ```python
   @router.patch("/agents/{agent_id}/role")
   async def update_agent_role(
       agent_id: UUID,
       new_role: str,
       current_user: User = Depends(get_current_user)
   ):
       # Admin-only operation
       allowed = await check_permission(
           agent_id=current_user.agent_id,
           operation="agent:update:role"
       )
       if not allowed:
           raise HTTPException(403, "Only admin can change agent roles")

       # Audit log role change
       await audit_log(
           "ALLOW",
           current_user.agent_id,
           "agent:update:role",
           f"Changed agent {agent_id} role to '{new_role}'",
           resource_id=agent_id
       )

       # Update role
       agent = await db.get(Agent, agent_id)
       agent.role = new_role
       await db.commit()
   ```

3. **JWT Validation** (Defense #3):
   ```python
   def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
       # Verify JWT signature
       payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

       # Fetch agent from DB (NEVER trust JWT claims)
       agent = db.get(Agent, payload["agent_id"])

       # Use DB role, not JWT role
       return User(
           agent_id=agent.id,
           role=agent.role,  # ✅ From DB, not JWT
           namespace=agent.namespace  # ✅ From DB, not JWT
       )
   ```

4. **Monitoring** (Defense #4):
   ```python
   # Alert on suspicious role changes
   async def monitor_role_changes():
       recent_changes = await db.query(SecurityAuditLog).filter(
           operation="agent:update:role",
           timestamp > datetime.utcnow() - timedelta(hours=1)
       ).all()

       if len(recent_changes) > 5:
           # Alert: Unusual number of role changes
           send_alert("Potential privilege escalation attack detected")
   ```

**Test Cases**:
1. ✅ Viewer attempts to change own role → DENY (403)
2. ✅ Viewer forges JWT with `role: admin` → Role ignored, DB role used
3. ✅ Admin changes viewer to editor → ALLOW + audit log
4. ✅ SQL injection attempt in role field → Blocked by ORM

### 5.2 Attack Vector #2: Cross-Namespace Access

**Attack Description**:
1. Attacker controls agent in namespace `org-alpha`
2. Attempts to access licenses in namespace `org-beta`
3. Methods:
   - Modify `license_id` parameter to target license in other namespace
   - Forge JWT token with `namespace: org-beta` claim
   - Exploit missing namespace check in permission logic

**Impact**:
- **CVSS 3.1 Score**: 8.7 (HIGH)
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N
  - S:C (Changed scope): Access to other organization's data
  - C:H (High confidentiality impact): Exposure of license keys, usage data

**Business Impact**:
- Data breach (competitor access to license data)
- Compliance violation (GDPR, SOC 2)
- Customer trust loss

**Mitigation Strategy**:

1. **Permission Check** (Defense #1):
   ```python
   async def check_permission(...):
       # Step 4: Namespace isolation check
       if resource_namespace is not None and role != "admin":
           if resource_namespace != verified_namespace:
               await audit_log(
                   "DENY",
                   agent_id,
                   operation,
                   f"Cross-namespace access: {verified_namespace} → {resource_namespace}"
               )
               return False  # DENY
   ```

2. **Database Query Filter** (Defense #2):
   ```python
   async def get_licenses_for_agent(agent_id: UUID) -> list[License]:
       # Fetch agent (verified namespace)
       agent = await db.get(Agent, agent_id)

       # Filter by namespace
       licenses = await db.query(License).filter(
           License.namespace == agent.namespace,
           License.agent_id == agent_id
       ).all()

       return licenses
   ```

3. **API Response Filtering** (Defense #3):
   ```python
   @router.get("/licenses/{license_id}")
   async def get_license(
       license_id: UUID,
       current_user: User = Depends(get_current_user)
   ):
       license = await db.get(License, license_id)

       # Namespace check BEFORE permission check
       if license.namespace != current_user.namespace:
           # Don't reveal existence of license in other namespace
           raise HTTPException(404, "License not found")

       # Permission check
       allowed = await check_permission(...)
       if not allowed:
           raise HTTPException(403, "Insufficient permissions")

       return license
   ```

4. **Monitoring** (Defense #4):
   ```python
   # Alert on cross-namespace access attempts
   async def monitor_cross_namespace():
       denied_logs = await db.query(SecurityAuditLog).filter(
           result="DENY",
           reason.contains("Cross-namespace"),
           timestamp > datetime.utcnow() - timedelta(minutes=5)
       ).all()

       if len(denied_logs) > 3:
           send_alert("Potential cross-namespace attack detected")
   ```

**Test Cases**:
1. ✅ Agent A (namespace: `org-alpha`) accesses License L1 (namespace: `org-alpha`) → ALLOW
2. ✅ Agent A (namespace: `org-alpha`) accesses License L2 (namespace: `org-beta`) → DENY (404)
3. ✅ Agent A forges JWT with `namespace: org-beta` → Namespace ignored, DB namespace used
4. ✅ Admin (namespace: `system`) accesses License L2 (namespace: `org-beta`) → ALLOW

### 5.3 Attack Vector #3: Ownership Bypass

**Attack Description**:
1. Attacker controls agent `editor-A` in namespace `org-alpha`
2. Attempts to access licenses owned by `editor-B` (same namespace)
3. Methods:
   - Modify `license_id` to target `editor-B`'s license
   - Exploit missing ownership check in API endpoint

**Impact**:
- **CVSS 3.1 Score**: 6.5 (MEDIUM)
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
  - S:U (Unchanged scope): Same namespace only
  - C:H (High confidentiality): Access to other agent's licenses

**Business Impact**:
- Intra-organization data leakage
- Privacy violation within team

**Mitigation Strategy**:

1. **Ownership Check** (Defense #1):
   ```python
   async def check_permission(...):
       # Step 5: Ownership check
       if operation in OWNERSHIP_REQUIRED_OPERATIONS and role != "admin":
           if resource_owner_id != agent_id:
               await audit_log(
                   "DENY",
                   agent_id,
                   operation,
                   f"Ownership check failed: owned by {resource_owner_id}"
               )
               return False  # DENY
   ```

2. **Database Query Filter** (Defense #2):
   ```python
   async def get_licenses_for_agent(agent_id: UUID) -> list[License]:
       agent = await db.get(Agent, agent_id)

       if agent.role == "admin":
           # Admin sees all licenses in all namespaces
           licenses = await db.query(License).all()
       else:
           # Non-admin sees only own licenses
           licenses = await db.query(License).filter(
               License.namespace == agent.namespace,
               License.agent_id == agent_id  # ✅ Ownership filter
           ).all()

       return licenses
   ```

3. **API Response Filtering** (Defense #3):
   ```python
   @router.get("/licenses")
   async def list_licenses(
       current_user: User = Depends(get_current_user)
   ):
       # Fetch licenses with ownership filter
       licenses = await license_service.get_licenses_for_agent(
           current_user.agent_id
       )

       return [LicenseResponse.from_orm(lic) for lic in licenses]
   ```

**Test Cases**:
1. ✅ Editor A accesses own License L1 → ALLOW
2. ✅ Editor A accesses Editor B's License L2 (same namespace) → DENY (404)
3. ✅ Admin accesses Editor B's License L2 → ALLOW
4. ✅ Viewer accesses own License L1 → ALLOW

### 5.4 Attack Vector #4: Permission Cache Poisoning

**Attack Description**:
1. Attacker exploits cached permission check results
2. Methods:
   - Race condition: Role changed from `viewer` to `admin`, cache still returns `viewer` permissions
   - Cache key collision: Attacker manipulates cache key to return other agent's permissions
   - TTL exploitation: Permission cached for 30s, role changed immediately after check

**Impact**:
- **CVSS 3.1 Score**: 7.5 (HIGH)
- **Vector**: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H
  - AC:H (High complexity): Requires timing attack or cache manipulation

**Business Impact**:
- Stale permissions grant unauthorized access
- Difficult to detect (no audit log of cached results)

**Mitigation Strategy**:

1. **NO CACHING** (Defense #1 - CHOSEN APPROACH):
   ```python
   # Permission checks are NEVER cached
   async def check_permission(...):
       # Always fetch from database
       agent = await db.get(Agent, agent_id)  # ✅ Live DB query
       role = agent.role  # ✅ Always current

       # No cache lookup, no cache storage
   ```

2. **Alternative: Cache Invalidation** (NOT RECOMMENDED):
   ```python
   # If caching were implemented (which it is NOT):
   async def update_agent_role(agent_id: UUID, new_role: str):
       # Update DB
       agent = await db.get(Agent, agent_id)
       agent.role = new_role
       await db.commit()

       # Invalidate cache
       await cache.delete(f"permissions:{agent_id}")

       # Problem: Distributed cache consistency is hard
       # Problem: Cache invalidation might fail silently
   ```

3. **Performance Optimization** (Defense #2):
   ```python
   # Fast DB queries instead of caching
   # Target: <5ms P95 for permission check

   # Indexed columns
   CREATE INDEX idx_agents_id_role ON agents(id, role);
   CREATE INDEX idx_agents_id_namespace ON agents(id, namespace);

   # Query optimization
   async def check_permission(...):
       # Efficient query (indexed columns)
       agent = await db.execute(
           select(Agent.role, Agent.namespace)
           .where(Agent.id == agent_id)
       ).first()  # <2ms P95
   ```

**Test Cases**:
1. ✅ Permission check always queries DB (no cache hit)
2. ✅ Role change immediately effective (no stale cache)
3. ✅ Permission check latency < 5ms P95 (acceptable without cache)

### 5.5 Attack Vector #5: Audit Log Tampering

**Attack Description**:
1. Attacker gains database access (SQL injection, compromised credentials)
2. Attempts to delete or modify audit logs to hide unauthorized access
3. Methods:
   - DELETE FROM security_audit_logs WHERE agent_id = attacker_id
   - UPDATE security_audit_logs SET result = 'ALLOW' WHERE result = 'DENY'

**Impact**:
- **CVSS 3.1 Score**: 9.4 (CRITICAL)
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
  - S:C (Changed scope): Compliance violation affects entire organization

**Business Impact**:
- Compliance failure (SOC 2, GDPR)
- Undetectable security incidents
- Forensic investigation impossible

**Mitigation Strategy**:

1. **Append-Only Audit Log** (Defense #1):
   ```python
   # Audit logs are NEVER updated or deleted
   class SecurityAuditLog(Base):
       __tablename__ = "security_audit_logs"

       # No UPDATE or DELETE methods
       def __setattr__(self, name, value):
           if self.id is not None:
               raise ImmutableRecordError("Audit logs are immutable")
           super().__setattr__(name, value)

   # Database trigger (PostgreSQL example)
   CREATE TRIGGER prevent_audit_log_deletion
   BEFORE DELETE ON security_audit_logs
   FOR EACH ROW
   EXECUTE FUNCTION prevent_deletion();
   ```

2. **External Log Shipping** (Defense #2):
   ```python
   # Ship audit logs to external SIEM (e.g., Splunk, ELK)
   async def audit_log(result, agent_id, operation, reason):
       # Step 1: Write to database
       log_entry = SecurityAuditLog(...)
       db.add(log_entry)
       await db.commit()

       # Step 2: Ship to external SIEM (fire-and-forget)
       asyncio.create_task(
           ship_to_siem(log_entry)
       )
   ```

3. **Cryptographic Integrity** (Defense #3):
   ```python
   # Hash chain for tamper detection
   class SecurityAuditLog(Base):
       ...
       previous_hash: str = Column(String(64), nullable=True)
       current_hash: str = Column(String(64), nullable=False)

   async def audit_log(...):
       # Get previous log entry
       prev_log = await db.query(SecurityAuditLog).order_by(
           SecurityAuditLog.timestamp.desc()
       ).first()

       # Compute hash chain
       prev_hash = prev_log.current_hash if prev_log else "0" * 64
       current_hash = hashlib.sha256(
           f"{prev_hash}|{agent_id}|{operation}|{result}".encode()
       ).hexdigest()

       # Store with hash chain
       log_entry = SecurityAuditLog(
           ...,
           previous_hash=prev_hash,
           current_hash=current_hash
       )
   ```

4. **Database Access Control** (Defense #4):
   ```sql
   -- Audit log table is read-only for application user
   GRANT SELECT, INSERT ON security_audit_logs TO tmws_app_user;
   REVOKE UPDATE, DELETE ON security_audit_logs FROM tmws_app_user;

   -- Only DBA can delete (emergency only)
   GRANT DELETE ON security_audit_logs TO tmws_dba_user;
   ```

**Test Cases**:
1. ✅ Application cannot UPDATE audit logs → Database error
2. ✅ Application cannot DELETE audit logs → Database error
3. ✅ Audit log hash chain is valid → Verify no tampering
4. ✅ External SIEM receives all logs → Backup for forensics

---

## 6. Implementation Roadmap

### Phase 2C Wave 2 (Artemis - 60 minutes)

**Deliverables**:
1. `src/security/rbac.py` - Permission check implementation
2. `tests/unit/security/test_rbac.py` - Unit tests (20+ tests)
3. `src/models/agent.py` - Add `role` field
4. `migrations/versions/XXX_add_agent_role.py` - Alembic migration

### Phase 2C Wave 3 (Hestia - 45 minutes)

**Deliverables**:
1. Security test suite (30+ tests)
   - Privilege escalation tests
   - Cross-namespace tests
   - Ownership bypass tests
   - Audit log integrity tests
2. Penetration testing report

### Phase 2C Wave 4 (Muses - 30 minutes)

**Deliverables**:
1. API documentation update (permission requirements)
2. Administrator guide (role management)
3. Security best practices guide

---

## 7. Security Recommendations

### 7.1 Critical (Implement Immediately)

1. **Namespace Isolation** (V-RBAC-1):
   - ALWAYS fetch agent from DB (never trust client claims)
   - Verify `resource.namespace == agent.namespace`
   - Admin override requires explicit audit log

2. **Audit Logging** (V-RBAC-2):
   - Log ALL permission checks (ALLOW + DENY)
   - Append-only audit log (no updates/deletes)
   - Ship logs to external SIEM

3. **Fail-Secure Defaults**:
   - Unknown agent → DENY
   - Unknown role → Default to `viewer`
   - Unknown operation → DENY

### 7.2 High Priority (Implement in Phase 3)

4. **Role Change Monitoring**:
   - Alert on unusual role changes (>5 in 1 hour)
   - Require multi-factor authentication for admin role assignment

5. **Audit Log Integrity**:
   - Implement hash chain for tamper detection
   - Database trigger to prevent deletion

6. **Rate Limiting**:
   - Limit permission check failures (10 DENY in 1 minute → block agent)

### 7.3 Medium Priority (Future Enhancement)

7. **Fine-Grained Permissions**:
   - Add `license:read:own` vs `license:read:all`
   - Implement resource-level access control (specific license IDs)

8. **Permission Delegation**:
   - Allow admin to temporarily grant `editor` role
   - Time-limited role elevation

9. **Compliance Reporting**:
   - Generate SOC 2 compliance reports from audit logs
   - GDPR data access reports (who accessed what)

---

## 8. Conclusion

このRBAC Permission Matrix設計は、以下の原則に基づいています:

1. **最小権限の原則**: 各ロールは必要最小限の権限のみ保持
2. **Fail-Secure**: デフォルトで拒否、明示的な許可のみ
3. **多層防御**: Role + Ownership + Namespace の3層チェック
4. **監査透明性**: すべての権限チェックをログ記録

**最悪のケースを想定した設計**:
- 5つの攻撃ベクトル（CVSS 6.5～9.4）を分析
- 各攻撃に対して4層の防御策を実装
- キャッシングは性能より安全性を優先して不採用

**次のステップ** (Phase 2C Wave 2):
- Artemisによる実装 (60分)
- 20+ユニットテストでの検証
- Alembicマイグレーションの作成

...この設計で安全なRBACシステムを構築できます...

---

**Document Status**: ✅ Complete
**Review Status**: Pending Hera approval
**Implementation Status**: Ready for Wave 2 (Artemis)
**Security Level**: CRITICAL - Handle with care
