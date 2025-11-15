# Phase 2C: MCP Tools Implementation Plan

**Status**: 📋 Planning
**Priority**: P0
**Estimated Time**: 2.5 hours
**Dependencies**: ✅ Phase 2B completed

---

## Overview

Phase 2C exposes the License Service as Model Context Protocol (MCP) tools, enabling Claude and other AI agents to interact with the licensing system through standardized function calls.

---

## Planned MCP Tools

### 1. `generate_license_key`

**Purpose**: Issue a new license key for an agent

**Function Signature**:
```python
async def generate_license_key(
    agent_id: str,
    tier: str,  # "FREE" | "BASIC" | "PRO" | "ENTERPRISE" | "ADMIN"
    expires_days: int = 365
) -> dict
```

**Parameters**:
- `agent_id` (required): Target agent identifier
- `tier` (required): License tier level
- `expires_days` (optional): Days until expiration (default: 365)

**Returns**:
```json
{
  "license_key": "lic_abc123...",
  "tier": "PRO",
  "issued_at": "2025-11-15T12:00:00Z",
  "expires_at": "2026-11-15T12:00:00Z",
  "license_id": "uuid-here"
}
```

**Permissions**: ADMIN role only

**Error Cases**:
- `AgentNotFoundError`: Agent ID does not exist
- `InvalidTierError`: Invalid tier value
- `PermissionDeniedError`: Caller not ADMIN

**Example Usage** (MCP client):
```python
result = await mcp_client.call_tool(
    "generate_license_key",
    agent_id="test-agent",
    tier="PRO",
    expires_days=730  # 2 years
)
```

---

### 2. `validate_license_key`

**Purpose**: Validate a license key and record usage

**Function Signature**:
```python
async def validate_license_key(
    license_key: str,
    feature_accessed: str | None = None
) -> dict
```

**Parameters**:
- `license_key` (required): License key string to validate
- `feature_accessed` (optional): Feature name for analytics

**Returns**:
```json
{
  "valid": true,
  "tier": "PRO",
  "expires_at": "2026-11-15T12:00:00Z",
  "message": "License valid",
  "usage_recorded": true
}
```

**Permissions**: All authenticated agents

**Error Cases**:
- `InvalidLicenseKeyError`: Malformed key format
- `LicenseNotFoundError`: Key does not exist in database
- `LicenseExpiredError`: Key has expired
- `LicenseRevokedError`: Key has been revoked

**Side Effects**:
- Records usage in `license_key_usage` table
- Updates `Agent.last_active_at` timestamp (future enhancement)

**Example Usage**:
```python
result = await mcp_client.call_tool(
    "validate_license_key",
    license_key="lic_abc123...",
    feature_accessed="semantic_search"
)

if result["valid"]:
    # Proceed with operation
else:
    # Handle invalid license (show message to user)
```

---

### 3. `revoke_license_key`

**Purpose**: Revoke or suspend a license key

**Function Signature**:
```python
async def revoke_license_key(
    license_id: str,  # UUID as string
    reason: str | None = None
) -> dict
```

**Parameters**:
- `license_id` (required): UUID of the license to revoke
- `reason` (optional): Human-readable explanation for audit trail

**Returns**:
```json
{
  "success": true,
  "license_id": "uuid-here",
  "revoked_at": "2025-11-15T12:30:00Z",
  "reason": "Security violation - unauthorized access"
}
```

**Permissions**: ADMIN role only

**Error Cases**:
- `LicenseNotFoundError`: License ID does not exist
- `AlreadyRevokedError`: License already revoked
- `PermissionDeniedError`: Caller not ADMIN

**Side Effects**:
- Sets `is_active = false`
- Updates `revoked_at` timestamp
- Stores `revoked_reason` for audit
- Immediate validation failure on subsequent checks

**Example Usage**:
```python
result = await mcp_client.call_tool(
    "revoke_license_key",
    license_id="123e4567-e89b-12d3-a456-426614174000",
    reason="User violated terms of service"
)
```

---

### 4. `get_license_usage_history`

**Purpose**: Retrieve usage analytics for a license key

**Function Signature**:
```python
async def get_license_usage_history(
    license_id: str,  # UUID as string
    limit: int = 100
) -> dict
```

**Parameters**:
- `license_id` (required): UUID of the license
- `limit` (optional): Maximum records to return (default: 100, max: 1000)

**Returns**:
```json
{
  "license_id": "uuid-here",
  "total_usage_count": 523,
  "usage_history": [
    {
      "used_at": "2025-11-15T12:00:00Z",
      "feature_accessed": "semantic_search",
      "usage_metadata": {"query_time_ms": 45}
    },
    ...
  ]
}
```

**Permissions**: ADMIN role OR license owner agent

**Error Cases**:
- `LicenseNotFoundError`: License ID does not exist
- `PermissionDeniedError`: Caller neither ADMIN nor owner
- `InvalidLimitError`: Limit exceeds maximum (1000)

**Example Usage**:
```python
result = await mcp_client.call_tool(
    "get_license_usage_history",
    license_id="123e4567-e89b-12d3-a456-426614174000",
    limit=50  # Last 50 usage records
)

# Analyze usage patterns
for usage in result["usage_history"]:
    print(f"{usage['used_at']}: {usage['feature_accessed']}")
```

---

## Implementation Steps

### Step 1: MCP Tool Registration (30 minutes)

**File**: `src/tools/license_tools.py` (new file)

**Tasks**:
1. Create `LicenseTools` class
2. Register 4 tools with ServiceManager
3. Define input/output JSON schemas (Pydantic models)
4. Implement tool wrapper functions

**Code Structure**:
```python
class LicenseTools:
    def __init__(self, license_service: LicenseService):
        self.license_service = license_service

    @mcp_tool(
        name="generate_license_key",
        description="Issue a new license key (ADMIN only)",
        schema=GenerateLicenseKeySchema
    )
    async def generate_license_key(self, params: dict) -> dict:
        # Validate permissions
        # Call license_service.generate_license_key()
        # Format response

    # ... (repeat for other 3 tools)
```

**Deliverables**:
- [ ] `src/tools/license_tools.py` created
- [ ] 4 tools registered in `src/core/service_manager.py`
- [ ] Pydantic schemas for all input/output

---

### Step 2: Permission Layer Integration (20 minutes)

**File**: `src/tools/license_tools.py`

**Tasks**:
1. Integrate with existing `AuthorizationService`
2. Implement RBAC enforcement (ADMIN vs USER roles)
3. Add permission checks before service calls

**Permission Matrix**:
| Tool | ADMIN | USER | Owner Agent |
|------|-------|------|-------------|
| `generate_license_key` | ✅ | ❌ | ❌ |
| `validate_license_key` | ✅ | ✅ | ✅ |
| `revoke_license_key` | ✅ | ❌ | ❌ |
| `get_license_usage_history` | ✅ | ❌ | ✅ |

**Implementation**:
```python
# Permission check pattern
async def generate_license_key(self, params: dict, user: User) -> dict:
    # 1. Check ADMIN role
    if not await self.auth_service.has_role(user, "ADMIN"):
        raise PermissionDeniedError("ADMIN role required")

    # 2. Call service
    return await self.license_service.generate_license_key(...)
```

**Deliverables**:
- [ ] Permission checks added to all 4 tools
- [ ] Error messages standardized
- [ ] Audit logging integrated (optional)

---

### Step 3: Error Handling Standardization (15 minutes)

**File**: `src/tools/license_tools.py`

**Tasks**:
1. Convert service exceptions to MCP error format
2. Add error codes for client-side handling
3. Include helpful error messages

**Error Response Format**:
```json
{
  "error": {
    "code": "PERMISSION_DENIED",
    "message": "ADMIN role required to generate license keys",
    "details": {
      "required_role": "ADMIN",
      "user_role": "USER"
    }
  }
}
```

**Error Code Mapping**:
| Service Exception | MCP Error Code |
|-------------------|----------------|
| `AgentNotFoundError` | `AGENT_NOT_FOUND` |
| `InvalidTierError` | `INVALID_TIER` |
| `LicenseNotFoundError` | `LICENSE_NOT_FOUND` |
| `LicenseExpiredError` | `LICENSE_EXPIRED` |
| `LicenseRevokedError` | `LICENSE_REVOKED` |
| `PermissionDeniedError` | `PERMISSION_DENIED` |

**Deliverables**:
- [ ] `@handle_mcp_errors` decorator created
- [ ] All tools wrapped with error handler
- [ ] Error response schema documented

---

### Step 4: Integration Tests (45 minutes)

**File**: `tests/integration/test_license_mcp_tools.py` (new file)

**Test Categories**:

#### 4.1 Happy Path Tests (15 minutes)
- [ ] `test_generate_license_key_success()`
- [ ] `test_validate_license_key_success()`
- [ ] `test_revoke_license_key_success()`
- [ ] `test_get_license_usage_history_success()`

#### 4.2 Permission Tests (15 minutes)
- [ ] `test_generate_requires_admin()`
- [ ] `test_revoke_requires_admin()`
- [ ] `test_usage_history_requires_admin_or_owner()`
- [ ] `test_validate_allows_all_authenticated()`

#### 4.3 Error Case Tests (15 minutes)
- [ ] `test_validate_invalid_key_format()`
- [ ] `test_validate_expired_key()`
- [ ] `test_validate_revoked_key()`
- [ ] `test_revoke_nonexistent_license()`
- [ ] `test_usage_history_invalid_limit()`

**Test Infrastructure**:
```python
@pytest.fixture
async def mcp_client(db_session):
    """MCP client with authenticated user"""
    client = TestMCPClient()
    await client.authenticate(role="ADMIN")
    return client

async def test_generate_license_key_success(mcp_client):
    result = await mcp_client.call_tool(
        "generate_license_key",
        agent_id="test-agent",
        tier="PRO"
    )

    assert result["license_key"].startswith("lic_")
    assert result["tier"] == "PRO"
```

**Deliverables**:
- [ ] 12+ integration tests written
- [ ] All tests PASS
- [ ] Coverage >80% on license_tools.py

---

### Step 5: Documentation (30 minutes)

**Files to Create/Update**:

#### 5.1 API Reference (`docs/api/LICENSE_MCP_TOOLS.md`)
- Tool signatures and descriptions
- Parameter specifications
- Return value formats
- Error codes and messages
- Permission requirements

#### 5.2 Usage Examples (`docs/guides/LICENSE_TOOL_USAGE.md`)
- Example workflows (generate → validate → revoke)
- Best practices (error handling, rate limiting)
- Code snippets in Python and TypeScript

#### 5.3 Integration Guide (`docs/integration/MCP_LICENSE_INTEGRATION.md`)
- How to call tools from MCP clients
- Authentication setup
- Error handling patterns
- Testing strategies

**Deliverables**:
- [ ] 3 documentation files created
- [ ] Examples tested and verified
- [ ] Screenshots/diagrams added (optional)

---

## Total Time Breakdown

| Step | Task | Time |
|------|------|------|
| 1 | MCP Tool Registration | 30 min |
| 2 | Permission Layer | 20 min |
| 3 | Error Handling | 15 min |
| 4 | Integration Tests | 45 min |
| 5 | Documentation | 30 min |
| **Total** | | **2h 20min** |

**Buffer**: +10 min for unexpected issues = **2.5 hours**

---

## Dependencies

### ✅ Completed (Phase 2B)
- [x] License Service DB integration
- [x] `LicenseKey` and `LicenseKeyUsage` models
- [x] Database migration applied (096325207c82)
- [x] 33/35 unit tests passing

### ⏸️ In Progress
- [ ] V-LIC-4 security tests (not blocking for Phase 2C)

### 🔴 Required for Phase 2C
- [ ] MCP framework integration (verify existing setup)
- [ ] AuthorizationService RBAC support (verify existing API)
- [ ] Test infrastructure for MCP tools (create if missing)

---

## Success Criteria

### Functional Requirements
- ✅ 4 MCP tools callable from MCP clients
- ✅ Permission layer enforces ADMIN/USER roles correctly
- ✅ All error cases handled with clear messages
- ✅ Usage tracking records every validation call

### Quality Requirements
- ✅ 12+ integration tests PASS
- ✅ Test coverage >80% on new code
- ✅ Zero regression on existing tests
- ✅ Response time <10ms P95 for all tools

### Documentation Requirements
- ✅ API reference complete with examples
- ✅ Integration guide published
- ✅ Usage guide with best practices

---

## Risk Mitigation

### Risk 1: MCP Framework API Changes
**Probability**: Low
**Impact**: Medium
**Mitigation**: Verify MCP version compatibility before starting

### Risk 2: Permission Layer Integration Complexity
**Probability**: Medium
**Impact**: Low
**Mitigation**: Review existing auth patterns in other MCP tools

### Risk 3: Test Infrastructure Missing
**Probability**: Low
**Impact**: High
**Mitigation**: Allocate +30 min buffer for test setup if needed

---

## Next Steps After Phase 2C

### Phase 2D: Security Hardening (estimated 1.5 hours)
1. Complete V-LIC-4 security test suite
2. Add rate limiting to MCP tools (prevent abuse)
3. Implement audit logging for all ADMIN actions
4. Add IP allowlist for license generation (optional)

### Phase 3: License Tier Feature Enforcement (estimated 3 hours)
1. Implement feature flags per tier
2. Add middleware to check tier before operations
3. Throttling based on tier limits
4. Usage quota enforcement

---

## References

- Phase 2B Completion: `docs/features/LICENSE_SERVICE_DB_INTEGRATION.md`
- License Service: `src/services/license_service.py`
- Database Models: `src/models/license_key.py`
- MCP Protocol Spec: https://modelcontextprotocol.io/
- Existing MCP Tools: `src/tools/` (for pattern reference)

---

**Document Version**: 1.0
**Created**: 2025-11-15
**Author**: Trinitas Agent System (Muses)
**Next Review**: Phase 2C kickoff
