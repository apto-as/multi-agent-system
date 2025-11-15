# License MCP Tools - Usage Examples

## Prerequisites

Before using the license MCP tools, ensure:

- MCP server is running (`python -m src.mcp_server`)
- Agent is authenticated with valid API key or JWT token
- Agent has appropriate role assigned (`viewer`, `editor`, or `admin`)
- Namespace is properly configured

## Example 1: Generate Free Tier License

**Scenario**: Create a new license key for a free-tier agent

**Required Role**: `editor` or `admin`

**Code**:

```python
import asyncio
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from src.tools.license_tools import generate_license_key
from src.core.database import get_db_session

async def generate_free_license_example():
    """Generate a FREE tier license for a new agent."""
    async with get_db_session() as session:
        result = await generate_license_key(
            db_session=session,
            agent_id=UUID("550e8400-e29b-41d4-a716-446655440000"),
            tier="FREE",
            expires_days=30  # 30-day trial
        )

        print(f"License Key: {result['license_key']}")
        print(f"Expires At: {result['expires_at']}")

        return result

# Run the example
asyncio.run(generate_free_license_example())
```

**Expected Output**:

```json
{
  "license_key": "TMWS-FREE-a1b2c3d4-e5f6-7890-abcd-ef1234567890-8F2A3D4E",
  "license_id": "123e4567-e89b-12d3-a456-426614174000",
  "tier": "FREE",
  "issued_at": "2025-11-15T10:30:00Z",
  "expires_at": "2025-12-15T10:30:00Z"
}
```

**Notes**:

- Free tier licenses expire after 30 days by default
- Namespace isolation is enforced (can only generate licenses for agents in your namespace)
- Rate limits apply: 10 generations/hour (FREE tier)

---

## Example 2: Validate License Key

**Scenario**: Check if a license key is valid and not expired

**Required Role**: `viewer`, `editor`, or `admin`

**Code**:

```python
import asyncio
from uuid import UUID
from src.tools.license_tools import validate_license_key
from src.core.database import get_db_session

async def validate_license_example():
    """Validate a license key and optionally track feature usage."""
    async with get_db_session() as session:
        result = await validate_license_key(
            db_session=session,
            agent_id=UUID("550e8400-e29b-41d4-a716-446655440000"),
            key="TMWS-PRO-a1b2c3d4-e5f6-7890-abcd-ef1234567890-8F2A3D4E",
            feature_accessed="semantic_search"  # Optional usage tracking
        )

        if result['valid']:
            print(f"✅ Valid license - Tier: {result['tier']}")
            print(f"Expires: {result['expires_at']}")
        else:
            print(f"❌ Invalid license - Error: {result['error']}")

        return result

asyncio.run(validate_license_example())
```

**Expected Output (Valid License)**:

```json
{
  "valid": true,
  "tier": "PRO",
  "expires_at": "2026-11-15T10:30:00Z",
  "is_perpetual": false,
  "agent_id": "123e4567-e89b-12d3-a456-426614174000",
  "error": null
}
```

**Expected Output (Expired License)**:

```json
{
  "valid": false,
  "tier": null,
  "expires_at": null,
  "is_perpetual": false,
  "agent_id": null,
  "error": "License key expired on 2025-10-01T00:00:00Z"
}
```

**Notes**:

- Validation checks HMAC checksum, expiration, and revocation status
- Returns detailed information for valid licenses
- Does not reveal information about licenses in other namespaces (security boundary)

---

## Example 3: Revoke License Key (Admin Only)

**Scenario**: Revoke a compromised license key

**Required Role**: `admin`

**Code**:

```python
[To be filled in Wave 3]
```

**Expected Output**:

```json
[To be filled in Wave 3]
```

**Notes**:

- Only admin role can revoke licenses
- Revocation is immediate and irreversible
- Audit log entry is created with revocation reason

---

## Example 4: Get Usage History

**Scenario**: View license usage statistics for an agent

**Required Role**: `viewer`, `editor`, or `admin`

**Code**:

```python
[To be filled in Wave 3]
```

**Expected Output**:

```json
[To be filled in Wave 3]
```

**Notes**:

- Usage history includes validation attempts, generation events, and revocations
- Filtered by date range if provided
- Limited to same namespace

---

## Example 5: Get License History

**Scenario**: Retrieve all license keys generated for an agent

**Required Role**: `viewer`, `editor`, or `admin`

**Code**:

```python
[To be filled in Wave 3]
```

**Expected Output**:

```json
[To be filled in Wave 3]
```

**Notes**:

- Includes active, expired, and revoked licenses
- Paginated results (use `limit` and `offset`)
- Sorted by creation date (newest first)

---

## Example 6: Permission Denied Scenario

**Scenario**: Viewer role attempts to generate a license key

**Required Role**: `viewer` (insufficient permissions)

**Code**:

```python
# Attempting to generate license as viewer role
[To be filled in Wave 3]
```

**Expected Error**:

```json
{
  "error": "PermissionError",
  "message": "Role viewer lacks permission for operation license:generate",
  "details": {
    "required_permission": "license:generate",
    "agent_role": "viewer",
    "available_permissions": ["license:read"]
  }
}
```

**Notes**:

- Permission errors are logged in security audit logs
- Error message clearly indicates required permission
- No sensitive information leaked in error response

---

## Example 7: Cross-Namespace Access Attempt (Blocked)

**Scenario**: Agent in namespace `alpha` attempts to validate license in namespace `beta`

**Required Role**: `viewer`, `editor`, or `admin` (insufficient for cross-namespace)

**Code**:

```python
# Agent in namespace "alpha" attempting cross-namespace access
[To be filled in Wave 3]
```

**Expected Error**:

```json
{
  "error": "NamespaceIsolationError",
  "message": "Cannot access resources in namespace beta from namespace alpha",
  "details": {
    "agent_namespace": "alpha",
    "target_namespace": "beta",
    "operation": "license:read"
  }
}
```

**Notes**:

- Namespace isolation is enforced at model level
- Cross-namespace access requires `SYSTEM` access level
- Attempted violations are logged as security events

---

## Example 8: Rate Limit Exceeded

**Scenario**: Agent exceeds rate limit for license generation

**Required Role**: `editor` or `admin`

**Code**:

```python
# Rapid license generation (exceeds rate limit)
[To be filled in Wave 3]
```

**Expected Error**:

```json
{
  "error": "RateLimitExceeded",
  "message": "Rate limit exceeded for operation license:generate",
  "details": {
    "limit": 10,
    "window": "60s",
    "retry_after": 45
  }
}
```

**Notes**:

- Rate limits vary by tier: [To be filled in Wave 3]
- `retry_after` indicates seconds until retry is allowed
- Rate limit state is tracked per agent

---

## Example 9: Batch License Generation

**Scenario**: Generate multiple license keys for a team of agents

**Required Role**: `editor` or `admin`

**Code**:

```python
[To be filled in Wave 3]
```

**Expected Output**:

```json
[To be filled in Wave 3]
```

**Notes**:

- Batch operations are subject to same rate limits
- Failed generations do not roll back successful ones
- Returns partial success with error details

---

## Example 10: License Expiration Handling

**Scenario**: Renew an expired license key

**Required Role**: `editor` or `admin`

**Code**:

```python
# Check if license is expired
[To be filled in Wave 3]

# Generate new license if expired
[To be filled in Wave 3]
```

**Expected Output**:

```json
[To be filled in Wave 3]
```

**Notes**:

- Expired licenses cannot be renewed (generate new one instead)
- Old expired licenses remain in history for audit purposes
- Expiration date is in UTC timezone

---

## Troubleshooting

### Common Errors

#### Error: "Agent not found"

**Symptom**: `AgentNotFoundError` when attempting any license operation

**Possible Causes**:

[To be filled in Wave 3]

**Resolution**:

[To be filled in Wave 3]

---

#### Error: "Permission denied"

**Symptom**: `PermissionError` despite having appropriate role

**Possible Causes**:

[To be filled in Wave 3]

**Resolution**:

[To be filled in Wave 3]

---

#### Error: "Invalid license key format"

**Symptom**: Validation fails with format error

**Possible Causes**:

[To be filled in Wave 3]

**Resolution**:

[To be filled in Wave 3]

---

#### Error: "Database connection failed"

**Symptom**: Operations fail with database errors

**Possible Causes**:

[To be filled in Wave 3]

**Resolution**:

[To be filled in Wave 3]

---

## Testing

### Unit Testing License Tools

```python
[To be filled in Wave 3]
```

### Integration Testing with MCP Server

```python
[To be filled in Wave 3]
```

---

## Best Practices

1. **Always handle errors gracefully**: License operations may fail due to network, permissions, or rate limits
2. **Cache validation results**: Avoid excessive validation calls by caching results (with appropriate TTL)
3. **Use appropriate timeouts**: Set reasonable timeouts for MCP tool calls
4. **Log operations**: Track license operations for debugging and auditing
5. **Rotate expired keys**: Regularly clean up expired license keys from your systems
6. **Monitor rate limits**: Track usage to avoid hitting rate limits during critical operations
7. **Secure storage**: Never log or expose license keys in plaintext

---

## Advanced Usage

### Custom Tier Configuration

```python
[To be filled in Wave 3]
```

### Automated License Lifecycle Management

```python
[To be filled in Wave 3]
```

### Integration with CI/CD Pipelines

```bash
[To be filled in Wave 3]
```

---

## See Also

- [License MCP Tools API Reference](../api/MCP_TOOLS_LICENSE.md)
- [RBAC Implementation Guide](../security/RBAC_IMPLEMENTATION_GUIDE.md)
- [Security Best Practices](../security/SECURITY_BEST_PRACTICES.md)
- [MCP Server Configuration](../../README.md#mcp-server-setup)
