# License Management MCP Tools

## Overview

This document describes the MCP (Model Context Protocol) tools for managing agent license keys in the TMWS system. These tools enable automated license generation, validation, revocation, and usage tracking with role-based access control.

## Authentication

All MCP tools require authentication via **API Key** or **JWT Token**. The authenticated agent's role determines which operations are permitted.

### Authentication Methods

**Option 1: API Key Authentication**

```python
from uuid import UUID

result = await generate_license_key(
    db_session=session,
    agent_id=UUID("550e8400-e29b-41d4-a716-446655440000"),
    tier="PRO",
    expires_days=365,
    api_key="sk_prod_abc123..."  # API key authentication
)
```

**Option 2: JWT Token Authentication**

```python
result = await generate_license_key(
    db_session=session,
    agent_id=UUID("550e8400-e29b-41d4-a716-446655440000"),
    tier="PRO",
    expires_days=365,
    jwt_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."  # JWT authentication
)
```

### HTTP Request Headers (MCP over HTTP)

```http
POST /mcp/tools/generate_license_key HTTP/1.1
Host: api.tmws.example.com
Content-Type: application/json
Authorization: Bearer sk_prod_abc123...

{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "tier": "PRO",
  "expires_days": 365
}
```

### Authentication Errors

**Error: Invalid API Key**
```json
{
  "error": "AuthenticationError",
  "message": "Invalid API key",
  "details": {
    "error_code": "INVALID_API_KEY",
    "hint": "Check that your API key is correct and active"
  }
}
```

**Error: Expired JWT Token**
```json
{
  "error": "AuthenticationError",
  "message": "JWT token expired",
  "details": {
    "error_code": "EXPIRED_TOKEN",
    "expired_at": "2025-11-14T10:00:00Z",
    "hint": "Generate a new JWT token"
  }
}
```

## Tools

### generate_license_key

**Permission Required**: `license:generate` (editor/admin role)

**Description**:

Generates a new license key for the specified agent. The license key format is `TMWS-{TIER}-{UUID}-{CHECKSUM}` where the checksum is an HMAC-SHA256 signature to prevent tampering.

**Who can use this?**

| Role | Permission |
|------|-----------|
| Viewer | ❌ Denied |
| Editor | ✅ Allowed |
| Admin | ✅ Allowed |

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| agent_id | string (UUID) | Yes | UUID of the agent for whom to generate the license. Must exist in the database. |
| tier | string | Yes | License tier, one of: `FREE`, `PRO`, `ENTERPRISE`. Determines feature access and rate limits. |
| expires_days | integer | No | Number of days until license expires (1-3650). If omitted, generates a perpetual license (never expires). |
| api_key | string | No | API key for authentication (provide either `api_key` or `jwt_token`). |
| jwt_token | string | No | JWT bearer token for authentication (provide either `api_key` or `jwt_token`). |

**Returns**:

```json
{
  "license_key": "string",       // Generated license key (TMWS-{TIER}-{UUID}-{CHECKSUM})
  "license_id": "string (UUID)", // License UUID for future reference
  "tier": "string",              // License tier (FREE/PRO/ENTERPRISE)
  "issued_at": "string (ISO)",   // ISO 8601 datetime when license was issued
  "expires_at": "string (ISO)|null"  // ISO 8601 datetime when license expires (null if perpetual)
}
```

**Errors**:

| Code | Message | Cause |
|------|---------|-------|
| `PermissionError` | Role viewer lacks permission for operation license:generate | Agent has viewer role (insufficient permissions) |
| `ValidationError` | Invalid tier: {tier}. Must be one of: FREE, PRO, ENTERPRISE | Invalid tier parameter |
| `ValidationError` | expires_days must be positive (got: {value}) | Negative or zero expires_days |
| `ValidationError` | Agent not found | agent_id does not exist in database |
| `AuthenticationError` | Invalid API key | api_key is invalid or expired |

**Example**:

```json
// Request
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "tier": "PRO",
  "expires_days": 365
}

// Response (200 OK)
{
  "license_key": "TMWS-PRO-a1b2c3d4-e5f6-7890-abcd-ef1234567890-8F2A3D4E5B6C7A8D",
  "license_id": "123e4567-e89b-12d3-a456-426614174000",
  "tier": "PRO",
  "issued_at": "2025-11-15T10:30:00Z",
  "expires_at": "2026-11-15T10:30:00Z"
}

// Error Response (403 Forbidden)
{
  "error": "PermissionError",
  "message": "Role viewer lacks permission for operation license:generate",
  "details": {
    "agent_id": "550e8400-e29b-41d4-a716-446655440000",
    "operation": "license:generate",
    "required_role": "editor or admin"
  }
}
```

---

### validate_license_key

**Permission Required**: `license:validate` (all roles)

**Description**:

Validates a license key's format, checksum, expiration, and revocation status. Returns detailed information about the license if valid.

**Who can use this?**

| Role | Permission |
|------|-----------|
| Viewer | ✅ Allowed |
| Editor | ✅ Allowed |
| Admin | ✅ Allowed |

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| agent_id | string (UUID) | Yes | UUID of the agent requesting validation (required for RBAC). |
| key | string | Yes | License key to validate (format: `TMWS-{TIER}-{UUID}-{CHECKSUM}`). |
| feature_accessed | string | No | Optional feature name for usage tracking (e.g., "semantic_search", "workflow_execution"). |
| api_key | string | No | API key for authentication. |
| jwt_token | string | No | JWT bearer token for authentication. |

**Returns**:

```json
{
  "valid": "boolean",           // True if license is valid and active
  "tier": "string|null",        // License tier (FREE/PRO/ENTERPRISE) if valid
  "expires_at": "string|null",  // ISO 8601 expiration datetime if applicable
  "is_perpetual": "boolean",    // True if license never expires
  "agent_id": "string|null",    // Agent UUID if license is valid
  "error": "string|null"        // Error message if validation failed
}
```

**Errors**:

| Code | Message | Cause |
|------|---------|-------|
| `ValidationError` | Invalid license key format | Key does not match `TMWS-{TIER}-{UUID}-{CHECKSUM}` pattern |
| `ValidationError` | Invalid checksum | HMAC signature verification failed (tampered key) |

**Example**:

```json
// Request
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "key": "TMWS-PRO-a1b2c3d4-e5f6-7890-abcd-ef1234567890-8F2A3D4E5B6C7A8D",
  "feature_accessed": "semantic_search"
}

// Response (200 OK) - Valid License
{
  "valid": true,
  "tier": "PRO",
  "expires_at": "2026-11-15T10:30:00Z",
  "is_perpetual": false,
  "agent_id": "123e4567-e89b-12d3-a456-426614174000",
  "error": null
}

// Response (200 OK) - Invalid License
{
  "valid": false,
  "tier": null,
  "expires_at": null,
  "is_perpetual": false,
  "agent_id": null,
  "error": "License key expired on 2025-10-01T00:00:00Z"
}
```

---

### revoke_license_key

**Permission Required**: `license:revoke` (admin role only)

**Description**:

Immediately revokes a license key, preventing any further use. This operation is irreversible and creates an audit log entry.

**Who can use this?**

| Role | Permission |
|------|-----------|
| Viewer | ❌ Denied |
| Editor | ❌ Denied |
| Admin | ✅ Allowed |

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| agent_id | string (UUID) | Yes | UUID of the admin agent requesting revocation. |
| license_id | string (UUID) | Yes | UUID of the license to revoke (not the license key string). |
| reason | string | No | Revocation reason for audit trail (e.g., "expired_subscription", "policy_violation", "user_request"). |
| api_key | string | No | API key for authentication. |
| jwt_token | string | No | JWT bearer token for authentication. |

**Returns**:

```json
{
  "success": "boolean",           // True if revocation succeeded
  "license_id": "string (UUID)",  // License UUID that was revoked
  "revoked_at": "string (ISO)",   // ISO 8601 datetime when license was revoked
  "reason": "string|null"         // Revocation reason if provided
}
```

**Errors**:

| Code | Message | Cause |
|------|---------|-------|
| `PermissionError` | Role editor lacks permission for operation license:revoke | Agent has editor role (admin required) |
| `NotFoundError` | LicenseKey not found | license_id does not exist |

**Example**:

```json
// Request
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "license_id": "123e4567-e89b-12d3-a456-426614174000",
  "reason": "expired_subscription"
}

// Response (200 OK)
{
  "success": true,
  "license_id": "123e4567-e89b-12d3-a456-426614174000",
  "revoked_at": "2025-11-15T11:00:00Z",
  "reason": "expired_subscription"
}
```

---

### get_license_usage

**Permission Required**: `license:usage:read` (with ownership check)

**Description**:

Retrieves usage history for a license key, including which features were accessed and when. **Viewer/Editor** can only read their own license usage; **Admin** can read any license.

**Who can use this?**

| Role | Permission | Ownership Check |
|------|-----------|-----------------|
| Viewer | ✅ Allowed | Own licenses only |
| Editor | ✅ Allowed | Own licenses only |
| Admin | ✅ Allowed | Any license |

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| agent_id | string (UUID) | Yes | UUID of the agent requesting usage data. |
| license_id | string (UUID) | Yes | UUID of the license to query. |
| start_date | string (ISO 8601) | No | Filter usage from this datetime (inclusive). |
| end_date | string (ISO 8601) | No | Filter usage to this datetime (inclusive). |
| limit | integer | No | Maximum records to return (default: 100, max: 1000). |
| api_key | string | No | API key for authentication. |
| jwt_token | string | No | JWT bearer token for authentication. |

**Returns**:

```json
[
  {
    "id": "string (UUID)",           // Usage record UUID
    "used_at": "string (ISO)",       // ISO 8601 datetime when feature was accessed
    "feature_accessed": "string|null", // Feature name (e.g., "semantic_search")
    "request_id": "string|null"      // Optional request correlation ID
  }
]
```

**Example**:

```json
// Request
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "license_id": "123e4567-e89b-12d3-a456-426614174000",
  "start_date": "2025-11-01T00:00:00Z",
  "end_date": "2025-11-15T23:59:59Z",
  "limit": 10
}

// Response (200 OK)
[
  {
    "id": "789e0123-e45b-67c8-d901-234567890abc",
    "used_at": "2025-11-15T10:30:00Z",
    "feature_accessed": "semantic_search",
    "request_id": "req_abc123"
  },
  {
    "id": "890f1234-f56c-78d9-e012-345678901bcd",
    "used_at": "2025-11-14T15:45:00Z",
    "feature_accessed": "workflow_execution",
    "request_id": null
  }
]
```

---

### get_license_history

**Permission Required**: `license:read` (with ownership check)

**Description**:

Retrieves all license keys generated for an agent, including active, expired, and revoked licenses. **Viewer/Editor** can only read their own history; **Admin** can read any agent's history.

**Who can use this?**

| Role | Permission | Ownership Check |
|------|-----------|-----------------|
| Viewer | ✅ Allowed | Own history only |
| Editor | ✅ Allowed | Own history only |
| Admin | ✅ Allowed | Any agent |

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| agent_id | string (UUID) | Yes | UUID of the agent requesting history. |
| target_agent_id | string (UUID) | Yes | UUID of the agent whose license history to retrieve. |
| limit | integer | No | Maximum records to return (default: 100, max: 1000). |
| offset | integer | No | Pagination offset (default: 0). |
| api_key | string | No | API key for authentication. |
| jwt_token | string | No | JWT bearer token for authentication. |

**Returns**:

```json
{
  "total": "integer",          // Total number of licenses
  "licenses": [
    {
      "license_id": "string (UUID)",  // License UUID
      "tier": "string",               // License tier (FREE/PRO/ENTERPRISE)
      "issued_at": "string (ISO)",    // When license was issued
      "expires_at": "string|null",    // When license expires (null if perpetual)
      "revoked_at": "string|null",    // When license was revoked (null if active)
      "status": "string"              // "active", "expired", or "revoked"
    }
  ]
}
```

**Example**:

```json
// Request
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "target_agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "limit": 10,
  "offset": 0
}

// Response (200 OK)
{
  "total": 3,
  "licenses": [
    {
      "license_id": "123e4567-e89b-12d3-a456-426614174000",
      "tier": "PRO",
      "issued_at": "2025-11-15T10:30:00Z",
      "expires_at": "2026-11-15T10:30:00Z",
      "revoked_at": null,
      "status": "active"
    },
    {
      "license_id": "234f5678-f90c-23d4-b567-527614174001",
      "tier": "FREE",
      "issued_at": "2025-10-01T08:00:00Z",
      "expires_at": "2025-10-31T23:59:59Z",
      "revoked_at": null,
      "status": "expired"
    },
    {
      "license_id": "345g6789-g01d-34e5-c678-638714174002",
      "tier": "PRO",
      "issued_at": "2025-09-01T12:00:00Z",
      "expires_at": null,
      "revoked_at": "2025-10-15T10:00:00Z",
      "status": "revoked"
    }
  ]
}
```

---

## Rate Limiting

All MCP tools are subject to rate limiting based on the authenticated agent's tier:

| Tier | Generate License | Validate License | Revoke License | Get Usage/History |
|------|------------------|------------------|----------------|-------------------|
| **FREE** | 10/hour | 100/hour | N/A | 50/hour |
| **PRO** | 100/hour | 1000/hour | 10/hour | 500/hour |
| **ENTERPRISE** | Unlimited | Unlimited | 100/hour | Unlimited |

**Rate Limit Headers** (HTTP responses):

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1699999999
```

**Rate Limit Exceeded Error**:

```json
{
  "error": "RateLimitExceeded",
  "message": "Rate limit exceeded for operation license:generate",
  "details": {
    "limit": 10,
    "window": "3600",
    "retry_after": 1200
  }
}
```

## Security Considerations

- All license keys are encrypted at rest
- License validation checks namespace isolation
- Audit logs are generated for all license operations
- Failed authentication attempts are logged and rate-limited

## See Also

- [RBAC Implementation Guide](../security/RBAC_IMPLEMENTATION_GUIDE.md)
- [Usage Examples](../examples/LICENSE_MCP_EXAMPLES.md)
- [Security Audit Documentation](../security/PHASE_1_SECURITY_AUDIT_REPORT.md)
