# API Key Management - User Self-Service

## Overview

TMWS provides comprehensive API key management endpoints that allow users to create, list, and revoke their own API keys without administrative intervention.

**Security Note**: These endpoints require JWT authentication (NOT API key authentication). Users can only manage their own API keys.

---

## Endpoints

### 1. Create API Key

**POST** `/api/v1/auth/api-keys/`

Create a new API key for the authenticated user.

#### Authentication
- **Required**: JWT Bearer Token
- **Authorization**: Any authenticated user

#### Request Body

```json
{
  "name": "My API Key",
  "description": "For production service",
  "scopes": ["read", "write"],
  "expires_days": null
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable key name (2-128 chars) |
| `description` | string | No | Key purpose description (max 500 chars) |
| `scopes` | array[string] | No | Access scopes (default: `["read"]`) |
| `expires_days` | integer\|null | No | Expiration in days (null = unlimited) |

#### Available Scopes

- `read` - Read-only access
- `write` - Read and write access
- `full` - Full API access
- `admin` - Administrative operations
- `memory` - Memory operations only
- `tasks` - Task operations only
- `workflows` - Workflow operations only

#### Response (201 Created)

```json
{
  "api_key": "abc123def456.1234567890abcdef1234567890abcdef",
  "key_info": {
    "key_id": "abc123def456",
    "name": "My API Key",
    "description": "For production service",
    "key_prefix": "12345678",
    "scopes": ["read", "write"],
    "is_active": true,
    "expires_at": null,
    "last_used_at": null,
    "total_requests": 0,
    "created_at": "2025-01-05T12:00:00Z"
  }
}
```

**IMPORTANT**: The `api_key` field contains the full API key in format `{key_id}.{raw_key}`. This is **ONLY shown once** - store it securely! You cannot retrieve it later.

#### Error Responses

- **400 Bad Request**: Invalid input (name too short/long, invalid scopes)
- **401 Unauthorized**: Missing or invalid JWT token
- **422 Unprocessable Entity**: Validation error (e.g., expires_days <= 0)
- **500 Internal Server Error**: Server-side error

---

### 2. List API Keys

**GET** `/api/v1/auth/api-keys/`

List all API keys for the authenticated user.

#### Authentication
- **Required**: JWT Bearer Token
- **Authorization**: Any authenticated user

#### Response (200 OK)

```json
{
  "api_keys": [
    {
      "key_id": "abc123def456",
      "name": "My API Key",
      "description": "For production service",
      "key_prefix": "12345678",
      "scopes": ["read", "write"],
      "is_active": true,
      "expires_at": null,
      "last_used_at": "2025-01-05T11:00:00Z",
      "total_requests": 1523,
      "created_at": "2025-01-04T10:00:00Z"
    },
    {
      "key_id": "xyz789ghi012",
      "name": "Development Key",
      "description": "For local testing",
      "key_prefix": "abcdefgh",
      "scopes": ["read"],
      "is_active": false,
      "expires_at": "2025-02-01T00:00:00Z",
      "last_used_at": "2025-01-03T15:30:00Z",
      "total_requests": 42,
      "created_at": "2025-01-01T09:00:00Z"
    }
  ],
  "total": 2
}
```

**Security**: Raw API keys are NEVER returned. Only the `key_prefix` (first 8 characters) is shown for identification.

#### Error Responses

- **401 Unauthorized**: Missing or invalid JWT token
- **500 Internal Server Error**: Server-side error

---

### 3. Revoke API Key

**DELETE** `/api/v1/auth/api-keys/{key_id}`

Revoke (deactivate) an API key. Revoked keys cannot be reactivated.

#### Authentication
- **Required**: JWT Bearer Token
- **Authorization**: User can only revoke their own keys

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `key_id` | string | The key_id to revoke (from list endpoint) |

#### Response (200 OK)

```json
{
  "message": "API key revoked successfully",
  "key_id": "abc123def456"
}
```

#### Error Responses

- **401 Unauthorized**: Missing or invalid JWT token
- **403 Forbidden**: Attempting to revoke another user's key
- **404 Not Found**: Key not found or belongs to different user
- **500 Internal Server Error**: Server-side error

---

## Usage Examples

### Create API Key with cURL

```bash
# Obtain JWT token first (via login endpoint)
TOKEN="your_jwt_token_here"

# Create API key
curl -X POST http://localhost:8000/api/v1/auth/api-keys/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Service Key",
    "description": "Used by production microservice",
    "scopes": ["read", "write", "tasks"],
    "expires_days": 90
  }'

# Response includes the API key - SAVE IT!
# {
#   "api_key": "abc123.def456ghi789...",
#   "key_info": { ... }
# }
```

### List API Keys

```bash
curl -X GET http://localhost:8000/api/v1/auth/api-keys/ \
  -H "Authorization: Bearer $TOKEN"
```

### Revoke API Key

```bash
# Get key_id from list endpoint
KEY_ID="abc123def456"

curl -X DELETE http://localhost:8000/api/v1/auth/api-keys/$KEY_ID \
  -H "Authorization: Bearer $TOKEN"
```

### Using the API Key

Once created, use the API key in requests:

```bash
# Store the full API key
API_KEY="abc123def456.1234567890abcdef..."

# Make authenticated request
curl -X GET http://localhost:8000/api/v1/tasks \
  -H "X-API-Key: $API_KEY"
```

---

## Python SDK Example

```python
import httpx
from typing import List

class TMWSClient:
    """TMWS API Client with key management."""

    def __init__(self, base_url: str, jwt_token: str):
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {jwt_token}"}

    def create_api_key(
        self,
        name: str,
        scopes: List[str] = None,
        description: str = None,
        expires_days: int = None,
    ) -> dict:
        """Create new API key."""
        payload = {
            "name": name,
            "scopes": scopes or ["read"],
        }
        if description:
            payload["description"] = description
        if expires_days:
            payload["expires_days"] = expires_days

        response = httpx.post(
            f"{self.base_url}/api/v1/auth/api-keys/",
            json=payload,
            headers=self.headers,
        )
        response.raise_for_status()
        return response.json()

    def list_api_keys(self) -> dict:
        """List all API keys."""
        response = httpx.get(
            f"{self.base_url}/api/v1/auth/api-keys/",
            headers=self.headers,
        )
        response.raise_for_status()
        return response.json()

    def revoke_api_key(self, key_id: str) -> dict:
        """Revoke API key."""
        response = httpx.delete(
            f"{self.base_url}/api/v1/auth/api-keys/{key_id}",
            headers=self.headers,
        )
        response.raise_for_status()
        return response.json()

# Usage
client = TMWSClient("http://localhost:8000", jwt_token="your_token")

# Create key
result = client.create_api_key(
    name="My Service Key",
    scopes=["read", "write", "memory"],
    description="Production API key for service X",
    expires_days=90,
)

# IMPORTANT: Save the API key!
api_key = result["api_key"]
print(f"API Key (save this!): {api_key}")

# List keys
keys = client.list_api_keys()
print(f"Total keys: {keys['total']}")

# Revoke key
client.revoke_api_key(result["key_info"]["key_id"])
```

---

## Security Considerations

### 1. API Key Storage
- **CRITICAL**: Raw API keys are only shown once during creation
- Store API keys in secure secret management systems (e.g., HashiCorp Vault, AWS Secrets Manager)
- Never commit API keys to version control
- Never log raw API keys

### 2. Scope Principle of Least Privilege
- Only grant scopes that are actually needed
- Use `read` scope for read-only operations
- Avoid `full` and `admin` scopes unless absolutely necessary
- Create separate keys for different services/purposes

### 3. Expiration Management
- Set `expires_days` for temporary keys
- Use unlimited expiration (`null`) only for long-lived production services
- Regularly rotate API keys (recommended: every 90 days)

### 4. Key Revocation
- Revoke compromised keys immediately
- Revoked keys cannot be reactivated - create new keys instead
- Monitor `last_used_at` to identify unused keys

### 5. Rate Limiting
- API keys are subject to rate limiting (configurable per key)
- Default: No rate limit (as per requirements)
- Production deployments should enable rate limiting

### 6. IP Restrictions
- Currently disabled (as per requirements)
- Future versions may support IP allowlisting

---

## Best Practices

### 1. Key Naming Convention
Use descriptive names that indicate:
- Service/application using the key
- Environment (production, staging, development)
- Purpose/scope

Examples:
- "Production Web Service - Read Only"
- "Staging Data Import - Write Access"
- "Development Testing - Full Access"

### 2. Key Rotation
```python
# Recommended rotation workflow
def rotate_api_key(client, old_key_id, key_name):
    # 1. Create new key
    new_key = client.create_api_key(
        name=f"{key_name} (rotated)",
        scopes=["read", "write"],
        expires_days=90,
    )

    # 2. Update service to use new key
    update_service_config(new_key["api_key"])

    # 3. Wait for old key to be unused
    time.sleep(300)  # 5 minutes grace period

    # 4. Revoke old key
    client.revoke_api_key(old_key_id)

    return new_key
```

### 3. Monitoring
Monitor these metrics:
- `total_requests` - Detect unusual activity
- `last_used_at` - Identify inactive keys
- `is_active` - Track revoked keys

---

## FAQ

### Q: Can I retrieve a raw API key after creation?
**A**: No. Raw API keys are only shown once during creation for security reasons. If lost, create a new key and revoke the old one.

### Q: What happens to API calls using a revoked key?
**A**: They will fail with `401 Unauthorized` error. The key is immediately unusable after revocation.

### Q: Can I reactivate a revoked key?
**A**: No. Once revoked, a key cannot be reactivated. Create a new key instead.

### Q: How many API keys can I create?
**A**: No hard limit, but it's recommended to keep the number manageable (typically 5-10 per user).

### Q: Do API keys expire automatically?
**A**: Only if you set `expires_days` during creation. Keys with `null` expiration never expire.

### Q: What's the difference between JWT tokens and API keys?
**A**:
- JWT tokens are for user authentication (web/mobile apps)
- API keys are for service-to-service authentication (long-lived)
- JWT tokens expire quickly (15 minutes), API keys can be unlimited
- Use JWT tokens for interactive sessions, API keys for automated services

---

## Integration Points

### 1. AuthService Methods Used
- `create_api_key()` - Create new key
- `list_user_api_keys()` - List user's keys
- `revoke_api_key()` - Revoke key
- `validate_api_key()` - Validate key (used by other endpoints)

### 2. Security Dependencies
- JWT authentication via `get_current_user` dependency
- User ID extraction from JWT token
- Bcrypt hashing for key storage

### 3. Database Models
- `APIKey` model (key_id, key_hash, key_prefix, scopes, expires_at, etc.)
- `User` model (key owner)

---

## Troubleshooting

### Error: "API key required in X-API-Key header"
**Solution**: Ensure you're using the API key in the correct header format:
```bash
curl -H "X-API-Key: your_key_id.your_raw_key" ...
```

### Error: "Invalid API key format"
**Solution**: API keys must be in format `{key_id}.{raw_key}`. Don't split or modify the key.

### Error: "API key not found or access denied"
**Solution**:
- Verify you're using the correct `key_id`
- Ensure you're the owner of the key
- Check if the key was already revoked

### Error: "Authentication required - missing credentials"
**Solution**: These endpoints require JWT authentication. Include your JWT token:
```bash
curl -H "Authorization: Bearer your_jwt_token" ...
```

---

## Version History

- **v2.2.0** (2025-01-09): Initial implementation of user self-service API key management
  - Create API key endpoint
  - List API keys endpoint
  - Revoke API key endpoint
  - Comprehensive security validation
  - Integration with existing AuthService
