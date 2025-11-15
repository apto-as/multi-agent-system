# Authentication Guide

**Version**: v2.3.0
**Last Updated**: 2025-11-13

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication Flow](#authentication-flow)
3. [JWT Token Format](#jwt-token-format)
4. [Generating Tokens](#generating-tokens)
5. [Using Tokens](#using-tokens)
6. [Token Validation](#token-validation)
7. [Security Best Practices](#security-best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Overview

TMWS uses JWT (JSON Web Tokens) for stateless authentication. All MCP Connection Management API endpoints require a valid JWT token in the `Authorization` header.

### Key Concepts

- **JWT**: Self-contained token with agent identity
- **Stateless**: No server-side session storage required
- **P0-1 Security**: Namespace verified from database (not trusted from token)
- **HS256 Algorithm**: HMAC with SHA-256 signing

---

## Authentication Flow

### Complete Authentication Process

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant DB

    Client->>API: Request with JWT token
    API->>API: Decode JWT (extract agent_id)
    API->>DB: Fetch agent by agent_id
    DB-->>API: Agent record (with namespace)
    API->>API: Verify namespace matches request
    API-->>Client: Authorized response
```

### Step-by-Step Breakdown

1. **Client sends request** with JWT token in `Authorization` header
2. **API decodes JWT** to extract `agent_id` from `sub` (subject) claim
3. **API fetches agent** from database to get **verified namespace**
4. **API verifies** request namespace matches agent's verified namespace
5. **API processes request** if authorized

### Security Critical: Namespace Verification

⚠️ **Never trust namespace from JWT claims directly**

```python
# ❌ WRONG: Trusting JWT claims (SECURITY VULNERABILITY)
namespace = jwt_claims.get("namespace")  # Can be forged!

# ✅ CORRECT: Verify from database
agent = await db.get_agent(agent_id)
verified_namespace = agent.namespace  # Source of truth
```

This prevents **namespace spoofing attacks** where an attacker modifies JWT claims to access other tenants' data.

---

## JWT Token Format

### Token Structure

JWT tokens have three parts separated by dots (`.`):

```
<header>.<payload>.<signature>
```

Example:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJleHAiOjE2OTk4NzY1NDN9.abc123...
```

### Header

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

- `alg`: Signing algorithm (HMAC with SHA-256)
- `typ`: Token type (JWT)

### Payload (Claims)

**Required Claims:**

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "exp": 1699876543
}
```

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | string (UUID) | Agent ID (subject) |
| `exp` | integer (Unix timestamp) | Token expiration time |

**Optional Claims:**

```json
{
  "iat": 1699876243,
  "roles": ["user", "admin"]
}
```

| Claim | Type | Description |
|-------|------|-------------|
| `iat` | integer | Issued at timestamp |
| `roles` | array[string] | User roles (for future RBAC) |

⚠️ **Security Note**: Do NOT include sensitive data like namespace in JWT payload. Namespace is verified from database.

### Signature

The signature is computed as:

```
HMAC-SHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret_key
)
```

---

## Generating Tokens

### Python Example

```python
from datetime import datetime, timedelta
from jose import jwt

# Configuration
SECRET_KEY = "your-32-char-minimum-secret-key-here"
ALGORITHM = "HS256"

def create_access_token(agent_id: str, expires_delta: timedelta = None) -> str:
    """Generate JWT token for agent.

    Args:
        agent_id: UUID of agent
        expires_delta: Token lifetime (default: 24 hours)

    Returns:
        JWT token string
    """
    if expires_delta is None:
        expires_delta = timedelta(hours=24)

    expire = datetime.utcnow() + expires_delta

    payload = {
        "sub": agent_id,  # Subject (agent ID)
        "exp": expire,    # Expiration
        "iat": datetime.utcnow()  # Issued at
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

# Usage
agent_id = "550e8400-e29b-41d4-a716-446655440000"
token = create_access_token(agent_id, expires_delta=timedelta(hours=24))
print(f"Token: {token}")
```

### Node.js Example

```javascript
const jwt = require('jsonwebtoken');

// Configuration
const SECRET_KEY = 'your-32-char-minimum-secret-key-here';
const ALGORITHM = 'HS256';

function createAccessToken(agentId, expiresIn = '24h') {
  /**
   * Generate JWT token for agent.
   *
   * @param {string} agentId - UUID of agent
   * @param {string} expiresIn - Token lifetime (e.g., '24h', '7d')
   * @returns {string} JWT token
   */
  const payload = {
    sub: agentId,  // Subject (agent ID)
    iat: Math.floor(Date.now() / 1000)  // Issued at
  };

  const token = jwt.sign(payload, SECRET_KEY, {
    algorithm: ALGORITHM,
    expiresIn: expiresIn
  });

  return token;
}

// Usage
const agentId = '550e8400-e29b-41d4-a716-446655440000';
const token = createAccessToken(agentId, '24h');
console.log(`Token: ${token}`);
```

### Bash Example (for testing)

```bash
#!/bin/bash

# Generate JWT token for testing (requires 'jq' and 'openssl')

AGENT_ID="550e8400-e29b-41d4-a716-446655440000"
SECRET_KEY="your-32-char-minimum-secret-key-here"
EXPIRY=$(($(date +%s) + 86400))  # 24 hours from now

# Create header
HEADER=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')

# Create payload
PAYLOAD=$(echo -n "{\"sub\":\"$AGENT_ID\",\"exp\":$EXPIRY}" | base64 | tr -d '=' | tr '+/' '-_')

# Create signature
SIGNATURE=$(echo -n "$HEADER.$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET_KEY" -binary | base64 | tr -d '=' | tr '+/' '-_')

# Combine into JWT
JWT="$HEADER.$PAYLOAD.$SIGNATURE"
echo "Token: $JWT"
```

---

## Using Tokens

### HTTP Request Example

```http
GET /api/v1/mcp/connections/550e8400-e29b-41d4-a716-446655440000/tools HTTP/1.1
Host: localhost:8000
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
```

### cURL Example

```bash
curl -X GET http://localhost:8000/api/v1/mcp/connections/550e8400-e29b-41d4-a716-446655440000/tools \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json"
```

### Python Requests Example

```python
import requests

BASE_URL = "http://localhost:8000"
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

response = requests.get(
    f"{BASE_URL}/api/v1/mcp/connections/550e8400-e29b-41d4-a716-446655440000/tools",
    headers=headers
)

print(response.json())
```

### JavaScript Fetch Example

```javascript
const BASE_URL = 'http://localhost:8000';
const TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';

async function getConnectionTools(connectionId) {
  const response = await fetch(
    `${BASE_URL}/api/v1/mcp/connections/${connectionId}/tools`,
    {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${TOKEN}`,
        'Content-Type': 'application/json'
      }
    }
  );

  return await response.json();
}

// Usage
const tools = await getConnectionTools('550e8400-e29b-41d4-a716-446655440000');
console.log(tools);
```

---

## Token Validation

### Validation Process

The server validates tokens through these steps:

1. **Extract token** from `Authorization: Bearer <token>` header
2. **Verify signature** using secret key
3. **Check expiration** (`exp` claim must be in future)
4. **Extract agent_id** from `sub` claim
5. **Verify agent exists** in database
6. **Extract verified namespace** from agent record

### Validation Errors

| Error | HTTP Status | Description |
|-------|-------------|-------------|
| Missing Authorization header | 401 | No token provided |
| Invalid token format | 401 | Token not in Bearer format |
| Invalid signature | 401 | Token tampered or wrong secret key |
| Expired token | 401 | Token `exp` claim is in past |
| Agent not found | 401 | Agent ID from token doesn't exist in DB |
| Server configuration error | 500 | Secret key not configured |

### Example Error Responses

**Missing Token:**
```json
{
  "detail": "Not authenticated"
}
```

**Invalid Token:**
```json
{
  "detail": "Could not validate credentials"
}
```

**Agent Not Found:**
```json
{
  "detail": "Agent not found"
}
```

---

## Security Best Practices

### Secret Key Management

#### Production

```bash
# Generate secure random key (64 hex characters = 32 bytes)
openssl rand -hex 32

# Store in environment variable (NEVER commit to git)
export TMWS_SECRET_KEY="your-generated-key-here"
```

#### Development

```bash
# For local development only
export TMWS_SECRET_KEY="development-secret-key-min-32-chars-required"
```

#### Using .env File

```bash
# .env (add to .gitignore!)
TMWS_SECRET_KEY=your-secret-key-here
TMWS_ENVIRONMENT=development
```

**⚠️ CRITICAL**: Never commit `.env` files to version control!

### Token Expiration

**Recommended Expiration Times:**

| Environment | Expiration | Rationale |
|-------------|------------|-----------|
| Development | 24 hours | Convenient for testing |
| Staging | 12 hours | Balance security & usability |
| Production | 1-4 hours | Minimize exposure window |
| API Keys | 90 days | Long-lived access |

**Example with Refresh Tokens:**

```python
def create_tokens(agent_id: str) -> tuple[str, str]:
    """Create access and refresh tokens.

    Returns:
        (access_token, refresh_token)
    """
    access_token = create_access_token(
        agent_id,
        expires_delta=timedelta(hours=1)  # Short-lived
    )

    refresh_token = create_access_token(
        agent_id,
        expires_delta=timedelta(days=7)  # Long-lived
    )

    return access_token, refresh_token
```

### Token Storage

#### Client-Side (Web)

```javascript
// ✅ GOOD: HttpOnly cookie (preferred)
// Server sets: Set-Cookie: token=...; HttpOnly; Secure; SameSite=Strict

// ⚠️ ACCEPTABLE: sessionStorage (cleared on tab close)
sessionStorage.setItem('jwt_token', token);

// ❌ AVOID: localStorage (persistent, XSS risk)
// localStorage.setItem('jwt_token', token);
```

#### Client-Side (Mobile)

```javascript
// Use secure encrypted storage
import * as SecureStore from 'expo-secure-store';

await SecureStore.setItemAsync('jwt_token', token);
```

#### Server-Side

```python
# Store in environment variable or secret manager
import os
SECRET_KEY = os.getenv('TMWS_SECRET_KEY')

# For production: use AWS Secrets Manager, Azure Key Vault, etc.
```

### Token Rotation

Implement token rotation to minimize exposure:

```python
def refresh_access_token(refresh_token: str) -> str:
    """Exchange refresh token for new access token.

    Args:
        refresh_token: Valid refresh token

    Returns:
        New access token

    Raises:
        HTTPException: If refresh token invalid/expired
    """
    try:
        # Validate refresh token
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        agent_id = payload.get("sub")

        # Generate new access token
        new_token = create_access_token(
            agent_id,
            expires_delta=timedelta(hours=1)
        )

        return new_token

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
```

### Rate Limiting

Combine authentication with rate limiting to prevent abuse:

```python
from fastapi import Depends, Request
from src.security.rate_limiter import check_rate_limit

@app.post("/api/v1/mcp/connections")
async def create_connection(
    request: Request,
    current_user: User = Depends(get_current_user),
    _rate_limit: None = Depends(check_rate_limit_mcp_create)
):
    # Both authentication and rate limiting enforced
    ...
```

---

## Troubleshooting

### Common Issues

#### 1. "Could not validate credentials"

**Cause**: Invalid token signature or wrong secret key

**Solution**:
```bash
# Check secret key is set
echo $TMWS_SECRET_KEY

# Verify secret key matches server configuration
grep TMWS_SECRET_KEY .env

# Regenerate token with correct secret key
```

#### 2. "Agent not found"

**Cause**: Agent ID in token doesn't exist in database

**Solution**:
```bash
# Check agent exists in database
sqlite3 ~/.tmws/data/tmws.db "SELECT * FROM agents WHERE agent_id = 'your-agent-id';"

# Create agent if missing
curl -X POST http://localhost:8000/api/v1/agents \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "your-agent-id", "namespace": "your-namespace"}'
```

#### 3. Token Expired

**Cause**: Token `exp` claim is in the past

**Solution**:
```python
# Check token expiration
import jwt
payload = jwt.decode(token, options={"verify_signature": False})
print(f"Expires at: {payload['exp']}")

# Generate new token
token = create_access_token(agent_id)
```

#### 4. "Namespace mismatch" (403 Forbidden)

**Cause**: Request namespace doesn't match agent's verified namespace

**Solution**:
```bash
# Check agent's namespace in database
sqlite3 ~/.tmws/data/tmws.db \
  "SELECT agent_id, namespace FROM agents WHERE agent_id = 'your-agent-id';"

# Use correct namespace in request
curl -X POST http://localhost:8000/api/v1/mcp/connections \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"namespace": "correct-namespace-from-db", ...}'
```

### Debug Mode

Enable debug logging to troubleshoot authentication:

```bash
export TMWS_LOG_LEVEL=DEBUG
export TMWS_DB_ECHO_SQL=true
```

Then check logs:

```bash
tail -f logs/tmws.log | grep -i "auth\|jwt\|token"
```

### Testing Authentication

Test token generation and validation:

```python
# tests/test_authentication.py
import pytest
from jose import jwt
from datetime import datetime, timedelta

def test_token_generation():
    """Test token can be generated and validated."""
    agent_id = "test-agent-id"
    secret_key = "test-secret-key-min-32-chars-12345"

    # Generate token
    payload = {
        "sub": agent_id,
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, secret_key, algorithm="HS256")

    # Validate token
    decoded = jwt.decode(token, secret_key, algorithms=["HS256"])
    assert decoded["sub"] == agent_id
```

---

## Reference

### Related Documentation

- [MCP Connection API](../api/MCP_CONNECTION_API.md)
- [Rate Limiting Guide](RATE_LIMITING_GUIDE.md)
- [Deployment Guide](../deployment/MCP_API_DEPLOYMENT.md)

### External Resources

- [JWT.io](https://jwt.io/) - JWT debugger and documentation
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) - JWT specification
- [OWASP JWT Security](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

---

**Document Author**: Muses (Knowledge Architect)
**Last Reviewed**: 2025-11-13
**Status**: Production-ready
