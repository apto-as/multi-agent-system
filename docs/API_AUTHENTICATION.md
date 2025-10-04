# API Authentication Guide

**TMWS v2.2.0 Authentication & Authorization**

This guide covers the complete authentication and authorization system for the Trinitas Memory & Workflow Service (TMWS).

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication Methods](#authentication-methods)
3. [JWT Token Authentication](#jwt-token-authentication)
4. [API Key Authentication](#api-key-authentication)
5. [Authorization & Scopes](#authorization--scopes)
6. [Development vs Production](#development-vs-production)
7. [Security Best Practices](#security-best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Overview

TMWS provides two authentication methods:

1. **JWT Token Authentication**: For user-based interactive sessions
2. **API Key Authentication**: For programmatic access and service integrations

Both methods support role-based access control (RBAC) and scope-based authorization.

### Authentication Flow Diagram

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ├─────────────────────────────────┐
       │                                 │
       ▼                                 ▼
┌─────────────┐                  ┌─────────────┐
│  JWT Token  │                  │  API Key    │
└──────┬──────┘                  └──────┬──────┘
       │                                 │
       └─────────────┬───────────────────┘
                     ▼
              ┌─────────────┐
              │   TMWS API  │
              └─────────────┘
```

---

## Authentication Methods

### 1. JWT Token Authentication

**Use Case**: User sessions, web applications, Claude Code integrations

**Flow**:
1. User authenticates with username/password
2. Receives access token (short-lived) and refresh token (long-lived)
3. Uses access token for API requests
4. Refreshes access token when expired using refresh token

**Advantages**:
- Stateless authentication
- Automatic expiration
- User session management
- Secure logout with token blacklisting

### 2. API Key Authentication

**Use Case**: Service-to-service, automation, CI/CD, third-party integrations

**Flow**:
1. User creates API key with specific scopes
2. API key is used in requests via `X-API-Key` header
3. Server validates key and checks permissions
4. API key can be revoked anytime

**Advantages**:
- No login required
- Fine-grained scope control
- IP address restrictions
- Rate limiting per key
- Usage tracking

---

## JWT Token Authentication

### Obtaining JWT Tokens

#### 1. User Login

**Endpoint**: `POST /api/v1/auth/login`

**Request**:
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your_username",
    "password": "your_password"
  }'
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "a1b2c3d4.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "username": "your_username",
    "email": "user@example.com",
    "roles": ["USER"],
    "agent_namespace": "default"
  }
}
```

#### 2. Using Access Token

Include the access token in the `Authorization` header:

```bash
curl http://localhost:8000/api/v1/tasks \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### 3. Refreshing Tokens

When access token expires (default: 1 hour), use refresh token:

**Endpoint**: `POST /api/v1/auth/refresh`

**Request**:
```bash
curl -X POST http://localhost:8000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "a1b2c3d4.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "e5f6g7h8.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

**Note**: Refresh tokens are single-use. Old refresh token is revoked when new one is issued.

#### 4. User Logout

**Endpoint**: `POST /api/v1/auth/logout`

**Request**:
```bash
curl -X POST http://localhost:8000/api/v1/auth/logout \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "a1b2c3d4.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

This will:
- Revoke the refresh token
- Blacklist the access token
- End the user session

---

## API Key Authentication

### Creating API Keys

#### 1. Create API Key

**Endpoint**: `POST /api/v1/auth/api-keys`

**Request**:
```bash
curl -X POST http://localhost:8000/api/v1/auth/api-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Service Key",
    "description": "API key for production automation",
    "scopes": ["READ", "WRITE"],
    "expires_days": 90,
    "allowed_ips": ["192.168.1.100", "10.0.0.0/24"],
    "rate_limit_per_hour": 1000
  }'
```

**Response**:
```json
{
  "key_id": "tmws_key_abc123def456",
  "api_key": "tmws_key_abc123def456.very_long_secure_random_string",
  "name": "Production Service Key",
  "scopes": ["READ", "WRITE"],
  "created_at": "2025-01-09T10:30:00Z",
  "expires_at": "2025-04-09T10:30:00Z",
  "allowed_ips": ["192.168.1.100", "10.0.0.0/24"],
  "rate_limit_per_hour": 1000
}
```

**IMPORTANT**: Store the `api_key` securely. It cannot be retrieved again.

#### 2. Using API Key

Include API key in the `X-API-Key` header:

```bash
curl http://localhost:8000/api/v1/tasks \
  -H "X-API-Key: tmws_key_abc123def456.very_long_secure_random_string"
```

#### 3. List API Keys

**Endpoint**: `GET /api/v1/auth/api-keys`

```bash
curl http://localhost:8000/api/v1/auth/api-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

**Response**:
```json
{
  "api_keys": [
    {
      "key_id": "tmws_key_abc123def456",
      "key_prefix": "tmws_key_",
      "name": "Production Service Key",
      "scopes": ["READ", "WRITE"],
      "created_at": "2025-01-09T10:30:00Z",
      "expires_at": "2025-04-09T10:30:00Z",
      "last_used_at": "2025-01-09T14:22:00Z",
      "usage_count": 342,
      "is_active": true
    }
  ],
  "total": 1
}
```

**Note**: Full API key is never returned after creation for security.

#### 4. Revoke API Key

**Endpoint**: `DELETE /api/v1/auth/api-keys/{key_id}`

```bash
curl -X DELETE http://localhost:8000/api/v1/auth/api-keys/tmws_key_abc123def456 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

---

## Authorization & Scopes

### User Roles

TMWS implements Role-Based Access Control (RBAC) with five roles:

| Role | Description | Typical Use Case |
|------|-------------|------------------|
| `SUPER_ADMIN` | Full system access | System administrators |
| `ADMIN` | Manage users, resources, policies | Project managers |
| `USER` | Standard user access | Regular users, developers |
| `READONLY` | Read-only access | Auditors, viewers |
| `SERVICE` | Service account access | Automation, CI/CD |

### Role Permissions Matrix

#### Resource Permissions

| Resource | SUPER_ADMIN | ADMIN | USER | READONLY | SERVICE |
|----------|-------------|-------|------|----------|---------|
| **Users** | Full | Create, Read, Update | Read (self) | Read (self) | None |
| **API Keys** | Full | Full | CRUD (own) | Read (own) | None |
| **Agents** | Full | Read, Update | Read | Read | Read |
| **Memories** | Full | Full | Full (own namespace) | Read | Create, Read, Update |
| **Tasks** | Full | Full | Full | Read | Create, Read, Update, Execute |
| **Workflows** | Full | Full | Full | Read | Create, Read, Execute |
| **Audit Logs** | Read, Audit | Read | None | None | None |
| **System Config** | Full | Read | None | None | None |

### API Key Scopes

API keys can have one or more of the following scopes:

| Scope | Permissions | Use Case |
|-------|-------------|----------|
| `FULL` | All operations except admin | Complete API access |
| `READ` | Read-only access to all resources | Monitoring, reporting |
| `WRITE` | Read + Create/Update (no delete) | Data entry, automation |
| `ADMIN` | Administrative operations | User management, configuration |
| `MEMORY` | Memory-specific operations | Memory service integration |
| `TASKS` | Task-specific operations | Task automation |
| `WORKFLOWS` | Workflow-specific operations | Workflow orchestration |

### Scope-Based Access Examples

#### READ Scope

```bash
# ✅ Allowed
GET /api/v1/tasks
GET /api/v1/memories
GET /api/v1/workflows

# ❌ Denied
POST /api/v1/tasks
PUT /api/v1/memories/{id}
DELETE /api/v1/workflows/{id}
```

#### WRITE Scope

```bash
# ✅ Allowed
GET /api/v1/tasks
POST /api/v1/tasks
PUT /api/v1/tasks/{id}

# ❌ Denied
DELETE /api/v1/tasks/{id}
POST /api/v1/users
```

#### MEMORY Scope

```bash
# ✅ Allowed
POST /api/v1/memory/store
POST /api/v1/memory/search
GET /api/v1/memory/recall

# ❌ Denied
POST /api/v1/tasks
POST /api/v1/workflows
```

---

## Development vs Production

### Development Mode (Default)

**Environment**: `TMWS_AUTH_ENABLED=false` or `TMWS_ENVIRONMENT=development`

**Behavior**:
- Authentication is **optional**
- All requests granted mock user with admin permissions
- Useful for local development and testing
- No credential management needed

**Example**:
```bash
# No authentication required
curl http://localhost:8000/api/v1/tasks

# Automatically granted all permissions
```

### Production Mode

**Environment**: `TMWS_AUTH_ENABLED=true` and `TMWS_ENVIRONMENT=production`

**Behavior**:
- Authentication is **required**
- All requests must include valid JWT or API key
- Full permission checking enforced
- Audit logging enabled

**Example**:
```bash
# ❌ Will fail with 401 Unauthorized
curl http://localhost:8000/api/v1/tasks

# ✅ Must include authentication
curl http://localhost:8000/api/v1/tasks \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Environment Configuration

```bash
# .env file for development
TMWS_ENVIRONMENT=development
TMWS_AUTH_ENABLED=false

# .env file for production
TMWS_ENVIRONMENT=production
TMWS_AUTH_ENABLED=true
TMWS_SECRET_KEY=your-very-long-random-secret-key-here
TMWS_JWT_EXPIRE_MINUTES=60
```

---

## Security Best Practices

### 1. Token Management

**DO**:
- ✅ Store tokens securely (keychain, environment variables, secrets manager)
- ✅ Use HTTPS in production
- ✅ Set appropriate token expiration times
- ✅ Implement token rotation
- ✅ Logout users when tokens are compromised

**DON'T**:
- ❌ Store tokens in localStorage (XSS vulnerability)
- ❌ Commit tokens to version control
- ❌ Share tokens between users
- ❌ Use long-lived access tokens
- ❌ Log tokens in application logs

### 2. API Key Security

**DO**:
- ✅ Create API keys with minimal required scopes
- ✅ Set expiration dates
- ✅ Use IP restrictions when possible
- ✅ Rotate keys regularly
- ✅ Monitor usage and revoke suspicious keys
- ✅ Store keys in secure vault (HashiCorp Vault, AWS Secrets Manager)

**DON'T**:
- ❌ Use `FULL` scope unless absolutely necessary
- ❌ Share API keys across services
- ❌ Hardcode keys in source code
- ❌ Use indefinite expiration
- ❌ Ignore rate limits

### 3. Password Requirements

TMWS enforces strong password policies:

- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)
- No common weak patterns (password, 123456, etc.)

### 4. Account Security

- Failed login attempts: Maximum 5 attempts
- Account lockout: 30 minutes after 5 failed attempts
- Password changes: Force logout all sessions
- Account suspension: Immediate session termination

### 5. Audit & Monitoring

All authentication events are logged:

```json
{
  "event_type": "LOGIN_SUCCESS",
  "timestamp": "2025-01-09T10:30:00Z",
  "user_id": "user@example.com",
  "ip_address": "192.168.1.100",
  "user_agent": "curl/7.68.0",
  "details": {
    "login_method": "password",
    "session_id": "sess_abc123"
  }
}
```

Monitor for:
- Multiple failed login attempts
- Login from unusual IP addresses
- Unusual API usage patterns
- Rate limit violations

---

## Troubleshooting

### Common Issues

#### 1. 401 Unauthorized

**Symptom**:
```json
{
  "error": "Authentication required - missing credentials",
  "status_code": 401
}
```

**Solutions**:
- Check that you're in production mode (`TMWS_AUTH_ENABLED=true`)
- Verify JWT token is included in `Authorization: Bearer TOKEN` header
- Verify API key is included in `X-API-Key` header
- Check token hasn't expired
- Ensure no typos in token/key

#### 2. 403 Forbidden - Insufficient Permissions

**Symptom**:
```json
{
  "error": "Permission required: create",
  "status_code": 403
}
```

**Solutions**:
- Check user role has required permissions
- Verify API key scope includes needed operations
- Confirm you're accessing resources in your namespace
- Check resource ownership for update/delete operations

#### 3. Token Expired

**Symptom**:
```json
{
  "error": "Token expired",
  "status_code": 401
}
```

**Solutions**:
- Use refresh token to get new access token
- Re-authenticate if refresh token also expired
- Check system clock synchronization

#### 4. API Key Invalid

**Symptom**:
```json
{
  "error": "Invalid API key",
  "status_code": 401
}
```

**Solutions**:
- Verify complete API key (format: `key_id.raw_key`)
- Check key hasn't been revoked
- Verify key hasn't expired
- Confirm IP address is in allowed list

#### 5. Rate Limit Exceeded

**Symptom**:
```json
{
  "error": "Rate limit exceeded",
  "status_code": 429,
  "retry_after": 60
}
```

**Solutions**:
- Wait for the time specified in `retry_after`
- Implement exponential backoff
- Request higher rate limit for API key
- Optimize request frequency

### Debug Mode

Enable detailed authentication logging:

```bash
# .env
TMWS_LOG_LEVEL=DEBUG
TMWS_LOG_AUTH_EVENTS=true
```

Check logs for authentication flow:

```bash
tail -f logs/tmws.log | grep -i "auth"
```

### Health Check

Verify authentication system status:

```bash
curl http://localhost:8000/health
```

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-09T10:30:00Z",
  "components": {
    "database": "healthy",
    "redis": "healthy",
    "authentication": "enabled"
  },
  "auth_mode": "production",
  "security_level": "high"
}
```

---

## Example Workflows

### Workflow 1: Initial Setup

```bash
# 1. Create user account (admin operation)
curl -X POST http://localhost:8000/api/v1/users \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "SecureP@ssw0rd123",
    "roles": ["USER"]
  }'

# 2. User login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "password": "SecureP@ssw0rd123"
  }'

# 3. Create API key for automation
curl -X POST http://localhost:8000/api/v1/auth/api-keys \
  -H "Authorization: Bearer USER_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CI/CD Pipeline",
    "scopes": ["TASKS", "WORKFLOWS"],
    "expires_days": 30
  }'
```

### Workflow 2: Service Integration

```python
import httpx
import os

class TMWSClient:
    def __init__(self, api_key: str, base_url: str):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {"X-API-Key": api_key}

    async def create_task(self, title: str, description: str):
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/tasks",
                headers=self.headers,
                json={"title": title, "description": description}
            )
            response.raise_for_status()
            return response.json()

# Usage
client = TMWSClient(
    api_key=os.getenv("TMWS_API_KEY"),
    base_url="https://tmws.example.com"
)

task = await client.create_task(
    title="Deploy v2.2.0",
    description="Deploy new version to production"
)
```

### Workflow 3: Token Refresh Automation

```python
import httpx
from datetime import datetime, timedelta
import asyncio

class TokenManager:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.access_token = None
        self.refresh_token = None
        self.expires_at = None

    async def login(self, username: str, password: str):
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/auth/login",
                json={"username": username, "password": password}
            )
            data = response.json()
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]
            self.expires_at = datetime.now() + timedelta(seconds=data["expires_in"])

    async def get_valid_token(self):
        # Check if token needs refresh (5 min buffer)
        if datetime.now() >= (self.expires_at - timedelta(minutes=5)):
            await self.refresh()
        return self.access_token

    async def refresh(self):
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/auth/refresh",
                json={"refresh_token": self.refresh_token}
            )
            data = response.json()
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]
            self.expires_at = datetime.now() + timedelta(seconds=data["expires_in"])

# Usage
manager = TokenManager("https://tmws.example.com")
await manager.login("user", "password")

# Automatically handles token refresh
token = await manager.get_valid_token()
```

---

## API Reference

### Authentication Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/api/v1/auth/login` | POST | User login | No |
| `/api/v1/auth/logout` | POST | User logout | Yes (JWT) |
| `/api/v1/auth/refresh` | POST | Refresh access token | No (refresh token) |
| `/api/v1/auth/api-keys` | GET | List API keys | Yes (JWT) |
| `/api/v1/auth/api-keys` | POST | Create API key | Yes (JWT) |
| `/api/v1/auth/api-keys/{id}` | DELETE | Revoke API key | Yes (JWT) |
| `/api/v1/users` | POST | Create user | Yes (ADMIN) |
| `/api/v1/users/{id}/password` | PUT | Change password | Yes (JWT) |

### Security Headers

All API requests should include:

```
Authorization: Bearer {jwt_token}
# OR
X-API-Key: {api_key}

# Recommended
Content-Type: application/json
User-Agent: YourApp/1.0.0
```

---

## Additional Resources

- [Quick Start Authentication Guide](./QUICK_START_AUTH.md)
- [API Reference Documentation](https://tmws.example.com/docs)
- [Security Best Practices](./security/SECURITY_IMPROVEMENT_ROADMAP.md)
- [Deployment Guide](./deployment/DEPLOYMENT_GUIDE_v2.2.0.md)
- [MCP Setup Guide](./guides/MCP_SETUP_GUIDE.md)

---

## Support

For authentication issues:

1. Check this guide and [troubleshooting section](#troubleshooting)
2. Review server logs with `TMWS_LOG_LEVEL=DEBUG`
3. Check system health at `/health` endpoint
4. Consult [GitHub Issues](https://github.com/apto-as/tmws/issues)

---

**Last Updated**: 2025-01-09
**TMWS Version**: 2.2.0
**Documentation Version**: 1.0
