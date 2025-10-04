# Authentication Documentation Summary

**TMWS v2.2.0 - Authentication System Documentation**

This document provides an overview of the complete authentication documentation created for TMWS.

---

## Documentation Files Created

### 1. API_AUTHENTICATION.md
**Location**: `/docs/API_AUTHENTICATION.md`

**Purpose**: Comprehensive authentication guide for the TMWS API

**Contents**:
- Authentication methods overview (JWT and API Key)
- Detailed JWT token authentication workflow
- API Key creation and management
- Authorization and scopes (RBAC)
- Role-based permissions matrix
- API key scope permissions
- Development vs Production modes
- Security best practices
- Troubleshooting guide
- Example workflows
- API reference

**Key Sections**:
- 🔐 JWT Token Authentication (login, refresh, logout)
- 🔑 API Key Authentication (create, use, revoke)
- 👥 User Roles (SUPER_ADMIN, ADMIN, USER, READONLY, SERVICE)
- 📊 Permissions Matrix (by resource and role)
- 🎯 Scope-Based Access (FULL, READ, WRITE, ADMIN, MEMORY, TASKS, WORKFLOWS)
- 🛡️ Security Best Practices
- 🔧 Troubleshooting Common Issues

---

### 2. QUICK_START_AUTH.md
**Location**: `/docs/QUICK_START_AUTH.md`

**Purpose**: Quick start guide to get authentication working in 5 minutes

**Contents**:
- Prerequisites
- Two setup paths (Development and Production)
- User creation guide
- Token acquisition (curl and Python examples)
- API key creation
- Testing your setup
- Common tasks (refresh, password change, key management)
- Integration examples (Python, JavaScript, Shell)
- Troubleshooting quick fixes
- Security checklist

**Key Features**:
- ⚡ Fast setup (< 5 minutes)
- 🔀 Two modes: Development (no auth) and Production (full auth)
- 💻 Code examples in multiple languages
- ✅ Security checklist
- 🆘 Quick troubleshooting

---

### 3. AUTHENTICATION_EXAMPLES.md
**Location**: `/docs/AUTHENTICATION_EXAMPLES.md`

**Purpose**: Complete, production-ready code examples in multiple languages

**Contents**:
- **Python Examples**:
  - Full-featured JWT client with automatic token refresh
  - API Key client
  - Error handling and retry logic

- **JavaScript/TypeScript Examples**:
  - TypeScript client with type safety
  - Node.js API key client
  - Fetch API integration

- **Go Examples**:
  - Complete Go client implementation
  - Struct-based type safety
  - Error handling patterns

- **Rust Examples**:
  - Async Rust client with tokio
  - Serde serialization
  - Type-safe error handling

- **Shell/Bash Examples**:
  - Complete CLI wrapper
  - Token management
  - All TMWS operations

- **cURL Examples**:
  - Complete workflow examples
  - All authentication flows
  - Error handling

**Key Features**:
- 🐍 Python (httpx, async/await)
- 📜 JavaScript/TypeScript (fetch, type-safe)
- 🔷 Go (standard library)
- 🦀 Rust (reqwest, tokio)
- 🐚 Bash/Shell (curl, jq)
- 🔄 Automatic token refresh
- ⚠️ Comprehensive error handling
- 🔁 Retry logic with exponential backoff

---

### 4. OpenAPI/Swagger Integration
**Location**: `/src/api/app.py` (updated)

**Changes Made**:
1. Enhanced API description with authentication information
2. Added custom OpenAPI schema generator
3. Defined security schemes:
   - **BearerAuth**: JWT token authentication
   - **ApiKeyAuth**: API key authentication
4. Added security requirements to all endpoints
5. Added authentication status to API metadata

**Swagger UI Features**:
- 🔒 Authentication buttons in Swagger UI
- 📝 Automatic "Authorize" dialog
- 🔐 Bearer token and API key input
- ✅ Authenticated requests from Swagger
- 📊 Current mode indicator (Production/Development)

**Access Swagger UI**: `http://localhost:8000/docs` (development only)

---

## Authentication System Overview

### Supported Methods

#### 1. JWT Token Authentication
- **Use Case**: User sessions, interactive applications
- **Flow**: Login → Access Token + Refresh Token → API Requests
- **Expiration**: 1 hour (configurable)
- **Refresh**: Automatic with refresh token
- **Features**: Stateless, secure logout, token blacklisting

#### 2. API Key Authentication
- **Use Case**: Service integrations, automation, CI/CD
- **Flow**: Create Key → Use in X-API-Key header
- **Expiration**: Configurable (or indefinite)
- **Features**: Scoped permissions, IP restrictions, rate limiting, usage tracking

---

### Role-Based Access Control (RBAC)

#### User Roles

| Role | Level | Use Case |
|------|-------|----------|
| SUPER_ADMIN | 5 | System administrators, full access |
| ADMIN | 4 | Project managers, resource management |
| USER | 3 | Regular users, own resources |
| READONLY | 2 | Auditors, viewers |
| SERVICE | 3 | Automation, CI/CD pipelines |

#### API Key Scopes

| Scope | Permissions | Typical Use |
|-------|-------------|-------------|
| FULL | All except admin | Complete API access |
| READ | Read-only | Monitoring, reporting |
| WRITE | Read + Create/Update | Data entry, automation |
| ADMIN | Administrative | User management |
| MEMORY | Memory operations | Memory service integration |
| TASKS | Task operations | Task automation |
| WORKFLOWS | Workflow operations | Workflow orchestration |

---

### Security Features

#### Password Requirements
- Minimum 12 characters
- Uppercase + lowercase + numbers + special chars
- No common weak patterns
- Strength validation on creation/change

#### Account Protection
- Maximum 5 failed login attempts
- 30-minute lockout after failed attempts
- Force logout on password change
- Session termination on account suspension

#### Token Security
- JWT with HS256 algorithm
- Short-lived access tokens (1 hour)
- Long-lived refresh tokens (30 days)
- Single-use refresh tokens (auto-revoke on use)
- Token blacklisting for logout
- Token expiration validation

#### API Key Security
- Cryptographically secure key generation (32 bytes)
- Bcrypt hashing for storage
- Format: `key_id.random_string`
- Optional IP address restrictions
- Rate limiting per key
- Usage tracking and last-used timestamp
- Configurable expiration

#### Audit Logging
All authentication events logged:
- Login attempts (success/failure)
- Token refresh operations
- API key creation/revocation
- Password changes
- Account status changes
- Permission violations

---

## Development vs Production

### Development Mode
**Environment**: `TMWS_AUTH_ENABLED=false`

**Behavior**:
- ✅ Authentication optional
- ✅ Mock user with admin permissions
- ✅ No credential management
- ✅ Easier local testing
- ✅ Swagger UI enabled

**Use Case**: Local development, testing, learning

### Production Mode
**Environment**: `TMWS_AUTH_ENABLED=true`

**Behavior**:
- 🔒 Authentication required
- 🔒 Full permission checking
- 🔒 Audit logging enabled
- 🔒 Security headers enforced
- 🔒 Swagger UI disabled

**Use Case**: Production deployments, multi-user environments

---

## Quick Reference

### Environment Variables

```bash
# Core Configuration
TMWS_ENVIRONMENT=production|development
TMWS_AUTH_ENABLED=true|false
TMWS_SECRET_KEY=<32+ character random string>

# JWT Configuration
TMWS_JWT_ALGORITHM=HS256
TMWS_JWT_EXPIRE_MINUTES=60

# Security
TMWS_RATE_LIMIT_ENABLED=true
TMWS_RATE_LIMIT_REQUESTS=100
TMWS_RATE_LIMIT_PERIOD=60
```

### Common Operations

#### Login (JWT)
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "pass"}'
```

#### Create API Key
```bash
curl -X POST http://localhost:8000/api/v1/auth/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Key", "scopes": ["READ", "WRITE"]}'
```

#### Use JWT Token
```bash
curl http://localhost:8000/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN"
```

#### Use API Key
```bash
curl http://localhost:8000/api/v1/tasks \
  -H "X-API-Key: $API_KEY"
```

---

## Testing Authentication

### Manual Testing

```bash
# 1. Test health endpoint (no auth required)
curl http://localhost:8000/health | jq

# 2. Test protected endpoint without auth (should fail in production)
curl http://localhost:8000/api/v1/tasks

# 3. Login and get token
TOKEN=$(curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "pass"}' | jq -r '.access_token')

# 4. Test with token (should succeed)
curl http://localhost:8000/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN"

# 5. Create API key
API_KEY=$(curl -X POST http://localhost:8000/api/v1/auth/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "scopes": ["FULL"]}' | jq -r '.api_key')

# 6. Test with API key
curl http://localhost:8000/api/v1/tasks \
  -H "X-API-Key: $API_KEY"
```

### Automated Testing

See `/tests/integration/test_api_authentication.py` and `/tests/security/test_authentication.py` for comprehensive test suites.

---

## Integration Guides

### Web Application Integration
- Use JWT tokens for user sessions
- Store tokens securely (HttpOnly cookies or memory)
- Implement automatic token refresh
- Handle 401/403 errors gracefully
- Logout = revoke refresh token + clear client state

### Service Integration
- Use API keys for service-to-service communication
- Store keys in secrets manager (Vault, AWS Secrets, etc.)
- Use minimal required scopes
- Implement exponential backoff for rate limits
- Monitor key usage and rotate regularly

### CLI Tool Integration
- Support both JWT and API key
- Store tokens in secure location (~/.tmws_token with 600 permissions)
- Implement automatic token refresh
- Provide clear error messages
- Support environment variable configuration

---

## Security Best Practices

### For Developers

1. ✅ **Never commit credentials**
   - Use `.env` files (gitignored)
   - Use environment variables
   - Use secrets managers

2. ✅ **Use HTTPS in production**
   - Tokens sent in plain text over HTTP
   - Enable TLS/SSL
   - Use HSTS headers

3. ✅ **Implement proper error handling**
   - Retry on 401 (token refresh)
   - Backoff on 429 (rate limit)
   - Don't expose sensitive errors to users

4. ✅ **Validate and sanitize inputs**
   - Use provided validation functions
   - Escape user inputs
   - Validate on both client and server

5. ✅ **Log authentication events**
   - Track login attempts
   - Monitor failed authentications
   - Alert on suspicious patterns

### For Administrators

1. ✅ **Strong secret keys**
   - Generate with `openssl rand -hex 32`
   - Minimum 32 characters
   - Never use default values

2. ✅ **Regular key rotation**
   - Rotate API keys monthly/quarterly
   - Rotate JWT secret annually
   - Document rotation procedures

3. ✅ **Monitor and audit**
   - Review audit logs regularly
   - Set up alerts for failed logins
   - Monitor API key usage patterns

4. ✅ **Principle of least privilege**
   - Grant minimum required scopes
   - Use role-based access control
   - Regular permission audits

5. ✅ **Incident response plan**
   - Document breach procedures
   - Quick API key revocation process
   - User notification procedures

---

## Troubleshooting Quick Links

### Common Issues

| Issue | Guide Section | Quick Fix |
|-------|---------------|-----------|
| 401 Unauthorized | [Troubleshooting](./API_AUTHENTICATION.md#troubleshooting) | Check token/key validity |
| 403 Forbidden | [Authorization](./API_AUTHENTICATION.md#authorization--scopes) | Verify user role/scope |
| Token Expired | [JWT Authentication](./API_AUTHENTICATION.md#jwt-token-authentication) | Use refresh token |
| Invalid API Key | [API Key Auth](./API_AUTHENTICATION.md#api-key-authentication) | Check key format |
| Rate Limited | [Troubleshooting](./API_AUTHENTICATION.md#troubleshooting) | Wait for retry-after |

### Debug Commands

```bash
# Check authentication status
curl http://localhost:8000/health | jq '.components.authentication'

# View current user
curl http://localhost:8000/api/v1/users/me \
  -H "Authorization: Bearer $TOKEN"

# List API keys
curl http://localhost:8000/api/v1/auth/api-keys \
  -H "Authorization: Bearer $TOKEN"

# Enable debug logging
export TMWS_LOG_LEVEL=DEBUG
```

---

## Migration from v1.x to v2.2.0

### Breaking Changes
1. **Authentication now required in production** (was optional before)
2. **API key format changed** (now includes key_id prefix)
3. **Refresh tokens are single-use** (auto-revoke on refresh)
4. **New permission system** (scope-based instead of simple roles)

### Migration Steps

1. **Update environment variables**:
   ```bash
   # Add new required variables
   export TMWS_AUTH_ENABLED=true
   export TMWS_SECRET_KEY=$(openssl rand -hex 32)
   ```

2. **Create user accounts**:
   ```bash
   python scripts/security_setup.py
   ```

3. **Migrate to new API key format**:
   - Revoke old API keys
   - Create new keys with scopes
   - Update client applications

4. **Update client code**:
   - Implement token refresh logic
   - Add error handling for 401/403
   - Update API key header format

---

## Additional Resources

### Documentation Files
- [API Authentication Guide](./API_AUTHENTICATION.md) - Comprehensive guide
- [Quick Start Guide](./QUICK_START_AUTH.md) - Get started in 5 minutes
- [Code Examples](./AUTHENTICATION_EXAMPLES.md) - Production-ready examples
- [Deployment Guide](./deployment/DEPLOYMENT_GUIDE_v2.2.0.md) - Production setup
- [Security Roadmap](./security/SECURITY_IMPROVEMENT_ROADMAP.md) - Future improvements

### API Reference
- Swagger UI: `http://localhost:8000/docs` (development only)
- ReDoc: `http://localhost:8000/redoc` (development only)
- OpenAPI JSON: `http://localhost:8000/openapi.json`

### Support
- GitHub Issues: https://github.com/apto-as/tmws/issues
- Discussions: https://github.com/apto-as/tmws/discussions
- Documentation: https://github.com/apto-as/tmws/tree/master/docs

---

## Changelog

### v2.2.0 (2025-01-09)
- ✅ Complete authentication documentation created
- ✅ JWT token authentication implemented
- ✅ API key authentication with scopes
- ✅ Role-based access control (RBAC)
- ✅ OpenAPI/Swagger integration
- ✅ Code examples in 6 languages
- ✅ Production security standards (404 compliance)
- ✅ Comprehensive audit logging
- ✅ Rate limiting and IP restrictions

---

**Last Updated**: 2025-01-09
**TMWS Version**: 2.2.0
**Documentation Version**: 1.0
