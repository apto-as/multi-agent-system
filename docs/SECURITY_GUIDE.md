# TMWS Security Guide
## Comprehensive Security Best Practices for Trinitas-agents

**Version**: v2.3.0
**Target Audience**: Trinitas-agents Development Team
**Last Updated**: 2025-11-14
**Status**: Production-ready
**Security Level**: P0-1 Compliant

---

## Table of Contents

1. [Overview](#overview)
2. [P0-1 Namespace Isolation (Critical)](#p0-1-namespace-isolation-critical)
3. [JWT Authentication](#jwt-authentication)
4. [API Key Authentication](#api-key-authentication)
5. [Rate Limiting](#rate-limiting)
6. [SQL Injection Prevention](#sql-injection-prevention)
7. [XSS Prevention](#xss-prevention)
8. [CSRF Protection](#csrf-protection)
9. [Security Audit Logging](#security-audit-logging)
10. [Input Validation](#input-validation)
11. [Secret Management](#secret-management)
12. [Access Control Levels](#access-control-levels)
13. [Security Best Practices](#security-best-practices)
14. [Compliance Checklist](#compliance-checklist)
15. [Incident Response](#incident-response)

---

## Overview

TMWS implements **defense-in-depth** security with multiple layers:

1. **Authentication Layer**: JWT + API Key authentication
2. **Authorization Layer**: P0-1 namespace isolation + RBAC
3. **Input Validation**: Comprehensive input sanitization
4. **Rate Limiting**: Protection against abuse and DoS
5. **Audit Logging**: Complete security event tracking
6. **Encryption**: Data protection at rest and in transit

### Security Principles

- **Zero Trust**: Never trust user input or JWT claims
- **Least Privilege**: Grant minimum required permissions
- **Fail Secure**: Default to deny, explicit allow
- **Defense in Depth**: Multiple security layers
- **Audit Everything**: Comprehensive logging

---

## P0-1 Namespace Isolation (Critical)

**Status**:  **CRITICAL SECURITY PATTERN - MANDATORY**

**CVSS**: 8.7 (HIGH) if violated - Cross-tenant data leakage

### What is P0-1?

**P0-1** is a security pattern that requires **namespace verification from database**, never from user input (e.g., JWT claims).

**Attack Vector** (if violated):
```python
# L VULNERABLE - Trusts JWT claim
namespace = jwt_payload.get("namespace")  # Attacker can forge this
memory.is_accessible_by(agent_id, namespace)

# Attacker's JWT: {"sub": "attacker", "namespace": "victim-namespace"}
# Result: Access to victim's data L
```

**Correct Implementation**:
```python
#  SECURE - Verifies from database
agent = await get_agent_from_db(agent_id)  # Database lookup
verified_namespace = agent.namespace  # Can't be forged
memory.is_accessible_by(agent_id, verified_namespace)

# Even if attacker forges JWT, database returns true namespace
# Result: Access denied 
```

### Implementation in TMWS

**File**: `src/api/dependencies.py:57-127`

```python
async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> User:
    """Extract and verify user from JWT token

    Security Flow (P0-1 Compliant):
    1. Decode JWT token to get agent_id
    2. Fetch agent from database (VERIFY existence)
    3. Extract namespace from database record (NOT from JWT)
    4. Return User with verified namespace
    """
    try:
        # 1. Decode JWT
        payload = jwt.decode(
            credentials.credentials,
            settings.secret_key,
            algorithms=["HS256"]
        )
        agent_id_str: str | None = payload.get("sub")

        if not agent_id_str:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject"
            )

        # 2. SECURITY CRITICAL: Verify agent exists in database
        agent_repo = AgentRepository(session)
        agent = await agent_repo.get_by_id(agent_id_str)

        if not agent:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Agent not found"
            )

        # 3. Extract VERIFIED namespace from database (NOT from JWT)
        verified_namespace = agent.namespace

        # 4. Return User with verified namespace
        return User(
            agent_id=str(agent.agent_id),
            namespace=verified_namespace,  #  Verified from DB
            roles=["user"]
        )

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )
```

### Memory Access Control

**File**: `src/models/memory.py:160-201`

```python
def is_accessible_by(
    self,
    agent_id: str | None,
    verified_namespace: str  #  Must be verified from DB
) -> bool:
    """
    Check if an agent can access this memory.

    SECURITY CRITICAL: verified_namespace MUST come from database,
    never from JWT claims or user input.

    Args:
        agent_id: Agent requesting access
        verified_namespace: Namespace verified from database (P0-1)

    Returns:
        True if access allowed, False otherwise
    """
    # System level: Read-only for all
    if self.access_level == "SYSTEM":
        return True

    # Public level: All agents in same namespace
    if self.access_level == "PUBLIC":
        return self.namespace == verified_namespace

    # Private level: Owner only
    if self.access_level == "PRIVATE":
        return self.agent_id == agent_id

    # Team level: Same namespace
    if self.access_level == "TEAM":
        return self.namespace == verified_namespace

    # Shared level: Owner or explicitly shared agents
    if self.access_level == "SHARED":
        if self.agent_id == agent_id:
            return True
        if self.shared_with_agents and agent_id in self.shared_with_agents:
            return self.namespace == verified_namespace
        return False

    # Default: Deny
    return False
```

### Testing Namespace Isolation

**File**: `tests/unit/security/test_namespace_isolation.py`

```python
async def test_namespace_isolation_prevents_cross_tenant_access():
    """Test P0-1: Agents cannot access other tenants' data"""

    # Setup: Two agents in different namespaces
    agent1 = await create_agent("agent1", namespace="tenant-a")
    agent2 = await create_agent("agent2", namespace="tenant-b")

    # Agent1 creates private memory
    memory = await create_memory(
        content="Secret data from tenant A",
        agent_id="agent1",
        namespace="tenant-a",
        access_level="PRIVATE"
    )

    # Test: Agent2 tries to access (should fail)
    verified_namespace = await get_agent_namespace("agent2")  # Returns "tenant-b"

    can_access = memory.is_accessible_by("agent2", verified_namespace)

    assert can_access is False  #  Access denied

    # Test: Even if Agent2 forges JWT with tenant-a namespace
    # P0-1 pattern ensures database lookup returns tenant-b
    forged_namespace = "tenant-a"  # Attacker's claim
    verified_namespace = await get_agent_namespace("agent2")  # Still returns "tenant-b"

    can_access = memory.is_accessible_by("agent2", verified_namespace)

    assert can_access is False  #  P0-1 prevents attack
```

### Namespace Validation

**Critical Rules**:

1.  **Always fetch namespace from database**
   ```python
   agent = await db.get(Agent, agent_id)
   namespace = agent.namespace  #  Verified
   ```

2. L **Never trust JWT claims**
   ```python
   namespace = jwt_payload.get("namespace")  # L Forgeable
   ```

3.  **Validate namespace format** (prevents path traversal - V-1 fix)
   ```python
   # Sanitize namespace (V-1 fix: Block . and /)
   namespace = namespace.replace(".", "-").replace("/", "-")
   # github.com/user/repo ’ github-com-user-repo 
   ```

4.  **Pass verified namespace explicitly**
   ```python
   def is_accessible_by(self, agent_id: str, verified_namespace: str):
       # Parameter name makes it clear: must be verified
   ```

---

## JWT Authentication

**Status**:  **REQUIRED** for REST API access

### Token Structure

```python
{
  "sub": "agent_id",           # Subject (agent identifier)
  "exp": 1700000000,           # Expiration timestamp
  "iat": 1699999000,           # Issued at timestamp
  "type": "access_token"       # Token type
}
```

**Important**: JWT does NOT contain `namespace` - this prevents forgery attacks.

### Token Generation

**File**: `src/security/jwt_service.py`

```python
from jose import jwt
from datetime import datetime, timedelta
from src.core.config import settings

def create_access_token(agent_id: str) -> str:
    """
    Create JWT access token for agent.

    SECURITY:
    - Does NOT include namespace (prevents forgery)
    - Short expiration (1 hour default)
    - HS256 algorithm (symmetric)
    """
    payload = {
        "sub": agent_id,
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iat": datetime.utcnow(),
        "type": "access_token"
    }

    token = jwt.encode(
        payload,
        settings.secret_key,  #  Never commit this
        algorithm="HS256"
    )

    return token

# Usage
token = create_access_token("artemis-optimizer")
print(f"Authorization: Bearer {token}")
```

### Token Validation

```python
from jose import jwt, JWTError
from fastapi import HTTPException, status

async def validate_token(token: str) -> dict:
    """
    Validate JWT token and extract payload.

    SECURITY:
    - Verifies signature with secret key
    - Checks expiration
    - Returns payload if valid
    """
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=["HS256"]
        )

        # Check token type
        if payload.get("type") != "access_token":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )

        return payload

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )
```

### Token Best Practices

1.  **Short expiration** (1 hour for access tokens)
2.  **Use refresh tokens** for long-lived sessions (7 days)
3.  **Rotate secret key** regularly (every 90 days)
4.  **Store secret key in environment** variable
5. L **Never include sensitive data** in JWT payload (it's readable)
6. L **Never include namespace** (prevents forgery)

### Environment Configuration

```bash
# .env (NEVER commit this file)
TMWS_SECRET_KEY="your-256-bit-secret-key-here-minimum-32-characters-long"
TMWS_ENVIRONMENT="production"
```

**Generate secure secret key**:
```bash
# Use openssl to generate random key
openssl rand -hex 32
```

---

## API Key Authentication

**Status**:  **ALTERNATIVE** authentication method (for service accounts)

### API Key Structure

API keys are stored hashed in database (bcrypt):

**Table**: `api_keys`
```sql
CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    key_hash VARCHAR(255) NOT NULL,  -- Bcrypt hash
    agent_id VARCHAR(255) NOT NULL,
    namespace VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### Creating API Keys

**File**: `src/services/auth_service.py`

```python
from passlib.context import CryptContext
import secrets

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def create_api_key(
    agent_id: str,
    namespace: str,
    name: str,
    expires_days: int = 90
) -> dict:
    """
    Create new API key for agent.

    Returns:
        {
            "api_key": "tmws_1234567890abcdef...",  # Show once
            "key_id": "uuid",
            "expires_at": "2025-02-15T00:00:00Z"
        }
    """
    # Generate random API key (32 bytes = 64 hex chars)
    raw_key = secrets.token_hex(32)
    api_key = f"tmws_{raw_key}"

    # Hash API key for storage (never store plaintext)
    key_hash = pwd_context.hash(api_key)

    # Store in database
    api_key_record = APIKey(
        key_hash=key_hash,
        agent_id=agent_id,
        namespace=namespace,
        name=name,
        is_active=True,
        expires_at=datetime.utcnow() + timedelta(days=expires_days)
    )

    await db.add(api_key_record)
    await db.commit()

    # Return API key ONCE (cannot be retrieved later)
    return {
        "api_key": api_key,  #   Show once only
        "key_id": str(api_key_record.id),
        "expires_at": api_key_record.expires_at.isoformat()
    }
```

### Validating API Keys

```python
async def validate_api_key(api_key: str) -> User:
    """
    Validate API key and return user.

    SECURITY:
    - Constant-time comparison (prevents timing attacks)
    - Check expiration
    - Check is_active flag
    - Verify namespace from database (P0-1)
    """
    if not api_key.startswith("tmws_"):
        raise HTTPException(401, "Invalid API key format")

    # Fetch all active API keys for comparison
    # Note: In production, use caching to avoid DB query on every request
    api_keys = await db.execute(
        select(APIKey).where(APIKey.is_active == True)
    )

    for key_record in api_keys.scalars():
        # Constant-time comparison (prevents timing attacks)
        if pwd_context.verify(api_key, key_record.key_hash):
            # Check expiration
            if key_record.expires_at and datetime.utcnow() > key_record.expires_at:
                raise HTTPException(401, "API key expired")

            # Fetch agent for verified namespace (P0-1)
            agent = await db.get(Agent, key_record.agent_id)

            return User(
                agent_id=key_record.agent_id,
                namespace=agent.namespace,  #  Verified from DB
                roles=["user"]
            )

    raise HTTPException(401, "Invalid API key")
```

### API Key Usage

```python
import requests

# Use API key in header
headers = {
    "X-API-Key": "tmws_1234567890abcdef...",
    "Content-Type": "application/json"
}

response = requests.post(
    "http://localhost:8000/api/v1/mcp/connections",
    json={...},
    headers=headers
)
```

### API Key Best Practices

1.  **Rotate API keys** every 90 days
2.  **Use descriptive names** ("CI/CD Pipeline", "Production Service")
3.  **Revoke unused keys** immediately
4.  **Monitor API key usage** (audit logs)
5. L **Never commit API keys** to git
6. L **Never share API keys** between services

---

## Rate Limiting

**Status**:  **ENABLED** - Protects against abuse and DoS attacks

### Rate Limits by Endpoint

| Endpoint | Rate Limit | Window | Burst |
|----------|-----------|--------|-------|
| `/api/v1/mcp/connections` (POST) | 10 req/min | 1 min | 20 |
| `/api/v1/mcp/connections/{id}/tools/{name}/execute` | 100 req/min | 1 min | 150 |
| `/health` | 1000 req/min | 1 min | 1500 |
| MCP Tool: `store_memory` | 100 req/min | 1 min | 150 |
| MCP Tool: `search_memories` | 200 req/min | 1 min | 300 |

### Implementation

**File**: `src/security/rate_limiter.py`

```python
from collections import defaultdict
from datetime import datetime, timedelta
import asyncio

class RateLimiter:
    """
    Token bucket rate limiter.

    Features:
    - Per-agent rate limiting
    - Configurable rates and burst sizes
    - Automatic token refill
    - Thread-safe (async locks)
    """

    def __init__(
        self,
        rate: int,        # Requests per window
        window_seconds: int,  # Time window
        burst: int        # Max burst size
    ):
        self.rate = rate
        self.window_seconds = window_seconds
        self.burst = burst

        self._buckets = defaultdict(lambda: {
            "tokens": burst,
            "last_refill": datetime.utcnow()
        })
        self._locks = defaultdict(asyncio.Lock)

    async def check_limit(self, agent_id: str) -> bool:
        """
        Check if request is allowed.

        Returns:
            True if allowed, False if rate limit exceeded
        """
        async with self._locks[agent_id]:
            bucket = self._buckets[agent_id]
            now = datetime.utcnow()

            # Refill tokens based on elapsed time
            elapsed = (now - bucket["last_refill"]).total_seconds()
            refill_amount = (elapsed / self.window_seconds) * self.rate

            bucket["tokens"] = min(
                self.burst,
                bucket["tokens"] + refill_amount
            )
            bucket["last_refill"] = now

            # Check if tokens available
            if bucket["tokens"] >= 1:
                bucket["tokens"] -= 1
                return True

            return False

    async def get_retry_after(self, agent_id: str) -> int:
        """
        Get seconds until next token available.

        Returns:
            Seconds to wait before retry
        """
        bucket = self._buckets[agent_id]
        tokens_needed = 1 - bucket["tokens"]
        seconds_per_token = self.window_seconds / self.rate

        return int(tokens_needed * seconds_per_token)

# Global rate limiters
rate_limiters = {
    "mcp_connections": RateLimiter(rate=10, window_seconds=60, burst=20),
    "mcp_execute": RateLimiter(rate=100, window_seconds=60, burst=150),
    "store_memory": RateLimiter(rate=100, window_seconds=60, burst=150),
    "search_memories": RateLimiter(rate=200, window_seconds=60, burst=300)
}
```

### FastAPI Integration

```python
from fastapi import HTTPException, status
from src.security.rate_limiter import rate_limiters

@app.post("/api/v1/mcp/connections")
async def create_connection(
    request: ConnectionRequest,
    current_user: User = Depends(get_current_user)
):
    """Create MCP connection with rate limiting"""

    # Check rate limit
    limiter = rate_limiters["mcp_connections"]

    if not await limiter.check_limit(current_user.agent_id):
        retry_after = await limiter.get_retry_after(current_user.agent_id)

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Retry after {retry_after} seconds",
            headers={"Retry-After": str(retry_after)}
        )

    # Process request
    connection = await create_mcp_connection(request)
    return connection
```

### Client-Side Retry Strategy

```python
import time
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Exponential backoff with retry
session = requests.Session()
retry = Retry(
    total=5,
    backoff_factor=1,  # 1s, 2s, 4s, 8s, 16s
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET", "POST", "PUT", "DELETE"]
)
adapter = HTTPAdapter(max_retries=retry)
session.mount("http://", adapter)
session.mount("https://", adapter)

# Use session for all requests
response = session.post(
    "http://localhost:8000/api/v1/mcp/connections",
    json={...},
    headers={"Authorization": f"Bearer {token}"}
)
```

### Rate Limit Best Practices

1.  **Implement exponential backoff** on client side
2.  **Monitor rate limit metrics** (Prometheus, Grafana)
3.  **Set different limits** for different user tiers
4.  **Log rate limit violations** for abuse detection
5.  **Use distributed rate limiting** for multi-instance deployments (Redis)

---

## SQL Injection Prevention

**Status**:  **CRITICAL** - CVSS 9.8 if violated

### Vulnerability Example (Fixed in v2.2.7)

**File**: `src/services/learning_service.py:704-710`

**Vulnerable Code** (before fix):
```python
# L VULNERABLE - SQL injection via f-string
filter_clause = f"WHERE shared_with_agents LIKE '%{agent_id}%'"

# Attack: agent_id = "'; DROP TABLE learning_patterns; --"
# Result: DROP TABLE executed L
```

**Fixed Code** (v2.2.7):
```python
#  SECURE - Parameterized query with bindparams()
from sqlalchemy import text

filter_clause = text(
    "EXISTS (SELECT 1 FROM json_each(learning_patterns.shared_with_agents) "
    "WHERE value = :agent_id)"
).bindparams(agent_id=agent_id)  #  Safe parameterization

# Attack: agent_id = "'; DROP TABLE learning_patterns; --"
# Result: Treated as literal string, no SQL injection 
```

### Prevention Techniques

#### 1. Use SQLAlchemy ORM (Preferred)

```python
#  SECURE - ORM automatically escapes
from sqlalchemy import select
from src.models import Memory

stmt = select(Memory).where(Memory.agent_id == user_input)
memories = await session.execute(stmt)

# SQLAlchemy generates: SELECT * FROM memories WHERE agent_id = ?
# Parameters: [user_input]   Safe
```

#### 2. Use bindparams() for Raw SQL

```python
#  SECURE - Parameterized query
from sqlalchemy import text

stmt = text(
    "SELECT * FROM memories WHERE agent_id = :agent_id AND namespace = :namespace"
).bindparams(agent_id=user_input, namespace=verified_namespace)

result = await session.execute(stmt)

# Generated: SELECT * FROM memories WHERE agent_id = ? AND namespace = ?
# Parameters: [user_input, verified_namespace]   Safe
```

#### 3. Avoid String Concatenation

```python
# L VULNERABLE - Never do this
query = f"SELECT * FROM memories WHERE agent_id = '{user_input}'"

# L VULNERABLE - Even with .format()
query = "SELECT * FROM memories WHERE agent_id = '{}'".format(user_input)

# L VULNERABLE - Even with %
query = "SELECT * FROM memories WHERE agent_id = '%s'" % user_input
```

### Testing SQL Injection

**File**: `tests/unit/security/test_sql_injection.py`

```python
import pytest
from src.services.learning_service import LearningService

@pytest.mark.asyncio
async def test_sql_injection_prevention():
    """Test that SQL injection attempts are blocked"""

    service = LearningService()

    # Attack payloads
    payloads = [
        "'; DROP TABLE learning_patterns; --",
        "' OR '1'='1",
        "'; DELETE FROM memories WHERE '1'='1'; --",
        "' UNION SELECT * FROM api_keys; --"
    ]

    for payload in payloads:
        # Should not raise error, should treat as literal string
        results = await service.search_patterns(
            query="test",
            agent_id=payload,  # Attack payload
            namespace="test-namespace"
        )

        # Verify no data returned (payload treated as literal)
        assert len(results) == 0

        # Verify database still intact
        all_patterns = await service.search_patterns(
            query="*",
            namespace="test-namespace"
        )
        assert len(all_patterns) > 0  #  Table not dropped
```

### SQL Injection Checklist

- [ ]  Use SQLAlchemy ORM for all queries
- [ ]  Use `bindparams()` for raw SQL
- [ ] L Never use f-strings for SQL
- [ ] L Never use string concatenation
- [ ] L Never use `.format()` or `%` for SQL
- [ ]  Validate and sanitize all user input
- [ ]  Use principle of least privilege for DB user
- [ ]  Test with SQL injection payloads

---

## XSS Prevention

**Status**:  **CRITICAL** - Cross-Site Scripting protection

### Attack Vectors

1. **Reflected XSS**: Malicious script in URL parameter
2. **Stored XSS**: Malicious script stored in database
3. **DOM-based XSS**: Client-side JavaScript manipulation

### Prevention Techniques

#### 1. Output Encoding (Server-Side)

```python
from html import escape
from markupsafe import Markup

#  SECURE - Escape HTML entities
def render_user_content(content: str) -> str:
    """
    Render user-generated content safely.

    Escapes: <, >, &, ", '
    """
    return escape(content)

# Example
user_input = "<script>alert('XSS')</script>"
safe_output = render_user_content(user_input)
# Result: "&lt;script&gt;alert('XSS')&lt;/script&gt;" 

# L VULNERABLE - Never render raw HTML
dangerous_output = user_input  # Renders: <script>alert('XSS')</script> L
```

#### 2. Content Security Policy (CSP)

```python
from fastapi import Response

@app.get("/")
async def index():
    """Serve frontend with CSP header"""

    response = Response(content=html_content, media_type="text/html")

    # Set CSP header
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "  # Allow inline scripts (carefully)
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://api.tmws.com; "
        "frame-ancestors 'none';"
    )

    return response
```

#### 3. Input Sanitization

```python
import bleach

ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'ul', 'li', 'ol']
ALLOWED_ATTRIBUTES = {}

def sanitize_html(user_input: str) -> str:
    """
    Sanitize user HTML input.

    Removes dangerous tags like <script>, <iframe>, etc.
    """
    return bleach.clean(
        user_input,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True
    )

# Example
user_input = "<p>Hello</p><script>alert('XSS')</script>"
safe_output = sanitize_html(user_input)
# Result: "<p>Hello</p>"  (script removed)
```

#### 4. React/Frontend (Automatic Escaping)

```jsx
//  SECURE - React automatically escapes
function UserProfile({ username }) {
    return <div>{username}</div>;  // Automatically escaped 
}

// Example
username = "<script>alert('XSS')</script>";
// Rendered as: &lt;script&gt;alert('XSS')&lt;/script&gt; 

// L VULNERABLE - dangerouslySetInnerHTML
function UserProfile({ username }) {
    return <div dangerouslySetInnerHTML={{__html: username}} />;  // L XSS risk
}
```

### Testing XSS

**File**: `tests/unit/security/test_xss.py`

```python
import pytest
from src.security.sanitization import sanitize_html, render_user_content

def test_xss_script_tag():
    """Test that <script> tags are removed"""

    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='javascript:alert(1)'>",
    ]

    for payload in payloads:
        # Test HTML sanitization
        sanitized = sanitize_html(payload)
        assert "<script>" not in sanitized.lower()
        assert "onerror=" not in sanitized.lower()
        assert "onload=" not in sanitized.lower()
        assert "javascript:" not in sanitized.lower()

        # Test HTML escaping
        escaped = render_user_content(payload)
        assert "&lt;" in escaped or "&gt;" in escaped  # Tags escaped
```

### XSS Prevention Checklist

- [ ]  Escape all user input on output
- [ ]  Use Content Security Policy (CSP)
- [ ]  Sanitize HTML input with allowlist
- [ ]  Use HTTP-only cookies for sessions
- [ ]  Set X-Content-Type-Options: nosniff
- [ ]  Set X-Frame-Options: DENY
- [ ] L Never use `dangerouslySetInnerHTML` without sanitization
- [ ] L Never trust user input

---

## CSRF Protection

**Status**:  **ENABLED** for state-changing operations

### What is CSRF?

**CSRF (Cross-Site Request Forgery)**: Attacker tricks user into making unwanted request to trusted site.

**Attack Example**:
```html
<!-- Attacker's malicious site -->
<img src="https://tmws.com/api/v1/memories/delete-all" />
<!-- User's browser sends cookies automatically L -->
```

### Prevention with CSRF Tokens

**File**: `src/security/csrf.py`

```python
import secrets
from fastapi import HTTPException, Request, Response
from datetime import datetime, timedelta

class CSRFProtection:
    """
    CSRF token generation and validation.

    Features:
    - Double-submit cookie pattern
    - Token expiration (1 hour)
    - Constant-time comparison
    """

    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self._tokens = {}  # In production, use Redis

    def generate_token(self, user_id: str) -> str:
        """Generate CSRF token for user"""
        token = secrets.token_hex(32)

        self._tokens[token] = {
            "user_id": user_id,
            "expires_at": datetime.utcnow() + timedelta(hours=1)
        }

        return token

    def validate_token(self, token: str, user_id: str) -> bool:
        """Validate CSRF token"""
        if token not in self._tokens:
            return False

        token_data = self._tokens[token]

        # Check expiration
        if datetime.utcnow() > token_data["expires_at"]:
            del self._tokens[token]
            return False

        # Constant-time comparison (prevents timing attacks)
        return secrets.compare_digest(token_data["user_id"], user_id)

csrf_protection = CSRFProtection(settings.secret_key)

# Dependency for CSRF validation
async def validate_csrf_token(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Validate CSRF token from header"""
    token = request.headers.get("X-CSRF-Token")

    if not token:
        raise HTTPException(400, "CSRF token missing")

    if not csrf_protection.validate_token(token, current_user.agent_id):
        raise HTTPException(403, "Invalid CSRF token")

    return True
```

### Using CSRF Protection

```python
from fastapi import Depends

@app.post(
    "/api/v1/memories",
    dependencies=[Depends(validate_csrf_token)]  #  CSRF protection
)
async def create_memory(
    request: MemoryRequest,
    current_user: User = Depends(get_current_user)
):
    """Create memory (protected against CSRF)"""
    memory = await memory_service.create_memory(request)
    return memory
```

### Client-Side Usage

```javascript
// 1. Get CSRF token from server
const response = await fetch('/api/v1/csrf-token', {
    credentials: 'include'
});
const { csrf_token } = await response.json();

// 2. Include token in all state-changing requests
await fetch('/api/v1/memories', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf_token  //  Include CSRF token
    },
    credentials: 'include',
    body: JSON.stringify({ content: '...' })
});
```

### CSRF Prevention Checklist

- [ ]  Use CSRF tokens for all POST/PUT/DELETE
- [ ]  Set SameSite=Lax on cookies
- [ ]  Validate CSRF token on server
- [ ]  Regenerate token after login
- [ ]  Use double-submit cookie pattern
- [ ] L Never accept state changes via GET
- [ ] L Never disable CORS in production

---

## Security Audit Logging

**Status**:  **ENABLED** - Comprehensive security event logging

### Log Categories

| Category | Events | Retention |
|----------|--------|-----------|
| Authentication | Login, logout, token generation | 90 days |
| Authorization | Access denied, permission checks | 90 days |
| Data Access | Memory read, search queries | 30 days |
| Data Modification | Create, update, delete | 180 days |
| Security Events | Rate limit, CSRF, SQL injection | 365 days |
| Admin Actions | User creation, permission changes | 365 days |

### Implementation

**File**: `src/security/audit_logger.py`

```python
from datetime import datetime
from sqlalchemy import insert
from src.models import SecurityAuditLog

class SecurityAuditLogger:
    """
    Comprehensive security audit logging.

    Features:
    - Structured logging (JSON)
    - Async writes (non-blocking)
    - Automatic context enrichment
    - Tamper-evident (append-only)
    """

    async def log_authentication(
        self,
        agent_id: str,
        action: str,  # login, logout, token_refresh
        success: bool,
        ip_address: str,
        user_agent: str,
        metadata: dict | None = None
    ):
        """Log authentication event"""
        await self._write_log(
            category="authentication",
            agent_id=agent_id,
            action=action,
            success=success,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata
        )

    async def log_authorization(
        self,
        agent_id: str,
        resource_type: str,  # memory, learning_pattern, etc.
        resource_id: str,
        action: str,  # read, write, delete
        allowed: bool,
        reason: str | None = None
    ):
        """Log authorization check"""
        await self._write_log(
            category="authorization",
            agent_id=agent_id,
            action=f"{action}_{resource_type}",
            success=allowed,
            metadata={
                "resource_type": resource_type,
                "resource_id": resource_id,
                "reason": reason
            }
        )

    async def log_security_event(
        self,
        agent_id: str,
        event_type: str,  # rate_limit, csrf, sql_injection, xss
        severity: str,    # low, medium, high, critical
        details: dict
    ):
        """Log security event"""
        await self._write_log(
            category="security",
            agent_id=agent_id,
            action=event_type,
            success=False,  # Security events are failures
            severity=severity,
            metadata=details
        )

    async def _write_log(self, **kwargs):
        """Write log entry to database"""
        stmt = insert(SecurityAuditLog).values(
            timestamp=datetime.utcnow(),
            **kwargs
        )
        await db.execute(stmt)
        await db.commit()

audit_logger = SecurityAuditLogger()
```

### Usage Examples

```python
# Log successful authentication
await audit_logger.log_authentication(
    agent_id="artemis-optimizer",
    action="login",
    success=True,
    ip_address="192.168.1.100",
    user_agent="Mozilla/5.0..."
)

# Log authorization denial
await audit_logger.log_authorization(
    agent_id="attacker",
    resource_type="memory",
    resource_id="uuid-1234",
    action="read",
    allowed=False,
    reason="Namespace mismatch (P0-1 violation)"
)

# Log rate limit violation
await audit_logger.log_security_event(
    agent_id="spammer",
    event_type="rate_limit_exceeded",
    severity="medium",
    details={
        "endpoint": "/api/v1/mcp/connections",
        "limit": 10,
        "attempts": 50,
        "window": "1 minute"
    }
)

# Log SQL injection attempt
await audit_logger.log_security_event(
    agent_id="attacker",
    event_type="sql_injection_attempt",
    severity="critical",
    details={
        "payload": "'; DROP TABLE memories; --",
        "endpoint": "/api/v1/memories/search",
        "blocked": True
    }
)
```

### Log Query Examples

```sql
-- Find all failed authentication attempts
SELECT * FROM security_audit_logs
WHERE category = 'authentication' AND success = FALSE
ORDER BY timestamp DESC LIMIT 100;

-- Find all P0-1 violations (namespace isolation)
SELECT * FROM security_audit_logs
WHERE category = 'authorization'
  AND success = FALSE
  AND metadata->>'reason' LIKE '%P0-1%'
ORDER BY timestamp DESC;

-- Find rate limit violations by agent
SELECT agent_id, COUNT(*) as violations
FROM security_audit_logs
WHERE action = 'rate_limit_exceeded'
  AND timestamp > NOW() - INTERVAL '24 hours'
GROUP BY agent_id
ORDER BY violations DESC;
```

### Alerting Rules

```python
# Alert on repeated authentication failures
async def check_brute_force_attack():
    """Alert if 10+ failed logins in 5 minutes"""

    stmt = text("""
        SELECT agent_id, COUNT(*) as attempts
        FROM security_audit_logs
        WHERE category = 'authentication'
          AND success = FALSE
          AND timestamp > NOW() - INTERVAL '5 minutes'
        GROUP BY agent_id
        HAVING COUNT(*) >= 10
    """)

    results = await db.execute(stmt)

    for row in results:
        await send_alert(
            severity="high",
            message=f"Brute force attack detected: {row.agent_id} "
                    f"({row.attempts} failed logins in 5 minutes)"
        )

# Alert on SQL injection attempts
async def check_sql_injection():
    """Alert on any SQL injection attempt"""

    stmt = text("""
        SELECT * FROM security_audit_logs
        WHERE action = 'sql_injection_attempt'
          AND timestamp > NOW() - INTERVAL '1 hour'
    """)

    results = await db.execute(stmt)

    for log in results:
        await send_alert(
            severity="critical",
            message=f"SQL injection attempt: {log.agent_id} "
                    f"Payload: {log.metadata['payload']}"
        )
```

---

## Input Validation

**Status**:  **MANDATORY** for all user input

### Validation Layers

1. **Type Validation**: Pydantic models
2. **Format Validation**: Regex patterns
3. **Range Validation**: Min/max constraints
4. **Semantic Validation**: Business logic

### Pydantic Validation

```python
from pydantic import BaseModel, Field, validator
import re

class MemoryCreateRequest(BaseModel):
    """Request model with comprehensive validation"""

    content: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Memory content"
    )

    memory_type: str = Field(
        ...,
        regex="^[a-z0-9_-]+$",
        min_length=1,
        max_length=50,
        description="Memory type (alphanumeric, dash, underscore only)"
    )

    importance_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Importance score (0.0 to 1.0)"
    )

    tags: list[str] = Field(
        default_factory=list,
        max_items=20,
        description="Tags for categorization"
    )

    access_level: str = Field(
        ...,
        regex="^(PRIVATE|TEAM|SHARED|PUBLIC|SYSTEM)$",
        description="Access control level"
    )

    namespace: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Namespace for multi-tenancy"
    )

    @validator("tags")
    def validate_tags(cls, v):
        """Validate tag format"""
        for tag in v:
            if not re.match(r"^[a-z0-9_-]+$", tag):
                raise ValueError(f"Invalid tag format: {tag}")
            if len(tag) > 50:
                raise ValueError(f"Tag too long: {tag}")
        return v

    @validator("namespace")
    def sanitize_namespace(cls, v):
        """Sanitize namespace (V-1 fix: prevent path traversal)"""
        # Block . and / to prevent path traversal
        sanitized = v.replace(".", "-").replace("/", "-")
        return sanitized

    @validator("content")
    def validate_content_safe(cls, v):
        """Check for obvious XSS/SQL injection attempts"""
        dangerous_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=",
            r"'; DROP TABLE",
            r"UNION SELECT"
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError(f"Potentially dangerous content detected")

        return v
```

### Custom Validators

```python
from fastapi import HTTPException

def validate_agent_id(agent_id: str) -> str:
    """Validate agent ID format"""
    if not re.match(r"^[a-z0-9_-]+$", agent_id):
        raise HTTPException(400, "Invalid agent ID format")

    if len(agent_id) > 255:
        raise HTTPException(400, "Agent ID too long")

    return agent_id

def validate_uuid(uuid_str: str) -> str:
    """Validate UUID format"""
    uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

    if not re.match(uuid_pattern, uuid_str, re.IGNORECASE):
        raise HTTPException(400, "Invalid UUID format")

    return uuid_str
```

### Input Sanitization

```python
import bleach
from html import escape

def sanitize_string(input_str: str) -> str:
    """Sanitize string input"""
    # 1. Strip whitespace
    cleaned = input_str.strip()

    # 2. Normalize unicode
    cleaned = cleaned.encode('utf-8').decode('utf-8')

    # 3. Remove null bytes
    cleaned = cleaned.replace('\x00', '')

    # 4. Escape HTML entities
    cleaned = escape(cleaned)

    return cleaned

def sanitize_html(html_input: str) -> str:
    """Sanitize HTML input (allowlist approach)"""
    ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'ul', 'li', 'ol', 'code']
    ALLOWED_ATTRIBUTES = {}

    return bleach.clean(
        html_input,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True
    )
```

---

## Secret Management

**Status**:  **CRITICAL** - Never commit secrets

### Environment Variables

**File**: `.env` (NEVER commit this)

```bash
# Database
TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"

# Security (CRITICAL - NEVER COMMIT)
TMWS_SECRET_KEY="your-256-bit-secret-key-minimum-32-characters-long"
TMWS_API_KEY_SALT="your-api-key-salt-minimum-32-characters-long"

# Environment
TMWS_ENVIRONMENT="production"

# CORS
TMWS_CORS_ORIGINS='["https://your-domain.com"]'

# Rate Limiting
TMWS_RATE_LIMIT_ENABLED="true"
TMWS_RATE_LIMIT_PER_MINUTE="100"

# Logging
TMWS_LOG_LEVEL="INFO"
```

**File**: `.env.example` (Commit this for reference)

```bash
# Database
TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"

# Security (GENERATE YOUR OWN - DO NOT USE THESE)
TMWS_SECRET_KEY="<generate-with-openssl-rand-hex-32>"
TMWS_API_KEY_SALT="<generate-with-openssl-rand-hex-32>"

# Environment
TMWS_ENVIRONMENT="development"

# CORS
TMWS_CORS_ORIGINS='["http://localhost:3000"]'
```

### Generating Secrets

```bash
# Generate secret key (256 bits)
openssl rand -hex 32

# Generate API key salt
openssl rand -hex 32

# Generate API key
python3 -c "import secrets; print(f'tmws_{secrets.token_hex(32)}')"
```

### Secret Rotation

**Quarterly rotation (every 90 days)**:

```python
# 1. Generate new secret key
new_secret_key = generate_secret_key()

# 2. Deploy with both old and new keys (grace period)
TMWS_SECRET_KEY = os.getenv("TMWS_SECRET_KEY")
TMWS_SECRET_KEY_NEW = os.getenv("TMWS_SECRET_KEY_NEW")

def verify_token(token: str):
    """Verify JWT with either old or new key"""
    try:
        # Try new key first
        return jwt.decode(token, TMWS_SECRET_KEY_NEW, algorithms=["HS256"])
    except JWTError:
        # Fallback to old key (grace period)
        return jwt.decode(token, TMWS_SECRET_KEY, algorithms=["HS256"])

# 3. After 24 hours, remove old key
TMWS_SECRET_KEY = os.getenv("TMWS_SECRET_KEY_NEW")
```

### Secret Storage Best Practices

1.  **Use environment variables** (not hardcoded)
2.  **Add .env to .gitignore**
3.  **Provide .env.example** for reference
4.  **Use secret management tools** (AWS Secrets Manager, HashiCorp Vault)
5.  **Rotate secrets regularly** (90 days)
6.  **Use different secrets** for dev/staging/prod
7. L **Never commit secrets** to git
8. L **Never log secrets** in application logs
9. L **Never share secrets** via email/Slack

---

## Access Control Levels

**Status**:  **GRANULAR** - 5 access levels

### Access Levels

| Level | Description | Use Case | Visibility |
|-------|-------------|----------|------------|
| `PRIVATE` | Owner only | Personal notes, credentials | Owner only |
| `TEAM` | Same namespace | Team collaboration | Namespace members |
| `SHARED` | Explicit agents | Cross-team sharing | Listed agents + owner |
| `PUBLIC` | All agents in namespace | Knowledge base | All in namespace |
| `SYSTEM` | System-wide (read-only) | System announcements | All agents (read-only) |

### Implementation

**File**: `src/models/memory.py`

```python
from enum import Enum

class AccessLevel(str, Enum):
    PRIVATE = "PRIVATE"
    TEAM = "TEAM"
    SHARED = "SHARED"
    PUBLIC = "PUBLIC"
    SYSTEM = "SYSTEM"

class Memory(Base):
    __tablename__ = "memories"

    access_level: Mapped[str] = mapped_column(
        String(50),
        default=AccessLevel.TEAM.value
    )
    shared_with_agents: Mapped[list[str] | None] = mapped_column(
        JSON,
        nullable=True
    )
```

### Access Control Matrix

| Memory Owner | Access Level | Agent (Same NS) | Agent (Diff NS) | System |
|--------------|--------------|-----------------|-----------------|--------|
| artemis | PRIVATE | L Denied | L Denied | L Denied |
| artemis | TEAM |  Allowed | L Denied | L Denied |
| artemis | SHARED (hestia) |  (if hestia) | L Denied | L Denied |
| artemis | PUBLIC |  Allowed | L Denied | L Denied |
| system | SYSTEM |  Read-only |  Read-only |  Read-only |

### Upgrade Access Level

```python
async def upgrade_memory_access(
    memory_id: str,
    new_access_level: str,
    shared_with: list[str] | None = None
):
    """
    Upgrade memory access level.

    Security:
    - Only owner can upgrade
    - Cannot downgrade SYSTEM level
    - Shared requires explicit agent list
    """
    memory = await db.get(Memory, memory_id)

    # Check ownership
    if memory.agent_id != current_user.agent_id:
        raise HTTPException(403, "Only owner can change access level")

    # Prevent downgrading SYSTEM
    if memory.access_level == "SYSTEM":
        raise HTTPException(403, "Cannot downgrade SYSTEM level")

    # Validate SHARED requires agent list
    if new_access_level == "SHARED" and not shared_with:
        raise HTTPException(400, "SHARED requires shared_with_agents list")

    # Update access level
    memory.access_level = new_access_level
    memory.shared_with_agents = shared_with

    await db.commit()

    # Audit log
    await audit_logger.log_security_event(
        agent_id=current_user.agent_id,
        event_type="access_level_change",
        severity="medium",
        details={
            "memory_id": str(memory_id),
            "old_level": memory.access_level,
            "new_level": new_access_level
        }
    )
```

---

## Security Best Practices

### 1. Authentication

-  Use JWT for short-lived sessions (1 hour)
-  Use refresh tokens for long-lived sessions (7 days)
-  Implement token rotation (invalidate old refresh token on use)
-  Hash API keys with bcrypt (never store plaintext)
-  Use constant-time comparison for API keys (prevent timing attacks)
-  Set short expiration for API keys (90 days)
- L Never include sensitive data in JWT payload

### 2. Authorization

-  Always verify namespace from database (P0-1)
-  Use principle of least privilege
-  Implement role-based access control (RBAC)
-  Audit all authorization checks
- L Never trust user input for authorization
- L Never skip authorization checks

### 3. Input Validation

-  Validate all user input with Pydantic
-  Sanitize HTML input with allowlist
-  Escape output for XSS prevention
-  Use parameterized queries for SQL
-  Implement rate limiting
- L Never trust user input
- L Never use string concatenation for SQL

### 4. Secrets Management

-  Store secrets in environment variables
-  Rotate secrets every 90 days
-  Use different secrets for each environment
-  Use secret management tools (Vault, AWS Secrets Manager)
- L Never commit secrets to git
- L Never log secrets
- L Never share secrets via email/Slack

### 5. Logging & Monitoring

-  Log all security events
-  Monitor for brute force attacks
-  Alert on SQL injection attempts
-  Track rate limit violations
-  Retain logs for 90-365 days
- L Never log sensitive data (passwords, API keys)

### 6. Network Security

-  Use HTTPS in production (TLS 1.3)
-  Set secure headers (CSP, X-Frame-Options, etc.)
-  Implement CORS properly
-  Use SameSite=Lax for cookies
- L Never allow HTTP in production
- L Never disable CORS in production

---

## Compliance Checklist

### Pre-Production Security Audit

#### Authentication & Authorization

- [ ]  JWT authentication implemented
- [ ]  API key authentication implemented
- [ ]  P0-1 namespace isolation verified
- [ ]  Access control levels tested
- [ ]  Token expiration enforced
- [ ]  Refresh token rotation implemented

#### Input Validation

- [ ]  Pydantic validation on all endpoints
- [ ]  SQL injection prevention (bindparams)
- [ ]  XSS prevention (output escaping)
- [ ]  CSRF protection enabled
- [ ]  Rate limiting configured
- [ ]  Input sanitization applied

#### Secrets Management

- [ ]  No secrets in git history
- [ ]  .env file in .gitignore
- [ ]  .env.example provided
- [ ]  Secrets rotated (90 days)
- [ ]  Different secrets per environment

#### Logging & Monitoring

- [ ]  Security audit logging enabled
- [ ]  Authentication events logged
- [ ]  Authorization checks logged
- [ ]  Security events logged
- [ ]  Alerting configured
- [ ]  Log retention policy (90-365 days)

#### Network Security

- [ ]  HTTPS enabled (TLS 1.3)
- [ ]  CSP header configured
- [ ]  X-Frame-Options: DENY
- [ ]  X-Content-Type-Options: nosniff
- [ ]  CORS origins restricted
- [ ]  SameSite=Lax cookies

#### Testing

- [ ]  Unit tests for security functions
- [ ]  Integration tests for P0-1
- [ ]  SQL injection tests
- [ ]  XSS tests
- [ ]  CSRF tests
- [ ]  Rate limiting tests
- [ ]  Penetration testing completed

#### Documentation

- [ ]  Security guide reviewed
- [ ]  Incident response plan
- [ ]  Security contact documented
- [ ]  Compliance requirements met

---

## Incident Response

### Incident Severity Levels

| Level | Description | Response Time | Example |
|-------|-------------|---------------|---------|
| P0 | Critical security breach | 15 minutes | Database compromise, credential leak |
| P1 | High-severity vulnerability | 2 hours | SQL injection, XSS, CSRF |
| P2 | Medium-severity issue | 24 hours | Rate limit bypass, weak auth |
| P3 | Low-severity finding | 7 days | Missing header, info disclosure |

### Incident Response Plan

#### Phase 1: Detection & Triage (0-15 minutes)

1. **Alert received** (security monitoring, audit logs)
2. **Assess severity** (P0-P3)
3. **Assemble incident team**:
   - Hestia (Security Guardian): Lead
   - Artemis (Technical): Investigation
   - Athena (Coordination): Communication
4. **Create incident ticket**

#### Phase 2: Containment (15-60 minutes)

**P0 Actions**:
1. **Isolate affected systems** (disable network access)
2. **Revoke compromised credentials** (API keys, tokens)
3. **Enable enhanced logging**
4. **Notify stakeholders**

**P1 Actions**:
1. **Block malicious IPs** (firewall rules)
2. **Disable affected endpoints** (temporary)
3. **Increase monitoring**

#### Phase 3: Investigation (1-4 hours)

1. **Collect evidence**:
   ```sql
   -- Security audit logs
   SELECT * FROM security_audit_logs
   WHERE timestamp > 'incident_start_time'
   ORDER BY timestamp;

   -- Authentication logs
   SELECT * FROM security_audit_logs
   WHERE category = 'authentication'
     AND timestamp > 'incident_start_time';
   ```

2. **Analyze attack vector**
3. **Identify root cause**
4. **Document findings**

#### Phase 4: Remediation (4-24 hours)

1. **Apply security patch**
2. **Update affected systems**
3. **Verify fix**
4. **Re-enable services**

#### Phase 5: Recovery (24-48 hours)

1. **Restore normal operations**
2. **Monitor for recurrence**
3. **Validate no data loss**
4. **Update security policies**

#### Phase 6: Post-Incident Review (48-72 hours)

1. **Root cause analysis**
2. **Timeline reconstruction**
3. **Lessons learned**
4. **Update incident playbook**
5. **Security improvements**

### Incident Communication Template

```markdown
# Security Incident Report

## Incident Summary

- **Incident ID**: INC-2025-001
- **Severity**: P0 (Critical)
- **Status**: Resolved
- **Detected**: 2025-11-14 10:30 UTC
- **Resolved**: 2025-11-14 14:00 UTC
- **Duration**: 3.5 hours

## Impact

- **Affected Systems**: TMWS API server
- **Affected Users**: None (contained before data access)
- **Data Exposure**: None confirmed

## Timeline

- 10:30 UTC: SQL injection attempt detected (automated alert)
- 10:32 UTC: Incident team assembled (Hestia, Artemis, Athena)
- 10:35 UTC: Malicious IP blocked, enhanced logging enabled
- 11:00 UTC: Root cause identified (missing bindparams in learning_service.py:704)
- 11:30 UTC: Security patch applied (bindparams() implementation)
- 12:00 UTC: Fix verified (penetration testing)
- 14:00 UTC: Service restored, incident closed

## Root Cause

SQL injection vulnerability in `learning_service.py:704` due to f-string usage in WHERE clause.

## Resolution

- Applied parameterized query with `bindparams()`
- Added regression tests
- Updated security scanning rules

## Lessons Learned

1. **Detection**: Automated alert worked as designed 
2. **Response**: 3.5 hour resolution (target: <4 hours) 
3. **Prevention**: Code review should catch f-strings in SQL
4. **Improvement**: Add pre-commit hook for SQL string checks

## Follow-up Actions

- [ ] Update code review checklist (Artemis)
- [ ] Add pre-commit hook for SQL validation (Artemis)
- [ ] Security training on SQL injection (Hestia)
- [ ] Update incident playbook (Athena)
```

### Emergency Contacts

**Security Team**:
- Hestia (Security Guardian): hestia@tmws.local
- Artemis (Technical Lead): artemis@tmws.local
- Athena (Coordination): athena@tmws.local

**Escalation**:
- P0/P1: Immediate notification
- P2: Within 2 hours
- P3: Daily summary

---

## Security Resources

### External References

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **CWE Top 25**: https://cwe.mitre.org/top25/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **SQLAlchemy Security**: https://docs.sqlalchemy.org/en/20/faq/security.html

### Internal Documentation

- **Quick Start**: `docs/QUICK_START_GUIDE.md`
- **MCP Tools Reference**: `docs/MCP_TOOLS_REFERENCE.md`
- **REST API Guide**: `docs/REST_API_GUIDE.md`
- **Integration Patterns**: `docs/INTEGRATION_PATTERNS.md`

### Testing

- **Security Tests**: `tests/unit/security/`
- **P0-1 Tests**: `tests/unit/security/test_namespace_isolation.py`
- **SQL Injection Tests**: `tests/unit/security/test_sql_injection.py`
- **XSS Tests**: `tests/unit/security/test_xss.py`

---

## Conclusion

TMWS implements **defense-in-depth security** with multiple layers:

1.  **P0-1 Namespace Isolation** (Critical)
2.  **JWT + API Key Authentication**
3.  **SQL Injection Prevention** (bindparams)
4.  **XSS Prevention** (output escaping)
5.  **CSRF Protection** (tokens)
6.  **Rate Limiting** (DoS protection)
7.  **Security Audit Logging** (compliance)
8.  **Input Validation** (Pydantic)

**Key Takeaways**:

- **Never trust user input** (validate, sanitize, escape)
- **Always verify namespace from database** (P0-1 pattern)
- **Use parameterized queries** (prevent SQL injection)
- **Log all security events** (audit trail)
- **Test security regularly** (penetration testing)

---

**Document Author**: Hestia (Security Guardian)
**Contributors**: Artemis, Athena, Hera
**Reviewed By**: Hera, Eris
**Last Updated**: 2025-11-14
**Status**: Production-ready
**Version**: 1.0.0
