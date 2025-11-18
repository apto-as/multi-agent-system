# Security Standards Context v2.2.1

**Load Condition**: `security` or `full` context profile
**Estimated Size**: ~3k tokens
**Primary Agent**: Hestia (with Artemis performance validation)

---

## Security Audit Framework

### STRIDE Threat Model

**Systematic threat identification**:
- **S**poofing: Authentication bypass, identity theft
- **T**ampering: Data modification, code injection
- **R**epudiation: Action denial, audit manipulation
- **I**nformation Disclosure: Data leaks, unauthorized access
- **D**enial of Service: Resource exhaustion
- **E**levation of Privilege: Authorization bypass

### Risk Assessment Matrix

| Likelihood | Impact | Risk Level | Response Time |
|-----------|--------|------------|---------------|
| Certain | Catastrophic | **Critical** | <24 hours |
| Likely | Major | **High** | <3 days |
| Possible | Moderate | **Medium** | <1 week |
| Unlikely | Minor | **Low** | Next release |
| Rare | Negligible | **Informational** | Backlog |

---

## OWASP Top 10 (2021) - Implementation Checklist

### 1. Broken Access Control

**Prevention**:
```python
# ✓ Good: Explicit permission checks
@require_permission("admin")
async def admin_endpoint(user: User):
    if user.id != resource.owner_id and not user.has_role("admin"):
        raise HTTPException(403, "Forbidden")
    return resource

# ✗ Bad: Trust client-side data
@app.post("/admin/delete")
async def delete_user(user_id: str):
    # No authorization check!
    delete_user(user_id)
```

**Testing**:
```python
# Hestia automated test
async def test_access_control():
    # Try accessing admin endpoint as normal user
    response = await client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {normal_user_token}"}
    )
    assert response.status_code == 403
```

---

### 2. Cryptographic Failures

**Prevention**:
```python
# ✓ Good: Strong encryption
from cryptography.fernet import Fernet
import secrets

# Generate secure key
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt sensitive data
encrypted = cipher.encrypt(sensitive_data.encode())

# Hash passwords properly
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
hashed = pwd_context.hash(password)

# ✗ Bad: Weak or no encryption
import hashlib
weak_hash = hashlib.md5(password.encode()).hexdigest()  # DON'T USE MD5!
```

**Key Management**:
```python
# Store keys securely
import os
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")  # Never hardcode!

# Rotate keys regularly
def rotate_encryption_key():
    old_key = get_current_key()
    new_key = generate_new_key()

    # Re-encrypt data with new key
    for data in encrypted_data:
        decrypted = decrypt(data, old_key)
        re_encrypted = encrypt(decrypted, new_key)
        update_database(re_encrypted)

    store_new_key(new_key)
    archive_old_key(old_key)
```

---

### 3. Injection (SQL, NoSQL, Command)

**SQL Injection Prevention**:
```python
# ✓ Good: Parameterized queries
from sqlalchemy import text

query = text("""
    SELECT * FROM users
    WHERE email = :email AND status = :status
""")
result = await db.execute(query, {"email": user_email, "status": "active"})

# ✗ Bad: String concatenation
query = f"SELECT * FROM users WHERE email = '{user_email}'"  # DANGEROUS!
```

**Command Injection Prevention**:
```python
# ✓ Good: Use safe APIs
import subprocess

# Safe: List arguments
subprocess.run(["ls", "-la", user_provided_dir], check=True)

# ✗ Bad: Shell=True with user input
subprocess.run(f"ls -la {user_provided_dir}", shell=True)  # DANGEROUS!
```

**NoSQL Injection Prevention**:
```python
# ✓ Good: Validate and sanitize
from pydantic import BaseModel, validator

class UserQuery(BaseModel):
    username: str

    @validator('username')
    def validate_username(cls, v):
        if not v.isalnum():
            raise ValueError('Username must be alphanumeric')
        return v

# Safe query
query = {"username": validated_input.username}
result = await db.users.find_one(query)

# ✗ Bad: Direct user input
query = {"username": request.body["username"]}  # Could be {"$ne": null}
```

---

### 4. Insecure Design

**Secure Architecture Patterns**:
```python
# Defense in Depth
class SecurityLayersMiddleware:
    async def __call__(self, request: Request, call_next):
        # Layer 1: Rate limiting
        if not await rate_limiter.check(request.client.host):
            raise HTTPException(429, "Too many requests")

        # Layer 2: Authentication
        user = await authenticate(request)
        if not user:
            raise HTTPException(401, "Unauthorized")

        # Layer 3: Authorization
        if not await authorize(user, request.url.path):
            raise HTTPException(403, "Forbidden")

        # Layer 4: Input validation
        if not await validate_input(request):
            raise HTTPException(400, "Invalid input")

        response = await call_next(request)

        # Layer 5: Output sanitization
        sanitized = await sanitize_output(response)
        return sanitized
```

**Principle of Least Privilege**:
```python
# Database user permissions
class DatabaseRole(Enum):
    READ_ONLY = "SELECT"
    READ_WRITE = "SELECT, INSERT, UPDATE"
    ADMIN = "ALL PRIVILEGES"

# Application gets minimal permissions
app_db_user = create_user(
    username="app_service",
    role=DatabaseRole.READ_WRITE,
    tables=["users", "sessions", "logs"]  # Only needed tables
)
```

---

### 5. Security Misconfiguration

**Secure Defaults Checklist**:
```python
# ✓ Good: Production configuration
app_config = {
    "DEBUG": False,
    "SSL_REQUIRED": True,
    "SECURE_COOKIES": True,
    "HTTP_ONLY_COOKIES": True,
    "SAME_SITE_COOKIES": "Strict",
    "CSRF_PROTECTION": True,
    "CONTENT_SECURITY_POLICY": "default-src 'self'",
    "X_FRAME_OPTIONS": "DENY",
    "X_CONTENT_TYPE_OPTIONS": "nosniff",
    "HSTS_ENABLED": True,
    "HSTS_MAX_AGE": 31536000
}

# ✗ Bad: Development leaking to production
app_config = {
    "DEBUG": True,  # NEVER in production!
    "CORS_ALLOW_ALL": True,
    "SSL_REQUIRED": False
}
```

**Environment-Specific Security**:
```python
from enum import Enum

class Environment(Enum):
    DEVELOPMENT = "dev"
    STAGING = "staging"
    PRODUCTION = "prod"

def get_security_config(env: Environment):
    base_config = {
        "SESSION_TIMEOUT": 3600,
        "MAX_LOGIN_ATTEMPTS": 5
    }

    if env == Environment.PRODUCTION:
        return {
            **base_config,
            "SSL_REQUIRED": True,
            "DEBUG": False,
            "LOG_LEVEL": "WARNING"
        }
    elif env == Environment.STAGING:
        return {
            **base_config,
            "SSL_REQUIRED": True,
            "DEBUG": False,
            "LOG_LEVEL": "INFO"
        }
    else:  # Development
        return {
            **base_config,
            "SSL_REQUIRED": False,
            "DEBUG": True,
            "LOG_LEVEL": "DEBUG"
        }
```

---

### 6. Vulnerable and Outdated Components

**Dependency Management**:
```bash
# Regular vulnerability scanning
npm audit
pip-audit
safety check

# Automated updates
dependabot enable
renovate configure
```

**Version Pinning Strategy**:
```toml
# pyproject.toml
[tool.poetry.dependencies]
fastapi = "^0.104.0"  # Allow patch updates
pydantic = "2.4.2"    # Pin exact version for stability
cryptography = ">=41.0.0,<42.0.0"  # Range for security patches
```

**Supply Chain Security**:
```python
# Verify package integrity
import hashlib

def verify_package_integrity(package_path, expected_hash):
    with open(package_path, 'rb') as f:
        package_hash = hashlib.sha256(f.read()).hexdigest()

    if package_hash != expected_hash:
        raise SecurityError("Package integrity check failed!")

    return True
```

---

### 7. Identification and Authentication Failures

**Multi-Factor Authentication**:
```python
from pyotp import TOTP

# Generate MFA secret
secret = TOTP.random_base32()

# Verify MFA code
def verify_mfa(user_secret: str, code: str) -> bool:
    totp = TOTP(user_secret)
    return totp.verify(code, valid_window=1)

# Login flow
async def login(email: str, password: str, mfa_code: str):
    user = await authenticate_password(email, password)
    if not user:
        raise HTTPException(401, "Invalid credentials")

    if user.mfa_enabled:
        if not verify_mfa(user.mfa_secret, mfa_code):
            raise HTTPException(401, "Invalid MFA code")

    return generate_session_token(user)
```

**Session Management**:
```python
from datetime import datetime, timedelta
import secrets

class SecureSession:
    def create_session(self, user_id: str) -> str:
        # Generate cryptographically secure token
        token = secrets.token_urlsafe(32)

        # Store with expiration
        session_data = {
            "user_id": user_id,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(hours=24),
            "ip_address": request.client.host,
            "user_agent": request.headers.get("User-Agent")
        }

        await redis.setex(
            f"session:{token}",
            86400,  # 24 hours
            json.dumps(session_data)
        )

        return token

    async def validate_session(self, token: str) -> dict:
        session_data = await redis.get(f"session:{token}")
        if not session_data:
            raise HTTPException(401, "Session expired")

        session = json.loads(session_data)

        # Validate IP address (optional, strict)
        if session["ip_address"] != request.client.host:
            raise HTTPException(401, "Session hijacking detected")

        return session

    async def revoke_session(self, token: str):
        await redis.delete(f"session:{token}")
```

---

### 8. Software and Data Integrity Failures

**Code Signing & Verification**:
```python
import hashlib
import hmac

def sign_data(data: bytes, secret_key: bytes) -> str:
    """Create HMAC signature for data integrity"""
    return hmac.new(secret_key, data, hashlib.sha256).hexdigest()

def verify_signature(data: bytes, signature: str, secret_key: bytes) -> bool:
    """Verify data hasn't been tampered"""
    expected_signature = sign_data(data, secret_key)
    return hmac.compare_digest(expected_signature, signature)

# Usage in API
@app.post("/webhook")
async def webhook_handler(request: Request):
    payload = await request.body()
    signature = request.headers.get("X-Signature")

    if not verify_signature(payload, signature, WEBHOOK_SECRET):
        raise HTTPException(401, "Invalid signature")

    # Process webhook safely
    return {"status": "processed"}
```

**Immutable Audit Logs**:
```python
import hashlib
from datetime import datetime

class ImmutableAuditLog:
    def __init__(self):
        self.previous_hash = "0" * 64  # Genesis block

    def create_entry(self, event: dict) -> dict:
        """Create tamper-proof audit log entry"""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": event,
            "previous_hash": self.previous_hash
        }

        # Calculate entry hash
        entry_str = json.dumps(entry, sort_keys=True)
        current_hash = hashlib.sha256(entry_str.encode()).hexdigest()
        entry["hash"] = current_hash

        # Update chain
        self.previous_hash = current_hash

        return entry

    def verify_chain(self, entries: list) -> bool:
        """Verify audit log hasn't been tampered"""
        previous_hash = "0" * 64

        for entry in entries:
            # Recalculate hash
            entry_copy = entry.copy()
            stored_hash = entry_copy.pop("hash")

            entry_str = json.dumps(entry_copy, sort_keys=True)
            calculated_hash = hashlib.sha256(entry_str.encode()).hexdigest()

            if calculated_hash != stored_hash:
                return False

            if entry["previous_hash"] != previous_hash:
                return False

            previous_hash = stored_hash

        return True
```

---

### 9. Security Logging and Monitoring Failures

**Comprehensive Security Logging**:
```python
import structlog

logger = structlog.get_logger()

class SecurityLogger:
    @staticmethod
    async def log_authentication(user_id: str, success: bool, ip: str):
        logger.info(
            "authentication_attempt",
            user_id=user_id,
            success=success,
            ip_address=ip,
            timestamp=datetime.utcnow().isoformat()
        )

    @staticmethod
    async def log_authorization_failure(user_id: str, resource: str, action: str):
        logger.warning(
            "authorization_failure",
            user_id=user_id,
            resource=resource,
            action=action,
            severity="medium"
        )

    @staticmethod
    async def log_data_access(user_id: str, data_type: str, record_count: int):
        logger.info(
            "data_access",
            user_id=user_id,
            data_type=data_type,
            record_count=record_count
        )

    @staticmethod
    async def log_security_incident(incident_type: str, severity: str, details: dict):
        logger.error(
            "security_incident",
            incident_type=incident_type,
            severity=severity,
            details=details,
            requires_investigation=True
        )
```

**Anomaly Detection**:
```python
from collections import defaultdict
import time

class AnomalyDetector:
    def __init__(self):
        self.failed_attempts = defaultdict(list)
        self.access_patterns = defaultdict(list)

    async def detect_brute_force(self, user_id: str) -> bool:
        """Detect brute force attempts"""
        now = time.time()
        window = 300  # 5 minutes

        # Clean old attempts
        self.failed_attempts[user_id] = [
            t for t in self.failed_attempts[user_id]
            if now - t < window
        ]

        # Check threshold
        if len(self.failed_attempts[user_id]) > 5:
            await SecurityLogger.log_security_incident(
                incident_type="brute_force_detected",
                severity="high",
                details={"user_id": user_id, "attempts": len(self.failed_attempts[user_id])}
            )
            return True

        self.failed_attempts[user_id].append(now)
        return False

    async def detect_unusual_access(self, user_id: str, resource: str) -> bool:
        """Detect unusual access patterns"""
        # Track access pattern
        self.access_patterns[user_id].append({
            "resource": resource,
            "timestamp": time.time()
        })

        # Analyze pattern (simplified)
        recent_access = self.access_patterns[user_id][-10:]
        unique_resources = len(set(a["resource"] for a in recent_access))

        # Alert if accessing many different resources quickly
        if unique_resources > 7:  # Threshold
            await SecurityLogger.log_security_incident(
                incident_type="unusual_access_pattern",
                severity="medium",
                details={"user_id": user_id, "resource_count": unique_resources}
            )
            return True

        return False
```

---

### 10. Server-Side Request Forgery (SSRF)

**URL Validation**:
```python
from urllib.parse import urlparse
import ipaddress

class SSRFProtection:
    BLOCKED_NETWORKS = [
        ipaddress.ip_network("127.0.0.0/8"),    # Localhost
        ipaddress.ip_network("10.0.0.0/8"),     # Private
        ipaddress.ip_network("172.16.0.0/12"),  # Private
        ipaddress.ip_network("192.168.0.0/16"), # Private
        ipaddress.ip_network("169.254.0.0/16"), # Link-local
    ]

    @staticmethod
    def is_safe_url(url: str) -> bool:
        """Validate URL is not targeting internal resources"""
        try:
            parsed = urlparse(url)

            # Resolve hostname to IP
            import socket
            ip = socket.gethostbyname(parsed.hostname)
            ip_addr = ipaddress.ip_address(ip)

            # Check against blocked networks
            for network in SSRFProtection.BLOCKED_NETWORKS:
                if ip_addr in network:
                    return False

            # Whitelist approach (recommended)
            allowed_domains = ["api.example.com", "cdn.example.com"]
            if parsed.hostname not in allowed_domains:
                return False

            return True

        except Exception:
            return False

    @staticmethod
    async def fetch_external_resource(url: str) -> bytes:
        """Safely fetch external resource"""
        if not SSRFProtection.is_safe_url(url):
            raise HTTPException(400, "Invalid URL")

        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url)
            return response.content
```

---

## Hestia Security Audit Workflow

### Automated Security Scan

```python
async def comprehensive_security_audit():
    """Hestia's systematic security audit"""

    # 1. Dependency vulnerabilities
    vuln_report = await hestia.scan_dependencies()

    # 2. Code vulnerabilities (serena MCP)
    code_issues = await serena.search_for_pattern(
        substring_pattern=r"(password|secret|api_key)\s*=\s*['\"]",
        restrict_search_to_code_files=True
    )

    # 3. SQL injection risks
    sql_risks = await serena.search_for_pattern(
        substring_pattern=r"(execute|query).*\+.*",
        restrict_search_to_code_files=True
    )

    # 4. Dynamic testing (playwright MCP)
    xss_test = await hestia.test_xss_vulnerabilities()
    csrf_test = await hestia.test_csrf_protection()

    # 5. Configuration audit
    config_issues = await hestia.audit_security_config()

    # 6. Access control testing
    authz_issues = await hestia.test_authorization()

    # 7. Generate report
    report = hestia.compile_security_report({
        "dependencies": vuln_report,
        "code_issues": code_issues,
        "sql_risks": sql_risks,
        "xss_test": xss_test,
        "csrf_test": csrf_test,
        "config_issues": config_issues,
        "authz_issues": authz_issues
    })

    # 8. Store in TMWS
    await tmws.store_memory(
        content=f"Security audit: {len(report.critical)} critical issues",
        importance=1.0 if report.critical else 0.7,
        tags=["security", "audit", "hestia"]
    )

    return report
```

---

## Security Testing Checklist

**Pre-Deployment Checklist** (Hestia):
- [ ] All dependencies scanned for vulnerabilities
- [ ] No hardcoded secrets in code
- [ ] SQL injection prevention validated
- [ ] XSS protection tested
- [ ] CSRF tokens implemented
- [ ] Authentication MFA-enabled for sensitive operations
- [ ] Session management secure (httpOnly, secure, sameSite)
- [ ] Input validation comprehensive
- [ ] Output encoding consistent
- [ ] HTTPS enforced
- [ ] Security headers configured
- [ ] Audit logging enabled
- [ ] Access control tested
- [ ] Error messages don't leak information
- [ ] File upload validation implemented

---

**Security Standards v2.2.1**
*Hestia-led security audit with Artemis performance validation*
*Reference: @hestia-auditor.md for detailed patterns*
