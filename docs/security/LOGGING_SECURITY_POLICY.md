# Logging Security Policy
## Trinitas Project - V-8 (CWE-532) Compliance

**Version**: 1.0.0
**Last Updated**: 2025-11-07
**Status**: Active
**Severity**: HIGH
**Compliance**: GDPR, CCPA, SOC 2, HIPAA

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Secure Logging Best Practices](#secure-logging-best-practices)
3. [Implementation Guide](#implementation-guide)
4. [Pattern Catalog](#pattern-catalog)
5. [Audit and Compliance](#audit-and-compliance)
6. [Incident Response](#incident-response)
7. [Developer Guidelines](#developer-guidelines)
8. [Examples and Templates](#examples-and-templates)
9. [References](#references)

---

## Executive Summary

### What is CWE-532?

**CWE-532: Insertion of Sensitive Information into Log File** is a critical security vulnerability where applications inadvertently write sensitive data to log files. This exposes confidential information to unauthorized parties who gain access to log files.

**Real-World Impact**:
- **Data Breaches**: Exposed API keys, passwords, tokens
- **Regulatory Violations**: GDPR fines up to €20M or 4% of annual revenue
- **Compliance Failures**: SOC 2, HIPAA, PCI-DSS audit failures
- **Reputational Damage**: Loss of customer trust

### Why Logging Security Matters

1. **Regulatory Compliance**:
   - **GDPR Article 5(1)(f)**: Data must be processed securely
   - **CCPA Section 1798.100**: Right to know what personal information is collected
   - **HIPAA Security Rule**: Protected Health Information (PHI) must be safeguarded
   - **SOC 2 CC6.1**: Logical and physical access controls

2. **Security Impact**:
   - Log files often have weaker access controls than production databases
   - Logs are retained longer than necessary, increasing exposure window
   - Logs are copied to multiple systems (log aggregation, monitoring, backups)
   - Attackers specifically target log files as they contain rich information

3. **Business Risk**:
   - Average data breach cost: **$4.45M** (IBM 2023)
   - GDPR fines: Up to **€20M or 4% of annual revenue**
   - Legal liability for negligence
   - Customer churn after breach

### Quick Reference: Do's and Don'ts

| ✅ **DO** | ❌ **DON'T** |
|----------|-------------|
| Log masked user IDs (`user_***7890`) | Log raw user IDs (`user_1234567890`) |
| Log masked emails (`j***@example.com`) | Log full emails (`john@example.com`) |
| Log error types (`AuthenticationError`) | Log error messages with secrets |
| Log operation IDs, trace IDs | Log session IDs, JWTs |
| Log masked API endpoints (`POST /api/users/***`) | Log full URLs with parameters |
| Use `safe_log_error()` in production | Use `exc_info=True` in production |
| Log performance metrics | Log database connection strings |
| Log success/failure status | Log credit card numbers, SSNs |
| Configure log rotation (7-30 days) | Keep logs indefinitely |
| Use structured logging (JSON) | Use unstructured string concatenation |

### Severity Classification

| Severity | Examples | Response Time | Action |
|----------|----------|---------------|--------|
| **CRITICAL** | Passwords, API keys, private keys, credit cards | **Immediate** | Emergency log rotation, incident response |
| **HIGH** | Session tokens, JWT, OAuth tokens, database credentials | **< 4 hours** | Log rotation, security review |
| **MEDIUM** | User IDs, email addresses, IP addresses (PII) | **< 24 hours** | Apply masking, update code |
| **LOW** | Internal paths, debug information | **Next sprint** | Code cleanup |

---

## Secure Logging Best Practices

### What to Log (Safe Information)

#### 1. Operational Metadata
```python
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# ✅ GOOD: Operational context
logger.info(
    "Operation completed",
    extra={
        "operation_id": "op_abc123",
        "trace_id": "trace_xyz789",
        "timestamp": datetime.utcnow().isoformat(),
        "duration_ms": 145,
        "status": "success"
    }
)
```

#### 2. Masked Identifiers
```python
from shared.utils.secure_logging import mask_user_id, mask_email

# ✅ GOOD: Masked user identification
logger.info(f"User {mask_user_id('user_1234567890')} performed action")
# Output: "User user_***7890 performed action"

# ✅ GOOD: Masked email
logger.info(f"Password reset sent to {mask_email('john@example.com')}")
# Output: "Password reset sent to j***@example.com"
```

#### 3. Error Types (Not Messages)
```python
# ✅ GOOD: Log error type
try:
    authenticate_user(username, password)
except AuthenticationError as e:
    logger.error(f"Authentication failed: {e.__class__.__name__}")
    # Output: "Authentication failed: AuthenticationError"

# ❌ BAD: Log error message (may contain secrets)
except AuthenticationError as e:
    logger.error(f"Authentication failed: {str(e)}")
    # Output: "Authentication failed: Invalid API key 'sk_live_abc123...'"
```

#### 4. Performance Metrics
```python
# ✅ GOOD: Performance tracking
logger.info(
    "Database query completed",
    extra={
        "query_type": "SELECT",
        "duration_ms": 42,
        "rows_returned": 150,
        "cache_hit": False
    }
)
```

#### 5. Business Events
```python
# ✅ GOOD: High-level business events
logger.info(
    "Order created",
    extra={
        "order_id": "ORD-12345",
        "masked_user": mask_user_id(user_id),
        "item_count": 3,
        "total_amount_cents": 4999  # Store in smallest unit
    }
)
```

### What NOT to Log (Sensitive Information)

#### 1. Authentication Credentials
```python
# ❌ CRITICAL: Never log passwords
logger.debug(f"Login attempt: {username} / {password}")

# ❌ CRITICAL: Never log API keys
logger.info(f"API request with key: {api_key}")

# ❌ CRITICAL: Never log private keys
logger.debug(f"Signing with key: {private_key}")

# ✅ GOOD: Log only operation result
logger.info(f"Login attempt for user {mask_user_id(user_id)}: success")
logger.info(f"API request authenticated: success")
logger.info(f"Document signed: success")
```

#### 2. Session Management
```python
# ❌ HIGH: Never log session IDs
logger.debug(f"Session ID: {session_id}")

# ❌ HIGH: Never log JWT tokens
logger.info(f"JWT token: {jwt_token}")

# ❌ HIGH: Never log OAuth tokens
logger.debug(f"OAuth access token: {access_token}")

# ✅ GOOD: Log session events only
logger.info(f"Session created for user {mask_user_id(user_id)}")
logger.info(f"Token refreshed for user {mask_user_id(user_id)}")
```

#### 3. Personally Identifiable Information (PII)
```python
# ❌ MEDIUM: Never log raw user IDs
logger.info(f"User {user_id} logged in")

# ❌ MEDIUM: Never log full email addresses
logger.info(f"Email sent to {user_email}")

# ❌ MEDIUM: Never log full names
logger.info(f"Profile updated for {first_name} {last_name}")

# ❌ MEDIUM: Never log phone numbers
logger.info(f"SMS sent to {phone_number}")

# ✅ GOOD: Use masking utilities
from shared.utils.secure_logging import mask_user_id, mask_email, mask_phone

logger.info(f"User {mask_user_id(user_id)} logged in")
logger.info(f"Email sent to {mask_email(user_email)}")
logger.info(f"SMS sent to {mask_phone(phone_number)}")
```

#### 4. Financial Information
```python
# ❌ CRITICAL: Never log credit card numbers
logger.debug(f"Payment with card: {credit_card_number}")

# ❌ CRITICAL: Never log CVV codes
logger.debug(f"CVV: {cvv}")

# ❌ MEDIUM: Never log full bank account numbers
logger.info(f"Transfer to account: {account_number}")

# ✅ GOOD: Log masked financial data
from shared.utils.secure_logging import mask_credit_card

logger.info(f"Payment processed with card {mask_credit_card(card_number)}")
# Output: "Payment processed with card ****-****-****-1234"
```

#### 5. System Secrets
```python
# ❌ CRITICAL: Never log database connection strings
logger.debug(f"Connecting to: {database_url}")
# Output: "Connecting to: postgresql://admin:secret123@db.example.com/prod"

# ❌ CRITICAL: Never log environment variables wholesale
logger.debug(f"Environment: {os.environ}")

# ❌ HIGH: Never log encryption keys
logger.debug(f"Encrypting with key: {encryption_key}")

# ✅ GOOD: Log operation without secrets
logger.info("Database connection established")
logger.info("Configuration loaded from environment")
logger.info("Data encrypted successfully")
```

#### 6. Stack Traces in Production
```python
# ❌ HIGH: Stack traces expose system internals
try:
    risky_operation()
except Exception as e:
    logger.error("Operation failed", exc_info=True)
    # Exposes: file paths, function names, library versions

# ✅ GOOD: Use safe error logging
from shared.utils.secure_logging import safe_log_error

try:
    risky_operation()
except Exception as e:
    safe_log_error(logger, "Operation failed", exception=e)
    # In production: Only logs error type and safe message
    # In development: Logs full stack trace for debugging
```

### Masking Strategies

#### 1. Partial Masking (Preserve Utility)
```python
# Show first and last characters, mask middle
def mask_user_id(user_id: str) -> str:
    """
    Masks user ID: user_1234567890 → user_***7890
    """
    if len(user_id) <= 8:
        return "***"
    return f"{user_id[:4]}***{user_id[-4:]}"

# Show domain, mask local part
def mask_email(email: str) -> str:
    """
    Masks email: john.doe@example.com → j***@example.com
    """
    parts = email.split("@")
    if len(parts) != 2:
        return "***@***"
    local = parts[0]
    domain = parts[1]
    if len(local) <= 2:
        masked_local = "*" * len(local)
    else:
        masked_local = f"{local[0]}***"
    return f"{masked_local}@{domain}"
```

#### 2. Complete Redaction (High Sensitivity)
```python
# Replace entirely with fixed string
def mask_password(password: str) -> str:
    """
    Completely redacts password: secret123 → [REDACTED]
    """
    return "[REDACTED]"

def mask_api_key(api_key: str) -> str:
    """
    Redacts API key: sk_live_abc123... → [API_KEY_REDACTED]
    """
    return "[API_KEY_REDACTED]"
```

#### 3. Hash-Based Masking (Consistency Required)
```python
import hashlib

def hash_identifier(identifier: str, salt: str = "trinitas_log_salt") -> str:
    """
    Hash-based masking for consistent pseudonymization.
    Same input always produces same output (within session).

    Use case: Tracking same user across log entries without revealing identity.
    """
    return hashlib.sha256(f"{salt}{identifier}".encode()).hexdigest()[:8]

# ✅ GOOD: Consistent pseudonym
user_hash = hash_identifier(user_id)
logger.info(f"User {user_hash} logged in")
logger.info(f"User {user_hash} viewed dashboard")
logger.info(f"User {user_hash} logged out")
# All three entries use same hash, enabling analysis without PII
```

#### 4. Truncation (Fixed Length)
```python
def truncate_token(token: str, visible_chars: int = 4) -> str:
    """
    Shows only first N characters: sk_live_abc123... → sk_l...
    """
    if len(token) <= visible_chars:
        return "***"
    return f"{token[:visible_chars]}..."
```

### Environment-Aware Logging

```python
import os
from shared.utils.secure_logging import safe_log_error

# Detect environment
ENV = os.getenv("ENVIRONMENT", "production").lower()
IS_PRODUCTION = ENV == "production"

# Development: Full stack traces for debugging
if not IS_PRODUCTION:
    logger.setLevel(logging.DEBUG)
    logger.error("Operation failed", exc_info=True)

# Production: Minimal information
else:
    logger.setLevel(logging.INFO)
    safe_log_error(logger, "Operation failed", exception=e)
```

### Log Levels and Sensitivity

| Log Level | Use Case | Sensitive Data Allowed? |
|-----------|----------|------------------------|
| **CRITICAL** | System failures, security incidents | ❌ Never |
| **ERROR** | Operation failures, exceptions | ❌ Never (use safe_log_error) |
| **WARNING** | Potential issues, deprecations | ❌ Never |
| **INFO** | Normal operations, business events | ⚠️ Only masked PII |
| **DEBUG** | Detailed debugging (dev only) | ⚠️ Only in non-production |

**Rule**: If you're unsure whether data is sensitive, **assume it is** and apply masking.

---

## Implementation Guide

### Step 1: Install Secure Logging Utilities

The Trinitas project provides `shared/utils/secure_logging.py` with all necessary utilities:

```bash
# Utilities are already available in the project
ls shared/utils/secure_logging.py
```

### Step 2: Import and Use in Your Code

```python
import logging
from shared.utils.secure_logging import (
    mask_user_id,
    mask_email,
    mask_phone,
    mask_credit_card,
    mask_ssn,
    mask_api_key,
    mask_url_params,
    safe_log_error,
    SecureLogger  # Wrapper class
)

logger = logging.getLogger(__name__)

# Example: User authentication
def authenticate_user(username: str, password: str):
    """
    Authenticate user with secure logging.
    """
    try:
        # ❌ NEVER log password
        # logger.debug(f"Authenticating: {username} / {password}")

        # ✅ GOOD: Log only masked username
        logger.info(f"Authentication attempt for user {mask_email(username)}")

        # Perform authentication logic
        user = User.authenticate(username, password)

        # ✅ GOOD: Log success with masked ID
        logger.info(f"Authentication successful for user {mask_user_id(user.id)}")

        return user

    except AuthenticationError as e:
        # ✅ GOOD: Use safe error logging
        safe_log_error(logger, "Authentication failed", exception=e)
        raise
```

### Step 3: Configure Logging

#### Python Logging Configuration (`logging_config.yaml`)

```yaml
version: 1
disable_existing_loggers: false

formatters:
  json:
    (): pythonjsonlogger.jsonlogger.JsonFormatter
    format: "%(asctime)s %(name)s %(levelname)s %(message)s"

  simple:
    format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

handlers:
  console:
    class: logging.StreamHandler
    level: INFO
    formatter: simple
    stream: ext://sys.stdout

  file:
    class: logging.handlers.RotatingFileHandler
    level: INFO
    formatter: json
    filename: logs/trinitas.log
    maxBytes: 10485760  # 10MB
    backupCount: 5
    encoding: utf8

  security:
    class: logging.handlers.RotatingFileHandler
    level: WARNING
    formatter: json
    filename: logs/security.log
    maxBytes: 10485760
    backupCount: 10  # Keep security logs longer
    encoding: utf8

loggers:
  shared.utils.secure_logging:
    level: INFO
    handlers: [console, file, security]
    propagate: false

  src.security:
    level: INFO
    handlers: [console, file, security]
    propagate: false

root:
  level: INFO
  handlers: [console, file]
```

#### Environment Variables

```bash
# .env.example
ENVIRONMENT=production  # production, staging, development
LOG_LEVEL=INFO
LOG_FILE_PATH=logs/trinitas.log
LOG_ROTATION_DAYS=30
LOG_MAX_SIZE_MB=10

# Security-specific settings
SECURITY_LOG_PATH=logs/security.log
AUDIT_LOG_PATH=logs/audit.log
ENABLE_SENSITIVE_DATA_DETECTION=true
```

### Step 4: Use SecureLogger Wrapper (Recommended)

For critical security operations, use the `SecureLogger` wrapper:

```python
from shared.utils.secure_logging import SecureLogger

logger = SecureLogger(__name__)

# Automatic PII masking
logger.info_masked("User logged in", user_id="user_1234567890", email="john@example.com")
# Output: "User logged in | user_id=user_***7890 | email=j***@example.com"

# Automatic sensitive data detection
logger.warning("Database connection failed", connection_string="postgresql://admin:secret@db.example.com")
# Output: "Database connection failed | connection_string=[REDACTED]"

# Safe error logging with automatic environment detection
try:
    risky_operation()
except Exception as e:
    logger.error_safe("Operation failed", exception=e)
    # Production: Only error type
    # Development: Full stack trace
```

### Step 5: Log Rotation and Retention

#### Automated Log Rotation (Linux/macOS)

```bash
# /etc/logrotate.d/trinitas
/var/log/trinitas/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 trinitas trinitas
    sharedscripts
    postrotate
        systemctl reload trinitas-service
    endscript
}

# Security logs: longer retention
/var/log/trinitas/security.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0600 trinitas trinitas
}
```

#### Manual Log Rotation (Python)

```python
import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

# Size-based rotation
handler = RotatingFileHandler(
    "logs/trinitas.log",
    maxBytes=10 * 1024 * 1024,  # 10MB
    backupCount=5,
    encoding="utf8"
)

# Time-based rotation
handler = TimedRotatingFileHandler(
    "logs/trinitas.log",
    when="midnight",
    interval=1,
    backupCount=30,  # Keep 30 days
    encoding="utf8"
)

logger.addHandler(handler)
```

### Step 6: Testing Your Implementation

```python
import unittest
from shared.utils.secure_logging import mask_user_id, mask_email, detect_sensitive_data

class TestSecureLogging(unittest.TestCase):

    def test_user_id_masking(self):
        """Test user ID masking preserves format."""
        masked = mask_user_id("user_1234567890")
        self.assertEqual(masked, "user_***7890")
        self.assertIn("***", masked)

    def test_email_masking(self):
        """Test email masking preserves domain."""
        masked = mask_email("john.doe@example.com")
        self.assertTrue(masked.endswith("@example.com"))
        self.assertIn("***", masked)

    def test_sensitive_data_detection(self):
        """Test detection of sensitive patterns."""
        text = "API key: sk_live_abc123... | User ID: user_1234567890"
        has_sensitive, patterns = detect_sensitive_data(text)
        self.assertTrue(has_sensitive)
        self.assertIn("API key", [p['type'] for p in patterns])

if __name__ == "__main__":
    unittest.main()
```

---

## Pattern Catalog

This section documents all sensitive data patterns detected by the Trinitas logging security system.

### Basic Sensitive Patterns

#### 1. Password-Related
```python
PATTERNS = [
    r"password['\"]?\s*[:=]\s*['\"]?([^'\"\s]+)",
    r"pwd['\"]?\s*[:=]\s*['\"]?([^'\"\s]+)",
    r"passwd['\"]?\s*[:=]\s*['\"]?([^'\"\s]+)",
]

# Examples detected:
# ❌ "password": "secret123"
# ❌ pwd="my_password"
# ❌ passwd: hunter2
```

**Why**: Passwords are the most common authentication credentials. Even development/test passwords should never be logged.

#### 2. API Keys
```python
PATTERNS = [
    r"api[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
    r"apikey['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
    r"api[_-]?token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
]

# Examples detected:
# ❌ api_key: sk_live_abc123def456...
# ❌ "apiKey": "AIzaSyC-abc123..."
# ❌ api-token=ghp_abc123def456...
```

**Why**: API keys provide programmatic access. Exposure allows unauthorized access to services.

#### 3. Secret Keys / Tokens
```python
PATTERNS = [
    r"secret[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
    r"auth[_-]?token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
    r"access[_-]?token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
]

# Examples detected:
# ❌ secret_key: "django-insecure-abc123..."
# ❌ auth_token: "eyJhbGciOiJIUzI1NiIs..."
# ❌ access-token=Bearer abc123def456
```

**Why**: Secret keys are used for encryption, signing, and authentication. Exposure compromises system security.

#### 4. Database Credentials
```python
PATTERNS = [
    r"db[_-]?password['\"]?\s*[:=]\s*['\"]?([^'\"\s]+)",
    r"database[_-]?password['\"]?\s*[:=]\s*['\"]?([^'\"\s]+)",
    r"db[_-]?user['\"]?\s*[:=]\s*['\"]?([^'\"\s]+)",
]

# Examples detected:
# ❌ db_password: "super_secret_db_pass"
# ❌ database-password="P@ssw0rd123"
# ❌ db_user: "admin"
```

**Why**: Database credentials grant access to all application data. Must never be logged.

#### 5. JWT Tokens
```python
PATTERNS = [
    r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",  # JWT format
]

# Examples detected:
# ❌ eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123
```

**Why**: JWT tokens contain user session data and authorization claims. Exposure allows session hijacking.

#### 6. Private Keys
```python
PATTERNS = [
    r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
    r"-----BEGIN OPENSSH PRIVATE KEY-----",
    r"private[_-]?key['\"]?\s*[:=]",
]

# Examples detected:
# ❌ -----BEGIN RSA PRIVATE KEY-----
# ❌ private_key: "-----BEGIN OPENSSH PRIVATE KEY-----"
```

**Why**: Private keys are used for encryption and digital signatures. Exposure allows impersonation.

### Advanced Sensitive Patterns

#### 7. Credit Card Numbers
```python
PATTERN = r"\b(?:\d{4}[-\s]?){3}\d{4}\b"

# Examples detected:
# ❌ 4532-1234-5678-9010
# ❌ 4532 1234 5678 9010
# ❌ 4532123456789010
```

**Why**: PCI-DSS strictly prohibits logging credit card numbers. Violations result in severe penalties.

**False Positives**: Timestamps, phone numbers, order IDs
**Mitigation**: Use `mask_credit_card()` which validates Luhn algorithm

#### 8. Social Security Numbers (SSN)
```python
PATTERN = r"\b\d{3}-\d{2}-\d{4}\b"

# Examples detected:
# ❌ 123-45-6789
```

**Why**: SSNs are protected under GLBA, CCPA, and state privacy laws. Exposure causes identity theft risk.

**False Positives**: Date ranges (e.g., 123-45-6789 looks like SSN)
**Mitigation**: Use `mask_ssn()` with strict validation

#### 9. Email Addresses (PII)
```python
PATTERN = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"

# Examples detected:
# ❌ john.doe@example.com
# ❌ user+test@gmail.com
```

**Why**: GDPR Article 4(1) defines email as PII. Must be masked unless explicit consent.

**False Positives**: Rare
**Mitigation**: Use `mask_email()` to preserve domain

#### 10. Phone Numbers
```python
PATTERN = r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"

# Examples detected:
# ❌ +1 (555) 123-4567
# ❌ 555-123-4567
# ❌ 5551234567
```

**Why**: Phone numbers are PII under GDPR, CCPA. Telemarketing regulations also apply.

**False Positives**: Employee IDs, product codes
**Mitigation**: Use `mask_phone()` with format validation

#### 11. IP Addresses (Context-Dependent)
```python
PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

# Examples detected:
# ❌ 192.168.1.100 (internal IP)
# ❌ 203.0.113.45 (external IP)
```

**Why**: GDPR considers IP addresses as PII. CCPA also includes IP in personal information.

**Context Matters**:
- **Internal IPs** (10.x.x.x, 192.168.x.x, 172.16-31.x.x): Lower risk
- **External IPs**: High risk (user tracking)

**Mitigation**: Mask last octet (`192.168.1.***`)

#### 12. URLs with Sensitive Parameters
```python
PATTERNS = [
    r"[\?&](token|key|secret|password|auth|session)=([^&\s]+)",
    r"https?://[^\s]*[\?&](api[_-]?key|access[_-]?token)=([^&\s]+)",
]

# Examples detected:
# ❌ https://api.example.com/data?api_key=abc123
# ❌ https://example.com/reset?token=xyz789
```

**Why**: URLs are often logged by proxies, web servers, and monitoring tools. Sensitive parameters expose credentials.

**Mitigation**: Use `mask_url_params()` to redact query parameters

#### 13. Database Connection Strings
```python
PATTERN = r"(?:postgresql|mysql|mongodb|redis)://(?:[^:]+):([^@]+)@"

# Examples detected:
# ❌ postgresql://admin:secret123@db.example.com:5432/prod
# ❌ mysql://root:password@localhost:3306/mydb
# ❌ mongodb://user:pass@cluster.mongodb.net/database
```

**Why**: Connection strings contain credentials and reveal infrastructure.

**Mitigation**: Log only protocol and host: `postgresql://db.example.com`

#### 14. AWS/Cloud Credentials
```python
PATTERNS = [
    r"AKIA[0-9A-Z]{16}",  # AWS Access Key ID
    r"aws_secret_access_key\s*[:=]\s*([A-Za-z0-9/+=]{40})",
]

# Examples detected:
# ❌ AKIAIOSFODNN7EXAMPLE
# ❌ aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Why**: AWS credentials grant full access to cloud resources. Exposure can result in massive financial loss.

#### 15. Session IDs
```python
PATTERN = r"session[_-]?id['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})"

# Examples detected:
# ❌ session_id: "abc123def456ghi789jkl012"
# ❌ sessionId=xyz789abc123def456
```

**Why**: Session IDs allow session hijacking. Never log full session IDs.

**Mitigation**: Hash or truncate: `session_***456`

### Pattern Detection Configuration

```python
# shared/utils/secure_logging.py

SENSITIVE_PATTERNS = {
    "password": [
        r"password['\"]?\s*[:=]\s*['\"]?([^'\"\s]+)",
        r"pwd['\"]?\s*[:=]\s*['\"]?([^'\"\s]+)",
    ],
    "api_key": [
        r"api[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
    ],
    "secret_key": [
        r"secret[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
    ],
    "jwt": [
        r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
    ],
    "database_credential": [
        r"(?:postgresql|mysql|mongodb)://(?:[^:]+):([^@]+)@",
    ],
    "aws_key": [
        r"AKIA[0-9A-Z]{16}",
    ],
}

ADVANCED_SENSITIVE_PATTERNS = {
    "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}

# Usage
from shared.utils.secure_logging import detect_sensitive_data

text = "User login: john@example.com with password secret123"
has_sensitive, patterns_found = detect_sensitive_data(text)

if has_sensitive:
    for pattern in patterns_found:
        print(f"Found {pattern['type']}: {pattern['match']}")
```

### Custom Pattern Addition

```python
from shared.utils.secure_logging import SecureLogger

# Add project-specific sensitive patterns
custom_patterns = {
    "internal_id": r"INT_[A-Z0-9]{10}",
    "vendor_key": r"VENDOR_KEY_[a-zA-Z0-9]{32}",
}

logger = SecureLogger(__name__, custom_patterns=custom_patterns)
```

---

## Audit and Compliance

### Pre-Commit Hook Setup

Install the pre-commit hook to automatically scan for sensitive data before commits:

```bash
# Install pre-commit hook
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Test the hook
git add logs/test.log
git commit -m "Test commit"
# Hook will scan for sensitive patterns and block if found
```

**Pre-Commit Hook** (`.git/hooks/pre-commit`):
```bash
#!/bin/bash
# Trinitas Logging Security Pre-Commit Hook

echo "🔍 Scanning for sensitive data in logs..."

# Run the log auditor on staged files
python3 shared/utils/log_auditor.py --staged

if [ $? -ne 0 ]; then
    echo "❌ Sensitive data detected in log files!"
    echo "   Please review findings and remove sensitive data before committing."
    echo "   Run: python3 shared/utils/log_auditor.py --verbose for details"
    exit 1
fi

echo "✅ No sensitive data detected"
exit 0
```

### Running Log Auditor

```bash
# Scan all log files
python3 shared/utils/log_auditor.py --directory logs/

# Scan specific file
python3 shared/utils/log_auditor.py --file logs/trinitas.log

# Verbose output with line numbers
python3 shared/utils/log_auditor.py --directory logs/ --verbose

# Generate audit report
python3 shared/utils/log_auditor.py --directory logs/ --report audit_report.json

# Scan for specific pattern types only
python3 shared/utils/log_auditor.py --directory logs/ --patterns password,api_key,jwt
```

**Example Output**:
```
🔍 Trinitas Log Auditor v1.0.0
================================

Scanning: logs/

📄 logs/trinitas.log
  ⚠️  Line 42: [password] Potential password found
  ⚠️  Line 156: [api_key] API key detected
  ⚠️  Line 289: [email] Email address (PII) found

📄 logs/security.log
  ✅ No sensitive data detected

================================
Summary:
  Files scanned: 2
  Sensitive patterns found: 3
  Critical: 2 (password, api_key)
  Medium: 1 (email)

❌ AUDIT FAILED
   Please review findings and remediate before deployment.
```

### Periodic Audit Schedule

**Recommended Schedule**:

| Frequency | Scope | Responsible Team | Action |
|-----------|-------|-----------------|--------|
| **Daily** | New commits | CI/CD Pipeline | Automated scan on commit |
| **Weekly** | Active logs | DevOps | Manual review of flagged items |
| **Monthly** | All log archives | Security Team | Full audit + report |
| **Quarterly** | Complete system | Compliance Officer | Compliance audit + certification |

**Automated Audits with CI/CD**:
```yaml
# .github/workflows/log-security-audit.yml
name: Log Security Audit

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt

      - name: Run log auditor
        run: |
          python3 shared/utils/log_auditor.py --directory logs/ --report audit_report.json

      - name: Upload audit report
        uses: actions/upload-artifact@v3
        with:
          name: audit-report
          path: audit_report.json

      - name: Fail on critical findings
        run: |
          if grep -q '"critical": true' audit_report.json; then
            echo "❌ Critical sensitive data detected!"
            exit 1
          fi
```

### Compliance Checklist

#### GDPR Compliance (EU General Data Protection Regulation)

- [ ] **Article 5(1)(f)**: Personal data processed securely
  - [ ] All PII (email, phone, IP) is masked in logs
  - [ ] Log access restricted to authorized personnel only
  - [ ] Log retention period does not exceed business need (max 30 days)

- [ ] **Article 17**: Right to erasure ("right to be forgotten")
  - [ ] User-specific logs can be deleted upon request
  - [ ] Procedure documented for log deletion requests

- [ ] **Article 25**: Data protection by design and by default
  - [ ] Logging system designed with PII masking from inception
  - [ ] Default configuration masks all PII

- [ ] **Article 32**: Security of processing
  - [ ] Log files encrypted at rest
  - [ ] Secure transmission (TLS) to log aggregation services
  - [ ] Access logs maintained (who accessed what log when)

- [ ] **Article 33**: Breach notification (72 hours)
  - [ ] Log breach detection mechanisms in place
  - [ ] Incident response plan includes log exposure scenarios

#### CCPA Compliance (California Consumer Privacy Act)

- [ ] **Section 1798.100**: Right to know
  - [ ] Consumers can request disclosure of logged personal information
  - [ ] Process documented for fulfilling disclosure requests

- [ ] **Section 1798.105**: Right to deletion
  - [ ] Consumers can request deletion of logged personal information
  - [ ] Deletion verified and confirmed to consumer

- [ ] **Section 1798.110**: Categories of personal information
  - [ ] Documented: What personal information is logged (email, IP, phone)
  - [ ] Documented: Purpose of logging (security, debugging, analytics)

- [ ] **Section 1798.150**: Private right of action (data breaches)
  - [ ] Reasonable security measures in place (encryption, access control)
  - [ ] Breach notification procedures defined

#### SOC 2 Compliance (Service Organization Control)

- [ ] **CC6.1**: Logical and physical access controls
  - [ ] Log files access restricted to authorized roles
  - [ ] Multi-factor authentication (MFA) for log access
  - [ ] Audit trail of log access maintained

- [ ] **CC6.6**: Logical access security measures
  - [ ] Passwords, API keys, tokens never logged
  - [ ] Encryption keys never logged
  - [ ] Session IDs masked or hashed

- [ ] **CC6.7**: Removal/adjustment of access rights
  - [ ] Employee offboarding includes log access revocation
  - [ ] Periodic access review (quarterly)

- [ ] **CC7.2**: Detection of security events
  - [ ] Automated scanning for sensitive data in logs
  - [ ] Alerts configured for critical findings

#### HIPAA Compliance (Health Insurance Portability and Accountability Act)

*Applies if Trinitas processes Protected Health Information (PHI)*

- [ ] **§ 164.312(a)(1)**: Access control
  - [ ] Log files containing PHI access restricted
  - [ ] Unique user identification for log access

- [ ] **§ 164.312(b)**: Audit controls
  - [ ] Audit logs capture who accessed PHI logs when
  - [ ] Audit logs retained for 6 years (HIPAA requirement)

- [ ] **§ 164.312(c)(1)**: Integrity controls
  - [ ] Log files protected from unauthorized alteration
  - [ ] Log integrity verification (e.g., digital signatures)

- [ ] **§ 164.312(e)(1)**: Transmission security
  - [ ] PHI logs transmitted using TLS/SSL
  - [ ] End-to-end encryption for log aggregation

- [ ] **§ 164.312(d)**: Person or entity authentication
  - [ ] MFA required for PHI log access
  - [ ] Strong password policies enforced

### Audit Report Template

```json
{
  "audit_metadata": {
    "audit_date": "2025-11-07T14:30:00Z",
    "auditor": "Muses (Knowledge Architect)",
    "scope": "logs/ directory",
    "trinitas_version": "v2.3.0"
  },
  "findings": {
    "total_files_scanned": 45,
    "files_with_sensitive_data": 3,
    "total_sensitive_patterns": 12,
    "breakdown": {
      "critical": 5,
      "high": 4,
      "medium": 3
    }
  },
  "critical_findings": [
    {
      "file": "logs/trinitas.log",
      "line": 42,
      "pattern_type": "password",
      "matched_text": "password=secret123",
      "severity": "CRITICAL",
      "recommendation": "Remove password from log. Use mask_password()."
    }
  ],
  "compliance_status": {
    "gdpr": "NON-COMPLIANT",
    "ccpa": "NON-COMPLIANT",
    "soc2": "COMPLIANT",
    "hipaa": "N/A"
  },
  "recommendations": [
    "Immediate remediation required for 5 critical findings",
    "Implement pre-commit hook to prevent future violations",
    "Conduct quarterly audits as per policy"
  ],
  "next_audit_due": "2026-02-07"
}
```

---

## Incident Response

### When Sensitive Data is Found in Logs

**Step 1: Assess Severity (0-5 minutes)**

| Severity | Data Type | Example | Response Time |
|----------|-----------|---------|---------------|
| **CRITICAL** | Passwords, private keys, credit cards | `password=secret123` | **Immediate** |
| **HIGH** | API keys, session tokens, AWS credentials | `api_key=sk_live_abc123` | **< 4 hours** |
| **MEDIUM** | User IDs, emails, phone numbers (PII) | `user_id=user_1234567890` | **< 24 hours** |
| **LOW** | Internal paths, debug info | `/home/admin/secrets/` | **Next sprint** |

**Step 2: Contain the Exposure (Immediate)**

```bash
# CRITICAL: Immediate log rotation and archival
sudo systemctl stop trinitas-service

# Rotate logs NOW (before attacker can access)
mv /var/log/trinitas/trinitas.log /var/log/trinitas/trinitas.log.INCIDENT_$(date +%Y%m%d_%H%M%S)

# Secure the archived log (restrict permissions)
chmod 600 /var/log/trinitas/trinitas.log.INCIDENT_*

# Restart service with new log file
sudo systemctl start trinitas-service
```

**Step 3: Revoke Compromised Credentials (< 1 hour)**

If passwords, API keys, or tokens were logged:

```bash
# Passwords: Force password reset
python3 scripts/force_password_reset.py --user-id <user_id>

# API Keys: Rotate keys immediately
python3 scripts/rotate_api_keys.py --key-id <key_id>

# Session Tokens: Invalidate all sessions
python3 scripts/invalidate_sessions.py --all

# AWS Credentials: Rotate via AWS CLI
aws iam delete-access-key --access-key-id AKIA...
aws iam create-access-key --user-name trinitas-service
```

**Step 4: Determine Blast Radius (< 2 hours)**

```bash
# Who accessed the log file?
sudo ausearch -f /var/log/trinitas/trinitas.log -ts recent

# Was the log copied or transmitted?
sudo grep "trinitas.log" /var/log/syslog
sudo grep "trinitas.log" /var/log/auth.log

# Check log aggregation services (Splunk, ELK, Datadog)
# Did sensitive data reach external systems?
```

**Step 5: Notification (< 72 hours for GDPR)**

**Internal Notification**:
```
TO: Security Team, Legal, Compliance Officer
SUBJECT: [URGENT] Sensitive Data in Application Logs

INCIDENT ID: INC-20251107-001
SEVERITY: CRITICAL
DISCOVERED: 2025-11-07 14:30 UTC
DATA TYPE: Passwords, API keys
EXPOSURE: Application logs (logs/trinitas.log)
BLAST RADIUS: 3 users, 2 API keys
CONTAINMENT: Logs rotated, credentials revoked

ACTION REQUIRED:
1. Review incident report (attached)
2. Legal: Assess notification obligations (GDPR, CCPA)
3. PR: Prepare external communication (if required)

CONTACT: security@trinitas.ai
```

**External Notification (if required by GDPR/CCPA)**:

*GDPR requires notification within 72 hours if breach affects user rights*

```
TO: Affected Users
SUBJECT: Security Incident Notification

Dear [User],

We are writing to inform you of a security incident affecting your Trinitas account.

WHAT HAPPENED:
On November 7, 2025, our monitoring systems detected that certain application logs inadvertently contained user authentication data (passwords, API keys). This was due to a logging configuration error.

WHAT DATA WAS INVOLVED:
- Your user ID
- Your API key (now revoked)
- Your last login timestamp

NO OTHER DATA (credit cards, SSN, personal messages) was affected.

WHAT WE HAVE DONE:
1. Immediately rotated all affected logs
2. Revoked and re-issued your API key
3. Implemented automated scanning to prevent recurrence
4. Notified relevant authorities (as required by GDPR)

WHAT YOU SHOULD DO:
1. Reset your password: https://trinitas.ai/reset-password
2. Update your API key in your applications (new key emailed separately)
3. Monitor your account for suspicious activity

We sincerely apologize for this incident and are taking extensive measures to prevent future occurrences.

For questions, contact: privacy@trinitas.ai

Sincerely,
Trinitas Security Team
```

**Step 6: Root Cause Analysis (< 7 days)**

```markdown
# Incident Postmortem: INC-20251107-001

## Summary
Passwords and API keys were inadvertently logged to `logs/trinitas.log` due to missing PII masking in authentication module.

## Timeline
- **14:00 UTC**: Automated log auditor flagged sensitive patterns
- **14:15 UTC**: Security team confirmed CRITICAL severity
- **14:30 UTC**: Logs rotated, service restarted
- **15:00 UTC**: Credentials revoked, users notified
- **16:00 UTC**: Legal/compliance review initiated

## Root Cause
Developer used `logger.debug(f"Auth attempt: {username} / {password}")` in commit `abc123` (2025-11-05). This code bypassed code review due to emergency hotfix process.

## Contributing Factors
1. Emergency hotfix bypassed normal code review
2. Pre-commit hook not enforced on `hotfix/*` branches
3. No automated test for logging security

## Impact
- **Users Affected**: 3
- **Credentials Exposed**: 2 API keys, 3 passwords
- **Exposure Duration**: 48 hours (log retention)
- **External Disclosure**: No (logs not transmitted to external systems)

## Remediation
- [x] Credentials rotated (completed 2025-11-07 15:00)
- [x] Affected users notified (completed 2025-11-07 15:30)
- [x] Code fixed (commit `def456`)
- [x] Pre-commit hook enforced on all branches
- [ ] Security training for development team (scheduled 2025-11-14)

## Prevention
1. **Immediate**:
   - Enforce pre-commit hook on all branches (no exceptions)
   - Add test case: `test_no_passwords_in_logs()`

2. **Short-term** (< 1 month):
   - Mandatory security training for all developers
   - Update emergency hotfix process (require security review)

3. **Long-term** (< 3 months):
   - Implement automated log scanning in CI/CD
   - Periodic penetration testing of logging system

## Lessons Learned
1. Emergency hotfixes need security review (no shortcuts)
2. Pre-commit hooks must be enforced organization-wide
3. Automated testing is critical (manual review is fallible)
```

### Log Purging Procedure

**When**: After incident response, or as part of normal retention policy

```bash
# Step 1: Archive sensitive logs securely
# Encrypt with strong password
tar -czf logs_incident_20251107.tar.gz logs/trinitas.log.INCIDENT_*
gpg --symmetric --cipher-algo AES256 logs_incident_20251107.tar.gz

# Move encrypted archive to secure storage
mv logs_incident_20251107.tar.gz.gpg /secure/archives/

# Step 2: Securely delete original logs
# Use shred (Linux) or srm (macOS) to overwrite data
shred -vfz -n 7 logs/trinitas.log.INCIDENT_*
# OR on macOS:
srm -vz logs/trinitas.log.INCIDENT_*

# Step 3: Verify deletion
ls -la logs/
# Ensure no .INCIDENT_* files remain

# Step 4: Update incident log
echo "$(date +%Y-%m-%d): Purged logs from INC-20251107-001" >> /secure/incident_log.txt
```

**Retention Policy**:
- **Normal logs**: 30 days rolling retention
- **Security logs**: 90 days rolling retention
- **Incident logs**: 1 year (encrypted archive), then purge
- **Audit logs**: 6 years (HIPAA requirement if applicable)

### Post-Incident Review Checklist

- [ ] Root cause identified and documented
- [ ] All affected credentials rotated
- [ ] All affected users notified (if required)
- [ ] Regulatory notifications filed (GDPR, CCPA if required)
- [ ] Code fix deployed to production
- [ ] Automated tests added to prevent recurrence
- [ ] Process improvements implemented
- [ ] Team training scheduled
- [ ] Incident postmortem shared with leadership

---

## Developer Guidelines

### For New Code: Use Secure Logging from Day 1

**Rule 1: Import secure utilities first**

```python
# ✅ GOOD: Import at module level
import logging
from shared.utils.secure_logging import mask_user_id, mask_email, safe_log_error

logger = logging.getLogger(__name__)

def process_user(user_id: str, email: str):
    logger.info(f"Processing user {mask_user_id(user_id)}")
    # ...
```

**Rule 2: Never log raw PII**

```python
# ❌ BAD
logger.info(f"User {user_id} performed action")

# ✅ GOOD
logger.info(f"User {mask_user_id(user_id)} performed action")
```

**Rule 3: Use safe_log_error() for exceptions**

```python
# ❌ BAD: Stack trace may expose secrets
try:
    authenticate()
except Exception as e:
    logger.error("Auth failed", exc_info=True)

# ✅ GOOD: Environment-aware error logging
try:
    authenticate()
except Exception as e:
    safe_log_error(logger, "Auth failed", exception=e)
```

**Rule 4: Review logging in code reviews**

Add to your code review checklist:
- [ ] No raw PII (user IDs, emails, phone numbers)
- [ ] No passwords, API keys, tokens
- [ ] No database connection strings
- [ ] Exceptions logged with `safe_log_error()`
- [ ] Log levels appropriate (no DEBUG in production code)

### For Legacy Code: Migration Guide

See [`docs/security/LOGGING_MIGRATION_GUIDE.md`](#) for detailed migration steps.

**Quick Migration Steps**:

1. **Find violations**:
```bash
# Search for common violation patterns
rg "logger\.(info|debug|warning)\(.*user_id" src/
rg "logger\.(info|debug|warning)\(.*email" src/
rg "logger\.(info|debug|warning)\(.*password" src/
rg "exc_info=True" src/
```

2. **Apply fixes**:
```python
# Before
logger.info(f"User {user_id} logged in")

# After
from shared.utils.secure_logging import mask_user_id
logger.info(f"User {mask_user_id(user_id)} logged in")
```

3. **Test**:
```bash
# Run unit tests
pytest tests/unit/test_secure_logging.py

# Run log auditor
python3 shared/utils/log_auditor.py --directory logs/
```

4. **Deploy**:
```bash
# Review changes
git diff

# Commit with secure logging tag
git commit -m "security: Apply PII masking in user authentication module (V-8)"

# Deploy to staging first
deploy --env staging

# Verify no sensitive data in staging logs
python3 shared/utils/log_auditor.py --directory /var/log/trinitas/ --remote staging

# Deploy to production
deploy --env production
```

### Code Review Checklist

**Logging Security Review** (add to your PR template):

```markdown
## Logging Security Checklist

- [ ] **PII Masking**: All user IDs, emails, phone numbers masked
- [ ] **Credentials**: No passwords, API keys, tokens logged
- [ ] **Database**: No connection strings or credentials logged
- [ ] **Error Handling**: Exceptions logged with `safe_log_error()`
- [ ] **Log Levels**: Appropriate levels (INFO for prod, DEBUG for dev only)
- [ ] **URL Parameters**: Sensitive URL parameters masked
- [ ] **Stack Traces**: Not logged in production code paths
- [ ] **Session Management**: No session IDs or JWT tokens logged
- [ ] **Tests Added**: Unit tests verify no sensitive data in logs

**Reviewer**: I have verified the above checklist
**Reviewer Signature**: @reviewer_username
```

### Testing Requirements

**Unit Test Example**:

```python
# tests/unit/test_secure_logging.py
import unittest
import logging
from io import StringIO
from shared.utils.secure_logging import mask_user_id, mask_email, safe_log_error

class TestSecureLogging(unittest.TestCase):

    def setUp(self):
        """Set up test logger."""
        self.logger = logging.getLogger("test")
        self.log_stream = StringIO()
        handler = logging.StreamHandler(self.log_stream)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)

    def test_user_id_not_in_logs(self):
        """Verify raw user IDs never appear in logs."""
        user_id = "user_1234567890"
        self.logger.info(f"User {mask_user_id(user_id)} logged in")

        log_output = self.log_stream.getvalue()
        self.assertNotIn(user_id, log_output, "Raw user ID found in log!")
        self.assertIn("user_***7890", log_output, "Masked user ID not in log!")

    def test_email_not_in_logs(self):
        """Verify raw emails never appear in logs."""
        email = "john.doe@example.com"
        self.logger.info(f"Email sent to {mask_email(email)}")

        log_output = self.log_stream.getvalue()
        self.assertNotIn(email, log_output, "Raw email found in log!")
        self.assertIn("@example.com", log_output, "Domain should be preserved")

    def test_exception_not_logged_in_production(self):
        """Verify stack traces not logged in production."""
        import os
        os.environ["ENVIRONMENT"] = "production"

        try:
            raise ValueError("Secret API key: sk_live_abc123")
        except Exception as e:
            safe_log_error(self.logger, "Operation failed", exception=e)

        log_output = self.log_stream.getvalue()
        self.assertNotIn("sk_live_abc123", log_output, "Secret in log!")
        self.assertNotIn("Traceback", log_output, "Stack trace in production log!")

        # Cleanup
        del os.environ["ENVIRONMENT"]

if __name__ == "__main__":
    unittest.main()
```

**Integration Test Example**:

```python
# tests/integration/test_logging_integration.py
import pytest
from your_app import authenticate_user
from shared.utils.log_auditor import scan_log_file

def test_authentication_logs_secure(tmp_path):
    """Integration test: Verify authentication logs no sensitive data."""
    log_file = tmp_path / "test.log"

    # Configure logger to write to temp file
    import logging
    logging.basicConfig(filename=str(log_file), level=logging.INFO)

    # Perform authentication (this should trigger logging)
    try:
        authenticate_user("test_user@example.com", "secret_password_123")
    except:
        pass  # We're testing logging, not auth logic

    # Scan log file for sensitive data
    has_sensitive, patterns = scan_log_file(str(log_file))

    assert not has_sensitive, f"Sensitive data found: {patterns}"
```

---

## Examples and Templates

### Example 1: User Authentication

```python
import logging
from shared.utils.secure_logging import mask_user_id, mask_email, safe_log_error

logger = logging.getLogger(__name__)

def authenticate_user(email: str, password: str):
    """
    Authenticate user with secure logging.

    ❌ NEVER log: raw email, password
    ✅ DO log: masked email, success/failure status
    """
    # ❌ BAD: Logs sensitive data
    # logger.info(f"Authentication attempt: {email} / {password}")

    # ✅ GOOD: Log only masked email
    logger.info(f"Authentication attempt for {mask_email(email)}")

    try:
        user = User.authenticate(email, password)

        # ✅ GOOD: Log success with masked user ID
        logger.info(f"Authentication successful for user {mask_user_id(user.id)}")

        return user

    except AuthenticationError as e:
        # ✅ GOOD: Use safe error logging
        safe_log_error(logger, "Authentication failed", exception=e)
        raise
```

### Example 2: API Request Logging

```python
from shared.utils.secure_logging import mask_url_params, mask_api_key

def log_api_request(request):
    """
    Log API request with masked sensitive parameters.
    """
    # ❌ BAD: Full URL may contain tokens
    # logger.info(f"API request: {request.url}")

    # ✅ GOOD: Mask sensitive query parameters
    safe_url = mask_url_params(request.url, ["token", "api_key", "secret"])
    logger.info(f"API request: {safe_url}")

    # ❌ BAD: Authorization header contains bearer token
    # logger.debug(f"Authorization: {request.headers.get('Authorization')}")

    # ✅ GOOD: Log only header presence
    has_auth = "Authorization" in request.headers
    logger.debug(f"Authorization header present: {has_auth}")
```

### Example 3: Database Query Logging

```python
def execute_query(query: str, params: dict):
    """
    Execute database query with secure logging.
    """
    # ❌ BAD: Logs query parameters (may contain PII)
    # logger.debug(f"Executing query: {query} with params: {params}")

    # ✅ GOOD: Log query type and row count only
    start_time = time.time()
    result = db.execute(query, params)
    duration_ms = (time.time() - start_time) * 1000

    logger.info(
        "Query executed",
        extra={
            "query_type": query.split()[0],  # SELECT, INSERT, UPDATE, DELETE
            "rows_affected": result.rowcount,
            "duration_ms": duration_ms
        }
    )

    return result
```

### Example 4: Payment Processing

```python
from shared.utils.secure_logging import mask_credit_card

def process_payment(card_number: str, cvv: str, amount_cents: int):
    """
    Process payment with PCI-DSS compliant logging.
    """
    # ❌ CRITICAL: Never log credit card or CVV
    # logger.info(f"Processing payment: {card_number} / {cvv}")

    # ✅ GOOD: Log only masked card and amount
    logger.info(
        "Payment processing initiated",
        extra={
            "masked_card": mask_credit_card(card_number),
            "amount_cents": amount_cents,
            "currency": "USD"
        }
    )

    try:
        transaction_id = payment_gateway.charge(card_number, cvv, amount_cents)

        # ✅ GOOD: Log transaction ID (not card details)
        logger.info(f"Payment successful: transaction_id={transaction_id}")

        return transaction_id

    except PaymentError as e:
        # ✅ GOOD: Safe error logging
        safe_log_error(logger, "Payment failed", exception=e)
        raise
```

### Example 5: User Registration

```python
from shared.utils.secure_logging import mask_email, mask_phone

def register_user(email: str, phone: str, password: str):
    """
    Register new user with GDPR-compliant logging.
    """
    # ❌ BAD: Logs PII and password
    # logger.info(f"Registering user: {email} / {phone} / {password}")

    # ✅ GOOD: Log only masked identifiers
    logger.info(
        "User registration started",
        extra={
            "masked_email": mask_email(email),
            "masked_phone": mask_phone(phone)
        }
    )

    try:
        user = User.create(email, phone, password)

        # ✅ GOOD: Log user ID (masked), not PII
        logger.info(f"User registration successful: {mask_user_id(user.id)}")

        return user

    except ValidationError as e:
        # ❌ BAD: Error message may contain PII
        # logger.error(f"Validation failed: {str(e)}")

        # ✅ GOOD: Log only error type
        logger.error(f"User registration failed: {e.__class__.__name__}")
        raise
```

### Example 6: Structured Logging with JSON

```python
import logging
import json
from datetime import datetime
from shared.utils.secure_logging import mask_user_id, mask_email

# Configure JSON logging
logger = logging.getLogger(__name__)

def log_user_action(user_id: str, action: str, metadata: dict = None):
    """
    Log user action with structured JSON format.
    """
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "user_id": mask_user_id(user_id),
        "action": action,
        "metadata": metadata or {}
    }

    # ✅ GOOD: Structured logging enables automated analysis
    logger.info(json.dumps(log_entry))
```

**JSON Log Output**:
```json
{
  "timestamp": "2025-11-07T14:30:00.123456Z",
  "user_id": "user_***7890",
  "action": "document_viewed",
  "metadata": {
    "document_id": "doc_abc123",
    "duration_seconds": 42
  }
}
```

### Template: Secure Logging Module

```python
# your_module/secure_logging_helper.py
"""
Project-specific secure logging utilities.
Extends shared/utils/secure_logging.py with domain-specific masking.
"""

import logging
from shared.utils.secure_logging import (
    mask_user_id as _mask_user_id,
    mask_email as _mask_email,
    safe_log_error,
)

# Project-specific logger
logger = logging.getLogger(__name__)

def mask_order_id(order_id: str) -> str:
    """
    Mask order ID: ORD-12345678 → ORD-***678
    """
    if not order_id.startswith("ORD-"):
        return "***"
    return f"ORD-***{order_id[-3:]}"

def mask_customer_id(customer_id: str) -> str:
    """
    Mask customer ID: CUST-87654321 → CUST-***321
    """
    if not customer_id.startswith("CUST-"):
        return "***"
    return f"CUST-***{customer_id[-3:]}"

def log_business_event(event_type: str, user_id: str, **kwargs):
    """
    Centralized business event logging with automatic PII masking.

    Usage:
        log_business_event("order_created", user_id="user_1234567890", order_id="ORD-12345678")
    """
    # Automatic masking of known PII fields
    masked_kwargs = {}
    for key, value in kwargs.items():
        if key == "user_id":
            masked_kwargs[key] = _mask_user_id(value)
        elif key == "email":
            masked_kwargs[key] = _mask_email(value)
        elif key == "order_id":
            masked_kwargs[key] = mask_order_id(value)
        elif key == "customer_id":
            masked_kwargs[key] = mask_customer_id(value)
        else:
            masked_kwargs[key] = value

    logger.info(
        f"Business event: {event_type}",
        extra={"user_id": _mask_user_id(user_id), **masked_kwargs}
    )

# Usage in application code
if __name__ == "__main__":
    log_business_event(
        "order_created",
        user_id="user_1234567890",
        order_id="ORD-12345678",
        customer_id="CUST-87654321",
        amount_cents=4999
    )
    # Output: "Business event: order_created | user_id=user_***7890 | order_id=ORD-***678 | customer_id=CUST-***321 | amount_cents=4999"
```

---

## References

### Standards and Regulations

1. **CWE-532: Insertion of Sensitive Information into Log File**
   - https://cwe.mitre.org/data/definitions/532.html

2. **GDPR (General Data Protection Regulation)**
   - Official Text: https://gdpr-info.eu/
   - Article 5 (Principles): https://gdpr-info.eu/art-5-gdpr/
   - Article 32 (Security): https://gdpr-info.eu/art-32-gdpr/

3. **CCPA (California Consumer Privacy Act)**
   - Official Text: https://oag.ca.gov/privacy/ccpa

4. **SOC 2 (Service Organization Control)**
   - AICPA Trust Services Criteria: https://www.aicpa.org/soc

5. **HIPAA (Health Insurance Portability and Accountability Act)**
   - Security Rule: https://www.hhs.gov/hipaa/for-professionals/security/

6. **PCI-DSS (Payment Card Industry Data Security Standard)**
   - Official Standards: https://www.pcisecuritystandards.org/

### Tools and Libraries

1. **Python `logging` module**: https://docs.python.org/3/library/logging.html
2. **`pythonjsonlogger`**: https://github.com/madzak/python-json-logger
3. **Splunk**: https://www.splunk.com/
4. **ELK Stack (Elasticsearch, Logstash, Kibana)**: https://www.elastic.co/elastic-stack
5. **Datadog**: https://www.datadoghq.com/

### Internal Documentation

1. **Trinitas Secure Logging Utilities**: `shared/utils/secure_logging.py`
2. **Log Auditor Tool**: `shared/utils/log_auditor.py`
3. **Logging Migration Guide**: `docs/security/LOGGING_MIGRATION_GUIDE.md`
4. **Quick Reference**: `docs/security/LOGGING_QUICK_REFERENCE.md`
5. **Security Overview**: `docs/security/SECURITY_OVERVIEW.md`

### Further Reading

1. **OWASP Logging Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
2. **NIST Guide to Computer Security Log Management**: https://csrc.nist.gov/publications/detail/sp/800-92/final
3. **"Logging Best Practices" by Troy Hunt**: https://www.troyhunt.com/

---

**Document Version**: 1.0.0
**Last Updated**: 2025-11-07
**Maintained By**: Muses (Knowledge Architect)
**Review Schedule**: Quarterly
**Next Review**: 2026-02-07

---

*"Through meticulous documentation and diligent implementation, we safeguard user privacy and organizational security. This policy is not merely compliance—it is our commitment to ethical data stewardship." - Muses*
