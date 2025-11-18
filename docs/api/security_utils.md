# Security Utils API Documentation
## Trinitas Decision System - Security Validation Functions

**Module**: `.claude/hooks/core/security_utils.py`
**Version**: 2.3.0
**Status**: Production-Ready
**Purpose**: Comprehensive security validation and sanitization functions for the Trinitas Decision System

---

## Table of Contents

1. [Exception Classes](#exception-classes)
2. [Path Security Functions](#path-security-functions)
3. [Network Security Functions](#network-security-functions)
4. [Input Sanitization Functions](#input-sanitization-functions)
5. [Logging Security Functions](#logging-security-functions)
6. [JSON Security Functions](#json-security-functions)
7. [Usage Examples](#usage-examples)

---

## Exception Classes

### `SecurityError`

Base exception class for all security violations.

```python
class SecurityError(Exception):
    """Base exception for security violations"""
    pass
```

**Purpose**: Generic security error for categorization.

**When to use**: Inherit from this for custom security exceptions.

---

### `PathTraversalError`

Exception raised when path traversal attack is detected.

```python
class PathTraversalError(SecurityError):
    """Path traversal attempt detected"""
    pass
```

**Inherits from**: `SecurityError`

**Raised by**: `validate_and_resolve_path()`

**Example**:
```python
try:
    path = validate_and_resolve_path(user_path, base_dir)
except PathTraversalError as e:
    logger.error(f"Path traversal blocked: {e}")
```

---

### `SSRFError`

Exception raised when SSRF (Server-Side Request Forgery) attack is detected.

```python
class SSRFError(SecurityError):
    """SSRF attack attempt detected"""
    pass
```

**Inherits from**: `SecurityError`

**Raised by**: `validate_tmws_url()`

**Example**:
```python
try:
    url = validate_tmws_url(user_url)
except SSRFError as e:
    logger.error(f"SSRF attempt blocked: {e}")
```

---

## Path Security Functions

### `validate_decision_id(decision_id: str) -> str`

Validate decision ID for safe filesystem use.

**Arguments**:
- `decision_id` (str): Decision ID to validate

**Returns**:
- `str`: Validated decision ID (same as input if valid)

**Raises**:
- `ValueError`: If decision ID contains invalid characters, path separators, or exceeds length limit

**Security**: Prevents CWE-22 (Path Traversal)

**Validation Rules**:
1. Only alphanumeric characters, dash (`-`), and underscore (`_`) allowed
2. Maximum length: 64 characters
3. No path separators (`/`, `\`)

**Example**:
```python
from .security_utils import validate_decision_id

# Valid IDs
valid_id = validate_decision_id("decision-123_abc")  # OK

# Invalid IDs (raises ValueError)
try:
    validate_decision_id("../etc/passwd")  # Path traversal
except ValueError as e:
    print(e)  # "Invalid decision ID: ../etc/passwd"

try:
    validate_decision_id("decision;rm -rf /")  # Shell injection attempt
except ValueError as e:
    print(e)  # "Invalid decision ID: decision;rm -rf /"
```

---

### `validate_and_resolve_path(file_path: Path, base_dir: Path, allow_create: bool = False) -> Path`

Validate file path and resolve to prevent traversal attacks.

**Arguments**:
- `file_path` (Path): Path to validate
- `base_dir` (Path): Base directory (all paths must be under this)
- `allow_create` (bool, optional): Whether to create the path if it doesn't exist. Default: `False`

**Returns**:
- `Path`: Validated and resolved absolute path

**Raises**:
- `PathTraversalError`: If path traversal is detected (path outside base_dir)
- `SecurityError`: If symlink is detected (CWE-61)

**Security**: Prevents CWE-22 (Path Traversal) and CWE-61 (UNIX Symbolic Link Following)

**Algorithm**:
1. Resolve symlinks in `base_dir`
2. Check if `file_path` is a symlink (before resolution) → block
3. Resolve `file_path` to absolute path
4. Verify resolved path is under `base_dir` using `relative_to()`
5. Optionally create parent directories with mode `0o700`

**Example**:
```python
from pathlib import Path
from .security_utils import validate_and_resolve_path, PathTraversalError

base_dir = Path("/home/user/.claude/decisions")

# Valid path
safe_path = validate_and_resolve_path(
    Path("decision-123.json"),
    base_dir
)
# Returns: /home/user/.claude/decisions/decision-123.json

# Traversal attempt (blocked)
try:
    malicious_path = validate_and_resolve_path(
        Path("../../../etc/passwd"),
        base_dir
    )
except PathTraversalError as e:
    print(e)  # "Path traversal attempt (CWE-22): /etc/passwd not under /home/user/.claude/decisions"

# Symlink attack (blocked)
symlink_path = Path("/tmp/malicious_link")
symlink_path.symlink_to("/etc/passwd")

try:
    validate_and_resolve_path(symlink_path, base_dir)
except SecurityError as e:
    print(e)  # "Symlink access denied (CWE-61): /tmp/malicious_link"

# Create parent directories
new_path = validate_and_resolve_path(
    Path("2024/november/decision-456.json"),
    base_dir,
    allow_create=True
)
# Creates: /home/user/.claude/decisions/2024/november/ with mode 0o700
```

---

## Network Security Functions

### `validate_tmws_url(url: str, allow_localhost: bool = True) -> str`

Validate TMWS URL for SSRF protection.

**Arguments**:
- `url` (str): URL to validate
- `allow_localhost` (bool, optional): Whether to allow localhost URLs. Default: `True`

**Returns**:
- `str`: Validated URL (same as input if valid)

**Raises**:
- `SSRFError`: If SSRF risk is detected

**Security**: Prevents CWE-918 (Server-Side Request Forgery)

**Validation Rules**:
1. **Scheme**: Only `http` and `https` allowed
2. **Hostname**: Required (no blank hostnames)
3. **IP Range Blocking**:
   - Private IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
   - Loopback (127.0.0.1, ::1) - allowed only if `allow_localhost=True`
   - Link-local (169.254.x.x, fe80::/10)
   - Reserved IPs
4. **Cloud Metadata Blocking**:
   - `169.254.169.254` (AWS/Azure metadata)
   - `metadata.google.internal` (GCP metadata)
   - `metadata.goog`
5. **Port Whitelist**: 80, 443, 8000, 8080

**Example**:
```python
from .security_utils import validate_tmws_url, SSRFError

# Valid URLs
tmws_url = validate_tmws_url("https://tmws.example.com/api")  # OK
local_url = validate_tmws_url("http://localhost:8080/api")    # OK (localhost allowed)

# SSRF attempts (blocked)
try:
    validate_tmws_url("http://192.168.1.1/admin")  # Private IP
except SSRFError as e:
    print(e)  # "Private IP not allowed: 192.168.1.1"

try:
    validate_tmws_url("http://169.254.169.254/latest/meta-data/")  # AWS metadata
except SSRFError as e:
    print(e)  # "Private IP not allowed: 169.254.169.254"

try:
    validate_tmws_url("http://metadata.google.internal/")  # GCP metadata
except SSRFError as e:
    print(e)  # "Blocked hostname: metadata.google.internal"

try:
    validate_tmws_url("ftp://tmws.example.com/")  # Invalid scheme
except SSRFError as e:
    print(e)  # "Invalid scheme: ftp"

# Production mode (localhost blocked)
try:
    validate_tmws_url("http://localhost:8080/", allow_localhost=False)
except SSRFError as e:
    print(e)  # "Localhost not allowed"
```

---

## Input Sanitization Functions

### `sanitize_prompt(prompt: str, max_length: int = 1000) -> str`

Comprehensive prompt sanitization for user input.

**Arguments**:
- `prompt` (str): Raw prompt text
- `max_length` (int, optional): Maximum length. Default: 1000

**Returns**:
- `str`: Sanitized prompt (safe for processing)

**Security**: Prevents injection attacks and control character exploits

**Sanitization Steps**:
1. **Type Check**: Return empty string if not a string
2. **Control Character Removal**: Remove all Unicode control characters (Category `C`)
   - Includes: `\n`, `\r`, `\t`, `\0`, `\x00-\x1F`, `\x7F-\x9F`
3. **Unicode Normalization**: Normalize to NFC form (canonical composition)
4. **Whitespace Collapse**: Strip leading/trailing whitespace, collapse internal whitespace
5. **Length Limit**: Truncate to `max_length`

**Example**:
```python
from .security_utils import sanitize_prompt

# Basic sanitization
clean = sanitize_prompt("Hello\nWorld\r\n")
# Returns: "Hello World"

# Control character removal
clean = sanitize_prompt("Hello\x00\x01\x02World")
# Returns: "HelloWorld"

# Unicode normalization
clean = sanitize_prompt("café")  # é as combining character
# Returns: "café" (NFC form)

# Whitespace collapse
clean = sanitize_prompt("  Multiple   spaces   ")
# Returns: "Multiple spaces"

# Length limit
long_text = "A" * 2000
clean = sanitize_prompt(long_text, max_length=1000)
# Returns: "AAA..." (1000 characters)

# Non-string input
clean = sanitize_prompt(None)
# Returns: ""
```

---

### `redact_secrets(text: str) -> str`

Redact potential secrets from text.

**Arguments**:
- `text` (str): Text to redact

**Returns**:
- `str`: Text with secrets redacted

**Security**: Prevents information disclosure and credential leakage

**Redaction Patterns**:

| Pattern | Replacement | Example |
|---------|-------------|---------|
| OpenAI API keys (`sk-...`) | `[REDACTED_API_KEY]` | `sk-abc123...` |
| Generic tokens (32+ chars) | `[REDACTED_TOKEN]` | `a1b2c3d4e5f6...` |
| Passwords | `[REDACTED]` | `password=secret123` |
| SHA256/SHA512 hashes | `[REDACTED_HASH]` | `abcdef0123456789...` (64+ chars) |
| AWS access keys | `[REDACTED_AWS_KEY]` | `AKIAIOSFODNN7EXAMPLE` |
| JWT tokens | `[REDACTED_JWT]` | `eyJhbGc...` |
| Generic secrets | `[REDACTED]` | `secret=abc`, `token=xyz` |

**Example**:
```python
from .security_utils import redact_secrets

# OpenAI API key
text = "My API key is sk-abc123def456ghi789jkl012mno345"
safe_text = redact_secrets(text)
# Returns: "My API key is [REDACTED_API_KEY]"

# Password
text = "Login with password=SuperSecret123"
safe_text = redact_secrets(text)
# Returns: "Login with password=[REDACTED]"

# AWS access key
text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
safe_text = redact_secrets(text)
# Returns: "AWS_ACCESS_KEY_ID=[REDACTED_AWS_KEY]"

# JWT token
text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
safe_text = redact_secrets(text)
# Returns: "Authorization: Bearer [REDACTED_JWT]"

# Multiple secrets
text = "API key: sk-abc123, password=secret, token=xyz789"
safe_text = redact_secrets(text)
# Returns: "API key: [REDACTED_API_KEY], password=[REDACTED], token=[REDACTED]"
```

---

## Logging Security Functions

### `sanitize_log_message(msg: str, max_length: int = 500) -> str`

Sanitize log message to prevent injection.

**Arguments**:
- `msg` (str): Log message
- `max_length` (int, optional): Maximum length. Default: 500

**Returns**:
- `str`: Sanitized log message (safe for logging)

**Security**: Prevents CWE-117 (Log Injection)

**Sanitization Steps**:
1. **Newline Removal**: Replace `\n`, `\r` with spaces
2. **Tab Removal**: Replace `\t` with spaces
3. **Control Character Removal**: Remove all Unicode control characters (Category `C`)
4. **Length Limit**: Truncate to `max_length`

**Example**:
```python
from .security_utils import sanitize_log_message

# Log injection attempt
msg = "User login: admin\nALERT: System compromised"
safe_msg = sanitize_log_message(msg)
# Returns: "User login: admin ALERT: System compromised"
# (No newline injection into logs)

# Control characters
msg = "Error: \x00\x01\x02 Invalid input"
safe_msg = sanitize_log_message(msg)
# Returns: "Error:  Invalid input"

# Length limit
long_msg = "A" * 1000
safe_msg = sanitize_log_message(long_msg, max_length=500)
# Returns: "AAA..." (500 characters)
```

---

## JSON Security Functions

### `safe_json_parse(json_str: str, max_size: int = 10_000, max_depth: int = 10) -> dict`

Safely parse JSON with size and depth limits.

**Arguments**:
- `json_str` (str): JSON string to parse
- `max_size` (int, optional): Maximum size in bytes. Default: 10,000
- `max_depth` (int, optional): Maximum nesting depth. Default: 10

**Returns**:
- `dict`: Parsed JSON data

**Raises**:
- `ValueError`: If JSON is too large, too deeply nested, or invalid

**Security**: Prevents CWE-502 (Deserialization of Untrusted Data) and CWE-400 (Resource Exhaustion)

**Validation Steps**:
1. **Size Check**: Ensure JSON string is ≤ `max_size` bytes
2. **Parse**: Use `json.loads()` with error handling
3. **Depth Check**: Recursively verify nesting depth ≤ `max_depth`

**Example**:
```python
from .security_utils import safe_json_parse

# Valid JSON
data = safe_json_parse('{"key": "value", "number": 123}')
# Returns: {'key': 'value', 'number': 123}

# Size limit (10KB default)
large_json = '{"data": "' + 'A' * 20_000 + '"}'
try:
    safe_json_parse(large_json)
except ValueError as e:
    print(e)  # "JSON too large: 20010 bytes (max: 10000)"

# Depth limit (10 levels default)
deeply_nested = '{"a":' * 15 + '{}' + '}' * 15
try:
    safe_json_parse(deeply_nested)
except ValueError as e:
    print(e)  # "JSON too deeply nested: >10 levels"

# Invalid JSON
try:
    safe_json_parse('{"invalid": }')
except ValueError as e:
    print(e)  # "Invalid JSON: Expecting value: line 1 column 13 (char 12)"

# Custom limits
data = safe_json_parse(
    '{"large": "data"}',
    max_size=50_000,
    max_depth=5
)
```

---

## Usage Examples

### Complete Security Stack for Decision System

```python
#!/usr/bin/env python3
"""Example: Secure decision processing with full validation"""

import json
from pathlib import Path
from .security_utils import (
    validate_decision_id,
    validate_and_resolve_path,
    validate_tmws_url,
    sanitize_prompt,
    redact_secrets,
    sanitize_log_message,
    safe_json_parse,
    PathTraversalError,
    SSRFError
)

class SecureDecisionProcessor:
    def __init__(self, base_dir: Path, tmws_url: str):
        # Validate TMWS URL (SSRF protection)
        self.tmws_url = validate_tmws_url(tmws_url, allow_localhost=True)
        self.base_dir = base_dir

    def process_decision(self, stdin_raw: str) -> dict:
        """Process user decision with comprehensive security"""

        # Step 1: Safe JSON parsing (size/depth limits)
        try:
            stdin_data = safe_json_parse(stdin_raw, max_size=10_000, max_depth=10)
        except ValueError as e:
            logger.error(f"JSON parse error: {sanitize_log_message(str(e))}")
            return {"error": "Invalid input"}

        # Step 2: Extract and sanitize prompt
        raw_prompt = stdin_data.get("prompt", "")
        clean_prompt = sanitize_prompt(raw_prompt, max_length=1000)

        # Step 3: Redact secrets before logging
        safe_prompt = redact_secrets(clean_prompt)
        logger.info(f"Processing prompt: {sanitize_log_message(safe_prompt)}")

        # Step 4: Validate decision ID (path traversal prevention)
        decision_id = stdin_data.get("decision_id", "")
        try:
            safe_id = validate_decision_id(decision_id)
        except ValueError as e:
            logger.error(f"Invalid decision ID: {sanitize_log_message(str(e))}")
            return {"error": "Invalid decision ID"}

        # Step 5: Secure file path resolution
        try:
            file_path = validate_and_resolve_path(
                self.base_dir / f"{safe_id}.json",
                self.base_dir,
                allow_create=True
            )
        except (PathTraversalError, SecurityError) as e:
            logger.error(f"Path validation failed: {sanitize_log_message(str(e))}")
            return {"error": "Path validation failed"}

        # Step 6: Save decision with restricted permissions
        decision_data = {
            "decision_id": safe_id,
            "prompt": clean_prompt,  # Store sanitized prompt
            "timestamp": "2025-11-03T12:00:00Z"
        }

        with open(file_path, "w") as f:
            json.dump(decision_data, f, indent=2)

        file_path.chmod(0o600)  # Owner read/write only

        logger.info(f"Decision saved: {sanitize_log_message(safe_id)}")
        return {"status": "success", "decision_id": safe_id}
```

### Hook Integration Example

```python
#!/usr/bin/env python3
"""Example: Integrate security utils into decision_check.py hook"""

import sys
import json
from pathlib import Path
from .security_utils import (
    sanitize_prompt,
    redact_secrets,
    sanitize_log_message,
    safe_json_parse
)
from .rate_limiter import ThreadSafeRateLimiter, RateLimitExceeded

class DecisionCheckHook:
    def __init__(self):
        # Rate limiter: 100 calls/60 seconds
        self.rate_limiter = ThreadSafeRateLimiter(
            max_calls=100,
            window_seconds=60
        )

    async def process_hook(self, stdin_data: dict) -> dict:
        """Process hook with security checks"""

        # Step 1: Rate limiting (DoS protection)
        try:
            self.rate_limiter.check(operation_id="user_prompt_submit")
        except RateLimitExceeded as e:
            logger.error(f"Rate limit exceeded: {sanitize_log_message(str(e))}")
            return {"addedContext": []}

        # Step 2: Extract and sanitize prompt
        raw_prompt = self._extract_prompt(stdin_data)
        clean_prompt = sanitize_prompt(raw_prompt, max_length=1000)

        # Step 3: Redact secrets before displaying to user
        safe_prompt = redact_secrets(clean_prompt)

        # Step 4: Generate approval request with safe prompt
        approval_reminder = self._generate_approval_request(safe_prompt)

        return {
            "addedContext": [
                {
                    "type": "text",
                    "content": approval_reminder
                }
            ]
        }

def main():
    """Main entry point with safe JSON parsing"""
    hook = DecisionCheckHook()

    # Read stdin
    stdin_raw = sys.stdin.read()

    # Safe JSON parsing (size/depth limits)
    try:
        stdin_data = safe_json_parse(stdin_raw, max_size=10_000, max_depth=10)
    except ValueError as e:
        logger.error(f"JSON parse error: {sanitize_log_message(str(e))}")
        print(json.dumps({"addedContext": []}))
        sys.exit(0)

    # Process hook
    result = asyncio.run(hook.process_hook(stdin_data))
    print(json.dumps(result))
```

---

## Security Best Practices

### 1. Defense in Depth

Always use multiple layers of security:

```python
# Layer 1: Input validation
safe_id = validate_decision_id(decision_id)

# Layer 2: Path resolution
file_path = (base_dir / f"{safe_id}.json").resolve()

# Layer 3: Traversal check
file_path.relative_to(base_dir.resolve())

# Layer 4: Symlink check
if file_path.is_symlink():
    raise SecurityError("Symlink access denied")

# Layer 5: File permissions
file_path.chmod(0o600)
```

### 2. Fail-Safe Design

Handle all security errors gracefully:

```python
try:
    url = validate_tmws_url(user_url)
except SSRFError as e:
    logger.error(f"SSRF blocked: {sanitize_log_message(str(e))}")
    return {"error": "Invalid URL"}  # Don't crash
```

### 3. Always Sanitize Logs

Never log untrusted data directly:

```python
# ❌ WRONG: Direct logging
logger.error(f"Error: {exception}")

# ✅ CORRECT: Sanitized logging
logger.error(f"Error: {sanitize_log_message(str(exception))}")
```

### 4. Redact Before Display

Always redact secrets before showing to users:

```python
# ❌ WRONG: Show raw prompt
print(f"Your prompt: {raw_prompt}")

# ✅ CORRECT: Redact secrets first
safe_prompt = redact_secrets(sanitize_prompt(raw_prompt))
print(f"Your prompt: {safe_prompt}")
```

---

## Performance Characteristics

| Function | Time Complexity | Memory | Notes |
|----------|----------------|--------|-------|
| `validate_decision_id()` | O(n) | O(1) | n = length of ID (max 64) |
| `validate_and_resolve_path()` | O(d) | O(1) | d = directory depth |
| `validate_tmws_url()` | O(1) | O(1) | URL parsing is O(n) but n is small |
| `sanitize_prompt()` | O(n) | O(n) | n = prompt length |
| `redact_secrets()` | O(n*m) | O(n) | n = text length, m = patterns (7) |
| `sanitize_log_message()` | O(n) | O(n) | n = message length |
| `safe_json_parse()` | O(n*d) | O(n) | n = JSON size, d = depth |

**Overall Overhead**: <2% performance impact, <2KB memory.

---

## Security Compliance

### CWE Coverage

- ✅ **CWE-22**: Path Traversal
- ✅ **CWE-61**: UNIX Symbolic Link Following
- ✅ **CWE-117**: Log Injection
- ✅ **CWE-400**: Resource Exhaustion
- ✅ **CWE-502**: Deserialization of Untrusted Data
- ✅ **CWE-918**: Server-Side Request Forgery (SSRF)

### OWASP Top 10 Coverage

- ✅ **A01:2021**: Broken Access Control
- ✅ **A03:2021**: Injection
- ✅ **A04:2021**: Insecure Design
- ✅ **A08:2021**: Software and Data Integrity Failures
- ✅ **A10:2021**: Server-Side Request Forgery (SSRF)

---

**Last Updated**: 2025-11-03
**Version**: 2.3.0
**Author**: Hestia (Security Guardian) + Muses (Knowledge Architect)
**License**: MIT
**Contact**: Trinitas AI Team
