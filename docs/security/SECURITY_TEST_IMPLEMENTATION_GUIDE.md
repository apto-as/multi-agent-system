# SECURITY TEST IMPLEMENTATION GUIDE
**Hestia (Security Guardian) - How to Implement Security Tests**

---

## PURPOSE
This guide provides concrete implementation templates for all security integration tests identified in the audit.

---

## FILE STRUCTURE

```
tests/
├── integration/
│   ├── security/
│   │   ├── __init__.py
│   │   ├── test_password_security.py          # Bcrypt migration
│   │   ├── test_jwt_security_vectors.py        # JWT attacks
│   │   ├── test_session_security.py            # Cookie/session
│   │   ├── test_cors_security.py               # CORS attacks
│   │   ├── test_production_security.py         # Production config
│   │   ├── test_rbac_security.py               # RBAC boundaries
│   │   ├── test_injection_attacks.py           # SQL/XSS
│   │   ├── test_rate_limiting_security.py      # Rate limit bypass
│   │   └── test_api_key_security.py            # API key attacks
│   └── conftest.py  # Shared fixtures
```

---

## FIXTURE REQUIREMENTS

### conftest.py - Security Test Fixtures
```python
"""Shared fixtures for security integration tests."""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from httpx import AsyncClient
import os

@pytest_asyncio.fixture
async def production_env():
    """Set production environment for testing."""
    original_env = os.environ.get("TMWS_ENVIRONMENT")
    os.environ["TMWS_ENVIRONMENT"] = "production"

    yield

    # Restore original environment
    if original_env:
        os.environ["TMWS_ENVIRONMENT"] = original_env
    else:
        del os.environ["TMWS_ENVIRONMENT"]


@pytest_asyncio.fixture
async def secure_client(async_client: AsyncClient, production_env):
    """Async client with production security settings."""
    return async_client


@pytest_asyncio.fixture
async def legacy_sha256_user(test_session: AsyncSession):
    """Create user with legacy SHA256+salt password hash."""
    import hashlib
    from src.models.user import User
    from uuid import uuid4

    salt = "legacy_salt_12345678"
    password = "LegacyPassword123!"
    sha256_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    legacy_hash = f"{salt}:{sha256_hash}"

    user = User(
        id=uuid4(),
        username="legacy_user",
        email="legacy@test.com",
        password_hash=legacy_hash
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    # Return user and plaintext password
    return user, password


@pytest_asyncio.fixture
async def bcrypt_user(test_session: AsyncSession):
    """Create user with bcrypt password hash."""
    from src.models.user import User
    from src.utils.security import hash_password
    from uuid import uuid4

    password = "BcryptPassword123!"

    user = User(
        id=uuid4(),
        username="bcrypt_user",
        email="bcrypt@test.com",
        password_hash=hash_password(password)
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    return user, password


@pytest.fixture
def malicious_jwt_creator():
    """Factory for creating malicious JWT tokens."""
    import jwt

    def create(payload: dict, algorithm: str = "HS256", secret: str = "fake_secret"):
        return jwt.encode(payload, secret, algorithm=algorithm)

    return create


@pytest_asyncio.fixture
async def namespace_isolated_agents(test_session: AsyncSession):
    """Create agents in different namespaces for isolation testing."""
    from src.models.agent import Agent
    from uuid import uuid4

    agent1 = Agent(
        id=uuid4(),
        agent_id="agent-namespace-1",
        namespace="namespace-1",
        display_name="Agent 1",
        status="active"
    )

    agent2 = Agent(
        id=uuid4(),
        agent_id="agent-namespace-2",
        namespace="namespace-2",
        display_name="Agent 2",
        status="active"
    )

    test_session.add_all([agent1, agent2])
    await test_session.commit()
    await test_session.refresh(agent1)
    await test_session.refresh(agent2)

    return agent1, agent2


@pytest.fixture
def timing_attack_detector():
    """Utility to detect timing attack vulnerabilities."""
    import time
    import statistics

    class TimingDetector:
        def __init__(self):
            self.measurements = []

        async def measure(self, coro):
            """Measure execution time of coroutine."""
            start = time.time()
            result = await coro
            elapsed = time.time() - start
            self.measurements.append(elapsed)
            return result, elapsed

        def is_constant_time(self, threshold: float = 0.05) -> bool:
            """Check if measurements indicate constant-time behavior."""
            if len(self.measurements) < 10:
                raise ValueError("Need at least 10 measurements")

            std_dev = statistics.stdev(self.measurements)
            mean = statistics.mean(self.measurements)

            # Coefficient of variation should be low for constant-time
            cv = std_dev / mean if mean > 0 else 1.0

            return cv < threshold

    return TimingDetector()
```

---

## TEMPLATE 1: Bcrypt Migration Tests

### tests/integration/security/test_password_security.py
```python
"""
Bcrypt Migration Security Tests (P0 CRITICAL)

Tests Issue #1: SHA256 → Bcrypt password hashing migration

CRITICAL SECURITY REQUIREMENTS:
1. New passwords MUST use bcrypt (not SHA256)
2. Legacy SHA256 passwords MUST still work
3. Hash format detection MUST be secure
4. Password verification MUST be constant-time

Attack Vectors Covered:
- GPU brute force attack (CVSS 7.5) - if SHA256 still used
- Hash format confusion attack
- Timing attack to enumerate users
- Authentication bypass via algorithm confusion

Author: Hestia (Security Guardian)
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.mark.security
@pytest.mark.integration
class TestBcryptMigrationSecurity:
    """P0 CRITICAL: Bcrypt migration security validation."""

    async def test_new_passwords_use_bcrypt_format(
        self,
        async_client: AsyncClient,
        test_session: AsyncSession
    ):
        """NEW passwords MUST use bcrypt format ($2b$...)

        SEVERITY: CRITICAL
        ATTACK: If SHA256 still used → GPU brute force (CVSS 7.5)
        CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
        """
        # Register new user
        response = await async_client.post("/auth/register", json={
            "username": "newuser_bcrypt",
            "email": "newbcrypt@test.com",
            "password": "SecurePassword123!"
        })

        assert response.status_code == 201, \
            f"User registration failed: {response.json()}"

        # Verify password hash format in database
        from sqlalchemy import select
        from src.models.user import User

        result = await test_session.execute(
            select(User).where(User.username == "newuser_bcrypt")
        )
        user = result.scalar_one()

        # CRITICAL: Hash MUST start with $2b$ (bcrypt format)
        assert user.password_hash.startswith("$2b$"), \
            f"NEW passwords MUST use bcrypt format, got: {user.password_hash[:20]}"

        # Verify hash length (bcrypt hashes are 60 chars)
        assert len(user.password_hash) == 60, \
            f"Bcrypt hash length incorrect: {len(user.password_hash)}"

    async def test_legacy_sha256_passwords_still_authenticate(
        self,
        async_client: AsyncClient,
        legacy_sha256_user
    ):
        """LEGACY SHA256 passwords MUST still work

        SEVERITY: CRITICAL
        BUSINESS IMPACT: Existing users locked out if migration breaks
        """
        user, password = legacy_sha256_user

        # Attempt login with legacy SHA256 password
        response = await async_client.post("/auth/login", json={
            "username": user.username,
            "password": password
        })

        assert response.status_code == 200, \
            f"Legacy SHA256 authentication failed: {response.json()}"

        response_data = response.json()
        assert "access_token" in response_data, \
            "Login response missing access_token"
        assert response_data["user"]["username"] == user.username, \
            "Wrong user authenticated"

    async def test_hash_format_detection_security(self, test_session: AsyncSession):
        """Hash format detection MUST be secure

        SEVERITY: CRITICAL
        ATTACK: Hash confusion → wrong algorithm → bypass
        """
        from src.utils.security import detect_hash_format

        # Bcrypt format detection
        bcrypt_hash = "$2b$12$abc123def456ghi789jkl"
        assert detect_hash_format(bcrypt_hash) == "bcrypt", \
            "Failed to detect bcrypt format"

        # SHA256+salt format detection
        sha256_hash = "salt123:hashvalue456"
        assert detect_hash_format(sha256_hash) == "sha256_salt", \
            "Failed to detect SHA256+salt format"

        # Empty hash MUST raise error
        with pytest.raises(ValueError, match="cannot be empty"):
            detect_hash_format("")

        # Unknown format MUST raise error (fail-secure)
        with pytest.raises(ValueError, match="Unknown hash format"):
            detect_hash_format("invalid_format_12345")

    async def test_password_verification_constant_time(
        self,
        async_client: AsyncClient,
        timing_attack_detector
    ):
        """Password verification MUST be constant-time

        SEVERITY: MEDIUM
        ATTACK: Timing attack to enumerate valid usernames
        """
        # Measure login time for non-existent user (multiple times)
        nonexistent_times = []
        for _ in range(20):
            _, elapsed = await timing_attack_detector.measure(
                async_client.post("/auth/login", json={
                    "username": "nonexistent_user",
                    "password": "WrongPassword123!"
                })
            )
            nonexistent_times.append(elapsed)

        # Measure login time for existing user with wrong password
        existing_times = []
        for _ in range(20):
            _, elapsed = await timing_attack_detector.measure(
                async_client.post("/auth/login", json={
                    "username": "testuser",  # Existing user
                    "password": "WrongPassword123!"
                })
            )
            existing_times.append(elapsed)

        # Calculate timing difference
        import statistics
        avg_nonexistent = statistics.mean(nonexistent_times)
        avg_existing = statistics.mean(existing_times)
        timing_diff = abs(avg_nonexistent - avg_existing)

        # Timing difference MUST be < 50ms (constant-time threshold)
        assert timing_diff < 0.05, \
            f"Timing attack vulnerability: {timing_diff*1000:.1f}ms difference"

    async def test_bcrypt_rejects_sha256_hash(self):
        """Bcrypt verification MUST reject SHA256 format

        SEVERITY: CRITICAL
        ATTACK: Algorithm confusion → authentication bypass
        """
        from src.utils.security import verify_password

        sha256_hash = "salt123:hashvalue456"
        password = "TestPassword123!"

        # MUST return False (not crash, not accept)
        result = verify_password(password, sha256_hash)

        assert result is False, \
            "Bcrypt verification MUST reject SHA256 hashes"
```

---

## TEMPLATE 2: JWT Security Tests

### tests/integration/security/test_jwt_security_vectors.py
```python
"""
JWT Security Attack Vector Tests (P0 CRITICAL)

Advanced JWT attack vectors beyond basic token validation.

Attack Vectors Covered:
- CVE-2015-9235: Algorithm confusion ('none' algorithm)
- Signature stripping attack
- CVE-2018-0114: Key injection via 'kid' header
- Token replay after logout

Author: Hestia (Security Guardian)
"""

import pytest
import jwt
from httpx import AsyncClient


@pytest.mark.security
@pytest.mark.integration
class TestJWTSecurityVectors:
    """P0 CRITICAL: Advanced JWT attack vectors."""

    async def test_jwt_algorithm_confusion_attack(self, async_client: AsyncClient):
        """MUST reject JWT with 'none' algorithm

        SEVERITY: CRITICAL
        ATTACK: CVE-2015-9235 - Algorithm confusion
        """
        # Create token with 'none' algorithm
        payload = {
            "sub": "admin",
            "username": "admin",
            "roles": ["admin"]
        }

        # JWT library will encode with 'none' algorithm
        malicious_token = jwt.encode(payload, "", algorithm="none")

        # Attempt authenticated request
        response = await async_client.get("/auth/me", headers={
            "Authorization": f"Bearer {malicious_token}"
        })

        assert response.status_code == 401, \
            "MUST reject 'none' algorithm tokens (CVE-2015-9235)"

        error_detail = response.json().get("detail", "")
        assert "Invalid token" in error_detail or "algorithm" in error_detail.lower()

    async def test_jwt_signature_stripping_attack(
        self,
        async_client: AsyncClient,
        test_user_data
    ):
        """MUST reject JWT with stripped signature

        SEVERITY: CRITICAL
        ATTACK: Remove signature to bypass verification
        """
        # Get valid token first
        login_response = await async_client.post("/auth/login", json={
            "username": test_user_data["username"],
            "password": test_user_data["password"]
        })

        valid_token = login_response.json()["access_token"]

        # Strip signature (remove last part after second '.')
        parts = valid_token.split('.')
        assert len(parts) == 3, "JWT should have 3 parts"

        stripped_token = f"{parts[0]}.{parts[1]}."  # Empty signature

        # Attempt authenticated request
        response = await async_client.get("/auth/me", headers={
            "Authorization": f"Bearer {stripped_token}"
        })

        assert response.status_code == 401, \
            "MUST reject signature-stripped tokens"

    async def test_jwt_kid_injection_attack(self, async_client: AsyncClient):
        """MUST sanitize 'kid' header to prevent injection

        SEVERITY: HIGH
        ATTACK: CVE-2018-0114 - Path traversal via 'kid'
        """
        # Create token with malicious 'kid' header
        payload = {"sub": "admin", "username": "admin"}

        malicious_token = jwt.encode(
            payload,
            "fake_secret",
            algorithm="HS256",
            headers={"kid": "../../etc/passwd"}  # Path traversal
        )

        # Attempt authenticated request
        response = await async_client.get("/auth/me", headers={
            "Authorization": f"Bearer {malicious_token}"
        })

        assert response.status_code == 401, \
            "MUST reject tokens with path traversal in 'kid'"

    async def test_jwt_replay_attack_after_logout(
        self,
        async_client: AsyncClient,
        test_user_data
    ):
        """Token MUST be blacklisted after logout

        SEVERITY: HIGH
        ATTACK: Reuse token after logout (replay attack)
        """
        # Login
        login_response = await async_client.post("/auth/login", json={
            "username": test_user_data["username"],
            "password": test_user_data["password"]
        })

        token = login_response.json()["access_token"]
        refresh_token = login_response.json()["refresh_token"]

        # Logout (blacklist token)
        logout_response = await async_client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
            json={"refresh_token": refresh_token}
        )

        assert logout_response.status_code == 200

        # Replay attack - try to use same token
        replay_response = await async_client.get("/auth/me", headers={
            "Authorization": f"Bearer {token}"
        })

        assert replay_response.status_code == 401, \
            "Blacklisted tokens MUST be rejected (replay attack)"
```

---

## TEMPLATE 3: CORS Security Tests

### tests/integration/security/test_cors_security.py
```python
"""
CORS Security Attack Vector Tests (P0 CRITICAL)

Tests Issue #5: CORS validation for production security

Attack Vectors Covered:
- Wildcard CORS in production
- Null origin (sandbox escape)
- Subdomain takeover
- HTTP downgrade attack
- Credential leak via wildcard
- Preflight cache poisoning

Author: Hestia (Security Guardian)
"""

import pytest
from httpx import AsyncClient
import os


@pytest.mark.security
@pytest.mark.integration
class TestCORSSecurityVectors:
    """P0 CRITICAL: CORS misconfiguration attacks."""

    @pytest.mark.production
    async def test_cors_wildcard_rejected_in_production(self):
        """Production MUST reject wildcard '*' CORS origin

        SEVERITY: CRITICAL
        ATTACK: Any website can make authenticated requests
        """
        # Set production environment
        os.environ["TMWS_ENVIRONMENT"] = "production"
        os.environ["TMWS_CORS_ORIGINS"] = '["*"]'

        # App initialization should FAIL
        with pytest.raises(ValueError, match="Wildcard.*not allowed in production"):
            from src.core.config_validators.cors_validator import validate_cors_origins
            validate_cors_origins(["*"], environment="production")

    async def test_cors_null_origin_rejected(self, async_client: AsyncClient):
        """MUST reject 'null' origin

        SEVERITY: CRITICAL
        ATTACK: Sandbox escape via data: URI or file:// origin
        """
        # Preflight request with 'null' origin
        response = await async_client.options(
            "/api/memories",
            headers={"Origin": "null"}
        )

        # MUST NOT have Access-Control-Allow-Origin: null
        allow_origin = response.headers.get("access-control-allow-origin")

        assert allow_origin != "null", \
            "MUST reject 'null' origin (sandbox escape attack)"

    async def test_cors_subdomain_takeover_attack(self, async_client: AsyncClient):
        """MUST reject subdomain if not explicitly allowed

        SEVERITY: HIGH
        ATTACK: Subdomain takeover → trusted CORS origin

        Scenario:
        - Allowed: https://app.example.com
        - Attack:  https://evil.example.com (attacker-controlled)
        """
        # Preflight with non-whitelisted subdomain
        response = await async_client.options(
            "/api/memories",
            headers={"Origin": "https://evil.example.com"}
        )

        allow_origin = response.headers.get("access-control-allow-origin")

        assert allow_origin != "https://evil.example.com", \
            "MUST reject non-whitelisted subdomains"

    @pytest.mark.production
    async def test_cors_http_downgrade_attack(
        self,
        async_client: AsyncClient,
        production_env
    ):
        """Production MUST reject HTTP origins (HTTPS only)

        SEVERITY: HIGH
        ATTACK: Downgrade HTTPS → HTTP to intercept requests
        """
        # Preflight with HTTP origin in production
        response = await async_client.options(
            "/api/memories",
            headers={"Origin": "http://app.example.com"}
        )

        allow_origin = response.headers.get("access-control-allow-origin")

        assert allow_origin != "http://app.example.com", \
            "Production MUST reject HTTP origins (HTTPS only)"

    async def test_cors_credential_leak_via_wildcard(
        self,
        async_client: AsyncClient
    ):
        """MUST NOT combine credentials=true with wildcard origin

        SEVERITY: CRITICAL
        ATTACK: Leak cookies/auth headers to any origin
        """
        # Preflight from untrusted origin
        response = await async_client.options(
            "/api/memories",
            headers={"Origin": "https://evil.com"}
        )

        allow_origin = response.headers.get("access-control-allow-origin")
        allow_credentials = response.headers.get("access-control-allow-credentials")

        # CRITICAL: If credentials=true, origin MUST be specific (not *)
        if allow_credentials == "true":
            assert allow_origin != "*", \
                "Wildcard origin + credentials = CRITICAL vulnerability"

    async def test_cors_preflight_cache_poisoning(
        self,
        async_client: AsyncClient
    ):
        """CORS preflight MUST have reasonable max-age

        SEVERITY: MEDIUM
        ATTACK: Long-lived cache poisoning
        """
        response = await async_client.options(
            "/api/memories",
            headers={
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "POST"
            }
        )

        max_age = response.headers.get("access-control-max-age", "0")
        max_age_int = int(max_age)

        # Max-age MUST be ≤ 24 hours (86400 seconds)
        assert max_age_int <= 86400, \
            f"CORS max-age too long ({max_age_int}s > 86400s) - cache poisoning risk"
```

---

## RUNNING THE TESTS

### Command Reference
```bash
# Run all security tests
pytest tests/integration/security/ -v -m security

# Run only P0 CRITICAL tests
pytest tests/integration/security/ -v -m "security and p0"

# Run only production security tests
pytest tests/integration/security/ -v -m "security and production"

# Run with coverage
pytest tests/integration/security/ --cov=src --cov-report=html

# Run specific test file
pytest tests/integration/security/test_cors_security.py -v

# Run with security audit output
pytest tests/integration/security/ -v --tb=short > security_audit.log 2>&1
```

### Pytest Markers
Add to pytest.ini:
```ini
[pytest]
markers =
    security: Security-focused tests
    p0: P0 CRITICAL priority
    p1: P1 HIGH priority
    p2: P2 MEDIUM priority
    production: Production environment only
    attack_vector: Attack vector simulation
```

---

## CI/CD INTEGRATION

### GitHub Actions Workflow
```yaml
name: Security Tests

on: [push, pull_request]

jobs:
  security-tests:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-asyncio pytest-cov

      - name: Run P0 CRITICAL security tests
        run: |
          pytest tests/integration/security/ \
            -v -m "security and p0" \
            --tb=short \
            --junitxml=security-report.xml

      - name: Security test must pass
        if: failure()
        run: exit 1
```

---

## SECURITY TEST CHECKLIST

Before deploying to production, ALL tests MUST pass:

### P0 CRITICAL (Must Pass - Zero Tolerance)
- [ ] Bcrypt migration security (5 tests)
- [ ] JWT attack vectors (4 tests)
- [ ] Session cookie security (4 tests)
- [ ] CORS security (6 tests)
- [ ] Production config validation (5 tests)

### P1 HIGH (Should Pass - Exceptions Require Approval)
- [ ] RBAC boundary tests (2 tests)
- [ ] SQL injection prevention (3 tests)
- [ ] XSS prevention (2 tests)
- [ ] Rate limiting bypass (2 tests)

### P2 MEDIUM (Should Pass - Document Exceptions)
- [ ] API key security (2 tests)
- [ ] Timing attack detection (2 tests)

---

**END OF IMPLEMENTATION GUIDE**
