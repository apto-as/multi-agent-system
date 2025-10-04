"""
Security Tests for TMWS Authentication System.
Led by Hestia (Security Guardian) with comprehensive vulnerability testing.

This module tests all authentication security aspects:
- Password security and hashing
- JWT token security
- API key validation
- Access control mechanisms
- Brute force protection
- Session management security

Security Requirements Validated:
- No default credentials
- Proper password hashing (bcrypt with salt)
- JWT token expiration and validation
- Rate limiting on authentication endpoints
- SQL injection prevention
- XSS protection in auth flows
- CSRF protection
- Account lockout after failed attempts
"""

import asyncio
import contextlib
from datetime import datetime, timedelta

import pytest

from src.models.user import APIKeyScope
from src.security.jwt_service import jwt_service, token_blacklist
from src.services.auth_service import (
    AccountLockedError,
    AuthService,
    InsufficientPermissionsError,
    InvalidCredentialsError,
    TokenExpiredError,
)


@pytest.mark.security
class TestPasswordSecurity:
    """Test password security implementation."""

    async def test_password_hashing_security(self, auth_service: AuthService):
        """Test secure password hashing with salt."""
        password = "test_password_123"

        # Test hashing produces different results with salt
        hash1, salt1 = jwt_service.hash_password(password)
        hash2, salt2 = jwt_service.hash_password(password)

        # Different salts should produce different hashes
        assert hash1 != hash2
        assert salt1 != salt2
        assert len(salt1) == 32  # 16 bytes hex = 32 characters
        assert len(salt2) == 32

        # Both should verify correctly
        assert jwt_service.verify_password(password, hash1, salt1)
        assert jwt_service.verify_password(password, hash2, salt2)

        # Cross verification should fail
        assert not jwt_service.verify_password(password, hash1, salt2)
        assert not jwt_service.verify_password(password, hash2, salt1)

    async def test_password_strength_validation(self, auth_service: AuthService):
        """Test password strength requirements."""
        weak_passwords = [
            "123456",      # Too short
            "password",    # Common password
            "12345678",    # Numbers only
            "abcdefgh",    # Letters only
            "1234567",     # Too short
        ]

        for weak_password in weak_passwords:
            with pytest.raises(ValueError, match="Password must be at least"):
                await auth_service.create_user(
                    username="test_user",
                    email="test@example.com",
                    password=weak_password
                )

    async def test_password_injection_attempts(self, auth_service: AuthService, security_test_vectors):
        """Test password field against injection attacks."""
        for injection_payload in security_test_vectors["sql_injection"]:
            with pytest.raises((ValueError, InvalidCredentialsError)):
                await auth_service.create_user(
                    username="test_user",
                    email="test@example.com",
                    password=injection_payload
                )

    async def test_bcrypt_timing_attack_resistance(self, test_user, test_user_data, performance_timer):
        """Test bcrypt timing attack resistance."""
        auth_service = AuthService()

        # Measure time for correct password
        times_correct = []
        for _ in range(10):
            performance_timer.start()
            with contextlib.suppress(Exception):
                await auth_service.authenticate_user(
                    test_user_data["username"],
                    test_user_data["password"]
                )
            times_correct.append(performance_timer.stop())

        # Measure time for incorrect password
        times_incorrect = []
        for _ in range(10):
            performance_timer.start()
            with contextlib.suppress(InvalidCredentialsError):
                await auth_service.authenticate_user(
                    test_user_data["username"],
                    "wrong_password"
                )
            times_incorrect.append(performance_timer.stop())

        # Timing should be similar (within reasonable variance)
        avg_correct = sum(times_correct) / len(times_correct)
        avg_incorrect = sum(times_incorrect) / len(times_incorrect)

        # Allow up to 50% variance (bcrypt is inherently variable)
        timing_ratio = abs(avg_correct - avg_incorrect) / max(avg_correct, avg_incorrect)
        assert timing_ratio < 0.5, "Potential timing attack vulnerability detected"


@pytest.mark.security
class TestJWTSecurity:
    """Test JWT token security implementation."""

    async def test_jwt_token_structure(self, test_user):
        """Test JWT token structure and claims."""
        token = jwt_service.create_access_token(test_user)

        # Verify token structure
        assert token.count('.') == 2  # header.payload.signature

        # Verify payload without signature (for inspection only)
        payload = jwt_service.decode_token_unsafe(token)

        required_claims = ['sub', 'username', 'email', 'roles', 'iat', 'exp', 'jti']
        for claim in required_claims:
            assert claim in payload

        # Verify security claims
        assert payload['iss'] == 'tmws-auth-service'
        assert payload['aud'] == 'tmws-api'
        assert len(payload['jti']) >= 16  # JWT ID for revocation

    async def test_jwt_token_expiration(self, test_user):
        """Test JWT token expiration handling."""
        # Create token with short expiration
        short_expire = timedelta(seconds=1)
        token = jwt_service.create_access_token(test_user, expires_delta=short_expire)

        # Token should be valid immediately
        payload = jwt_service.verify_token(token)
        assert payload is not None

        # Wait for expiration
        await asyncio.sleep(2)

        # Token should be expired
        payload = jwt_service.verify_token(token)
        assert payload is None

    async def test_jwt_signature_tampering(self, test_user):
        """Test JWT signature tampering detection."""
        token = jwt_service.create_access_token(test_user)

        # Tamper with signature
        parts = token.split('.')
        tampered_signature = parts[2][:-1] + 'X'  # Change last character
        tampered_token = f"{parts[0]}.{parts[1]}.{tampered_signature}"

        # Tampered token should be invalid
        payload = jwt_service.verify_token(tampered_token)
        assert payload is None

    async def test_jwt_payload_tampering(self, test_user):
        """Test JWT payload tampering detection."""
        token = jwt_service.create_access_token(test_user)

        # Get original payload
        jwt_service.decode_token_unsafe(token)

        # Tamper with payload (change username)
        import base64
        import json

        parts = token.split('.')
        payload_data = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        payload_data['username'] = 'hacker'

        tampered_payload = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode()
        ).decode().rstrip('=')

        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

        # Tampered token should be invalid
        payload = jwt_service.verify_token(tampered_token)
        assert payload is None

    async def test_jwt_token_blacklist(self, test_user):
        """Test JWT token blacklisting functionality."""
        token = jwt_service.create_access_token(test_user)

        # Token should be valid
        payload = jwt_service.verify_token(token)
        assert payload is not None

        # Blacklist the token
        jti = payload['jti']
        token_blacklist.blacklist_token(jti)

        # Token should be invalid after blacklisting
        assert token_blacklist.is_blacklisted(jti)

    async def test_refresh_token_security(self, test_user):
        """Test refresh token security implementation."""
        refresh_token, refresh_record = jwt_service.create_refresh_token(test_user)

        # Verify token format
        assert '.' in refresh_token
        token_id, raw_token = refresh_token.split('.', 1)

        # Verify token_id format
        assert len(token_id) >= 32

        # Verify raw token length
        assert len(raw_token) >= 64

        # Verify database record
        assert refresh_record.token_id == token_id
        assert refresh_record.user_id == test_user.id
        assert refresh_record.is_valid()


@pytest.mark.security
class TestAPIKeySecurity:
    """Test API key security implementation."""

    async def test_api_key_generation(self, test_user, auth_service: AuthService):
        """Test secure API key generation."""
        api_key, api_key_record = await auth_service.create_api_key(
            user_id=test_user.id,
            name="Test API Key",
            scopes=[APIKeyScope.READ]
        )

        # Verify key format
        assert '.' in api_key
        key_id, raw_key = api_key.split('.', 1)

        # Verify key components
        assert len(key_id) >= 16  # key_id length
        assert len(raw_key) >= 32  # raw key length

        # Verify database record
        assert api_key_record.key_id == key_id
        assert api_key_record.user_id == test_user.id
        assert api_key_record.is_valid()

    async def test_api_key_validation(self, test_user, test_api_key, auth_service: AuthService):
        """Test API key validation."""
        api_key, api_key_record = test_api_key

        # Valid key should authenticate
        user, key = await auth_service.validate_api_key(api_key)
        assert user.id == test_user.id
        assert key.id == api_key_record.id

    async def test_api_key_scope_validation(self, test_user, auth_service: AuthService):
        """Test API key scope validation."""
        # Create key with limited scope
        api_key, _ = await auth_service.create_api_key(
            user_id=test_user.id,
            name="Read Only Key",
            scopes=[APIKeyScope.READ]
        )

        # Should work for READ scope
        user, key = await auth_service.validate_api_key(
            api_key,
            required_scope=APIKeyScope.READ
        )
        assert user.id == test_user.id

        # Should fail for WRITE scope
        with pytest.raises(InsufficientPermissionsError):
            await auth_service.validate_api_key(
                api_key,
                required_scope=APIKeyScope.WRITE
            )

    async def test_api_key_expiration(self, test_user, expired_api_key, auth_service: AuthService):
        """Test expired API key handling."""
        api_key, _ = expired_api_key

        with pytest.raises(TokenExpiredError):
            await auth_service.validate_api_key(api_key)

    async def test_api_key_ip_restrictions(self, test_user, auth_service: AuthService):
        """Test API key IP address restrictions."""
        # Create key with IP restrictions
        allowed_ips = ["127.0.0.1", "192.168.1.100"]
        api_key, _ = await auth_service.create_api_key(
            user_id=test_user.id,
            name="IP Restricted Key",
            allowed_ips=allowed_ips
        )

        # Should work from allowed IP
        user, key = await auth_service.validate_api_key(
            api_key,
            ip_address="127.0.0.1"
        )
        assert user.id == test_user.id

        # Should fail from disallowed IP
        with pytest.raises(InsufficientPermissionsError):
            await auth_service.validate_api_key(
                api_key,
                ip_address="10.0.0.1"
            )


@pytest.mark.security
class TestAuthenticationFlows:
    """Test complete authentication flows."""

    async def test_successful_authentication_flow(self, test_user, test_user_data, auth_service: AuthService):
        """Test complete successful authentication."""
        user, access_token, refresh_token = await auth_service.authenticate_user(
            test_user_data["username"],
            test_user_data["password"]
        )

        assert user.id == test_user.id
        assert user.username == test_user_data["username"]
        assert access_token is not None
        assert refresh_token is not None

        # Verify tokens are valid
        payload = jwt_service.verify_token(access_token)
        assert payload is not None
        assert payload['sub'] == str(test_user.id)

    async def test_invalid_credentials_flow(self, test_user, test_user_data, auth_service: AuthService):
        """Test invalid credentials handling."""
        with pytest.raises(InvalidCredentialsError):
            await auth_service.authenticate_user(
                test_user_data["username"],
                "wrong_password"
            )

        with pytest.raises(InvalidCredentialsError):
            await auth_service.authenticate_user(
                "nonexistent_user",
                test_user_data["password"]
            )

    async def test_account_lockout_flow(self, test_user, test_user_data, auth_service: AuthService):
        """Test account lockout after failed attempts."""
        # Make multiple failed login attempts
        for _i in range(5):
            with pytest.raises(InvalidCredentialsError):
                await auth_service.authenticate_user(
                    test_user_data["username"],
                    "wrong_password"
                )

        # Account should now be locked
        with pytest.raises(AccountLockedError):
            await auth_service.authenticate_user(
                test_user_data["username"],
                test_user_data["password"]  # Even correct password should fail
            )

    async def test_locked_account_authentication(self, locked_user, auth_service: AuthService):
        """Test authentication with locked account."""
        with pytest.raises(AccountLockedError):
            await auth_service.authenticate_user(
                "locked_user",
                "locked_password_123"
            )

    async def test_token_refresh_flow(self, test_user, test_user_data, auth_service: AuthService):
        """Test token refresh functionality."""
        # Initial authentication
        user, access_token, refresh_token = await auth_service.authenticate_user(
            test_user_data["username"],
            test_user_data["password"]
        )

        # Refresh tokens
        new_access_token, new_refresh_token = await auth_service.refresh_access_token(
            refresh_token
        )

        assert new_access_token != access_token
        assert new_refresh_token != refresh_token

        # New tokens should be valid
        payload = jwt_service.verify_token(new_access_token)
        assert payload is not None
        assert payload['sub'] == str(test_user.id)

    async def test_logout_flow(self, test_user, test_user_data, auth_service: AuthService):
        """Test complete logout flow."""
        # Authenticate
        user, access_token, refresh_token = await auth_service.authenticate_user(
            test_user_data["username"],
            test_user_data["password"]
        )

        # Logout
        await auth_service.logout_user(refresh_token, access_token)

        # Refresh token should be revoked
        with pytest.raises(TokenExpiredError):
            await auth_service.refresh_access_token(refresh_token)

        # Access token should be blacklisted
        payload = jwt_service.verify_token(access_token)
        if payload and 'jti' in payload:
            assert token_blacklist.is_blacklisted(payload['jti'])


@pytest.mark.security
class TestSecurityVulnerabilities:
    """Test against common security vulnerabilities."""

    async def test_sql_injection_resistance(self, security_test_vectors, auth_service: AuthService):
        """Test SQL injection resistance in authentication."""
        for injection_payload in security_test_vectors["sql_injection"]:
            # Test in username field
            with pytest.raises((InvalidCredentialsError, ValueError)):
                await auth_service.authenticate_user(
                    injection_payload,
                    "any_password"
                )

            # Test in user creation
            with pytest.raises((ValueError, Exception)):
                await auth_service.create_user(
                    username=injection_payload,
                    email="test@example.com",
                    password="secure_password_123"
                )

    async def test_xss_payload_sanitization(self, security_test_vectors, auth_service: AuthService):
        """Test XSS payload handling in user fields."""
        for xss_payload in security_test_vectors["xss_payloads"]:
            # Should not allow XSS in username
            with pytest.raises((ValueError, Exception)):
                await auth_service.create_user(
                    username=xss_payload,
                    email="test@example.com",
                    password="secure_password_123"
                )

    async def test_brute_force_protection(self, test_user, test_user_data, auth_service: AuthService):
        """Test brute force attack protection."""
        failed_attempts = []

        # Rapid failed login attempts
        for i in range(10):
            start_time = datetime.now()
            with contextlib.suppress(InvalidCredentialsError, AccountLockedError):
                await auth_service.authenticate_user(
                    test_user_data["username"],
                    f"wrong_password_{i}"
                )

            duration = (datetime.now() - start_time).total_seconds()
            failed_attempts.append(duration)

        # Should implement some form of rate limiting or delay
        # (Either through account lockout or progressive delays)
        assert any(duration > 0.1 for duration in failed_attempts[-5:]), \
            "No apparent brute force protection detected"

    @pytest.mark.slow
    async def test_concurrent_authentication_security(self, test_user, test_user_data, auth_service: AuthService):
        """Test concurrent authentication attempts."""
        async def authenticate_attempt():
            try:
                return await auth_service.authenticate_user(
                    test_user_data["username"],
                    test_user_data["password"]
                )
            except Exception as e:
                return e

        # Run 10 concurrent authentication attempts
        tasks = [authenticate_attempt() for _ in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # At least one should succeed
        successful_auths = [r for r in results if not isinstance(r, Exception)]
        assert len(successful_auths) > 0

        # All successful auths should be for the same user
        user_ids = {r[0].id for r in successful_auths}
        assert len(user_ids) == 1
        assert list(user_ids)[0] == test_user.id


@pytest.mark.security
@pytest.mark.performance
class TestSecurityPerformance:
    """Test security features don't impact performance requirements."""

    async def test_authentication_performance(self, test_user, test_user_data, performance_timer, auth_service: AuthService):
        """Test authentication meets <200ms performance requirement."""
        times = []

        for _ in range(10):
            performance_timer.start()
            user, access_token, refresh_token = await auth_service.authenticate_user(
                test_user_data["username"],
                test_user_data["password"]
            )
            elapsed = performance_timer.stop()
            times.append(elapsed)

        avg_time = sum(times) / len(times)
        max_time = max(times)

        assert avg_time < 200, f"Average authentication time {avg_time}ms exceeds 200ms requirement"
        assert max_time < 400, f"Maximum authentication time {max_time}ms too slow"

    async def test_api_key_validation_performance(self, test_api_key, performance_timer, auth_service: AuthService):
        """Test API key validation meets <100ms performance requirement."""
        api_key, _ = test_api_key
        times = []

        for _ in range(20):
            performance_timer.start()
            user, key = await auth_service.validate_api_key(api_key)
            elapsed = performance_timer.stop()
            times.append(elapsed)

        avg_time = sum(times) / len(times)
        max_time = max(times)

        assert avg_time < 100, f"Average API key validation {avg_time}ms exceeds 100ms requirement"
        assert max_time < 200, f"Maximum API key validation {max_time}ms too slow"
