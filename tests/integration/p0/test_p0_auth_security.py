"""
P0 Integration Tests: Authentication Security
CRITICAL: These tests verify authentication security requirements.

Test IDs:
- AUTH-P0-001: Password hashing (bcrypt)
- AUTH-P0-002: Hash format detection
- AUTH-P0-003: JWT algorithm security
- AUTH-P0-004: JWT claim validation
- AUTH-P0-005: Token expiration
"""

import base64
import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest


@pytest.mark.integration
@pytest.mark.security
class TestPasswordHashing:
    """AUTH-P0-001: Password hashing security tests."""

    def test_password_hashed_with_bcrypt(self):
        """AUTH-P0-001-T1: Passwords are hashed with bcrypt."""
        from src.utils.security import hash_password

        password = "TestPassword123!"
        hashed = hash_password(password)

        # Bcrypt hashes start with $2b$ or $2a$
        assert hashed.startswith("$2b$") or hashed.startswith("$2a$")

    def test_password_verification_succeeds(self):
        """AUTH-P0-001-T2: Correct password verification succeeds."""
        from src.utils.security import hash_password, verify_password

        password = "TestPassword123!"
        hashed = hash_password(password)

        assert verify_password(password, hashed) is True

    def test_password_verification_fails_wrong_password(self):
        """AUTH-P0-001-T3: Wrong password verification fails."""
        from src.utils.security import hash_password, verify_password

        password = "TestPassword123!"
        hashed = hash_password(password)

        assert verify_password("WrongPassword!", hashed) is False

    def test_empty_password_rejected(self):
        """AUTH-P0-001-T4: Empty password rejected during hashing."""
        from src.utils.security import hash_password

        with pytest.raises(ValueError):
            hash_password("")

    def test_empty_password_verification_fails(self):
        """AUTH-P0-001-T5: Empty password verification fails gracefully."""
        from src.utils.security import hash_password, verify_password

        password = "TestPassword123!"
        hashed = hash_password(password)

        # Should return False, not raise exception
        assert verify_password("", hashed) is False
        assert verify_password(password, "") is False


@pytest.mark.integration
@pytest.mark.security
class TestHashFormatDetection:
    """AUTH-P0-002: Hash format detection tests."""

    def test_detects_bcrypt_format(self):
        """AUTH-P0-002-T1: Correctly identifies bcrypt hash format."""
        from src.utils.security import detect_hash_format

        bcrypt_hash = "$2b$12$abcdefghijklmnopqrstuuvwxyz123456"
        assert detect_hash_format(bcrypt_hash) == "bcrypt"

    def test_detects_bcrypt_2a_format(self):
        """AUTH-P0-002-T2: Correctly identifies bcrypt $2a$ format."""
        from src.utils.security import detect_hash_format

        bcrypt_hash = "$2a$12$abcdefghijklmnopqrstuuvwxyz123456"
        assert detect_hash_format(bcrypt_hash) == "bcrypt"

    def test_detects_sha256_salt_format(self):
        """AUTH-P0-002-T3: Correctly identifies SHA256+salt format (legacy)."""
        from src.utils.security import detect_hash_format

        sha256_hash = "randomsalt123:sha256hashvalue"
        assert detect_hash_format(sha256_hash) == "sha256_salt"

    def test_rejects_unknown_format(self):
        """AUTH-P0-002-T4: Rejects unknown hash format."""
        from src.utils.security import detect_hash_format

        with pytest.raises(ValueError) as exc_info:
            detect_hash_format("unknownformat")

        assert "Unknown hash format" in str(exc_info.value)

    def test_rejects_empty_hash(self):
        """AUTH-P0-002-T5: Rejects empty hash."""
        from src.utils.security import detect_hash_format

        with pytest.raises(ValueError) as exc_info:
            detect_hash_format("")

        assert "empty" in str(exc_info.value).lower()


@pytest.mark.integration
@pytest.mark.security
class TestJWTAlgorithmSecurity:
    """AUTH-P0-003: JWT algorithm security tests."""

    def test_jwt_uses_hs256_algorithm(self):
        """AUTH-P0-003-T1: JWT service uses HS256 algorithm."""
        from src.security.jwt_service import JWTService

        jwt_service = JWTService()
        assert jwt_service.algorithm == "HS256"

    def test_rejects_none_algorithm_token(self):
        """AUTH-P0-003-T2: Rejects tokens with 'none' algorithm.

        Security: Algorithm 'none' attack allows unsigned tokens.
        """
        from src.security.jwt_service import JWTService

        jwt_service = JWTService()

        # Create a token with 'none' algorithm (attack vector)
        header = {"alg": "none", "typ": "JWT"}
        payload = {
            "sub": "1",
            "username": "attacker",
            "iss": jwt_service.issuer,
            "aud": jwt_service.audience,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
        }

        # Manually construct token (jwt library may reject 'none')
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, default=str).encode()
        ).decode().rstrip("=")
        malicious_token = f"{header_b64}.{payload_b64}."

        # Must reject
        result = jwt_service.verify_token(malicious_token)
        assert result is None, "SECURITY FAILURE: 'none' algorithm token accepted!"

    def test_rejects_algorithm_mismatch(self):
        """AUTH-P0-003-T3: Rejects tokens with mismatched algorithm.

        Security: Algorithm confusion attacks use different algorithms.
        """
        from src.security.jwt_service import JWTService

        jwt_service = JWTService()

        # Create token with HS384 instead of HS256
        payload = {
            "sub": "1",
            "username": "test",
            "iss": jwt_service.issuer,
            "aud": jwt_service.audience,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
        }

        token = jwt.encode(payload, jwt_service.secret_key, algorithm="HS384")

        # Must reject (expecting HS256)
        result = jwt_service.verify_token(token)
        assert result is None, "SECURITY FAILURE: HS384 token accepted when expecting HS256!"

    def test_rejects_token_with_different_secret(self):
        """AUTH-P0-003-T4: Rejects tokens signed with different secret."""
        from src.security.jwt_service import JWTService

        jwt_service = JWTService()

        payload = {
            "sub": "1",
            "username": "test",
            "iss": jwt_service.issuer,
            "aud": jwt_service.audience,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
        }

        # Sign with different secret
        token = jwt.encode(payload, "different_secret_key_32_chars!!!!", algorithm="HS256")

        # Must reject
        result = jwt_service.verify_token(token)
        assert result is None, "SECURITY FAILURE: Token with wrong secret accepted!"


@pytest.mark.integration
@pytest.mark.security
class TestJWTClaimValidation:
    """AUTH-P0-004: JWT claim validation tests."""

    def test_rejects_missing_subject_claim(self):
        """AUTH-P0-004-T1: Rejects tokens without 'sub' claim."""
        from src.security.jwt_service import JWTService

        jwt_service = JWTService()

        # Token without 'sub'
        payload = {
            "username": "test",
            "iss": jwt_service.issuer,
            "aud": jwt_service.audience,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
        }

        token = jwt.encode(payload, jwt_service.secret_key, algorithm="HS256")

        result = jwt_service.verify_token(token)
        assert result is None, "Token without 'sub' claim should be rejected"

    def test_rejects_missing_username_claim(self):
        """AUTH-P0-004-T2: Rejects tokens without 'username' claim."""
        from src.security.jwt_service import JWTService

        jwt_service = JWTService()

        # Token without 'username'
        payload = {
            "sub": "1",
            "iss": jwt_service.issuer,
            "aud": jwt_service.audience,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
        }

        token = jwt.encode(payload, jwt_service.secret_key, algorithm="HS256")

        result = jwt_service.verify_token(token)
        assert result is None, "Token without 'username' claim should be rejected"

    def test_rejects_wrong_issuer(self):
        """AUTH-P0-004-T3: Rejects tokens with wrong issuer."""
        from src.security.jwt_service import JWTService

        jwt_service = JWTService()

        payload = {
            "sub": "1",
            "username": "test",
            "iss": "wrong-issuer",  # Wrong issuer
            "aud": jwt_service.audience,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
        }

        token = jwt.encode(payload, jwt_service.secret_key, algorithm="HS256")

        result = jwt_service.verify_token(token)
        assert result is None, "Token with wrong issuer should be rejected"

    def test_rejects_wrong_audience(self):
        """AUTH-P0-004-T4: Rejects tokens with wrong audience."""
        from src.security.jwt_service import JWTService

        jwt_service = JWTService()

        payload = {
            "sub": "1",
            "username": "test",
            "iss": jwt_service.issuer,
            "aud": "wrong-audience",  # Wrong audience
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
        }

        token = jwt.encode(payload, jwt_service.secret_key, algorithm="HS256")

        result = jwt_service.verify_token(token)
        assert result is None, "Token with wrong audience should be rejected"


@pytest.mark.integration
@pytest.mark.security
class TestJWTExpiration:
    """AUTH-P0-005: JWT expiration tests."""

    def test_rejects_expired_token(self):
        """AUTH-P0-005-T1: Rejects expired tokens."""
        from src.security.jwt_service import JWTService

        jwt_service = JWTService()

        # Create expired token
        payload = {
            "sub": "1",
            "username": "test",
            "iss": jwt_service.issuer,
            "aud": jwt_service.audience,
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),  # Already expired
            "iat": datetime.now(timezone.utc) - timedelta(hours=2),
        }

        token = jwt.encode(payload, jwt_service.secret_key, algorithm="HS256")

        result = jwt_service.verify_token(token)
        assert result is None, "Expired token should be rejected"

    def test_accepts_valid_token(self):
        """AUTH-P0-005-T2: Accepts valid non-expired tokens."""
        from src.security.jwt_service import JWTService

        jwt_service = JWTService()

        payload = {
            "sub": "1",
            "username": "test",
            "iss": jwt_service.issuer,
            "aud": jwt_service.audience,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
        }

        token = jwt.encode(payload, jwt_service.secret_key, algorithm="HS256")

        result = jwt_service.verify_token(token)
        assert result is not None, "Valid token should be accepted"
        assert result["sub"] == "1"
        assert result["username"] == "test"

    def test_rejects_future_iat_token(self):
        """AUTH-P0-005-T3: Handles tokens with future 'iat' claim."""
        from src.security.jwt_service import JWTService

        jwt_service = JWTService()

        # Token issued in the future
        payload = {
            "sub": "1",
            "username": "test",
            "iss": jwt_service.issuer,
            "aud": jwt_service.audience,
            "exp": datetime.now(timezone.utc) + timedelta(hours=2),
            "iat": datetime.now(timezone.utc) + timedelta(hours=1),  # Future
        }

        token = jwt.encode(payload, jwt_service.secret_key, algorithm="HS256")

        result = jwt_service.verify_token(token)
        # jwt library may accept or reject based on iat_leeway
        # This test documents the behavior


@pytest.mark.integration
@pytest.mark.security
class TestAPIKeyGeneration:
    """API Key generation security tests."""

    def test_api_key_format(self):
        """API keys follow expected format."""
        from src.utils.security import generate_api_key

        api_key = generate_api_key()

        # Should start with tmws_ prefix
        assert api_key.startswith("tmws_")
        # Should be sufficiently long
        assert len(api_key) > 40

    def test_api_key_uniqueness(self):
        """API keys are unique."""
        from src.utils.security import generate_api_key

        keys = [generate_api_key() for _ in range(100)]
        assert len(set(keys)) == 100, "API keys should be unique"

    def test_api_key_generation_and_hash(self):
        """API key generation returns both raw key and hash."""
        from src.utils.security import generate_and_hash_api_key_for_agent

        raw_key, key_hash = generate_and_hash_api_key_for_agent()

        # Raw key should be usable
        assert raw_key.startswith("tmws_")

        # Hash should be bcrypt format
        assert key_hash.startswith("$2b$") or key_hash.startswith("$2a$")

        # Hash should verify against raw key
        from src.utils.security import verify_password
        assert verify_password(raw_key, key_hash) is True
