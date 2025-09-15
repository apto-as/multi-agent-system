"""
Unit Tests for JWTService - JWT Token Management.
Led by Artemis (Technical Perfectionist) with focus on cryptographic security and performance.

This module tests all JWT service functionality including:
- Token generation and validation
- Password hashing and verification
- Token expiration handling
- Security features (blacklist, tampering detection)
- Performance requirements (<200ms for token operations)
"""

import pytest
import time
import secrets
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from src.security.jwt_service import (
    JWTService, 
    TokenBlacklist,
    jwt_service,
    token_blacklist,
    create_tokens_for_user,
    verify_and_extract_user,
    hash_password,
    verify_password
)
from src.models.user import User, UserRole


@pytest.mark.unit
class TestJWTServiceInitialization:
    """Test JWT service initialization and configuration."""
    
    def test_jwt_service_initialization(self):
        """Test JWT service initializes with correct configuration."""
        service = JWTService()
        
        assert service.algorithm == "HS256"
        assert service.issuer == "tmws-auth-service"
        assert service.audience == "tmws-api"
        assert service.access_token_expire_minutes == 15
        assert service.refresh_token_expire_days == 30
        
        # Verify cryptographic settings
        assert service.pwd_context.schemes == ["bcrypt"]
        assert service._base_claims["iss"] == "tmws-auth-service"
        assert service._base_claims["aud"] == "tmws-api"
    
    def test_jwt_service_secret_key_validation(self):
        """Test JWT service validates secret key length."""
        with patch('src.security.jwt_service.get_settings') as mock_settings:
            mock_settings.return_value.TMWS_SECRET_KEY = "short_key"
            
            with pytest.raises(ValueError, match="JWT secret key must be at least 32 characters"):
                JWTService()
    
    def test_jwt_service_singleton_behavior(self):
        """Test that jwt_service is properly configured."""
        assert isinstance(jwt_service, JWTService)
        assert jwt_service.secret_key is not None
        assert len(jwt_service.secret_key) >= 32


@pytest.mark.unit
class TestPasswordHashing:
    """Test password hashing and verification."""
    
    def test_password_hashing_produces_different_results(self):
        """Test that password hashing produces different results each time."""
        password = "test_password_123"
        
        hash1, salt1 = jwt_service.hash_password(password)
        hash2, salt2 = jwt_service.hash_password(password)
        
        # Different salts should produce different hashes
        assert hash1 != hash2
        assert salt1 != salt2
        assert len(salt1) == 32  # 16 bytes hex = 32 chars
        assert len(salt2) == 32
    
    def test_password_verification_success(self):
        """Test successful password verification."""
        password = "secure_password_123"
        password_hash, salt = jwt_service.hash_password(password)
        
        assert jwt_service.verify_password(password, password_hash, salt)
    
    def test_password_verification_failure(self):
        """Test password verification with wrong password."""
        password = "secure_password_123"
        wrong_password = "wrong_password"
        password_hash, salt = jwt_service.hash_password(password)
        
        assert not jwt_service.verify_password(wrong_password, password_hash, salt)
    
    def test_password_verification_wrong_salt(self):
        """Test password verification with wrong salt."""
        password = "secure_password_123"
        password_hash, salt = jwt_service.hash_password(password)
        wrong_salt = secrets.token_hex(16)
        
        assert not jwt_service.verify_password(password, password_hash, wrong_salt)
    
    @pytest.mark.performance
    def test_password_hashing_performance(self, performance_timer):
        """Test password hashing meets reasonable performance requirements."""
        password = "performance_test_password_123"
        times = []
        
        for _ in range(10):
            performance_timer.start()
            hash_password(password)
            elapsed = performance_timer.stop()
            times.append(elapsed)
        
        avg_time = sum(times) / len(times)
        max_time = max(times)
        
        # Password hashing should be reasonable but secure (allow up to 1 second)
        assert avg_time < 1000, f"Average password hashing time {avg_time}ms too slow"
        assert max_time < 2000, f"Maximum password hashing time {max_time}ms too slow"
    
    def test_convenience_functions(self):
        """Test convenience functions work correctly."""
        password = "test_convenience_password"
        
        # Test convenience hash function
        password_hash, salt = hash_password(password)
        assert len(password_hash) > 50  # bcrypt hash length
        assert len(salt) == 32
        
        # Test convenience verify function
        assert verify_password(password, password_hash, salt)
        assert not verify_password("wrong", password_hash, salt)


@pytest.mark.unit
class TestAccessTokenGeneration:
    """Test access token generation and validation."""
    
    @pytest.fixture
    def test_user(self):
        """Create test user for token tests."""
        return User(
            id="test-user-id",
            username="testuser",
            email="test@example.com",
            roles=[UserRole.USER],
            agent_namespace="test",
            preferred_agent_id="test-agent"
        )
    
    def test_create_access_token_structure(self, test_user):
        """Test access token has correct structure."""
        token = jwt_service.create_access_token(test_user)
        
        # JWT should have 3 parts
        assert token.count('.') == 2
        
        # Should be able to decode (insecurely for testing)
        payload = jwt_service.decode_token_unsafe(token)
        
        # Check required claims
        required_claims = ['sub', 'username', 'email', 'roles', 'iat', 'exp', 'jti']
        for claim in required_claims:
            assert claim in payload
        
        # Check claim values
        assert payload['sub'] == str(test_user.id)
        assert payload['username'] == test_user.username
        assert payload['email'] == test_user.email
        assert payload['roles'] == [role.value for role in test_user.roles]
        assert payload['agent_namespace'] == test_user.agent_namespace
        assert payload['preferred_agent_id'] == test_user.preferred_agent_id
        assert payload['iss'] == jwt_service.issuer
        assert payload['aud'] == jwt_service.audience
    
    def test_create_access_token_expiration(self, test_user):
        """Test access token expiration setting."""
        token = jwt_service.create_access_token(test_user)
        payload = jwt_service.decode_token_unsafe(token)
        
        issued_at = datetime.fromtimestamp(payload['iat'], tz=timezone.utc)
        expires_at = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
        
        expected_duration = timedelta(minutes=jwt_service.access_token_expire_minutes)
        actual_duration = expires_at - issued_at
        
        # Allow 1 minute variance for test execution
        assert abs((actual_duration - expected_duration).total_seconds()) < 60
    
    def test_create_access_token_custom_expiration(self, test_user):
        """Test access token with custom expiration."""
        custom_expiry = timedelta(minutes=30)
        token = jwt_service.create_access_token(test_user, expires_delta=custom_expiry)
        payload = jwt_service.decode_token_unsafe(token)
        
        issued_at = datetime.fromtimestamp(payload['iat'], tz=timezone.utc)
        expires_at = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
        
        actual_duration = expires_at - issued_at
        assert abs((actual_duration - custom_expiry).total_seconds()) < 60
    
    def test_create_access_token_additional_claims(self, test_user):
        """Test access token with additional claims."""
        additional_claims = {
            "custom_claim": "custom_value",
            "permissions": ["read", "write"]
        }
        
        token = jwt_service.create_access_token(test_user, additional_claims=additional_claims)
        payload = jwt_service.decode_token_unsafe(token)
        
        assert payload['custom_claim'] == "custom_value"
        assert payload['permissions'] == ["read", "write"]
    
    @pytest.mark.performance
    def test_create_access_token_performance(self, test_user, performance_timer):
        """Test access token generation meets <200ms requirement."""
        times = []
        
        for _ in range(50):
            performance_timer.start()
            token = jwt_service.create_access_token(test_user)
            elapsed = performance_timer.stop()
            times.append(elapsed)
        
        avg_time = sum(times) / len(times)
        max_time = max(times)
        
        assert avg_time < 50, f"Average token generation {avg_time}ms too slow"
        assert max_time < 200, f"Maximum token generation {max_time}ms exceeds requirement"
    
    def test_create_access_token_uniqueness(self, test_user):
        """Test that each access token is unique."""
        tokens = [jwt_service.create_access_token(test_user) for _ in range(10)]
        
        # All tokens should be different
        assert len(set(tokens)) == len(tokens)
        
        # JTI claims should all be different
        jtis = []
        for token in tokens:
            payload = jwt_service.decode_token_unsafe(token)
            jtis.append(payload['jti'])
        
        assert len(set(jtis)) == len(jtis)


@pytest.mark.unit
class TestTokenValidation:
    """Test token validation functionality."""
    
    @pytest.fixture
    def test_user(self):
        return User(
            id="test-user-id",
            username="testuser", 
            email="test@example.com",
            roles=[UserRole.USER],
            agent_namespace="test"
        )
    
    def test_verify_valid_token(self, test_user):
        """Test verification of valid token."""
        token = jwt_service.create_access_token(test_user)
        payload = jwt_service.verify_token(token)
        
        assert payload is not None
        assert payload['sub'] == str(test_user.id)
        assert payload['username'] == test_user.username
    
    def test_verify_expired_token(self, test_user):
        """Test verification of expired token."""
        # Create token with very short expiry
        expired_token = jwt_service.create_access_token(
            test_user, 
            expires_delta=timedelta(seconds=-1)  # Already expired
        )
        
        payload = jwt_service.verify_token(expired_token)
        assert payload is None
    
    def test_verify_invalid_signature(self, test_user):
        """Test verification with invalid signature."""
        token = jwt_service.create_access_token(test_user)
        
        # Tamper with signature
        parts = token.split('.')
        tampered_signature = parts[2][:-1] + 'X'
        tampered_token = f"{parts[0]}.{parts[1]}.{tampered_signature}"
        
        payload = jwt_service.verify_token(tampered_token)
        assert payload is None
    
    def test_verify_malformed_token(self):
        """Test verification of malformed token."""
        malformed_tokens = [
            "not.a.token",
            "only.two.parts",
            "",
            "single_string_token",
            "too.many.parts.here.invalid"
        ]
        
        for token in malformed_tokens:
            payload = jwt_service.verify_token(token)
            assert payload is None
    
    @pytest.mark.performance
    def test_verify_token_performance(self, test_user, performance_timer):
        """Test token verification meets <200ms requirement."""
        token = jwt_service.create_access_token(test_user)
        times = []
        
        for _ in range(100):
            performance_timer.start()
            payload = jwt_service.verify_token(token)
            elapsed = performance_timer.stop()
            times.append(elapsed)
        
        avg_time = sum(times) / len(times)
        max_time = max(times)
        
        assert avg_time < 20, f"Average token verification {avg_time}ms too slow"
        assert max_time < 200, f"Maximum token verification {max_time}ms exceeds requirement"
    
    def test_verify_and_extract_user_integration(self, test_user):
        """Test integrated verification and user extraction."""
        token = jwt_service.create_access_token(test_user)
        user_info = verify_and_extract_user(token)
        
        assert user_info is not None
        assert user_info['user_id'] == str(test_user.id)
        assert user_info['username'] == test_user.username
        assert user_info['email'] == test_user.email
        assert user_info['roles'] == [role.value for role in test_user.roles]
        assert user_info['agent_namespace'] == test_user.agent_namespace


@pytest.mark.unit
class TestRefreshTokens:
    """Test refresh token functionality."""
    
    @pytest.fixture
    def test_user(self):
        return User(
            id="test-user-id",
            username="testuser",
            email="test@example.com"
        )
    
    def test_create_refresh_token_format(self, test_user):
        """Test refresh token creation and format."""
        refresh_token, refresh_record = jwt_service.create_refresh_token(test_user)
        
        # Should have correct format
        assert '.' in refresh_token
        token_id, raw_token = refresh_token.split('.', 1)
        
        assert len(token_id) >= 32
        assert len(raw_token) >= 64
        
        # Record should be created correctly
        assert refresh_record.token_id == token_id
        assert refresh_record.user_id == test_user.id
        assert refresh_record.expires_at > datetime.now(timezone.utc)
    
    def test_verify_refresh_token_format(self, test_user):
        """Test refresh token format verification."""
        refresh_token, _ = jwt_service.create_refresh_token(test_user)
        token_id = jwt_service.verify_refresh_token(refresh_token)
        
        assert token_id is not None
        assert len(token_id) >= 32
    
    def test_verify_refresh_token_invalid_format(self):
        """Test refresh token verification with invalid formats."""
        invalid_tokens = [
            "invalid_format",
            "no_dot_separator",
            "",
            "short.token",
            "very_short_token_id.token_part"
        ]
        
        for invalid_token in invalid_tokens:
            token_id = jwt_service.verify_refresh_token(invalid_token)
            assert token_id is None
    
    def test_verify_refresh_token_hash(self, test_user):
        """Test refresh token hash verification."""
        refresh_token, refresh_record = jwt_service.create_refresh_token(test_user)
        _, raw_token = refresh_token.split('.', 1)
        
        # Correct token should verify
        assert jwt_service.verify_refresh_token_hash(raw_token, refresh_record.token_hash)
        
        # Wrong token should not verify
        assert not jwt_service.verify_refresh_token_hash("wrong_token", refresh_record.token_hash)


@pytest.mark.unit
class TestAPIKeyTokens:
    """Test API key token functionality."""
    
    @pytest.fixture
    def test_user(self):
        return User(
            id="test-user-id",
            username="testuser",
            email="test@example.com",
            agent_namespace="test"
        )
    
    def test_create_api_key_token(self, test_user):
        """Test API key token creation."""
        api_key_id = "test-api-key-123"
        scopes = ["read", "write"]
        
        token = jwt_service.create_api_key_token(api_key_id, test_user, scopes)
        payload = jwt_service.decode_token_unsafe(token)
        
        assert payload['sub'] == str(test_user.id)
        assert payload['username'] == test_user.username
        assert payload['api_key_id'] == api_key_id
        assert payload['scopes'] == scopes
        assert payload['token_type'] == "api_key"
        assert payload['agent_namespace'] == test_user.agent_namespace
    
    def test_create_api_key_token_expiration(self, test_user):
        """Test API key token expiration."""
        api_key_id = "test-api-key-123"
        scopes = ["read"]
        custom_expiry = timedelta(hours=12)
        
        token = jwt_service.create_api_key_token(
            api_key_id, test_user, scopes, expires_delta=custom_expiry
        )
        payload = jwt_service.decode_token_unsafe(token)
        
        issued_at = datetime.fromtimestamp(payload['iat'], tz=timezone.utc)
        expires_at = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
        actual_duration = expires_at - issued_at
        
        assert abs((actual_duration - custom_expiry).total_seconds()) < 60


@pytest.mark.unit
class TestTokenBlacklist:
    """Test token blacklist functionality."""
    
    def test_blacklist_token(self):
        """Test token blacklisting."""
        blacklist = TokenBlacklist()
        test_jti = "test-jwt-id-123"
        
        # Initially not blacklisted
        assert not blacklist.is_blacklisted(test_jti)
        
        # Blacklist token
        blacklist.blacklist_token(test_jti)
        assert blacklist.is_blacklisted(test_jti)
    
    def test_multiple_blacklist_operations(self):
        """Test multiple blacklist operations."""
        blacklist = TokenBlacklist()
        jtis = [f"test-jti-{i}" for i in range(10)]
        
        # Blacklist multiple tokens
        for jti in jtis:
            blacklist.blacklist_token(jti)
        
        # All should be blacklisted
        for jti in jtis:
            assert blacklist.is_blacklisted(jti)
        
        # Non-blacklisted token should not be affected
        assert not blacklist.is_blacklisted("non-blacklisted-token")
    
    def test_global_blacklist_instance(self):
        """Test global blacklist instance."""
        assert isinstance(token_blacklist, TokenBlacklist)
        
        test_jti = "global-test-jti"
        token_blacklist.blacklist_token(test_jti)
        assert token_blacklist.is_blacklisted(test_jti)


@pytest.mark.unit
class TestTokenUtilities:
    """Test token utility functions."""
    
    @pytest.fixture
    def test_user(self):
        return User(
            id="test-user-id",
            username="testuser",
            email="test@example.com",
            roles=[UserRole.USER]
        )
    
    def test_create_tokens_for_user(self, test_user):
        """Test convenience function for creating tokens."""
        access_token, refresh_token = create_tokens_for_user(test_user)
        
        # Verify access token
        payload = jwt_service.verify_token(access_token)
        assert payload is not None
        assert payload['sub'] == str(test_user.id)
        
        # Verify refresh token format
        assert '.' in refresh_token
        token_id = jwt_service.verify_refresh_token(refresh_token)
        assert token_id is not None
    
    def test_get_token_expiry(self, test_user):
        """Test token expiry extraction."""
        token = jwt_service.create_access_token(test_user)
        expiry = jwt_service.get_token_expiry(token)
        
        assert expiry is not None
        assert isinstance(expiry, datetime)
        assert expiry > datetime.now(timezone.utc)
    
    def test_validate_token_claims(self):
        """Test token claims validation."""
        payload = {
            'sub': 'user-123',
            'username': 'testuser',
            'roles': ['user'],
            'exp': time.time() + 3600
        }
        
        required_claims = ['sub', 'username', 'roles']
        assert jwt_service.validate_token_claims(payload, required_claims)
        
        # Missing claim
        required_claims_missing = ['sub', 'username', 'missing_claim']
        assert not jwt_service.validate_token_claims(payload, required_claims_missing)
    
    def test_extract_user_info(self):
        """Test user info extraction from payload."""
        payload = {
            'sub': 'user-123',
            'username': 'testuser',
            'email': 'test@example.com',
            'roles': ['user', 'admin'],
            'agent_namespace': 'test_ns',
            'preferred_agent_id': 'test-agent',
            'session_timeout': 600
        }
        
        user_info = jwt_service.extract_user_info(payload)
        
        assert user_info['user_id'] == 'user-123'
        assert user_info['username'] == 'testuser'
        assert user_info['email'] == 'test@example.com'
        assert user_info['roles'] == ['user', 'admin']
        assert user_info['agent_namespace'] == 'test_ns'
        assert user_info['preferred_agent_id'] == 'test-agent'
        assert user_info['session_timeout'] == 600
    
    def test_is_token_type(self):
        """Test token type checking."""
        api_key_payload = {'token_type': 'api_key'}
        user_payload = {'token_type': 'access'}
        no_type_payload = {}
        
        assert jwt_service.is_token_type(api_key_payload, 'api_key')
        assert not jwt_service.is_token_type(api_key_payload, 'access')
        assert jwt_service.is_token_type(user_payload, 'access')
        assert not jwt_service.is_token_type(no_type_payload, 'api_key')
    
    def test_get_token_scopes(self):
        """Test token scopes extraction."""
        payload_with_scopes = {'scopes': ['read', 'write', 'admin']}
        payload_without_scopes = {}
        
        scopes1 = jwt_service.get_token_scopes(payload_with_scopes)
        scopes2 = jwt_service.get_token_scopes(payload_without_scopes)
        
        assert scopes1 == ['read', 'write', 'admin']
        assert scopes2 == []


@pytest.mark.unit
class TestPasswordResetTokens:
    """Test password reset token functionality."""
    
    @pytest.fixture
    def test_user(self):
        return User(
            id="test-user-id",
            username="testuser",
            email="test@example.com"
        )
    
    def test_create_password_reset_token(self, test_user):
        """Test password reset token creation."""
        token = jwt_service.create_password_reset_token(test_user)
        payload = jwt_service.decode_token_unsafe(token)
        
        assert payload['sub'] == str(test_user.id)
        assert payload['username'] == test_user.username
        assert payload['token_type'] == 'password_reset'
        
        # Should have short expiry (30 minutes)
        issued_at = datetime.fromtimestamp(payload['iat'], tz=timezone.utc)
        expires_at = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
        duration = expires_at - issued_at
        
        # Should be approximately 30 minutes
        assert abs(duration.total_seconds() - 1800) < 60  # 1800 seconds = 30 minutes
    
    def test_password_reset_token_validation(self, test_user):
        """Test password reset token can be validated."""
        token = jwt_service.create_password_reset_token(test_user)
        payload = jwt_service.verify_token(token)
        
        assert payload is not None
        assert payload['token_type'] == 'password_reset'
        assert payload['sub'] == str(test_user.id)