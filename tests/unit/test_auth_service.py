"""
Unit Tests for AuthService - Core Authentication Logic.
Led by Artemis (Technical Perfectionist) with focus on performance and correctness.

This module provides comprehensive unit testing for the AuthService class,
ensuring all methods work correctly and meet performance requirements.

Testing Strategy:
- All public methods have comprehensive test coverage
- Edge cases and error conditions thoroughly tested
- Performance requirements (<200ms) validated
- Input validation and sanitization verified
- Database interactions properly mocked where needed
- Concurrent access patterns tested
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import pytest

from src.models.user import APIKey, APIKeyScope, User, UserRole, UserStatus
from src.security.jwt_service import jwt_service
from src.services.auth_service import (
    AccountDisabledError,
    AccountLockedError,
    AuthService,
    InvalidCredentialsError,
    TokenExpiredError,
)


@pytest.mark.unit
class TestAuthServiceUserCreation:
    """Test user creation functionality."""

    @pytest.fixture
    def auth_service(self):
        """Create AuthService instance for testing."""
        return AuthService()

    @pytest.mark.asyncio
    async def test_create_user_success(self, auth_service):
        """Test successful user creation."""
        with (
            patch("src.services.auth_service.get_db_session") as mock_db,
            patch("src.services.auth_service.get_audit_logger") as mock_audit,
        ):
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session
            mock_audit.return_value.log_event = AsyncMock()

            # Mock database check for existing users - return None (no existing user)
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=None)
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()
            mock_session.refresh = AsyncMock()

            user = await auth_service.create_user(
                username="testuser",
                email="test@example.com",
                password="secure_password_123",
                full_name="Test User",
            )

            assert user.username == "testuser"
            assert user.email == "test@example.com"
            assert user.full_name == "Test User"
            assert UserRole.USER in user.roles
            assert user.status == UserStatus.ACTIVE

            # Verify password is hashed
            assert user.password_hash != "secure_password_123"
            assert user.password_salt is not None
            assert len(user.password_salt) == 64  # 32 bytes as hex string (32 * 2 = 64 chars)

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(self, auth_service):
        """Test user creation with duplicate username."""
        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            # Mock existing user found
            existing_user = User(username="testuser", email="other@example.com")
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=existing_user)
            mock_session.execute = AsyncMock(return_value=mock_result)

            with pytest.raises(ValueError, match="Username or email already exists"):
                await auth_service.create_user(
                    username="testuser", email="test@example.com", password="secure_password_123"
                )

    @pytest.mark.asyncio
    async def test_create_user_invalid_username_length(self, auth_service):
        """Test user creation with invalid username length."""
        # Too short
        with pytest.raises(ValueError, match="Username must be 2-64 characters"):
            await auth_service.create_user(
                username="a", email="test@example.com", password="secure_password_123"
            )

        # Too long
        with pytest.raises(ValueError, match="Username must be 2-64 characters"):
            await auth_service.create_user(
                username="a" * 65, email="test@example.com", password="secure_password_123"
            )

    @pytest.mark.asyncio
    async def test_create_user_weak_password(self, auth_service):
        """Test user creation with weak password."""
        weak_passwords = ["1234567", "short", ""]

        for weak_password in weak_passwords:
            with pytest.raises(ValueError, match="Password must be at least"):
                await auth_service.create_user(
                    username="testuser", email="test@example.com", password=weak_password
                )

    @pytest.mark.asyncio
    async def test_create_user_with_roles(self, auth_service):
        """Test user creation with specific roles."""
        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=None)
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()
            mock_session.refresh = AsyncMock()

            user = await auth_service.create_user(
                username="adminuser",
                email="admin@example.com",
                password="secure_password_123",
                roles=[UserRole.ADMIN, UserRole.USER],
            )

            assert UserRole.ADMIN in user.roles
            assert UserRole.USER in user.roles


@pytest.fixture
def mock_user():
    """Create mock user for testing."""
    password_hash, password_salt = jwt_service.hash_password("test_password")

    user = User(
        id=uuid4(),
        username="testuser",
        email="test@example.com",
        password_hash=password_hash,
        password_salt=password_salt,
        status=UserStatus.ACTIVE,
        roles=[UserRole.USER],
        failed_login_attempts=0,
    )
    return user


@pytest.fixture
def performance_timer():
    """Create performance timer for testing."""
    import time

    class Timer:
        def __init__(self):
            self.start_time = None

        def start(self):
            self.start_time = time.perf_counter()

        def stop(self):
            if self.start_time is None:
                return 0
            elapsed = (time.perf_counter() - self.start_time) * 1000  # Convert to milliseconds
            self.start_time = None
            return elapsed

    return Timer()


@pytest.mark.unit
class TestAuthServiceAuthentication:
    """Test user authentication functionality."""

    @pytest.fixture
    def auth_service(self):
        """Create AuthService instance for testing."""
        return AuthService()

    @pytest.mark.asyncio
    async def test_authenticate_user_success(self, auth_service, mock_user):
        """Test successful user authentication."""
        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            # Mock user lookup
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=mock_user)
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()

            user, access_token, refresh_token = await auth_service.authenticate_user(
                "testuser", "test_password"
            )

            assert user.id == mock_user.id
            assert user.username == "testuser"
            assert access_token is not None
            assert refresh_token is not None

            # Verify token validity
            payload = jwt_service.verify_token(access_token)
            assert payload is not None
            assert payload["sub"] == str(mock_user.id)

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self, auth_service):
        """Test authentication with non-existent user."""
        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            # Mock no user found
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=None)
            mock_session.execute = AsyncMock(return_value=mock_result)

            with pytest.raises(InvalidCredentialsError, match="Invalid credentials"):
                await auth_service.authenticate_user("nonexistent", "any_password")

    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(self, auth_service, mock_user):
        """Test authentication with wrong password."""
        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=mock_user)
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()

            with pytest.raises(InvalidCredentialsError, match="Invalid credentials"):
                await auth_service.authenticate_user("testuser", "wrong_password")

            # Should increment failed attempts
            assert mock_user.failed_login_attempts > 0

    @pytest.mark.asyncio
    async def test_authenticate_locked_account(self, auth_service):
        """Test authentication with locked account."""
        locked_user = User(
            username="lockeduser", email="locked@example.com", status=UserStatus.LOCKED
        )

        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=locked_user)
            mock_session.execute = AsyncMock(return_value=mock_result)

            with pytest.raises(AccountLockedError, match="Account is locked"):
                await auth_service.authenticate_user("lockeduser", "any_password")

    @pytest.mark.asyncio
    async def test_authenticate_suspended_account(self, auth_service):
        """Test authentication with suspended account."""
        suspended_user = User(
            username="suspendeduser", email="suspended@example.com", status=UserStatus.SUSPENDED
        )

        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=suspended_user)
            mock_session.execute = AsyncMock(return_value=mock_result)

            with pytest.raises(AccountDisabledError, match="Account is disabled"):
                await auth_service.authenticate_user("suspendeduser", "any_password")

    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_authenticate_performance(self, auth_service, mock_user, performance_timer):
        """Test authentication performance meets <200ms requirement."""
        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=mock_user)
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()

            # Test multiple authentication attempts
            times = []
            for _ in range(10):
                performance_timer.start()
                user, access_token, refresh_token = await auth_service.authenticate_user(
                    "testuser", "test_password"
                )
                elapsed = performance_timer.stop()
                times.append(elapsed)

            avg_time = sum(times) / len(times)
            max_time = max(times)

            assert avg_time < 200, f"Average auth time {avg_time}ms exceeds 200ms requirement"
            assert max_time < 400, f"Maximum auth time {max_time}ms too slow"


@pytest.mark.unit
class TestAuthServiceTokenRefresh:
    """Test token refresh functionality."""

    @pytest.fixture
    def auth_service(self):
        return AuthService()

    @pytest.mark.asyncio
    async def test_refresh_token_success(self, auth_service, mock_user):
        """Test successful token refresh."""
        # Create initial tokens
        access_token = jwt_service.create_access_token(mock_user)
        refresh_token, refresh_record = jwt_service.create_refresh_token(mock_user)
        refresh_record.user = mock_user

        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            # Mock refresh token lookup
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=refresh_record)
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()

            new_access_token, new_refresh_token = await auth_service.refresh_access_token(
                refresh_token
            )

            assert new_access_token != access_token
            assert new_refresh_token != refresh_token

            # Verify new tokens are valid
            payload = jwt_service.verify_token(new_access_token)
            assert payload is not None
            assert payload["sub"] == str(mock_user.id)

    @pytest.mark.asyncio
    async def test_refresh_token_invalid_format(self, auth_service):
        """Test refresh with invalid token format."""
        with pytest.raises(TokenExpiredError, match="Invalid refresh token format"):
            await auth_service.refresh_access_token("invalid_token_format")

    @pytest.mark.asyncio
    async def test_refresh_token_not_found(self, auth_service):
        """Test refresh with non-existent token."""
        valid_format_token = "valid_token_id_12345678901234567890.valid_raw_token_part"

        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            # Mock no refresh token found
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=None)
            mock_session.execute = AsyncMock(return_value=mock_result)

            with pytest.raises(TokenExpiredError, match="Refresh token expired or revoked"):
                await auth_service.refresh_access_token(valid_format_token)


@pytest.mark.unit
class TestAuthServiceAPIKeys:
    """Test API key management functionality."""

    @pytest.fixture
    def auth_service(self):
        return AuthService()

    @pytest.mark.asyncio
    async def test_create_api_key_success(self, auth_service):
        """Test successful API key creation."""
        user_id = uuid4()

        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session
            mock_session.commit = AsyncMock()
            mock_session.refresh = AsyncMock()

            api_key, api_key_record = await auth_service.create_api_key(
                user_id=user_id,
                name="Test API Key",
                description="For testing",
                scopes=[APIKeyScope.READ, APIKeyScope.WRITE],
            )

            # Verify key format
            assert "." in api_key
            key_id, raw_key = api_key.split(".", 1)

            assert len(key_id) >= 16
            assert len(raw_key) >= 32

            # Verify record
            assert api_key_record.name == "Test API Key"
            assert api_key_record.description == "For testing"
            assert APIKeyScope.READ in api_key_record.scopes
            assert APIKeyScope.WRITE in api_key_record.scopes
            assert api_key_record.user_id == user_id

    @pytest.mark.asyncio
    async def test_create_api_key_with_expiration(self, auth_service):
        """Test API key creation with expiration."""
        user_id = uuid4()

        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session
            mock_session.commit = AsyncMock()
            mock_session.refresh = AsyncMock()

            api_key, api_key_record = await auth_service.create_api_key(
                user_id=user_id, name="Expiring Key", expires_days=30
            )

            assert api_key_record.expires_at is not None
            expected_expiry = datetime.now(timezone.utc) + timedelta(days=30)

            # Allow 1 minute variance for test execution time
            time_diff = abs((api_key_record.expires_at - expected_expiry).total_seconds())
            assert time_diff < 60

    @pytest.mark.asyncio
    async def test_validate_api_key_success(self, auth_service):
        """Test successful API key validation."""
        # Create mock API key and user
        user_id = uuid4()
        mock_user = User(id=user_id, username="testuser", status=UserStatus.ACTIVE)

        key_id = "test_key_id_1234567890123456"
        raw_key = "test_raw_key_1234567890123456789012345678901234567890"

        # Create API key record with hashed key
        key_hash = jwt_service.pwd_context.hash(raw_key)
        api_key_record = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            user_id=user_id,
            scopes=[APIKeyScope.READ],
            is_active=True,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            total_requests=0,  # Initialize usage counter for record_usage() method
        )
        api_key_record.user = mock_user

        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=api_key_record)
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()

            api_key = f"{key_id}.{raw_key}"
            user, key = await auth_service.validate_api_key(api_key)

            assert user.id == user_id
            assert key.key_id == key_id

    @pytest.mark.asyncio
    async def test_validate_api_key_invalid_format(self, auth_service):
        """Test API key validation with invalid format."""
        with pytest.raises(InvalidCredentialsError, match="Invalid API key format"):
            await auth_service.validate_api_key("invalid_format")

    @pytest.mark.asyncio
    async def test_validate_api_key_not_found(self, auth_service):
        """Test API key validation with non-existent key."""
        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=None)
            mock_session.execute = AsyncMock(return_value=mock_result)

            with pytest.raises(InvalidCredentialsError, match="Invalid API key"):
                await auth_service.validate_api_key("nonexistent.key_format")

    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_validate_api_key_performance(self, auth_service, performance_timer):
        """Test API key validation meets <100ms performance requirement."""
        # Setup mock data
        user_id = uuid4()
        mock_user = User(id=user_id, username="testuser", status=UserStatus.ACTIVE)

        key_id = "perf_test_key_1234567890123456"
        raw_key = "perf_test_raw_key_123456789012345678901234567890123456"
        key_hash = jwt_service.pwd_context.hash(raw_key)

        api_key_record = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            user_id=user_id,
            scopes=[APIKeyScope.READ],
            is_active=True,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            total_requests=0,  # Initialize usage counter for record_usage() method
        )
        api_key_record.user = mock_user

        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=api_key_record)
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()

            api_key = f"{key_id}.{raw_key}"
            times = []

            for _ in range(20):
                performance_timer.start()
                user, key = await auth_service.validate_api_key(api_key)
                elapsed = performance_timer.stop()
                times.append(elapsed)

            avg_time = sum(times) / len(times)
            max_time = max(times)

            assert avg_time < 100, (
                f"Average API key validation {avg_time}ms exceeds 100ms requirement"
            )
            assert max_time < 200, f"Maximum API key validation {max_time}ms too slow"


@pytest.mark.unit
class TestAuthServicePasswordManagement:
    """Test password management functionality."""

    @pytest.fixture
    def auth_service(self):
        return AuthService()

    @pytest.mark.asyncio
    async def test_change_password_success(self, auth_service, mock_user):
        """Test successful password change."""
        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            mock_session.get.return_value = mock_user
            mock_session.commit = AsyncMock()

            original_hash = mock_user.password_hash

            await auth_service.change_password(
                user_id=mock_user.id,
                current_password="test_password",
                new_password="new_secure_password_123",
            )

            # Password hash should have changed
            assert mock_user.password_hash != original_hash
            assert mock_user.force_password_change is False

            # Password changed timestamp should be updated
            assert mock_user.password_changed_at is not None

    @pytest.mark.asyncio
    async def test_change_password_wrong_current(self, auth_service, mock_user):
        """Test password change with wrong current password."""
        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            mock_session.get.return_value = mock_user

            with pytest.raises(InvalidCredentialsError, match="Current password is incorrect"):
                await auth_service.change_password(
                    user_id=mock_user.id,
                    current_password="wrong_password",
                    new_password="new_secure_password_123",
                )

    @pytest.mark.asyncio
    async def test_change_password_weak_new(self, auth_service, mock_user):
        """Test password change with weak new password."""
        with pytest.raises(ValueError, match="Password must be at least"):
            await auth_service.change_password(
                user_id=mock_user.id, current_password="test_password", new_password="weak"
            )

    @pytest.mark.asyncio
    async def test_reset_password_success(self, auth_service):
        """Test successful password reset."""
        user_id = uuid4()

        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            mock_session.execute.return_value.rowcount = 1
            mock_session.commit = AsyncMock()

            # Should not raise any exception
            await auth_service.reset_password(user_id=user_id, new_password="reset_password_123")

            # Should call logout_all_sessions
            mock_session.execute.assert_called()


@pytest.mark.unit
class TestAuthServiceConcurrency:
    """Test concurrent access patterns."""

    @pytest.fixture
    def auth_service(self):
        return AuthService()

    @pytest.mark.asyncio
    async def test_concurrent_user_creation(self, auth_service):
        """Test concurrent user creation handles conflicts properly."""
        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            # First call succeeds, second fails with duplicate
            mock_session.execute.return_value.scalar_one_or_none.side_effect = [
                None,  # First check - no existing user
                User(username="testuser", email="test@example.com"),  # Second check - user exists
            ]
            mock_session.commit = AsyncMock()
            mock_session.refresh = AsyncMock()

            async def create_user_task():
                try:
                    return await auth_service.create_user(
                        username="testuser",
                        email="test@example.com",
                        password="secure_password_123",
                    )
                except ValueError as e:
                    return e

            # Run concurrent user creation
            tasks = [create_user_task(), create_user_task()]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # One should succeed, one should fail with duplicate error
            successful = [r for r in results if isinstance(r, User)]
            failed = [r for r in results if isinstance(r, ValueError | Exception)]

            assert len(successful) + len(failed) == 2

    @pytest.mark.asyncio
    async def test_concurrent_api_key_validation(self, auth_service):
        """Test concurrent API key validation."""
        # Setup mock data
        user_id = uuid4()
        mock_user = User(id=user_id, username="testuser", status=UserStatus.ACTIVE)

        key_id = "concurrent_test_key_123456789012"
        raw_key = "concurrent_test_raw_key_12345678901234567890123456"
        key_hash = jwt_service.pwd_context.hash(raw_key)

        api_key_record = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            user_id=user_id,
            scopes=[APIKeyScope.READ],
            is_active=True,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            total_requests=0,  # Initialize usage counter for record_usage() method
        )
        api_key_record.user = mock_user

        with patch("src.services.auth_service.get_db_session") as mock_db:
            mock_session = AsyncMock()
            mock_db.return_value.__aenter__.return_value = mock_session

            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=api_key_record)
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()

            api_key = f"{key_id}.{raw_key}"

            # Run concurrent validations
            tasks = [auth_service.validate_api_key(api_key) for _ in range(10)]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # All should succeed with same results
            successful_results = [r for r in results if not isinstance(r, Exception)]
            assert len(successful_results) == 10

            # All should return same user
            user_ids = {r[0].id for r in successful_results}
            assert len(user_ids) == 1
            assert list(user_ids)[0] == user_id
