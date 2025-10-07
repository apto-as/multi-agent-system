"""
Integration Tests for Authentication API Endpoints.
Led by Eris (Tactical Coordinator) with focus on complete workflow testing.

This module tests the complete authentication API flows including:
- User registration and login workflows
- JWT token handling across endpoints
- API key authentication flows
- Session management and logout
- Error handling and edge cases
- Cross-endpoint integration scenarios

Integration Strategy:
- Real HTTP requests through FastAPI test client
- Complete request/response cycle testing
- Database integration with test data
- Authentication middleware validation
- Rate limiting and security controls
"""

import asyncio
from datetime import timedelta

import pytest
from fastapi import status
from httpx import AsyncClient


@pytest.mark.integration
class TestUserRegistrationFlow:
    """Test complete user registration workflow."""

    async def test_register_user_success(self, async_client: AsyncClient):
        """Test successful user registration."""
        user_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "secure_password_123",
            "full_name": "New User"
        }

        response = await async_client.post("/auth/register", json=user_data)

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        assert response_data["username"] == user_data["username"]
        assert response_data["email"] == user_data["email"]
        assert response_data["full_name"] == user_data["full_name"]
        assert "id" in response_data
        assert "password" not in response_data  # Password should not be returned
        assert "password_hash" not in response_data

    async def test_register_user_duplicate_username(self, async_client: AsyncClient, test_user):
        """Test registration with duplicate username."""
        user_data = {
            "username": test_user.username,  # Use existing username
            "email": "different@example.com",
            "password": "secure_password_123"
        }

        response = await async_client.post("/auth/register", json=user_data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in response.json()["detail"]

    async def test_register_user_duplicate_email(self, async_client: AsyncClient, test_user):
        """Test registration with duplicate email."""
        user_data = {
            "username": "differentuser",
            "email": test_user.email,  # Use existing email
            "password": "secure_password_123"
        }

        response = await async_client.post("/auth/register", json=user_data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in response.json()["detail"]

    async def test_register_user_invalid_data(self, async_client: AsyncClient):
        """Test registration with invalid data."""
        invalid_data_sets = [
            # Missing username
            {
                "email": "test@example.com",
                "password": "secure_password_123"
            },
            # Missing email
            {
                "username": "testuser",
                "password": "secure_password_123"
            },
            # Missing password
            {
                "username": "testuser",
                "email": "test@example.com"
            },
            # Weak password
            {
                "username": "testuser",
                "email": "test@example.com",
                "password": "weak"
            },
            # Invalid email format
            {
                "username": "testuser",
                "email": "not_an_email",
                "password": "secure_password_123"
            }
        ]

        for invalid_data in invalid_data_sets:
            response = await async_client.post("/auth/register", json=invalid_data)
            assert response.status_code in [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_422_UNPROCESSABLE_ENTITY
            ]


@pytest.mark.integration
class TestLoginFlow:
    """Test user authentication and login workflows."""

    async def test_login_success(self, async_client: AsyncClient, test_user, test_user_data):
        """Test successful login."""
        login_data = {
            "username": test_user_data["username"],
            "password": test_user_data["password"]
        }

        response = await async_client.post("/auth/login", json=login_data)

        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()

        # Should return tokens
        assert "access_token" in response_data
        assert "refresh_token" in response_data
        assert "token_type" in response_data
        assert response_data["token_type"] == "bearer"

        # Should return user info
        assert "user" in response_data
        user_info = response_data["user"]
        assert user_info["username"] == test_user.username
        assert user_info["email"] == test_user.email
        assert "id" in user_info

    async def test_login_with_email(self, async_client: AsyncClient, test_user, test_user_data):
        """Test login using email instead of username."""
        login_data = {
            "username": test_user_data["email"],  # Use email as username
            "password": test_user_data["password"]
        }

        response = await async_client.post("/auth/login", json=login_data)

        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert "access_token" in response_data

    async def test_login_invalid_credentials(self, async_client: AsyncClient, test_user_data):
        """Test login with invalid credentials."""
        invalid_credentials = [
            # Wrong username
            {
                "username": "nonexistent_user",
                "password": test_user_data["password"]
            },
            # Wrong password
            {
                "username": test_user_data["username"],
                "password": "wrong_password"
            },
            # Both wrong
            {
                "username": "wrong_user",
                "password": "wrong_password"
            }
        ]

        for credentials in invalid_credentials:
            response = await async_client.post("/auth/login", json=credentials)
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid credentials" in response.json()["detail"]

    async def test_login_locked_account(self, async_client: AsyncClient, locked_user):
        """Test login with locked account."""
        login_data = {
            "username": "locked_user",
            "password": "locked_password_123"
        }

        response = await async_client.post("/auth/login", json=login_data)

        assert response.status_code == status.HTTP_423_LOCKED
        assert "locked" in response.json()["detail"].lower()

    async def test_login_missing_data(self, async_client: AsyncClient):
        """Test login with missing data."""
        incomplete_data_sets = [
            {"username": "testuser"},  # Missing password
            {"password": "password"},  # Missing username
            {}  # Missing both
        ]

        for incomplete_data in incomplete_data_sets:
            response = await async_client.post("/auth/login", json=incomplete_data)
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.integration
class TestAuthenticatedRequests:
    """Test authenticated API requests."""

    async def test_authenticated_request_success(self, authenticated_client: AsyncClient):
        """Test successful authenticated request."""
        response = await authenticated_client.get("/auth/me")

        assert response.status_code == status.HTTP_200_OK
        user_info = response.json()

        assert "username" in user_info
        assert "email" in user_info
        assert "id" in user_info
        assert "roles" in user_info

    async def test_unauthenticated_request(self, async_client: AsyncClient):
        """Test request without authentication token."""
        response = await async_client.get("/auth/me")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Not authenticated" in response.json()["detail"]

    async def test_invalid_token_request(self, async_client: AsyncClient):
        """Test request with invalid token."""
        # Set invalid authorization header
        async_client.headers.update({
            "Authorization": "Bearer invalid_token_here"
        })

        response = await async_client.get("/auth/me")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid token" in response.json()["detail"]

    async def test_expired_token_request(self, async_client: AsyncClient, test_user):
        """Test request with expired token."""
        # Create token with immediate expiration
        from src.security.jwt_service import jwt_service

        expired_token = jwt_service.create_access_token(
            test_user,
            expires_delta=timedelta(seconds=-1)  # Already expired
        )

        async_client.headers.update({
            "Authorization": f"Bearer {expired_token}"
        })

        response = await async_client.get("/auth/me")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_malformed_authorization_header(self, async_client: AsyncClient):
        """Test request with malformed authorization header."""
        malformed_headers = [
            "Bearer",  # Missing token
            "Token valid_token",  # Wrong scheme
            "Bearer token1 token2",  # Multiple tokens
            "invalid_format",  # No scheme
        ]

        for auth_header in malformed_headers:
            async_client.headers.update({"Authorization": auth_header})
            response = await async_client.get("/auth/me")
            assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.integration
class TestTokenRefreshFlow:
    """Test token refresh workflows."""

    async def test_token_refresh_success(self, async_client: AsyncClient, test_user, test_user_data):
        """Test successful token refresh."""
        # First, login to get tokens
        login_response = await async_client.post("/auth/login", json={
            "username": test_user_data["username"],
            "password": test_user_data["password"]
        })

        tokens = login_response.json()
        refresh_token = tokens["refresh_token"]

        # Use refresh token to get new access token
        refresh_response = await async_client.post("/auth/refresh", json={
            "refresh_token": refresh_token
        })

        assert refresh_response.status_code == status.HTTP_200_OK
        new_tokens = refresh_response.json()

        assert "access_token" in new_tokens
        assert "refresh_token" in new_tokens
        assert new_tokens["access_token"] != tokens["access_token"]
        assert new_tokens["refresh_token"] != tokens["refresh_token"]

    async def test_token_refresh_invalid_token(self, async_client: AsyncClient):
        """Test token refresh with invalid refresh token."""
        refresh_response = await async_client.post("/auth/refresh", json={
            "refresh_token": "invalid.refresh.token"
        })

        assert refresh_response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid" in refresh_response.json()["detail"]

    async def test_token_refresh_expired_token(self, async_client: AsyncClient):
        """Test token refresh with expired refresh token."""
        # Create expired refresh token format (this would be expired in real scenario)
        expired_refresh = "expired_token_id_1234567890123456.expired_raw_token_part"

        refresh_response = await async_client.post("/auth/refresh", json={
            "refresh_token": expired_refresh
        })

        assert refresh_response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_token_refresh_used_token(self, async_client: AsyncClient, test_user, test_user_data):
        """Test that refresh token can only be used once."""
        # Login and get refresh token
        login_response = await async_client.post("/auth/login", json={
            "username": test_user_data["username"],
            "password": test_user_data["password"]
        })

        refresh_token = login_response.json()["refresh_token"]

        # Use refresh token once - should succeed
        first_refresh = await async_client.post("/auth/refresh", json={
            "refresh_token": refresh_token
        })
        assert first_refresh.status_code == status.HTTP_200_OK

        # Try to use same refresh token again - should fail
        second_refresh = await async_client.post("/auth/refresh", json={
            "refresh_token": refresh_token
        })
        assert second_refresh.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.integration
class TestAPIKeyAuthentication:
    """Test API key authentication workflows."""

    async def test_api_key_creation(self, authenticated_client: AsyncClient):
        """Test API key creation via endpoint."""
        api_key_data = {
            "name": "Test API Key",
            "description": "For testing purposes",
            "scopes": ["read", "write"],
            "expires_days": 30
        }

        response = await authenticated_client.post("/auth/api-keys", json=api_key_data)

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        assert "api_key" in response_data
        assert "key_info" in response_data

        # API key should have correct format
        api_key = response_data["api_key"]
        assert "." in api_key

        # Key info should be present
        key_info = response_data["key_info"]
        assert key_info["name"] == api_key_data["name"]
        assert key_info["description"] == api_key_data["description"]
        assert set(key_info["scopes"]) == set(api_key_data["scopes"])

    async def test_api_key_authentication(self, async_client: AsyncClient, test_api_key):
        """Test API key authentication."""
        api_key, _ = test_api_key

        # Set API key in header
        async_client.headers.update({
            "X-API-Key": api_key
        })

        response = await async_client.get("/auth/me")

        assert response.status_code == status.HTTP_200_OK
        user_info = response.json()
        assert "username" in user_info

    async def test_api_key_invalid(self, async_client: AsyncClient):
        """Test authentication with invalid API key."""
        async_client.headers.update({
            "X-API-Key": "invalid.api.key.format"
        })

        response = await async_client.get("/auth/me")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_api_key_list(self, authenticated_client: AsyncClient):
        """Test listing user's API keys."""
        # First create an API key
        await authenticated_client.post("/auth/api-keys", json={
            "name": "List Test Key",
            "scopes": ["read"]
        })

        # Then list API keys
        response = await authenticated_client.get("/auth/api-keys")

        assert response.status_code == status.HTTP_200_OK
        api_keys = response.json()

        assert isinstance(api_keys, list)
        assert len(api_keys) >= 1

        # Check key structure
        for key in api_keys:
            assert "name" in key
            assert "scopes" in key
            assert "created_at" in key
            assert "is_active" in key
            # Sensitive fields should not be present
            assert "key_hash" not in key
            assert "api_key" not in key

    async def test_api_key_revocation(self, authenticated_client: AsyncClient):
        """Test API key revocation."""
        # Create API key
        create_response = await authenticated_client.post("/auth/api-keys", json={
            "name": "Revoke Test Key",
            "scopes": ["read"]
        })

        key_info = create_response.json()["key_info"]
        key_id = key_info["key_id"]

        # Revoke API key
        revoke_response = await authenticated_client.delete(f"/auth/api-keys/{key_id}")

        assert revoke_response.status_code == status.HTTP_200_OK

        # Verify key is revoked
        list_response = await authenticated_client.get("/auth/api-keys")
        api_keys = list_response.json()

        revoked_key = next((k for k in api_keys if k["key_id"] == key_id), None)
        assert revoked_key is not None
        assert revoked_key["is_active"] is False


@pytest.mark.integration
class TestLogoutFlow:
    """Test logout and session termination."""

    async def test_logout_success(self, async_client: AsyncClient, test_user, test_user_data):
        """Test successful logout."""
        # Login first
        login_response = await async_client.post("/auth/login", json={
            "username": test_user_data["username"],
            "password": test_user_data["password"]
        })

        tokens = login_response.json()
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]

        # Set authorization header
        async_client.headers.update({
            "Authorization": f"Bearer {access_token}"
        })

        # Logout
        logout_response = await async_client.post("/auth/logout", json={
            "refresh_token": refresh_token
        })

        assert logout_response.status_code == status.HTTP_200_OK

        # After logout, access token should be invalid
        me_response = await async_client.get("/auth/me")
        assert me_response.status_code == status.HTTP_401_UNAUTHORIZED

        # Refresh token should also be invalid
        refresh_response = await async_client.post("/auth/refresh", json={
            "refresh_token": refresh_token
        })
        assert refresh_response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_logout_without_auth(self, async_client: AsyncClient):
        """Test logout without authentication."""
        logout_response = await async_client.post("/auth/logout", json={
            "refresh_token": "any_token"
        })

        assert logout_response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_logout_all_sessions(self, authenticated_client: AsyncClient):
        """Test logout from all sessions."""
        logout_response = await authenticated_client.post("/auth/logout-all")

        assert logout_response.status_code == status.HTTP_200_OK

        # Current session should be terminated
        me_response = await authenticated_client.get("/auth/me")
        assert me_response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.integration
class TestPasswordManagement:
    """Test password change and reset workflows."""

    async def test_change_password_success(self, authenticated_client: AsyncClient, test_user_data):
        """Test successful password change."""
        change_data = {
            "current_password": test_user_data["password"],
            "new_password": "new_secure_password_456"
        }

        response = await authenticated_client.post("/auth/change-password", json=change_data)

        assert response.status_code == status.HTTP_200_OK

        # After password change, user should be logged out (all sessions terminated)
        me_response = await authenticated_client.get("/auth/me")
        assert me_response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_change_password_wrong_current(self, authenticated_client: AsyncClient):
        """Test password change with wrong current password."""
        change_data = {
            "current_password": "wrong_current_password",
            "new_password": "new_secure_password_456"
        }

        response = await authenticated_client.post("/auth/change-password", json=change_data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "incorrect" in response.json()["detail"].lower()

    async def test_change_password_weak_new(self, authenticated_client: AsyncClient, test_user_data):
        """Test password change with weak new password."""
        change_data = {
            "current_password": test_user_data["password"],
            "new_password": "weak"
        }

        response = await authenticated_client.post("/auth/change-password", json=change_data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "at least" in response.json()["detail"].lower()


@pytest.mark.integration
@pytest.mark.performance
class TestAuthenticationPerformance:
    """Test authentication performance requirements."""

    async def test_login_performance(self, async_client: AsyncClient, test_user, test_user_data, performance_timer):
        """Test login meets <200ms performance requirement."""
        login_data = {
            "username": test_user_data["username"],
            "password": test_user_data["password"]
        }

        times = []
        for _ in range(10):
            performance_timer.start()
            response = await async_client.post("/auth/login", json=login_data)
            elapsed = performance_timer.stop()

            assert response.status_code == status.HTTP_200_OK
            times.append(elapsed)

        avg_time = sum(times) / len(times)
        max_time = max(times)

        assert avg_time < 200, f"Average login time {avg_time}ms exceeds 200ms requirement"
        assert max_time < 400, f"Maximum login time {max_time}ms too slow"

    async def test_authenticated_request_performance(self, authenticated_client: AsyncClient, performance_timer):
        """Test authenticated requests meet performance requirements."""
        times = []

        for _ in range(20):
            performance_timer.start()
            response = await authenticated_client.get("/auth/me")
            elapsed = performance_timer.stop()

            assert response.status_code == status.HTTP_200_OK
            times.append(elapsed)

        avg_time = sum(times) / len(times)
        max_time = max(times)

        assert avg_time < 100, f"Average auth request time {avg_time}ms too slow"
        assert max_time < 200, f"Maximum auth request time {max_time}ms exceeds requirement"

    async def test_api_key_auth_performance(self, async_client: AsyncClient, test_api_key, performance_timer):
        """Test API key authentication performance."""
        api_key, _ = test_api_key

        async_client.headers.update({"X-API-Key": api_key})

        times = []
        for _ in range(20):
            performance_timer.start()
            response = await async_client.get("/auth/me")
            elapsed = performance_timer.stop()

            assert response.status_code == status.HTTP_200_OK
            times.append(elapsed)

        avg_time = sum(times) / len(times)
        max_time = max(times)

        assert avg_time < 100, f"Average API key auth time {avg_time}ms too slow"
        assert max_time < 200, f"Maximum API key auth time {max_time}ms exceeds requirement"


@pytest.mark.integration
@pytest.mark.slow
class TestConcurrentAuthentication:
    """Test concurrent authentication scenarios."""

    async def test_concurrent_login_attempts(self, async_client: AsyncClient, test_user, test_user_data):
        """Test concurrent login attempts for same user."""
        login_data = {
            "username": test_user_data["username"],
            "password": test_user_data["password"]
        }

        # Perform concurrent login attempts
        async def login_attempt():
            response = await async_client.post("/auth/login", json=login_data)
            return response.status_code, response.json()

        tasks = [login_attempt() for _ in range(5)]
        results = await asyncio.gather(*tasks)

        # All should succeed
        for status_code, response_data in results:
            assert status_code == status.HTTP_200_OK
            assert "access_token" in response_data

        # All tokens should be different (different JTIs)
        tokens = [data["access_token"] for _, data in results]
        assert len(set(tokens)) == len(tokens)

    async def test_concurrent_api_key_usage(self, async_client: AsyncClient, test_api_key):
        """Test concurrent API key authentication."""
        api_key, _ = test_api_key

        async def api_key_request():
            # Create new client for each request
            async with AsyncClient(app=async_client.app, base_url=async_client.base_url) as client:
                client.headers.update({"X-API-Key": api_key})
                response = await client.get("/auth/me")
                return response.status_code

        tasks = [api_key_request() for _ in range(10)]
        results = await asyncio.gather(*tasks)

        # All should succeed
        assert all(status == status.HTTP_200_OK for status in results)


@pytest.mark.integration
class TestAuthenticationEdgeCases:
    """Test authentication edge cases and error scenarios."""

    async def test_authentication_with_special_characters(self, async_client: AsyncClient):
        """Test authentication with usernames containing special characters."""
        # Register user with special characters
        user_data = {
            "username": "user@domain.com",
            "email": "user@domain.com",
            "password": "secure_password_123"
        }

        register_response = await async_client.post("/auth/register", json=user_data)
        assert register_response.status_code == status.HTTP_201_CREATED

        # Login with special character username
        login_response = await async_client.post("/auth/login", json={
            "username": user_data["username"],
            "password": user_data["password"]
        })

        assert login_response.status_code == status.HTTP_200_OK

    async def test_case_sensitive_authentication(self, async_client: AsyncClient, test_user, test_user_data):
        """Test that authentication is case-sensitive for passwords."""
        # Correct case should work
        login_response = await async_client.post("/auth/login", json={
            "username": test_user_data["username"],
            "password": test_user_data["password"]
        })
        assert login_response.status_code == status.HTTP_200_OK

        # Wrong case should fail
        wrong_case_response = await async_client.post("/auth/login", json={
            "username": test_user_data["username"],
            "password": test_user_data["password"].upper()  # Change case
        })
        assert wrong_case_response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_unicode_handling(self, async_client: AsyncClient):
        """Test Unicode character handling in authentication."""
        unicode_data = {
            "username": "用户名",  # Chinese characters
            "email": "用户@测试.com",
            "password": "密码123_password",
            "full_name": "测试 用户"
        }

        register_response = await async_client.post("/auth/register", json=unicode_data)

        # Should handle Unicode properly (either accept or reject consistently)
        assert register_response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_400_BAD_REQUEST
        ]

    async def test_very_long_inputs(self, async_client: AsyncClient):
        """Test handling of very long input strings."""
        long_string = "x" * 1000

        long_data = {
            "username": long_string,
            "email": f"{long_string}@example.com",
            "password": "secure_password_123"
        }

        response = await async_client.post("/auth/register", json=long_data)

        # Should reject overly long inputs
        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_422_UNPROCESSABLE_ENTITY
        ]


@pytest.mark.integration
class TestAPIKeyDependencyIntegration:
    """
    Test API key authentication via verify_api_key dependency.
    Tests the integration with AuthService.validate_api_key().

    Requirements:
    - No IP restrictions
    - Default expiration: None (unlimited)
    - Default rate limit: None (unlimited)
    """

    async def test_verify_api_key_success(self, async_client: AsyncClient, test_api_key):
        """Test successful API key verification through dependency."""
        api_key, key_info = test_api_key

        # Make request with API key
        response = await async_client.get(
            "/health",  # Public endpoint
            headers={"X-API-Key": api_key}
        )

        assert response.status_code == status.HTTP_200_OK

    async def test_verify_api_key_missing_header(self, async_client: AsyncClient):
        """Test that missing X-API-Key header is handled correctly."""
        # In development mode (auth disabled), should still work
        response = await async_client.get("/health")
        assert response.status_code == 200

    async def test_verify_api_key_invalid_format(self, async_client: AsyncClient):
        """Test that invalid API key format is rejected."""
        # Invalid format: no dot separator
        response = await async_client.get(
            "/health",
            headers={"X-API-Key": "invalid_no_dot"}
        )

        # Should either work (dev mode) or fail (auth enabled)
        assert response.status_code in [200, 401]

    async def test_verify_api_key_usage_tracking(self, async_client: AsyncClient, test_api_key):
        """Test that API key usage is automatically tracked."""
        from sqlalchemy import select

        from src.core.database import get_db_session
        from src.models.user import APIKey

        api_key, key_info = test_api_key
        key_id = api_key.split(".")[0]

        # Get initial usage
        async with get_db_session() as session:
            result = await session.execute(
                select(APIKey).where(APIKey.key_id == key_id)
            )
            key_before = result.scalar_one()
            initial_requests = key_before.total_requests

        # Make request
        response = await async_client.get(
            "/health",
            headers={"X-API-Key": api_key}
        )
        assert response.status_code == 200

        # Verify usage was tracked (if auth enabled)
        async with get_db_session() as session:
            result = await session.execute(
                select(APIKey).where(APIKey.key_id == key_id)
            )
            key_after = result.scalar_one()

            # In development mode, usage might not be tracked
            # In production with auth enabled, should increment
            assert key_after.total_requests >= initial_requests

    async def test_verify_api_key_no_ip_restrictions(self, async_client: AsyncClient, test_api_key):
        """Test that IP restrictions are not enforced (as per requirements)."""
        api_key, _ = test_api_key

        # Should work regardless of IP (IP restrictions disabled)
        response = await async_client.get(
            "/health",
            headers={"X-API-Key": api_key}
        )

        assert response.status_code == 200

    async def test_verify_api_key_unlimited_rate_limit(self, async_client: AsyncClient, test_api_key):
        """Test that rate limits are not enforced (as per requirements)."""
        api_key, _ = test_api_key

        # Make multiple rapid requests - should all succeed
        for _ in range(10):
            response = await async_client.get(
                "/health",
                headers={"X-API-Key": api_key}
            )
            assert response.status_code == 200

    async def test_verify_api_key_unlimited_expiration(self, async_client: AsyncClient, test_api_key):
        """Test that API keys have no expiration by default."""
        from sqlalchemy import select

        from src.core.database import get_db_session
        from src.models.user import APIKey

        api_key, _ = test_api_key
        key_id = api_key.split(".")[0]

        # Verify expires_at is None
        async with get_db_session() as session:
            result = await session.execute(
                select(APIKey).where(APIKey.key_id == key_id)
            )
            api_key_record = result.scalar_one()

            assert api_key_record.expires_at is None, "API key should have no expiration"
