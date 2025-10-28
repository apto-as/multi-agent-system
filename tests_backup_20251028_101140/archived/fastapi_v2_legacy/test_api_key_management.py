"""
Integration tests for API Key Management endpoints.
Tests user self-service API key creation, listing, and revocation.
"""

import pytest
from fastapi import status

from src.models.user import APIKeyScope, UserRole

pytestmark = pytest.mark.asyncio


class TestAPIKeyManagement:
    """Test suite for API key management endpoints."""

    @pytest.fixture
    async def test_user(self, db_session, auth_service):
        """Create test user for API key operations."""
        user = await auth_service.create_user(
            username="api_key_test_user",
            email="apikey@test.com",
            password="SecurePassword123!",
            full_name="API Key Test User",
            roles=[UserRole.USER],
        )
        yield user

        # Cleanup - revoke all API keys
        api_keys = await auth_service.list_user_api_keys(user.id)
        for key in api_keys:
            await auth_service.revoke_api_key(key.key_id, user.id)

    @pytest.fixture
    def auth_headers(self, test_user):
        """Create JWT authentication headers for test user."""
        from src.api.security import create_access_token

        token = create_access_token(
            {
                "sub": str(test_user.id),
                "username": test_user.username,
                "roles": [role.value for role in test_user.roles],
            }
        )
        return {"Authorization": f"Bearer {token}"}

    async def test_create_api_key_basic(self, client, auth_headers):
        """Test creating basic API key with default settings."""
        response = await client.post(
            "/api/v1/auth/api-keys/",
            json={
                "name": "Test API Key",
                "description": "For testing purposes",
                "scopes": ["read"],
            },
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()

        # Verify response structure
        assert "api_key" in data
        assert "key_info" in data

        # Verify API key format: key_id.raw_key
        api_key = data["api_key"]
        assert "." in api_key
        key_id, raw_key = api_key.split(".", 1)
        assert len(key_id) > 0
        assert len(raw_key) > 0

        # Verify key info
        key_info = data["key_info"]
        assert key_info["key_id"] == key_id
        assert key_info["name"] == "Test API Key"
        assert key_info["description"] == "For testing purposes"
        assert key_info["scopes"] == ["read"]
        assert key_info["is_active"] is True
        assert key_info["expires_at"] is None  # Default: unlimited
        assert key_info["total_requests"] == 0
        assert key_info["last_used_at"] is None

    async def test_create_api_key_with_expiration(self, client, auth_headers):
        """Test creating API key with expiration."""
        response = await client.post(
            "/api/v1/auth/api-keys/",
            json={
                "name": "Expiring Key",
                "description": "Expires in 30 days",
                "scopes": ["read", "write"],
                "expires_days": 30,
            },
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()

        key_info = data["key_info"]
        assert key_info["expires_at"] is not None
        assert key_info["scopes"] == ["read", "write"]

    async def test_create_api_key_multiple_scopes(self, client, auth_headers):
        """Test creating API key with multiple scopes."""
        response = await client.post(
            "/api/v1/auth/api-keys/",
            json={
                "name": "Multi-Scope Key",
                "scopes": ["read", "write", "memory", "tasks"],
            },
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()

        key_info = data["key_info"]
        assert set(key_info["scopes"]) == {"read", "write", "memory", "tasks"}

    async def test_create_api_key_invalid_name(self, client, auth_headers):
        """Test creating API key with invalid name."""
        # Name too short (< 2 characters)
        response = await client.post(
            "/api/v1/auth/api-keys/",
            json={"name": "a", "scopes": ["read"]},
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Name too long (> 128 characters)
        response = await client.post(
            "/api/v1/auth/api-keys/",
            json={"name": "x" * 129, "scopes": ["read"]},
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_create_api_key_no_scopes(self, client, auth_headers):
        """Test creating API key without scopes uses default."""
        response = await client.post(
            "/api/v1/auth/api-keys/",
            json={"name": "Default Scope Key"},
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()

        # Should default to READ scope
        assert data["key_info"]["scopes"] == ["read"]

    async def test_create_api_key_unauthorized(self, client):
        """Test creating API key without authentication fails."""
        response = await client.post(
            "/api/v1/auth/api-keys/",
            json={"name": "Unauthorized Key", "scopes": ["read"]},
        )

        # In development mode with auth disabled, this might succeed
        # In production mode, should fail with 401
        # Check settings to determine expected behavior
        from src.core.config import get_settings

        settings = get_settings()
        if settings.auth_enabled:
            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_list_api_keys_empty(self, client, auth_headers):
        """Test listing API keys when user has none."""
        response = await client.get("/api/v1/auth/api-keys/", headers=auth_headers)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "api_keys" in data
        assert "total" in data
        assert data["total"] == 0
        assert data["api_keys"] == []

    async def test_list_api_keys_with_keys(self, client, auth_headers):
        """Test listing API keys after creating some."""
        # Create multiple API keys
        keys_created = []
        for i in range(3):
            response = await client.post(
                "/api/v1/auth/api-keys/",
                json={
                    "name": f"Test Key {i + 1}",
                    "description": f"Description {i + 1}",
                    "scopes": ["read"],
                },
                headers=auth_headers,
            )
            assert response.status_code == status.HTTP_201_CREATED
            keys_created.append(response.json()["key_info"])

        # List all keys
        response = await client.get("/api/v1/auth/api-keys/", headers=auth_headers)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["total"] == 3
        assert len(data["api_keys"]) == 3

        # Verify no raw keys are returned
        for key_info in data["api_keys"]:
            assert "key_hash" not in key_info
            assert "key_id" in key_info
            assert "key_prefix" in key_info
            assert "name" in key_info

    async def test_list_api_keys_shows_usage_stats(self, client, auth_headers, auth_service):
        """Test that listing shows usage statistics."""
        # Create API key
        response = await client.post(
            "/api/v1/auth/api-keys/",
            json={"name": "Stats Test Key", "scopes": ["read"]},
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_201_CREATED
        api_key = response.json()["api_key"]

        # Simulate usage by validating the key
        await auth_service.validate_api_key(api_key, ip_address="127.0.0.1")

        # List keys
        response = await client.get("/api/v1/auth/api-keys/", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["total"] == 1

        key_info = data["api_keys"][0]
        assert key_info["total_requests"] == 1
        assert key_info["last_used_at"] is not None

    async def test_revoke_api_key(self, client, auth_headers):
        """Test revoking an API key."""
        # Create API key
        response = await client.post(
            "/api/v1/auth/api-keys/",
            json={"name": "Key to Revoke", "scopes": ["read"]},
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_201_CREATED
        key_id = response.json()["key_info"]["key_id"]

        # Revoke key
        response = await client.delete(f"/api/v1/auth/api-keys/{key_id}", headers=auth_headers)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "API key revoked successfully"
        assert data["key_id"] == key_id

        # Verify key is inactive
        response = await client.get("/api/v1/auth/api-keys/", headers=auth_headers)
        data = response.json()

        revoked_key = next((k for k in data["api_keys"] if k["key_id"] == key_id), None)
        assert revoked_key is not None
        assert revoked_key["is_active"] is False

    async def test_revoke_nonexistent_key(self, client, auth_headers):
        """Test revoking a key that doesn't exist."""
        fake_key_id = "nonexistent_key_id_12345"

        response = await client.delete(f"/api/v1/auth/api-keys/{fake_key_id}", headers=auth_headers)

        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_revoke_other_users_key(self, client, auth_service, db_session):
        """Test that users cannot revoke other users' API keys."""
        # Create first user and their API key
        user1 = await auth_service.create_user(
            username="user1_key_test",
            email="user1_key@test.com",
            password="Password123!",
        )
        raw_key1, api_key1 = await auth_service.create_api_key(
            user_id=user1.id, name="User1 Key", scopes=[APIKeyScope.READ]
        )

        # Create second user
        user2 = await auth_service.create_user(
            username="user2_key_test",
            email="user2_key@test.com",
            password="Password123!",
        )

        # Create auth headers for user2
        from src.api.security import create_access_token

        token = create_access_token(
            {"sub": str(user2.id), "username": user2.username, "roles": ["user"]}
        )
        user2_headers = {"Authorization": f"Bearer {token}"}

        # User2 tries to revoke User1's key
        response = await client.delete(
            f"/api/v1/auth/api-keys/{api_key1.key_id}", headers=user2_headers
        )

        # Should fail with 404 (not revealing if key exists)
        assert response.status_code == status.HTTP_404_NOT_FOUND

        # Cleanup
        await auth_service.revoke_api_key(api_key1.key_id, user1.id)

    async def test_api_key_shown_only_once(self, client, auth_headers):
        """Test that raw API key is only shown during creation."""
        # Create API key
        create_response = await client.post(
            "/api/v1/auth/api-keys/",
            json={"name": "One-Time Key", "scopes": ["read"]},
            headers=auth_headers,
        )
        assert create_response.status_code == status.HTTP_201_CREATED

        raw_api_key = create_response.json()["api_key"]
        key_id = create_response.json()["key_info"]["key_id"]

        # List keys - should NOT contain raw API key
        list_response = await client.get("/api/v1/auth/api-keys/", headers=auth_headers)
        assert list_response.status_code == status.HTTP_200_OK

        for key_info in list_response.json()["api_keys"]:
            assert "api_key" not in key_info
            assert raw_api_key not in str(key_info)
            # Only prefix should be shown
            if key_info["key_id"] == key_id:
                assert key_info["key_prefix"] == raw_api_key.split(".")[1][:8]

    async def test_create_api_key_full_scope(self, client, auth_headers):
        """Test creating API key with FULL scope."""
        response = await client.post(
            "/api/v1/auth/api-keys/",
            json={"name": "Full Access Key", "scopes": ["full"]},
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["key_info"]["scopes"] == ["full"]

    async def test_api_key_validation_after_creation(self, client, auth_headers, auth_service):
        """Test that created API key can be validated."""
        # Create API key
        response = await client.post(
            "/api/v1/auth/api-keys/",
            json={"name": "Validation Test Key", "scopes": ["read", "write"]},
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_201_CREATED

        raw_api_key = response.json()["api_key"]

        # Validate the key
        user, api_key = await auth_service.validate_api_key(
            raw_api_key, required_scope=APIKeyScope.READ
        )

        assert user is not None
        assert api_key is not None
        assert api_key.name == "Validation Test Key"
        assert APIKeyScope.READ in api_key.scopes
        assert APIKeyScope.WRITE in api_key.scopes

    async def test_revoked_key_cannot_be_used(self, client, auth_headers, auth_service):
        """Test that revoked API key cannot be validated."""
        # Create API key
        response = await client.post(
            "/api/v1/auth/api-keys/",
            json={"name": "Key to Revoke and Test", "scopes": ["read"]},
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_201_CREATED

        raw_api_key = response.json()["api_key"]
        key_id = response.json()["key_info"]["key_id"]

        # Verify key works
        user, api_key = await auth_service.validate_api_key(raw_api_key)
        assert user is not None

        # Revoke key
        revoke_response = await client.delete(
            f"/api/v1/auth/api-keys/{key_id}", headers=auth_headers
        )
        assert revoke_response.status_code == status.HTTP_200_OK

        # Try to validate revoked key
        from src.services.auth_service import TokenExpiredError

        with pytest.raises(TokenExpiredError):
            await auth_service.validate_api_key(raw_api_key)
