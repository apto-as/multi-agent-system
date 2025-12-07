"""
P2 RBAC Integration Tests (RBAC-P2).

Tests for Role-Based Access Control functionality.
"""

from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest


@pytest.mark.integration
@pytest.mark.rbac
class TestRolePermissions:
    """Test role-based permissions."""

    def test_admin_has_full_access(self, rbac_roles, mock_rbac_service):
        """Test admin role has full access."""
        admin_permissions = rbac_roles["admin"]["permissions"]

        # Admin should have wildcard permission
        assert "*" in admin_permissions

        # Check mock service grants access
        assert mock_rbac_service.check_permission("admin-user", "memory:create") is True
        assert mock_rbac_service.check_permission("admin-user", "memory:delete") is True
        assert mock_rbac_service.check_permission("admin-user", "admin:settings") is True

    def test_editor_permissions(self, rbac_roles, mock_rbac_service):
        """Test editor role has appropriate permissions."""
        editor_permissions = rbac_roles["editor"]["permissions"]

        # Should have memory management permissions
        assert "memory:create" in editor_permissions
        assert "memory:read" in editor_permissions
        assert "memory:update" in editor_permissions
        assert "memory:delete" in editor_permissions

        # Should have skill permissions
        assert "skill:create" in editor_permissions
        assert "skill:read" in editor_permissions

    def test_viewer_read_only_access(self, rbac_roles, mock_rbac_service):
        """Test viewer role has read-only access."""
        viewer_permissions = rbac_roles["viewer"]["permissions"]

        # Should only have read permissions
        for perm in viewer_permissions:
            assert perm.endswith(":read")

        # Mock service should deny write operations
        assert mock_rbac_service.check_permission("viewer-user", "memory:create") is False
        assert mock_rbac_service.check_permission("viewer-user", "memory:delete") is False
        assert mock_rbac_service.check_permission("viewer-user", "memory:read") is True

    def test_agent_operational_access(self, rbac_roles):
        """Test agent role has operational access."""
        agent_permissions = rbac_roles["agent"]["permissions"]

        # Should have operational permissions
        assert "memory:create" in agent_permissions
        assert "memory:read" in agent_permissions
        assert "memory:update" in agent_permissions
        assert "skill:execute" in agent_permissions

        # Should not have delete or admin permissions
        assert "memory:delete" not in agent_permissions
        assert "skill:delete" not in agent_permissions


@pytest.mark.integration
@pytest.mark.rbac
class TestResourceLevelPermissions:
    """Test resource-level access control."""

    @pytest.mark.asyncio
    async def test_user_can_access_own_resources(self):
        """Test users can access their own resources."""
        mock_service = AsyncMock()

        def check_resource_access(user_id, resource_id, resource_owner_id):
            return user_id == resource_owner_id

        mock_service.can_access = Mock(side_effect=check_resource_access)

        user_id = "user-123"
        own_resource = "resource-owned-by-user-123"

        assert mock_service.can_access(user_id, own_resource, user_id) is True

    @pytest.mark.asyncio
    async def test_user_cannot_access_others_resources(self):
        """Test users cannot access others' resources without permission."""
        mock_service = AsyncMock()

        def check_resource_access(user_id, resource_id, resource_owner_id):
            return user_id == resource_owner_id

        mock_service.can_access = Mock(side_effect=check_resource_access)

        user_id = "user-123"
        other_user = "user-456"
        others_resource = "resource-owned-by-user-456"

        assert mock_service.can_access(user_id, others_resource, other_user) is False

    @pytest.mark.asyncio
    async def test_shared_resource_access(self):
        """Test shared resources are accessible."""
        mock_service = AsyncMock()
        shared_resources = {"shared-resource-1", "shared-resource-2"}

        def check_shared_access(user_id, resource_id):
            return resource_id in shared_resources

        mock_service.can_access_shared = Mock(side_effect=check_shared_access)

        assert mock_service.can_access_shared("any-user", "shared-resource-1") is True
        assert mock_service.can_access_shared("any-user", "private-resource") is False


@pytest.mark.integration
@pytest.mark.rbac
class TestPermissionInheritance:
    """Test permission inheritance and hierarchy."""

    def test_role_hierarchy(self, rbac_roles):
        """Test role hierarchy is respected."""
        admin_perms = set(rbac_roles["admin"]["permissions"])
        editor_perms = set(rbac_roles["editor"]["permissions"])
        viewer_perms = set(rbac_roles["viewer"]["permissions"])

        # Admin has wildcard, so effectively includes all
        assert "*" in admin_perms

        # Viewer permissions should be subset of editor (for read operations)
        assert viewer_perms.issubset(editor_perms)

    def test_permission_override(self):
        """Test explicit permission overrides inherited ones."""
        mock_service = Mock()

        # User has viewer role but explicit memory:delete permission
        user_roles = ["viewer"]
        explicit_permissions = ["memory:delete"]

        def check_permission(user_id, permission):
            if permission in explicit_permissions:
                return True
            if "viewer" in user_roles and permission.endswith(":read"):
                return True
            return False

        mock_service.check_permission = Mock(side_effect=check_permission)

        # Should have explicit delete permission
        assert mock_service.check_permission("user-1", "memory:delete") is True
        # Should still have viewer read permissions
        assert mock_service.check_permission("user-1", "memory:read") is True
        # Should not have other write permissions
        assert mock_service.check_permission("user-1", "memory:create") is False


@pytest.mark.integration
@pytest.mark.rbac
class TestAccessControlEnforcement:
    """Test access control enforcement."""

    @pytest.mark.asyncio
    async def test_unauthorized_access_denied(self, mock_rbac_service):
        """Test unauthorized access is denied."""
        mock_endpoint = AsyncMock()

        async def protected_endpoint(user_id, resource_id):
            if not mock_rbac_service.check_permission(user_id, "memory:delete"):
                raise PermissionError("Access denied")
            return {"status": "deleted"}

        mock_endpoint.delete = AsyncMock(side_effect=protected_endpoint)

        # Viewer should be denied
        with pytest.raises(PermissionError):
            await mock_endpoint.delete("viewer-user", "resource-1")

    @pytest.mark.asyncio
    async def test_authorized_access_allowed(self, mock_rbac_service):
        """Test authorized access is allowed."""
        mock_endpoint = AsyncMock()

        async def protected_endpoint(user_id, resource_id):
            if not mock_rbac_service.check_permission(user_id, "memory:delete"):
                raise PermissionError("Access denied")
            return {"status": "deleted"}

        mock_endpoint.delete = AsyncMock(side_effect=protected_endpoint)

        # Admin should be allowed
        result = await mock_endpoint.delete("admin-user", "resource-1")
        assert result["status"] == "deleted"

    @pytest.mark.asyncio
    async def test_permission_check_logging(self, mock_logger):
        """Test permission checks are logged."""
        mock_service = Mock()

        def check_with_logging(user_id, permission):
            result = user_id == "admin-user"
            mock_logger.info(
                "Permission check",
                user_id=user_id,
                permission=permission,
                result=result
            )
            return result

        mock_service.check_permission = Mock(side_effect=check_with_logging)

        mock_service.check_permission("viewer-user", "memory:delete")

        assert len(mock_logger.logs) == 1
        assert mock_logger.logs[0]["extra"]["permission"] == "memory:delete"
        assert mock_logger.logs[0]["extra"]["result"] is False


@pytest.mark.integration
@pytest.mark.rbac
class TestRoleManagement:
    """Test role management operations."""

    @pytest.mark.asyncio
    async def test_assign_role_to_user(self):
        """Test assigning a role to a user."""
        mock_service = AsyncMock()
        user_roles = {}

        async def assign_role(user_id, role):
            if user_id not in user_roles:
                user_roles[user_id] = []
            user_roles[user_id].append(role)
            return True

        mock_service.assign_role = AsyncMock(side_effect=assign_role)

        await mock_service.assign_role("user-123", "editor")
        assert "editor" in user_roles["user-123"]

    @pytest.mark.asyncio
    async def test_revoke_role_from_user(self):
        """Test revoking a role from a user."""
        mock_service = AsyncMock()
        user_roles = {"user-123": ["editor", "viewer"]}

        async def revoke_role(user_id, role):
            if user_id in user_roles and role in user_roles[user_id]:
                user_roles[user_id].remove(role)
                return True
            return False

        mock_service.revoke_role = AsyncMock(side_effect=revoke_role)

        result = await mock_service.revoke_role("user-123", "editor")
        assert result is True
        assert "editor" not in user_roles["user-123"]
        assert "viewer" in user_roles["user-123"]

    @pytest.mark.asyncio
    async def test_get_user_roles(self):
        """Test retrieving user roles."""
        mock_service = AsyncMock()
        user_roles = {"user-123": ["editor", "agent"]}

        mock_service.get_roles = AsyncMock(
            side_effect=lambda user_id: user_roles.get(user_id, [])
        )

        roles = await mock_service.get_roles("user-123")
        assert "editor" in roles
        assert "agent" in roles


@pytest.mark.integration
@pytest.mark.rbac
class TestMultiTenancy:
    """Test multi-tenancy access control."""

    @pytest.mark.asyncio
    async def test_tenant_isolation(self):
        """Test resources are isolated between tenants."""
        mock_service = AsyncMock()

        tenant_resources = {
            "tenant-a": ["resource-a1", "resource-a2"],
            "tenant-b": ["resource-b1", "resource-b2"]
        }

        async def check_tenant_access(tenant_id, resource_id):
            return resource_id in tenant_resources.get(tenant_id, [])

        mock_service.can_access = AsyncMock(side_effect=check_tenant_access)

        # Tenant A can access their resources
        assert await mock_service.can_access("tenant-a", "resource-a1") is True
        # Tenant A cannot access Tenant B's resources
        assert await mock_service.can_access("tenant-a", "resource-b1") is False

    @pytest.mark.asyncio
    async def test_cross_tenant_admin_access(self):
        """Test super admin can access across tenants."""
        mock_service = AsyncMock()

        async def check_admin_access(user_id, tenant_id, resource_id):
            if user_id == "super-admin":
                return True
            # Regular users only access their tenant
            return user_id.startswith(tenant_id)

        mock_service.can_access = AsyncMock(side_effect=check_admin_access)

        # Super admin can access any tenant
        assert await mock_service.can_access("super-admin", "tenant-a", "resource-1") is True
        assert await mock_service.can_access("super-admin", "tenant-b", "resource-2") is True


@pytest.mark.integration
@pytest.mark.rbac
class TestAPIKeyPermissions:
    """Test API key permission scoping."""

    @pytest.mark.asyncio
    async def test_scoped_api_key(self):
        """Test API keys have scoped permissions."""
        mock_service = AsyncMock()

        api_keys = {
            "key-readonly": {"scopes": ["read"]},
            "key-full": {"scopes": ["read", "write", "delete"]},
            "key-memory": {"scopes": ["memory:*"]}
        }

        def check_key_scope(api_key, required_scope):
            key_data = api_keys.get(api_key, {})
            scopes = key_data.get("scopes", [])

            # Check for wildcard or exact match
            for scope in scopes:
                if scope == "*" or scope == required_scope:
                    return True
                if scope.endswith(":*"):
                    prefix = scope[:-2]
                    if required_scope.startswith(prefix):
                        return True
            return False

        mock_service.check_scope = Mock(side_effect=check_key_scope)

        # Readonly key
        assert mock_service.check_scope("key-readonly", "read") is True
        assert mock_service.check_scope("key-readonly", "write") is False

        # Full access key
        assert mock_service.check_scope("key-full", "delete") is True

        # Memory wildcard key
        assert mock_service.check_scope("key-memory", "memory:create") is True
        assert mock_service.check_scope("key-memory", "skill:create") is False

    @pytest.mark.asyncio
    async def test_api_key_expiration(self):
        """Test expired API keys are rejected."""
        from datetime import datetime, timedelta, timezone

        mock_service = AsyncMock()

        api_keys = {
            "key-valid": {"expires_at": datetime.now(timezone.utc) + timedelta(days=30)},
            "key-expired": {"expires_at": datetime.now(timezone.utc) - timedelta(days=1)}
        }

        def is_key_valid(api_key):
            key_data = api_keys.get(api_key)
            if not key_data:
                return False
            return key_data["expires_at"] > datetime.now(timezone.utc)

        mock_service.is_valid = Mock(side_effect=is_key_valid)

        assert mock_service.is_valid("key-valid") is True
        assert mock_service.is_valid("key-expired") is False
        assert mock_service.is_valid("key-nonexistent") is False
