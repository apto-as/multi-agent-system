"""
RBAC Permission Validation Test Suite.

Tests permission matrix enforcement from docs/security/RBAC_PERMISSION_MATRIX.md.

Security Requirements:
- V-RBAC-1: Permission checks must fetch agent from database (namespace isolation)
- V-RBAC-2: All permission checks must be audited
- V-RBAC-3: Ownership checks for license:read and license:usage:read
- V-RBAC-4: Fail-secure for unknown operations/roles

Test Categories:
1. Permission Matrix Validation (8 tests)
2. Ownership Validation (4 tests)
3. Security Boundaries (4 tests)
4. Decorator Integration (4 tests)

Total: 20 tests
"""

from uuid import uuid4

import pytest

from src.models.agent import Agent
from src.models.audit_log import SecurityAuditLog


class TestPermissionMatrix:
    """
    Category 1: Permission Matrix Validation (8 tests).

    Validates RBAC permission matrix from docs/security/RBAC_PERMISSION_MATRIX.md:

    | Role   | license:validate | license:generate | license:revoke | license:admin |
    |--------|------------------|------------------|----------------|---------------|
    | Viewer | ✅               | ❌               | ❌             | ❌            |
    | Editor | ✅               | ✅               | ❌             | ❌            |
    | Admin  | ✅               | ✅               | ✅             | ✅            |
    """

    async def test_viewer_can_validate_license(self, test_session, viewer_agent):
        """Viewer role can validate licenses (READ operation)."""
        from src.security.rbac import check_permission

        allowed = await check_permission(
            test_session,
            viewer_agent.id,
            "license:validate",
        )
        assert allowed is True, "Viewer should be able to validate licenses"

    async def test_viewer_cannot_generate_license(self, test_session, viewer_agent):
        """Viewer role CANNOT generate licenses (lacks permission)."""
        from src.security.rbac import check_permission

        allowed = await check_permission(
            test_session,
            viewer_agent.id,
            "license:generate",
        )
        assert allowed is False, "Viewer should NOT be able to generate licenses"

    async def test_editor_can_generate_license(self, test_session, editor_agent):
        """Editor role can generate licenses."""
        from src.security.rbac import check_permission

        allowed = await check_permission(
            test_session,
            editor_agent.id,
            "license:generate",
        )
        assert allowed is True, "Editor should be able to generate licenses"

    async def test_editor_cannot_revoke_license(self, test_session, editor_agent):
        """Editor role CANNOT revoke licenses (ADMIN only)."""
        from src.security.rbac import check_permission

        allowed = await check_permission(
            test_session,
            editor_agent.id,
            "license:revoke",
        )
        assert allowed is False, "Editor should NOT be able to revoke licenses"

    async def test_admin_can_revoke_license(self, test_session, admin_agent):
        """Admin role can revoke licenses."""
        from src.security.rbac import check_permission

        allowed = await check_permission(
            test_session,
            admin_agent.id,
            "license:revoke",
        )
        assert allowed is True, "Admin should be able to revoke licenses"

    async def test_admin_has_all_permissions(self, test_session, admin_agent):
        """
        Admin role has ALL permissions (8 operations).

        Validates that admin has full access to:
        - license:validate, license:read, license:usage:read
        - license:generate, license:revoke
        - license:admin, agent:update:tier, system:audit
        """
        from src.security.rbac import check_permission

        operations = [
            "license:validate",
            "license:read",
            "license:usage:read",
            "license:generate",
            "license:revoke",
            "license:admin",
            "agent:update:tier",
            "system:audit",
        ]

        for operation in operations:
            allowed = await check_permission(
                test_session, admin_agent.id, operation
            )
            assert allowed is True, f"Admin should have {operation} permission"

    async def test_unknown_operation_denies_all_roles(self, test_session, admin_agent):
        """
        Unknown operation denies even ADMIN (fail-secure).

        V-RBAC-4: System must fail-secure for undefined operations.
        """
        from src.security.rbac import check_permission

        allowed = await check_permission(
            test_session,
            admin_agent.id,
            "unknown:operation",  # Not in permission matrix
        )
        assert allowed is False, "Unknown operation should be denied even for admin"

    async def test_unknown_role_defaults_to_viewer(self, test_session):
        """
        Unknown role defaults to viewer permissions (fail-secure).

        V-RBAC-4: Invalid roles should default to minimal permissions (viewer).
        """
        from src.security.rbac import check_permission

        # Create agent with invalid role
        agent = Agent(
            id=str(uuid4()),
            agent_id="test-unknown-role",
            display_name="Test Unknown Role",
            namespace="test",
            status="active",
            health_score=1.0,
            role="invalid_role",  # Not in Role enum
        )
        test_session.add(agent)
        await test_session.commit()
        await test_session.refresh(agent)

        # Should default to viewer (can validate, cannot generate)
        allowed_validate = await check_permission(
            test_session, agent.id, "license:validate"
        )
        assert allowed_validate is True, "Unknown role should default to viewer (can validate)"

        allowed_generate = await check_permission(
            test_session, agent.id, "license:generate"
        )
        assert allowed_generate is False, "Unknown role should default to viewer (cannot generate)"


class TestOwnershipChecks:
    """
    Category 2: Ownership Validation (4 tests).

    Tests V-RBAC-3: Ownership checks for license:read and license:usage:read.

    Rules:
    - Viewer/Editor: Can only read licenses they own
    - Admin: Can read any license (no ownership check)
    - Ownership not required for non-READ operations (generate, revoke, etc.)
    """

    async def test_viewer_can_read_own_license(self, test_session, viewer_agent):
        """Viewer can read licenses they own."""
        from src.security.rbac import check_permission

        allowed = await check_permission(
            test_session,
            viewer_agent.id,
            "license:read",
            resource_owner_id=viewer_agent.id,  # Owns resource
        )
        assert allowed is True, "Viewer should be able to read their own licenses"

    async def test_viewer_cannot_read_other_license(self, test_session, viewer_agent, editor_agent):
        """Viewer CANNOT read licenses owned by others."""
        from src.security.rbac import check_permission

        allowed = await check_permission(
            test_session,
            viewer_agent.id,
            "license:read",
            resource_owner_id=editor_agent.id,  # Does NOT own
        )
        assert allowed is False, "Viewer should NOT be able to read others' licenses"

    async def test_admin_can_read_any_license(self, test_session, admin_agent, viewer_agent):
        """Admin can read licenses owned by anyone (no ownership check)."""
        from src.security.rbac import check_permission

        allowed = await check_permission(
            test_session,
            admin_agent.id,
            "license:read",
            resource_owner_id=viewer_agent.id,  # Does not own, but ADMIN
        )
        assert allowed is True, "Admin should be able to read any license"

    async def test_ownership_not_required_for_generate(self, test_session, editor_agent):
        """license:generate does NOT require ownership check."""
        from src.security.rbac import check_permission

        # resource_owner_id should be ignored for non-ownership operations
        allowed = await check_permission(
            test_session,
            editor_agent.id,
            "license:generate",
            resource_owner_id=uuid4(),  # Random owner, should be ignored
        )
        assert allowed is True, "license:generate should not require ownership check"


class TestSecurityBoundaries:
    """
    Category 3: Security Boundaries (4 tests).

    Tests V-RBAC-1 (namespace isolation) and V-RBAC-2 (audit logging).

    V-RBAC-1: Permission checks must fetch agent from database (never trust client)
    V-RBAC-2: All permission checks must be audited (ALLOW and DENY)
    """

    async def test_nonexistent_agent_denied(self, test_session):
        """Non-existent agent is DENIED (V-RBAC-1: fetch from DB)."""
        from src.security.rbac import check_permission

        fake_agent_id = uuid4()

        allowed = await check_permission(
            test_session,
            fake_agent_id,
            "license:validate",
        )
        assert allowed is False, "Non-existent agent should be denied"

    async def test_permission_check_audited_allow(self, test_session, viewer_agent):
        """
        ALLOW permission check is audited (V-RBAC-2).

        Validates that successful permission checks are logged to security_audit_logs.
        """
        from sqlalchemy import select

        from src.security.rbac import check_permission

        # Clear existing audit logs for this agent
        await test_session.execute(
            SecurityAuditLog.__table__.delete().where(
                SecurityAuditLog.user_id == str(viewer_agent.id)
            )
        )
        await test_session.commit()

        # Perform permission check
        await check_permission(
            test_session,
            viewer_agent.id,
            "license:validate",
        )
        await test_session.commit()

        # Verify audit log
        stmt = select(SecurityAuditLog).where(
            SecurityAuditLog.user_id == str(viewer_agent.id)
        )
        result = await test_session.execute(stmt)
        logs = result.scalars().all()

        assert len(logs) >= 1, "Permission check should create audit log"
        latest_log = logs[-1]
        assert latest_log.event_type == "permission_check", "Event type should be permission_check"
        assert latest_log.details["operation"] == "license:validate", "Operation should be logged"
        assert latest_log.details["result"] == "ALLOW", "Result should be ALLOW"

    async def test_permission_check_audited_deny(self, test_session, viewer_agent):
        """
        DENY permission check is also audited (V-RBAC-2).

        Validates that failed permission checks are logged to security_audit_logs.
        """
        from sqlalchemy import select

        from src.security.rbac import check_permission

        # Clear existing audit logs for this agent
        await test_session.execute(
            SecurityAuditLog.__table__.delete().where(
                SecurityAuditLog.user_id == str(viewer_agent.id)
            )
        )
        await test_session.commit()

        # Perform denied permission check
        await check_permission(
            test_session,
            viewer_agent.id,
            "license:generate",  # Viewer lacks this permission
        )
        await test_session.commit()

        # Verify audit log
        stmt = select(SecurityAuditLog).where(
            SecurityAuditLog.user_id == str(viewer_agent.id)
        )
        result = await test_session.execute(stmt)
        logs = result.scalars().all()

        assert len(logs) >= 1, "Denied permission check should create audit log"
        latest_log = logs[-1]
        assert latest_log.event_type == "permission_check", "Event type should be permission_check"
        assert latest_log.details["result"] == "DENY", "Result should be DENY"

    async def test_fail_secure_unknown_operation(self, test_session, admin_agent):
        """
        Unknown operation fails secure (DENY even for ADMIN).

        V-RBAC-4: System must fail-secure for undefined operations.
        Validates that audit log shows DENY for unknown operations.
        """
        from sqlalchemy import select

        from src.security.rbac import check_permission

        # Clear existing audit logs for this agent
        await test_session.execute(
            SecurityAuditLog.__table__.delete().where(
                SecurityAuditLog.user_id == str(admin_agent.id)
            )
        )
        await test_session.commit()

        allowed = await check_permission(
            test_session,
            admin_agent.id,
            "license:delete",  # Not in permission matrix
        )
        assert allowed is False, "Unknown operation should fail-secure (DENY)"

        # Verify audit log shows DENY
        await test_session.commit()
        stmt = select(SecurityAuditLog).where(
            SecurityAuditLog.user_id == str(admin_agent.id)
        )
        result = await test_session.execute(stmt)
        logs = result.scalars().all()
        assert len(logs) >= 1, "Unknown operation should be audited"
        latest_log = logs[-1]
        assert latest_log.details["result"] == "DENY", "Unknown operation should be denied"


class TestRequirePermissionDecorator:
    """
    Category 4: Decorator Integration (4 tests).

    Tests @require_permission decorator on MCP tools.

    Requirements:
    - Decorator must enforce permission checks
    - Must raise PermissionError for unauthorized users
    - Must require db_session and agent_id parameters
    """

    async def test_decorator_allows_authorized_user(self, test_session, editor_agent):
        """Decorator allows user with correct permission."""
        from src.security.rbac import require_permission

        @require_permission("license:generate")
        async def test_function(db_session, agent_id):
            return {"success": True}

        result = await test_function(
            db_session=test_session,
            agent_id=editor_agent.id,
        )
        assert result["success"] is True, "Authorized user should be allowed"

    async def test_decorator_denies_unauthorized_user(self, test_session, viewer_agent):
        """Decorator raises PermissionError for unauthorized user."""
        from src.core.exceptions import PermissionError
        from src.security.rbac import require_permission

        @require_permission("license:generate")
        async def test_function(db_session, agent_id):
            return {"success": True}

        with pytest.raises(PermissionError) as exc_info:
            await test_function(
                db_session=test_session,
                agent_id=viewer_agent.id,
            )

        assert "Permission denied" in str(exc_info.value), "Should raise PermissionError with message"

    async def test_decorator_requires_db_session(self):
        """Decorator raises error if db_session missing."""
        from src.core.exceptions import PermissionError
        from src.security.rbac import require_permission

        @require_permission("license:generate")
        async def test_function(agent_id):  # Missing db_session
            return {"success": True}

        with pytest.raises(PermissionError) as exc_info:
            await test_function(agent_id=uuid4())

        assert "requires db_session" in str(exc_info.value), "Should require db_session parameter"

    async def test_decorator_requires_agent_id(self, test_session):
        """Decorator raises error if agent_id missing."""
        from src.core.exceptions import PermissionError
        from src.security.rbac import require_permission

        @require_permission("license:generate")
        async def test_function(db_session):  # Missing agent_id
            return {"success": True}

        with pytest.raises(PermissionError) as exc_info:
            await test_function(db_session=test_session)

        assert "agent_id" in str(exc_info.value), "Should require agent_id parameter"


# ============================================================================
# Test Fixtures (add to tests/conftest.py)
# ============================================================================
# These fixtures should be added to tests/conftest.py for reusability:

"""
@pytest_asyncio.fixture
async def viewer_agent(test_session):
    '''Create agent with viewer role.'''
    from uuid import uuid4
    from src.models.agent import Agent

    agent = Agent(
        id=str(uuid4()),
        agent_id="test-viewer",
        display_name="Test Viewer",
        namespace="test",
        status="active",
        health_score=1.0,
        role="viewer",
    )
    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def editor_agent(test_session):
    '''Create agent with editor role.'''
    from uuid import uuid4
    from src.models.agent import Agent

    agent = Agent(
        id=str(uuid4()),
        agent_id="test-editor",
        display_name="Test Editor",
        namespace="test",
        status="active",
        health_score=1.0,
        role="editor",
    )
    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def admin_agent(test_session):
    '''Create agent with admin role.'''
    from uuid import uuid4
    from src.models.agent import Agent

    agent = Agent(
        id=str(uuid4()),
        agent_id="test-admin",
        display_name="Test Admin",
        namespace="test",
        status="active",
        health_score=1.0,
        role="admin",
    )
    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)
    return agent
"""
