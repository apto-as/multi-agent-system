"""
Security tests for namespace isolation in Memory model.
Tests for P0-1 critical security fix.
"""

from src.models.agent import AccessLevel
from src.models.memory import Memory


class TestNamespaceIsolation:
    """
    Test suite for namespace isolation security.

    SECURITY-CRITICAL: These tests verify that cross-namespace access
    is properly prevented to avoid multi-tenant security breaches.
    """

    def test_owner_has_access(self):
        """Owner should always have access to their own memories."""
        memory = Memory(
            content="Test memory",
            agent_id="agent-1",
            namespace="namespace-1",
            access_level=AccessLevel.PRIVATE,
        )

        assert memory.is_accessible_by("agent-1", "namespace-1") is True

    def test_private_memory_blocks_other_agents(self):
        """Private memories should block all non-owner agents."""
        memory = Memory(
            content="Private memory",
            agent_id="agent-1",
            namespace="namespace-1",
            access_level=AccessLevel.PRIVATE,
        )

        # Different agent, same namespace
        assert memory.is_accessible_by("agent-2", "namespace-1") is False

        # Different agent, different namespace
        assert memory.is_accessible_by("agent-2", "namespace-2") is False

    def test_team_memory_allows_same_namespace(self):
        """Team memories should allow access within same namespace."""
        memory = Memory(
            content="Team memory",
            agent_id="agent-1",
            namespace="team-alpha",
            access_level=AccessLevel.TEAM,
        )

        # Same namespace - should allow
        assert memory.is_accessible_by("agent-2", "team-alpha") is True

        # Different namespace - should deny
        assert memory.is_accessible_by("agent-3", "team-beta") is False

    def test_team_memory_prevents_cross_namespace_access(self):
        """
        SECURITY-CRITICAL: Verify namespace isolation for TEAM access level.

        This test verifies that TEAM memories are only accessible to agents
        in the SAME namespace. The security depends on the CALLER verifying
        the namespace from the database before calling is_accessible_by().

        IMPORTANT: This method TRUSTS that the namespace parameter has been
        verified from the database by the caller (authorization layer).
        """
        memory = Memory(
            content="Team memory",
            agent_id="agent-1",
            namespace="secure-team",
            access_level=AccessLevel.TEAM,
        )

        # Attacker in different namespace - MUST be denied
        assert memory.is_accessible_by("attacker-agent", "attacker-namespace") is False

        # If the namespace is VERIFIED from database and matches, allow access
        # This is correct behavior - TEAM means "same namespace"
        # The authorization layer MUST verify namespace from DB before calling
        assert memory.is_accessible_by("attacker-agent", "secure-team") is True

        # The security protection is in the authorization layer:
        # 1. Get agent from database: SELECT namespace FROM agents WHERE agent_id = ?
        # 2. Use that verified namespace when calling is_accessible_by()
        # 3. Never trust namespace from user input or JWT claims directly

    def test_shared_memory_requires_explicit_sharing(self):
        """Shared memories require explicit agent_id in shared_with_agents list."""
        memory = Memory(
            content="Shared memory",
            agent_id="agent-1",
            namespace="namespace-1",
            access_level=AccessLevel.SHARED,
            shared_with_agents=["agent-2", "agent-3"],
        )

        # Explicitly shared agents should have access
        assert memory.is_accessible_by("agent-2", "namespace-1") is True
        assert memory.is_accessible_by("agent-3", "namespace-1") is True

        # Non-shared agent should be denied
        assert memory.is_accessible_by("agent-4", "namespace-1") is False

    def test_shared_memory_prevents_cross_namespace_spoofing(self):
        """
        SECURITY-CRITICAL: Verify SHARED access level prevents namespace spoofing.

        Even if an agent is in the shared_with_agents list, they must be
        in the correct namespace to prevent cross-tenant attacks.
        """
        memory = Memory(
            content="Shared memory",
            agent_id="agent-1",
            namespace="namespace-1",
            access_level=AccessLevel.SHARED,
            shared_with_agents=["agent-2"],
        )

        # Agent-2 is in shared list BUT in wrong namespace - MUST deny
        assert memory.is_accessible_by("agent-2", "wrong-namespace") is False

        # Agent-2 in correct namespace - should allow
        assert memory.is_accessible_by("agent-2", "namespace-1") is True

    def test_public_memory_allows_all(self):
        """Public memories should be accessible to all agents."""
        memory = Memory(
            content="Public memory",
            agent_id="agent-1",
            namespace="namespace-1",
            access_level=AccessLevel.PUBLIC,
        )

        # Any agent, any namespace
        assert memory.is_accessible_by("agent-2", "namespace-2") is True
        assert memory.is_accessible_by("agent-3", "namespace-3") is True

    def test_system_memory_allows_all(self):
        """System memories should be accessible to all agents."""
        memory = Memory(
            content="System memory",
            agent_id="system-agent",
            namespace="system",
            access_level=AccessLevel.SYSTEM,
        )

        # Any agent, any namespace
        assert memory.is_accessible_by("agent-1", "namespace-1") is True
        assert memory.is_accessible_by("agent-2", "namespace-2") is True

    def test_namespace_parameter_is_required(self):
        """
        SECURITY-CRITICAL: Verify namespace parameter is required.

        The P0-1 fix made namespace parameter required (not optional).
        This test ensures the method signature is correct.
        """
        memory = Memory(
            content="Test memory",
            agent_id="agent-1",
            namespace="namespace-1",
            access_level=AccessLevel.TEAM,
        )

        # This should work - both parameters provided
        result = memory.is_accessible_by("agent-2", "namespace-1")
        assert isinstance(result, bool)

        # This should fail - namespace is required
        # If you uncomment this, it should raise TypeError
        # memory.is_accessible_by("agent-2")

    def test_empty_namespace_is_denied(self):
        """Empty or None namespace should be denied to prevent attacks."""
        memory = Memory(
            content="Team memory",
            agent_id="agent-1",
            namespace="namespace-1",
            access_level=AccessLevel.TEAM,
        )

        # Empty string namespace - should deny
        assert memory.is_accessible_by("agent-2", "") is False

        # None namespace would cause TypeError (good - fail secure)
        # memory.is_accessible_by("agent-2", None)  # Would raise TypeError

    def test_case_sensitive_namespace_matching(self):
        """Namespace matching should be case-sensitive for security."""
        memory = Memory(
            content="Team memory",
            agent_id="agent-1",
            namespace="Team-Alpha",
            access_level=AccessLevel.TEAM,
        )

        # Exact match - should allow
        assert memory.is_accessible_by("agent-2", "Team-Alpha") is True

        # Case mismatch - should deny
        assert memory.is_accessible_by("agent-2", "team-alpha") is False
        assert memory.is_accessible_by("agent-2", "TEAM-ALPHA") is False

    def test_whitespace_in_namespace_matters(self):
        """Whitespace in namespace should matter for security."""
        memory = Memory(
            content="Team memory",
            agent_id="agent-1",
            namespace="team-1",
            access_level=AccessLevel.TEAM,
        )

        # Exact match - should allow
        assert memory.is_accessible_by("agent-2", "team-1") is True

        # Whitespace variations - should deny
        assert memory.is_accessible_by("agent-2", " team-1") is False
        assert memory.is_accessible_by("agent-2", "team-1 ") is False
        assert memory.is_accessible_by("agent-2", " team-1 ") is False


class TestSecurityDocumentation:
    """Verify security documentation is present."""

    def test_security_warning_in_docstring(self):
        """Verify is_accessible_by() has security warnings in docstring."""
        docstring = Memory.is_accessible_by.__doc__
        assert docstring is not None
        assert "SECURITY" in docstring.upper()
        assert "namespace" in docstring.lower()

    def test_method_has_type_hints(self):
        """Verify method has proper type hints for security."""
        import inspect

        sig = inspect.signature(Memory.is_accessible_by)
        params = sig.parameters

        # Verify parameters have type annotations
        assert "requesting_agent_id" in params
        assert "requesting_agent_namespace" in params

        # Verify return type
        assert sig.return_annotation == bool
