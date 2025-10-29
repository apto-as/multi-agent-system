"""Tests for Cross-Agent Access Policies in Field Encryption.

This test suite validates the 5-tier access control system:
- PRIVATE: Owner only
- TEAM: Same namespace
- SHARED: Explicit agent list
- PUBLIC: All agents
- SYSTEM: System-level access

Security Critical Tests:
- Namespace verification (MUST be from DB, never from JWT)
- Cross-namespace access prevention
- Backward compatibility with v1.0 metadata
"""

import pytest

from src.models.agent import AccessLevel
from src.security.data_encryption import (
    DataClassification,
    EncryptionKeyManager,
    FieldEncryption,
)
from src.security.encryption_policies import CrossAgentAccessPolicy


class TestCrossAgentAccessPolicies:
    """Test suite for cross-agent access control in field encryption."""

    @pytest.fixture
    def key_manager(self):
        """Create encryption key manager."""
        return EncryptionKeyManager()

    @pytest.fixture
    def field_encryption(self, key_manager):
        """Create field encryption instance."""
        return FieldEncryption(key_manager)

    # =====================================================
    # Test 1: PRIVATE Access Level (Owner Only)
    # =====================================================

    @pytest.mark.asyncio
    async def test_private_access_owner_can_decrypt(self, field_encryption):
        """PRIVATE: Owner can decrypt their own data."""
        agent_id = "agent-001"
        namespace = "team-alpha"

        # Encrypt with PRIVATE access
        encrypted = await field_encryption.encrypt_field(
            data="Secret message",
            field_name="content",
            agent_id=agent_id,
            namespace=namespace,
            access_level=AccessLevel.PRIVATE,
        )

        # Owner can decrypt
        decrypted = await field_encryption.decrypt_field(
            encrypted, requesting_agent=agent_id, requesting_namespace=namespace,
        )

        assert decrypted == "Secret message"

    @pytest.mark.asyncio
    async def test_private_access_other_agent_denied(self, field_encryption):
        """PRIVATE: Other agents cannot decrypt, even in same namespace."""
        owner_agent = "agent-001"
        other_agent = "agent-002"
        namespace = "team-alpha"

        # Encrypt with PRIVATE access
        encrypted = await field_encryption.encrypt_field(
            data="Secret message",
            field_name="content",
            agent_id=owner_agent,
            namespace=namespace,
            access_level=AccessLevel.PRIVATE,
        )

        # Other agent (same namespace) should be denied
        with pytest.raises(PermissionError, match="Access denied.*PRIVATE"):
            await field_encryption.decrypt_field(
                encrypted, requesting_agent=other_agent, requesting_namespace=namespace,
            )

    # =====================================================
    # Test 2: TEAM Access Level (Same Namespace)
    # =====================================================

    @pytest.mark.asyncio
    async def test_team_access_same_namespace_allowed(self, field_encryption):
        """TEAM: Agents in same namespace can decrypt."""
        owner_agent = "agent-001"
        team_agent = "agent-002"
        namespace = "team-alpha"

        # Encrypt with TEAM access
        encrypted = await field_encryption.encrypt_field(
            data="Team secret",
            field_name="content",
            agent_id=owner_agent,
            namespace=namespace,
            access_level=AccessLevel.TEAM,
        )

        # Team member can decrypt
        decrypted = await field_encryption.decrypt_field(
            encrypted, requesting_agent=team_agent, requesting_namespace=namespace,
        )

        assert decrypted == "Team secret"

    @pytest.mark.asyncio
    async def test_team_access_different_namespace_denied(self, field_encryption):
        """TEAM: Agents from different namespace are denied."""
        owner_agent = "agent-001"
        other_agent = "agent-003"
        owner_namespace = "team-alpha"
        other_namespace = "team-beta"

        # Encrypt with TEAM access
        encrypted = await field_encryption.encrypt_field(
            data="Team secret",
            field_name="content",
            agent_id=owner_agent,
            namespace=owner_namespace,
            access_level=AccessLevel.TEAM,
        )

        # Agent from different namespace should be denied
        with pytest.raises(PermissionError, match="Different namespace"):
            await field_encryption.decrypt_field(
                encrypted, requesting_agent=other_agent, requesting_namespace=other_namespace,
            )

    # =====================================================
    # Test 3: SHARED Access Level (Explicit List)
    # =====================================================

    @pytest.mark.asyncio
    async def test_shared_access_allowed_agents(self, field_encryption):
        """SHARED: Explicitly shared agents can decrypt."""
        owner_agent = "agent-001"
        shared_agent = "agent-002"
        namespace = "team-alpha"

        # Encrypt with SHARED access
        encrypted = await field_encryption.encrypt_field(
            data="Shared data",
            field_name="content",
            agent_id=owner_agent,
            namespace=namespace,
            access_level=AccessLevel.SHARED,
            shared_with_agents=["agent-002", "agent-004"],
        )

        # Shared agent can decrypt
        decrypted = await field_encryption.decrypt_field(
            encrypted, requesting_agent=shared_agent, requesting_namespace=namespace,
        )

        assert decrypted == "Shared data"

    @pytest.mark.asyncio
    async def test_shared_access_not_in_list_denied(self, field_encryption):
        """SHARED: Agents not in shared list are denied."""
        owner_agent = "agent-001"
        not_shared_agent = "agent-003"
        namespace = "team-alpha"

        # Encrypt with SHARED access
        encrypted = await field_encryption.encrypt_field(
            data="Shared data",
            field_name="content",
            agent_id=owner_agent,
            namespace=namespace,
            access_level=AccessLevel.SHARED,
            shared_with_agents=["agent-002", "agent-004"],
        )

        # Agent not in list should be denied
        with pytest.raises(PermissionError, match="Not in shared agent list"):
            await field_encryption.decrypt_field(
                encrypted, requesting_agent=not_shared_agent, requesting_namespace=namespace,
            )

    @pytest.mark.asyncio
    async def test_shared_access_wrong_namespace_denied(self, field_encryption):
        """SHARED: Agent in list but wrong namespace is denied (namespace spoofing prevention)."""
        owner_agent = "agent-001"
        shared_agent = "agent-002"
        owner_namespace = "team-alpha"
        wrong_namespace = "team-beta"

        # Encrypt with SHARED access
        encrypted = await field_encryption.encrypt_field(
            data="Shared data",
            field_name="content",
            agent_id=owner_agent,
            namespace=owner_namespace,
            access_level=AccessLevel.SHARED,
            shared_with_agents=["agent-002"],
        )

        # Agent in list but from different namespace should be denied
        # This prevents namespace spoofing attacks
        with pytest.raises(PermissionError, match="Namespace mismatch"):
            await field_encryption.decrypt_field(
                encrypted, requesting_agent=shared_agent, requesting_namespace=wrong_namespace,
            )

    # =====================================================
    # Test 4: PUBLIC Access Level (All Agents)
    # =====================================================

    @pytest.mark.asyncio
    async def test_public_access_any_agent_allowed(self, field_encryption):
        """PUBLIC: Any agent can decrypt."""
        owner_agent = "agent-001"
        any_agent = "agent-999"
        owner_namespace = "team-alpha"
        other_namespace = "team-gamma"

        # Encrypt with PUBLIC access
        encrypted = await field_encryption.encrypt_field(
            data="Public announcement",
            field_name="content",
            agent_id=owner_agent,
            namespace=owner_namespace,
            access_level=AccessLevel.PUBLIC,
        )

        # Any agent from any namespace can decrypt
        decrypted = await field_encryption.decrypt_field(
            encrypted, requesting_agent=any_agent, requesting_namespace=other_namespace,
        )

        assert decrypted == "Public announcement"

    # =====================================================
    # Test 5: SYSTEM Access Level
    # =====================================================

    @pytest.mark.asyncio
    async def test_system_access_any_agent_allowed(self, field_encryption):
        """SYSTEM: Any agent can decrypt system-level data."""
        system_agent = "system"
        user_agent = "agent-001"
        namespace = "default"

        # Encrypt with SYSTEM access
        encrypted = await field_encryption.encrypt_field(
            data="System configuration",
            field_name="config",
            agent_id=system_agent,
            namespace=namespace,
            access_level=AccessLevel.SYSTEM,
        )

        # Any agent can decrypt system data
        decrypted = await field_encryption.decrypt_field(
            encrypted, requesting_agent=user_agent, requesting_namespace=namespace,
        )

        assert decrypted == "System configuration"

    # =====================================================
    # Test 6: Backward Compatibility (v1.0 metadata)
    # =====================================================

    @pytest.mark.asyncio
    async def test_backward_compatibility_v1_metadata(self, field_encryption):
        """Backward compatibility: v1.0 metadata (no access_level) defaults to PRIVATE."""
        owner_agent = "agent-001"
        other_agent = "agent-002"
        namespace = "team-alpha"

        # Simulate v1.0 encrypted data (no access_level, no namespace in metadata)
        encrypted = await field_encryption.encrypt_field(
            data="Old encrypted data",
            field_name="content",
            agent_id=owner_agent,
            classification=DataClassification.CONFIDENTIAL,
        )

        # Remove access control fields to simulate v1.0
        encrypted["metadata"]["encryption_version"] = "1.0"
        encrypted["metadata"].pop("access_level", None)
        encrypted["metadata"].pop("namespace", None)
        encrypted["metadata"].pop("shared_with_agents", None)

        # Owner can still decrypt
        decrypted = await field_encryption.decrypt_field(
            encrypted, requesting_agent=owner_agent, requesting_namespace=namespace,
        )
        assert decrypted == "Old encrypted data"

        # Other agent should be denied (defaults to PRIVATE)
        with pytest.raises(PermissionError, match="Access denied"):
            await field_encryption.decrypt_field(
                encrypted, requesting_agent=other_agent, requesting_namespace=namespace,
            )

    # =====================================================
    # Test 7: Metadata Validation
    # =====================================================

    def test_validate_metadata_missing_fields(self):
        """Metadata validation: Missing required fields in v2.0 metadata."""
        invalid_metadata = {
            "agent_id": "agent-001",
            "encryption_version": "2.0",  # v2.0 requires namespace and access_level
            # Missing: namespace, access_level
        }

        is_valid, error = CrossAgentAccessPolicy.validate_metadata(invalid_metadata)

        assert not is_valid
        assert "Missing required field" in error

    def test_validate_metadata_invalid_access_level(self):
        """Metadata validation: Invalid access_level value."""
        invalid_metadata = {
            "agent_id": "agent-001",
            "namespace": "team-alpha",
            "access_level": "INVALID_LEVEL",
        }

        is_valid, error = CrossAgentAccessPolicy.validate_metadata(invalid_metadata)

        assert not is_valid
        assert "Invalid access_level" in error

    def test_validate_metadata_shared_without_list(self):
        """Metadata validation: SHARED level requires shared_with_agents list."""
        invalid_metadata = {
            "agent_id": "agent-001",
            "namespace": "team-alpha",
            "access_level": AccessLevel.SHARED.value,
            # Missing: shared_with_agents
        }

        is_valid, error = CrossAgentAccessPolicy.validate_metadata(invalid_metadata)

        assert not is_valid
        assert "shared_with_agents" in error

    def test_validate_metadata_valid(self):
        """Metadata validation: Valid metadata."""
        valid_metadata = {
            "agent_id": "agent-001",
            "namespace": "team-alpha",
            "access_level": AccessLevel.PRIVATE.value,
        }

        is_valid, error = CrossAgentAccessPolicy.validate_metadata(valid_metadata)

        assert is_valid
        assert error is None

    # =====================================================
    # Test 8: Security Edge Cases
    # =====================================================

    @pytest.mark.asyncio
    async def test_namespace_spoofing_prevention_team(self, field_encryption):
        """Security: Prevent namespace spoofing in TEAM access."""
        owner_agent = "agent-001"
        attacker_agent = "agent-attacker"
        real_namespace = "team-alpha"

        # Encrypt with TEAM access
        encrypted = await field_encryption.encrypt_field(
            data="Team secret",
            field_name="content",
            agent_id=owner_agent,
            namespace=real_namespace,
            access_level=AccessLevel.TEAM,
        )

        # Attacker claims to be in same namespace
        # In real system, requesting_namespace would be verified from DB
        # Here we simulate attacker passing wrong namespace
        # The system should verify namespace from DB, not trust attacker's claim

        # If attacker's actual namespace (from DB) is different, access denied
        attacker_real_namespace = "attacker-namespace"
        with pytest.raises(PermissionError, match="Different namespace"):
            await field_encryption.decrypt_field(
                encrypted,
                requesting_agent=attacker_agent,
                requesting_namespace=attacker_real_namespace,
            )

    @pytest.mark.asyncio
    async def test_empty_shared_list_denies_all(self, field_encryption):
        """Security: Empty shared_with_agents list denies all non-owners."""
        owner_agent = "agent-001"
        other_agent = "agent-002"
        namespace = "team-alpha"

        # Encrypt with SHARED but empty list
        encrypted = await field_encryption.encrypt_field(
            data="Not actually shared",
            field_name="content",
            agent_id=owner_agent,
            namespace=namespace,
            access_level=AccessLevel.SHARED,
            shared_with_agents=[],  # Empty list
        )

        # Owner can still access
        decrypted = await field_encryption.decrypt_field(
            encrypted, requesting_agent=owner_agent, requesting_namespace=namespace,
        )
        assert decrypted == "Not actually shared"

        # Other agent should be denied
        with pytest.raises(PermissionError, match="Not in shared agent list"):
            await field_encryption.decrypt_field(
                encrypted, requesting_agent=other_agent, requesting_namespace=namespace,
            )

    # =====================================================
    # Test 9: Complex Data Types
    # =====================================================

    @pytest.mark.asyncio
    async def test_team_access_with_dict_data(self, field_encryption):
        """TEAM access with complex dict data."""
        owner_agent = "agent-001"
        team_agent = "agent-002"
        namespace = "team-alpha"

        complex_data = {
            "user": "john_doe",
            "permissions": ["read", "write"],
            "metadata": {"created": "2025-10-27", "version": 2},
        }

        # Encrypt dict with TEAM access
        encrypted = await field_encryption.encrypt_field(
            data=complex_data,
            field_name="user_data",
            agent_id=owner_agent,
            namespace=namespace,
            access_level=AccessLevel.TEAM,
        )

        # Team member can decrypt
        decrypted = await field_encryption.decrypt_field(
            encrypted, requesting_agent=team_agent, requesting_namespace=namespace,
        )

        assert decrypted == complex_data

    @pytest.mark.asyncio
    async def test_public_access_with_list_data(self, field_encryption):
        """PUBLIC access with list data."""
        owner_agent = "agent-001"
        any_agent = "agent-999"
        namespace = "team-alpha"

        list_data = ["item1", "item2", "item3"]

        # Encrypt list with PUBLIC access
        encrypted = await field_encryption.encrypt_field(
            data=list_data,
            field_name="items",
            agent_id=owner_agent,
            namespace=namespace,
            access_level=AccessLevel.PUBLIC,
        )

        # Any agent can decrypt
        decrypted = await field_encryption.decrypt_field(
            encrypted, requesting_agent=any_agent, requesting_namespace="other-namespace",
        )

        assert decrypted == list_data


class TestCrossAgentAccessPolicyUnit:
    """Unit tests for CrossAgentAccessPolicy class."""

    def test_check_access_private_owner(self):
        """PRIVATE: Owner access succeeds."""
        is_allowed, reason = CrossAgentAccessPolicy.check_access(
            owner_agent_id="agent-001",
            owner_namespace="team-alpha",
            requesting_agent_id="agent-001",
            requesting_namespace="team-alpha",
            access_level=AccessLevel.PRIVATE,
        )

        assert is_allowed
        assert reason == "Owner access"

    def test_check_access_private_other(self):
        """PRIVATE: Other agent denied."""
        is_allowed, reason = CrossAgentAccessPolicy.check_access(
            owner_agent_id="agent-001",
            owner_namespace="team-alpha",
            requesting_agent_id="agent-002",
            requesting_namespace="team-alpha",
            access_level=AccessLevel.PRIVATE,
        )

        assert not is_allowed
        assert "PRIVATE data (owner only)" in reason

    def test_check_access_team_same_namespace(self):
        """TEAM: Same namespace access succeeds."""
        is_allowed, reason = CrossAgentAccessPolicy.check_access(
            owner_agent_id="agent-001",
            owner_namespace="team-alpha",
            requesting_agent_id="agent-002",
            requesting_namespace="team-alpha",
            access_level=AccessLevel.TEAM,
        )

        assert is_allowed
        assert "Team access" in reason

    def test_check_access_team_different_namespace(self):
        """TEAM: Different namespace denied."""
        is_allowed, reason = CrossAgentAccessPolicy.check_access(
            owner_agent_id="agent-001",
            owner_namespace="team-alpha",
            requesting_agent_id="agent-002",
            requesting_namespace="team-beta",
            access_level=AccessLevel.TEAM,
        )

        assert not is_allowed
        assert "Different namespace" in reason

    def test_check_access_shared_in_list(self):
        """SHARED: Agent in shared list succeeds."""
        is_allowed, reason = CrossAgentAccessPolicy.check_access(
            owner_agent_id="agent-001",
            owner_namespace="team-alpha",
            requesting_agent_id="agent-002",
            requesting_namespace="team-alpha",
            access_level=AccessLevel.SHARED,
            shared_with_agents=["agent-002", "agent-003"],
        )

        assert is_allowed
        assert "Shared access" in reason

    def test_check_access_shared_not_in_list(self):
        """SHARED: Agent not in shared list denied."""
        is_allowed, reason = CrossAgentAccessPolicy.check_access(
            owner_agent_id="agent-001",
            owner_namespace="team-alpha",
            requesting_agent_id="agent-004",
            requesting_namespace="team-alpha",
            access_level=AccessLevel.SHARED,
            shared_with_agents=["agent-002", "agent-003"],
        )

        assert not is_allowed
        assert "Not in shared agent list" in reason

    def test_check_access_shared_namespace_mismatch(self):
        """SHARED: Namespace mismatch prevention."""
        is_allowed, reason = CrossAgentAccessPolicy.check_access(
            owner_agent_id="agent-001",
            owner_namespace="team-alpha",
            requesting_agent_id="agent-002",
            requesting_namespace="team-beta",
            access_level=AccessLevel.SHARED,
            shared_with_agents=["agent-002"],
        )

        assert not is_allowed
        assert "Namespace mismatch" in reason

    def test_check_access_public(self):
        """PUBLIC: Any agent succeeds."""
        is_allowed, reason = CrossAgentAccessPolicy.check_access(
            owner_agent_id="agent-001",
            owner_namespace="team-alpha",
            requesting_agent_id="agent-999",
            requesting_namespace="team-gamma",
            access_level=AccessLevel.PUBLIC,
        )

        assert is_allowed
        assert reason == "Public access"

    def test_check_access_system(self):
        """SYSTEM: Any agent succeeds."""
        is_allowed, reason = CrossAgentAccessPolicy.check_access(
            owner_agent_id="system",
            owner_namespace="default",
            requesting_agent_id="agent-001",
            requesting_namespace="team-alpha",
            access_level=AccessLevel.SYSTEM,
        )

        assert is_allowed
        assert reason == "System-level access"

    def test_check_access_invalid_level(self):
        """Invalid access level denied."""
        is_allowed, reason = CrossAgentAccessPolicy.check_access(
            owner_agent_id="agent-001",
            owner_namespace="team-alpha",
            requesting_agent_id="agent-002",
            requesting_namespace="team-alpha",
            access_level="INVALID",
        )

        assert not is_allowed
        assert "Invalid access level" in reason
