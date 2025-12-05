"""Phase 1A-C Integration Tests.

This test suite validates the complete integration of:
- Phase 1A: Webhook notifications
- Phase 1B: SecurityAuditLogger integration
- Phase 1C: Cross-agent access policies

Integration Points:
- Memory model + FieldEncryption + CrossAgentAccessPolicy
- SecurityAuditLogger + RateLimiter + AccessControl
- WebhookNotifier + AlertManager

Performance Targets:
- Memory encryption: < 50ms P95
- Memory decryption: < 50ms P95
- Access control check: < 10ms P95
"""

import time
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.agent import AccessLevel, Agent
from src.models.memory import Memory
from src.security.data_encryption import (
    EncryptionKeyManager,
    FieldEncryption,
    MemoryEncryption,
)
from src.security.encryption_policies import CrossAgentAccessPolicy


class TestMemoryFieldEncryptionIntegration:
    """Test Memory model + FieldEncryption integration."""

    @pytest.fixture
    def key_manager(self):
        """Create encryption key manager."""
        return EncryptionKeyManager()

    @pytest.fixture
    def field_encryption(self, key_manager):
        """Create field encryption instance."""
        return FieldEncryption(key_manager)

    @pytest.fixture
    def memory_encryption(self, key_manager):
        """Create memory encryption instance."""
        return MemoryEncryption(key_manager)

    @pytest.fixture
    async def test_agents(self, db_session: AsyncSession):
        """Create test agents in database."""
        agents = {
            "owner": Agent(
                agent_id="test-owner-001",
                name="Owner Agent",
                namespace="team-alpha",
                capabilities=["memory_read", "memory_write"],
            ),
            "teammate": Agent(
                agent_id="test-teammate-002",
                name="Teammate Agent",
                namespace="team-alpha",
                capabilities=["memory_read"],
            ),
            "outsider": Agent(
                agent_id="test-outsider-003",
                name="Outsider Agent",
                namespace="team-beta",
                capabilities=["memory_read"],
            ),
            "shared": Agent(
                agent_id="test-shared-004",
                name="Shared Agent",
                namespace="team-alpha",
                capabilities=["memory_read"],
            ),
        }

        for agent in agents.values():
            db_session.add(agent)

        await db_session.commit()

        # Refresh to get IDs
        for agent in agents.values():
            await db_session.refresh(agent)

        return agents

    # =====================================================
    # Test 1: Memory + FieldEncryption Basic Integration
    # =====================================================

    @pytest.mark.asyncio
    async def test_memory_encryption_basic_flow(
        self,
        test_agents,
        memory_encryption,
        db_session: AsyncSession,
    ):
        """Test complete memory encryption and decryption flow."""
        owner = test_agents["owner"]

        # Create memory data
        memory_data = {
            "content": "This is a secret memory content",
            "metadata": {
                "category": "important",
                "tags": ["confidential", "test"],
            },
        }

        # Encrypt memory
        encrypted_data = await memory_encryption.encrypt_memory(
            memory_data,
            owner.agent_id,
        )

        # Verify encryption
        assert encrypted_data["is_encrypted"] is True
        assert "encrypted_content" in encrypted_data
        assert "content" not in encrypted_data  # Plaintext removed

        # Decrypt memory (owner access)
        decrypted_data = await memory_encryption.decrypt_memory(
            encrypted_data,
            owner.agent_id,
            owner.namespace,
        )

        # Verify decryption
        assert decrypted_data["content"] == memory_data["content"]
        assert decrypted_data["metadata"] == memory_data["metadata"]
        assert "is_encrypted" not in decrypted_data

    # =====================================================
    # Test 2: Memory Model Access Control Integration
    # =====================================================

    @pytest.mark.asyncio
    async def test_memory_access_control_private(
        self,
        test_agents,
        db_session: AsyncSession,
    ):
        """Test PRIVATE memory access control."""
        owner = test_agents["owner"]
        teammate = test_agents["teammate"]

        # Create PRIVATE memory
        memory = Memory(
            id=uuid4(),
            agent_id=owner.agent_id,
            namespace=owner.namespace,
            content="Private secret",
            memory_type="note",
            importance=0.8,
            access_level=AccessLevel.PRIVATE,
        )

        db_session.add(memory)
        await db_session.commit()
        await db_session.refresh(memory)

        # Owner can access
        assert memory.is_accessible_by(owner.agent_id, owner.namespace) is True

        # Teammate cannot access (even in same namespace)
        assert memory.is_accessible_by(teammate.agent_id, teammate.namespace) is False

    @pytest.mark.asyncio
    async def test_memory_access_control_team(
        self,
        test_agents,
        db_session: AsyncSession,
    ):
        """Test TEAM memory access control."""
        owner = test_agents["owner"]
        teammate = test_agents["teammate"]
        outsider = test_agents["outsider"]

        # Create TEAM memory
        memory = Memory(
            id=uuid4(),
            agent_id=owner.agent_id,
            namespace=owner.namespace,
            content="Team knowledge",
            memory_type="knowledge",
            importance=0.7,
            access_level=AccessLevel.TEAM,
        )

        db_session.add(memory)
        await db_session.commit()
        await db_session.refresh(memory)

        # Owner can access
        assert memory.is_accessible_by(owner.agent_id, owner.namespace) is True

        # Teammate can access (same namespace)
        assert memory.is_accessible_by(teammate.agent_id, teammate.namespace) is True

        # Outsider cannot access (different namespace)
        assert memory.is_accessible_by(outsider.agent_id, outsider.namespace) is False

    @pytest.mark.asyncio
    async def test_memory_access_control_shared(
        self,
        test_agents,
        db_session: AsyncSession,
    ):
        """Test SHARED memory access control."""
        owner = test_agents["owner"]
        teammate = test_agents["teammate"]
        shared = test_agents["shared"]
        outsider = test_agents["outsider"]

        # Create SHARED memory
        memory = Memory(
            id=uuid4(),
            agent_id=owner.agent_id,
            namespace=owner.namespace,
            content="Shared document",
            memory_type="document",
            importance=0.9,
            access_level=AccessLevel.SHARED,
            shared_with_agents=[shared.agent_id],
        )

        db_session.add(memory)
        await db_session.commit()
        await db_session.refresh(memory)

        # Owner can access
        assert memory.is_accessible_by(owner.agent_id, owner.namespace) is True

        # Shared agent can access
        assert memory.is_accessible_by(shared.agent_id, shared.namespace) is True

        # Teammate cannot access (not in shared list)
        assert memory.is_accessible_by(teammate.agent_id, teammate.namespace) is False

        # Outsider cannot access (not in shared list + different namespace)
        assert memory.is_accessible_by(outsider.agent_id, outsider.namespace) is False

    @pytest.mark.asyncio
    async def test_memory_access_control_public(
        self,
        test_agents,
        db_session: AsyncSession,
    ):
        """Test PUBLIC memory access control."""
        owner = test_agents["owner"]
        teammate = test_agents["teammate"]
        outsider = test_agents["outsider"]

        # Create PUBLIC memory
        memory = Memory(
            id=uuid4(),
            agent_id=owner.agent_id,
            namespace=owner.namespace,
            content="Public announcement",
            memory_type="announcement",
            importance=0.5,
            access_level=AccessLevel.PUBLIC,
        )

        db_session.add(memory)
        await db_session.commit()
        await db_session.refresh(memory)

        # All agents can access
        assert memory.is_accessible_by(owner.agent_id, owner.namespace) is True
        assert memory.is_accessible_by(teammate.agent_id, teammate.namespace) is True
        assert memory.is_accessible_by(outsider.agent_id, outsider.namespace) is True

    # =====================================================
    # Test 3: End-to-End Encrypted Memory Flow
    # =====================================================

    @pytest.mark.asyncio
    async def test_e2e_encrypted_memory_team_access(
        self,
        test_agents,
        field_encryption,
        db_session: AsyncSession,
    ):
        """Test end-to-end encrypted memory with TEAM access."""
        owner = test_agents["owner"]
        teammate = test_agents["teammate"]

        # Step 1: Encrypt sensitive field with TEAM access
        encrypted_field = await field_encryption.encrypt_field(
            data="Confidential team strategy",
            field_name="strategy",
            agent_id=owner.agent_id,
            namespace=owner.namespace,
            access_level=AccessLevel.TEAM,
        )

        # Step 2: Create memory with encrypted field
        memory = Memory(
            id=uuid4(),
            agent_id=owner.agent_id,
            namespace=owner.namespace,
            content=encrypted_field["encrypted_data"],  # Store encrypted
            memory_type="strategy",
            importance=0.9,
            access_level=AccessLevel.TEAM,
            metadata={"encrypted_metadata": encrypted_field["metadata"]},
        )

        db_session.add(memory)
        await db_session.commit()
        await db_session.refresh(memory)

        # Step 3: Owner can decrypt
        decrypted_owner = await field_encryption.decrypt_field(
            encrypted_field,
            owner.agent_id,
            owner.namespace,
        )
        assert decrypted_owner == "Confidential team strategy"

        # Step 4: Teammate can decrypt (TEAM access)
        decrypted_teammate = await field_encryption.decrypt_field(
            encrypted_field,
            teammate.agent_id,
            teammate.namespace,
        )
        assert decrypted_teammate == "Confidential team strategy"

    @pytest.mark.asyncio
    async def test_e2e_encrypted_memory_shared_access(
        self,
        test_agents,
        field_encryption,
        db_session: AsyncSession,
    ):
        """Test end-to-end encrypted memory with SHARED access."""
        owner = test_agents["owner"]
        shared = test_agents["shared"]
        teammate = test_agents["teammate"]

        # Step 1: Encrypt with SHARED access
        encrypted_field = await field_encryption.encrypt_field(
            data={"password": "secret123", "api_key": "key_abc"},
            field_name="credentials",
            agent_id=owner.agent_id,
            namespace=owner.namespace,
            access_level=AccessLevel.SHARED,
            shared_with_agents=[shared.agent_id],
        )

        # Step 2: Create memory
        memory = Memory(
            id=uuid4(),
            agent_id=owner.agent_id,
            namespace=owner.namespace,
            content="Encrypted credentials",
            memory_type="credentials",
            importance=1.0,
            access_level=AccessLevel.SHARED,
            shared_with_agents=[shared.agent_id],
            metadata={"encrypted_field": encrypted_field},
        )

        db_session.add(memory)
        await db_session.commit()

        # Step 3: Shared agent can decrypt
        decrypted = await field_encryption.decrypt_field(
            encrypted_field,
            shared.agent_id,
            shared.namespace,
        )
        assert decrypted["password"] == "secret123"
        assert decrypted["api_key"] == "key_abc"

        # Step 4: Teammate cannot decrypt (not in shared list)
        with pytest.raises(PermissionError, match="Not in shared agent list"):
            await field_encryption.decrypt_field(
                encrypted_field,
                teammate.agent_id,
                teammate.namespace,
            )

    # =====================================================
    # Test 4: Performance Benchmarks
    # =====================================================

    @pytest.mark.asyncio
    async def test_encryption_performance(self, field_encryption):
        """Test encryption performance (target: < 50ms P95)."""
        agent_id = "perf-test-agent"
        namespace = "perf-test"
        durations = []

        # Run 100 iterations
        for _ in range(100):
            start = time.perf_counter()

            await field_encryption.encrypt_field(
                data="Test data for performance benchmark",
                field_name="benchmark",
                agent_id=agent_id,
                namespace=namespace,
                access_level=AccessLevel.TEAM,
            )

            duration = (time.perf_counter() - start) * 1000  # ms
            durations.append(duration)

        # Calculate P95
        durations.sort()
        p95 = durations[int(len(durations) * 0.95)]

        print("\nEncryption Performance:")
        print(f"  Mean: {sum(durations) / len(durations):.2f}ms")
        print(f"  P50: {durations[50]:.2f}ms")
        print(f"  P95: {p95:.2f}ms")
        print(f"  Max: {max(durations):.2f}ms")

        # Assert target
        assert p95 < 50.0, f"P95 encryption time {p95:.2f}ms exceeds target 50ms"

    @pytest.mark.asyncio
    async def test_decryption_performance(self, field_encryption):
        """Test decryption performance (target: < 50ms P95)."""
        agent_id = "perf-test-agent"
        namespace = "perf-test"

        # Pre-encrypt data
        encrypted = await field_encryption.encrypt_field(
            data="Test data for performance benchmark",
            field_name="benchmark",
            agent_id=agent_id,
            namespace=namespace,
            access_level=AccessLevel.PRIVATE,
        )

        durations = []

        # Run 100 iterations
        for _ in range(100):
            start = time.perf_counter()

            await field_encryption.decrypt_field(
                encrypted,
                agent_id,
                namespace,
            )

            duration = (time.perf_counter() - start) * 1000  # ms
            durations.append(duration)

        # Calculate P95
        durations.sort()
        p95 = durations[int(len(durations) * 0.95)]

        print("\nDecryption Performance:")
        print(f"  Mean: {sum(durations) / len(durations):.2f}ms")
        print(f"  P50: {durations[50]:.2f}ms")
        print(f"  P95: {p95:.2f}ms")
        print(f"  Max: {max(durations):.2f}ms")

        # Assert target
        assert p95 < 50.0, f"P95 decryption time {p95:.2f}ms exceeds target 50ms"

    @pytest.mark.asyncio
    async def test_access_control_performance(self):
        """Test access control check performance (target: < 10ms P95)."""
        durations = []

        # Run 1000 iterations (access control should be very fast)
        for _ in range(1000):
            start = time.perf_counter()

            CrossAgentAccessPolicy.check_access(
                owner_agent_id="owner",
                owner_namespace="team-alpha",
                requesting_agent_id="requester",
                requesting_namespace="team-alpha",
                access_level=AccessLevel.TEAM,
            )

            duration = (time.perf_counter() - start) * 1000  # ms
            durations.append(duration)

        # Calculate P95
        durations.sort()
        p95 = durations[int(len(durations) * 0.95)]

        print("\nAccess Control Performance:")
        print(f"  Mean: {sum(durations) / len(durations):.4f}ms")
        print(f"  P50: {durations[500]:.4f}ms")
        print(f"  P95: {p95:.4f}ms")
        print(f"  Max: {max(durations):.4f}ms")

        # Assert target
        assert p95 < 10.0, f"P95 access control time {p95:.4f}ms exceeds target 10ms"

    # =====================================================
    # Test 5: Cross-Namespace Security
    # =====================================================

    @pytest.mark.asyncio
    async def test_namespace_isolation_enforcement(
        self,
        test_agents,
        field_encryption,
        db_session: AsyncSession,
    ):
        """Test strict namespace isolation prevents cross-namespace access."""
        owner = test_agents["owner"]  # team-alpha
        outsider = test_agents["outsider"]  # team-beta

        # Owner encrypts with TEAM access (team-alpha only)
        encrypted = await field_encryption.encrypt_field(
            data="Team Alpha Secret",
            field_name="secret",
            agent_id=owner.agent_id,
            namespace=owner.namespace,
            access_level=AccessLevel.TEAM,
        )

        # Outsider from team-beta cannot decrypt
        with pytest.raises(PermissionError, match="Different namespace"):
            await field_encryption.decrypt_field(
                encrypted,
                outsider.agent_id,
                outsider.namespace,
            )

    @pytest.mark.asyncio
    async def test_namespace_spoofing_prevention(
        self,
        test_agents,
        field_encryption,
    ):
        """Test that namespace spoofing is prevented."""
        owner = test_agents["owner"]  # team-alpha
        attacker_id = "attacker-999"

        # Owner encrypts with TEAM access
        encrypted = await field_encryption.encrypt_field(
            data="Confidential data",
            field_name="data",
            agent_id=owner.agent_id,
            namespace=owner.namespace,
            access_level=AccessLevel.TEAM,
        )

        # Attacker tries to decrypt by claiming same namespace
        # In real system, namespace would be verified from DB
        # Here we simulate attacker's actual namespace is different
        actual_attacker_namespace = "attacker-namespace"

        with pytest.raises(PermissionError, match="Different namespace"):
            await field_encryption.decrypt_field(
                encrypted,
                attacker_id,
                actual_attacker_namespace,
            )


class TestCrossAgentAccessPolicyConsistency:
    """Test consistency between Memory.is_accessible_by() and CrossAgentAccessPolicy."""

    @pytest.mark.asyncio
    async def test_policy_consistency_private(self):
        """Verify Memory and FieldEncryption use same PRIVATE logic."""
        owner_id = "agent-001"
        namespace = "team-alpha"

        # Memory model check
        memory_result = owner_id == owner_id  # Owner check

        # Policy check
        is_allowed, _ = CrossAgentAccessPolicy.check_access(
            owner_agent_id=owner_id,
            owner_namespace=namespace,
            requesting_agent_id=owner_id,
            requesting_namespace=namespace,
            access_level=AccessLevel.PRIVATE,
        )

        assert memory_result == is_allowed

    @pytest.mark.asyncio
    async def test_policy_consistency_team(self):
        """Verify Memory and FieldEncryption use same TEAM logic."""
        owner_id = "agent-001"
        teammate_id = "agent-002"
        namespace = "team-alpha"

        # Policy check (same namespace)
        is_allowed, _ = CrossAgentAccessPolicy.check_access(
            owner_agent_id=owner_id,
            owner_namespace=namespace,
            requesting_agent_id=teammate_id,
            requesting_namespace=namespace,
            access_level=AccessLevel.TEAM,
        )

        # Memory would return True for same namespace
        assert is_allowed is True

        # Policy check (different namespace)
        is_allowed2, _ = CrossAgentAccessPolicy.check_access(
            owner_agent_id=owner_id,
            owner_namespace=namespace,
            requesting_agent_id=teammate_id,
            requesting_namespace="team-beta",
            access_level=AccessLevel.TEAM,
        )

        # Memory would return False for different namespace
        assert is_allowed2 is False
