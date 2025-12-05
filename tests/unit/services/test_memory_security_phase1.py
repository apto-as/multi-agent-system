"""
Security tests for Phase 1 memory methods (V-PRUNE/NS-1 fixes).

This test suite validates critical security measures for:
- cleanup_namespace() (V-NS-1)
- prune_expired_memories() (V-PRUNE-1/2/3)
- set_memory_ttl() (ownership verification)

Author: Artemis (Technical Perfectionist) + Hestia (Security Guardian)
Created: 2025-11-24
Phase: v2.4.0 Phase 1-4 - Security Test Suite
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from src.core.exceptions import AuthorizationError, ValidationError
from src.models.agent import AccessLevel as AgentAccessLevel
from src.models.agent import Agent, AgentStatus
from src.models.memory import AccessLevel, Memory
from src.services.memory_service import HybridMemoryService

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture(autouse=True)
def mock_ollama_services():
    """Mock Ollama services globally to bypass connection requirements.

    This fixture patches get_ollama_embedding_service() and get_vector_search_service()
    at the module level to prevent any Ollama connection attempts.
    """
    # Create mock embedding service
    mock_embedding = MagicMock()
    mock_embedding.get_model_info = MagicMock(
        return_value={"model_name": "zylonai/multilingual-e5-large", "dimension": 1024}
    )
    mock_embedding.embed = AsyncMock(return_value=[0.0] * 1024)

    # Create mock vector service
    mock_vector = MagicMock()
    mock_vector.initialize = AsyncMock(return_value=None)
    mock_vector.delete_memories_batch = AsyncMock(return_value=None)
    mock_vector.search = AsyncMock(return_value=[])

    # Patch at import time
    with patch(
        "src.services.memory_service.get_ollama_embedding_service", return_value=mock_embedding
    ):
        with patch(
            "src.services.memory_service.get_vector_search_service", return_value=mock_vector
        ):
            yield (mock_embedding, mock_vector)


@pytest.fixture
def mock_vector_service():
    """Create a mock vector service that bypasses Ollama connection.

    For security tests, we don't need actual vector operations - we only
    test authorization and parameter validation logic.
    """
    mock_service = MagicMock()
    mock_service.initialize = AsyncMock(return_value=None)
    mock_service.delete_memories_batch = AsyncMock(return_value=None)
    return mock_service


@pytest.fixture
async def test_agent_alpha(test_session):
    """Create test agent 'alpha' in namespace 'test-alpha'."""
    agent = Agent(
        agent_id=f"test-agent-alpha-{uuid4()}",
        display_name="Test Agent Alpha",
        namespace="test-alpha",
        tier="FREE",
        default_access_level=AgentAccessLevel.PRIVATE,
        status=AgentStatus.ACTIVE,
    )
    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)
    return agent


@pytest.fixture
async def test_agent_beta(test_session):
    """Create test agent 'beta' in namespace 'test-beta'."""
    agent = Agent(
        agent_id=f"test-agent-beta-{uuid4()}",
        display_name="Test Agent Beta",
        namespace="test-beta",
        tier="FREE",
        default_access_level=AgentAccessLevel.PRIVATE,
        status=AgentStatus.ACTIVE,
    )
    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)
    return agent


@pytest.fixture
async def test_memory_alpha(test_session, test_agent_alpha):
    """Create test memory owned by agent alpha."""
    memory = Memory(
        agent_id=test_agent_alpha.agent_id,
        namespace=test_agent_alpha.namespace,
        content="Test memory for alpha",
        access_level=AccessLevel.PRIVATE,
        importance_score=0.5,
        access_count=0,
    )
    test_session.add(memory)
    await test_session.commit()
    await test_session.refresh(memory)
    return memory


@pytest.fixture
async def test_expired_memory_alpha(test_session, test_agent_alpha):
    """Create expired test memory owned by agent alpha."""
    memory = Memory(
        agent_id=test_agent_alpha.agent_id,
        namespace=test_agent_alpha.namespace,
        content="Expired test memory for alpha",
        access_level=AccessLevel.PRIVATE,
        importance_score=0.5,
        access_count=0,
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),  # Expired yesterday
    )
    test_session.add(memory)
    await test_session.commit()
    await test_session.refresh(memory)
    return memory


# ============================================================================
# cleanup_namespace() Security Tests (5 tests)
# ============================================================================


@pytest.mark.asyncio
class TestCleanupNamespaceSecurity:
    """Security tests for cleanup_namespace() method."""

    async def test_cleanup_authorization_success(
        self, test_session, test_agent_alpha, test_memory_alpha, mock_vector_service
    ):
        """Test cleanup succeeds when agent namespace matches target."""
        service = HybridMemoryService(test_session)
        service.vector_service = mock_vector_service
        service._initialized = True  # Bypass initialization

        # Agent alpha can cleanup their own namespace
        result = await service.cleanup_namespace(
            namespace=test_agent_alpha.namespace,
            agent_id=test_agent_alpha.agent_id,
            days=1,  # Delete memories older than 1 day
            min_importance=0.0,
            dry_run=True,
        )

        assert result["dry_run"] is True
        assert result["namespace"] == test_agent_alpha.namespace

    async def test_cleanup_authorization_cross_namespace(
        self, test_session, test_agent_alpha, test_agent_beta, mock_vector_service
    ):
        """V-NS-1: Test cleanup fails when agent tries to access different namespace."""
        service = HybridMemoryService(test_session)
        service.vector_service = mock_vector_service
        service._initialized = True

        # Agent alpha attempts to cleanup beta's namespace
        with pytest.raises(AuthorizationError) as exc_info:
            await service.cleanup_namespace(
                namespace=test_agent_beta.namespace,  # Different namespace
                agent_id=test_agent_alpha.agent_id,
                days=1,
                min_importance=0.0,
            )

        assert "not authorized" in str(exc_info.value).lower()
        assert test_agent_beta.namespace in str(exc_info.value)

    async def test_cleanup_parameter_validation_days(
        self, test_session, test_agent_alpha, mock_vector_service
    ):
        """V-PRUNE-2: Test cleanup validates days parameter."""
        service = HybridMemoryService(test_session)
        service.vector_service = mock_vector_service
        service._initialized = True

        # Test days < 1
        with pytest.raises(ValidationError) as exc_info:
            await service.cleanup_namespace(
                namespace=test_agent_alpha.namespace,
                agent_id=test_agent_alpha.agent_id,
                days=0,  # Invalid: < 1
                min_importance=0.0,
            )
        assert "days must be at least 1" in str(exc_info.value)

        # Test days > 3650
        with pytest.raises(ValidationError) as exc_info:
            await service.cleanup_namespace(
                namespace=test_agent_alpha.namespace,
                agent_id=test_agent_alpha.agent_id,
                days=5000,  # Invalid: > 3650
                min_importance=0.0,
            )
        assert "3650" in str(exc_info.value)

    async def test_cleanup_parameter_validation_importance(
        self, test_session, test_agent_alpha, mock_vector_service
    ):
        """V-PRUNE-2: Test cleanup validates min_importance parameter."""
        service = HybridMemoryService(test_session)
        service.vector_service = mock_vector_service
        service._initialized = True

        # Test importance < 0.0
        with pytest.raises(ValidationError) as exc_info:
            await service.cleanup_namespace(
                namespace=test_agent_alpha.namespace,
                agent_id=test_agent_alpha.agent_id,
                days=1,
                min_importance=-0.1,  # Invalid: < 0.0
            )
        assert "between 0.0 and 1.0" in str(exc_info.value)

        # Test importance > 1.0
        with pytest.raises(ValidationError) as exc_info:
            await service.cleanup_namespace(
                namespace=test_agent_alpha.namespace,
                agent_id=test_agent_alpha.agent_id,
                days=1,
                min_importance=1.5,  # Invalid: > 1.0
            )
        assert "between 0.0 and 1.0" in str(exc_info.value)

    async def test_cleanup_dry_run(
        self, test_session, test_agent_alpha, test_memory_alpha, mock_vector_service
    ):
        """Test cleanup dry-run mode does not delete memories."""
        service = HybridMemoryService(test_session)
        service.vector_service = mock_vector_service
        service._initialized = True

        # Perform dry-run cleanup (old memories, low importance)
        result = await service.cleanup_namespace(
            namespace=test_agent_alpha.namespace,
            agent_id=test_agent_alpha.agent_id,
            days=1,
            min_importance=0.0,
            dry_run=True,
        )

        assert result["dry_run"] is True
        assert result["deleted_count"] == 0

        # Verify memory still exists
        from sqlalchemy import select

        stmt = select(Memory).where(Memory.id == test_memory_alpha.id)
        result = await test_session.execute(stmt)
        memory = result.scalar_one_or_none()
        assert memory is not None  # Memory should still exist


# ============================================================================
# prune_expired_memories() Security Tests (6 tests)
# ============================================================================


@pytest.mark.asyncio
class TestPruneExpiredMemoriesSecurity:
    """Security tests for prune_expired_memories() method."""

    async def test_prune_authorization_success(
        self, test_session, test_agent_alpha, test_expired_memory_alpha, mock_vector_service
    ):
        """Test prune succeeds when agent namespace matches target."""
        service = HybridMemoryService(test_session)
        service.vector_service = mock_vector_service
        service._initialized = True

        # Agent alpha can prune their own namespace
        result = await service.prune_expired_memories(
            namespace=test_agent_alpha.namespace,
            agent_id=test_agent_alpha.agent_id,
            limit=1000,
            dry_run=True,
        )

        assert result["dry_run"] is True
        assert result["namespace"] == test_agent_alpha.namespace
        assert result["expired_count"] == 1  # Should find the expired memory

    async def test_prune_respects_namespace(
        self,
        test_session,
        test_agent_alpha,
        test_agent_beta,
        test_expired_memory_alpha,
        mock_vector_service,
    ):
        """V-PRUNE-1: Test prune only affects target namespace."""
        service = HybridMemoryService(test_session)
        service.vector_service = mock_vector_service
        service._initialized = True

        # Create expired memory for agent beta
        expired_beta = Memory(
            agent_id=test_agent_beta.agent_id,
            namespace=test_agent_beta.namespace,
            content="Expired memory for beta",
            access_level=AccessLevel.PRIVATE,
            importance_score=0.5,
            access_count=0,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        test_session.add(expired_beta)
        await test_session.commit()

        # Alpha prunes their namespace (should only affect alpha's memories)
        result = await service.prune_expired_memories(
            namespace=test_agent_alpha.namespace,
            agent_id=test_agent_alpha.agent_id,
            limit=1000,
            dry_run=True,
        )

        assert result["expired_count"] == 1  # Only alpha's expired memory

        # Beta prunes their namespace (should only affect beta's memories)
        result = await service.prune_expired_memories(
            namespace=test_agent_beta.namespace,
            agent_id=test_agent_beta.agent_id,
            limit=1000,
            dry_run=True,
        )

        assert result["expired_count"] == 1  # Only beta's expired memory

    async def test_prune_authorization_cross_namespace(
        self, test_session, test_agent_alpha, test_agent_beta, mock_vector_service
    ):
        """V-NS-1: Test prune fails when agent tries to access different namespace."""
        service = HybridMemoryService(test_session)
        service.vector_service = mock_vector_service
        service._initialized = True

        # Agent alpha attempts to prune beta's namespace
        with pytest.raises(AuthorizationError) as exc_info:
            await service.prune_expired_memories(
                namespace=test_agent_beta.namespace,  # Different namespace
                agent_id=test_agent_alpha.agent_id,
                limit=1000,
            )

        assert "not authorized" in str(exc_info.value).lower()
        assert test_agent_beta.namespace in str(exc_info.value)

    async def test_prune_batch_limit(
        self, test_session, test_agent_alpha, test_expired_memory_alpha, mock_vector_service
    ):
        """V-PRUNE-3: Test prune enforces batch limit."""
        service = HybridMemoryService(test_session)
        service.vector_service = mock_vector_service
        service._initialized = True

        # Test limit < 1
        with pytest.raises(ValidationError) as exc_info:
            await service.prune_expired_memories(
                namespace=test_agent_alpha.namespace,
                agent_id=test_agent_alpha.agent_id,
                limit=0,  # Invalid: < 1
            )
        assert "limit must be at least 1" in str(exc_info.value)

        # Test limit > 100,000
        with pytest.raises(ValidationError) as exc_info:
            await service.prune_expired_memories(
                namespace=test_agent_alpha.namespace,
                agent_id=test_agent_alpha.agent_id,
                limit=200_000,  # Invalid: > 100,000
            )
        assert "100,000" in str(exc_info.value)

    async def test_prune_dry_run(
        self, test_session, test_agent_alpha, test_expired_memory_alpha, mock_vector_service
    ):
        """Test prune dry-run mode does not delete memories."""
        service = HybridMemoryService(test_session)
        service.vector_service = mock_vector_service
        service._initialized = True

        # Perform dry-run prune
        result = await service.prune_expired_memories(
            namespace=test_agent_alpha.namespace,
            agent_id=test_agent_alpha.agent_id,
            limit=1000,
            dry_run=True,
        )

        assert result["dry_run"] is True
        assert result["deleted_count"] == 0
        assert result["expired_count"] == 1  # Should find 1 expired memory

        # Verify memory still exists
        from sqlalchemy import select

        stmt = select(Memory).where(Memory.id == test_expired_memory_alpha.id)
        result = await test_session.execute(stmt)
        memory = result.scalar_one_or_none()
        assert memory is not None  # Memory should still exist

    async def test_prune_only_expired(
        self,
        test_session,
        test_agent_alpha,
        test_memory_alpha,
        test_expired_memory_alpha,
        mock_vector_service,
    ):
        """Test prune only deletes expired memories, not active ones."""
        service = HybridMemoryService(test_session)
        service.vector_service = mock_vector_service
        service._initialized = True

        # Perform actual prune (not dry-run)
        result = await service.prune_expired_memories(
            namespace=test_agent_alpha.namespace,
            agent_id=test_agent_alpha.agent_id,
            limit=1000,
            dry_run=False,
        )

        assert result["dry_run"] is False
        assert result["deleted_count"] == 1  # Should delete 1 expired memory
        assert result["expired_count"] == 1

        # Verify expired memory is deleted
        from sqlalchemy import select

        stmt = select(Memory).where(Memory.id == test_expired_memory_alpha.id)
        result = await test_session.execute(stmt)
        expired_memory = result.scalar_one_or_none()
        assert expired_memory is None  # Expired memory should be deleted

        # Verify active memory still exists
        stmt = select(Memory).where(Memory.id == test_memory_alpha.id)
        result = await test_session.execute(stmt)
        active_memory = result.scalar_one_or_none()
        assert active_memory is not None  # Active memory should still exist


# ============================================================================
# set_memory_ttl() Security Tests (3 tests)
# ============================================================================


@pytest.mark.asyncio
class TestSetMemoryTTLSecurity:
    """Security tests for set_memory_ttl() method."""

    async def test_ttl_ownership_success(
        self, test_session, test_agent_alpha, test_memory_alpha, mock_vector_service
    ):
        """Test TTL update succeeds when agent owns the memory."""
        service = HybridMemoryService(test_session)
        service.vector_service = mock_vector_service
        service._initialized = True

        # Agent alpha can update their own memory's TTL
        result = await service.set_memory_ttl(
            memory_id=test_memory_alpha.id,
            agent_id=test_agent_alpha.agent_id,
            ttl_days=30,
        )

        assert result["success"] is True
        assert result["memory_id"] == str(test_memory_alpha.id)
        assert result["ttl_days"] == 30
        assert result["expires_at"] is not None

    async def test_ttl_ownership_cross_agent(
        self,
        test_session,
        test_agent_alpha,
        test_agent_beta,
        test_memory_alpha,
        mock_vector_service,
    ):
        """P0-1: Test TTL update fails when agent doesn't own the memory."""
        service = HybridMemoryService(test_session)
        service.vector_service = mock_vector_service
        service._initialized = True

        # Agent beta attempts to update alpha's memory TTL
        with pytest.raises(AuthorizationError) as exc_info:
            await service.set_memory_ttl(
                memory_id=test_memory_alpha.id,  # Alpha's memory
                agent_id=test_agent_beta.agent_id,  # Beta trying to update
                ttl_days=30,
            )

        assert "not authorized" in str(exc_info.value).lower()
        assert str(test_memory_alpha.id) in str(exc_info.value)

    async def test_ttl_parameter_validation(
        self, test_session, test_agent_alpha, test_memory_alpha, mock_vector_service
    ):
        """Test TTL update validates ttl_days parameter."""
        service = HybridMemoryService(test_session)
        service.vector_service = mock_vector_service
        service._initialized = True

        # Test ttl_days < 1
        with pytest.raises(ValidationError) as exc_info:
            await service.set_memory_ttl(
                memory_id=test_memory_alpha.id,
                agent_id=test_agent_alpha.agent_id,
                ttl_days=0,  # Invalid: < 1
            )
        assert "ttl_days must be at least 1" in str(exc_info.value)

        # Test ttl_days > 3650
        with pytest.raises(ValidationError) as exc_info:
            await service.set_memory_ttl(
                memory_id=test_memory_alpha.id,
                agent_id=test_agent_alpha.agent_id,
                ttl_days=5000,  # Invalid: > 3650
            )
        assert "3650" in str(exc_info.value)

        # Test ttl_days = None (permanent) should succeed
        result = await service.set_memory_ttl(
            memory_id=test_memory_alpha.id,
            agent_id=test_agent_alpha.agent_id,
            ttl_days=None,  # Valid: permanent memory
        )
        assert result["success"] is True
        assert result["ttl_days"] is None
        assert result["expires_at"] is None
