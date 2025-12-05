"""
Security Tests for Access Authorization (TMWS v2.3.0 Phase 1B Part 1)

Tests the authorization check BEFORE access tracking:
- V-ACCESS-1: Prevents unauthorized agents from incrementing access_count
- Ensures authorization check happens before memory.update_access()
- Verifies namespace isolation during access tracking

This resolves the MEDIUM security risk identified in Phase 1A where
access tracking occurred before authorization check.
"""

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from src.core.exceptions import AuthorizationError
from src.models.agent import Agent
from src.models.memory import AccessLevel, Memory
from src.services.memory_service import HybridMemoryService


@pytest.fixture
def mock_session():
    """Mock async database session."""
    session = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock()
    session.execute = AsyncMock()
    return session


@pytest.fixture
def mock_agent_service():
    """Mock agent service for namespace verification."""
    service = AsyncMock()
    return service


@pytest.fixture
def memory_service(mock_session, mock_agent_service):
    """Create HybridMemoryService with mocked dependencies."""
    service = HybridMemoryService(mock_session)
    service.agent_service = mock_agent_service  # Inject mock agent service
    return service


def create_test_memory(
    memory_id: str | None = None,
    agent_id: str = "test-agent",
    namespace: str = "test-namespace",
    access_level: AccessLevel = AccessLevel.PRIVATE,
) -> Memory:
    """Create a test Memory object with configurable access control."""
    return Memory(
        id=memory_id or str(uuid4()),
        content="Test memory content",
        agent_id=agent_id,
        namespace=namespace,
        importance_score=0.8,
        relevance_score=0.5,
        access_count=0,
        accessed_at=None,
        access_level=access_level,
        tags=["test"],
        context={},
        embedding_model="zylonai/multilingual-e5-large",
        embedding_dimension=1024,
    )


def create_test_agent(
    agent_id: str = "test-agent",
    namespace: str = "test-namespace",
) -> Agent:
    """Create a test Agent object."""
    return Agent(
        agent_id=agent_id,
        display_name=f"Test Agent {agent_id}",
        agent_type="test",
        namespace=namespace,
        capabilities={},
        config={},  # Fixed: was 'configuration', correct field name is 'config'
    )


class TestAccessAuthorizationOwner:
    """Test authorization when caller is the memory owner."""

    @pytest.mark.asyncio
    async def test_owner_can_access_private_memory(
        self, memory_service, mock_session, mock_agent_service
    ):
        """Test that memory owner can access their own PRIVATE memory."""
        # Arrange
        memory_id = str(uuid4())
        owner_id = "owner-agent"
        owner_namespace = "owner-namespace"

        test_memory = create_test_memory(
            memory_id=memory_id,
            agent_id=owner_id,
            namespace=owner_namespace,
            access_level=AccessLevel.PRIVATE,
        )
        owner_agent = create_test_agent(agent_id=owner_id, namespace=owner_namespace)

        # Mock database responses
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result
        mock_agent_service.get_agent_by_id.return_value = owner_agent

        # Act
        result = await memory_service.get_memory(
            memory_id=memory_id,
            caller_agent_id=owner_id,
            track_access=True,
        )

        # Assert
        assert result is not None
        assert result.access_count == 1  # Access tracked
        mock_session.commit.assert_called_once()


class TestAccessAuthorizationUnauthorized:
    """Test authorization when caller is NOT authorized."""

    @pytest.mark.asyncio
    async def test_unauthorized_agent_blocked_private_memory(
        self, memory_service, mock_session, mock_agent_service
    ):
        """Test that unauthorized agent CANNOT access PRIVATE memory (V-ACCESS-1)."""
        # Arrange
        memory_id = str(uuid4())
        owner_id = "owner-agent"
        owner_namespace = "owner-namespace"
        unauthorized_id = "hacker-agent"
        unauthorized_namespace = "hacker-namespace"

        test_memory = create_test_memory(
            memory_id=memory_id,
            agent_id=owner_id,
            namespace=owner_namespace,
            access_level=AccessLevel.PRIVATE,
        )
        unauthorized_agent = create_test_agent(
            agent_id=unauthorized_id,
            namespace=unauthorized_namespace,
        )

        # Mock database responses
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result
        mock_agent_service.get_agent_by_id.return_value = unauthorized_agent

        # Act & Assert
        with pytest.raises(AuthorizationError) as exc_info:
            await memory_service.get_memory(
                memory_id=memory_id,
                caller_agent_id=unauthorized_id,
                track_access=True,
            )

        # Verify error message is informative
        assert "Access denied" in str(exc_info.value)
        assert memory_id in str(exc_info.value)

        # SECURITY: Verify access was NOT tracked
        assert test_memory.access_count == 0
        mock_session.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_cross_namespace_team_memory_blocked(
        self, memory_service, mock_session, mock_agent_service
    ):
        """Test that TEAM memory blocks cross-namespace access (namespace isolation)."""
        # Arrange
        memory_id = str(uuid4())
        owner_id = "team-a-agent"
        team_a_namespace = "team-a"
        attacker_id = "team-b-agent"
        team_b_namespace = "team-b"

        test_memory = create_test_memory(
            memory_id=memory_id,
            agent_id=owner_id,
            namespace=team_a_namespace,
            access_level=AccessLevel.TEAM,  # Team-level access
        )
        attacker_agent = create_test_agent(
            agent_id=attacker_id,
            namespace=team_b_namespace,  # Different namespace
        )

        # Mock database responses
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result
        mock_agent_service.get_agent_by_id.return_value = attacker_agent

        # Act & Assert
        with pytest.raises(AuthorizationError):
            await memory_service.get_memory(
                memory_id=memory_id,
                caller_agent_id=attacker_id,
                track_access=True,
            )

        # SECURITY: Verify cross-namespace access was blocked
        assert test_memory.access_count == 0
        mock_session.commit.assert_not_called()


class TestAccessAuthorizationTeamAccess:
    """Test authorization for TEAM-level access."""

    @pytest.mark.asyncio
    async def test_same_namespace_team_member_can_access(
        self, memory_service, mock_session, mock_agent_service
    ):
        """Test that team member in SAME namespace can access TEAM memory."""
        # Arrange
        memory_id = str(uuid4())
        owner_id = "team-member-1"
        teammate_id = "team-member-2"
        shared_namespace = "engineering-team"

        test_memory = create_test_memory(
            memory_id=memory_id,
            agent_id=owner_id,
            namespace=shared_namespace,
            access_level=AccessLevel.TEAM,
        )
        teammate_agent = create_test_agent(
            agent_id=teammate_id,
            namespace=shared_namespace,  # Same namespace
        )

        # Mock database responses
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result
        mock_agent_service.get_agent_by_id.return_value = teammate_agent

        # Act
        result = await memory_service.get_memory(
            memory_id=memory_id,
            caller_agent_id=teammate_id,
            track_access=True,
        )

        # Assert
        assert result is not None
        assert result.access_count == 1  # Access tracked
        mock_session.commit.assert_called_once()


class TestAccessAuthorizationPublicAccess:
    """Test authorization for PUBLIC-level access."""

    @pytest.mark.asyncio
    async def test_any_agent_can_access_public_memory(
        self, memory_service, mock_session, mock_agent_service
    ):
        """Test that any agent can access PUBLIC memory."""
        # Arrange
        memory_id = str(uuid4())
        owner_id = "public-content-owner"
        owner_namespace = "public-namespace"
        reader_id = "random-agent"
        reader_namespace = "random-namespace"

        test_memory = create_test_memory(
            memory_id=memory_id,
            agent_id=owner_id,
            namespace=owner_namespace,
            access_level=AccessLevel.PUBLIC,
        )
        reader_agent = create_test_agent(
            agent_id=reader_id,
            namespace=reader_namespace,  # Different namespace
        )

        # Mock database responses
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result
        mock_agent_service.get_agent_by_id.return_value = reader_agent

        # Act
        result = await memory_service.get_memory(
            memory_id=memory_id,
            caller_agent_id=reader_id,
            track_access=True,
        )

        # Assert
        assert result is not None
        assert result.access_count == 1  # Access tracked
        mock_session.commit.assert_called_once()


class TestAccessAuthorizationBackwardCompatibility:
    """Test backward compatibility when caller_agent_id is NOT provided."""

    @pytest.mark.asyncio
    async def test_no_caller_id_skips_authorization(self, memory_service, mock_session):
        """Test that omitting caller_agent_id skips authorization (backward compatibility)."""
        # Arrange
        memory_id = str(uuid4())
        test_memory = create_test_memory(memory_id=memory_id)

        # Mock database response
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result

        # Act - Call without caller_agent_id (old API)
        result = await memory_service.get_memory(
            memory_id=memory_id,
            # caller_agent_id NOT provided
            track_access=True,
        )

        # Assert
        assert result is not None
        assert result.access_count == 1  # Still tracked (Phase 1A behavior)
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_track_access_false_skips_authorization(self, memory_service, mock_session):
        """Test that track_access=False skips both authorization and tracking."""
        # Arrange
        memory_id = str(uuid4())
        test_memory = create_test_memory(memory_id=memory_id)

        # Mock database response
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result

        # Act - Admin query (no tracking, no authorization)
        result = await memory_service.get_memory(
            memory_id=memory_id,
            caller_agent_id="admin-agent",
            track_access=False,
        )

        # Assert
        assert result is not None
        assert result.access_count == 0  # NOT tracked
        mock_session.commit.assert_not_called()


class TestAccessAuthorizationEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_nonexistent_caller_agent_raises_error(
        self, memory_service, mock_session, mock_agent_service
    ):
        """Test that nonexistent caller agent raises appropriate error."""
        # Arrange
        memory_id = str(uuid4())
        test_memory = create_test_memory(memory_id=memory_id)

        # Mock database responses
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_memory
        mock_session.execute.return_value = mock_result
        mock_agent_service.get_agent_by_id.return_value = None  # Agent not found

        # Act & Assert
        with pytest.raises(AuthorizationError) as exc_info:
            await memory_service.get_memory(
                memory_id=memory_id,
                caller_agent_id="nonexistent-agent",
                track_access=True,
            )

        # Verify error message indicates agent not found
        assert "not found" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_nonexistent_memory_no_authorization_check(self, memory_service, mock_session):
        """Test that authorization is skipped for nonexistent memory."""
        # Arrange
        memory_id = str(uuid4())

        # Mock database response - memory not found
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        # Act
        result = await memory_service.get_memory(
            memory_id=memory_id,
            caller_agent_id="some-agent",
            track_access=True,
        )

        # Assert
        assert result is None  # Memory not found
        # Authorization check should NOT have been attempted
        mock_session.commit.assert_not_called()
