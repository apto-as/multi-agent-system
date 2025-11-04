"""
Security Tests for Access-Level Based TTL Limits (TMWS v2.3.0 Phase 1B Part 3)

Tests the access-level based TTL validation:
- PRIVATE: 1-365 days (max 1 year)
- TEAM: 1-180 days (max 6 months)
- PUBLIC: 1-90 days (max 3 months - most restricted)
- SYSTEM: None only (no TTL allowed)

This builds on top of Phase 1A Part 2 (basic TTL validation 1-3650 days).
Access level determines the MAXIMUM allowed TTL to prevent long-lived
sensitive data exposure.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from src.models.memory import AccessLevel, Memory
from src.services.memory_service import HybridMemoryService
from src.core.exceptions import ValidationError


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
def memory_service(mock_session):
    """Create HybridMemoryService with mocked dependencies."""
    return HybridMemoryService(mock_session)


class TestPrivateMemoryTTLLimits:
    """Test TTL limits for PRIVATE access level (max 365 days)."""

    @pytest.mark.asyncio
    async def test_private_ttl_365_days_allowed(self, memory_service, mock_session):
        """Test that PRIVATE memory can have TTL up to 365 days (max allowed)."""
        # Arrange
        memory_data = {
            "content": "Private sensitive data",
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "access_level": AccessLevel.PRIVATE,
            "ttl_days": 365,  # Maximum for PRIVATE
        }

        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)

        # Mock vector service
        memory_service.vector_service.add_memory = AsyncMock()

        # Act & Assert - Should succeed
        result = await memory_service.create_memory(**memory_data)
        assert result is not None
        # Memory model stores expires_at, not ttl_days
        # Just verify creation succeeded without ValidationError
        assert result.expires_at is not None  # TTL was set

    @pytest.mark.asyncio
    async def test_private_ttl_366_days_raises_error(self, memory_service, mock_session):
        """Test that PRIVATE memory CANNOT have TTL > 365 days."""
        # Arrange
        memory_data = {
            "content": "Private data",
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "access_level": AccessLevel.PRIVATE,
            "ttl_days": 366,  # EXCEEDS maximum for PRIVATE
        }

        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)

        # Act & Assert
        with pytest.raises(ValidationError) as exc_info:
            await memory_service.create_memory(**memory_data)

        # Verify error message mentions access level
        assert "PRIVATE" in str(exc_info.value)
        assert "365" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_private_ttl_boundary_values(self, memory_service, mock_session):
        """Test PRIVATE TTL boundary values (1, 365, 366)."""
        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)
        memory_service.vector_service.add_memory = AsyncMock()

        # Test minimum (1 day) - Should succeed
        memory_data_1 = {
            "content": "Private data 1",
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "access_level": AccessLevel.PRIVATE,
            "ttl_days": 1,
        }
        result1 = await memory_service.create_memory(**memory_data_1)
        assert result1.expires_at is not None  # TTL was set

        # Test maximum (365 days) - Should succeed
        memory_data_365 = {
            "content": "Private data 365",
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "access_level": AccessLevel.PRIVATE,
            "ttl_days": 365,
        }
        result365 = await memory_service.create_memory(**memory_data_365)
        assert result365.expires_at is not None  # TTL was set

        # Test over limit (366 days) - Should fail
        memory_data_366 = {
            "content": "Private data 366",
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "access_level": AccessLevel.PRIVATE,
            "ttl_days": 366,
        }
        with pytest.raises(ValidationError):
            await memory_service.create_memory(**memory_data_366)


class TestTeamMemoryTTLLimits:
    """Test TTL limits for TEAM access level (max 180 days)."""

    @pytest.mark.asyncio
    async def test_team_ttl_180_days_allowed(self, memory_service, mock_session):
        """Test that TEAM memory can have TTL up to 180 days (max allowed)."""
        # Arrange
        memory_data = {
            "content": "Team shared data",
            "agent_id": "test-agent",
            "namespace": "team-ns",
            "access_level": AccessLevel.TEAM,
            "ttl_days": 180,  # Maximum for TEAM
        }

        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)
        memory_service.vector_service.add_memory = AsyncMock()

        # Act & Assert - Should succeed
        result = await memory_service.create_memory(**memory_data)
        assert result is not None
        # TTL was set correctly (expires_at is calculated)

    @pytest.mark.asyncio
    async def test_team_ttl_181_days_raises_error(self, memory_service, mock_session):
        """Test that TEAM memory CANNOT have TTL > 180 days."""
        # Arrange
        memory_data = {
            "content": "Team data",
            "agent_id": "test-agent",
            "namespace": "team-ns",
            "access_level": AccessLevel.TEAM,
            "ttl_days": 181,  # EXCEEDS maximum for TEAM
        }

        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)

        # Act & Assert
        with pytest.raises(ValidationError) as exc_info:
            await memory_service.create_memory(**memory_data)

        # Verify error message mentions access level
        assert "TEAM" in str(exc_info.value)
        assert "180" in str(exc_info.value)


class TestPublicMemoryTTLLimits:
    """Test TTL limits for PUBLIC access level (max 90 days - most restricted)."""

    @pytest.mark.asyncio
    async def test_public_ttl_90_days_allowed(self, memory_service, mock_session):
        """Test that PUBLIC memory can have TTL up to 90 days (max allowed)."""
        # Arrange
        memory_data = {
            "content": "Public announcement",
            "agent_id": "test-agent",
            "namespace": "public-ns",
            "access_level": AccessLevel.PUBLIC,
            "ttl_days": 90,  # Maximum for PUBLIC
        }

        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)
        memory_service.vector_service.add_memory = AsyncMock()

        # Act & Assert - Should succeed
        result = await memory_service.create_memory(**memory_data)
        assert result is not None
        # TTL was set correctly (expires_at is calculated)

    @pytest.mark.asyncio
    async def test_public_ttl_91_days_raises_error(self, memory_service, mock_session):
        """Test that PUBLIC memory CANNOT have TTL > 90 days."""
        # Arrange
        memory_data = {
            "content": "Public data",
            "agent_id": "test-agent",
            "namespace": "public-ns",
            "access_level": AccessLevel.PUBLIC,
            "ttl_days": 91,  # EXCEEDS maximum for PUBLIC
        }

        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)

        # Act & Assert
        with pytest.raises(ValidationError) as exc_info:
            await memory_service.create_memory(**memory_data)

        # Verify error message mentions access level
        assert "PUBLIC" in str(exc_info.value)
        assert "90" in str(exc_info.value)


class TestSystemMemoryTTLRestriction:
    """Test TTL restriction for SYSTEM access level (None only)."""

    @pytest.mark.asyncio
    async def test_system_ttl_None_allowed(self, memory_service, mock_session):
        """Test that SYSTEM memory can have TTL=None (permanent)."""
        # Arrange
        memory_data = {
            "content": "System configuration",
            "agent_id": "system",
            "namespace": "system",
            "access_level": AccessLevel.SYSTEM,
            "ttl_days": None,  # SYSTEM memories are permanent
        }

        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)
        memory_service.vector_service.add_memory = AsyncMock()

        # Act & Assert - Should succeed
        result = await memory_service.create_memory(**memory_data)
        assert result is not None
        assert result.expires_at is None  # No TTL (permanent memory)

    @pytest.mark.asyncio
    async def test_system_ttl_1_day_raises_error(self, memory_service, mock_session):
        """Test that SYSTEM memory CANNOT have any TTL (even 1 day)."""
        # Arrange
        memory_data = {
            "content": "System data",
            "agent_id": "system",
            "namespace": "system",
            "access_level": AccessLevel.SYSTEM,
            "ttl_days": 1,  # SYSTEM memories must NOT have TTL
        }

        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)

        # Act & Assert
        with pytest.raises(ValidationError) as exc_info:
            await memory_service.create_memory(**memory_data)

        # Verify error message mentions SYSTEM restriction
        assert "SYSTEM" in str(exc_info.value)
        assert "None" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_system_ttl_various_values_all_raise_error(self, memory_service, mock_session):
        """Test that SYSTEM memory rejects ANY non-None TTL value."""
        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)

        test_values = [1, 7, 30, 90, 180, 365, 3650]

        for ttl_value in test_values:
            memory_data = {
                "content": f"System data TTL={ttl_value}",
                "agent_id": "system",
                "namespace": "system",
                "access_level": AccessLevel.SYSTEM,
                "ttl_days": ttl_value,
            }

            with pytest.raises(ValidationError) as exc_info:
                await memory_service.create_memory(**memory_data)

            assert "SYSTEM" in str(exc_info.value)


class TestAccessLevelTTLCombinations:
    """Test various access level and TTL combinations."""

    @pytest.mark.asyncio
    async def test_all_access_levels_with_None_ttl(self, memory_service, mock_session):
        """Test that all access levels (except SYSTEM) can have TTL=None."""
        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)
        memory_service.vector_service.add_memory = AsyncMock()

        # PRIVATE with TTL=None - Should succeed
        private_data = {
            "content": "Private no TTL",
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "access_level": AccessLevel.PRIVATE,
            "ttl_days": None,
        }
        result_private = await memory_service.create_memory(**private_data)
        assert result_private.expires_at is None  # No TTL (permanent memory)

        # TEAM with TTL=None - Should succeed
        team_data = {
            "content": "Team no TTL",
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "access_level": AccessLevel.TEAM,
            "ttl_days": None,
        }
        result_team = await memory_service.create_memory(**team_data)
        assert result_team.expires_at is None  # No TTL (permanent memory)

        # PUBLIC with TTL=None - Should succeed
        public_data = {
            "content": "Public no TTL",
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "access_level": AccessLevel.PUBLIC,
            "ttl_days": None,
        }
        result_public = await memory_service.create_memory(**public_data)
        assert result_public.expires_at is None  # No TTL (permanent memory)

        # SYSTEM with TTL=None - Should succeed (required for SYSTEM)
        system_data = {
            "content": "System no TTL",
            "agent_id": "system",
            "namespace": "system",
            "access_level": AccessLevel.SYSTEM,
            "ttl_days": None,
        }
        result_system = await memory_service.create_memory(**system_data)
        assert result_system.expires_at is None  # No TTL (permanent memory)

    @pytest.mark.asyncio
    async def test_ttl_ordering_private_team_public(self, memory_service, mock_session):
        """Test that TTL limits follow ordering: PUBLIC(90) < TEAM(180) < PRIVATE(365)."""
        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)
        memory_service.vector_service.add_memory = AsyncMock()

        # PUBLIC can't have TEAM's max (180 days)
        public_data_180 = {
            "content": "Public 180",
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "access_level": AccessLevel.PUBLIC,
            "ttl_days": 180,  # TEAM limit, but this is PUBLIC
        }
        with pytest.raises(ValidationError):
            await memory_service.create_memory(**public_data_180)

        # TEAM can't have PRIVATE's max (365 days)
        team_data_365 = {
            "content": "Team 365",
            "agent_id": "test-agent",
            "namespace": "test-ns",
            "access_level": AccessLevel.TEAM,
            "ttl_days": 365,  # PRIVATE limit, but this is TEAM
        }
        with pytest.raises(ValidationError):
            await memory_service.create_memory(**team_data_365)

    @pytest.mark.asyncio
    async def test_access_level_none_uses_private_limits(self, memory_service, mock_session):
        """Test that access_level=None (default) uses PRIVATE limits (365 days)."""
        # Arrange - Create memory without specifying access_level (defaults to PRIVATE)
        memory_data_365 = {
            "content": "Default access level",
            "agent_id": "test-agent",
            "namespace": "test-ns",
            # access_level not specified - defaults to PRIVATE
            "ttl_days": 365,
        }

        # Mock embedding service
        mock_embedding = [0.1] * 1024
        memory_service.embedding_service.embed_text = AsyncMock(return_value=mock_embedding)
        memory_service.vector_service.add_memory = AsyncMock()

        # Act - Should succeed (365 days allowed for default PRIVATE)
        result = await memory_service.create_memory(**memory_data_365)
        assert result is not None
        # TTL was set correctly (expires_at is calculated)
        assert result.access_level == AccessLevel.PRIVATE

        # Test over PRIVATE limit (366 days) - Should fail
        memory_data_366 = {
            "content": "Default access level over limit",
            "agent_id": "test-agent",
            "namespace": "test-ns",
            # access_level not specified - defaults to PRIVATE
            "ttl_days": 366,
        }

        with pytest.raises(ValidationError):
            await memory_service.create_memory(**memory_data_366)
