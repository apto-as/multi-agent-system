"""Unit tests for PersonaSyncService (P0.1 Narrative Gap fix).

Tests dual-source persona loading with DB priority.

Author: Metis (Testing)
Created: 2025-12-12 (Phase 2: P0.1 Narrative Gap)
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from src.models.agent import Agent, AgentStatus
from src.models.persona import Persona, PersonaType, PersonaRole
from src.services.persona_sync_service import PersonaSyncService


@pytest.fixture
def mock_session():
    """Create mock async session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.flush = AsyncMock()
    session.add = MagicMock()
    return session


@pytest.fixture
def sync_service(mock_session):
    """Create PersonaSyncService instance."""
    return PersonaSyncService(mock_session)


@pytest.fixture
def sample_agent():
    """Create sample Agent model."""
    from src.models.agent import AccessLevel

    agent = Agent(
        agent_id="athena-conductor",
        display_name="Athena - Harmonious Conductor",
        namespace="default",
        agent_type="orchestrator",
        capabilities={"orchestration": True, "coordination": True},
        status=AgentStatus.ACTIVE,
        trust_score=0.85,
        total_tasks=42,
        successful_tasks=40,
        default_access_level=AccessLevel.PRIVATE,  # Add missing field
    )
    # Mock to_dict to avoid None issues
    agent.to_dict = lambda: {
        "agent_id": "athena-conductor",
        "display_name": "Athena - Harmonious Conductor",
        "namespace": "default",
        "trust_score": 0.85,
        "total_tasks": 42,
        "successful_tasks": 40,
        "status": "active",
    }
    return agent


@pytest.fixture
def sample_persona():
    """Create sample Persona model."""
    persona = Persona(
        name="athena-conductor",
        type=PersonaType.ATHENA,
        role=PersonaRole.CONDUCTOR,
        display_name="Athena - Harmonious Conductor",
        description="System harmony and coordination specialist",
        specialties=["orchestration", "workflow", "coordination"],
        capabilities=["orchestration", "workflow_automation", "parallel_execution"],
        tier="STRATEGIC",
        emoji="🏛️",
        markdown_source="# Athena\n\nTest content",
        version="2.4.18",
        trigger_words=["orchestrate", "coordinate", "harmonize"],
        is_active=True,
    )
    # Mock to_dict to avoid created_at/updated_at None issues
    persona.to_dict = lambda: {
        "name": "athena-conductor",
        "display_name": "Athena - Harmonious Conductor",
        "tier": "STRATEGIC",
        "emoji": "🏛️",
        "capabilities": ["orchestration", "workflow_automation", "parallel_execution"],
        "markdown_source": "# Athena\n\nTest content",
    }
    return persona


class TestGetPersonaMerged:
    """Test get_persona_merged method."""

    async def test_db_priority_agent_only(self, sync_service, mock_session, sample_agent):
        """Test DB priority when only Agent exists."""
        # Mock Agent query
        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = sample_agent

        # Mock Persona query
        persona_result = MagicMock()
        persona_result.scalar_one_or_none.return_value = None

        mock_session.execute.side_effect = [agent_result, persona_result]

        result = await sync_service.get_persona_merged("athena-conductor")

        assert result is not None
        assert result["source"] == "merged"
        assert result["persona_id"] == "athena-conductor"
        assert result["agent_data"] is not None
        assert result["agent_data"]["display_name"] == "Athena - Harmonious Conductor"
        assert result["persona_data"] is None

    async def test_db_priority_persona_only(self, sync_service, mock_session, sample_persona):
        """Test DB priority when only Persona exists."""
        # Mock Agent query
        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = None

        # Mock Persona query
        persona_result = MagicMock()
        persona_result.scalar_one_or_none.return_value = sample_persona

        mock_session.execute.side_effect = [agent_result, persona_result]

        result = await sync_service.get_persona_merged("athena-conductor")

        assert result is not None
        assert result["source"] == "merged"
        assert result["persona_data"] is not None
        assert result["persona_data"]["tier"] == "STRATEGIC"
        assert result["agent_data"] is None

    async def test_db_priority_both_models(
        self, sync_service, mock_session, sample_agent, sample_persona
    ):
        """Test DB priority when both Agent and Persona exist."""
        # Mock Agent query
        agent_result = MagicMock()
        agent_result.scalar_one_or_none.return_value = sample_agent

        # Mock Persona query
        persona_result = MagicMock()
        persona_result.scalar_one_or_none.return_value = sample_persona

        mock_session.execute.side_effect = [agent_result, persona_result]

        result = await sync_service.get_persona_merged("athena-conductor")

        assert result is not None
        assert result["source"] == "merged"
        assert result["agent_data"] is not None
        assert result["persona_data"] is not None
        assert result["agent_data"]["trust_score"] == 0.85
        assert result["persona_data"]["emoji"] == "🏛️"

    async def test_md_fallback(self, sync_service, mock_session):
        """Test MD file fallback when DB is empty."""
        # Mock empty DB queries
        empty_result = MagicMock()
        empty_result.scalar_one_or_none.return_value = None
        mock_session.execute.side_effect = [empty_result, empty_result]

        # Mock MD file existence
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "read_text", return_value="# Athena\n\nTest MD"):
                result = await sync_service.get_persona_merged("athena-conductor")

                assert result is not None
                assert result["source"] == "md"
                assert result["md_data"] is not None
                assert result["md_data"]["content"] == "# Athena\n\nTest MD"

    async def test_not_found(self, sync_service, mock_session):
        """Test when persona not found in DB or MD."""
        # Mock empty DB queries
        empty_result = MagicMock()
        empty_result.scalar_one_or_none.return_value = None
        mock_session.execute.side_effect = [empty_result, empty_result]

        # Mock MD file not exists
        with patch.object(Path, "exists", return_value=False):
            result = await sync_service.get_persona_merged("nonexistent")

            assert result is None


class TestNormalizePersonaId:
    """Test _normalize_persona_id method."""

    def test_short_to_full_mapping(self, sync_service):
        """Test short name to full name conversion."""
        assert sync_service._normalize_persona_id("athena") == "athena-conductor"
        assert sync_service._normalize_persona_id("artemis") == "artemis-optimizer"
        assert sync_service._normalize_persona_id("hestia") == "hestia-auditor"

    def test_full_name_unchanged(self, sync_service):
        """Test full name stays unchanged."""
        assert sync_service._normalize_persona_id("athena-conductor") == "athena-conductor"
        assert sync_service._normalize_persona_id("artemis-optimizer") == "artemis-optimizer"

    def test_case_insensitive(self, sync_service):
        """Test case insensitivity."""
        assert sync_service._normalize_persona_id("ATHENA") == "athena-conductor"
        assert sync_service._normalize_persona_id("Artemis") == "artemis-optimizer"


class TestSyncMdToDb:
    """Test sync_md_to_db method."""

    async def test_directory_not_found(self, sync_service):
        """Test when directory doesn't exist."""
        with patch.object(Path, "exists", return_value=False):
            result = await sync_service.sync_md_to_db(Path("/nonexistent"))

            assert result["total"] == 0
            assert result["errors"] == 1

    async def test_successful_sync(self, sync_service, mock_session):
        """Test successful MD→DB sync."""
        # Mock PersonaLoader.sync_personas
        with patch.object(
            sync_service.persona_loader,
            "sync_personas",
            return_value={
                "total": 2,
                "created": 1,
                "updated": 1,
                "errors": 0,
                "results": [],
            },
        ):
            result = await sync_service.sync_md_to_db()

            assert result["total"] == 2
            assert result["created"] == 1
            assert result["updated"] == 1
            assert result["errors"] == 0


class TestGenerateMdFromPersona:
    """Test _generate_md_from_persona method."""

    def test_use_existing_markdown_source(self, sync_service, sample_persona):
        """Test using existing markdown_source."""
        sample_persona.markdown_source = "# Existing MD\n\nContent"

        result = sync_service._generate_md_from_persona(sample_persona)

        assert result == "# Existing MD\n\nContent"

    def test_generate_minimal_md(self, sync_service, sample_persona):
        """Test generating minimal MD when markdown_source is None."""
        sample_persona.markdown_source = None

        result = sync_service._generate_md_from_persona(sample_persona)

        assert "# 🏛️ Athena - Harmonious Conductor" in result
        assert "## Core Identity" in result
        assert "STRATEGIC" in result
        assert "orchestration" in result
