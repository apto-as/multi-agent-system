"""
Verification Tests for Trinitas Agent Auto-Registration (Phase 4)

These tests verify that the 6 Trinitas agents are properly registered in the database.

Test Coverage:
1. All 6 agents exist
2. All agent fields are correctly populated
3. JSON fields (config, capabilities) are properly stored
4. Namespace exists and is active
5. No duplicate agents

NOTE: These tests use the actual .tmws/db/tmws.db database, not an in-memory test database.
"""

import os

import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.models.agent import AccessLevel, Agent, AgentNamespace, AgentStatus


# Custom fixture for actual database access
@pytest_asyncio.fixture
async def real_db_session():
    """Provides a database session connected to the actual .tmws/db/tmws.db file"""
    # Use absolute path to the actual database
    db_path = os.path.abspath(".tmws/db/tmws.db")
    database_url = f"sqlite+aiosqlite:///{db_path}"

    # Create engine
    engine = create_async_engine(
        database_url,
        poolclass=StaticPool,
        echo=False,
        connect_args={"check_same_thread": False},
    )

    # Create session
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        yield session

    await engine.dispose()


# Test Constants
EXPECTED_AGENTS = {
    "athena-conductor": {
        "display_name": "Athena (Harmonious Conductor)",
        "agent_type": "trinitas",
        "agent_subtype": "conductor",
        "capabilities": ["orchestration", "workflow", "coordination"],
    },
    "artemis-optimizer": {
        "display_name": "Artemis (Technical Perfectionist)",
        "agent_type": "trinitas",
        "agent_subtype": "optimizer",
        "capabilities": ["performance", "optimization", "technical_excellence"],
    },
    "hestia-auditor": {
        "display_name": "Hestia (Security Guardian)",
        "agent_type": "trinitas",
        "agent_subtype": "auditor",
        "capabilities": ["security", "audit", "risk_assessment"],
    },
    "eris-coordinator": {
        "display_name": "Eris (Tactical Coordinator)",
        "agent_type": "trinitas",
        "agent_subtype": "coordinator",
        "capabilities": ["tactical", "team_coordination", "conflict_resolution"],
    },
    "hera-strategist": {
        "display_name": "Hera (Strategic Commander)",
        "agent_type": "trinitas",
        "agent_subtype": "strategist",
        "capabilities": ["strategy", "planning", "architecture"],
    },
    "muses-documenter": {
        "display_name": "Muses (Knowledge Architect)",
        "agent_type": "trinitas",
        "agent_subtype": "documenter",
        "capabilities": ["documentation", "knowledge", "archival"],
    },
}


@pytest.mark.asyncio
class TestTrinitasVerification:
    """Verification test suite for Trinitas agent registration"""

    async def test_1_namespace_exists(self, real_db_session: AsyncSession):
        """Test 1: 'trinitas' namespace exists and is active"""
        result = await real_db_session.execute(
            select(AgentNamespace).where(AgentNamespace.namespace == "trinitas")
        )
        namespace = result.scalar_one_or_none()

        assert namespace is not None, "Trinitas namespace does not exist"
        assert namespace.namespace == "trinitas"
        assert namespace.is_active is True
        assert namespace.default_access_level == "system"

    async def test_2_all_six_agents_exist(self, real_db_session: AsyncSession):
        """Test 2: All 6 Trinitas agents are registered"""
        result = await real_db_session.execute(select(Agent).where(Agent.namespace == "trinitas"))
        agents = result.scalars().all()

        # Check count
        assert len(agents) == 6, f"Expected 6 agents, found {len(agents)}"

        # Check agent IDs
        agent_ids = {agent.agent_id for agent in agents}
        expected_ids = set(EXPECTED_AGENTS.keys())
        assert agent_ids == expected_ids, f"Agent IDs mismatch: {agent_ids} != {expected_ids}"

    async def test_3_athena_conductor_details(self, real_db_session: AsyncSession):
        """Test 3: athena-conductor agent has correct details"""
        result = await real_db_session.execute(
            select(Agent).where(Agent.agent_id == "athena-conductor")
        )
        agent = result.scalar_one_or_none()

        expected = EXPECTED_AGENTS["athena-conductor"]

        assert agent is not None, "athena-conductor agent not found"
        assert agent.display_name == expected["display_name"]
        assert agent.agent_type == expected["agent_type"]
        assert agent.namespace == "trinitas"
        assert agent.default_access_level == AccessLevel.SYSTEM
        assert agent.status == AgentStatus.ACTIVE
        assert agent.config["agent_subtype"] == expected["agent_subtype"]
        assert agent.capabilities == expected["capabilities"]

    async def test_4_artemis_optimizer_details(self, real_db_session: AsyncSession):
        """Test 4: artemis-optimizer agent has correct details"""
        result = await real_db_session.execute(
            select(Agent).where(Agent.agent_id == "artemis-optimizer")
        )
        agent = result.scalar_one_or_none()

        expected = EXPECTED_AGENTS["artemis-optimizer"]

        assert agent is not None, "artemis-optimizer agent not found"
        assert agent.display_name == expected["display_name"]
        assert agent.agent_type == expected["agent_type"]
        assert agent.config["agent_subtype"] == expected["agent_subtype"]
        assert agent.capabilities == expected["capabilities"]

    async def test_5_hestia_auditor_details(self, real_db_session: AsyncSession):
        """Test 5: hestia-auditor agent has correct details"""
        result = await real_db_session.execute(
            select(Agent).where(Agent.agent_id == "hestia-auditor")
        )
        agent = result.scalar_one_or_none()

        expected = EXPECTED_AGENTS["hestia-auditor"]

        assert agent is not None, "hestia-auditor agent not found"
        assert agent.display_name == expected["display_name"]
        assert agent.agent_type == expected["agent_type"]
        assert agent.config["agent_subtype"] == expected["agent_subtype"]
        assert agent.capabilities == expected["capabilities"]

    async def test_6_eris_coordinator_details(self, real_db_session: AsyncSession):
        """Test 6: eris-coordinator agent has correct details"""
        result = await real_db_session.execute(
            select(Agent).where(Agent.agent_id == "eris-coordinator")
        )
        agent = result.scalar_one_or_none()

        expected = EXPECTED_AGENTS["eris-coordinator"]

        assert agent is not None, "eris-coordinator agent not found"
        assert agent.display_name == expected["display_name"]
        assert agent.agent_type == expected["agent_type"]
        assert agent.config["agent_subtype"] == expected["agent_subtype"]
        assert agent.capabilities == expected["capabilities"]

    async def test_7_hera_strategist_details(self, real_db_session: AsyncSession):
        """Test 7: hera-strategist agent has correct details"""
        result = await real_db_session.execute(
            select(Agent).where(Agent.agent_id == "hera-strategist")
        )
        agent = result.scalar_one_or_none()

        expected = EXPECTED_AGENTS["hera-strategist"]

        assert agent is not None, "hera-strategist agent not found"
        assert agent.display_name == expected["display_name"]
        assert agent.agent_type == expected["agent_type"]
        assert agent.config["agent_subtype"] == expected["agent_subtype"]
        assert agent.capabilities == expected["capabilities"]

    async def test_8_muses_documenter_details(self, real_db_session: AsyncSession):
        """Test 8: muses-documenter agent has correct details"""
        result = await real_db_session.execute(
            select(Agent).where(Agent.agent_id == "muses-documenter")
        )
        agent = result.scalar_one_or_none()

        expected = EXPECTED_AGENTS["muses-documenter"]

        assert agent is not None, "muses-documenter agent not found"
        assert agent.display_name == expected["display_name"]
        assert agent.agent_type == expected["agent_type"]
        assert agent.config["agent_subtype"] == expected["agent_subtype"]
        assert agent.capabilities == expected["capabilities"]

    async def test_9_no_duplicate_agents(self, real_db_session: AsyncSession):
        """Test 9: No duplicate agents exist in the database"""
        # Count agents per agent_id
        result = await real_db_session.execute(
            select(Agent.agent_id, func.count(Agent.id).label("count"))
            .where(Agent.namespace == "trinitas")
            .group_by(Agent.agent_id)
        )
        agent_counts = result.all()

        # All counts should be 1
        duplicates = [(agent_id, count) for agent_id, count in agent_counts if count > 1]
        assert len(duplicates) == 0, f"Found duplicate agents: {duplicates}"

    async def test_10_all_agents_active(self, real_db_session: AsyncSession):
        """Test 10: All Trinitas agents are in ACTIVE status"""
        result = await real_db_session.execute(select(Agent).where(Agent.namespace == "trinitas"))
        agents = result.scalars().all()

        inactive_agents = [agent.agent_id for agent in agents if agent.status != AgentStatus.ACTIVE]
        assert len(inactive_agents) == 0, f"Found inactive agents: {inactive_agents}"

    async def test_11_all_agents_system_access(self, real_db_session: AsyncSession):
        """Test 11: All Trinitas agents have SYSTEM access level"""
        result = await real_db_session.execute(select(Agent).where(Agent.namespace == "trinitas"))
        agents = result.scalars().all()

        wrong_access_agents = [
            agent.agent_id for agent in agents if agent.default_access_level != AccessLevel.SYSTEM
        ]
        assert len(wrong_access_agents) == 0, (
            f"Found agents with wrong access level: {wrong_access_agents}"
        )

    async def test_12_all_json_fields_valid(self, real_db_session: AsyncSession):
        """Test 12: All agents have valid JSON fields (config, capabilities)"""
        result = await real_db_session.execute(select(Agent).where(Agent.namespace == "trinitas"))
        agents = result.scalars().all()

        for agent in agents:
            # Check config is dict
            assert isinstance(agent.config, dict), f"{agent.agent_id}: config is not a dict"
            assert "agent_subtype" in agent.config, (
                f"{agent.agent_id}: config missing agent_subtype"
            )

            # Check capabilities is list
            assert isinstance(agent.capabilities, list), (
                f"{agent.agent_id}: capabilities is not a list"
            )
            assert len(agent.capabilities) > 0, f"{agent.agent_id}: capabilities is empty"
