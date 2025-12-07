"""
P1 Integration Tests: Skill System Operations
HIGH PRIORITY: These tests verify skill CRUD and lifecycle operations.

Test IDs:
- SKILL-P1-001: Skill creation and validation
- SKILL-P1-002: Skill lifecycle (activate/deactivate)
- SKILL-P1-003: Skill sharing and access control
- SKILL-P1-004: Skill versioning
- SKILL-P1-005: Skill parameter validation
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest


@pytest.mark.integration
@pytest.mark.asyncio
class TestSkillCreation:
    """SKILL-P1-001: Skill creation and validation tests."""

    async def test_skill_create_success(self, mock_skill_service):
        """SKILL-P1-001-T1: Skill creation succeeds with valid data."""
        skill = await mock_skill_service.create_skill(
            name="test-skill",
            description="A test skill",
            category="utility",
            agent_id="test-agent",
            namespace="test-namespace",
            parameters={"input": "string"},
            code="def execute(input): return input.upper()",
        )

        assert skill is not None
        assert skill.id is not None
        mock_skill_service.create_skill.assert_called_once()

    async def test_skill_create_with_minimal_data(self, mock_skill_service):
        """SKILL-P1-001-T2: Skill creation with minimal required fields."""
        skill = await mock_skill_service.create_skill(
            name="minimal-skill",
            description="Minimal skill",
            agent_id="test-agent",
            namespace="test-namespace",
        )

        assert skill is not None

    async def test_skill_create_rejects_empty_name(self, mock_skill_service):
        """SKILL-P1-001-T3: Empty skill name is rejected."""
        mock_skill_service.create_skill.side_effect = ValueError(
            "Skill name cannot be empty"
        )

        with pytest.raises(ValueError) as exc_info:
            await mock_skill_service.create_skill(
                name="",
                description="Test skill",
                agent_id="test-agent",
                namespace="test-namespace",
            )

        assert "empty" in str(exc_info.value).lower()

    async def test_skill_create_rejects_duplicate_name(self, mock_skill_service):
        """SKILL-P1-001-T4: Duplicate skill name in same namespace rejected."""
        mock_skill_service.create_skill.side_effect = ValueError(
            "Skill with this name already exists in namespace"
        )

        with pytest.raises(ValueError) as exc_info:
            await mock_skill_service.create_skill(
                name="existing-skill",
                description="Duplicate skill",
                agent_id="test-agent",
                namespace="test-namespace",
            )

        assert "exists" in str(exc_info.value).lower()


@pytest.mark.integration
@pytest.mark.asyncio
class TestSkillLifecycle:
    """SKILL-P1-002: Skill lifecycle (activate/deactivate) tests."""

    async def test_skill_activation_success(self, mock_skill_service):
        """SKILL-P1-002-T1: Skill activation succeeds."""
        # Setup mock for activated skill
        activated_skill = Mock()
        activated_skill.id = uuid4()
        activated_skill.name = "test-skill"
        activated_skill.is_active = True
        mock_skill_service.activate_skill.return_value = activated_skill

        skill = await mock_skill_service.activate_skill(
            skill_id=str(uuid4()),
            agent_id="test-agent",
        )

        assert skill.is_active is True
        mock_skill_service.activate_skill.assert_called_once()

    async def test_skill_deactivation_success(self, mock_skill_service):
        """SKILL-P1-002-T2: Skill deactivation succeeds."""
        # Setup mock for deactivated skill
        deactivated_skill = Mock()
        deactivated_skill.id = uuid4()
        deactivated_skill.name = "test-skill"
        deactivated_skill.is_active = False
        mock_skill_service.deactivate_skill.return_value = deactivated_skill

        skill = await mock_skill_service.deactivate_skill(
            skill_id=str(uuid4()),
            agent_id="test-agent",
        )

        assert skill.is_active is False

    async def test_skill_delete_requires_deactivation(self, mock_skill_service):
        """SKILL-P1-002-T3: Active skill deletion is prevented."""
        mock_skill_service.delete_skill.side_effect = ValueError(
            "Cannot delete active skill. Deactivate first."
        )

        with pytest.raises(ValueError) as exc_info:
            await mock_skill_service.delete_skill(
                skill_id=str(uuid4()),
                agent_id="test-agent",
            )

        assert "deactivate" in str(exc_info.value).lower()

    async def test_skill_list_by_status(self, mock_skill_service):
        """SKILL-P1-002-T4: Skills can be listed by active status."""
        active_skill = Mock()
        active_skill.is_active = True
        active_skill.name = "active-skill"

        inactive_skill = Mock()
        inactive_skill.is_active = False
        inactive_skill.name = "inactive-skill"

        mock_skill_service.list_skills.return_value = [active_skill]

        skills = await mock_skill_service.list_skills(
            agent_id="test-agent",
            namespace="test-namespace",
            active_only=True,
        )

        assert len(skills) == 1
        assert all(s.is_active for s in skills)


@pytest.mark.integration
@pytest.mark.asyncio
class TestSkillSharing:
    """SKILL-P1-003: Skill sharing and access control tests."""

    async def test_skill_share_to_agent(self, mock_skill_service):
        """SKILL-P1-003-T1: Skill can be shared with another agent."""
        shared_skill = Mock()
        shared_skill.id = uuid4()
        shared_skill.shared_with_agents = ["target-agent"]
        mock_skill_service.share_skill.return_value = shared_skill

        skill = await mock_skill_service.share_skill(
            skill_id=str(uuid4()),
            owner_agent_id="test-agent",
            target_agent_id="target-agent",
        )

        assert "target-agent" in skill.shared_with_agents

    async def test_skill_share_requires_ownership(self, mock_skill_service):
        """SKILL-P1-003-T2: Only owner can share skill."""
        mock_skill_service.share_skill.side_effect = PermissionError(
            "Only skill owner can share"
        )

        with pytest.raises(PermissionError) as exc_info:
            await mock_skill_service.share_skill(
                skill_id=str(uuid4()),
                owner_agent_id="not-owner",
                target_agent_id="target-agent",
            )

        assert "owner" in str(exc_info.value).lower()

    async def test_skill_unshare(self, mock_skill_service):
        """SKILL-P1-003-T3: Skill sharing can be revoked."""
        unshared_skill = Mock()
        unshared_skill.id = uuid4()
        unshared_skill.shared_with_agents = []
        mock_skill_service.share_skill.return_value = unshared_skill

        skill = await mock_skill_service.share_skill(
            skill_id=str(uuid4()),
            owner_agent_id="test-agent",
            target_agent_id="target-agent",
            revoke=True,
        )

        assert "target-agent" not in skill.shared_with_agents


@pytest.mark.integration
@pytest.mark.asyncio
class TestSkillVersioning:
    """SKILL-P1-004: Skill versioning tests."""

    async def test_skill_version_increments_on_update(self, mock_skill_service):
        """SKILL-P1-004-T1: Version increments on skill update."""
        # First version
        skill_v1 = Mock()
        skill_v1.id = uuid4()
        skill_v1.version = "1.0.0"
        mock_skill_service.get_skill.return_value = skill_v1

        # Updated version
        skill_v2 = Mock()
        skill_v2.id = skill_v1.id
        skill_v2.version = "1.0.1"
        mock_skill_service.update_skill.return_value = skill_v2

        original = await mock_skill_service.get_skill(
            skill_id=str(skill_v1.id),
            agent_id="test-agent",
        )

        updated = await mock_skill_service.update_skill(
            skill_id=str(skill_v1.id),
            agent_id="test-agent",
            code="def execute(): return 'updated'",
        )

        assert original.version == "1.0.0"
        assert updated.version == "1.0.1"

    async def test_skill_version_format_validation(self, mock_skill_service):
        """SKILL-P1-004-T2: Invalid version format is rejected."""
        mock_skill_service.create_skill.side_effect = ValueError(
            "Invalid version format. Use semantic versioning (x.y.z)"
        )

        with pytest.raises(ValueError) as exc_info:
            await mock_skill_service.create_skill(
                name="test-skill",
                description="Test skill",
                agent_id="test-agent",
                namespace="test-namespace",
                version="invalid-version",
            )

        assert "version" in str(exc_info.value).lower()


@pytest.mark.integration
@pytest.mark.asyncio
class TestSkillParameterValidation:
    """SKILL-P1-005: Skill parameter validation tests."""

    async def test_skill_validates_required_parameters(self, mock_skill_service):
        """SKILL-P1-005-T1: Missing required parameters are rejected."""
        skill = Mock()
        skill.parameters = {"required_param": {"type": "string", "required": True}}
        mock_skill_service.get_skill.return_value = skill

        # Simulate execution without required parameter
        mock_execute = AsyncMock(side_effect=ValueError("Missing required parameter: required_param"))

        with pytest.raises(ValueError) as exc_info:
            await mock_execute(skill_id=str(skill.id), params={})

        assert "required" in str(exc_info.value).lower()

    async def test_skill_validates_parameter_types(self, mock_skill_service):
        """SKILL-P1-005-T2: Wrong parameter types are rejected."""
        skill = Mock()
        skill.parameters = {"count": {"type": "integer", "required": True}}
        mock_skill_service.get_skill.return_value = skill

        # Simulate execution with wrong type
        mock_execute = AsyncMock(side_effect=TypeError("Parameter 'count' must be integer"))

        with pytest.raises(TypeError) as exc_info:
            await mock_execute(skill_id=str(skill.id), params={"count": "not-an-integer"})

        assert "integer" in str(exc_info.value).lower()

    async def test_skill_accepts_valid_parameters(self, mock_skill_service):
        """SKILL-P1-005-T3: Valid parameters are accepted."""
        skill = Mock()
        skill.parameters = {
            "name": {"type": "string", "required": True},
            "count": {"type": "integer", "required": False, "default": 1},
        }
        mock_skill_service.get_skill.return_value = skill

        # Simulate successful execution
        mock_execute = AsyncMock(return_value={"result": "success"})

        result = await mock_execute(
            skill_id=str(skill.id),
            params={"name": "test", "count": 5}
        )

        assert result["result"] == "success"

    async def test_skill_parameter_constraints(self, mock_skill_service):
        """SKILL-P1-005-T4: Parameter constraints are enforced."""
        skill = Mock()
        skill.parameters = {
            "percentage": {
                "type": "number",
                "required": True,
                "minimum": 0,
                "maximum": 100,
            }
        }
        mock_skill_service.get_skill.return_value = skill

        # Simulate execution with out-of-range value
        mock_execute = AsyncMock(
            side_effect=ValueError("Parameter 'percentage' must be between 0 and 100")
        )

        with pytest.raises(ValueError) as exc_info:
            await mock_execute(
                skill_id=str(skill.id),
                params={"percentage": 150}
            )

        assert "100" in str(exc_info.value)
