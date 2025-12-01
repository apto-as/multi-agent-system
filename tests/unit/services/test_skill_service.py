"""Unit tests for SkillService - Day 1 Full Implementation + Day 2 Task 1 (delete_skill)

Tests cover:
- create_skill(): 6 tests (success, validation errors, Progressive Disclosure)
- get_skill(): 9 tests (detail levels, access control, not found)
- update_skill(): 12 tests (metadata, versioning, access control, validation)
- list_skills(): 14 tests (Progressive Disclosure, access control, filtering, pagination)
- delete_skill(): 6 tests (soft delete, access control, idempotency, activated skill check)

Total: 47 tests (6 + 9 + 12 + 14 + 6)
"""

import uuid
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.application.dtos.response_dtos import SkillDTO
from src.core.exceptions import (
    NotFoundError,
    ValidationError,
)
from src.models.agent import AccessLevel, Agent, AgentStatus
from src.models.skill import Skill, SkillVersion
from src.services.skill_service import SkillService

# Sample skill content for testing
VALID_SKILL_CONTENT = """```json
{
  "name": "security-audit",
  "persona": "hestia-auditor",
  "version": "1.0.0"
}
```

## Core Instructions

This skill performs comprehensive security audits on code and infrastructure.

### Key Capabilities
- Vulnerability scanning
- Code review
- Compliance checking

### Usage
Invoke with `/trinitas execute hestia "security audit"`
"""


@pytest.mark.asyncio
class TestSkillServiceCreate:
    """Test SkillService.create_skill() method"""

    async def test_create_skill_success(self, db_session):
        """✅ Test successful skill creation"""
        # Create agent first
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test-namespace",
        )
        db_session.add(agent)
        await db_session.commit()

        # Create service
        service = SkillService(db_session)

        # Create skill
        result = await service.create_skill(
            name="security-audit",
            namespace="test-namespace",
            content=VALID_SKILL_CONTENT,
            created_by="test-agent",
            display_name="Security Audit",
            description="Comprehensive security audit skill",
            persona="hestia-auditor",
            tags=["security", "audit", "compliance"],
            access_level=AccessLevel.PRIVATE,
        )

        # Assertions
        assert isinstance(result, SkillDTO)
        assert result.name == "security-audit"
        assert result.namespace == "test-namespace"
        assert result.created_by == "test-agent"
        assert result.display_name == "Security Audit"
        assert result.description == "Comprehensive security audit skill"
        assert result.persona == "hestia-auditor"
        assert result.tags == ["security", "audit", "compliance"]
        assert result.access_level == "private"  # Lowercase (AccessLevel.PRIVATE.value)
        assert result.version == 1
        assert result.version_count == 1
        assert result.is_deleted is False

        # detail_level=2 by default (metadata + core instructions)
        assert result.core_instructions is not None
        assert "security audits" in result.core_instructions.lower()
        assert result.content is None  # Full content not included in level 2

        # Content hash must be present
        assert result.content_hash is not None
        assert len(result.content_hash) == 64  # SHA256 = 64 hex chars

        # Timestamps
        assert result.created_at is not None
        assert result.updated_at is not None

    async def test_create_skill_invalid_name(self, db_session):
        """❌ Test ValidationError for invalid skill name"""
        # Create agent first
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test-namespace",
        )
        db_session.add(agent)
        await db_session.commit()

        service = SkillService(db_session)

        # Invalid names (must start with lowercase letter)
        invalid_names = [
            "Security-Audit",  # Uppercase
            "1security",  # Starts with number
            "_security",  # Starts with underscore
            "a",  # Too short (1 char, minimum 2)
            "security audit",  # Space
            "security/audit",  # Slash
        ]

        for invalid_name in invalid_names:
            with pytest.raises(ValidationError) as exc_info:
                await service.create_skill(
                    name=invalid_name,
                    namespace="test-namespace",
                    content=VALID_SKILL_CONTENT,
                    created_by="test-agent",
                )

            assert "Invalid skill name format" in str(exc_info.value)

    async def test_create_skill_invalid_namespace(self, db_session):
        """❌ Test ValidationError for invalid namespace"""
        # Create agent first
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test-namespace",
        )
        db_session.add(agent)
        await db_session.commit()

        service = SkillService(db_session)

        # Invalid namespaces (path traversal prevention)
        invalid_namespaces = [
            "test.namespace",  # Dot (path traversal)
            "test/namespace",  # Slash (path traversal)
            "test\\namespace",  # Backslash (Windows path traversal)
            "../admin",  # Classic path traversal
        ]

        for invalid_namespace in invalid_namespaces:
            with pytest.raises(ValidationError) as exc_info:
                await service.create_skill(
                    name="security-audit",
                    namespace=invalid_namespace,
                    content=VALID_SKILL_CONTENT,
                    created_by="test-agent",
                )

            error_msg = str(exc_info.value)
            assert (
                "path traversal" in error_msg.lower()
                or "Invalid namespace format" in error_msg
            )

    async def test_create_skill_invalid_content(self, db_session):
        """❌ Test ValidationError for invalid content"""
        # Create agent first
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test-namespace",
        )
        db_session.add(agent)
        await db_session.commit()

        service = SkillService(db_session)

        # Empty content
        with pytest.raises(ValidationError) as exc_info:
            await service.create_skill(
                name="security-audit",
                namespace="test-namespace",
                content="",  # Empty
                created_by="test-agent",
            )

        assert "Skill content is required" in str(exc_info.value)

        # Whitespace only
        with pytest.raises(ValidationError) as exc_info:
            await service.create_skill(
                name="security-audit",
                namespace="test-namespace",
                content="   \n\t  ",  # Whitespace only
                created_by="test-agent",
            )

        assert "Skill content is required" in str(exc_info.value)

    async def test_create_skill_progressive_disclosure_parsing(self, db_session):
        """✅ Test Progressive Disclosure layer parsing"""
        # Create agent
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test-namespace",
        )
        db_session.add(agent)
        await db_session.commit()

        service = SkillService(db_session)

        # Create skill with structured content
        result = await service.create_skill(
            name="security-audit",
            namespace="test-namespace",
            content=VALID_SKILL_CONTENT,
            created_by="test-agent",
        )

        # Verify Progressive Disclosure layers were parsed
        assert result.core_instructions is not None
        # Core instructions should contain the security audit description
        assert "security audits" in result.core_instructions.lower()

        # Verify content hash was computed
        assert result.content_hash is not None
        assert len(result.content_hash) == 64

        # Verify version was created
        assert result.version == 1

    async def test_create_skill_version_1_autocreation(self, db_session):
        """✅ Test that version 1 is automatically created"""
        # Create agent
        agent = Agent(
            agent_id="test-agent",
            display_name="Test Agent",
            namespace="test-namespace",
        )
        db_session.add(agent)
        await db_session.commit()

        service = SkillService(db_session)

        # Create skill
        result = await service.create_skill(
            name="security-audit",
            namespace="test-namespace",
            content=VALID_SKILL_CONTENT,
            created_by="test-agent",
        )

        # Verify version 1 was created
        assert result.version == 1
        assert result.version_count == 1

        # Verify SkillVersion record was created in database
        from sqlalchemy import select

        stmt = select(SkillVersion).where(
            SkillVersion.skill_id == result.id, SkillVersion.version == 1
        )
        version_result = await db_session.execute(stmt)
        version = version_result.scalar_one_or_none()

        assert version is not None
        assert version.version == 1
        assert version.content == VALID_SKILL_CONTENT
        assert version.created_by == "test-agent"


@pytest.mark.asyncio
class TestSkillServiceGet:
    """Test SkillService.get_skill() method"""

    async def _create_test_skill(
        self, db_session, agent_id="test-agent", namespace="test-namespace"
    ):
        """Helper: Create a test skill and return its ID"""
        # Create agent if needed
        from sqlalchemy import select

        stmt = select(Agent).where(Agent.agent_id == agent_id)
        result = await db_session.execute(stmt)
        existing_agent = result.scalar_one_or_none()

        if not existing_agent:
            agent = Agent(
                agent_id=agent_id,
                display_name="Test Agent",
                namespace=namespace,
            )
            db_session.add(agent)
            await db_session.commit()

        # Create service
        service = SkillService(db_session)

        # Create skill
        skill_dto = await service.create_skill(
            name="test-skill",
            namespace=namespace,
            content=VALID_SKILL_CONTENT,
            created_by=agent_id,
            access_level=AccessLevel.PRIVATE,
        )

        return skill_dto.id

    async def test_get_skill_detail_level_1(self, db_session):
        """✅ Test get_skill() with detail_level=1 (metadata only)"""
        skill_id = await self._create_test_skill(db_session)

        service = SkillService(db_session)

        # Get skill with detail_level=1
        result = await service.get_skill(
            skill_id=skill_id,
            agent_id="test-agent",
            namespace="test-namespace",
            detail_level=1,
        )

        # Assertions: Metadata only
        assert result.name == "test-skill"
        assert result.namespace == "test-namespace"
        assert result.version == 1

        # No content at level 1
        assert result.core_instructions is None
        assert result.content is None
        assert result.content_hash is None

    async def test_get_skill_detail_level_2(self, db_session):
        """✅ Test get_skill() with detail_level=2 (metadata + core)"""
        skill_id = await self._create_test_skill(db_session)

        service = SkillService(db_session)

        # Get skill with detail_level=2
        result = await service.get_skill(
            skill_id=skill_id,
            agent_id="test-agent",
            namespace="test-namespace",
            detail_level=2,
        )

        # Assertions: Metadata + Core Instructions
        assert result.name == "test-skill"
        assert result.core_instructions is not None
        assert "security audits" in result.core_instructions.lower()

        # Full content not included at level 2
        assert result.content is None

        # Content hash is included (for integrity verification)
        assert result.content_hash is not None

    async def test_get_skill_detail_level_3(self, db_session):
        """✅ Test get_skill() with detail_level=3 (full content)"""
        skill_id = await self._create_test_skill(db_session)

        service = SkillService(db_session)

        # Get skill with detail_level=3
        result = await service.get_skill(
            skill_id=skill_id,
            agent_id="test-agent",
            namespace="test-namespace",
            detail_level=3,
        )

        # Assertions: Full Content
        assert result.name == "test-skill"
        assert result.core_instructions is not None
        assert result.content is not None
        assert result.content == VALID_SKILL_CONTENT

        # Content hash is included
        assert result.content_hash is not None

    async def test_get_skill_invalid_detail_level(self, db_session):
        """❌ Test ValidationError for invalid detail_level"""
        skill_id = await self._create_test_skill(db_session)

        service = SkillService(db_session)

        # Invalid detail levels
        for invalid_level in [0, 4, -1, 100]:
            with pytest.raises(ValidationError) as exc_info:
                await service.get_skill(
                    skill_id=skill_id,
                    agent_id="test-agent",
                    namespace="test-namespace",
                    detail_level=invalid_level,
                )

            assert "Invalid detail_level" in str(exc_info.value)

    async def test_get_skill_not_found(self, db_session):
        """❌ Test NotFoundError for nonexistent skill"""
        service = SkillService(db_session)

        # Random UUID that doesn't exist (as string)
        nonexistent_id = str(uuid4())

        with pytest.raises(NotFoundError) as exc_info:
            await service.get_skill(
                skill_id=nonexistent_id,
                agent_id="test-agent",
                namespace="test-namespace",
                detail_level=2,
            )

        assert "Skill" in str(exc_info.value)
        assert nonexistent_id in str(exc_info.value)

    async def test_get_skill_access_denied_private(self, db_session):
        """❌ Test NotFoundError for PRIVATE skill (different owner)"""
        # Create skill as agent1
        skill_id = await self._create_test_skill(
            db_session, agent_id="agent1", namespace="namespace1"
        )

        # Create agent2 in different namespace
        agent2 = Agent(
            agent_id="agent2",
            display_name="Agent 2",
            namespace="namespace2",
        )
        db_session.add(agent2)
        await db_session.commit()

        service = SkillService(db_session)

        # agent2 tries to access agent1's PRIVATE skill
        # Should return NotFoundError (no information leak)
        with pytest.raises(NotFoundError) as exc_info:
            await service.get_skill(
                skill_id=skill_id,
                agent_id="agent2",
                namespace="namespace2",  # Different namespace
                detail_level=2,
            )

        assert "Skill" in str(exc_info.value)
        assert skill_id in str(exc_info.value)

    async def test_get_skill_access_granted_team(self, db_session):
        """✅ Test access granted for TEAM skill (same namespace)"""
        # Create agent1
        agent1 = Agent(
            agent_id="agent1",
            display_name="Agent 1",
            namespace="shared-namespace",
        )
        db_session.add(agent1)
        await db_session.commit()

        # Create TEAM skill as agent1
        service = SkillService(db_session)
        skill_dto = await service.create_skill(
            name="team-skill",
            namespace="shared-namespace",
            content=VALID_SKILL_CONTENT,
            created_by="agent1",
            access_level=AccessLevel.TEAM,  # TEAM level
        )

        # Create agent2 in SAME namespace
        agent2 = Agent(
            agent_id="agent2",
            display_name="Agent 2",
            namespace="shared-namespace",  # Same namespace
        )
        db_session.add(agent2)
        await db_session.commit()

        # agent2 should be able to access TEAM skill
        result = await service.get_skill(
            skill_id=skill_dto.id,
            agent_id="agent2",
            namespace="shared-namespace",
            detail_level=2,
        )

        # Assertions: Access granted
        assert result.name == "team-skill"
        assert result.access_level == "team"  # Lowercase

    async def test_get_skill_access_granted_public(self, db_session):
        """✅ Test access granted for PUBLIC skill (any agent)"""
        # Create agent1
        agent1 = Agent(
            agent_id="agent1",
            display_name="Agent 1",
            namespace="namespace1",
        )
        db_session.add(agent1)
        await db_session.commit()

        # Create PUBLIC skill as agent1
        service = SkillService(db_session)
        skill_dto = await service.create_skill(
            name="public-skill",
            namespace="namespace1",
            content=VALID_SKILL_CONTENT,
            created_by="agent1",
            access_level=AccessLevel.PUBLIC,  # PUBLIC level
        )

        # Create agent2 in DIFFERENT namespace
        agent2 = Agent(
            agent_id="agent2",
            display_name="Agent 2",
            namespace="namespace2",
        )
        db_session.add(agent2)
        await db_session.commit()

        # agent2 should be able to access PUBLIC skill
        result = await service.get_skill(
            skill_id=skill_dto.id,
            agent_id="agent2",
            namespace="namespace2",  # Different namespace
            detail_level=2,
        )

        # Assertions: Access granted
        assert result.name == "public-skill"
        assert result.access_level == "public"  # Lowercase

    async def test_get_skill_deleted_returns_404(self, db_session):
        """✅ Test NotFoundError for deleted skill"""
        # Create skill
        skill_id = await self._create_test_skill(db_session)

        # Mark skill as deleted
        from sqlalchemy import update

        stmt = update(Skill).where(Skill.id == skill_id).values(is_deleted=True)
        await db_session.execute(stmt)
        await db_session.commit()

        service = SkillService(db_session)

        # Try to get deleted skill
        with pytest.raises(NotFoundError) as exc_info:
            await service.get_skill(
                skill_id=skill_id,
                agent_id="test-agent",
                namespace="test-namespace",
                detail_level=2,
            )

        assert "Skill" in str(exc_info.value)
        assert skill_id in str(exc_info.value)


@pytest.mark.asyncio
class TestSkillServiceUpdate:
    """Test SkillService.update_skill() method (Phase 1: Day 1 Afternoon)"""

    async def _create_test_skill(
        self, db_session, agent_id="test-agent", namespace="test-namespace"
    ):
        """Helper: Create a test skill and return its ID"""
        # Create agent if needed
        from sqlalchemy import select

        stmt = select(Agent).where(Agent.agent_id == agent_id)
        result = await db_session.execute(stmt)
        existing_agent = result.scalar_one_or_none()

        if not existing_agent:
            agent = Agent(
                agent_id=agent_id,
                display_name="Test Agent",
                namespace=namespace,
            )
            db_session.add(agent)
            await db_session.commit()

        # Create service
        service = SkillService(db_session)

        # Create skill
        skill_dto = await service.create_skill(
            name="test-skill",
            namespace=namespace,
            content=VALID_SKILL_CONTENT,
            created_by=agent_id,
            tags=["original", "tag1"],
            access_level=AccessLevel.PRIVATE,
        )

        return skill_dto.id

    async def test_update_skill_metadata_only(self, db_session):
        """✅ Test successful metadata-only update (no version increment)"""
        skill_id = await self._create_test_skill(db_session)

        service = SkillService(db_session)

        # Update metadata only
        result = await service.update_skill(
            skill_id=skill_id,
            agent_id="test-agent",
            namespace="test-namespace",
            name="updated-skill-name",
            tags=["updated", "new-tags"],
            access_level=AccessLevel.TEAM,
        )

        # Assertions
        assert result.name == "updated-skill-name"
        assert result.tags == ["updated", "new-tags"]
        assert result.access_level == "team"
        assert result.version == 1  # No version increment
        assert result.version_count == 1

    async def test_update_skill_content_triggers_versioning(self, db_session):
        """✅ Test content update triggers version increment"""
        skill_id = await self._create_test_skill(db_session)

        service = SkillService(db_session)

        # New content
        new_content = """```json
{
  "name": "updated-audit",
  "version": "2.0.0"
}
```

## Core Instructions

Updated security audit instructions.

### New Features
- Advanced vulnerability scanning
- AI-powered code review
"""

        # Update content
        result = await service.update_skill(
            skill_id=skill_id,
            agent_id="test-agent",
            namespace="test-namespace",
            content=new_content,
        )

        # Assertions
        assert result.version == 2  # Version incremented
        assert result.version_count == 2
        assert result.content == new_content
        assert "Updated security audit" in result.core_instructions

        # Verify SkillVersion v2 was created
        from sqlalchemy import select

        stmt = select(SkillVersion).where(
            SkillVersion.skill_id == skill_id, SkillVersion.version == 2
        )
        version_result = await db_session.execute(stmt)
        version_v2 = version_result.scalar_one_or_none()

        assert version_v2 is not None
        assert version_v2.version == 2
        assert version_v2.content == new_content

    async def test_update_skill_partial_update_name_only(self, db_session):
        """✅ Test partial update (only name provided)"""
        skill_id = await self._create_test_skill(db_session)

        service = SkillService(db_session)

        # Update only name
        result = await service.update_skill(
            skill_id=skill_id,
            agent_id="test-agent",
            namespace="test-namespace",
            name="new-name-only",
        )

        # Assertions
        assert result.name == "new-name-only"
        assert result.tags == ["original", "tag1"]  # Unchanged
        assert result.access_level == "private"  # Unchanged
        assert result.version == 1  # No version increment

    async def test_update_skill_multiple_fields_no_content(self, db_session):
        """✅ Test multiple field update without content (no versioning)"""
        skill_id = await self._create_test_skill(db_session)

        service = SkillService(db_session)

        # Update multiple fields (no content)
        result = await service.update_skill(
            skill_id=skill_id,
            agent_id="test-agent",
            namespace="test-namespace",
            name="multi-update",
            tags=["tag1", "tag2", "tag3"],
            access_level=AccessLevel.PUBLIC,
        )

        # Assertions
        assert result.name == "multi-update"
        assert result.tags == ["tag1", "tag2", "tag3"]
        assert result.access_level == "public"
        assert result.version == 1  # No version increment

    async def test_update_skill_content_and_metadata(self, db_session):
        """✅ Test content + metadata update (versioning + metadata change)"""
        skill_id = await self._create_test_skill(db_session)

        service = SkillService(db_session)

        new_content = """```json
{"name": "v2", "version": "2.0.0"}
```

## Core Instructions
Version 2 content.
"""

        # Update both content and metadata
        result = await service.update_skill(
            skill_id=skill_id,
            agent_id="test-agent",
            namespace="test-namespace",
            name="v2-skill",
            content=new_content,
            tags=["v2", "updated"],
            access_level=AccessLevel.TEAM,
        )

        # Assertions
        assert result.name == "v2-skill"
        assert result.tags == ["v2", "updated"]
        assert result.access_level == "team"
        assert result.version == 2  # Version incremented
        assert result.version_count == 2
        assert result.content == new_content

    async def test_update_skill_invalid_skill_id(self, db_session):
        """❌ Test NotFoundError for invalid skill_id"""
        service = SkillService(db_session)

        # Random UUID
        nonexistent_id = str(uuid4())

        with pytest.raises(NotFoundError) as exc_info:
            await service.update_skill(
                skill_id=nonexistent_id,
                agent_id="test-agent",
                namespace="test-namespace",
                name="new-name",
            )

        assert "Skill" in str(exc_info.value)
        assert nonexistent_id in str(exc_info.value)

    async def test_update_skill_access_denied_different_owner(self, db_session):
        """❌ Test NotFoundError for access denied (different owner)"""
        # Create skill as agent1
        skill_id = await self._create_test_skill(
            db_session, agent_id="agent1", namespace="namespace1"
        )

        # Create agent2
        agent2 = Agent(
            agent_id="agent2",
            display_name="Agent 2",
            namespace="namespace2",
        )
        db_session.add(agent2)
        await db_session.commit()

        service = SkillService(db_session)

        # agent2 tries to update agent1's skill
        with pytest.raises(NotFoundError) as exc_info:
            await service.update_skill(
                skill_id=skill_id,
                agent_id="agent2",
                namespace="namespace2",
                name="hacked-name",
            )

        assert "Skill" in str(exc_info.value)
        # Verify skill was NOT updated
        from sqlalchemy import select

        stmt = select(Skill).where(Skill.id == skill_id)
        result = await db_session.execute(stmt)
        skill = result.scalar_one()
        assert skill.name == "test-skill"  # Unchanged

    async def test_update_skill_access_denied_wrong_namespace(self, db_session):
        """❌ Test NotFoundError for access denied (wrong namespace)"""
        # Create skill as agent1 in namespace1
        skill_id = await self._create_test_skill(
            db_session, agent_id="agent1", namespace="namespace1"
        )

        # Create agent2 in different namespace
        agent2 = Agent(
            agent_id="agent2",
            display_name="Agent 2",
            namespace="namespace2",
        )
        db_session.add(agent2)
        await db_session.commit()

        service = SkillService(db_session)

        # agent2 tries to update agent1's skill (different namespace)
        # Even if skill is TEAM level, agent2 can't update because not owner
        with pytest.raises(NotFoundError) as exc_info:
            await service.update_skill(
                skill_id=skill_id,
                agent_id="agent2",
                namespace="namespace2",  # Different namespace
                name="hacked-name",
            )

        assert "Skill" in str(exc_info.value)

    async def test_update_skill_invalid_name(self, db_session):
        """❌ Test ValidationError for invalid name"""
        skill_id = await self._create_test_skill(db_session)

        service = SkillService(db_session)

        # Invalid names
        invalid_names = [
            "Invalid-Name",  # Uppercase
            "1invalid",  # Starts with number
            "invalid name",  # Space
        ]

        for invalid_name in invalid_names:
            with pytest.raises(ValidationError) as exc_info:
                await service.update_skill(
                    skill_id=skill_id,
                    agent_id="test-agent",
                    namespace="test-namespace",
                    name=invalid_name,
                )

            assert "Invalid skill name format" in str(exc_info.value)

    async def test_update_skill_invalid_tags(self, db_session):
        """❌ Test ValidationError for invalid tags"""
        skill_id = await self._create_test_skill(db_session)

        service = SkillService(db_session)

        # Too many tags
        with pytest.raises(ValidationError) as exc_info:
            await service.update_skill(
                skill_id=skill_id,
                agent_id="test-agent",
                namespace="test-namespace",
                tags=[f"tag{i}" for i in range(21)],  # 21 tags (max 20)
            )

        # Validation service might use different message
        error_msg = str(exc_info.value)
        assert ("Maximum 20 tags allowed" in error_msg or "Too many tags" in error_msg)

    async def test_update_skill_invalid_content(self, db_session):
        """❌ Test ValidationError for invalid content"""
        skill_id = await self._create_test_skill(db_session)

        service = SkillService(db_session)

        # Empty content
        with pytest.raises(ValidationError) as exc_info:
            await service.update_skill(
                skill_id=skill_id,
                agent_id="test-agent",
                namespace="test-namespace",
                content="",  # Empty
            )

        assert "Skill content is required" in str(exc_info.value)

    async def test_update_skill_deleted_returns_404(self, db_session):
        """✅ Test NotFoundError for deleted skill"""
        # Create skill
        skill_id = await self._create_test_skill(db_session)

        # Mark skill as deleted
        from sqlalchemy import update

        stmt = update(Skill).where(Skill.id == skill_id).values(is_deleted=True)
        await db_session.execute(stmt)
        await db_session.commit()

        service = SkillService(db_session)

        # Try to update deleted skill
        with pytest.raises(NotFoundError) as exc_info:
            await service.update_skill(
                skill_id=skill_id,
                agent_id="test-agent",
                namespace="test-namespace",
                name="new-name",
            )

        assert "Skill" in str(exc_info.value)


@pytest.mark.asyncio
class TestSkillServiceList:
    """Test SkillService.list_skills() method - Day 1 Afternoon Phase 2"""

    async def _create_agent(self, db_session, agent_id: str, namespace: str) -> Agent:
        """Helper: Create test agent"""
        agent = Agent(
            agent_id=agent_id,
            namespace=namespace,
            display_name=f"Test Agent {agent_id}",
            capabilities={"test": True},  # capabilities is dict[str, Any]
            status=AgentStatus.ACTIVE,
        )
        db_session.add(agent)
        await db_session.commit()
        await db_session.refresh(agent)
        return agent

    async def _create_skill_for_list(
        self,
        db_session,
        name: str,
        namespace: str,
        created_by: str,
        tags: list[str] | None = None,
        access_level: AccessLevel = AccessLevel.PRIVATE,
    ) -> str:
        """Helper: Create skill for list tests"""
        service = SkillService(db_session)
        result = await service.create_skill(
            name=name,
            namespace=namespace,
            content=VALID_SKILL_CONTENT,
            created_by=created_by,
            tags=tags or [],
            access_level=access_level,
        )
        return str(result.id)

    async def test_list_skills_default_parameters(self, db_session):
        """✅ Test list_skills with default parameters (detail_level=2, limit=50, offset=0)"""
        # Setup: Create agent
        await self._create_agent(db_session, "agent1", "namespace1")

        # Create 3 skills
        await self._create_skill_for_list(
            db_session, "skill1", "namespace1", "agent1", tags=["tag1"]
        )
        await self._create_skill_for_list(
            db_session, "skill2", "namespace1", "agent1", tags=["tag2"]
        )
        await self._create_skill_for_list(
            db_session, "skill3", "namespace1", "agent1", tags=["tag3"]
        )

        # List skills
        service = SkillService(db_session)
        results = await service.list_skills(agent_id="agent1", namespace="namespace1")

        # Assertions
        assert len(results) == 3
        assert all(isinstance(r, SkillDTO) for r in results)

        # Verify detail_level=2 (metadata + core_instructions)
        assert results[0].core_instructions is not None
        assert results[0].content is None  # No full content at level 2

        # Verify ordering (newest first)
        assert results[0].name == "skill3"  # Last created, first in list
        assert results[1].name == "skill2"
        assert results[2].name == "skill1"

    async def test_list_skills_detail_level_1(self, db_session):
        """✅ Test detail_level=1 (metadata only)"""
        await self._create_agent(db_session, "agent1", "namespace1")
        await self._create_skill_for_list(db_session, "skill1", "namespace1", "agent1")

        service = SkillService(db_session)
        results = await service.list_skills(
            agent_id="agent1", namespace="namespace1", detail_level=1
        )

        # Assertions
        assert len(results) == 1
        assert results[0].name == "skill1"
        assert results[0].core_instructions is None  # No core at level 1
        assert results[0].content is None

    async def test_list_skills_detail_level_3(self, db_session):
        """✅ Test detail_level=3 (full content)"""
        await self._create_agent(db_session, "agent1", "namespace1")
        await self._create_skill_for_list(db_session, "skill1", "namespace1", "agent1")

        service = SkillService(db_session)
        results = await service.list_skills(
            agent_id="agent1", namespace="namespace1", detail_level=3
        )

        # Assertions
        assert len(results) == 1
        assert results[0].name == "skill1"
        assert results[0].core_instructions is not None
        assert results[0].content is not None  # Full content at level 3
        assert results[0].content == VALID_SKILL_CONTENT

    async def test_list_skills_filter_by_single_tag(self, db_session):
        """✅ Test filter by single tag"""
        await self._create_agent(db_session, "agent1", "namespace1")

        # Create skills with different tags
        await self._create_skill_for_list(
            db_session, "skill1", "namespace1", "agent1", tags=["security", "audit"]
        )
        await self._create_skill_for_list(
            db_session, "skill2", "namespace1", "agent1", tags=["performance"]
        )
        await self._create_skill_for_list(
            db_session, "skill3", "namespace1", "agent1", tags=["security", "scan"]
        )

        service = SkillService(db_session)
        results = await service.list_skills(
            agent_id="agent1", namespace="namespace1", tags=["security"]
        )

        # Assertions
        assert len(results) == 2
        assert {r.name for r in results} == {"skill1", "skill3"}

    async def test_list_skills_filter_by_multiple_tags_and_logic(self, db_session):
        """✅ Test filter by multiple tags (AND logic)"""
        await self._create_agent(db_session, "agent1", "namespace1")

        # Create skills
        await self._create_skill_for_list(
            db_session, "skill1", "namespace1", "agent1", tags=["security", "audit"]
        )
        await self._create_skill_for_list(
            db_session, "skill2", "namespace1", "agent1", tags=["security"]
        )
        await self._create_skill_for_list(
            db_session, "skill3", "namespace1", "agent1", tags=["audit"]
        )

        service = SkillService(db_session)
        # Filter by both "security" AND "audit"
        results = await service.list_skills(
            agent_id="agent1", namespace="namespace1", tags=["security", "audit"]
        )

        # Assertions - only skill1 has both tags
        assert len(results) == 1
        assert results[0].name == "skill1"

    async def test_list_skills_filter_by_access_level(self, db_session):
        """✅ Test filter by access_level"""
        await self._create_agent(db_session, "agent1", "namespace1")

        # Create skills with different access levels
        await self._create_skill_for_list(
            db_session,
            "private1",
            "namespace1",
            "agent1",
            access_level=AccessLevel.PRIVATE,
        )
        await self._create_skill_for_list(
            db_session, "public1", "namespace1", "agent1", access_level=AccessLevel.PUBLIC
        )
        await self._create_skill_for_list(
            db_session, "team1", "namespace1", "agent1", access_level=AccessLevel.TEAM
        )

        service = SkillService(db_session)
        # Filter by PUBLIC only
        results = await service.list_skills(
            agent_id="agent1",
            namespace="namespace1",
            access_level=AccessLevel.PUBLIC,
        )

        # Assertions
        assert len(results) == 1
        assert results[0].name == "public1"

    async def test_list_skills_pagination_limit(self, db_session):
        """✅ Test pagination with limit"""
        await self._create_agent(db_session, "agent1", "namespace1")

        # Create 15 skills
        for i in range(1, 16):
            await self._create_skill_for_list(
                db_session, f"skill{i:02d}", "namespace1", "agent1"
            )

        service = SkillService(db_session)
        results = await service.list_skills(
            agent_id="agent1", namespace="namespace1", limit=10
        )

        # Assertions
        assert len(results) == 10

    async def test_list_skills_pagination_offset(self, db_session):
        """✅ Test pagination with offset"""
        await self._create_agent(db_session, "agent1", "namespace1")

        # Create 10 skills
        for i in range(1, 11):
            await self._create_skill_for_list(
                db_session, f"skill{i:02d}", "namespace1", "agent1"
            )

        service = SkillService(db_session)
        # Get skills from offset 5
        results = await service.list_skills(
            agent_id="agent1", namespace="namespace1", limit=10, offset=5
        )

        # Assertions
        assert len(results) == 5  # 10 total, offset 5, so 5 remaining

    async def test_list_skills_access_control_private(self, db_session):
        """✅ Test access control - PRIVATE skills only visible to owner"""
        await self._create_agent(db_session, "agent1", "namespace1")
        await self._create_agent(db_session, "agent2", "namespace1")  # Same namespace

        # Agent1 creates PRIVATE skill
        await self._create_skill_for_list(
            db_session,
            "private1",
            "namespace1",
            "agent1",
            access_level=AccessLevel.PRIVATE,
        )

        service = SkillService(db_session)

        # Agent2 should NOT see agent1's private skill
        results = await service.list_skills(agent_id="agent2", namespace="namespace1")

        assert len(results) == 0

    async def test_list_skills_access_control_team(self, db_session):
        """✅ Test access control - TEAM skills visible to same namespace"""
        await self._create_agent(db_session, "agent1", "namespace1")
        await self._create_agent(db_session, "agent2", "namespace1")  # Same namespace
        await self._create_agent(db_session, "agent3", "namespace2")  # Different namespace

        # Agent1 creates TEAM skill
        await self._create_skill_for_list(
            db_session, "team1", "namespace1", "agent1", access_level=AccessLevel.TEAM
        )

        service = SkillService(db_session)

        # Agent2 (same namespace) should see it
        results_agent2 = await service.list_skills(
            agent_id="agent2", namespace="namespace1"
        )
        assert len(results_agent2) == 1
        assert results_agent2[0].name == "team1"

        # Agent3 (different namespace) should NOT see it
        results_agent3 = await service.list_skills(
            agent_id="agent3", namespace="namespace2"
        )
        assert len(results_agent3) == 0

    async def test_list_skills_access_control_public(self, db_session):
        """✅ Test access control - PUBLIC skills visible to all agents"""
        await self._create_agent(db_session, "agent1", "namespace1")
        await self._create_agent(db_session, "agent2", "namespace2")  # Different namespace

        # Agent1 creates PUBLIC skill
        await self._create_skill_for_list(
            db_session, "public1", "namespace1", "agent1", access_level=AccessLevel.PUBLIC
        )

        service = SkillService(db_session)

        # Agent2 (different namespace) should see PUBLIC skill
        results = await service.list_skills(agent_id="agent2", namespace="namespace2")

        assert len(results) == 1
        assert results[0].name == "public1"

    async def test_list_skills_invalid_detail_level(self, db_session):
        """❌ Test invalid detail_level raises ValidationError"""
        await self._create_agent(db_session, "agent1", "namespace1")

        service = SkillService(db_session)

        # Test detail_level=0
        with pytest.raises(ValidationError) as exc_info:
            await service.list_skills(
                agent_id="agent1", namespace="namespace1", detail_level=0
            )
        assert "detail_level" in str(exc_info.value).lower()

        # Test detail_level=4
        with pytest.raises(ValidationError) as exc_info:
            await service.list_skills(
                agent_id="agent1", namespace="namespace1", detail_level=4
            )
        assert "detail_level" in str(exc_info.value).lower()

    async def test_list_skills_invalid_limit(self, db_session):
        """❌ Test invalid limit raises ValidationError"""
        await self._create_agent(db_session, "agent1", "namespace1")

        service = SkillService(db_session)

        # Test limit=0
        with pytest.raises(ValidationError) as exc_info:
            await service.list_skills(agent_id="agent1", namespace="namespace1", limit=0)
        assert "limit" in str(exc_info.value).lower()

        # Test limit=101
        with pytest.raises(ValidationError) as exc_info:
            await service.list_skills(
                agent_id="agent1", namespace="namespace1", limit=101
            )
        assert "limit" in str(exc_info.value).lower()

    async def test_list_skills_invalid_offset(self, db_session):
        """❌ Test invalid offset raises ValidationError"""
        await self._create_agent(db_session, "agent1", "namespace1")

        service = SkillService(db_session)

        # Test offset=-1
        with pytest.raises(ValidationError) as exc_info:
            await service.list_skills(
                agent_id="agent1", namespace="namespace1", offset=-1
            )
        assert "offset" in str(exc_info.value).lower()


class TestSkillServiceDelete:
    """Test suite for delete_skill() method - Soft delete with P0-1 access control"""

    async def _create_agent(
        self, session: AsyncSession, agent_id: str, namespace: str
    ) -> None:
        """Helper: Create agent for testing"""
        from src.models.agent import Agent, AgentStatus

        agent = Agent(
            agent_id=agent_id,
            namespace=namespace,
            display_name=f"Test Agent {agent_id}",
            capabilities={"test": True},
            status=AgentStatus.ACTIVE,
        )
        session.add(agent)
        await session.commit()

    async def _create_skill(
        self, session: AsyncSession, agent_id: str, namespace: str, name: str
    ) -> str:
        """Helper: Create skill and return ID (as string)"""
        from src.models.skill import Skill, SkillVersion

        skill_id = str(uuid.uuid4())
        skill = Skill(
            id=skill_id,
            name=name,
            namespace=namespace,
            created_by=agent_id,
            access_level=AccessLevel.PRIVATE,
            tags_json="[]",
        )
        session.add(skill)

        version = SkillVersion(
            id=str(uuid.uuid4()),
            skill_id=skill_id,
            version=1,
            content="# Test Skill\n\nTest content",
            created_by=agent_id,
        )
        session.add(version)

        await session.commit()
        return skill_id

    async def _create_activation(
        self, session: AsyncSession, skill_id: str, agent_id: str, namespace: str
    ) -> None:
        """Helper: Create skill activation record"""
        from datetime import datetime, timezone

        from src.models.skill import SkillActivation

        activation = SkillActivation(
            id=str(uuid.uuid4()),
            skill_id=skill_id,
            agent_id=agent_id,
            version=1,
            namespace=namespace,
            activated_at=datetime.now(timezone.utc),
        )
        session.add(activation)
        await session.commit()

    @pytest.mark.asyncio
    async def test_delete_skill_success(self, db_session: AsyncSession) -> None:
        """✅ Test successful skill deletion (soft delete)"""
        # Arrange: Create agent and skill
        await self._create_agent(db_session, "agent1", "namespace1")
        skill_id = await self._create_skill(
            db_session, "agent1", "namespace1", "test-skill"
        )

        service = SkillService(db_session)

        # Act: Delete skill
        await service.delete_skill(
            skill_id=skill_id, agent_id="agent1", namespace="namespace1"
        )

        # Assert: Skill is soft-deleted
        from sqlalchemy import select

        from src.models.skill import Skill

        result = await db_session.execute(select(Skill).where(Skill.id == skill_id))
        skill = result.scalar_one_or_none()

        assert skill is not None  # Still in database
        assert skill.is_deleted is True  # Soft deleted
        assert skill.updated_at is not None  # Updated timestamp

    @pytest.mark.asyncio
    async def test_deleted_skill_invisible_to_get_skill(
        self, db_session: AsyncSession
    ) -> None:
        """✅ Test deleted skill is invisible to get_skill() (returns NotFoundError)"""
        # Arrange: Create and delete skill
        await self._create_agent(db_session, "agent1", "namespace1")
        skill_id = await self._create_skill(
            db_session, "agent1", "namespace1", "test-skill"
        )

        service = SkillService(db_session)
        await service.delete_skill(
            skill_id=skill_id, agent_id="agent1", namespace="namespace1"
        )

        # Act & Assert: get_skill() returns NotFoundError
        with pytest.raises(NotFoundError) as exc_info:
            await service.get_skill(
                skill_id=skill_id,
                agent_id="agent1",
                namespace="namespace1",
                detail_level=2,
            )

        assert "not found" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_deleted_skill_invisible_to_list_skills(
        self, db_session: AsyncSession
    ) -> None:
        """✅ Test deleted skill is invisible to list_skills() (not in results)"""
        # Arrange: Create two skills, delete one
        await self._create_agent(db_session, "agent1", "namespace1")
        skill1_id = await self._create_skill(
            db_session, "agent1", "namespace1", "skill1"
        )
        skill2_id = await self._create_skill(
            db_session, "agent1", "namespace1", "skill2"
        )

        service = SkillService(db_session)
        await service.delete_skill(
            skill_id=skill1_id, agent_id="agent1", namespace="namespace1"
        )

        # Act: List skills
        skills = await service.list_skills(
            agent_id="agent1", namespace="namespace1", limit=50, offset=0
        )

        # Assert: Only non-deleted skill is returned
        assert len(skills) == 1
        assert skills[0].id == skill2_id
        assert str(skill1_id) not in [str(s.id) for s in skills]

    @pytest.mark.asyncio
    async def test_delete_other_agent_skill_not_found(
        self, db_session: AsyncSession
    ) -> None:
        """❌ Test cannot delete other agent's skill (returns NotFoundError, not 403)"""
        # Arrange: Create two agents and skill owned by agent1
        await self._create_agent(db_session, "agent1", "namespace1")
        await self._create_agent(db_session, "agent2", "namespace1")
        skill_id = await self._create_skill(
            db_session, "agent1", "namespace1", "test-skill"
        )

        service = SkillService(db_session)

        # Act & Assert: agent2 cannot delete agent1's skill (404, not 403)
        with pytest.raises(NotFoundError) as exc_info:
            await service.delete_skill(
                skill_id=skill_id, agent_id="agent2", namespace="namespace1"
            )

        assert "not found" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_delete_already_deleted_skill_idempotent(
        self, db_session: AsyncSession
    ) -> None:
        """❌ Test deleting already deleted skill returns NotFoundError (idempotent)"""
        # Arrange: Create and delete skill
        await self._create_agent(db_session, "agent1", "namespace1")
        skill_id = await self._create_skill(
            db_session, "agent1", "namespace1", "test-skill"
        )

        service = SkillService(db_session)
        await service.delete_skill(
            skill_id=skill_id, agent_id="agent1", namespace="namespace1"
        )

        # Act & Assert: Second deletion returns NotFoundError
        with pytest.raises(NotFoundError) as exc_info:
            await service.delete_skill(
                skill_id=skill_id, agent_id="agent1", namespace="namespace1"
            )

        assert "not found" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_delete_activated_skill_validation_error(
        self, db_session: AsyncSession
    ) -> None:
        """❌ Test cannot delete activated skill (must deactivate first)"""
        # Arrange: Create skill with recent activation
        await self._create_agent(db_session, "agent1", "namespace1")
        skill_id = await self._create_skill(
            db_session, "agent1", "namespace1", "test-skill"
        )

        # Create activation within last 24 hours
        await self._create_activation(db_session, skill_id, "agent1", "namespace1")

        service = SkillService(db_session)

        # Act & Assert: Cannot delete activated skill
        with pytest.raises(ValidationError) as exc_info:
            await service.delete_skill(
                skill_id=skill_id, agent_id="agent1", namespace="namespace1"
            )

        error_str = str(exc_info.value).lower()
        assert "activated" in error_str


class TestSkillServiceShare:
    """Test suite for share_skill() method - SHARED access control management"""

    async def _create_agent(
        self, session: AsyncSession, agent_id: str, namespace: str
    ) -> None:
        """Helper: Create agent for testing"""
        from src.models.agent import Agent, AgentStatus

        agent = Agent(
            agent_id=agent_id,
            namespace=namespace,
            display_name=f"Test Agent {agent_id}",
            capabilities={"test": True},
            status=AgentStatus.ACTIVE,
        )
        session.add(agent)
        await session.commit()

    async def _create_skill(
        self,
        session: AsyncSession,
        agent_id: str,
        namespace: str,
        skill_name: str,
        access_level: AccessLevel = AccessLevel.PRIVATE,
    ) -> uuid.UUID:
        """Helper: Create skill for testing"""
        from src.models.skill import Skill, SkillVersion

        skill_id = uuid.uuid4()
        skill = Skill(
            id=str(skill_id),
            name=skill_name,
            namespace=namespace,
            created_by=agent_id,
            access_level=access_level,
            tags_json="[]",
        )
        session.add(skill)

        # Create version
        version = SkillVersion(
            id=str(uuid.uuid4()),
            skill_id=str(skill_id),
            version=1,
            content=f"# {skill_name}\nTest content",
            created_by=agent_id,
        )
        session.add(version)
        await session.commit()
        return skill_id

    @pytest.mark.asyncio
    async def test_share_skill_add_single_agent_success(
        self, db_session: AsyncSession
    ) -> None:
        """✅ Test share skill with single agent (successful add)"""
        # Arrange: Create owner and collaborator in same namespace
        await self._create_agent(db_session, "owner-123", "namespace1")
        await self._create_agent(db_session, "collaborator-456", "namespace1")

        skill_id = await self._create_skill(
            db_session,
            "owner-123",
            "namespace1",
            "shared-skill",
            access_level=AccessLevel.SHARED,
        )

        service = SkillService(db_session)

        # Act: Share with single agent
        result_dto = await service.share_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
            agent_ids_to_add=["collaborator-456"],
        )

        # Assert: Skill shared successfully
        assert str(result_dto.id) == str(skill_id)
        assert result_dto.name == "shared-skill"
        assert result_dto.access_level == AccessLevel.SHARED.value

        # Verify SkillSharedAgent record created
        from sqlalchemy import select

        from src.models.skill import SkillSharedAgent

        shared_stmt = select(SkillSharedAgent).where(
            SkillSharedAgent.skill_id == str(skill_id),
            SkillSharedAgent.agent_id == "collaborator-456",
        )
        result = await db_session.execute(shared_stmt)
        shared_record = result.scalar_one_or_none()
        assert shared_record is not None
        assert shared_record.agent_id == "collaborator-456"

    @pytest.mark.asyncio
    async def test_share_skill_add_multiple_agents_success(
        self, db_session: AsyncSession
    ) -> None:
        """✅ Test share skill with multiple agents"""
        # Arrange: Create owner and 3 collaborators
        await self._create_agent(db_session, "owner-123", "namespace1")
        await self._create_agent(db_session, "agent-a", "namespace1")
        await self._create_agent(db_session, "agent-b", "namespace1")
        await self._create_agent(db_session, "agent-c", "namespace1")

        skill_id = await self._create_skill(
            db_session,
            "owner-123",
            "namespace1",
            "multi-share-skill",
            access_level=AccessLevel.SHARED,
        )

        service = SkillService(db_session)

        # Act: Share with multiple agents
        await service.share_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
            agent_ids_to_add=["agent-a", "agent-b", "agent-c"],
        )

        # Assert: 3 SkillSharedAgent records created
        from sqlalchemy import select

        from src.models.skill import SkillSharedAgent

        shared_stmt = select(SkillSharedAgent).where(
            SkillSharedAgent.skill_id == str(skill_id)
        )
        result = await db_session.execute(shared_stmt)
        shared_records = result.scalars().all()
        assert len(shared_records) == 3
        shared_agent_ids = {record.agent_id for record in shared_records}
        assert shared_agent_ids == {"agent-a", "agent-b", "agent-c"}

    @pytest.mark.asyncio
    async def test_share_skill_remove_single_agent_success(
        self, db_session: AsyncSession
    ) -> None:
        """✅ Test remove single agent from shared skill"""
        # Arrange: Create owner, collaborator, and shared skill
        await self._create_agent(db_session, "owner-123", "namespace1")
        await self._create_agent(db_session, "collaborator-456", "namespace1")

        skill_id = await self._create_skill(
            db_session,
            "owner-123",
            "namespace1",
            "shared-skill",
            access_level=AccessLevel.SHARED,
        )

        # Share with collaborator first
        service = SkillService(db_session)
        await service.share_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
            agent_ids_to_add=["collaborator-456"],
        )

        # Act: Remove collaborator from sharing
        await service.share_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
            agent_ids_to_remove=["collaborator-456"],
        )

        # Assert: SkillSharedAgent record deleted
        from sqlalchemy import select

        from src.models.skill import SkillSharedAgent

        shared_stmt = select(SkillSharedAgent).where(
            SkillSharedAgent.skill_id == str(skill_id),
            SkillSharedAgent.agent_id == "collaborator-456",
        )
        result = await db_session.execute(shared_stmt)
        shared_record = result.scalar_one_or_none()
        assert shared_record is None

    @pytest.mark.asyncio
    async def test_share_skill_add_and_remove_in_single_call_success(
        self, db_session: AsyncSession
    ) -> None:
        """✅ Test add and remove agents in single call (atomic operation)"""
        # Arrange: Create owner and 4 agents
        await self._create_agent(db_session, "owner-123", "namespace1")
        await self._create_agent(db_session, "agent-a", "namespace1")
        await self._create_agent(db_session, "agent-b", "namespace1")
        await self._create_agent(db_session, "agent-c", "namespace1")
        await self._create_agent(db_session, "agent-d", "namespace1")

        skill_id = await self._create_skill(
            db_session,
            "owner-123",
            "namespace1",
            "mixed-share-skill",
            access_level=AccessLevel.SHARED,
        )

        service = SkillService(db_session)

        # First, share with agents A and B
        await service.share_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
            agent_ids_to_add=["agent-a", "agent-b"],
        )

        # Act: Add C and D, remove A and B (atomic)
        await service.share_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
            agent_ids_to_add=["agent-c", "agent-d"],
            agent_ids_to_remove=["agent-a", "agent-b"],
        )

        # Assert: Only C and D remain
        from sqlalchemy import select

        from src.models.skill import SkillSharedAgent

        shared_stmt = select(SkillSharedAgent).where(
            SkillSharedAgent.skill_id == str(skill_id)
        )
        result = await db_session.execute(shared_stmt)
        shared_records = result.scalars().all()
        assert len(shared_records) == 2
        shared_agent_ids = {record.agent_id for record in shared_records}
        assert shared_agent_ids == {"agent-c", "agent-d"}

    @pytest.mark.asyncio
    async def test_share_skill_idempotent_add_success(
        self, db_session: AsyncSession
    ) -> None:
        """✅ Test idempotent add (adding same agent twice is no-op)"""
        # Arrange
        await self._create_agent(db_session, "owner-123", "namespace1")
        await self._create_agent(db_session, "collaborator-456", "namespace1")

        skill_id = await self._create_skill(
            db_session,
            "owner-123",
            "namespace1",
            "idempotent-skill",
            access_level=AccessLevel.SHARED,
        )

        service = SkillService(db_session)

        # Act: Share twice with same agent
        await service.share_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
            agent_ids_to_add=["collaborator-456"],
        )

        await service.share_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
            agent_ids_to_add=["collaborator-456"],  # Same agent again
        )

        # Assert: Only 1 SkillSharedAgent record (no duplicate)
        from sqlalchemy import select

        from src.models.skill import SkillSharedAgent

        shared_stmt = select(SkillSharedAgent).where(
            SkillSharedAgent.skill_id == str(skill_id),
            SkillSharedAgent.agent_id == "collaborator-456",
        )
        result = await db_session.execute(shared_stmt)
        shared_records = result.scalars().all()
        assert len(shared_records) == 1

    @pytest.mark.asyncio
    async def test_share_skill_idempotent_remove_success(
        self, db_session: AsyncSession
    ) -> None:
        """✅ Test idempotent remove (removing non-shared agent is no-op)"""
        # Arrange
        await self._create_agent(db_session, "owner-123", "namespace1")
        await self._create_agent(db_session, "never-shared-agent", "namespace1")

        skill_id = await self._create_skill(
            db_session,
            "owner-123",
            "namespace1",
            "remove-test-skill",
            access_level=AccessLevel.SHARED,
        )

        service = SkillService(db_session)

        # Act: Remove agent that was never shared (should not error)
        result_dto = await service.share_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
            agent_ids_to_remove=["never-shared-agent"],
        )

        # Assert: No error, operation succeeds
        assert str(result_dto.id) == str(skill_id)
        assert result_dto.name == "remove-test-skill"

    @pytest.mark.asyncio
    async def test_share_skill_cannot_share_non_shared_skill_validation_error(
        self, db_session: AsyncSession
    ) -> None:
        """❌ Test cannot share non-SHARED skill (ValidationError)"""
        # Arrange: Create PRIVATE skill (not SHARED)
        await self._create_agent(db_session, "owner-123", "namespace1")
        await self._create_agent(db_session, "collaborator-456", "namespace1")

        skill_id = await self._create_skill(
            db_session,
            "owner-123",
            "namespace1",
            "private-skill",
            access_level=AccessLevel.PRIVATE,  # Not SHARED
        )

        service = SkillService(db_session)

        # Act & Assert: Cannot share PRIVATE skill
        with pytest.raises(ValidationError) as exc_info:
            await service.share_skill(
                skill_id=skill_id,
                agent_id="owner-123",
                namespace="namespace1",
                agent_ids_to_add=["collaborator-456"],
            )

        error_str = str(exc_info.value).lower()
        assert "shared" in error_str
        assert "shared" in error_str

    @pytest.mark.asyncio
    async def test_share_skill_invalid_agent_id_validation_error(
        self, db_session: AsyncSession
    ) -> None:
        """❌ Test cannot share with non-existent agent (ValidationError)"""
        # Arrange: Create skill but no collaborator
        await self._create_agent(db_session, "owner-123", "namespace1")

        skill_id = await self._create_skill(
            db_session,
            "owner-123",
            "namespace1",
            "shared-skill",
            access_level=AccessLevel.SHARED,
        )

        service = SkillService(db_session)

        # Act & Assert: Cannot share with non-existent agent
        with pytest.raises(ValidationError) as exc_info:
            await service.share_skill(
                skill_id=skill_id,
                agent_id="owner-123",
                namespace="namespace1",
                agent_ids_to_add=["nonexistent-agent-999"],
            )

        error_str = str(exc_info.value).lower()
        assert "invalid" in error_str
        assert "agent" in error_str

    @pytest.mark.asyncio
    async def test_share_skill_cross_namespace_validation_error(
        self, db_session: AsyncSession
    ) -> None:
        """❌ Test cannot share with agent in different namespace (ValidationError)"""
        # Arrange: Create owner in namespace1, collaborator in namespace2
        await self._create_agent(db_session, "owner-123", "namespace1")
        await self._create_agent(db_session, "other-agent-456", "namespace2")

        skill_id = await self._create_skill(
            db_session,
            "owner-123",
            "namespace1",
            "shared-skill",
            access_level=AccessLevel.SHARED,
        )

        service = SkillService(db_session)

        # Act & Assert: Cannot share with agent in different namespace
        with pytest.raises(ValidationError) as exc_info:
            await service.share_skill(
                skill_id=skill_id,
                agent_id="owner-123",
                namespace="namespace1",
                agent_ids_to_add=["other-agent-456"],  # Different namespace
            )

        error_str = str(exc_info.value).lower()
        assert "invalid" in error_str
        assert "agent" in error_str

    @pytest.mark.asyncio
    async def test_share_skill_non_owner_cannot_share_not_found_error(
        self, db_session: AsyncSession
    ) -> None:
        """❌ Test non-owner cannot modify sharing (NotFoundError for security)"""
        # Arrange: Create owner and non-owner
        await self._create_agent(db_session, "owner-123", "namespace1")
        await self._create_agent(db_session, "non-owner-456", "namespace1")
        await self._create_agent(db_session, "collaborator-789", "namespace1")

        skill_id = await self._create_skill(
            db_session,
            "owner-123",
            "namespace1",
            "shared-skill",
            access_level=AccessLevel.SHARED,
        )

        service = SkillService(db_session)

        # Act & Assert: Non-owner cannot modify sharing
        with pytest.raises(NotFoundError) as exc_info:
            await service.share_skill(
                skill_id=skill_id,
                agent_id="non-owner-456",  # Not the owner
                namespace="namespace1",
                agent_ids_to_add=["collaborator-789"],
            )

        error_str = str(exc_info.value).lower()
        assert "not found" in error_str


class TestSkillActivation:
    """Test suite for activate_skill() and deactivate_skill() methods"""

    async def _create_agent(
        self, db_session: AsyncSession, agent_id: str, namespace: str
    ) -> None:
        """Helper: Create agent for testing"""
        from src.models.agent import Agent

        agent = Agent(
            id=agent_id,
            agent_id=agent_id,
            namespace=namespace,
            display_name=f"Agent {agent_id}",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(agent)
        await db_session.commit()

    async def _create_skill(
        self,
        db_session: AsyncSession,
        agent_id: str,
        namespace: str,
        skill_name: str,
        access_level: AccessLevel = AccessLevel.PRIVATE,
    ) -> UUID:
        """Helper: Create skill for testing"""
        from src.models.skill import Skill, SkillVersion

        skill_id = str(uuid.uuid4())
        skill = Skill(
            id=skill_id,
            name=skill_name,
            namespace=namespace,
            created_by=agent_id,
            access_level=access_level,
            version_count=1,
            active_version=1,
        )
        db_session.add(skill)

        # Create version
        version = SkillVersion(
            id=str(uuid.uuid4()),
            skill_id=skill_id,
            version=1,
            content="# Test Skill\n\nTest content",
            core_instructions="Core instructions for testing",
            created_by=agent_id,
        )
        db_session.add(version)
        await db_session.commit()

        return UUID(skill_id)

    @pytest.mark.asyncio
    async def test_activate_skill_success(self, db_session: AsyncSession) -> None:
        """✅ Test successful skill activation"""
        # Arrange
        await self._create_agent(db_session, "owner-123", "namespace1")
        skill_id = await self._create_skill(
            db_session, "owner-123", "namespace1", "test-skill"
        )

        service = SkillService(db_session)

        # Act: Activate skill
        result = await service.activate_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
        )

        # Assert
        assert result.id == str(skill_id)
        assert result.name == "test-skill"

        # Verify SkillActivation record was created
        from src.models.skill import SkillActivation

        activation_stmt = select(SkillActivation).where(
            SkillActivation.skill_id == str(skill_id),
            SkillActivation.agent_id == "owner-123",
        )
        activation_result = await db_session.execute(activation_stmt)
        activation = activation_result.scalar_one_or_none()

        assert activation is not None
        assert activation.skill_id == str(skill_id)
        assert activation.agent_id == "owner-123"
        assert activation.namespace == "namespace1"
        assert activation.activation_type == "mcp_tool"
        assert activation.layer_loaded == 2  # Progressive Disclosure Layer 2
        assert activation.tokens_loaded == 2000
        assert activation.success is None  # NULL = active

    @pytest.mark.asyncio
    async def test_activate_skill_idempotent(self, db_session: AsyncSession) -> None:
        """✅ Test activating already-active skill (idempotent)"""
        # Arrange
        await self._create_agent(db_session, "owner-123", "namespace1")
        skill_id = await self._create_skill(
            db_session, "owner-123", "namespace1", "test-skill"
        )

        service = SkillService(db_session)

        # Activate once
        await service.activate_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
        )

        # Act: Activate again (idempotent)
        result = await service.activate_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
        )

        # Assert: Should succeed without error
        assert result.id == str(skill_id)

        # Verify only one active activation record exists
        from src.models.skill import SkillActivation

        activation_stmt = (
            select(SkillActivation)
            .where(
                SkillActivation.skill_id == str(skill_id),
                SkillActivation.agent_id == "owner-123",
            )
            .order_by(SkillActivation.activated_at.desc())
        )
        activation_result = await db_session.execute(activation_stmt)
        activations = activation_result.scalars().all()

        # Should have 1 activation (idempotent, not duplicated)
        assert len(activations) == 1
        assert activations[0].success is None  # Still active

    @pytest.mark.asyncio
    async def test_activate_skill_one_per_namespace_validation_error(
        self, db_session: AsyncSession
    ) -> None:
        """❌ Test one-active-per-namespace enforcement (ValidationError)"""
        # Arrange: Create two skills in same namespace
        await self._create_agent(db_session, "owner-123", "namespace1")
        skill1_id = await self._create_skill(
            db_session, "owner-123", "namespace1", "skill-1"
        )
        skill2_id = await self._create_skill(
            db_session, "owner-123", "namespace1", "skill-2"
        )

        service = SkillService(db_session)

        # Activate first skill
        await service.activate_skill(
            skill_id=skill1_id,
            agent_id="owner-123",
            namespace="namespace1",
        )

        # Act & Assert: Cannot activate second skill (one-per-namespace rule)
        with pytest.raises(ValidationError) as exc_info:
            await service.activate_skill(
                skill_id=skill2_id,
                agent_id="owner-123",
                namespace="namespace1",
            )

        error_str = str(exc_info.value).lower()
        assert "already active" in error_str or "one" in error_str
        assert "namespace" in error_str

    @pytest.mark.asyncio
    async def test_activate_skill_deleted_skill_not_found_error(
        self, db_session: AsyncSession
    ) -> None:
        """❌ Test cannot activate deleted skill (NotFoundError)"""
        # Arrange: Create and delete skill
        await self._create_agent(db_session, "owner-123", "namespace1")
        skill_id = await self._create_skill(
            db_session, "owner-123", "namespace1", "deleted-skill"
        )

        # Delete skill
        from src.models.skill import Skill

        skill_stmt = select(Skill).where(Skill.id == str(skill_id))
        skill_result = await db_session.execute(skill_stmt)
        skill = skill_result.scalar_one()
        skill.is_deleted = True
        await db_session.commit()

        service = SkillService(db_session)

        # Act & Assert: Cannot activate deleted skill
        with pytest.raises(NotFoundError) as exc_info:
            await service.activate_skill(
                skill_id=skill_id,
                agent_id="owner-123",
                namespace="namespace1",
            )

        error_str = str(exc_info.value).lower()
        assert "not found" in error_str

    @pytest.mark.asyncio
    async def test_activate_skill_non_owner_not_found_error(
        self, db_session: AsyncSession
    ) -> None:
        """❌ Test non-owner cannot activate (NotFoundError for security)"""
        # Arrange: Create owner and non-owner
        await self._create_agent(db_session, "owner-123", "namespace1")
        await self._create_agent(db_session, "non-owner-456", "namespace1")
        skill_id = await self._create_skill(
            db_session, "owner-123", "namespace1", "test-skill"
        )

        service = SkillService(db_session)

        # Act & Assert: Non-owner cannot activate
        with pytest.raises(NotFoundError) as exc_info:
            await service.activate_skill(
                skill_id=skill_id,
                agent_id="non-owner-456",  # Not the owner
                namespace="namespace1",
            )

        error_str = str(exc_info.value).lower()
        assert "not found" in error_str

    @pytest.mark.asyncio
    async def test_activate_deactivate_activate_workflow(
        self, db_session: AsyncSession
    ) -> None:
        """✅ Test full lifecycle: activate → deactivate → activate again"""
        # Arrange
        await self._create_agent(db_session, "owner-123", "namespace1")
        skill_id = await self._create_skill(
            db_session, "owner-123", "namespace1", "test-skill"
        )

        service = SkillService(db_session)

        # Act 1: Activate
        await service.activate_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
        )

        # Act 2: Deactivate
        await service.deactivate_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
        )

        # Act 3: Activate again
        result = await service.activate_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
        )

        # Assert: Should succeed
        assert result.id == str(skill_id)

        # Verify activation history
        from src.models.skill import SkillActivation

        activation_stmt = (
            select(SkillActivation)
            .where(
                SkillActivation.skill_id == str(skill_id),
                SkillActivation.agent_id == "owner-123",
            )
            .order_by(SkillActivation.activated_at.desc())
        )
        activation_result = await db_session.execute(activation_stmt)
        activations = activation_result.scalars().all()

        # Should have 2 activations (first deactivated, second active)
        assert len(activations) == 2
        assert activations[0].success is None  # Latest = active
        assert activations[1].success is False  # First = deactivated

    @pytest.mark.asyncio
    async def test_different_namespaces_can_have_active_skills(
        self, db_session: AsyncSession
    ) -> None:
        """✅ Test different namespaces can have different active skills"""
        # Arrange: Two agents in different namespaces
        await self._create_agent(db_session, "agent-123", "namespace1")
        await self._create_agent(db_session, "agent-456", "namespace2")

        skill1_id = await self._create_skill(
            db_session, "agent-123", "namespace1", "skill-1"
        )
        skill2_id = await self._create_skill(
            db_session, "agent-456", "namespace2", "skill-2"
        )

        service = SkillService(db_session)

        # Act: Activate both skills (different namespaces)
        result1 = await service.activate_skill(
            skill_id=skill1_id,
            agent_id="agent-123",
            namespace="namespace1",
        )
        result2 = await service.activate_skill(
            skill_id=skill2_id,
            agent_id="agent-456",
            namespace="namespace2",
        )

        # Assert: Both should succeed
        assert result1.id == str(skill1_id)
        assert result2.id == str(skill2_id)

    @pytest.mark.asyncio
    async def test_deactivate_skill_success(self, db_session: AsyncSession) -> None:
        """✅ Test successful skill deactivation"""
        # Arrange: Activate skill first
        await self._create_agent(db_session, "owner-123", "namespace1")
        skill_id = await self._create_skill(
            db_session, "owner-123", "namespace1", "test-skill"
        )

        service = SkillService(db_session)
        await service.activate_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
        )

        # Act: Deactivate skill
        result = await service.deactivate_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
        )

        # Assert
        assert result.id == str(skill_id)

        # Verify SkillActivation record was updated
        from src.models.skill import SkillActivation

        activation_stmt = (
            select(SkillActivation)
            .where(
                SkillActivation.skill_id == str(skill_id),
                SkillActivation.agent_id == "owner-123",
            )
            .order_by(SkillActivation.activated_at.desc())
            .limit(1)
        )
        activation_result = await db_session.execute(activation_stmt)
        activation = activation_result.scalar_one_or_none()

        assert activation is not None
        assert activation.success is False  # Deactivated
        assert activation.duration_ms is not None
        assert activation.duration_ms > 0

    @pytest.mark.asyncio
    async def test_deactivate_skill_idempotent(self, db_session: AsyncSession) -> None:
        """✅ Test deactivating non-active skill (idempotent)"""
        # Arrange: Create skill but don't activate
        await self._create_agent(db_session, "owner-123", "namespace1")
        skill_id = await self._create_skill(
            db_session, "owner-123", "namespace1", "test-skill"
        )

        service = SkillService(db_session)

        # Act: Deactivate without activating first (idempotent)
        result = await service.deactivate_skill(
            skill_id=skill_id,
            agent_id="owner-123",
            namespace="namespace1",
        )

        # Assert: Should succeed without error
        assert result.id == str(skill_id)

    @pytest.mark.asyncio
    async def test_deactivate_skill_deleted_skill_not_found_error(
        self, db_session: AsyncSession
    ) -> None:
        """❌ Test cannot deactivate deleted skill (NotFoundError)"""
        # Arrange: Create and delete skill
        await self._create_agent(db_session, "owner-123", "namespace1")
        skill_id = await self._create_skill(
            db_session, "owner-123", "namespace1", "deleted-skill"
        )

        # Delete skill
        from src.models.skill import Skill

        skill_stmt = select(Skill).where(Skill.id == str(skill_id))
        skill_result = await db_session.execute(skill_stmt)
        skill = skill_result.scalar_one()
        skill.is_deleted = True
        await db_session.commit()

        service = SkillService(db_session)

        # Act & Assert: Cannot deactivate deleted skill
        with pytest.raises(NotFoundError) as exc_info:
            await service.deactivate_skill(
                skill_id=skill_id,
                agent_id="owner-123",
                namespace="namespace1",
            )

        error_str = str(exc_info.value).lower()
        assert "not found" in error_str

    @pytest.mark.asyncio
    async def test_deactivate_skill_non_owner_not_found_error(
        self, db_session: AsyncSession
    ) -> None:
        """❌ Test non-owner cannot deactivate (NotFoundError for security)"""
        # Arrange: Create owner and non-owner
        await self._create_agent(db_session, "owner-123", "namespace1")
        await self._create_agent(db_session, "non-owner-456", "namespace1")
        skill_id = await self._create_skill(
            db_session, "owner-123", "namespace1", "test-skill"
        )

        service = SkillService(db_session)

        # Act & Assert: Non-owner cannot deactivate
        with pytest.raises(NotFoundError) as exc_info:
            await service.deactivate_skill(
                skill_id=skill_id,
                agent_id="non-owner-456",  # Not the owner
                namespace="namespace1",
            )

        error_str = str(exc_info.value).lower()
        assert "not found" in error_str

    @pytest.mark.asyncio
    async def test_deactivate_allows_another_skill_activation(
        self, db_session: AsyncSession
    ) -> None:
        """✅ Test deactivation frees namespace slot for another activation"""
        # Arrange: Create two skills
        await self._create_agent(db_session, "owner-123", "namespace1")
        skill1_id = await self._create_skill(
            db_session, "owner-123", "namespace1", "skill-1"
        )
        skill2_id = await self._create_skill(
            db_session, "owner-123", "namespace1", "skill-2"
        )

        service = SkillService(db_session)

        # Activate skill-1
        await service.activate_skill(
            skill_id=skill1_id,
            agent_id="owner-123",
            namespace="namespace1",
        )

        # Act 1: Deactivate skill-1
        await service.deactivate_skill(
            skill_id=skill1_id,
            agent_id="owner-123",
            namespace="namespace1",
        )

        # Act 2: Activate skill-2 (should succeed now)
        result = await service.activate_skill(
            skill_id=skill2_id,
            agent_id="owner-123",
            namespace="namespace1",
        )

        # Assert: Skill-2 activation succeeded
        assert result.id == str(skill2_id)
        assert result.name == "skill-2"
