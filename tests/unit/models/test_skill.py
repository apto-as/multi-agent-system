"""Unit tests for Skill models and SkillValidationService.

Tests cover:
- Skill model CRUD operations
- SkillVersion management
- Progressive Disclosure layer extraction
- Access control logic (is_accessible_by)
- SkillValidationService validation methods
- Security constraints (S-3-M1, S-3-M2, S-3-M3)
"""

from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import ValidationError
from src.models.agent import AccessLevel
from src.models.skill import Skill, SkillActivation, SkillMCPTool, SkillSharedAgent, SkillVersion
from src.services.skill_validation_service import SkillValidationService

# ===== Fixtures =====


@pytest.fixture
def validation_service():
    """Create SkillValidationService instance."""
    return SkillValidationService()


@pytest.fixture
async def sample_skill(test_session: AsyncSession):
    """Create a sample skill for testing."""
    skill = Skill(
        id=str(uuid4()),
        name="test-skill",
        display_name="Test Skill",
        description="A test skill for unit testing",
        namespace="test-namespace",
        created_by="test-agent-id",
        persona="artemis-optimizer",
        access_level=AccessLevel.PRIVATE,
        tags_json='["test", "unit-test"]',
        version_count=1,
        active_version=1,
        is_deleted=False,
    )
    test_session.add(skill)
    await test_session.commit()
    await test_session.refresh(skill)
    return skill


@pytest.fixture
async def sample_skill_version(test_session: AsyncSession, sample_skill: Skill):
    """Create a sample skill version."""
    content = """---
name: test-skill
version: 1.0.0
---

## Core Instructions

This is a test skill for validating the Progressive Disclosure architecture.

### Usage

1. Initialize the skill
2. Execute the task
3. Collect results

## Examples

Example 1: Basic usage
Example 2: Advanced usage
"""
    version = SkillVersion(
        id=str(uuid4()),
        skill_id=sample_skill.id,
        version=1,
        content=content,
        metadata_json='{"name": "test-skill", "version": "1.0.0"}',
        core_instructions="This is a test skill for validating the Progressive Disclosure architecture.",
        auxiliary_content=content,
        content_hash=SkillVersion.compute_content_hash(content),
        created_by="test-agent-id",
    )
    test_session.add(version)
    await test_session.commit()
    await test_session.refresh(version)
    return version


# ===== Skill Model Tests =====


@pytest.mark.asyncio
async def test_skill_creation(test_session: AsyncSession):
    """Test creating a skill."""
    skill = Skill(
        id=str(uuid4()),
        name="new-skill",
        namespace="test",
        created_by="agent-1",
        access_level=AccessLevel.PRIVATE,
    )

    test_session.add(skill)
    await test_session.commit()

    # Verify creation
    result = await test_session.execute(select(Skill).where(Skill.name == "new-skill"))
    created_skill = result.scalar_one()

    assert created_skill.name == "new-skill"
    assert created_skill.namespace == "test"
    assert created_skill.access_level == AccessLevel.PRIVATE
    assert created_skill.version_count == 1
    assert created_skill.active_version == 1
    assert created_skill.is_deleted is False


@pytest.mark.asyncio
async def test_skill_tags_property(test_session: AsyncSession, sample_skill: Skill):
    """Test tags property serialization/deserialization."""
    # Read tags
    assert sample_skill.tags == ["test", "unit-test"]

    # Update tags
    sample_skill.tags = ["updated", "new-tag"]
    await test_session.commit()
    await test_session.refresh(sample_skill)

    # Verify update
    assert sample_skill.tags == ["updated", "new-tag"]
    assert sample_skill.tags_json == '["updated", "new-tag"]'


@pytest.mark.asyncio
async def test_skill_is_accessible_by_owner(test_session: AsyncSession, sample_skill: Skill):
    """Test owner always has access."""
    assert sample_skill.is_accessible_by("test-agent-id", "test-namespace") is True


@pytest.mark.asyncio
async def test_skill_is_accessible_by_private(test_session: AsyncSession, sample_skill: Skill):
    """Test PRIVATE access level blocks non-owners."""
    sample_skill.access_level = AccessLevel.PRIVATE
    await test_session.commit()

    assert sample_skill.is_accessible_by("other-agent", "test-namespace") is False


@pytest.mark.asyncio
async def test_skill_is_accessible_by_public(test_session: AsyncSession, sample_skill: Skill):
    """Test PUBLIC access level allows everyone."""
    sample_skill.access_level = AccessLevel.PUBLIC
    await test_session.commit()

    assert sample_skill.is_accessible_by("any-agent", "any-namespace") is True


@pytest.mark.asyncio
async def test_skill_is_accessible_by_team(test_session: AsyncSession, sample_skill: Skill):
    """Test TEAM access level allows same namespace."""
    sample_skill.access_level = AccessLevel.TEAM
    await test_session.commit()

    # Same namespace
    assert sample_skill.is_accessible_by("team-agent", "test-namespace") is True

    # Different namespace
    assert sample_skill.is_accessible_by("other-agent", "other-namespace") is False


@pytest.mark.asyncio
async def test_skill_is_accessible_by_shared(test_session: AsyncSession):
    """Test SHARED access level requires explicit sharing."""
    from sqlalchemy.orm import selectinload

    # Create a skill with SHARED access level
    skill = Skill(
        id=str(uuid4()),
        name="shared-skill",
        namespace="test-namespace",
        created_by="owner-agent",
        access_level=AccessLevel.SHARED,
    )
    test_session.add(skill)
    await test_session.commit()

    # Re-fetch with eager loading
    result = await test_session.execute(
        select(Skill).where(Skill.id == skill.id).options(selectinload(Skill.shared_agents))
    )
    skill = result.scalar_one()

    # Not explicitly shared
    assert skill.is_accessible_by("shared-agent", "test-namespace") is False

    # Add explicit sharing
    shared_agent = SkillSharedAgent(
        id=str(uuid4()), skill_id=skill.id, agent_id="shared-agent"
    )
    test_session.add(shared_agent)
    await test_session.flush()  # Ensure shared_agent is written

    # Re-fetch with eager loading
    await test_session.refresh(skill, ["shared_agents"])

    # Now accessible
    assert skill.is_accessible_by("shared-agent", "test-namespace") is True

    # Different namespace still blocked
    assert skill.is_accessible_by("shared-agent", "other-namespace") is False


@pytest.mark.asyncio
async def test_skill_soft_delete(test_session: AsyncSession, sample_skill: Skill):
    """Test soft delete blocks access."""
    sample_skill.is_deleted = True
    await test_session.commit()

    # Even owner cannot access deleted skills
    assert sample_skill.is_accessible_by("test-agent-id", "test-namespace") is False


@pytest.mark.asyncio
async def test_skill_get_active_version(
    test_session: AsyncSession, sample_skill: Skill, sample_skill_version: SkillVersion
):
    """Test retrieving active version."""
    from sqlalchemy.orm import selectinload

    # Re-fetch skill with eager-loaded versions
    result = await test_session.execute(
        select(Skill).where(Skill.id == sample_skill.id).options(selectinload(Skill.versions))
    )
    sample_skill = result.scalar_one()

    active_version = sample_skill.get_active_version()

    assert active_version is not None
    assert active_version.version == 1
    assert active_version.skill_id == sample_skill.id


# ===== SkillVersion Model Tests =====


@pytest.mark.asyncio
async def test_skill_version_content_hash(test_session: AsyncSession):
    """Test content hash computation."""
    content = "Test skill content"
    hash_value = SkillVersion.compute_content_hash(content)

    assert len(hash_value) == 64  # SHA256 = 64 hex chars
    assert hash_value == SkillVersion.compute_content_hash(content)  # Deterministic


@pytest.mark.asyncio
async def test_skill_version_verify_content_integrity(
    test_session: AsyncSession, sample_skill_version: SkillVersion
):
    """Test content integrity verification."""
    # Original content should verify
    assert sample_skill_version.verify_content_integrity() is True

    # Tampered content should fail
    sample_skill_version.content = "Tampered content"
    assert sample_skill_version.verify_content_integrity() is False


@pytest.mark.asyncio
async def test_skill_version_metadata_property(test_session: AsyncSession, sample_skill_version: SkillVersion):
    """Test metadata serialization/deserialization."""
    metadata = sample_skill_version.get_metadata()

    assert metadata["name"] == "test-skill"
    assert metadata["version"] == "1.0.0"

    # Update metadata
    new_metadata = {"name": "updated-skill", "version": "2.0.0"}
    sample_skill_version.set_metadata(new_metadata)
    await test_session.commit()
    await test_session.refresh(sample_skill_version)

    assert sample_skill_version.get_metadata() == new_metadata


# ===== SkillValidationService Tests =====


def test_validate_skill_name_valid(validation_service: SkillValidationService):
    """Test valid skill name."""
    assert validation_service.validate_skill_name("valid-skill-name") == "valid-skill-name"
    assert validation_service.validate_skill_name("skill_123") == "skill_123"
    assert validation_service.validate_skill_name("ab") == "ab"  # Minimum 2 chars (1 letter + 1 char)


def test_validate_skill_name_invalid(validation_service: SkillValidationService):
    """Test invalid skill names."""
    # Empty
    with pytest.raises(ValidationError, match="Skill name is required"):
        validation_service.validate_skill_name("")

    # Starts with number
    with pytest.raises(ValidationError, match="Invalid skill name format"):
        validation_service.validate_skill_name("123-skill")

    # Uppercase letters
    with pytest.raises(ValidationError, match="Invalid skill name format"):
        validation_service.validate_skill_name("Uppercase-Skill")

    # Special characters
    with pytest.raises(ValidationError, match="Invalid skill name format"):
        validation_service.validate_skill_name("skill@name")


def test_validate_skill_name_null_bytes(validation_service: SkillValidationService):
    """Test S-3-M2: Null byte sanitization."""
    result = validation_service.validate_skill_name("skill\x00name")
    assert result == "skillname"  # Null bytes removed


def test_validate_namespace_valid(validation_service: SkillValidationService):
    """Test valid namespace."""
    assert validation_service.validate_namespace("valid-namespace") == "valid-namespace"
    assert validation_service.validate_namespace("123namespace") == "123namespace"  # Can start with number


def test_validate_namespace_invalid(validation_service: SkillValidationService):
    """Test invalid namespaces."""
    # Empty
    with pytest.raises(ValidationError, match="Namespace is required"):
        validation_service.validate_namespace("")

    # Path traversal (dots)
    with pytest.raises(ValidationError, match="path traversal"):
        validation_service.validate_namespace("namespace.with.dots")

    # Path traversal (slashes)
    with pytest.raises(ValidationError, match="path traversal"):
        validation_service.validate_namespace("namespace/with/slash")


def test_validate_tags_valid(validation_service: SkillValidationService):
    """Test valid tags."""
    tags = validation_service.validate_tags(["tag1", "tag-2", "tag_3"])
    assert tags == ["tag1", "tag-2", "tag_3"]


def test_validate_tags_invalid(validation_service: SkillValidationService):
    """Test invalid tags."""
    # Too many tags
    with pytest.raises(ValidationError, match="Too many tags"):
        validation_service.validate_tags([f"tag{i}" for i in range(21)])

    # Invalid format (uppercase)
    with pytest.raises(ValidationError, match="Invalid tag format"):
        validation_service.validate_tags(["ValidTag"])


def test_validate_access_level_valid(validation_service: SkillValidationService):
    """Test valid access level."""
    assert validation_service.validate_access_level("private") == AccessLevel.PRIVATE
    assert validation_service.validate_access_level(AccessLevel.PUBLIC) == AccessLevel.PUBLIC


def test_validate_access_level_invalid(validation_service: SkillValidationService):
    """Test invalid access level."""
    with pytest.raises(ValidationError, match="Invalid access level"):
        validation_service.validate_access_level("INVALID_LEVEL")


def test_validate_content_valid(validation_service: SkillValidationService):
    """Test valid content."""
    content = "Valid skill content"
    assert validation_service.validate_content(content) == content


def test_validate_content_invalid(validation_service: SkillValidationService):
    """Test invalid content."""
    # Empty content
    with pytest.raises(ValidationError, match="Skill content is required"):
        validation_service.validate_content("")

    # Whitespace only
    with pytest.raises(ValidationError, match="Skill content is required"):
        validation_service.validate_content("   ")

    # Too long
    with pytest.raises(ValidationError, match="Content exceeds maximum length"):
        validation_service.validate_content("x" * 50001)


def test_parse_progressive_disclosure_layers(validation_service: SkillValidationService):
    """Test Progressive Disclosure layer extraction (JSON frontmatter only)."""
    content = """```json
{
  "name": "test-skill",
  "version": "1.0.0"
}
```

## Core Instructions

This is the core instructions section.
It contains the essential information.

## Examples

Example 1: Basic usage
Example 2: Advanced usage
"""

    layers = validation_service.parse_progressive_disclosure_layers(content)

    # Verify all layers
    assert "metadata" in layers
    assert "core_instructions" in layers
    assert "auxiliary_content" in layers
    assert "content_hash" in layers

    # Verify metadata (JSON frontmatter)
    assert layers["metadata"]["name"] == "test-skill"
    assert layers["metadata"]["version"] == "1.0.0"

    # Verify core instructions
    assert "core instructions section" in layers["core_instructions"].lower()

    # Verify content hash
    assert len(layers["content_hash"]) == 64  # SHA256


def test_extract_metadata_yaml_frontmatter(validation_service: SkillValidationService):
    """Test YAML frontmatter is no longer supported (V-SKILL-2 mitigation).

    SECURITY: YAML support was removed due to YAML bomb vulnerability (CVSS 7.5).
    This test verifies that YAML frontmatter is ignored and returns empty dict.
    """
    content = """---
name: test
author: artemis
---

Content here
"""
    metadata = validation_service._extract_metadata(content)
    # YAML is no longer supported (V-SKILL-2 security fix)
    assert metadata == {}, "YAML frontmatter should be ignored (security mitigation)"


def test_extract_metadata_json_frontmatter(validation_service: SkillValidationService):
    """Test JSON frontmatter extraction."""
    content = """```json
{"name": "test", "author": "artemis"}
```

Content here
"""
    metadata = validation_service._extract_metadata(content)
    assert metadata["name"] == "test"
    assert metadata["author"] == "artemis"


def test_extract_metadata_no_frontmatter(validation_service: SkillValidationService):
    """Test no frontmatter returns empty dict."""
    content = "Just regular content without frontmatter"
    metadata = validation_service._extract_metadata(content)
    assert metadata == {}


def test_extract_core_instructions_with_section(validation_service: SkillValidationService):
    """Test core instructions extraction with ## Core Instructions section."""
    content = """# Skill

## Core Instructions

These are the core instructions.
They span multiple lines.

## Other Section

This should not be included.
"""
    core = validation_service._extract_core_instructions(content)
    assert "core instructions" in core.lower()
    assert "other section" not in core.lower()


def test_extract_core_instructions_without_section(validation_service: SkillValidationService):
    """Test core instructions fallback when section not found."""
    content = "Content without Core Instructions section"
    core = validation_service._extract_core_instructions(content)
    assert core == content[:8000]  # Truncated to max length


def test_estimate_token_count(validation_service: SkillValidationService):
    """Test token count estimation."""
    text = "This is a test sentence with some words."
    tokens = validation_service.estimate_token_count(text)
    assert tokens > 0
    assert tokens == len(text) // 4  # Rough approximation


def test_validate_token_budget_within_budget(validation_service: SkillValidationService):
    """Test token budget validation within budget."""
    # Layer 2: 2000 token budget
    text = "x" * 7000  # ~1750 tokens
    validation_service.validate_token_budget(text, 2)  # Should not raise


def test_validate_token_budget_exceeds_budget(validation_service: SkillValidationService):
    """Test token budget validation exceeds budget."""
    # Layer 1: 100 token budget
    text = "x" * 500  # ~125 tokens
    with pytest.raises(ValidationError, match="exceeds token budget"):
        validation_service.validate_token_budget(text, 1)


def test_validate_token_budget_invalid_layer(validation_service: SkillValidationService):
    """Test token budget validation with invalid layer."""
    with pytest.raises(ValidationError, match="Invalid layer number"):
        validation_service.validate_token_budget("text", 99)


# ===== SkillActivation Model Tests =====


@pytest.mark.asyncio
async def test_skill_activation_creation(test_session: AsyncSession, sample_skill: Skill):
    """Test creating a skill activation record."""
    activation = SkillActivation(
        id=str(uuid4()),
        skill_id=sample_skill.id,
        agent_id="test-agent",
        version=1,
        namespace="test",
        activation_type="mcp_tool",
        layer_loaded=2,
        tokens_loaded=2000,
        duration_ms=150,
        success=True,
    )

    test_session.add(activation)
    await test_session.commit()

    # Verify creation
    result = await test_session.execute(select(SkillActivation).where(SkillActivation.skill_id == sample_skill.id))
    created_activation = result.scalar_one()

    assert created_activation.skill_id == sample_skill.id
    assert created_activation.layer_loaded == 2
    assert created_activation.success is True


# ===== SkillMCPTool Model Tests =====


@pytest.mark.asyncio
async def test_skill_mcp_tool_creation(test_session: AsyncSession, sample_skill: Skill):
    """Test creating a skill MCP tool reference."""
    mcp_tool = SkillMCPTool(
        id=str(uuid4()),
        skill_id=sample_skill.id,
        mcp_server_name="serena",
        tool_name="find_symbol",
        detail_level="summary",
        load_when_condition='{"context": "code_analysis"}',
    )

    test_session.add(mcp_tool)
    await test_session.commit()

    # Verify creation
    result = await test_session.execute(select(SkillMCPTool).where(SkillMCPTool.skill_id == sample_skill.id))
    created_tool = result.scalar_one()

    assert created_tool.tool_name == "find_symbol"
    assert created_tool.load_condition == {"context": "code_analysis"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
