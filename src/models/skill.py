"""Skill models for TMWS v2.4.0 - Progressive Disclosure Skills System.

Architecture:
- Progressive Disclosure: 4 layers (Layer 1-3 in MVP, Layer 4 future)
  - Layer 1: Metadata (~100 tokens)
  - Layer 2: Core Instructions (~2,000 tokens)
  - Layer 3: Full Context (~10,000 tokens)
  - Layer 4: Just-in-Time Memory (future)
- Storage: SKILL.md content in database (not filesystem)
- Versioning: Integer-based sequential versions
- Access Control: PRIVATE/TEAM/SHARED/PUBLIC/SYSTEM (same as Memory)
- Namespace Isolation: Critical security requirement (S-2)
- Content Integrity: SHA256 hashing for tamper detection (S-1)

Security:
- Namespace isolation enforced at model level
- Content hash verification prevents unauthorized modification
- Soft delete preserves audit trail
- Foreign key constraints prevent orphaned records

Performance:
- Composite indexes for common query patterns
- JSON storage for SQLite compatibility
- Efficient version lookup (O(log n) with B-tree index)
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .agent import AccessLevel
from .base import TMWSBase


class Skill(TMWSBase):
    """Skill master table with metadata and access control.

    A Skill represents a reusable AI capability with Progressive Disclosure support.
    Skills are versioned, namespace-isolated, and access-controlled.
    """

    __tablename__ = "skills"

    # Core identification
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment='Skill name (e.g., "security-audit")',
    )

    display_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment='Human-readable name (e.g., "Security Audit")',
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Brief description of skill purpose",
    )

    # Namespace and ownership
    namespace: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Namespace for multi-tenant isolation",
    )

    created_by: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        comment="Agent ID who created this skill",
    )

    # Optional persona association
    persona: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        index=True,
        comment='Associated persona (e.g., "hestia-auditor")',
    )

    # Access control
    access_level: Mapped[AccessLevel] = mapped_column(
        sa.Enum(AccessLevel, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        default=AccessLevel.PRIVATE,
        comment="Access control level",
    )

    # Tags (JSON array for SQLite compatibility)
    tags_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="[]",
        server_default="[]",
        comment="JSON array of tags (SQLite-compatible)",
    )

    # Version management
    version_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
        comment="Total number of versions",
    )

    active_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
        comment="Currently active version number",
    )

    # Soft delete (preserves audit trail)
    is_deleted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="0",
        comment="Soft delete flag (preserves analytics)",
    )

    # Relationships
    versions: Mapped[list[SkillVersion]] = relationship(
        "SkillVersion",
        back_populates="skill",
        cascade="all, delete-orphan",
        order_by="SkillVersion.version.desc()",
    )

    activations: Mapped[list[SkillActivation]] = relationship(
        "SkillActivation",
        back_populates="skill",
        cascade="all, delete-orphan",
    )

    mcp_tools: Mapped[list[SkillMCPTool]] = relationship(
        "SkillMCPTool",
        back_populates="skill",
        cascade="all, delete-orphan",
    )

    shared_agents: Mapped[list[SkillSharedAgent]] = relationship(
        "SkillSharedAgent",
        back_populates="skill",
        cascade="all, delete-orphan",
    )

    memory_filters: Mapped[list[SkillMemoryFilter]] = relationship(
        "SkillMemoryFilter",
        back_populates="skill",
        cascade="all, delete-orphan",
    )

    # Indexes
    __table_args__ = (
        Index("ix_skills_namespace_name", "namespace", "name", unique=True),
        Index("ix_skills_is_deleted", "is_deleted"),
    )

    @property
    def tags(self) -> list[str]:
        """Deserialize tags from JSON."""
        try:
            return json.loads(self.tags_json)
        except (json.JSONDecodeError, TypeError):
            return []

    @tags.setter
    def tags(self, value: list[str]) -> None:
        """Serialize tags to JSON."""
        self.tags_json = json.dumps(value)

    def is_accessible_by(self, requesting_agent_id: str, requesting_agent_namespace: str) -> bool:
        """Check if skill is accessible by the given agent.

        SECURITY-CRITICAL: This method implements namespace isolation for multi-tenant security.
        The requesting agent's namespace MUST be verified by the caller against the database
        before calling this method.

        Args:
            requesting_agent_id: ID of the agent requesting access
            requesting_agent_namespace: Verified namespace of the requesting agent (MUST be verified against DB)

        Returns:
            bool: True if access is allowed, False otherwise

        Security Notes:
            - The namespace parameter MUST come from a verified Agent record in the database
            - Never accept namespace from user input or JWT claims directly
            - Always verify: SELECT namespace FROM agents WHERE agent_id = ?
        """
        # Soft-deleted skills are not accessible
        if self.is_deleted:
            return False

        # Owner always has access
        if requesting_agent_id == self.created_by:
            return True

        # Check access level
        if self.access_level == AccessLevel.PUBLIC:
            return True
        elif self.access_level == AccessLevel.SYSTEM:
            return True  # System skills are accessible to all
        elif self.access_level == AccessLevel.SHARED:
            # Must be explicitly shared with this agent
            shared_agent_ids = [sa.agent_id for sa in self.shared_agents]
            if requesting_agent_id not in shared_agent_ids:
                return False
            # Additional check: verify namespace matches
            return requesting_agent_namespace == self.namespace
        elif self.access_level == AccessLevel.TEAM:
            # SECURITY FIX: Verify namespace matches AND it's the skill's namespace
            return requesting_agent_namespace == self.namespace
        else:  # PRIVATE
            return False

    def get_active_version(self) -> SkillVersion | None:
        """Get the currently active version of this skill."""
        for version in self.versions:
            if version.version == self.active_version:
                return version
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert skill to dictionary for API serialization."""
        result = super().to_dict()
        result["tags"] = self.tags  # Deserialize JSON tags
        return result

    def __repr__(self) -> str:
        return f"<Skill(name='{self.name}', namespace='{self.namespace}', version={self.active_version})>"


class SkillVersion(TMWSBase):
    """Skill version storage with Progressive Disclosure content layers.

    Each version stores the full SKILL.md content plus pre-extracted layers
    for Progressive Disclosure optimization.
    """

    __tablename__ = "skill_versions"

    # Foreign key to parent skill
    skill_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("skills.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Foreign key to skills.id",
    )

    # Sequential version number
    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Sequential version number (1, 2, 3, ...)",
    )

    # Full content
    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Full SKILL.md content",
    )

    # Progressive Disclosure layers
    metadata_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Layer 1: Extracted metadata (~100 tokens, JSON)",
    )

    core_instructions: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Layer 2: Core instructions section (~2,000 tokens)",
    )

    auxiliary_content: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Layer 3: Auxiliary content section (~10,000 tokens)",
    )

    # Content integrity
    content_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="SHA256 hash of content for integrity verification",
    )

    # Authorship
    created_by: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("agents.id"),
        nullable=False,
        comment="Agent ID who created this version",
    )

    # Relationship
    skill: Mapped[Skill] = relationship("Skill", back_populates="versions")

    # Indexes
    __table_args__ = (Index("ix_skill_versions_skill_version", "skill_id", "version", unique=True),)

    @staticmethod
    def compute_content_hash(content: str) -> str:
        """Compute SHA256 hash of content for integrity verification."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def verify_content_integrity(self) -> bool:
        """Verify that content has not been tampered with."""
        if not self.content_hash:
            return False  # No hash stored, cannot verify
        computed_hash = self.compute_content_hash(self.content)
        return computed_hash == self.content_hash

    def get_metadata(self) -> dict[str, Any]:
        """Deserialize metadata from JSON."""
        if not self.metadata_json:
            return {}
        try:
            return json.loads(self.metadata_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_metadata(self, value: dict[str, Any]) -> None:
        """Serialize metadata to JSON."""
        self.metadata_json = json.dumps(value)

    def __repr__(self) -> str:
        return f"<SkillVersion(skill_id='{self.skill_id}', version={self.version})>"


class SkillActivation(TMWSBase):
    """Skill activation history for analytics and usage tracking.

    Tracks every time a skill is activated, including which layer was loaded
    (Progressive Disclosure), execution duration, and success status.
    """

    __tablename__ = "skill_activations"

    # Foreign keys
    skill_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("skills.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Foreign key to skills.id",
    )

    agent_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Agent who activated the skill",
    )

    # Activation context
    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Skill version that was activated",
    )

    namespace: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Namespace context of activation",
    )

    activation_type: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
        comment='Type of activation (e.g., "mcp_tool", "api_call")',
    )

    # Progressive Disclosure metrics
    layer_loaded: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Progressive Disclosure layer loaded (1, 2, or 3)",
    )

    tokens_loaded: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Estimated tokens loaded",
    )

    # Performance metrics
    activated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.current_timestamp(),
        index=True,
        comment="Activation timestamp",
    )

    duration_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Execution duration in milliseconds",
    )

    # Execution result
    success: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
        comment="Whether activation was successful",
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Error message if activation failed",
    )

    # Relationships
    skill: Mapped[Skill] = relationship("Skill", back_populates="activations")

    # Indexes
    __table_args__ = (Index("ix_skill_activations_agent_time", "agent_id", "activated_at"),)

    def __repr__(self) -> str:
        return f"<SkillActivation(skill_id='{self.skill_id}', agent_id='{self.agent_id}', layer={self.layer_loaded})>"


class SkillMCPTool(TMWSBase):
    """MCP tool references for Progressive Disclosure.

    Skills can reference MCP tools with detail_level control:
    - "summary": Load only tool name and description
    - "full": Load complete tool schema and parameters
    """

    __tablename__ = "skill_mcp_tools"

    # Foreign key
    skill_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("skills.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Foreign key to skills.id",
    )

    # MCP tool identification
    mcp_server_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment='MCP server name (e.g., "serena", "tmws")',
    )

    tool_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment='MCP tool name (e.g., "search_for_pattern")',
    )

    # Progressive Disclosure control
    detail_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="summary",
        server_default="summary",
        comment='Detail level to load ("summary" or "full")',
    )

    load_when_condition: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Condition expression for loading full schema (JSON)",
    )

    # Relationship
    skill: Mapped[Skill] = relationship("Skill", back_populates="mcp_tools")

    @property
    def load_condition(self) -> dict[str, Any]:
        """Deserialize load condition from JSON."""
        if not self.load_when_condition:
            return {}
        try:
            return json.loads(self.load_when_condition)
        except (json.JSONDecodeError, TypeError):
            return {}

    @load_condition.setter
    def load_condition(self, value: dict[str, Any]) -> None:
        """Serialize load condition to JSON."""
        self.load_when_condition = json.dumps(value)

    def __repr__(self) -> str:
        return f"<SkillMCPTool(skill_id='{self.skill_id}', tool='{self.mcp_server_name}:{self.tool_name}')>"


class SkillSharedAgent(TMWSBase):
    """Explicit agent sharing for SHARED access level.

    When a skill has access_level=SHARED, this table defines which agents
    have explicit access (whitelist approach).
    """

    __tablename__ = "skill_shared_agents"

    # Foreign keys
    skill_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("skills.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Foreign key to skills.id",
    )

    agent_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Agent granted explicit access",
    )

    # Metadata
    shared_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.current_timestamp(),
        comment="When access was granted",
    )

    # Relationship
    skill: Mapped[Skill] = relationship("Skill", back_populates="shared_agents")

    # Indexes
    __table_args__ = (
        Index("ix_skill_shared_agents_skill_agent", "skill_id", "agent_id", unique=True),
    )

    def __repr__(self) -> str:
        return f"<SkillSharedAgent(skill_id='{self.skill_id}', agent_id='{self.agent_id}')>"


class SkillMemoryFilter(TMWSBase):
    """Just-in-Time Memory filters for Layer 4 (future implementation).

    Skills can define memory filters to automatically load relevant memories
    when activated (Layer 4 of Progressive Disclosure).
    """

    __tablename__ = "skill_memory_filters"

    # Foreign key
    skill_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("skills.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Foreign key to skills.id",
    )

    # Filter specification
    filter_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment='Type of filter ("tag", "namespace", "importance", etc.)',
    )

    filter_value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Filter value (JSON for complex filters)",
    )

    # Priority (higher = applied first)
    priority: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        index=True,
        comment="Filter priority (higher = applied first)",
    )

    # Relationship
    skill: Mapped[Skill] = relationship("Skill", back_populates="memory_filters")

    @property
    def filter_config(self) -> dict[str, Any]:
        """Deserialize filter value from JSON."""
        try:
            return json.loads(self.filter_value)
        except (json.JSONDecodeError, TypeError):
            return {"raw": self.filter_value}

    @filter_config.setter
    def filter_config(self, value: dict[str, Any]) -> None:
        """Serialize filter config to JSON."""
        self.filter_value = json.dumps(value)

    def __repr__(self) -> str:
        return f"<SkillMemoryFilter(skill_id='{self.skill_id}', type='{self.filter_type}')>"
