"""Response DTOs for MCP Connection workflows

All response DTOs are immutable (@dataclass(frozen=True)) and provide:
- from_aggregate(): Convert domain aggregate to DTO
- to_dict(): Serialize to JSON-compatible dict
"""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True)
class ToolDTO:
    """Response DTO for MCP tool"""

    name: str
    description: str
    input_schema: dict
    category: str

    @classmethod
    def from_entity(cls, tool) -> "ToolDTO":
        """Convert Tool entity to DTO"""
        return cls(
            name=tool.name,
            description=tool.description,
            input_schema=tool.input_schema,
            category=tool.category.value,
        )

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dict"""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "category": self.category,
        }


@dataclass(frozen=True)
class MCPConnectionDTO:
    """Response DTO for MCP connection"""

    id: UUID
    server_name: str
    url: str
    namespace: str
    agent_id: UUID
    status: str
    tools: list[ToolDTO]
    created_at: datetime
    connected_at: datetime | None
    disconnected_at: datetime | None
    error_message: str | None

    @classmethod
    def from_aggregate(cls, connection) -> "MCPConnectionDTO":
        """Convert MCPConnection aggregate to DTO"""
        return cls(
            id=connection.id,
            server_name=str(connection.server_name),
            url=str(connection.config.url),  # URL is in config
            namespace=connection.namespace,
            agent_id=connection.agent_id,
            status=connection.status.value,
            tools=[ToolDTO.from_entity(tool) for tool in connection.tools],
            created_at=connection.created_at,
            connected_at=connection.connected_at,
            disconnected_at=connection.disconnected_at,
            error_message=connection.error_message,
        )

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dict"""
        return {
            "id": str(self.id),
            "server_name": self.server_name,
            "url": self.url,
            "namespace": self.namespace,
            "agent_id": str(self.agent_id),
            "status": self.status,
            "tools": [tool.to_dict() for tool in self.tools],
            "created_at": self.created_at.isoformat(),
            "connected_at": (
                self.connected_at.isoformat() if self.connected_at else None
            ),
            "disconnected_at": (
                self.disconnected_at.isoformat()
                if self.disconnected_at
                else None
            ),
            "error_message": self.error_message,
        }


@dataclass(frozen=True)
class ToolExecutionResultDTO:
    """Response DTO for tool execution result"""

    connection_id: UUID
    tool_name: str
    result: dict

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dict"""
        return {
            "connection_id": str(self.connection_id),
            "tool_name": self.tool_name,
            "result": self.result,
        }


@dataclass(frozen=True)
class DisconnectionResultDTO:
    """Response DTO for disconnection result"""

    connection_id: UUID
    server_name: str
    disconnected_at: datetime

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dict"""
        return {
            "connection_id": str(self.connection_id),
            "server_name": self.server_name,
            "disconnected_at": self.disconnected_at.isoformat(),
        }

from pydantic import BaseModel, Field


class SkillDTO(BaseModel):
    """Response DTO for Skill with Progressive Disclosure support.

    This DTO represents a skill at different detail levels:
    - detail_level=1: Metadata only (name, persona, namespace, tags)
    - detail_level=2: + Core Instructions (~2000 tokens)
    - detail_level=3: Full Content (~10000 tokens)
    """

    # Core identification
    id: str = Field(description="UUID as string")
    name: str
    namespace: str
    created_by: str

    # Optional metadata
    display_name: str | None = None
    description: str | None = None
    persona: str | None = None
    tags: list[str] = Field(default_factory=list)

    # Access control
    access_level: str

    # Version management
    version: int
    version_count: int

    # Progressive Disclosure content (None if not requested)
    core_instructions: str | None = None
    content: str | None = None
    content_hash: str | None = None

    # Audit timestamps
    created_at: datetime
    updated_at: datetime

    # Soft delete flag
    is_deleted: bool = False

    class Config:
        from_attributes = True

    @classmethod
    def from_models(
        cls,
        skill,
        skill_version,
        detail_level: int = 2,
    ) -> "SkillDTO":
        """Convert Skill and SkillVersion models to DTO.

        Args:
            skill: Skill model instance
            skill_version: SkillVersion model instance (active version)
            detail_level: Progressive Disclosure level (1, 2, or 3)

        Returns:
            SkillDTO with appropriate content based on detail_level
        """
        # detail_level=1: Metadata only
        if detail_level == 1:
            return cls(
                id=str(skill.id),
                name=skill.name,
                namespace=skill.namespace,
                created_by=skill.created_by,
                display_name=skill.display_name,
                description=skill.description,
                persona=skill.persona,
                tags=skill.tags if skill.tags else [],
                access_level=skill.access_level.value,
                version=skill.active_version,
                version_count=skill.version_count,
                core_instructions=None,
                content=None,
                content_hash=None,
                created_at=skill.created_at,
                updated_at=skill.updated_at,
                is_deleted=skill.is_deleted,
            )

        # detail_level=2: Metadata + Core Instructions
        elif detail_level == 2:
            return cls(
                id=str(skill.id),
                name=skill.name,
                namespace=skill.namespace,
                created_by=skill.created_by,
                display_name=skill.display_name,
                description=skill.description,
                persona=skill.persona,
                tags=skill.tags if skill.tags else [],
                access_level=skill.access_level.value,
                version=skill.active_version,
                version_count=skill.version_count,
                core_instructions=skill_version.core_instructions,
                content=None,
                content_hash=skill_version.content_hash,
                created_at=skill.created_at,
                updated_at=skill.updated_at,
                is_deleted=skill.is_deleted,
            )

        # detail_level=3: Full Content
        else:
            return cls(
                id=str(skill.id),
                name=skill.name,
                namespace=skill.namespace,
                created_by=skill.created_by,
                display_name=skill.display_name,
                description=skill.description,
                persona=skill.persona,
                tags=skill.tags if skill.tags else [],
                access_level=skill.access_level.value,
                version=skill.active_version,
                version_count=skill.version_count,
                core_instructions=skill_version.core_instructions,
                content=skill_version.content,
                content_hash=skill_version.content_hash,
                created_at=skill.created_at,
                updated_at=skill.updated_at,
                is_deleted=skill.is_deleted,
            )
