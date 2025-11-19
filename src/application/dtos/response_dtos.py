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
