"""Request DTOs for MCP Connection workflows

All request DTOs use Pydantic for validation and provide clear error messages.
"""

from uuid import UUID

from pydantic import BaseModel, Field, HttpUrl, field_validator


class CreateConnectionRequest(BaseModel):
    """Request DTO for creating MCP connection"""

    server_name: str = Field(
        ..., min_length=1, max_length=100, description="MCP server name"
    )
    url: HttpUrl = Field(
        ..., description="MCP server URL (must be valid HTTP/HTTPS URL)"
    )
    namespace: str = Field(
        ..., min_length=1, max_length=255, description="Namespace for isolation"
    )
    agent_id: UUID = Field(..., description="Agent identifier")
    timeout: int = Field(
        default=30,
        ge=1,
        le=300,
        description="Connection timeout in seconds",
    )
    retry_attempts: int = Field(
        default=3, ge=0, le=10, description="Number of retry attempts"
    )
    auth_required: bool = Field(
        default=False, description="Whether authentication is required"
    )
    api_key: str | None = Field(
        default=None, description="API key for authentication"
    )

    @field_validator("server_name")
    def validate_server_name(cls, v):
        """Validate server name format"""
        if not v.replace("-", "").replace("_", "").isalnum():
            raise ValueError(
                "Server name must contain only alphanumeric, hyphen, or underscore"
            )
        return v

    @field_validator("api_key")
    def validate_api_key(cls, v, info):
        """Validate API key when auth_required is True"""
        if info.data.get("auth_required") and not v:
            raise ValueError("API key required when auth_required is True")
        return v


class DiscoverToolsRequest(BaseModel):
    """Request DTO for discovering tools"""

    connection_id: UUID = Field(..., description="MCP connection identifier")
    namespace: str = Field(
        ..., min_length=1, max_length=255, description="Namespace for authorization"
    )
    agent_id: UUID = Field(..., description="Agent identifier")


class ExecuteToolRequest(BaseModel):
    """Request DTO for executing tool"""

    connection_id: UUID = Field(..., description="MCP connection identifier")
    tool_name: str = Field(
        ..., min_length=1, max_length=100, description="Tool name to execute"
    )
    arguments: dict = Field(
        default_factory=dict, description="Tool-specific arguments"
    )
    namespace: str = Field(
        ..., min_length=1, max_length=255, description="Namespace for authorization"
    )
    agent_id: UUID = Field(..., description="Agent identifier")


class DisconnectRequest(BaseModel):
    """Request DTO for disconnecting"""

    connection_id: UUID = Field(..., description="MCP connection identifier")
    namespace: str = Field(
        ..., min_length=1, max_length=255, description="Namespace for authorization"
    )
    agent_id: UUID = Field(..., description="Agent identifier")
