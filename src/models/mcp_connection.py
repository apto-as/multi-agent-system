"""MCP Connection database model for TMWS.

This model provides persistence for MCPConnection aggregates following
DDD repository pattern.

Architecture:
- SQLite: All metadata, configuration, and tool lists
- No vector embeddings needed for MCP connections
- Namespace isolation enforced at model level

Author: Artemis (Technical Perfectionist)
Created: 2025-11-12 (Phase 1-1-B: Infrastructure Implementation)
"""

from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy import JSON, DateTime, Index, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import TMWSBase


class MCPConnectionModel(TMWSBase):
    """Database model for MCP server connections.

    This model persists MCPConnection aggregates to SQLite database.
    It stores connection metadata, configuration, and discovered tools.

    Attributes:
        server_name: Name of the MCP server (indexed)
        namespace: Namespace for isolation (indexed)
        agent_id: Agent that owns this connection (indexed)
        status: Connection status enum value (indexed)
        config_json: Connection configuration as JSON
        tools_json: List of discovered tools as JSON
        error_message: Error message if status is ERROR (nullable)
        connected_at: When connection became ACTIVE (nullable)
        disconnected_at: When connection was closed (nullable)
        error_at: When error occurred (nullable)
        created_at: Record creation timestamp (auto)
        updated_at: Record update timestamp (auto)

    Indexes:
        - (namespace, agent_id): For namespace isolation queries
        - status: For filtering by status
        - server_name: For server-specific queries

    Example:
        >>> from sqlalchemy.ext.asyncio import AsyncSession
        >>> model = MCPConnectionModel(
        ...     server_name="test_server",
        ...     namespace="project-x",
        ...     agent_id="agent-1",
        ...     status="disconnected",
        ...     config_json={"url": "http://localhost:8080"}
        ... )
        >>> session.add(model)
        >>> await session.commit()
    """

    __tablename__ = "mcp_connections"

    # Core identification
    server_name: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True,
        comment="Name of the MCP server",
    )

    # Namespace isolation (security-critical)
    namespace: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True,
        comment="Namespace for multi-tenant isolation",
    )

    agent_id: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True,
        comment="Agent that owns this connection",
    )

    # Connection state
    status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True,
        comment="Connection status: disconnected, connecting, active, error",
    )

    # Configuration and tools (stored as JSON)
    config_json: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        comment="Connection configuration as JSON (server_name, url, timeout, etc.)",
    )

    tools_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        server_default=sa.text("'[]'"),
        comment="Discovered tools as JSON array",
    )

    # Error tracking
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Error message if status is ERROR",
    )

    error_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When error occurred",
    )

    # Timestamps
    connected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When connection became ACTIVE",
    )

    disconnected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When connection was closed",
    )

    # Composite indexes for performance
    __table_args__ = (
        Index("ix_mcp_connection_namespace_agent", "namespace", "agent_id"),
        Index("ix_mcp_connection_status", "status"),
        Index("ix_mcp_connection_server_name", "server_name"),
    )

    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return (
            f"<MCPConnectionModel("
            f"id={self.id}, "
            f"server_name='{self.server_name}', "
            f"status='{self.status}', "
            f"namespace='{self.namespace}'"
            f")>"
        )
