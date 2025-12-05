"""Tool Discovery models for TMWS - Dynamic tool orchestration with namespace isolation.

Architecture: SQLite (metadata) + Go Orchestrator (Docker management)
- SQLite: Stores tool metadata, dependencies, instances, verification history
- Go Orchestrator: Manages Docker containers and tool lifecycle

Security: V-TOOL-1 - Namespace isolation enforced at model level
Performance: Covering indexes for <20ms P95 queries
"""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import MetadataMixin, TMWSBase


class DiscoveredTool(TMWSBase, MetadataMixin):
    """
    Discovered tools in the system.

    Security: V-TOOL-1 - Namespace isolation enforced via namespace column.
    Performance: Covering indexes on (tool_id, category, namespace) for <20ms queries.
    """

    __tablename__ = "discovered_tools"

    # Tool Identity
    tool_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique identifier for the tool (e.g., 'genai-toolbox-v1')",
    )

    name: Mapped[str] = mapped_column(
        String(100), nullable=False, comment="Human-readable tool name"
    )

    category: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Tool category: 'MCP', 'CLI', 'API', 'LIBRARY'",
    )

    # Source & Version
    source_path: Mapped[str] = mapped_column(
        String(500), nullable=False, comment="File system path or container image URL"
    )

    version: Mapped[str] = mapped_column(
        String(20), nullable=False, comment="Semantic version (e.g., '1.0.0')"
    )

    # Tool-specific metadata (renamed from 'metadata' to avoid SQLAlchemy reserved word)
    tool_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        comment="Tool-specific metadata (capabilities, config, etc.)",
    )

    # V-TOOL-1: Namespace Isolation
    namespace: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Project-specific namespace (enforces tool isolation)",
    )

    # Discovery Timestamps
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="When the tool was first discovered",
    )

    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last successful verification timestamp",
    )

    # Soft Delete
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False, comment="False if tool is deactivated"
    )

    # Relationships
    dependencies: Mapped[list["ToolDependency"]] = relationship(
        "ToolDependency",
        foreign_keys="ToolDependency.tool_id",
        back_populates="tool",
        cascade="all, delete-orphan",
    )

    instances: Mapped[list["ToolInstance"]] = relationship(
        "ToolInstance", back_populates="tool", cascade="all, delete-orphan"
    )

    verification_history: Mapped[list["ToolVerificationHistory"]] = relationship(
        "ToolVerificationHistory", back_populates="tool", cascade="all, delete-orphan"
    )

    # Composite Indexes (Performance: <20ms P95)
    __table_args__ = (
        Index("idx_discovered_tools_category_active", "category", "is_active"),
        Index("idx_discovered_tools_namespace_active", "namespace", "is_active"),
        Index(
            "idx_discovered_tools_category_namespace",
            "category",
            "namespace",
            "is_active",
        ),
    )

    def __repr__(self) -> str:
        return f"<DiscoveredTool(id={self.id}, tool_id='{self.tool_id}', name='{self.name}', version='{self.version}')>"


class ToolDependency(TMWSBase):
    """Tool dependency graph for safe container orchestration."""

    __tablename__ = "tool_dependencies"

    # Foreign Keys
    tool_id: Mapped[UUID] = mapped_column(
        ForeignKey("discovered_tools.id", ondelete="CASCADE"),
        nullable=False,
        comment="Tool that has the dependency",
    )

    depends_on_tool_id: Mapped[UUID] = mapped_column(
        ForeignKey("discovered_tools.id", ondelete="CASCADE"),
        nullable=False,
        comment="Tool that is depended upon",
    )

    # Dependency Type
    dependency_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Dependency type: 'required', 'optional', 'recommended'",
    )

    # Relationships
    tool: Mapped["DiscoveredTool"] = relationship(
        "DiscoveredTool", foreign_keys=[tool_id], back_populates="dependencies"
    )

    # Indexes
    __table_args__ = (Index("idx_tool_dependencies_tool_id", "tool_id"),)

    def __repr__(self) -> str:
        return f"<ToolDependency(tool_id={self.tool_id}, depends_on={self.depends_on_tool_id}, type='{self.dependency_type}')>"


class ToolInstance(TMWSBase, MetadataMixin):
    """Running instances of tools (Docker containers)."""

    __tablename__ = "tool_instances"

    # Foreign Key
    tool_id: Mapped[UUID] = mapped_column(
        ForeignKey("discovered_tools.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Reference to discovered tool",
    )

    # Instance Identity
    instance_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique instance identifier (e.g., Docker container ID)",
    )

    # Status
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
        comment="Instance status: 'starting', 'running', 'stopping', 'stopped', 'error'",
    )

    # Container Info
    container_id: Mapped[str | None] = mapped_column(
        String(100), nullable=True, comment="Docker container ID"
    )

    container_name: Mapped[str | None] = mapped_column(
        String(100), nullable=True, comment="Docker container name"
    )

    # Network
    host: Mapped[str | None] = mapped_column(
        String(100), nullable=True, comment="Host address (e.g., 'localhost')"
    )

    port: Mapped[int | None] = mapped_column(Integer, nullable=True, comment="Exposed port number")

    # Resource Usage
    cpu_limit: Mapped[str | None] = mapped_column(
        String(20), nullable=True, comment="CPU limit (e.g., '0.5')"
    )

    memory_limit: Mapped[str | None] = mapped_column(
        String(20), nullable=True, comment="Memory limit (e.g., '512m')"
    )

    # Lifecycle
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Instance start time"
    )

    stopped_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Instance stop time"
    )

    # Relationships
    tool: Mapped["DiscoveredTool"] = relationship("DiscoveredTool", back_populates="instances")

    # Indexes
    __table_args__ = (
        Index("idx_tool_instances_status", "status"),
        Index("idx_tool_instances_tool_status", "tool_id", "status"),
    )

    def __repr__(self) -> str:
        return f"<ToolInstance(id={self.id}, instance_id='{self.instance_id}', status='{self.status}')>"


class ToolVerificationHistory(TMWSBase):
    """History of tool verification attempts."""

    __tablename__ = "tool_verification_history"

    # Foreign Key
    tool_id: Mapped[UUID] = mapped_column(
        ForeignKey("discovered_tools.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Reference to verified tool",
    )

    # Verification Result
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
        comment="Verification timestamp",
    )

    success: Mapped[bool] = mapped_column(
        Boolean, nullable=False, comment="True if verification passed"
    )

    # Details
    verification_method: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Verification method: 'docker_inspect', 'health_check', 'manual'",
    )

    error_message: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Error message if verification failed"
    )

    # Verification-specific metadata (renamed from 'metadata' to avoid SQLAlchemy reserved word)
    verification_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        comment="Verification-specific metadata (health check response, etc.)",
    )

    # Relationships
    tool: Mapped["DiscoveredTool"] = relationship(
        "DiscoveredTool", back_populates="verification_history"
    )

    # Indexes
    __table_args__ = (
        Index("idx_tool_verification_tool_time", "tool_id", "verified_at"),
        Index("idx_tool_verification_success", "success"),
    )

    def __repr__(self) -> str:
        return f"<ToolVerificationHistory(id={self.id}, tool_id={self.tool_id}, success={self.success})>"
