"""Add Tool Discovery schema for Phase 4 Day 1

Revision ID: add_tool_discovery_001
Revises: 571948cc671b
Create Date: 2025-11-22 10:00:00.000000

Architecture:
- SQLite (metadata) + Go Orchestrator (Docker management)
- Namespace isolation (V-TOOL-1) enforced at model level
- Covering indexes for <20ms P95 query performance

Tables:
1. discovered_tools - Tool metadata and discovery information
2. tool_dependencies - Dependency graph for safe orchestration
3. tool_instances - Running container instances
4. tool_verification_history - Verification audit trail

Performance Targets:
- Tool registration: <10ms P95
- Tool lookup: <5ms P95
- Tool listing: <15ms P95

Security:
- V-TOOL-1: Namespace isolation (namespace column + indexes)
- V-TOOL-2: Category whitelist enforcement (application layer)
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql, sqlite

# revision identifiers, used by Alembic.
revision: str = "add_tool_discovery_001"
down_revision: str | Sequence[str] | None = "571948cc671b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema - Add Tool Discovery tables for Phase 4 Day 1."""

    # Table 1: discovered_tools
    op.create_table(
        "discovered_tools",
        # Primary Key (UUID)
        sa.Column(
            "id",
            sa.Uuid() if sa.engine.url.make_url(op.get_bind().engine.url).drivername == "postgresql"
            else sa.String(36),
            nullable=False,
            comment="UUID primary key",
        ),
        # Tool Identity
        sa.Column(
            "tool_id",
            sa.String(length=100),
            nullable=False,
            comment="Unique tool identifier (e.g., 'genai-toolbox-v1')",
        ),
        sa.Column(
            "name",
            sa.String(length=100),
            nullable=False,
            comment="Human-readable tool name",
        ),
        sa.Column(
            "category",
            sa.String(length=50),
            nullable=False,
            comment="Tool category: MCP, CLI, API, LIBRARY",
        ),
        # Source & Version
        sa.Column(
            "source_path",
            sa.String(length=500),
            nullable=False,
            comment="File system path or container image URL",
        ),
        sa.Column(
            "version",
            sa.String(length=20),
            nullable=False,
            comment="Semantic version (e.g., '1.0.0')",
        ),
        # Tool-specific metadata (renamed from 'metadata' to avoid SQLAlchemy reserved word)
        sa.Column(
            "tool_metadata",
            sa.JSON(),
            nullable=False,
            server_default="{}",
            comment="Tool-specific metadata (capabilities, config, etc.)",
        ),
        # V-TOOL-1: Namespace Isolation
        sa.Column(
            "namespace",
            sa.String(length=100),
            nullable=False,
            comment="Project-specific namespace (enforces tool isolation)",
        ),
        # Discovery Timestamps
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            comment="When the tool was first discovered",
        ),
        sa.Column(
            "last_verified_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="Last successful verification timestamp",
        ),
        # Timestamps (MetadataMixin)
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        # Soft Delete
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default="1",
            comment="False if tool is deactivated",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tool_id", name="uq_discovered_tools_tool_id"),
    )

    # Indexes for discovered_tools (Performance: <20ms P95)
    op.create_index(
        "ix_discovered_tools_tool_id", "discovered_tools", ["tool_id"], unique=False
    )
    op.create_index(
        "ix_discovered_tools_category", "discovered_tools", ["category"], unique=False
    )
    op.create_index(
        "ix_discovered_tools_namespace", "discovered_tools", ["namespace"], unique=False
    )
    op.create_index(
        "idx_discovered_tools_category_active",
        "discovered_tools",
        ["category", "is_active"],
        unique=False,
    )
    op.create_index(
        "idx_discovered_tools_namespace_active",
        "discovered_tools",
        ["namespace", "is_active"],
        unique=False,
    )
    op.create_index(
        "idx_discovered_tools_category_namespace",
        "discovered_tools",
        ["category", "namespace", "is_active"],
        unique=False,
    )

    # Table 2: tool_dependencies
    op.create_table(
        "tool_dependencies",
        # Primary Key (UUID)
        sa.Column(
            "id",
            sa.Uuid() if sa.engine.url.make_url(op.get_bind().engine.url).drivername == "postgresql"
            else sa.String(36),
            nullable=False,
            comment="UUID primary key",
        ),
        # Foreign Keys
        sa.Column(
            "tool_id",
            sa.Uuid() if sa.engine.url.make_url(op.get_bind().engine.url).drivername == "postgresql"
            else sa.String(36),
            nullable=False,
            comment="Tool that has the dependency",
        ),
        sa.Column(
            "depends_on_tool_id",
            sa.Uuid() if sa.engine.url.make_url(op.get_bind().engine.url).drivername == "postgresql"
            else sa.String(36),
            nullable=False,
            comment="Tool that is depended upon",
        ),
        # Dependency Type
        sa.Column(
            "dependency_type",
            sa.String(length=50),
            nullable=False,
            comment="Dependency type: required, optional, recommended",
        ),
        # Timestamps
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["tool_id"],
            ["discovered_tools.id"],
            name="fk_tool_dependencies_tool_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["depends_on_tool_id"],
            ["discovered_tools.id"],
            name="fk_tool_dependencies_depends_on",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "idx_tool_dependencies_tool_id",
        "tool_dependencies",
        ["tool_id"],
        unique=False,
    )

    # Table 3: tool_instances
    op.create_table(
        "tool_instances",
        # Primary Key (UUID)
        sa.Column(
            "id",
            sa.Uuid() if sa.engine.url.make_url(op.get_bind().engine.url).drivername == "postgresql"
            else sa.String(36),
            nullable=False,
            comment="UUID primary key",
        ),
        # Foreign Key
        sa.Column(
            "tool_id",
            sa.Uuid() if sa.engine.url.make_url(op.get_bind().engine.url).drivername == "postgresql"
            else sa.String(36),
            nullable=False,
            comment="Reference to discovered tool",
        ),
        # Instance Identity
        sa.Column(
            "instance_id",
            sa.String(length=100),
            nullable=False,
            comment="Unique instance identifier (e.g., Docker container ID)",
        ),
        # Status
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            comment="Instance status: starting, running, stopping, stopped, error",
        ),
        # Container Info
        sa.Column(
            "container_id",
            sa.String(length=100),
            nullable=True,
            comment="Docker container ID",
        ),
        sa.Column(
            "container_name",
            sa.String(length=100),
            nullable=True,
            comment="Docker container name",
        ),
        # Network
        sa.Column(
            "host",
            sa.String(length=100),
            nullable=True,
            comment="Host address (e.g., 'localhost')",
        ),
        sa.Column(
            "port",
            sa.Integer(),
            nullable=True,
            comment="Exposed port number",
        ),
        # Resource Usage
        sa.Column(
            "cpu_limit",
            sa.String(length=20),
            nullable=True,
            comment="CPU limit (e.g., '0.5')",
        ),
        sa.Column(
            "memory_limit",
            sa.String(length=20),
            nullable=True,
            comment="Memory limit (e.g., '512m')",
        ),
        # Lifecycle
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="Instance start time",
        ),
        sa.Column(
            "stopped_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="Instance stop time",
        ),
        # Timestamps
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["tool_id"],
            ["discovered_tools.id"],
            name="fk_tool_instances_tool_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("instance_id", name="uq_tool_instances_instance_id"),
    )

    op.create_index(
        "ix_tool_instances_instance_id",
        "tool_instances",
        ["instance_id"],
        unique=False,
    )
    op.create_index(
        "ix_tool_instances_tool_id", "tool_instances", ["tool_id"], unique=False
    )
    op.create_index(
        "idx_tool_instances_status", "tool_instances", ["status"], unique=False
    )
    op.create_index(
        "idx_tool_instances_tool_status",
        "tool_instances",
        ["tool_id", "status"],
        unique=False,
    )

    # Table 4: tool_verification_history
    op.create_table(
        "tool_verification_history",
        # Primary Key (UUID)
        sa.Column(
            "id",
            sa.Uuid() if sa.engine.url.make_url(op.get_bind().engine.url).drivername == "postgresql"
            else sa.String(36),
            nullable=False,
            comment="UUID primary key",
        ),
        # Foreign Key
        sa.Column(
            "tool_id",
            sa.Uuid() if sa.engine.url.make_url(op.get_bind().engine.url).drivername == "postgresql"
            else sa.String(36),
            nullable=False,
            comment="Reference to verified tool",
        ),
        # Verification Result
        sa.Column(
            "verified_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            comment="Verification timestamp",
        ),
        sa.Column(
            "success",
            sa.Boolean(),
            nullable=False,
            comment="True if verification passed",
        ),
        # Details
        sa.Column(
            "verification_method",
            sa.String(length=50),
            nullable=False,
            comment="Verification method: docker_inspect, health_check, manual",
        ),
        sa.Column(
            "error_message",
            sa.Text(),
            nullable=True,
            comment="Error message if verification failed",
        ),
        # Verification-specific metadata (renamed from 'metadata' to avoid SQLAlchemy reserved word)
        sa.Column(
            "verification_metadata",
            sa.JSON(),
            nullable=False,
            server_default="{}",
            comment="Verification-specific metadata (health check response, etc.)",
        ),
        # Timestamps
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["tool_id"],
            ["discovered_tools.id"],
            name="fk_tool_verification_history_tool_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "idx_tool_verification_tool_time",
        "tool_verification_history",
        ["tool_id", "verified_at"],
        unique=False,
    )
    op.create_index(
        "idx_tool_verification_success",
        "tool_verification_history",
        ["success"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema - Remove Tool Discovery tables."""

    # Drop indexes first
    op.drop_index("idx_tool_verification_success", table_name="tool_verification_history")
    op.drop_index("idx_tool_verification_tool_time", table_name="tool_verification_history")

    op.drop_index("idx_tool_instances_tool_status", table_name="tool_instances")
    op.drop_index("idx_tool_instances_status", table_name="tool_instances")
    op.drop_index("ix_tool_instances_tool_id", table_name="tool_instances")
    op.drop_index("ix_tool_instances_instance_id", table_name="tool_instances")

    op.drop_index("idx_tool_dependencies_tool_id", table_name="tool_dependencies")

    op.drop_index(
        "idx_discovered_tools_category_namespace", table_name="discovered_tools"
    )
    op.drop_index(
        "idx_discovered_tools_namespace_active", table_name="discovered_tools"
    )
    op.drop_index(
        "idx_discovered_tools_category_active", table_name="discovered_tools"
    )
    op.drop_index("ix_discovered_tools_namespace", table_name="discovered_tools")
    op.drop_index("ix_discovered_tools_category", table_name="discovered_tools")
    op.drop_index("ix_discovered_tools_tool_id", table_name="discovered_tools")

    # Drop tables (reverse order due to foreign keys)
    op.drop_table("tool_verification_history")
    op.drop_table("tool_instances")
    op.drop_table("tool_dependencies")
    op.drop_table("discovered_tools")
