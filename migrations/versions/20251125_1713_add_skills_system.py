"""Add Skills System tables for TMWS v2.4.0 (Phase 5A).

Revision ID: 20251125_1713_add_skills_system
Revises: f7147db33f6e
Create Date: 2025-11-25 17:13:00.000000

Skills System Architecture:
- Progressive Disclosure (Layer 1-3)
- Version management (integer-based sequential versions)
- Namespace isolation (critical security)
- Access control (reuses Memory's AccessLevel enum)
- Analytics tracking (activation history)
- MCP tool integration support
- Memory filter support (Layer 4)

Security:
- Namespace isolation enforced at every query
- Content hash verification (SHA256)
- Foreign key constraints for referential integrity
- Soft delete pattern (preserves audit trail)

Performance:
- Composite indexes for common query patterns
- JSON storage for SQLite compatibility
- Efficient version lookup (skill_id, version) index
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

# revision identifiers, used by Alembic
revision = '20251125_1713_add_skills_system'
down_revision = 'f7147db33f6e'  # Last migration: add_token_consumption_table
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create Skills System tables."""

    # Table 1: skills (master table)
    op.create_table(
        'skills',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False,
                  comment='Primary key UUID (string format)'),
        sa.Column('name', sa.String(255), nullable=False,
                  comment='Skill name (e.g., "security-audit")'),
        sa.Column('display_name', sa.String(255), nullable=True,
                  comment='Human-readable name (e.g., "Security Audit")'),
        sa.Column('description', sa.Text, nullable=True,
                  comment='Brief description of skill purpose'),
        sa.Column('namespace', sa.String(255), nullable=False,
                  comment='Namespace for multi-tenant isolation'),
        sa.Column('persona', sa.String(50), nullable=True,
                  comment='Associated persona (e.g., "hestia-auditor")'),
        sa.Column('created_by', sa.String(36), nullable=False,
                  comment='Agent ID who created this skill'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.current_timestamp(),
                  comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.current_timestamp(),
                  comment='Record last update timestamp'),
        sa.Column('access_level', sa.String(20), nullable=False, server_default='PRIVATE',
                  comment='Access control level'),
        sa.Column('tags_json', sa.Text, nullable=False, server_default='[]',
                  comment='JSON array of tags (SQLite-compatible)'),
        sa.Column('version_count', sa.Integer, nullable=False, server_default='1',
                  comment='Total number of versions'),
        sa.Column('active_version', sa.Integer, nullable=False, server_default='1',
                  comment='Currently active version number'),
        sa.Column('is_deleted', sa.Boolean, nullable=False, server_default='0',
                  comment='Soft delete flag (preserves analytics)'),

        # Foreign keys
        sa.ForeignKeyConstraint(['created_by'], ['agents.id'], ondelete='CASCADE'),

        # Check constraints
        sa.CheckConstraint(
            "access_level IN ('PRIVATE', 'TEAM', 'SHARED', 'PUBLIC', 'SYSTEM')",
            name='ck_skills_access_level'
        ),

        comment='Skills master table with metadata and access control'
    )

    # Indexes for skills table
    op.create_index('ix_skills_namespace', 'skills', ['namespace'])
    op.create_index('ix_skills_created_by', 'skills', ['created_by'])
    op.create_index('ix_skills_persona', 'skills', ['persona'])
    op.create_index('ix_skills_is_deleted', 'skills', ['is_deleted'])
    # Composite unique index: namespace + name (unique within namespace)
    op.create_index('ix_skills_namespace_name', 'skills', ['namespace', 'name'], unique=True)

    # Table 2: skill_versions (version storage with Progressive Disclosure layers)
    op.create_table(
        'skill_versions',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False,
                  comment='Primary key UUID (string format)'),
        sa.Column('skill_id', sa.String(36), nullable=False,
                  comment='Foreign key to skills.id'),
        sa.Column('version', sa.Integer, nullable=False,
                  comment='Sequential version number (1, 2, 3, ...)'),
        sa.Column('content', sa.Text, nullable=False,
                  comment='Full SKILL.md content'),
        sa.Column('metadata_json', sa.Text, nullable=True,
                  comment='Layer 1: Extracted metadata (~100 tokens, JSON)'),
        sa.Column('core_instructions', sa.Text, nullable=True,
                  comment='Layer 2: Core instructions section (~2,000 tokens)'),
        sa.Column('auxiliary_content', sa.Text, nullable=True,
                  comment='Layer 3: Auxiliary content section (~10,000 tokens)'),
        sa.Column('content_hash', sa.String(64), nullable=True,
                  comment='SHA256 hash of content for integrity verification'),
        sa.Column('created_by', sa.String(36), nullable=False,
                  comment='Agent ID who created this version'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.current_timestamp(),
                  comment='Version creation timestamp'),

        # Foreign keys
        sa.ForeignKeyConstraint(['skill_id'], ['skills.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['agents.id']),

        comment='Skill versions with Progressive Disclosure content layers'
    )

    # Indexes for skill_versions table
    op.create_index('ix_skill_versions_skill_id', 'skill_versions', ['skill_id'])
    # Composite unique index: skill_id + version (unique version per skill)
    op.create_index('ix_skill_versions_skill_version', 'skill_versions',
                   ['skill_id', 'version'], unique=True)

    # Table 3: skill_activations (usage tracking and analytics)
    op.create_table(
        'skill_activations',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False,
                  comment='Primary key UUID (string format)'),
        sa.Column('skill_id', sa.String(36), nullable=False,
                  comment='Foreign key to skills.id'),
        sa.Column('version', sa.Integer, nullable=False,
                  comment='Skill version that was activated'),
        sa.Column('agent_id', sa.String(36), nullable=False,
                  comment='Agent who activated the skill'),
        sa.Column('namespace', sa.String(255), nullable=False,
                  comment='Namespace context of activation'),
        sa.Column('activation_type', sa.String(20), nullable=True,
                  comment='Type of activation (e.g., "mcp_tool", "api_call")'),
        sa.Column('layer_loaded', sa.Integer, nullable=True,
                  comment='Progressive Disclosure layer loaded (1, 2, or 3)'),
        sa.Column('tokens_loaded', sa.Integer, nullable=True,
                  comment='Estimated tokens loaded'),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.current_timestamp(),
                  comment='Activation timestamp'),
        sa.Column('duration_ms', sa.Integer, nullable=True,
                  comment='Execution duration in milliseconds'),
        sa.Column('success', sa.Boolean, nullable=True,
                  comment='Whether activation was successful'),
        sa.Column('error_message', sa.Text, nullable=True,
                  comment='Error message if activation failed'),

        # Foreign keys
        sa.ForeignKeyConstraint(['skill_id'], ['skills.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ondelete='CASCADE'),

        comment='Skill activation history for analytics and usage tracking'
    )

    # Indexes for skill_activations table
    op.create_index('ix_skill_activations_skill_id', 'skill_activations', ['skill_id'])
    op.create_index('ix_skill_activations_agent_id', 'skill_activations', ['agent_id'])
    op.create_index('ix_skill_activations_namespace', 'skill_activations', ['namespace'])
    op.create_index('ix_skill_activations_activated_at', 'skill_activations', ['activated_at'])
    # Composite index for analytics queries
    op.create_index('ix_skill_activations_agent_time', 'skill_activations',
                   ['agent_id', 'activated_at'])

    # Table 4: skill_mcp_tools (optional MCP tool linkage)
    op.create_table(
        'skill_mcp_tools',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False,
                  comment='Primary key UUID (string format)'),
        sa.Column('skill_id', sa.String(36), nullable=False,
                  comment='Foreign key to skills.id'),
        sa.Column('mcp_server_name', sa.String(255), nullable=True,
                  comment='MCP server name (e.g., "serena", "tmws")'),
        sa.Column('tool_name', sa.String(255), nullable=True,
                  comment='MCP tool name (e.g., "search_for_pattern")'),
        sa.Column('detail_level', sa.String(20), nullable=True, server_default='summary',
                  comment='Detail level to load ("summary" or "full")'),
        sa.Column('load_when_condition', sa.Text, nullable=True,
                  comment='Condition expression for loading full schema (JSON)'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.current_timestamp(),
                  comment='Record creation timestamp'),

        # Foreign keys
        sa.ForeignKeyConstraint(['skill_id'], ['skills.id'], ondelete='CASCADE'),

        # Check constraints
        sa.CheckConstraint(
            "detail_level IN ('summary', 'full')",
            name='ck_skill_mcp_tools_detail_level'
        ),

        comment='MCP tool references for Progressive Disclosure'
    )

    # Indexes for skill_mcp_tools table
    op.create_index('ix_skill_mcp_tools_skill_id', 'skill_mcp_tools', ['skill_id'])

    # Table 5: skill_shared_agents (for SHARED access level)
    op.create_table(
        'skill_shared_agents',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False,
                  comment='Primary key UUID (string format)'),
        sa.Column('skill_id', sa.String(36), nullable=False,
                  comment='Foreign key to skills.id'),
        sa.Column('agent_id', sa.String(36), nullable=False,
                  comment='Agent granted explicit access'),
        sa.Column('shared_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.current_timestamp(),
                  comment='When access was granted'),

        # Foreign keys
        sa.ForeignKeyConstraint(['skill_id'], ['skills.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ondelete='CASCADE'),

        comment='Explicit agent sharing for SHARED access level'
    )

    # Indexes for skill_shared_agents table
    op.create_index('ix_skill_shared_agents_skill_id', 'skill_shared_agents', ['skill_id'])
    op.create_index('ix_skill_shared_agents_agent_id', 'skill_shared_agents', ['agent_id'])
    # Composite unique index: skill_id + agent_id (prevent duplicate shares)
    op.create_index('ix_skill_shared_agents_skill_agent', 'skill_shared_agents',
                   ['skill_id', 'agent_id'], unique=True)

    # Table 6: skill_memory_filters (Layer 4 Just-in-Time Memory filters)
    op.create_table(
        'skill_memory_filters',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False,
                  comment='Primary key UUID (string format)'),
        sa.Column('skill_id', sa.String(36), nullable=False,
                  comment='Foreign key to skills.id'),
        sa.Column('filter_type', sa.String(50), nullable=False,
                  comment='Type of filter ("tag", "namespace", "importance", etc.)'),
        sa.Column('filter_value', sa.Text, nullable=False,
                  comment='Filter value (JSON for complex filters)'),
        sa.Column('priority', sa.Integer, nullable=False, server_default='0',
                  comment='Filter priority (higher = applied first)'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.current_timestamp(),
                  comment='Record creation timestamp'),

        # Foreign keys
        sa.ForeignKeyConstraint(['skill_id'], ['skills.id'], ondelete='CASCADE'),

        comment='Just-in-Time Memory filters for Layer 4 (future)'
    )

    # Indexes for skill_memory_filters table
    op.create_index('ix_skill_memory_filters_skill_id', 'skill_memory_filters', ['skill_id'])
    op.create_index('ix_skill_memory_filters_priority', 'skill_memory_filters', ['priority'])


def downgrade() -> None:
    """Drop Skills System tables."""

    # Drop tables in reverse order (respects foreign key constraints)
    op.drop_table('skill_memory_filters')
    op.drop_table('skill_shared_agents')
    op.drop_table('skill_mcp_tools')
    op.drop_table('skill_activations')
    op.drop_table('skill_versions')
    op.drop_table('skills')
