"""add_license_key_system

Revision ID: 096325207c82
Revises: ff4b1a18d2f0
Create Date: 2025-11-15 12:06:57.646686

Phase 2B: Database Migration - License Key System
- Create license_keys table for key storage and validation
- Create license_key_usage table for usage tracking
- Add tier column to agents table
- Add strategic indexes for performance

Author: Artemis (Technical Perfectionist)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '096325207c82'
down_revision: Union[str, Sequence[str], None] = 'ff4b1a18d2f0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema - Add license key system."""
    # Create license_keys table
    op.create_table(
        'license_keys',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('agent_id', sa.UUID(), nullable=False),
        sa.Column('tier', sa.Enum('FREE', 'PRO', 'ENTERPRISE', name='tierenum'), nullable=False),
        sa.Column('license_key_hash', sa.String(length=64), nullable=False),
        sa.Column('issued_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_reason', sa.Text(), nullable=True),
        sa.CheckConstraint('expires_at IS NULL OR expires_at > issued_at', name='check_expiration_after_issuance'),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('license_key_hash')
    )

    # Create indexes for license_keys
    op.create_index('idx_license_keys_hash_lookup', 'license_keys', ['license_key_hash', 'is_active'], unique=False)
    op.create_index('idx_license_keys_expiration', 'license_keys', ['expires_at', 'is_active'], unique=False)
    op.create_index('idx_license_keys_agent', 'license_keys', ['agent_id', 'is_active'], unique=False)

    # Create license_key_usage table
    op.create_table(
        'license_key_usage',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('license_key_id', sa.UUID(), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('feature_accessed', sa.String(length=128), nullable=True),
        sa.Column('usage_metadata', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['license_key_id'], ['license_keys.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for license_key_usage
    op.create_index('idx_license_key_usage_time', 'license_key_usage', ['license_key_id', 'used_at'], unique=False)
    op.create_index('idx_license_key_usage_feature', 'license_key_usage', ['license_key_id', 'feature_accessed'], unique=False)

    # Add tier column to agents table
    op.add_column('agents', sa.Column('tier', sa.Text(), nullable=False, server_default='FREE', comment='License tier (FREE, PRO, ENTERPRISE)'))
    op.create_index(op.f('ix_agents_tier'), 'agents', ['tier'], unique=False)


def downgrade() -> None:
    """Downgrade schema - Remove license key system."""
    # Remove tier column from agents
    op.drop_index(op.f('ix_agents_tier'), table_name='agents')
    op.drop_column('agents', 'tier')

    # Drop license_key_usage table
    op.drop_index('idx_license_key_usage_feature', table_name='license_key_usage')
    op.drop_index('idx_license_key_usage_time', table_name='license_key_usage')
    op.drop_table('license_key_usage')

    # Drop license_keys table
    op.drop_index('idx_license_keys_agent', table_name='license_keys')
    op.drop_index('idx_license_keys_expiration', table_name='license_keys')
    op.drop_index('idx_license_keys_hash_lookup', table_name='license_keys')
    op.drop_table('license_keys')
