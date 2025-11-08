"""Agent trust and verification system

Revision ID: 20251107_agent_trust
Revises: d42bfef42946
Create Date: 2025-11-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

# revision identifiers, used by Alembic.
revision: str = '20251107_agent_trust'
down_revision: Union[str, None] = 'd42bfef42946'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add trust tracking and verification tables"""

    # Add trust columns to agents table
    op.add_column(
        'agents',
        sa.Column('trust_score', sa.Float(), nullable=False, server_default='0.5',
                 comment='Trust score (0.0 - 1.0) based on verification accuracy')
    )
    op.add_column(
        'agents',
        sa.Column('total_verifications', sa.Integer(), nullable=False, server_default='0')
    )
    op.add_column(
        'agents',
        sa.Column('accurate_verifications', sa.Integer(), nullable=False, server_default='0')
    )

    # Create verification_records table
    op.create_table(
        'verification_records',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('agent_id', sa.String(length=64), nullable=False),
        sa.Column('claim_type', sa.String(length=64), nullable=False),
        sa.Column('claim_content', sa.JSON(), nullable=False),
        sa.Column('verification_command', sa.Text(), nullable=False),
        sa.Column('verification_result', sa.JSON(), nullable=False),
        sa.Column('accurate', sa.Boolean(), nullable=False),
        sa.Column('evidence_memory_id', sa.UUID(), nullable=True),
        sa.Column('verified_at', sa.DateTime(), nullable=False),
        sa.Column('verified_by_agent_id', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(
            ['agent_id'],
            ['agents.agent_id'],
            name='fk_verification_agent'
        ),
        sa.ForeignKeyConstraint(
            ['evidence_memory_id'],
            ['memories.id'],
            name='fk_verification_evidence'
        )
    )

    # Indexes for verification_records
    op.create_index(
        'idx_verification_agent_time',
        'verification_records',
        ['agent_id', 'verified_at'],
        unique=False
    )
    op.create_index(
        'idx_verification_claim_type',
        'verification_records',
        ['claim_type', 'accurate'],
        unique=False
    )

    # Create trust_score_history table
    op.create_table(
        'trust_score_history',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('agent_id', sa.String(length=64), nullable=False),
        sa.Column('old_score', sa.Float(), nullable=False),
        sa.Column('new_score', sa.Float(), nullable=False),
        sa.Column('verification_record_id', sa.UUID(), nullable=True),
        sa.Column('reason', sa.String(length=255), nullable=False),
        sa.Column('changed_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(
            ['agent_id'],
            ['agents.agent_id'],
            name='fk_trust_history_agent'
        ),
        sa.ForeignKeyConstraint(
            ['verification_record_id'],
            ['verification_records.id'],
            name='fk_trust_history_verification'
        )
    )

    # Index for trust history
    op.create_index(
        'idx_trust_history_agent_time',
        'trust_score_history',
        ['agent_id', 'changed_at'],
        unique=False
    )


def downgrade() -> None:
    """Remove trust tracking and verification tables"""
    op.drop_index('idx_trust_history_agent_time', table_name='trust_score_history')
    op.drop_table('trust_score_history')

    op.drop_index('idx_verification_claim_type', table_name='verification_records')
    op.drop_index('idx_verification_agent_time', table_name='verification_records')
    op.drop_table('verification_records')

    # Remove trust columns from agents table
    op.drop_column('agents', 'accurate_verifications')
    op.drop_column('agents', 'total_verifications')
    op.drop_column('agents', 'trust_score')
