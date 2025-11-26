"""add_token_consumption_table_sqlite_only

Revision ID: f7147db33f6e
Revises: 0d10be0b0497
Create Date: 2025-11-24 16:02:50.919141

Phase 2D-2: V-2 Progressive Disclosure - SQLite-Only Token Budget
- Remove Redis dependency (simplify architecture)
- Add token_consumption table for SQLite-based tracking
- Atomic upsert operations (race-condition safe)
- Automatic cleanup via window_hour index

Author: Artemis (Technical Perfectionist) + Trinitas Team
Strategic Direction: Hera (Strategic Commander)
Coordination: Eris (Tactical Coordinator)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f7147db33f6e'
down_revision: Union[str, Sequence[str], None] = '0d10be0b0497'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema - Add token_consumption table (SQLite-only)."""

    # Create token_consumption table
    op.create_table(
        'token_consumption',
        sa.Column('agent_id', sa.UUID(), nullable=False),
        sa.Column('window_hour', sa.String(length=10), nullable=False,
                  comment='Format: YYYYMMDDHH (e.g., 2025112416)'),
        sa.Column('consumption_count', sa.Integer(), nullable=False, server_default='0',
                  comment='Total tokens consumed in this hour'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.PrimaryKeyConstraint('agent_id', 'window_hour', name='pk_token_consumption'),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ondelete='CASCADE'),
        comment='Token consumption tracking for budget enforcement (SQLite-only, Redis removed)'
    )

    # Create index for cleanup (delete old window_hour records)
    op.create_index(
        'idx_token_consumption_cleanup',
        'token_consumption',
        ['window_hour'],
        unique=False
    )

    # Create index for agent lookup
    op.create_index(
        'idx_token_consumption_agent_hour',
        'token_consumption',
        ['agent_id', 'window_hour'],
        unique=False
    )


def downgrade() -> None:
    """Downgrade schema - Remove token_consumption table."""

    # Drop indexes
    op.drop_index('idx_token_consumption_agent_hour', table_name='token_consumption')
    op.drop_index('idx_token_consumption_cleanup', table_name='token_consumption')

    # Drop table
    op.drop_table('token_consumption')
