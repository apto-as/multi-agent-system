"""add_administrator_tier_to_license_system

Revision ID: 0d10be0b0497
Revises: add_tool_discovery_001
Create Date: 2025-11-24 15:39:44.496983

Phase 2D-2: V-2 Progressive Disclosure - Phase 2
- Add ADMINISTRATOR tier to TierEnum (unlimited + perpetual)
- Update license_keys table to support new tier
- Backward compatible (existing FREE/PRO/ENTERPRISE unchanged)

Author: Artemis (Technical Perfectionist)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0d10be0b0497'
down_revision: Union[str, Sequence[str], None] = 'add_tool_discovery_001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema - Add ADMINISTRATOR tier to license system."""
    # SQLite: Recreate TierEnum with ADMINISTRATOR added
    # Since SQLite enums are CHECK constraints, we need to recreate the table

    with op.batch_alter_table('license_keys', schema=None) as batch_op:
        # Drop old enum constraint (implicitly replaced by new one)
        batch_op.alter_column(
            'tier',
            existing_type=sa.Enum('FREE', 'PRO', 'ENTERPRISE', name='tierenum'),
            type_=sa.Enum('FREE', 'PRO', 'ENTERPRISE', 'ADMINISTRATOR', name='tierenum'),
            existing_nullable=False
        )


def downgrade() -> None:
    """Downgrade schema - Remove ADMINISTRATOR tier from license system."""
    # Remove ADMINISTRATOR tier (revert to 3-tier system)

    with op.batch_alter_table('license_keys', schema=None) as batch_op:
        # Revert to original 3-tier enum
        batch_op.alter_column(
            'tier',
            existing_type=sa.Enum('FREE', 'PRO', 'ENTERPRISE', 'ADMINISTRATOR', name='tierenum'),
            type_=sa.Enum('FREE', 'PRO', 'ENTERPRISE', name='tierenum'),
            existing_nullable=False
        )
