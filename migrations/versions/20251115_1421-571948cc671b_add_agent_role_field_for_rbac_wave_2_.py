"""Add Agent.role field for RBAC (Wave 2 - minimal)

Revision ID: 571948cc671b
Revises: 096325207c82
Create Date: 2025-11-15 14:21:19.957361

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '571948cc671b'
down_revision: Union[str, Sequence[str], None] = '096325207c82'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema - Add Agent.role field for RBAC."""
    # Add role column to agents table
    op.add_column(
        'agents',
        sa.Column(
            'role',
            sa.Text(),
            server_default='viewer',
            nullable=False,
            comment='RBAC role (viewer, editor, admin)'
        )
    )

    # Create index on role for efficient filtering
    op.create_index(
        op.f('ix_agents_role'),
        'agents',
        ['role'],
        unique=False
    )


def downgrade() -> None:
    """Downgrade schema - Remove Agent.role field."""
    # Drop index first
    op.drop_index(op.f('ix_agents_role'), table_name='agents')

    # Drop column
    op.drop_column('agents', 'role')
