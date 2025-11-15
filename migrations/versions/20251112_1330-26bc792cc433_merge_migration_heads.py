"""Merge migration heads

Revision ID: 26bc792cc433
Revises: e674ec434eeb, 20251107_agent_trust
Create Date: 2025-11-12 13:30:07.717536

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '26bc792cc433'
down_revision: Union[str, Sequence[str], None] = ('e674ec434eeb', '20251107_agent_trust')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
