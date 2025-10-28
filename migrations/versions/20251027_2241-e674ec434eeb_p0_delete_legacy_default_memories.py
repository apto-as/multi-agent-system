"""p0_delete_legacy_default_memories

Revision ID: e674ec434eeb
Revises: 486c2cd055fe
Create Date: 2025-10-27 22:41:36.637970

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e674ec434eeb'
down_revision: Union[str, Sequence[str], None] = '486c2cd055fe'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    P0-1 Cleanup: Delete legacy-default memories (User-approved 2025-10-27).

    Background:
    - These 3 memories were migrated from 'default' namespace in previous migration
    - User explicitly approved deletion: "削除して良いです"
    - Memories are system documentation that will be recreated with proper namespaces

    Note: ChromaDB vectors must be cleaned separately (handled by service layer)
    """
    # Delete all memories with namespace='legacy-default'
    op.execute(
        """
        DELETE FROM memories
        WHERE namespace = 'legacy-default'
        """
    )

    # Also clean up related tables if they exist
    op.execute(
        """
        DELETE FROM memory_patterns
        WHERE namespace = 'legacy-default'
        """
    )


def downgrade() -> None:
    """
    Downgrade: Not supported.

    The deleted memories contained system documentation that was already
    migrated from the insecure 'default' namespace. Restoration would
    require the original content, which is not preserved.

    If rollback is needed, recreate memories with proper project-specific namespaces.
    """
    pass  # No restoration - user approved permanent deletion
