"""p0_migrate_default_namespace_to_project_specific

Revision ID: 486c2cd055fe
Revises: d42bfef42946
Create Date: 2025-10-27 21:51:59.339198

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '486c2cd055fe'
down_revision: Union[str, Sequence[str], None] = 'd42bfef42946'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    P0-1 Security Fix: Migrate 'default' namespace to 'legacy-default'.

    Background:
    - Default namespace caused cross-project memory leakage (CVSS 9.8)
    - All existing memories with namespace='default' are moved to 'legacy-default'
    - This allows them to be identified and manually migrated to project-specific namespaces

    Security Impact:
    - Prevents new memories from using 'default' namespace
    - Isolates existing 'default' memories in a separate namespace
    - Forces explicit project-specific namespaces going forward
    """
    # Update all 'default' namespace memories to 'legacy-default'
    op.execute(
        """
        UPDATE memories
        SET namespace = 'legacy-default'
        WHERE namespace = 'default'
        """
    )

    # Do the same for other tables that use namespace
    op.execute(
        """
        UPDATE memory_patterns
        SET namespace = 'legacy-default'
        WHERE namespace = 'default'
        """
    )


def downgrade() -> None:
    """
    Downgrade: Revert 'legacy-default' back to 'default'.

    Warning: This downgrade re-introduces the security vulnerability!
    Only use for emergency rollback.
    """
    # Revert 'legacy-default' namespace back to 'default'
    op.execute(
        """
        UPDATE memories
        SET namespace = 'default'
        WHERE namespace = 'legacy-default'
        """
    )

    op.execute(
        """
        UPDATE memory_patterns
        SET namespace = 'default'
        WHERE namespace = 'legacy-default'
        """
    )
