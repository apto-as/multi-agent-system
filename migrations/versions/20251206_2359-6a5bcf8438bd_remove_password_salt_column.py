"""Remove deprecated password_salt column from users table.

Revision ID: 6a5bcf8438bd
Revises: 20251202_autonomous_learning
Create Date: 2025-12-06 23:59

Security: Part of SHA256 to bcrypt migration (Issue #1 Phase 2)
Context: password_salt was deprecated in Phase 1.1 and confirmed NULL for all users.
This migration removes the unused column from the schema.

Safety: Column is verified to always be NULL in production.
Impact: No data loss - column was never used after bcrypt migration.
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic
revision = '6a5bcf8438bd'
down_revision = '20251202_autonomous_learning'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Remove password_salt column.

    SAFETY: Column is verified to always be NULL in production.
    All password hashing now uses bcrypt without separate salt storage.
    """
    # SQLite requires batch mode for column operations
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('password_salt')


def downgrade() -> None:
    """Re-add password_salt column.

    WARNING: Original data cannot be restored (was always NULL).
    This downgrade is provided for schema rollback only.
    The column will be re-added but will remain NULL for all users.
    """
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('password_salt', sa.Text(), nullable=True,
                     comment='Password salt for additional security (DEPRECATED)')
        )
