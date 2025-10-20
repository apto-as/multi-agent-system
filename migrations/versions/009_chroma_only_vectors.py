"""Chroma-only vector storage architecture

Revision ID: 009
Revises: 008
Create Date: 2025-10-16

Changes:
- Remove all embedding vector columns from SQLite (vectors stored in Chroma only)
- Add embedding_model and embedding_dimension for metadata tracking
- Note: JSONB → JSON and UUID changes are no-ops for SQLite

This migration supports the SQLite + Chroma architecture where:
- SQLite: Metadata, relationships, access control only
- Chroma: 100% vector storage and semantic search
"""

import contextlib
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "009"
down_revision: str | None = "008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Remove embedding vectors from SQLite, add metadata tracking fields."""

    # Check if we're using SQLite
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        # SQLite requires table recreation for column removal
        with op.batch_alter_table("memories_v2", schema=None) as batch_op:
            # Drop embedding vector columns (if they exist)
            with contextlib.suppress(Exception):
                batch_op.drop_column("embedding")  # Column may not exist

            with contextlib.suppress(Exception):
                batch_op.drop_column("embedding_v2")

            with contextlib.suppress(Exception):
                batch_op.drop_column("embedding_v3")

            # Add metadata tracking fields
            batch_op.add_column(
                sa.Column(
                    "embedding_model",
                    sa.Text(),
                    nullable=False,
                    server_default="zylonai/multilingual-e5-large",
                    comment="Embedding model used in Chroma: 'zylonai/multilingual-e5-large' (1024-dim)",
                )
            )
            batch_op.add_column(
                sa.Column(
                    "embedding_dimension",
                    sa.Integer(),
                    nullable=False,
                    server_default="1024",
                    comment="Embedding dimension for Chroma vectors",
                )
            )
    else:
        # PostgreSQL path (for future compatibility)
        # Drop old vector columns
        op.drop_column("memories_v2", "embedding")
        op.drop_column("memories_v2", "embedding_v2")
        op.drop_column("memories_v2", "embedding_v3")

        # Add metadata tracking fields
        op.add_column(
            "memories_v2",
            sa.Column(
                "embedding_model",
                sa.Text(),
                nullable=False,
                server_default="zylonai/multilingual-e5-large",
            ),
        )
        op.add_column(
            "memories_v2",
            sa.Column(
                "embedding_dimension",
                sa.Integer(),
                nullable=False,
                server_default=1024,
            ),
        )


def downgrade() -> None:
    """Revert to storing vectors in database (not recommended)."""

    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("memories_v2", schema=None) as batch_op:
            # Remove metadata tracking fields
            batch_op.drop_column("embedding_dimension")
            batch_op.drop_column("embedding_model")

            # Note: Cannot restore vector data - would need to regenerate from Chroma
            # Adding placeholder columns only
            batch_op.add_column(sa.Column("embedding", sa.JSON(), nullable=True))
            batch_op.add_column(sa.Column("embedding_v2", sa.JSON(), nullable=True))
            batch_op.add_column(sa.Column("embedding_v3", sa.JSON(), nullable=True))
    else:
        # PostgreSQL path
        from pgvector.sqlalchemy import Vector

        op.drop_column("memories_v2", "embedding_dimension")
        op.drop_column("memories_v2", "embedding_model")

        # Add back vector columns (empty)
        op.add_column("memories_v2", sa.Column("embedding", Vector(384), nullable=True))
        op.add_column("memories_v2", sa.Column("embedding_v2", Vector(768), nullable=True))
        op.add_column("memories_v2", sa.Column("embedding_v3", Vector(1024), nullable=True))
