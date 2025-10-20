"""Multilingual-E5 embedding support with 768-dimensional vectors

Revision ID: 007
Revises: 006
Create Date: 2025-01-10

This migration adds support for Multilingual-E5 embeddings (768 dimensions) while
maintaining backward compatibility with existing all-MiniLM-L6-v2 embeddings (384 dimensions).

Key changes:
- Add embedding_v2 column (Vector(768)) for Multilingual-E5 support
- Add embedding_model column to track which model generated the embedding
- Create CONCURRENT index for zero-downtime deployment
- Mark existing embeddings with their model type

Background:
TMWS needs to support Japanese-English mixed content with high cross-lingual
similarity (>0.85). Multilingual-E5 provides superior multilingual support
compared to all-MiniLM-L6-v2.
"""

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector

# revision identifiers
revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade():
    """Add Multilingual-E5 support (768-dimensional embeddings)."""

    print("🚀 Starting Multilingual-E5 migration...")

    # 1. Add embedding_v2 column (768 dimensions for Multilingual-E5)
    print("📊 Adding embedding_v2 column (Vector(768))...")
    op.add_column(
        "memories_v2",
        sa.Column(
            "embedding_v2",
            Vector(768),
            nullable=True,
            comment="Multilingual-E5 embedding (768 dimensions) for cross-lingual semantic search",
        ),
    )

    # 2. Add embedding_model column to track which model generated the embedding
    print("🏷️ Adding embedding_model column...")
    op.add_column(
        "memories_v2",
        sa.Column(
            "embedding_model",
            sa.Text(),
            nullable=True,
            comment="Model used for embedding: 'all-MiniLM-L6-v2' or 'multilingual-e5-base'",
        ),
    )

    # 3. Mark existing embeddings with their model type
    print("📝 Marking existing embeddings as all-MiniLM-L6-v2...")
    op.execute("""
        UPDATE memories_v2
        SET embedding_model = 'all-MiniLM-L6-v2'
        WHERE embedding IS NOT NULL
        AND embedding_model IS NULL
    """)

    # 4. Create vector index for embedding_v2
    # Note: Using regular index (not CONCURRENTLY) to work within transaction
    print("🔍 Creating IVFFlat index for embedding_v2...")
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_memory_embedding_v2
        ON memories_v2 USING ivfflat (embedding_v2 vector_cosine_ops)
        WITH (lists = 100)
    """)

    print("✅ Migration 007 completed successfully!")
    print("📌 Next steps:")
    print("   1. Run embedding migration script to populate embedding_v2")
    print("   2. Test cross-lingual search (Japanese ↔ English)")
    print("   3. Monitor performance with both embedding versions")


def downgrade():
    """Remove Multilingual-E5 support."""

    print("🔄 Rolling back Multilingual-E5 migration...")

    # Drop index first
    print("🗑️ Dropping ix_memory_embedding_v2 index...")
    op.execute("DROP INDEX IF EXISTS ix_memory_embedding_v2")

    # Drop columns
    print("📉 Dropping embedding_v2 column...")
    op.drop_column("memories_v2", "embedding_v2")

    print("🏷️ Dropping embedding_model column...")
    op.drop_column("memories_v2", "embedding_model")

    print("✅ Rollback completed successfully!")
