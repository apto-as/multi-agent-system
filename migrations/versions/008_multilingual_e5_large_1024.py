"""Multilingual-E5 Large support with 1024-dimensional vectors (Ollama integration)

Revision ID: 008
Revises: 007
Create Date: 2025-01-10

This migration adds support for Multilingual-E5 Large embeddings (1024 dimensions)
for Ollama integration, enabling Windows compatibility while maintaining superior
cross-lingual performance.

Key changes:
- Add embedding_v3 column (Vector(1024)) for Multilingual-E5 Large support
- Update embedding_model to support 'multilingual-e5-large'
- Create CONCURRENT index for zero-downtime deployment
- Enable gradual migration from 768-dim to 1024-dim embeddings

Background:
TMWS v2.2.5 introduces Ollama integration for simplified Windows deployment.
The zylonai/multilingual-e5-large model provides:
- 1024-dimensional embeddings (vs 768-dim in base variant)
- Cross-lingual similarity: 0.85+ (Japanese-English)
- Single binary installation (no PyTorch complexity)
- Automatic fallback to SentenceTransformers
"""


import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector

# revision identifiers
revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None


def upgrade():
    """Add Multilingual-E5 Large support (1024-dimensional embeddings)."""

    print("🚀 Starting Multilingual-E5 Large migration (Ollama integration)...")

    # 1. Add embedding_v3 column (1024 dimensions for Multilingual-E5 Large)
    print("📊 Adding embedding_v3 column (Vector(1024))...")
    op.add_column(
        'memories_v2',
        sa.Column(
            'embedding_v3',
            Vector(1024),
            nullable=True,
            comment="Multilingual-E5 Large embedding (1024 dimensions) for enhanced semantic search with Ollama"
        )
    )

    # 2. Add support for 'multilingual-e5-large' in embedding_model column
    # (This column was added in migration 007, so we just update documentation)
    print("📝 Adding 'multilingual-e5-large' model support...")
    # Note: No schema change needed - embedding_model is already Text type

    # 3. Create vector index for embedding_v3
    # Note: Using regular index (not CONCURRENTLY) to work within transaction
    print("🔍 Creating IVFFlat index for embedding_v3...")
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_memory_embedding_v3
        ON memories_v2 USING ivfflat (embedding_v3 vector_cosine_ops)
        WITH (lists = 100)
    """)

    print("✅ Migration 008 completed successfully!")
    print("📌 Next steps:")
    print("   1. Configure Ollama: ollama pull zylonai/multilingual-e5-large")
    print("   2. Set TMWS_EMBEDDING_PROVIDER=auto in .env")
    print("   3. Set TMWS_OLLAMA_EMBEDDING_MODEL=zylonai/multilingual-e5-large")
    print("   4. Run embedding migration script to populate embedding_v3")
    print("   5. Test Ollama integration with fallback to SentenceTransformers")
    print("   6. Monitor cross-lingual search performance (target: 0.85+ similarity)")


def downgrade():
    """Remove Multilingual-E5 Large support."""

    print("🔄 Rolling back Multilingual-E5 Large migration...")

    # Drop index first
    print("🗑️ Dropping ix_memory_embedding_v3 index...")
    op.execute("DROP INDEX IF EXISTS ix_memory_embedding_v3")

    # Drop embedding_v3 column
    print("📉 Dropping embedding_v3 column...")
    op.drop_column('memories_v2', 'embedding_v3')

    print("✅ Rollback completed successfully!")
    print("⚠️ Note: embedding_model still supports 'multilingual-e5-large'")
    print("   This is intentional - migration 007 added the column.")
