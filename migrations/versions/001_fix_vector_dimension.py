"""Initial database schema with 384-dimension vectors for all-MiniLM-L6-v2

Revision ID: 001_fix_vector_dimension
Revises:
Create Date: 2024-01-01 10:00:00.000000

"""
import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    """Create initial schema or upgrade to 384-dimension vectors for all-MiniLM-L6-v2."""
    # Enable pgvector extension
    op.execute("CREATE EXTENSION IF NOT EXISTS vector;")

    # Check if memories table exists
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    if 'memories' not in tables:
        # New installation - create tables using SQLAlchemy metadata
        from src.models.base import Base
        Base.metadata.create_all(bind=conn)
    else:
        # Existing installation - update vector dimension
        # Drop existing vector index if it exists
        op.execute("DROP INDEX IF EXISTS idx_memories_embedding;")

        # Check if embedding column exists
        columns = [col['name'] for col in inspector.get_columns('memories')]
        if 'embedding' in columns:
            # Drop the embedding column with old dimension
            op.drop_column('memories', 'embedding')

        # Add the embedding column with correct dimension
        op.add_column('memories',
            sa.Column('embedding',
                     Vector(384),
                     nullable=True,
                     comment="Vector embedding for semantic search (all-MiniLM-L6-v2 dimension)")
        )

        # Recreate the vector index with proper dimension
        op.execute("""
            CREATE INDEX idx_memories_embedding
            ON memories USING ivfflat (embedding vector_cosine_ops)
            WITH (lists = 100);
        """)


def downgrade():
    """Downgrade to 1536-dimension vectors (OpenAI ada-002)."""
    # Drop existing vector index
    op.execute("DROP INDEX IF EXISTS idx_memories_embedding;")

    # Drop the embedding column with 384 dimension
    op.drop_column('memories', 'embedding')

    # Add the embedding column with old dimension
    op.add_column('memories',
        sa.Column('embedding',
                 Vector(1536),
                 nullable=True,
                 comment="Vector embedding for semantic search (OpenAI ada-002 dimension)")
    )

    # Recreate the vector index with old dimension
    op.execute("""
        CREATE INDEX idx_memories_embedding
        ON memories USING ivfflat (embedding vector_cosine_ops)
        WITH (lists = 100);
    """)
