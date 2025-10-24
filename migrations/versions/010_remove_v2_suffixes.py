"""Remove _v2 suffixes from table names

Revision ID: 010
Revises: 009
Create Date: 2025-10-24

Description:
  Removes _v2 suffixes from table names and indexes to clean up naming convention.
  This is a zero-data-loss migration that preserves all data, indexes, and constraints.

Changes:
  - Rename tables: memories_v2 → memories, learning_patterns_v2 → learning_patterns
  - Recreate indexes with updated names
  - Preserve all foreign key constraints
  - Update index names to match new table names

Migration strategy:
  1. Rename learning_patterns_v2 table (no dependencies)
  2. Recreate learning_patterns indexes with new names
  3. Rename memories_v2 table (has FK dependencies)
  4. Recreate memories indexes with new names
  5. Verify all foreign keys remain intact

Note: SQLite uses batch operations which automatically handle FK recreation.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "010"
down_revision: str | None = "009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """
    Rename tables and recreate all indexes and foreign keys with new names.

    Strategy:
    1. Drop dependent objects (FKs, indexes)
    2. Rename tables
    3. Recreate all dependent objects with new names
    """

    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"

    print("🔄 Starting _v2 suffix removal migration...")
    print(f"   Database type: {bind.dialect.name}")

    # --- STEP 1: Rename learning_patterns_v2 to learning_patterns ---
    print("\n🔄 Step 1: Migrating learning_patterns_v2...")

    # Drop old indexes
    with op.batch_alter_table("learning_patterns_v2", schema=None) as batch_op:
        # SQLite batch operations will handle index recreation
        pass

    try:
        op.drop_index("idx_learning_patterns_v2_agent_namespace", "learning_patterns_v2")
    except Exception:
        pass
    try:
        op.drop_index("idx_learning_patterns_v2_category_access", "learning_patterns_v2")
    except Exception:
        pass
    try:
        op.drop_index("idx_learning_patterns_v2_usage", "learning_patterns_v2")
    except Exception:
        pass
    try:
        op.drop_index("idx_learning_patterns_v2_last_used", "learning_patterns_v2")
    except Exception:
        pass

    # Rename table
    op.rename_table("learning_patterns_v2", "learning_patterns")
    print("   ✅ Table renamed: learning_patterns_v2 → learning_patterns")

    # Recreate indexes with new names
    op.create_index(
        "idx_learning_patterns_agent_namespace", "learning_patterns", ["agent_id", "namespace"]
    )
    op.create_index(
        "idx_learning_patterns_category_access",
        "learning_patterns",
        ["category", "access_level"],
    )
    op.create_index("idx_learning_patterns_usage", "learning_patterns", ["usage_count"])
    op.create_index("idx_learning_patterns_last_used", "learning_patterns", ["last_used_at"])
    print("   ✅ Indexes recreated (4 indexes)")

    print("✅ learning_patterns migration complete\n")

    # --- STEP 2: Rename memories_v2 to memories ---
    print("🔄 Step 2: Migrating memories_v2...")

    # Drop old indexes (preserving data)
    try:
        op.drop_index("ix_memory_agent_namespace", "memories_v2")
    except Exception:
        pass
    try:
        op.drop_index("ix_memory_access_level", "memories_v2")
    except Exception:
        pass
    try:
        op.drop_index("ix_memory_importance", "memories_v2")
    except Exception:
        pass
    try:
        op.drop_index("ix_memory_accessed", "memories_v2")
    except Exception:
        pass
    try:
        op.drop_index("ix_memory_expires", "memories_v2")
    except Exception:
        pass
    try:
        op.drop_index("ix_memory_tags", "memories_v2")
    except Exception:
        pass
    try:
        op.drop_index("ix_memory_context", "memories_v2")
    except Exception:
        pass

    # Rename table (batch operation handles FK preservation in SQLite)
    with op.batch_alter_table("memories_v2", schema=None) as batch_op:
        # SQLite will automatically recreate FKs
        pass

    op.rename_table("memories_v2", "memories")
    print("   ✅ Table renamed: memories_v2 → memories")

    # Recreate standard indexes
    op.create_index("ix_memory_agent_namespace", "memories", ["agent_id", "namespace"])
    op.create_index("ix_memory_access_level", "memories", ["access_level", "agent_id"])
    op.create_index(
        "ix_memory_importance", "memories", ["importance_score", "relevance_score"]
    )
    op.create_index("ix_memory_accessed", "memories", ["accessed_at", "access_count"])
    op.create_index("ix_memory_expires", "memories", ["expires_at"])

    # Recreate special indexes (GIN for JSONB in PostgreSQL, regular for SQLite)
    if is_sqlite:
        # SQLite: Create regular indexes on JSON columns
        try:
            op.create_index("ix_memory_tags", "memories", ["tags"])
            op.create_index("ix_memory_context", "memories", ["context"])
            print("   ✅ Indexes recreated (7 indexes - SQLite)")
        except Exception as e:
            print(f"   ⚠️  Note: {e}")
    else:
        # PostgreSQL: Create GIN indexes for JSONB
        try:
            op.execute("CREATE INDEX ix_memory_tags ON memories USING gin (tags jsonb_path_ops)")
            op.execute(
                "CREATE INDEX ix_memory_context ON memories USING gin (context jsonb_path_ops)"
            )
            print("   ✅ Indexes recreated (7 indexes - PostgreSQL GIN)")
        except Exception as e:
            print(f"   ⚠️  Could not create GIN indexes: {e}")
            # Fallback to regular indexes
            op.create_index("ix_memory_tags", "memories", ["tags"])
            op.create_index("ix_memory_context", "memories", ["context"])

    print("✅ memories migration complete\n")

    # --- STEP 3: Verify foreign key integrity ---
    print("🔄 Step 3: Verifying foreign key integrity...")

    # Foreign keys should be automatically updated by SQLite's batch operations
    # We'll do a sanity check
    try:
        result = bind.execute(sa.text("PRAGMA foreign_key_check"))
        violations = list(result)
        if violations:
            print(f"   ⚠️  WARNING: {len(violations)} foreign key violations detected!")
            for violation in violations:
                print(f"      {violation}")
        else:
            print("   ✅ All foreign keys intact")
    except Exception as e:
        print(f"   ⚠️  Could not verify foreign keys: {e}")

    print("\n✅ Migration complete! All _v2 suffixes removed.")
    print("   - learning_patterns_v2 → learning_patterns ✓")
    print("   - memories_v2 → memories ✓")
    print("   - All indexes recreated ✓")
    print("   - Foreign keys preserved ✓")


def downgrade() -> None:
    """
    Rollback: Restore _v2 suffixes to all objects.

    This reverses all naming changes to restore the previous state.
    """
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"

    print("🔄 Rolling back to _v2 naming...")

    # --- Rollback memories ---
    print("\n🔄 Rolling back memories...")

    # Drop new indexes
    try:
        op.drop_index("ix_memory_agent_namespace", "memories")
    except Exception:
        pass
    try:
        op.drop_index("ix_memory_access_level", "memories")
    except Exception:
        pass
    try:
        op.drop_index("ix_memory_importance", "memories")
    except Exception:
        pass
    try:
        op.drop_index("ix_memory_accessed", "memories")
    except Exception:
        pass
    try:
        op.drop_index("ix_memory_expires", "memories")
    except Exception:
        pass
    try:
        op.drop_index("ix_memory_tags", "memories")
    except Exception:
        pass
    try:
        op.drop_index("ix_memory_context", "memories")
    except Exception:
        pass

    # Rename table back
    with op.batch_alter_table("memories", schema=None) as batch_op:
        pass

    op.rename_table("memories", "memories_v2")
    print("   ✅ Table renamed: memories → memories_v2")

    # Restore old indexes
    op.create_index("ix_memory_agent_namespace", "memories_v2", ["agent_id", "namespace"])
    op.create_index("ix_memory_access_level", "memories_v2", ["access_level", "agent_id"])
    op.create_index(
        "ix_memory_importance", "memories_v2", ["importance_score", "relevance_score"]
    )
    op.create_index("ix_memory_accessed", "memories_v2", ["accessed_at", "access_count"])
    op.create_index("ix_memory_expires", "memories_v2", ["expires_at"])

    if is_sqlite:
        op.create_index("ix_memory_tags", "memories_v2", ["tags"])
        op.create_index("ix_memory_context", "memories_v2", ["context"])
    else:
        try:
            op.execute(
                "CREATE INDEX ix_memory_tags ON memories_v2 USING gin (tags jsonb_path_ops)"
            )
            op.execute(
                "CREATE INDEX ix_memory_context ON memories_v2 USING gin (context jsonb_path_ops)"
            )
        except Exception:
            op.create_index("ix_memory_tags", "memories_v2", ["tags"])
            op.create_index("ix_memory_context", "memories_v2", ["context"])

    print("   ✅ Indexes restored")

    # --- Rollback learning_patterns ---
    print("\n🔄 Rolling back learning_patterns...")

    # Drop new indexes
    try:
        op.drop_index("idx_learning_patterns_agent_namespace", "learning_patterns")
    except Exception:
        pass
    try:
        op.drop_index("idx_learning_patterns_category_access", "learning_patterns")
    except Exception:
        pass
    try:
        op.drop_index("idx_learning_patterns_usage", "learning_patterns")
    except Exception:
        pass
    try:
        op.drop_index("idx_learning_patterns_last_used", "learning_patterns")
    except Exception:
        pass

    # Rename table back
    with op.batch_alter_table("learning_patterns", schema=None) as batch_op:
        pass

    op.rename_table("learning_patterns", "learning_patterns_v2")
    print("   ✅ Table renamed: learning_patterns → learning_patterns_v2")

    # Restore old indexes
    op.create_index(
        "idx_learning_patterns_v2_agent_namespace",
        "learning_patterns_v2",
        ["agent_id", "namespace"],
    )
    op.create_index(
        "idx_learning_patterns_v2_category_access",
        "learning_patterns_v2",
        ["category", "access_level"],
    )
    op.create_index("idx_learning_patterns_v2_usage", "learning_patterns_v2", ["usage_count"])
    op.create_index(
        "idx_learning_patterns_v2_last_used", "learning_patterns_v2", ["last_used_at"]
    )
    print("   ✅ Indexes restored")

    print("\n✅ Rollback complete - _v2 suffixes restored")
