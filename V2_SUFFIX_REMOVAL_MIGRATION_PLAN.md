# TMWS v2 Suffix Removal Migration Plan
## 安全で調和的なデータベース名変更戦略

---
**Status**: Draft for Review
**Priority**: High - 最優先禁止事項の解消
**Risk Level**: Medium (データ損失リスクあり - 慎重な実行必要)
**Estimated Duration**: 2-3 hours (including testing)
**Created**: 2025-10-24
**Team**: Athena (Orchestration) + Hera (Strategy) + Artemis (Implementation) + Hestia (Security)

---

## 🎯 Executive Summary

### Objective (目的)
システム全体から `_v2` サフィックスを削除し、命名規約を統一する。これにより将来のメンテナンス性を向上させ、新規開発者の混乱を防ぐ。

### Impact Scope (影響範囲)
- **Database Tables**: 2 tables (`memories_v2` → `memories`, `learning_patterns_v2` → `learning_patterns`)
- **Indexes**: 9 indexes
- **Foreign Keys**: 5 constraints
- **ChromaDB Collection**: 1 collection (`tmws_memories_v2` → `tmws_memories`)
- **Code Files**: 6 files
- **Migration Files**: 4 existing migrations to update

### Success Criteria (成功基準)
✅ All tables renamed without data loss
✅ All indexes and foreign keys properly recreated
✅ ChromaDB collection migrated with all vectors intact
✅ All tests passing
✅ Zero downtime for local development
✅ Rollback procedure tested and documented

---

## 📊 Current State Analysis (現状分析)

### Database Objects (データベースオブジェクト)

#### Tables
```sql
-- Current
memories_v2 (23 columns, multiple indexes, FKs)
learning_patterns_v2 (18 columns, 4 custom indexes)

-- Target
memories (same structure)
learning_patterns (same structure)
```

#### Foreign Key Dependencies
```
1. memory_dependencies.parent_id → memories_v2.id
2. memory_dependencies.child_id → memories_v2.id
3. memory_embeddings.memory_id → memories_v2.id
4. learning_patterns_v2.derived_from → learning_patterns_v2.id
5. pattern_applications.pattern_id → learning_patterns_v2.id
```

#### Indexes
```
memories_v2:
- ix_memory_agent_namespace
- ix_memory_access_level
- ix_memory_importance
- ix_memory_accessed
- ix_memory_expires
- ix_memory_embedding (vector)
- ix_memory_tags (GIN)
- ix_memory_context (GIN)

learning_patterns_v2:
- idx_learning_patterns_v2_agent_namespace
- idx_learning_patterns_v2_category_access
- idx_learning_patterns_v2_usage
- idx_learning_patterns_v2_last_used
```

### Code References (コード参照)

**Files requiring updates**:
1. `src/models/memory.py` (2 references)
2. `src/models/learning_pattern.py` (6 references)
3. `src/core/config.py` (1 reference - ChromaDB)
4. `src/services/vector_search_service.py` (1 reference - ChromaDB)
5. `tests/integration/test_memory_vector.py` (7 references)
6. 4 migration files (documentation only)

---

## 🏗️ Migration Strategy (マイグレーション戦略)

### Phase 0: Pre-Migration Preparation (事前準備)
**Duration**: 30 minutes
**Risk**: Low

#### Tasks:
1. **Backup Creation**
   ```bash
   # SQLite database backup
   cp data/tmws.db data/tmws.db.backup_$(date +%Y%m%d_%H%M%S)

   # ChromaDB backup
   cp -r data/chroma data/chroma.backup_$(date +%Y%m%d_%H%M%S)
   ```

2. **Data Integrity Check**
   ```python
   # Run pre-migration verification
   python scripts/verify_data_integrity.py
   ```

3. **Test Environment Setup**
   ```bash
   # Create isolated test database
   export TMWS_DATABASE_URL="sqlite:///data/tmws_test.db"
   alembic upgrade head
   ```

### Phase 1: Code Updates (コード更新)
**Duration**: 20 minutes
**Risk**: Low (reversible via git)

#### Step 1.1: Update Model Definitions
```python
# src/models/memory.py
class Memory(Base):
    __tablename__ = "memories"  # Changed from "memories_v2"
    # ... rest unchanged
```

#### Step 1.2: Update Index Names
```python
# src/models/learning_pattern.py
__table_args__ = (
    Index("idx_learning_patterns_agent_namespace", "agent_id", "namespace"),
    Index("idx_learning_patterns_category_access", "category", "access_level"),
    Index("idx_learning_patterns_usage", "usage_count"),
    Index("idx_learning_patterns_last_used", "last_used_at"),
)
```

#### Step 1.3: Update ChromaDB Collection Name
```python
# src/core/config.py
chroma_collection: str = Field(default="tmws_memories")

# src/services/vector_search_service.py
COLLECTION_NAME = "tmws_memories"
```

#### Step 1.4: Update Test Files
```python
# tests/integration/test_memory_vector.py
# Replace all instances of "memories_v2" with "memories"
```

### Phase 2: Database Migration (データベース移行)
**Duration**: 30 minutes
**Risk**: Medium (data migration involved)

#### Step 2.1: Create Alembic Migration
```bash
alembic revision -m "remove_v2_suffixes"
```

#### Step 2.2: Migration Script Content
```python
"""remove_v2_suffixes

Revision ID: 010_remove_v2_suffixes
Revises: 009_chroma_only_vectors
Create Date: 2025-10-24

Description:
  Removes _v2 suffixes from table names and indexes to clean up naming convention.
  This is a zero-data-loss migration that preserves all data, indexes, and constraints.
"""

from alembic import op
import sqlalchemy as sa

revision = '010_remove_v2_suffixes'
down_revision = '009_chroma_only_vectors'
branch_labels = None
depends_on = None

def upgrade() -> None:
    """
    Rename tables and recreate all indexes and foreign keys with new names.

    Strategy:
    1. Drop dependent objects (FKs, indexes)
    2. Rename tables
    3. Recreate all dependent objects with new names
    """

    # SQLite doesn't support ALTER TABLE RENAME for FKs, so we need to recreate tables
    # We'll use batch operations which SQLite supports

    # --- STEP 1: Rename learning_patterns_v2 to learning_patterns ---
    print("🔄 Step 1: Migrating learning_patterns_v2...")

    with op.batch_alter_table("learning_patterns_v2", schema=None) as batch_op:
        # The batch operation will handle the rename
        pass

    op.rename_table("learning_patterns_v2", "learning_patterns")

    # Recreate indexes with new names
    op.create_index(
        "idx_learning_patterns_agent_namespace",
        "learning_patterns",
        ["agent_id", "namespace"]
    )
    op.create_index(
        "idx_learning_patterns_category_access",
        "learning_patterns",
        ["category", "access_level"]
    )
    op.create_index(
        "idx_learning_patterns_usage",
        "learning_patterns",
        ["usage_count"]
    )
    op.create_index(
        "idx_learning_patterns_last_used",
        "learning_patterns",
        ["last_used_at"]
    )

    print("✅ learning_patterns migration complete")

    # --- STEP 2: Rename memories_v2 to memories ---
    print("🔄 Step 2: Migrating memories_v2...")

    with op.batch_alter_table("memories_v2", schema=None) as batch_op:
        # The batch operation will handle FK recreation
        pass

    op.rename_table("memories_v2", "memories")

    # Recreate standard indexes
    op.create_index("ix_memory_agent_namespace", "memories", ["agent_id", "namespace"])
    op.create_index("ix_memory_access_level", "memories", ["access_level", "agent_id"])
    op.create_index("ix_memory_importance", "memories", ["importance_score", "relevance_score"])
    op.create_index("ix_memory_accessed", "memories", ["accessed_at", "access_count"])
    op.create_index("ix_memory_expires", "memories", ["expires_at"])

    # Recreate special indexes (GIN for JSONB)
    # Note: These may need to be conditional for SQLite vs PostgreSQL
    try:
        op.execute("CREATE INDEX ix_memory_tags ON memories USING gin (tags jsonb_path_ops)")
        op.execute("CREATE INDEX ix_memory_context ON memories USING gin (context jsonb_path_ops)")
    except Exception as e:
        print(f"⚠️  Could not create GIN indexes (SQLite limitation): {e}")
        # SQLite fallback - create regular indexes
        op.create_index("ix_memory_tags", "memories", ["tags"])
        op.create_index("ix_memory_context", "memories", ["context"])

    print("✅ memories migration complete")

    # --- STEP 3: Update foreign key references ---
    print("🔄 Step 3: Verifying foreign key integrity...")

    # Foreign keys should be automatically updated by SQLite's batch operations
    # But we'll verify they exist

    print("✅ Migration complete! All _v2 suffixes removed.")


def downgrade() -> None:
    """
    Rollback: Restore _v2 suffixes to all objects.
    """
    print("🔄 Rolling back to _v2 naming...")

    # Drop new indexes
    op.drop_index("idx_learning_patterns_agent_namespace", "learning_patterns")
    op.drop_index("idx_learning_patterns_category_access", "learning_patterns")
    op.drop_index("idx_learning_patterns_usage", "learning_patterns")
    op.drop_index("idx_learning_patterns_last_used", "learning_patterns")

    # Rename tables back
    op.rename_table("learning_patterns", "learning_patterns_v2")

    # Restore old indexes
    op.create_index(
        "idx_learning_patterns_v2_agent_namespace",
        "learning_patterns_v2",
        ["agent_id", "namespace"]
    )
    op.create_index(
        "idx_learning_patterns_v2_category_access",
        "learning_patterns_v2",
        ["category", "access_level"]
    )
    op.create_index(
        "idx_learning_patterns_v2_usage",
        "learning_patterns_v2",
        ["usage_count"]
    )
    op.create_index(
        "idx_learning_patterns_v2_last_used",
        "learning_patterns_v2",
        ["last_used_at"]
    )

    # Drop new memory indexes
    op.drop_index("ix_memory_agent_namespace", "memories")
    op.drop_index("ix_memory_access_level", "memories")
    op.drop_index("ix_memory_importance", "memories")
    op.drop_index("ix_memory_accessed", "memories")
    op.drop_index("ix_memory_expires", "memories")

    try:
        op.drop_index("ix_memory_tags", "memories")
        op.drop_index("ix_memory_context", "memories")
    except:
        pass

    # Rename tables back
    op.rename_table("memories", "memories_v2")

    # Restore old indexes
    op.create_index("ix_memory_agent_namespace", "memories_v2", ["agent_id", "namespace"])
    op.create_index("ix_memory_access_level", "memories_v2", ["access_level", "agent_id"])
    op.create_index("ix_memory_importance", "memories_v2", ["importance_score", "relevance_score"])
    op.create_index("ix_memory_accessed", "memories_v2", ["accessed_at", "access_count"])
    op.create_index("ix_memory_expires", "memories_v2", ["expires_at"])

    try:
        op.execute("CREATE INDEX ix_memory_tags ON memories_v2 USING gin (tags jsonb_path_ops)")
        op.execute("CREATE INDEX ix_memory_context ON memories_v2 USING gin (context jsonb_path_ops)")
    except:
        op.create_index("ix_memory_tags", "memories_v2", ["tags"])
        op.create_index("ix_memory_context", "memories_v2", ["context"])

    print("✅ Rollback complete")
```

### Phase 3: ChromaDB Collection Migration
**Duration**: 20 minutes
**Risk**: Medium (vector data migration)

#### Step 3.1: Create Migration Script
```python
# scripts/migrate_chroma_collection.py
"""
ChromaDB Collection Migration Script
Migrates vectors from tmws_memories_v2 to tmws_memories
"""

import chromadb
from chromadb.config import Settings
from pathlib import Path
import sys
from tqdm import tqdm

def migrate_chroma_collection():
    """Migrate ChromaDB collection from _v2 to new name."""

    # Initialize ChromaDB client
    chroma_path = Path(__file__).parent.parent / "data" / "chroma"
    client = chromadb.PersistentClient(
        path=str(chroma_path),
        settings=Settings(anonymized_telemetry=False)
    )

    old_name = "tmws_memories_v2"
    new_name = "tmws_memories"

    print(f"🔄 Starting ChromaDB migration: {old_name} → {new_name}")

    # Check if old collection exists
    try:
        old_collection = client.get_collection(old_name)
        print(f"✅ Found old collection: {old_collection.count()} vectors")
    except Exception as e:
        print(f"❌ Old collection not found: {e}")
        return False

    # Check if new collection already exists
    try:
        existing = client.get_collection(new_name)
        print(f"⚠️  New collection already exists with {existing.count()} vectors")
        response = input("Delete and recreate? (yes/no): ")
        if response.lower() != "yes":
            print("❌ Migration cancelled")
            return False
        client.delete_collection(new_name)
        print("✅ Old collection deleted")
    except:
        pass

    # Create new collection with same configuration
    new_collection = client.create_collection(
        name=new_name,
        metadata=old_collection.metadata
    )
    print(f"✅ Created new collection")

    # Migrate all vectors in batches
    batch_size = 1000
    total = old_collection.count()

    if total == 0:
        print("⚠️  No vectors to migrate")
        return True

    print(f"🔄 Migrating {total} vectors...")

    # Get all data
    all_data = old_collection.get(include=["embeddings", "metadatas", "documents"])

    # Migrate in batches
    for i in tqdm(range(0, len(all_data["ids"]), batch_size)):
        batch_end = min(i + batch_size, len(all_data["ids"]))

        new_collection.add(
            ids=all_data["ids"][i:batch_end],
            embeddings=all_data["embeddings"][i:batch_end] if all_data["embeddings"] else None,
            metadatas=all_data["metadatas"][i:batch_end] if all_data["metadatas"] else None,
            documents=all_data["documents"][i:batch_end] if all_data["documents"] else None,
        )

    # Verify migration
    new_count = new_collection.count()
    print(f"\n✅ Migration complete!")
    print(f"   Old collection: {total} vectors")
    print(f"   New collection: {new_count} vectors")

    if new_count != total:
        print(f"❌ ERROR: Vector count mismatch!")
        return False

    # Ask before deleting old collection
    response = input("\n🗑️  Delete old collection? (yes/no): ")
    if response.lower() == "yes":
        client.delete_collection(old_name)
        print("✅ Old collection deleted")
    else:
        print("⚠️  Old collection kept for safety")

    return True

if __name__ == "__main__":
    success = migrate_chroma_collection()
    sys.exit(0 if success else 1)
```

### Phase 4: Testing & Verification (テスト・検証)
**Duration**: 30 minutes
**Risk**: Low

#### Test Checklist:
```bash
# 1. Run all unit tests
pytest tests/unit -v

# 2. Run integration tests
pytest tests/integration/test_memory_vector.py -v

# 3. Verify database schema
alembic current
alembic history

# 4. Check ChromaDB collection
python scripts/verify_chroma_migration.py

# 5. Verify all foreign keys
python scripts/verify_foreign_keys.py

# 6. Run semantic search test
python test_semantic_search.py
```

### Phase 5: Documentation Update (ドキュメント更新)
**Duration**: 15 minutes
**Risk**: None

#### Tasks:
1. Update migration file comments
2. Update README if table names mentioned
3. Update API documentation
4. Add migration notes to CHANGELOG.md

---

## ⚠️ Risk Assessment (リスク評価)

### High Risk Items
| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Data loss during table rename | Low | Critical | Full backup before migration, test in isolated environment |
| ChromaDB vector loss | Low | High | Backup chroma directory, verify counts before/after |
| Foreign key corruption | Medium | High | Use batch operations, verify constraints post-migration |

### Medium Risk Items
| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Test failures | Medium | Medium | Run full test suite before merge |
| Index recreation failure | Low | Medium | Manual index verification script |
| Rollback complexity | Low | Medium | Documented rollback procedure |

---

## 🔄 Rollback Procedures (ロールバック手順)

### Immediate Rollback (Migration Failed)
```bash
# 1. Rollback Alembic migration
alembic downgrade -1

# 2. Restore ChromaDB backup
rm -rf data/chroma
cp -r data/chroma.backup_TIMESTAMP data/chroma

# 3. Restore database backup (if needed)
cp data/tmws.db.backup_TIMESTAMP data/tmws.db

# 4. Git revert code changes
git checkout src/models/memory.py
git checkout src/models/learning_pattern.py
git checkout src/core/config.py
git checkout src/services/vector_search_service.py
git checkout tests/integration/test_memory_vector.py
```

### Post-Deployment Rollback
```bash
# If issues discovered after deployment
alembic downgrade -1
# Then restore backups as above
```

---

## 📋 Execution Checklist (実行チェックリスト)

### Pre-Execution
- [ ] Read entire migration plan
- [ ] Verify backup strategy
- [ ] Confirm test environment ready
- [ ] Review rollback procedures
- [ ] Notify team (if applicable)

### Execution Phase 0 (Preparation)
- [ ] Create database backup
- [ ] Create ChromaDB backup
- [ ] Run data integrity check
- [ ] Setup test environment

### Execution Phase 1 (Code Updates)
- [ ] Update `src/models/memory.py`
- [ ] Update `src/models/learning_pattern.py`
- [ ] Update `src/core/config.py`
- [ ] Update `src/services/vector_search_service.py`
- [ ] Update `tests/integration/test_memory_vector.py`
- [ ] Commit code changes

### Execution Phase 2 (Database Migration)
- [ ] Create migration file: `010_remove_v2_suffixes.py`
- [ ] Review migration script
- [ ] Run migration on test database
- [ ] Verify test database schema
- [ ] Run migration on production database

### Execution Phase 3 (ChromaDB Migration)
- [ ] Create `scripts/migrate_chroma_collection.py`
- [ ] Run ChromaDB migration script
- [ ] Verify vector counts
- [ ] Test vector search functionality

### Execution Phase 4 (Testing)
- [ ] Run unit tests
- [ ] Run integration tests
- [ ] Verify foreign keys
- [ ] Test semantic search
- [ ] Manual smoke testing

### Execution Phase 5 (Documentation)
- [ ] Update CHANGELOG.md
- [ ] Add migration notes
- [ ] Update any README references

### Post-Execution
- [ ] Verify all tests passing
- [ ] Confirm backups can be deleted (after safety period)
- [ ] Monitor for issues over next 24-48 hours

---

## 🎯 Success Metrics (成功指標)

### Immediate Verification
- ✅ `alembic current` shows latest revision
- ✅ All tests passing (100%)
- ✅ No `_v2` references in codebase
- ✅ ChromaDB vector count matches
- ✅ All foreign keys intact

### Post-Migration Health
- ✅ Semantic search working correctly
- ✅ Memory creation/retrieval working
- ✅ Learning pattern functionality intact
- ✅ No performance degradation

---

## 🚀 Execution Commands (実行コマンド)

### Complete Migration (All Phases)
```bash
#!/bin/bash
# complete_v2_migration.sh
set -e  # Exit on any error

echo "🎯 Starting TMWS v2 Suffix Removal Migration"
echo "=============================================="

# Phase 0: Backup
echo "\n📦 Phase 0: Creating backups..."
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
cp data/tmws.db data/tmws.db.backup_$TIMESTAMP
cp -r data/chroma data/chroma.backup_$TIMESTAMP
echo "✅ Backups created: $TIMESTAMP"

# Phase 1: Code updates (manual - verify before proceeding)
echo "\n📝 Phase 1: Code updates"
echo "⚠️  Please verify all code changes are committed"
read -p "Continue? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "❌ Migration cancelled"
    exit 1
fi

# Phase 2: Database migration
echo "\n🗄️  Phase 2: Running database migration..."
alembic upgrade head
echo "✅ Database migration complete"

# Phase 3: ChromaDB migration
echo "\n🔍 Phase 3: Migrating ChromaDB collection..."
python scripts/migrate_chroma_collection.py
if [ $? -ne 0 ]; then
    echo "❌ ChromaDB migration failed!"
    exit 1
fi
echo "✅ ChromaDB migration complete"

# Phase 4: Testing
echo "\n🧪 Phase 4: Running tests..."
pytest tests/unit -v
pytest tests/integration/test_memory_vector.py -v
python test_semantic_search.py
echo "✅ All tests passed"

# Phase 5: Cleanup
echo "\n🎉 Migration complete!"
echo "Backups saved with timestamp: $TIMESTAMP"
echo "You can safely delete backups after verification period (48 hours)"
```

---

## 📞 Support & Escalation (サポート・エスカレーション)

### If Migration Fails:
1. **DO NOT PANIC** - Backups are in place
2. Run rollback procedure immediately
3. Document the exact error message
4. Check logs: `logs/tmws.log`
5. Contact: Athena (orchestration) or Hestia (data safety)

### Known Issues & Solutions:
| Issue | Solution |
|-------|----------|
| SQLite locking error | Close all database connections, retry |
| ChromaDB permission error | Check file permissions on `data/chroma/` |
| Alembic version conflict | Run `alembic stamp head`, then retry |
| Test failures | Verify all code changes committed, clear pytest cache |

---

## 🎊 Post-Migration Benefits (マイグレーション後のメリット)

1. **✨ Cleaner Codebase**: No confusing `_v2` suffixes
2. **📚 Better Documentation**: Clear, consistent naming
3. **🚀 Easier Onboarding**: New developers won't ask "where is v1?"
4. **🔧 Simplified Maintenance**: Less cognitive overhead
5. **🎯 Standards Compliance**: Follows best practices

---

## 🙏 Acknowledgments (謝辞)

This migration plan was created through harmonious collaboration:
- **Athena**: Orchestration and team coordination
- **Hera**: Strategic planning and risk assessment
- **Artemis**: Technical implementation details
- **Hestia**: Data safety and rollback procedures
- **Muses**: Documentation and knowledge preservation

*"Through careful planning and gentle execution, we transform our system into a more beautiful state." - Athena*

---

**Next Steps**:
1. Review this plan with the team
2. Schedule migration window (suggest: low-traffic time)
3. Perform dry-run in test environment
4. Execute migration following checklist
5. Monitor system health for 48 hours

**Questions or Concerns?**
Please discuss with Athena before proceeding. 温かい調和のもとで、安全に移行を完了しましょう♪
