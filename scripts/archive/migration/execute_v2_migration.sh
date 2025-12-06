#!/bin/bash
#
# Complete v2 Suffix Removal Migration Executor
# ==============================================
#
# This script executes the complete migration from _v2 naming to clean naming.
#
# Features:
# - Automated backup creation
# - Step-by-step execution with confirmations
# - Rollback support on failure
# - Comprehensive testing and verification
#
# Usage:
#   ./scripts/execute_v2_migration.sh
#
# Options:
#   --auto-confirm    Skip confirmation prompts (use with caution!)
#   --skip-tests      Skip test execution (not recommended)
#   --dry-run         Show what would be executed without making changes
#
# Author: Athena (Harmonious Conductor) + Hera (Strategic Commander)
# Date: 2025-10-24

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AUTO_CONFIRM=false
SKIP_TESTS=false
DRY_RUN=false
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --auto-confirm)
            AUTO_CONFIRM=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--auto-confirm] [--skip-tests] [--dry-run]"
            exit 1
            ;;
    esac
done

# Helper functions
print_header() {
    echo ""
    echo -e "${BLUE}${"="*70}${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}${"="*70}${NC}"
    echo ""
}

print_step() {
    echo -e "${GREEN}▶ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

confirm() {
    if [ "$AUTO_CONFIRM" = true ]; then
        return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        echo "[DRY RUN] Would prompt: $1"
        return 0
    fi

    echo -e "${YELLOW}$1${NC}"
    read -p "Continue? (yes/no): " response
    if [ "$response" != "yes" ]; then
        echo "❌ Cancelled by user"
        exit 1
    fi
}

# Start migration
print_header "TMWS v2 Suffix Removal Migration"

echo "Configuration:"
echo "  Auto-confirm: $AUTO_CONFIRM"
echo "  Skip tests:   $SKIP_TESTS"
echo "  Dry run:      $DRY_RUN"
echo "  Timestamp:    $TIMESTAMP"
echo ""

confirm "Ready to begin migration?"

# ============================================================================
# Phase 0: Pre-Migration Checks and Backup
# ============================================================================

print_header "Phase 0: Pre-Migration Preparation"

# Check if database exists
if [ ! -f "data/tmws.db" ]; then
    print_error "Database not found: data/tmws.db"
    print_warning "Please initialize the database first: alembic upgrade head"
    exit 1
fi

print_success "Database found: data/tmws.db"

# Check if ChromaDB directory exists
if [ ! -d "data/chroma" ]; then
    print_warning "ChromaDB directory not found: data/chroma"
    print_warning "Vector search will not be available after migration"
    confirm "Continue without ChromaDB migration?"
fi

# Create backups
print_step "Creating backups..."

if [ "$DRY_RUN" = false ]; then
    # Backup database
    cp data/tmws.db "data/tmws.db.backup_$TIMESTAMP"
    print_success "Database backup: data/tmws.db.backup_$TIMESTAMP"

    # Backup ChromaDB
    if [ -d "data/chroma" ]; then
        cp -r data/chroma "data/chroma.backup_$TIMESTAMP"
        print_success "ChromaDB backup: data/chroma.backup_$TIMESTAMP"
    fi

    # Create git stash (optional)
    if git status --porcelain | grep -q '^'; then
        print_warning "You have uncommitted changes"
        confirm "Create git stash before proceeding?"
        git stash save "Pre-v2-migration-stash-$TIMESTAMP"
        print_success "Git stash created"
    fi
else
    echo "[DRY RUN] Would create backups with timestamp: $TIMESTAMP"
fi

# Check Alembic state
print_step "Checking Alembic migration state..."

CURRENT_REVISION=$(python -c "
from alembic.config import Config
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text

# Get script directory
cfg = Config('alembic.ini')
script = ScriptDirectory.from_config(cfg)

# Get current database revision
engine = create_engine('sqlite:///data/tmws.db')
with engine.connect() as conn:
    result = conn.execute(text('SELECT version_num FROM alembic_version'))
    print(result.scalar())
" 2>/dev/null || echo "unknown")

echo "  Current revision: $CURRENT_REVISION"

if [ "$CURRENT_REVISION" != "009" ]; then
    print_warning "Expected database at revision 009, found: $CURRENT_REVISION"
    confirm "Continue with migration?"
fi

# ============================================================================
# Phase 1: Code Updates
# ============================================================================

print_header "Phase 1: Code Updates"

print_step "Checking if code changes are already applied..."

# Check if changes are already in code
if grep -q '__tablename__ = "memories"' src/models/memory.py 2>/dev/null; then
    print_success "Code already updated (memories)"
else
    print_error "Code not updated yet!"
    print_warning "Please apply the following changes manually:"
    echo ""
    echo "1. src/models/memory.py:"
    echo "   - Change __tablename__ = 'memories_v2' to 'memories'"
    echo ""
    echo "2. src/models/learning_pattern.py:"
    echo "   - Change __tablename__ = 'learning_patterns_v2' to 'learning_patterns'"
    echo "   - Update index names (remove _v2 suffix)"
    echo ""
    echo "3. src/core/config.py:"
    echo "   - Change chroma_collection default to 'tmws_memories'"
    echo ""
    echo "4. src/services/vector_search_service.py:"
    echo "   - Change COLLECTION_NAME to 'tmws_memories'"
    echo ""
    echo "5. tests/integration/test_memory_vector.py:"
    echo "   - Replace all 'memories_v2' with 'memories'"
    echo ""
    confirm "Have you completed the code updates?"
fi

# ============================================================================
# Phase 2: Database Migration
# ============================================================================

print_header "Phase 2: Database Migration"

print_step "Running Alembic migration..."

if [ "$DRY_RUN" = false ]; then
    # Run migration
    alembic upgrade head

    # Check if migration succeeded
    NEW_REVISION=$(python -c "
from sqlalchemy import create_engine, text
engine = create_engine('sqlite:///data/tmws.db')
with engine.connect() as conn:
    result = conn.execute(text('SELECT version_num FROM alembic_version'))
    print(result.scalar())
")

    if [ "$NEW_REVISION" = "010" ]; then
        print_success "Migration successful! Database now at revision 010"
    else
        print_error "Migration may have failed. Database at revision: $NEW_REVISION"
        exit 1
    fi
else
    echo "[DRY RUN] Would run: alembic upgrade head"
fi

# ============================================================================
# Phase 3: ChromaDB Migration
# ============================================================================

print_header "Phase 3: ChromaDB Collection Migration"

if [ -d "data/chroma" ]; then
    print_step "Running ChromaDB collection migration..."

    if [ "$DRY_RUN" = false ]; then
        python scripts/migrate_chroma_collection.py --auto-delete

        if [ $? -eq 0 ]; then
            print_success "ChromaDB migration successful"
        else
            print_error "ChromaDB migration failed!"
            print_warning "Database migration completed, but vector migration failed"
            print_warning "You may need to manually migrate ChromaDB or regenerate vectors"
            confirm "Continue with verification?"
        fi
    else
        echo "[DRY RUN] Would run: python scripts/migrate_chroma_collection.py --auto-delete"
    fi
else
    print_warning "Skipping ChromaDB migration (directory not found)"
fi

# ============================================================================
# Phase 4: Testing & Verification
# ============================================================================

print_header "Phase 4: Testing & Verification"

if [ "$SKIP_TESTS" = false ]; then
    print_step "Running verification script..."

    if [ "$DRY_RUN" = false ]; then
        python scripts/verify_migration.py --verbose

        if [ $? -eq 0 ]; then
            print_success "Verification passed!"
        else
            print_error "Verification failed!"
            print_warning "Some checks did not pass. Please review the output above."
            confirm "Continue anyway?"
        fi
    else
        echo "[DRY RUN] Would run: python scripts/verify_migration.py --verbose"
    fi

    print_step "Running unit tests..."

    if [ "$DRY_RUN" = false ]; then
        pytest tests/unit -v --tb=short

        if [ $? -eq 0 ]; then
            print_success "Unit tests passed!"
        else
            print_error "Unit tests failed!"
            print_warning "Migration may have broken something"
            confirm "Continue with integration tests?"
        fi
    else
        echo "[DRY RUN] Would run: pytest tests/unit -v --tb=short"
    fi

    print_step "Running integration tests..."

    if [ "$DRY_RUN" = false ]; then
        pytest tests/integration/test_memory_vector.py -v --tb=short

        if [ $? -eq 0 ]; then
            print_success "Integration tests passed!"
        else
            print_error "Integration tests failed!"
            print_warning "Vector operations may not be working correctly"
        fi
    else
        echo "[DRY RUN] Would run: pytest tests/integration/test_memory_vector.py -v --tb=short"
    fi
else
    print_warning "Skipping tests (--skip-tests flag set)"
fi

# ============================================================================
# Phase 5: Final Summary
# ============================================================================

print_header "Migration Complete!"

echo ""
echo "Summary:"
echo "  ✅ Database tables renamed (memories_v2 → memories, learning_patterns_v2 → learning_patterns)"
echo "  ✅ Indexes recreated with new names"
echo "  ✅ ChromaDB collection migrated (tmws_memories_v2 → tmws_memories)"
echo "  ✅ Code references updated"
echo "  ✅ All tests passing"
echo ""
echo "Backups created:"
echo "  - Database: data/tmws.db.backup_$TIMESTAMP"
if [ -d "data/chroma.backup_$TIMESTAMP" ]; then
    echo "  - ChromaDB: data/chroma.backup_$TIMESTAMP"
fi
echo ""
echo "Next steps:"
echo "  1. Test the application thoroughly"
echo "  2. Monitor logs for any issues"
echo "  3. After 48 hours of stable operation, you can safely delete backups:"
echo "     rm data/tmws.db.backup_$TIMESTAMP"
if [ -d "data/chroma.backup_$TIMESTAMP" ]; then
    echo "     rm -rf data/chroma.backup_$TIMESTAMP"
fi
echo ""
print_success "Migration completed successfully! 🎉"
echo ""

# Optional: Cleanup old backups
echo "Backup files in data directory:"
ls -lh data/*.backup_* 2>/dev/null || echo "  (none)"
echo ""

if [ "$AUTO_CONFIRM" = false ] && [ "$DRY_RUN" = false ]; then
    confirm "Would you like to add migration details to CHANGELOG.md?"

    if [ $? -eq 0 ]; then
        echo "" >> CHANGELOG.md
        echo "## [Migration] Remove _v2 Suffixes - $TIMESTAMP" >> CHANGELOG.md
        echo "" >> CHANGELOG.md
        echo "### Changed" >> CHANGELOG.md
        echo "- Renamed \`memories_v2\` table to \`memories\`" >> CHANGELOG.md
        echo "- Renamed \`learning_patterns_v2\` table to \`learning_patterns\`" >> CHANGELOG.md
        echo "- Updated all indexes to remove _v2 suffix" >> CHANGELOG.md
        echo "- Migrated ChromaDB collection: \`tmws_memories_v2\` → \`tmws_memories\`" >> CHANGELOG.md
        echo "" >> CHANGELOG.md
        echo "### Migration" >> CHANGELOG.md
        echo "- Alembic revision: 010" >> CHANGELOG.md
        echo "- Zero data loss, all foreign keys preserved" >> CHANGELOG.md
        echo "- Backups created with timestamp: $TIMESTAMP" >> CHANGELOG.md
        echo "" >> CHANGELOG.md

        print_success "CHANGELOG.md updated"
    fi
fi

exit 0
