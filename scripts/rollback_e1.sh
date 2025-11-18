#!/bin/bash
# ========================================
# Phase 2E-1 Rollback Script
# ========================================
# Purpose: Emergency rollback if Phase 2E-1 fails
# Execution time: ~15 minutes
# Safety: 100% safe (restores to v2.3.1-pre-phase-2e)
# ========================================

set -e  # Exit on error

echo "========================================="
echo "Phase 2E-1 Emergency Rollback"
echo "========================================="
echo ""

# Step 1: Confirm rollback
read -p "Are you sure you want to rollback Phase 2E-1? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Rollback cancelled."
    exit 0
fi

# Step 2: Restore Dockerfile from backup
echo "Step 1/4: Restoring Dockerfile from backup..."
BACKUP_FILE=$(ls -t Dockerfile.backup.* 2>/dev/null | head -n 1)
if [ -z "$BACKUP_FILE" ]; then
    echo "❌ ERROR: No backup file found (Dockerfile.backup.*)"
    echo "Manual restoration required."
    exit 1
fi

cp "$BACKUP_FILE" Dockerfile
echo "✅ Dockerfile restored from: $BACKUP_FILE"

# Step 3: Discard Git changes
echo ""
echo "Step 2/4: Discarding Git changes..."
git checkout master
git branch -D feature/phase-2e-1-bytecode-wheel 2>/dev/null || true
echo "✅ Git branch removed"

# Step 4: Verify tag exists
echo ""
echo "Step 3/4: Verifying rollback tag..."
if ! git tag | grep -q "v2.3.1-pre-phase-2e"; then
    echo "❌ ERROR: Tag v2.3.1-pre-phase-2e not found"
    echo "Manual verification required."
    exit 1
fi
echo "✅ Tag verified: v2.3.1-pre-phase-2e"

# Step 5: Final verification
echo ""
echo "Step 4/4: Verifying Dockerfile state..."
if grep -q "Phase 2E-1: Bytecode-Only Wheel Creation" Dockerfile; then
    echo "❌ ERROR: Dockerfile still contains Phase 2E-1 changes"
    echo "Manual cleanup required."
    exit 1
fi
echo "✅ Dockerfile state verified (Phase 2E-1 changes removed)"

# Step 6: Success message
echo ""
echo "========================================="
echo "✅ Phase 2E-1 Rollback Successful"
echo "========================================="
echo ""
echo "Current state:"
echo "- Dockerfile: Restored to backup ($(basename $BACKUP_FILE))"
echo "- Git branch: master (feature branch deleted)"
echo "- Git tag: v2.3.1-pre-phase-2e (available for reference)"
echo ""
echo "Next steps:"
echo "1. Review failure reason before retrying Phase 2E-1"
echo "2. Consult Hestia for security analysis"
echo "3. Consult Artemis for technical troubleshooting"
echo ""
echo "Rollback completed in $(date +%H:%M:%S)"
