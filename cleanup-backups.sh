#!/usr/bin/env bash
# =============================================================================
# TMWS Backup Cleanup Script
# =============================================================================
# This script removes ONLY the backups created by the TMWS installer.
# It does NOT remove the actual TMWS installation.
#
# Backup location: ~/.trinitas-backup/
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/cleanup-backups.sh | bash
#
# Or with confirmation skip:
#   curl -fsSL ... | bash -s -- --force
#
# List backups without removing:
#   curl -fsSL ... | bash -s -- --list
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Flags
FORCE=false
LIST_ONLY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --force|-f)
            FORCE=true
            shift
            ;;
        --list|-l)
            LIST_ONLY=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--force] [--list]"
            echo ""
            echo "Options:"
            echo "  --force, -f    Skip confirmation prompts"
            echo "  --list, -l     List backups without removing"
            echo "  --help, -h     Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Get real home directory
if [ -n "${SUDO_USER:-}" ]; then
    REAL_HOME=$(eval echo "~$SUDO_USER")
else
    REAL_HOME="$HOME"
fi

BACKUP_DIR="${REAL_HOME}/.trinitas-backup"

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              TMWS BACKUP CLEANUP                                      ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if backup directory exists
if [ ! -d "$BACKUP_DIR" ]; then
    log_info "No backup directory found at: $BACKUP_DIR"
    log_info "Nothing to clean up."
    exit 0
fi

# List all backups
backups=($(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort))

if [ ${#backups[@]} -eq 0 ]; then
    log_info "Backup directory exists but is empty."
    if [ "$LIST_ONLY" = false ]; then
        rm -rf "$BACKUP_DIR"
        log_success "Removed empty backup directory."
    fi
    exit 0
fi

# Calculate total size
total_size=$(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)

echo -e "${BLUE}Backup Directory:${NC} $BACKUP_DIR"
echo -e "${BLUE}Total Size:${NC} $total_size"
echo -e "${BLUE}Backup Count:${NC} ${#backups[@]}"
echo ""
echo "Found backups:"
echo ""

for backup in "${backups[@]}"; do
    backup_name=$(basename "$backup")
    backup_size=$(du -sh "$backup" 2>/dev/null | cut -f1)

    # Read backup info if available
    info_file="$backup/backup-info.txt"
    if [ -f "$info_file" ]; then
        backup_date=$(grep "Date:" "$info_file" 2>/dev/null | cut -d: -f2- | xargs || echo "Unknown")
    else
        # Parse from directory name (format: YYYYMMDD-HHMMSS)
        if [[ "$backup_name" =~ ^([0-9]{4})([0-9]{2})([0-9]{2})-([0-9]{2})([0-9]{2})([0-9]{2})$ ]]; then
            backup_date="${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]} ${BASH_REMATCH[4]}:${BASH_REMATCH[5]}:${BASH_REMATCH[6]}"
        else
            backup_date="Unknown"
        fi
    fi

    # List contents
    contents=""
    [ -d "$backup/trinitas" ] && contents="${contents}trinitas "
    [ -d "$backup/claude" ] && contents="${contents}claude "
    [ -d "$backup/tmws" ] && contents="${contents}tmws "
    contents=$(echo "$contents" | xargs)

    echo -e "  ${YELLOW}$backup_name${NC} ($backup_size)"
    echo -e "    Date: $backup_date"
    echo -e "    Contents: ${contents:-empty}"
    echo ""
done

# List only mode
if [ "$LIST_ONLY" = true ]; then
    log_info "List mode - no changes made."
    exit 0
fi

# Confirmation
if [ "$FORCE" = false ]; then
    echo -e "${YELLOW}This will permanently delete all ${#backups[@]} backup(s) (${total_size}).${NC}"
    echo ""
    # Read from /dev/tty to work with curl | bash
    if [ -t 0 ]; then
        # Running interactively
        read -p "Are you sure you want to continue? (yes/no): " confirm
    else
        # Running via pipe (curl | bash)
        exec < /dev/tty
        read -p "Are you sure you want to continue? (yes/no): " confirm
    fi
    if [ "$confirm" != "yes" ]; then
        log_info "Cleanup cancelled."
        exit 0
    fi
fi

echo ""
log_info "Removing backups..."

# Remove each backup
for backup in "${backups[@]}"; do
    backup_name=$(basename "$backup")
    rm -rf "$backup"
    log_success "Removed: $backup_name"
done

# Remove the backup directory itself
rmdir "$BACKUP_DIR" 2>/dev/null || true

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              CLEANUP COMPLETE                                         ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
log_success "All backups have been removed."
echo ""
