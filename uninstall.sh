#!/usr/bin/env bash
# =============================================================================
# TMWS Complete Uninstall Script
# =============================================================================
# This script removes all TMWS-related files, including:
# - Configuration files (~/.tmws/)
# - Database files
# - Backup files
# - LaunchAgent (macOS)
# - Claude Code MCP configuration
# - OpenCode MCP configuration
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/uninstall.sh | bash
#
# Or with confirmation skip:
#   curl -fsSL ... | bash -s -- --force
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Flags
FORCE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --force|-f)
            FORCE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--force]"
            echo ""
            echo "Options:"
            echo "  --force, -f    Skip confirmation prompts"
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

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get real home directory (even when running as root via sudo)
if [ -n "${SUDO_USER:-}" ]; then
    REAL_HOME=$(eval echo "~$SUDO_USER")
    REAL_USER="$SUDO_USER"
else
    REAL_HOME="$HOME"
    REAL_USER="$(whoami)"
fi

echo ""
echo -e "${RED}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║              TMWS COMPLETE UNINSTALL                                  ║${NC}"
echo -e "${RED}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# List what will be removed
log_info "The following will be removed:"
echo ""

ITEMS_TO_REMOVE=()

# TMWS data directory
if [ -d "${REAL_HOME}/.tmws" ]; then
    echo "  - ${REAL_HOME}/.tmws/ (config, database, backups)"
    ITEMS_TO_REMOVE+=("${REAL_HOME}/.tmws")
fi

# LaunchAgent (macOS)
LAUNCHAGENT="${REAL_HOME}/Library/LaunchAgents/com.apto.tmws-server.plist"
if [ -f "$LAUNCHAGENT" ]; then
    echo "  - $LAUNCHAGENT (LaunchAgent)"
    ITEMS_TO_REMOVE+=("$LAUNCHAGENT")
fi

# Claude Code MCP configuration
CLAUDE_MCP="${REAL_HOME}/.claude/mcp.json"
if [ -f "$CLAUDE_MCP" ]; then
    if grep -q "tmws" "$CLAUDE_MCP" 2>/dev/null; then
        echo "  - TMWS entry in $CLAUDE_MCP"
    fi
fi

# OpenCode MCP configuration
OPENCODE_CONFIG="${REAL_HOME}/.config/opencode/config.json"
if [ -f "$OPENCODE_CONFIG" ]; then
    if grep -q "tmws" "$OPENCODE_CONFIG" 2>/dev/null; then
        echo "  - TMWS entry in $OPENCODE_CONFIG"
    fi
fi

# TMWS binaries in PATH
for bin in tmws-server tmws-mcp tmws-hook tmws-cli; do
    for path in /usr/local/bin ~/.local/bin; do
        if [ -f "${path}/${bin}" ]; then
            echo "  - ${path}/${bin}"
            ITEMS_TO_REMOVE+=("${path}/${bin}")
        fi
    done
done

echo ""

if [ ${#ITEMS_TO_REMOVE[@]} -eq 0 ]; then
    log_info "No TMWS installation found. Nothing to remove."
    exit 0
fi

# Confirmation
if [ "$FORCE" = false ]; then
    echo -e "${YELLOW}WARNING: This will permanently delete all TMWS data including:${NC}"
    echo "  - All memories and agent data"
    echo "  - Configuration files"
    echo "  - Backup files"
    echo ""
    read -p "Are you sure you want to continue? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        log_info "Uninstall cancelled."
        exit 0
    fi
fi

echo ""
log_info "Starting uninstall..."

# Stop TMWS server if running
if pgrep -x "tmws-server" > /dev/null 2>&1; then
    log_info "Stopping TMWS server..."
    pkill -x "tmws-server" 2>/dev/null || true
    sleep 1
fi

# Unload LaunchAgent (macOS)
if [ -f "$LAUNCHAGENT" ]; then
    log_info "Unloading LaunchAgent..."
    launchctl unload "$LAUNCHAGENT" 2>/dev/null || true
fi

# Remove directories and files
for item in "${ITEMS_TO_REMOVE[@]}"; do
    if [ -e "$item" ]; then
        log_info "Removing $item..."
        rm -rf "$item"
        log_success "Removed $item"
    fi
done

# Clean up Claude Code MCP configuration
if [ -f "$CLAUDE_MCP" ]; then
    if grep -q "tmws" "$CLAUDE_MCP" 2>/dev/null; then
        log_info "Cleaning TMWS from Claude Code MCP config..."
        # Create backup
        cp "$CLAUDE_MCP" "${CLAUDE_MCP}.bak"
        # Remove tmws entry using jq if available, otherwise warn
        if command -v jq &> /dev/null; then
            jq 'del(.mcpServers.tmws)' "$CLAUDE_MCP" > "${CLAUDE_MCP}.tmp" && mv "${CLAUDE_MCP}.tmp" "$CLAUDE_MCP"
            log_success "Removed TMWS from Claude Code MCP config"
        else
            log_warn "jq not found. Please manually remove 'tmws' from $CLAUDE_MCP"
        fi
    fi
fi

# Clean up OpenCode MCP configuration
if [ -f "$OPENCODE_CONFIG" ]; then
    if grep -q "tmws" "$OPENCODE_CONFIG" 2>/dev/null; then
        log_info "Cleaning TMWS from OpenCode config..."
        cp "$OPENCODE_CONFIG" "${OPENCODE_CONFIG}.bak"
        if command -v jq &> /dev/null; then
            jq 'del(.mcpServers.tmws)' "$OPENCODE_CONFIG" > "${OPENCODE_CONFIG}.tmp" && mv "${OPENCODE_CONFIG}.tmp" "$OPENCODE_CONFIG"
            log_success "Removed TMWS from OpenCode config"
        else
            log_warn "jq not found. Please manually remove 'tmws' from $OPENCODE_CONFIG"
        fi
    fi
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              UNINSTALL COMPLETE                                       ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
log_success "All TMWS files have been removed."
echo ""
echo "To reinstall TMWS, run:"
echo "  curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install.sh | bash"
echo ""
