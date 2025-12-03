#!/usr/bin/env bash
# =============================================================================
# Trinitas Uninstaller v2.4.12
# Removes Trinitas configuration and integration files
# =============================================================================

set -euo pipefail

# Version
VERSION="2.4.12"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }

# Platform detection
detect_platform() {
    case "$(uname -s)" in
        Darwin*) PLATFORM="macOS" ;;
        Linux*)  PLATFORM="Linux" ;;
        MINGW*|CYGWIN*|MSYS*) PLATFORM="Windows" ;;
        *)       PLATFORM="Unknown" ;;
    esac
}

# Configuration paths
TRINITAS_CONFIG_DIR="${HOME}/.trinitas"
CLAUDE_CONFIG_DIR="${HOME}/.claude"
OPENCODE_CONFIG_DIR="${HOME}/.config/opencode"

# Show banner
show_banner() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║           🗑️  Trinitas Uninstaller v${VERSION}                       ║"
    echo "║                                                                   ║"
    echo "║  This script will remove Trinitas configuration files.           ║"
    echo "║  Your data and memories stored in TMWS will NOT be deleted.      ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo ""
}

# Confirm uninstallation
confirm_uninstall() {
    echo "The following will be removed:"
    echo ""
    
    if [[ -d "${TRINITAS_CONFIG_DIR}" ]]; then
        echo "  📁 ${TRINITAS_CONFIG_DIR}/ (Shared Trinitas config)"
    fi
    
    if [[ -f "${CLAUDE_CONFIG_DIR}/CLAUDE.md" ]]; then
        echo "  📄 ${CLAUDE_CONFIG_DIR}/CLAUDE.md (Claude Code config)"
    fi
    
    if [[ -d "${CLAUDE_CONFIG_DIR}/agents" ]]; then
        echo "  📁 ${CLAUDE_CONFIG_DIR}/agents/ (Agent definitions)"
    fi
    
    if [[ -d "${CLAUDE_CONFIG_DIR}/hooks" ]]; then
        echo "  📁 ${CLAUDE_CONFIG_DIR}/hooks/ (Claude Code hooks)"
    fi
    
    if [[ -d "${CLAUDE_CONFIG_DIR}/commands" ]]; then
        echo "  📁 ${CLAUDE_CONFIG_DIR}/commands/ (Slash commands)"
    fi
    
    if [[ -f "${OPENCODE_CONFIG_DIR}/opencode.md" ]]; then
        echo "  📄 ${OPENCODE_CONFIG_DIR}/opencode.md (OpenCode config)"
    fi
    
    if [[ -d "${OPENCODE_CONFIG_DIR}/plugin" ]]; then
        echo "  📁 ${OPENCODE_CONFIG_DIR}/plugin/ (OpenCode plugins)"
    fi
    
    if [[ -d "${OPENCODE_CONFIG_DIR}/command" ]]; then
        echo "  📁 ${OPENCODE_CONFIG_DIR}/command/ (OpenCode commands)"
    fi
    
    echo ""
    echo -e "${YELLOW}⚠️  This action cannot be undone!${NC}"
    echo ""
    
    read -p "Are you sure you want to continue? [y/N] " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        info "Uninstallation cancelled."
        exit 0
    fi
}

# Create backup before removal
create_backup() {
    local backup_dir="${HOME}/.trinitas-backup-$(date +%Y%m%d-%H%M%S)"
    
    info "Creating backup at ${backup_dir}..."
    mkdir -p "${backup_dir}"
    
    # Backup Trinitas config
    if [[ -d "${TRINITAS_CONFIG_DIR}" ]]; then
        cp -r "${TRINITAS_CONFIG_DIR}" "${backup_dir}/trinitas"
        success "Backed up ~/.trinitas/"
    fi
    
    # Backup Claude config (Trinitas-related only)
    if [[ -f "${CLAUDE_CONFIG_DIR}/CLAUDE.md" ]] || \
       [[ -d "${CLAUDE_CONFIG_DIR}/agents" ]] || \
       [[ -d "${CLAUDE_CONFIG_DIR}/hooks" ]] || \
       [[ -d "${CLAUDE_CONFIG_DIR}/commands" ]]; then
        mkdir -p "${backup_dir}/claude"
        
        [[ -f "${CLAUDE_CONFIG_DIR}/CLAUDE.md" ]] && cp "${CLAUDE_CONFIG_DIR}/CLAUDE.md" "${backup_dir}/claude/"
        [[ -f "${CLAUDE_CONFIG_DIR}/AGENTS.md" ]] && cp "${CLAUDE_CONFIG_DIR}/AGENTS.md" "${backup_dir}/claude/"
        [[ -d "${CLAUDE_CONFIG_DIR}/agents" ]] && cp -r "${CLAUDE_CONFIG_DIR}/agents" "${backup_dir}/claude/"
        [[ -d "${CLAUDE_CONFIG_DIR}/hooks" ]] && cp -r "${CLAUDE_CONFIG_DIR}/hooks" "${backup_dir}/claude/"
        [[ -d "${CLAUDE_CONFIG_DIR}/commands" ]] && cp -r "${CLAUDE_CONFIG_DIR}/commands" "${backup_dir}/claude/"
        
        success "Backed up Claude Code config"
    fi
    
    # Backup OpenCode config (Trinitas-related only)
    if [[ -f "${OPENCODE_CONFIG_DIR}/opencode.md" ]] || \
       [[ -d "${OPENCODE_CONFIG_DIR}/plugin" ]] || \
       [[ -d "${OPENCODE_CONFIG_DIR}/command" ]]; then
        mkdir -p "${backup_dir}/opencode"
        
        [[ -f "${OPENCODE_CONFIG_DIR}/opencode.md" ]] && cp "${OPENCODE_CONFIG_DIR}/opencode.md" "${backup_dir}/opencode/"
        [[ -d "${OPENCODE_CONFIG_DIR}/plugin" ]] && cp -r "${OPENCODE_CONFIG_DIR}/plugin" "${backup_dir}/opencode/"
        [[ -d "${OPENCODE_CONFIG_DIR}/command" ]] && cp -r "${OPENCODE_CONFIG_DIR}/command" "${backup_dir}/opencode/"
        [[ -d "${OPENCODE_CONFIG_DIR}/agent" ]] && cp -r "${OPENCODE_CONFIG_DIR}/agent" "${backup_dir}/opencode/"
        
        success "Backed up OpenCode config"
    fi
    
    success "Backup created at ${backup_dir}"
    echo ""
}

# Remove Trinitas shared config
remove_trinitas_config() {
    if [[ -d "${TRINITAS_CONFIG_DIR}" ]]; then
        info "Removing shared Trinitas config..."
        rm -rf "${TRINITAS_CONFIG_DIR}"
        success "Removed ~/.trinitas/"
    fi
}

# Remove Claude Code integration
remove_claude_integration() {
    info "Removing Claude Code integration..."
    
    # Remove Trinitas-specific files (preserve user's own CLAUDE.md if it exists)
    if [[ -f "${CLAUDE_CONFIG_DIR}/AGENTS.md" ]]; then
        rm -f "${CLAUDE_CONFIG_DIR}/AGENTS.md"
        success "Removed AGENTS.md"
    fi
    
    if [[ -d "${CLAUDE_CONFIG_DIR}/agents" ]]; then
        rm -rf "${CLAUDE_CONFIG_DIR}/agents"
        success "Removed agents/"
    fi
    
    if [[ -d "${CLAUDE_CONFIG_DIR}/hooks" ]]; then
        rm -rf "${CLAUDE_CONFIG_DIR}/hooks"
        success "Removed hooks/"
    fi
    
    # Remove trinitas command only (preserve other commands)
    if [[ -f "${CLAUDE_CONFIG_DIR}/commands/trinitas.md" ]]; then
        rm -f "${CLAUDE_CONFIG_DIR}/commands/trinitas.md"
        success "Removed commands/trinitas.md"
    fi
    
    if [[ -f "${CLAUDE_CONFIG_DIR}/commands/tmws.md" ]]; then
        rm -f "${CLAUDE_CONFIG_DIR}/commands/tmws.md"
        success "Removed commands/tmws.md"
    fi
    
    # Note: We don't remove CLAUDE.md as it may contain user-specific instructions
    warn "CLAUDE.md not removed - please edit manually if needed"
}

# Remove OpenCode integration
remove_opencode_integration() {
    info "Removing OpenCode integration..."
    
    # Remove Trinitas-specific plugins
    local plugins=(
        "trinitas-trigger-processor.js"
        "trinitas-orchestration.js"
        "trinitas-memory-bridge.js"
    )
    
    for plugin in "${plugins[@]}"; do
        if [[ -f "${OPENCODE_CONFIG_DIR}/plugin/${plugin}" ]]; then
            rm -f "${OPENCODE_CONFIG_DIR}/plugin/${plugin}"
            success "Removed plugin/${plugin}"
        fi
    done
    
    # Remove Trinitas commands
    if [[ -f "${OPENCODE_CONFIG_DIR}/command/trinitas.md" ]]; then
        rm -f "${OPENCODE_CONFIG_DIR}/command/trinitas.md"
        success "Removed command/trinitas.md"
    fi
    
    # Remove agent definitions
    if [[ -d "${OPENCODE_CONFIG_DIR}/agent" ]]; then
        rm -rf "${OPENCODE_CONFIG_DIR}/agent"
        success "Removed agent/"
    fi
    
    # Note: We don't remove opencode.md as it may contain user-specific config
    warn "opencode.md not removed - please edit manually if needed"
}

# Clean up MCP server entry from settings
cleanup_mcp_settings() {
    info "Note: MCP server settings in settings.json need manual cleanup"
    
    if [[ -f "${CLAUDE_CONFIG_DIR}/.mcp.json" ]]; then
        warn "Please manually edit ${CLAUDE_CONFIG_DIR}/.mcp.json to remove TMWS server"
    fi
    
    if [[ -f "${OPENCODE_CONFIG_DIR}/opencode.json" ]]; then
        warn "Please manually edit ${OPENCODE_CONFIG_DIR}/opencode.json to remove TMWS server"
    fi
}

# Show completion message
show_completion() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║           ✅ Trinitas Uninstallation Complete                     ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Next steps:"
    echo "  1. If you had TMWS MCP server running, stop it"
    echo "  2. Edit your IDE settings to remove TMWS MCP server reference"
    echo "  3. Your backup is saved at ~/.trinitas-backup-*"
    echo ""
    echo "To reinstall later: ./install_trinitas.sh"
    echo ""
}

# Main execution
main() {
    detect_platform
    show_banner
    confirm_uninstall
    create_backup
    
    remove_trinitas_config
    remove_claude_integration
    remove_opencode_integration
    cleanup_mcp_settings
    
    show_completion
}

# Run main
main "$@"
