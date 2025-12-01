#!/bin/bash

# ============================================================================
# Trinitas Agent System - Unified Cross-Platform Installer
# Version: 2.4.8
# Supports: Claude Code, OpenCode
# Platforms: macOS, Linux, Windows (via WSL or Git Bash)
#
# Usage:
#   ./install_trinitas.sh                    # Interactive mode
#   ./install_trinitas.sh --platform claude  # Claude Code only
#   ./install_trinitas.sh --platform opencode # OpenCode only
#   ./install_trinitas.sh --platform both    # Both platforms
#   ./install_trinitas.sh --update           # Update existing installation
#   ./install_trinitas.sh --uninstall        # Restore from backup
# ============================================================================

set -e

# Version
VERSION="2.4.8"
TRINITAS_VERSION="2.4.8"

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Path definitions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Claude Code paths
CLAUDE_CONFIG_DIR="${HOME}/.claude"
CLAUDE_BACKUP_DIR="${HOME}/.claude/backup"
CLAUDE_AGENTS_SRC="${SCRIPT_DIR}/src/trinitas/agents"

# OpenCode paths
OPENCODE_CONFIG_DIR="${HOME}/.config/opencode"
OPENCODE_BACKUP_DIR="${HOME}/.config/opencode.backup.${TIMESTAMP}"
OPENCODE_AGENTS_SRC="${SCRIPT_DIR}/.opencode/agent"

# Hooks and shared paths (TMWS structure)
HOOKS_SRC="${SCRIPT_DIR}/hooks"
SHARED_SRC="${SCRIPT_DIR}/shared"

# Agent definitions - ALL 9 AGENTS (Core 6 + Support 3)
CORE_AGENTS=("athena" "artemis" "hestia" "eris" "hera" "muses")
SUPPORT_AGENTS=("aphrodite" "metis" "aurora")
ALL_AGENTS=("${CORE_AGENTS[@]}" "${SUPPORT_AGENTS[@]}")

# Claude Code agent file names (with suffixes)
CLAUDE_CORE_FILES=("athena-conductor" "artemis-optimizer" "hestia-auditor" "eris-coordinator" "hera-strategist" "muses-documenter")
CLAUDE_SUPPORT_FILES=("aphrodite-designer" "metis-developer" "aurora-researcher")
CLAUDE_ALL_FILES=("${CLAUDE_CORE_FILES[@]}" "${CLAUDE_SUPPORT_FILES[@]}")

# ============================================================================
# Utility Functions
# ============================================================================

print_header() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║     Trinitas Agent System - Unified Installer v${VERSION}     ║"
    echo "║       Claude Code & OpenCode Cross-Platform Support        ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_step() {
    echo -e "${MAGENTA}▶${NC} $1"
}

detect_os() {
    case "$(uname -s)" in
        Darwin*)    OS="macOS" ;;
        Linux*)     OS="Linux" ;;
        CYGWIN*|MINGW*|MSYS*) OS="Windows" ;;
        *)          OS="Unknown" ;;
    esac
    echo "$OS"
}

# ============================================================================
# Prerequisites Check
# ============================================================================

check_prerequisites() {
    print_step "Checking prerequisites..."

    # Check if source directories exist (TMWS structure)
    if [ ! -d "${CLAUDE_AGENTS_SRC}" ]; then
        print_error "Claude Code agents not found: ${CLAUDE_AGENTS_SRC}"
        echo "Please run this script from the TMWS project root."
        exit 1
    fi

    if [ ! -d "${OPENCODE_AGENTS_SRC}" ]; then
        print_error "OpenCode agents not found: ${OPENCODE_AGENTS_SRC}"
        echo "Please run this script from the TMWS project root."
        exit 1
    fi

    # Check for pyproject.toml to verify TMWS root
    if [ ! -f "${SCRIPT_DIR}/pyproject.toml" ]; then
        print_warning "pyproject.toml not found - may not be TMWS root"
    fi

    # Get version from pyproject.toml
    if [ -f "${SCRIPT_DIR}/pyproject.toml" ]; then
        local version=$(grep -m1 'version = "' "${SCRIPT_DIR}/pyproject.toml" | sed 's/.*version = "\([^"]*\)".*/\1/')
        if [ -n "$version" ]; then
            print_success "TMWS version: ${version}"
        fi
    fi

    # Detect OS
    DETECTED_OS=$(detect_os)
    print_success "Detected OS: ${DETECTED_OS}"

    # Show source paths
    print_info "Claude agents: ${CLAUDE_AGENTS_SRC}"
    print_info "OpenCode agents: ${OPENCODE_AGENTS_SRC}"

    print_success "Prerequisites satisfied"
    echo ""
}

# ============================================================================
# Platform Selection
# ============================================================================

select_platform() {
    if [ -n "$PLATFORM" ]; then
        return 0
    fi

    echo -e "${CYAN}Select installation target:${NC}"
    echo ""
    echo "  1) Claude Code only     (~/.claude/)"
    echo "  2) OpenCode only        (~/.config/opencode/)"
    echo "  3) Both platforms"
    echo "  4) Cancel"
    echo ""
    read -p "Choose (1-4): " -n 1 -r
    echo

    case $REPLY in
        1) PLATFORM="claude" ;;
        2) PLATFORM="opencode" ;;
        3) PLATFORM="both" ;;
        *)
            print_warning "Installation cancelled"
            exit 0
            ;;
    esac

    echo ""
}

# ============================================================================
# Claude Code Installation
# ============================================================================

install_claude_code() {
    print_step "Installing Trinitas for Claude Code..."
    echo ""

    # Create directories
    mkdir -p "${CLAUDE_CONFIG_DIR}"
    mkdir -p "${CLAUDE_CONFIG_DIR}/agents"
    mkdir -p "${CLAUDE_BACKUP_DIR}"

    # Backup existing configuration
    backup_claude_config

    # Install agents (ALL 9)
    install_claude_agents

    # Install hooks
    install_claude_hooks

    # Install global configuration
    install_claude_global_config

    print_success "Claude Code installation complete!"
    echo ""
}

backup_claude_config() {
    print_info "Creating Claude Code backup..."

    local backup_created=false

    # Backup CLAUDE.md
    if [ -f "${CLAUDE_CONFIG_DIR}/CLAUDE.md" ]; then
        cp "${CLAUDE_CONFIG_DIR}/CLAUDE.md" "${CLAUDE_BACKUP_DIR}/CLAUDE_${TIMESTAMP}.md"
        print_success "Backed up: CLAUDE.md"
        backup_created=true
    fi

    # Backup AGENTS.md
    if [ -f "${CLAUDE_CONFIG_DIR}/AGENTS.md" ]; then
        cp "${CLAUDE_CONFIG_DIR}/AGENTS.md" "${CLAUDE_BACKUP_DIR}/AGENTS_${TIMESTAMP}.md"
        print_success "Backed up: AGENTS.md"
        backup_created=true
    fi

    # Backup agents directory
    if [ -d "${CLAUDE_CONFIG_DIR}/agents" ] && [ "$(ls -A ${CLAUDE_CONFIG_DIR}/agents 2>/dev/null)" ]; then
        mkdir -p "${CLAUDE_BACKUP_DIR}/agents_${TIMESTAMP}"
        cp -r "${CLAUDE_CONFIG_DIR}/agents/"* "${CLAUDE_BACKUP_DIR}/agents_${TIMESTAMP}/" 2>/dev/null || true
        print_success "Backed up: agents/ directory"
        backup_created=true
    fi

    # Backup hooks directory
    if [ -d "${CLAUDE_CONFIG_DIR}/hooks" ] && [ "$(ls -A ${CLAUDE_CONFIG_DIR}/hooks 2>/dev/null)" ]; then
        mkdir -p "${CLAUDE_BACKUP_DIR}/hooks_${TIMESTAMP}"
        cp -r "${CLAUDE_CONFIG_DIR}/hooks/"* "${CLAUDE_BACKUP_DIR}/hooks_${TIMESTAMP}/" 2>/dev/null || true
        print_success "Backed up: hooks/ directory"
        backup_created=true
    fi

    if [ "$backup_created" = true ]; then
        print_info "Backup location: ${CLAUDE_BACKUP_DIR}"
    else
        print_info "No existing files to backup (fresh installation)"
    fi
    echo ""
}

install_claude_agents() {
    print_info "Installing Claude Code agents (9 total)..."

    local installed_count=0
    local failed_count=0

    for agent_file in "${CLAUDE_ALL_FILES[@]}"; do
        local src_file="${CLAUDE_AGENTS_SRC}/${agent_file}.md"
        local dst_file="${CLAUDE_CONFIG_DIR}/agents/${agent_file}.md"

        if [ -f "$src_file" ]; then
            cp "$src_file" "$dst_file"
            print_success "Installed: ${agent_file}"
            ((installed_count++))
        else
            print_warning "Not found: ${agent_file} (skipped)"
            ((failed_count++))
        fi
    done

    echo ""
    print_info "Agents installed: ${installed_count}/9"

    if [ $installed_count -ge 6 ]; then
        print_success "Core agents (6) installed successfully"
    fi

    if [ $installed_count -eq 9 ]; then
        print_success "Support agents (3) installed successfully"
    elif [ $installed_count -lt 9 ] && [ $installed_count -ge 6 ]; then
        print_warning "Some support agents not available (optional)"
    fi
    echo ""
}

install_claude_hooks() {
    print_info "Installing Claude Code hooks..."

    mkdir -p "${CLAUDE_CONFIG_DIR}/hooks/core"

    # Install protocol_injector.py (PreCompact hook)
    if [ -f "${HOOKS_SRC}/core/protocol_injector.py" ]; then
        cp "${HOOKS_SRC}/core/protocol_injector.py" "${CLAUDE_CONFIG_DIR}/hooks/core/"
        print_success "Installed: protocol_injector.py"
    else
        print_warning "protocol_injector.py not found (optional)"
    fi

    # Install dynamic_context_loader.py (UserPromptSubmit hook)
    if [ -f "${HOOKS_SRC}/core/dynamic_context_loader.py" ]; then
        cp "${HOOKS_SRC}/core/dynamic_context_loader.py" "${CLAUDE_CONFIG_DIR}/hooks/core/"
        print_success "Installed: dynamic_context_loader.py"
    else
        print_warning "dynamic_context_loader.py not found (optional)"
    fi

    # Install shared utilities
    if [ -d "${SHARED_SRC}/utils" ]; then
        mkdir -p "${CLAUDE_CONFIG_DIR}/shared/utils"
        cp "${SHARED_SRC}/utils/"*.py "${CLAUDE_CONFIG_DIR}/shared/utils/" 2>/dev/null || true
        print_success "Installed: shared utilities"
    fi

    # Generate settings.json
    local TEMPLATE_FILE="${HOOKS_SRC}/settings_global.template.json"
    local SETTINGS_FILE="${CLAUDE_CONFIG_DIR}/settings.json"

    if [ -f "${TEMPLATE_FILE}" ]; then
        sed "s|{{GLOBAL_CONFIG_DIR}}|${CLAUDE_CONFIG_DIR}|g" "${TEMPLATE_FILE}" > "${SETTINGS_FILE}"
        print_success "Generated: settings.json"
    else
        print_warning "Hook settings template not found"
    fi
    echo ""
}

install_claude_global_config() {
    print_info "Installing Claude Code global configuration..."

    # Note: CLAUDE.md is typically a user's personal file
    # We do not overwrite it, but provide AGENTS.md

    # Check if CLAUDE.md exists at global level
    if [ ! -f "${CLAUDE_CONFIG_DIR}/CLAUDE.md" ]; then
        print_info "CLAUDE.md not found - skipping (user should configure manually)"
    else
        print_success "CLAUDE.md already exists (preserved)"
    fi

    # Install AGENTS.md (agent coordination rules)
    # Use the one from .claude directory if exists, otherwise from .opencode
    if [ -f "${SCRIPT_DIR}/.opencode/AGENTS.md" ]; then
        cp "${SCRIPT_DIR}/.opencode/AGENTS.md" "${CLAUDE_CONFIG_DIR}/AGENTS.md"
        print_success "Installed: AGENTS.md"
    else
        print_warning "AGENTS.md not found"
    fi
    echo ""
}

# ============================================================================
# OpenCode Installation
# ============================================================================

install_opencode() {
    print_step "Installing Trinitas for OpenCode..."
    echo ""

    # Check if source exists
    if [ ! -d "${OPENCODE_AGENTS_SRC}" ]; then
        print_error "OpenCode agent source not found: ${OPENCODE_AGENTS_SRC}"
        print_info "OpenCode installation skipped"
        return 1
    fi

    # Backup existing configuration
    backup_opencode_config

    # Create directories
    mkdir -p "${OPENCODE_CONFIG_DIR}/agent"

    # Install agents (ALL 9)
    install_opencode_agents

    # Install system instructions
    install_opencode_system_instructions

    print_success "OpenCode installation complete!"
    echo ""
}

backup_opencode_config() {
    if [ -d "${OPENCODE_CONFIG_DIR}" ]; then
        print_info "Creating OpenCode backup..."
        cp -r "${OPENCODE_CONFIG_DIR}" "${OPENCODE_BACKUP_DIR}"
        print_success "Backed up to: ${OPENCODE_BACKUP_DIR}"
        echo ""
    fi
}

install_opencode_agents() {
    print_info "Installing OpenCode agents (9 total)..."

    local installed_count=0

    for agent in "${ALL_AGENTS[@]}"; do
        local src_file="${OPENCODE_AGENTS_SRC}/${agent}.md"
        local dst_file="${OPENCODE_CONFIG_DIR}/agent/${agent}.md"

        if [ -f "$src_file" ]; then
            cp "$src_file" "$dst_file"
            print_success "Installed: ${agent}"
            ((installed_count++))
        else
            print_warning "Not found: ${agent} (skipped)"
        fi
    done

    echo ""
    print_info "Agents installed: ${installed_count}/9"
    echo ""
}

install_opencode_system_instructions() {
    print_info "Installing OpenCode system instructions..."

    local OPENCODE_SRC="${SCRIPT_DIR}/.opencode"

    # Install AGENTS.md
    if [ -f "${OPENCODE_SRC}/AGENTS.md" ]; then
        cp "${OPENCODE_SRC}/AGENTS.md" "${OPENCODE_CONFIG_DIR}/"
        print_success "Installed: AGENTS.md"
    fi

    # Copy documentation (optional)
    if [ -d "${OPENCODE_SRC}/docs" ]; then
        cp -r "${OPENCODE_SRC}/docs" "${OPENCODE_CONFIG_DIR}/"
        print_success "Installed: documentation"
    fi
    echo ""
}

# ============================================================================
# Verification
# ============================================================================

verify_installation() {
    print_step "Verifying installation..."
    echo ""

    local all_success=true

    if [ "$PLATFORM" = "claude" ] || [ "$PLATFORM" = "both" ]; then
        echo -e "${CYAN}Claude Code (~/.claude/):${NC}"

        # Count agents
        local claude_agents=$(ls -1 "${CLAUDE_CONFIG_DIR}/agents/"*.md 2>/dev/null | wc -l | tr -d ' ')
        echo "  Agents:    ${claude_agents}/9"

        # Check core files
        [ -f "${CLAUDE_CONFIG_DIR}/CLAUDE.md" ] && echo "  CLAUDE.md: ✓" || echo "  CLAUDE.md: ✗"
        [ -f "${CLAUDE_CONFIG_DIR}/AGENTS.md" ] && echo "  AGENTS.md: ✓" || echo "  AGENTS.md: ✗"
        [ -f "${CLAUDE_CONFIG_DIR}/settings.json" ] && echo "  Hooks:     ✓" || echo "  Hooks:     ✗"

        if [ "$claude_agents" -lt 6 ]; then
            all_success=false
        fi
        echo ""
    fi

    if [ "$PLATFORM" = "opencode" ] || [ "$PLATFORM" = "both" ]; then
        echo -e "${CYAN}OpenCode (~/.config/opencode/):${NC}"

        # Count agents
        local opencode_agents=$(ls -1 "${OPENCODE_CONFIG_DIR}/agent/"*.md 2>/dev/null | wc -l | tr -d ' ')
        echo "  Agents:    ${opencode_agents}/9"

        # Check core files
        [ -f "${OPENCODE_CONFIG_DIR}/AGENTS.md" ] && echo "  AGENTS.md: ✓" || echo "  AGENTS.md: ✗"

        if [ "$opencode_agents" -lt 6 ]; then
            all_success=false
        fi
        echo ""
    fi

    if [ "$all_success" = true ]; then
        print_success "Installation verified successfully!"
    else
        print_warning "Some components may be missing"
    fi
    echo ""
}

# ============================================================================
# Summary and Usage
# ============================================================================

show_summary() {
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Installation Complete! v${VERSION}                  ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${CYAN}Installed Components:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "${WHITE}Core Agents (6):${NC}"
    echo "  • Athena  - Harmonious Conductor 🏛️"
    echo "  • Artemis - Technical Perfectionist 🏹"
    echo "  • Hestia  - Security Guardian 🔥"
    echo "  • Eris    - Tactical Coordinator ⚔️"
    echo "  • Hera    - Strategic Commander 🎭"
    echo "  • Muses   - Knowledge Architect 📚"
    echo ""
    echo -e "${WHITE}Support Agents (3):${NC}"
    echo "  • Aphrodite - UI/UX Designer 🌸"
    echo "  • Metis     - Development Assistant 🔧"
    echo "  • Aurora    - Research Assistant 🌅"
    echo ""

    echo -e "${CYAN}Next Steps:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [ "$PLATFORM" = "claude" ] || [ "$PLATFORM" = "both" ]; then
        echo ""
        echo -e "${WHITE}Claude Code:${NC}"
        echo "  1. Restart Claude Code to load new configuration"
        echo "  2. Test: 'Trinitasシステムの動作確認'"
        echo "  3. Test persona: 'optimize this code' (Artemis detection)"
    fi

    if [ "$PLATFORM" = "opencode" ] || [ "$PLATFORM" = "both" ]; then
        echo ""
        echo -e "${WHITE}OpenCode:${NC}"
        echo "  1. Start OpenCode: opencode"
        echo "  2. Select agent: opencode --agent athena"
        echo "  3. Switch agents with Tab key"
    fi

    echo ""
    echo -e "${MAGENTA}🎭 Trinitas Agent System is ready!${NC}"
    echo ""
}

# ============================================================================
# Uninstall / Restore
# ============================================================================

uninstall() {
    print_step "Restoring from backup..."
    echo ""

    # Find latest Claude backup
    local latest_claude_backup=$(ls -t "${CLAUDE_BACKUP_DIR}"/CLAUDE_*.md 2>/dev/null | head -n1)
    if [ -n "$latest_claude_backup" ]; then
        cp "$latest_claude_backup" "${CLAUDE_CONFIG_DIR}/CLAUDE.md"
        print_success "Restored Claude Code configuration"
    else
        print_warning "No Claude Code backup found"
    fi

    # Find latest OpenCode backup
    local latest_opencode_backup=$(ls -td "${HOME}/.config/opencode.backup."* 2>/dev/null | head -n1)
    if [ -n "$latest_opencode_backup" ] && [ -d "$latest_opencode_backup" ]; then
        rm -rf "${OPENCODE_CONFIG_DIR}"
        cp -r "$latest_opencode_backup" "${OPENCODE_CONFIG_DIR}"
        print_success "Restored OpenCode configuration"
    else
        print_warning "No OpenCode backup found"
    fi

    echo ""
    print_success "Restore complete!"
}

# ============================================================================
# Help
# ============================================================================

show_help() {
    echo "Trinitas Agent System - Unified Installer v${VERSION}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -v, --version           Show version information"
    echo "  -y, --yes               Skip confirmation prompts"
    echo "  -p, --platform PLATFORM Target platform (claude|opencode|both)"
    echo "  -u, --update            Update existing installation"
    echo "  --uninstall             Restore from latest backup"
    echo ""
    echo "Platforms:"
    echo "  claude   - Install for Claude Code (~/.claude/)"
    echo "  opencode - Install for OpenCode (~/.config/opencode/)"
    echo "  both     - Install for both platforms"
    echo ""
    echo "Examples:"
    echo "  $0                        # Interactive mode"
    echo "  $0 --platform claude      # Claude Code only"
    echo "  $0 --platform opencode    # OpenCode only"
    echo "  $0 --platform both --yes  # Both, non-interactive"
    echo "  $0 --uninstall            # Restore previous config"
    echo ""
    echo "Agents installed:"
    echo "  Core (6):    Athena, Artemis, Hestia, Eris, Hera, Muses"
    echo "  Support (3): Aphrodite, Metis, Aurora"
}

show_version() {
    echo "Trinitas Unified Installer v${VERSION}"
    echo "Trinitas Agent System v${TRINITAS_VERSION}"
    echo "Supports: Claude Code, OpenCode"
    echo "Platforms: macOS, Linux, Windows (WSL/Git Bash)"
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Parse arguments
    PLATFORM=""
    SKIP_CONFIRM=false
    MODE="install"

    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            -y|--yes)
                SKIP_CONFIRM=true
                shift
                ;;
            -p|--platform)
                PLATFORM="$2"
                shift 2
                ;;
            -u|--update)
                MODE="update"
                shift
                ;;
            --uninstall)
                MODE="uninstall"
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Handle uninstall mode
    if [ "$MODE" = "uninstall" ]; then
        print_header
        uninstall
        exit 0
    fi

    # Main installation flow
    print_header
    check_prerequisites
    select_platform

    # Confirmation
    if [ "$SKIP_CONFIRM" = false ]; then
        echo -e "${YELLOW}This will install Trinitas v${TRINITAS_VERSION} for: ${PLATFORM}${NC}"
        echo "Existing configurations will be backed up."
        echo ""
        read -p "Continue? [y/N]: " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_warning "Installation cancelled"
            exit 0
        fi
        echo ""
    fi

    # Execute installation
    case $PLATFORM in
        claude)
            install_claude_code
            ;;
        opencode)
            install_opencode
            ;;
        both)
            install_claude_code
            install_opencode
            ;;
        *)
            print_error "Invalid platform: ${PLATFORM}"
            exit 1
            ;;
    esac

    # Verify and summarize
    verify_installation
    show_summary
}

# Run main
main "$@"
