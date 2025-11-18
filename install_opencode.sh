#!/bin/bash

# ============================================================================
# Trinitas → Open Code Phase 1 Installer (Minimal)
# Version: 1.3.0
# Description: Install Trinitas agents for Open Code to ~/.config/opencode/
# Note: Open Code does not support JavaScript plugins (only npm packages)
#       This installer only deploys agent definitions and system instructions
# ============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/.opencode"
TARGET_DIR="$HOME/.config/opencode"
BACKUP_DIR="$HOME/.config/opencode.backup.$(date +%Y%m%d_%H%M%S)"

# Functions
print_header() {
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}   Trinitas → Open Code Phase 1 Installer${NC}"
    echo -e "${BLUE}   (Minimal: Agents + System Instructions)${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo ""
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

check_prerequisites() {
    echo -e "${BLUE}[1/4] Checking prerequisites...${NC}"

    # Check if source directory exists
    if [ ! -d "$SOURCE_DIR" ]; then
        print_error "Source directory not found: $SOURCE_DIR"
        echo "Please run this script from the trinitas-agents directory"
        exit 1
    fi

    # Check if opencode.json exists
    if [ ! -f "$SCRIPT_DIR/opencode.json" ]; then
        print_error "opencode.json not found"
        echo "Please ensure you're on the feature/opencode-migration branch"
        exit 1
    fi

    # Check for Open Code CLI
    if command -v opencode &> /dev/null; then
        print_success "Open Code CLI is installed: $(opencode --version 2>/dev/null || echo 'version unknown')"
    else
        print_warning "Open Code CLI not found. Install it with:"
        echo "  npm i -g opencode-ai@latest"
        echo "  or"
        echo "  brew install sst/tap/opencode"
        echo ""
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    print_success "Prerequisites check complete"
    echo ""
}

backup_existing() {
    echo -e "${BLUE}[2/4] Backing up existing configuration...${NC}"

    if [ -d "$TARGET_DIR" ]; then
        print_warning "Existing ~/.config/opencode/ directory found"
        echo "Creating backup at: $BACKUP_DIR"

        # Create backup
        cp -r "$TARGET_DIR" "$BACKUP_DIR"
        print_success "Backup created successfully"

        # Ask user what to do
        echo ""
        echo "What would you like to do with the existing ~/.config/opencode/ directory?"
        echo "  1) Merge (add Trinitas agents, keep existing)"
        echo "  2) Replace (clean install)"
        echo "  3) Cancel"
        read -p "Choose (1-3): " -n 1 -r
        echo

        case $REPLY in
            1)
                print_success "Will merge with existing configuration"
                INSTALL_MODE="merge"
                ;;
            2)
                print_warning "Removing existing ~/.config/opencode/ directory"
                rm -rf "$TARGET_DIR"
                print_success "Removed existing directory"
                INSTALL_MODE="replace"
                ;;
            *)
                print_warning "Installation cancelled"
                echo "Your backup is at: $BACKUP_DIR"
                exit 0
                ;;
        esac
    else
        print_success "No existing configuration found"
        INSTALL_MODE="new"
    fi
    echo ""
}

install_agents() {
    echo -e "${BLUE}[3/4] Installing Trinitas agents...${NC}"

    # Create target directory
    mkdir -p "$TARGET_DIR/agent"

    # Copy agents
    echo "Installing 6 Trinitas agents..."
    for agent in athena artemis hestia eris hera muses; do
        if [ -f "$SOURCE_DIR/agent/$agent.md" ]; then
            cp "$SOURCE_DIR/agent/$agent.md" "$TARGET_DIR/agent/"
            print_success "Installed agent: $agent"
        else
            print_error "Agent not found: $agent"
        fi
    done

    echo ""
}

install_plugins() {
    echo -e "${BLUE}[4/5] Installing Trinitas plugins...${NC}"

    # Create plugin directory
    mkdir -p "$TARGET_DIR/plugin"

    # Copy plugins
    echo "Installing Trinitas Open Code plugins..."
    PLUGIN_COUNT=0

    for plugin in "$SOURCE_DIR/plugin"/*.js; do
        if [ -f "$plugin" ]; then
            plugin_name=$(basename "$plugin")
            cp "$plugin" "$TARGET_DIR/plugin/"
            print_success "Installed plugin: $plugin_name"
            ((PLUGIN_COUNT++))
        fi
    done

    if [ $PLUGIN_COUNT -eq 0 ]; then
        print_warning "No plugins found (optional feature)"
    else
        echo ""
        echo -e "${GREEN}✓ Installed $PLUGIN_COUNT Trinitas plugins${NC}"
        echo "  • dynamic-context-loader.js - Context detection & suggestions"
        echo "  • narrative-engine.js - Persona-based narrative system"
        echo "  • performance-monitor.js - Performance tracking"
        echo "  • quality-enforcer.js - Code quality enforcement"
    fi

    echo ""
}

install_system_instructions() {
    echo -e "${BLUE}[5/6] Installing system instructions...${NC}"

    # Install AGENTS.md (global system instructions with embedded rules)
    if [ -f "$SCRIPT_DIR/.opencode/AGENTS.md" ]; then
        cp "$SCRIPT_DIR/.opencode/AGENTS.md" "$TARGET_DIR/"
        print_success "Installed global system instructions (AGENTS.md)"
    else
        print_warning "AGENTS.md not found (will use agent defaults)"
    fi

    # Copy documentation files (optional)
    if [ -d "$SOURCE_DIR/docs" ]; then
        cp -r "$SOURCE_DIR/docs" "$TARGET_DIR/"
        print_success "Installed modular documentation"
    fi

    echo ""
}


verify_installation() {
    echo -e "${BLUE}Verifying installation...${NC}"

    # Count installed items
    AGENT_COUNT=$(ls -1 "$TARGET_DIR/agent/"*.md 2>/dev/null | wc -l)
    PLUGIN_COUNT=$(ls -1 "$TARGET_DIR/plugin/"*.js 2>/dev/null | wc -l)
    DOC_COUNT=$(ls -1 "$TARGET_DIR/docs/"*.md 2>/dev/null | wc -l)
    AGENTS_MD_EXISTS=0
    if [ -f "$TARGET_DIR/AGENTS.md" ]; then
        AGENTS_MD_EXISTS=1
    fi

    echo "Installed components:"
    echo "  • Agents:    $AGENT_COUNT/6"
    echo "  • Plugins:   $PLUGIN_COUNT/4"
    echo "  • System:    $([ $AGENTS_MD_EXISTS -eq 1 ] && echo '✓ AGENTS.md' || echo '✗ AGENTS.md missing')"
    echo "  • Docs:      $DOC_COUNT modular documents"

    if [ $AGENT_COUNT -eq 6 ] && [ $PLUGIN_COUNT -eq 4 ] && [ $AGENTS_MD_EXISTS -eq 1 ]; then
        print_success "Full Trinitas system installed successfully!"
    elif [ $AGENT_COUNT -eq 6 ] && [ $AGENTS_MD_EXISTS -eq 1 ]; then
        print_success "Trinitas agents installed (plugins optional)"
    else
        print_warning "Some components may be missing"
    fi

    echo ""
}

print_usage() {
    echo -e "${GREEN}Installation Complete!${NC}"
    echo ""
    echo "To start using Trinitas agents with Open Code:"
    echo ""
    echo "  1. Start Open Code in any project:"
    echo "     ${BLUE}opencode${NC}"
    echo ""
    echo "  2. Use a specific agent:"
    echo "     ${BLUE}opencode --agent athena${NC}  # System architect"
    echo "     ${BLUE}opencode --agent artemis${NC} # Technical optimizer"
    echo "     ${BLUE}opencode --agent hestia${NC}  # Security guardian"
    echo ""
    echo "  3. Switch agents with Tab key while running"
    echo ""
    echo "Available Trinitas Agents:"
    echo "  • ${BLUE}athena${NC}  - Harmonious system architect"
    echo "  • ${BLUE}artemis${NC} - Technical perfectionist"
    echo "  • ${BLUE}hestia${NC}  - Security guardian"
    echo "  • ${BLUE}eris${NC}    - Tactical coordinator"
    echo "  • ${BLUE}hera${NC}    - Strategic commander"
    echo "  • ${BLUE}muses${NC}   - Knowledge architect"
    echo ""
    echo -e "${YELLOW}Note: Open Code Features${NC}"
    echo "  • ✓ Trinitas agents (6 specialized personas)"
    echo "  • ✓ File-based local memory (simple & private)"
    echo "  • ✓ Agent switching and coordination"
    echo "  • ✗ JavaScript plugins (not supported by Open Code)"
    echo ""

    if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
        echo "Your backup is at: $BACKUP_DIR"
    fi
}

# Main execution
main() {
    clear
    print_header

    check_prerequisites
    backup_existing
    install_agents
    install_plugins
    install_system_instructions
    verify_installation
    print_usage
}

# Run main function
main
