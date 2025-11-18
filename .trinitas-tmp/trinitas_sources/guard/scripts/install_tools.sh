#!/bin/bash
# Trinitas Quality Guardian - Language Tools Installer
# Automatically installs quality tools for detected languages

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Source detector
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD_DIR="$(dirname "$SCRIPT_DIR")"
source "${GUARD_DIR}/core/detector.sh"

# Installation status
INSTALLED_TOOLS=()
FAILED_TOOLS=()

# Show banner
show_banner() {
    echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   Quality Tools Auto-Installer v2.0    ║${NC}"
    echo -e "${CYAN}║   Trinitas Quality Guardian System     ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo ""
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Python tools
install_python_tools() {
    echo -e "${BLUE}🐍 Installing Python quality tools...${NC}"

    # Check Python/pip
    if ! command_exists python3 && ! command_exists python; then
        echo -e "${RED}  ❌ Python not found${NC}"
        FAILED_TOOLS+=("Python")
        return 1
    fi

    local PIP_CMD=""
    if command_exists pip3; then
        PIP_CMD="pip3"
    elif command_exists pip; then
        PIP_CMD="pip"
    else
        echo -e "${YELLOW}  ⚠️  pip not found, trying to install...${NC}"
        python3 -m ensurepip --user 2>/dev/null || python -m ensurepip --user 2>/dev/null

        if command_exists pip3; then
            PIP_CMD="pip3"
        elif command_exists pip; then
            PIP_CMD="pip"
        else
            echo -e "${RED}  ❌ Failed to install pip${NC}"
            FAILED_TOOLS+=("pip")
            return 1
        fi
    fi

    # Install tools
    local tools=("ruff" "pytest" "bandit" "black" "mypy")
    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            echo -e "${GREEN}  ✓ $tool already installed${NC}"
            INSTALLED_TOOLS+=("$tool")
        else
            echo -e "${CYAN}  📦 Installing $tool...${NC}"
            if $PIP_CMD install --user "$tool" --quiet 2>/dev/null; then
                echo -e "${GREEN}  ✓ $tool installed successfully${NC}"
                INSTALLED_TOOLS+=("$tool")
            else
                echo -e "${YELLOW}  ⚠️  Failed to install $tool${NC}"
                FAILED_TOOLS+=("$tool")
            fi
        fi
    done
}

# Install JavaScript/TypeScript tools
install_javascript_tools() {
    echo -e "${BLUE}📦 Installing JavaScript/TypeScript quality tools...${NC}"

    # Check Node.js/npm
    if ! command_exists node || ! command_exists npm; then
        echo -e "${YELLOW}  ⚠️  Node.js/npm not found${NC}"
        echo -e "${CYAN}  💡 Install Node.js from: https://nodejs.org/${NC}"
        FAILED_TOOLS+=("Node.js")
        return 1
    fi

    # Check if package.json exists (local project)
    if [ -f "package.json" ]; then
        echo -e "${CYAN}  📁 Local project detected, installing as dev dependencies...${NC}"

        local packages=(
            "eslint"
            "@typescript-eslint/parser"
            "@typescript-eslint/eslint-plugin"
            "prettier"
            "eslint-config-prettier"
            "eslint-plugin-security"
            "jest"
        )

        npm install --save-dev "${packages[@]}" --silent 2>/dev/null

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}  ✓ JavaScript/TypeScript tools installed locally${NC}"
            INSTALLED_TOOLS+=("eslint" "prettier" "jest")
        else
            echo -e "${YELLOW}  ⚠️  Some packages failed to install${NC}"
            FAILED_TOOLS+=("npm-packages")
        fi
    else
        # Global installation
        echo -e "${CYAN}  🌍 Installing globally...${NC}"

        local tools=("eslint" "prettier" "typescript")
        for tool in "${tools[@]}"; do
            if command_exists "$tool"; then
                echo -e "${GREEN}  ✓ $tool already installed${NC}"
                INSTALLED_TOOLS+=("$tool")
            else
                echo -e "${CYAN}  📦 Installing $tool...${NC}"
                if npm install -g "$tool" --silent 2>/dev/null; then
                    echo -e "${GREEN}  ✓ $tool installed successfully${NC}"
                    INSTALLED_TOOLS+=("$tool")
                else
                    echo -e "${YELLOW}  ⚠️  Failed to install $tool (may need sudo)${NC}"
                    FAILED_TOOLS+=("$tool")
                fi
            fi
        done
    fi
}

# Install Go tools
install_go_tools() {
    echo -e "${BLUE}🐹 Installing Go quality tools...${NC}"

    # Check Go
    if ! command_exists go; then
        echo -e "${YELLOW}  ⚠️  Go not found${NC}"
        echo -e "${CYAN}  💡 Install Go from: https://golang.org/dl/${NC}"
        FAILED_TOOLS+=("Go")
        return 1
    fi

    # Install golangci-lint
    if command_exists golangci-lint; then
        echo -e "${GREEN}  ✓ golangci-lint already installed${NC}"
        INSTALLED_TOOLS+=("golangci-lint")
    else
        echo -e "${CYAN}  📦 Installing golangci-lint...${NC}"
        if curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | \
           sh -s -- -b "$(go env GOPATH)/bin" 2>/dev/null; then
            echo -e "${GREEN}  ✓ golangci-lint installed successfully${NC}"
            INSTALLED_TOOLS+=("golangci-lint")
        else
            echo -e "${YELLOW}  ⚠️  Failed to install golangci-lint${NC}"
            FAILED_TOOLS+=("golangci-lint")
        fi
    fi

    # Install other Go tools
    local tools=(
        "golang.org/x/tools/cmd/goimports@latest"
        "github.com/securego/gosec/v2/cmd/gosec@latest"
        "golang.org/x/lint/golint@latest"
    )

    for tool_path in "${tools[@]}"; do
        tool_name=$(basename "${tool_path%@*}")
        if command_exists "$tool_name"; then
            echo -e "${GREEN}  ✓ $tool_name already installed${NC}"
            INSTALLED_TOOLS+=("$tool_name")
        else
            echo -e "${CYAN}  📦 Installing $tool_name...${NC}"
            if go install "$tool_path" 2>/dev/null; then
                echo -e "${GREEN}  ✓ $tool_name installed successfully${NC}"
                INSTALLED_TOOLS+=("$tool_name")
            else
                echo -e "${YELLOW}  ⚠️  Failed to install $tool_name${NC}"
                FAILED_TOOLS+=("$tool_name")
            fi
        fi
    done
}

# Install Rust tools
install_rust_tools() {
    echo -e "${BLUE}🦀 Installing Rust quality tools...${NC}"

    # Check Rust/Cargo
    if ! command_exists cargo; then
        echo -e "${YELLOW}  ⚠️  Cargo not found${NC}"
        echo -e "${CYAN}  💡 Install Rust from: https://rustup.rs/${NC}"
        FAILED_TOOLS+=("Rust")
        return 1
    fi

    # Ensure rustfmt and clippy are installed (come with rustup)
    echo -e "${CYAN}  📦 Ensuring rustfmt and clippy are available...${NC}"
    rustup component add rustfmt clippy 2>/dev/null

    if command_exists rustfmt && command_exists cargo-clippy; then
        echo -e "${GREEN}  ✓ rustfmt and clippy installed${NC}"
        INSTALLED_TOOLS+=("rustfmt" "clippy")
    fi

    # Install cargo-audit
    if command_exists cargo-audit; then
        echo -e "${GREEN}  ✓ cargo-audit already installed${NC}"
        INSTALLED_TOOLS+=("cargo-audit")
    else
        echo -e "${CYAN}  📦 Installing cargo-audit...${NC}"
        if cargo install cargo-audit --quiet 2>/dev/null; then
            echo -e "${GREEN}  ✓ cargo-audit installed successfully${NC}"
            INSTALLED_TOOLS+=("cargo-audit")
        else
            echo -e "${YELLOW}  ⚠️  Failed to install cargo-audit${NC}"
            FAILED_TOOLS+=("cargo-audit")
        fi
    fi

    # Install cargo-expand (useful for macro debugging)
    if command_exists cargo-expand; then
        echo -e "${GREEN}  ✓ cargo-expand already installed${NC}"
        INSTALLED_TOOLS+=("cargo-expand")
    else
        echo -e "${CYAN}  📦 Installing cargo-expand...${NC}"
        if cargo install cargo-expand --quiet 2>/dev/null; then
            echo -e "${GREEN}  ✓ cargo-expand installed successfully${NC}"
            INSTALLED_TOOLS+=("cargo-expand")
        else
            echo -e "${YELLOW}  ⚠️  Failed to install cargo-expand${NC}"
            FAILED_TOOLS+=("cargo-expand")
        fi
    fi
}

# Detect and install tools for current project
install_for_current_project() {
    local project_dir="${1:-.}"

    echo -e "${BLUE}🔍 Detecting project languages...${NC}"

    # Detect languages
    local languages=($(detect_languages "$project_dir"))

    if [ ${#languages[@]} -eq 0 ]; then
        echo -e "${YELLOW}⚠️  No supported languages detected in current directory${NC}"
        echo -e "${CYAN}💡 Tip: Navigate to a project directory and run again${NC}"
        return 1
    fi

    echo -e "${GREEN}✓ Detected languages: ${languages[*]}${NC}"
    echo ""

    # Install tools for each detected language
    for lang in "${languages[@]}"; do
        case "$lang" in
            python)
                install_python_tools
                ;;
            javascript|typescript)
                install_javascript_tools
                ;;
            go)
                install_go_tools
                ;;
            rust)
                install_rust_tools
                ;;
        esac
        echo ""
    done
}

# Install all tools
install_all_tools() {
    echo -e "${BLUE}📦 Installing tools for all supported languages...${NC}"
    echo ""

    install_python_tools
    echo ""
    install_javascript_tools
    echo ""
    install_go_tools
    echo ""
    install_rust_tools
}

# Show summary
show_summary() {
    echo ""
    echo -e "${CYAN}════════════════════════════════${NC}"
    echo -e "${CYAN}       Installation Summary${NC}"
    echo -e "${CYAN}════════════════════════════════${NC}"

    if [ ${#INSTALLED_TOOLS[@]} -gt 0 ]; then
        echo -e "${GREEN}✅ Successfully installed/verified:${NC}"
        for tool in "${INSTALLED_TOOLS[@]}"; do
            echo -e "  ${GREEN}✓${NC} $tool"
        done
    fi

    if [ ${#FAILED_TOOLS[@]} -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}⚠️  Failed to install:${NC}"
        for tool in "${FAILED_TOOLS[@]}"; do
            echo -e "  ${YELLOW}✗${NC} $tool"
        done
    fi

    echo ""
    if [ ${#FAILED_TOOLS[@]} -eq 0 ]; then
        echo -e "${GREEN}🎉 All tools are ready!${NC}"
        echo -e "${CYAN}Run 'trinitas-guard check' to verify your code quality${NC}"
    else
        echo -e "${YELLOW}Some tools failed to install.${NC}"
        echo -e "${CYAN}You may need to install them manually or with appropriate permissions.${NC}"
    fi
}

# Main execution
main() {
    show_banner

    # Parse arguments
    case "${1:-auto}" in
        all)
            install_all_tools
            ;;
        python)
            install_python_tools
            ;;
        javascript|js|typescript|ts)
            install_javascript_tools
            ;;
        go|golang)
            install_go_tools
            ;;
        rust)
            install_rust_tools
            ;;
        auto|*)
            install_for_current_project "."
            ;;
    esac

    show_summary
}

# Help message
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "Trinitas Quality Guardian - Tools Installer"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  auto       Detect and install tools for current project (default)"
    echo "  all        Install tools for all supported languages"
    echo "  python     Install Python tools only"
    echo "  javascript Install JavaScript/TypeScript tools only"
    echo "  go         Install Go tools only"
    echo "  rust       Install Rust tools only"
    echo ""
    echo "Examples:"
    echo "  $0             # Auto-detect and install"
    echo "  $0 all         # Install everything"
    echo "  $0 python      # Install Python tools only"
    exit 0
fi

# Run main
main "$@"