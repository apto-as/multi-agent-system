#!/bin/bash
# =============================================================================
# Trinitas Multi-Agent System Installer v2.4.37
# For OpenCode on Linux/macOS/WSL
# =============================================================================
#
# This installer sets up:
#   1. TMWS-Go (Trinitas Memory & Workflow System) native binaries
#   2. Trinitas agents, plugins, and configuration for OpenCode
#   3. Pre-activated ENTERPRISE license
#
# Features:
#   - Native binary installation (no Docker required)
#   - Automatic backup of existing installations
#   - Upgrade support for existing TMWS/Trinitas installations
#   - Platform-specific optimizations
#
# Supported platforms: Ubuntu 20.04+, Debian 11+, macOS 12+, WSL2
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install-opencode.sh | bash
#   # or
#   ./install-opencode.sh
#
# =============================================================================

set -euo pipefail

# Version
INSTALLER_VERSION="2.4.37"
TMWS_VERSION="2.4.37"
INSTALLER_TYPE="opencode"

# =============================================================================
# Resolve actual user's home directory
# =============================================================================
resolve_real_home() {
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        if command -v getent &> /dev/null; then
            getent passwd "$SUDO_USER" | cut -d: -f6
        else
            eval echo "~$SUDO_USER"
        fi
    elif [ "$(id -u)" = "0" ] && [ -z "${SUDO_USER:-}" ]; then
        echo "$HOME"
    else
        echo "$HOME"
    fi
}

REAL_HOME="$(resolve_real_home)"
REAL_USER="${SUDO_USER:-$(whoami)}"

# Installation directories
TMWS_INSTALL_DIR="${TMWS_INSTALL_DIR:-${REAL_HOME}/.tmws}"
TMWS_BIN_DIR="${TMWS_INSTALL_DIR}/bin"
TRINITAS_CONFIG_DIR="${REAL_HOME}/.trinitas"
OPENCODE_CONFIG_DIR="${REAL_HOME}/.config/opencode"
BACKUP_DIR="${REAL_HOME}/.trinitas-backup"

# Pre-activated ENTERPRISE license (TMWS-Go v1.0)
DEFAULT_LICENSE_KEY="TMWS-1.0-eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtdWx0aS1hZ2VudC1zeXN0ZW0tdHJpYWwtdjEuMCIsImlzcyI6InRtd3MuYXB0by5haSIsImlhdCI6MTc2NjI0NDc0OSwiZXhwIjoxNzc0MDIwNzQ5LCJuYmYiOjE3NjYyNDQ3NDksImxpZCI6Ijc4OGNlYzE4LWMzYTAtNGI4Ny05ZWM2LWZmOTAyZTAyM2E5YSIsImx0eXBlIjoiZW50ZXJwcmlzZSIsIm9yZyI6IlRyaW5pdGFzIENvbW11bml0eSIsImZlYXR1cmVzIjpbIm1lbW9yeS5iYXNpYyIsIm1lbW9yeS5hZHZhbmNlZCIsImFnZW50LmJhc2ljIiwiYWdlbnQuYWR2YW5jZWQiLCJhZ2VudC50cnVzdCIsInNraWxscy5iYXNpYyIsInNraWxscy5hZHZhbmNlZCIsInBhdHRlcm5zLmxlYXJuaW5nIiwidHJpbml0YXMucm91dGluZyIsInRyaW5pdGFzLm9yY2hlc3RyYXRpb24iLCJtY3AuaHViLmJhc2ljIiwibWNwLmh1Yi5hZHZhbmNlZCIsImxpZmVjeWNsZS5zY2hlZHVsZXIiLCJjb252ZXJzYXRpb24ubG9nZ2luZyIsImVudGVycHJpc2UubXVsdGl0ZW5hbmN5Il0sIm1heF9tZW1vcmllcyI6LTEsIm1heF9hZ2VudHMiOi0xLCJtYXhfc2tpbGxzIjotMSwibWF4X21jcF9zZXJ2ZXJzIjotMX0.Vnrbd857WfMc3dsNJEYMlkSilXEat1n_vc4Z6BKeAnENyEeMydjO3RBMuZ3GutNSy0CnkBvBYsJbN0x_TDxuDQ"
DEFAULT_LICENSE_PUBLIC_KEY="XRa6aVOcwUzeurz2AGx+/1KlC3CEokjWcq3pqcd0fIo="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${MAGENTA}[STEP]${NC} $1"; }

# Banner
show_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   ████████╗██████╗ ██╗███╗   ██╗██╗████████╗ █████╗ ███████╗         ║
║   ╚══██╔══╝██╔══██╗██║████╗  ██║██║╚══██╔══╝██╔══██╗██╔════╝         ║
║      ██║   ██████╔╝██║██╔██╗ ██║██║   ██║   ███████║███████╗         ║
║      ██║   ██╔══██╗██║██║╚██╗██║██║   ██║   ██╔══██║╚════██║         ║
║      ██║   ██║  ██║██║██║ ╚████║██║   ██║   ██║  ██║███████║         ║
║      ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝         ║
║                                                                       ║
║            Multi-Agent System Installer v2.4.37                       ║
║            For OpenCode (Native Mode)                                 ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Detect OS
detect_os() {
    local os
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$os" in
        darwin) echo "darwin" ;;
        linux) echo "linux" ;;
        *) log_error "Unsupported OS: $os" ; exit 1 ;;
    esac
}

# Detect architecture
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) log_error "Unsupported architecture: $arch" ; exit 1 ;;
    esac
}

# Platform detection
detect_platform() {
    case "$(uname -s)" in
        Darwin*)
            PLATFORM="macOS"
            PACKAGE_MANAGER="brew"
            ;;
        Linux*)
            PLATFORM="Linux"
            if [ -f /etc/debian_version ]; then
                PACKAGE_MANAGER="apt"
            elif [ -f /etc/redhat-release ]; then
                PACKAGE_MANAGER="yum"
            else
                PACKAGE_MANAGER="unknown"
            fi
            if grep -qi microsoft /proc/version 2>/dev/null; then
                PLATFORM="WSL"
            fi
            ;;
        *)
            PLATFORM="Unknown"
            PACKAGE_MANAGER="unknown"
            ;;
    esac
    log_info "Detected platform: ${PLATFORM} (${PACKAGE_MANAGER})"
}

# Get latest TMWS release version
get_latest_tmws_version() {
    local version
    version=$(curl -fsSL "https://api.github.com/repos/apto-as/multi-agent-system/releases" 2>/dev/null | \
        grep '"tag_name":' | grep 'tmws-v' | head -1 | sed -E 's/.*"tmws-(v[^"]+)".*/\1/')
    if [ -z "$version" ]; then
        echo "v${TMWS_VERSION}"
    else
        echo "$version"
    fi
}

# Download and install native TMWS binaries
install_native_binaries() {
    log_step "Installing TMWS native binaries..."

    local os arch version url archive_name tmp_dir
    os=$(detect_os)
    arch=$(detect_arch)
    version=$(get_latest_tmws_version)

    archive_name="tmws-${os}-${arch}.tar.gz"
    url="https://github.com/apto-as/multi-agent-system/releases/download/tmws-${version}/${archive_name}"

    log_info "Downloading TMWS ${version} for ${os}/${arch}..."
    log_info "URL: ${url}"

    tmp_dir=$(mktemp -d -t tmws-install.XXXXXXXX)
    trap "rm -rf $tmp_dir" EXIT

    if ! curl -fsSL "$url" -o "${tmp_dir}/${archive_name}"; then
        log_error "Failed to download TMWS binaries"
        log_error "URL: ${url}"
        exit 1
    fi

    mkdir -p "${TMWS_BIN_DIR}"
    tar -xzf "${tmp_dir}/${archive_name}" -C "${tmp_dir}"

    for bin in tmws-server tmws-mcp tmws-cli tmws-hook; do
        if [ -f "${tmp_dir}/${bin}" ]; then
            mv "${tmp_dir}/${bin}" "${TMWS_BIN_DIR}/"
            chmod +x "${TMWS_BIN_DIR}/${bin}"
            log_success "Installed ${bin}"
        fi
    done

    ln -sf "${TMWS_BIN_DIR}/tmws-mcp" "${TMWS_BIN_DIR}/tmws" 2>/dev/null || true
    log_success "TMWS binaries installed to ${TMWS_BIN_DIR}"
}

# Setup PATH
setup_native_path() {
    log_step "Setting up PATH..."

    local shell_rc=""
    local shell_name

    if [ -n "${SUDO_USER:-}" ]; then
        shell_name=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f7 | xargs basename 2>/dev/null || echo "bash")
    else
        shell_name=$(basename "$SHELL")
    fi

    case "$shell_name" in
        bash) shell_rc="${REAL_HOME}/.bashrc" ;;
        zsh) shell_rc="${REAL_HOME}/.zshrc" ;;
        fish) shell_rc="${REAL_HOME}/.config/fish/config.fish" ;;
        *) log_warn "Unknown shell: $shell_name. Add ${TMWS_BIN_DIR} to PATH manually." ; return ;;
    esac

    if [ -f "$shell_rc" ]; then
        if ! grep -q "TMWS_HOME" "$shell_rc"; then
            if [ "$shell_name" = "fish" ]; then
                echo "" >> "$shell_rc"
                echo "# TMWS" >> "$shell_rc"
                echo "set -gx TMWS_HOME ${TMWS_INSTALL_DIR}" >> "$shell_rc"
                echo "fish_add_path ${TMWS_BIN_DIR}" >> "$shell_rc"
            else
                echo "" >> "$shell_rc"
                echo "# TMWS" >> "$shell_rc"
                echo "export TMWS_HOME=\"${TMWS_INSTALL_DIR}\"" >> "$shell_rc"
                echo "export PATH=\"\$TMWS_HOME/bin:\$PATH\"" >> "$shell_rc"
            fi
            log_success "Added TMWS to PATH in ${shell_rc}"
        else
            log_info "TMWS already in PATH"
        fi
    fi
}

# Check for existing installation
check_existing_installation() {
    log_step "Checking for existing installation..."

    local existing=false
    local existing_items=()

    if [ -d "${TRINITAS_CONFIG_DIR}" ]; then
        existing=true
        existing_items+=("~/.trinitas/")
    fi

    if [ -d "${OPENCODE_CONFIG_DIR}" ] && [ -f "${OPENCODE_CONFIG_DIR}/opencode.md" ]; then
        existing=true
        existing_items+=("~/.config/opencode/ (Trinitas config)")
    fi

    if [ -d "${REAL_HOME}/.tmws" ]; then
        existing=true
        existing_items+=("~/.tmws/ (data)")
    fi

    if [ "$existing" = true ]; then
        log_warn "Existing Trinitas/TMWS installation detected:"
        for item in "${existing_items[@]}"; do
            echo "  - ${item}"
        done
        echo ""
        return 0
    else
        log_info "No existing installation found (fresh install)"
        return 1
    fi
}

# Create backup
create_backup() {
    log_step "Creating backup of existing installation..."

    local backup_timestamp=$(date +%Y%m%d-%H%M%S)
    local backup_path="${BACKUP_DIR}/${backup_timestamp}"

    mkdir -p "${backup_path}"

    if [ -d "${TRINITAS_CONFIG_DIR}" ]; then
        cp -r "${TRINITAS_CONFIG_DIR}" "${backup_path}/trinitas"
        log_success "Backed up ~/.trinitas/"
    fi

    if [ -d "${OPENCODE_CONFIG_DIR}" ]; then
        mkdir -p "${backup_path}/opencode"
        for file in opencode.md opencode.json AGENTS.md; do
            if [ -f "${OPENCODE_CONFIG_DIR}/${file}" ]; then
                cp "${OPENCODE_CONFIG_DIR}/${file}" "${backup_path}/opencode/"
            fi
        done
        for dir in agent plugin command; do
            if [ -d "${OPENCODE_CONFIG_DIR}/${dir}" ]; then
                cp -r "${OPENCODE_CONFIG_DIR}/${dir}" "${backup_path}/opencode/"
            fi
        done
        log_success "Backed up ~/.config/opencode/ (Trinitas config)"
    fi

    if [ -d "${REAL_HOME}/.tmws" ]; then
        mkdir -p "${backup_path}/tmws"
        find "${REAL_HOME}/.tmws" -maxdepth 2 -type f \( -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.env" \) \
            -exec cp {} "${backup_path}/tmws/" \; 2>/dev/null || true
        log_success "Backed up ~/.tmws/ (config only)"
    fi

    cat > "${backup_path}/backup-info.txt" << EOF
Trinitas Backup (OpenCode)
==========================
Date: $(date -Iseconds)
Previous Version: $(cat "${TRINITAS_CONFIG_DIR}/.version" 2>/dev/null || echo "unknown")
New Version: ${TMWS_VERSION}
Installer: ${INSTALLER_TYPE}
Platform: ${PLATFORM}

Contents:
$(ls -la "${backup_path}")
EOF

    echo ""
    log_success "Backup created at: ${backup_path}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."

    local missing=()

    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi

    if ! command -v git &> /dev/null; then
        log_warn "git not found (optional)"
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing prerequisites: ${missing[*]}"
        echo ""
        echo "Please install the missing packages:"
        case "$PACKAGE_MANAGER" in
            apt)
                echo "  sudo apt update && sudo apt install -y ${missing[*]}"
                ;;
            brew)
                echo "  brew install ${missing[*]}"
                ;;
            *)
                echo "  Please install: ${missing[*]}"
                ;;
        esac
        exit 1
    fi

    log_success "All prerequisites satisfied"
}

# Create directory structure
create_directories() {
    log_step "Creating directory structure..."

    mkdir -p "${TRINITAS_CONFIG_DIR}"
    mkdir -p "${OPENCODE_CONFIG_DIR}/agent"
    mkdir -p "${OPENCODE_CONFIG_DIR}/plugin"
    mkdir -p "${OPENCODE_CONFIG_DIR}/command"
    mkdir -p "${TMWS_INSTALL_DIR}/data"

    echo "${TMWS_VERSION}" > "${TRINITAS_CONFIG_DIR}/.version"
    log_success "Directories created"
}

# Generate secret key
generate_secret_key() {
    if command -v openssl &> /dev/null; then
        openssl rand -hex 32
    else
        head -c 32 /dev/urandom | xxd -p | tr -d '\n'
    fi
}

# Setup TMWS configuration
setup_tmws_config() {
    log_step "Setting up TMWS configuration..."

    local config_file="${TMWS_INSTALL_DIR}/config.yaml"
    local env_file="${TMWS_INSTALL_DIR}/.env"

    # Create config.yaml
    cat > "${config_file}" << EOF
# TMWS-Go Configuration
# Version: ${TMWS_VERSION}
# Generated: $(date -Iseconds)

database:
  driver: "sqlite3"
  path: "${TMWS_INSTALL_DIR}/data/tmws.db"
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: 5m

vector:
  backend: "sqlite-vec"
  dimension: 1024
  distance: "cosine"

memory:
  default_ttl: 720h
  max_memories_per_namespace: 10000
  cleanup_interval: 1h

embedding:
  provider: "ollama"
  model: "mxbai-embed-large"
  dimension: 1024
  batch_size: 32
EOF

    # Create .env file
    local existing_secret=""
    if [ -f "${env_file}" ]; then
        existing_secret=$(grep "^TMWS_SECRET_KEY=" "${env_file}" 2>/dev/null | cut -d'=' -f2 || echo "")
    fi

    local secret_key="${existing_secret:-$(generate_secret_key)}"

    cat > "${env_file}" << EOF
# TMWS-Go Environment - Generated by Trinitas Installer
# Version: ${TMWS_VERSION}
# Generated: $(date -Iseconds)
# Mode: native

TMWS_ENV=development
TMWS_LOG_LEVEL=info
TMWS_SECRET_KEY=${secret_key}
TMWS_LICENSE_KEY="${DEFAULT_LICENSE_KEY}"
TMWS_LICENSE_PUBLIC_KEY="${DEFAULT_LICENSE_PUBLIC_KEY}"
TMWS_CONFIG_PATH=${config_file}
OLLAMA_HOST=http://localhost:11434
EOF

    chmod 600 "${env_file}"
    log_success "TMWS configuration created"
}

# Install OpenCode configuration
install_opencode_config() {
    log_step "Installing Trinitas configuration for OpenCode..."

    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || echo "")"
    local config_src="${script_dir}/config/open-code"
    local github_base="https://raw.githubusercontent.com/apto-as/multi-agent-system/main"
    local use_github=false

    if [ -z "${script_dir}" ] || [ ! -d "${config_src}" ]; then
        log_info "Downloading configuration from GitHub..."
        use_github=true
        config_src=$(mktemp -d -t trinitas-install.XXXXXXXX)
        trap 'rm -rf "${config_src}" 2>/dev/null || true' EXIT

        mkdir -p "${config_src}/agent" "${config_src}/command" "${config_src}/plugin"

        # Download main config files
        curl -fsSL "${github_base}/config/open-code/opencode.md" -o "${config_src}/opencode.md" 2>/dev/null || true
        curl -fsSL "${github_base}/config/open-code/opencode.json" -o "${config_src}/opencode.json" 2>/dev/null || true
        curl -fsSL "${github_base}/config/open-code/AGENTS.md" -o "${config_src}/AGENTS.md" 2>/dev/null || true

        # Download agents (11 total)
        for agent in clotho lachesis athena artemis hestia eris hera muses aphrodite metis aurora; do
            curl -fsSL "${github_base}/config/open-code/agent/${agent}.md" -o "${config_src}/agent/${agent}.md" 2>/dev/null || true
        done

        # Download commands
        curl -fsSL "${github_base}/config/open-code/command/trinitas.md" -o "${config_src}/command/trinitas.md" 2>/dev/null || true

        # Download plugins
        curl -fsSL "${github_base}/config/open-code/plugin/trinitas-orchestration.js" -o "${config_src}/plugin/trinitas-orchestration.js" 2>/dev/null || true
        curl -fsSL "${github_base}/config/open-code/plugin/trinitas-trigger-processor.js" -o "${config_src}/plugin/trinitas-trigger-processor.js" 2>/dev/null || true
    fi

    # Copy files
    if [ -f "${config_src}/opencode.md" ]; then
        cp "${config_src}/opencode.md" "${OPENCODE_CONFIG_DIR}/"
        log_success "Copied opencode.md"
    else
        log_error "opencode.md not found - this is required for Trinitas to function"
    fi

    if [ -f "${config_src}/AGENTS.md" ]; then
        cp "${config_src}/AGENTS.md" "${OPENCODE_CONFIG_DIR}/"
        log_success "Copied AGENTS.md"
    fi

    if [ -d "${config_src}/agent" ] && [ "$(ls -A ${config_src}/agent 2>/dev/null)" ]; then
        rm -rf "${OPENCODE_CONFIG_DIR}/agent"
        mkdir -p "${OPENCODE_CONFIG_DIR}/agent"
        cp -r "${config_src}/agent"/* "${OPENCODE_CONFIG_DIR}/agent/"
        log_success "Copied agent definitions (11 agents)"
    fi

    if [ -d "${config_src}/command" ] && [ "$(ls -A ${config_src}/command 2>/dev/null)" ]; then
        rm -rf "${OPENCODE_CONFIG_DIR}/command"
        mkdir -p "${OPENCODE_CONFIG_DIR}/command"
        cp -r "${config_src}/command"/* "${OPENCODE_CONFIG_DIR}/command/"
        log_success "Copied command definitions"
    fi

    if [ -d "${config_src}/plugin" ] && [ "$(ls -A ${config_src}/plugin 2>/dev/null)" ]; then
        rm -rf "${OPENCODE_CONFIG_DIR}/plugin"
        mkdir -p "${OPENCODE_CONFIG_DIR}/plugin"
        cp -r "${config_src}/plugin"/* "${OPENCODE_CONFIG_DIR}/plugin/"
        log_success "Copied plugins (orchestration, trigger-processor)"
    fi

    if [ "${use_github}" = true ] && [ -d "${config_src}" ]; then
        rm -rf "${config_src}"
    fi
}

# Configure OpenCode settings
configure_opencode_settings() {
    log_step "Configuring OpenCode MCP settings..."

    cat > "${OPENCODE_CONFIG_DIR}/opencode.json" << EOF
{
  "\$schema": "https://opencode.ai/config.json",
  "mcp": {
    "tmws": {
      "type": "local",
      "command": ["${TMWS_BIN_DIR}/tmws-mcp"],
      "env": {
        "TMWS_CONFIG_PATH": "${TMWS_INSTALL_DIR}/config.yaml",
        "OLLAMA_HOST": "http://localhost:11434"
      },
      "enabled": true,
      "timeout": 10000
    },
    "context7": {
      "type": "local",
      "command": ["npx", "-y", "@upstash/context7-mcp"],
      "enabled": true
    },
    "serena": {
      "type": "local",
      "command": ["uvx", "--from", "git+https://github.com/oraios/serena", "serena-mcp-server", "--context", "ide-assistant"],
      "enabled": true
    }
  },
  "instructions": [
    "{file:~/.config/opencode/opencode.md}",
    "{file:~/.config/opencode/AGENTS.md}"
  ]
}
EOF

    log_success "OpenCode configuration created (native mode)"
}

# Check Ollama
check_ollama() {
    log_step "Checking Ollama installation..."

    if command -v ollama &> /dev/null; then
        log_success "Ollama is installed"

        if curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
            log_success "Ollama is running"

            if ollama list 2>/dev/null | grep -q "mxbai-embed-large"; then
                log_success "Required model available"
            else
                log_warn "Required model not found. Run: ollama pull mxbai-embed-large"
            fi
        else
            log_warn "Ollama is not running. Start with: ollama serve"
        fi
    else
        log_warn "Ollama is not installed"
        echo "Install: curl -fsSL https://ollama.ai/install.sh | sh"
    fi
}

# Fix file ownership
fix_ownership() {
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        log_step "Fixing file ownership for user: ${SUDO_USER}..."

        for dir in "${TMWS_INSTALL_DIR}" "${TRINITAS_CONFIG_DIR}" "${OPENCODE_CONFIG_DIR}"; do
            if [ -d "$dir" ]; then
                chown -R "${SUDO_USER}:$(id -gn "$SUDO_USER" 2>/dev/null || echo "$SUDO_USER")" "$dir" 2>/dev/null || true
            fi
        done

        log_success "File ownership fixed"
    fi
}

# Show completion message
show_completion() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Installation Complete! (OpenCode)                           ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}What was installed:${NC}"
    echo "  - TMWS-Go native binaries (tmws-mcp, tmws-server, tmws-cli)"
    echo "  - Trinitas 11-agent configuration for OpenCode"
    echo "  - Pre-activated ENTERPRISE license"
    echo ""
    echo -e "${CYAN}Configuration locations:${NC}"
    echo "  - TMWS binaries:   ${TMWS_BIN_DIR}/"
    echo "  - TMWS config:     ${TMWS_INSTALL_DIR}/"
    echo "  - OpenCode:        ${OPENCODE_CONFIG_DIR}/"
    if [ -d "${BACKUP_DIR}" ]; then
        echo "  - Backups:         ${BACKUP_DIR}/"
    fi
    echo ""
    echo -e "${CYAN}Quick start:${NC}"
    echo "  1. Reload your shell or run: source ~/.bashrc (or ~/.zshrc)"
    echo "  2. Ensure Ollama is running: ollama serve"
    echo "  3. Pull embedding model: ollama pull mxbai-embed-large"
    echo "  4. Start OpenCode in your project directory"
    echo "  5. Use /trinitas command to interact with agents"
    echo ""
    echo -e "${GREEN}License: ENTERPRISE (TMWS-Go v${TMWS_VERSION})${NC}"
    echo ""
    echo -e "${GREEN}Enjoy Trinitas Multi-Agent System!${NC}"
    echo ""
}

# Main
main() {
    show_banner

    if [ -n "${SUDO_USER:-}" ]; then
        log_warn "sudo is not required for native mode installation"
        log_info "Installing for user: ${SUDO_USER} (${REAL_HOME})"
        echo ""
    fi

    detect_platform
    check_prerequisites

    if check_existing_installation; then
        echo ""
        if [ -t 0 ]; then
            read -p "Do you want to upgrade? (existing data will be backed up) [Y/n] " -n 1 -r
        else
            read -p "Do you want to upgrade? (existing data will be backed up) [Y/n] " -n 1 -r < /dev/tty
        fi
        echo ""
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            create_backup
        else
            log_info "Installation cancelled"
            exit 0
        fi
    fi

    create_directories
    install_native_binaries
    setup_native_path
    setup_tmws_config
    install_opencode_config
    configure_opencode_settings
    fix_ownership
    check_ollama
    show_completion
}

main "$@"
