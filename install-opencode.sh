#!/bin/bash
# =============================================================================
# Trinitas Multi-Agent System Installer v2.4.12
# For OpenCode on Linux/macOS/WSL
# =============================================================================
#
# This installer sets up:
#   1. TMWS (Trinitas Memory & Workflow System) via Docker
#   2. Trinitas agents, plugins, and configuration for OpenCode
#   3. License key activation (90-day ENTERPRISE trial included)
#
# Features:
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
INSTALLER_VERSION="2.4.12"
TMWS_VERSION="2.4.12"
INSTALLER_TYPE="opencode"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
TMWS_IMAGE="ghcr.io/apto-as/tmws:${TMWS_VERSION}"
TRINITAS_CONFIG_DIR="${HOME}/.trinitas"
OPENCODE_CONFIG_DIR="${HOME}/.config/opencode"
BACKUP_DIR="${HOME}/.trinitas-backup"

# License key (ENTERPRISE trial)
DEFAULT_LICENSE_KEY="TMWS-ENTERPRISE-020d8e77-de36-48a1-b585-7f66aef78c06-20260303-Tp9UYRt6ucUB21hPF9lqZoH.FjSslvfr~if1ThD75L.ro~Kx5glyVyGPm0n4xuziJ~Qmc87PZipJWCefj2HEAA"

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
║            Multi-Agent System Installer v2.4.12                       ║
║            For OpenCode - 90-Day ENTERPRISE Trial                     ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
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
            # WSL detection
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

    if [ -d "${HOME}/.tmws" ]; then
        existing=true
        existing_items+=("~/.tmws/ (data)")
    fi

    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "tmws"; then
        existing=true
        existing_items+=("tmws Docker container")
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

# Create backup of existing installation
create_backup() {
    log_step "Creating backup of existing installation..."

    local backup_timestamp=$(date +%Y%m%d-%H%M%S)
    local backup_path="${BACKUP_DIR}/${backup_timestamp}"

    mkdir -p "${backup_path}"

    # Backup ~/.trinitas
    if [ -d "${TRINITAS_CONFIG_DIR}" ]; then
        cp -r "${TRINITAS_CONFIG_DIR}" "${backup_path}/trinitas"
        log_success "Backed up ~/.trinitas/"
    fi

    # Backup ~/.config/opencode (Trinitas-related files only)
    if [ -d "${OPENCODE_CONFIG_DIR}" ]; then
        mkdir -p "${backup_path}/opencode"

        # Core config files
        for file in opencode.md opencode.json AGENTS.md; do
            if [ -f "${OPENCODE_CONFIG_DIR}/${file}" ]; then
                cp "${OPENCODE_CONFIG_DIR}/${file}" "${backup_path}/opencode/"
            fi
        done

        # Directories
        for dir in agent plugin command; do
            if [ -d "${OPENCODE_CONFIG_DIR}/${dir}" ]; then
                cp -r "${OPENCODE_CONFIG_DIR}/${dir}" "${backup_path}/opencode/"
            fi
        done

        log_success "Backed up ~/.config/opencode/ (Trinitas config)"
    fi

    # Backup ~/.tmws (metadata only, not large DB files)
    if [ -d "${HOME}/.tmws" ]; then
        mkdir -p "${backup_path}/tmws"

        find "${HOME}/.tmws" -maxdepth 2 -type f \( -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.env" \) \
            -exec cp {} "${backup_path}/tmws/" \; 2>/dev/null || true

        log_success "Backed up ~/.tmws/ (config only)"
    fi

    # Record backup info
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

# Stop existing TMWS container
stop_existing_tmws() {
    log_step "Stopping existing TMWS container..."

    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "tmws-app"; then
        docker stop tmws-app 2>/dev/null || true
        log_success "Stopped tmws-app container"
    fi

    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "tmws-app"; then
        docker rm tmws-app 2>/dev/null || true
        log_success "Removed old tmws-app container"
    fi

    # Also check for legacy container names
    for container in tmws tmws-server trinitas-tmws; do
        if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${container}$"; then
            docker stop "${container}" 2>/dev/null || true
            docker rm "${container}" 2>/dev/null || true
            log_info "Removed legacy container: ${container}"
        fi
    done
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."

    local missing=()

    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi

    if ! command -v git &> /dev/null; then
        missing+=("git")
    fi

    if ! command -v docker &> /dev/null; then
        missing+=("docker")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing prerequisites: ${missing[*]}"
        echo ""
        echo "Please install the missing packages:"
        case "$PACKAGE_MANAGER" in
            apt)
                echo "  sudo apt update && sudo apt install -y ${missing[*]}"
                if [[ " ${missing[*]} " =~ " docker " ]]; then
                    echo ""
                    echo "For Docker on Ubuntu/Debian:"
                    echo "  curl -fsSL https://get.docker.com | sudo sh"
                    echo "  sudo usermod -aG docker \$USER"
                fi
                ;;
            brew)
                echo "  brew install ${missing[*]}"
                if [[ " ${missing[*]} " =~ " docker " ]]; then
                    echo ""
                    echo "For Docker on macOS:"
                    echo "  brew install --cask docker"
                fi
                ;;
            *)
                echo "  Please install: ${missing[*]}"
                ;;
        esac
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
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
    mkdir -p "${HOME}/.tmws/db"
    mkdir -p "${HOME}/.tmws/logs"
    mkdir -p "${HOME}/.tmws/vector_store"

    echo "${TMWS_VERSION}" > "${TRINITAS_CONFIG_DIR}/.version"

    log_success "Directories created"
}

# Pull TMWS Docker image
pull_tmws_image() {
    log_step "Pulling TMWS Docker image (${TMWS_IMAGE})..."

    if docker pull "${TMWS_IMAGE}"; then
        log_success "TMWS image pulled successfully"
    else
        log_error "Failed to pull TMWS image"
        exit 1
    fi
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

    local env_file="${TRINITAS_CONFIG_DIR}/.env"

    local existing_secret=""
    if [ -f "${env_file}" ]; then
        existing_secret=$(grep "^TMWS_SECRET_KEY=" "${env_file}" 2>/dev/null | cut -d'=' -f2 || echo "")
    fi

    local secret_key="${existing_secret:-$(generate_secret_key)}"

    cat > "${env_file}" << EOF
# TMWS Configuration - Generated by Trinitas Installer
# Version: ${TMWS_VERSION}
# Generated: $(date -Iseconds)
# Installer: ${INSTALLER_TYPE}

# Environment
TMWS_ENVIRONMENT=production
TMWS_LOG_LEVEL=INFO

# Security (Auto-generated - DO NOT SHARE)
TMWS_SECRET_KEY=${secret_key}

# License Key (90-day ENTERPRISE trial)
TMWS_LICENSE_KEY="${DEFAULT_LICENSE_KEY}"

# Database (SQLite - stored in ~/.tmws/db/)
TMWS_DATABASE_URL=sqlite+aiosqlite:////root/.tmws/db/tmws.db

# Embedding Service (Ollama required)
OLLAMA_BASE_URL=http://host.docker.internal:11434
EOF

    chmod 600 "${env_file}"
    log_success "TMWS configuration created"
}

# Create Docker Compose file
create_docker_compose() {
    log_step "Creating Docker Compose configuration..."

    cat > "${TRINITAS_CONFIG_DIR}/docker-compose.yml" << EOF
# Trinitas TMWS Docker Compose
# Version: ${TMWS_VERSION}
# Installer: ${INSTALLER_TYPE}

services:
  tmws:
    image: ${TMWS_IMAGE}
    container_name: tmws-app
    restart: unless-stopped
    ports:
      - "8892:8892"
      - "8000:8000"
    volumes:
      - ${HOME}/.tmws/db:/root/.tmws/db
      - ${HOME}/.tmws/logs:/root/.tmws/logs
      - ${HOME}/.tmws/vector_store:/root/.tmws/vector_store
    env_file:
      - .env
    extra_hosts:
      - "host.docker.internal:host-gateway"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
EOF

    log_success "Docker Compose configuration created"
}

# Install OpenCode configuration
install_opencode_config() {
    log_step "Installing Trinitas configuration for OpenCode..."

    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Copy opencode.md from distribution
    if [ -f "${script_dir}/opencode/opencode.md" ]; then
        cp "${script_dir}/opencode/opencode.md" "${OPENCODE_CONFIG_DIR}/"
        log_success "Copied opencode.md"
    else
        log_warn "opencode.md not found in distribution"
    fi

    # Copy AGENTS.md
    if [ -f "${script_dir}/opencode/AGENTS.md" ]; then
        cp "${script_dir}/opencode/AGENTS.md" "${OPENCODE_CONFIG_DIR}/"
        log_success "Copied AGENTS.md"
    fi

    # Copy agent definitions (OpenCode uses different naming)
    if [ -d "${script_dir}/opencode/agent" ]; then
        rm -rf "${OPENCODE_CONFIG_DIR}/agent"
        mkdir -p "${OPENCODE_CONFIG_DIR}/agent"
        cp -r "${script_dir}/opencode/agent"/* "${OPENCODE_CONFIG_DIR}/agent/"
        log_success "Copied agent definitions (9 agents)"
    fi

    # Copy commands
    if [ -d "${script_dir}/opencode/command" ]; then
        rm -rf "${OPENCODE_CONFIG_DIR}/command"
        mkdir -p "${OPENCODE_CONFIG_DIR}/command"
        cp -r "${script_dir}/opencode/command"/* "${OPENCODE_CONFIG_DIR}/command/"
        log_success "Copied command definitions"
    fi

    # Copy plugins
    if [ -d "${script_dir}/opencode/plugin" ]; then
        rm -rf "${OPENCODE_CONFIG_DIR}/plugin"
        mkdir -p "${OPENCODE_CONFIG_DIR}/plugin"
        cp -r "${script_dir}/opencode/plugin"/* "${OPENCODE_CONFIG_DIR}/plugin/"
        log_success "Copied plugins (orchestration, trigger-processor)"
    fi
}

# Configure OpenCode settings
configure_opencode_settings() {
    log_step "Configuring OpenCode MCP settings..."

    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Copy opencode.json from distribution if available
    if [ -f "${script_dir}/opencode/opencode.json" ]; then
        cp "${script_dir}/opencode/opencode.json" "${OPENCODE_CONFIG_DIR}/"
        log_success "Copied opencode.json"
    else
        # Fallback: create default configuration
        cat > "${OPENCODE_CONFIG_DIR}/opencode.json" << 'EOF'
{
  "mcpServers": {
    "tmws": {
      "command": "docker",
      "args": ["exec", "-i", "tmws-app", "python", "-m", "src.mcp_server"],
      "env": {}
    }
  },
  "plugins": {
    "enabled": true,
    "directory": "plugin"
  },
  "commands": {
    "enabled": true,
    "directory": "command"
  }
}
EOF
        log_success "Created default opencode.json"
    fi
}

# Start TMWS
start_tmws() {
    log_step "Starting TMWS..."

    cd "${TRINITAS_CONFIG_DIR}"

    if command -v docker-compose &> /dev/null; then
        docker-compose up -d
    else
        docker compose up -d
    fi

    log_info "Waiting for TMWS to start..."
    local max_attempts=30
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
            log_success "TMWS is running and healthy"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done

    log_warn "TMWS health check timed out (may still be starting)"
}

# Verify license
verify_license() {
    log_step "Verifying license..."

    local response
    response=$(curl -sf http://localhost:8000/api/v1/license/status 2>/dev/null || echo '{"error": "connection failed"}')

    if echo "$response" | grep -q '"tier"'; then
        local tier=$(echo "$response" | grep -o '"tier":"[^"]*"' | cut -d'"' -f4)
        log_success "License verified: ${tier}"
    else
        log_warn "Could not verify license (TMWS may still be starting)"
    fi
}

# Check Ollama
check_ollama() {
    log_step "Checking Ollama installation..."

    if command -v ollama &> /dev/null; then
        log_success "Ollama is installed"

        if curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
            log_success "Ollama is running"

            if ollama list 2>/dev/null | grep -q "multilingual-e5-large"; then
                log_success "Required model available"
            else
                log_warn "Required model not found. Run: ollama pull zylonai/multilingual-e5-large"
            fi
        else
            log_warn "Ollama is not running. Start with: ollama serve"
        fi
    else
        log_warn "Ollama is not installed"
        echo "Install: curl -fsSL https://ollama.ai/install.sh | sh"
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
    echo "  - TMWS Docker container (ghcr.io/apto-as/tmws:${TMWS_VERSION})"
    echo "  - Trinitas 9-agent configuration for OpenCode"
    echo "  - 90-day ENTERPRISE trial license"
    echo ""
    echo -e "${CYAN}Configuration locations:${NC}"
    echo "  - TMWS config:     ${TRINITAS_CONFIG_DIR}/"
    echo "  - OpenCode:        ${OPENCODE_CONFIG_DIR}/"
    echo "  - Data storage:    ${HOME}/.tmws/"
    if [ -d "${BACKUP_DIR}" ]; then
        echo "  - Backups:         ${BACKUP_DIR}/"
    fi
    echo ""
    echo -e "${CYAN}Quick start:${NC}"
    echo "  1. Ensure Ollama is running: ollama serve"
    echo "  2. Start OpenCode in your project directory"
    echo "  3. Use /trinitas command to interact with agents"
    echo ""
    echo -e "${YELLOW}License: ENTERPRISE Trial${NC}"
    echo ""
    echo -e "${GREEN}Enjoy Trinitas Multi-Agent System!${NC}"
    echo ""
}

# Main
main() {
    show_banner
    detect_platform
    check_prerequisites

    if check_existing_installation; then
        echo ""
        read -p "Do you want to upgrade? (existing data will be backed up) [Y/n] " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            create_backup
            stop_existing_tmws
        else
            log_info "Installation cancelled"
            exit 0
        fi
    fi

    create_directories
    pull_tmws_image
    setup_tmws_config
    create_docker_compose
    install_opencode_config
    configure_opencode_settings
    start_tmws
    verify_license
    check_ollama
    show_completion
}

main "$@"
