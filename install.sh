#!/bin/bash
# =============================================================================
# Trinitas Multi-Agent System Installer v2.4.16
# For Claude Code on Linux/macOS/WSL
# =============================================================================
#
# This installer sets up:
#   1. TMWS (Trinitas Memory & Workflow System) via Docker
#   2. Trinitas agents, hooks, and configuration for Claude Code
#   3. Pre-activated ENTERPRISE license
#
# Features:
#   - Automatic backup of existing installations
#   - Upgrade support for existing TMWS/Trinitas installations
#   - Platform-specific optimizations
#
# Supported platforms: Ubuntu 20.04+, Debian 11+, macOS 12+, WSL2
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install.sh | bash
#   # or
#   ./install.sh
#
# =============================================================================

set -euo pipefail

# Version
INSTALLER_VERSION="2.4.16"
TMWS_VERSION="2.4.16"
INSTALLER_TYPE="claude-code"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
TMWS_IMAGE="ghcr.io/apto-as/tmws:latest"
TRINITAS_CONFIG_DIR="${HOME}/.trinitas"
CLAUDE_CONFIG_DIR="${HOME}/.claude"
BACKUP_DIR="${HOME}/.trinitas-backup"

# Pre-activated ENTERPRISE license
DEFAULT_LICENSE_KEY="TMWS-ENTERPRISE-020d8e77-de36-48a1-b585-7f66aef78c06-20260303-Tp9UYRt6ucUB21hPF9lqZoH.FjSslvfr~if1ThD75L.ro~Kx5glyVyGPm0n4xuziJ~Qmc87PZipJWCefj2HEAA"
DEFAULT_LICENSE_PUBLIC_KEY="hWZG1qVDWLQj1bzq/CzU23Sjg5XDsEOB0/9+3vzXcRU="

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
║            Multi-Agent System Installer v2.4.16                       ║
║            For Claude Code                                            ║
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

    if [ -d "${CLAUDE_CONFIG_DIR}" ] && [ -f "${CLAUDE_CONFIG_DIR}/CLAUDE.md" ]; then
        existing=true
        existing_items+=("~/.claude/ (Trinitas config)")
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

    # Backup ~/.claude (Trinitas-related files only)
    if [ -d "${CLAUDE_CONFIG_DIR}" ]; then
        mkdir -p "${backup_path}/claude"

        # Core config files
        for file in CLAUDE.md AGENTS.md settings.json .mcp.json; do
            if [ -f "${CLAUDE_CONFIG_DIR}/${file}" ]; then
                cp "${CLAUDE_CONFIG_DIR}/${file}" "${backup_path}/claude/"
            fi
        done

        # Directories
        for dir in agents commands hooks; do
            if [ -d "${CLAUDE_CONFIG_DIR}/${dir}" ]; then
                cp -r "${CLAUDE_CONFIG_DIR}/${dir}" "${backup_path}/claude/"
            fi
        done

        log_success "Backed up ~/.claude/ (Trinitas config)"
    fi

    # Backup ~/.tmws (metadata only, not large DB files)
    if [ -d "${HOME}/.tmws" ]; then
        mkdir -p "${backup_path}/tmws"

        # Copy small config files, skip large DB/vector files
        find "${HOME}/.tmws" -maxdepth 2 -type f \( -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.env" \) \
            -exec cp {} "${backup_path}/tmws/" \; 2>/dev/null || true

        log_success "Backed up ~/.tmws/ (config only)"
    fi

    # Record backup info
    cat > "${backup_path}/backup-info.txt" << EOF
Trinitas Backup
===============
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

    # Check curl
    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi

    # Check git
    if ! command -v git &> /dev/null; then
        missing+=("git")
    fi

    # Check Docker
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
                    echo "  # Log out and back in for group changes"
                fi
                ;;
            brew)
                echo "  brew install ${missing[*]}"
                if [[ " ${missing[*]} " =~ " docker " ]]; then
                    echo ""
                    echo "For Docker on macOS:"
                    echo "  brew install --cask docker"
                    echo "  # Then open Docker Desktop"
                fi
                ;;
            *)
                echo "  Please install: ${missing[*]}"
                ;;
        esac
        exit 1
    fi

    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        echo ""
        case "$PLATFORM" in
            macOS)
                echo "Please start Docker Desktop:"
                echo "  open -a Docker"
                ;;
            Linux|WSL)
                echo "Please start Docker:"
                echo "  sudo systemctl start docker"
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
    mkdir -p "${CLAUDE_CONFIG_DIR}/agents"
    mkdir -p "${CLAUDE_CONFIG_DIR}/commands"
    mkdir -p "${CLAUDE_CONFIG_DIR}/hooks/core"
    mkdir -p "${HOME}/.tmws/db"
    mkdir -p "${HOME}/.tmws/logs"
    mkdir -p "${HOME}/.tmws/vector_store"

    # Make TMWS data directories writable by Docker container (UID 1000)
    # This ensures compatibility across different host user UIDs
    chmod -R 777 "${HOME}/.tmws"

    # Record version
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
        # Fallback: use /dev/urandom
        head -c 32 /dev/urandom | xxd -p | tr -d '\n'
    fi
}

# Setup TMWS configuration
setup_tmws_config() {
    log_step "Setting up TMWS configuration..."

    local env_file="${TRINITAS_CONFIG_DIR}/.env"

    # Preserve existing secret key if available
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

# Environment (development mode - no CORS validation required)
TMWS_ENVIRONMENT=development
TMWS_LOG_LEVEL=INFO

# Security (Auto-generated - DO NOT SHARE)
TMWS_SECRET_KEY=${secret_key}

# Pre-activated ENTERPRISE license
TMWS_LICENSE_KEY="${DEFAULT_LICENSE_KEY}"
TMWS_LICENSE_PUBLIC_KEY="${DEFAULT_LICENSE_PUBLIC_KEY}"

# Database (SQLite - stored in /app/.tmws/db/ inside container)
TMWS_DATABASE_URL=sqlite+aiosqlite:////app/.tmws/db/tmws.db

# Embedding Service (Ollama required)
TMWS_OLLAMA_BASE_URL=http://host.docker.internal:11434
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
    command: ["tail", "-f", "/dev/null"]  # Keep container running, MCP called via docker exec
    ports:
      - "8892:8892"  # MCP Server
      - "8000:8000"  # REST API
    volumes:
      - ${HOME}/.tmws/db:/app/.tmws/db
      - ${HOME}/.tmws/logs:/app/.tmws/logs
      - ${HOME}/.tmws/vector_store:/app/.tmws/vector_store
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

# Install Trinitas agent configuration for Claude Code
install_claude_config() {
    log_step "Installing Trinitas configuration for Claude Code..."

    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || echo "")"
    local config_src="${script_dir}/claudecode"
    local github_base="https://raw.githubusercontent.com/apto-as/multi-agent-system/main"
    local use_github=false

    # Check if running via curl | bash (script_dir will be empty or invalid)
    if [ -z "${script_dir}" ] || [ ! -d "${config_src}" ]; then
        log_info "Downloading configuration from GitHub..."
        use_github=true
        config_src=$(mktemp -d -t trinitas-install.XXXXXXXX)
        trap 'rm -rf "${config_src}" 2>/dev/null || true' EXIT

        # Download claudecode directory contents
        mkdir -p "${config_src}/agents" "${config_src}/commands" "${config_src}/hooks/core"

        # Download main config files
        curl -fsSL "${github_base}/claudecode/CLAUDE.md" -o "${config_src}/CLAUDE.md" 2>/dev/null || true
        curl -fsSL "${github_base}/claudecode/AGENTS.md" -o "${config_src}/AGENTS.md" 2>/dev/null || true
        curl -fsSL "${github_base}/claudecode/SUBAGENT_EXECUTION_RULES.md" -o "${config_src}/SUBAGENT_EXECUTION_RULES.md" 2>/dev/null || true

        # Download agents
        for agent in athena-conductor artemis-optimizer hestia-auditor eris-coordinator hera-strategist muses-documenter aphrodite-designer metis-developer aurora-researcher; do
            curl -fsSL "${github_base}/claudecode/agents/${agent}.md" -o "${config_src}/agents/${agent}.md" 2>/dev/null || true
        done

        # Download commands
        for cmd in trinitas tmws self-introduction status; do
            curl -fsSL "${github_base}/claudecode/commands/${cmd}.md" -o "${config_src}/commands/${cmd}.md" 2>/dev/null || true
        done

        # Download hooks
        curl -fsSL "${github_base}/claudecode/hooks/settings.json" -o "${config_src}/hooks/settings.json" 2>/dev/null || true
        for hook in dynamic_context_loader protocol_injector; do
            curl -fsSL "${github_base}/claudecode/hooks/core/${hook}.py" -o "${config_src}/hooks/core/${hook}.py" 2>/dev/null || true
        done
    fi

    # Copy CLAUDE.md
    if [ -f "${config_src}/CLAUDE.md" ]; then
        cp "${config_src}/CLAUDE.md" "${CLAUDE_CONFIG_DIR}/"
        log_success "Copied CLAUDE.md"
    else
        log_error "CLAUDE.md not found - this is required for Trinitas to function"
    fi

    # Copy AGENTS.md
    if [ -f "${config_src}/AGENTS.md" ]; then
        cp "${config_src}/AGENTS.md" "${CLAUDE_CONFIG_DIR}/"
        log_success "Copied AGENTS.md"
    else
        log_warn "AGENTS.md not found"
    fi

    # Copy SUBAGENT_EXECUTION_RULES.md
    if [ -f "${config_src}/SUBAGENT_EXECUTION_RULES.md" ]; then
        cp "${config_src}/SUBAGENT_EXECUTION_RULES.md" "${CLAUDE_CONFIG_DIR}/"
        log_success "Copied SUBAGENT_EXECUTION_RULES.md"
    fi

    # Copy agents directory
    if [ -d "${config_src}/agents" ] && [ "$(ls -A ${config_src}/agents 2>/dev/null)" ]; then
        rm -rf "${CLAUDE_CONFIG_DIR}/agents"
        cp -r "${config_src}/agents" "${CLAUDE_CONFIG_DIR}/"
        log_success "Copied agents/ (9 agent definitions)"
    fi

    # Copy commands directory
    if [ -d "${config_src}/commands" ] && [ "$(ls -A ${config_src}/commands 2>/dev/null)" ]; then
        rm -rf "${CLAUDE_CONFIG_DIR}/commands"
        cp -r "${config_src}/commands" "${CLAUDE_CONFIG_DIR}/"
        log_success "Copied commands/"
    fi

    # Copy hooks directory
    if [ -d "${config_src}/hooks" ] && [ "$(ls -A ${config_src}/hooks 2>/dev/null)" ]; then
        rm -rf "${CLAUDE_CONFIG_DIR}/hooks"
        cp -r "${config_src}/hooks" "${CLAUDE_CONFIG_DIR}/"
        # Set executable permissions on Python hook scripts
        find "${CLAUDE_CONFIG_DIR}/hooks" -type f -name "*.py" -exec chmod 0755 {} \; 2>/dev/null || true
        log_success "Copied hooks/"
    fi

    # Cleanup temp directory if used
    if [ "${use_github}" = true ] && [ -d "${config_src}" ]; then
        rm -rf "${config_src}"
    fi
}

# Configure Claude Code MCP settings
configure_mcp_settings() {
    log_step "Configuring Claude Code MCP settings..."

    local mcp_config="${CLAUDE_CONFIG_DIR}/.mcp.json"

    cat > "${mcp_config}" << 'EOF'
{
  "mcpServers": {
    "tmws": {
      "command": "docker",
      "args": [
        "exec", "-i", "tmws-app",
        "python", "-m", "src.mcp_server"
      ],
      "env": {}
    }
  }
}
EOF

    log_success "MCP configuration created"
}

# Start TMWS
start_tmws() {
    log_step "Starting TMWS..."

    cd "${TRINITAS_CONFIG_DIR}"

    # Start with docker-compose
    if command -v docker-compose &> /dev/null; then
        docker-compose up -d
    else
        docker compose up -d
    fi

    # Wait for health check
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
        local expires=$(echo "$response" | grep -o '"expires_at":"[^"]*"' | cut -d'"' -f4)

        log_success "License verified: ${tier}"
        if [ -n "$expires" ]; then
            log_info "Expires: ${expires}"
        fi
    else
        log_warn "Could not verify license (TMWS may still be starting)"
    fi
}

# Check Ollama
check_ollama() {
    log_step "Checking Ollama installation..."

    if command -v ollama &> /dev/null; then
        log_success "Ollama is installed"

        # Check if running
        if curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
            log_success "Ollama is running"

            # Check for required model
            if ollama list 2>/dev/null | grep -q "multilingual-e5-large"; then
                log_success "Required model (multilingual-e5-large) is available"
            else
                log_warn "Required model not found. Installing..."
                ollama pull zylonai/multilingual-e5-large || log_warn "Could not pull model automatically"
            fi
        else
            log_warn "Ollama is not running. Start with: ollama serve"
        fi
    else
        log_warn "Ollama is not installed"
        echo ""
        echo "Ollama is required for semantic search functionality."
        echo "Install Ollama:"
        case "$PLATFORM" in
            macOS)
                echo "  brew install ollama"
                ;;
            Linux|WSL)
                echo "  curl -fsSL https://ollama.ai/install.sh | sh"
                ;;
        esac
        echo ""
        echo "Then run:"
        echo "  ollama serve"
        echo "  ollama pull zylonai/multilingual-e5-large"
    fi
}

# Show completion message
show_completion() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Installation Complete! (Claude Code)                        ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}What was installed:${NC}"
    echo "  - TMWS Docker container (ghcr.io/apto-as/tmws:${TMWS_VERSION})"
    echo "  - Trinitas 9-agent configuration for Claude Code"
    echo "  - Pre-activated ENTERPRISE license"
    echo ""
    echo -e "${CYAN}Configuration locations:${NC}"
    echo "  - TMWS config:     ${TRINITAS_CONFIG_DIR}/"
    echo "  - Claude Code:     ${CLAUDE_CONFIG_DIR}/"
    echo "  - Data storage:    ${HOME}/.tmws/"
    if [ -d "${BACKUP_DIR}" ]; then
        echo "  - Backups:         ${BACKUP_DIR}/"
    fi
    echo ""
    echo -e "${CYAN}Services:${NC}"
    echo "  - MCP Server:      localhost:8892"
    echo "  - REST API:        localhost:8000"
    echo "  - Health check:    http://localhost:8000/health"
    echo ""
    echo -e "${CYAN}Quick start:${NC}"
    echo "  1. Ensure Ollama is running: ollama serve"
    echo "  2. Start Claude Code in your project directory"
    echo "  3. Use /trinitas command to interact with agents"
    echo ""
    echo -e "${CYAN}Useful commands:${NC}"
    echo "  - View logs:       docker logs -f tmws-app"
    echo "  - Restart TMWS:    cd ~/.trinitas && docker compose restart"
    echo "  - Stop TMWS:       docker stop tmws-app"
    echo ""
    echo -e "${GREEN}License: ENTERPRISE${NC}"
    echo ""
    echo -e "${GREEN}Enjoy Trinitas Multi-Agent System!${NC}"
    echo ""
}

# Main installation flow
main() {
    show_banner
    detect_platform
    check_prerequisites

    # Handle existing installation
    if check_existing_installation; then
        echo ""
        # Use /dev/tty to read input when running via curl | bash
        if [ -t 0 ]; then
            read -p "Do you want to upgrade? (existing data will be backed up) [Y/n] " -n 1 -r
        else
            read -p "Do you want to upgrade? (existing data will be backed up) [Y/n] " -n 1 -r < /dev/tty
        fi
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
    install_claude_config
    configure_mcp_settings
    start_tmws
    verify_license
    check_ollama
    show_completion
}

# Run main
main "$@"
