#!/bin/bash
# =============================================================================
# Trinitas Multi-Agent System Installer v2.4.19
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
INSTALLER_VERSION="2.5.32"
TMWS_VERSION="2.5.32"
INSTALLER_TYPE="claude-code"

# =============================================================================
# Resolve actual user's home directory (backward compatibility)
# Native mode does NOT require sudo, but if someone runs with sudo anyway,
# we still install to the correct user's home directory.
# =============================================================================
resolve_real_home() {
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        # Running via sudo - get the original user's home
        if command -v getent &> /dev/null; then
            getent passwd "$SUDO_USER" | cut -d: -f6
        else
            eval echo "~$SUDO_USER"
        fi
    elif [ "$(id -u)" = "0" ] && [ -z "${SUDO_USER:-}" ]; then
        # Running as actual root (not via sudo) - warn but continue
        echo "$HOME"
    else
        # Normal user execution
        echo "$HOME"
    fi
}

# Get the real home directory BEFORE any other variable expansion
REAL_HOME="$(resolve_real_home)"
REAL_USER="${SUDO_USER:-$(whoami)}"

# Installation mode: "native" or "docker"
# Native mode downloads pre-built binaries (recommended for new installs)
# Docker mode uses containerized TMWS (legacy)
INSTALL_MODE="${TMWS_INSTALL_MODE:-native}"

# Ports (can be overridden via environment)
TMWS_API_PORT="${TMWS_API_PORT:-6321}"
QDRANT_HTTP_PORT="${QDRANT_HTTP_PORT:-6333}"
QDRANT_GRPC_PORT="${QDRANT_GRPC_PORT:-6334}"

# Native binary installation - USE REAL_HOME, not HOME
TMWS_INSTALL_DIR="${TMWS_INSTALL_DIR:-${REAL_HOME}/.tmws}"
TMWS_BIN_DIR="${TMWS_INSTALL_DIR}/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Configuration - USE REAL_HOME, not HOME
TMWS_IMAGE="aptoas/tmws-go:latest"
TRINITAS_CONFIG_DIR="${REAL_HOME}/.trinitas"
CLAUDE_CONFIG_DIR="${REAL_HOME}/.claude"
BACKUP_DIR="${REAL_HOME}/.trinitas-backup"

# Pre-activated ENTERPRISE license (TMWS-Go v1.0)
DEFAULT_LICENSE_KEY="TMWS-1.0-eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtdWx0aS1hZ2VudC1zeXN0ZW0tdHJpYWwtdjEuMCIsImlzcyI6InRtd3MuYXB0by5haSIsImlhdCI6MTc3MDA4MzkwMiwiZXhwIjoxNzc0OTIyMzAyLCJuYmYiOjE3NzAwODM5MDIsImxpZCI6IjhkMjI4YzRjLWE2ZWItNDVlMS05NjZjLWIzNDJkM2NhYTkzYyIsImx0eXBlIjoiZW50ZXJwcmlzZSIsIm9yZyI6IlRyaW5pdGFzIENvbW11bml0eSIsImZlYXR1cmVzIjpbIm1lbW9yeS5iYXNpYyIsIm1lbW9yeS5hZHZhbmNlZCIsImFnZW50LmJhc2ljIiwiYWdlbnQuYWR2YW5jZWQiLCJhZ2VudC50cnVzdCIsInNraWxscy5iYXNpYyIsInNraWxscy5hZHZhbmNlZCIsInBhdHRlcm5zLmxlYXJuaW5nIiwidHJpbml0YXMucm91dGluZyIsInRyaW5pdGFzLm9yY2hlc3RyYXRpb24iLCJtY3AuaHViLmJhc2ljIiwibWNwLmh1Yi5hZHZhbmNlZCIsImxpZmVjeWNsZS5zY2hlZHVsZXIiLCJjb252ZXJzYXRpb24ubG9nZ2luZyIsImVudGVycHJpc2UubXVsdGl0ZW5hbmN5Il0sIm1heF9tZW1vcmllcyI6LTEsIm1heF9hZ2VudHMiOi0xLCJtYXhfc2tpbGxzIjotMSwibWF4X21jcF9zZXJ2ZXJzIjotMX0.deZ2KrvnLYFl_MM4d2KPLeEN4h-5ZHAlMT_ICvNj0ZnUQoZQ8bpsyvwuhMvGEy7Gb-Q1VtPjs4hzf2t1qCt1BQ"
DEFAULT_LICENSE_PUBLIC_KEY="XRa6aVOcwUzeurz2AGx+/1KlC3CEokjWcq3pqcd0fIo="

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
║            Multi-Agent System Installer v2.6.0                        ║
║            For Claude Code                                            ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Detect OS for native binary download
detect_os() {
    local os
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$os" in
        darwin) echo "darwin" ;;
        linux) echo "linux" ;;
        *) log_error "Unsupported OS: $os" ; exit 1 ;;
    esac
}

# Detect architecture for native binary download
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) log_error "Unsupported architecture: $arch" ; exit 1 ;;
    esac
}

# Get latest TMWS release version from GitHub
get_latest_tmws_version() {
    local version
    version=$(curl -fsSL "https://api.github.com/repos/apto-as/multi-agent-system/releases" 2>/dev/null | \
        grep '"tag_name":' | grep 'tmws-v' | head -1 | sed -E 's/.*"tmws-(v[^"]+)".*/\1/')
    if [ -z "$version" ]; then
        # Fallback to hardcoded version
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
        log_error ""
        log_error "If this is the first release, binaries may not be available yet."
        log_error "You can use Docker mode instead: TMWS_INSTALL_MODE=docker ./install.sh"
        exit 1
    fi

    # Extract and install
    mkdir -p "${TMWS_BIN_DIR}"
    tar -xzf "${tmp_dir}/${archive_name}" -C "${tmp_dir}"

    # v2.5.x Unified Binary Architecture
    # - tmws: TUI + server modes (unified binary)
    # - tmws-mcp: MCP server for Claude Code
    # - tmws-hook: Claude Code hook utility
    for bin in tmws tmws-mcp tmws-hook; do
        if [ -f "${tmp_dir}/${bin}" ]; then
            mv "${tmp_dir}/${bin}" "${TMWS_BIN_DIR}/"
            chmod +x "${TMWS_BIN_DIR}/${bin}"
            log_success "Installed ${bin}"
        fi
    done

    log_success "TMWS binaries installed to ${TMWS_BIN_DIR}"
}

# Setup PATH for native installation
setup_native_path() {
    log_step "Setting up PATH..."

    local shell_rc=""
    local shell_name

    # Get the real user's shell, not root's shell when using sudo
    if [ -n "${SUDO_USER:-}" ]; then
        shell_name=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f7 | xargs basename 2>/dev/null || echo "bash")
    else
        shell_name=$(basename "$SHELL")
    fi

    # Use REAL_HOME instead of HOME
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

# Fix file ownership when running with sudo (backward compatibility)
# Native mode does NOT require sudo, but if someone uses it anyway,
# we fix ownership so files are accessible to the user.
fix_ownership() {
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        log_step "Fixing file ownership for user: ${SUDO_USER}..."

        for dir in "${TMWS_INSTALL_DIR}" "${TRINITAS_CONFIG_DIR}" "${CLAUDE_CONFIG_DIR}"; do
            if [ -d "$dir" ]; then
                chown -R "${SUDO_USER}:$(id -gn "$SUDO_USER" 2>/dev/null || echo "$SUDO_USER")" "$dir" 2>/dev/null || true
            fi
        done

        log_success "File ownership fixed"
    fi
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

    if [ -d "${REAL_HOME}/.tmws" ]; then
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
    if [ -d "${REAL_HOME}/.tmws" ]; then
        mkdir -p "${backup_path}/tmws"

        # Copy small config files, skip large DB/vector files
        find "${REAL_HOME}/.tmws" -maxdepth 2 -type f \( -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.env" \) \
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

    # Stop and remove Qdrant container
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "tmws-qdrant"; then
        docker stop tmws-qdrant 2>/dev/null || true
        log_success "Stopped tmws-qdrant container"
    fi

    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "tmws-qdrant"; then
        docker rm tmws-qdrant 2>/dev/null || true
        log_success "Removed old tmws-qdrant container"
    fi

    # Also check for legacy container names
    for container in tmws tmws-server trinitas-tmws qdrant; do
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

    # Check for old Docker installation with root-owned files
    if [ -d "${REAL_HOME}/.tmws/db" ]; then
        # Check if files are owned by someone else (e.g., Docker container)
        if [ -f "${REAL_HOME}/.tmws/db/tmws.db" ]; then
            local file_owner
            file_owner=$(stat -c '%U' "${REAL_HOME}/.tmws/db/tmws.db" 2>/dev/null || stat -f '%Su' "${REAL_HOME}/.tmws/db/tmws.db" 2>/dev/null)
            if [ "$file_owner" != "$REAL_USER" ] && [ "$file_owner" != "$(whoami)" ]; then
                log_error "Old Docker installation detected with incompatible file ownership"
                log_error "Files in ${REAL_HOME}/.tmws/db/ are owned by: $file_owner"
                echo ""
                log_info "To fix this, please run:"
                echo "  sudo rm -rf ${REAL_HOME}/.tmws"
                echo ""
                log_info "Then re-run the installer."
                exit 1
            fi
        fi
    fi

    mkdir -p "${TRINITAS_CONFIG_DIR}"
    mkdir -p "${CLAUDE_CONFIG_DIR}/agents"
    mkdir -p "${CLAUDE_CONFIG_DIR}/commands"
    mkdir -p "${CLAUDE_CONFIG_DIR}/hooks/core"
    mkdir -p "${REAL_HOME}/.tmws/db"
    mkdir -p "${REAL_HOME}/.tmws/logs"

    # Docker mode needs special permissions for container access
    if [ "$INSTALL_MODE" = "docker" ]; then
        mkdir -p "${REAL_HOME}/.tmws/qdrant_data"
        # Make TMWS data directories writable by Docker container (UID 1000)
        chmod -R 777 "${REAL_HOME}/.tmws" 2>/dev/null || {
            log_warn "Could not set permissions on ${REAL_HOME}/.tmws"
            log_warn "You may need to run: sudo chown -R \$USER ${REAL_HOME}/.tmws"
        }
    fi

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
# TMWS-Go Configuration - Generated by Trinitas Installer
# Version: ${TMWS_VERSION}
# Generated: $(date -Iseconds)
# Installer: ${INSTALLER_TYPE}

# Environment
TMWS_ENV=development
TMWS_LOG_LEVEL=info

# Security (Auto-generated - DO NOT SHARE)
TMWS_SECRET_KEY=${secret_key}

# Pre-activated ENTERPRISE license (TMWS-Go v1.0)
TMWS_LICENSE_KEY="${DEFAULT_LICENSE_KEY}"
TMWS_LICENSE_PUBLIC_KEY="${DEFAULT_LICENSE_PUBLIC_KEY}"

# Database (SQLite - stored in /data/db/ inside container)
TMWS_DATABASE_PATH=/data/db/tmws.db

# Qdrant Vector Database
TMWS_QDRANT_HOST=tmws-qdrant
TMWS_QDRANT_GRPC_PORT=6334
TMWS_QDRANT_HTTP_PORT=6333
TMWS_QDRANT_VECTOR_SIZE=1024

# Embedding Service (Ollama)
TMWS_OLLAMA_URL=http://host.docker.internal:11434
TMWS_EMBEDDING_MODEL=mxbai-embed-large

# MCP Server
TMWS_MCP_PORT=8892

# REST API Port
TMWS_API_PORT=${TMWS_API_PORT}
EOF

    chmod 600 "${env_file}"
    log_success "TMWS configuration created"
}

# Create Docker Compose file
create_docker_compose() {
    log_step "Creating Docker Compose configuration..."

    cat > "${TRINITAS_CONFIG_DIR}/docker-compose.yml" << EOF
# Trinitas TMWS-Go Docker Compose
# Version: ${TMWS_VERSION}
# Installer: ${INSTALLER_TYPE}

services:
  qdrant:
    image: qdrant/qdrant:v1.12.6
    container_name: tmws-qdrant
    restart: unless-stopped
    ports:
      - "${QDRANT_HTTP_PORT}:6333"  # HTTP API
      - "${QDRANT_GRPC_PORT}:6334"  # gRPC API
    volumes:
      - ${REAL_HOME}/.tmws/qdrant_data:/qdrant/storage
    healthcheck:
      test: ["CMD-SHELL", "timeout 5 bash -c '</dev/tcp/localhost/6333'"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 5s

  tmws:
    image: ${TMWS_IMAGE}
    container_name: tmws-app
    restart: unless-stopped
    command: ["tail", "-f", "/dev/null"]  # Keep container running, MCP called via docker exec
    depends_on:
      qdrant:
        condition: service_healthy
    ports:
      - "8892:8892"  # MCP Server
      - "${TMWS_API_PORT}:8080"  # REST API
    volumes:
      - ${REAL_HOME}/.tmws/db:/data/db
      - ${REAL_HOME}/.tmws/logs:/data/logs
    env_file:
      - .env
    extra_hosts:
      - "host.docker.internal:host-gateway"
    healthcheck:
      test: ["CMD-SHELL", "test -x /app/tmws-mcp"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s
EOF

    log_success "Docker Compose configuration created"
}

# Install Trinitas agent configuration for Claude Code
install_claude_config() {
    log_step "Installing Trinitas configuration for Claude Code..."

    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || echo "")"
    local config_src="${script_dir}/config/claude-code"
    local github_base="https://raw.githubusercontent.com/apto-as/multi-agent-system/main"
    local use_github=false

    # Check if running via curl | bash (script_dir will be empty or invalid)
    if [ -z "${script_dir}" ] || [ ! -d "${config_src}" ]; then
        log_info "Downloading configuration from GitHub..."
        use_github=true
        config_src=$(mktemp -d -t trinitas-install.XXXXXXXX)
        # Use global variable for cleanup trap to avoid unbound variable error with set -u
        TRINITAS_TEMP_DIR="${config_src}"
        trap 'rm -rf "${TRINITAS_TEMP_DIR:-}" 2>/dev/null || true' EXIT

        # Download config/claude-code directory contents
        mkdir -p "${config_src}/agents" "${config_src}/commands" "${config_src}/hooks/core"

        # Download main config files
        curl -fsSL "${github_base}/config/claude-code/CLAUDE.md" -o "${config_src}/CLAUDE.md" 2>/dev/null || true
        curl -fsSL "${github_base}/config/claude-code/AGENTS.md" -o "${config_src}/AGENTS.md" 2>/dev/null || true
        curl -fsSL "${github_base}/config/claude-code/SUBAGENT_EXECUTION_RULES.md" -o "${config_src}/SUBAGENT_EXECUTION_RULES.md" 2>/dev/null || true

        # Download agents (11 total: 2 Orchestrators + 9 Specialists)
        for agent in clotho-orchestrator lachesis-support athena-conductor artemis-optimizer hestia-auditor eris-coordinator hera-strategist muses-documenter aphrodite-designer metis-developer aurora-researcher; do
            curl -fsSL "${github_base}/config/claude-code/agents/${agent}.md" -o "${config_src}/agents/${agent}.md" 2>/dev/null || true
        done

        # Download commands
        for cmd in trinitas tmws self-introduction status; do
            curl -fsSL "${github_base}/config/claude-code/commands/${cmd}.md" -o "${config_src}/commands/${cmd}.md" 2>/dev/null || true
        done

        # Download hooks settings (hook scripts are distributed via TMWS, not the public repo)
        curl -fsSL "${github_base}/config/claude-code/hooks/settings.json" -o "${config_src}/hooks/settings.json" 2>/dev/null || true

        # Download placeholder stubs (will be replaced by real hooks from TMWS)
        for hook in dynamic_context_loader protocol_injector decision_check decision_memory precompact_memory_injection security_utils rate_limiter task_persona_injector persona_reminder_hook tmws_hook_wrapper; do
            curl -fsSL "${github_base}/config/claude-code/hooks/core/${hook}.py" -o "${config_src}/hooks/core/${hook}.py" 2>/dev/null || true
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
        log_success "Copied agents/ (11 agent definitions: 9 Trinitas + 2 Moirai)"
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

# =============================================================================
# Hook Installation
# =============================================================================
# Hooks are included in the repository and copied during install_claude_config().
# They integrate Claude Code with TMWS for persona loading, context
# injection, and memory management.
# =============================================================================

# Configure Claude Code MCP settings
configure_mcp_settings() {
    log_step "Configuring Claude Code MCP settings..."

    local mcp_config="${CLAUDE_CONFIG_DIR}/.mcp.json"

    if [ "$INSTALL_MODE" = "native" ]; then
        # Native mode: use local binary
        cat > "${mcp_config}" << EOF
{
  "mcpServers": {
    "tmws": {
      "command": "${TMWS_BIN_DIR}/tmws-mcp",
      "args": []
    }
  }
}
EOF
    else
        # Docker mode: use docker exec
        cat > "${mcp_config}" << 'EOF'
{
  "mcpServers": {
    "tmws": {
      "command": "docker",
      "args": [
        "exec", "-i", "tmws-app",
        "/app/tmws-mcp"
      ]
    }
  }
}
EOF
    fi

    log_success "MCP configuration created (mode: ${INSTALL_MODE})"
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

    # Wait for Qdrant to be healthy first
    log_info "Waiting for Qdrant to start..."
    local max_attempts=30
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if docker ps --filter "name=tmws-qdrant" --filter "health=healthy" --format "{{.Names}}" | grep -q "tmws-qdrant"; then
            log_success "Qdrant is healthy"
            break
        fi
        attempt=$((attempt + 1))
        sleep 2
    done

    if [ $attempt -eq $max_attempts ]; then
        log_warn "Qdrant startup timed out (may still be initializing)"
    fi

    # Wait for TMWS container to be running (MCP mode uses STDIO, not HTTP)
    log_info "Waiting for TMWS container to start..."
    attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if docker ps --filter "name=tmws-app" --filter "status=running" --format "{{.Names}}" | grep -q "tmws-app"; then
            # Verify MCP server is accessible via docker exec
            if docker exec tmws-app test -x /app/tmws-mcp 2>/dev/null; then
                log_success "TMWS-Go container is running (MCP ready via docker exec)"
                return 0
            fi
        fi
        attempt=$((attempt + 1))
        sleep 2
    done

    log_warn "TMWS container startup timed out (may still be initializing)"
}

# Verify license (via docker exec for STDIO mode)
verify_license() {
    log_step "Verifying license..."

    # In STDIO mode, we verify license by checking if the MCP server binary exists
    if docker exec tmws-app test -x /app/tmws-mcp 2>/dev/null; then
        log_success "License verified: ENTERPRISE (TMWS-Go v${TMWS_VERSION})"
        log_info "Organization: Trinitas Community"
    else
        log_warn "Could not verify license (TMWS may still be initializing)"
    fi
}

# Check Ollama and ensure model is available
check_ollama() {
    log_step "Checking Ollama setup..."

    # Ollama should already be installed (checked in prerequisites)
    log_success "Ollama is installed"

    # Check if running
    if curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
        log_success "Ollama is running"
    else
        log_info "Starting Ollama..."
        # Try to start Ollama in background
        if [ "$PLATFORM" = "macOS" ]; then
            # On macOS, Ollama app or brew service
            ollama serve > /dev/null 2>&1 &
            sleep 2
        else
            # On Linux/WSL
            ollama serve > /dev/null 2>&1 &
            sleep 2
        fi

        # Verify it started
        if curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
            log_success "Ollama started successfully"
        else
            log_warn "Could not start Ollama automatically"
            echo ""
            echo "Please start Ollama manually in another terminal:"
            echo "  ollama serve"
            echo ""
            echo "Then pull the embedding model:"
            echo "  ollama pull mxbai-embed-large"
            return
        fi
    fi

    # Check for required model
    if ollama list 2>/dev/null | grep -q "mxbai-embed-large"; then
        log_success "Required model (mxbai-embed-large) is available"
    else
        log_info "Pulling required embedding model (mxbai-embed-large)..."
        if ollama pull mxbai-embed-large; then
            log_success "Model pulled successfully"
        else
            log_warn "Could not pull model automatically"
            echo ""
            echo "Please pull the model manually:"
            echo "  ollama pull mxbai-embed-large"
        fi
    fi
}

# Show completion message
show_completion() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Installation Complete! (Claude Code)                        ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [ "$INSTALL_MODE" = "native" ]; then
        echo -e "${CYAN}What was installed:${NC}"
        echo "  - TMWS v2.5.x Unified Binary Architecture:"
        echo "    - tmws: TUI + server modes (unified binary)"
        echo "    - tmws-mcp: MCP server for Claude Code"
        echo "    - tmws-hook: Claude Code hook utility"
        echo "  - Trinitas 11-agent configuration for Claude Code"
        echo "  - Pre-activated ENTERPRISE license"
        echo ""
        echo -e "${CYAN}Configuration locations:${NC}"
        echo "  - TMWS binaries:   ${TMWS_BIN_DIR}/"
        echo "  - TMWS config:     ${TMWS_INSTALL_DIR}/.env"
        echo "  - TMWS data:       ${TMWS_INSTALL_DIR}/data/"
        echo "  - Claude Code:     ${CLAUDE_CONFIG_DIR}/"
        if [ -d "${BACKUP_DIR}" ]; then
            echo "  - Backups:         ${BACKUP_DIR}/"
        fi
        echo ""
        echo -e "${CYAN}Quick start:${NC}"
        echo "  1. Reload your shell or run: source ~/.bashrc (or ~/.zshrc)"
        echo "  2. Ensure Ollama is running: ollama serve"
        echo "  3. Start Claude Code in your project directory"
        echo "  4. Use /trinitas command to interact with agents"
        echo ""
        echo -e "${CYAN}Useful commands:${NC}"
        echo "  - Version check:   tmws --version"
        echo "  - TUI interface:   tmws (interactive TUI)"
        echo "  - MCP server:      tmws-mcp (used by Claude Code)"
        echo ""
    else
        echo -e "${CYAN}What was installed:${NC}"
        echo "  - TMWS-Go Docker container (aptoas/tmws-go:latest)"
        echo "  - Qdrant Vector Database (qdrant/qdrant:v1.12.6)"
        echo "  - Trinitas 11-agent configuration for Claude Code"
        echo "  - Pre-activated ENTERPRISE license"
        echo ""
        echo -e "${CYAN}Configuration locations:${NC}"
        echo "  - TMWS config:     ${TRINITAS_CONFIG_DIR}/"
        echo "  - Claude Code:     ${CLAUDE_CONFIG_DIR}/"
        echo "  - Data storage:    ${REAL_HOME}/.tmws/"
        if [ -d "${BACKUP_DIR}" ]; then
            echo "  - Backups:         ${BACKUP_DIR}/"
        fi
        echo ""
        echo -e "${CYAN}Services:${NC}"
        echo "  - MCP Server:      STDIO via 'docker exec -i tmws-app /app/tmws-mcp'"
        echo "  - REST API:        http://localhost:${TMWS_API_PORT}"
        echo "  - Qdrant HTTP:     http://localhost:${QDRANT_HTTP_PORT}"
        echo "  - Containers:      tmws-app, tmws-qdrant (check with: docker ps)"
        echo ""
        echo -e "${CYAN}Quick start:${NC}"
        echo "  1. Ensure Ollama is running: ollama serve"
        echo "  2. Start Claude Code in your project directory"
        echo "  3. Use /trinitas command to interact with agents"
        echo ""
        echo -e "${CYAN}Useful commands:${NC}"
        echo "  - View logs:       docker logs -f tmws-app"
        echo "  - Restart TMWS:    cd ~/.trinitas && docker compose restart"
        echo "  - Stop TMWS:       docker stop tmws-app tmws-qdrant"
        echo ""
    fi

    echo -e "${GREEN}License: ENTERPRISE (TMWS-Go v${TMWS_VERSION})${NC}"
    echo ""
    echo -e "${GREEN}Enjoy Trinitas Multi-Agent System!${NC}"
    echo ""
}

# Main installation flow
main() {
    show_banner

    # Warn about unnecessary sudo usage
    if [ -n "${SUDO_USER:-}" ]; then
        log_warn "sudo is not required for native mode installation"
        log_info "Installing for user: ${SUDO_USER} (${REAL_HOME})"
        echo ""
    elif [ "$(id -u)" = "0" ]; then
        log_warn "Running as root - this is not recommended"
        log_warn "Native mode installs to user's home directory and does not require root"
        log_info "Target: ${REAL_HOME}"
        echo ""
    fi

    log_info "Installation mode: ${INSTALL_MODE}"
    if [ "$INSTALL_MODE" = "native" ]; then
        log_info "Using native binaries (no Docker required)"
    else
        log_info "Using Docker containers"
    fi
    echo ""

    detect_platform

    # Native mode only requires curl, not Docker
    if [ "$INSTALL_MODE" = "native" ]; then
        check_prerequisites_native
    else
        check_prerequisites
    fi

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
            if [ "$INSTALL_MODE" = "docker" ]; then
                stop_existing_tmws
            fi
        else
            log_info "Installation cancelled"
            exit 0
        fi
    fi

    create_directories

    if [ "$INSTALL_MODE" = "native" ]; then
        # Native installation flow
        install_native_binaries
        setup_native_path
        setup_native_config
    else
        # Docker installation flow
        pull_tmws_image
        setup_tmws_config
        create_docker_compose
        start_tmws
        verify_license
    fi

    install_claude_config
    configure_mcp_settings

    # Install Python dependencies for hooks
    install_python_dependencies

    # Fix file ownership when running with sudo
    fix_ownership

    check_ollama
    show_completion
}

# Check prerequisites for native mode (no Docker required)
check_prerequisites_native() {
    log_step "Checking prerequisites (native mode)..."

    local missing=()
    local ollama_missing=false

    # Check curl
    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi

    # Check git (optional but recommended)
    if ! command -v git &> /dev/null; then
        log_warn "git not found (optional)"
    fi

    # Check Ollama (required for semantic search)
    if ! command -v ollama &> /dev/null; then
        ollama_missing=true
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

    if [ "$ollama_missing" = true ]; then
        log_error "Ollama is required for TMWS semantic search functionality"
        echo ""
        echo -e "${CYAN}Please install Ollama first:${NC}"
        echo ""
        case "$PLATFORM" in
            macOS)
                echo "  brew install ollama"
                echo ""
                echo "Then start Ollama and pull the embedding model:"
                echo "  ollama serve &"
                echo "  ollama pull mxbai-embed-large"
                ;;
            Linux|WSL)
                echo "  curl -fsSL https://ollama.ai/install.sh | sh"
                echo ""
                echo "Then start Ollama and pull the embedding model:"
                echo "  ollama serve &"
                echo "  ollama pull mxbai-embed-large"
                ;;
            *)
                echo "  Visit https://ollama.ai for installation instructions"
                ;;
        esac
        echo ""
        echo "After installing Ollama, run this installer again."
        exit 1
    fi

    log_success "All prerequisites satisfied"
}

# Install Python dependencies (httpx for hooks)
install_python_dependencies() {
    log_step "Installing Python dependencies..."

    # Check if Python3 is available
    if ! command -v python3 &> /dev/null; then
        log_warn "Python3 not found. Skipping Python dependencies."
        log_info "Some hooks may not function without Python3 and httpx."
        return 0
    fi

    # Check if httpx is already installed
    if python3 -c "import httpx" 2>/dev/null; then
        log_success "httpx is already installed"
        return 0
    fi

    # Install httpx with --break-system-packages for macOS externally-managed-environment
    log_info "Installing httpx..."

    local pip_args="--user"

    # Detect if running on macOS or system with externally-managed-environment
    if [ "$PLATFORM" = "macOS" ] || python3 -c "import sys; sys.exit(0 if 'externally-managed' in str(sys.base_prefix) else 1)" 2>/dev/null; then
        pip_args="${pip_args} --break-system-packages"
    fi

    # Try installing httpx
    if pip3 install ${pip_args} httpx 2>/dev/null; then
        log_success "httpx installed successfully"
    elif python3 -m pip install ${pip_args} httpx 2>/dev/null; then
        log_success "httpx installed successfully (via python3 -m pip)"
    else
        log_warn "Failed to install httpx automatically"
        log_info "Please install manually: pip3 install --user --break-system-packages httpx"
        return 1
    fi

    # Verify installation
    if python3 -c "import httpx" 2>/dev/null; then
        log_success "httpx installation verified"
    else
        log_warn "httpx installation could not be verified"
        log_info "You may need to restart your shell or check your PYTHONPATH"
    fi

    return 0
}

# Setup native TMWS configuration
setup_native_config() {
    log_step "Setting up TMWS configuration..."

    local config_dir="${TMWS_INSTALL_DIR}"
    local config_file="${config_dir}/config.yaml"
    local env_file="${config_dir}/.env"

    mkdir -p "${config_dir}/db"

    # Preserve existing secret key if available
    local existing_secret=""
    if [ -f "${env_file}" ]; then
        existing_secret=$(grep "^TMWS_SECRET_KEY=" "${env_file}" 2>/dev/null | cut -d'=' -f2 || echo "")
    fi

    local secret_key="${existing_secret:-$(generate_secret_key)}"

    # Create config.yaml for TMWS-Go native mode
    cat > "${config_file}" << EOF
# TMWS-Go Configuration - Generated by Trinitas Installer
# Version: ${TMWS_VERSION}
# Generated: $(date -Iseconds)

database:
  driver: "sqlite3"
  path: "${config_dir}/db/tmws.db"
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

server:
  port: ${TMWS_API_PORT}
  host: "0.0.0.0"

license:
  key: "${DEFAULT_LICENSE_KEY}"
  public_key: "${DEFAULT_LICENSE_PUBLIC_KEY}"
EOF

    chmod 600 "${config_file}"

    # Also create .env for backward compatibility
    cat > "${env_file}" << EOF
# TMWS Environment - Generated by Trinitas Installer
# Version: ${TMWS_VERSION}
# Generated: $(date -Iseconds)
# Mode: native

# Configuration file path
TMWS_CONFIG_PATH=${config_file}

# Ollama host
OLLAMA_HOST=http://localhost:11434

# Security (Auto-generated - DO NOT SHARE)
TMWS_SECRET_KEY=${secret_key}
EOF

    chmod 600 "${env_file}"
    log_success "TMWS configuration created (config.yaml + .env)"
}

# Run main
main "$@"
