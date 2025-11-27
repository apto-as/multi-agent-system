#!/bin/bash
# TMWS Installer Script
#
# This script installs TMWS (Trinitas Memory & Workflow Service) on Linux systems.
# It supports Ubuntu/Debian and RHEL/CentOS distributions.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/apto-as/tmws/master/scripts/install/install.sh | bash
#
# Or download and run:
#   wget https://raw.githubusercontent.com/apto-as/tmws/master/scripts/install/install.sh
#   chmod +x install.sh
#   sudo ./install.sh
#
# Options:
#   --license KEY       TMWS license key (required for PRO/ENTERPRISE)
#   --user USERNAME     System user for TMWS (default: tmws)
#   --no-ollama         Skip Ollama installation
#   --no-systemd        Skip systemd service installation
#   --version TAG       Docker image tag (default: latest)
#
# Author: Trinitas Development Team
# Created: 2025-11-27
# Version: 1.0.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
TMWS_USER="${TMWS_USER:-tmws}"
TMWS_HOME="/home/${TMWS_USER}/.tmws"
TMWS_VERSION="${TMWS_VERSION:-latest}"
TMWS_IMAGE="ghcr.io/apto-as/tmws:${TMWS_VERSION}"
INSTALL_OLLAMA=true
INSTALL_SYSTEMD=true
LICENSE_KEY=""

# Print colored message
print_msg() {
    local color=$1
    local msg=$2
    echo -e "${color}${msg}${NC}"
}

print_info() { print_msg "$BLUE" "[INFO] $1"; }
print_success() { print_msg "$GREEN" "[SUCCESS] $1"; }
print_warning() { print_msg "$YELLOW" "[WARNING] $1"; }
print_error() { print_msg "$RED" "[ERROR] $1"; }

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --license)
                LICENSE_KEY="$2"
                shift 2
                ;;
            --user)
                TMWS_USER="$2"
                TMWS_HOME="/home/${TMWS_USER}/.tmws"
                shift 2
                ;;
            --no-ollama)
                INSTALL_OLLAMA=false
                shift
                ;;
            --no-systemd)
                INSTALL_SYSTEMD=false
                shift
                ;;
            --version)
                TMWS_VERSION="$2"
                TMWS_IMAGE="ghcr.io/apto-as/tmws:${TMWS_VERSION}"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat << EOF
TMWS Installer

Usage: $0 [OPTIONS]

Options:
    --license KEY       TMWS license key (required for PRO/ENTERPRISE)
    --user USERNAME     System user for TMWS (default: tmws)
    --no-ollama         Skip Ollama installation
    --no-systemd        Skip systemd service installation
    --version TAG       Docker image tag (default: latest)
    -h, --help          Show this help message

Examples:
    # Basic installation
    sudo ./install.sh

    # With license key
    sudo ./install.sh --license "TMWS-PRO-..."

    # Custom user and version
    sudo ./install.sh --user myuser --version v2.4.1
EOF
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Please run as root (sudo ./install.sh)"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect OS"
        exit 1
    fi
    print_info "Detected OS: $OS $VERSION"
}

# Install Docker if not present
install_docker() {
    if command -v docker &> /dev/null; then
        print_info "Docker already installed"
        return
    fi

    print_info "Installing Docker..."
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
            curl -fsSL https://download.docker.com/linux/$OS/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/$OS $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
            apt-get update
            apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
        centos|rhel|fedora)
            dnf install -y dnf-plugins-core
            dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
        *)
            print_error "Unsupported OS: $OS"
            print_info "Please install Docker manually: https://docs.docker.com/engine/install/"
            exit 1
            ;;
    esac

    systemctl enable docker
    systemctl start docker
    print_success "Docker installed"
}

# Install Ollama
install_ollama() {
    if [ "$INSTALL_OLLAMA" = false ]; then
        print_info "Skipping Ollama installation"
        return
    fi

    if command -v ollama &> /dev/null; then
        print_info "Ollama already installed"
    else
        print_info "Installing Ollama..."
        curl -fsSL https://ollama.ai/install.sh | sh
        print_success "Ollama installed"
    fi

    # Start Ollama service
    print_info "Starting Ollama service..."
    if systemctl is-active --quiet ollama; then
        print_info "Ollama service already running"
    else
        systemctl enable ollama
        systemctl start ollama
        sleep 5  # Wait for Ollama to start
    fi

    # Pull embedding model
    print_info "Pulling embedding model (zylonai/multilingual-e5-large)..."
    ollama pull zylonai/multilingual-e5-large
    print_success "Embedding model ready"
}

# Create TMWS user
create_user() {
    if id "$TMWS_USER" &>/dev/null; then
        print_info "User $TMWS_USER already exists"
    else
        print_info "Creating user $TMWS_USER..."
        useradd -m -s /bin/bash "$TMWS_USER"
        print_success "User $TMWS_USER created"
    fi

    # Add user to docker group
    usermod -aG docker "$TMWS_USER"
}

# Create TMWS directories
create_directories() {
    print_info "Creating TMWS directories..."
    mkdir -p "$TMWS_HOME"/{db,logs,vector_store,config}
    chown -R "$TMWS_USER:$TMWS_USER" "$TMWS_HOME"
    chmod 700 "$TMWS_HOME"
    print_success "Directories created at $TMWS_HOME"
}

# Generate secret key
generate_secret_key() {
    openssl rand -hex 32
}

# Create docker-compose.yml
create_docker_compose() {
    print_info "Creating Docker Compose configuration..."

    # Generate secret key if not exists
    local secret_key
    if [ -f "$TMWS_HOME/.secret_key" ]; then
        secret_key=$(cat "$TMWS_HOME/.secret_key")
    else
        secret_key=$(generate_secret_key)
        echo "$secret_key" > "$TMWS_HOME/.secret_key"
        chmod 600 "$TMWS_HOME/.secret_key"
        chown "$TMWS_USER:$TMWS_USER" "$TMWS_HOME/.secret_key"
    fi

    cat > "$TMWS_HOME/docker-compose.yml" << EOF
# TMWS Docker Compose Configuration
# Generated by TMWS Installer
# Version: ${TMWS_VERSION}

services:
  tmws:
    image: ${TMWS_IMAGE}
    container_name: tmws-app
    hostname: tmws

    # STDIO MCP Server Requirements
    tty: true
    stdin_open: true

    ports:
      - "8000:8000"

    volumes:
      - ${TMWS_HOME}/db:/app/.tmws/db
      - ${TMWS_HOME}/logs:/app/.tmws/logs
      - ${TMWS_HOME}/vector_store:/app/.tmws/vector_store
      - ${TMWS_HOME}/config:/app/config

    environment:
      - TMWS_ENVIRONMENT=production
      - TMWS_SECRET_KEY=${secret_key}
      - TMWS_DATABASE_URL=sqlite+aiosqlite:////app/.tmws/db/tmws.db
      - TMWS_OLLAMA_BASE_URL=http://host.docker.internal:11434
      - TMWS_OLLAMA_MODEL=zylonai/multilingual-e5-large
      - TMWS_CHROMA_PERSIST_DIRECTORY=/app/.tmws/vector_store
      - TMWS_LOG_LEVEL=INFO
      - TMWS_LOG_FILE=/app/.tmws/logs/tmws.log
EOF

    # Add license key if provided
    if [ -n "$LICENSE_KEY" ]; then
        echo "      - TMWS_LICENSE_KEY=${LICENSE_KEY}" >> "$TMWS_HOME/docker-compose.yml"
    fi

    cat >> "$TMWS_HOME/docker-compose.yml" << 'EOF'

    restart: unless-stopped

    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G

    extra_hosts:
      - "host.docker.internal:host-gateway"

    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
EOF

    chown "$TMWS_USER:$TMWS_USER" "$TMWS_HOME/docker-compose.yml"
    print_success "Docker Compose configuration created"
}

# Install wrapper script
install_wrapper() {
    print_info "Installing tmws-mcp wrapper script..."

    cat > /usr/local/bin/tmws-mcp << 'WRAPPER_EOF'
#!/bin/bash
# TMWS MCP STDIO Wrapper Script
set -e

COMPOSE_FILE="${TMWS_COMPOSE_FILE:-$HOME/.tmws/docker-compose.yml}"
PROJECT_NAME="${TMWS_PROJECT_NAME:-tmws}"
CONTAINER_NAME="${PROJECT_NAME}-app"

log() { echo "[tmws-mcp] $1" >&2; }

check_docker() {
    if ! docker info >/dev/null 2>&1; then
        log "ERROR: Docker is not running"
        exit 1
    fi
}

is_container_running() {
    docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"
}

start_container() {
    if [ ! -f "$COMPOSE_FILE" ]; then
        log "ERROR: Docker Compose file not found: $COMPOSE_FILE"
        exit 1
    fi
    log "Starting TMWS container..."
    docker-compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d >/dev/null 2>&1
    local max_wait=30
    local wait_count=0
    while [ $wait_count -lt $max_wait ]; do
        if is_container_running; then
            log "Container started"
            return 0
        fi
        sleep 1
        wait_count=$((wait_count + 1))
    done
    log "ERROR: Container failed to start"
    exit 1
}

main() {
    check_docker
    if ! is_container_running; then
        start_container
    fi
    log "Connecting to TMWS MCP server..."
    exec docker attach --no-stdin=false "$CONTAINER_NAME"
}

main
WRAPPER_EOF

    chmod +x /usr/local/bin/tmws-mcp
    print_success "Wrapper script installed at /usr/local/bin/tmws-mcp"
}

# Install systemd service
install_systemd_service() {
    if [ "$INSTALL_SYSTEMD" = false ]; then
        print_info "Skipping systemd service installation"
        return
    fi

    print_info "Installing systemd service..."

    cat > /etc/systemd/system/tmws.service << EOF
[Unit]
Description=TMWS - Trinitas Memory & Workflow Service
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=${TMWS_USER}
Group=docker
WorkingDirectory=${TMWS_HOME}
Environment=COMPOSE_PROJECT_NAME=tmws
Environment=COMPOSE_FILE=${TMWS_HOME}/docker-compose.yml
ExecStart=/usr/bin/docker-compose -f \${COMPOSE_FILE} -p \${COMPOSE_PROJECT_NAME} up -d
ExecStop=/usr/bin/docker-compose -f \${COMPOSE_FILE} -p \${COMPOSE_PROJECT_NAME} down
ExecReload=/usr/bin/docker-compose -f \${COMPOSE_FILE} -p \${COMPOSE_PROJECT_NAME} restart
TimeoutStartSec=120
TimeoutStopSec=60
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable tmws
    print_success "systemd service installed and enabled"
}

# Pull Docker image
pull_docker_image() {
    print_info "Pulling TMWS Docker image: $TMWS_IMAGE"
    docker pull "$TMWS_IMAGE"
    print_success "Docker image pulled"
}

# Start TMWS
start_tmws() {
    print_info "Starting TMWS..."
    if [ "$INSTALL_SYSTEMD" = true ]; then
        systemctl start tmws
    else
        cd "$TMWS_HOME"
        su - "$TMWS_USER" -c "docker-compose -f $TMWS_HOME/docker-compose.yml up -d"
    fi

    # Wait for container to be ready
    sleep 5

    if docker ps | grep -q tmws-app; then
        print_success "TMWS is running"
    else
        print_error "TMWS failed to start. Check logs with: docker logs tmws-app"
        exit 1
    fi
}

# Print installation summary
print_summary() {
    echo ""
    print_success "=========================================="
    print_success "TMWS Installation Complete!"
    print_success "=========================================="
    echo ""
    echo "Configuration:"
    echo "  - Home Directory: $TMWS_HOME"
    echo "  - Docker Image: $TMWS_IMAGE"
    echo "  - User: $TMWS_USER"
    if [ -n "$LICENSE_KEY" ]; then
        echo "  - License: Configured"
    else
        echo "  - License: FREE tier (configure TMWS_LICENSE_KEY for PRO/ENTERPRISE)"
    fi
    echo ""
    echo "Useful Commands:"
    echo "  - Status:   sudo systemctl status tmws"
    echo "  - Logs:     docker logs -f tmws-app"
    echo "  - Restart:  sudo systemctl restart tmws"
    echo "  - Stop:     sudo systemctl stop tmws"
    echo ""
    echo "MCP Integration:"
    echo "  - Wrapper script: /usr/local/bin/tmws-mcp"
    echo "  - Add to Claude: claude mcp add tmws -- tmws-mcp"
    echo ""
    echo "For more information: https://github.com/apto-as/tmws"
    echo ""
}

# Main installation flow
main() {
    parse_args "$@"

    print_info "Starting TMWS installation..."
    echo ""

    check_root
    detect_os
    install_docker
    install_ollama
    create_user
    create_directories
    create_docker_compose
    install_wrapper
    install_systemd_service
    pull_docker_image
    start_tmws
    print_summary
}

# Run main function with all arguments
main "$@"
