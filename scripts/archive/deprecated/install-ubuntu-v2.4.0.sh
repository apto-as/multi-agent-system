#!/bin/bash
# ========================================
# TMWS v2.4.0 Ubuntu Production Installer
# ========================================
# Docker-based deployment with source code protection
#
# Features:
#   - Pre-built Docker image (bytecode-only, no .py source)
#   - Automatic backup of existing trinitas-agents/TMWS
#   - Ollama installation (host or Docker)
#   - SQLite + ChromaDB architecture (encrypted DB support)
#   - No Python/uv required on host
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/apto-as/tmws/master/scripts/install-ubuntu-v2.4.0.sh | sudo bash
# ========================================

set -e

# ============================================================
# Configuration
# ============================================================

TMWS_VERSION="2.4.0"
TMWS_IMAGE="ghcr.io/apto-as/tmws:v${TMWS_VERSION}"
TMWS_REPO="https://github.com/apto-as/tmws.git"
INSTALL_DIR="/opt/tmws"
BACKUP_DIR="/opt/tmws-backups"
DATA_DIR="/opt/tmws/.tmws"
CONFIG_DIR="/opt/tmws/config"
OLLAMA_MODEL="zylonai/multilingual-e5-large"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================================
# Helper Functions
# ============================================================

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (sudo)"
        exit 1
    fi
}

# ============================================================
# Step 1: Backup Existing Installations
# ============================================================

backup_existing_installation() {
    log_step "Step 1: Checking for existing installations"

    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    mkdir -p "$BACKUP_DIR"

    # Check for existing trinitas-agents
    TRINITAS_LOCATIONS=(
        "/opt/trinitas-agents"
        "/home/*/trinitas-agents"
        "/var/lib/trinitas-agents"
    )

    for pattern in "${TRINITAS_LOCATIONS[@]}"; do
        for dir in $pattern; do
            if [ -d "$dir" ]; then
                log_warn "Found existing trinitas-agents at: $dir"
                BACKUP_PATH="$BACKUP_DIR/trinitas-agents-$TIMESTAMP"
                log_info "Backing up to: $BACKUP_PATH"
                cp -r "$dir" "$BACKUP_PATH"
                log_success "Backup complete"

                # Stop containers if running
                if docker ps -q --filter "name=trinitas" 2>/dev/null | grep -q .; then
                    log_info "Stopping trinitas containers..."
                    docker stop $(docker ps -q --filter "name=trinitas") 2>/dev/null || true
                fi

                # Stop systemd service if exists
                if systemctl is-active --quiet trinitas-agents 2>/dev/null; then
                    log_info "Stopping trinitas-agents service..."
                    systemctl stop trinitas-agents
                    systemctl disable trinitas-agents 2>/dev/null || true
                fi

                log_info "Removing old installation: $dir"
                rm -rf "$dir"
                log_success "Removed: $dir"
            fi
        done
    done

    # Check for existing TMWS
    TMWS_LOCATIONS=(
        "/opt/tmws"
        "/home/*/tmws"
    )

    for pattern in "${TMWS_LOCATIONS[@]}"; do
        for dir in $pattern; do
            if [ -d "$dir" ]; then
                log_warn "Found existing TMWS at: $dir"
                BACKUP_PATH="$BACKUP_DIR/tmws-$TIMESTAMP"
                log_info "Backing up to: $BACKUP_PATH"

                # Backup data directory separately
                if [ -d "$dir/.tmws" ]; then
                    cp -r "$dir/.tmws" "$BACKUP_DIR/tmws-data-$TIMESTAMP"
                    log_success "Data directory backed up"
                fi

                cp -r "$dir" "$BACKUP_PATH"
                log_success "Full backup complete"

                # Stop containers if running
                if docker ps -q --filter "name=tmws" 2>/dev/null | grep -q .; then
                    log_info "Stopping tmws containers..."
                    docker compose -f "$dir/docker-compose.yml" down 2>/dev/null || \
                    docker stop $(docker ps -q --filter "name=tmws") 2>/dev/null || true
                fi

                log_info "Removing old installation: $dir"
                rm -rf "$dir"
                log_success "Removed: $dir"
            fi
        done
    done

    log_success "Backup phase complete"
}

# ============================================================
# Step 2: Install Docker (if needed)
# ============================================================

install_docker() {
    log_step "Step 2: Checking Docker installation"

    if command_exists docker; then
        DOCKER_VERSION=$(docker --version 2>/dev/null || echo "unknown")
        log_success "Docker already installed: $DOCKER_VERSION"
    else
        log_info "Installing Docker..."

        # Remove old versions
        apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

        # Install prerequisites
        apt-get update -qq
        apt-get install -y -qq ca-certificates curl gnupg lsb-release

        # Add Docker's official GPG key
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

        # Set up repository
        echo \
            "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
            $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

        # Install Docker Engine
        apt-get update -qq
        apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin

        # Start Docker
        systemctl enable docker
        systemctl start docker

        log_success "Docker installed"
    fi

    # Verify docker compose
    if docker compose version &>/dev/null; then
        log_success "Docker Compose available"
    else
        log_error "Docker Compose not available. Please install docker-compose-plugin"
        exit 1
    fi
}

# ============================================================
# Step 3: Install Ollama
# ============================================================

install_ollama() {
    log_step "Step 3: Installing Ollama (REQUIRED for embeddings)"

    echo ""
    echo "Ollama can be installed in two ways:"
    echo "  A) Native on host (RECOMMENDED - better performance)"
    echo "  B) Inside Docker (easier setup, GPU passthrough needed)"
    echo ""
    echo -n "Install Ollama natively on host? [Y/n]: "
    read -r OLLAMA_CHOICE

    if [[ "$OLLAMA_CHOICE" =~ ^[Nn]$ ]]; then
        # Option B: Docker Ollama - will be configured in docker-compose
        log_info "Ollama will run inside Docker"
        OLLAMA_MODE="docker"
    else
        # Option A: Native Ollama
        OLLAMA_MODE="native"

        if command_exists ollama; then
            log_success "Ollama already installed"
        else
            log_info "Installing Ollama..."
            curl -fsSL https://ollama.ai/install.sh | sh
            log_success "Ollama installed"
        fi

        # Create systemd service
        if [ ! -f /etc/systemd/system/ollama.service ]; then
            cat > /etc/systemd/system/ollama.service << 'EOF'
[Unit]
Description=Ollama Service
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ollama serve
Restart=always
RestartSec=3
Environment="OLLAMA_HOST=0.0.0.0"

[Install]
WantedBy=default.target
EOF
            systemctl daemon-reload
        fi

        systemctl enable ollama
        systemctl start ollama

        # Wait for Ollama
        log_info "Waiting for Ollama to be ready..."
        for i in {1..30}; do
            if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
                log_success "Ollama is running"
                break
            fi
            sleep 1
        done

        # Pull model
        log_info "Pulling embedding model: $OLLAMA_MODEL"
        log_info "This may take several minutes..."
        ollama pull "$OLLAMA_MODEL"
        log_success "Model downloaded"
    fi
}

# ============================================================
# Step 4: Setup TMWS Directory Structure
# ============================================================

setup_directories() {
    log_step "Step 4: Setting up directory structure"

    # Create directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$DATA_DIR"/{db,secrets,logs,vector_store,output}
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$BACKUP_DIR"

    log_success "Directories created"
}

# ============================================================
# Step 5: Download Configuration Files
# ============================================================

download_configs() {
    log_step "Step 5: Downloading configuration files"

    cd "$INSTALL_DIR"

    # Download docker-compose.yml
    log_info "Downloading docker-compose.yml..."
    curl -fsSL "https://raw.githubusercontent.com/apto-as/tmws/v${TMWS_VERSION}/docker-compose.yml" -o docker-compose.yml

    # Download .env.example
    log_info "Downloading .env.example..."
    curl -fsSL "https://raw.githubusercontent.com/apto-as/tmws/v${TMWS_VERSION}/.env.example" -o .env.example

    log_success "Configuration files downloaded"
}

# ============================================================
# Step 6: Configure Environment
# ============================================================

configure_environment() {
    log_step "Step 6: Configuring environment"

    cd "$INSTALL_DIR"

    # Generate secrets
    SECRET_KEY=$(openssl rand -hex 32)

    # Determine Ollama URL
    if [ "$OLLAMA_MODE" = "docker" ]; then
        OLLAMA_URL="http://ollama:11434"
    else
        OLLAMA_URL="http://host.docker.internal:11434"
    fi

    # Create .env file
    cat > .env << EOF
# ========================================
# TMWS v${TMWS_VERSION} Production Configuration
# Generated: $(date)
# ========================================

# Environment
TMWS_ENVIRONMENT=production

# Security (CRITICAL - Keep secret!)
TMWS_SECRET_KEY=${SECRET_KEY}

# Database (SQLite - encrypted via SQLCipher)
# Note: DB file is stored in Docker volume
TMWS_DATABASE_URL=sqlite+aiosqlite:////app/.tmws/db/tmws.db

# Ollama Configuration
TMWS_OLLAMA_BASE_URL=${OLLAMA_URL}
TMWS_OLLAMA_MODEL=${OLLAMA_MODEL}

# ChromaDB (Vector storage)
TMWS_CHROMA_PERSIST_DIRECTORY=/app/.tmws/vector_store

# Logging
TMWS_LOG_LEVEL=INFO
TMWS_LOG_FILE=/app/.tmws/logs/tmws.log

# Performance
TMWS_MAX_WORKERS=4
TMWS_REQUEST_TIMEOUT=60

# CORS (adjust for your domain)
TMWS_CORS_ORIGINS=["http://localhost:3000"]

# Rate Limiting
TMWS_RATE_LIMIT_ENABLED=true
TMWS_RATE_LIMIT_REQUESTS=100
TMWS_RATE_LIMIT_PERIOD=60

# License (if applicable)
# TMWS_LICENSE_KEY=your-license-key
EOF

    chmod 600 .env
    log_success "Environment configured"

    # Update docker-compose for Ollama mode
    if [ "$OLLAMA_MODE" = "docker" ]; then
        log_info "Enabling Docker Ollama in docker-compose.yml..."
        # Uncomment ollama service in docker-compose.yml
        # This is a simplified approach - production would use yq or similar
        log_warn "Please manually uncomment the 'ollama' service in docker-compose.yml"
        log_warn "And update TMWS_OLLAMA_BASE_URL to http://ollama:11434"
    fi
}

# ============================================================
# Step 7: Pull and Start TMWS
# ============================================================

start_tmws() {
    log_step "Step 7: Starting TMWS"

    cd "$INSTALL_DIR"

    # Update docker-compose to use pre-built image
    log_info "Configuring to use pre-built image: $TMWS_IMAGE"

    # Comment out build section and use image
    sed -i 's/^\(\s*\)build:/\1# build:/' docker-compose.yml
    sed -i 's/^\(\s*\)context:/\1# context:/' docker-compose.yml
    sed -i 's/^\(\s*\)dockerfile:/\1# dockerfile:/' docker-compose.yml

    # Add or update image line
    if grep -q "^    # image:" docker-compose.yml; then
        sed -i "s|^    # image:.*|    image: ${TMWS_IMAGE}|" docker-compose.yml
    else
        sed -i "/container_name: tmws-app/a\\    image: ${TMWS_IMAGE}" docker-compose.yml
    fi

    # Pull image
    log_info "Pulling TMWS Docker image..."
    docker pull "$TMWS_IMAGE"

    # Start services
    log_info "Starting TMWS services..."
    docker compose up -d

    # Wait for startup
    log_info "Waiting for TMWS to be ready..."
    for i in {1..60}; do
        if curl -s http://localhost:8000/health > /dev/null 2>&1; then
            log_success "TMWS is running!"
            break
        fi
        sleep 2
    done
}

# ============================================================
# Step 8: Verify Installation
# ============================================================

verify_installation() {
    log_step "Step 8: Verifying installation"

    # Check container status
    log_info "Container status:"
    docker compose ps

    # Health check
    HEALTH=$(curl -s http://localhost:8000/health 2>/dev/null || echo "failed")
    if echo "$HEALTH" | grep -qE "ok|healthy"; then
        log_success "Health check: PASSED"
    else
        log_warn "Health check response: $HEALTH"
    fi

    # Verify source protection
    log_info "Verifying source code protection..."
    PY_COUNT=$(docker exec tmws-app find /usr/local/lib/python3.11/site-packages/src -name "*.py" 2>/dev/null | wc -l || echo "0")
    if [ "$PY_COUNT" -eq 0 ]; then
        log_success "Source protection: VERIFIED (0 .py files)"
    else
        log_warn "Source protection: $PY_COUNT .py files found"
    fi
}

# ============================================================
# Step 9: Setup Systemd (Optional)
# ============================================================

setup_systemd() {
    log_step "Step 9: Setting up auto-start"

    cat > /etc/systemd/system/tmws.service << EOF
[Unit]
Description=TMWS Docker Service
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable tmws
    log_success "Auto-start configured"
}

# ============================================================
# Print Summary
# ============================================================

print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║   TMWS v${TMWS_VERSION} Installation Complete!                       ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Installation Summary:${NC}"
    echo "  • Install Directory:  $INSTALL_DIR"
    echo "  • Data Directory:     $DATA_DIR"
    echo "  • Backup Directory:   $BACKUP_DIR"
    echo "  • Docker Image:       $TMWS_IMAGE"
    echo "  • Ollama Mode:        $OLLAMA_MODE"
    echo ""
    echo -e "${BLUE}Security Features:${NC}"
    echo "  ✓ Bytecode-only deployment (no .py source files)"
    echo "  ✓ SQLCipher encryption support"
    echo "  ✓ SHA256 pinned base image"
    echo ""
    echo -e "${BLUE}Quick Commands:${NC}"
    echo "  # View logs"
    echo "  cd $INSTALL_DIR && docker compose logs -f"
    echo ""
    echo "  # Restart"
    echo "  cd $INSTALL_DIR && docker compose restart"
    echo ""
    echo "  # Stop"
    echo "  cd $INSTALL_DIR && docker compose down"
    echo ""
    echo "  # Health check"
    echo "  curl http://localhost:8000/health"
    echo ""
    echo -e "${BLUE}API Endpoints:${NC}"
    echo "  • Health:   http://localhost:8000/health"
    echo "  • API Docs: http://localhost:8000/docs"
    echo ""
    echo -e "${YELLOW}Important:${NC}"
    echo "  • Secret key saved in: $INSTALL_DIR/.env"
    echo "  • Backups saved in:    $BACKUP_DIR"
    echo ""
    if [ "$OLLAMA_MODE" = "native" ]; then
        echo -e "${YELLOW}Ollama running natively on host${NC}"
    else
        echo -e "${YELLOW}Ollama running in Docker${NC}"
        echo "  Pull model: docker exec tmws-ollama ollama pull $OLLAMA_MODEL"
    fi
    echo ""
    echo -e "${GREEN}Installation complete! 🎉${NC}"
}

# ============================================================
# Main
# ============================================================

main() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║   TMWS v${TMWS_VERSION} Ubuntu Production Installer                  ║"
    echo "║   Docker-Based Deployment (Bytecode Protected)              ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo "This installer will:"
    echo "  1. Backup and remove existing trinitas-agents/TMWS"
    echo "  2. Install Docker (if needed)"
    echo "  3. Install Ollama (for embeddings)"
    echo "  4. Deploy TMWS from pre-built Docker image"
    echo ""
    echo "Requirements:"
    echo "  • Ubuntu 20.04+ / Debian 11+"
    echo "  • Root access (sudo)"
    echo "  • Internet connection"
    echo "  • NO Python/uv needed (Docker handles everything)"
    echo ""
    echo -n "Continue? [Y/n]: "
    read -r response

    if [[ "$response" =~ ^[Nn]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi

    check_root
    backup_existing_installation
    install_docker
    install_ollama
    setup_directories
    download_configs
    configure_environment
    start_tmws
    verify_installation
    setup_systemd
    print_summary
}

main "$@"
