#!/bin/bash
# TMWS v2.4.0 Ubuntu Production Installer
# Complete installation including Ollama, with backup of existing installations
#
# Features:
#   - Automatic backup of existing trinitas-agents and TMWS installations
#   - Ollama installation and model setup
#   - SQLite + ChromaDB architecture (no PostgreSQL required)
#   - Systemd service configuration
#   - Optional Nginx reverse proxy
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/apto-as/tmws/master/scripts/install-ubuntu-v2.4.0.sh | bash
#   # or
#   wget -qO- https://raw.githubusercontent.com/apto-as/tmws/master/scripts/install-ubuntu-v2.4.0.sh | bash

set -e

# ============================================================
# Configuration
# ============================================================

TMWS_VERSION="2.4.0"
TMWS_REPO="https://github.com/apto-as/tmws.git"
INSTALL_DIR="/opt/tmws"
BACKUP_DIR="/opt/tmws-backups"
DATA_DIR="/var/lib/tmws"
LOG_DIR="/var/log/tmws"
OLLAMA_MODEL="zylonai/multilingual-e5-large"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================
# Helper Functions
# ============================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (sudo)"
        exit 1
    fi
}

check_ubuntu() {
    if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
        log_warn "This script is designed for Ubuntu. Proceeding anyway..."
    fi
}

# ============================================================
# Backup Functions
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
                log_success "Backup complete: $BACKUP_PATH"

                # Stop service if running
                if systemctl is-active --quiet trinitas-agents 2>/dev/null; then
                    log_info "Stopping trinitas-agents service..."
                    systemctl stop trinitas-agents
                    systemctl disable trinitas-agents 2>/dev/null || true
                fi

                # Remove old installation
                log_info "Removing old trinitas-agents installation..."
                rm -rf "$dir"
                log_success "Removed: $dir"
            fi
        done
    done

    # Check for existing TMWS
    TMWS_LOCATIONS=(
        "/opt/tmws"
        "/home/*/tmws"
        "/var/lib/tmws-old"
    )

    for pattern in "${TMWS_LOCATIONS[@]}"; do
        for dir in $pattern; do
            if [ -d "$dir" ] && [ "$dir" != "$INSTALL_DIR" ]; then
                log_warn "Found existing TMWS at: $dir"
                BACKUP_PATH="$BACKUP_DIR/tmws-old-$TIMESTAMP"
                log_info "Backing up to: $BACKUP_PATH"
                cp -r "$dir" "$BACKUP_PATH"
                log_success "Backup complete: $BACKUP_PATH"

                # Stop service if running
                if systemctl is-active --quiet tmws 2>/dev/null; then
                    log_info "Stopping tmws service..."
                    systemctl stop tmws
                fi

                # Remove old installation
                log_info "Removing old TMWS installation..."
                rm -rf "$dir"
                log_success "Removed: $dir"
            fi
        done
    done

    # Backup existing TMWS data if upgrading
    if [ -d "$DATA_DIR" ]; then
        log_info "Backing up existing TMWS data..."
        BACKUP_PATH="$BACKUP_DIR/tmws-data-$TIMESTAMP"
        cp -r "$DATA_DIR" "$BACKUP_PATH"
        log_success "Data backup complete: $BACKUP_PATH"
    fi

    log_success "Backup phase complete"
}

# ============================================================
# System Dependencies
# ============================================================

install_system_dependencies() {
    log_step "Step 2: Installing system dependencies"

    # Update package lists
    log_info "Updating package lists..."
    apt-get update -qq

    # Install essential packages
    log_info "Installing essential packages..."
    apt-get install -y -qq \
        curl \
        wget \
        git \
        build-essential \
        python3.11 \
        python3.11-venv \
        python3.11-dev \
        python3-pip \
        ca-certificates \
        gnupg \
        lsb-release \
        jq \
        unzip

    log_success "System dependencies installed"
}

# ============================================================
# Ollama Installation
# ============================================================

install_ollama() {
    log_step "Step 3: Installing Ollama (REQUIRED for embeddings)"

    if command_exists ollama; then
        OLLAMA_VERSION=$(ollama --version 2>/dev/null | head -1 || echo "unknown")
        log_info "Ollama already installed: $OLLAMA_VERSION"
    else
        log_info "Installing Ollama..."
        curl -fsSL https://ollama.ai/install.sh | sh
        log_success "Ollama installed"
    fi

    # Ensure Ollama service is running
    log_info "Configuring Ollama service..."

    # Create systemd service if not exists
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

    # Wait for Ollama to be ready
    log_info "Waiting for Ollama to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
            log_success "Ollama is running"
            break
        fi
        sleep 1
    done

    # Pull required model
    log_info "Pulling embedding model: $OLLAMA_MODEL"
    log_info "This may take several minutes on first run..."
    ollama pull "$OLLAMA_MODEL"

    log_success "Ollama setup complete"
}

# ============================================================
# UV Installation (Python package manager)
# ============================================================

install_uv() {
    log_step "Step 4: Installing uv (Python package manager)"

    if command_exists uv; then
        UV_VERSION=$(uv --version 2>/dev/null || echo "unknown")
        log_info "uv already installed: $UV_VERSION"
    else
        log_info "Installing uv..."
        curl -LsSf https://astral.sh/uv/install.sh | sh

        # Add to PATH for current session
        export PATH="$HOME/.cargo/bin:$PATH"

        # Also add for the tmws user
        if id "tmws" &>/dev/null; then
            echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> /home/tmws/.bashrc
        fi

        log_success "uv installed"
    fi
}

# ============================================================
# TMWS Installation
# ============================================================

install_tmws() {
    log_step "Step 5: Installing TMWS v$TMWS_VERSION"

    # Create tmws user if not exists
    if ! id "tmws" &>/dev/null; then
        log_info "Creating tmws user..."
        useradd -r -m -s /bin/bash -d /home/tmws tmws
    fi

    # Create directories
    log_info "Creating directories..."
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$BACKUP_DIR"

    # Clone repository
    if [ -d "$INSTALL_DIR/.git" ]; then
        log_info "Updating existing repository..."
        cd "$INSTALL_DIR"
        git fetch origin
        git checkout "v$TMWS_VERSION" 2>/dev/null || git checkout master
        git pull origin master 2>/dev/null || true
    else
        log_info "Cloning TMWS repository..."
        rm -rf "$INSTALL_DIR"
        git clone "$TMWS_REPO" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
        git checkout "v$TMWS_VERSION" 2>/dev/null || git checkout master
    fi

    # Create virtual environment and install dependencies
    log_info "Setting up Python environment..."
    cd "$INSTALL_DIR"

    if command_exists uv; then
        uv venv --python python3.11
        source .venv/bin/activate
        uv sync --all-extras
    else
        python3.11 -m venv .venv
        source .venv/bin/activate
        pip install --upgrade pip
        pip install -e ".[dev]"
    fi

    # Set ownership
    chown -R tmws:tmws "$INSTALL_DIR"
    chown -R tmws:tmws "$DATA_DIR"
    chown -R tmws:tmws "$LOG_DIR"

    log_success "TMWS installed"
}

# ============================================================
# Configuration
# ============================================================

configure_tmws() {
    log_step "Step 6: Configuring TMWS"

    # Generate secret key
    SECRET_KEY=$(openssl rand -hex 32)

    # Create .env file
    log_info "Creating configuration file..."
    cat > "$INSTALL_DIR/.env" << EOF
# TMWS v$TMWS_VERSION Production Configuration
# Generated: $(date)

# Database (SQLite - no external DB required)
TMWS_DATABASE_URL="sqlite+aiosqlite:///$DATA_DIR/tmws.db"

# Security
TMWS_SECRET_KEY="$SECRET_KEY"
TMWS_ENVIRONMENT="production"

# Ollama (REQUIRED for embeddings)
TMWS_OLLAMA_BASE_URL="http://localhost:11434"
TMWS_EMBEDDING_MODEL="$OLLAMA_MODEL"

# Server
TMWS_HOST="127.0.0.1"
TMWS_PORT="8000"

# Logging
TMWS_LOG_LEVEL="INFO"
TMWS_LOG_FILE="$LOG_DIR/tmws.log"

# ChromaDB (vector storage)
TMWS_CHROMA_PERSIST_DIR="$DATA_DIR/chroma"

# Rate Limiting
TMWS_RATE_LIMIT_ENABLED="true"
TMWS_RATE_LIMIT_REQUESTS="100"
TMWS_RATE_LIMIT_PERIOD="60"
EOF

    chmod 600 "$INSTALL_DIR/.env"
    chown tmws:tmws "$INSTALL_DIR/.env"

    # Create data directories
    mkdir -p "$DATA_DIR/chroma"
    chown -R tmws:tmws "$DATA_DIR"

    # Run database migrations
    log_info "Running database migrations..."
    cd "$INSTALL_DIR"
    sudo -u tmws bash -c "source .venv/bin/activate && alembic upgrade head"

    log_success "Configuration complete"
}

# ============================================================
# Systemd Service
# ============================================================

setup_systemd_service() {
    log_step "Step 7: Setting up systemd service"

    cat > /etc/systemd/system/tmws.service << EOF
[Unit]
Description=TMWS - Trinitas Memory & Workflow Service v$TMWS_VERSION
After=network.target ollama.service
Wants=ollama.service

[Service]
Type=exec
User=tmws
Group=tmws
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/.venv/bin:/usr/local/bin:/usr/bin:/bin"
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=$INSTALL_DIR/.venv/bin/python -m uvicorn src.main:app --host 127.0.0.1 --port 8000
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=10

# Security hardening
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR $DATA_DIR $LOG_DIR

[Install]
WantedBy=multi-user.target
EOF

    # Reload and enable service
    systemctl daemon-reload
    systemctl enable tmws

    log_success "Systemd service configured"
}

# ============================================================
# Nginx (Optional)
# ============================================================

setup_nginx() {
    log_step "Step 8: Setting up Nginx reverse proxy (optional)"

    echo -n "Would you like to setup Nginx as reverse proxy? [y/N]: "
    read -r response

    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log_info "Skipping Nginx setup"
        return
    fi

    # Install nginx
    if ! command_exists nginx; then
        log_info "Installing Nginx..."
        apt-get install -y -qq nginx
    fi

    # Create nginx config
    cat > /etc/nginx/sites-available/tmws << 'EOF'
upstream tmws_backend {
    server 127.0.0.1:8000;
    keepalive 32;
}

server {
    listen 80;
    server_name _;

    # Security headers
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=tmws_api:10m rate=10r/s;

    location / {
        limit_req zone=tmws_api burst=20 nodelay;

        proxy_pass http://tmws_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Health check endpoint (no rate limit)
    location /health {
        proxy_pass http://tmws_backend/health;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }
}
EOF

    # Enable site
    ln -sf /etc/nginx/sites-available/tmws /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

    # Test and reload
    nginx -t && systemctl reload nginx

    log_success "Nginx configured"
}

# ============================================================
# Firewall (Optional)
# ============================================================

setup_firewall() {
    log_step "Step 9: Configuring firewall (optional)"

    if command_exists ufw; then
        echo -n "Would you like to configure UFW firewall? [y/N]: "
        read -r response

        if [[ "$response" =~ ^[Yy]$ ]]; then
            log_info "Configuring UFW..."
            ufw allow ssh
            ufw allow http
            ufw allow https
            ufw --force enable
            log_success "Firewall configured"
        fi
    else
        log_info "UFW not installed, skipping firewall configuration"
    fi
}

# ============================================================
# Final Steps
# ============================================================

finalize_installation() {
    log_step "Step 10: Finalizing installation"

    # Start TMWS service
    log_info "Starting TMWS service..."
    systemctl start tmws

    # Wait for service to be ready
    log_info "Waiting for TMWS to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:8000/health > /dev/null 2>&1; then
            log_success "TMWS is running"
            break
        fi
        sleep 1
    done

    # Final verification
    log_info "Running verification..."
    HEALTH_RESPONSE=$(curl -s http://localhost:8000/health 2>/dev/null || echo "failed")

    if echo "$HEALTH_RESPONSE" | grep -q "ok\|healthy"; then
        log_success "Health check passed"
    else
        log_warn "Health check returned: $HEALTH_RESPONSE"
    fi
}

# ============================================================
# Print Summary
# ============================================================

print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║   TMWS v$TMWS_VERSION Installation Complete!                       ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Installation Summary:${NC}"
    echo "  • TMWS Location:     $INSTALL_DIR"
    echo "  • Data Directory:    $DATA_DIR"
    echo "  • Log Directory:     $LOG_DIR"
    echo "  • Backup Directory:  $BACKUP_DIR"
    echo ""
    echo -e "${BLUE}Services:${NC}"
    echo "  • TMWS:    systemctl status tmws"
    echo "  • Ollama:  systemctl status ollama"
    echo ""
    echo -e "${BLUE}Quick Commands:${NC}"
    echo "  # Check service status"
    echo "  systemctl status tmws"
    echo ""
    echo "  # View logs"
    echo "  journalctl -u tmws -f"
    echo ""
    echo "  # Restart service"
    echo "  systemctl restart tmws"
    echo ""
    echo "  # Health check"
    echo "  curl http://localhost:8000/health"
    echo ""
    echo -e "${BLUE}API Endpoints:${NC}"
    echo "  • Health:     http://localhost:8000/health"
    echo "  • API Docs:   http://localhost:8000/docs"
    echo "  • MCP:        http://localhost:8000/api/v1/mcp/"
    echo ""
    echo -e "${YELLOW}Important:${NC}"
    echo "  • Secret key saved in: $INSTALL_DIR/.env"
    echo "  • Backups saved in:    $BACKUP_DIR"
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
    echo "║   TMWS v$TMWS_VERSION Ubuntu Production Installer                  ║"
    echo "║   Trinitas Memory & Workflow System                         ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo "This script will install:"
    echo "  • TMWS v$TMWS_VERSION (Trinitas Memory & Workflow System)"
    echo "  • Ollama (for ML embeddings)"
    echo "  • Required Python dependencies"
    echo "  • Systemd services"
    echo ""
    echo "Existing installations will be backed up before removal."
    echo ""
    echo -n "Continue with installation? [Y/n]: "
    read -r response

    if [[ "$response" =~ ^[Nn]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi

    # Run installation steps
    check_root
    check_ubuntu
    backup_existing_installation
    install_system_dependencies
    install_ollama
    install_uv
    install_tmws
    configure_tmws
    setup_systemd_service
    setup_nginx
    setup_firewall
    finalize_installation
    print_summary
}

# Run main function
main "$@"
