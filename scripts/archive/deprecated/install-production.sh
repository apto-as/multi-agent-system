#!/bin/bash
# TMWS v2.3.1 Production Installation Script
# For Mac/Linux - Individual Developer Configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TMWS_DIR="$HOME/.tmws"
TMWS_DATA_DIR="$TMWS_DIR/data"
TMWS_CONFIG_DIR="$TMWS_DIR/config"
TMWS_CHROMA_DIR="$TMWS_DIR/.chroma"
TMWS_SCRIPTS_DIR="$TMWS_DIR/scripts"
TMWS_BACKUPS_DIR="$TMWS_DIR/backups"

# Print functions
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    print_error "Do not run this script as root!"
    exit 1
fi

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="mac"
        print_info "Detected: macOS"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        print_info "Detected: Linux"
    else
        print_error "Unsupported OS: $OSTYPE"
        exit 1
    fi
}

# Check Python version
check_python() {
    print_header "Checking Python Installation"

    if command -v python3.11 &> /dev/null; then
        PYTHON_CMD="python3.11"
    elif command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    else
        print_error "Python 3.11+ not found"
        print_info "Install Python 3.11+ first:"
        if [ "$OS" = "mac" ]; then
            print_info "  brew install python@3.11"
        else
            print_info "  sudo apt install python3.11"
        fi
        exit 1
    fi

    PYTHON_VERSION=$($PYTHON_CMD --version | cut -d ' ' -f 2)
    print_success "Python $PYTHON_VERSION found"
}

# Install uv
install_uv() {
    print_header "Installing uv Package Manager"

    if command -v uv &> /dev/null; then
        print_success "uv already installed"
        uv --version
    else
        print_info "Installing uv..."
        curl -LsSf https://astral.sh/uv/install.sh | sh

        # Add to PATH
        if [ "$OS" = "mac" ]; then
            echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
            export PATH="$HOME/.cargo/bin:$PATH"
        else
            echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
            export PATH="$HOME/.cargo/bin:$PATH"
        fi

        print_success "uv installed successfully"
    fi
}

# Install Ollama
install_ollama() {
    print_header "Installing Ollama"

    if command -v ollama &> /dev/null; then
        print_success "Ollama already installed"
        ollama --version
    else
        print_info "Installing Ollama..."
        curl -fsSL https://ollama.ai/install.sh | sh
        print_success "Ollama installed successfully"
    fi

    # Download model
    print_info "Downloading Multilingual-E5-Large model (約1GB、10-15分)..."
    print_warning "This may take a while..."

    ollama pull zylonai/multilingual-e5-large || {
        print_error "Failed to download model"
        print_info "You can download it later with: ollama pull zylonai/multilingual-e5-large"
    }
}

# Create directory structure
create_directories() {
    print_header "Creating Directory Structure"

    mkdir -p "$TMWS_DATA_DIR"
    mkdir -p "$TMWS_CONFIG_DIR"
    mkdir -p "$TMWS_CHROMA_DIR"
    mkdir -p "$TMWS_SCRIPTS_DIR"
    mkdir -p "$TMWS_BACKUPS_DIR"

    print_success "Directories created at $TMWS_DIR"
}

# Create .env configuration
create_env_config() {
    print_header "Creating Configuration File"

    SECRET_KEY=$(openssl rand -hex 32)

    cat > "$TMWS_DIR/.env" << EOF
# TMWS v2.3.1 Configuration
# Generated on $(date)

TMWS_ENVIRONMENT=production
TMWS_SECRET_KEY=$SECRET_KEY
TMWS_DATABASE_URL=sqlite+aiosqlite:///$TMWS_DATA_DIR/tmws.db
TMWS_OLLAMA_BASE_URL=http://localhost:11434
TMWS_LOG_LEVEL=INFO
TMWS_CORS_ORIGINS=["http://localhost:3000"]
TMWS_AUTH_ENABLED=true
TMWS_RATE_LIMIT_ENABLED=true
TMWS_RATE_LIMIT_PER_MINUTE=60
EOF

    chmod 600 "$TMWS_DIR/.env"
    print_success "Configuration file created: $TMWS_DIR/.env"
}

# Install TMWS
install_tmws() {
    print_header "Installing TMWS"

    print_info "Installing TMWS via uvx..."
    uvx --from tmws tmws-mcp-server --version || {
        print_error "Failed to install TMWS"
        exit 1
    }

    print_success "TMWS installed successfully"
}

# Create backup script
create_backup_script() {
    print_header "Creating Backup Script"

    cat > "$TMWS_SCRIPTS_DIR/backup.sh" << 'EOF'
#!/bin/bash
# TMWS Backup Script

BACKUP_DIR="$HOME/.tmws/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/tmws_backup_$TIMESTAMP"

mkdir -p "$BACKUP_PATH"

# SQLite backup
if [ -f "$HOME/.tmws/data/tmws.db" ]; then
    sqlite3 "$HOME/.tmws/data/tmws.db" ".backup '$BACKUP_PATH/tmws.db'"
    echo "✅ Database backed up"
fi

# ChromaDB backup
if [ -d "$HOME/.tmws/.chroma" ]; then
    cp -r "$HOME/.tmws/.chroma" "$BACKUP_PATH/chroma"
    echo "✅ ChromaDB backed up"
fi

# Config backup
if [ -f "$HOME/.tmws/.env" ]; then
    cp "$HOME/.tmws/.env" "$BACKUP_PATH/.env"
    echo "✅ Config backed up"
fi

# Compress
tar -czf "$BACKUP_PATH.tar.gz" -C "$BACKUP_DIR" "tmws_backup_$TIMESTAMP"
rm -rf "$BACKUP_PATH"

# Keep only last 7 days
find "$BACKUP_DIR" -name "tmws_backup_*.tar.gz" -mtime +7 -delete

echo "✅ Backup completed: $BACKUP_PATH.tar.gz"
EOF

    chmod +x "$TMWS_SCRIPTS_DIR/backup.sh"
    print_success "Backup script created: $TMWS_SCRIPTS_DIR/backup.sh"
}

# Create health check script
create_health_check_script() {
    print_header "Creating Health Check Script"

    cat > "$TMWS_SCRIPTS_DIR/health-check.sh" << 'EOF'
#!/bin/bash

echo "🔍 TMWS Health Check"
echo "===================="

# Ollama check
if curl -s http://localhost:11434/api/tags > /dev/null; then
    echo "✅ Ollama: Running"
else
    echo "❌ Ollama: Not running"
fi

# Database check
if [ -f ~/.tmws/data/tmws.db ]; then
    SIZE=$(du -sh ~/.tmws/data/tmws.db | cut -f1)
    echo "✅ Database: $SIZE"
else
    echo "❌ Database: Not found"
fi

# ChromaDB check
if [ -d ~/.tmws/.chroma ]; then
    SIZE=$(du -sh ~/.tmws/.chroma | cut -f1)
    echo "✅ ChromaDB: $SIZE"
else
    echo "❌ ChromaDB: Not found"
fi

# Disk usage
DISK=$(df -h ~ | awk 'NR==2 {print $5}')
echo "💾 Disk usage: $DISK"

# Memory count
MEMORIES=$(sqlite3 ~/.tmws/data/tmws.db "SELECT COUNT(*) FROM memories;" 2>/dev/null || echo "0")
echo "📝 Total memories: $MEMORIES"

echo "===================="
EOF

    chmod +x "$TMWS_SCRIPTS_DIR/health-check.sh"
    print_success "Health check script created: $TMWS_SCRIPTS_DIR/health-check.sh"
}

# Setup Ollama autostart
setup_ollama_autostart() {
    print_header "Setting up Ollama Autostart"

    if [ "$OS" = "mac" ]; then
        # macOS launchd
        PLIST_FILE="$HOME/Library/LaunchAgents/com.ollama.serve.plist"

        cat > "$PLIST_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ollama.serve</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/ollama</string>
        <string>serve</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/ollama.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/ollama.err</string>
</dict>
</plist>
EOF

        launchctl load "$PLIST_FILE" 2>/dev/null || true
        print_success "Ollama autostart configured (launchd)"

    else
        # Linux systemd
        SERVICE_FILE="/tmp/ollama.service"

        cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Ollama Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
ExecStart=/usr/local/bin/ollama serve
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

        print_info "To enable Ollama autostart, run:"
        print_info "  sudo cp $SERVICE_FILE /etc/systemd/system/"
        print_info "  sudo systemctl daemon-reload"
        print_info "  sudo systemctl enable ollama.service"
        print_info "  sudo systemctl start ollama.service"
    fi
}

# Setup cron backup
setup_cron_backup() {
    print_header "Setting up Automatic Backup"

    print_info "Would you like to setup automatic daily backups? (y/n)"
    read -r SETUP_CRON

    if [[ "$SETUP_CRON" =~ ^[Yy]$ ]]; then
        CRON_ENTRY="0 2 * * * $TMWS_SCRIPTS_DIR/backup.sh >> /tmp/tmws_backup.log 2>&1"

        (crontab -l 2>/dev/null || true; echo "$CRON_ENTRY") | crontab -

        print_success "Automatic backup configured (daily at 2 AM)"
    else
        print_info "Skipped automatic backup setup"
        print_info "You can run backups manually: $TMWS_SCRIPTS_DIR/backup.sh"
    fi
}

# Configure Claude Desktop
configure_claude_desktop() {
    print_header "Claude Desktop Configuration"

    if [ "$OS" = "mac" ]; then
        CLAUDE_CONFIG="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
    else
        CLAUDE_CONFIG="$HOME/.config/claude/claude_desktop_config.json"
    fi

    print_info "Claude Desktop configuration file:"
    print_info "  $CLAUDE_CONFIG"
    print_info ""
    print_info "Add the following to your Claude Desktop config:"
    echo ""
    cat << 'EOF'
{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": ["--from", "tmws", "tmws-mcp-server"],
      "env": {
        "TMWS_DATABASE_URL": "sqlite+aiosqlite:///~/.tmws/data/tmws.db",
        "TMWS_OLLAMA_BASE_URL": "http://localhost:11434"
      }
    }
  }
}
EOF
    echo ""
    print_warning "Please configure Claude Desktop manually and restart it"
}

# Final verification
final_verification() {
    print_header "Final Verification"

    # Start Ollama if not running
    if ! curl -s http://localhost:11434/api/tags > /dev/null; then
        print_info "Starting Ollama..."
        ollama serve > /dev/null 2>&1 &
        sleep 3
    fi

    # Check Ollama
    if curl -s http://localhost:11434/api/tags > /dev/null; then
        print_success "Ollama is running"
    else
        print_error "Ollama is not running"
        print_info "Start Ollama manually: ollama serve"
    fi

    # Check TMWS
    if uvx --from tmws tmws-mcp-server --version > /dev/null 2>&1; then
        print_success "TMWS is installed"
    else
        print_error "TMWS installation failed"
    fi

    # Run health check
    print_info ""
    "$TMWS_SCRIPTS_DIR/health-check.sh"
}

# Print summary
print_summary() {
    print_header "Installation Complete! 🎉"

    echo ""
    print_success "TMWS v2.3.1 has been installed successfully!"
    echo ""
    print_info "📁 Installation Directory: $TMWS_DIR"
    print_info "📝 Configuration: $TMWS_DIR/.env"
    print_info "💾 Backup Script: $TMWS_SCRIPTS_DIR/backup.sh"
    print_info "🔍 Health Check: $TMWS_SCRIPTS_DIR/health-check.sh"
    echo ""
    print_info "📚 Documentation: PRODUCTION_DEPLOYMENT_UVX.md"
    echo ""
    print_warning "Next Steps:"
    echo "  1. Configure Claude Desktop (see above)"
    echo "  2. Restart Claude Desktop"
    echo "  3. Verify MCP connection (should see 'tmws' with green status)"
    echo "  4. Test with: store_memory / search_memories"
    echo ""
    print_info "For help, see: https://github.com/apto-as/tmws"
}

# Main installation flow
main() {
    print_header "TMWS v2.3.1 Production Installation"
    echo ""
    print_info "This script will install TMWS for production use"
    print_info "Configuration: Individual Developer (Ollama Native + TMWS uvx)"
    echo ""
    print_warning "Press Enter to continue, Ctrl+C to cancel"
    read -r

    detect_os
    check_python
    install_uv
    install_ollama
    create_directories
    create_env_config
    install_tmws
    create_backup_script
    create_health_check_script
    setup_ollama_autostart
    setup_cron_backup
    configure_claude_desktop
    final_verification
    print_summary
}

# Run main
main
