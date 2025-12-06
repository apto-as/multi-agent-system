#!/bin/bash
# TMWS Production Installation Script
# Simple, direct installation without Docker

set -e

echo "========================================="
echo "TMWS Production Installation"
echo "========================================="

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    DISTRO=$(lsb_release -si 2>/dev/null || echo "Unknown")
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo -e "${RED}Unsupported OS: $OSTYPE${NC}"
    exit 1
fi

echo "Detected OS: $OS"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install PostgreSQL
install_postgresql() {
    echo -e "${YELLOW}Installing PostgreSQL...${NC}"
    
    if [[ "$OS" == "macos" ]]; then
        if command_exists brew; then
            brew install postgresql@15
            brew services start postgresql@15
        else
            echo -e "${RED}Homebrew not found. Please install Homebrew first.${NC}"
            exit 1
        fi
    else
        # Ubuntu/Debian
        sudo apt-get update
        sudo apt-get install -y postgresql-15 postgresql-contrib-15 postgresql-15-pgvector
        sudo systemctl start postgresql
        sudo systemctl enable postgresql
    fi
    
    echo -e "${GREEN}PostgreSQL installed successfully${NC}"
}

# Function to install Redis
install_redis() {
    echo -e "${YELLOW}Installing Redis...${NC}"
    
    if [[ "$OS" == "macos" ]]; then
        brew install redis
        brew services start redis
    else
        # Ubuntu/Debian
        sudo apt-get install -y redis-server
        sudo systemctl start redis-server
        sudo systemctl enable redis-server
    fi
    
    echo -e "${GREEN}Redis installed successfully${NC}"
}

# Function to install Python dependencies
install_python_deps() {
    echo -e "${YELLOW}Installing Python dependencies...${NC}"
    
    # Ensure Python 3.11+
    if ! command_exists python3.11; then
        if [[ "$OS" == "macos" ]]; then
            brew install python@3.11
        else
            sudo apt-get install -y python3.11 python3.11-venv python3.11-dev
        fi
    fi
    
    # Create virtual environment
    python3.11 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install TMWS
    pip install -e .
    
    echo -e "${GREEN}Python dependencies installed${NC}"
}

# Function to setup database
setup_database() {
    echo -e "${YELLOW}Setting up database...${NC}"
    
    # Generate secure password if not provided
    if [ -z "$TMWS_DB_PASSWORD" ]; then
        TMWS_DB_PASSWORD=$(openssl rand -base64 32)
        echo "Generated DB password: $TMWS_DB_PASSWORD"
    fi
    
    # Create database and user
    if [[ "$OS" == "macos" ]]; then
        psql postgres <<EOF
CREATE USER tmws_user WITH PASSWORD '$TMWS_DB_PASSWORD';
CREATE DATABASE tmws OWNER tmws_user;
\c tmws
CREATE EXTENSION IF NOT EXISTS vector;
GRANT ALL PRIVILEGES ON DATABASE tmws TO tmws_user;
EOF
    else
        sudo -u postgres psql <<EOF
CREATE USER tmws_user WITH PASSWORD '$TMWS_DB_PASSWORD';
CREATE DATABASE tmws OWNER tmws_user;
\c tmws
CREATE EXTENSION IF NOT EXISTS vector;
GRANT ALL PRIVILEGES ON DATABASE tmws TO tmws_user;
EOF
    fi
    
    # Run migrations
    source venv/bin/activate
    alembic upgrade head
    
    echo -e "${GREEN}Database setup complete${NC}"
}

# Function to setup Redis
setup_redis() {
    echo -e "${YELLOW}Configuring Redis...${NC}"
    
    # Generate Redis password
    if [ -z "$TMWS_REDIS_PASSWORD" ]; then
        TMWS_REDIS_PASSWORD=$(openssl rand -base64 32)
        echo "Generated Redis password: $TMWS_REDIS_PASSWORD"
    fi
    
    # Configure Redis with password
    if [[ "$OS" == "macos" ]]; then
        REDIS_CONF="/usr/local/etc/redis.conf"
    else
        REDIS_CONF="/etc/redis/redis.conf"
    fi
    
    # Backup original config
    sudo cp $REDIS_CONF ${REDIS_CONF}.backup
    
    # Add password
    echo "requirepass $TMWS_REDIS_PASSWORD" | sudo tee -a $REDIS_CONF
    
    # Restart Redis
    if [[ "$OS" == "macos" ]]; then
        brew services restart redis
    else
        sudo systemctl restart redis-server
    fi
    
    echo -e "${GREEN}Redis configured${NC}"
}

# Function to create environment file
create_env_file() {
    echo -e "${YELLOW}Creating environment configuration...${NC}"
    
    cat > .env.production <<EOF
# TMWS Production Configuration
# Generated on $(date)

# Database
TMWS_DATABASE_URL=postgresql://tmws_user:${TMWS_DB_PASSWORD}@localhost:5432/tmws
TMWS_DATABASE_POOL_SIZE=20
TMWS_DATABASE_MAX_OVERFLOW=40

# Redis
TMWS_REDIS_URL=redis://:${TMWS_REDIS_PASSWORD}@localhost:6379/0

# Security
TMWS_SECRET_KEY=$(openssl rand -base64 64)
TMWS_JWT_SECRET_KEY=$(openssl rand -base64 32)
TMWS_JWT_ALGORITHM=HS256
TMWS_ACCESS_TOKEN_EXPIRE_MINUTES=30
TMWS_AUTH_ENABLED=true

# API Configuration
TMWS_HOST=127.0.0.1
TMWS_PORT=8000
TMWS_WORKERS=4
TMWS_ENVIRONMENT=production

# Rate Limiting
TMWS_RATE_LIMIT_ENABLED=true
TMWS_RATE_LIMIT_REQUESTS=100
TMWS_RATE_LIMIT_PERIOD=60

# Embedding Configuration
TMWS_EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
TMWS_EMBEDDING_DIMENSION=384
TMWS_MAX_EMBEDDING_BATCH_SIZE=32

# Logging
TMWS_LOG_LEVEL=INFO
TMWS_LOG_FILE=/var/log/tmws/tmws.log

# Backup
TMWS_BACKUP_ENABLED=true
TMWS_BACKUP_PATH=/var/backups/tmws
TMWS_BACKUP_RETENTION_DAYS=30
EOF
    
    chmod 600 .env.production
    echo -e "${GREEN}Environment file created${NC}"
}

# Function to setup systemd service
setup_systemd() {
    echo -e "${YELLOW}Setting up systemd service...${NC}"
    
    TMWS_PATH=$(pwd)
    
    sudo tee /etc/systemd/system/tmws.service > /dev/null <<EOF
[Unit]
Description=TMWS - Trinitas Memory & Workflow Service
After=network.target postgresql.service redis.service
Requires=postgresql.service redis.service

[Service]
Type=exec
User=$USER
Group=$USER
WorkingDirectory=$TMWS_PATH
Environment="PATH=$TMWS_PATH/venv/bin:/usr/local/bin:/usr/bin:/bin"
EnvironmentFile=$TMWS_PATH/.env.production
ExecStart=$TMWS_PATH/venv/bin/python -m uvicorn tmws.main:app --host 127.0.0.1 --port 8000 --workers 4
ExecReload=/bin/kill -s HUP \$MAINPID
ExecStop=/bin/kill -s TERM \$MAINPID
Restart=always
RestartSec=10

# Security
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$TMWS_PATH /var/log/tmws /var/backups/tmws

[Install]
WantedBy=multi-user.target
EOF
    
    # Create required directories
    sudo mkdir -p /var/log/tmws
    sudo mkdir -p /var/backups/tmws
    sudo chown -R $USER:$USER /var/log/tmws /var/backups/tmws
    
    # Reload and start service
    sudo systemctl daemon-reload
    sudo systemctl enable tmws
    
    echo -e "${GREEN}Systemd service configured${NC}"
}

# Function to setup nginx (optional)
setup_nginx() {
    echo -e "${YELLOW}Would you like to setup Nginx as reverse proxy? (y/n)${NC}"
    read -r response
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        if ! command_exists nginx; then
            if [[ "$OS" == "macos" ]]; then
                brew install nginx
            else
                sudo apt-get install -y nginx
            fi
        fi
        
        # Create nginx config
        sudo tee /etc/nginx/sites-available/tmws > /dev/null <<'EOF'
server {
    listen 80;
    server_name localhost;
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=tmws_limit:10m rate=10r/s;
    
    location / {
        limit_req zone=tmws_limit burst=20 nodelay;
        
        proxy_pass http://127.0.0.1:8000;
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
}
EOF
        
        # Enable site
        sudo ln -sf /etc/nginx/sites-available/tmws /etc/nginx/sites-enabled/
        sudo nginx -t && sudo systemctl reload nginx
        
        echo -e "${GREEN}Nginx configured${NC}"
    fi
}

# Main installation flow
main() {
    echo -e "${YELLOW}Starting TMWS production installation...${NC}"
    
    # Check prerequisites
    if ! command_exists psql; then
        install_postgresql
    else
        echo -e "${GREEN}PostgreSQL already installed${NC}"
    fi
    
    if ! command_exists redis-cli; then
        install_redis
    else
        echo -e "${GREEN}Redis already installed${NC}"
    fi
    
    # Setup Python environment
    install_python_deps
    
    # Setup services
    setup_database
    setup_redis
    
    # Create configuration
    create_env_file
    
    # Setup service
    if [[ "$OS" == "linux" ]]; then
        setup_systemd
    fi
    
    # Optional nginx setup
    setup_nginx
    
    echo ""
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}TMWS Installation Complete!${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Review the configuration in .env.production"
    echo "2. Start the service:"
    if [[ "$OS" == "linux" ]]; then
        echo "   sudo systemctl start tmws"
    else
        echo "   ./scripts/start_production.sh"
    fi
    echo "3. Check the service status:"
    echo "   curl http://localhost:8000/health"
    echo ""
    echo "Important files:"
    echo "- Configuration: .env.production"
    echo "- Logs: /var/log/tmws/tmws.log"
    echo "- Backups: /var/backups/tmws/"
    echo ""
    echo -e "${YELLOW}Save these credentials securely:${NC}"
    echo "DB Password: $TMWS_DB_PASSWORD"
    echo "Redis Password: $TMWS_REDIS_PASSWORD"
}

# Run main function
main