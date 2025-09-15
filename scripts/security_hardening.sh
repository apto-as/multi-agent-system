#!/bin/bash
# TMWS Security Hardening Script
# Applies security best practices to production deployment

set -e

echo "========================================="
echo "TMWS Security Hardening"
echo "========================================="

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if running as root (some commands need sudo)
if [ "$EUID" -eq 0 ]; then 
   echo -e "${RED}Please do not run this script as root${NC}"
   exit 1
fi

# PostgreSQL Security Hardening
harden_postgresql() {
    echo -e "${YELLOW}Hardening PostgreSQL...${NC}"
    
    # Get PostgreSQL version and config path
    PG_VERSION=$(psql --version | awk '{print $3}' | awk -F. '{print $1}')
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        PG_CONFIG_DIR="/usr/local/var/postgres"
    else
        PG_CONFIG_DIR="/etc/postgresql/${PG_VERSION}/main"
    fi
    
    # Create PostgreSQL security configuration
    cat > /tmp/postgresql_security.conf <<'EOF'
# PostgreSQL Security Configuration for TMWS

# Connection Settings
listen_addresses = 'localhost'  # Only local connections
max_connections = 100
superuser_reserved_connections = 3

# Authentication
password_encryption = scram-sha-256

# SSL (if certificates are available)
# ssl = on
# ssl_cert_file = 'server.crt'
# ssl_key_file = 'server.key'
# ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL'
# ssl_prefer_server_ciphers = on

# Resource Limits
shared_buffers = 256MB
work_mem = 4MB
maintenance_work_mem = 64MB

# Query Tuning
effective_cache_size = 1GB
random_page_cost = 1.1

# Write Ahead Log
wal_level = replica
max_wal_size = 1GB
min_wal_size = 80MB

# Logging
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_rotation_age = 1d
log_rotation_size = 100MB
log_connections = on
log_disconnections = on
log_duration = off
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
log_statement = 'ddl'  # Log DDL statements

# Security
row_security = on

# Statement Timeout (30 seconds)
statement_timeout = 30000
EOF
    
    echo -e "${YELLOW}PostgreSQL configuration created. Please review and apply manually.${NC}"
    echo "Configuration saved to: /tmp/postgresql_security.conf"
    
    # Update pg_hba.conf for secure authentication
    cat > /tmp/pg_hba_security.conf <<'EOF'
# PostgreSQL Client Authentication Configuration

# TYPE  DATABASE        USER            ADDRESS                 METHOD

# Local connections
local   all             postgres                                peer
local   all             tmws_user                              scram-sha-256
local   all             all                                    scram-sha-256

# IPv4 local connections
host    all             all             127.0.0.1/32            scram-sha-256

# IPv6 local connections
host    all             all             ::1/128                 scram-sha-256

# Reject all other connections
host    all             all             0.0.0.0/0               reject
host    all             all             ::/0                    reject
EOF
    
    echo "pg_hba.conf template saved to: /tmp/pg_hba_security.conf"
    echo -e "${GREEN}PostgreSQL hardening configuration created${NC}"
}

# Redis Security Hardening
harden_redis() {
    echo -e "${YELLOW}Hardening Redis...${NC}"
    
    cat > /tmp/redis_security.conf <<'EOF'
# Redis Security Configuration for TMWS

# Network and Security
bind 127.0.0.1 ::1
protected-mode yes
port 6379

# Password (set via requirepass)
# requirepass will be set by the installation script

# Disable dangerous commands
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command KEYS ""
rename-command CONFIG "CONFIG_b8c4a3f2"
rename-command SHUTDOWN "SHUTDOWN_7d8e9c1b"

# Persistence
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename tmws.rdb
dir /var/lib/redis

# Logging
loglevel notice
logfile /var/log/redis/redis-server.log

# Limits
maxclients 10000
maxmemory 512mb
maxmemory-policy allkeys-lru

# Slow log
slowlog-log-slower-than 10000
slowlog-max-len 128

# Advanced
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
list-max-ziplist-size -2
list-compress-depth 0
tcp-keepalive 300
timeout 0
tcp-backlog 511
EOF
    
    echo "Redis configuration saved to: /tmp/redis_security.conf"
    echo -e "${GREEN}Redis hardening configuration created${NC}"
}

# File System Security
secure_filesystem() {
    echo -e "${YELLOW}Securing file system...${NC}"
    
    # Set proper permissions for TMWS directories
    TMWS_DIR=$(pwd)
    
    # Secure configuration files
    chmod 600 .env* 2>/dev/null || true
    chmod 600 config/*.yaml 2>/dev/null || true
    
    # Secure log directory
    if [ -d "/var/log/tmws" ]; then
        sudo chmod 750 /var/log/tmws
        sudo chown $USER:$USER /var/log/tmws
    fi
    
    # Secure backup directory
    if [ -d "/var/backups/tmws" ]; then
        sudo chmod 750 /var/backups/tmws
        sudo chown $USER:$USER /var/backups/tmws
    fi
    
    # Create secure temporary directory
    if [ ! -d "/tmp/tmws" ]; then
        mkdir -p /tmp/tmws
        chmod 700 /tmp/tmws
    fi
    
    echo -e "${GREEN}File system permissions secured${NC}"
}

# Firewall Configuration (UFW for Ubuntu/Debian)
configure_firewall() {
    echo -e "${YELLOW}Configuring firewall...${NC}"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v ufw >/dev/null 2>&1; then
            echo "Suggested UFW rules:"
            echo "  sudo ufw default deny incoming"
            echo "  sudo ufw default allow outgoing"
            echo "  sudo ufw allow ssh"
            echo "  sudo ufw allow 80/tcp    # HTTP"
            echo "  sudo ufw allow 443/tcp   # HTTPS"
            echo "  sudo ufw enable"
            echo ""
            echo -e "${YELLOW}Please review and apply these rules manually${NC}"
        else
            echo "UFW not installed. Consider installing it for firewall management."
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "On macOS, configure firewall through System Preferences > Security & Privacy > Firewall"
    fi
}

# SSL/TLS Certificate Setup
setup_ssl() {
    echo -e "${YELLOW}Setting up SSL/TLS...${NC}"
    
    # Create directory for certificates
    mkdir -p certs
    
    # Generate self-signed certificate for development/testing
    if [ ! -f "certs/server.crt" ]; then
        echo -e "${YELLOW}Generating self-signed certificate for development...${NC}"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout certs/server.key \
            -out certs/server.crt \
            -subj "/C=US/ST=State/L=City/O=TMWS/CN=localhost"
        
        chmod 600 certs/server.key
        chmod 644 certs/server.crt
        
        echo -e "${GREEN}Self-signed certificate generated${NC}"
    fi
    
    # Create certificate for PostgreSQL
    cp certs/server.crt certs/postgres.crt
    cp certs/server.key certs/postgres.key
    chmod 600 certs/postgres.key
    
    echo ""
    echo "For production, obtain certificates from Let's Encrypt:"
    echo "  sudo apt-get install certbot"
    echo "  sudo certbot certonly --standalone -d yourdomain.com"
}

# Security Audit Script
create_audit_script() {
    echo -e "${YELLOW}Creating security audit script...${NC}"
    
    cat > scripts/security_audit.sh <<'EOF'
#!/bin/bash
# TMWS Security Audit Script

echo "========================================="
echo "TMWS Security Audit"
echo "========================================="

# Check for common security issues

echo "1. Checking file permissions..."
find . -type f -perm 0777 2>/dev/null | grep -v ".git"

echo "2. Checking for sensitive data in logs..."
grep -r "password\|secret\|token\|key" logs/ 2>/dev/null | grep -v "Binary file"

echo "3. Checking for open ports..."
if command -v netstat >/dev/null 2>&1; then
    netstat -tuln | grep LISTEN
elif command -v ss >/dev/null 2>&1; then
    ss -tuln | grep LISTEN
fi

echo "4. Checking PostgreSQL connections..."
psql -U tmws_user -d tmws -c "SELECT client_addr, state, query_start FROM pg_stat_activity WHERE client_addr IS NOT NULL;" 2>/dev/null || echo "Could not check PostgreSQL connections"

echo "5. Checking Redis connections..."
redis-cli CLIENT LIST 2>/dev/null || echo "Could not check Redis connections"

echo "6. Checking for outdated packages..."
pip list --outdated

echo "7. Checking for security updates..."
if command -v apt >/dev/null 2>&1; then
    apt list --upgradable 2>/dev/null | grep -i security
fi

echo ""
echo "Audit complete. Review the output for any security concerns."
EOF
    
    chmod +x scripts/security_audit.sh
    echo -e "${GREEN}Security audit script created${NC}"
}

# Create backup script
create_backup_script() {
    echo -e "${YELLOW}Creating backup script...${NC}"
    
    cat > scripts/backup.sh <<'EOF'
#!/bin/bash
# TMWS Backup Script

set -e

# Configuration
BACKUP_DIR="/var/backups/tmws"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Starting TMWS backup...${NC}"

# Create backup directory
mkdir -p $BACKUP_DIR

# Load environment
if [ -f ".env.production" ]; then
    export $(grep -v '^#' .env.production | xargs)
fi

# Backup database
echo "Backing up database..."
PGPASSWORD=$TMWS_DB_PASSWORD pg_dump -U tmws_user -h localhost tmws | gzip > $BACKUP_DIR/tmws_db_$TIMESTAMP.sql.gz

# Backup Redis
echo "Backing up Redis..."
redis-cli --rdb $BACKUP_DIR/tmws_redis_$TIMESTAMP.rdb

# Backup configuration files
echo "Backing up configuration..."
tar -czf $BACKUP_DIR/tmws_config_$TIMESTAMP.tar.gz \
    .env.production \
    config/ \
    scripts/ \
    2>/dev/null || true

# Remove old backups
echo "Cleaning old backups..."
find $BACKUP_DIR -name "tmws_*" -type f -mtime +$RETENTION_DAYS -delete

echo -e "${GREEN}Backup complete!${NC}"
echo "Backup location: $BACKUP_DIR"
ls -lh $BACKUP_DIR/tmws_*_$TIMESTAMP.*
EOF
    
    chmod +x scripts/backup.sh
    echo -e "${GREEN}Backup script created${NC}"
}

# Main security hardening flow
main() {
    echo -e "${YELLOW}Starting security hardening...${NC}"
    
    # PostgreSQL hardening
    harden_postgresql
    
    # Redis hardening
    harden_redis
    
    # File system security
    secure_filesystem
    
    # Firewall configuration
    configure_firewall
    
    # SSL/TLS setup
    setup_ssl
    
    # Create audit script
    create_audit_script
    
    # Create backup script
    create_backup_script
    
    echo ""
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}Security Hardening Complete!${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Review and apply PostgreSQL configuration:"
    echo "   sudo cp /tmp/postgresql_security.conf $PG_CONFIG_DIR/"
    echo "   sudo cp /tmp/pg_hba_security.conf $PG_CONFIG_DIR/pg_hba.conf"
    echo "   sudo systemctl restart postgresql"
    echo ""
    echo "2. Review and apply Redis configuration:"
    echo "   sudo cp /tmp/redis_security.conf /etc/redis/redis.conf"
    echo "   sudo systemctl restart redis"
    echo ""
    echo "3. Run security audit:"
    echo "   ./scripts/security_audit.sh"
    echo ""
    echo "4. Setup regular backups:"
    echo "   crontab -e"
    echo "   0 2 * * * /path/to/tmws/scripts/backup.sh"
    echo ""
    echo "5. For production SSL certificates:"
    echo "   Use Let's Encrypt or your CA of choice"
    echo ""
    echo -e "${YELLOW}Remember to regularly update and audit your system!${NC}"
}

# Run main function
main