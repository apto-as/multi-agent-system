#!/bin/bash
# SSL/TLS Certificate Automation Script for TMWS Production
# Hestia Security Implementation - Let's Encrypt with Automatic Renewal
set -euo pipefail

# Configuration
DOMAIN="${TMWS_DOMAIN:-tmws.company.com}"
EMAIL="${TMWS_ADMIN_EMAIL:-admin@company.com}"
WEBROOT_PATH="/var/www/certbot"
NGINX_CONFIG_PATH="/etc/nginx/sites-available/tmws-ssl"
CERT_PATH="/etc/letsencrypt/live/$DOMAIN"
LOG_FILE="/var/log/tmws/ssl-automation.log"

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error_exit "This script must be run as root"
fi

# Create necessary directories
mkdir -p /var/log/tmws
mkdir -p "$WEBROOT_PATH"

log "Starting SSL/TLS certificate automation for domain: $DOMAIN"

# Install Certbot if not present
install_certbot() {
    log "Installing Certbot..."
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y certbot python3-certbot-nginx
    elif command -v yum &> /dev/null; then
        yum install -y certbot python3-certbot-nginx
    else
        error_exit "Unsupported package manager. Please install Certbot manually."
    fi
}

# Generate initial certificate
generate_initial_cert() {
    log "Generating initial SSL certificate..."
    
    # Create temporary nginx config for certificate validation
    cat > /etc/nginx/sites-available/tmws-temp << EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    location /.well-known/acme-challenge/ {
        root $WEBROOT_PATH;
    }
    
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}
EOF
    
    # Enable temporary config
    ln -sf /etc/nginx/sites-available/tmws-temp /etc/nginx/sites-enabled/tmws-temp
    nginx -t && systemctl reload nginx
    
    # Generate certificate
    certbot certonly \
        --webroot \
        --webroot-path="$WEBROOT_PATH" \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        --domains "$DOMAIN" \
        --non-interactive
    
    if [ $? -eq 0 ]; then
        log "SSL certificate generated successfully"
    else
        error_exit "Failed to generate SSL certificate"
    fi
}

# Create production nginx SSL configuration
create_ssl_nginx_config() {
    log "Creating production nginx SSL configuration..."
    
    cat > "$NGINX_CONFIG_PATH" << EOF
# TMWS Production SSL Configuration - Hestia Security Hardened
upstream tmws_backend {
    server 127.0.0.1:8000;
    keepalive 32;
}

# Rate limiting zones
limit_req_zone \$binary_remote_addr zone=tmws_api:10m rate=10r/s;
limit_req_zone \$binary_remote_addr zone=tmws_auth:10m rate=5r/s;
limit_conn_zone \$binary_remote_addr zone=tmws_conn:10m;

server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    
    # SSL Configuration - Maximum Security
    ssl_certificate $CERT_PATH/fullchain.pem;
    ssl_certificate_key $CERT_PATH/privkey.pem;
    ssl_trusted_certificate $CERT_PATH/chain.pem;
    
    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Security Headers - Maximum Paranoia Mode
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), accelerometer=(), gyroscope=();" always;
    
    # Rate Limiting
    limit_req zone=tmws_api burst=20 nodelay;
    limit_conn tmws_conn 10;
    
    # Request Size Limits
    client_max_body_size 10M;
    client_body_timeout 60s;
    client_header_timeout 60s;
    
    # Logging with Security Focus
    access_log /var/log/nginx/tmws-access.log combined;
    error_log /var/log/nginx/tmws-error.log warn;
    
    # Hide nginx version
    server_tokens off;
    
    # API Routes with Additional Security
    location /api/ {
        limit_req zone=tmws_api burst=10 nodelay;
        
        proxy_pass http://tmws_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        
        # Security headers for API
        add_header X-API-Version "3.1" always;
        add_header Cache-Control "no-store, no-cache, must-revalidate" always;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Authentication endpoints with stricter limits
    location ~ ^/api/v1/(auth|login|register) {
        limit_req zone=tmws_auth burst=3 nodelay;
        
        proxy_pass http://tmws_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://tmws_backend;
        proxy_set_header Host \$host;
    }
    
    # Block suspicious requests
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    location ~ \.(php|asp|aspx|jsp|cgi)$ {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF
    
    log "SSL nginx configuration created"
}

# Setup automatic renewal
setup_auto_renewal() {
    log "Setting up automatic SSL certificate renewal..."
    
    cat > /etc/cron.d/tmws-ssl-renewal << EOF
# TMWS SSL Certificate Auto-Renewal - Runs twice daily
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 2,14 * * * root /usr/bin/certbot renew --quiet --nginx && /bin/systemctl reload nginx
EOF
    
    # Test renewal process
    certbot renew --dry-run
    if [ $? -eq 0 ]; then
        log "SSL auto-renewal configured successfully"
    else
        error_exit "Failed to configure SSL auto-renewal"
    fi
}

# Create SSL monitoring script
create_ssl_monitor() {
    log "Creating SSL certificate monitoring script..."
    
    cat > /usr/local/bin/tmws-ssl-monitor.sh << 'EOF'
#!/bin/bash
# TMWS SSL Certificate Monitoring
# Sends alerts when certificates are expiring

DOMAIN="${TMWS_DOMAIN:-tmws.company.com}"
ALERT_EMAIL="${TMWS_ADMIN_EMAIL:-admin@company.com}"
DAYS_WARNING=30

# Check certificate expiry
CERT_EXPIRY=$(openssl x509 -noout -dates -in /etc/letsencrypt/live/$DOMAIN/cert.pem | grep notAfter | cut -d= -f2)
CERT_EXPIRY_DATE=$(date -d "$CERT_EXPIRY" +%s)
CURRENT_DATE=$(date +%s)
DAYS_REMAINING=$(( (CERT_EXPIRY_DATE - CURRENT_DATE) / 86400 ))

if [ $DAYS_REMAINING -le $DAYS_WARNING ]; then
    echo "WARNING: SSL certificate for $DOMAIN expires in $DAYS_REMAINING days" | \
    mail -s "TMWS SSL Certificate Expiry Warning" $ALERT_EMAIL
    logger "TMWS SSL Monitor: Certificate expires in $DAYS_REMAINING days"
fi

# Log certificate status
logger "TMWS SSL Monitor: Certificate for $DOMAIN valid for $DAYS_REMAINING days"
EOF

    chmod +x /usr/local/bin/tmws-ssl-monitor.sh
    
    # Add to crontab
    echo "0 6 * * * root /usr/local/bin/tmws-ssl-monitor.sh" >> /etc/cron.d/tmws-ssl-renewal
}

# Main execution
main() {
    log "=== TMWS SSL/TLS Automation Started ==="
    
    # Check if certificate already exists
    if [ -f "$CERT_PATH/fullchain.pem" ]; then
        log "SSL certificate already exists. Checking validity..."
        openssl x509 -checkend 86400 -noout -in "$CERT_PATH/fullchain.pem"
        if [ $? -eq 0 ]; then
            log "Existing certificate is valid for at least 24 hours"
        else
            log "Existing certificate is expiring soon. Renewing..."
            certbot renew --force-renewal
        fi
    else
        install_certbot
        generate_initial_cert
    fi
    
    create_ssl_nginx_config
    setup_auto_renewal
    create_ssl_monitor
    
    # Enable SSL configuration
    rm -f /etc/nginx/sites-enabled/tmws-temp
    ln -sf "$NGINX_CONFIG_PATH" /etc/nginx/sites-enabled/tmws-ssl
    
    # Test and reload nginx
    nginx -t
    if [ $? -eq 0 ]; then
        systemctl reload nginx
        log "SSL configuration applied successfully"
    else
        error_exit "Nginx configuration test failed"
    fi
    
    log "=== TMWS SSL/TLS Automation Completed Successfully ==="
    log "Certificate location: $CERT_PATH"
    log "Auto-renewal configured with monitoring"
}

# Trap errors
trap 'error_exit "Script interrupted"' INT TERM

# Run main function
main "$@"