#!/bin/bash
# HashiCorp Vault Initialization and Configuration Script
# Hestia Security Implementation - Automated Secret Management Setup
set -euo pipefail

# Configuration
VAULT_ADDR="${VAULT_ADDR:-https://vault:8200}"
VAULT_CONFIG_PATH="/vault/config"
VAULT_INIT_FILE="/vault/data/.vault-init"
VAULT_POLICY_DIR="/vault/policies"
LOG_FILE="/var/log/vault/vault-init.log"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

error_exit() {
    log "${RED}ERROR: $1${NC}"
    exit 1
}

success() {
    log "${GREEN}SUCCESS: $1${NC}"
}

warning() {
    log "${YELLOW}WARNING: $1${NC}"
}

# Wait for Vault to be ready
wait_for_vault() {
    log "Waiting for Vault to be ready..."
    local retries=0
    local max_retries=30
    
    while [ $retries -lt $max_retries ]; do
        if vault status > /dev/null 2>&1; then
            success "Vault is ready"
            return 0
        fi
        
        log "Vault not ready, waiting... (attempt $((retries + 1))/$max_retries)"
        sleep 5
        ((retries++))
    done
    
    error_exit "Vault failed to become ready after $max_retries attempts"
}

# Initialize Vault if not already initialized
initialize_vault() {
    log "Checking if Vault is initialized..."
    
    if vault status 2>/dev/null | grep -q "Initialized.*true"; then
        success "Vault is already initialized"
        return 0
    fi
    
    log "Initializing Vault..."
    
    # Initialize with 5 key shares, 3 required for unsealing
    vault operator init \
        -key-shares=5 \
        -key-threshold=3 \
        -format=json > "$VAULT_INIT_FILE"
    
    if [ $? -eq 0 ]; then
        success "Vault initialized successfully"
        chmod 600 "$VAULT_INIT_FILE"
        
        # Extract unseal keys and root token
        UNSEAL_KEYS=($(jq -r '.unseal_keys_b64[]' "$VAULT_INIT_FILE"))
        ROOT_TOKEN=$(jq -r '.root_token' "$VAULT_INIT_FILE")
        
        log "Vault initialization complete. Unseal keys and root token saved to $VAULT_INIT_FILE"
        warning "CRITICAL: Backup the unseal keys and root token securely!"
        
        return 0
    else
        error_exit "Failed to initialize Vault"
    fi
}

# Unseal Vault
unseal_vault() {
    log "Checking if Vault needs unsealing..."
    
    if vault status 2>/dev/null | grep -q "Sealed.*false"; then
        success "Vault is already unsealed"
        return 0
    fi
    
    if [ ! -f "$VAULT_INIT_FILE" ]; then
        error_exit "Vault initialization file not found. Cannot unseal."
    fi
    
    log "Unsealing Vault..."
    
    # Extract unseal keys
    UNSEAL_KEYS=($(jq -r '.unseal_keys_b64[]' "$VAULT_INIT_FILE"))
    
    # Use first 3 keys to unseal (threshold is 3)
    for i in {0..2}; do
        log "Using unseal key $((i + 1))/3"
        vault operator unseal "${UNSEAL_KEYS[i]}"
    done
    
    if vault status 2>/dev/null | grep -q "Sealed.*false"; then
        success "Vault unsealed successfully"
    else
        error_exit "Failed to unseal Vault"
    fi
}

# Authenticate with root token
authenticate_vault() {
    if [ ! -f "$VAULT_INIT_FILE" ]; then
        error_exit "Vault initialization file not found"
    fi
    
    ROOT_TOKEN=$(jq -r '.root_token' "$VAULT_INIT_FILE")
    export VAULT_TOKEN="$ROOT_TOKEN"
    
    log "Authenticating with Vault..."
    if vault auth -method=token "$ROOT_TOKEN" > /dev/null 2>&1; then
        success "Authenticated with Vault"
    else
        error_exit "Failed to authenticate with Vault"
    fi
}

# Enable authentication methods
enable_auth_methods() {
    log "Configuring authentication methods..."
    
    # Enable AppRole auth method for applications
    if ! vault auth list | grep -q "approle/"; then
        log "Enabling AppRole authentication..."
        vault auth enable approle
        success "AppRole authentication enabled"
    fi
    
    # Enable Kubernetes auth method if in K8s environment
    if [ -f "/var/run/secrets/kubernetes.io/serviceaccount/token" ]; then
        log "Kubernetes environment detected, enabling Kubernetes auth..."
        if ! vault auth list | grep -q "kubernetes/"; then
            vault auth enable kubernetes
            
            # Configure Kubernetes auth
            vault write auth/kubernetes/config \
                token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
                kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443" \
                kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
            
            success "Kubernetes authentication configured"
        fi
    fi
}

# Enable secret engines
enable_secret_engines() {
    log "Configuring secret engines..."
    
    # Enable KV v2 secret engine for TMWS secrets
    if ! vault secrets list | grep -q "tmws/"; then
        log "Enabling KV v2 secret engine for TMWS..."
        vault secrets enable -path=tmws kv-v2
        success "TMWS KV secret engine enabled"
    fi
    
    # Enable database secret engine for dynamic credentials
    if ! vault secrets list | grep -q "database/"; then
        log "Enabling database secret engine..."
        vault secrets enable database
        success "Database secret engine enabled"
    fi
    
    # Enable PKI secret engine for certificate management
    if ! vault secrets list | grep -q "pki/"; then
        log "Enabling PKI secret engine..."
        vault secrets enable pki
        vault secrets tune -max-lease-ttl=87600h pki  # 10 years
        success "PKI secret engine enabled"
    fi
    
    # Enable Transit secret engine for encryption as a service
    if ! vault secrets list | grep -q "transit/"; then
        log "Enabling Transit secret engine..."
        vault secrets enable transit
        success "Transit secret engine enabled"
    fi
}

# Create policies
create_policies() {
    log "Creating Vault policies..."
    
    mkdir -p "$VAULT_POLICY_DIR"
    
    # TMWS Application Policy
    cat > "$VAULT_POLICY_DIR/tmws-app.hcl" << 'EOF'
# TMWS Application Policy - Minimum Required Permissions
path "tmws/data/config/*" {
  capabilities = ["read"]
}

path "tmws/data/secrets/*" {
  capabilities = ["read"]
}

path "database/creds/tmws-role" {
  capabilities = ["read"]
}

path "transit/encrypt/tmws" {
  capabilities = ["update"]
}

path "transit/decrypt/tmws" {
  capabilities = ["update"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
EOF

    vault policy write tmws-app "$VAULT_POLICY_DIR/tmws-app.hcl"
    success "TMWS application policy created"
    
    # Admin Policy
    cat > "$VAULT_POLICY_DIR/tmws-admin.hcl" << 'EOF'
# TMWS Admin Policy - Full Access to TMWS Secrets
path "tmws/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "database/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "pki/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "transit/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "auth/approle/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

    vault policy write tmws-admin "$VAULT_POLICY_DIR/tmws-admin.hcl"
    success "TMWS admin policy created"
}

# Configure AppRole for TMWS application
configure_approle() {
    log "Configuring AppRole for TMWS application..."
    
    # Create AppRole
    vault write auth/approle/role/tmws-app \
        token_policies="tmws-app" \
        token_ttl=1h \
        token_max_ttl=4h \
        bind_secret_id=true \
        secret_id_ttl=0 \
        token_num_uses=0
    
    # Get Role ID
    ROLE_ID=$(vault read -field=role_id auth/approle/role/tmws-app/role-id)
    
    # Generate Secret ID
    SECRET_ID=$(vault write -field=secret_id auth/approle/role/tmws-app/secret-id)
    
    # Save credentials securely
    cat > /vault/data/tmws-approle-credentials << EOF
VAULT_ROLE_ID=$ROLE_ID
VAULT_SECRET_ID=$SECRET_ID
EOF
    chmod 600 /vault/data/tmws-approle-credentials
    
    success "AppRole configured for TMWS application"
    log "Role ID and Secret ID saved to /vault/data/tmws-approle-credentials"
}

# Setup database dynamic secrets
configure_database_secrets() {
    log "Configuring database dynamic secrets..."
    
    # Configure PostgreSQL connection
    vault write database/config/tmws-postgres \
        plugin_name=postgresql-database-plugin \
        connection_url="postgresql://{{username}}:{{password}}@postgres:5432/tmws_production?sslmode=require" \
        allowed_roles="tmws-role" \
        username="vault_admin" \
        password="$POSTGRES_VAULT_PASSWORD"
    
    # Create role for TMWS application
    vault write database/roles/tmws-role \
        db_name=tmws-postgres \
        creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
        default_ttl="1h" \
        max_ttl="24h"
    
    success "Database dynamic secrets configured"
}

# Setup PKI for internal certificates
configure_pki() {
    log "Configuring PKI for internal certificates..."
    
    # Generate root CA
    vault write pki/root/generate/internal \
        common_name="TMWS Internal CA" \
        ttl=87600h \
        key_bits=4096
    
    # Configure CA and CRL URLs
    vault write pki/config/urls \
        issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
        crl_distribution_points="$VAULT_ADDR/v1/pki/crl"
    
    # Create role for internal certificates
    vault write pki/roles/tmws-internal \
        allowed_domains="tmws.internal,postgres.internal,redis.internal,vault.internal" \
        allow_subdomains=true \
        max_ttl="8760h" \
        key_bits=2048
    
    success "PKI configured for internal certificates"
}

# Setup Transit encryption
configure_transit() {
    log "Configuring Transit encryption..."
    
    # Create encryption key for TMWS
    vault write -f transit/keys/tmws
    
    success "Transit encryption key created"
}

# Store initial secrets
store_initial_secrets() {
    log "Storing initial secrets..."
    
    # Generate and store application secrets
    TMWS_SECRET_KEY=$(openssl rand -base64 64 | tr -d '\n')
    JWT_SECRET=$(openssl rand -base64 64 | tr -d '\n')
    ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    
    # Store secrets in Vault
    vault kv put tmws/config/app \
        secret_key="$TMWS_SECRET_KEY" \
        jwt_secret="$JWT_SECRET" \
        encryption_key="$ENCRYPTION_KEY"
    
    # Store database credentials (will be replaced by dynamic secrets)
    vault kv put tmws/secrets/database \
        username="tmws_user" \
        password="$POSTGRES_PASSWORD"
    
    # Store Redis credentials
    vault kv put tmws/secrets/redis \
        password="$REDIS_PASSWORD"
    
    success "Initial secrets stored in Vault"
}

# Create monitoring and health check
setup_monitoring() {
    log "Setting up Vault monitoring..."
    
    # Create health check script
    cat > /usr/local/bin/vault-health-check.sh << 'EOF'
#!/bin/bash
# Vault Health Check Script

VAULT_ADDR="${VAULT_ADDR:-https://vault:8200}"

# Check Vault status
if ! vault status > /dev/null 2>&1; then
    echo "CRITICAL: Vault is not responding"
    exit 2
fi

# Check if sealed
if vault status 2>/dev/null | grep -q "Sealed.*true"; then
    echo "CRITICAL: Vault is sealed"
    exit 2
fi

# Check if initialized
if ! vault status 2>/dev/null | grep -q "Initialized.*true"; then
    echo "CRITICAL: Vault is not initialized"
    exit 2
fi

echo "OK: Vault is healthy"
exit 0
EOF
    
    chmod +x /usr/local/bin/vault-health-check.sh
    
    # Add to cron for monitoring
    echo "*/5 * * * * root /usr/local/bin/vault-health-check.sh" >> /etc/cron.d/vault-monitoring
    
    success "Vault monitoring configured"
}

# Main execution
main() {
    log "=== Starting Vault Initialization and Configuration ==="
    
    # Create necessary directories
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$VAULT_POLICY_DIR"
    
    # Wait for Vault service
    wait_for_vault
    
    # Initialize and unseal Vault
    initialize_vault
    unseal_vault
    authenticate_vault
    
    # Configure Vault
    enable_auth_methods
    enable_secret_engines
    create_policies
    configure_approle
    
    # Setup advanced features
    configure_database_secrets
    configure_pki
    configure_transit
    store_initial_secrets
    setup_monitoring
    
    success "=== Vault Configuration Complete ==="
    log "Vault is ready for production use"
    
    warning "IMPORTANT SECURITY REMINDERS:"
    warning "1. Backup the unseal keys and root token securely"
    warning "2. Rotate the root token after setting up admin users"
    warning "3. Enable audit logging for compliance"
    warning "4. Consider using auto-unseal with cloud KMS"
    warning "5. Regularly backup Vault data"
}

# Trap errors
trap 'error_exit "Script interrupted"' INT TERM

# Check if running in correct environment
if [ ! -d "/vault" ]; then
    error_exit "This script must run in a Vault container environment"
fi

# Run main function
main "$@"