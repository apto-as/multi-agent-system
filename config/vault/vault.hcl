# HashiCorp Vault Configuration for TMWS Production
# Hestia Security Implementation - Maximum Security Configuration

# Storage backend - File storage for simplicity, consider Consul for HA
storage "file" {
  path = "/vault/data"
}

# Listener configuration - TLS only
listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  
  # TLS Configuration - Only TLS 1.2+
  tls_cert_file = "/vault/tls/vault.crt"
  tls_key_file  = "/vault/tls/vault.key"
  tls_min_version = "tls12"
  tls_cipher_suites = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
  
  # Security headers
  tls_disable_client_certs = false
  tls_require_and_verify_client_cert = false
}

# API address
api_addr = "https://vault:8200"
cluster_addr = "https://vault:8201"

# Disable UI for security
ui = false

# Logging
log_level = "INFO"
log_format = "json"

# Seal configuration - Auto-unseal with cloud KMS in production
# seal "awskms" {
#   region = "us-east-1"
#   kms_key_id = "arn:aws:kms:us-east-1:ACCOUNT:key/KEY-ID"
# }

# Performance tuning
max_lease_ttl = "168h"       # 1 week maximum
default_lease_ttl = "24h"    # 1 day default

# Disable mlock for containerized environments
disable_mlock = true

# Plugin directory
plugin_directory = "/vault/plugins"

# Telemetry
telemetry {
  prometheus_retention_time = "24h"
  disable_hostname = true
}