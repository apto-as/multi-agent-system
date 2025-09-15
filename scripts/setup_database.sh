#!/bin/bash

#############################################
# TMWS Database Setup Script v2.2.0
#
# This script sets up PostgreSQL database for TMWS
# including pgvector extension and initial schema
#############################################

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DB_HOST="${TMWS_DB_HOST:-localhost}"
DB_PORT="${TMWS_DB_PORT:-5432}"
DB_NAME="${TMWS_DB_NAME:-tmws}"
DB_USER="${TMWS_DB_USER:-tmws_user}"
DB_PASSWORD="${TMWS_DB_PASSWORD:-tmws_password}"
ENVIRONMENT="${TMWS_ENVIRONMENT:-development}"
SKIP_BACKUP="${SKIP_BACKUP:-false}"

# Function to print colored messages
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root/sudo
check_privileges() {
    if [[ "$ENVIRONMENT" == "production" ]] && [[ $EUID -ne 0 ]]; then
        log_error "This script must be run with sudo in production environment"
        exit 1
    fi
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        DISTRO=$(lsb_release -si 2>/dev/null || echo "Unknown")
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        log_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
    log_info "Detected OS: $OS ${DISTRO:-}"
}

# Function to check PostgreSQL installation
check_postgresql() {
    log_info "Checking PostgreSQL installation..."

    if ! command -v psql &> /dev/null; then
        log_error "PostgreSQL is not installed"

        if [[ "$OS" == "macos" ]]; then
            log_info "Install with: brew install postgresql@15"
        elif [[ "$OS" == "linux" ]]; then
            log_info "Install with: sudo apt-get install postgresql-15 postgresql-client-15"
        fi
        exit 1
    fi

    # Check PostgreSQL version
    PG_VERSION=$(psql --version | grep -oE '[0-9]+' | head -1)
    if [[ $PG_VERSION -lt 14 ]]; then
        log_error "PostgreSQL 14+ is required (found version $PG_VERSION)"
        exit 1
    fi

    log_success "PostgreSQL $PG_VERSION found"
}

# Function to check if database exists
database_exists() {
    local db_name=$1
    psql -h "$DB_HOST" -p "$DB_PORT" -U postgres -lqt | cut -d \| -f 1 | grep -qw "$db_name"
}

# Function to check if user exists
user_exists() {
    local user_name=$1
    psql -h "$DB_HOST" -p "$DB_PORT" -U postgres -tAc "SELECT 1 FROM pg_user WHERE usename='$user_name'" | grep -q 1
}

# Function to backup existing database
backup_database() {
    if [[ "$SKIP_BACKUP" == "true" ]]; then
        log_warning "Skipping database backup (SKIP_BACKUP=true)"
        return
    fi

    if database_exists "$DB_NAME"; then
        log_info "Backing up existing database..."
        BACKUP_FILE="tmws_backup_$(date +%Y%m%d_%H%M%S).sql"

        pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME" > "$BACKUP_FILE" 2>/dev/null || {
            log_warning "Could not backup as $DB_USER, trying as postgres..."
            pg_dump -h "$DB_HOST" -p "$DB_PORT" -U postgres "$DB_NAME" > "$BACKUP_FILE"
        }

        if [[ -f "$BACKUP_FILE" ]]; then
            gzip "$BACKUP_FILE"
            log_success "Database backed up to ${BACKUP_FILE}.gz"
        fi
    fi
}

# Function to install pgvector extension
install_pgvector() {
    log_info "Checking pgvector extension..."

    # Check if pgvector is available
    if ! psql -h "$DB_HOST" -p "$DB_PORT" -U postgres -d postgres -c "SELECT * FROM pg_available_extensions WHERE name='vector'" | grep -q vector; then
        log_warning "pgvector extension not found, attempting to install..."

        if [[ "$OS" == "macos" ]]; then
            log_info "Installing pgvector with Homebrew..."
            brew install pgvector
        elif [[ "$OS" == "linux" ]]; then
            log_info "Installing pgvector..."
            sudo apt-get update
            sudo apt-get install -y postgresql-$PG_VERSION-pgvector
        fi
    else
        log_success "pgvector extension is available"
    fi
}

# Function to create database and user
create_database() {
    log_info "Setting up database and user..."

    # Create user if not exists
    if ! user_exists "$DB_USER"; then
        log_info "Creating user: $DB_USER"
        psql -h "$DB_HOST" -p "$DB_PORT" -U postgres <<EOF
CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
EOF
        log_success "User $DB_USER created"
    else
        log_info "User $DB_USER already exists, updating password..."
        psql -h "$DB_HOST" -p "$DB_PORT" -U postgres <<EOF
ALTER USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
EOF
    fi

    # Create database if not exists
    if ! database_exists "$DB_NAME"; then
        log_info "Creating database: $DB_NAME"
        psql -h "$DB_HOST" -p "$DB_PORT" -U postgres <<EOF
CREATE DATABASE $DB_NAME OWNER $DB_USER;
EOF
        log_success "Database $DB_NAME created"
    else
        log_warning "Database $DB_NAME already exists"
    fi

    # Grant privileges
    psql -h "$DB_HOST" -p "$DB_PORT" -U postgres <<EOF
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
EOF

    # Enable extensions
    log_info "Enabling required extensions..."
    psql -h "$DB_HOST" -p "$DB_PORT" -U postgres -d "$DB_NAME" <<EOF
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
EOF

    log_success "Extensions enabled"
}

# Function to set production security settings
set_production_security() {
    if [[ "$ENVIRONMENT" != "production" ]]; then
        return
    fi

    log_info "Applying production security settings..."

    psql -h "$DB_HOST" -p "$DB_PORT" -U postgres -d "$DB_NAME" <<EOF
-- Revoke default public privileges
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO $DB_USER;

-- Set connection limits
ALTER USER $DB_USER CONNECTION LIMIT 100;

-- Set statement timeout (30 seconds)
ALTER DATABASE $DB_NAME SET statement_timeout = '30s';

-- Enable SSL enforcement (if supported)
ALTER DATABASE $DB_NAME SET ssl = on;

-- Row level security for sensitive tables (will be applied after migration)
-- ALTER TABLE users ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
EOF

    log_success "Production security settings applied"
}

# Function to optimize database settings
optimize_database() {
    log_info "Optimizing database settings..."

    psql -h "$DB_HOST" -p "$DB_PORT" -U postgres -d "$DB_NAME" <<EOF
-- Optimize for vector searches
ALTER DATABASE $DB_NAME SET max_parallel_workers_per_gather = 4;
ALTER DATABASE $DB_NAME SET max_parallel_workers = 8;
ALTER DATABASE $DB_NAME SET max_parallel_maintenance_workers = 4;

-- Optimize memory settings
ALTER DATABASE $DB_NAME SET shared_buffers = '256MB';
ALTER DATABASE $DB_NAME SET effective_cache_size = '1GB';
ALTER DATABASE $DB_NAME SET maintenance_work_mem = '128MB';
ALTER DATABASE $DB_NAME SET work_mem = '4MB';

-- Optimize for SSD
ALTER DATABASE $DB_NAME SET random_page_cost = 1.1;
ALTER DATABASE $DB_NAME SET effective_io_concurrency = 200;

-- Enable query optimization
ALTER DATABASE $DB_NAME SET jit = off;  -- Disable JIT for better connection times
ALTER DATABASE $DB_NAME SET enable_partitionwise_aggregate = on;
ALTER DATABASE $DB_NAME SET enable_partitionwise_join = on;
EOF

    log_success "Database optimizations applied"
}

# Function to run Alembic migrations
run_migrations() {
    log_info "Running database migrations..."

    # Check if alembic is installed
    if ! command -v alembic &> /dev/null; then
        log_warning "Alembic not found, installing..."
        pip install alembic sqlalchemy asyncpg psycopg2-binary
    fi

    # Export database URL for Alembic
    export TMWS_DATABASE_URL="postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"

    # Check if we're in the right directory
    if [[ ! -f "alembic.ini" ]]; then
        log_error "alembic.ini not found. Please run this script from the TMWS root directory"
        exit 1
    fi

    # Run migrations
    log_info "Applying migrations..."
    alembic upgrade head

    log_success "Migrations completed"
}

# Function to create initial data
create_initial_data() {
    log_info "Creating initial data..."

    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
-- Create default personas if they don't exist
INSERT INTO personas (id, name, description, capabilities, configuration, created_at)
VALUES
    ('athena-conductor', 'Athena', 'Harmonious Conductor - System coordination and orchestration',
     '["orchestration", "coordination", "harmony", "workflow"]'::jsonb,
     '{"style": "warm", "approach": "collaborative"}'::jsonb, NOW()),
    ('artemis-optimizer', 'Artemis', 'Technical Perfectionist - Performance and optimization',
     '["optimization", "performance", "quality", "technical"]'::jsonb,
     '{"style": "precise", "approach": "analytical"}'::jsonb, NOW()),
    ('hestia-auditor', 'Hestia', 'Security Guardian - Security and audit',
     '["security", "audit", "risk", "vulnerability"]'::jsonb,
     '{"style": "cautious", "approach": "defensive"}'::jsonb, NOW()),
    ('eris-coordinator', 'Eris', 'Tactical Coordinator - Team and resource coordination',
     '["coordination", "tactical", "team", "resources"]'::jsonb,
     '{"style": "strategic", "approach": "tactical"}'::jsonb, NOW()),
    ('hera-strategist', 'Hera', 'Strategic Commander - Long-term planning and strategy',
     '["strategy", "planning", "architecture", "vision"]'::jsonb,
     '{"style": "commanding", "approach": "strategic"}'::jsonb, NOW()),
    ('muses-documenter', 'Muses', 'Knowledge Architect - Documentation and knowledge management',
     '["documentation", "knowledge", "archive", "learning"]'::jsonb,
     '{"style": "thorough", "approach": "systematic"}'::jsonb, NOW())
ON CONFLICT (id) DO NOTHING;

-- Create system user for internal operations (if auth is enabled)
-- This will be handled by auth migrations
EOF

    log_success "Initial data created"
}

# Function to verify setup
verify_setup() {
    log_info "Verifying database setup..."

    # Test connection
    if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1" &> /dev/null; then
        log_success "Database connection successful"
    else
        log_error "Cannot connect to database"
        exit 1
    fi

    # Check extensions
    EXTENSIONS=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT extname FROM pg_extension WHERE extname IN ('vector', 'pgcrypto', 'pg_trgm', 'uuid-ossp')")

    for ext in vector pgcrypto pg_trgm uuid-ossp; do
        if echo "$EXTENSIONS" | grep -q "$ext"; then
            log_success "Extension $ext is enabled"
        else
            log_error "Extension $ext is not enabled"
            exit 1
        fi
    done

    # Check tables (after migration)
    TABLE_COUNT=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'")
    log_info "Found $TABLE_COUNT tables in database"

    log_success "Database setup verification completed"
}

# Function to print connection info
print_connection_info() {
    echo ""
    echo "======================================"
    echo "   TMWS Database Setup Complete!"
    echo "======================================"
    echo ""
    echo "Connection Information:"
    echo "  Host:     $DB_HOST"
    echo "  Port:     $DB_PORT"
    echo "  Database: $DB_NAME"
    echo "  User:     $DB_USER"
    echo ""
    echo "Connection String:"
    echo "  postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
    echo ""
    echo "Environment Variable:"
    echo "  export TMWS_DATABASE_URL=\"postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}\""
    echo ""

    if [[ "$ENVIRONMENT" == "production" ]]; then
        echo "⚠️  PRODUCTION ENVIRONMENT DETECTED"
        echo "Please ensure you:"
        echo "  1. Change the default password"
        echo "  2. Configure SSL certificates"
        echo "  3. Set up regular backups"
        echo "  4. Monitor database performance"
    fi
}

# Main execution
main() {
    echo "======================================"
    echo "   TMWS Database Setup Script v2.2.0"
    echo "======================================"
    echo ""

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --host)
                DB_HOST="$2"
                shift 2
                ;;
            --port)
                DB_PORT="$2"
                shift 2
                ;;
            --database)
                DB_NAME="$2"
                shift 2
                ;;
            --user)
                DB_USER="$2"
                shift 2
                ;;
            --password)
                DB_PASSWORD="$2"
                shift 2
                ;;
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --skip-backup)
                SKIP_BACKUP="true"
                shift
                ;;
            --help)
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --host HOST           Database host (default: localhost)"
                echo "  --port PORT           Database port (default: 5432)"
                echo "  --database NAME       Database name (default: tmws)"
                echo "  --user USER           Database user (default: tmws_user)"
                echo "  --password PASSWORD   Database password (default: tmws_password)"
                echo "  --environment ENV     Environment (development/production)"
                echo "  --skip-backup         Skip database backup"
                echo "  --help                Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Check privileges if production
    check_privileges

    # Detect operating system
    detect_os

    # Check PostgreSQL installation
    check_postgresql

    # Install pgvector if needed
    install_pgvector

    # Backup existing database
    backup_database

    # Create database and user
    create_database

    # Apply production security settings
    set_production_security

    # Optimize database
    optimize_database

    # Run migrations
    run_migrations

    # Create initial data
    create_initial_data

    # Verify setup
    verify_setup

    # Print connection info
    print_connection_info

    log_success "Database setup completed successfully!"
}

# Run main function
main "$@"