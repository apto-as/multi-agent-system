#!/bin/bash
# ==============================================
# TMWS Deployment Script
# Automated deployment for different environments
# ==============================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE_DEV="docker-compose.yml"
COMPOSE_FILE_PROD="docker-compose.prod.yml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
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

# Environment validation
validate_environment() {
    local env="$1"
    
    case "$env" in
        "development"|"dev")
            if [ ! -f "$PROJECT_DIR/$COMPOSE_FILE_DEV" ]; then
                log_error "Development compose file not found: $COMPOSE_FILE_DEV"
                exit 1
            fi
            ;;
        "production"|"prod")
            if [ ! -f "$PROJECT_DIR/$COMPOSE_FILE_PROD" ]; then
                log_error "Production compose file not found: $COMPOSE_FILE_PROD"
                exit 1
            fi
            
            # Check required environment variables for production
            local required_vars=(
                "POSTGRES_PASSWORD"
                "REDIS_PASSWORD" 
                "TMWS_SECRET_KEY"
            )
            
            for var in "${required_vars[@]}"; do
                if [ -z "${!var:-}" ]; then
                    log_error "Required environment variable not set: $var"
                    exit 1
                fi
            done
            ;;
        *)
            log_error "Invalid environment: $env"
            exit 1
            ;;
    esac
}

# Pre-deployment checks
pre_deployment_checks() {
    local env="$1"
    
    log_info "Running pre-deployment checks for $env"
    
    # Check Docker and Docker Compose
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    # Check disk space (require at least 2GB free)
    local available_space=$(df / | awk 'NR==2 {print $4}')
    local required_space=2097152  # 2GB in KB
    
    if [ "$available_space" -lt "$required_space" ]; then
        log_warning "Low disk space: $(($available_space/1024/1024))GB available"
    fi
    
    log_success "Pre-deployment checks passed"
}

# Database migration
run_migrations() {
    local env="$1"
    local compose_file="$2"
    
    log_info "Running database migrations"
    
    # Wait for database to be ready
    log_info "Waiting for database to be ready..."
    docker-compose -f "$compose_file" exec -T postgres sh -c '
        until pg_isready -h localhost -p 5432 -U ${POSTGRES_USER:-tmws_user}; do
            echo "Waiting for database..."
            sleep 2
        done
    '
    
    # Run migrations
    docker-compose -f "$compose_file" exec -T tmws python -m alembic upgrade head
    
    log_success "Database migrations completed"
}

# Health check
health_check() {
    local compose_file="$1"
    local max_attempts=30
    local attempt=0
    
    log_info "Performing health checks..."
    
    while [ $attempt -lt $max_attempts ]; do
        if docker-compose -f "$compose_file" exec -T tmws curl -f http://localhost:8000/health &> /dev/null; then
            log_success "Application is healthy"
            return 0
        fi
        
        attempt=$((attempt + 1))
        log_info "Health check attempt $attempt/$max_attempts..."
        sleep 5
    done
    
    log_error "Health check failed after $max_attempts attempts"
    return 1
}

# Backup function
backup_data() {
    local env="$1"
    local compose_file="$2"
    
    if [ "$env" = "production" ]; then
        log_info "Creating backup before deployment"
        
        local backup_dir="$PROJECT_DIR/backups/$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$backup_dir"
        
        # Database backup
        docker-compose -f "$compose_file" exec -T postgres pg_dump -U "${POSTGRES_USER:-tmws_user}" "${POSTGRES_DB:-tmws}" > "$backup_dir/database.sql"
        
        # Redis backup (if applicable)
        docker-compose -f "$compose_file" exec -T redis redis-cli --rdb /tmp/dump.rdb
        docker-compose -f "$compose_file" exec -T redis cat /tmp/dump.rdb > "$backup_dir/redis.rdb"
        
        log_success "Backup created: $backup_dir"
    fi
}

# Deployment function
deploy() {
    local env="$1"
    local action="${2:-up}"
    local build="${3:-false}"
    
    cd "$PROJECT_DIR"
    
    case "$env" in
        "development"|"dev")
            local compose_file="$COMPOSE_FILE_DEV"
            ;;
        "production"|"prod")
            local compose_file="$COMPOSE_FILE_PROD"
            ;;
    esac
    
    log_info "Starting deployment: $env environment"
    
    # Validate environment
    validate_environment "$env"
    
    # Pre-deployment checks
    pre_deployment_checks "$env"
    
    # Create backup for production
    if [ "$env" = "production" ] && [ "$action" = "up" ]; then
        backup_data "$env" "$compose_file"
    fi
    
    # Build images if requested
    if [ "$build" = "true" ]; then
        log_info "Building images..."
        docker-compose -f "$compose_file" build --parallel
    fi
    
    case "$action" in
        "up"|"start")
            log_info "Starting services..."
            docker-compose -f "$compose_file" up -d
            
            # Wait a bit for services to start
            sleep 10
            
            # Run migrations
            run_migrations "$env" "$compose_file"
            
            # Health check
            if health_check "$compose_file"; then
                log_success "Deployment completed successfully"
            else
                log_error "Deployment failed health checks"
                exit 1
            fi
            ;;
            
        "down"|"stop")
            log_info "Stopping services..."
            docker-compose -f "$compose_file" down
            log_success "Services stopped"
            ;;
            
        "restart")
            log_info "Restarting services..."
            docker-compose -f "$compose_file" restart
            
            # Health check after restart
            if health_check "$compose_file"; then
                log_success "Services restarted successfully"
            else
                log_error "Restart failed health checks"
                exit 1
            fi
            ;;
            
        "logs")
            docker-compose -f "$compose_file" logs -f
            ;;
            
        "status")
            docker-compose -f "$compose_file" ps
            ;;
            
        *)
            log_error "Unknown action: $action"
            exit 1
            ;;
    esac
}

# Rollback function
rollback() {
    local env="$1"
    local backup_path="$2"
    
    log_warning "Starting rollback process for $env"
    
    if [ ! -d "$backup_path" ]; then
        log_error "Backup path does not exist: $backup_path"
        exit 1
    fi
    
    case "$env" in
        "development"|"dev")
            local compose_file="$COMPOSE_FILE_DEV"
            ;;
        "production"|"prod")
            local compose_file="$COMPOSE_FILE_PROD"
            ;;
    esac
    
    # Stop services
    docker-compose -f "$compose_file" down
    
    # Restore database
    if [ -f "$backup_path/database.sql" ]; then
        log_info "Restoring database..."
        docker-compose -f "$compose_file" up -d postgres
        sleep 10
        docker-compose -f "$compose_file" exec -T postgres psql -U "${POSTGRES_USER:-tmws_user}" -d "${POSTGRES_DB:-tmws}" < "$backup_path/database.sql"
    fi
    
    # Start services
    docker-compose -f "$compose_file" up -d
    
    if health_check "$compose_file"; then
        log_success "Rollback completed successfully"
    else
        log_error "Rollback failed"
        exit 1
    fi
}

# Show help
show_help() {
    cat << EOF
TMWS Deployment Script

Usage:
    $0 ENVIRONMENT ACTION [OPTIONS]

Environments:
    development, dev     - Development environment
    production, prod     - Production environment

Actions:
    up, start           - Start services
    down, stop          - Stop services
    restart             - Restart services
    logs                - Show logs
    status              - Show service status
    rollback BACKUP_PATH - Rollback to backup

Options:
    --build             - Build images before deployment

Examples:
    $0 development up                    # Start development environment
    $0 production up --build            # Build and start production
    $0 production rollback ./backups/20231201-120000

Environment Variables (Production):
    POSTGRES_PASSWORD   - Database password
    REDIS_PASSWORD      - Redis password
    TMWS_SECRET_KEY     - Application secret key

EOF
}

# Parse arguments
if [ "$#" -eq 0 ] || [ "$1" = "--help" ]; then
    show_help
    exit 0
fi

ENVIRONMENT="$1"
ACTION="${2:-up}"
BUILD="false"

# Parse options
shift 2 2>/dev/null || true
while [ "$#" -gt 0 ]; do
    case "$1" in
        --build)
            BUILD="true"
            shift
            ;;
        rollback)
            if [ -z "${2:-}" ]; then
                log_error "Backup path required for rollback"
                exit 1
            fi
            rollback "$ENVIRONMENT" "$2"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Execute deployment
deploy "$ENVIRONMENT" "$ACTION" "$BUILD"