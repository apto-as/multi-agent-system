#!/bin/bash
# ==============================================
# TMWS Docker Build Script
# Automated build process for all environments
# ==============================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
IMAGE_NAME="tmws"
REGISTRY="${REGISTRY:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Build function
build_image() {
    local target="$1"
    local tag="$2"
    
    log_info "Building $target image with tag: $tag"
    
    # Build with BuildKit for optimal caching
    DOCKER_BUILDKIT=1 docker build \
        --target "$target" \
        --tag "$IMAGE_NAME:$tag" \
        --build-arg BUILDKIT_INLINE_CACHE=1 \
        --cache-from "$IMAGE_NAME:$tag" \
        "$PROJECT_DIR"
    
    log_success "Successfully built $IMAGE_NAME:$tag"
}

# Multi-architecture build function
build_multiarch() {
    local target="$1"
    local tag="$2"
    
    log_info "Building multi-architecture $target image with tag: $tag"
    
    # Create buildx instance if it doesn't exist
    if ! docker buildx inspect tmws-builder > /dev/null 2>&1; then
        docker buildx create --name tmws-builder --use
    fi
    
    docker buildx build \
        --target "$target" \
        --platform linux/amd64,linux/arm64 \
        --tag "$IMAGE_NAME:$tag" \
        --cache-from type=gha \
        --cache-to type=gha,mode=max \
        --push \
        "$PROJECT_DIR"
    
    log_success "Successfully built and pushed multi-arch $IMAGE_NAME:$tag"
}

# Security scan function
security_scan() {
    local image="$1"
    
    log_info "Running security scan on $image"
    
    # Check if trivy is available
    if command -v trivy &> /dev/null; then
        trivy image "$image"
    else
        log_warning "Trivy not found, skipping security scan"
        log_info "Install trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
    fi
}

# Size optimization check
check_image_size() {
    local image="$1"
    local max_size_mb="$2"
    
    log_info "Checking image size for $image"
    
    local size_bytes=$(docker inspect "$image" --format='{{.Size}}')
    local size_mb=$((size_bytes / 1024 / 1024))
    
    log_info "Image size: ${size_mb}MB"
    
    if [ "$size_mb" -gt "$max_size_mb" ]; then
        log_error "Image size ${size_mb}MB exceeds maximum ${max_size_mb}MB"
        exit 1
    else
        log_success "Image size ${size_mb}MB is within limit (${max_size_mb}MB)"
    fi
}

# Main build process
main() {
    local environment="${1:-development}"
    local push="${2:-false}"
    local multiarch="${3:-false}"
    
    cd "$PROJECT_DIR"
    
    log_info "Starting TMWS build process"
    log_info "Environment: $environment"
    log_info "Push: $push"
    log_info "Multi-arch: $multiarch"
    
    # Get version from VERSION file
    local version="latest"
    if [ -f "VERSION" ]; then
        version=$(cat VERSION | tr -d '[:space:]')
        log_info "Version: $version"
    fi
    
    case "$environment" in
        "development"|"dev")
            if [ "$multiarch" = "true" ]; then
                build_multiarch "development" "dev"
                build_multiarch "development" "dev-$version"
            else
                build_image "development" "dev"
                build_image "development" "dev-$version"
                check_image_size "$IMAGE_NAME:dev" 200  # 200MB limit for dev
            fi
            ;;
        
        "production"|"prod")
            if [ "$multiarch" = "true" ]; then
                build_multiarch "production" "prod"
                build_multiarch "production" "prod-$version"
                build_multiarch "production" "latest"
            else
                build_image "production" "prod"
                build_image "production" "prod-$version"
                build_image "production" "latest"
                check_image_size "$IMAGE_NAME:prod" 100  # 100MB limit for production
                security_scan "$IMAGE_NAME:prod"
            fi
            ;;
        
        "all")
            log_info "Building all targets"
            if [ "$multiarch" = "true" ]; then
                build_multiarch "development" "dev"
                build_multiarch "production" "prod"
                build_multiarch "production" "latest"
            else
                build_image "development" "dev"
                build_image "production" "prod"
                build_image "production" "latest"
                check_image_size "$IMAGE_NAME:dev" 200
                check_image_size "$IMAGE_NAME:prod" 100
                security_scan "$IMAGE_NAME:prod"
            fi
            ;;
        
        *)
            log_error "Unknown environment: $environment"
            log_info "Available environments: development, production, all"
            exit 1
            ;;
    esac
    
    # Push to registry if requested
    if [ "$push" = "true" ] && [ -n "$REGISTRY" ] && [ "$multiarch" != "true" ]; then
        log_info "Pushing images to registry: $REGISTRY"
        
        case "$environment" in
            "development"|"dev")
                docker tag "$IMAGE_NAME:dev" "$REGISTRY/$IMAGE_NAME:dev"
                docker push "$REGISTRY/$IMAGE_NAME:dev"
                ;;
            "production"|"prod")
                docker tag "$IMAGE_NAME:prod" "$REGISTRY/$IMAGE_NAME:prod"
                docker tag "$IMAGE_NAME:latest" "$REGISTRY/$IMAGE_NAME:latest"
                docker push "$REGISTRY/$IMAGE_NAME:prod"
                docker push "$REGISTRY/$IMAGE_NAME:latest"
                ;;
            "all")
                docker tag "$IMAGE_NAME:dev" "$REGISTRY/$IMAGE_NAME:dev"
                docker tag "$IMAGE_NAME:prod" "$REGISTRY/$IMAGE_NAME:prod"
                docker tag "$IMAGE_NAME:latest" "$REGISTRY/$IMAGE_NAME:latest"
                docker push "$REGISTRY/$IMAGE_NAME:dev"
                docker push "$REGISTRY/$IMAGE_NAME:prod"
                docker push "$REGISTRY/$IMAGE_NAME:latest"
                ;;
        esac
        
        log_success "Images pushed to registry"
    fi
    
    log_success "Build process completed successfully"
    
    # Display final image information
    log_info "Built images:"
    docker images | grep "$IMAGE_NAME" | head -10
}

# Help function
show_help() {
    cat << EOF
TMWS Docker Build Script

Usage:
    $0 [ENVIRONMENT] [PUSH] [MULTIARCH]

Arguments:
    ENVIRONMENT  - development|production|all (default: development)
    PUSH         - true|false (default: false)
    MULTIARCH    - true|false (default: false)

Examples:
    $0                           # Build development image
    $0 production               # Build production image
    $0 production true          # Build and push production image
    $0 all true true            # Build all images with multi-arch and push

Environment Variables:
    REGISTRY     - Docker registry URL (for pushing)

EOF
}

# Check arguments
if [ "$#" -gt 0 ] && [ "$1" = "--help" ]; then
    show_help
    exit 0
fi

# Run main function
main "$@"