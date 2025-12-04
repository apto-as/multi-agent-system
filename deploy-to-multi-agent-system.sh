#!/bin/bash
# deploy-to-multi-agent-system.sh
# TMWS の更新内容を multi-agent-system 配布リポジトリへデプロイするスクリプト
#
# ARCHITECTURE (正しいデプロイフロー):
#   dist-config/ (SSoT: Single Source of Truth)
#       ↓ (this script)
#   multi-agent-system/ (配布用リポジトリ)
#       ↓ (user runs install.sh)
#   ~/.claude/ or ~/.config/opencode/ (ユーザー本番環境)
#
# IMPORTANT: 本番環境 (~/.claude/) からコピーしてはいけません。
#            dist-config/ がすべての設定ファイルの正規ソースです。
#
# Version: 2.4.12
# Last Updated: 2025-12-03

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMWS_DIR="${SCRIPT_DIR}"
MULTI_AGENT_DIR="/Users/apto-as/workspace/github.com/apto-as/multi-agent-system"

# SSoT: Single Source of Truth for distribution configs
DIST_CONFIG_DIR="${TMWS_DIR}/dist-config"

log_step() {
    echo -e "${BLUE}==>${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

print_banner() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║     TMWS → Multi-Agent-System Deploy Script v2.4.12              ║"
    echo "║     Trinitas Memory & Workflow System                            ║"
    echo "║                                                                  ║"
    echo "║     Source: dist-config/ (SSoT)                                  ║"
    echo "║     Target: multi-agent-system/                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
}

check_prerequisites() {
    log_step "Checking prerequisites..."

    # Check dist-config directory (SSoT)
    if [ ! -d "${DIST_CONFIG_DIR}" ]; then
        log_error "dist-config directory not found: ${DIST_CONFIG_DIR}"
        log_error "This is the Single Source of Truth for distribution configs."
        log_error "Please create it first or run: cp -r ~/.claude dist-config/claudecode"
        exit 1
    fi

    # Check dist-config/claudecode
    if [ ! -d "${DIST_CONFIG_DIR}/claudecode" ]; then
        log_error "dist-config/claudecode not found"
        exit 1
    fi

    # Check dist-config/opencode
    if [ ! -d "${DIST_CONFIG_DIR}/opencode" ]; then
        log_error "dist-config/opencode not found"
        exit 1
    fi

    # Check multi-agent-system directory
    if [ ! -d "${MULTI_AGENT_DIR}" ]; then
        log_error "multi-agent-system directory not found: ${MULTI_AGENT_DIR}"
        exit 1
    fi

    log_success "Prerequisites check passed"
    log_success "SSoT: ${DIST_CONFIG_DIR}"
}

deploy_claudecode_files() {
    log_step "Deploying Claude Code files from dist-config/claudecode..."

    local src_dir="${DIST_CONFIG_DIR}/claudecode"
    local dest_dir="${MULTI_AGENT_DIR}/claudecode"

    # Create destination directory if not exists
    mkdir -p "${dest_dir}"

    # Sync claudecode directory (excluding __pycache__ and .pyc files)
    rsync -av --delete \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        --exclude='.DS_Store' \
        "${src_dir}/" "${dest_dir}/"

    log_success "Claude Code files deployed"
}

deploy_opencode_files() {
    log_step "Deploying OpenCode files from dist-config/opencode..."

    local src_dir="${DIST_CONFIG_DIR}/opencode"
    local dest_dir="${MULTI_AGENT_DIR}/opencode"

    # Create destination directory if not exists
    mkdir -p "${dest_dir}"

    # Sync opencode directory
    rsync -av --delete \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        --exclude='.DS_Store' \
        "${src_dir}/" "${dest_dir}/"

    log_success "OpenCode files deployed"
}

deploy_license_files() {
    log_step "Deploying license files..."

    local dest_dir="${MULTI_AGENT_DIR}"

    # Copy license.json (90-day trial)
    if [ -f "${TMWS_DIR}/license.json" ]; then
        cp "${TMWS_DIR}/license.json" "${dest_dir}/"
        log_success "Copied license.json"
    fi

    # Note: Dockerfile and docker-compose.yml are NOT copied
    # Docker images are built and pushed via GitHub Actions in tmws repo
    # install.sh pulls images from ghcr.io/apto-as/tmws
}

show_diff_summary() {
    log_step "Checking changes in multi-agent-system..."

    cd "${MULTI_AGENT_DIR}"

    if git diff --quiet 2>/dev/null; then
        log_warning "No changes detected"
    else
        echo ""
        echo "Changed files:"
        git status --short
        echo ""
    fi
}

print_next_steps() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  Deployment Complete!"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    echo "Next steps:"
    echo "  1. cd ${MULTI_AGENT_DIR}"
    echo "  2. Review changes: git diff"
    echo "  3. Commit changes: git add . && git commit -m 'chore: update from TMWS v2.4.12'"
    echo "  4. Push changes: git push origin main"
    echo ""
    echo "To update dist-config/ (SSoT) in the future:"
    echo "  - Edit files directly in: ${DIST_CONFIG_DIR}/"
    echo "  - Then run this script to deploy"
    echo ""
    echo "WARNING: Do NOT copy from ~/.claude/ to dist-config/"
    echo "         dist-config/ is the canonical source."
    echo ""
}

# Main execution
main() {
    print_banner
    check_prerequisites
    deploy_claudecode_files
    deploy_opencode_files
    deploy_license_files
    show_diff_summary
    print_next_steps
}

# Run
main "$@"
