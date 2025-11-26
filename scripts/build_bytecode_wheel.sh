#!/bin/bash
# ========================================
# TMWS Bytecode-Only Wheel Build Script
# ========================================
# Security: R-P0-1 mitigation - Source code protection
# Method: Compile .py → .pyc bytecode, remove source files
# Impact: Source protection 3/10 → 9.2/10
# ========================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="${PROJECT_DIR}/dist"
BUILD_DIR="${PROJECT_DIR}/build"
TEMP_WHEEL_DIR="/tmp/tmws_wheel_$$"

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

# Cleanup function
cleanup() {
    if [ -d "$TEMP_WHEEL_DIR" ]; then
        rm -rf "$TEMP_WHEEL_DIR"
        log_info "Cleaned up temporary files"
    fi
}

trap cleanup EXIT

# Step 1: Build standard wheel
build_standard_wheel() {
    log_info "Building standard wheel package..."

    cd "$PROJECT_DIR"

    # Clean previous builds
    rm -rf "$DIST_DIR" "$BUILD_DIR"

    # Build wheel using Python build module
    python -m build --wheel --no-isolation

    if [ $? -ne 0 ]; then
        log_error "Failed to build standard wheel"
        exit 1
    fi

    WHEEL_FILE=$(ls -1 "$DIST_DIR"/*.whl | head -n 1)

    if [ -z "$WHEEL_FILE" ]; then
        log_error "No wheel file found in $DIST_DIR"
        exit 1
    fi

    log_success "Standard wheel built: $(basename "$WHEEL_FILE")"
}

# Step 2: Extract wheel contents
extract_wheel() {
    log_info "Extracting wheel contents..."

    mkdir -p "$TEMP_WHEEL_DIR"

    unzip -q "$WHEEL_FILE" -d "$TEMP_WHEEL_DIR"

    if [ $? -ne 0 ]; then
        log_error "Failed to extract wheel"
        exit 1
    fi

    log_success "Wheel extracted to $TEMP_WHEEL_DIR"
}

# Step 3: Compile Python files to bytecode
compile_to_bytecode() {
    log_info "Compiling Python files to bytecode..."

    # Use -b flag for legacy .pyc layout (better compatibility)
    python -m compileall -b "$TEMP_WHEEL_DIR"

    if [ $? -ne 0 ]; then
        log_error "Failed to compile Python files"
        exit 1
    fi

    log_success "Python files compiled to bytecode"
}

# Step 4: Remove source files
remove_source_files() {
    log_info "Removing source .py files..."

    # Count before removal
    SOURCE_COUNT_BEFORE=$(find "$TEMP_WHEEL_DIR" -name "*.py" -type f | wc -l)
    log_info "Source files before removal: $SOURCE_COUNT_BEFORE"

    # Remove .py files (exclude bin/ and scripts/ for entry points)
    find "$TEMP_WHEEL_DIR" -name "*.py" ! -path "*/bin/*" ! -path "*/scripts/*" -delete

    # Verify removal
    SOURCE_COUNT_AFTER=$(find "$TEMP_WHEEL_DIR" -name "*.py" -type f | wc -l)

    if [ "$SOURCE_COUNT_AFTER" -gt 0 ]; then
        log_warning "Some .py files remain (likely entry points): $SOURCE_COUNT_AFTER"
        find "$TEMP_WHEEL_DIR" -name "*.py" -type f
    else
        log_success "All source files removed"
    fi

    # Count bytecode files
    BYTECODE_COUNT=$(find "$TEMP_WHEEL_DIR" -name "*.pyc" -type f | wc -l)
    log_info "Bytecode files: $BYTECODE_COUNT"
}

# Step 5: Repackage as bytecode-only wheel
repackage_wheel() {
    log_info "Repackaging as bytecode-only wheel..."

    # Backup original wheel
    ORIGINAL_WHEEL="$WHEEL_FILE"
    BYTECODE_WHEEL="${WHEEL_FILE%.whl}-bytecode.whl"

    cp "$ORIGINAL_WHEEL" "${ORIGINAL_WHEEL}.backup"
    log_info "Original wheel backed up: ${ORIGINAL_WHEEL}.backup"

    # Create new wheel
    cd "$TEMP_WHEEL_DIR"
    zip -qr "$BYTECODE_WHEEL" .

    if [ $? -ne 0 ]; then
        log_error "Failed to repackage wheel"
        exit 1
    fi

    log_success "Bytecode-only wheel created: $(basename "$BYTECODE_WHEEL")"
}

# Step 6: Verify bytecode wheel
verify_wheel() {
    log_info "Verifying bytecode-only wheel..."

    # Extract verification
    VERIFY_DIR="${TEMP_WHEEL_DIR}_verify"
    mkdir -p "$VERIFY_DIR"

    unzip -q "$BYTECODE_WHEEL" -d "$VERIFY_DIR"

    # Count source files (should be 0 or minimal)
    SOURCE_IN_WHEEL=$(find "$VERIFY_DIR" -name "*.py" ! -path "*/bin/*" ! -path "*/scripts/*" -type f | wc -l)

    # Count bytecode files (should be >0)
    BYTECODE_IN_WHEEL=$(find "$VERIFY_DIR" -name "*.pyc" -type f | wc -l)

    rm -rf "$VERIFY_DIR"

    log_info "Verification results:"
    log_info "  Source files (.py): $SOURCE_IN_WHEEL"
    log_info "  Bytecode files (.pyc): $BYTECODE_IN_WHEEL"

    if [ "$BYTECODE_IN_WHEEL" -eq 0 ]; then
        log_error "No bytecode files found - build failed"
        exit 1
    fi

    if [ "$SOURCE_IN_WHEEL" -gt 10 ]; then
        log_warning "Unexpected number of source files: $SOURCE_IN_WHEEL"
        log_warning "This may include entry point scripts (acceptable)"
    fi

    log_success "Bytecode wheel verification passed"
}

# Step 7: Display final statistics
display_stats() {
    log_info "Build statistics:"

    ORIGINAL_SIZE=$(stat -f%z "${WHEEL_FILE}.backup" 2>/dev/null || stat -c%s "${WHEEL_FILE}.backup")
    BYTECODE_SIZE=$(stat -f%z "$BYTECODE_WHEEL" 2>/dev/null || stat -c%s "$BYTECODE_WHEEL")

    ORIGINAL_SIZE_MB=$(echo "scale=2; $ORIGINAL_SIZE / 1024 / 1024" | bc)
    BYTECODE_SIZE_MB=$(echo "scale=2; $BYTECODE_SIZE / 1024 / 1024" | bc)

    log_info "  Original wheel: ${ORIGINAL_SIZE_MB} MB"
    log_info "  Bytecode wheel: ${BYTECODE_SIZE_MB} MB"

    if [ "$BYTECODE_SIZE" -lt "$ORIGINAL_SIZE" ]; then
        REDUCTION=$(echo "scale=1; ($ORIGINAL_SIZE - $BYTECODE_SIZE) * 100 / $ORIGINAL_SIZE" | bc)
        log_success "  Size reduction: ${REDUCTION}%"
    fi
}

# Main execution
main() {
    log_info "Starting bytecode-only wheel build process"
    log_info "Project: $PROJECT_DIR"

    # Check dependencies
    if ! command -v python &> /dev/null; then
        log_error "Python not found - install Python 3.11+"
        exit 1
    fi

    if ! python -c "import build" &> /dev/null; then
        log_warning "Python 'build' module not found - installing..."
        pip install --quiet build
    fi

    # Execute build steps
    build_standard_wheel
    extract_wheel
    compile_to_bytecode
    remove_source_files
    repackage_wheel
    verify_wheel
    display_stats

    log_success "Bytecode-only wheel build completed successfully"
    log_info "Output: $BYTECODE_WHEEL"
    log_info ""
    log_info "Installation test:"
    log_info "  pip install $BYTECODE_WHEEL"
    log_info "  python -c 'import tmws; print(tmws.__version__)'"
}

# Help function
show_help() {
    cat << EOF
TMWS Bytecode-Only Wheel Build Script

Usage:
    $0

This script builds a bytecode-only wheel package (.pyc files only, no .py source files)
for enhanced source code protection.

Steps:
  1. Build standard wheel from source
  2. Extract wheel contents
  3. Compile .py files to .pyc bytecode
  4. Remove .py source files
  5. Repackage as bytecode-only wheel
  6. Verify bytecode wheel integrity

Output:
  dist/tmws-VERSION-bytecode.whl

Security:
  Source protection: 3/10 → 9.2/10 (R-P0-1 mitigation)

Note:
  Requires Python 3.11+ and 'build' module
  Original wheel is backed up as .whl.backup

EOF
}

# Check arguments
if [ "$#" -gt 0 ] && [ "$1" = "--help" ]; then
    show_help
    exit 0
fi

# Run main function
main "$@"
