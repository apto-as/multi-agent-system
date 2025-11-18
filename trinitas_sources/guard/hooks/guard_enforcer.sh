#!/bin/bash
# Trinitas Quality Guardian - Enforcement Mechanism
# Automatically runs quality checks on common developer commands

# Source the detector and default settings
GUARD_DIR="$(dirname "${BASH_SOURCE[0]}")/.."
source "${GUARD_DIR}/core/detector.sh"

# Load default settings if exists
if [ -f "${GUARD_DIR}/config/default_settings.sh" ]; then
    source "${GUARD_DIR}/config/default_settings.sh"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration (loaded from default_settings.sh or environment)
# These are now set by default_settings.sh but can be overridden
TRINITAS_GUARD_ENABLED="${TRINITAS_GUARD_ENABLED:-true}"
TRINITAS_GUARD_MODE="${TRINITAS_GUARD_MODE:-warn}"  # warn, block, fix

# Use progressive mode if enabled
if type get_progressive_mode &>/dev/null; then
    TRINITAS_GUARD_MODE="$(get_progressive_mode)"
fi

# Check if guard should run
should_run_guard() {
    [ "$TRINITAS_GUARD_ENABLED" = "true" ] || [ "$TRINITAS_GUARD_ENABLED" = "1" ]
}

# Run language-specific quality checks
run_quality_checks() {
    local language="$1"
    local mode="${2:-$TRINITAS_GUARD_MODE}"
    local result=0

    echo -e "${CYAN}🛡️ Trinitas Quality Guardian Active${NC}"
    echo -e "${BLUE}Detected language: ${WHITE}$language${NC}"

    case "$language" in
        python)
            echo -e "${PURPLE}🏹 Artemis: Running Python quality checks...${NC}"
            if command -v ruff &> /dev/null; then
                if [ "$mode" = "fix" ]; then
                    ruff format . && ruff check . --fix
                else
                    ruff format --check . && ruff check .
                fi
                result=$?
            else
                echo -e "${YELLOW}⚠️  Ruff not installed. Install with: pip install ruff${NC}"
                result=1
            fi
            ;;

        javascript|typescript)
            echo -e "${PURPLE}🏹 Artemis: Running JavaScript/TypeScript quality checks...${NC}"
            if [ -f "package.json" ]; then
                if command -v npm &> /dev/null; then
                    if [ "$mode" = "fix" ]; then
                        npm run lint:fix 2>/dev/null || npx eslint . --fix
                    else
                        npm run lint 2>/dev/null || npx eslint .
                    fi
                    result=$?
                else
                    echo -e "${YELLOW}⚠️  npm not found${NC}"
                    result=1
                fi
            fi
            ;;

        go)
            echo -e "${PURPLE}🏹 Artemis: Running Go quality checks...${NC}"
            if command -v golangci-lint &> /dev/null; then
                if [ "$mode" = "fix" ]; then
                    go fmt ./... && golangci-lint run --fix
                else
                    golangci-lint run
                fi
                result=$?
            elif command -v go &> /dev/null; then
                go fmt ./... && go vet ./...
                result=$?
            else
                echo -e "${YELLOW}⚠️  Go tools not found${NC}"
                result=1
            fi
            ;;

        rust)
            echo -e "${PURPLE}🏹 Artemis: Running Rust quality checks...${NC}"
            if command -v cargo &> /dev/null; then
                if [ "$mode" = "fix" ]; then
                    cargo fmt && cargo clippy --fix --allow-dirty
                else
                    cargo fmt --check && cargo clippy -- -D warnings
                fi
                result=$?
            else
                echo -e "${YELLOW}⚠️  Cargo not found${NC}"
                result=1
            fi
            ;;

        *)
            echo -e "${YELLOW}⚠️  No quality checks available for: $language${NC}"
            return 0
            ;;
    esac

    if [ $result -eq 0 ]; then
        echo -e "${GREEN}✅ Quality checks passed!${NC}"
    else
        echo -e "${RED}❌ Quality issues detected${NC}"

        if [ "$mode" = "block" ]; then
            echo -e "${RED}Blocking operation due to quality issues${NC}"
            echo -e "${CYAN}Tip: Set TRINITAS_GUARD_MODE=fix to auto-fix issues${NC}"
            return 1
        elif [ "$mode" = "warn" ]; then
            echo -e "${YELLOW}⚠️  Continuing despite quality issues (warning mode)${NC}"
            echo -e "${CYAN}Tip: Set TRINITAS_GUARD_MODE=block to enforce quality${NC}"
        fi
    fi

    return 0
}

# Enhanced cd function
cd() {
    builtin cd "$@"
    local result=$?

    if [ $result -eq 0 ] && should_run_guard; then
        local language=$(get_primary_language ".")
        if is_language_supported "$language" 2>/dev/null; then
            echo -e "\n${CYAN}📁 Entered project directory with ${WHITE}$language${CYAN} code${NC}"
            echo -e "${BLUE}Quality Guardian is monitoring this project${NC}"
            echo -e "${YELLOW}Tip: Run 'trinitas-guard check' for full quality report${NC}\n"
        fi
    fi

    return $result
}

# Pre-commit wrapper
git() {
    if [ "$1" = "commit" ] && should_run_guard; then
        local language=$(get_primary_language ".")
        if is_language_supported "$language" 2>/dev/null; then
            echo -e "\n${CYAN}🔍 Pre-commit quality check...${NC}"

            if ! run_quality_checks "$language"; then
                if [ "$TRINITAS_GUARD_MODE" = "block" ]; then
                    echo -e "${RED}Commit blocked due to quality issues${NC}"
                    return 1
                fi
            fi
        fi
    fi

    command git "$@"
}

# npm/yarn wrapper for JavaScript projects
npm() {
    local cmd="$1"

    if should_run_guard && [[ "$cmd" =~ ^(run|build|start|test)$ ]]; then
        local language=$(get_primary_language ".")
        if [ "$language" = "javascript" ] || [ "$language" = "typescript" ]; then
            echo -e "\n${CYAN}🔍 Pre-execution quality check...${NC}"

            if ! run_quality_checks "$language"; then
                if [ "$TRINITAS_GUARD_MODE" = "block" ]; then
                    echo -e "${RED}Execution blocked due to quality issues${NC}"
                    return 1
                fi
            fi
        fi
    fi

    command npm "$@"
}

# cargo wrapper for Rust projects
cargo() {
    local cmd="$1"

    if should_run_guard && [[ "$cmd" =~ ^(build|run|test)$ ]]; then
        echo -e "\n${CYAN}🔍 Pre-build quality check...${NC}"

        if ! run_quality_checks "rust"; then
            if [ "$TRINITAS_GUARD_MODE" = "block" ]; then
                echo -e "${RED}Build blocked due to quality issues${NC}"
                return 1
            fi
        fi
    fi

    command cargo "$@"
}

# go wrapper for Go projects
go() {
    local cmd="$1"

    if should_run_guard && [[ "$cmd" =~ ^(build|run|test)$ ]]; then
        echo -e "\n${CYAN}🔍 Pre-build quality check...${NC}"

        if ! run_quality_checks "go"; then
            if [ "$TRINITAS_GUARD_MODE" = "block" ]; then
                echo -e "${RED}Build blocked due to quality issues${NC}"
                return 1
            fi
        fi
    fi

    command go "$@"
}

# Manual quality check command
trinitas-guard() {
    case "${1:-help}" in
        check)
            local language=$(get_primary_language ".")
            if is_language_supported "$language" 2>/dev/null; then
                run_quality_checks "$language" "warn"
            else
                echo -e "${YELLOW}⚠️  Unsupported or unknown project type${NC}"
                echo -e "${BLUE}Detected: $language${NC}"
            fi
            ;;

        fix)
            local language=$(get_primary_language ".")
            if is_language_supported "$language" 2>/dev/null; then
                run_quality_checks "$language" "fix"
            else
                echo -e "${YELLOW}⚠️  Cannot auto-fix: unsupported project type${NC}"
            fi
            ;;

        disable)
            export TRINITAS_GUARD_ENABLED=false
            echo -e "${YELLOW}⚠️  Quality Guardian disabled for this session${NC}"
            ;;

        enable)
            export TRINITAS_GUARD_ENABLED=true
            echo -e "${GREEN}✅ Quality Guardian enabled${NC}"
            ;;

        mode)
            if [ -n "$2" ]; then
                export TRINITAS_GUARD_MODE="$2"
                echo -e "${GREEN}✅ Guardian mode set to: $2${NC}"
            else
                echo -e "${BLUE}Current mode: $TRINITAS_GUARD_MODE${NC}"
                echo -e "${CYAN}Available modes: warn, block, fix${NC}"
            fi
            ;;

        status)
            echo -e "${CYAN}🛡️ Trinitas Quality Guardian Status${NC}"
            echo -e "${BLUE}Enabled: ${WHITE}$TRINITAS_GUARD_ENABLED${NC}"
            echo -e "${BLUE}Mode: ${WHITE}$TRINITAS_GUARD_MODE${NC}"

            local language=$(get_primary_language ".")
            echo -e "${BLUE}Current project: ${WHITE}$language${NC}"

            if is_language_supported "$language" 2>/dev/null; then
                echo -e "${GREEN}✅ Project supported${NC}"
            else
                echo -e "${YELLOW}⚠️  Project not supported${NC}"
            fi
            ;;

        *)
            echo -e "${CYAN}Trinitas Quality Guardian - Usage${NC}"
            echo -e "${WHITE}Commands:${NC}"
            echo -e "  ${GREEN}check${NC}     - Run quality checks"
            echo -e "  ${GREEN}fix${NC}       - Auto-fix quality issues"
            echo -e "  ${GREEN}enable${NC}    - Enable guardian"
            echo -e "  ${GREEN}disable${NC}   - Disable guardian"
            echo -e "  ${GREEN}mode${NC} <m>  - Set mode (warn/block/fix)"
            echo -e "  ${GREEN}status${NC}    - Show current status"
            echo -e ""
            echo -e "${WHITE}Environment variables:${NC}"
            echo -e "  ${BLUE}TRINITAS_GUARD_ENABLED${NC} - Enable/disable (true/false)"
            echo -e "  ${BLUE}TRINITAS_GUARD_MODE${NC}    - Set mode (warn/block/fix)"
            ;;
    esac
}

# Export functions
export -f cd
export -f git
export -f npm
export -f cargo
export -f go
export -f trinitas-guard