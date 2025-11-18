#!/bin/bash
# Trinitas Quality Guardian - Default Settings
# Optimal defaults for immediate productivity

# ====================================
# Core Configuration
# ====================================

# Guardian activation (true by default)
export TRINITAS_GUARD_ENABLED="${TRINITAS_GUARD_ENABLED:-true}"

# Default mode: warn (non-intrusive but informative)
# Options: warn, block, fix
export TRINITAS_GUARD_MODE="${TRINITAS_GUARD_MODE:-warn}"

# ====================================
# Mode Progression Strategy
# ====================================
# Recommended progression for new users:
# Week 1-2: warn mode (learn what quality issues exist)
# Week 3-4: fix mode (auto-fix issues to learn patterns)
# Week 5+:  block mode (enforce quality standards)

# Auto-progression (optional feature)
export TRINITAS_GUARD_AUTO_PROGRESS="${TRINITAS_GUARD_AUTO_PROGRESS:-false}"
export TRINITAS_GUARD_PROGRESS_DAYS="${TRINITAS_GUARD_PROGRESS_DAYS:-14}"

# ====================================
# Language-specific Settings
# ====================================

# Python
export TRINITAS_GUARD_PYTHON_ENABLED="${TRINITAS_GUARD_PYTHON_ENABLED:-true}"
export TRINITAS_GUARD_PYTHON_TOOLS="${TRINITAS_GUARD_PYTHON_TOOLS:-ruff}"

# JavaScript/TypeScript
export TRINITAS_GUARD_JS_ENABLED="${TRINITAS_GUARD_JS_ENABLED:-true}"
export TRINITAS_GUARD_JS_TOOLS="${TRINITAS_GUARD_JS_TOOLS:-eslint,prettier}"

# Go
export TRINITAS_GUARD_GO_ENABLED="${TRINITAS_GUARD_GO_ENABLED:-true}"
export TRINITAS_GUARD_GO_TOOLS="${TRINITAS_GUARD_GO_TOOLS:-golangci-lint,gofmt}"

# Rust
export TRINITAS_GUARD_RUST_ENABLED="${TRINITAS_GUARD_RUST_ENABLED:-true}"
export TRINITAS_GUARD_RUST_TOOLS="${TRINITAS_GUARD_RUST_TOOLS:-rustfmt,clippy}"

# ====================================
# Performance Settings
# ====================================

# Skip checks for small changes (lines changed)
export TRINITAS_GUARD_MIN_CHANGES="${TRINITAS_GUARD_MIN_CHANGES:-1}"

# Timeout for quality checks (seconds)
export TRINITAS_GUARD_TIMEOUT="${TRINITAS_GUARD_TIMEOUT:-30}"

# Parallel execution for multi-file checks
export TRINITAS_GUARD_PARALLEL="${TRINITAS_GUARD_PARALLEL:-true}"

# ====================================
# Notification Settings
# ====================================

# Show tips and suggestions
export TRINITAS_GUARD_SHOW_TIPS="${TRINITAS_GUARD_SHOW_TIPS:-true}"

# Verbosity level (0=quiet, 1=normal, 2=verbose)
export TRINITAS_GUARD_VERBOSITY="${TRINITAS_GUARD_VERBOSITY:-1}"

# Show emoji in output
export TRINITAS_GUARD_USE_EMOJI="${TRINITAS_GUARD_USE_EMOJI:-true}"

# ====================================
# Integration Settings
# ====================================

# Git integration
export TRINITAS_GUARD_GIT_HOOKS="${TRINITAS_GUARD_GIT_HOOKS:-true}"

# CI/CD detection (auto-adjust behavior in CI environments)
export TRINITAS_GUARD_CI_MODE="${TRINITAS_GUARD_CI_MODE:-auto}"

# IDE integration hints
export TRINITAS_GUARD_IDE_HINTS="${TRINITAS_GUARD_IDE_HINTS:-true}"

# ====================================
# Helper Functions
# ====================================

# Get current mode based on installation age
get_progressive_mode() {
    if [ "$TRINITAS_GUARD_AUTO_PROGRESS" != "true" ]; then
        echo "$TRINITAS_GUARD_MODE"
        return
    fi

    local install_date_file="$HOME/.claude/guard/.install_date"
    if [ ! -f "$install_date_file" ]; then
        date +%s > "$install_date_file"
        echo "warn"
        return
    fi

    local install_date=$(cat "$install_date_file")
    local current_date=$(date +%s)
    local days_elapsed=$(( (current_date - install_date) / 86400 ))

    if [ $days_elapsed -lt $TRINITAS_GUARD_PROGRESS_DAYS ]; then
        echo "warn"
    elif [ $days_elapsed -lt $((TRINITAS_GUARD_PROGRESS_DAYS * 2)) ]; then
        echo "fix"
    else
        echo "block"
    fi
}

# Check if running in CI environment
is_ci_environment() {
    if [ -n "$CI" ] || [ -n "$CONTINUOUS_INTEGRATION" ] || \
       [ -n "$GITHUB_ACTIONS" ] || [ -n "$GITLAB_CI" ] || \
       [ -n "$JENKINS_URL" ] || [ -n "$CIRCLECI" ]; then
        return 0
    fi
    return 1
}

# Adjust settings for CI
if is_ci_environment && [ "$TRINITAS_GUARD_CI_MODE" = "auto" ]; then
    export TRINITAS_GUARD_MODE="block"  # Strict in CI
    export TRINITAS_GUARD_VERBOSITY="2"  # Verbose output
    export TRINITAS_GUARD_USE_EMOJI="false"  # No emoji in CI logs
    export TRINITAS_GUARD_SHOW_TIPS="false"  # No tips in CI
fi

# Export the progressive mode function
export -f get_progressive_mode
export -f is_ci_environment