#!/bin/bash
# Trinitas Quality Guardian - Language Detector
# Detects programming language of current project

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Detect project language(s)
detect_languages() {
    local project_dir="${1:-.}"
    local detected_languages=()

    # Python detection
    if [ -f "$project_dir/pyproject.toml" ] || \
       [ -f "$project_dir/setup.py" ] || \
       [ -f "$project_dir/requirements.txt" ] || \
       [ -f "$project_dir/Pipfile" ]; then
        detected_languages+=("python")
    fi

    # JavaScript/TypeScript detection
    if [ -f "$project_dir/package.json" ]; then
        detected_languages+=("javascript")

        # Check for TypeScript
        if [ -f "$project_dir/tsconfig.json" ] || \
           grep -q '"typescript"' "$project_dir/package.json" 2>/dev/null; then
            detected_languages+=("typescript")
        fi
    fi

    # Go detection
    if [ -f "$project_dir/go.mod" ] || \
       [ -f "$project_dir/go.sum" ]; then
        detected_languages+=("go")
    fi

    # Rust detection
    if [ -f "$project_dir/Cargo.toml" ] || \
       [ -f "$project_dir/Cargo.lock" ]; then
        detected_languages+=("rust")
    fi

    # Ruby detection
    if [ -f "$project_dir/Gemfile" ] || \
       [ -f "$project_dir/Rakefile" ]; then
        detected_languages+=("ruby")
    fi

    # Java/Kotlin detection
    if [ -f "$project_dir/pom.xml" ] || \
       [ -f "$project_dir/build.gradle" ] || \
       [ -f "$project_dir/build.gradle.kts" ]; then
        detected_languages+=("java")

        if [ -f "$project_dir/build.gradle.kts" ] || \
           find "$project_dir" -name "*.kt" -o -name "*.kts" 2>/dev/null | head -1 | grep -q .; then
            detected_languages+=("kotlin")
        fi
    fi

    # Output detected languages
    if [ ${#detected_languages[@]} -eq 0 ]; then
        echo "unknown"
    else
        printf "%s\n" "${detected_languages[@]}" | sort | uniq
    fi
}

# Get primary language (most dominant)
get_primary_language() {
    local project_dir="${1:-.}"
    local languages=($(detect_languages "$project_dir"))

    if [ ${#languages[@]} -eq 0 ] || [ "${languages[0]}" = "unknown" ]; then
        echo "unknown"
        return
    fi

    # Priority order for primary language
    local priority_order=("typescript" "javascript" "python" "go" "rust" "java" "kotlin" "ruby")

    for lang in "${priority_order[@]}"; do
        for detected in "${languages[@]}"; do
            if [ "$lang" = "$detected" ]; then
                echo "$lang"
                return
            fi
        done
    done

    # Default to first detected
    echo "${languages[0]}"
}

# Check if language is supported by Quality Guardian
is_language_supported() {
    local language="$1"
    local supported_languages=("python" "javascript" "typescript" "go" "rust")

    for supported in "${supported_languages[@]}"; do
        if [ "$language" = "$supported" ]; then
            return 0
        fi
    done

    return 1
}

# Main execution
if [ "${1:-}" = "--primary" ]; then
    get_primary_language "${2:-.}"
elif [ "${1:-}" = "--check" ]; then
    language="${2:-}"
    if is_language_supported "$language"; then
        echo "supported"
        exit 0
    else
        echo "unsupported"
        exit 1
    fi
else
    detect_languages "${1:-.}"
fi