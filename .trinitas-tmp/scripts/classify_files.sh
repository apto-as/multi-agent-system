#!/bin/bash
# ============================================================================
# File Classification Script for Platform Separation
# Author: Hera (Strategic Commander)
# Purpose: Classify all files by platform affinity
# Version: 1.0.0
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Platform Separation: File Classifier  ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo ""

# ============================================================================
# Classification Lists
# ============================================================================

# Claude Code Only
CLAUDE_ONLY=(
    ".claude/"
    "install_trinitas_config_v2.2.4.sh"
    "hooks/core/df2_behavior_injector.py"
)

# OpenCode Only
OPENCODE_ONLY=(
    ".opencode/"
    "opencode.json"
    "install_opencode.sh"
    "docs/archive/opencode_migration/"
)

# Shared (needs platform detection)
SHARED=(
    "shared/utils/trinitas_component.py"
    "shared/utils/secure_file_loader.py"
    "shared/security/access_validator.py"
    "shared/security/tool-matrix.json"
    "shared/tools/core_tools.yaml"
)

# Agents (duplicate for both platforms)
AGENTS=(
    "agents/athena-conductor.md"
    "agents/artemis-optimizer.md"
    "agents/hestia-auditor.md"
    "agents/eris-coordinator.md"
    "agents/hera-strategist.md"
    "agents/muses-documenter.md"
)

# Common (stays at root)
COMMON=(
    "README.md"
    "CLAUDE.md"
    "AGENTS.md"
    "LICENSE"
    "VERSION"
    ".gitignore"
    "requirements-dev.txt"
    "requirements-test.txt"
    "pytest.ini"
)

# ============================================================================
# Analysis Functions
# ============================================================================

count_references() {
    local pattern="$1"
    local file="$2"

    if [ -f "$file" ]; then
        grep -o "$pattern" "$file" 2>/dev/null | wc -l | tr -d ' '
    else
        echo "0"
    fi
}

analyze_file() {
    local file="$1"

    if [ ! -f "$file" ]; then
        return
    fi

    local claude_refs=$(count_references '\.claude' "$file")
    local opencode_refs=$(count_references '\.opencode' "$file")

    echo "$file:$claude_refs:$opencode_refs"
}

# ============================================================================
# Main Classification
# ============================================================================

echo -e "${BLUE}[1/5] Analyzing Claude Code files...${NC}"
CLAUDE_TOTAL=0
for item in "${CLAUDE_ONLY[@]}"; do
    if [ -e "$PROJECT_ROOT/$item" ]; then
        CLAUDE_TOTAL=$((CLAUDE_TOTAL + 1))
        echo -e "  ${GREEN}✓${NC} $item"
    else
        echo -e "  ${YELLOW}⚠${NC} $item (not found)"
    fi
done

echo ""
echo -e "${BLUE}[2/5] Analyzing OpenCode files...${NC}"
OPENCODE_TOTAL=0
for item in "${OPENCODE_ONLY[@]}"; do
    if [ -e "$PROJECT_ROOT/$item" ]; then
        OPENCODE_TOTAL=$((OPENCODE_TOTAL + 1))
        echo -e "  ${GREEN}✓${NC} $item"
    else
        echo -e "  ${YELLOW}⚠${NC} $item (not found)"
    fi
done

echo ""
echo -e "${BLUE}[3/5] Analyzing Shared files...${NC}"
SHARED_TOTAL=0
for item in "${SHARED[@]}"; do
    if [ -e "$PROJECT_ROOT/$item" ]; then
        SHARED_TOTAL=$((SHARED_TOTAL + 1))

        # Analyze platform references
        result=$(analyze_file "$PROJECT_ROOT/$item")
        claude_refs=$(echo "$result" | cut -d':' -f2)
        opencode_refs=$(echo "$result" | cut -d':' -f3)

        if [ "$claude_refs" -gt 0 ] && [ "$opencode_refs" -gt 0 ]; then
            echo -e "  ${YELLOW}⚠${NC} $item (MIXED: $claude_refs claude, $opencode_refs opencode)"
        elif [ "$claude_refs" -gt 0 ]; then
            echo -e "  ${CYAN}→${NC} $item (leans Claude: $claude_refs refs)"
        elif [ "$opencode_refs" -gt 0 ]; then
            echo -e "  ${CYAN}→${NC} $item (leans OpenCode: $opencode_refs refs)"
        else
            echo -e "  ${GREEN}✓${NC} $item (platform-agnostic)"
        fi
    else
        echo -e "  ${RED}✗${NC} $item (not found)"
    fi
done

echo ""
echo -e "${BLUE}[4/5] Analyzing Agents...${NC}"
AGENTS_TOTAL=0
for item in "${AGENTS[@]}"; do
    if [ -e "$PROJECT_ROOT/$item" ]; then
        AGENTS_TOTAL=$((AGENTS_TOTAL + 1))
        echo -e "  ${GREEN}✓${NC} $item (needs duplication)"
    else
        echo -e "  ${RED}✗${NC} $item (not found)"
    fi
done

echo ""
echo -e "${BLUE}[5/5] Analyzing Common files...${NC}"
COMMON_TOTAL=0
for item in "${COMMON[@]}"; do
    if [ -e "$PROJECT_ROOT/$item" ]; then
        COMMON_TOTAL=$((COMMON_TOTAL + 1))
        echo -e "  ${GREEN}✓${NC} $item"
    else
        echo -e "  ${YELLOW}⚠${NC} $item (optional)"
    fi
done

# ============================================================================
# Conflict Detection
# ============================================================================

echo ""
echo -e "${BLUE}[Conflict Detection] Searching for problematic patterns...${NC}"

# Conflict 1: DEFAULT_CONFIG_DIR
echo -e "${YELLOW}Conflict 1: DEFAULT_CONFIG_DIR inconsistency${NC}"
grep -rn "DEFAULT_CONFIG_DIR\s*=" \
    "$PROJECT_ROOT/hooks" \
    "$PROJECT_ROOT/shared" \
    2>/dev/null | while read -r line; do
    echo "  - $line"
done

echo ""

# Conflict 2: Security policy contradictions
echo -e "${YELLOW}Conflict 2: .claude in security policies${NC}"
grep -rn "\.claude" \
    "$PROJECT_ROOT/shared/security" \
    2>/dev/null | while read -r line; do
    echo "  - $line"
done

echo ""

# Conflict 3: Both platforms in same file
echo -e "${YELLOW}Conflict 3: Files with both .claude and .opencode${NC}"
find "$PROJECT_ROOT" -type f \
    \( -name "*.py" -o -name "*.sh" -o -name "*.json" \) \
    -not -path "*/.*" \
    -not -path "*/docs/*" \
    -not -path "*/tests/*" \
    -exec grep -l "\.claude" {} \; | while read -r file; do
    if grep -q "\.opencode" "$file"; then
        echo -e "  ${RED}✗${NC} $file (BOTH platforms)"
    fi
done

# ============================================================================
# Summary Report
# ============================================================================

echo ""
echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           Classification Summary       ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo ""

TOTAL_FILES=$((CLAUDE_TOTAL + OPENCODE_TOTAL + SHARED_TOTAL + AGENTS_TOTAL + COMMON_TOTAL))

echo -e "${GREEN}Claude Code Only:${NC}    $CLAUDE_TOTAL files"
echo -e "${BLUE}OpenCode Only:${NC}       $OPENCODE_TOTAL files"
echo -e "${YELLOW}Shared (refactor):${NC}   $SHARED_TOTAL files"
echo -e "${CYAN}Agents (duplicate):${NC}  $AGENTS_TOTAL files"
echo -e "${NC}Common (root):${NC}       $COMMON_TOTAL files"
echo ""
echo -e "${MAGENTA}Total Classified:${NC}    $TOTAL_FILES files"

# ============================================================================
# Migration Recommendations
# ============================================================================

echo ""
echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║      Migration Recommendations         ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo ""

echo -e "${GREEN}Next Steps:${NC}"
echo "  1. Review conflicts above (especially DEFAULT_CONFIG_DIR)"
echo "  2. Run migration script in dry-run mode:"
echo -e "     ${YELLOW}./scripts/migrate_to_separated.sh --dry-run${NC}"
echo "  3. Create platform detection utility:"
echo -e "     ${YELLOW}shared/utils/platform_detector.py${NC}"
echo "  4. Execute migration:"
echo -e "     ${YELLOW}./scripts/migrate_to_separated.sh --execute${NC}"
echo ""

echo -e "${YELLOW}Critical Conflicts to Resolve:${NC}"
echo "  • DEFAULT_CONFIG_DIR: df2_behavior_injector.py vs trinitas_component.py"
echo "  • Security: .claude in both block and allow lists"
echo "  • Installers: 2 competing scripts at root level"
echo ""

echo -e "${GREEN}✓ Classification complete!${NC}"
echo -e "${BLUE}See: PLATFORM_SEPARATION_STRATEGY.md for full plan${NC}"
