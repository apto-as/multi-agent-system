#!/bin/bash
# Trinitas v2.2.0 Installation Verification Script
# 完全なインストール確認と診断レポート生成

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# Results array
declare -a CHECK_RESULTS

# Banner
show_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════╗"
    echo "║     Trinitas v2.2.0 Installation Check     ║"
    echo "║         Comprehensive Verification         ║"
    echo "╚════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "User: $USER"
    echo "Home: $HOME"
    echo ""
}

# Check function
check() {
    local description="$1"
    local command="$2"
    local expected="$3"
    local severity="${4:-error}"  # error, warning, info

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    echo -n -e "${BLUE}Checking:${NC} $description... "

    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        CHECK_RESULTS+=("✓ $description")
        return 0
    else
        if [ "$severity" = "warning" ]; then
            echo -e "${YELLOW}⚠ WARNING${NC}"
            WARNING_CHECKS=$((WARNING_CHECKS + 1))
            CHECK_RESULTS+=("⚠ $description (optional)")
            return 1
        else
            echo -e "${RED}✗ FAIL${NC}"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
            CHECK_RESULTS+=("✗ $description")
            return 1
        fi
    fi
}

# Section header
section() {
    echo ""
    echo -e "${PURPLE}━━━ $1 ━━━${NC}"
}

# 1. Core Files Check
check_core_files() {
    section "Core Configuration Files"

    check "~/.claude/ directory exists" \
          "[ -d '$HOME/.claude' ]"

    check "CLAUDE.md installed" \
          "[ -f '$HOME/.claude/CLAUDE.md' ]"

    check "AGENTS.md installed" \
          "[ -f '$HOME/.claude/AGENTS.md' ]"

    # File size check
    if [ -f "$HOME/.claude/CLAUDE.md" ]; then
        local size_kb=$(( $(stat -f%z "$HOME/.claude/CLAUDE.md" 2>/dev/null || stat -c%s "$HOME/.claude/CLAUDE.md" 2>/dev/null || echo 0) / 1024 ))
        echo -e "${CYAN}  └─ CLAUDE.md size: ${WHITE}${size_kb}KB${NC}"

        if [ $size_kb -le 5 ]; then
            echo -e "${GREEN}     Excellent: Optimized for fast loading${NC}"
        elif [ $size_kb -le 10 ]; then
            echo -e "${YELLOW}     Good: Acceptable size${NC}"
        else
            echo -e "${YELLOW}     Large: May affect loading speed${NC}"
        fi
    fi
}

# 2. Agent Files Check
check_agent_files() {
    section "Trinitas Agent Definitions"

    local agents=(
        "athena-conductor.md"
        "artemis-optimizer.md"
        "hestia-auditor.md"
        "eris-coordinator.md"
        "hera-strategist.md"
        "muses-documenter.md"
    )

    for agent in "${agents[@]}"; do
        check "Agent: $agent" \
              "[ -f '$HOME/.claude/agents/$agent' ]"
    done
}

# 3. Quality Guardian Check
check_quality_guardian() {
    section "Quality Guardian Framework"

    check "Guardian directory installed" \
          "[ -d '$HOME/.claude/guard' ]" \
          "" "warning"

    if [ -d "$HOME/.claude/guard" ]; then
        check "Guardian command script" \
              "[ -f '$HOME/.claude/guard/scripts/guard_command.sh' ]" \
              "" "warning"

        check "Language detector" \
              "[ -f '$HOME/.claude/guard/core/detector.sh' ]" \
              "" "warning"

        check "Enforcer hook" \
              "[ -f '$HOME/.claude/guard/hooks/guard_enforcer.sh' ]" \
              "" "warning"

        # Check trinitas-guard command
        check "trinitas-guard command available" \
              "[ -L '$HOME/.local/bin/trinitas-guard' ] || [ -f '$HOME/.local/bin/trinitas-guard' ]" \
              "" "warning"

        # Check if enforcer is loaded in shell
        if grep -q "guard_enforcer.sh" "$HOME/.bashrc" 2>/dev/null || \
           grep -q "guard_enforcer.sh" "$HOME/.zshrc" 2>/dev/null; then
            echo -e "${GREEN}  ✓ Enforcer integrated in shell${NC}"
        else
            echo -e "${YELLOW}  ⚠ Enforcer not integrated (use --enforce to enable)${NC}"
        fi
    else
        echo -e "${YELLOW}  ⚠ Quality Guardian not installed${NC}"
        echo -e "${CYAN}  💡 Install with: ./install_trinitas_config.sh${NC}"
    fi
}

# 4. Hook Settings Check
check_hook_settings() {
    section "Hook Configuration"

    check "Project .claude/settings.json" \
          "[ -f '$(pwd)/.claude/settings.json' ]" \
          "" "warning"

    if [ -f "$(pwd)/.claude/settings.json" ]; then
        if grep -q "protocol_injector.py" "$(pwd)/.claude/settings.json" 2>/dev/null; then
            echo -e "${GREEN}  ✓ Hook properly configured${NC}"
        else
            echo -e "${YELLOW}  ⚠ Hook configuration may be incomplete${NC}"
        fi
    fi
}

# 5. Language Tools Check
check_language_tools() {
    section "Development Tools (Optional)"

    echo -e "${CYAN}Python tools:${NC}"
    check "  ruff" "command -v ruff" "" "warning"
    check "  pytest" "command -v pytest" "" "warning"
    check "  bandit" "command -v bandit" "" "warning"

    echo -e "${CYAN}JavaScript tools:${NC}"
    check "  npm" "command -v npm" "" "warning"
    check "  eslint (global)" "command -v eslint" "" "warning"

    echo -e "${CYAN}Go tools:${NC}"
    check "  go" "command -v go" "" "warning"
    check "  golangci-lint" "command -v golangci-lint" "" "warning"

    echo -e "${CYAN}Rust tools:${NC}"
    check "  cargo" "command -v cargo" "" "warning"
    check "  rustfmt" "command -v rustfmt" "" "warning"

    if [ $WARNING_CHECKS -gt 0 ]; then
        echo ""
        echo -e "${CYAN}💡 To install missing tools:${NC}"
        echo -e "   ${WHITE}~/.claude/guard/scripts/install_tools.sh auto${NC}"
    fi
}

# 6. Functional Tests
check_functional() {
    section "Functional Tests"

    # Test trinitas-guard if available
    if command -v trinitas-guard &>/dev/null; then
        echo -e "${CYAN}Testing trinitas-guard command:${NC}"

        # Capture status output
        if trinitas-guard status &>/dev/null; then
            echo -e "${GREEN}  ✓ trinitas-guard status works${NC}"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            echo -e "${YELLOW}  ⚠ trinitas-guard status failed${NC}"
            WARNING_CHECKS=$((WARNING_CHECKS + 1))
        fi

        TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    fi

    # Test language detection if detector exists
    if [ -f "$HOME/.claude/guard/core/detector.sh" ]; then
        echo -e "${CYAN}Testing language detection:${NC}"

        source "$HOME/.claude/guard/core/detector.sh" 2>/dev/null

        if type -t detect_languages &>/dev/null; then
            local detected=$(get_primary_language "." 2>/dev/null)
            if [ -n "$detected" ]; then
                echo -e "${GREEN}  ✓ Detected project language: ${WHITE}$detected${NC}"
            else
                echo -e "${YELLOW}  ⚠ No language detected in current directory${NC}"
            fi
        fi
    fi
}

# 7. Configuration Report
show_configuration() {
    section "Current Configuration"

    # Environment variables
    echo -e "${CYAN}Environment variables:${NC}"
    echo -e "  TRINITAS_GUARD_ENABLED: ${WHITE}${TRINITAS_GUARD_ENABLED:-not set}${NC}"
    echo -e "  TRINITAS_GUARD_MODE: ${WHITE}${TRINITAS_GUARD_MODE:-not set}${NC}"

    # Path check
    if [[ ":$PATH:" == *":$HOME/.local/bin:"* ]]; then
        echo -e "${GREEN}  ✓ ~/.local/bin is in PATH${NC}"
    else
        echo -e "${YELLOW}  ⚠ ~/.local/bin not in PATH${NC}"
        echo -e "${CYAN}    Add to PATH: export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
    fi
}

# 8. Generate Summary Report
generate_report() {
    section "Installation Report"

    local success_rate=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))

    echo -e "${CYAN}╔════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║          Test Summary              ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════╝${NC}"
    echo ""
    echo -e "Total Checks:    ${WHITE}$TOTAL_CHECKS${NC}"
    echo -e "Passed:          ${GREEN}$PASSED_CHECKS${NC}"
    echo -e "Warnings:        ${YELLOW}$WARNING_CHECKS${NC}"
    echo -e "Failed:          ${RED}$FAILED_CHECKS${NC}"
    echo -e "Success Rate:    ${WHITE}${success_rate}%${NC}"
    echo ""

    # Overall Status
    if [ $FAILED_CHECKS -eq 0 ]; then
        if [ $WARNING_CHECKS -eq 0 ]; then
            echo -e "${GREEN}🎉 PERFECT! Trinitas v2.2.0 is fully installed and configured!${NC}"
        else
            echo -e "${GREEN}✅ SUCCESS! Core installation is complete.${NC}"
            echo -e "${YELLOW}   Some optional features are not configured.${NC}"
        fi
    else
        echo -e "${RED}❌ INCOMPLETE: Some required components are missing.${NC}"
        echo -e "${CYAN}   Please run the installer: ./install_trinitas_config.sh${NC}"
    fi

    # Save report to file
    local report_file="$HOME/.claude/installation_report_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "Trinitas v2.2.0 Installation Report"
        echo "Generated: $(date)"
        echo "================================"
        echo ""
        echo "Check Results:"
        for result in "${CHECK_RESULTS[@]}"; do
            echo "  $result"
        done
        echo ""
        echo "Summary:"
        echo "  Total: $TOTAL_CHECKS"
        echo "  Passed: $PASSED_CHECKS"
        echo "  Warnings: $WARNING_CHECKS"
        echo "  Failed: $FAILED_CHECKS"
        echo "  Success Rate: ${success_rate}%"
    } > "$report_file"

    echo ""
    echo -e "${CYAN}📄 Report saved to:${NC}"
    echo -e "   ${WHITE}$report_file${NC}"
}

# Quick test commands
show_quick_tests() {
    section "Quick Test Commands"

    echo -e "${CYAN}You can test Trinitas with these commands:${NC}"
    echo ""
    echo -e "${WHITE}1. Basic test (in Claude Desktop):${NC}"
    echo "   'Trinitasシステムの動作確認をしてください'"
    echo ""
    echo -e "${WHITE}2. Quality Guardian test:${NC}"
    echo "   trinitas-guard status"
    echo "   trinitas-guard check"
    echo ""
    echo -e "${WHITE}3. Agent activation test:${NC}"
    echo "   'Athenaとして戦略を立案してください'"
    echo "   'Artemisとして最適化案を提示してください'"
    echo ""
}

# Main execution
main() {
    show_banner

    check_core_files
    check_agent_files
    check_quality_guardian
    check_hook_settings
    check_language_tools
    check_functional
    show_configuration

    generate_report
    show_quick_tests
}

# Run
main "$@"