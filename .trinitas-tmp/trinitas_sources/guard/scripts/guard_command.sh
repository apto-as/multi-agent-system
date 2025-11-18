#!/bin/bash
# Trinitas Quality Guardian Command Interface
# Main entry point for all guardian operations

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Find Trinitas root directory
find_trinitas_root() {
    local current_dir="$PWD"
    while [ "$current_dir" != "/" ]; do
        if [ -d "$current_dir/trinitas_sources/guard" ]; then
            echo "$current_dir"
            return 0
        fi
        current_dir=$(dirname "$current_dir")
    done

    # Check if we're in user's home .claude directory
    if [ -d "$HOME/.claude/trinitas_sources/guard" ]; then
        echo "$HOME/.claude"
        return 0
    fi

    return 1
}

TRINITAS_ROOT=$(find_trinitas_root) || {
    echo -e "${RED}Error: Cannot find Trinitas installation${NC}"
    exit 1
}

GUARD_DIR="$TRINITAS_ROOT/trinitas_sources/guard"
TEMPLATES_DIR="$GUARD_DIR/templates"
SCRIPTS_DIR="$GUARD_DIR/scripts"

# Command functions
cmd_init() {
    echo -e "${CYAN}🏛️ Athena: Initializing Quality Guardian for your project...${NC}"
    echo

    # Check what kind of project this is
    local project_type="unknown"
    if [ -f "pyproject.toml" ] || [ -f "setup.py" ]; then
        project_type="python"
    elif [ -f "package.json" ]; then
        project_type="javascript"
    fi

    echo -e "${BLUE}Detected project type: ${WHITE}$project_type${NC}"
    echo

    # Create necessary directories
    echo -e "${GREEN}Creating quality infrastructure...${NC}"
    mkdir -p .github/workflows
    mkdir -p tests

    # Copy appropriate templates
    if [ "$project_type" = "python" ]; then
        echo -e "${PURPLE}🏹 Artemis: Setting up Python quality tools...${NC}"

        # Copy Ruff configuration
        if [ ! -f "pyproject.toml" ]; then
            cp "$TEMPLATES_DIR/ruff/pyproject.toml" pyproject.toml
            echo "  ✅ Created pyproject.toml with Ruff configuration"
        else
            echo "  ℹ️  pyproject.toml exists, please merge Ruff settings manually"
            echo "      Reference: $TEMPLATES_DIR/ruff/pyproject.toml"
        fi

        # Copy pytest configuration
        if [ ! -f "pytest.ini" ]; then
            cp "$TEMPLATES_DIR/pytest/pytest.ini" pytest.ini
            echo "  ✅ Created pytest.ini"
        fi

        # Copy pre-commit configuration
        if [ ! -f ".pre-commit-config.yaml" ]; then
            cp "$TEMPLATES_DIR/pre_commit/pre-commit-config.yaml" .pre-commit-config.yaml
            echo "  ✅ Created .pre-commit-config.yaml"
        fi
    fi

    # Copy GitHub Actions workflow
    if [ ! -f ".github/workflows/quality-guardian.yml" ]; then
        cp "$TEMPLATES_DIR/github_actions/quality-guardian-ci.yaml" .github/workflows/quality-guardian.yml
        echo "  ✅ Created GitHub Actions workflow"
    fi

    echo
    echo -e "${GREEN}✅ Quality Guardian initialized successfully!${NC}"
    echo
    echo -e "${CYAN}Next steps:${NC}"
    echo "  1. Run 'trinitas guard check' to verify your setup"
    echo "  2. Install pre-commit hooks: pre-commit install"
    echo "  3. Commit the configuration files to your repository"
    echo
}

cmd_check() {
    echo -e "${CYAN}🏛️ Running Trinitas Quality Guardian checks...${NC}"
    echo

    # Run the quality check script
    if [ -f "$SCRIPTS_DIR/quality_check.py" ]; then
        python "$SCRIPTS_DIR/quality_check.py" "$@"
    else
        echo -e "${RED}Error: Quality check script not found${NC}"
        exit 1
    fi
}

cmd_fix() {
    echo -e "${PURPLE}🏹 Artemis: Auto-fixing code quality issues...${NC}"
    echo

    # Run Ruff with fix flag
    if command -v ruff &> /dev/null; then
        echo "Running Ruff formatter..."
        ruff format .
        echo "Running Ruff linter with fixes..."
        ruff check . --fix
        echo -e "${GREEN}✅ Auto-fix completed${NC}"
    else
        echo -e "${YELLOW}⚠️  Ruff not installed. Install with: pip install ruff${NC}"
    fi
}

cmd_setup_ci() {
    echo -e "${PURPLE}🎭 Hera: Setting up CI/CD pipeline...${NC}"
    echo

    # Ensure .github/workflows directory exists
    mkdir -p .github/workflows

    # Copy GitHub Actions workflow
    cp "$TEMPLATES_DIR/github_actions/quality-guardian-ci.yaml" .github/workflows/quality-guardian.yml
    echo "  ✅ Created .github/workflows/quality-guardian.yml"

    # Create branch protection script
    cat > setup_branch_protection.sh << 'EOF'
#!/bin/bash
# Script to setup branch protection rules
# Requires GitHub CLI (gh) to be installed and authenticated

REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
BRANCH="main"

echo "Setting up branch protection for $REPO:$BRANCH"

gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  /repos/$REPO/branches/$BRANCH/protection \
  -f required_status_checks='{"strict":true,"contexts":["Athena: Quality Gate"]}' \
  -f enforce_admins=false \
  -f required_pull_request_reviews='{"dismiss_stale_reviews":true,"require_code_owner_reviews":false,"required_approving_review_count":1}' \
  -f restrictions=null

echo "✅ Branch protection rules configured"
EOF

    chmod +x setup_branch_protection.sh
    echo "  ✅ Created setup_branch_protection.sh"

    echo
    echo -e "${GREEN}CI/CD setup completed!${NC}"
    echo
    echo "Next steps:"
    echo "  1. Commit the workflow file"
    echo "  2. Push to GitHub"
    echo "  3. Run ./setup_branch_protection.sh to enable branch protection"
}

cmd_install_hooks() {
    echo -e "${YELLOW}⚔️ Eris: Installing pre-commit hooks...${NC}"
    echo

    # Check if pre-commit is installed
    if ! command -v pre-commit &> /dev/null; then
        echo "Installing pre-commit..."
        pip install pre-commit
    fi

    # Install the hooks
    pre-commit install
    echo "  ✅ Pre-commit hooks installed"

    # Run against all files to check current state
    echo
    echo "Running initial check against all files..."
    pre-commit run --all-files || true

    echo
    echo -e "${GREEN}✅ Hooks installed successfully!${NC}"
    echo "Commits will now be automatically checked for quality."
}

cmd_report() {
    echo -e "${CYAN}📚 Muses: Generating quality report...${NC}"
    echo

    # Run quality check with JSON output
    local report_file="quality_report_$(date +%Y%m%d_%H%M%S).txt"
    python "$SCRIPTS_DIR/quality_check.py" -v -o "$report_file"

    echo
    echo -e "${GREEN}✅ Report saved to: $report_file${NC}"
}

cmd_help() {
    cat << EOF
${CYAN}Trinitas Quality Guardian - Command Interface${NC}

${WHITE}Usage:${NC} trinitas guard <command> [options]

${WHITE}Commands:${NC}
  ${GREEN}init${NC}        Initialize Quality Guardian in your project
  ${GREEN}check${NC}       Run quality checks on your code
  ${GREEN}fix${NC}         Auto-fix code quality issues
  ${GREEN}setup-ci${NC}    Setup CI/CD pipeline with GitHub Actions
  ${GREEN}install-hooks${NC} Install pre-commit hooks
  ${GREEN}report${NC}      Generate detailed quality report
  ${GREEN}help${NC}        Show this help message

${WHITE}Examples:${NC}
  trinitas guard init           # Initialize guardian in current project
  trinitas guard check          # Run quality checks
  trinitas guard check -v       # Run with verbose output
  trinitas guard fix            # Auto-fix issues
  trinitas guard setup-ci       # Setup GitHub Actions

${WHITE}Agent Responsibilities:${NC}
  ${PURPLE}🏹 Artemis${NC}: Code quality, formatting, complexity
  ${RED}🔥 Hestia${NC}: Security scanning, vulnerability detection
  ${CYAN}🏛️ Athena${NC}: Overall coordination, quality gates
  ${BLUE}📚 Muses${NC}: Documentation, reporting
  ${PURPLE}🎭 Hera${NC}: CI/CD, automation
  ${YELLOW}⚔️ Eris${NC}: Integration, consistency

For more information, see: $GUARD_DIR/README.md
EOF
}

# Main command dispatcher
case "${1:-help}" in
    init)
        shift
        cmd_init "$@"
        ;;
    check)
        shift
        cmd_check "$@"
        ;;
    fix)
        shift
        cmd_fix "$@"
        ;;
    setup-ci)
        shift
        cmd_setup_ci "$@"
        ;;
    install-hooks)
        shift
        cmd_install_hooks "$@"
        ;;
    report)
        shift
        cmd_report "$@"
        ;;
    help|--help|-h)
        cmd_help
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo
        cmd_help
        exit 1
        ;;
esac