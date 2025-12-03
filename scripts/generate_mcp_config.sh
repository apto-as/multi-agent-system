#!/bin/bash
# ============================================================================
# TMWS MCP Configuration Generator
# Version: 2.4.12
#
# Generates .mcp.json configuration for Claude Code and OpenCode
# based on installation mode (Docker, Local, UV)
#
# Usage:
#   ./generate_mcp_config.sh                    # Interactive mode
#   ./generate_mcp_config.sh --mode docker      # Docker mode
#   ./generate_mcp_config.sh --mode local       # Local Python mode
#   ./generate_mcp_config.sh --mode uv          # UV mode (recommended)
#   ./generate_mcp_config.sh --output ~/.claude/.mcp.json  # Custom output
# ============================================================================

set -e

VERSION="2.4.12"

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_info() { echo -e "${BLUE}ℹ${NC} $1"; }

# Default values
MODE=""
OUTPUT_FILE=""
ENVIRONMENT="development"
DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"
SECRET_KEY=""

show_help() {
    echo "TMWS MCP Configuration Generator v${VERSION}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help           Show this help message"
    echo "  -m, --mode MODE      Installation mode (docker|local|uv)"
    echo "  -o, --output FILE    Output file path (default: ~/.claude/.mcp.json)"
    echo "  -e, --env ENV        Environment (development|production|test)"
    echo "  --dry-run            Show generated config without writing"
    echo ""
    echo "Modes:"
    echo "  docker  - Use Docker container (recommended for production)"
    echo "  local   - Use local Python installation with pip"
    echo "  uv      - Use UV package manager (recommended for development)"
    echo ""
    echo "Examples:"
    echo "  $0 --mode docker"
    echo "  $0 --mode uv --output ~/.claude/.mcp.json"
    echo "  $0 --mode local --env production"
}

detect_installation() {
    # Check if Docker container exists
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q 'tmws-app'; then
        echo "docker"
        return 0
    fi

    # Check if UV is available and project has uv.lock
    if command -v uv &>/dev/null && [ -f "${PROJECT_DIR}/uv.lock" ]; then
        echo "uv"
        return 0
    fi

    # Check if pip installation exists
    if pip show tmws &>/dev/null 2>&1 || pip3 show tmws &>/dev/null 2>&1; then
        echo "local"
        return 0
    fi

    # Default to uv (most portable)
    echo "uv"
}

generate_secret_key() {
    if command -v openssl &>/dev/null; then
        openssl rand -hex 32
    elif command -v python3 &>/dev/null; then
        python3 -c "import secrets; print(secrets.token_hex(32))"
    else
        # Fallback
        head -c 32 /dev/urandom | xxd -p | tr -d '\n'
    fi
}

generate_config() {
    local mode="$1"
    local env="$2"

    case "$mode" in
        docker)
            cat <<EOF
{
  "\$comment": "TMWS MCP Configuration - Docker Mode (Generated v${VERSION})",
  "mcpServers": {
    "tmws": {
      "type": "stdio",
      "command": "docker",
      "args": ["exec", "-i", "tmws-app", "tmws-mcp-server"],
      "env": {}
    },
    "context7": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@upstash/context7-mcp"],
      "env": {}
    },
    "playwright": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@playwright/mcp@latest"],
      "env": {}
    },
    "serena-mcp-server": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/oraios/serena", "serena-mcp-server", "--context", "ide-assistant"],
      "env": {}
    }
  }
}
EOF
            ;;
        uv)
            cat <<EOF
{
  "\$comment": "TMWS MCP Configuration - UV Mode (Generated v${VERSION})",
  "mcpServers": {
    "tmws": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--project", "${PROJECT_DIR}", "tmws-mcp-server"],
      "env": {
        "TMWS_ENVIRONMENT": "${env}",
        "TMWS_DATABASE_URL": "${DATABASE_URL}"
      }
    },
    "context7": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@upstash/context7-mcp"],
      "env": {}
    },
    "playwright": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@playwright/mcp@latest"],
      "env": {}
    },
    "serena-mcp-server": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/oraios/serena", "serena-mcp-server", "--context", "ide-assistant"],
      "env": {}
    }
  }
}
EOF
            ;;
        local)
            cat <<EOF
{
  "\$comment": "TMWS MCP Configuration - Local Python Mode (Generated v${VERSION})",
  "mcpServers": {
    "tmws": {
      "type": "stdio",
      "command": "python3",
      "args": ["-m", "src.mcp_server"],
      "env": {
        "TMWS_ENVIRONMENT": "${env}",
        "TMWS_DATABASE_URL": "${DATABASE_URL}",
        "PYTHONPATH": "${PROJECT_DIR}"
      }
    },
    "context7": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@upstash/context7-mcp"],
      "env": {}
    },
    "playwright": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@playwright/mcp@latest"],
      "env": {}
    },
    "serena-mcp-server": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/oraios/serena", "serena-mcp-server", "--context", "ide-assistant"],
      "env": {}
    }
  }
}
EOF
            ;;
        *)
            print_error "Unknown mode: $mode"
            exit 1
            ;;
    esac
}

main() {
    local dry_run=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -m|--mode)
                MODE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -e|--env)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Auto-detect mode if not specified
    if [ -z "$MODE" ]; then
        print_info "Detecting installation mode..."
        MODE=$(detect_installation)
        print_success "Detected mode: $MODE"
    fi

    # Default output file
    if [ -z "$OUTPUT_FILE" ]; then
        OUTPUT_FILE="${HOME}/.claude/.mcp.json"
    fi

    echo ""
    echo -e "${CYAN}TMWS MCP Configuration Generator v${VERSION}${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    print_info "Mode: ${MODE}"
    print_info "Environment: ${ENVIRONMENT}"
    print_info "Output: ${OUTPUT_FILE}"
    echo ""

    # Generate config
    local config
    config=$(generate_config "$MODE" "$ENVIRONMENT")

    if [ "$dry_run" = true ]; then
        echo -e "${CYAN}Generated Configuration:${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "$config"
        exit 0
    fi

    # Create output directory
    mkdir -p "$(dirname "$OUTPUT_FILE")"

    # Backup existing file
    if [ -f "$OUTPUT_FILE" ]; then
        local backup="${OUTPUT_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$OUTPUT_FILE" "$backup"
        print_success "Backed up existing config: $backup"
    fi

    # Write config
    echo "$config" > "$OUTPUT_FILE"
    print_success "Configuration written: $OUTPUT_FILE"

    echo ""
    echo -e "${GREEN}MCP configuration generated successfully!${NC}"
    echo ""
    print_info "Restart Claude Code to apply changes"
}

main "$@"
