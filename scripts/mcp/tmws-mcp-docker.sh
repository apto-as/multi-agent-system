#!/bin/bash
# TMWS MCP Docker Wrapper for Claude Desktop (Mac/Linux)
# Purpose: Bridge Claude Desktop ↔ Docker container for MCP protocol
# Architecture: Claude Desktop → this script → docker exec → MCP Server

set -euo pipefail

# Configuration
CONTAINER_NAME="tmws-app"
MCP_COMMAND="python -m src.mcp_server"

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to print error messages
error() {
    echo -e "${RED}ERROR:${NC} $1" >&2
}

# Function to print warning messages
warn() {
    echo -e "${YELLOW}WARNING:${NC} $1" >&2
}

# Function to print success messages
success() {
    echo -e "${GREEN}SUCCESS:${NC} $1" >&2
}

# Cleanup function for graceful shutdown
cleanup() {
    warn "Received termination signal, shutting down MCP server..."
    exit 0
}

# Trap signals for graceful shutdown
trap cleanup SIGINT SIGTERM

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    error "Docker is not running."
    error "→ Please start Docker Desktop and try again."
    exit 1
fi

# Check if container exists
if ! docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    error "TMWS container '${CONTAINER_NAME}' does not exist."
    error "→ Run: ./scripts/start-tmws.sh"
    error "→ Or: docker-compose up -d"
    exit 1
fi

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    error "TMWS container '${CONTAINER_NAME}' is not running."
    error "→ Start the container: docker-compose up -d"
    error "→ Or run: ./scripts/start-tmws.sh"
    exit 1
fi

# Execute MCP server inside container
# -i: Keep STDIN open (required for MCP stdio protocol)
# The MCP protocol communicates via stdin/stdout
docker exec -i "${CONTAINER_NAME}" ${MCP_COMMAND}

# Exit with the same code as the docker exec command
exit $?
