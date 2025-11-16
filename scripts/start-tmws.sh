#!/bin/bash
# TMWS Startup Script - Intelligent Environment Detection
# Purpose: One-command startup for Mac/Linux with automatic configuration

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🚀 TMWS Startup - Detecting environment..."

# Function: Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function: Wait for service health
wait_for_health() {
    local url=$1
    local max_attempts=30
    local attempt=1

    echo "⏳ Waiting for TMWS health check..."
    while [ $attempt -le $max_attempts ]; do
        if curl -s "$url" >/dev/null 2>&1; then
            echo -e "${GREEN}✅ Health check passed!${NC}"
            return 0
        fi
        echo -n "."
        sleep 1
        attempt=$((attempt + 1))
    done

    echo -e "${RED}❌ Health check timeout${NC}"
    return 1
}

# Step 1: Detect OS
OS=$(uname -s)
COMPOSE_FILE=""

case "$OS" in
    Darwin)
        echo "📱 Detected: macOS (using hybrid mode)"
        COMPOSE_FILE="docker-compose.mac.yml"
        ;;
    Linux)
        echo "🐧 Detected: Linux (using full Docker mode)"
        COMPOSE_FILE="docker-compose.yml"
        ;;
    *)
        echo -e "${RED}❌ Unsupported OS: $OS${NC}"
        echo "   This script supports macOS and Linux only."
        echo "   For Windows, use: scripts\\start-tmws.bat"
        exit 1
        ;;
esac

# Step 2: Check Docker
if ! command_exists docker; then
    echo -e "${RED}❌ Docker not found${NC}"
    echo "   Install Docker from: https://www.docker.com/get-started"
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running${NC}"
    echo "   Please start Docker Desktop and try again."
    exit 1
fi

echo -e "${GREEN}✅ Docker is running${NC}"

# Step 3: Check docker-compose
if ! command_exists docker-compose && ! docker compose version >/dev/null 2>&1; then
    echo -e "${RED}❌ docker-compose not found${NC}"
    echo "   Install with: brew install docker-compose (macOS)"
    echo "   Or use Docker Desktop with built-in compose"
    exit 1
fi

# Use modern 'docker compose' if available, fallback to 'docker-compose'
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
else
    DOCKER_COMPOSE="docker-compose"
fi

echo -e "${GREEN}✅ docker-compose available${NC}"

# Step 4: Check .env file
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠️  .env not found, creating from .env.example${NC}"
    if [ -f .env.example ]; then
        cp .env.example .env
        echo -e "${GREEN}✅ Created .env from template${NC}"
        echo -e "${YELLOW}⚠️  Please review .env and set TMWS_SECRET_KEY if needed${NC}"
    else
        echo -e "${RED}❌ .env.example not found${NC}"
        exit 1
    fi
fi

# Step 5: Mac-specific - Check Ollama (optional but recommended)
if [ "$OS" = "Darwin" ]; then
    if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Ollama detected (native mode recommended)${NC}"
    else
        echo -e "${YELLOW}⚠️  Ollama not detected on localhost:11434${NC}"
        echo "   Mac hybrid mode works best with native Ollama."
        echo "   Install: brew install ollama && ollama serve"
        echo "   Or TMWS will use Docker Ollama (slower)."
    fi
fi

# Step 6: Start TMWS
echo ""
echo "🐳 Starting TMWS with $COMPOSE_FILE..."
$DOCKER_COMPOSE -f "$COMPOSE_FILE" up -d

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to start TMWS${NC}"
    echo "   Check logs with: $DOCKER_COMPOSE -f $COMPOSE_FILE logs"
    exit 1
fi

# Step 7: Wait for health check
if wait_for_health "http://localhost:8000/health"; then
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✅ TMWS started successfully!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "🌐 TMWS API: http://localhost:8000"
    echo "📚 API Docs: http://localhost:8000/docs"
    echo "🔧 Health: http://localhost:8000/health"
    echo ""
    echo "📝 Next steps:"
    echo "   1. Configure Claude Desktop MCP:"
    echo "      Update MCP settings with: scripts/mcp/tmws-mcp-docker.sh"
    echo "   2. View logs: $DOCKER_COMPOSE -f $COMPOSE_FILE logs -f"
    echo "   3. Stop TMWS: ./scripts/stop-tmws.sh"
    echo ""

    # Optional: Tail logs if --logs flag provided
    if [[ "$1" == "--logs" ]]; then
        echo "📋 Tailing logs (Ctrl+C to exit)..."
        $DOCKER_COMPOSE -f "$COMPOSE_FILE" logs -f
    fi
else
    echo -e "${RED}❌ TMWS started but health check failed${NC}"
    echo "   Check logs: $DOCKER_COMPOSE -f $COMPOSE_FILE logs tmws"
    exit 1
fi
