#!/bin/bash
# TMWS Shutdown Script - Graceful Shutdown
# Purpose: One-command shutdown with data preservation

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🛑 TMWS Shutdown - Graceful stop..."

# Function: Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Step 1: Detect OS for compose file
OS=$(uname -s)
COMPOSE_FILE=""

case "$OS" in
    Darwin)
        echo "📱 Detected: macOS"
        COMPOSE_FILE="docker-compose.mac.yml"
        ;;
    Linux)
        echo "🐧 Detected: Linux"
        COMPOSE_FILE="docker-compose.yml"
        ;;
    *)
        echo -e "${RED}❌ Unsupported OS: $OS${NC}"
        exit 1
        ;;
esac

# Step 2: Check if Docker is available
if ! command_exists docker; then
    echo -e "${RED}❌ Docker not found${NC}"
    exit 1
fi

# Use modern 'docker compose' if available, fallback to 'docker-compose'
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
else
    DOCKER_COMPOSE="docker-compose"
fi

# Step 3: Check if TMWS is running
if ! $DOCKER_COMPOSE -f "$COMPOSE_FILE" ps | grep -q tmws; then
    echo -e "${YELLOW}⚠️  TMWS is not running${NC}"
    echo "   No action needed."
    exit 0
fi

# Step 4: Stop containers (preserve volumes by default)
echo "🐳 Stopping TMWS containers..."
$DOCKER_COMPOSE -f "$COMPOSE_FILE" down

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✅ TMWS stopped successfully${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "💾 Data preserved in ./data/"
    echo ""
    echo "📝 Next steps:"
    echo "   • Restart: ./scripts/start-tmws.sh"
    echo "   • Remove all data: $DOCKER_COMPOSE -f $COMPOSE_FILE down -v"
    echo "   • View stopped containers: docker ps -a"
    echo ""
else
    echo -e "${RED}❌ Failed to stop TMWS${NC}"
    echo "   Check running containers: docker ps"
    exit 1
fi
