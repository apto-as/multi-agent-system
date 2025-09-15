#!/bin/bash
# TMWS Production Start Script (for non-systemd systems like macOS)

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${RED}Virtual environment not found. Please run install_production.sh first.${NC}"
    exit 1
fi

# Check if production config exists
if [ ! -f ".env.production" ]; then
    echo -e "${RED}Production configuration not found. Please run install_production.sh first.${NC}"
    exit 1
fi

# Load environment variables
export $(grep -v '^#' .env.production | xargs)

# Activate virtual environment
source venv/bin/activate

# Create log directory if it doesn't exist
mkdir -p logs

# Function to check service health
check_health() {
    sleep 3
    if curl -s http://localhost:8000/health > /dev/null; then
        echo -e "${GREEN}TMWS is running and healthy!${NC}"
        return 0
    else
        echo -e "${YELLOW}TMWS is starting...${NC}"
        return 1
    fi
}

# Start TMWS
echo -e "${YELLOW}Starting TMWS in production mode...${NC}"

# Use nohup for background execution with proper logging
nohup python -m uvicorn tmws.main:app \
    --host 127.0.0.1 \
    --port 8000 \
    --workers 4 \
    --log-level info \
    --access-log \
    > logs/tmws.log 2>&1 &

# Save PID
echo $! > tmws.pid

echo -e "${GREEN}TMWS started with PID $(cat tmws.pid)${NC}"

# Check health
check_health

echo ""
echo "To stop TMWS, run: ./scripts/stop_production.sh"
echo "To view logs: tail -f logs/tmws.log"
echo "To check status: curl http://localhost:8000/health"