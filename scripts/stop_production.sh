#!/bin/bash
# TMWS Production Stop Script

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if PID file exists
if [ -f "tmws.pid" ]; then
    PID=$(cat tmws.pid)
    
    # Check if process is running
    if ps -p $PID > /dev/null; then
        echo -e "${YELLOW}Stopping TMWS (PID: $PID)...${NC}"
        kill -TERM $PID
        
        # Wait for graceful shutdown
        sleep 2
        
        # Check if still running
        if ps -p $PID > /dev/null; then
            echo -e "${YELLOW}Force stopping TMWS...${NC}"
            kill -KILL $PID
        fi
        
        rm tmws.pid
        echo -e "${GREEN}TMWS stopped successfully${NC}"
    else
        echo -e "${YELLOW}TMWS process not found (PID: $PID)${NC}"
        rm tmws.pid
    fi
else
    echo -e "${YELLOW}PID file not found. Checking for running processes...${NC}"
    
    # Try to find running TMWS processes
    PIDS=$(pgrep -f "uvicorn tmws.main:app" || true)
    
    if [ -n "$PIDS" ]; then
        echo -e "${YELLOW}Found TMWS processes: $PIDS${NC}"
        kill -TERM $PIDS
        echo -e "${GREEN}TMWS processes stopped${NC}"
    else
        echo -e "${YELLOW}No TMWS processes found${NC}"
    fi
fi