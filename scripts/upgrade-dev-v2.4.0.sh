#!/bin/bash
# TMWS v2.4.0 Development Environment Upgrade Script
# For macOS development environments with existing TMWS installations

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}TMWS v2.4.0 Development Upgrade${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

# Detect current directory
TMWS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$TMWS_DIR"

echo -e "${YELLOW}Working directory: $TMWS_DIR${NC}"

# Step 1: Backup current state
echo -e "\n${YELLOW}Step 1: Backing up current state...${NC}"

BACKUP_DIR="$TMWS_DIR/backups/upgrade-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup .env if exists
if [ -f ".env" ]; then
    cp .env "$BACKUP_DIR/.env.backup"
    echo -e "${GREEN}  ✓ .env backed up${NC}"
fi

# Backup data directory if exists
if [ -d "data" ]; then
    cp -r data "$BACKUP_DIR/data.backup"
    echo -e "${GREEN}  ✓ data/ directory backed up${NC}"
fi

echo -e "${GREEN}  Backup location: $BACKUP_DIR${NC}"

# Step 2: Update git repository
echo -e "\n${YELLOW}Step 2: Updating git repository...${NC}"

# Stash any local changes
if ! git diff --quiet; then
    echo -e "${YELLOW}  Stashing local changes...${NC}"
    git stash push -m "Pre-upgrade stash $(date +%Y%m%d-%H%M%S)"
fi

# Fetch and checkout v2.4.0
git fetch origin
git checkout master
git pull origin master

# Verify version
CURRENT_VERSION=$(grep -E '^version = ' pyproject.toml | cut -d'"' -f2)
echo -e "${GREEN}  ✓ Updated to version: $CURRENT_VERSION${NC}"

# Step 3: Check Ollama installation
echo -e "\n${YELLOW}Step 3: Checking Ollama (REQUIRED)...${NC}"

if command -v ollama &> /dev/null; then
    OLLAMA_VERSION=$(ollama --version 2>/dev/null || echo "unknown")
    echo -e "${GREEN}  ✓ Ollama installed: $OLLAMA_VERSION${NC}"

    # Check if Ollama is running
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo -e "${GREEN}  ✓ Ollama server running${NC}"
    else
        echo -e "${YELLOW}  Starting Ollama server...${NC}"
        ollama serve &
        sleep 3
    fi

    # Check for required model
    if ollama list | grep -q "multilingual-e5-large"; then
        echo -e "${GREEN}  ✓ multilingual-e5-large model available${NC}"
    else
        echo -e "${YELLOW}  Pulling multilingual-e5-large model...${NC}"
        ollama pull zylonai/multilingual-e5-large
    fi
else
    echo -e "${RED}  ✗ Ollama not installed!${NC}"
    echo -e "${YELLOW}  Please install Ollama:${NC}"
    echo -e "    brew install ollama"
    echo -e "    ollama serve &"
    echo -e "    ollama pull zylonai/multilingual-e5-large"
    exit 1
fi

# Step 4: Update Python dependencies
echo -e "\n${YELLOW}Step 4: Updating Python dependencies...${NC}"

# Check if uv is installed
if command -v uv &> /dev/null; then
    echo -e "${GREEN}  ✓ uv found${NC}"

    # Sync dependencies
    uv sync --all-extras
    echo -e "${GREEN}  ✓ Dependencies updated${NC}"
else
    echo -e "${YELLOW}  uv not found, using pip...${NC}"

    # Activate venv if exists
    if [ -d ".venv" ]; then
        source .venv/bin/activate
    else
        python3.11 -m venv .venv
        source .venv/bin/activate
    fi

    pip install --upgrade pip
    pip install -e ".[dev]"
    echo -e "${GREEN}  ✓ Dependencies updated${NC}"
fi

# Step 5: Update .env configuration
echo -e "\n${YELLOW}Step 5: Updating .env configuration...${NC}"

# Create or update .env
if [ -f ".env" ]; then
    # Check if TMWS_OLLAMA_BASE_URL exists
    if grep -q "TMWS_OLLAMA_BASE_URL" .env; then
        # Update to localhost if using Docker URL
        if grep -q "host.docker.internal" .env; then
            sed -i.bak 's|host.docker.internal:11434|localhost:11434|g' .env
            echo -e "${GREEN}  ✓ Updated Ollama URL to localhost${NC}"
        else
            echo -e "${GREEN}  ✓ Ollama URL already configured${NC}"
        fi
    else
        echo 'TMWS_OLLAMA_BASE_URL="http://localhost:11434"' >> .env
        echo -e "${GREEN}  ✓ Added Ollama URL to .env${NC}"
    fi
else
    # Create new .env from example
    if [ -f ".env.example" ]; then
        cp .env.example .env
        sed -i.bak 's|host.docker.internal:11434|localhost:11434|g' .env 2>/dev/null || true
    else
        # Create minimal .env
        cat > .env << 'EOF'
# TMWS v2.4.0 Development Configuration
TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"
TMWS_SECRET_KEY="dev-secret-key-change-in-production-minimum-32-chars"
TMWS_ENVIRONMENT="development"
TMWS_OLLAMA_BASE_URL="http://localhost:11434"
TMWS_LOG_LEVEL="DEBUG"
EOF
    fi
    echo -e "${GREEN}  ✓ Created .env file${NC}"
fi

# Step 6: Run database migrations
echo -e "\n${YELLOW}Step 6: Running database migrations...${NC}"

# Ensure data directory exists
mkdir -p data

# Activate venv for alembic
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Run migrations
if command -v alembic &> /dev/null; then
    alembic upgrade head
    echo -e "${GREEN}  ✓ Database migrations applied${NC}"
else
    python -m alembic upgrade head
    echo -e "${GREEN}  ✓ Database migrations applied${NC}"
fi

# Step 7: Run quick verification tests
echo -e "\n${YELLOW}Step 7: Running verification tests...${NC}"

# Run a quick test
if command -v pytest &> /dev/null; then
    pytest tests/unit/test_health.py -v --tb=short 2>/dev/null && \
        echo -e "${GREEN}  ✓ Health tests passed${NC}" || \
        echo -e "${YELLOW}  ⚠ Some tests failed (non-blocking)${NC}"
else
    echo -e "${YELLOW}  Skipping tests (pytest not found)${NC}"
fi

# Step 8: Display summary
echo -e "\n${GREEN}=========================================${NC}"
echo -e "${GREEN}Upgrade Complete!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "${BLUE}TMWS v2.4.0 is ready for development.${NC}"
echo ""
echo "Quick start commands:"
echo "  # Start TMWS server"
echo "  uv run uvicorn src.main:app --reload"
echo ""
echo "  # Or run MCP server"
echo "  uv run python -m src.mcp_server"
echo ""
echo "  # Run tests"
echo "  pytest tests/unit/ -v"
echo ""
echo "Backup location: $BACKUP_DIR"
echo ""
echo -e "${YELLOW}Note: Ensure Ollama is running before starting TMWS${NC}"
echo "  ollama serve &"
