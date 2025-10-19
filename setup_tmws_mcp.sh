#!/bin/bash
# TMWS v2.3.0 MCP Server Setup Script (Option A: Hybrid uvx approach)
#
# This script sets up TMWS in ~/.tmws-repo for Claude Desktop MCP integration
# Usage: ./setup_tmws_mcp.sh

set -e  # Exit on error

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
print_header() {
    echo -e "\n${BLUE}===================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===================================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Configuration
INSTALL_DIR="$HOME/.tmws-repo"
REPO_URL="https://github.com/apto-as/tmws"
CURRENT_DIR=$(pwd)

print_header "TMWS v2.3.0 MCP Server Setup (Option A)"

# Check prerequisites
print_info "Checking prerequisites..."

# Check Python version
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [[ $PYTHON_MAJOR -ge 3 ]] && [[ $PYTHON_MINOR -ge 11 ]]; then
    print_success "Python $PYTHON_VERSION found"
else
    print_error "Python 3.11+ required for v2.3.0 (found $PYTHON_VERSION)"
    exit 1
fi

# Check uv
if ! command -v uv &> /dev/null; then
    print_error "uv is not installed. Install it with: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi
print_success "uv found: $(uv --version)"

# Check Redis
if ! redis-cli ping &> /dev/null; then
    print_warning "Redis is not running. Start it with: brew services start redis"
    read -p "Continue without Redis? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    print_success "Redis is running"
fi

# Check git
if ! command -v git &> /dev/null; then
    print_error "git is not installed"
    exit 1
fi
print_success "git found"

echo ""

# Step 1: Clone or update repository
print_header "Step 1: Repository Setup"

if [ -d "$INSTALL_DIR" ]; then
    print_info "Directory $INSTALL_DIR already exists"
    read -p "Update existing installation? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Updating repository..."
        cd "$INSTALL_DIR"
        git pull
        cd "$CURRENT_DIR"
        print_success "Repository updated"
    else
        print_info "Using existing installation"
    fi
else
    print_info "Cloning repository to $INSTALL_DIR..."
    git clone "$REPO_URL" "$INSTALL_DIR"
    print_success "Repository cloned"
fi

cd "$INSTALL_DIR"

# Step 2: Install dependencies with uv
print_header "Step 2: Installing Dependencies"

print_info "Installing dependencies with uv..."
uv sync
print_success "Dependencies installed"

# Step 3: Create data directories
print_header "Step 3: Creating Data Directories"

mkdir -p "$INSTALL_DIR/data/chroma"
chmod 700 "$INSTALL_DIR/data/chroma"
print_success "ChromaDB data directory: $INSTALL_DIR/data/chroma"

# Step 4: Environment configuration
print_header "Step 4: Environment Configuration"

if [ ! -f "$INSTALL_DIR/.env" ]; then
    print_info "Creating .env file..."
    cat > "$INSTALL_DIR/.env" <<EOF
# TMWS v2.3.0 Environment Configuration
# Generated on $(date)

# === ENVIRONMENT ===
TMWS_ENVIRONMENT=production
TMWS_DEBUG=false

# === DATABASE (PostgreSQL + pgvector) ===
# IMPORTANT: Replace with your Supabase/PostgreSQL connection string
TMWS_DATABASE_URL=postgresql://user:password@host:5432/database
# Example Supabase: postgresql://postgres.[PROJECT_REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:5432/postgres

# === REDIS (Sub-millisecond coordination) ===
TMWS_REDIS_URL=redis://localhost:6379/0
TMWS_REDIS_POOL_SIZE=10

# === CHROMADB (Ultra-fast vector search) ===
TMWS_CHROMA_PERSIST_DIRECTORY=$INSTALL_DIR/data/chroma
TMWS_CHROMA_COLLECTION=tmws_memories
TMWS_CHROMA_CACHE_SIZE=10000

# === VECTOR & EMBEDDINGS (v2.3.0: Multilingual-E5) ===
TMWS_VECTOR_DIMENSION=768
TMWS_EMBEDDING_MODEL=intfloat/multilingual-e5-base

# === SECURITY ===
# IMPORTANT: Generate a secure random key with: openssl rand -hex 32
TMWS_SECRET_KEY=$(openssl rand -hex 32)
TMWS_AUTH_ENABLED=false

# === API CONFIGURATION ===
TMWS_API_HOST=0.0.0.0
TMWS_API_PORT=8000

# === MCP SERVER ===
TMWS_MCP_ENABLED=true
EOF
    print_success ".env file created"
    print_warning "IMPORTANT: Edit $INSTALL_DIR/.env and set your DATABASE_URL!"
else
    print_info ".env file already exists, skipping"
fi

# Step 5: Database migration
print_header "Step 5: Database Migration"

print_info "Before running migration, make sure DATABASE_URL is set correctly in .env"
read -p "Have you configured DATABASE_URL in .env? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "Running database migrations..."
    uv run alembic upgrade head
    print_success "Database migration completed"
else
    print_warning "Skipping database migration. Run manually later with: cd $INSTALL_DIR && uv run alembic upgrade head"
fi

# Step 6: ChromaDB initialization
print_header "Step 6: ChromaDB Initialization"

if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "Initializing ChromaDB collection..."
    uv run python scripts/initialize_chroma.py
    print_success "ChromaDB initialized"
else
    print_warning "Skipping ChromaDB initialization. Run manually later with: cd $INSTALL_DIR && uv run python scripts/initialize_chroma.py"
fi

# Step 7: Claude Desktop MCP configuration
print_header "Step 7: Claude Desktop MCP Configuration"

CLAUDE_CONFIG="$HOME/Library/Application Support/Claude/claude_desktop_config.json"

print_info "Claude Desktop MCP configuration location:"
echo "  $CLAUDE_CONFIG"
echo ""
print_info "Add the following to your Claude Desktop MCP configuration:"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
cat <<EOF

{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": [
        "--from",
        "$INSTALL_DIR",
        "tmws-mcp-server"
      ],
      "env": {
        "TMWS_DATABASE_URL": "your_postgresql_url_here",
        "TMWS_REDIS_URL": "redis://localhost:6379/0",
        "TMWS_CHROMA_PERSIST_DIRECTORY": "$INSTALL_DIR/data/chroma",
        "TMWS_SECRET_KEY": "$(cat $INSTALL_DIR/.env | grep TMWS_SECRET_KEY | cut -d'=' -f2)",
        "TMWS_ENVIRONMENT": "production"
      }
    }
  }
}

EOF
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

read -p "Would you like to automatically add this to Claude Desktop config? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Backup existing config
    if [ -f "$CLAUDE_CONFIG" ]; then
        cp "$CLAUDE_CONFIG" "$CLAUDE_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"
        print_success "Backed up existing config"
    fi

    # Create config directory if it doesn't exist
    mkdir -p "$(dirname "$CLAUDE_CONFIG")"

    # Use Python to merge JSON configurations
    python3 <<PYTHON_SCRIPT
import json
import os

config_file = "$CLAUDE_CONFIG"
install_dir = "$INSTALL_DIR"

# Load existing config or create new
if os.path.exists(config_file):
    with open(config_file, 'r') as f:
        config = json.load(f)
else:
    config = {"mcpServers": {}}

# Ensure mcpServers exists
if "mcpServers" not in config:
    config["mcpServers"] = {}

# Read SECRET_KEY from .env
secret_key = "$(cat $INSTALL_DIR/.env | grep TMWS_SECRET_KEY | cut -d'=' -f2)"

# Add TMWS MCP server
config["mcpServers"]["tmws"] = {
    "command": "uvx",
    "args": [
        "--from",
        install_dir,
        "tmws-mcp-server"
    ],
    "env": {
        "TMWS_DATABASE_URL": "your_postgresql_url_here",
        "TMWS_REDIS_URL": "redis://localhost:6379/0",
        "TMWS_CHROMA_PERSIST_DIRECTORY": f"{install_dir}/data/chroma",
        "TMWS_SECRET_KEY": secret_key,
        "TMWS_ENVIRONMENT": "production"
    }
}

# Write back
with open(config_file, 'w') as f:
    json.dump(config, f, indent=2)

print("✅ Configuration updated")
PYTHON_SCRIPT

    print_success "Claude Desktop config updated"
    print_warning "IMPORTANT: Edit the config and replace 'your_postgresql_url_here' with your actual DATABASE_URL"
    print_info "Config location: $CLAUDE_CONFIG"
else
    print_info "Skipping automatic configuration. Add the JSON manually to Claude Desktop config"
fi

# Final summary
print_header "Setup Complete!"

echo -e "${GREEN}✅ TMWS v2.3.0 MCP Server is installed at: $INSTALL_DIR${NC}"
echo ""
echo "📋 Next Steps:"
echo ""
echo "1. Edit configuration:"
echo "   ${YELLOW}vim $INSTALL_DIR/.env${NC}"
echo "   - Set TMWS_DATABASE_URL to your PostgreSQL/Supabase URL"
echo ""
echo "2. Edit Claude Desktop MCP config:"
echo "   ${YELLOW}vim \"$CLAUDE_CONFIG\"${NC}"
echo "   - Replace 'your_postgresql_url_here' with your actual DATABASE_URL"
echo ""
echo "3. Restart Claude Desktop to load the MCP server"
echo ""
echo "4. Test the installation:"
echo "   ${YELLOW}cd $INSTALL_DIR && uv run python -c 'from src.mcp_server import main; print(\"✅ Import successful\")'${NC}"
echo ""
echo "📚 Documentation:"
echo "   - Architecture: $INSTALL_DIR/docs/ARCHITECTURE_V2.3.0.md"
echo "   - Deployment: $INSTALL_DIR/docs/DEPLOYMENT_GUIDE.md"
echo "   - MCP Tools: $INSTALL_DIR/docs/MCP_TOOLS_REFERENCE.md"
echo ""
echo -e "${BLUE}🎉 Happy coding with TMWS v2.3.0!${NC}"
echo ""

cd "$CURRENT_DIR"
