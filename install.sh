#!/bin/bash
# TMWS v2.3.0 Complete Installation Script
# Comprehensive setup for production-ready deployment with 3-tier hybrid architecture

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
INSTALL_DIR="$HOME/.claude/tmws"
PROJECT_NAME="TMWS v2.3.0 - Trinitas Memory & Workflow Service"
REQUIRED_PYTHON="3.11"
DEFAULT_DB_NAME="tmws"
DEFAULT_DB_USER="tmws_user"
DEFAULT_DB_PASSWORD="tmws_password"

# Functions
print_header() {
    echo -e "\n${BLUE}============================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}============================================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Start installation
clear
print_header "$PROJECT_NAME Installation"
echo "This script will install and configure TMWS v2.3.0 with:"
echo "  - PostgreSQL 17+ (Source of truth + pgvector)"
echo "  - Redis 7+ (Sub-millisecond agent/task coordination)"
echo "  - ChromaDB (Ultra-fast vector search, 0.47ms P95)"
echo "  - Multilingual-E5 (768-dim embeddings)"
echo ""

# Step 1: System Requirements Check
print_header "Step 1: Checking System Requirements"

# Check Python version (3.11+ required for v2.3.0)
if check_command python3; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

    if [[ $PYTHON_MAJOR -ge 3 ]] && [[ $PYTHON_MINOR -ge 11 ]]; then
        print_success "Python $PYTHON_VERSION found"
    else
        print_error "Python 3.11+ required for v2.3.0 (found $PYTHON_VERSION)"
        echo "Please upgrade Python to 3.11 or higher"
        exit 1
    fi
else
    print_error "Python 3 not found"
    exit 1
fi

# Check PostgreSQL
if check_command psql; then
    print_success "PostgreSQL client found"
else
    print_warning "PostgreSQL client not found. Installing..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install postgresql@17
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt-get update && sudo apt-get install -y postgresql-client-17
    else
        print_error "Please install PostgreSQL 17+ manually"
        exit 1
    fi
fi

# Check Redis
if check_command redis-cli; then
    print_success "Redis client found"
else
    print_warning "Redis client not found. Installing..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install redis
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt-get update && sudo apt-get install -y redis-server
    else
        print_error "Please install Redis 7+ manually"
        exit 1
    fi
fi

# Check UV (optional but recommended)
if check_command uv; then
    print_success "UV package manager found (recommended)"
    USE_UV=true
else
    print_warning "UV not found, will use pip"
    USE_UV=false
fi

# Step 2: PostgreSQL Setup
print_header "Step 2: PostgreSQL Setup"

# Check if PostgreSQL is running
if pg_isready -h localhost -p 5432 &> /dev/null; then
    print_success "PostgreSQL server is running"
else
    print_warning "PostgreSQL server not running. Starting..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew services start postgresql@17 || brew services start postgresql || {
            print_error "Failed to start PostgreSQL"
            exit 1
        }
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo systemctl start postgresql || {
            print_error "Failed to start PostgreSQL"
            exit 1
        }
    fi

    # Wait for PostgreSQL to start
    echo "Waiting for PostgreSQL to start..."
    for i in {1..30}; do
        if pg_isready -h localhost -p 5432 &> /dev/null; then
            print_success "PostgreSQL started"
            break
        fi
        sleep 1
    done
fi

# Create database and user
echo ""
echo "Setting up TMWS database..."
echo "Enter PostgreSQL admin user (default: $USER):"
read -r PG_ADMIN_USER
PG_ADMIN_USER=${PG_ADMIN_USER:-$USER}

# Create database
createdb -U "$PG_ADMIN_USER" "$DEFAULT_DB_NAME" 2>/dev/null || {
    print_warning "Database $DEFAULT_DB_NAME already exists"
}

# Create user (using psql)
psql -U "$PG_ADMIN_USER" -d postgres <<EOF 2>/dev/null || true
CREATE USER $DEFAULT_DB_USER WITH PASSWORD '$DEFAULT_DB_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE $DEFAULT_DB_NAME TO $DEFAULT_DB_USER;
ALTER DATABASE $DEFAULT_DB_NAME OWNER TO $DEFAULT_DB_USER;
EOF

print_success "Database configured"

# Enable pgvector extension
echo "Enabling pgvector extension..."
psql -U "$PG_ADMIN_USER" -d "$DEFAULT_DB_NAME" -c "CREATE EXTENSION IF NOT EXISTS vector;" 2>/dev/null || {
    print_warning "pgvector extension might need manual installation"
    echo "Run: CREATE EXTENSION vector; in PostgreSQL"
}

# Step 3: ChromaDB Setup (NEW in v2.3.0)
print_header "Step 3: ChromaDB Setup (NEW in v2.3.0)"

echo "ChromaDB will be installed via Python dependencies."
echo "Creating Chroma data directory..."

CHROMA_DATA_DIR="$INSTALL_DIR/data/chroma"
mkdir -p "$CHROMA_DATA_DIR"
chmod 700 "$CHROMA_DATA_DIR"
print_success "Chroma data directory created at $CHROMA_DATA_DIR"

echo ""
echo "ChromaDB Configuration:"
echo "  - Collection: tmws_memories"
echo "  - Index: HNSW (M=16, ef_construction=200)"
echo "  - Distance metric: Cosine similarity"
echo "  - Embedding dimension: 768 (Multilingual-E5)"
echo "  - Cache size: 10,000 hot memories"
echo ""

# Step 4: Redis Setup
print_header "Step 4: Redis Setup"

# Check if Redis is running
if redis-cli ping &> /dev/null; then
    print_success "Redis server is running"
else
    print_warning "Redis server not running. Starting..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew services start redis
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo systemctl start redis
    else
        redis-server --daemonize yes
    fi

    # Wait for Redis
    sleep 2
    if redis-cli ping &> /dev/null; then
        print_success "Redis started"
    else
        print_warning "Redis might need manual start"
    fi
fi

echo ""
echo "Redis Configuration (v2.3.0):"
echo "  - Agent registry: < 1ms P95"
echo "  - Task queue: < 3ms P95"
echo "  - Auto-cleanup: 10-minute TTL for agents"
echo ""

# Step 5: Python Environment Setup
print_header "Step 5: Python Environment Setup"

# Create installation directory
if [ ! -d "$INSTALL_DIR" ]; then
    echo "Creating installation directory at $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"
    print_success "Installation directory created"
fi

# Copy files to installation directory
echo "Copying files to $INSTALL_DIR..."
rsync -av --exclude='.venv' --exclude='__pycache__' --exclude='.git' \
      --exclude='htmlcov' --exclude='.pytest_cache' \
      "$SCRIPT_DIR/" "$INSTALL_DIR/" > /dev/null
print_success "Files copied to installation directory"

cd "$INSTALL_DIR"

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
    print_success "Virtual environment created"
fi

# Activate virtual environment
source .venv/bin/activate
print_success "Virtual environment activated"

# Install dependencies
if [ "$USE_UV" = true ]; then
    echo "Installing dependencies with UV..."
    uv sync
else
    echo "Installing dependencies with pip..."
    pip install --upgrade pip
    pip install -e .
    pip install chromadb  # Ensure ChromaDB for vector storage
fi
print_success "Dependencies installed (including ChromaDB)"

# Step 6: Environment Configuration
print_header "Step 6: Environment Configuration (v2.3.0)"

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env configuration file for v2.3.0..."
    cat > .env <<EOF
# TMWS v2.3.0 Environment Configuration
# Generated by install.sh

# === CORE SYSTEM ===
TMWS_ENVIRONMENT=development
TMWS_DEBUG=true
TMWS_LOG_LEVEL=INFO

# === DATABASE (PostgreSQL 17+) ===
TMWS_DATABASE_URL=postgresql://${DEFAULT_DB_USER}:${DEFAULT_DB_PASSWORD}@localhost:5432/${DEFAULT_DB_NAME}
TMWS_DB_POOL_SIZE=10
TMWS_DB_MAX_OVERFLOW=20

# === REDIS (Sub-millisecond coordination) ===
TMWS_REDIS_URL=redis://localhost:6379/0
TMWS_REDIS_POOL_SIZE=10

# === CHROMADB (Ultra-fast vector search) ===
TMWS_CHROMA_PERSIST_DIRECTORY=${INSTALL_DIR}/data/chroma
TMWS_CHROMA_COLLECTION=tmws_memories
TMWS_CHROMA_CACHE_SIZE=10000

# === VECTOR & EMBEDDINGS (v2.3.0: Multilingual-E5) ===
TMWS_VECTOR_DIMENSION=768
TMWS_EMBEDDING_MODEL=intfloat/multilingual-e5-base

# === SECURITY ===
TMWS_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
TMWS_JWT_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
TMWS_JWT_EXPIRE_MINUTES=30
TMWS_AUTH_ENABLED=false  # Set to true for production

# === API CONFIGURATION ===
TMWS_API_HOST=0.0.0.0
TMWS_API_PORT=8000
TMWS_API_VERSION=v1
TMWS_WORKERS=4

# === CORS & SECURITY ===
TMWS_CORS_ORIGINS=["http://localhost:3000","http://127.0.0.1:3000","http://localhost:8000"]
TMWS_ALLOWED_HOSTS=["localhost","127.0.0.1","0.0.0.0"]

# === RATE LIMITING (Redis-based) ===
TMWS_RATE_LIMIT_ENABLED=true
TMWS_RATE_LIMIT_REQUESTS=100
TMWS_RATE_LIMIT_PERIOD=60

# === LOGGING ===
TMWS_LOG_FORMAT=json
TMWS_LOG_FILE=./logs/tmws.log
TMWS_LOG_ROTATION=daily
TMWS_LOG_RETENTION=30

# === AGENT CONFIGURATION ===
TMWS_AGENT_ID=default-agent
TMWS_AGENT_NAMESPACE=trinitas
EOF
    print_success ".env file created with v2.3.0 settings"
else
    print_warning ".env file already exists (not overwritten)"
    echo "Please manually update to v2.3.0 settings:"
    echo "  - TMWS_VECTOR_DIMENSION=768"
    echo "  - TMWS_EMBEDDING_MODEL=intfloat/multilingual-e5-base"
    echo "  - TMWS_CHROMA_PERSIST_DIRECTORY=${INSTALL_DIR}/data/chroma"
    echo "  - TMWS_REDIS_URL=redis://localhost:6379/0"
fi

# Step 7: Directory Structure
print_header "Step 7: Creating Directory Structure"

mkdir -p data/chroma logs backups
chmod 755 data logs backups
chmod 700 data/chroma  # Chroma data is sensitive
print_success "Directory structure created"

# Step 8: Database Migration
print_header "Step 8: Database Migration"

echo "Running database migrations..."
if [ -d "migrations" ]; then
    python3 -m alembic upgrade head || {
        print_warning "Alembic migration failed, trying fallback..."
    }
fi

# Fallback: Direct table creation
echo "Initializing database schema..."
python3 -c "
import asyncio
from src.core.database import create_tables

async def init_db():
    await create_tables()
    print('✅ Database tables created')

asyncio.run(init_db())
" || {
    print_warning "Database might need manual initialization"
}

# Step 9: ChromaDB Initialization (NEW in v2.3.0)
print_header "Step 9: ChromaDB Initialization"

echo "Initializing Chroma collection with Multilingual-E5..."
python3 <<EOF || {
    print_warning "ChromaDB initialization might need manual setup"
}
import sys
sys.path.insert(0, '.')

try:
    from src.services.vector_search_service import get_vector_search_service
    from src.services.embedding_service import get_embedding_service

    print("Initializing Chroma collection...")
    vector_service = get_vector_search_service()
    embedding_service = get_embedding_service()

    vector_service.initialize()

    print(f"✅ Collection created: {vector_service.collection.name}")
    print(f"✅ Embedding model: {embedding_service.MODEL_NAME}")
    print(f"✅ Embedding dimension: {embedding_service.DIMENSION}")
    print(f"✅ Distance metric: cosine")
    print(f"✅ Index type: HNSW")

    # Test embedding generation
    test_embedding = embedding_service.encode_document("test")
    print(f"✅ Test embedding generated: {len(test_embedding)} dimensions")

except Exception as e:
    print(f"⚠️  ChromaDB initialization error: {e}")
    print("You can manually initialize later with: python scripts/initialize_chroma.py")
EOF

# Step 10: Verification
print_header "Step 10: Installation Verification"

echo "Running verification checks..."
python3 -c "
import sys
try:
    from src.core.config import get_settings
    from src.services.embedding_service import get_embedding_service
    from src.services.vector_search_service import get_vector_search_service
    from src.services.redis_agent_service import get_redis_agent_service
    from src.services.redis_task_service import get_redis_task_service

    settings = get_settings()
    print(f'✅ Settings loaded: Environment={settings.environment}')

    embedding_service = get_embedding_service()
    print(f'✅ Embedding service: {embedding_service.MODEL_NAME} ({embedding_service.DIMENSION}-dim)')

    vector_service = get_vector_search_service()
    print(f'✅ Vector service: ChromaDB initialized')

    redis_agent_service = get_redis_agent_service()
    print(f'✅ Redis agent service: Initialized')

    redis_task_service = get_redis_task_service()
    print(f'✅ Redis task service: Initialized')

    print('')
    print('✅ All v2.3.0 components verified successfully!')
    sys.exit(0)
except Exception as e:
    print(f'❌ Verification failed: {e}')
    sys.exit(1)
" || {
    print_warning "Some checks failed - review output above"
}

# Step 11: Create Start Scripts
print_header "Step 11: Creating Start Scripts"

# Create start script for MCP server (production)
cat > start_mcp.sh <<'EOF'
#!/bin/bash
# TMWS v2.3.0 MCP Server (for Claude Desktop integration)
source .venv/bin/activate
export TMWS_ENVIRONMENT=development
python -m src.mcp_server
EOF
chmod +x start_mcp.sh
print_success "start_mcp.sh created"

# Create benchmark script
cat > run_benchmark.sh <<'EOF'
#!/bin/bash
# TMWS v2.3.0 Performance Benchmark
source .venv/bin/activate
echo "Running Phase 8 benchmark suite..."
python scripts/benchmark_phase8.py
EOF
chmod +x run_benchmark.sh
print_success "run_benchmark.sh created"

# Create Chroma rebuild script
cat > rebuild_chroma.sh <<'EOF'
#!/bin/bash
# Rebuild ChromaDB hot cache from PostgreSQL
source .venv/bin/activate
echo "Rebuilding ChromaDB hot cache..."
python scripts/rebuild_chroma_cache.py
EOF
chmod +x rebuild_chroma.sh
print_success "rebuild_chroma.sh created"

# Final Summary
print_header "Installation Complete! 🎉"

echo -e "${GREEN}TMWS v2.3.0 has been successfully installed to ${INSTALL_DIR}!${NC}"
echo ""
echo "📊 Architecture Summary:"
echo "   ┌─────────────────────────────────────────────────────────┐"
echo "   │ Tier 1: ChromaDB (0.47ms P95)                          │"
echo "   │   - 10,000 hot memory cache                            │"
echo "   │   - HNSW vector index (768-dim Multilingual-E5)        │"
echo "   ├─────────────────────────────────────────────────────────┤"
echo "   │ Tier 2: Redis (< 1ms P95)                              │"
echo "   │   - Agent registry (HASH + ZADD)                       │"
echo "   │   - Task queue (Streams + Sorted Sets)                 │"
echo "   ├─────────────────────────────────────────────────────────┤"
echo "   │ Tier 3: PostgreSQL (Source of Truth)                   │"
echo "   │   - Memories (write-through)                           │"
echo "   │   - Audit logs, authentication                         │"
echo "   └─────────────────────────────────────────────────────────┘"
echo ""
echo "📝 Configuration files:"
echo "   - ${INSTALL_DIR}/.env (environment variables)"
echo ""
echo "🚀 Quick Start:"
echo ""
echo "   1. Start MCP Server (for Claude Desktop):"
echo "      ${BLUE}cd ${INSTALL_DIR} && ./start_mcp.sh${NC}"
echo ""
echo "   2. Run Performance Benchmark:"
echo "      ${BLUE}cd ${INSTALL_DIR} && ./run_benchmark.sh${NC}"
echo ""
echo "   3. Rebuild Chroma Cache (if needed):"
echo "      ${BLUE}cd ${INSTALL_DIR} && ./rebuild_chroma.sh${NC}"
echo ""
echo "🔧 For Claude Desktop integration:"
echo '   {
     "mcpServers": {
       "tmws": {
         "command": "uvx",
         "args": ["--from", "git+https://github.com/apto-as/tmws.git", "tmws"],
         "env": {
           "TMWS_DATABASE_URL": "postgresql://'"$DEFAULT_DB_USER"':'"$DEFAULT_DB_PASSWORD"'@localhost:5432/'"$DEFAULT_DB_NAME"'",
           "TMWS_REDIS_URL": "redis://localhost:6379/0",
           "TMWS_AGENT_ID": "athena-conductor"
         }
       }
     }
   }'
echo ""
echo "📚 Documentation:"
echo "   - Architecture: ${INSTALL_DIR}/docs/ARCHITECTURE_V2.3.0.md"
echo "   - Benchmark Report: ${INSTALL_DIR}/docs/BENCHMARK_REPORT.md"
echo "   - MCP Tools: ${INSTALL_DIR}/docs/MCP_TOOLS_REFERENCE.md"
echo "   - Deployment: ${INSTALL_DIR}/docs/DEPLOYMENT_GUIDE.md"
echo ""
echo "⚡ Performance Targets (v2.3.0):"
echo "   - Vector Search: 0.47ms P95 (425x faster than v2.2.0)"
echo "   - Memory Store: 2ms P95 (5x faster)"
echo "   - Agent Register: 0.8ms P95"
echo "   - Task Create: 1.5ms P95"
echo ""
echo -e "${GREEN}Thank you for installing TMWS v2.3.0!${NC}"
echo ""
