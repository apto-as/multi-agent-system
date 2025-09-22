#!/bin/bash

# TMWS Multi-Instance Setup Script
# Sets up database-level sharing for multiple Claude Code instances

set -e

echo "==================================================="
echo "TMWS Multi-Instance Setup - Database-Level Sharing"
echo "==================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if PostgreSQL is running
if ! pg_isready -q; then
    echo -e "${RED}PostgreSQL is not running. Please start PostgreSQL first.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ PostgreSQL is running${NC}"

# Database configuration
DB_NAME="${TMWS_DB_NAME:-tmws}"
DB_USER="${TMWS_DB_USER:-tmws_user}"
DB_PASS="${TMWS_DB_PASS:-tmws_password}"

echo ""
echo "Database Configuration:"
echo "  Database: $DB_NAME"
echo "  User: $DB_USER"
echo ""

# Create database if not exists
echo "Setting up database..."
createdb "$DB_NAME" 2>/dev/null || echo "  Database already exists"

# Create user if not exists
psql postgres -tc "SELECT 1 FROM pg_user WHERE usename = '$DB_USER'" | grep -q 1 || {
    echo "  Creating user $DB_USER..."
    psql postgres -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
}

# Grant privileges
echo "  Granting privileges..."
psql postgres -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"

# Install pgvector extension
echo "Installing pgvector extension..."
PGPASSWORD=$DB_PASS psql -U $DB_USER -d $DB_NAME -c "CREATE EXTENSION IF NOT EXISTS vector;" 2>/dev/null || {
    echo -e "${YELLOW}  Note: pgvector extension may require superuser privileges${NC}"
    psql -d $DB_NAME -c "CREATE EXTENSION IF NOT EXISTS vector;"
}

PGPASSWORD=$DB_PASS psql -U $DB_USER -d $DB_NAME -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;" 2>/dev/null || {
    psql -d $DB_NAME -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;"
}

echo -e "${GREEN}✓ Database extensions installed${NC}"

# Run migrations
echo ""
echo "Running migrations..."
cd "$(dirname "$0")/.."

# Check if alembic is installed
if ! command -v alembic &> /dev/null; then
    echo "Installing alembic..."
    pip install alembic
fi

# Set database URL for migrations
export DATABASE_URL="postgresql://$DB_USER:$DB_PASS@localhost:5432/$DB_NAME"

# Run migrations
alembic upgrade head

echo -e "${GREEN}✓ Migrations completed${NC}"

# Create example .env file if not exists
if [ ! -f .env ]; then
    echo ""
    echo "Creating .env file..."
    cat > .env << EOF
# TMWS Multi-Instance Configuration

# Database (shared by all instances)
TMWS_DATABASE_URL=postgresql://$DB_USER:$DB_PASS@localhost:5432/$DB_NAME

# Instance Configuration (unique per Claude Code terminal)
# Change these for each instance:
TMWS_AGENT_ID=athena-conductor-1
TMWS_AGENT_NAMESPACE=trinitas

# Performance Settings
TMWS_CACHE_TTL=60
TMWS_POOL_SIZE=10
TMWS_POOL_MAX_SIZE=20

# Security
TMWS_SECRET_KEY=$(openssl rand -hex 32)

# Logging
TMWS_LOG_LEVEL=INFO
EOF

    echo -e "${GREEN}✓ .env file created${NC}"
fi

# Create Claude Code configurations
echo ""
echo "Creating Claude Code configuration examples..."

mkdir -p config/claude_code

# Instance 1 config
cat > config/claude_code/instance1.json << 'EOF'
{
  "mcpServers": {
    "tmws": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/apto-as/tmws.git", "tmws"],
      "env": {
        "TMWS_AGENT_ID": "athena-conductor-1",
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws"
      }
    }
  }
}
EOF

# Instance 2 config
cat > config/claude_code/instance2.json << 'EOF'
{
  "mcpServers": {
    "tmws": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/apto-as/tmws.git", "tmws"],
      "env": {
        "TMWS_AGENT_ID": "artemis-optimizer-1",
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws"
      }
    }
  }
}
EOF

# Instance 3 config
cat > config/claude_code/instance3.json << 'EOF'
{
  "mcpServers": {
    "tmws": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/apto-as/tmws.git", "tmws"],
      "env": {
        "TMWS_AGENT_ID": "hestia-auditor-1",
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws"
      }
    }
  }
}
EOF

echo -e "${GREEN}✓ Claude Code configurations created${NC}"

# Test database connection
echo ""
echo "Testing database connection..."
PGPASSWORD=$DB_PASS psql -U $DB_USER -d $DB_NAME -c "SELECT version();" > /dev/null 2>&1 && {
    echo -e "${GREEN}✓ Database connection successful${NC}"
} || {
    echo -e "${RED}✗ Database connection failed${NC}"
    exit 1
}

# Check tables
echo "Checking multi-instance tables..."
TABLES=$(PGPASSWORD=$DB_PASS psql -U $DB_USER -d $DB_NAME -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('agent_instances', 'shared_memories', 'task_coordination', 'sync_events', 'cache_invalidations');")

if [ "$TABLES" -ge 5 ]; then
    echo -e "${GREEN}✓ All multi-instance tables present${NC}"
else
    echo -e "${YELLOW}⚠ Some tables may be missing. Run migrations again.${NC}"
fi

echo ""
echo "==================================================="
echo -e "${GREEN}Setup Complete!${NC}"
echo "==================================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Copy a Claude Code configuration to your Claude Code settings:"
echo "   cat config/claude_code/instance1.json"
echo ""
echo "2. Start Claude Code in terminal 1 with instance1 config"
echo ""
echo "3. Start Claude Code in terminal 2 with instance2 config"
echo "   (Remember to change TMWS_AGENT_ID for each instance)"
echo ""
echo "4. All instances will share memories, tasks, and workflows!"
echo ""
echo "Database URL for all instances:"
echo "  postgresql://$DB_USER:$DB_PASS@localhost:5432/$DB_NAME"
echo ""
echo "==================================================="