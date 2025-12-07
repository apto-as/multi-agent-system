#!/bin/bash

#############################################
# TMWS Quick Database Setup for MCP
#
# One-command setup for Claude Desktop users
# Usage: ./setup_db_quick.sh
#############################################

set -e

echo "🚀 TMWS Quick Database Setup"
echo "============================"
echo ""

# Check if PostgreSQL is running
if ! pg_isready -q; then
    echo "❌ PostgreSQL is not running"
    echo "Please start PostgreSQL first:"
    echo "  macOS: brew services start postgresql@15"
    echo "  Linux: sudo systemctl start postgresql"
    exit 1
fi

echo "✅ PostgreSQL is running"

# Create database and user
echo "📦 Setting up database..."
psql -U postgres <<EOF 2>/dev/null || sudo -u postgres psql <<EOF
-- Create user if not exists
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_user WHERE usename = 'tmws_user') THEN
        CREATE USER tmws_user WITH PASSWORD 'tmws_password';
    END IF;
END\$\$;

-- Create database if not exists
SELECT 'CREATE DATABASE tmws OWNER tmws_user'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'tmws')\gexec

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE tmws TO tmws_user;

-- Connect to tmws database
\c tmws

-- Create extensions
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant schema privileges
GRANT ALL ON SCHEMA public TO tmws_user;
EOF

echo "✅ Database created successfully"

# Run migrations if alembic is available
if command -v alembic &> /dev/null; then
    echo "📝 Running migrations..."
    export TMWS_DATABASE_URL="postgresql://tmws_user:tmws_password@localhost:5432/tmws"

    if [ -f "alembic.ini" ]; then
        alembic upgrade head 2>/dev/null || echo "⚠️  Migrations may already be applied"
    else
        echo "⚠️  alembic.ini not found - skipping migrations"
    fi
else
    echo "⚠️  Alembic not installed - skipping migrations"
    echo "   Install with: pip install alembic sqlalchemy asyncpg"
fi

echo ""
echo "✨ Setup Complete!"
echo "=================="
echo ""
echo "Database URL:"
echo "  postgresql://tmws_user:tmws_password@localhost:5432/tmws"
echo ""
echo "Add to Claude Desktop config:"
echo '  "env": {'
echo '    "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws"'
echo '  }'
echo ""
echo "Test with:"
echo "  uvx --from git+https://github.com/apto-as/tmws.git@v2.2.0 tmws"
echo ""