#!/bin/bash

# Phase 2E-3 MCP Server Startup Test
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

source .test-licenses.txt
SECRET_KEY="5d0789051bae899f8897f9e5c4fbcf66eb5a7c6aac2d3bf296614d74cdbad26f"

echo "========================================"
echo "Phase 2E-3: MCP Server Startup Test"
echo "========================================"
echo ""

echo "Test 1: Check tmws-mcp-server binary exists..."
docker run --rm \
  -e TMWS_DATABASE_URL="sqlite+aiosqlite:///:memory:" \
  -e TMWS_SECRET_KEY="$SECRET_KEY" \
  -e TMWS_ENVIRONMENT="development" \
  tmws:v2.4.0-test \
  which tmws-mcp-server && echo -e "${GREEN}✅ Test 1: PASSED - Binary found${NC}" || echo -e "${RED}❌ Test 1: FAILED - Binary not found${NC}"

echo ""
echo "Test 2: Check Python module is importable..."
docker run --rm \
  -e TMWS_DATABASE_URL="sqlite+aiosqlite:///:memory:" \
  -e TMWS_SECRET_KEY="$SECRET_KEY" \
  -e TMWS_ENVIRONMENT="development" \
  tmws:v2.4.0-test \
  python3 -c "import src.mcp_server; print('✅ MCP server module imported successfully')" && \
  echo -e "${GREEN}✅ Test 2: PASSED - Module importable${NC}" || echo -e "${RED}❌ Test 2: FAILED${NC}"

echo ""
echo "Test 3: Check license service is available..."
docker run --rm \
  -e TMWS_LICENSE_KEY="$ENTERPRISE_LICENSE" \
  -e TMWS_DATABASE_URL="sqlite+aiosqlite:///:memory:" \
  -e TMWS_SECRET_KEY="$SECRET_KEY" \
  -e TMWS_ENVIRONMENT="development" \
  tmws:v2.4.0-test \
  python3 -c "
from src.services.license_service import LicenseService
print('✅ LicenseService available')
" && echo -e "${GREEN}✅ Test 3: PASSED - License service available${NC}" || echo -e "${RED}❌ Test 3: FAILED${NC}"

echo ""
echo "========================================"
echo "MCP Server Startup: Tests Complete"
echo "========================================"
