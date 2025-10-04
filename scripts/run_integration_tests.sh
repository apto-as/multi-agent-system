#!/bin/bash
# Integration Test Automation for TMWS v2.2.0 Pattern Execution Service
# Coordinator: Eris (Tactical Coordinator)
#
# This script orchestrates comprehensive integration testing across:
# - Multi-agent concurrency (50+ sessions)
# - WebSocket MCP integration
# - Database (PostgreSQL + pgvector)
# - Cache (Redis cluster)
# - Performance benchmarks (100+ RPS)
# - Error recovery scenarios

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_ENV="${TEST_ENV:-integration}"
PARALLEL_WORKERS="${PARALLEL_WORKERS:-4}"
TIMEOUT="${TIMEOUT:-600}"  # 10 minutes
REPORT_DIR="./test-reports/integration"

# Create report directory
mkdir -p "$REPORT_DIR"

echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  TMWS v2.2.0 Pattern Execution Integration Tests${NC}"
echo -e "${BLUE}  Coordinator: Eris (Tactical Coordinator)${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo ""

# Step 1: Pre-flight checks
echo -e "${YELLOW}[1/7] Running pre-flight checks...${NC}"

check_service() {
    local service=$1
    local check_cmd=$2

    echo -n "  Checking $service... "
    if eval "$check_cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}✗${NC}"
        return 1
    fi
}

PREFLIGHT_FAILED=0

# Check PostgreSQL
if ! check_service "PostgreSQL" "psql -h localhost -U postgres -c 'SELECT 1' > /dev/null 2>&1"; then
    echo -e "${RED}  PostgreSQL is not running. Start with: docker-compose up -d postgres${NC}"
    PREFLIGHT_FAILED=1
fi

# Check pgvector extension
if ! check_service "pgvector" "psql -h localhost -U postgres -d tmws -c 'SELECT 1 FROM pg_extension WHERE extname = \"vector\"' | grep -q 1"; then
    echo -e "${RED}  pgvector extension not installed. Run: psql -U postgres -d tmws -c 'CREATE EXTENSION vector'${NC}"
    PREFLIGHT_FAILED=1
fi

# Check Redis
if ! check_service "Redis" "redis-cli ping"; then
    echo -e "${RED}  Redis is not running. Start with: docker-compose up -d redis${NC}"
    PREFLIGHT_FAILED=1
fi

# Check Python environment
if ! check_service "Python venv" "python -c 'import pytest, asyncio, sqlalchemy, redis'"; then
    echo -e "${RED}  Python dependencies missing. Run: pip install -r requirements.txt${NC}"
    PREFLIGHT_FAILED=1
fi

if [ $PREFLIGHT_FAILED -eq 1 ]; then
    echo -e "${RED}Pre-flight checks failed. Fix the issues above before running tests.${NC}"
    exit 1
fi

echo -e "${GREEN}All pre-flight checks passed!${NC}\n"

# Step 2: Setup test environment
echo -e "${YELLOW}[2/7] Setting up test environment...${NC}"

# Set environment variables
export TMWS_ENVIRONMENT=testing
export TMWS_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/tmws_test"
export TMWS_REDIS_URL="redis://localhost:6379/1"  # Use test DB
export TMWS_AUTH_ENABLED=false  # Disable for integration tests
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Create test database if needed
psql -h localhost -U postgres -c "DROP DATABASE IF EXISTS tmws_test" > /dev/null 2>&1 || true
psql -h localhost -U postgres -c "CREATE DATABASE tmws_test" > /dev/null 2>&1
psql -h localhost -U postgres -d tmws_test -c "CREATE EXTENSION IF NOT EXISTS vector" > /dev/null 2>&1

echo -e "  ${GREEN}✓${NC} Test database created"
echo -e "  ${GREEN}✓${NC} Environment configured\n"

# Step 3: Run multi-agent concurrency tests
echo -e "${YELLOW}[3/7] Running multi-agent concurrency tests (50+ agents)...${NC}"

pytest tests/integration/test_pattern_integration.py::TestMultiAgentConcurrency \
    -v \
    --tb=short \
    --timeout=$TIMEOUT \
    --maxfail=3 \
    --junit-xml="$REPORT_DIR/concurrency-junit.xml" \
    --html="$REPORT_DIR/concurrency-report.html" \
    --self-contained-html \
    2>&1 | tee "$REPORT_DIR/concurrency.log"

CONCURRENCY_EXIT=$?

if [ $CONCURRENCY_EXIT -eq 0 ]; then
    echo -e "${GREEN}✓ Multi-agent concurrency tests passed${NC}\n"
else
    echo -e "${RED}✗ Multi-agent concurrency tests failed${NC}\n"
fi

# Step 4: Run WebSocket MCP integration tests
echo -e "${YELLOW}[4/7] Running WebSocket MCP integration tests...${NC}"

pytest tests/integration/test_pattern_integration.py::TestWebSocketMCPIntegration \
    -v \
    --tb=short \
    --timeout=$TIMEOUT \
    --junit-xml="$REPORT_DIR/websocket-junit.xml" \
    --html="$REPORT_DIR/websocket-report.html" \
    --self-contained-html \
    2>&1 | tee "$REPORT_DIR/websocket.log"

WEBSOCKET_EXIT=$?

if [ $WEBSOCKET_EXIT -eq 0 ]; then
    echo -e "${GREEN}✓ WebSocket MCP integration tests passed${NC}\n"
else
    echo -e "${RED}✗ WebSocket MCP integration tests failed${NC}\n"
fi

# Step 5: Run database integration tests
echo -e "${YELLOW}[5/7] Running database integration tests (PostgreSQL + pgvector)...${NC}"

pytest tests/integration/test_pattern_integration.py::TestDatabaseIntegration \
    -v \
    --tb=short \
    --timeout=$TIMEOUT \
    --junit-xml="$REPORT_DIR/database-junit.xml" \
    --html="$REPORT_DIR/database-report.html" \
    --self-contained-html \
    2>&1 | tee "$REPORT_DIR/database.log"

DATABASE_EXIT=$?

if [ $DATABASE_EXIT -eq 0 ]; then
    echo -e "${GREEN}✓ Database integration tests passed${NC}\n"
else
    echo -e "${RED}✗ Database integration tests failed${NC}\n"
fi

# Step 6: Run performance integration tests
echo -e "${YELLOW}[6/7] Running performance integration tests (100+ RPS)...${NC}"

pytest tests/integration/test_pattern_integration.py::TestPerformanceIntegration \
    -v \
    --tb=short \
    --timeout=$TIMEOUT \
    --junit-xml="$REPORT_DIR/performance-junit.xml" \
    --html="$REPORT_DIR/performance-report.html" \
    --self-contained-html \
    --benchmark-only \
    2>&1 | tee "$REPORT_DIR/performance.log"

PERFORMANCE_EXIT=$?

if [ $PERFORMANCE_EXIT -eq 0 ]; then
    echo -e "${GREEN}✓ Performance integration tests passed${NC}\n"
else
    echo -e "${RED}✗ Performance integration tests failed${NC}\n"
fi

# Step 7: Run error recovery tests
echo -e "${YELLOW}[7/7] Running error recovery integration tests...${NC}"

pytest tests/integration/test_pattern_integration.py::TestErrorRecoveryIntegration \
    -v \
    --tb=short \
    --timeout=$TIMEOUT \
    --junit-xml="$REPORT_DIR/error-recovery-junit.xml" \
    --html="$REPORT_DIR/error-recovery-report.html" \
    --self-contained-html \
    2>&1 | tee "$REPORT_DIR/error-recovery.log"

ERROR_RECOVERY_EXIT=$?

if [ $ERROR_RECOVERY_EXIT -eq 0 ]; then
    echo -e "${GREEN}✓ Error recovery tests passed${NC}\n"
else
    echo -e "${RED}✗ Error recovery tests failed${NC}\n"
fi

# Generate summary report
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Integration Test Summary${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo ""

TOTAL_FAILED=0

print_result() {
    local name=$1
    local exit_code=$2

    if [ $exit_code -eq 0 ]; then
        echo -e "  ${GREEN}✓${NC} $name"
    else
        echo -e "  ${RED}✗${NC} $name"
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
}

print_result "Multi-Agent Concurrency" $CONCURRENCY_EXIT
print_result "WebSocket MCP Integration" $WEBSOCKET_EXIT
print_result "Database Integration" $DATABASE_EXIT
print_result "Performance Integration" $PERFORMANCE_EXIT
print_result "Error Recovery" $ERROR_RECOVERY_EXIT

echo ""
echo -e "Reports saved to: ${BLUE}$REPORT_DIR/${NC}"
echo ""

# Extract key metrics from logs
echo -e "${BLUE}Key Metrics:${NC}"

extract_metric() {
    local file=$1
    local pattern=$2
    local description=$3

    if [ -f "$file" ]; then
        local value=$(grep -o "$pattern" "$file" | head -1 || echo "N/A")
        echo -e "  $description: ${GREEN}$value${NC}"
    fi
}

extract_metric "$REPORT_DIR/concurrency.log" "Success rate: [0-9.]*%" "Concurrency Success Rate"
extract_metric "$REPORT_DIR/performance.log" "Actual RPS: [0-9.]*" "Throughput"
extract_metric "$REPORT_DIR/performance.log" "P95 latency: [0-9.]*ms" "P95 Latency"
extract_metric "$REPORT_DIR/performance.log" "Token reduction: [0-9.]*%" "Token Reduction"

echo ""

# Cleanup
echo -e "${YELLOW}Cleaning up test environment...${NC}"
# Keep test database for inspection, but clear Redis test DB
redis-cli -n 1 FLUSHDB > /dev/null 2>&1 || true
echo -e "${GREEN}✓ Cleanup complete${NC}\n"

# Final exit code
if [ $TOTAL_FAILED -eq 0 ]; then
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  ✓ ALL INTEGRATION TESTS PASSED${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    exit 0
else
    echo -e "${RED}═══════════════════════════════════════════════════════${NC}"
    echo -e "${RED}  ✗ $TOTAL_FAILED TEST SUITE(S) FAILED${NC}"
    echo -e "${RED}═══════════════════════════════════════════════════════${NC}"
    exit 1
fi
