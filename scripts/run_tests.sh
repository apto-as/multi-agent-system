#!/bin/bash
# TMWS Test Runner Script
# Supports both SQLite (default) and PostgreSQL testing modes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN} $1${NC}"
    echo -e "${GREEN}========================================${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Check if PostgreSQL container is running
check_postgresql() {
    if docker-compose -f docker-compose.test.yml ps postgres-test | grep -q "Up"; then
        echo "PostgreSQL test container is running"
        return 0
    else
        echo "PostgreSQL test container is not running"
        return 1
    fi
}

# Start PostgreSQL container if needed
start_postgresql() {
    print_header "Starting PostgreSQL Test Container"
    docker-compose -f docker-compose.test.yml up -d postgres-test

    # Wait for PostgreSQL to be ready
    echo "Waiting for PostgreSQL to be ready..."
    for i in {1..30}; do
        if docker exec tmws-postgres-test pg_isready -U tmws_user -d tmws_test; then
            print_success "PostgreSQL is ready"
            # Ensure pgvector extension is installed
            docker exec tmws-postgres-test psql -U tmws_user -d tmws_test -c "CREATE EXTENSION IF NOT EXISTS vector;" > /dev/null 2>&1
            return 0
        fi
        echo "Waiting... ($i/30)"
        sleep 2
    done

    print_error "PostgreSQL failed to start"
    return 1
}

# Run SQLite tests
run_sqlite_tests() {
    print_header "Running SQLite Tests"
    export TEST_USE_POSTGRESQL=false
    export TMWS_DATABASE_URL="sqlite+aiosqlite:///:memory:"

    echo "Running unit tests..."
    pytest tests/unit/ -v --tb=short -m "not postgresql"

    echo "Running basic integration tests..."
    pytest tests/integration/ -v --tb=short -m "not postgresql and not vector"
}

# Run PostgreSQL tests
run_postgresql_tests() {
    print_header "Running PostgreSQL Tests"

    if ! check_postgresql; then
        if ! start_postgresql; then
            print_error "Cannot run PostgreSQL tests - container failed to start"
            return 1
        fi
    fi

    export TEST_USE_POSTGRESQL=true
    export TMWS_DATABASE_URL="postgresql+asyncpg://tmws_user:tmws_password@localhost:5432/tmws_test"

    echo "Running PostgreSQL integration tests..."
    pytest tests/integration/ -v --tb=short -m "postgresql or vector"

    echo "Running memory vector tests..."
    pytest tests/integration/test_memory_vector.py -v --tb=short

    echo "Running memory service integration tests..."
    pytest tests/integration/test_memory_service.py -v --tb=short
}

# Run security tests
run_security_tests() {
    print_header "Running Security Tests (Hestia Domain)"
    export TEST_USE_POSTGRESQL=false
    pytest tests/security/ -v --tb=short -m "security"
}

# Run performance tests
run_performance_tests() {
    print_header "Running Performance Tests"
    if check_postgresql; then
        export TEST_USE_POSTGRESQL=true
        export TMWS_DATABASE_URL="postgresql+asyncpg://tmws_user:tmws_password@localhost:5432/tmws_test"
    else
        print_warning "PostgreSQL not available, running performance tests with SQLite"
        export TEST_USE_POSTGRESQL=false
    fi

    pytest tests/ -v --tb=short -m "performance" --durations=10
}

# Run coverage report
run_coverage() {
    print_header "Generating Coverage Report"
    export TEST_USE_POSTGRESQL=false

    # Run tests with coverage
    pytest tests/ --cov=src --cov-report=html --cov-report=xml --cov-report=term-missing \
           --cov-fail-under=80 -m "not slow and not postgresql"

    print_success "Coverage report generated in htmlcov/"
}

# Main function
main() {
    local mode=${1:-"all"}

    case $mode in
        "sqlite")
            run_sqlite_tests
            ;;
        "postgresql")
            run_postgresql_tests
            ;;
        "security")
            run_security_tests
            ;;
        "performance")
            run_performance_tests
            ;;
        "coverage")
            run_coverage
            ;;
        "all")
            print_header "Running Complete Test Suite"
            run_sqlite_tests
            echo ""
            run_postgresql_tests
            echo ""
            run_security_tests
            echo ""
            run_coverage
            ;;
        "help"|"-h"|"--help")
            echo "TMWS Test Runner"
            echo ""
            echo "Usage: $0 [mode]"
            echo ""
            echo "Modes:"
            echo "  sqlite      - Run SQLite-based tests only"
            echo "  postgresql  - Run PostgreSQL integration tests"
            echo "  security    - Run security tests (Hestia domain)"
            echo "  performance - Run performance tests"
            echo "  coverage    - Generate coverage report"
            echo "  all         - Run complete test suite (default)"
            echo "  help        - Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0              # Run all tests"
            echo "  $0 postgresql   # Run PostgreSQL tests only"
            echo "  $0 coverage     # Generate coverage report"
            ;;
        *)
            print_error "Unknown mode: $mode"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"