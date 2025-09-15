#!/bin/bash
# Quick Test Validation for TMWS Phase 1
# Runs essential tests for rapid development feedback

set -e

echo "🚀 TMWS Phase 1 - Quick Test Validation"
echo "======================================"

# Set test environment
export TMWS_ENVIRONMENT=test
export TMWS_SECRET_KEY="quick_test_secret_key_for_development_validation_32_chars"
export TMWS_AUTH_ENABLED=true

# Use SQLite for quick testing
export TMWS_DATABASE_URL="sqlite:///./test_quick.db"

echo "📋 Running essential tests (fast execution)..."

# Run critical tests only
python -m pytest \
    tests/unit/test_auth_service.py \
    tests/unit/test_jwt_service.py \
    tests/security/test_authentication.py::TestPasswordSecurity \
    tests/security/test_authentication.py::TestJWTSecurity \
    tests/integration/test_api_authentication.py::TestLoginFlow \
    -v \
    -m "not slow" \
    --tb=short \
    --timeout=60

echo "✅ Quick validation completed!"
echo "💡 For comprehensive testing, run: python scripts/test-runner.py"