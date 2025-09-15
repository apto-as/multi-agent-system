#!/bin/bash
# Security Test Suite for TMWS Phase 1
# Comprehensive security validation led by Hestia

set -e

echo "🔒 TMWS Phase 1 - Security Test Suite (Hestia Domain)"
echo "=================================================="

# Set test environment  
export TMWS_ENVIRONMENT=test
export TMWS_SECRET_KEY="security_test_secret_key_for_hestia_validation_suite"
export TMWS_AUTH_ENABLED=true
export TMWS_DATABASE_URL="${TMWS_DATABASE_URL:-postgresql://postgres:postgres@localhost:5432/tmws_test}"

echo "🛡️  Initializing security test environment..."

# Check database connectivity
if command -v pg_isready >/dev/null 2>&1; then
    if pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
        echo "✅ PostgreSQL available for security testing"
    else
        echo "⚠️  PostgreSQL not available, using SQLite"
        export TMWS_DATABASE_URL="sqlite:///./test_security.db"
    fi
else
    echo "⚠️  pg_isready not found, using SQLite"  
    export TMWS_DATABASE_URL="sqlite:///./test_security.db"
fi

# Run database migrations
echo "📊 Setting up test database..."
python -m alembic upgrade head

echo "🔍 Running comprehensive security tests..."

# Run all security tests with detailed reporting
python -m pytest tests/security/ \
    -v \
    -m security \
    --tb=short \
    --html=security_test_report.html \
    --self-contained-html \
    --junitxml=security_junit.xml \
    --timeout=900

echo ""
echo "🎯 Security Test Summary"
echo "======================="

# Parse and display security test results
if [ -f security_junit.xml ]; then
    python3 -c "
import xml.etree.ElementTree as ET
try:
    tree = ET.parse('security_junit.xml')
    root = tree.getroot()
    
    total = 0
    passed = 0
    failed = 0
    
    for testsuite in root.findall('testsuite'):
        suite_tests = int(testsuite.get('tests', 0))
        suite_failures = int(testsuite.get('failures', 0))
        suite_errors = int(testsuite.get('errors', 0))
        
        total += suite_tests
        failed += suite_failures + suite_errors
    
    passed = total - failed
    success_rate = (passed / total * 100) if total > 0 else 0
    
    print(f'Total Security Tests: {total}')
    print(f'Passed: {passed}')
    print(f'Failed: {failed}') 
    print(f'Success Rate: {success_rate:.1f}%')
    
    if failed == 0:
        print('\\n🎉 All security tests passed! System is secure.')
        exit(0)
    else:
        print(f'\\n❌ {failed} security test(s) failed. Review required.')
        exit(1)
        
except Exception as e:
    print(f'Error parsing results: {e}')
    exit(1)
"
else
    echo "❌ No security test results found"
    exit 1
fi