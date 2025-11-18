#!/bin/bash
# Trinitas Hooks Verification Script v2.2.4
# Validates UserPromptSubmit hook implementation

set -e

echo "=== Trinitas Hooks Verification ==="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test 1: Check settings.json
echo "Test 1: Checking settings.json..."
if jq . ~/.claude/hooks/settings.json > /dev/null 2>&1; then
    echo -e "${GREEN}✓ settings.json is valid JSON${NC}"
else
    echo -e "${RED}✗ settings.json has syntax errors${NC}"
    exit 1
fi

# Test 2: Check UserPromptSubmit registration
echo "Test 2: Checking UserPromptSubmit hook registration..."
if jq -e '.hooks.UserPromptSubmit' ~/.claude/hooks/settings.json > /dev/null 2>&1; then
    echo -e "${GREEN}✓ UserPromptSubmit hook is registered${NC}"
else
    echo -e "${RED}✗ UserPromptSubmit hook is NOT registered${NC}"
    echo -e "${YELLOW}Action required: Add UserPromptSubmit to settings.json${NC}"
    exit 1
fi

# Test 3: Check dynamic_context_loader.py exists
echo "Test 3: Checking dynamic_context_loader.py..."
if [ -f ~/.claude/hooks/core/dynamic_context_loader.py ]; then
    echo -e "${GREEN}✓ dynamic_context_loader.py exists${NC}"
else
    echo -e "${RED}✗ dynamic_context_loader.py not found${NC}"
    exit 1
fi

# Test 4: Functional test - Artemis detection
echo "Test 4: Testing Artemis persona detection..."
OUTPUT=$(echo '{"prompt":{"text":"optimize database performance"}}' | \
    python3 ~/.claude/hooks/core/dynamic_context_loader.py 2>/dev/null)

if echo "$OUTPUT" | jq -e '.addedContext[0].text' | grep -q "Artemis"; then
    echo -e "${GREEN}✓ Artemis persona detected correctly${NC}"
else
    echo -e "${RED}✗ Artemis persona detection failed${NC}"
    exit 1
fi

# Test 5: Functional test - Hestia detection
echo "Test 5: Testing Hestia persona detection..."
OUTPUT=$(echo '{"prompt":{"text":"security audit for XSS"}}' | \
    python3 ~/.claude/hooks/core/dynamic_context_loader.py 2>/dev/null)

if echo "$OUTPUT" | jq -e '.addedContext[0].text' | grep -q "Hestia"; then
    echo -e "${GREEN}✓ Hestia persona detected correctly${NC}"
else
    echo -e "${RED}✗ Hestia persona detection failed${NC}"
    exit 1
fi

# Test 6: Performance test
echo "Test 6: Testing performance (<20ms target)..."
START=$(python3 -c 'import time; print(int(time.time() * 1000))')
echo '{"prompt":{"text":"optimize performance"}}' | \
    python3 ~/.claude/hooks/core/dynamic_context_loader.py > /dev/null 2>&1
END=$(python3 -c 'import time; print(int(time.time() * 1000))')
DURATION=$((END - START))

if [ $DURATION -lt 20 ]; then
    echo -e "${GREEN}✓ Performance: ${DURATION}ms (within target)${NC}"
else
    echo -e "${YELLOW}⚠ Performance: ${DURATION}ms (exceeds 20ms target)${NC}"
fi

# Test 7: Token count verification
echo "Test 7: Testing token output size..."
OUTPUT=$(echo '{"prompt":{"text":"optimize database performance"}}' | \
    python3 ~/.claude/hooks/core/dynamic_context_loader.py 2>/dev/null)

CHARS=$(echo "$OUTPUT" | jq -r '.addedContext[0].text' | wc -c | tr -d ' ')
TOKENS=$((CHARS / 4))

if [ $TOKENS -lt 600 ]; then
    echo -e "${GREEN}✓ Token count: ~${TOKENS} tokens (within 600 target)${NC}"
else
    echo -e "${YELLOW}⚠ Token count: ~${TOKENS} tokens (exceeds 600 target)${NC}"
fi

# Test 8: Check SessionStart status
echo "Test 8: Checking SessionStart hook status..."
if jq -e '.hooks.SessionStart' ~/.claude/hooks/settings.json > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠ SessionStart hook is still registered${NC}"
    echo -e "${YELLOW}Recommendation: Remove SessionStart for optimal performance${NC}"
else
    echo -e "${GREEN}✓ SessionStart hook removed (optimal configuration)${NC}"
fi

echo ""
echo "=== Verification Complete ==="
echo ""
echo "Summary:"
echo "  - UserPromptSubmit: Registered and functional"
echo "  - Performance: ${DURATION}ms"
echo "  - Token output: ~${TOKENS} tokens"
echo ""

if jq -e '.hooks.SessionStart' ~/.claude/hooks/settings.json > /dev/null 2>&1; then
    echo -e "${YELLOW}Next step: Remove SessionStart hook for 96% token reduction${NC}"
else
    echo -e "${GREEN}Configuration is optimal!${NC}"
fi
