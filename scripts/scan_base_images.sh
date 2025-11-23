#!/bin/bash
# ========================================
# Local Base Image Security Scanner
# ========================================
# V-5 Phase 1: Supply Chain Hardening (CVSS 7.1 HIGH mitigation)
# Purpose: Scan Docker base images for CRITICAL/HIGH vulnerabilities before build
# Usage: ./scripts/scan_base_images.sh
# Requirements: docker, trivy
# ========================================

set -e  # Exit on error
set -u  # Exit on undefined variable

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOCKERFILE="Dockerfile"
SEVERITY="CRITICAL,HIGH"
EXIT_CODE=1  # Fail if vulnerabilities found

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}🔍 Pre-Build Security Scan: Base Images${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check prerequisites
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ ERROR: docker is not installed${NC}"
    echo "Install: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v trivy &> /dev/null; then
    echo -e "${RED}❌ ERROR: trivy is not installed${NC}"
    echo "Install: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
    exit 1
fi

# Check if Dockerfile exists
if [ ! -f "$DOCKERFILE" ]; then
    echo -e "${RED}❌ ERROR: Dockerfile not found${NC}"
    echo "Expected location: ./$DOCKERFILE"
    exit 1
fi

# Extract base images from Dockerfile
echo -e "${BLUE}📦 Extracting base images from Dockerfile...${NC}"
BASE_IMAGES=$(grep "^FROM" "$DOCKERFILE" | awk '{print $2}')

if [ -z "$BASE_IMAGES" ]; then
    echo -e "${RED}❌ ERROR: No base images found in Dockerfile${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}Base images to scan:${NC}"
for IMAGE in $BASE_IMAGES; do
    echo "  • $IMAGE"
done
echo ""

# Scan each base image
TOTAL_IMAGES=0
PASSED_IMAGES=0
FAILED_IMAGES=0

for IMAGE in $BASE_IMAGES; do
    TOTAL_IMAGES=$((TOTAL_IMAGES + 1))

    echo "========================================="
    echo -e "${BLUE}📦 Scanning: $IMAGE${NC}"
    echo "========================================="

    # Pull image if not exists locally
    echo "Pulling image..."
    docker pull "$IMAGE" 2>/dev/null || true

    # Run Trivy scan
    echo "Running security scan (CRITICAL,HIGH)..."

    if trivy image \
        --severity "$SEVERITY" \
        --exit-code "$EXIT_CODE" \
        --format table \
        --quiet \
        "$IMAGE"; then

        echo -e "${GREEN}✅ PASSED: No CRITICAL/HIGH vulnerabilities found${NC}"
        PASSED_IMAGES=$((PASSED_IMAGES + 1))
    else
        echo -e "${RED}❌ FAILED: CRITICAL/HIGH vulnerabilities detected!${NC}"
        echo ""
        echo -e "${YELLOW}Action Required:${NC}"
        echo "  1. Update base image SHA256 in Dockerfile"
        echo "  2. Choose a patched version from Docker Hub"
        echo "  3. Re-run this scan to verify"
        echo ""
        FAILED_IMAGES=$((FAILED_IMAGES + 1))
    fi

    echo ""
done

# Final summary
echo "========================================="
echo -e "${BLUE}📊 Scan Summary${NC}"
echo "========================================="
echo "Total images scanned: $TOTAL_IMAGES"
echo -e "${GREEN}Passed: $PASSED_IMAGES${NC}"
if [ "$FAILED_IMAGES" -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED_IMAGES${NC}"
fi
echo ""

if [ "$FAILED_IMAGES" -eq 0 ]; then
    echo -e "${GREEN}✅ All base images passed security scan${NC}"
    echo -e "${GREEN}✅ Safe to proceed with Docker build${NC}"
    exit 0
else
    echo -e "${RED}❌ Security scan failed for $FAILED_IMAGES image(s)${NC}"
    echo -e "${RED}❌ Build BLOCKED to prevent supply chain attack${NC}"
    echo ""
    echo -e "${YELLOW}Documentation:${NC}"
    echo "  docs/deployment/BYTECODE_WHEEL_GUIDE.md (SHA256 update procedure)"
    exit 1
fi

# ========================================
# Expected Behavior:
# - SUCCESS (exit 0): All base images clean
# - FAILURE (exit 1): Vulnerabilities detected
#
# Risk Reduction: 80% (V-5 Phase 1)
# Time Budget: 30 minutes (Task 2/3)
# ========================================
