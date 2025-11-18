#!/bin/bash
# Generate invalid license key for testing

# Method 1: Completely invalid format
INVALID_KEY_1="invalid-key-format"

# Method 2: Valid structure but wrong HMAC signature
# License format: base64(license_data) + "." + hmac_signature
LICENSE_DATA='{"licensee":"Test User","issued_at":"2025-11-17","expires_at":"2026-11-17","features":["basic"]}'
LICENSE_B64=$(echo -n "$LICENSE_DATA" | base64)
# Wrong HMAC (random string instead of proper signature)
WRONG_HMAC="0000000000000000000000000000000000000000000000000000000000000000"
INVALID_KEY_2="${LICENSE_B64}.${WRONG_HMAC}"

echo "Invalid License Key 1 (malformed): $INVALID_KEY_1"
echo ""
echo "Invalid License Key 2 (wrong HMAC): $INVALID_KEY_2"

# Export for docker-compose
export INVALID_LICENSE_1="$INVALID_KEY_1"
export INVALID_LICENSE_2="$INVALID_KEY_2"

echo ""
echo "Exported INVALID_LICENSE_1 and INVALID_LICENSE_2"
