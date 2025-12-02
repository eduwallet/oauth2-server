#!/bin/bash

# Test script for proxy mode userinfo endpoint
# Tests that proxy userinfo correctly forwards requests to upstream provider
# using the mapped upstream access token from token exchange

set -e

# Configuration
SERVER_URL="http://localhost:8080"
MOCK_PROVIDER_PORT=9999
MOCK_PROVIDER_URL="http://localhost:$MOCK_PROVIDER_PORT"
TEST_USERNAME="john.doe"
TEST_PASSWORD="password123"
TEST_SCOPE="openid profile email"
API_KEY="${API_KEY:-super-secure-random-api-key-change-in-production-32-chars-minimum}"

echo "🧪 Proxy UserInfo Test"
echo "======================"
echo "Testing proxy mode UserInfo endpoint with token exchange"
echo "Using mock upstream provider at: $MOCK_PROVIDER_URL"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper function for colored output
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "success" ]; then
        echo -e "${GREEN}✅ $message${NC}"
    elif [ "$status" = "error" ]; then
        echo -e "${RED}❌ $message${NC}"
    elif [ "$status" = "info" ]; then
        echo -e "${YELLOW}ℹ️  $message${NC}"
    else
        echo "$message"
    fi
}
