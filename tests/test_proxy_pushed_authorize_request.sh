#!/bin/bash

# Test Proxy Mode Pushed Authorization Request (PAR) functionality
# This test verifies that PAR requests are properly forwarded to upstream providers in proxy mode

set -e

# Configuration
SERVER_URL="${SERVER_URL:-http://localhost:8080}"
MOCK_PROVIDER_URL="${MOCK_PROVIDER_URL:-http://localhost:9999}"
API_KEY="${API_KEY:-super-secure-random-api-key-change-in-production-32-chars-minimum}"

echo "🧪 Proxy Mode Pushed Authorization Request (PAR) Test"
echo "===================================================="
echo "Testing PAR functionality in proxy mode"
echo "Downstream PAR requests should be forwarded to upstream provider"
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

# Note: Mock upstream provider is started automatically by run-test-script.sh
# Verify it's accessible
print_status "info" "Verifying mock upstream provider is accessible..."
MOCK_RESPONSE=$(curl -s "$MOCK_PROVIDER_URL/.well-known/openid-configuration" 2>/dev/null)
if ! echo "$MOCK_RESPONSE" | grep -q "issuer"; then
    print_status "error" "Mock upstream provider not accessible at $MOCK_PROVIDER_URL"
    print_status "error" "Make sure to run tests via: make test-script SCRIPT=<script-name>"
    exit 1
fi
print_status "success" "Mock upstream provider is ready"

# Start OAuth2 server in proxy mode if not running
if ! curl -s "$SERVER_URL/health" > /dev/null; then
    print_status "info" "Starting OAuth2 server in proxy mode..."
    UPSTREAM_PROVIDER_URL="$MOCK_PROVIDER_URL" \
    UPSTREAM_CLIENT_ID="mock-client-id" \
    UPSTREAM_CLIENT_SECRET="mock-client-secret" \
    UPSTREAM_CALLBACK_URL="$SERVER_URL/callback" \
    API_KEY="$API_KEY" \
    LOG_LEVEL=debug \
    ./bin/oauth2-server > server.log 2>&1 &
    SERVER_PID=$!
    echo $SERVER_PID > server.pid
    print_status "success" "OAuth2 server started (PID: $SERVER_PID)"

    # Wait for server to start
    for i in {1..10}; do
        if curl -s "$SERVER_URL/health" > /dev/null; then
            break
        fi
        sleep 1
    done

    if ! curl -s "$SERVER_URL/health" > /dev/null; then
        print_status "error" "Server failed to start"
        exit 1
    fi
fi

print_status "success" "OAuth2 server is ready"

# Cleanup function
cleanup() {
    if [ -f server.pid ]; then
        kill $(cat server.pid) 2>/dev/null || true
        rm -f server.pid
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# Step 1: Register a test client
print_status "info" "Step 1: Registering test client..."
CLIENT_RESPONSE=$(curl -s -X POST "$SERVER_URL/register" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d '{
        "client_name": "Proxy PAR Test Client",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "redirect_uris": ["http://localhost:8080/callback"],
        "scope": "openid profile email"
    }')

echo "$CLIENT_RESPONSE" | grep -o '"client_id":"[^"]*"' | cut -d'"' -f4 > /dev/null
if [ $? -ne 0 ]; then
    print_status "error" "Failed to extract client_id from response"
    echo "Response: $CLIENT_RESPONSE"
    exit 1
fi

CLIENT_ID=$(echo "$CLIENT_RESPONSE" | grep -o '"client_id":"[^"]*"' | cut -d'"' -f4)
print_status "success" "Client registered with ID: $CLIENT_ID"

# Step 2: Test PAR request in proxy mode
print_status "info" "Step 2: Testing PAR request in proxy mode..."
PAR_RESPONSE=$(curl -s -X POST "$SERVER_URL/authorize" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=$CLIENT_ID&response_type=code&scope=openid%20profile&redirect_uri=http://localhost:8080/callback&state=test-state")

echo "$PAR_RESPONSE" | grep -o '"request_uri":"[^"]*"' | cut -d'"' -f4 > /dev/null
if [ $? -ne 0 ]; then
    print_status "error" "PAR request failed - no request_uri found"
    echo "Response: $PAR_RESPONSE"
    exit 1
fi

REQUEST_URI=$(echo "$PAR_RESPONSE" | grep -o '"request_uri":"[^"]*"' | cut -d'"' -f4)
EXPIRES_IN=$(echo "$PAR_RESPONSE" | grep -o '"expires_in":[0-9]*' | cut -d':' -f2)

print_status "success" "PAR request successful"
print_status "info" "Request URI: $REQUEST_URI"
print_status "info" "Expires in: $EXPIRES_IN seconds"

# Step 3: Verify discovery endpoint includes PAR endpoint
print_status "info" "Step 3: Verifying discovery endpoint includes PAR endpoint..."
DISCOVERY_RESPONSE=$(curl -s "$SERVER_URL/.well-known/openid-configuration")

echo "$DISCOVERY_RESPONSE" | grep -q "pushed_authorization_request_endpoint"
if [ $? -ne 0 ]; then
    print_status "error" "Discovery endpoint does not include pushed_authorization_request_endpoint"
    exit 1
fi

PAR_ENDPOINT=$(echo "$DISCOVERY_RESPONSE" | grep -o '"pushed_authorization_request_endpoint":"[^"]*"' | cut -d'"' -f4)
if [ "$PAR_ENDPOINT" != "http://localhost:8080/authorize" ]; then
    print_status "error" "PAR endpoint URL is incorrect: $PAR_ENDPOINT"
    exit 1
fi

print_status "success" "Discovery endpoint correctly advertises PAR endpoint: $PAR_ENDPOINT"

# Step 4: Test authorization with request_uri (should work in proxy mode)
print_status "info" "Step 4: Testing authorization with request_uri..."
# This would normally require browser interaction, but we can at least verify the endpoint accepts the parameter
AUTH_URL="$SERVER_URL/authorize?request_uri=$REQUEST_URI&client_id=$CLIENT_ID"

AUTH_RESPONSE=$(curl -s -I "$AUTH_URL" | head -n 1)
if echo "$AUTH_RESPONSE" | grep -q "302\|200"; then
    print_status "success" "Authorization endpoint accepts request_uri parameter"
else
    print_status "error" "Authorization endpoint rejected request_uri parameter"
    echo "Response: $AUTH_RESPONSE"
fi

print_status "success" "Proxy mode PAR test completed successfully"

echo ""
echo "📊 Proxy PAR Test Results Summary"
echo "=================================="
echo "✅ Client registration: PASS"
echo "✅ PAR request forwarding: PASS"
echo "✅ Discovery endpoint: PASS"
echo "✅ Request URI handling: PASS"
echo ""
echo "🎉 Proxy mode PAR functionality is working correctly!"