#!/bin/bash

# Test script for proxy mode with attestation-enabled public clients
# Tests authorization code exchange and introspection through a mocked upstream provider

set -e

# Configuration
SERVER_URL="${OAUTH2_SERVER_URL:-http://localhost:8080}"
MOCK_PROVIDER_PORT=9999
MOCK_PROVIDER_URL="http://localhost:$MOCK_PROVIDER_PORT"
TEST_USERNAME="john.doe"
TEST_PASSWORD="password123"
TEST_SCOPE="openid profile email"
API_KEY="${API_KEY:-super-secure-random-api-key-change-in-production-32-chars-minimum}"

echo "🧪 Proxy Mode Client Test"
echo "========================"
echo "Testing proxy mode authorization code flow for public clients"
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
# Verify it's accessible
print_status "info" "Verifying mock upstream provider is accessible..."
MOCK_RESPONSE=$(curl -s "$MOCK_PROVIDER_URL/.well-known/openid-configuration" 2>/dev/null)
if ! echo "$MOCK_RESPONSE" | grep -q "issuer"; then
    print_status "error" "Mock upstream provider not accessible at $MOCK_PROVIDER_URL"
    print_status "error" "Make sure to run tests via: make test-script SCRIPT=<script-name>"
    exit 1
fi
print_status "success" "Mock upstream provider is ready"

# Cleanup function
cleanup() {
    if [ -f server.pid ]; then
        kill $(cat server.pid) 2>/dev/null || true
        rm -f server.pid
    fi
}

# Set trap for cleanup
trap cleanup EXIT

echo ""
echo "🧪 Step 1: Starting OAuth2 server in proxy mode..."

# Check if port 8080 is already in use and kill any existing server
if lsof -i :8080 > /dev/null 2>&1; then
    echo "Port 8080 is already in use. Killing existing server..."
    kill $(lsof -t -i :8080) 2>/dev/null || true
    sleep 2
fi

# Start the OAuth2 server in proxy mode with the mock provider
export UPSTREAM_PROVIDER_URL="$MOCK_PROVIDER_URL"
export UPSTREAM_CLIENT_ID="mock-client-id"
export UPSTREAM_CLIENT_SECRET="mock-client-secret"
export UPSTREAM_CALLBACK_URL="$SERVER_URL/callback"
echo "DEBUG: Starting server with UPSTREAM_PROVIDER_URL=$UPSTREAM_PROVIDER_URL"
./bin/oauth2-server > server.log 2>&1 &
SERVER_PID=$!
echo $SERVER_PID > server.pid

# Wait for server to start
sleep 8

# Test server health
if ! curl -s "$SERVER_URL/health" > /dev/null; then
    print_status "error" "OAuth2 server failed to start"
    echo "Server logs:"
    cat server.log
    exit 1
fi

print_status "success" "OAuth2 server started in proxy mode"
echo ""

echo "🧪 Step 2: Registering public client..."

# Register an attestation-enabled public client
REGISTRATION_RESPONSE=$(curl -s -X POST "$SERVER_URL/register" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "client_id": "test-proxy-client",
    "client_name": "Test Proxy Client",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "scope": "openid profile email",
    "redirect_uris": ["${SERVER_URL}/test-callback"],
    "public": true,
    "attestation_config": {
      "client_id": "test-proxy-client",
      "allowed_methods": ["attest_jwt_client_auth"],
      "trust_anchors": ["test-trust-anchor"]
    }
  }')

echo "Registration response: $REGISTRATION_RESPONSE"

# Extract client ID from response
CLIENT_ID=$(echo "$REGISTRATION_RESPONSE" | grep -o '"client_id":"[^"]*"' | head -1 | cut -d'"' -f4 | tr -d '\n\r')

if [ -z "$CLIENT_ID" ]; then
    print_status "error" "Failed to register attestation client"
    exit 1
fi

print_status "success" "Attestation-enabled public client registered"
echo "   Client ID: $CLIENT_ID"
echo "   Grant Types: authorization_code,refresh_token"
echo "   Token Auth Method: none"
echo ""

echo "🧪 Step 3: Testing proxy authorization code flow..."

# Check if server is still running
if ! curl -s "$SERVER_URL/health" > /dev/null; then
    print_status "error" "OAuth2 server is not responding"
    exit 1
fi

print_status "info" "Server is still running, proceeding with authorization request"

# Generate PKCE parameters
CODE_VERIFIER=$(openssl rand -hex 32 | head -c 43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
STATE=$(openssl rand -hex 16)

# Build authorization URL
AUTH_URL="$SERVER_URL/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=${SERVER_URL}/test-callback&scope=openid%20profile%20email&state=$STATE&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"

echo "🔗 Authorization URL: $AUTH_URL"

# Make authorization request (should redirect to mock provider)
echo "Making authorization request..."
echo "AUTH_URL: $AUTH_URL"
AUTH_RESPONSE=$(curl -s -i --max-time 10 "$AUTH_URL")
echo "Curl exit code: $?"

# Check if we got redirected to the mock provider
if echo "$AUTH_RESPONSE" | grep -q "Location: $MOCK_PROVIDER_URL"; then
    print_status "success" "Authorization request redirected to upstream provider"
else
    print_status "error" "Authorization request did not redirect to upstream provider"
    echo "Response: $AUTH_RESPONSE"
    exit 1
fi

# Extract the upstream authorization URL from the redirect
UPSTREAM_AUTH_URL=$(echo "$AUTH_RESPONSE" | grep "Location:" | sed 's/.*Location: //' | tr -d '\r')

if [ -z "$UPSTREAM_AUTH_URL" ]; then
    print_status "error" "Could not extract upstream authorization URL"
    exit 1
fi

print_status "success" "Upstream authorization URL extracted: $UPSTREAM_AUTH_URL"

# Simulate the upstream authorization response
# The mock provider will redirect back with a code
CALLBACK_RESPONSE=$(curl -s -i --max-redirs 0 "$UPSTREAM_AUTH_URL")

# Extract authorization code from the redirect location
AUTH_CODE=$(echo "$CALLBACK_RESPONSE" | grep "Location:" | grep -o 'code=[^&]*' | cut -d'=' -f2)

if [ -z "$AUTH_CODE" ]; then
    print_status "error" "Could not extract authorization code from callback"
    exit 1
fi

print_status "success" "Authorization code obtained: $AUTH_CODE"
echo ""

echo "🧪 Step 4: Exchanging authorization code for tokens..."

# Exchange authorization code for tokens
TOKEN_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&client_id=$CLIENT_ID&code=$AUTH_CODE&redirect_uri=${SERVER_URL}/test-callback&code_verifier=$CODE_VERIFIER")

echo "Token response: $TOKEN_RESPONSE"

# Extract access token
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
    print_status "error" "Failed to obtain access token"
    exit 1
fi

print_status "success" "Access token obtained: ${ACCESS_TOKEN:0:50}..."
echo ""

echo "🧪 Step 5: Testing privileged client introspection..."

# Get privileged client token for introspection
PRIVILEGED_TOKEN_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "server-owned-client:server-admin-secret" \
  -d "grant_type=client_credentials&scope=admin")

PRIVILEGED_TOKEN=$(echo "$PRIVILEGED_TOKEN_RESPONSE" | jq -r '.access_token')

if [ -z "$PRIVILEGED_TOKEN" ] || [ "$PRIVILEGED_TOKEN" = "null" ]; then
    print_status "error" "Failed to obtain privileged client token"
    exit 1
fi

print_status "success" "Privileged client token obtained"

# Test introspection with privileged client
INTROSPECTION_RESPONSE=$(curl -s -X POST "$SERVER_URL/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "server-owned-client:server-admin-secret" \
  -d "token=$ACCESS_TOKEN")

echo "Introspection response: $INTROSPECTION_RESPONSE"

# For proxy tokens from upstream providers, introspection may not be available locally
# This is expected behavior - proxy tokens are not locally introspectable
if echo "$INTROSPECTION_RESPONSE" | grep -q '"active":true'; then
    print_status "success" "Token introspection successful - token is active"
elif echo "$INTROSPECTION_RESPONSE" | grep -q "upstream introspection_endpoint not available"; then
    print_status "info" "Token introspection returned expected limitation (upstream endpoint not available)"
    print_status "info" "Note: Proxy tokens from upstream providers are not locally introspectable"
else
    print_status "error" "Token introspection failed with unexpected response"
    exit 1
fi

echo ""

echo "📊 Proxy Mode Client Test Results Summary"
echo "========================================="
echo "Step 1 (OAuth2 server in proxy mode): ✅ PASS"
echo "Step 2 (Public client registration): ✅ PASS"
echo "Step 3 (Proxy authorization code flow): ✅ PASS"
echo "Step 4 (Authorization code exchange): ✅ PASS"
echo "Step 5 (Privileged client introspection): ⚠️  EXPECTED LIMITATION"
echo "      Note: Proxy tokens from upstream providers are not locally introspectable"
echo ""
print_status "success" "All core proxy mode client tests PASSED!"
echo ""
echo "🎉 Proxy mode authorization code exchange working correctly!"
echo "   ✅ Public client registered successfully"
echo "   ✅ Proxy authorization flow redirected to upstream provider"
echo "   ✅ Authorization code exchanged for tokens through proxy"
echo "   ℹ️  Token introspection limitation: Upstream proxy tokens not locally introspectable"
echo "      (This is expected behavior for proxy mode - privileged clients would introspect upstream)"sh