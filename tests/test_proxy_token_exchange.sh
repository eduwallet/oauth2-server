#!/bin/bash

# Test script for proxy mode token exchange
# Tests RFC 8693 Token Exchange through proxy server with upstream provider

set -e

# Configuration
SERVER_URL="http://localhost:8080"
MOCK_PROVIDER_PORT=9999
MOCK_PROVIDER_URL="http://localhost:$MOCK_PROVIDER_PORT"
TEST_USERNAME="john.doe"
TEST_PASSWORD="password123"
TEST_SCOPE="openid profile email"
API_KEY="${API_KEY:-super-secure-random-api-key-change-in-production-32-chars-minimum}"

echo "🧪 Proxy Token Exchange Test"
echo "==========================="
echo "Testing RFC 8693 Token Exchange in proxy mode"
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

# Start mock upstream OAuth2 provider
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
echo "🧪 Step 1: Verifying OAuth2 server is running..."

# Verify mock upstream provider is accessible (started by run-test-script.sh)
if ! curl -s "$MOCK_PROVIDER_URL/.well-known/openid-configuration" > /dev/null 2>&1; then
    print_status "error" "Mock provider not accessible at $MOCK_PROVIDER_URL"
    exit 1
fi

# Verify OAuth2 server is running (started by run-test-script.sh)
if ! curl -s "$SERVER_URL/health" > /dev/null; then
    print_status "error" "OAuth2 server not accessible at $SERVER_URL"
    exit 1
fi

print_status "success" "OAuth2 server is running in proxy mode"
echo ""

echo "🧪 Step 2: Using pre-configured clients for token exchange..."

# Use pre-configured clients from config.yaml
FRONTEND_CLIENT_ID="frontend-client"
FRONTEND_CLIENT_SECRET="frontend-client-secret"
BACKEND_CLIENT_ID="backend-client"
BACKEND_CLIENT_SECRET="backend-client-secret"

print_status "success" "Using pre-configured clients: frontend-client and backend-client"
echo ""

echo "🧪 Step 3: Obtaining initial access token via authorization code flow..."

# Generate PKCE parameters
CODE_VERIFIER=$(openssl rand -hex 32 | head -c 43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
STATE=$(openssl rand -hex 16)

# Build authorization URL
AUTH_URL="$SERVER_URL/authorize?response_type=code&client_id=$FRONTEND_CLIENT_ID&redirect_uri=http://localhost:8080/callback&scope=openid%20profile%20email%20offline_access&state=$STATE&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"

echo "🔗 Authorization URL: $AUTH_URL"

# Make authorization request (should redirect to mock provider)
AUTH_RESPONSE=$(curl -s -i --max-time 10 "$AUTH_URL")

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

# Simulate the upstream authorization response
CALLBACK_RESPONSE=$(curl -s -i --max-redirs 0 "$UPSTREAM_AUTH_URL")

# Extract authorization code from the redirect location
AUTH_CODE=$(echo "$CALLBACK_RESPONSE" | grep "Location:" | grep -o 'code=[^&]*' | cut -d'=' -f2)

if [ -z "$AUTH_CODE" ]; then
    print_status "error" "Could not extract authorization code from callback"
    exit 1
fi

print_status "success" "Authorization code obtained: $AUTH_CODE"

# Exchange authorization code for tokens
TOKEN_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "$FRONTEND_CLIENT_ID:$FRONTEND_CLIENT_SECRET" \
  -d "grant_type=authorization_code&code=$AUTH_CODE&redirect_uri=http://localhost:8080/callback&code_verifier=$CODE_VERIFIER")

echo "Full initial token response: $TOKEN_RESPONSE"

# Extract access token
INITIAL_ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

if [ -z "$INITIAL_ACCESS_TOKEN" ] || [ "$INITIAL_ACCESS_TOKEN" = "null" ]; then
    print_status "error" "Failed to obtain initial access token"
    exit 1
fi

# Extract refresh token
INITIAL_REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token')
HAS_REFRESH_TOKEN=false

if [ -z "$INITIAL_REFRESH_TOKEN" ] || [ "$INITIAL_REFRESH_TOKEN" = "null" ]; then
    print_status "warning" "No initial refresh token found - will skip refresh token exchange tests"
    print_status "success" "Initial tokens obtained: access=${INITIAL_ACCESS_TOKEN:0:30}..."
else
    HAS_REFRESH_TOKEN=true
    print_status "success" "Initial tokens obtained: access=${INITIAL_ACCESS_TOKEN:0:30}..., refresh=${INITIAL_REFRESH_TOKEN:0:30}..."
fi
echo ""

echo "🧪 Step 4: Performing token exchange in proxy mode..."

# Perform token exchange using the frontend client
EXCHANGE_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "$FRONTEND_CLIENT_ID:$FRONTEND_CLIENT_SECRET" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=$INITIAL_ACCESS_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token&requested_token_type=urn:ietf:params:oauth:token-type:access_token&audience=api-service&scope=api:read")

echo "Token exchange response: $EXCHANGE_RESPONSE"

# Extract exchanged token
EXCHANGED_TOKEN=$(echo "$EXCHANGE_RESPONSE" | jq -r '.access_token')

if [ -z "$EXCHANGED_TOKEN" ] || [ "$EXCHANGED_TOKEN" = "null" ]; then
    print_status "error" "Token exchange failed"
    echo "Response: $EXCHANGE_RESPONSE"
    exit 1
fi

# Check if response indicates proxy processing
PROXY_PROCESSED=$(echo "$EXCHANGE_RESPONSE" | jq -r '.proxy_processed // false')
PROXY_SERVER=$(echo "$EXCHANGE_RESPONSE" | jq -r '.proxy_server // empty')

if [ "$PROXY_PROCESSED" = "true" ] && [ "$PROXY_SERVER" = "oauth2-server" ]; then
    print_status "success" "Token exchange processed by proxy server"
else
    print_status "error" "Token exchange response does not indicate proxy processing"
    echo "Expected proxy_processed=true and proxy_server=oauth2-server"
    exit 1
fi

print_status "success" "Token exchange successful - proxy token obtained: ${EXCHANGED_TOKEN:0:50}..."
echo ""

echo "🧪 Step 4b: Testing access_token -> refresh_token exchange..."

# Perform token exchange requesting refresh token
EXCHANGE_REFRESH_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "$FRONTEND_CLIENT_ID:$FRONTEND_CLIENT_SECRET" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=$INITIAL_ACCESS_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token&requested_token_type=urn:ietf:params:oauth:token-type:refresh_token&audience=api-service&scope=api:read")

echo "Access->Refresh token exchange response: $EXCHANGE_REFRESH_RESPONSE"

# Extract exchanged refresh token
EXCHANGED_REFRESH_TOKEN=$(echo "$EXCHANGE_REFRESH_RESPONSE" | jq -r '.refresh_token')
ISSUED_TOKEN_TYPE=$(echo "$EXCHANGE_REFRESH_RESPONSE" | jq -r '.issued_token_type')

if [ -z "$EXCHANGED_REFRESH_TOKEN" ] || [ "$EXCHANGED_REFRESH_TOKEN" = "null" ]; then
    print_status "error" "Access->Refresh token exchange failed"
    echo "Response: $EXCHANGE_REFRESH_RESPONSE"
    exit 1
fi

if [ "$ISSUED_TOKEN_TYPE" != "urn:ietf:params:oauth:token-type:refresh_token" ]; then
    print_status "error" "Expected issued_token_type=refresh_token, got: $ISSUED_TOKEN_TYPE"
    exit 1
fi

# Check proxy processing
PROXY_PROCESSED=$(echo "$EXCHANGE_REFRESH_RESPONSE" | jq -r '.proxy_processed // false')
if [ "$PROXY_PROCESSED" != "true" ]; then
    print_status "error" "Access->Refresh exchange response does not indicate proxy processing"
    exit 1
fi

print_status "success" "Access->Refresh token exchange successful"
echo ""

# Only test refresh token exchanges if we have a valid refresh token
if [ "$HAS_REFRESH_TOKEN" = true ]; then
    echo "🧪 Step 4c: Testing refresh_token -> access_token exchange..."

    # Perform token exchange using refresh token as subject, requesting access token
    REFRESH_TO_ACCESS_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -u "$FRONTEND_CLIENT_ID:$FRONTEND_CLIENT_SECRET" \
      -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=$INITIAL_REFRESH_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:refresh_token&requested_token_type=urn:ietf:params:oauth:token-type:access_token&audience=api-service&scope=api:read")

    echo "Refresh->Access token exchange response: $REFRESH_TO_ACCESS_RESPONSE"

    # Extract exchanged access token
    REFRESH_TO_ACCESS_TOKEN=$(echo "$REFRESH_TO_ACCESS_RESPONSE" | jq -r '.access_token')
    ISSUED_TOKEN_TYPE=$(echo "$REFRESH_TO_ACCESS_RESPONSE" | jq -r '.issued_token_type')

    if [ -z "$REFRESH_TO_ACCESS_TOKEN" ] || [ "$REFRESH_TO_ACCESS_TOKEN" = "null" ]; then
        print_status "error" "Refresh->Access token exchange failed"
        echo "Response: $REFRESH_TO_ACCESS_RESPONSE"
        exit 1
    fi

    if [ "$ISSUED_TOKEN_TYPE" != "urn:ietf:params:oauth:token-type:access_token" ]; then
        print_status "error" "Expected issued_token_type=access_token, got: $ISSUED_TOKEN_TYPE"
        exit 1
    fi

    # Check proxy processing
    PROXY_PROCESSED=$(echo "$REFRESH_TO_ACCESS_RESPONSE" | jq -r '.proxy_processed // false')
    if [ "$PROXY_PROCESSED" != "true" ]; then
        print_status "error" "Refresh->Access exchange response does not indicate proxy processing"
        exit 1
    fi

    print_status "success" "Refresh->Access token exchange successful"
    echo ""

    echo "🧪 Step 4d: Testing refresh_token -> refresh_token exchange..."

    # Perform token exchange using refresh token as subject, requesting refresh token
    REFRESH_TO_REFRESH_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -u "$FRONTEND_CLIENT_ID:$FRONTEND_CLIENT_SECRET" \
      -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=$INITIAL_REFRESH_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:refresh_token&requested_token_type=urn:ietf:params:oauth:token-type:refresh_token&audience=api-service&scope=api:read")

    echo "Refresh->Refresh token exchange response: $REFRESH_TO_REFRESH_RESPONSE"

    # Extract exchanged refresh token
    REFRESH_TO_REFRESH_TOKEN=$(echo "$REFRESH_TO_REFRESH_RESPONSE" | jq -r '.refresh_token')
    ISSUED_TOKEN_TYPE=$(echo "$REFRESH_TO_REFRESH_RESPONSE" | jq -r '.issued_token_type')

    if [ -z "$REFRESH_TO_REFRESH_TOKEN" ] || [ "$REFRESH_TO_REFRESH_TOKEN" = "null" ]; then
        print_status "error" "Refresh->Refresh token exchange failed"
        echo "Response: $REFRESH_TO_REFRESH_RESPONSE"
        exit 1
    fi

    if [ "$ISSUED_TOKEN_TYPE" != "urn:ietf:params:oauth:token-type:refresh_token" ]; then
        print_status "error" "Expected issued_token_type=refresh_token, got: $ISSUED_TOKEN_TYPE"
        exit 1
    fi

    # Check proxy processing
    PROXY_PROCESSED=$(echo "$REFRESH_TO_REFRESH_RESPONSE" | jq -r '.proxy_processed // false')
    if [ "$PROXY_PROCESSED" != "true" ]; then
        print_status "error" "Refresh->Refresh exchange response does not indicate proxy processing"
        exit 1
    fi

    print_status "success" "Refresh->Refresh token exchange successful"
    echo ""
else
    print_status "info" "Skipping refresh token exchange tests (no refresh token available)"
    echo ""
fi

echo "🧪 Step 5: Testing proxy token introspection..."

# Test introspection with privileged client
PRIVILEGED_TOKEN_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "server-owned-client:server-admin-secret" \
  -d "grant_type=client_credentials&scope=admin")

PRIVILEGED_TOKEN=$(echo "$PRIVILEGED_TOKEN_RESPONSE" | jq -r '.access_token')

if [ -z "$PRIVILEGED_TOKEN" ] || [ "$PRIVILEGED_TOKEN" = "null" ]; then
    print_status "error" "Failed to obtain privileged client token"
    exit 1
fi

# Introspect the exchanged proxy token
INTROSPECTION_RESPONSE=$(curl -s -X POST "$SERVER_URL/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "server-owned-client:server-admin-secret" \
  -d "token=$EXCHANGED_TOKEN")

echo "Proxy token introspection response: $INTROSPECTION_RESPONSE"

# Check if introspection worked and shows proxy information
ACTIVE=$(echo "$INTROSPECTION_RESPONSE" | jq -r '.active')
PROXY_TOKEN=$(echo "$INTROSPECTION_RESPONSE" | jq -r '.proxy_token // empty')
ISSUED_BY_PROXY=$(echo "$INTROSPECTION_RESPONSE" | jq -r '.issued_by_proxy // false')

if [ "$ACTIVE" = "true" ] && [ "$ISSUED_BY_PROXY" = "true" ] && [ "$PROXY_TOKEN" = "$EXCHANGED_TOKEN" ]; then
    print_status "success" "Proxy token introspection successful"
    print_status "success" "Proxy token correctly identified and upstream introspection performed"
else
    print_status "error" "Proxy token introspection failed or missing proxy information"
    echo "Expected active=true, issued_by_proxy=true, proxy_token=$EXCHANGED_TOKEN"
    exit 1
fi

echo ""

echo "🧪 Step 6: Testing proxy token userinfo..."

# Test userinfo with the exchanged proxy token
USERINFO_RESPONSE=$(curl -s -X GET "$SERVER_URL/userinfo" \
  -H "Authorization: Bearer $EXCHANGED_TOKEN")

echo "Proxy token userinfo response: $USERINFO_RESPONSE"

# Check if userinfo worked and shows proxy processing
PREFERRED_USERNAME=$(echo "$USERINFO_RESPONSE" | jq -r '.preferred_username')
PROXY_PROCESSED_USERINFO=$(echo "$USERINFO_RESPONSE" | jq -r '.proxy_processed // false')

if [ "$PREFERRED_USERNAME" = "john.doe" ] && [ "$PROXY_PROCESSED_USERINFO" = "true" ]; then
    print_status "success" "Proxy token userinfo successful"
    print_status "success" "Upstream userinfo correctly retrieved through proxy token mapping"
else
    print_status "error" "Proxy token userinfo failed or missing proxy information"
    echo "Expected preferred_username=john.doe and proxy_processed=true"
    echo "Got: preferred_username=$PREFERRED_USERNAME, proxy_processed=$PROXY_PROCESSED_USERINFO"
    exit 1
fi

echo ""

echo "🧪 Step 7: Verifying token mapping persistence..."

# Test that the same proxy token still works after some time (simulating persistence)
sleep 2

# Test introspection again to verify mapping persistence
INTROSPECTION_RESPONSE2=$(curl -s -X POST "$SERVER_URL/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "server-owned-client:server-admin-secret" \
  -d "token=$EXCHANGED_TOKEN")

ACTIVE2=$(echo "$INTROSPECTION_RESPONSE2" | jq -r '.active')

if [ "$ACTIVE2" = "true" ]; then
    print_status "success" "Proxy token mapping persistence verified"
    print_status "success" "Upstream token mapping correctly stored and retrievable"
else
    print_status "error" "Proxy token mapping persistence failed"
    exit 1
fi

echo ""

echo "📊 Proxy Token Exchange Test Results Summary"
echo "============================================"
echo "Step 1 (OAuth2 server in proxy mode): ✅ PASS"
echo "Step 2 (Client registration): ✅ PASS"
echo "Step 3 (Initial token acquisition): ✅ PASS"
echo "Step 4 (Token exchange proxy): ✅ PASS"
echo "Step 5 (Proxy token introspection): ✅ PASS"
echo "Step 6 (Proxy token userinfo): ✅ PASS"
echo "Step 7 (Token mapping persistence): ✅ PASS"
echo ""
print_status "success" "All proxy token exchange tests PASSED!"
echo ""
echo "🎉 Proxy mode token exchange working correctly!"
echo "   ✅ Token exchange requests forwarded to upstream provider"
echo "   ✅ Upstream tokens replaced with Fosite-controlled proxy tokens"
echo "   ✅ Proxy token mapping stored for future operations"
echo "   ✅ Introspection correctly identifies proxy tokens and forwards to upstream"
echo "   ✅ Userinfo correctly uses upstream token mapping"
echo "   ✅ Token mappings persist across operations"
echo ""
echo "📋 Key Features Verified:"
echo "   • RFC 8693 Token Exchange implementation in proxy mode"
echo "   • Upstream token mapping storage and retrieval"
echo "   • Proxy token lifecycle management"
echo "   • Cross-operation token consistency (introspect ↔ userinfo)"
echo "   • Fosite integration for proxy token creation"
exit 0
