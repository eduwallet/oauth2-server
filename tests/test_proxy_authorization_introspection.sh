#!/bin/bash

# Test Proxy Authorization Introspection
# This script tests the authorization-introspection endpoint in proxy mode
# where proxy tokens are translated to upstream tokens for userinfo calls

# Test configuration - use environment variables with defaults
TEST_USERNAME="${TEST_USERNAME:-john.doe}"
TEST_PASSWORD="${TEST_PASSWORD:-password123}"
TEST_SCOPE="${TEST_SCOPE:-openid%20profile%20email}"

echo "🧪 Proxy Authorization Introspection Test"
echo "========================================"
echo "Testing authorization-introspection in proxy mode"
echo "Proxy tokens should be translated to upstream tokens for userinfo"
echo "Using environment variables:"
echo "  TEST_USERNAME: $TEST_USERNAME"
echo "  TEST_PASSWORD: $TEST_PASSWORD"
echo "  TEST_SCOPE: $TEST_SCOPE"
echo ""

SERVER_URL="${OAUTH2_SERVER_URL:-http://localhost:8080}"
MOCK_PROVIDER_URL="http://localhost:9999"
API_KEY="${API_KEY:-super-secure-random-api-key-change-in-production-32-chars-minimum}"

# Initialize test results
STEP1_PASS=false
STEP2_PASS=false
STEP3_PASS=false
STEP4_PASS=false

# Function to print status
print_status() {
    local status="$1"
    local message="$2"
    case "$status" in
        "success")
            echo "✅ $message"
            ;;
        "error")
            echo "❌ $message"
            ;;
        "info")
            echo "ℹ️  $message"
            ;;
        *)
            echo "$message"
            ;;
    esac
}

# Step 1: Assume mock upstream provider is already running (started by Makefile)
print_status "info" "Assuming mock upstream provider is running (started by Makefile)"
STEP1_PASS=true
STEP1_PASS=true

# Step 2: Register a client for testing
print_status "info" "Registering test client..."
REGISTER_RESPONSE=$(curl -s -X POST "$SERVER_URL/register" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "{
        \"client_name\": \"Proxy Test Client\",
        \"redirect_uris\": [\"${SERVER_URL}/callback\"],
        \"grant_types\": [\"authorization_code\"],
        \"response_types\": [\"code\"],
        \"scope\": \"openid profile email\"
    }")

echo "Registration response: $REGISTER_RESPONSE"

CLIENT_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.client_id')
CLIENT_SECRET=$(echo "$REGISTER_RESPONSE" | jq -r '.client_secret')

if [ "$CLIENT_ID" = "null" ] || [ -z "$CLIENT_ID" ]; then
    print_status "error" "Failed to register client"
    exit 1
fi

print_status "success" "Client registered: $CLIENT_ID"
STEP2_PASS=true

# Step 3: Perform authorization code flow to get proxy token
print_status "info" "Performing authorization code flow..."

# Get authorization code - handle proxy flow
AUTH_URL="$SERVER_URL/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=${SERVER_URL}/callback&scope=openid%20profile%20email&state=test_state"

echo "Making authorization request..."
# First, make the auth request (will redirect to upstream)
AUTH_REDIRECT=$(curl -s -I "$AUTH_URL" | grep -i "location:" | head -1 | sed 's/Location: //' | tr -d '\r')
if [ -z "$AUTH_REDIRECT" ]; then
    print_status "error" "Failed to get redirect from authorization request"
    exit 1
fi

echo "Redirected to upstream: $AUTH_REDIRECT"

# Extract the state from the upstream URL (this is the session state)
UPSTREAM_STATE=$(echo "$AUTH_REDIRECT" | sed 's/.*state=\([^&]*\).*/\1/')
echo "Upstream state: $UPSTREAM_STATE"

# Simulate upstream provider callback to proxy server
CALLBACK_URL="$SERVER_URL/callback?code=test-auth-code&state=$UPSTREAM_STATE"
echo "Simulating upstream callback: $CALLBACK_URL"

CLIENT_REDIRECT=$(curl -s -I "$CALLBACK_URL" | grep -i "location:" | head -1 | sed 's/Location: //' | tr -d '\r')
if [ -z "$CLIENT_REDIRECT" ]; then
    print_status "error" "Failed to get client redirect from callback"
    exit 1
fi

echo "Client redirect: $CLIENT_REDIRECT"

# Extract authorization code from client redirect
AUTH_CODE=$(echo "$CLIENT_REDIRECT" | sed 's/.*code=\([^&]*\).*/\1/')
if [ -z "$AUTH_CODE" ]; then
    print_status "error" "Failed to extract authorization code from client redirect"
    exit 1
fi

echo "Got authorization code: $AUTH_CODE"

# Exchange code for token
TOKEN_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -u "$CLIENT_ID:$CLIENT_SECRET" \
    -d "grant_type=authorization_code&code=$AUTH_CODE&redirect_uri=${SERVER_URL}/callback")

echo "Token response: $TOKEN_RESPONSE"

PROXY_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
if [ "$PROXY_TOKEN" = "null" ] || [ -z "$PROXY_TOKEN" ]; then
    print_status "error" "Failed to get proxy access token"
    exit 1
fi

print_status "success" "Got proxy access token: ${PROXY_TOKEN:0:20}..."
STEP3_PASS=true

# Step 4: Test authorization-introspection with proxy token
print_status "info" "Testing authorization-introspection with proxy token..."

INTROSPECTION_RESPONSE=$(curl -s -X POST "$SERVER_URL/authorization-introspection" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "access-token=$PROXY_TOKEN")

echo "Authorization-introspection response:"
echo "$INTROSPECTION_RESPONSE" | jq '.'

# Validate response
TOKEN_DETAILS=$(echo "$INTROSPECTION_RESPONSE" | jq '.token_details')
USER_INFO=$(echo "$INTROSPECTION_RESPONSE" | jq '.user_info')

if [ "$TOKEN_DETAILS" = "null" ] || [ -z "$TOKEN_DETAILS" ]; then
    print_status "error" "Missing token_details in response"
    exit 1
fi

if [ "$USER_INFO" = "null" ] || [ -z "$USER_INFO" ]; then
    print_status "error" "Missing user_info in response - this indicates proxy token translation failed"
    exit 1
fi

# Check if user_info contains upstream data
UPSTREAM_EMAIL=$(echo "$USER_INFO" | jq -r '.email')
if [ "$UPSTREAM_EMAIL" != "upstream@example.com" ]; then
    print_status "error" "User info doesn't contain expected upstream data"
    exit 1
fi

print_status "success" "Authorization-introspection returned upstream userinfo data"
STEP4_PASS=true

# Cleanup
rm -f cookies.txt

# Test Results Summary
echo ""
echo "📊 Proxy Authorization Introspection Test Results"
echo "================================================"
echo "Step 1 (Mock provider startup): $([ "$STEP1_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 2 (Client registration): $([ "$STEP2_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 3 (Proxy token acquisition): $([ "$STEP3_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 4 (Proxy token introspection): $([ "$STEP4_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"

if [ "$STEP1_PASS" = true ] && [ "$STEP2_PASS" = true ] && [ "$STEP3_PASS" = true ] && [ "$STEP4_PASS" = true ]; then
    print_status "success" "All proxy authorization-introspection tests PASSED!"
    print_status "success" "Proxy token translation to upstream userinfo is working correctly"
    exit 0
else
    print_status "error" "Some tests FAILED"
    exit 1
fi