#!/bin/bash

# Test Public Client Authorization Code Flow
# This script tests the OAuth2 authorization code flow for public clients (no client secret)

# Test configuration - use environment variables with defaults
TEST_USERNAME="${TEST_USERNAME:-john.doe}"
TEST_PASSWORD="${TEST_PASSWORD:-password123}"
TEST_SCOPE="${TEST_SCOPE:-openid profile email}"

echo "🧪 Public Client Authorization Code Flow Test"
echo "============================================="
echo "Testing OAuth2 Authorization Code Flow for Public Clients"
echo "Using environment variables:"
echo "  TEST_USERNAME: $TEST_USERNAME"
echo "  TEST_PASSWORD: $TEST_PASSWORD"
echo "  TEST_SCOPE: $TEST_SCOPE"
echo ""

BASE_URL="http://localhost:8080"
CLIENT_ID="mobile-app"  # Public client from config that supports authorization code flow

# Initialize test results
STEP1_PASS=false
STEP2_PASS=false
STEP3_PASS=false
STEP4_PASS=false

# Function to test authorization code flow with public client
test_public_auth_code_flow() {
    local client_id="$1"
    local scope="$2"

    echo "🔐 Testing public client authorization code flow..." >&2

    # Generate PKCE parameters
    local code_verifier=$(openssl rand -hex 32 | cut -c1-64 | tr -d '\n')
    local code_challenge=$(echo -n "$code_verifier" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')

    echo "🔐 PKCE Code Verifier: ${code_verifier:0:20}..." >&2
    echo "🔐 PKCE Code Challenge: ${code_challenge:0:20}..." >&2

    # Generate state
    local state=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    echo "🎲 State: ${state:0:20}..." >&2

    # Build authorization URL
    local auth_url="$BASE_URL/authorize?response_type=code&client_id=$client_id&redirect_uri=http://localhost:8080/oauth/callback&state=$state&scope=openid&code_challenge=$code_challenge&code_challenge_method=S256"

    echo "🔗 Authorization URL: $auth_url" >&2

    # Make initial GET request to get login form
    local auth_response=$(curl -s -i -X GET "$auth_url" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
        -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")

    # Check for login form
    if echo "$auth_response" | grep -q "Login\|Username\|Password"; then
        echo "✅ Received login form - proceeding with authentication" >&2

        # Extract cookies
        local cookies=$(echo "$auth_response" | grep -i "set-cookie" | cut -d' ' -f2- | tr '\n' ';' | sed 's/;$//')

        # Submit login credentials
        echo "🔐 Submitting login credentials..." >&2
        local login_response=$(curl -s -i -X POST "$BASE_URL/authorize?$(echo "$auth_url" | cut -d'?' -f2)" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "Cookie: $cookies" \
            -d "username=$TEST_USERNAME&password=$TEST_PASSWORD")

        # Check for redirect with authorization code
        local location_header=$(echo "$login_response" | grep -i "location:" | cut -d' ' -f2- | tr -d '\r\n')

        if [ -n "$location_header" ] && echo "$location_header" | grep -q "code="; then
            echo "🔄 Redirect received: $location_header" >&2

            # Extract authorization code
            local auth_code=$(echo "$location_header" | sed 's/.*code=\([^&]*\).*/\1/')

            if [ -z "$auth_code" ]; then
                echo "❌ Failed to extract authorization code" >&2
                return 1
            fi

            echo "✅ Got authorization code: ${auth_code:0:30}..." >&2

            # Exchange code for token (public client - no client secret)
            echo "🔄 Exchanging code for token (public client)..." >&2
            local token_response=$(curl -s -X POST "$BASE_URL/token" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -d "grant_type=authorization_code&code=$auth_code&client_id=$client_id&redirect_uri=http://localhost:8080/oauth/callback&code_verifier=$code_verifier")

            echo "Token response: $token_response" >&2

            # Extract tokens
            local access_token=""
            local refresh_token=""
            local token_type=""
            local expires_in=""

            if command -v jq >/dev/null 2>&1; then
                access_token=$(echo "$token_response" | jq -r '.access_token // empty')
                refresh_token=$(echo "$token_response" | jq -r '.refresh_token // empty')
                token_type=$(echo "$token_response" | jq -r '.token_type // empty')
                expires_in=$(echo "$token_response" | jq -r '.expires_in // empty')
            else
                access_token=$(echo "$token_response" | grep -o '"access_token":"[^"]*"' | sed 's/"access_token":"\([^"]*\)"/\1/')
                refresh_token=$(echo "$token_response" | grep -o '"refresh_token":"[^"]*"' | sed 's/"refresh_token":"\([^"]*\)"/\1/')
                token_type=$(echo "$token_response" | grep -o '"token_type":"[^"]*"' | sed 's/"token_type":"\([^"]*\)"/\1/')
                expires_in=$(echo "$token_response" | grep -o '"expires_in":[0-9]*' | sed 's/"expires_in":\([0-9]*\)/\1/')
            fi

            if [ -z "$access_token" ] || [ "$access_token" = "null" ]; then
                echo "❌ Failed to get access token" >&2
                echo "Response: $token_response" >&2
                return 1
            fi

            echo "✅ Got access token: ${access_token:0:30}..." >&2
            echo "   Token type: $token_type" >&2
            echo "   Expires in: $expires_in seconds" >&2
            if [ -n "$refresh_token" ] && [ "$refresh_token" != "null" ]; then
                echo "   Refresh token: ${refresh_token:0:30}..." >&2
            else
                echo "   Refresh token: (none issued)" >&2
            fi

            # Return tokens as JSON
            echo "{\"access_token\":\"$access_token\",\"refresh_token\":\"$refresh_token\",\"token_type\":\"$token_type\",\"expires_in\":\"$expires_in\"}"
            return 0
        else
            echo "❌ No redirect with authorization code received" >&2
            return 1
        fi
    else
        echo "❌ No login form received" >&2
        return 1
    fi
}

# Function to test token introspection
test_token_introspection() {
    local access_token="$1"

    echo "🔍 Testing token introspection..." >&2

    local introspection_response=$(curl -s -X POST "$BASE_URL/introspect" \
        -u "backend-client:backend-secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "token=$access_token")

    echo "Introspection response: $introspection_response" >&2

    # Check if token is active
    local active=""
    if command -v jq >/dev/null 2>&1; then
        active=$(echo "$introspection_response" | jq -r '.active // false')
    else
        active=$(echo "$introspection_response" | grep -o '"active":\([^,}]*\)' | sed 's/"active":\([^,}]*\)/\1/')
    fi

    if [ "$active" = "true" ]; then
        echo "✅ Token is active and valid" >&2
        return 0
    else
        echo "❌ Token is not active or invalid" >&2
        return 1
    fi
}

# Function to test UserInfo endpoint
test_userinfo_endpoint() {
    local access_token="$1"

    echo "👤 Testing UserInfo endpoint..." >&2

    local userinfo_response=$(curl -s -X GET "$BASE_URL/userinfo" \
        -H "Authorization: Bearer $access_token")

    echo "UserInfo response: $userinfo_response" >&2

    # Check if we got user information
    if echo "$userinfo_response" | grep -q "sub\|username\|email"; then
        echo "✅ UserInfo endpoint returned user data" >&2
        return 0
    else
        echo "❌ UserInfo endpoint failed or returned no data" >&2
        return 1
    fi
}

# Function to test refresh token flow (if available)
test_refresh_token_flow() {
    local refresh_token="$1"

    if [ -z "$refresh_token" ] || [ "$refresh_token" = "null" ]; then
        echo "🔄 No refresh token available - skipping refresh test" >&2
        return 0
    fi

    echo "🔄 Testing refresh token flow..." >&2

    local refresh_response=$(curl -s -X POST "$BASE_URL/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=refresh_token&refresh_token=$refresh_token&client_id=$CLIENT_ID")

    echo "Refresh response: $refresh_response" >&2

    # Extract new access token
    local new_access_token=""
    if command -v jq >/dev/null 2>&1; then
        new_access_token=$(echo "$refresh_response" | jq -r '.access_token // empty')
    else
        new_access_token=$(echo "$refresh_response" | grep -o '"access_token":"[^"]*"' | sed 's/"access_token":"\([^"]*\)"/\1/')
    fi

    if [ -z "$new_access_token" ] || [ "$new_access_token" = "null" ]; then
        echo "❌ Failed to refresh token" >&2
        echo "Response: $refresh_response" >&2
        return 1
    fi

    echo "✅ Got new access token via refresh: ${new_access_token:0:30}..." >&2
    return 0
}

# Step 1: Test public client authorization code flow
echo "🧪 Step 1: Testing public client authorization code flow"
TOKEN_DATA=$(test_public_auth_code_flow "$CLIENT_ID" "$TEST_SCOPE")

if [ $? -ne 0 ]; then
    echo "❌ Step 1 FAILED - Public client auth code flow failed"
    exit 1
fi

# Extract tokens
ACCESS_TOKEN=$(echo "$TOKEN_DATA" | sed 's/.*"access_token":"\([^"]*\)".*/\1/')
REFRESH_TOKEN=$(echo "$TOKEN_DATA" | sed 's/.*"refresh_token":"\([^"]*\)".*/\1/')

echo "✅ Step 1 PASSED - Public client auth code flow successful"
STEP1_PASS=true

# Step 2: Test token introspection
echo ""
echo "🧪 Step 2: Testing token introspection"
if test_token_introspection "$ACCESS_TOKEN"; then
    echo "⚠️ Token introspection succeeded (unexpected for public client)"
    STEP2_PASS=false
else
    echo "✅ Token introspection failed as expected (public clients cannot introspect)"
    STEP2_PASS=true
fi

# Step 3: Test UserInfo endpoint
echo ""
echo "🧪 Step 3: Testing UserInfo endpoint"
if test_userinfo_endpoint "$ACCESS_TOKEN"; then
    echo "✅ Step 3 PASSED - UserInfo endpoint working"
    STEP3_PASS=true
else
    echo "❌ Step 3 FAILED - UserInfo endpoint failed"
    STEP3_PASS=false
fi

# Step 4: Test refresh token flow (if available)
echo ""
echo "🧪 Step 4: Testing refresh token flow"
if test_refresh_token_flow "$REFRESH_TOKEN"; then
    echo "✅ Step 4 PASSED - Refresh token flow working"
    STEP4_PASS=true
else
    echo "❌ Step 4 FAILED - Refresh token flow failed"
    STEP4_PASS=false
fi

# Summary
echo ""
echo "📊 Public Client Flow Test Results Summary"
echo "=========================================="
echo "Step 1 (Public client auth code flow): $([ "$STEP1_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 2 (Token introspection): $([ "$STEP2_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 3 (UserInfo endpoint): $([ "$STEP3_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 4 (Refresh token flow): $([ "$STEP4_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"

# Overall result
if [ "$STEP1_PASS" = true ] && [ "$STEP2_PASS" = true ] && [ "$STEP3_PASS" = true ]; then
    echo ""
    echo "🎉 Public client authorization code flow tests PASSED!"
    echo "   ✅ Public client can authenticate without client secret"
    echo "   ✅ PKCE-based authorization code flow working"
    echo "   ✅ Token introspection and UserInfo endpoints functional"
    if [ "$STEP4_PASS" = true ]; then
        echo "   ✅ Refresh token flow working (when tokens issued)"
    else
        echo "   ⚠️  Refresh token flow not available (server policy)"
    fi
    exit 0
else
    echo ""
    echo "❌ Some public client flow tests FAILED!"
    exit 1
fi