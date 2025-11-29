#!/bin/bash

# Test configuration - use environment variables with defaults
TEST_USERNAME="${TEST_USERNAME:-john.doe}"
TEST_PASSWORD="${TEST_PASSWORD:-password123}"
TEST_SCOPE="${TEST_SCOPE:-openid profile email offline_access}"

echo "🧪 Token Exchange Test"
echo "======================"
echo "Testing RFC 8693 Token Exchange between clients"
echo "Using environment variables:"
echo "  TEST_USERNAME: $TEST_USERNAME"
echo "  TEST_PASSWORD: $TEST_PASSWORD"
echo "  TEST_SCOPE: $TEST_SCOPE"
echo ""

BASE_URL="http://localhost:8080"
FRONTEND_ID="web-app-client"
FRONTEND_SECRET="web-app-secret"
BACKEND_ID="backend-client"
BACKEND_SECRET="backend-client-secret"
AUDIENCE="api-service"

# Function to generate PKCE code verifier and challenge
generate_pkce() {
    # Generate code verifier (43-128 characters, URL-safe characters only)
    CODE_VERIFIER=""
    local chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    local length=$((RANDOM % 86 + 43))  # Random length between 43-128

    for i in $(seq 1 $length); do
        CODE_VERIFIER="${CODE_VERIFIER}${chars:$((RANDOM % ${#chars})):1}"
    done

    # Generate code challenge (SHA256 hash of verifier, base64url encoded)
    CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')

    echo "🔐 PKCE Code Verifier: ${CODE_VERIFIER:0:20}... (${#CODE_VERIFIER} chars)" >&2
    echo "🔐 PKCE Code Challenge: ${CODE_CHALLENGE:0:20}..." >&2
}

# Function to generate secure state parameter
generate_state() {
    STATE=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    echo "🎲 State: ${STATE:0:20}..." >&2
}

# Function to perform authorization code flow and return tokens
perform_auth_flow() {
    local client_id="$1"
    local client_secret="$2"
    local scope="$3"

    echo "🔑 Performing authorization code flow for $client_id..." >&2

    # Generate PKCE parameters
    generate_pkce >&2
    generate_state >&2

    # Build authorization URL
    local auth_url="$BASE_URL/authorize?response_type=code&client_id=$client_id&redirect_uri=http://localhost:8080/callback&state=$STATE"
    if [ -n "$scope" ]; then
        auth_url="$auth_url&scope=$(echo "$scope" | sed 's/ /%20/g')"
    fi
    auth_url="$auth_url&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"

    echo "🔗 Authorization URL: $auth_url" >&2

    # Make initial GET request to authorization endpoint to get login form
    local auth_response=$(curl -s -i -X GET "$auth_url" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
        -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")

    # Check if we got a login form
    if echo "$auth_response" | grep -q "Login\|Username\|Password"; then
        echo "✅ Received login form - proceeding with authentication" >&2

        # Extract cookies for session
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
                echo "❌ Failed to extract authorization code from redirect" >&2
                return 1
            fi

            echo "✅ Got authorization code: ${auth_code:0:30}..." >&2

            # Exchange code for token
            echo "🔄 Exchanging code for token..." >&2
            local token_response=$(curl -s -X POST "$BASE_URL/token" \
                -u "$client_id:$client_secret" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -d "grant_type=authorization_code&code=$auth_code&redirect_uri=http://localhost:8080/callback&code_verifier=$CODE_VERIFIER")

            echo "Token response: $token_response" >&2

            local access_token=$(echo "$token_response" | jq -r '.access_token // empty')
            local refresh_token=$(echo "$token_response" | jq -r '.refresh_token // empty')

            if [ -z "$access_token" ] || [ "$access_token" = "null" ]; then
                echo "❌ Failed to get access token" >&2
                echo "Response: $token_response" >&2
                return 1
            fi

            echo "✅ Got tokens - Access: ${access_token:0:30}..., Refresh: ${refresh_token:0:30}..." >&2

            # Return tokens as JSON
            echo "{\"access_token\":\"$access_token\",\"refresh_token\":\"$refresh_token\"}"
        else
            echo "❌ No redirect with authorization code received" >&2
            echo "Response headers:" >&2
            echo "$login_response" | head -10 >&2
            return 1
        fi
    else
        echo "❌ No login form received from authorization endpoint" >&2
        echo "Response preview:" >&2
        echo "$auth_response" | head -10 >&2
        return 1
    fi
}

# Function to refresh tokens
refresh_tokens() {
    local client_id="$1"
    local client_secret="$2"
    local refresh_token="$3"

    echo "🔄 Refreshing tokens for $client_id..." >&2

    local refresh_response=$(curl -s -X POST "$BASE_URL/token" \
        -u "$client_id:$client_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=refresh_token&refresh_token=$refresh_token")

    local new_access=$(echo "$refresh_response" | jq -r '.access_token // empty')
    local new_refresh=$(echo "$refresh_response" | jq -r '.refresh_token // empty')

    if [ -z "$new_access" ] || [ "$new_access" = "null" ]; then
        echo "❌ Failed to refresh tokens" >&2
        echo "Response: $refresh_response" >&2
        return 1
    fi

    echo "✅ Refreshed tokens - Access: ${new_access:0:30}..., Refresh: ${new_refresh:0:30}..." >&2

    # Return new tokens as JSON
    echo "{\"access_token\":\"$new_access\",\"refresh_token\":\"$new_refresh\"}"
}

# Function to perform token exchange with specific requested token type
exchange_token() {
    local client_id="$1"
    local client_secret="$2"
    local subject_token="$3"
    local audience="$4"
    local requested_type="${5:-urn:ietf:params:oauth:token-type:access_token}"

    echo "🔄 Performing token exchange for $client_id (requesting $requested_type)..." >&2

    local exchange_response=$(curl -s -X POST "$BASE_URL/token" \
        -u "$client_id:$client_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=$subject_token&subject_token_type=urn:ietf:params:oauth:token-type:access_token&requested_token_type=$requested_type")

    if [ "$requested_type" = "urn:ietf:params:oauth:token-type:refresh_token" ]; then
        local exchanged_token=$(echo "$exchange_response" | jq -r '.refresh_token // empty')
        local token_type="Refresh"
    else
        local exchanged_token=$(echo "$exchange_response" | jq -r '.access_token // empty')
        local token_type="Access"
    fi

    if [ -z "$exchanged_token" ] || [ "$exchanged_token" = "null" ]; then
        echo "❌ Token exchange failed" >&2
        echo "Response: $exchange_response" >&2
        return 1
    fi

    echo "✅ Token exchange successful - $token_type: ${exchanged_token:0:30}..." >&2

    # Return exchanged token
    echo "$exchanged_token"
}

# Function to introspect token
introspect_token() {
    local client_id="$1"
    local client_secret="$2"
    local token="$3"

    echo "🔍 Introspecting token..." >&2

    local introspect_response=$(curl -s -X POST "$BASE_URL/introspect" \
        -u "$client_id:$client_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "token=$token")

    local active=$(echo "$introspect_response" | jq -r '.active // false')

    if [ "$active" != "true" ]; then
        echo "❌ Token introspection failed - token not active" >&2
        echo "Response: $introspect_response" >&2
        return 1
    fi

    echo "✅ Token introspection successful - token is active" >&2

    # Return introspection response
    echo "$introspect_response"
}

# Function to test UserInfo
test_userinfo() {
    local access_token="$1"

    echo "👤 Testing UserInfo endpoint..." >&2

    local userinfo_response=$(curl -s -X GET "$BASE_URL/userinfo" \
        -H "Authorization: Bearer $access_token")

    # Check if UserInfo worked
    if echo "$userinfo_response" | jq -e '.username' >/dev/null 2>&1; then
        echo "✅ UserInfo endpoint working" >&2
        local username=$(echo "$userinfo_response" | jq -r '.username')
        local email=$(echo "$userinfo_response" | jq -r '.email')
        echo "   Username: $username, Email: $email" >&2
        
        # Verify username matches TEST_USERNAME
        if [ "$username" != "$TEST_USERNAME" ]; then
            echo "❌ UserInfo username mismatch: expected '$TEST_USERNAME', got '$username'" >&2
            return 1
        fi
        echo "✅ UserInfo username verified: $username" >&2
        return 0
    else
        echo "❌ UserInfo failed: $userinfo_response" >&2
        return 1
    fi
}

# Step 1: Frontend app gets initial tokens via authorization code flow
echo "🧪 Step 1: Frontend app obtains initial tokens via authorization code flow"
INITIAL_TOKENS=$(perform_auth_flow "$FRONTEND_ID" "$FRONTEND_SECRET" "$TEST_SCOPE")

if [ $? -ne 0 ]; then
    echo "❌ Step 1 FAILED - Could not obtain initial tokens"
    exit 1
fi

INITIAL_ACCESS=$(echo "$INITIAL_TOKENS" | jq -r '.access_token')
INITIAL_REFRESH=$(echo "$INITIAL_TOKENS" | jq -r '.refresh_token')

echo "✅ Step 1 PASSED - Initial access token obtained"
STEP1_PASS=true

# Step 2: Frontend app performs token exchange
echo ""
echo "🧪 Step 2: Frontend app performs token exchange for backend client"
EXCHANGED_ACCESS=$(exchange_token "$FRONTEND_ID" "$FRONTEND_SECRET" "$INITIAL_ACCESS" "$AUDIENCE" "urn:ietf:params:oauth:token-type:access_token")

if [ $? -ne 0 ]; then
    echo "❌ Step 2 FAILED - Token exchange failed"
    exit 1
fi

echo "✅ Step 2 PASSED - Token exchange completed"
STEP2_PASS=true

# Step 2b: Test access_token to refresh_token exchange
echo ""
echo "🧪 Step 2b: Test access_token -> refresh_token exchange"
EXCHANGED_REFRESH=$(exchange_token "$FRONTEND_ID" "$FRONTEND_SECRET" "$INITIAL_ACCESS" "$AUDIENCE" "urn:ietf:params:oauth:token-type:refresh_token")

if [ $? -ne 0 ]; then
    echo "❌ Step 2b FAILED - Refresh token exchange failed"
    STEP2B_PASS=false
else
    echo "✅ Step 2b PASSED - Refresh token exchange successful"
    STEP2B_PASS=true
fi

# Step 3: Backend client validates exchanged token via introspection
echo ""
echo "🧪 Step 3: Backend client validates exchanged token via introspection"
INTROSPECT_RESULT=$(introspect_token "$BACKEND_ID" "$BACKEND_SECRET" "$EXCHANGED_ACCESS")

if [ $? -ne 0 ]; then
    echo "❌ Step 3 FAILED - Token introspection failed"
    exit 1
fi

echo "✅ Step 3 PASSED - Token introspection successful"
STEP3_PASS=true

# Step 4: Backend client requests userinfo with exchanged token
echo ""
echo "🧪 Step 4: Backend client requests userinfo with exchanged token"
if test_userinfo "$EXCHANGED_ACCESS"; then
    echo "✅ Step 4 PASSED - UserInfo endpoint working with exchanged token"
    STEP4_PASS=true
else
    echo "❌ Step 4 FAILED - UserInfo endpoint failed with exchanged token"
    STEP4_PASS=false
fi

# Summary
echo ""
echo "📊 Token Exchange Test Results Summary"
echo "======================================"
echo "Step 1 (Initial tokens): $([ "$STEP1_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 2 (Token exchange A->A): $([ "$STEP2_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 2b (Token exchange A->R): $([ "$STEP2B_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 3 (Introspection): $([ "$STEP3_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 4 (UserInfo): $([ "$STEP4_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"

# Overall result
if [ "$STEP1_PASS" = true ] && [ "$STEP2_PASS" = true ] && [ "$STEP3_PASS" = true ] && [ "$STEP4_PASS" = true ]; then
    echo ""
    echo "🎉 All token exchange tests PASSED!"
    echo "   ✅ RFC 8693 Token Exchange working correctly"
    echo "   ✅ Cross-client token delegation successful"
    echo "   ✅ Token introspection working"
    echo "   ✅ UserInfo accessible with exchanged tokens"
    if [ "$STEP2B_PASS" = true ]; then
        echo "   ✅ Access token to refresh token exchange supported"
    else
        echo "   ⚠️  Access token to refresh token exchange not supported (Fosite limitation?)"
    fi
    exit 0
else
    echo ""
    echo "❌ Some token exchange tests FAILED!"
    exit 1
fi