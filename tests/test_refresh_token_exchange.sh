#!/bin/bash

# Test configuration - use environment variables with defaults
TEST_USERNAME="${TEST_USERNAME:-john.doe}"
TEST_PASSWORD="${TEST_PASSWORD:-password123}"
TEST_SCOPE="${TEST_SCOPE:-openid profile email offline_access}"
API_KEY="${API_KEY:-super-secure-random-api-key-change-in-production-32-chars-minimum}"

echo "🔄🔄 Refresh Token Exchange Test"
echo "==============================="
echo "Testing refresh token functionality combined with token exchange:"
echo "- Register client with refresh token and token exchange support"
echo "- Obtain initial tokens (including refresh token) via authorization code flow"
echo "- Use refresh token in token exchange to get new refresh token"
echo "- Use exchanged refresh token to obtain access tokens"
echo "- Test UserInfo with exchanged tokens"
echo ""
echo "Using environment variables:"
echo "  TEST_USERNAME: $TEST_USERNAME"
echo "  TEST_PASSWORD: $TEST_PASSWORD"
echo "  TEST_SCOPE: $TEST_SCOPE"
echo ""

BASE_URL="${OAUTH2_SERVER_URL:-http://localhost:8080}"
CLIENT_NAME="Refresh Token Exchange Client"

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

# Function to register a client
register_client() {
    local client_name="$1"

    echo "📝 Registering client: $client_name" >&2

    CLIENT_REGISTRATION_PAYLOAD='{
        "client_name": "'$client_name'",
        "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "'$TEST_SCOPE'",
        "redirect_uris": ["'${BASE_URL}'/callback"]
    }'

    REGISTRATION_RESPONSE=$(curl -s -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -d "$CLIENT_REGISTRATION_PAYLOAD")

    if [ $? -ne 0 ]; then
        echo "❌ Failed to register client $client_name - curl error" >&2
        return 1
    fi

    CLIENT_ID=$(echo "$REGISTRATION_RESPONSE" | jq -r '.client_id' 2>/dev/null)
    CLIENT_SECRET=$(echo "$REGISTRATION_RESPONSE" | jq -r '.client_secret' 2>/dev/null)

    if [ "$CLIENT_ID" = "null" ] || [ -z "$CLIENT_ID" ]; then
        echo "❌ Failed to extract client_id for $client_name" >&2
        return 1
    fi

    if [ "$CLIENT_SECRET" = "null" ] || [ -z "$CLIENT_SECRET" ]; then
        echo "❌ Failed to extract client_secret for $client_name" >&2
        return 1
    fi

    echo "✅ Registered $client_name with ID: $CLIENT_ID" >&2
    echo "$CLIENT_ID:$CLIENT_SECRET"
}

# Function to perform authorization code flow and return tokens
perform_auth_flow() {
    local client_id="$1"
    local client_secret="$2"

    echo "🔑 Performing authorization code flow..." >&2

    # Generate PKCE parameters
    generate_pkce >&2
    generate_state >&2

    # Build authorization URL
    local auth_url="$BASE_URL/authorize?response_type=code&client_id=$client_id&redirect_uri=${BASE_URL}/callback&state=$STATE"
    auth_url="$auth_url&scope=$(echo "$TEST_SCOPE" | sed 's/ /%20/g')"
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
                -d "grant_type=authorization_code&code=$auth_code&redirect_uri=${BASE_URL}/callback&code_verifier=$CODE_VERIFIER")

            echo "Token response: $token_response" >&2

            local access_token=$(echo "$token_response" | jq -r '.access_token // empty')
            local refresh_token=$(echo "$token_response" | jq -r '.refresh_token // empty')

            if [ -z "$access_token" ] || [ "$access_token" = "null" ]; then
                echo "❌ Failed to get access token" >&2
                echo "Response: $token_response" >&2
                return 1
            fi

            if [ -z "$refresh_token" ] || [ "$refresh_token" = "null" ]; then
                echo "❌ Failed to get refresh token" >&2
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

# Function to perform token exchange with refresh token as subject
exchange_refresh_token() {
    local client_id="$1"
    local client_secret="$2"
    local subject_refresh_token="$3"

    echo "🔄 Performing token exchange with refresh token as subject..." >&2

    local exchange_response=$(curl -s -X POST "$BASE_URL/token" \
        -u "$client_id:$client_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=${subject_refresh_token}&subject_token_type=urn:ietf:params:oauth:token-type:refresh_token&requested_token_type=urn:ietf:params:oauth:token-type:refresh_token")

    if [ $? -ne 0 ]; then
        echo "❌ Token exchange request failed" >&2
        return 1
    fi

    echo "Exchange response: $exchange_response" >&2

    local exchanged_refresh_token=$(echo "$exchange_response" | jq -r '.refresh_token // empty')
    local exchanged_access_token=$(echo "$exchange_response" | jq -r '.access_token // empty')

    if [ -z "$exchanged_refresh_token" ] || [ "$exchanged_refresh_token" = "null" ]; then
        echo "❌ Failed to obtain exchanged refresh token" >&2
        return 1
    fi

    echo "✅ Obtained exchanged refresh token: ${exchanged_refresh_token:0:30}..." >&2

    if [ -n "$exchanged_access_token" ] && [ "$exchanged_access_token" != "null" ]; then
        echo "✅ Also obtained exchanged access token: ${exchanged_access_token:0:30}..." >&2
    fi

    # Return exchanged tokens as JSON
    echo "{\"access_token\":\"$exchanged_access_token\",\"refresh_token\":\"$exchanged_refresh_token\"}"
}

# Function to refresh tokens using exchanged refresh token
refresh_with_exchanged_token() {
    local client_id="$1"
    local client_secret="$2"
    local refresh_token="$3"

    echo "🔄 Using exchanged refresh token to obtain access token..." >&2

    local refresh_response=$(curl -s -X POST "$BASE_URL/token" \
        -u "$client_id:$client_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=refresh_token&refresh_token=${refresh_token}")

    if [ $? -ne 0 ]; then
        echo "❌ Refresh token request failed" >&2
        return 1
    fi

    echo "Refresh response: $refresh_response" >&2

    local final_access_token=$(echo "$refresh_response" | jq -r '.access_token // empty')
    local final_refresh_token=$(echo "$refresh_response" | jq -r '.refresh_token // empty')

    if [ -z "$final_access_token" ] || [ "$final_access_token" = "null" ]; then
        echo "❌ Failed to obtain final access token" >&2
        return 1
    fi

    echo "✅ Obtained final access token: ${final_access_token:0:30}..." >&2

    if [ -n "$final_refresh_token" ] && [ "$final_refresh_token" != "null" ]; then
        echo "✅ Also obtained final refresh token: ${final_refresh_token:0:30}..." >&2
    fi

    # Return final tokens as JSON
    echo "{\"access_token\":\"$final_access_token\",\"refresh_token\":\"$final_refresh_token\"}"
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

# Step 1: Register client with refresh token and token exchange support
echo "🧪 Step 1: Registering client with refresh token and token exchange support"
CLIENT_CREDS=$(register_client "$CLIENT_NAME")

if [ $? -ne 0 ]; then
    echo "❌ Step 1 FAILED - Could not register client"
    exit 1
fi

CLIENT_ID=$(echo "$CLIENT_CREDS" | cut -d: -f1)
CLIENT_SECRET=$(echo "$CLIENT_CREDS" | cut -d: -f2)

echo "✅ Step 1 PASSED - Client registered with ID: $CLIENT_ID"
STEP1_PASS=true

# Step 2: Client performs authorization code flow to get initial tokens including refresh token
echo ""
echo "🧪 Step 2: Client performs authorization code flow to obtain initial tokens"
INITIAL_TOKENS=$(perform_auth_flow "$CLIENT_ID" "$CLIENT_SECRET")

if [ $? -ne 0 ]; then
    echo "❌ Step 2 FAILED - Could not obtain initial tokens"
    exit 1
fi

INITIAL_ACCESS=$(echo "$INITIAL_TOKENS" | jq -r '.access_token')
INITIAL_REFRESH=$(echo "$INITIAL_TOKENS" | jq -r '.refresh_token')

echo "✅ Step 2 PASSED - Initial tokens obtained"
STEP2_PASS=true

# Step 3: Verify initial access token works
echo ""
echo "🧪 Step 3: Verifying initial access token works with UserInfo"
if test_userinfo "$INITIAL_ACCESS"; then
    echo "✅ Step 3 PASSED - Initial access token validated"
    STEP3_PASS=true
else
    echo "❌ Step 3 FAILED - Initial access token validation failed"
    STEP3_PASS=false
fi

# Step 4: Client performs token exchange using refresh token as subject to get new refresh token
echo ""
echo "🧪 Step 4: Client performs token exchange using refresh token as subject"
EXCHANGED_TOKENS=$(exchange_refresh_token "$CLIENT_ID" "$CLIENT_SECRET" "$INITIAL_REFRESH")

if [ $? -ne 0 ]; then
    echo "❌ Step 4 FAILED - Token exchange failed"
    exit 1
fi

EXCHANGED_ACCESS=$(echo "$EXCHANGED_TOKENS" | jq -r '.access_token')
EXCHANGED_REFRESH=$(echo "$EXCHANGED_TOKENS" | jq -r '.refresh_token')

echo "✅ Step 4 PASSED - Token exchange completed"
STEP4_PASS=true

# Step 5: Client uses the exchanged refresh token to obtain a final access token
echo ""
echo "🧪 Step 5: Client uses exchanged refresh token to obtain final access token"
FINAL_TOKENS=$(refresh_with_exchanged_token "$CLIENT_ID" "$CLIENT_SECRET" "$EXCHANGED_REFRESH")

if [ $? -ne 0 ]; then
    echo "❌ Step 5 FAILED - Refresh with exchanged token failed"
    exit 1
fi

FINAL_ACCESS=$(echo "$FINAL_TOKENS" | jq -r '.access_token')
FINAL_REFRESH=$(echo "$FINAL_TOKENS" | jq -r '.refresh_token')

echo "✅ Step 5 PASSED - Final access token obtained"
STEP5_PASS=true

# Step 6: Verify final access token works
echo ""
echo "🧪 Step 6: Verifying final access token works with UserInfo"
if test_userinfo "$FINAL_ACCESS"; then
    echo "✅ Step 6 PASSED - Final access token validated"
    STEP6_PASS=true
else
    echo "❌ Step 6 FAILED - Final access token validation failed"
    STEP6_PASS=false
fi

# Step 7: Test that the final refresh token can be used again
echo ""
echo "🧪 Step 7: Testing that the final refresh token can be used again"
SECOND_REFRESH_TOKENS=$(refresh_with_exchanged_token "$CLIENT_ID" "$CLIENT_SECRET" "$FINAL_REFRESH")

if [ $? -ne 0 ]; then
    echo "❌ Step 7 FAILED - Second refresh failed"
    exit 1
fi

SECOND_ACCESS=$(echo "$SECOND_REFRESH_TOKENS" | jq -r '.access_token')

echo "✅ Step 7 PASSED - Second refresh token use successful"
STEP7_PASS=true

# Step 8: Verify the second access token works
echo ""
echo "🧪 Step 8: Verifying the second access token works"
if test_userinfo "$SECOND_ACCESS"; then
    echo "✅ Step 8 PASSED - Second access token validated"
    STEP8_PASS=true
else
    echo "❌ Step 8 FAILED - Second access token validation failed"
    STEP8_PASS=false
fi

# Cleanup
echo ""
echo "🧪 Cleaning up..."
if [ -f "/tmp/cookies.txt" ]; then
    rm -f /tmp/cookies.txt
fi

# Summary
echo ""
echo "📊 Refresh Token Exchange Test Results Summary"
echo "=============================================="
echo "Step 1 (Client registration): $([ "$STEP1_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 2 (Initial tokens): $([ "$STEP2_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 3 (Initial token validation): $([ "$STEP3_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 4 (Token exchange): $([ "$STEP4_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 5 (Refresh with exchanged token): $([ "$STEP5_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 6 (Final token validation): $([ "$STEP6_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 7 (Second refresh): $([ "$STEP7_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 8 (Second token validation): $([ "$STEP8_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"

# Overall result
if [ "$STEP1_PASS" = true ] && [ "$STEP2_PASS" = true ] && [ "$STEP3_PASS" = true ] && [ "$STEP4_PASS" = true ] && [ "$STEP5_PASS" = true ] && [ "$STEP6_PASS" = true ] && [ "$STEP7_PASS" = true ] && [ "$STEP8_PASS" = true ]; then
    echo ""
    echo "🎉 All refresh token exchange tests PASSED!"
    echo ""
    echo "Summary:"
    echo "- ✅ Client registered with refresh token and token exchange support"
    echo "- ✅ Initial tokens obtained via authorization code flow"
    echo "- ✅ Initial access token validated with UserInfo"
    echo "- ✅ Refresh token used as subject in token exchange"
    echo "- ✅ Exchanged refresh token used to obtain access tokens"
    echo "- ✅ Final access token validated with UserInfo"
    echo "- ✅ Refresh token reuse tested and validated"
    echo ""
    echo "Initial Refresh Token: ${INITIAL_REFRESH:0:50}..."
    echo "Exchanged Refresh Token: ${EXCHANGED_REFRESH:0:50}..."
    echo "Final Access Token: ${FINAL_ACCESS:0:50}..."
    echo "Second Access Token: ${SECOND_ACCESS:0:50}..."
    exit 0
else
    echo ""
    echo "❌ Some refresh token exchange tests FAILED!"
    exit 1
fi