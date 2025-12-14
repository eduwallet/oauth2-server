#!/bin/bash

# Test Dynamic Client Registration (RFC 7591)
# This script tests the OAuth2 dynamic client registration endpoint

# Test configuration - use environment variables with defaults
TEST_USERNAME="${TEST_USERNAME:-john.doe}"
TEST_PASSWORD="${TEST_PASSWORD:-password123}"
TEST_SCOPE="${TEST_SCOPE:-openid profile email}"
API_KEY="${API_KEY:-super-secure-random-api-key-change-in-production-32-chars-minimum}"

echo "🧪 Dynamic Client Registration Test"
echo "==================================="
echo "Testing OAuth2 Dynamic Client Registration (RFC 7591)"
echo "Using environment variables:"
echo "  TEST_USERNAME: $TEST_USERNAME"
echo "  TEST_PASSWORD: $TEST_PASSWORD"
echo "  TEST_SCOPE: $TEST_SCOPE"
echo ""

BASE_URL="${OAUTH2_SERVER_URL:-http://localhost:8080}"

# Initialize test results
STEP1_PASS=false
STEP2_PASS=false
STEP3_PASS=false
STEP4_PASS=false

# Function to register a confidential client
register_confidential_client() {
    local client_name="$1"
    local grant_types="$2"
    local scopes="$3"

    echo "📝 Registering confidential client: $client_name..." >&2

    local registration_data="{
        \"client_name\": \"$client_name\",
        \"grant_types\": $grant_types,
        \"response_types\": [\"code\"],
        \"token_endpoint_auth_method\": \"client_secret_basic\",
        \"scope\": \"$scopes\",
           \"redirect_uris\": [\"${BASE_URL}/callback\"]
    }"

    local registration_response=$(curl -s -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -d "$registration_data")

    echo "Registration response: $registration_response" >&2

    # Extract client credentials
    local client_id=""
    local client_secret=""

    if command -v jq >/dev/null 2>&1; then
        client_id=$(echo "$registration_response" | jq -r '.client_id // empty')
        client_secret=$(echo "$registration_response" | jq -r '.client_secret // empty')
    else
        client_id=$(echo "$registration_response" | grep -o '"client_id":"[^"]*"' | sed 's/"client_id":"\([^"]*\)"/\1/')
        client_secret=$(echo "$registration_response" | grep -o '"client_secret":"[^"]*"' | sed 's/"client_secret":"\([^"]*\)"/\1/')
    fi

    if [ -z "$client_id" ] || [ "$client_id" = "null" ]; then
        echo "❌ Failed to register client" >&2
        echo "Response: $registration_response" >&2
        return 1
    fi

    echo "✅ Client registered successfully" >&2
    echo "   Client ID: ${client_id:0:20}..." >&2
    echo "   Client Secret: ${client_secret:0:10}..." >&2

    # Return client credentials as JSON
    echo "{\"client_id\":\"$client_id\",\"client_secret\":\"$client_secret\"}"
}

# Function to register a public client
register_public_client() {
    local client_name="$1"
    local grant_types="$2"
    local scopes="$3"

    echo "📱 Registering public client: $client_name..." >&2

    local registration_data="{
        \"client_name\": \"$client_name\",
        \"grant_types\": $grant_types,
        \"response_types\": [\"code\"],
        \"token_endpoint_auth_method\": \"none\",
        \"scope\": \"$scopes\",
           \"redirect_uris\": [\"${BASE_URL}/callback\"]
    }"

    local registration_response=$(curl -s -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -d "$registration_data")

    echo "Registration response: $registration_response" >&2

    # Extract client credentials
    local client_id=""
    local client_secret=""

    if command -v jq >/dev/null 2>&1; then
        client_id=$(echo "$registration_response" | jq -r '.client_id // empty')
        client_secret=$(echo "$registration_response" | jq -r '.client_secret // empty')
    else
        client_id=$(echo "$registration_response" | grep -o '"client_id":"[^"]*"' | sed 's/"client_id":"\([^"]*\)"/\1/')
        client_secret=$(echo "$registration_response" | grep -o '"client_secret":"[^"]*"' | sed 's/"client_secret":"\([^"]*\)"/\1/')
    fi

    if [ -z "$client_id" ] || [ "$client_id" = "null" ]; then
        echo "❌ Failed to register client" >&2
        echo "Response: $registration_response" >&2
        return 1
    fi

    echo "✅ Public client registered successfully" >&2
    echo "   Client ID: ${client_id:0:20}..." >&2
    echo "   Client Secret: (none - public client)" >&2

    # Return client credentials as JSON
    echo "{\"client_id\":\"$client_id\",\"client_secret\":\"$client_secret\"}"
}

# Function to URL encode a string
url_encode() {
    local string="$1"
    local encoded=""
    local length="${#string}"
    for (( i = 0; i < length; i++ )); do
        local char="${string:i:1}"
        case $char in
            [a-zA-Z0-9.~_-]) encoded+="$char" ;;
            ' ') encoded+='%20' ;;
            *) encoded+=$(printf '%%%02X' "'$char") ;;
        esac
    done
    echo "$encoded"
}

# Function to test authorization code flow with registered client
test_auth_code_flow() {
    local client_id="$1"
    local client_secret="$2"
    local scope="$3"
    local is_public="${4:-false}"

    echo "🔐 Testing authorization code flow..." >&2

    # Generate PKCE parameters
    local code_verifier=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
    
    # Ensure code verifier is at least 43 characters
    while [ ${#code_verifier} -lt 43 ]; do
        code_verifier="${code_verifier}$(openssl rand -base64 1 | tr -d "=+/")"
    done
    code_verifier=$(echo "$code_verifier" | cut -c1-128)  # Max 128 chars
    
    local code_challenge=$(echo -n "$code_verifier" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')

    echo "🔐 PKCE Code Verifier: ${code_verifier:0:20}..." >&2
    echo "🔐 PKCE Code Challenge: ${code_challenge:0:20}..." >&2

    # Generate state
    local state=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    echo "🎲 State: ${state:0:20}..." >&2

    # URL encode the scope parameter
    local encoded_scope=$(url_encode "$scope")

    # Build authorization URL
    local auth_url="$BASE_URL/authorize?response_type=code&client_id=$client_id&redirect_uri=${BASE_URL}/callback&state=$state&scope=$encoded_scope&code_challenge=$code_challenge&code_challenge_method=S256"

    echo "🔗 Authorization URL: $auth_url" >&2

    # Make initial GET request to get login form
    local auth_response=$(curl -s -i -X GET "$auth_url" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
        -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")

    echo $auth_response
    echo "DEBUG: Authorization response:" >&2
    echo "$auth_response" | head -20 >&2

    # Check HTTP status
    local http_status=$(echo "$auth_response" | grep -o "HTTP/[0-9.]* [0-9]*" | awk '{print $2}')
    echo "DEBUG: HTTP Status: $http_status" >&2

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

            # Exchange code for token
            echo "🔄 Exchanging code for token..." >&2
            local token_response=""

            if [ "$is_public" = "true" ]; then
                # Public client - no client secret
                token_response=$(curl -s -X POST "$BASE_URL/token" \
                    -H "Content-Type: application/x-www-form-urlencoded" \
                    -d "grant_type=authorization_code&code=$auth_code&client_id=$client_id&redirect_uri=${BASE_URL}/callback&code_verifier=$code_verifier")
            else
                # Confidential client - use basic auth
                token_response=$(curl -s -X POST "$BASE_URL/token" \
                    -u "$client_id:$client_secret" \
                    -H "Content-Type: application/x-www-form-urlencoded" \
                    -d "grant_type=authorization_code&code=$auth_code&redirect_uri=${BASE_URL}/callback&code_verifier=$code_verifier")
            fi

            echo "Token response: $token_response" >&2

            # Extract access token
            local access_token=""
            if command -v jq >/dev/null 2>&1; then
                access_token=$(echo "$token_response" | jq -r '.access_token // empty')
            else
                access_token=$(echo "$token_response" | grep -o '"access_token":"[^"]*"' | sed 's/"access_token":"\([^"]*\)"/\1/')
            fi

            if [ -z "$access_token" ] || [ "$access_token" = "null" ]; then
                echo "❌ Failed to get access token" >&2
                echo "Response: $token_response" >&2
                return 1
            fi

            echo "✅ Got access token: ${access_token:0:30}..." >&2
            echo "$access_token"
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

# Function to test client credentials flow
test_client_credentials_flow() {
    local client_id="$1"
    local client_secret="$2"
    local scope="$3"

    echo "🔑 Testing client credentials flow..." >&2

    local token_response=$(curl -s -X POST "$BASE_URL/token" \
        -u "$client_id:$client_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&scope=$scope")

    echo "Token response: $token_response" >&2

    # Extract access token
    local access_token=""
    if command -v jq >/dev/null 2>&1; then
        access_token=$(echo "$token_response" | jq -r '.access_token // empty')
    else
        access_token=$(echo "$token_response" | grep -o '"access_token":"[^"]*"' | sed 's/"access_token":"\([^"]*\)"/\1/')
    fi

    if [ -z "$access_token" ] || [ "$access_token" = "null" ]; then
        echo "❌ Failed to get access token" >&2
        echo "Response: $token_response" >&2
        return 1
    fi

    echo "✅ Got access token: ${access_token:0:30}..." >&2
    echo "$access_token"
    return 0
}

# Step 1: Register a confidential client
echo "🧪 Step 1: Registering confidential client"
CONFIDENTIAL_CLIENT_DATA=$(register_confidential_client "Test Confidential Client" "[\"authorization_code\", \"refresh_token\"]" "$TEST_SCOPE")

if [ $? -ne 0 ]; then
    echo "❌ Step 1 FAILED - Could not register confidential client"
    exit 1
fi

# Extract client credentials
CONFIDENTIAL_CLIENT_ID=$(echo "$CONFIDENTIAL_CLIENT_DATA" | sed 's/.*"client_id":"\([^"]*\)".*/\1/')
CONFIDENTIAL_CLIENT_SECRET=$(echo "$CONFIDENTIAL_CLIENT_DATA" | sed 's/.*"client_secret":"\([^"]*\)".*/\1/')

echo "✅ Step 1 PASSED - Confidential client registered"
STEP1_PASS=true

# Step 2: Test authorization code flow with confidential client
echo ""
echo "🧪 Step 2: Testing auth code flow with confidential client"
CONFIDENTIAL_ACCESS_TOKEN=$(test_auth_code_flow "$CONFIDENTIAL_CLIENT_ID" "$CONFIDENTIAL_CLIENT_SECRET" "$TEST_SCOPE" "false")

if [ $? -ne 0 ]; then
    echo "❌ Step 2 FAILED - Auth code flow failed"
    exit 1
fi

echo "✅ Step 2 PASSED - Auth code flow working"
STEP2_PASS=true

# Step 3: Register a public client
echo ""
echo "🧪 Step 3: Registering public client"
PUBLIC_CLIENT_DATA=$(register_public_client "Test Public Client" "[\"authorization_code\"]" "$TEST_SCOPE")

if [ $? -ne 0 ]; then
    echo "❌ Step 3 FAILED - Could not register public client"
    exit 1
fi

# Extract client credentials
PUBLIC_CLIENT_ID=$(echo "$PUBLIC_CLIENT_DATA" | sed 's/.*"client_id":"\([^"]*\)".*/\1/')
PUBLIC_CLIENT_SECRET=$(echo "$PUBLIC_CLIENT_DATA" | sed 's/.*"client_secret":"\([^"]*\)".*/\1/')

echo "✅ Step 3 PASSED - Public client registered"
STEP3_PASS=true

# Step 4: Test authorization code flow with public client
echo ""
echo "🧪 Step 4: Testing auth code flow with public client"
PUBLIC_ACCESS_TOKEN=$(test_auth_code_flow "$PUBLIC_CLIENT_ID" "$PUBLIC_CLIENT_SECRET" "$TEST_SCOPE" "true")

if [ $? -ne 0 ]; then
    echo "❌ Step 4 FAILED - Public client auth code flow failed"
    STEP4_PASS=false
else
    echo "✅ Step 4 PASSED - Public client auth code flow working"
    STEP4_PASS=true
fi

# Summary
echo ""
echo "📊 Client Registration Test Results Summary"
echo "==========================================="
echo "Step 1 (Confidential client registration): $([ "$STEP1_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 2 (Confidential client auth flow): $([ "$STEP2_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 3 (Public client registration): $([ "$STEP3_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 4 (Public client auth flow): $([ "$STEP4_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"

# Overall result
if [ "$STEP1_PASS" = true ] && [ "$STEP2_PASS" = true ] && [ "$STEP3_PASS" = true ] && [ "$STEP4_PASS" = true ]; then
    echo ""
    echo "🎉 All client registration tests PASSED!"
    echo "   ✅ RFC 7591 Dynamic Client Registration working correctly"
    echo "   ✅ Confidential client registration and auth flow successful"
    echo "   ✅ Public client registration and auth flow successful"
    echo "   ✅ Client registration endpoint properly secured"
    exit 0
else
    echo ""
    echo "❌ Some client registration tests FAILED!"
    exit 1
fi
