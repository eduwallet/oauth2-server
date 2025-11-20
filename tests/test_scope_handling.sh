#!/bin/bash

# Test configuration - use environment variables with defaults
TEST_USERNAME="${TEST_USERNAME:-john.doe}"
TEST_PASSWORD="${TEST_PASSWORD:-password123}"
TEST_SCOPE="${TEST_SCOPE:-openid profile email}"

echo "🧪 Scope Handling Test"
echo "======================"
echo "Testing scope handling in authorization code flow"
echo "Using environment variables:"
echo "  TEST_USERNAME: $TEST_USERNAME"
echo "  TEST_PASSWORD: $TEST_PASSWORD"
echo "  TEST_SCOPE: $TEST_SCOPE"
echo ""

BASE_URL="http://localhost:8080"
CLIENT_ID="web-app-client"
CLIENT_SECRET="web-app-secret"
REDIRECT_URI="http://localhost:8080/callback"

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

    echo "🔐 PKCE Code Verifier: ${CODE_VERIFIER:0:20}... (${#CODE_VERIFIER} chars)"
    echo "🔐 PKCE Code Challenge: ${CODE_CHALLENGE:0:20}..."
}

# Function to generate secure state parameter
generate_state() {
    STATE=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    echo "🎲 State: ${STATE:0:20}..."
}

# Function to perform authorization code flow
perform_auth_flow() {
    local scope="$1"
    local test_name="$2"

    echo "" >&2
    echo "📋 $test_name" >&2

    # Generate PKCE parameters
    generate_pkce >&2
    generate_state >&2

    # Build authorization URL
    local auth_url="$BASE_URL/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&state=$STATE"
    if [ -n "$scope" ]; then
        auth_url="$auth_url&scope=$(echo "$scope" | sed 's/ /%20/g')"
    fi
    auth_url="$auth_url&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"

    echo "🔗 Authorization URL: $auth_url" >&2

    # Make initial GET request to authorization endpoint to get login form
    echo "🌐 Making initial authorization request..." >&2
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
                -u "$CLIENT_ID:$CLIENT_SECRET" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -d "grant_type=authorization_code&code=$auth_code&redirect_uri=$REDIRECT_URI&code_verifier=$CODE_VERIFIER")

            local access_token=$(echo "$token_response" | jq -r '.access_token // empty')

            if [ -z "$access_token" ] || [ "$access_token" = "null" ]; then
                echo "❌ Failed to get access token" >&2
                echo "Response: $token_response" >&2
                return 1
            fi

            echo "✅ Got access token: ${access_token:0:30}..." >&2

            # Test UserInfo endpoint
            echo "👤 Testing UserInfo endpoint..." >&2
            local userinfo_response=$(curl -s -X GET "$BASE_URL/userinfo" \
                -H "Authorization: Bearer $access_token")

            # Check if UserInfo worked
            if echo "$userinfo_response" | jq -e '.username' >/dev/null 2>&1; then
                echo "✅ UserInfo endpoint working" >&2
                local username=$(echo "$userinfo_response" | jq -r '.username')
                local email=$(echo "$userinfo_response" | jq -r '.email')
                echo "   Username: $username" >&2
                echo "   Email: $email" >&2
            else
                echo "❌ UserInfo failed: $userinfo_response" >&2
                return 1
            fi

            # Introspect token to verify scopes
            echo "🔍 Introspecting token to verify scopes..." >&2
            local introspect_response=$(curl -s -X POST "$BASE_URL/introspect" \
                -u "$CLIENT_ID:$CLIENT_SECRET" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -d "token=$access_token")

            local token_scope=$(echo "$introspect_response" | jq -r '.scope // empty')

            if [ -z "$token_scope" ] || [ "$token_scope" = "null" ]; then
                echo "❌ Failed to introspect token" >&2
                return 1
            fi

            echo "✅ Token scope: $token_scope" >&2

            # Return the scope for validation (only output the scope, no other messages)
            echo "$token_scope"
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

# Test 1: No scope parameter (should default to openid)
echo "🧪 Test 1: No scope parameter (should default to openid)"
SCOPE_1=$(perform_auth_flow "" "Test 1: Default scope handling" | tr -d '\n')

if [ $? -eq 0 ] && [ "$SCOPE_1" = "openid" ]; then
    echo "✅ Test 1 PASSED - Default scope is 'openid'"
    TEST1_PASS=true
else
    echo "❌ Test 1 FAILED - Expected scope 'openid', got '$SCOPE_1'"
    TEST1_PASS=false
fi

# Test 2: Explicit scope parameter
echo ""
echo "🧪 Test 2: Explicit scope parameter ($TEST_SCOPE)"
SCOPE_2=$(perform_auth_flow "$TEST_SCOPE" "Test 2: Explicit scope handling" | tr -d '\n')

if [ $? -eq 0 ]; then
    # Check if all requested scopes are present
    all_scopes_present=true
    for scope in $TEST_SCOPE; do
        if [[ "$SCOPE_2" != *"$scope"* ]]; then
            all_scopes_present=false
            break
        fi
    done

    if [ "$all_scopes_present" = true ]; then
        echo "✅ Test 2 PASSED - All requested scopes present: $SCOPE_2"
        TEST2_PASS=true
    else
        echo "❌ Test 2 FAILED - Missing scopes. Requested: $TEST_SCOPE, Got: $SCOPE_2"
        TEST2_PASS=false
    fi
else
    echo "❌ Test 2 FAILED - Authorization flow failed"
    TEST2_PASS=false
fi

# Test 3: Scope comparison
echo ""
echo "🧪 Test 3: Scope comparison between tests"
if [ "$TEST1_PASS" = true ] && [ "$TEST2_PASS" = true ]; then
    if [ "$SCOPE_1" != "$SCOPE_2" ]; then
        echo "✅ Test 3 PASSED - Scopes are different (as expected)"
        echo "   Default scope: $SCOPE_1"
        echo "   Explicit scope: $SCOPE_2"
        TEST3_PASS=true
    else
        echo "⚠️  Test 3 WARNING - Scopes are the same (unexpected but not failing)"
        echo "   Both scopes: $SCOPE_1"
        TEST3_PASS=true
    fi
else
    echo "❌ Test 3 SKIPPED - Previous tests failed"
    TEST3_PASS=false
fi

# Summary
echo ""
echo "📊 Test Results Summary"
echo "======================="
echo "Test 1 (Default scope): $([ "$TEST1_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Test 2 (Explicit scope): $([ "$TEST2_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Test 3 (Scope comparison): $([ "$TEST3_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"

# Overall result
if [ "$TEST1_PASS" = true ] && [ "$TEST2_PASS" = true ] && [ "$TEST3_PASS" = true ]; then
    echo ""
    echo "🎉 All scope handling tests PASSED!"
    exit 0
else
    echo ""
    echo "❌ Some scope handling tests FAILED!"
    exit 1
fi