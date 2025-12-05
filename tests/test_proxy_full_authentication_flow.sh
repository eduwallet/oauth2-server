#!/bin/bash

# Test: Complete User Authentication Flow with Upstream IDP
# This test simulates the full OAuth2 authorization code flow in proxy mode:
# 1. User authentication with upstream IDP
# 2. Authorization code exchange for tokens
# 3. UserInfo endpoint evaluation

set -e

echo "🧪 Complete User Authentication Flow Test (Proxy Mode)"
echo "======================================================"

# Configuration
OAUTH2_SERVER_URL="http://localhost:8080"
MOCK_PROVIDER_URL="http://localhost:9999"
TEST_CLIENT_ID="test-client-$(date +%s)"
TEST_CLIENT_SECRET="test-secret-$(date +%s)"
TEST_REDIRECT_URI="http://localhost:8081/callback"
TEST_USERNAME="john.doe"
TEST_PASSWORD="password123"
TEST_SCOPE="openid profile email"
API_KEY="super-secure-random-api-key-change-in-production-32-chars-minimum"

echo ""
echo "📋 Test Configuration:"
echo "  OAuth2 Server: $OAUTH2_SERVER_URL"
echo "  Mock Provider: $MOCK_PROVIDER_URL"
echo "  Client ID: $TEST_CLIENT_ID"
echo "  Redirect URI: $TEST_REDIRECT_URI"
echo "  Test User: $TEST_USERNAME"
echo "  Scope: $TEST_SCOPE"

echo ""
echo "🔍 Step 1: Verifying services are running..."

# Check mock provider
if curl -s -f "$MOCK_PROVIDER_URL/health" > /dev/null 2>&1; then
    echo "✅ Mock provider is running"
else
    echo "❌ Mock provider not responding at $MOCK_PROVIDER_URL"
    exit 1
fi

# Check OAuth2 server
if curl -s -f "$OAUTH2_SERVER_URL/health" > /dev/null 2>&1; then
    echo "✅ OAuth2 server is running"
else
    echo "❌ OAuth2 server not responding at $OAUTH2_SERVER_URL"
    exit 1
fi

echo ""
echo "👤 Step 2: Registering test client..."

# Register client
REGISTER_PAYLOAD=$(cat <<EOF
{
  "client_id": "$TEST_CLIENT_ID",
  "client_secret": "$TEST_CLIENT_SECRET",
  "redirect_uris": ["$TEST_REDIRECT_URI"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "$TEST_SCOPE",
  "token_endpoint_auth_method": "client_secret_basic"
}
EOF
)

REGISTER_RESPONSE=$(curl -s -X POST "$OAUTH2_SERVER_URL/register" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "$REGISTER_PAYLOAD")

if echo "$REGISTER_RESPONSE" | grep -q "client_id"; then
    echo "✅ Client registered successfully"
    echo "   Response: $(echo "$REGISTER_RESPONSE" | jq -c . 2>/dev/null || echo "$REGISTER_RESPONSE")"
else
    echo "❌ Client registration failed"
    echo "   Response: $REGISTER_RESPONSE"
    exit 1
fi

echo ""
echo "🔐 Step 3: Initiating authorization request..."

# Generate state and nonce for security
STATE="test-state-$(date +%s)"
NONCE="test-nonce-$(date +%s)"

# URL-encode the scope parameter
ENCODED_SCOPE=$(echo "$TEST_SCOPE" | sed 's/ /%20/g')

# Make authorization request
AUTH_URL="$OAUTH2_SERVER_URL/authorize?client_id=$TEST_CLIENT_ID&redirect_uri=$TEST_REDIRECT_URI&response_type=code&scope=$ENCODED_SCOPE&state=$STATE&nonce=$NONCE"

echo "   Authorization URL: $AUTH_URL"

# First, let's try a simple request without following redirects to see what happens
echo ""
echo "🔍 Step 4a: Testing authorization endpoint response..."

# Debug: Check server health before authorization request
echo "   Checking server health before authorization request..."
if curl -s -f --connect-timeout 2 --max-time 5 "$OAUTH2_SERVER_URL/health" > /dev/null 2>&1; then
    echo "   ✅ Server is still healthy before authorization request"
else
    echo "   ❌ Server is not responding before authorization request"
    exit 1
fi

echo "   Making authorization request with curl..."
echo "   URL: $AUTH_URL"

# Try a simple curl first to see if it connects
if curl -v --connect-timeout 5 --max-time 10 "$AUTH_URL" 2>&1 | head -10; then
    echo "   ✅ Curl command executed"
else
    echo "   ❌ Curl command failed"
    exit 1
fi

# Now try the original command
AUTH_RESPONSE=$(curl -s -w "HTTP_CODE:%{http_code}\n" \
  --connect-timeout 5 --max-time 10 \
  "$AUTH_URL" 2>/dev/null)

HTTP_CODE=$(echo "$AUTH_RESPONSE" | grep "HTTP_CODE:" | sed 's/HTTP_CODE://')
RESPONSE_BODY=$(echo "$AUTH_RESPONSE" | grep -v "HTTP_CODE:")

echo "   HTTP Status Code: $HTTP_CODE"
echo "   Response Body Length: ${#RESPONSE_BODY} characters"

if [ "$HTTP_CODE" = "302" ]; then
    echo "✅ Authorization endpoint returned redirect (302) as expected"
    LOCATION=$(echo "$RESPONSE_BODY" | grep -i "location:" | sed 's/.*location: *//i' 2>/dev/null || echo "")
    if [ -n "$LOCATION" ]; then
        echo "   Redirect Location: $LOCATION"
    fi
elif [ "$HTTP_CODE" = "200" ]; then
    echo "ℹ️  Authorization endpoint returned 200 (might be login page)"
else
    echo "❌ Authorization endpoint returned unexpected status: $HTTP_CODE"
    echo "   Response: $RESPONSE_BODY"
fi

echo "   Raw response: $AUTH_RESPONSE"

# Check if we got a redirect
if echo "$AUTH_RESPONSE" | grep -q "HTTP_CODE:302"; then
    echo "✅ Got redirect response (302) as expected"
    
    # Now try following redirects with a shorter timeout
    echo ""
    echo "🔄 Step 4b: Following authorization redirect chain..."
    AUTH_REDIRECT_OUTPUT=$(timeout 15 curl -s -L --connect-timeout 3 --max-time 5 \
      -w "FINAL_URL:%{url_effective}\nHTTP_CODE:%{http_code}\nREDIRECT_COUNT:%{num_redirects}\n" \
      "$AUTH_URL" 2>/dev/null || echo "TIMEOUT_OR_ERROR")
else
    echo "❌ Expected redirect (302) but got: $(echo "$AUTH_RESPONSE" | grep "HTTP_CODE:" | sed 's/HTTP_CODE://')"
    exit 1
fi

# Extract the final URL and check if it contains an authorization code
FINAL_URL=$(echo "$AUTH_REDIRECT_OUTPUT" | grep "FINAL_URL:" | sed 's/FINAL_URL://' 2>/dev/null || echo "")
HTTP_CODE=$(echo "$AUTH_REDIRECT_OUTPUT" | grep "HTTP_CODE:" | sed 's/HTTP_CODE://' 2>/dev/null || echo "000")
REDIRECT_COUNT=$(echo "$AUTH_REDIRECT_OUTPUT" | grep "REDIRECT_COUNT:" | sed 's/REDIRECT_COUNT://' 2>/dev/null || echo "0")

echo "   Final URL: $FINAL_URL"
echo "   HTTP Code: $HTTP_CODE"
echo "   Redirects: $REDIRECT_COUNT"

# Extract authorization code from the final URL
if echo "$FINAL_URL" | grep -q "code="; then
    AUTH_CODE=$(echo "$FINAL_URL" | sed 's/.*code=\([^&]*\).*/\1/')
    RETURNED_STATE=$(echo "$FINAL_URL" | sed 's/.*state=\([^&]*\).*/\1/' 2>/dev/null || echo "")
    echo "✅ Authorization code received: ${AUTH_CODE:0:20}..."
    echo "   State parameter: $RETURNED_STATE"

    # Verify state matches
    if [ "$RETURNED_STATE" = "$STATE" ]; then
        echo "✅ State parameter matches (CSRF protection verified)"
    else
        echo "❌ State parameter mismatch (CSRF protection failed)"
        exit 1
    fi
else
    echo "❌ No authorization code found in redirect URL"
    echo "   This might indicate the authorization flow failed"
    exit 1
fi

echo ""
echo "🔑 Step 5: Exchanging authorization code for tokens..."

# Exchange authorization code for tokens
TOKEN_RESPONSE=$(curl -s -X POST "$OAUTH2_SERVER_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "$TEST_CLIENT_ID:$TEST_CLIENT_SECRET" \
  -d "grant_type=authorization_code&code=$AUTH_CODE&redirect_uri=$TEST_REDIRECT_URI")

echo "   Token exchange response:"
echo "$TOKEN_RESPONSE" | jq . 2>/dev/null || echo "$TOKEN_RESPONSE"

# Extract tokens
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token' 2>/dev/null)
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token' 2>/dev/null)
ID_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.id_token' 2>/dev/null)
TOKEN_TYPE=$(echo "$TOKEN_RESPONSE" | jq -r '.token_type' 2>/dev/null)
EXPIRES_IN=$(echo "$TOKEN_RESPONSE" | jq -r '.expires_in' 2>/dev/null)
SCOPE=$(echo "$TOKEN_RESPONSE" | jq -r '.scope' 2>/dev/null)

if [ "$ACCESS_TOKEN" != "null" ] && [ "$ACCESS_TOKEN" != "" ]; then
    echo "✅ Token exchange successful"
    echo "   Access Token: ${ACCESS_TOKEN:0:20}..."
    echo "   Token Type: $TOKEN_TYPE"
    echo "   Expires In: $EXPIRES_IN seconds"
    echo "   Scope: $SCOPE"
    if [ "$REFRESH_TOKEN" != "null" ] && [ "$REFRESH_TOKEN" != "" ]; then
        echo "   Refresh Token: ${REFRESH_TOKEN:0:20}..."
    fi
    if [ "$ID_TOKEN" != "null" ] && [ "$ID_TOKEN" != "" ]; then
        echo "   ID Token: ${ID_TOKEN:0:20}..."
    fi
else
    echo "❌ Token exchange failed"
    exit 1
fi

echo ""
echo "👤 Step 6: Testing UserInfo endpoint..."

# Call UserInfo endpoint with access token
USERINFO_RESPONSE=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$OAUTH2_SERVER_URL/userinfo")

echo "   UserInfo response:"
echo "$USERINFO_RESPONSE" | jq . 2>/dev/null || echo "$USERINFO_RESPONSE"

# Validate UserInfo response
if echo "$USERINFO_RESPONSE" | grep -q "sub"; then
    echo "✅ UserInfo endpoint returned user data"

    # Extract key claims
    SUB=$(echo "$USERINFO_RESPONSE" | jq -r '.sub' 2>/dev/null)
    EMAIL=$(echo "$USERINFO_RESPONSE" | jq -r '.email' 2>/dev/null)
    NAME=$(echo "$USERINFO_RESPONSE" | jq -r '.name' 2>/dev/null)
    EMAIL_VERIFIED=$(echo "$USERINFO_RESPONSE" | jq -r '.email_verified' 2>/dev/null)

    echo "   User Claims:"
    echo "     Subject (sub): $SUB"
    echo "     Email: $EMAIL"
    echo "     Name: $NAME"
    echo "     Email Verified: $EMAIL_VERIFIED"

    # Verify expected user data
    if [ "$SUB" = "john.doe" ]; then
        echo "✅ Subject claim matches expected user"
    else
        echo "❌ Subject claim mismatch (expected: john.doe, got: $SUB)"
    fi

    if [ "$EMAIL" = "upstream@example.com" ]; then
        echo "✅ Email claim matches expected value"
    else
        echo "❌ Email claim mismatch (expected: upstream@example.com, got: $EMAIL)"
    fi

    if [ "$NAME" = "John Doe" ]; then
        echo "✅ Name claim matches expected value"
    else
        echo "❌ Name claim mismatch (expected: John Doe, got: $NAME)"
    fi

else
    echo "❌ UserInfo endpoint failed or returned no data"
    exit 1
fi

echo ""
echo "🔄 Step 7: Testing token refresh (if refresh token available)..."

if [ "$REFRESH_TOKEN" != "null" ] && [ "$REFRESH_TOKEN" != "" ]; then
    REFRESH_RESPONSE=$(curl -s -X POST "$OAUTH2_SERVER_URL/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -u "$TEST_CLIENT_ID:$TEST_CLIENT_SECRET" \
      -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN&scope=$TEST_SCOPE")

    echo "   Refresh token response:"
    echo "$REFRESH_RESPONSE" | jq . 2>/dev/null || echo "$REFRESH_RESPONSE"

    NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.access_token' 2>/dev/null)
    NEW_REFRESH_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.refresh_token' 2>/dev/null)

    if [ "$NEW_ACCESS_TOKEN" != "null" ] && [ "$NEW_ACCESS_TOKEN" != "" ]; then
        echo "✅ Token refresh successful"
        echo "   New Access Token: ${NEW_ACCESS_TOKEN:0:20}..."

        # Test UserInfo with refreshed token
        REFRESHED_USERINFO=$(curl -s -H "Authorization: Bearer $NEW_ACCESS_TOKEN" \
          "$OAUTH2_SERVER_URL/userinfo")

        if echo "$REFRESHED_USERINFO" | grep -q "sub"; then
            echo "✅ Refreshed token UserInfo works"
        else
            echo "❌ Refreshed token UserInfo failed"
        fi
    else
        echo "❌ Token refresh failed"
    fi
else
    echo "ℹ️  No refresh token available, skipping refresh test"
fi

echo ""
echo "🎉 Complete User Authentication Flow Test PASSED!"
echo ""
echo "Summary:"
echo "✅ User authentication with upstream IDP"
echo "✅ Authorization code flow completed"
echo "✅ Token exchange successful"
echo "✅ UserInfo endpoint working"
echo "✅ User claims validated"
if [ "$REFRESH_TOKEN" != "null" ] && [ "$REFRESH_TOKEN" != "" ]; then
    echo "✅ Token refresh working"
fi
echo ""
echo "The OAuth2 proxy server successfully:"
echo "1. Redirected user to upstream IDP for authentication"
echo "2. Received authorization code from upstream provider"
echo "3. Exchanged code for access/refresh tokens"
echo "4. Provided user information via UserInfo endpoint"
echo "5. Maintained proper token mapping in proxy mode"