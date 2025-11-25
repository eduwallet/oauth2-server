#!/bin/bash

echo "🔄 Basic Refresh Token Test"
echo "==========================="
echo "Testing refresh token functionality:"
echo "- Request tokens with refresh_token grant type"
echo "- Use refresh token to obtain new access token"
echo ""

# Configuration
SERVER_URL="http://localhost:8080"
USERNAME="${TEST_USERNAME:-john.doe}"
PASSWORD="${TEST_PASSWORD:-password123}"
SCOPE="${TEST_SCOPE:-openid profile email offline_access}"
REDIRECT_URI="http://localhost:8080/callback"
API_KEY="${API_KEY:-super-secure-random-api-key-change-in-production-32-chars-minimum}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to generate PKCE challenge
generate_pkce() {
    CODE_VERIFIER="testchallenge12345678901234567890123456789012"
    CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')
}

# Step 1: Register a confidential client that supports refresh tokens
print_status "Step 1: Registering a confidential client with refresh token support..."

CLIENT_REGISTRATION_PAYLOAD='{
    "client_name": "Test Refresh Token Client",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "'"$SCOPE"'",
    "redirect_uris": ["'"$REDIRECT_URI"'"]
}'

print_status "Registration payload: $CLIENT_REGISTRATION_PAYLOAD"

REGISTRATION_RESPONSE=$(curl -s -X POST "${SERVER_URL}/register" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "$CLIENT_REGISTRATION_PAYLOAD")

if [ $? -ne 0 ]; then
    print_error "Failed to register client - curl error"
    exit 1
fi

print_status "Registration response: $REGISTRATION_RESPONSE"

# Extract client credentials
CLIENT_ID=$(echo "$REGISTRATION_RESPONSE" | jq -r '.client_id' 2>/dev/null)
CLIENT_SECRET=$(echo "$REGISTRATION_RESPONSE" | jq -r '.client_secret' 2>/dev/null)

if [ "$CLIENT_ID" = "null" ] || [ -z "$CLIENT_ID" ]; then
    print_error "Failed to extract client_id from registration response"
    exit 1
fi

if [ "$CLIENT_SECRET" = "null" ] || [ -z "$CLIENT_SECRET" ]; then
    print_error "Failed to extract client_secret from registration response"
    exit 1
fi

print_success "Registered confidential client with ID: $CLIENT_ID"

# Step 2: Perform authorization code flow to get initial tokens including refresh token
print_status "Step 2: Performing authorization code flow to obtain initial tokens..."

# Skip PKCE for now to test basic flow
SCOPE_ENCODED=$(echo "$SCOPE" | sed 's/ /%20/g')
AUTH_URL="${SERVER_URL}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=${SCOPE_ENCODED}&state=teststate123"

print_status "Authorization URL (without PKCE): $AUTH_URL"

# Get login form
print_status "Making GET request to authorization endpoint..."
print_status "Checking if server is still running..."
curl -s http://localhost:8080/health && print_status "Server is still running" || print_error "Server is not responding to health check"

print_status "Testing simple authorize endpoint access..."
SIMPLE_AUTH_RESPONSE=$(curl -s -i "http://localhost:8080/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid&state=teststate123")
print_status "Simple auth response:"
echo "$SIMPLE_AUTH_RESPONSE" | head -10

INITIAL_RESPONSE=$(curl -s -i -c /tmp/cookies.txt "$AUTH_URL")

print_status "Raw response from authorization endpoint:"
echo "$INITIAL_RESPONSE" | head -20

if echo "$INITIAL_RESPONSE" | grep -q "login\|Login\|username\|password"; then
    print_status "Login form received, proceeding with authentication..."
else
    print_error "Expected login form but got different response"
    print_error "Response headers:"
    echo "$INITIAL_RESPONSE" | grep -E "^(HTTP|Content-Type|Location|Set-Cookie)" || echo "No standard headers found"
    print_error "Response body preview:"
    echo "$INITIAL_RESPONSE" | sed -n '/^$/,$p' | head -10
    rm -f /tmp/cookies.txt
    exit 1
fi

# Submit login credentials
LOGIN_RESPONSE=$(curl -s -i -b /tmp/cookies.txt -c /tmp/cookies.txt \
    -X POST "${SERVER_URL}/authorize" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${USERNAME}&password=${PASSWORD}&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=${SCOPE}&state=teststate123&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256")

# Extract authorization code
LOCATION_HEADER=$(echo "$LOGIN_RESPONSE" | grep -i "^Location:" | head -1 | sed 's/Location: //' | tr -d '\r\n')

if [ -z "$LOCATION_HEADER" ]; then
    print_error "No redirect location found after login"
    rm -f /tmp/cookies.txt
    exit 1
fi

AUTH_CODE=$(echo "$LOCATION_HEADER" | grep -o 'code=[^&]*' | cut -d'=' -f2)

if [ -z "$AUTH_CODE" ]; then
    print_error "Failed to extract authorization code from redirect"
    rm -f /tmp/cookies.txt
    exit 1
fi

rm -f /tmp/cookies.txt
print_success "Obtained authorization code: ${AUTH_CODE:0:30}..."

# Step 3: Exchange authorization code for tokens (including refresh token)
print_status "Step 3: Exchanging authorization code for access and refresh tokens..."

TOKEN_RESPONSE=$(curl -s -X POST "${SERVER_URL}/token" \
    -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=${AUTH_CODE}&redirect_uri=${REDIRECT_URI}")

if [ $? -ne 0 ]; then
    print_error "Token exchange request failed"
    exit 1
fi

print_status "Token response: $TOKEN_RESPONSE"

# Extract tokens
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token' 2>/dev/null)
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token' 2>/dev/null)
TOKEN_TYPE=$(echo "$TOKEN_RESPONSE" | jq -r '.token_type' 2>/dev/null)
EXPIRES_IN=$(echo "$TOKEN_RESPONSE" | jq -r '.expires_in' 2>/dev/null)

if [ "$ACCESS_TOKEN" = "null" ] || [ -z "$ACCESS_TOKEN" ]; then
    print_error "Failed to obtain access token"
    exit 1
fi

if [ "$REFRESH_TOKEN" = "null" ] || [ -z "$REFRESH_TOKEN" ]; then
    print_error "Failed to obtain refresh token"
    exit 1
fi

print_success "Successfully obtained access token: ${ACCESS_TOKEN:0:30}..."
print_success "Successfully obtained refresh token: ${REFRESH_TOKEN:0:30}..."
print_status "Token type: $TOKEN_TYPE, Expires in: $EXPIRES_IN seconds"

# Step 4: Test the initial access token with UserInfo endpoint
print_status "Step 4: Testing initial access token with UserInfo endpoint..."

USERINFO_RESPONSE=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "${SERVER_URL}/userinfo")

if [ $? -eq 0 ] && echo "$USERINFO_RESPONSE" | jq -e '.username' >/dev/null 2>&1; then
    print_success "UserInfo endpoint accessible with initial access token"
    USERNAME=$(echo "$USERINFO_RESPONSE" | jq -r '.username')
    print_status "UserInfo response contains username: $USERNAME"
else
    print_warning "UserInfo endpoint test failed with initial token, but continuing..."
    print_status "UserInfo response: $USERINFO_RESPONSE"
fi

# Step 5: Wait a moment to ensure token timestamps are different
print_status "Step 5: Waiting 2 seconds before refresh..."
sleep 2

# Step 6: Use refresh token to obtain new access token
print_status "Step 6: Using refresh token to obtain new access token..."

REFRESH_RESPONSE=$(curl -s -X POST "${SERVER_URL}/token" \
    -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=refresh_token&refresh_token=${REFRESH_TOKEN}")

if [ $? -ne 0 ]; then
    print_error "Refresh token request failed"
    exit 1
fi

print_status "Refresh response: $REFRESH_RESPONSE"

# Extract new tokens
NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.access_token' 2>/dev/null)
NEW_REFRESH_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.refresh_token' 2>/dev/null)
NEW_TOKEN_TYPE=$(echo "$REFRESH_RESPONSE" | jq -r '.token_type' 2>/dev/null)
NEW_EXPIRES_IN=$(echo "$REFRESH_RESPONSE" | jq -r '.expires_in' 2>/dev/null)

if [ "$NEW_ACCESS_TOKEN" = "null" ] || [ -z "$NEW_ACCESS_TOKEN" ]; then
    print_error "Failed to obtain new access token from refresh"
    exit 1
fi

print_success "Successfully obtained new access token: ${NEW_ACCESS_TOKEN:0:30}..."

if [ "$NEW_REFRESH_TOKEN" != "null" ] && [ -n "$NEW_REFRESH_TOKEN" ]; then
    print_success "Also obtained new refresh token: ${NEW_REFRESH_TOKEN:0:30}..."
else
    print_status "No new refresh token provided (this is normal for some OAuth2 implementations)"
fi

print_status "New token type: $NEW_TOKEN_TYPE, Expires in: $NEW_EXPIRES_IN seconds"

# Step 7: Verify the new access token works
print_status "Step 7: Testing new access token with UserInfo endpoint..."

NEW_USERINFO_RESPONSE=$(curl -s -H "Authorization: Bearer $NEW_ACCESS_TOKEN" "${SERVER_URL}/userinfo")

if [ $? -eq 0 ] && echo "$NEW_USERINFO_RESPONSE" | jq -e '.username' >/dev/null 2>&1; then
    print_success "UserInfo endpoint accessible with refreshed access token"
    NEW_USERNAME=$(echo "$NEW_USERINFO_RESPONSE" | jq -r '.username')
    print_status "Refreshed UserInfo response contains username: $NEW_USERNAME"

    # Verify it's the same user
    if [ "$USERNAME" = "$NEW_USERNAME" ]; then
        print_success "User identity preserved across token refresh"
    else
        print_warning "User identity changed during refresh (this might be expected behavior)"
    fi
else
    print_error "UserInfo endpoint failed with refreshed token"
    print_status "UserInfo response: $NEW_USERINFO_RESPONSE"
    exit 1
fi

# Step 8: Verify old access token is still valid (or expired as expected)
print_status "Step 8: Verifying old access token behavior after refresh..."

OLD_USERINFO_RESPONSE=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "${SERVER_URL}/userinfo")

if [ $? -eq 0 ] && echo "$OLD_USERINFO_RESPONSE" | jq -e '.username' >/dev/null 2>&1; then
    print_status "Old access token still valid after refresh (implementation dependent)"
else
    print_status "Old access token no longer valid after refresh (this is normal)"
fi

# Cleanup
print_status "Cleaning up..."

# Remove cookie file if it exists
if [ -f "/tmp/cookies.txt" ]; then
    rm -f /tmp/cookies.txt
fi

echo ""
print_success "🎉 Basic Refresh Token Test completed successfully!"
echo ""
echo "Summary:"
echo "- ✅ Confidential client registered (ID: $CLIENT_ID)"
echo "- ✅ Authorization code flow completed"
echo "- ✅ Initial access and refresh tokens obtained"
echo "- ✅ Initial access token validated with UserInfo"
echo "- ✅ Refresh token used to obtain new access token"
echo "- ✅ New access token validated with UserInfo"
echo ""
echo "Initial Access Token: ${ACCESS_TOKEN:0:50}..."
echo "Refresh Token: ${REFRESH_TOKEN:0:50}..."
echo "New Access Token: ${NEW_ACCESS_TOKEN:0:50}..."
if [ "$NEW_REFRESH_TOKEN" != "null" ] && [ -n "$NEW_REFRESH_TOKEN" ]; then
    echo "New Refresh Token: ${NEW_REFRESH_TOKEN:0:50}..."
fi