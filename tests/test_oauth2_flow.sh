#!/bin/bash

echo "=== Automated OAuth2 Authorization Code Flow Test ==="
echo "This script tests the complete OAuth2 authorization code flow with PKCE."
echo "Assumes the OAuth2 server is already running on localhost:8080."
echo ""

# Configuration
SERVER_URL="http://localhost:8080"
USERNAME="${TEST_USERNAME:-john.doe}"
PASSWORD="${TEST_PASSWORD:-password123}"
SCOPE="${TEST_SCOPE:-openid profile email}"
REDIRECT_URI="http://localhost:8080/callback"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper function for colored output
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

# Step 1: Register a public client
print_status "Step 1: Registering a public client..."

CLIENT_REGISTRATION_PAYLOAD='{
    "client_name": "Test Public Client - Automated Test",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "scope": "'$SCOPE'",
    "redirect_uris": ["'$REDIRECT_URI'"]
}'

print_status "Registration payload: $CLIENT_REGISTRATION_PAYLOAD"

REGISTRATION_RESPONSE=$(curl -s -X POST "${SERVER_URL}/register" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: super-secure-random-api-key-change-in-production-32-chars-minimum" \
    -d "$CLIENT_REGISTRATION_PAYLOAD")

if [ $? -ne 0 ]; then
    print_error "Failed to register client - curl error"
    exit 1
fi

print_status "Registration response: $REGISTRATION_RESPONSE"

# Extract client ID
CLIENT_ID=$(echo "$REGISTRATION_RESPONSE" | jq -r '.client_id' 2>/dev/null)

if [ "$CLIENT_ID" = "null" ] || [ -z "$CLIENT_ID" ]; then
    print_error "Failed to extract client_id from registration response"
    print_error "Response: $REGISTRATION_RESPONSE"
    exit 1
fi

print_success "Registered public client with ID: $CLIENT_ID"

# Step 2: Initiate authorization request
print_status "Step 2: Initiating authorization request..."

# Generate PKCE challenge (using S256 as required by the server)
CODE_CHALLENGE_METHOD="S256"
# For S256, we need to hash the verifier
CODE_VERIFIER="testchallenge12345678901234567890123456789012"  # Must be 43-128 chars
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')

AUTH_URL="${SERVER_URL}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=${SCOPE}&state=teststate123&code_challenge=${CODE_CHALLENGE}&code_challenge_method=${CODE_CHALLENGE_METHOD}"

print_status "Authorization URL: $AUTH_URL"

# Step 3: Simulate user login and get authorization code
print_status "Step 3: Simulating user login and getting authorization code..."

# First, make a GET request to the authorization endpoint to get any session cookies
# Use a minimal URL for the GET request to avoid URL length issues
MINIMAL_AUTH_URL="${SERVER_URL}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=openid&state=teststate123"
print_status "Making initial GET request to authorization endpoint..."
INITIAL_RESPONSE=$(curl -s -i -c /tmp/cookies.txt "$MINIMAL_AUTH_URL")

# Check if we got a login form (should contain HTML with form elements)
if echo "$INITIAL_RESPONSE" | grep -q "login\|Login\|username\|password"; then
    print_status "Login form received, proceeding with authentication..."
else
    print_error "Expected login form but got different response"
    print_error "Response preview:"
    echo "$INITIAL_RESPONSE" | head -10
    exit 1
fi

# Now POST the login credentials to the authorization endpoint with all required parameters
print_status "Submitting login credentials..."
LOGIN_RESPONSE=$(curl -s -i -b /tmp/cookies.txt -c /tmp/cookies.txt \
    -X POST "${SERVER_URL}/authorize" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${USERNAME}&password=${PASSWORD}&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=${SCOPE}&state=teststate123&code_challenge=${CODE_CHALLENGE}&code_challenge_method=${CODE_CHALLENGE_METHOD}")

# Check if login was successful and we got a redirect with authorization code
LOCATION_HEADER=$(echo "$LOGIN_RESPONSE" | grep -i "^Location:" | head -1 | sed 's/Location: //' | tr -d '\r\n')

if [ -z "$LOCATION_HEADER" ]; then
    print_error "No redirect location found after login"
    print_error "Login response headers:"
    echo "$LOGIN_RESPONSE" | head -20
    rm -f /tmp/cookies.txt
    exit 1
fi

print_status "Redirect location: $LOCATION_HEADER"

# Extract authorization code from the redirect URL
AUTH_CODE=$(echo "$LOCATION_HEADER" | grep -o 'code=[^&]*' | cut -d'=' -f2)

if [ -z "$AUTH_CODE" ]; then
    print_error "Failed to extract authorization code from redirect"
    print_error "Location header: $LOCATION_HEADER"
    rm -f /tmp/cookies.txt
    exit 1
fi

rm -f /tmp/cookies.txt
print_success "Obtained authorization code: ${AUTH_CODE:0:30}..."

# Step 4: Exchange authorization code for tokens
print_status "Step 4: Exchanging authorization code for access token..."

TOKEN_RESPONSE=$(curl -s -X POST "${SERVER_URL}/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=${AUTH_CODE}&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&code_verifier=${CODE_VERIFIER}")

if [ $? -ne 0 ]; then
    print_error "Token exchange request failed"
    exit 1
fi

print_status "Token response: $TOKEN_RESPONSE"

# Extract tokens
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token' 2>/dev/null)
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token' 2>/dev/null)
ID_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.id_token' 2>/dev/null)

if [ "$ACCESS_TOKEN" = "null" ] || [ -z "$ACCESS_TOKEN" ]; then
    print_error "Failed to obtain access token"
    print_error "Full response: $TOKEN_RESPONSE"
    exit 1
fi

print_success "Successfully obtained access token: ${ACCESS_TOKEN:0:30}..."
if [ "$REFRESH_TOKEN" != "null" ] && [ -n "$REFRESH_TOKEN" ]; then
    print_success "Also obtained refresh token: ${REFRESH_TOKEN:0:30}..."
fi
if [ "$ID_TOKEN" != "null" ] && [ -n "$ID_TOKEN" ]; then
    print_success "Also obtained ID token: ${ID_TOKEN:0:30}..."
fi

# Optional: Test the access token with UserInfo endpoint
print_status "Testing access token with UserInfo endpoint..."

USERINFO_RESPONSE=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "${SERVER_URL}/userinfo")

if [ $? -eq 0 ]; then
    print_success "UserInfo endpoint accessible"
    print_status "UserInfo response: $USERINFO_RESPONSE"
else
    print_warning "UserInfo endpoint test failed, but token exchange was successful"
fi

# Cleanup
print_status "Cleaning up..."

# Remove cookie file if it exists
if [ -f "cookies.txt" ]; then
    rm -f cookies.txt
fi

echo ""
print_success "🎉 OAuth2 Authorization Code Flow completed successfully!"
echo ""
echo "Summary:"
echo "- ✅ Public client registered (ID: $CLIENT_ID)"
echo "- ✅ Authorization request initiated"
echo "- ✅ User login simulated"
echo "- ✅ Authorization code obtained"
echo "- ✅ Code exchanged for tokens"
echo ""
echo "Access Token: ${ACCESS_TOKEN:0:50}..."
if [ "$REFRESH_TOKEN" != "null" ] && [ -n "$REFRESH_TOKEN" ]; then
    echo "Refresh Token: ${REFRESH_TOKEN:0:50}..."
fi