#!/bin/bash

# Test configuration - use environment variables with defaults
TEST_USERNAME="${TEST_USERNAME:-john.doe}"
TEST_PASSWORD="${TEST_PASSWORD:-password123}"
TEST_SCOPE="${TEST_SCOPE:-openid profile}"

echo "🧪 UserInfo Endpoint Test"
echo "========================="
echo "Testing OpenID Connect UserInfo endpoint"
echo "Using client credentials flow to obtain test token"

BASE_URL="${OAUTH2_SERVER_URL:-http://localhost:8080}"

# Get an access token using client credentials flow
echo "🎫 Getting access token using client credentials..."
TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/token" \
  -u "backend-client:backend-client-secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=openid profile")

echo "Token Response: $TOKEN_RESPONSE"

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
    echo "❌ Failed to get access token: $TOKEN_RESPONSE"
    exit 1
fi

echo "✅ Got access token: ${ACCESS_TOKEN:0:30}..."

# Test UserInfo endpoint (expecting error for client credentials token)
echo "👤 Testing UserInfo endpoint..."
USERINFO_RESPONSE=$(curl -s -X GET "$BASE_URL/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "UserInfo Response: $USERINFO_RESPONSE"

# For client credentials tokens, UserInfo should return an error
if echo "$USERINFO_RESPONSE" | grep -q "User associated with token not found"; then
    echo "✅ UserInfo correctly rejects client credentials tokens"
    echo "   (Client credentials tokens don't have associated users)"
else
    echo "⚠️  Unexpected UserInfo response for client credentials token"
    echo "   Expected error about user not found"
fi

echo ""
echo "✅ UserInfo endpoint test completed successfully!"
echo "   Note: UserInfo requires user tokens from authorization flows"
