#!/bin/bash

# Test configuration - use environment variables with defaults
TEST_USERNAME="${TEST_USERNAME:-john.doe}"
TEST_PASSWORD="${TEST_PASSWORD:-password123}"
TEST_SCOPE="${TEST_SCOPE:-openid profile email}"

echo "🧪 Token Introspection Test"
echo "=========================="
echo "Testing RFC 7662 token introspection endpoint"
echo "Using client credentials flow to obtain test token"

BASE_URL="${OAUTH2_SERVER_URL:-http://localhost:8080}"

# Use smart-tv-app for device flow (public client, gets auto-completed)
CLIENT_ID="smart-tv-app"
CLIENT_SECRET=""

# Get an access token using client credentials flow (more reliable than device flow)
echo "🎫 Getting access token using client credentials..."
BASIC_AUTH=$(echo -n "backend-client:backend-client-secret" | base64)
TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $BASIC_AUTH" \
  -d "grant_type=client_credentials&scope=api:read")

echo "Token Response: $TOKEN_RESPONSE"

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
    echo "❌ Failed to get access token: $TOKEN_RESPONSE"
    exit 1
fi

echo "✅ Got access token: ${ACCESS_TOKEN:0:30}..."

# For introspection, we need a confidential client
INTROSPECT_CLIENT_ID="backend-client"
INTROSPECT_CLIENT_SECRET="backend-client-secret"

# Test introspection with Basic authentication
echo "🔍 Testing token introspection..."
INTROSPECTION_RESPONSE=$(curl -s -X POST "$BASE_URL/introspect" \
  -u "$INTROSPECT_CLIENT_ID:$INTROSPECT_CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN")

echo "Introspection Response: $INTROSPECTION_RESPONSE"

# Check if introspection was successful
ACTIVE=$(echo "$INTROSPECTION_RESPONSE" | jq -r '.active // false')
if [ "$ACTIVE" = "true" ]; then
    echo "✅ Token introspection successful - token is active"
else
    echo "❌ Token introspection failed or token is not active"
    exit 1
fi

echo ""
echo "✅ Token introspection test completed successfully!"
