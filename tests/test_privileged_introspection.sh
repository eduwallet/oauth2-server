#!/bin/bash

# Test configuration - use environment variables with defaults
TEST_USERNAME="${TEST_USERNAME:-john.doe}"
TEST_PASSWORD="${TEST_PASSWORD:-password123}"
TEST_SCOPE="${TEST_SCOPE:-api:read}"

echo "🧪 Privileged Client Token Test"
echo "================================="
echo "Testing privileged client token acquisition"
echo "Privileged clients can request admin scope for elevated permissions"

BASE_URL="http://localhost:8080"

# Step 1: Get a token for a regular client using client credentials
echo "📋 Getting access token for regular client..."
TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/token" \
  -u "backend-client:backend-client-secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=api:read")

echo "Token Response: $TOKEN_RESPONSE"

REGULAR_ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')

if [ -z "$REGULAR_ACCESS_TOKEN" ] || [ "$REGULAR_ACCESS_TOKEN" = "null" ]; then
    echo "❌ Failed to get access token for regular client: $TOKEN_RESPONSE"
    exit 1
fi

echo "Regular Client Access Token: $REGULAR_ACCESS_TOKEN"

# Step 2: Get access token for privileged client using client_credentials
echo "🔑 Getting access token for privileged client..."
PRIVILEGED_TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/token" \
  -u "server-owned-client:server-admin-secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=admin")

echo "Privileged Token Response: $PRIVILEGED_TOKEN_RESPONSE"

PRIVILEGED_ACCESS_TOKEN=$(echo "$PRIVILEGED_TOKEN_RESPONSE" | jq -r '.access_token // empty')

if [ -z "$PRIVILEGED_ACCESS_TOKEN" ] || [ "$PRIVILEGED_ACCESS_TOKEN" = "null" ]; then
    echo "❌ Failed to get access token for privileged client: $PRIVILEGED_TOKEN_RESPONSE"
    exit 1
fi

echo "Privileged Client Access Token: $PRIVILEGED_ACCESS_TOKEN"

# Step 3: Test that regular client can introspect its own token
echo "🔍 Testing regular client introspection..."
INTROSPECTION_RESPONSE=$(curl -s -X POST "$BASE_URL/introspect" \
  -u "backend-client:backend-client-secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$REGULAR_ACCESS_TOKEN")

echo "Introspection Response: $INTROSPECTION_RESPONSE"

# Verify introspection was successful
ACTIVE=$(echo "$INTROSPECTION_RESPONSE" | jq -r '.active // false')
CLIENT_ID=$(echo "$INTROSPECTION_RESPONSE" | jq -r '.client_id // empty')

if [ "$ACTIVE" != "true" ]; then
    echo "❌ Introspection failed: token not active"
    exit 1
fi

if [ "$CLIENT_ID" != "backend-client" ]; then
    echo "❌ Introspection failed: wrong client_id returned"
    exit 1
fi

echo "✅ Regular client successfully introspected its own token!"
echo "   - Token active: $ACTIVE"
echo "   - Client ID: $CLIENT_ID"
echo "   - Scopes: $(echo "$INTROSPECTION_RESPONSE" | jq -r '.scope // "none"')"
echo "   - Expires at: $(echo "$INTROSPECTION_RESPONSE" | jq -r '.exp // "unknown"')"

echo ""
echo "✅ Privileged client token test completed successfully!"