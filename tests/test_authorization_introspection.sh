#!/bin/bash

# Test script for authorization-introspection endpoint
# This endpoint combines token introspection with userinfo data
# Tests the cross-client scenario where:
# - Token is created for TOKEN_CLIENT_ID (web-app-client)
# - Introspection is performed by INTROSPECTION_CLIENT_ID (backend-client)
# - This works because backend-client is in web-app-client's audience list

set -e

# Configuration
SERVER_URL="http://localhost:8080"
TOKEN_CLIENT_ID="web-app-client"
TOKEN_CLIENT_SECRET="web-app-secret"
INTROSPECTION_CLIENT_ID="backend-client"
INTROSPECTION_CLIENT_SECRET="backend-client-secret"
USERNAME="john.doe"
PASSWORD="password123"

echo "🧪 Testing authorization-introspection endpoint"
echo "=========================================="

# Step 1: Get an access token
echo "📝 Step 1: Obtaining access token..."
TOKEN_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "$TOKEN_CLIENT_ID:$TOKEN_CLIENT_SECRET" \
  -d "grant_type=password&username=$USERNAME&password=$PASSWORD&scope=openid profile email")

echo "Token response: $TOKEN_RESPONSE"

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
if [ "$ACCESS_TOKEN" = "null" ] || [ -z "$ACCESS_TOKEN" ]; then
  echo "❌ Failed to obtain access token"
  exit 1
fi

echo "✅ Obtained access token: ${ACCESS_TOKEN:0:20}..."

# Step 2: Test authorization-introspection endpoint
echo ""
echo "📝 Step 2: Testing authorization-introspection endpoint..."

INTROSPECTION_RESPONSE=$(curl -s -X POST "$SERVER_URL/authorization-introspection" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "$INTROSPECTION_CLIENT_ID:$INTROSPECTION_CLIENT_SECRET" \
  -d "access-token=$ACCESS_TOKEN")

echo "Authorization-introspection response:"
echo "$INTROSPECTION_RESPONSE" | jq '.'

# Validate response structure
echo ""
echo "📝 Step 3: Validating response structure..."

# Check if response contains token-details
if echo "$INTROSPECTION_RESPONSE" | jq -e '.["token-details"]' > /dev/null; then
  echo "✅ Response contains token-details"
else
  echo "❌ Response missing token-details"
  exit 1
fi

# Check if response contains user-info
if echo "$INTROSPECTION_RESPONSE" | jq -e '.["user-info"]' > /dev/null; then
  echo "✅ Response contains user-info"
else
  echo "❌ Response missing user-info"
  exit 1
fi

# Check if token is active
TOKEN_ACTIVE=$(echo "$INTROSPECTION_RESPONSE" | jq -r '.["token-details"].active')
if [ "$TOKEN_ACTIVE" = "true" ]; then
  echo "✅ Token is active"
else
  echo "❌ Token is not active"
  exit 1
fi

# Check if client_id matches
RESPONSE_CLIENT_ID=$(echo "$INTROSPECTION_RESPONSE" | jq -r '.["token-details"].client_id')
if [ "$RESPONSE_CLIENT_ID" = "$TOKEN_CLIENT_ID" ]; then
  echo "✅ Token client_id matches expected client ($TOKEN_CLIENT_ID)"
else
  echo "❌ Token client_id mismatch: expected $TOKEN_CLIENT_ID, got $RESPONSE_CLIENT_ID"
  exit 1
fi

echo ""
echo "🎉 All tests passed! Authorization-introspection endpoint is working correctly."

# Test with invalid token
echo ""
echo "📝 Step 4: Testing with invalid token..."

INVALID_RESPONSE=$(curl -s -X POST "$SERVER_URL/authorization-introspection" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "$INTROSPECTION_CLIENT_ID:$INTROSPECTION_CLIENT_SECRET" \
  -d "access-token=invalid-token")

echo "Invalid token response:"
echo "$INVALID_RESPONSE" | jq '.'

# Check if invalid token returns inactive status
INVALID_ACTIVE=$(echo "$INVALID_RESPONSE" | jq -r '.["token-details"].active')
if [ "$INVALID_ACTIVE" = "false" ]; then
  echo "✅ Invalid token correctly returns inactive status"
else
  echo "❌ Invalid token should return inactive status"
  exit 1
fi

echo ""
echo "🎉 Invalid token test passed!"

echo ""
echo "✅ All authorization-introspection tests completed successfully!"