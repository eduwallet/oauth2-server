#!/bin/bash

# Quick introspection test
set -e

BASE_URL="http://localhost:8080"
# Try public client first (no authentication needed)
CLIENT_ID="smart-tv-app"
CLIENT_SECRET=""

echo "🧪 Quick Introspection Test"
echo "=========================="

# Get a device code
echo "📋 Getting device code..."
DEVICE_RESPONSE=$(curl -s -X POST "$BASE_URL/device/authorize" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT_ID&scope=api:read")

echo "Device Response: $DEVICE_RESPONSE"

DEVICE_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.device_code')
USER_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.user_code')

echo "Device Code: $DEVICE_CODE"
echo "User Code: $USER_CODE"

# Approve device (simulate user approval)
echo "✅ Simulating device approval..."
curl -s -X POST "$BASE_URL/device/verify" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user_code=$USER_CODE&username=john.doe&password=password123"

echo "Device approved"

# Get access token
echo "🎫 Getting access token..."
TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=$DEVICE_CODE&client_id=$CLIENT_ID")

echo "Token Response: $TOKEN_RESPONSE"

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
    echo "❌ Failed to get access token: $TOKEN_RESPONSE"
    exit 1
fi

echo "Access Token: $ACCESS_TOKEN"

# For introspection, we need a confidential client
INTROSPECT_CLIENT_ID="backend-client"
INTROSPECT_CLIENT_SECRET="backend-client-secret"

# Test introspection with Basic authentication
echo "🔍 Testing introspection with Basic auth..."
INTROSPECTION_RESPONSE=$(curl -s -X POST "$BASE_URL/oauth/introspect" \
  -u "$INTROSPECT_CLIENT_ID:$INTROSPECT_CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN")

echo "Introspection Response: $INTROSPECTION_RESPONSE"

echo "✅ Test completed!"
