#!/bin/bash

# RFC8693 Token Exchange Test Script
# This script tests the RFC8693 Token Exchange implementation

set -e

BASE_URL="http://localhost:8080"
CLIENT_ID="backend-client"
CLIENT_SECRET="backend-client-secret"

echo "🧪 Testing RFC8693 Token Exchange Implementation"
echo "================================================"

# Step 1: Get an access token through client credentials flow
echo "📋 Step 1: Getting initial access token..."

RESPONSE=$(curl -s -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=api:read")

echo "Response: $RESPONSE"

# Extract access token
SUBJECT_TOKEN=$(echo "$RESPONSE" | grep -o '"access_token":"[^"]*"' | sed 's/"access_token":"\([^"]*\)"/\1/')

if [ -z "$SUBJECT_TOKEN" ]; then
    echo "❌ Failed to get initial access token"
    exit 1
fi

echo "✅ Got initial access token: ${SUBJECT_TOKEN:0:20}..."

echo $SUBJECT_TOKEN
echo $(echo -n "$CLIENT_ID:$CLIENT_SECRET" | base64)

# Step 2: Perform RFC8693 Token Exchange

echo "📋 Step 2: Performing RFC8693 Token Exchange..."
EXCHANGE_RESPONSE=$(curl -s -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n "$CLIENT_ID:$CLIENT_SECRET" | base64)" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=$SUBJECT_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token&requested_token_type=urn:ietf:params:oauth:token-type:access_token")

echo "Token Exchange Response: $EXCHANGE_RESPONSE"

# Check if exchange was successful
NEW_TOKEN=$(echo "$EXCHANGE_RESPONSE" | grep -o '"access_token":"[^"]*"' | sed 's/"access_token":"\([^"]*\)"/\1/')

if [ -n "$NEW_TOKEN" ]; then
    echo "✅ Token exchange successful!"
    echo "✅ New access token: ${NEW_TOKEN:0:20}..."
    echo ""
    echo "🎉 RFC8693 Token Exchange implementation is working!"
else
    echo "❌ Token exchange failed"
    echo "Response: $EXCHANGE_RESPONSE"
    exit 1
fi
