#!/bin/bash

# Dynamic Client Registration Test Script
# ======================================

echo "🔄 Testing Dynamic Client Registration"
echo "======================================"
echo ""

BASE_URL="http://localhost:8080"
REGISTRATION_ENDPOINT="$BASE_URL/oauth2/register"

# Test if server is running
if ! curl -s "$BASE_URL/" >/dev/null 2>&1; then
    echo "❌ Server not running on $BASE_URL"
    echo "   Start with: make run"
    exit 1
fi

echo "✅ Server is running"
echo ""

# Test 1: Basic client registration (no initial access token required)
echo "🧪 Test 1: Basic Client Registration"
echo "-----------------------------------"

REGISTRATION_REQUEST='{
  "redirect_uris": ["https://client.example.org/callback"],
  "client_name": "Test Dynamic Client",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "client_secret_basic"
}'

echo "Request payload:"
echo "$REGISTRATION_REQUEST" | jq . 2>/dev/null || echo "$REGISTRATION_REQUEST"
echo ""

echo "Sending registration request..."
RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "$REGISTRATION_REQUEST" \
  "$REGISTRATION_ENDPOINT")

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d "$REGISTRATION_REQUEST" \
  "$REGISTRATION_ENDPOINT")

echo "HTTP Status: $HTTP_CODE"
echo "Response:"
echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
echo ""

if [ "$HTTP_CODE" = "201" ]; then
    echo "✅ Client registration successful!"
    
    # Extract client credentials
    CLIENT_ID=$(echo "$RESPONSE" | jq -r '.client_id' 2>/dev/null)
    CLIENT_SECRET=$(echo "$RESPONSE" | jq -r '.client_secret' 2>/dev/null)
    
    if [ "$CLIENT_ID" != "null" ] && [ "$CLIENT_ID" != "" ]; then
        echo "📋 Client Details:"
        echo "   Client ID: $CLIENT_ID"
        echo "   Client Secret: $CLIENT_SECRET"
        echo ""
        
        # Test 2: Use the registered client to get a token
        echo "🧪 Test 2: Test Registered Client (Client Credentials Flow)"
        echo "---------------------------------------------------------"
        
        TOKEN_REQUEST="grant_type=client_credentials&scope=profile"
        
        echo "Testing client credentials flow..."
        TOKEN_RESPONSE=$(curl -s -X POST \
          -u "$CLIENT_ID:$CLIENT_SECRET" \
          -H "Content-Type: application/x-www-form-urlencoded" \
          -d "$TOKEN_REQUEST" \
          "$BASE_URL/oauth2/token")
        
        TOKEN_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
          -u "$CLIENT_ID:$CLIENT_SECRET" \
          -H "Content-Type: application/x-www-form-urlencoded" \
          -d "$TOKEN_REQUEST" \
          "$BASE_URL/oauth2/token")
        
        echo "HTTP Status: $TOKEN_HTTP_CODE"
        echo "Token Response:"
        echo "$TOKEN_RESPONSE" | jq . 2>/dev/null || echo "$TOKEN_RESPONSE"
        echo ""
        
        if [ "$TOKEN_HTTP_CODE" = "200" ]; then
            echo "✅ Token request successful! Client is working."
        else
            echo "❌ Token request failed"
        fi
    fi
else
    echo "❌ Client registration failed"
fi

echo ""

# Test 3: Invalid registration request
echo "🧪 Test 3: Invalid Registration Request"
echo "--------------------------------------"

INVALID_REQUEST='{
  "grant_types": ["invalid_grant_type"]
}'

echo "Sending invalid request..."
INVALID_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "$INVALID_REQUEST" \
  "$REGISTRATION_ENDPOINT")

INVALID_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d "$INVALID_REQUEST" \
  "$REGISTRATION_ENDPOINT")

echo "HTTP Status: $INVALID_HTTP_CODE"
echo "Response:"
echo "$INVALID_RESPONSE" | jq . 2>/dev/null || echo "$INVALID_RESPONSE"
echo ""

if [ "$INVALID_HTTP_CODE" = "400" ]; then
    echo "✅ Invalid request properly rejected"
else
    echo "❌ Invalid request should have been rejected with 400"
fi

echo ""
echo "🎯 Dynamic Client Registration Tests Complete!"
echo ""
echo "📋 Summary:"
echo "   • Dynamic client registration endpoint: $REGISTRATION_ENDPOINT"
echo "   • Discovery endpoints include registration_endpoint when enabled"
echo "   • Clients can be registered without initial access token (demo mode)"
echo "   • Registered clients can immediately request tokens"
echo ""
echo "📖 For production:"
echo "   • Set require_initial_access_token: true in config"
echo "   • Use proper initial access tokens"
echo "   • Implement client secret rotation"
echo "   • Add proper validation and rate limiting"
