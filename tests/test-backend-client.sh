#!/bin/bash

# Test Client Credentials + Token Exchange Registration
# ====================================================

echo "🔄 Testing Client Credentials + Token Exchange Registration"
echo "=========================================================="
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

# Test: Client with only backend grant types (no redirect URIs needed)
echo "🧪 Test: Backend Service Client (client_credentials + token_exchange)"
echo "--------------------------------------------------------------------"

REGISTRATION_REQUEST='{
  "client_name": "Backend Service Client",
  "grant_types": [
    "client_credentials",
    "refresh_token", 
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "response_types": ["code"],
  "scope": "profile email",
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
        
        # Test the registered client with client_credentials flow
        echo "🧪 Testing Client Credentials Flow"
        echo "---------------------------------"
        
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
            echo "✅ Client credentials flow successful!"
        else
            echo "❌ Client credentials flow failed"
        fi
    fi
else
    echo "❌ Client registration failed"
    echo ""
    echo "🔍 Error Analysis:"
    ERROR=$(echo "$RESPONSE" | jq -r '.error' 2>/dev/null)
    ERROR_DESC=$(echo "$RESPONSE" | jq -r '.error_description' 2>/dev/null)
    echo "   Error: $ERROR"
    echo "   Description: $ERROR_DESC"
fi

echo ""
echo "🎯 Backend Service Client Test Complete!"
echo ""
echo "📖 This test verifies that clients using only backend grant types"
echo "   (client_credentials, refresh_token, token_exchange) do not require"
echo "   redirect URIs, even if they have response_types specified."
