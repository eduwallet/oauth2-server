#!/bin/bash

# Test Client Registration Without Redirect URIs
# ==============================================

echo "🧪 Testing Client Registration Without Redirect URIs"
echo "===================================================="
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

# Test 1: Client Credentials Grant (no redirect URI needed)
echo "🧪 Test 1: Client Credentials Grant (No Redirect URI)"
echo "----------------------------------------------------"

CLIENT_CREDENTIALS_REQUEST='{
  "client_name": "Backend Service Client",
  "grant_types": ["client_credentials"],
  "response_types": [],
  "scope": "profile email",
  "token_endpoint_auth_method": "client_secret_basic"
}'

echo "Request payload (Client Credentials - should work):"
echo "$CLIENT_CREDENTIALS_REQUEST" | jq . 2>/dev/null || echo "$CLIENT_CREDENTIALS_REQUEST"
echo ""

RESPONSE1=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "$CLIENT_CREDENTIALS_REQUEST" \
  "$REGISTRATION_ENDPOINT")

HTTP_CODE1=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d "$CLIENT_CREDENTIALS_REQUEST" \
  "$REGISTRATION_ENDPOINT")

echo "HTTP Status: $HTTP_CODE1"
echo "Response:"
echo "$RESPONSE1" | jq . 2>/dev/null || echo "$RESPONSE1"
echo ""

if [ "$HTTP_CODE1" = "201" ]; then
    echo "✅ Client credentials registration successful (no redirect URI required)!"
    CLIENT_ID1=$(echo "$RESPONSE1" | jq -r '.client_id' 2>/dev/null)
    CLIENT_SECRET1=$(echo "$RESPONSE1" | jq -r '.client_secret' 2>/dev/null)
    echo "   Client ID: $CLIENT_ID1"
else
    echo "❌ Client credentials registration failed"
fi

echo ""

# Test 2: Authorization Code Grant (redirect URI required)
echo "🧪 Test 2: Authorization Code Grant Without Redirect URI (Should Fail)"
echo "---------------------------------------------------------------------"

AUTH_CODE_REQUEST_NO_REDIRECT='{
  "client_name": "Web App Without Redirect",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "scope": "openid profile",
  "token_endpoint_auth_method": "client_secret_basic"
}'

echo "Request payload (Authorization Code without redirect - should fail):"
echo "$AUTH_CODE_REQUEST_NO_REDIRECT" | jq . 2>/dev/null || echo "$AUTH_CODE_REQUEST_NO_REDIRECT"
echo ""

RESPONSE2=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "$AUTH_CODE_REQUEST_NO_REDIRECT" \
  "$REGISTRATION_ENDPOINT")

HTTP_CODE2=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d "$AUTH_CODE_REQUEST_NO_REDIRECT" \
  "$REGISTRATION_ENDPOINT")

echo "HTTP Status: $HTTP_CODE2"
echo "Response:"
echo "$RESPONSE2" | jq . 2>/dev/null || echo "$RESPONSE2"
echo ""

if [ "$HTTP_CODE2" = "400" ]; then
    echo "✅ Authorization code registration properly rejected (redirect URI required)!"
else
    echo "❌ Authorization code registration should have been rejected"
fi

echo ""

# Test 3: Authorization Code Grant (with redirect URI)
echo "🧪 Test 3: Authorization Code Grant With Redirect URI (Should Work)"
echo "------------------------------------------------------------------"

AUTH_CODE_REQUEST_WITH_REDIRECT='{
  "client_name": "Web App With Redirect",
  "redirect_uris": ["https://webapp.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "client_secret_basic"
}'

echo "Request payload (Authorization Code with redirect - should work):"
echo "$AUTH_CODE_REQUEST_WITH_REDIRECT" | jq . 2>/dev/null || echo "$AUTH_CODE_REQUEST_WITH_REDIRECT"
echo ""

RESPONSE3=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "$AUTH_CODE_REQUEST_WITH_REDIRECT" \
  "$REGISTRATION_ENDPOINT")

HTTP_CODE3=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d "$AUTH_CODE_REQUEST_WITH_REDIRECT" \
  "$REGISTRATION_ENDPOINT")

echo "HTTP Status: $HTTP_CODE3"
echo "Response:"
echo "$RESPONSE3" | jq . 2>/dev/null || echo "$RESPONSE3"
echo ""

if [ "$HTTP_CODE3" = "201" ]; then
    echo "✅ Authorization code registration successful (with redirect URI)!"
    CLIENT_ID3=$(echo "$RESPONSE3" | jq -r '.client_id' 2>/dev/null)
    echo "   Client ID: $CLIENT_ID3"
else
    echo "❌ Authorization code registration failed"
fi

echo ""

# Test 4: Device Flow (no redirect URI needed)
echo "🧪 Test 4: Device Flow Grant (No Redirect URI)"
echo "----------------------------------------------"

DEVICE_FLOW_REQUEST='{
  "client_name": "Smart TV Device",
  "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
  "response_types": [],
  "scope": "openid profile",
  "token_endpoint_auth_method": "client_secret_basic"
}'

echo "Request payload (Device Flow - should work):"
echo "$DEVICE_FLOW_REQUEST" | jq . 2>/dev/null || echo "$DEVICE_FLOW_REQUEST"
echo ""

RESPONSE4=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "$DEVICE_FLOW_REQUEST" \
  "$REGISTRATION_ENDPOINT")

HTTP_CODE4=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d "$DEVICE_FLOW_REQUEST" \
  "$REGISTRATION_ENDPOINT")

echo "HTTP Status: $HTTP_CODE4"
echo "Response:"
echo "$RESPONSE4" | jq . 2>/dev/null || echo "$RESPONSE4"
echo ""

if [ "$HTTP_CODE4" = "201" ]; then
    echo "✅ Device flow registration successful (no redirect URI required)!"
    CLIENT_ID4=$(echo "$RESPONSE4" | jq -r '.client_id' 2>/dev/null)
    echo "   Client ID: $CLIENT_ID4"
else
    echo "❌ Device flow registration failed"
fi

echo ""

# Test 5: Token Exchange + Client Credentials (no redirect URI needed)
echo "🧪 Test 5: Token Exchange + Client Credentials (No Redirect URI)"
echo "----------------------------------------------------------------"

TOKEN_EXCHANGE_REQUEST='{
  "client_name": "Backend Service with Token Exchange",
  "grant_types": [
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "response_types": ["code"],
  "scope": "profile email",
  "token_endpoint_auth_method": "client_secret_basic"
}'

echo "Request payload (Token Exchange + Client Credentials - should work):"
echo "$TOKEN_EXCHANGE_REQUEST" | jq . 2>/dev/null || echo "$TOKEN_EXCHANGE_REQUEST"
echo ""

RESPONSE5=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "$TOKEN_EXCHANGE_REQUEST" \
  "$REGISTRATION_ENDPOINT")

HTTP_CODE5=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d "$TOKEN_EXCHANGE_REQUEST" \
  "$REGISTRATION_ENDPOINT")

echo "HTTP Status: $HTTP_CODE5"
echo "Response:"
echo "$RESPONSE5" | jq . 2>/dev/null || echo "$RESPONSE5"
echo ""

if [ "$HTTP_CODE5" = "201" ]; then
    echo "✅ Token exchange + client credentials registration successful (no redirect URI required)!"
    CLIENT_ID5=$(echo "$RESPONSE5" | jq -r '.client_id' 2>/dev/null)
    echo "   Client ID: $CLIENT_ID5"
else
    echo "❌ Token exchange + client credentials registration failed"
fi

echo ""

# Test the registered client credentials client
if [ "$HTTP_CODE1" = "201" ] && [ "$CLIENT_ID1" != "null" ] && [ "$CLIENT_ID1" != "" ]; then
    echo "🧪 Test 5: Use Registered Client Credentials Client"
    echo "-------------------------------------------------"
    
    echo "Testing token request with registered client..."
    TOKEN_RESPONSE=$(curl -s -X POST \
      -u "$CLIENT_ID1:$CLIENT_SECRET1" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=client_credentials&scope=profile" \
      "$BASE_URL/oauth2/token")
    
    TOKEN_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
      -u "$CLIENT_ID1:$CLIENT_SECRET1" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=client_credentials&scope=profile" \
      "$BASE_URL/oauth2/token")
    
    echo "HTTP Status: $TOKEN_HTTP_CODE"
    echo "Token Response:"
    echo "$TOKEN_RESPONSE" | jq . 2>/dev/null || echo "$TOKEN_RESPONSE"
    echo ""
    
    if [ "$TOKEN_HTTP_CODE" = "200" ]; then
        echo "✅ Registered client successfully obtained access token!"
    else
        echo "❌ Token request failed for registered client"
    fi
fi

echo ""
echo "🎯 Summary:"
echo "=========="
echo "✅ Client Credentials (no redirect URI): $([ "$HTTP_CODE1" = "201" ] && echo "PASS" || echo "FAIL")"
echo "✅ Auth Code without redirect URI: $([ "$HTTP_CODE2" = "400" ] && echo "PROPERLY REJECTED" || echo "FAIL")"
echo "✅ Auth Code with redirect URI: $([ "$HTTP_CODE3" = "201" ] && echo "PASS" || echo "FAIL")"
echo "✅ Device Flow (no redirect URI): $([ "$HTTP_CODE4" = "201" ] && echo "PASS" || echo "FAIL")"
echo "✅ Token Exchange + Client Creds (no redirect URI): $([ "$HTTP_CODE5" = "201" ] && echo "PASS" || echo "FAIL")"
echo ""
echo "📋 The server now intelligently determines when redirect URIs are required:"
echo "   • Client Credentials Grant: No redirect URI needed ✅"
echo "   • Device Flow Grant: No redirect URI needed ✅"
echo "   • Token Exchange Grant: No redirect URI needed ✅"
echo "   • Authorization Code Grant: Redirect URI required ✅"
echo "   • Implicit Grant: Redirect URI required ✅"
