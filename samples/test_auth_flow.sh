#!/bin/bash

echo "=== Testing Authorization Code Flow + UserInfo ==="

# Step 1: Get authorization code (simulate login)
echo "1. Getting authorization code..."
AUTH_CODE=$(curl -s -L "http://localhost:8080/auth?response_type=code&client_id=web-app-client&redirect_uri=http://localhost:8080/callback&scope=openid%20profile%20email&state=teststate123&code_challenge=testchallenge&code_challenge_method=S256" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john.doe&password=password123" | grep -o 'code=[^&]*' | cut -d'=' -f2)

if [ -z "$AUTH_CODE" ]; then
    echo "❌ Failed to get authorization code"
    exit 1
fi

echo "✅ Authorization Code: ${AUTH_CODE:0:30}..."

# Step 2: Exchange code for token
echo "2. Exchanging code for access token..."
TOKEN_RESPONSE=$(curl -s -X POST "http://localhost:8080/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'web-app-client:web-app-secret' | base64)" \
  -d "grant_type=authorization_code&code=$AUTH_CODE&redirect_uri=http://localhost:8080/callback&code_verifier=testchallenge")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token' 2>/dev/null)

if [ "$ACCESS_TOKEN" = "null" ] || [ -z "$ACCESS_TOKEN" ]; then
    echo "❌ Failed to get access token"
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi

echo "✅ Access Token: ${ACCESS_TOKEN:0:30}..."

# Step 3: Test UserInfo
echo "3. Testing UserInfo endpoint..."
USERINFO_RESPONSE=$(curl -s -X GET "http://localhost:8080/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -w "HTTP_STATUS:%{http_code}")

HTTP_STATUS=$(echo "$USERINFO_RESPONSE" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
RESPONSE_BODY=$(echo "$USERINFO_RESPONSE" | sed 's/HTTP_STATUS:[0-9]*$//')

echo "HTTP Status: $HTTP_STATUS"
if [ "$HTTP_STATUS" = "200" ]; then
    echo "✅ UserInfo works!"
    echo "Response: $RESPONSE_BODY"
else
    echo "❌ UserInfo failed: $RESPONSE_BODY"
fi

echo "=== Test completed ==="
