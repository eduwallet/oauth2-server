#!/bin/bash

echo "=== Testing UserInfo Endpoint with Client Credentials ==="

# Get a token using client credentials
echo "1. Getting access token via client credentials..."

TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'backend-client:backend-client-secret' | base64)" \
  -d "grant_type=client_credentials&scope=openid%20profile%20api:read")

echo "Token Response:"
echo "$TOKEN_RESPONSE" | jq . 2>/dev/null || echo "$TOKEN_RESPONSE"

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token' 2>/dev/null)

if [ "$ACCESS_TOKEN" != "null" ] && [ "$ACCESS_TOKEN" != "" ]; then
    echo "✅ Access Token: ${ACCESS_TOKEN:0:30}..."
    
    echo ""
    echo "2. Testing UserInfo endpoint..."
    USERINFO_RESPONSE=$(curl -s -X GET http://localhost:8080/userinfo \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -w "HTTP_STATUS:%{http_code}")
    
    # Extract HTTP status and response body
    HTTP_STATUS=$(echo "$USERINFO_RESPONSE" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
    RESPONSE_BODY=$(echo "$USERINFO_RESPONSE" | sed 's/HTTP_STATUS:[0-9]*$//')
    
    echo "HTTP Status: $HTTP_STATUS"
    echo "Response Body:"
    echo "$RESPONSE_BODY" | jq . 2>/dev/null || echo "$RESPONSE_BODY"
    
    if [ "$HTTP_STATUS" = "200" ]; then
        echo "✅ UserInfo endpoint works!"
    else
        echo "❌ UserInfo endpoint failed with status $HTTP_STATUS"
        
        # Debug: Let's try introspection to see if the token is valid
        echo ""
        echo "3. Debug: Testing token introspection..."
        INTROSPECT_RESPONSE=$(curl -s -X POST http://localhost:8080/oauth/introspect \
          -H "Content-Type: application/x-www-form-urlencoded" \
          -H "Authorization: Basic $(echo -n 'backend-client:backend-client-secret' | base64)" \
          -d "token=$ACCESS_TOKEN")
        
        echo "Introspection Response:"
        echo "$INTROSPECT_RESPONSE" | jq . 2>/dev/null || echo "$INTROSPECT_RESPONSE"
    fi
else
    echo "❌ Failed to get access token"
fi

echo ""
echo "=== Test completed ==="
