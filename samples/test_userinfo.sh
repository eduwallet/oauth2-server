#!/bin/bash

echo "=== Testing UserInfo Endpoint with Device Flow Token ==="

# First, get a token through device flow
echo "1. Getting access token via device flow..."

DEVICE_AUTH_RESPONSE=$(curl -s -X POST http://localhost:8080/device/authorize \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=smart-tv-app&scope=openid%20profile%20offline_access")

DEVICE_CODE=$(echo "$DEVICE_AUTH_RESPONSE" | jq -r '.device_code' 2>/dev/null)
USER_CODE=$(echo "$DEVICE_AUTH_RESPONSE" | jq -r '.user_code' 2>/dev/null)

if [ "$DEVICE_CODE" != "null" ] && [ "$DEVICE_CODE" != "" ]; then
    echo "✅ Device Code: ${DEVICE_CODE:0:20}..."
    echo "✅ User Code: $USER_CODE"
    
    # Simulate user verification and consent
    echo "2. Simulating user authorization..."
    curl -s -X POST http://localhost:8080/device/verify \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "user_code=$USER_CODE&username=admin&password=password" > /dev/null
    
    curl -s -X POST http://localhost:8080/device/consent \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "user_code=$USER_CODE&username=admin&action=approve" > /dev/null
    
    sleep 2
    
    # Get token
    echo "3. Getting access token..."
    TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8080/oauth/token \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=$DEVICE_CODE&client_id=smart-tv-app")
    
    ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token' 2>/dev/null)
    
    if [ "$ACCESS_TOKEN" != "null" ] && [ "$ACCESS_TOKEN" != "" ]; then
        echo "✅ Access Token: ${ACCESS_TOKEN:0:30}..."
        
        echo ""
        echo "4. Testing UserInfo endpoint..."
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
            echo "5. Debug: Testing token introspection..."
            INTROSPECT_RESPONSE=$(curl -s -X POST http://localhost:8080/oauth/introspect \
              -H "Content-Type: application/x-www-form-urlencoded" \
              -H "Authorization: Basic $(echo -n 'smart-tv-app:' | base64)" \
              -d "token=$ACCESS_TOKEN")
            
            echo "Introspection Response:"
            echo "$INTROSPECT_RESPONSE" | jq . 2>/dev/null || echo "$INTROSPECT_RESPONSE"
        fi
    else
        echo "❌ Failed to get access token"
        echo "$TOKEN_RESPONSE"
    fi
else
    echo "❌ Device authorization failed"
fi

echo ""
echo "=== Test completed ==="
