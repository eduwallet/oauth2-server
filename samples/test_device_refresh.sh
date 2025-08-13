#!/bin/bash

echo "=== Testing Device Authorization with Refresh Token Support ==="

# Test device authorization with offline_access scope
echo "1. Testing device authorization with offline_access..."

DEVICE_AUTH_RESPONSE=$(curl -s -X POST http://localhost:8080/device/authorize \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=smart-tv-app&scope=openid%20profile%20offline_access")

echo "Device Authorization Response:"
echo "$DEVICE_AUTH_RESPONSE" | jq . 2>/dev/null || echo "$DEVICE_AUTH_RESPONSE"

# Extract codes
DEVICE_CODE=$(echo "$DEVICE_AUTH_RESPONSE" | jq -r '.device_code' 2>/dev/null)
USER_CODE=$(echo "$DEVICE_AUTH_RESPONSE" | jq -r '.user_code' 2>/dev/null)

if [ "$DEVICE_CODE" != "null" ] && [ "$DEVICE_CODE" != "" ]; then
    echo ""
    echo "✅ Device Code: ${DEVICE_CODE:0:20}..."
    echo "✅ User Code: $USER_CODE"
    
    echo ""
    echo "2. User needs to authorize the device..."
    echo "   Please go to: http://localhost:8080/device?user_code=$USER_CODE"
    echo "   Use credentials: admin/password"
    echo ""
    echo "   OR use the manual verification:"
    
    # Simulate user verification
    echo "   Simulating user verification..."
    curl -s -X POST http://localhost:8080/device/verify \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "user_code=$USER_CODE&username=admin&password=password" > /dev/null
    
    # Simulate consent approval
    echo "   Simulating consent approval..."
    curl -s -X POST http://localhost:8080/device/consent \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "user_code=$USER_CODE&username=admin&action=approve" > /dev/null
    
    # Wait a moment for the authorization to complete
    sleep 2
    
    echo ""
    echo "3. Testing token request with device code..."
    
    TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8080/oauth/token \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=$DEVICE_CODE&client_id=smart-tv-app")
    
    echo "Token Response:"
    echo "$TOKEN_RESPONSE" | jq . 2>/dev/null || echo "$TOKEN_RESPONSE"
    
    # Check for refresh token
    ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token' 2>/dev/null)
    REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token' 2>/dev/null)
    
    echo ""
    if [ "$ACCESS_TOKEN" != "null" ] && [ "$ACCESS_TOKEN" != "" ]; then
        echo "✅ Access Token: ${ACCESS_TOKEN:0:30}..."
        
        if [ "$REFRESH_TOKEN" != "null" ] && [ "$REFRESH_TOKEN" != "" ]; then
            echo "✅ Refresh Token: ${REFRESH_TOKEN:0:30}..."
            echo "🎉 SUCCESS: Device flow with refresh token works!"
            
            echo ""
            echo "4. Testing refresh token..."
            REFRESH_RESPONSE=$(curl -s -X POST http://localhost:8080/oauth/token \
              -H "Content-Type: application/x-www-form-urlencoded" \
              -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN&client_id=smart-tv-app")
            
            echo "Refresh Response:"
            echo "$REFRESH_RESPONSE" | jq . 2>/dev/null || echo "$REFRESH_RESPONSE"
            
        else
            echo "❌ ISSUE: No refresh token provided despite offline_access scope!"
            echo "   This indicates the scope granting is not working properly."
        fi
    else
        echo "❌ Token request failed"
    fi
else
    echo "❌ Device authorization failed"
fi

echo ""
echo "=== Test completed ==="
