#!/bin/bash

echo "=== Testing Device Authorization with Fosite Native Flow ==="

# Test device authorization
echo "1. Testing device authorization..."

DEVICE_AUTH_RESPONSE=$(curl -s -X POST http://localhost:8080/device/authorize \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=smart-tv-app&scope=openid%20profile")

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
    echo "2. Testing token request with device code..."
    
    TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8080/oauth/token \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=$DEVICE_CODE&client_id=smart-tv-app")
    
    echo "Token Response:"
    echo "$TOKEN_RESPONSE" | jq . 2>/dev/null || echo "$TOKEN_RESPONSE"
else
    echo "❌ Device authorization failed"
fi
