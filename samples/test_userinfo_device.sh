#!/bin/bash

echo "=== Testing UserInfo Endpoint with Device Flow (Proper User Context) ==="

# Step 1: Create device authorization
echo "1. Creating device authorization..."
DEVICE_AUTH_RESPONSE=$(curl -s -X POST http://localhost:8080/device/authorize \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=smart-tv-app&scope=openid%20profile%20offline_access")

echo "Device authorization response:"
echo "$DEVICE_AUTH_RESPONSE" | jq . 2>/dev/null || echo "$DEVICE_AUTH_RESPONSE"

DEVICE_CODE=$(echo "$DEVICE_AUTH_RESPONSE" | jq -r '.device_code' 2>/dev/null)
USER_CODE=$(echo "$DEVICE_AUTH_RESPONSE" | jq -r '.user_code' 2>/dev/null)

if [ "$DEVICE_CODE" = "null" ] || [ "$DEVICE_CODE" = "" ]; then
    echo "❌ Failed to get device code"
    exit 1
fi

echo "✅ Device Code: ${DEVICE_CODE:0:20}..."
echo "✅ User Code: $USER_CODE"

# Step 2: Simulate user authorization
echo ""
echo "2. Simulating user verification..."
VERIFY_RESPONSE=$(curl -s -X POST http://localhost:8080/device/verify \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user_code=$USER_CODE&username=testuser&password=testpass" \
  -w "HTTP_STATUS:%{http_code}")

VERIFY_STATUS=$(echo "$VERIFY_RESPONSE" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
echo "Verification status: $VERIFY_STATUS"

if [ "$VERIFY_STATUS" != "200" ]; then
    echo "❌ User verification failed"
    echo "$VERIFY_RESPONSE"
    exit 1
fi

# Step 3: Simulate consent approval
echo ""
echo "3. Simulating consent approval..."
CONSENT_RESPONSE=$(curl -s -X POST http://localhost:8080/device/consent \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user_code=$USER_CODE&username=testuser&action=approve" \
  -w "HTTP_STATUS:%{http_code}")

CONSENT_STATUS=$(echo "$CONSENT_RESPONSE" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
echo "Consent status: $CONSENT_STATUS"

if [ "$CONSENT_STATUS" != "200" ]; then
    echo "❌ Consent approval failed"
    echo "$CONSENT_RESPONSE"
    exit 1
fi

# Wait for authorization to complete
sleep 3

# Step 4: Exchange device code for token
echo ""
echo "4. Exchanging device code for access token..."
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=$DEVICE_CODE&client_id=smart-tv-app")

echo "Token response:"
echo "$TOKEN_RESPONSE" | jq . 2>/dev/null || echo "$TOKEN_RESPONSE"

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token' 2>/dev/null)

if [ "$ACCESS_TOKEN" = "null" ] || [ "$ACCESS_TOKEN" = "" ]; then
    echo "❌ Failed to get access token"
    exit 1
fi

echo "✅ Access Token: ${ACCESS_TOKEN:0:30}..."

# Step 5: Test UserInfo endpoint
echo ""
echo "5. Testing UserInfo endpoint..."
USERINFO_RESPONSE=$(curl -s -X GET http://localhost:8080/userinfo \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -w "HTTP_STATUS:%{http_code}")

HTTP_STATUS=$(echo "$USERINFO_RESPONSE" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
RESPONSE_BODY=$(echo "$USERINFO_RESPONSE" | sed 's/HTTP_STATUS:[0-9]*$//')

echo "HTTP Status: $HTTP_STATUS"
echo "UserInfo Response:"
echo "$RESPONSE_BODY" | jq . 2>/dev/null || echo "$RESPONSE_BODY"

if [ "$HTTP_STATUS" = "200" ]; then
    echo "✅ UserInfo endpoint works perfectly!"
else
    echo "❌ UserInfo endpoint failed with status $HTTP_STATUS"
    
    # Debug with introspection
    echo ""
    echo "6. Debug: Testing token introspection..."
    INTROSPECT_RESPONSE=$(curl -s -X POST http://localhost:8080/oauth/introspect \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "Authorization: Basic $(echo -n 'smart-tv-app:' | base64)" \
      -d "token=$ACCESS_TOKEN")
    
    echo "Introspection Response:"
    echo "$INTROSPECT_RESPONSE" | jq . 2>/dev/null || echo "$INTROSPECT_RESPONSE"
fi

echo ""
echo "=== Test completed ==="
