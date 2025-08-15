#!/bin/bash

echo "=== Testing Device Flow Client Registration ==="

# Register a client specifically for device flow
echo "1. Registering a device flow client..."

REGISTRATION_RESPONSE=$(curl -s -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test Device Client",
    "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
    "response_types": [],
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "openid profile offline_access"
  }')

echo "Registration Response:"
echo "$REGISTRATION_RESPONSE" | jq . 2>/dev/null || echo "$REGISTRATION_RESPONSE"

# Extract client credentials
CLIENT_ID=$(echo "$REGISTRATION_RESPONSE" | jq -r '.client_id' 2>/dev/null)
CLIENT_SECRET=$(echo "$REGISTRATION_RESPONSE" | jq -r '.client_secret' 2>/dev/null)

if [ "$CLIENT_ID" != "null" ] && [ "$CLIENT_ID" != "" ]; then
    echo ""
    echo "2. Testing device authorization with registered client..."
    echo "Client ID: $CLIENT_ID"
    echo "Client Secret: ${CLIENT_SECRET:0:10}..."
    
    # Create Basic Auth header
    BASIC_AUTH=$(echo -n "$CLIENT_ID:$CLIENT_SECRET" | base64)
    echo "Basic Auth: Basic $BASIC_AUTH"
    
    # Test device authorization with proper authentication
    echo ""
    echo "Testing device authorization with Basic auth..."
    DEVICE_AUTH_RESPONSE=$(curl -s -X POST http://localhost:8080/device/authorize \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "Authorization: Basic $BASIC_AUTH" \
      -d "client_id=$CLIENT_ID&scope=openid%20profile%20offline_access")
    
    echo "Device Authorization Response:"
    echo "$DEVICE_AUTH_RESPONSE" | jq . 2>/dev/null || echo "$DEVICE_AUTH_RESPONSE"

    echo ""
    echo "Testing device authorization with client credentials in body..."
    DEVICE_AUTH_RESPONSE2=$(curl -s -X POST http://localhost:8080/device/authorize \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=openid%20profile%20offline_access")
    
    echo "Device Authorization Response (credentials in body):"
    echo "$DEVICE_AUTH_RESPONSE2" | jq . 2>/dev/null || echo "$DEVICE_AUTH_RESPONSE2"
else
    echo "❌ Client registration failed"
fi
